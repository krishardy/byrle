//! An artifact's `maven-metadata.xml` as records, and as the byte spans of its versions,
//! `<latest>` and `<release>`, so the filter removes what the policy refuses and leaves
//! every other byte as the repository wrote it.

use std::collections::HashSet;
use std::ops::Range;

use quick_xml::events::Event;

use crate::identity::PackageKey;
use crate::record::{Artifact, DocumentDetail, PackageMetadata, PackageRecord, Provenance};

use super::paths::filename;

/// One element's text, the bytes of the whole element, and the bytes of its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub text: String,
    pub whole: Range<usize>,
    pub inner: Range<usize>,
}

/// What an artifact's `maven-metadata.xml` holds that the proxy reads.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Metadata {
    pub group: Option<Element>,
    pub artifact: Option<Element>,
    pub latest: Option<Element>,
    pub release: Option<Element>,
    pub versions: Vec<Element>,
    /// Whether the document has `<versioning><versions>`, which a group's file has not.
    pub has_versions: bool,
}

/// The elements read, by where each is in the document.
const GROUP: &[&str] = &["metadata", "groupId"];
const ARTIFACT: &[&str] = &["metadata", "artifactId"];
const LATEST: &[&str] = &["metadata", "versioning", "latest"];
const RELEASE: &[&str] = &["metadata", "versioning", "release"];
const VERSIONS: &[&str] = &["metadata", "versioning", "versions"];
const VERSION: &[&str] = &["metadata", "versioning", "versions", "version"];

/// The element being read: its path, its start, and its text so far.
struct Open {
    path: Vec<String>,
    start: usize,
    inner: usize,
    text: String,
    nested: bool,
}

/// Read `decoded` as `maven-metadata.xml`. Errors when it is not well-formed XML, names an
/// entity XML does not define, or holds an element inside one read for its text.
pub fn parse(decoded: &[u8]) -> Result<Metadata, String> {
    let text = std::str::from_utf8(decoded).map_err(|e| e.to_string())?;
    let mut reader = quick_xml::Reader::from_str(text);
    let mut metadata = Metadata::default();
    let mut path: Vec<String> = Vec::new();
    let mut open: Option<Open> = None;
    loop {
        let before = position(&reader);
        let event = reader.read_event().map_err(|e| e.to_string())?;
        match event {
            Event::Start(start) => {
                path.push(start.name().as_ref().to_owned());
                if path == VERSIONS {
                    metadata.has_versions = true;
                }
                match &mut open {
                    Some(open) => open.nested = true,
                    None if is_read(&path) => {
                        open = Some(Open {
                            path: path.clone(),
                            start: before,
                            inner: position(&reader),
                            text: String::new(),
                            nested: false,
                        });
                    }
                    None => {}
                }
            }
            Event::Empty(empty) => {
                if let Some(open) = &mut open {
                    open.nested = true;
                }
                let name = empty.name().as_ref().to_owned();
                if [path.as_slice(), &[name]].concat() == VERSIONS {
                    metadata.has_versions = true;
                }
            }
            Event::Text(t) => append(&mut open, &t.xml10_content()),
            Event::CData(c) => append(&mut open, &c.into_inner()),
            Event::GeneralRef(r) => {
                let resolved = match r.resolve_char_ref().map_err(|e| e.to_string())? {
                    Some(c) => c,
                    None => predefined(&r.into_inner())?,
                };
                append(&mut open, &resolved.to_string());
            }
            Event::End(_) => {
                if let Some(read) = open.take_if(|o| o.path == path) {
                    if read.nested {
                        return Err(format!("<{}> holds an element", path.join("><")));
                    }
                    let element = Element {
                        text: read.text.trim().to_owned(),
                        whole: read.start..position(&reader),
                        inner: read.inner..before,
                    };
                    place(&mut metadata, &read.path, element);
                }
                path.pop();
            }
            Event::Eof if path.is_empty() => return Ok(metadata),
            Event::Eof => return Err(format!("<{}> is not closed", path.join("><"))),
            _ => {}
        }
    }
}

/// Where the reader is in the document.
fn position(reader: &quick_xml::Reader<&[u8]>) -> usize {
    usize::try_from(reader.buffer_position()).expect("a document in memory fits a usize")
}

/// Whether the element at `path` is one whose text is read.
fn is_read(path: &[String]) -> bool {
    [GROUP, ARTIFACT, LATEST, RELEASE, VERSION]
        .iter()
        .any(|read| path == *read)
}

fn append(open: &mut Option<Open>, text: &str) {
    if let Some(open) = open {
        open.text.push_str(text);
    }
}

/// One of the five entities XML defines. Errors for any other, as no DTD defines more.
fn predefined(name: &str) -> Result<char, String> {
    match name {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        other => Err(format!("&{other}; is no entity XML defines")),
    }
}

/// Keep `element`, read at `path`. A second `<latest>`, `<release>` or coordinate is kept
/// in place of the first, as a reader that keeps the last one read sees it.
fn place(metadata: &mut Metadata, path: &[String], element: Element) {
    let slot = if path == GROUP {
        &mut metadata.group
    } else if path == ARTIFACT {
        &mut metadata.artifact
    } else if path == LATEST {
        &mut metadata.latest
    } else if path == RELEASE {
        &mut metadata.release
    } else {
        metadata.versions.push(element);
        return;
    };
    *slot = Some(element);
}

impl Metadata {
    /// Whether this is `key`'s: its `<groupId>` and `<artifactId>` are the key's, and it
    /// lists versions. A group's plugin prefixes and a snapshot's builds are neither.
    pub fn is_of(&self, key: &PackageKey) -> bool {
        let named = |element: &Option<Element>, expected: Option<&str>| {
            element.as_ref().map(|e| e.text.as_str()) == expected
        };
        self.has_versions
            && named(&self.group, key.namespace())
            && named(&self.artifact, Some(key.name()))
    }

    /// Each listed version as a record of `key`, its jar under `versions`.
    pub fn records(&self, key: &PackageKey, versions: &str) -> PackageMetadata {
        PackageMetadata {
            key: key.clone(),
            latest: self.release.as_ref().map(|e| e.text.clone()),
            records: self
                .versions
                .iter()
                .filter(|v| !v.text.is_empty())
                .map(|v| record(key, &v.text, None, versions))
                .collect(),
            skipped: Vec::new(),
        }
    }

    /// `decoded`, this document's bytes, without the versions in `refused`. A `<latest>` or
    /// `<release>` naming one names the highest version left, or is removed with none left.
    pub fn without(&self, decoded: &[u8], refused: &HashSet<String>) -> Vec<u8> {
        let kept: Vec<&str> = self
            .versions
            .iter()
            .map(|v| v.text.as_str())
            .filter(|v| !refused.contains(*v))
            .collect();
        let mut edits: Vec<(Range<usize>, String)> = self
            .versions
            .iter()
            .filter(|v| refused.contains(&v.text))
            .map(|v| (line(decoded, &v.whole), String::new()))
            .collect();
        let releases: Vec<&str> = kept
            .iter()
            .copied()
            .filter(|v| !v.ends_with("-SNAPSHOT"))
            .collect();
        for (element, candidates) in [(&self.latest, &kept), (&self.release, &releases)] {
            let Some(element) = element.as_ref().filter(|e| refused.contains(&e.text)) else {
                continue;
            };
            edits.push(match highest(candidates) {
                Some(highest) => (element.inner.clone(), escaped(highest)),
                None => (line(decoded, &element.whole), String::new()),
            });
        }
        edits.sort_by_key(|(range, _)| range.start);
        let mut out = Vec::with_capacity(decoded.len());
        let mut at = 0;
        for (range, replacement) in edits {
            out.extend_from_slice(&decoded[at..range.start]);
            out.extend_from_slice(replacement.as_bytes());
            at = range.end;
        }
        out.extend_from_slice(&decoded[at..]);
        out
    }
}

/// `whole` widened to its line, when nothing but spaces and tabs share the line with it.
fn line(decoded: &[u8], whole: &Range<usize>) -> Range<usize> {
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    let before = decoded[..whole.start]
        .iter()
        .rev()
        .take_while(|b| blank(b))
        .count();
    let start = whole.start - before;
    let after = decoded[whole.end..].iter().take_while(|b| blank(b)).count();
    let end = whole.end + after;
    let starts_line = start == 0 || decoded[start - 1] == b'\n';
    match decoded.get(end) {
        Some(b'\n') if starts_line => start..end + 1,
        _ => whole.clone(),
    }
}

/// The highest of `versions` in Maven's order, which [`std::iter::Iterator::max_by`] finds
/// without sorting: the order is not total.
fn highest<'a>(versions: &[&'a str]) -> Option<&'a str> {
    use crate::intel::comparable_version::Version;
    versions
        .iter()
        .copied()
        .max_by(|a, b| Version::parse(a).cmp(&Version::parse(b)))
}

/// `text` with `&`, `<` and `>` escaped, as element text.
fn escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// One version as the common record, published at `published_at`, its one file the jar.
pub fn record(
    key: &PackageKey,
    version: &str,
    published_at: Option<jiff::Timestamp>,
    versions: &str,
) -> PackageRecord {
    let jar = filename(key, version);
    PackageRecord {
        package: key
            .at_version(version)
            .expect("an empty version is not kept"),
        detail: DocumentDetail::Full,
        published_at,
        maintainers: None,
        repository: None,
        yanked: None,
        deprecated: None,
        has_install_scripts: false,
        install_scripts: None,
        provenance: Provenance::default(),
        direct_dependencies: Vec::new(),
        artifacts: vec![Artifact {
            filename: jar.clone(),
            runs_install_scripts: false,
            url: format!("{versions}{version}/{jar}"),
            integrity: None,
            yanked: None,
            legacy_sha1: None,
            attestation_url: None,
            file_count: None,
            unpacked_size: None,
        }],
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::identity::Ecosystem;

    const VERSIONS: &str = "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/";

    fn lang3() -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Maven, "org.apache.commons:commons-lang3")
            .unwrap()
    }

    fn refused(versions: &[&str]) -> HashSet<String> {
        versions.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn an_artifact_s_versions_are_its_records() {
        let fixture = super::super::fixture("commons-lang3.xml");
        let metadata = parse(&fixture).expect("parses");
        assert!(metadata.is_of(&lang3()));
        let records = metadata.records(&lang3(), VERSIONS);
        assert_eq!(records.records.len(), 27);
        assert_eq!(records.latest.as_deref(), Some("3.21.0"));
        let first = &records.records[0];
        assert_eq!(first.package.version(), "3.0");
        assert_eq!(first.artifacts[0].filename, "commons-lang3-3.0.jar");
        assert_eq!(
            first.artifacts[0].url,
            format!("{VERSIONS}3.0/commons-lang3-3.0.jar")
        );
        assert_eq!(metadata.without(&fixture, &HashSet::new()), fixture);
    }

    /// A group's file lists plugin prefixes, and a file naming another artifact is not
    /// this one's.
    #[test]
    fn a_file_with_no_versions_or_other_coordinates_is_not_the_artifact_s() {
        let plugins = parse(&super::super::fixture("plugins.xml")).expect("parses");
        let key =
            PackageKey::from_registry_name(Ecosystem::Maven, "org.apache.maven:plugins").unwrap();
        assert!(!plugins.is_of(&key));
        let other = parse(
            b"<metadata><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
              <versioning><versions><version>1.0</version></versions></versioning></metadata>",
        )
        .unwrap();
        assert!(!other.is_of(&lang3()));
        let empty = parse(
            b"<metadata><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>\
              <versioning><versions/></versioning></metadata>",
        )
        .unwrap();
        assert!(empty.is_of(&lang3()));
        assert!(empty.records(&lang3(), VERSIONS).records.is_empty());
    }

    /// Each refused version's line goes; `<latest>` and `<release>` naming the refused
    /// 3.21.0 name 3.20.0, the highest left.
    #[test]
    fn a_refused_version_s_line_is_removed_and_latest_moves_down() {
        let fixture = super::super::fixture("commons-lang3.xml");
        let metadata = parse(&fixture).unwrap();
        let filtered = metadata.without(&fixture, &refused(&["3.21.0", "3.0"]));
        let text = String::from_utf8(filtered.clone()).unwrap();
        assert!(!text.contains("<version>3.21.0</version>"), "{text}");
        assert!(!text.contains("<version>3.0</version>"), "{text}");
        assert!(text.contains("<latest>3.20.0</latest>"), "{text}");
        assert!(text.contains("<release>3.20.0</release>"), "{text}");
        let expected = String::from_utf8(fixture.clone())
            .unwrap()
            .replace("      <version>3.0</version>\n", "")
            .replace("      <version>3.21.0</version>\n", "")
            .replace("<latest>3.21.0</latest>", "<latest>3.20.0</latest>")
            .replace("<release>3.21.0</release>", "<release>3.20.0</release>");
        assert_eq!(text, expected);
        let again = parse(&filtered).unwrap();
        assert_eq!(again.versions.len(), 25);
        assert!(again.is_of(&lang3()));
    }

    #[test]
    fn with_every_version_refused_latest_and_release_are_removed() {
        let body = b"<metadata>\n  <versioning>\n    <latest>2.0</latest>\n    <release>1.0</release>\n    <versions>\n      <version>1.0</version>\n      <version>2.0</version>\n    </versions>\n  </versioning>\n</metadata>\n";
        let filtered = parse(body)
            .unwrap()
            .without(body, &refused(&["1.0", "2.0"]));
        assert_eq!(
            String::from_utf8(filtered).unwrap(),
            "<metadata>\n  <versioning>\n    <versions>\n    </versions>\n  </versioning>\n</metadata>\n"
        );
    }

    /// A release is no snapshot; latest may be one.
    #[test]
    fn release_skips_a_snapshot_and_latest_does_not() {
        let body = b"<metadata><versioning><latest>3.0</latest><release>3.0</release><versions><version>1.0</version><version>2.0-SNAPSHOT</version><version>3.0</version></versions></versioning></metadata>";
        let filtered = parse(body).unwrap().without(body, &refused(&["3.0"]));
        let text = String::from_utf8(filtered).unwrap();
        assert!(text.contains("<latest>2.0-SNAPSHOT</latest>"), "{text}");
        assert!(text.contains("<release>1.0</release>"), "{text}");
        assert!(!text.contains("<version>3.0</version>"), "{text}");
    }

    /// Text is read as mvn reads it: entities and CDATA resolved, comments skipped.
    #[test]
    fn a_version_written_with_entities_cdata_or_a_comment_is_read_as_its_text() {
        let body = b"<metadata><versioning><versions>\
            <version>1&#46;0</version><version><![CDATA[2.0]]></version>\
            <version>3<!-- x -->.0</version><version>a&amp;b</version><version> 5.0 </version>\
            </versions></versioning></metadata>";
        let metadata = parse(body).unwrap();
        let read: Vec<&str> = metadata.versions.iter().map(|v| v.text.as_str()).collect();
        assert_eq!(read, ["1.0", "2.0", "3.0", "a&b", "5.0"]);
        let filtered = metadata.without(body, &refused(&["2.0", "a&b"]));
        let again = parse(&filtered).unwrap();
        let left: Vec<&str> = again.versions.iter().map(|v| v.text.as_str()).collect();
        assert_eq!(left, ["1.0", "3.0", "5.0"]);
    }

    #[test]
    fn a_new_highest_is_escaped() {
        let body = b"<metadata><versioning><latest>2</latest><versions><version>1&lt;x</version><version>2</version></versions></versioning></metadata>";
        let filtered = parse(body).unwrap().without(body, &refused(&["2"]));
        assert!(
            String::from_utf8(filtered)
                .unwrap()
                .contains("<latest>1&lt;x</latest>")
        );
    }

    #[test]
    fn what_is_not_maven_metadata_does_not_read() {
        for (body, said) in [
            (&b"<metadata><versioning>"[..], "not closed"),
            (b"<metadata></versioning>", "mismatched"),
            (b"<a>&nbsp;</a>", "no entity"),
            (b"<a>&#0;</a>", "char"),
            (b"\xff", "utf-8"),
            (
                b"<metadata><versioning><versions><version><b/>1</version></versions></versioning></metadata>",
                "holds an element",
            ),
            (
                b"<metadata><versioning><versions><version><b>1</b></version></versions></versioning></metadata>",
                "holds an element",
            ),
        ] {
            assert!(parse(body).is_err(), "{said}");
        }
        assert!(
            parse(b"<metadata><versioning><versions><version><b>1</b></version></versions></versioning></metadata>")
                .unwrap_err()
                .contains("holds an element")
        );
        assert_eq!(predefined("quot"), Ok('"'));
        assert_eq!(predefined("apos"), Ok('\''));
        assert_eq!(predefined("gt"), Ok('>'));
    }

    /// A snapshot's file names its artifact and lists builds, not versions.
    #[test]
    fn a_file_naming_the_artifact_with_no_versions_is_not_its_metadata() {
        let snapshot = parse(
            b"<metadata><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>\
              <version>3.18.0-SNAPSHOT</version><versioning><snapshot><buildNumber>1</buildNumber>\
              </snapshot></versioning></metadata>",
        )
        .unwrap();
        assert!(!snapshot.has_versions);
        assert!(!snapshot.is_of(&lang3()));
    }

    /// A removed version takes its line when it is alone on it, trailing blanks included,
    /// and only itself when text shares the line.
    #[test]
    fn a_removed_version_takes_its_line_only_when_alone_on_it() {
        let alone = b"<metadata><versioning><versions>\n  <version>1</version>  \n  <version>2</version>\n</versions></versioning></metadata>";
        assert_eq!(
            String::from_utf8(parse(alone).unwrap().without(alone, &refused(&["1"]))).unwrap(),
            "<metadata><versioning><versions>\n  <version>2</version>\n</versions></versioning></metadata>"
        );
        let shared = b"<metadata><versioning><versions><version>1</version>\n<version>2</version>\n</versions></versioning></metadata>";
        assert_eq!(
            String::from_utf8(parse(shared).unwrap().without(shared, &refused(&["1"]))).unwrap(),
            "<metadata><versioning><versions>\n<version>2</version>\n</versions></versioning></metadata>"
        );
        let first = b"<version>1</version>\nrest";
        let whole = 0..b"<version>1</version>".len();
        assert_eq!(line(first, &whole), 0..whole.end + 1);
    }

    /// The last of two `<latest>` elements is the one kept, and a version on a line with
    /// others is removed alone.
    #[test]
    fn a_second_element_replaces_the_first_and_a_shared_line_keeps_the_rest() {
        let body = b"<metadata><groupId>a</groupId><groupId>b</groupId><versioning><versions> <version>1</version> <version>2</version>\n</versions></versioning></metadata>";
        let metadata = parse(body).unwrap();
        assert_eq!(metadata.group.as_ref().unwrap().text, "b");
        let filtered = metadata.without(body, &refused(&["1"]));
        assert_eq!(
            String::from_utf8(filtered).unwrap(),
            "<metadata><groupId>a</groupId><groupId>b</groupId><versioning><versions>  <version>2</version>\n</versions></versioning></metadata>"
        );
    }
}
