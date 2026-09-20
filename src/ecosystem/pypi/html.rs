//! PEP 503's HTML simple index, read into the same [`Project`] PEP 691 JSON reads into.
//!
//! An index that serves only HTML is common: measured 2026-09-21, `download.pytorch.org`,
//! `pypi.nvidia.com`, `www.piwheels.org` and `data.pyg.org` answer `text/html` even when
//! asked for `application/vnd.pypi.simple.v1+json` and nothing else. Reading it is what
//! lets the policy filter those indexes and the rewrite point their files at the proxy.
//!
//! # What this reads, and what it does not
//!
//! A PEP 503 page is a flat list of anchors, and this reads exactly that: `<a href=...>`
//! elements with their attributes and their text. It is not an HTML parser. A page it
//! cannot read is an error rather than a page read as no files, so the proxy forwards it
//! and says `UNINSPECTED` instead of reporting a project with nothing in it.
//!
//! | Written as | Read as |
//! |---|---|
//! | `href` | the file's URL, resolved against the page's own URL: piwheels writes `/simple/idna/idna-3.20-py3-none-any.whl#sha256=...` |
//! | the fragment, `#sha256=<hex>` | the digest, the way PEP 503 carries one |
//! | the anchor's text | the filename |
//! | `data-yanked` | PEP 592: the reason, empty when the attribute has no value |
//! | `data-requires-python` | as written, with `&gt;` and friends turned back |
//! | `data-upload-time` | the publish time, which PEP 503 has no field for. `download.pytorch.org` writes it; PyPI's HTML does not |
//! | `data-provenance` | PEP 740: where the file's attestation bundle is |

use super::error::PypiError;
use super::paths::{filename_parts, normalise};
use super::wire::{File, Project};

/// Read a PEP 503 page.
///
/// `page` is the URL the body came from, which relative hrefs are resolved against, and
/// which the project's name is read from when `name` is empty: a PEP 503 page does not
/// name itself the way a PEP 691 document does, and the proxy reads a body without knowing
/// which project asked for it.
pub fn parse(name: &str, page: &str, bytes: &[u8]) -> Result<Project, PypiError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PypiError::NotHtml("not UTF-8"))?;
    let page = reqwest::Url::parse(page).map_err(|_| PypiError::NotHtml("the page has no URL"))?;
    let mut files = Vec::new();
    for anchor in anchors(text)? {
        let Some(href) = anchor.attribute("href") else {
            return Err(PypiError::NotHtml("an anchor with no href"));
        };
        let url = page
            .join(&href)
            .map_err(|_| PypiError::NotHtml("an href that is not a URL"))?;
        let filename = unescape(anchor.text.trim());
        let Some((_, version, kind)) = filename_parts(&filename) else {
            // An index lists eggs, installers and its own navigation. `wire::parse` skips
            // the same filenames rather than refusing the document.
            continue;
        };
        files.push(File {
            filename,
            version,
            kind,
            sha256: digest(url.fragment()),
            // The fragment is kept: pip checks the bytes it downloads against it, and
            // `origin::reachable_path` carries it through the rewrite.
            url: url.to_string(),
            upload_time: anchor.attribute("data-upload-time"),
            yanked: anchor.attribute("data-yanked"),
            requires_python: anchor.attribute("data-requires-python"),
            // PEP 740 writes it as an attribute here and as a key in the JSON form.
            provenance: anchor.attribute("data-provenance"),
        });
    }
    if files.is_empty() {
        return Err(PypiError::NotHtml("no distribution file on the page"));
    }
    let name = match normalise(name) {
        name if !name.is_empty() => name,
        // `/simple/idna/` is the project pip asked for. A page served from somewhere with
        // no name in its path leaves the filenames, which all carry one.
        _ => named_by(&page)
            .or_else(|| named_by_file(&files))
            .ok_or(PypiError::NotHtml(
                "a page with no project name in its URL or its filenames",
            ))?,
    };
    Ok(Project { name, files })
}

/// The project a page's URL names, which is its last path segment.
fn named_by(page: &reqwest::Url) -> Option<String> {
    let segment = page.path_segments()?.rfind(|s| !s.is_empty())?;
    Some(normalise(segment)).filter(|name| !name.is_empty())
}

/// The project its files name. Every distribution filename starts with it.
fn named_by_file(files: &[File]) -> Option<String> {
    let (name, _, _) = filename_parts(&files.first()?.filename)?;
    Some(normalise(&name)).filter(|name| !name.is_empty())
}

/// `#sha256=<hex>`, the only digest PEP 503 defines a place for.
fn digest(fragment: Option<&str>) -> Option<String> {
    let hex = fragment?.strip_prefix("sha256=")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| hex.to_owned())
}

/// One `<a>` element: where it is on the page, its attributes as written, and its text.
struct Anchor<'a> {
    /// Where `<a` starts, and where the element ends: after `</a>`, and after the `<br>`
    /// an index writes between entries, so removing one leaves no orphan separator.
    start: usize,
    end: usize,
    attributes: Vec<(String, Option<String>)>,
    text: &'a str,
}

/// Where one file's anchor is on the page, for [`super::rewrite`] to cut out.
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub filename: String,
}

/// Every anchor's span and filename, read from the same scan [`parse`] uses.
pub fn anchor_spans(text: &str) -> Result<Vec<Span>, PypiError> {
    Ok(anchors(text)?
        .into_iter()
        .map(|anchor| Span {
            start: anchor.start,
            end: anchor.end,
            filename: unescape(anchor.text.trim()),
        })
        .collect())
}

impl Anchor<'_> {
    /// An attribute's value, with entities turned back. A valueless attribute, which is
    /// how `data-yanked` says "yanked, no reason", reads as an empty string.
    fn attribute(&self, name: &str) -> Option<String> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| unescape(value.as_deref().unwrap_or("")))
    }
}

/// Every anchor on the page, in the order it is written.
///
/// An element this cannot read ends the whole document: half a list of files is a list
/// with files missing, and a missing file reads as a version the index does not have.
fn anchors(text: &str) -> Result<Vec<Anchor<'_>>, PypiError> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = find_anchor(&text[from..]).map(|at| from + at) {
        let after_tag = at + 2;
        let Some(tag_end) = text[after_tag..].find('>').map(|end| after_tag + end) else {
            return Err(PypiError::NotHtml("an anchor tag that never closes"));
        };
        let attributes = attributes(&text[after_tag..tag_end])?;
        let body = tag_end + 1;
        let Some(close) = text[body..].find("</a").map(|at| body + at) else {
            return Err(PypiError::NotHtml("an anchor that is never closed"));
        };
        let Some(closed) = text[close..].find('>').map(|end| close + end + 1) else {
            return Err(PypiError::NotHtml("a closing tag that never closes"));
        };
        out.push(Anchor {
            start: at,
            end: closed + separator(&text[closed..]),
            attributes,
            text: &text[body..close],
        });
        from = closed;
    }
    Ok(out)
}

/// How much of what follows an anchor belongs to it: the `<br>` an index writes between
/// entries, and the line break after it.
fn separator(text: &str) -> usize {
    let mut taken = 0;
    for tag in ["<br/>", "<br />", "<br>"] {
        if text.starts_with(tag) {
            taken = tag.len();
            break;
        }
    }
    taken + text[taken..].len() - text[taken..].trim_start_matches('\n').len()
}

/// Where the next `<a` tag starts, which is `<a` followed by a space or a `>`.
fn find_anchor(text: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(at) = text[from..].find("<a") {
        let at = from + at;
        match text[at + 2..].chars().next() {
            Some(c) if c.is_whitespace() || c == '>' => return Some(at),
            // `<abbr>`, `<address>`: a tag whose name starts with an a.
            Some(_) => from = at + 2,
            None => return None,
        }
    }
    None
}

/// The attributes written inside one tag.
fn attributes(text: &str) -> Result<Vec<(String, Option<String>)>, PypiError> {
    let mut out = Vec::new();
    let mut rest = text.trim_end_matches('/').trim();
    while !rest.is_empty() {
        let name_end = rest
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(rest.len());
        let name = rest[..name_end].to_ascii_lowercase();
        rest = rest[name_end..].trim_start();
        let value = match rest.strip_prefix('=') {
            None => None,
            Some(after) => {
                let after = after.trim_start();
                let quote = after
                    .chars()
                    .next()
                    .filter(|c| *c == '"' || *c == '\'')
                    .ok_or(PypiError::NotHtml("an unquoted attribute value"))?;
                let after = &after[1..];
                let end = after
                    .find(quote)
                    .ok_or(PypiError::NotHtml("an attribute value that never closes"))?;
                rest = after[end + 1..].trim_start();
                Some(after[..end].to_owned())
            }
        };
        if !name.is_empty() {
            out.push((name, value));
        }
    }
    Ok(out)
}

/// The five entities an index writes. `data-requires-python="&gt;=3.9"` is piwheels.
fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::super::wire::Kind;
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pypi/");
        std::fs::read(format!("{dir}{name}")).expect("fixture is missing")
    }

    /// piwheels, read 2026-09-21: relative hrefs, the digest in the fragment, and
    /// `data-requires-python` with an entity in it.
    #[test]
    fn a_relative_href_is_resolved_against_the_page_it_was_written_on() {
        let project = parse(
            "idna",
            "https://www.piwheels.org/simple/idna/",
            &fixture("piwheels-idna.html"),
        )
        .expect("the page reads");
        let file = &project.files[0];
        assert_eq!(file.filename, "idna-3.20-py3-none-any.whl");
        assert_eq!(file.version, "3.20");
        assert_eq!(file.kind, Kind::Wheel);
        assert_eq!(
            file.url,
            "https://www.piwheels.org/simple/idna/idna-3.20-py3-none-any.whl\
             #sha256=ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c"
        );
        assert_eq!(
            file.sha256.as_deref(),
            Some("ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c")
        );
        assert_eq!(file.requires_python.as_deref(), Some(">=3.9"));
        assert_eq!(file.upload_time, None, "PEP 503 has no field for it");
        assert_eq!(file.yanked, None);
    }

    /// pytorch, read 2026-09-21: absolute hrefs on another origin, and a
    /// `data-upload-time` that PEP 503 does not define but this index writes.
    #[test]
    fn an_absolute_href_and_an_upload_time_are_read_as_written() {
        let project = parse(
            "torch",
            "https://download.pytorch.org/whl/torch/",
            &fixture("pytorch-torch.html"),
        )
        .expect("the page reads");
        assert_eq!(project.files.len(), 3);
        let file = &project.files[0];
        assert!(
            file.url
                .starts_with("https://download-r2.pytorch.org/whl/cpu/torch-0.3.0.post4"),
            "{}",
            file.url
        );
        assert_eq!(file.upload_time.as_deref(), Some("2023-10-05T23:52:11Z"));
    }

    /// The proxy reads a forwarded body without knowing which project was asked for, and a
    /// PEP 503 page does not name itself. The page's own URL names it.
    #[test]
    fn a_page_that_does_not_name_itself_is_named_by_its_url() {
        let project = parse(
            "",
            "https://www.piwheels.org/simple/idna/",
            &fixture("piwheels-idna.html"),
        )
        .expect("the page reads");
        assert_eq!(project.name, "idna");

        // A page whose URL has no name in it: every filename carries one.
        let page = r#"<a href="a-1.0.tar.gz">a-1.0.tar.gz</a>"#;
        let project = parse("", "https://example.test/", page.as_bytes()).expect("reads");
        assert_eq!(project.name, "a");
    }

    /// PEP 592 in HTML: the reason is the attribute's value, and a valueless attribute is
    /// a yank with no reason.
    #[test]
    fn data_yanked_is_read_with_and_without_a_reason() {
        let page = r#"<a href="a-1.0.tar.gz" data-yanked="broken sdist">a-1.0.tar.gz</a>
                      <a href="a-2.0.tar.gz" data-yanked>a-2.0.tar.gz</a>
                      <a href="a-3.0.tar.gz">a-3.0.tar.gz</a>"#;
        let project = parse("a", "https://example.test/simple/a/", page.as_bytes()).expect("reads");
        let yanked: Vec<Option<&str>> = project.files.iter().map(|f| f.yanked.as_deref()).collect();
        assert_eq!(yanked, [Some("broken sdist"), Some(""), None]);
    }

    /// A page this cannot read is an error, not a project with no files: an empty project
    /// reads as a package the index does not have.
    #[test]
    fn a_page_that_cannot_be_read_is_an_error() {
        for (label, page) in [
            ("no files", "<html><body><h1>Links</h1></body></html>"),
            (
                "an anchor that never closes",
                r#"<a href="a-1.0.tar.gz">a-1.0"#,
            ),
            ("a tag that never closes", r#"<a href="a-1.0.tar.gz""#),
            (
                "an unquoted value",
                r#"<a href=a-1.0.tar.gz>a-1.0.tar.gz</a>"#,
            ),
            (
                "a value that never closes",
                r#"<a href="a-1.0.tar.gz>a-1.0.tar.gz</a>"#,
            ),
        ] {
            assert!(
                parse("a", "https://example.test/simple/a/", page.as_bytes()).is_err(),
                "{label}"
            );
        }
    }

    /// Anything that is not a distribution filename is skipped, the way `wire::parse`
    /// skips an egg. An index's own navigation links are that.
    #[test]
    fn a_link_that_is_not_a_distribution_is_skipped() {
        let page = r#"<a href="../">..</a>
                      <a href="a-1.0.tar.gz">a-1.0.tar.gz</a>
                      <abbr title="x">not an anchor</abbr>"#;
        let project = parse("a", "https://example.test/simple/a/", page.as_bytes()).expect("reads");
        assert_eq!(project.files.len(), 1);
        assert_eq!(project.files[0].filename, "a-1.0.tar.gz");
    }
}
