//! PEP 440 versions: what a PyPI version is, and how two of them order.
//!
//! Written here rather than taken from a crate. The rules are the "Version scheme" section of
//! PEP 440 as the `packaging` library implements them, which is what pip resolves with.
//! `examples/pep440_conformance.rs` compares this module with `packaging` over every version
//! OSV lists for PyPI.
//!
//! | Written | Normalised | Why |
//! |---|---|---|
//! | `V1.0` | `1.0` | case and a leading `v` are ignored |
//! | `1.0-1` | `1.0.post1` | a number after `-` is a post-release |
//! | `1.0alpha2`, `1.0-a.2` | `1.0a2` | alternative spellings and separators |
//! | `1.0c1`, `1.0pre1` | `1.0rc1` | |
//! | `1.0.dev` | `1.0.dev0` | a missing number is 0 |
//! | `1.0+Ubuntu-1` | `1.0+ubuntu.1` | local segments are joined with `.` |
//!
//! Order, lowest first, for one release: `1.0.dev0`, `1.0a1.dev0`, `1.0a1`, `1.0rc1`, `1.0`,
//! `1.0+local`, `1.0.post1.dev0`, `1.0.post1`. `1.0` and `1.0.0` are equal.

use std::cmp::Ordering;
use std::fmt;

/// A pre-release phase, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Alpha,
    Beta,
    ReleaseCandidate,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "a",
            Self::Beta => "b",
            Self::ReleaseCandidate => "rc",
        }
    }
}

/// Spellings PEP 440 accepts for each phase. A longer spelling is listed before the shorter
/// one it starts with, so `alpha` is not read as `a` followed by `lpha`.
const PHASES: &[(&str, Phase)] = &[
    ("alpha", Phase::Alpha),
    ("a", Phase::Alpha),
    ("beta", Phase::Beta),
    ("b", Phase::Beta),
    ("preview", Phase::ReleaseCandidate),
    ("pre", Phase::ReleaseCandidate),
    ("rc", Phase::ReleaseCandidate),
    ("c", Phase::ReleaseCandidate),
];

const POST: &[&str] = &["post", "rev", "r"];

/// One part of a local version. A number orders above any text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Local {
    Text(String),
    Number(u64),
}

/// Where the pre-release part puts a version among its release's versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PreKey {
    /// A development release of the final release, such as `1.0.dev0`, orders below every
    /// pre-release of it.
    DevOfFinal,
    Pre(Phase, u64),
    Final,
}

/// Where the development part puts a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DevKey {
    Dev(u64),
    NotDev,
}

/// What two versions are compared by, most significant first. The derived order compares the
/// fields in the order they are declared.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Key<'a> {
    epoch: u64,
    /// Without trailing zeros, so `1.0` and `1.0.0` are equal.
    release: &'a [u64],
    pre: PreKey,
    post: Option<u64>,
    dev: DevKey,
    local: Option<&'a [Local]>,
}

/// A PEP 440 version.
#[derive(Debug, Clone)]
pub struct Version {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(Phase, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Option<Vec<Local>>,
}

impl Version {
    /// Read a version, or `None` when it is not a PEP 440 version.
    pub fn parse(s: &str) -> Option<Self> {
        Reader::new(s).version()
    }

    fn key(&self) -> Key<'_> {
        let significant = self
            .release
            .iter()
            .rposition(|&n| n != 0)
            .map_or(0, |last| last + 1);
        let pre = match (self.pre, self.post, self.dev) {
            (Some((phase, n)), _, _) => PreKey::Pre(phase, n),
            (None, None, Some(_)) => PreKey::DevOfFinal,
            (None, _, _) => PreKey::Final,
        };
        Key {
            epoch: self.epoch,
            release: &self.release[..significant],
            pre,
            post: self.post,
            dev: self.dev.map_or(DevKey::NotDev, DevKey::Dev),
            local: self.local.as_deref(),
        }
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

/// The normalised form.
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        if self.epoch != 0 {
            out.push_str(&format!("{}!", self.epoch));
        }
        let release: Vec<String> = self.release.iter().map(u64::to_string).collect();
        out.push_str(&release.join("."));
        if let Some((phase, n)) = self.pre {
            out.push_str(&format!("{}{n}", phase.as_str()));
        }
        if let Some(n) = self.post {
            out.push_str(&format!(".post{n}"));
        }
        if let Some(n) = self.dev {
            out.push_str(&format!(".dev{n}"));
        }
        if let Some(local) = &self.local {
            let parts: Vec<String> = local
                .iter()
                .map(|part| match part {
                    Local::Text(text) => text.clone(),
                    Local::Number(n) => n.to_string(),
                })
                .collect();
            out.push_str(&format!("+{}", parts.join(".")));
        }
        f.write_str(&out)
    }
}

/// A cursor over a lowercased version string. It only moves over ASCII bytes, so every
/// slice of `text` it takes is on a character boundary.
struct Reader {
    text: String,
    at: usize,
}

impl Reader {
    fn new(s: &str) -> Self {
        Self {
            text: s.trim().to_ascii_lowercase(),
            at: 0,
        }
    }

    fn version(mut self) -> Option<Version> {
        self.eat("v");
        let start = self.at;
        let epoch = match self.number() {
            Some(n) if self.eat("!") => n,
            _ => {
                self.at = start;
                0
            }
        };
        let mut release = vec![self.number()?];
        loop {
            let before = self.at;
            if !self.eat(".") {
                break;
            }
            match self.number() {
                Some(n) => release.push(n),
                None => {
                    self.at = before;
                    break;
                }
            }
        }
        let pre = self.pre();
        let post = self.post();
        let dev = self.labelled(&["dev"]).map(|(_, n)| n);
        let local = if self.eat("+") {
            Some(self.local()?)
        } else {
            None
        };
        (self.at == self.text.len()).then_some(Version {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    fn pre(&mut self) -> Option<(Phase, u64)> {
        let labels: Vec<&str> = PHASES.iter().map(|(label, _)| *label).collect();
        let (label, n) = self.labelled(&labels)?;
        PHASES
            .iter()
            .find(|(written, _)| *written == label)
            .map(|(_, phase)| (*phase, n))
    }

    /// `-N`, or a post label with an optional number.
    fn post(&mut self) -> Option<u64> {
        let start = self.at;
        if self.eat("-")
            && let Some(n) = self.number()
        {
            return Some(n);
        }
        self.at = start;
        self.labelled(POST).map(|(_, n)| n)
    }

    /// An optional separator, one of `labels`, then an optional separator and number. A
    /// missing number is 0, and a separator with no number after it is consumed, as
    /// `packaging` reads `1.0a.` as `1.0a0`. Nothing is consumed when no label follows.
    fn labelled(&mut self, labels: &[&'static str]) -> Option<(&'static str, u64)> {
        let start = self.at;
        self.separator();
        let Some(label) = labels
            .iter()
            .copied()
            .find(|label| self.text[self.at..].starts_with(label))
        else {
            self.at = start;
            return None;
        };
        self.at += label.len();
        self.separator();
        Some((label, self.number().unwrap_or(0)))
    }

    /// Letters and digits in parts joined by `.`, `-` or `_`.
    fn local(&mut self) -> Option<Vec<Local>> {
        let mut parts = Vec::new();
        loop {
            let start = self.at;
            while self
                .text
                .as_bytes()
                .get(self.at)
                .is_some_and(u8::is_ascii_alphanumeric)
            {
                self.at += 1;
            }
            let part = &self.text[start..self.at];
            if part.is_empty() {
                return None;
            }
            // `part` is letters and digits only, so it parses when every one is a digit.
            parts.push(match part.parse::<u64>() {
                Ok(n) => Local::Number(n),
                Err(_) => Local::Text(part.to_owned()),
            });
            if !self.separator() {
                return Some(parts);
            }
        }
    }

    fn separator(&mut self) -> bool {
        let found = matches!(self.text.as_bytes().get(self.at), Some(b'.' | b'-' | b'_'));
        if found {
            self.at += 1;
        }
        found
    }

    fn eat(&mut self, expected: &str) -> bool {
        let found = self.text[self.at..].starts_with(expected);
        if found {
            self.at += expected.len();
        }
        found
    }

    /// Digits, as a number. `None` when there are none, or they do not fit in a `u64`.
    fn number(&mut self) -> Option<u64> {
        let start = self.at;
        while self
            .text
            .as_bytes()
            .get(self.at)
            .is_some_and(u8::is_ascii_digit)
        {
            self.at += 1;
        }
        match self.text[start..self.at].parse() {
            Ok(n) => Some(n),
            Err(_) => {
                self.at = start;
                None
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("`{s}` is a PEP 440 version"))
    }

    #[test]
    fn each_spelling_normalises_as_packaging_does() {
        for (written, normalised) in [
            ("1.0", "1.0"),
            ("V1.0", "1.0"),
            ("  1.0\n", "1.0"),
            ("1!2.0", "1!2.0"),
            ("0!2.0", "2.0"),
            ("1.0a1", "1.0a1"),
            ("1.0alpha1", "1.0a1"),
            ("1.0-A.2", "1.0a2"),
            ("1.0_beta_3", "1.0b3"),
            ("1.0c1", "1.0rc1"),
            ("1.0pre1", "1.0rc1"),
            ("1.0preview1", "1.0rc1"),
            ("1.0rc", "1.0rc0"),
            ("1.0-1", "1.0.post1"),
            ("1.0.post", "1.0.post0"),
            ("1.0-r2", "1.0.post2"),
            ("1.0rev3", "1.0.post3"),
            ("1.0.dev", "1.0.dev0"),
            ("1.0-dev4", "1.0.dev4"),
            ("1.0a1.post2.dev3", "1.0a1.post2.dev3"),
            ("1.0+Ubuntu-1", "1.0+ubuntu.1"),
            ("1.0+abc_def.2", "1.0+abc.def.2"),
            ("2.6.11-1", "2.6.11.post1"),
            ("1.0a.post1", "1.0a0.post1"),
            ("1.0-a-", "1.0a0"),
            ("1.0.post.", "1.0.post0"),
            ("1.0a1-1", "1.0a1.post1"),
            ("1.0-1.dev2", "1.0.post1.dev2"),
            ("01.02", "1.2"),
            ("1.0-0", "1.0.post0"),
        ] {
            assert_eq!(v(written).to_string(), normalised, "{written}");
        }
    }

    #[test]
    fn what_is_not_a_version_is_refused() {
        for written in [
            "",
            "v",
            "abc",
            "1.0.",
            "1..0",
            "1.0+",
            "1.0+a..b",
            "1.0+a-",
            "1.0 1",
            "1.0-",
            "1.0.",
            "1.0-1-",
            "1!",
            "!1.0",
            "1.0post1rc1",
            // `packaging` reads any size of number. This reads up to `u64::MAX`, and no
            // version OSV lists for PyPI is larger.
            "18446744073709551616",
            "1.0+ü",
        ] {
            assert!(Version::parse(written).is_none(), "`{written}` parsed");
        }
    }

    /// The order `packaging` gives, lowest first.
    #[test]
    fn versions_order_as_packaging_orders_them() {
        let ordered = [
            "1.0.dev0",
            "1.0a1.dev0",
            "1.0a1",
            "1.0a1.post1.dev0",
            "1.0a1.post1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0+abc",
            "1.0+abc.1",
            "1.0+1",
            "1.0+2",
            "1.0.post1.dev0",
            "1.0.post1",
            "1.0.1",
            "1.1.dev0",
            "2.0",
            "1!0.1",
        ];
        for pair in ordered.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
            assert!(v(pair[1]) > v(pair[0]), "{} > {}", pair[1], pair[0]);
        }
    }

    #[test]
    fn trailing_zeros_in_the_release_do_not_change_the_version() {
        assert_eq!(v("1.0"), v("1.0.0"));
        assert_eq!(v("1"), v("1.0.0.0"));
        assert_eq!(v("1.0").partial_cmp(&v("1.0.0")), Some(Ordering::Equal));
        assert_ne!(v("1.0"), v("1.0.1"));
        assert_eq!(v("0"), v("0.0"));
    }
}
