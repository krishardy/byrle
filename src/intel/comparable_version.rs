//! Maven versions, ordered as `ComparableVersion` in Maven 3.10.0 orders them. Any string
//! is one. The order is not total, as Maven's is not, so these are never given to std's
//! sorts, which may panic on such an order. See docs/maven-plan.md, step 3.

use std::cmp::Ordering;

/// Qualifiers in order, `""` a release; one not here is above them all, compared as text.
const QUALIFIERS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

/// Where `""`, a release, is in [`QUALIFIERS`].
const RELEASE: usize = 5;

/// The most digits Maven reads as a Java `int`; a narrower number is below a wider one.
const INT_DIGITS: usize = 9;
/// The most digits Maven reads as a Java `long`, above which it is a `BigInteger`.
const LONG_DIGITS: usize = 18;

#[derive(Debug, Clone)]
enum Item {
    Leaf(Leaf),
    List(Vec<Item>),
}

#[derive(Debug, Clone)]
enum Leaf {
    /// Its width, 0 for `int` to 2 for `BigInteger`, and its digits without leading zeros.
    Number(u8, String),
    /// A qualifier, after Maven's aliases.
    Text(String),
}

impl Leaf {
    /// Maven's `isNull`: zero, or a qualifier that is a release.
    fn is_null(&self) -> bool {
        match self {
            Self::Number(_, digits) => digits == "0",
            Self::Text(text) => text.is_empty(),
        }
    }
}

/// A Maven version, compared as Maven compares it.
#[derive(Debug, Clone)]
pub struct Version(Vec<Item>);

impl Version {
    pub fn parse(s: &str) -> Self {
        Self(Builder::default().parse(&s.to_lowercase()))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
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
        lists(&self.0, &other.0)
    }
}

/// A version's lists while it is read, a nested list named by its index here.
#[derive(Default)]
struct Builder {
    lists: Vec<Vec<Node>>,
}

enum Node {
    Leaf(Leaf),
    List(usize),
}

impl Builder {
    fn parse(mut self, version: &str) -> Vec<Item> {
        self.lists.push(Vec::new());
        let mut list = 0;
        let mut digits = false;
        let mut start = 0;
        for (i, c) in version.char_indices() {
            match c {
                '.' | '-' => {
                    let item = if i == start {
                        Leaf::Number(0, "0".to_owned())
                    } else {
                        item(digits, &version[start..i])
                    };
                    self.lists[list].push(Node::Leaf(item));
                    start = i + 1;
                    if c == '-' {
                        list = self.open(list);
                    }
                }
                '0'..='9' => {
                    if !digits && i > start {
                        if !self.lists[list].is_empty() {
                            list = self.open(list);
                        }
                        let text = qualifier(&version[start..i], true);
                        self.lists[list].push(Node::Leaf(text));
                        start = i;
                        list = self.open(list);
                    }
                    digits = true;
                }
                _ => {
                    if digits && i > start {
                        let number = item(true, &version[start..i]);
                        self.lists[list].push(Node::Leaf(number));
                        start = i;
                        list = self.open(list);
                    }
                    digits = false;
                }
            }
        }
        if !digits && !self.lists[list].is_empty() {
            list = self.open(list);
        }
        self.lists[list].push(Node::Leaf(item(digits, &version[start..])));
        for at in (0..self.lists.len()).rev() {
            self.normalise(at);
        }
        self.build(0)
    }

    /// A new list, appended to `list`.
    fn open(&mut self, list: usize) -> usize {
        self.lists.push(Vec::new());
        let new = self.lists.len() - 1;
        self.lists[list].push(Node::List(new));
        new
    }

    /// Maven's `normalize`: trailing null items removed, looking past a non-empty list.
    fn normalise(&mut self, at: usize) {
        let mut i = self.lists[at].len();
        while i > 0 {
            i -= 1;
            let empty = match &self.lists[at][i] {
                Node::Leaf(leaf) => leaf.is_null(),
                Node::List(inner) => self.lists[*inner].is_empty(),
            };
            if empty {
                self.lists[at].remove(i);
            } else if matches!(self.lists[at][i], Node::Leaf(_)) {
                break;
            }
        }
    }

    fn build(&mut self, at: usize) -> Vec<Item> {
        let nodes = std::mem::take(&mut self.lists[at]);
        nodes
            .into_iter()
            .map(|node| match node {
                Node::Leaf(leaf) => Item::Leaf(leaf),
                Node::List(inner) => Item::List(self.build(inner)),
            })
            .collect()
    }
}

/// Maven's `parseItem`: a number, or a qualifier not followed by a digit.
fn item(digits: bool, text: &str) -> Leaf {
    if !digits {
        return qualifier(text, false);
    }
    let stripped = text.trim_start_matches('0');
    let (written, value) = if stripped.is_empty() {
        (text, "0")
    } else {
        (stripped, stripped)
    };
    let width = match written.len() {
        n if n <= INT_DIGITS => 0,
        n if n <= LONG_DIGITS => 1,
        _ => 2,
    };
    Leaf::Number(width, value.to_owned())
}

/// Maven's `StringItem`, with its aliases: `a1` is `alpha-1`, `ga` a release, `cr` `rc`.
fn qualifier(text: &str, before_digit: bool) -> Leaf {
    let text = match text {
        "a" if before_digit => "alpha",
        "b" if before_digit => "beta",
        "m" if before_digit => "milestone",
        other => other,
    };
    let text = match text {
        "ga" | "final" | "release" => "",
        "cr" => "rc",
        other => other,
    };
    Leaf::Text(text.to_owned())
}

/// Maven's `comparableQualifier`: a known qualifier's index, or `7-` and an unknown one.
fn comparable(text: &str) -> String {
    QUALIFIERS
        .iter()
        .position(|q| *q == text)
        .map_or_else(|| format!("{}-{text}", QUALIFIERS.len()), |i| i.to_string())
}

/// Java's `String.compareTo`, which compares UTF-16 code units.
fn java_strings(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `item` against `other`, where `None` is the absence of an item, as Maven's
/// `compareTo(null)` is.
fn compare(item: &Item, other: Option<&Item>) -> Ordering {
    use Leaf::{Number, Text};
    match (item, other) {
        (Item::Leaf(Number(_, digits)), None) => {
            if digits == "0" {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        (Item::Leaf(Number(w, a)), Some(Item::Leaf(Number(v, b)))) => {
            w.cmp(v).then(a.len().cmp(&b.len())).then(a.cmp(b))
        }
        (Item::Leaf(Number(..)), Some(_)) => Ordering::Greater,
        (Item::Leaf(Text(text)), None) => java_strings(&comparable(text), &RELEASE.to_string()),
        (Item::Leaf(Text(a)), Some(Item::Leaf(Text(b)))) => {
            java_strings(&comparable(a), &comparable(b))
        }
        (Item::Leaf(Text(_)), Some(_)) => Ordering::Less,
        (Item::List(items), None) => items
            .iter()
            .map(|i| compare(i, None))
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal),
        (Item::List(_), Some(Item::Leaf(Number(..)))) => Ordering::Less,
        (Item::List(_), Some(Item::Leaf(Text(_)))) => Ordering::Greater,
        (Item::List(a), Some(Item::List(b))) => lists(a, b),
    }
}

/// Maven's comparison of two lists, item by item, the shorter one's missing items as
/// nothing.
fn lists(a: &[Item], b: &[Item]) -> Ordering {
    padded(a)
        .zip(padded(b))
        .take(a.len().max(b.len()))
        .map(|pair| match pair {
            (Some(l), r) => compare(l, r),
            (None, r) => r.map_or(Ordering::Equal, |r| compare(r, None).reverse()),
        })
        .find(|o| o.is_ne())
        .unwrap_or(Ordering::Equal)
}

/// `items`, then nothing without end.
fn padded(items: &[Item]) -> impl Iterator<Item = Option<&Item>> {
    items.iter().map(Some).chain(std::iter::repeat(None))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Whether each of `written` is below the next.
    fn ascending(written: &[&str]) {
        for pair in written.windows(2) {
            assert_eq!(
                cmp(pair[0], pair[1]),
                Ordering::Less,
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
    }

    fn cmp(a: &str, b: &str) -> Ordering {
        Version::parse(a).cmp(&Version::parse(b))
    }

    /// Each pair asserted here was compared by Maven 3.10.0's `ComparableVersion` too, and
    /// Maven gave the same answer.
    #[test]
    fn qualifiers_order_as_maven_orders_them() {
        let written = [
            "1-alpha2snapshot",
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ];
        ascending(&written);
    }

    #[test]
    fn numbers_order_as_maven_orders_them() {
        let written = [
            "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1",
            "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11",
            "11", "11.a", "11b", "11c", "11m",
        ];
        ascending(&written);
    }

    #[test]
    fn equal_spellings_are_equal() {
        for (a, b) in [
            ("1", "1.0.0"),
            ("1-ga", "1"),
            ("1.final", "1"),
            ("1-RELEASE", "1"),
            ("1-cr1", "1-rc1"),
            ("1a1", "1-alpha-1"),
            ("1.0.0-0.0.0", "1"),
            ("1-", "1"),
            ("1x", "1-x"),
            ("1.0001", "1.1"),
        ] {
            assert_eq!(cmp(a, b), Ordering::Equal, "{a} == {b}");
            assert_eq!(Version::parse(a), Version::parse(b));
        }
        assert_ne!(Version::parse("1"), Version::parse("1.1"));
    }

    /// A number Java reads as a `long` is above one it reads as an `int`, even a run of
    /// ten zeros, which Maven does not strip.
    #[test]
    fn a_wider_number_is_above_a_narrower_one_whatever_its_value() {
        assert_eq!(cmp("1.0000000000.1", "1.5"), Ordering::Greater);
        assert_eq!(
            cmp("1.0000000000000000000.1", "1.1234567890"),
            Ordering::Greater
        );
        assert_eq!(cmp("1.1234567890", "1.123456789"), Ordering::Greater);
        assert_eq!(
            cmp("1.1234567890123456789", "1.123456789012345678"),
            Ordering::Greater
        );
        assert_eq!(
            cmp("1.99999999999999999999", "1.10000000000000000000"),
            Ordering::Greater
        );
        assert_eq!(cmp("1.1000000000", "1.2000000000"), Ordering::Less);
    }

    #[test]
    fn an_unknown_qualifier_is_above_every_known_one_and_compared_as_text() {
        assert_eq!(cmp("1-xyz", "1-sp"), Ordering::Greater);
        assert_eq!(cmp("1-abc", "1-abd"), Ordering::Less);
        assert_eq!(cmp("1-abc", "1-abc"), Ordering::Equal);
    }

    #[test]
    fn a_trailing_list_is_compared_with_nothing_by_its_items() {
        assert_eq!(cmp("1-1", "1"), Ordering::Greater);
        assert_eq!(cmp("1", "1-1"), Ordering::Less);
        assert_eq!(cmp("1-alpha", "1"), Ordering::Less);
        assert_eq!(cmp("1-sp", "1"), Ordering::Greater);
        assert_eq!(cmp("1.1", "1-1"), Ordering::Greater);
        assert_eq!(cmp("1-1", "1.1"), Ordering::Less);
        assert_eq!(cmp("1-1", "1.sp.1"), Ordering::Greater);
        assert_eq!(cmp("1-sp", "1-1"), Ordering::Less);
        assert_eq!(cmp("1.sp", "1.1"), Ordering::Less);
        assert_eq!(cmp("1.sp", "1-1"), Ordering::Less);
        assert_eq!(cmp("1-1", "1.sp.1"), Ordering::Greater);
        assert!(Version::parse("1.0-alpha") < Version::parse("1.0.1"));
    }

    /// Text is compared as Java compares strings, by UTF-16 code unit: U+FF5E is above
    /// U+1F600 there, and below it by code point.
    #[test]
    fn text_is_compared_by_utf16_code_unit() {
        assert_eq!(cmp("1-\u{ff5e}", "1-\u{1f600}"), Ordering::Greater);
    }

    /// `pr1` is no qualifier Maven knows, so `2.10.0.pr1` is above `2.10.0`.
    #[test]
    fn spring_and_jackson_versions_order_as_maven_orders_them() {
        ascending(&[
            "6.2.0-RC1",
            "6.2.0",
            "6.2.19",
            "7.0.0-M1",
            "7.0.0",
            "7.0.8",
            "7.1.0-M2",
        ]);
        ascending(&[
            "2.9.10",
            "2.9.10.8",
            "2.10.0",
            "2.10.0.pr1",
            "2.17.0-rc1",
            "2.17.0",
        ]);
    }

    #[test]
    fn maven_s_order_has_a_cycle_and_it_is_kept() {
        let [a, b, c] = ["1.0-dev-2.20021231.045254", "1.0.0.beta.2", "1.0.0"];
        assert_eq!(cmp(a, b), Ordering::Less);
        assert_eq!(cmp(b, c), Ordering::Less);
        assert_eq!(cmp(c, a), Ordering::Less);
    }

    #[test]
    fn an_empty_version_is_below_every_other_and_equal_to_zero() {
        assert_eq!(cmp("", "0"), Ordering::Equal);
        assert_eq!(cmp("", "0.0.1"), Ordering::Less);
        assert_eq!(cmp("..", "0"), Ordering::Equal);
    }
}
