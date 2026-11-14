//! The top-level settings of two policies, compared key by key, whatever packages they are
//! decided over. `policy diff` reports each that moved, and `policy check` each looser than
//! its default. See docs/engineering_decisions/0132-settings-compared-directly.md.

use std::cmp::Ordering;

use super::strictness::{Direction, Strictness};
use super::{Action, Policy};

/// One setting the two policies give differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub key: String,
    pub from: String,
    pub to: String,
    pub strictness: Strictness,
}

/// Each setting `to` gives otherwise than `from`, in the order the policy reference lists
/// them, then each `signal_weights` key either sets otherwise.
///
/// A weight is compared as its share of `risk_threshold`, so a key weighing the threshold
/// by default moves with it and is not listed. A key neither sets is not listed.
pub fn compared(from: &Policy, to: &Policy) -> Vec<Setting> {
    let days = |key: &str, of: fn(&Policy) -> u32, direction: Direction| {
        let (before, after) = (of(from), of(to));
        setting(key, before, after, direction.strictness(after, before))
    };
    let action = |key: &str, of: fn(&Policy) -> Action| {
        let (before, after) = (of(from), of(to));
        setting(
            key,
            before.as_str(),
            after.as_str(),
            after.strictness_against(before),
        )
    };
    let cvss = setting(
        "max_cvss",
        from.max_cvss,
        to.max_cvss,
        match to.max_cvss.partial_cmp(&from.max_cvss) {
            Some(Ordering::Less) => Strictness::Stricter,
            Some(Ordering::Greater) => Strictness::Looser,
            _ => Strictness::Same,
        },
    );
    let mut settings = vec![
        days(
            "cooldown_days",
            |p| p.cooldown_days,
            Direction::HigherIsStricter,
        ),
        cvss,
        action("install_scripts", |p| p.install_scripts),
        action("kev", |p| p.kev),
        action("deprecated", |p| p.deprecated),
        action("yanked", |p| p.yanked),
        action("provenance", |p| p.provenance),
        days(
            "provenance_window_days",
            |p| p.provenance_window_days,
            Direction::HigherIsStricter,
        ),
        days(
            "provenance_half_life",
            |p| p.provenance_half_life,
            Direction::HigherIsStricter,
        ),
        days(
            "risk_threshold",
            |p| p.risk_threshold,
            Direction::LowerIsStricter,
        ),
    ];
    let keys: std::collections::BTreeSet<&str> = from
        .signal_weights
        .keys()
        .chain(to.signal_weights.keys())
        .collect();
    settings.extend(keys.into_iter().map(|key| weight(key, from, to)));
    settings.retain(|s| s.strictness != Strictness::Same);
    settings
}

/// `key`'s weight under each policy, as a share of its threshold.
fn weight(key: &str, from: &Policy, to: &Policy) -> Setting {
    let share = |p: &Policy| (u64::from(p.weight_of(key)), u64::from(p.risk_threshold));
    let ((before, of), (after, to_of)) = (share(from), share(to));
    let strictness = match (after * of).cmp(&(before * to_of)) {
        Ordering::Greater => Strictness::Stricter,
        Ordering::Less => Strictness::Looser,
        Ordering::Equal => Strictness::Same,
    };
    setting(
        &format!("signal_weights.{key}"),
        format!("{before} of {of}"),
        format!("{after} of {to_of}"),
        strictness,
    )
}

fn setting(key: &str, from: impl ToString, to: impl ToString, strictness: Strictness) -> Setting {
    Setting {
        key: key.to_owned(),
        from: from.to_string(),
        to: to.to_string(),
        strictness,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn policy(yaml: &str) -> Policy {
        Policy::parse(&format!("version: 1\n{yaml}")).expect("the policy parses")
    }

    fn moved(from: &str, to: &str) -> Vec<(String, String, String, Strictness)> {
        compared(&policy(from), &policy(to))
            .into_iter()
            .map(|s| (s.key, s.from, s.to, s.strictness))
            .collect()
    }

    fn row(key: &str, from: &str, to: &str, s: Strictness) -> (String, String, String, Strictness) {
        (key.to_owned(), from.to_owned(), to.to_owned(), s)
    }

    /// The review's case: `known_malware` weighed 0, which no package decides, is looser.
    #[test]
    fn a_weight_lowered_is_looser_and_raised_is_stricter() {
        assert_eq!(
            moved("", "signal_weights: { known_malware: 0 }\n"),
            [row(
                "signal_weights.known_malware",
                "100 of 100",
                "0 of 100",
                Strictness::Looser
            )]
        );
        assert_eq!(
            moved("signal_weights: { guarddog.error: 0 }\n", ""),
            [row(
                "signal_weights.guarddog.error",
                "0 of 100",
                "1 of 100",
                Strictness::Stricter
            )]
        );
        assert_eq!(
            moved("", "signal_weights: { new_package: 1 }\n"),
            [],
            "set to its default"
        );
    }

    /// A threshold raised is looser. A weight that is its default moves with it and is not
    /// listed; one set to the same number is a smaller share, so looser.
    #[test]
    fn a_weight_is_compared_as_its_share_of_the_threshold() {
        assert_eq!(
            moved("", "risk_threshold: 200\n"),
            [row("risk_threshold", "100", "200", Strictness::Looser)]
        );
        assert_eq!(
            moved(
                "signal_weights: { denied: 100 }\n",
                "risk_threshold: 200\nsignal_weights: { denied: 100 }\n"
            ),
            [
                row("risk_threshold", "100", "200", Strictness::Looser),
                row(
                    "signal_weights.denied",
                    "100 of 100",
                    "100 of 200",
                    Strictness::Looser
                ),
            ]
        );
        assert_eq!(
            moved(
                "signal_weights: { denied: 100 }\n",
                "risk_threshold: 50\nsignal_weights: { denied: 50 }\n"
            ),
            [row("risk_threshold", "100", "50", Strictness::Stricter)],
            "half of half is the same share"
        );
    }

    /// Each top-level setting, in the reference's order, each way it moves.
    #[test]
    fn each_top_level_setting_is_compared_in_its_own_direction() {
        let looser = "cooldown_days: 1\nmax_cvss: 9.5\ninstall_scripts: allow\nkev: allow\n\
                      yanked: allow\nprovenance: allow\nprovenance_window_days: 1\n\
                      provenance_half_life: 1\n";
        let rows = moved("deprecated: block\n", looser);
        assert_eq!(
            rows.iter()
                .map(|(key, _, _, s)| (key.as_str(), *s))
                .collect::<Vec<_>>(),
            [
                ("cooldown_days", Strictness::Looser),
                ("max_cvss", Strictness::Looser),
                ("install_scripts", Strictness::Looser),
                ("kev", Strictness::Looser),
                ("deprecated", Strictness::Looser),
                ("yanked", Strictness::Looser),
                ("provenance", Strictness::Looser),
                ("provenance_window_days", Strictness::Looser),
                ("provenance_half_life", Strictness::Looser),
            ]
        );
        assert_eq!(rows[1], row("max_cvss", "6.9", "9.5", Strictness::Looser));
        assert_eq!(rows[2].1, "block");
        assert!(
            moved(looser, "deprecated: block\n")
                .iter()
                .all(|(_, _, _, s)| *s == Strictness::Stricter)
        );
        assert_eq!(moved(looser, looser), []);
    }
}
