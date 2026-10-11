//! The source comparison read as a detector built in: the rules a stored comparison of an
//! artifact with its source fires. The comparison itself runs in the analyser, keyed by the
//! artifact's digest. See docs/engineering_decisions/source-diff.md.

use super::{Detecting, Detection, Detector, Finding};
use crate::analysis::source::{COMPARER, Sourced};

/// Its name, which its rules are not prefixed with in `signal_weights`.
pub const NAME: &str = "source";

/// Every rule it reports, in the order it reports them.
pub const RULES: [&str; 4] = [
    "source_install_scripts",
    "source_dependencies",
    "source_install_files",
    "source_differing",
];

/// The source comparison's findings.
#[derive(Debug, Clone, Copy, Default)]
pub struct Source;

impl Detector<Sourced> for Source {
    fn name(&self) -> &str {
        NAME
    }

    /// The comparer's, which keys each stored comparison.
    fn version(&self) -> &str {
        COMPARER
    }

    /// Answers on the first poll: see [`super::at_once`].
    fn detect<'a>(&'a self, sourced: &'a Sourced) -> Detecting<'a> {
        Box::pin(std::future::ready(Ok(detection(sourced))))
    }
}

/// The rules `sourced` fires: install scripts, dependencies and install files the source
/// lacks, and files that differ. Optional dependencies, Markdown and files only in the
/// package are kept by the store and fire none: see source-diff.md. Nothing compared fires
/// nothing.
fn detection(sourced: &Sourced) -> Detection {
    let Sourced::Compared {
        repository,
        reference,
        comparison,
    } = sourced
    else {
        return Detection::default();
    };
    let at = format!("{repository}@{reference}");
    let files: Vec<String> = comparison
        .lifecycle_files
        .iter()
        .map(|(_, file)| file.clone())
        .collect();
    let lacks = |names: &[String], otherwise: &str| {
        (!names.is_empty()).then(|| format!("{at} lacks{otherwise}: {}", names.join(", ")))
    };
    let differing = comparison
        .differing
        .first()
        .map(|first| match comparison.differing.len() {
            1 => format!("1 file differs from {at}: `{first}`"),
            count => format!("{count} files differ from {at}, first `{first}`"),
        });
    let findings = [
        lacks(&comparison.lifecycle_scripts, " or has otherwise"),
        lacks(&comparison.dependencies, ""),
        lacks(&files, " or has otherwise"),
        differing,
    ]
    .into_iter()
    .zip(RULES)
    .filter_map(|(detail, rule)| {
        Some(Finding {
            rule: rule.to_owned(),
            detail: detail?,
        })
    })
    .collect();
    Detection {
        findings,
        errors: Vec::new(),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::detector::at_once;
    use crate::analysis::source::Comparison;

    fn compared(comparison: Comparison) -> Sourced {
        Sourced::Compared {
            repository: "o/r".to_owned(),
            reference: "v1".to_owned(),
            comparison: Box::new(comparison),
        }
    }

    /// Each finding, as `rule: detail`.
    fn fired(sourced: &Sourced) -> Vec<String> {
        at_once(Source.detect(sourced))
            .expect("it answers at once")
            .expect("it runs")
            .findings
            .iter()
            .map(|finding| format!("{}: {}", finding.rule, finding.detail))
            .collect()
    }

    /// Install scripts, dependencies, install files and differing files each fire a rule.
    /// Optional dependencies, Markdown, files only in the package and no comparison do not.
    #[test]
    fn a_comparison_with_the_source_fires_its_rules() {
        let sourced = compared(Comparison {
            manifests: true,
            lifecycle_scripts: vec!["postinstall".to_owned()],
            dependencies: vec!["a".to_owned(), "b".to_owned()],
            optional_dependencies: vec!["c".to_owned()],
            lifecycle_files: vec![("postinstall".to_owned(), "x.js".to_owned())],
            lifecycle_targets: 1,
            differing: vec!["x.js".to_owned(), "y.js".to_owned()],
            differing_markdown: vec!["README.md".to_owned()],
            only_in_package: vec!["dist/x.js".to_owned()],
            same: 3,
        });
        assert_eq!(
            fired(&sourced),
            [
                "source_install_scripts: o/r@v1 lacks or has otherwise: postinstall",
                "source_dependencies: o/r@v1 lacks: a, b",
                "source_install_files: o/r@v1 lacks or has otherwise: x.js",
                "source_differing: 2 files differ from o/r@v1, first `x.js`",
            ]
        );
        let quiet = compared(Comparison {
            optional_dependencies: vec!["c".to_owned()],
            differing_markdown: vec!["README.md".to_owned()],
            only_in_package: vec!["dist/x.js".to_owned()],
            ..Comparison::default()
        });
        assert_eq!(fired(&quiet), Vec::<String>::new());
        let one = compared(Comparison {
            differing: vec!["x.js".to_owned()],
            ..Comparison::default()
        });
        assert_eq!(
            fired(&one),
            ["source_differing: 1 file differs from o/r@v1: `x.js`"]
        );
        assert_eq!(
            fired(&Sourced::NotCompared("why".to_owned())),
            Vec::<String>::new()
        );
        assert_eq!((Source.name(), Source.version()), (NAME, COMPARER));
    }
}
