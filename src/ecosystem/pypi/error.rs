//! What can go wrong reading a simple index.

#[derive(Debug)]
pub enum PypiError {
    /// The body is not a PEP 691 document.
    NotJson(serde_json::Error),
    /// A name that normalises to nothing, so no index path can be built for it.
    UnusableName(String),
    /// The document lists no file this build can read.
    NothingReadable { name: String, files: usize },
    /// The body is not a PEP 503 page this build can read, and why.
    NotHtml(&'static str),
}

impl std::fmt::Display for PypiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJson(e) => write!(f, "the index is not readable: {e}"),
            Self::UnusableName(name) => write!(f, "`{name}` is not a usable project name"),
            Self::NotHtml(why) => write!(f, "the HTML index is not readable: {why}"),
            Self::NothingReadable { name, files } => write!(
                f,
                "the index for `{name}` lists {files} files and none is readable"
            ),
        }
    }
}

impl std::error::Error for PypiError {}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn a_json_error_says_the_index_is_not_readable() {
        let e = PypiError::NotJson(serde_json::from_str::<()>("{").unwrap_err());
        assert!(
            e.to_string().starts_with("the index is not readable: "),
            "{e}"
        );
    }
}
