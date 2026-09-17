//! What can go wrong reading a simple index.

#[derive(Debug)]
pub enum PypiError {
    /// The body is not a PEP 691 document.
    NotJson(serde_json::Error),
    /// A name that normalises to nothing, so no index path can be built for it.
    UnusableName(String),
    /// The document lists no file this build can read.
    NothingReadable { name: String, files: usize },
}

impl std::fmt::Display for PypiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJson(e) => write!(f, "the index is not readable: {e}"),
            Self::UnusableName(name) => write!(f, "`{name}` is not a usable project name"),
            Self::NothingReadable { name, files } => write!(
                f,
                "the index for `{name}` lists {files} files and none is readable"
            ),
        }
    }
}

impl std::error::Error for PypiError {}
