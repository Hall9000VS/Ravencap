use thiserror::Error;

pub type Result<T> = std::result::Result<T, RustyArchiveError>;

#[derive(Debug, Error)]
pub enum RustyArchiveError {
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    #[error("invalid archive path: {0}")]
    InvalidPath(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("age error: {0}")]
    Age(String),

    #[error("format error: {0}")]
    Format(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
