use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("direktori tidak ditemukan: {0}")]
    DirNotFound(PathBuf),
    #[error("{file}:{line}: {message}")]
    Config {
        file: PathBuf,
        line: usize,
        message: String,
    },
    #[error("id template ganda '{id}': {first} dan {second}")]
    DuplicateTemplate {
        id: String,
        first: PathBuf,
        second: PathBuf,
    },
    #[error("severity tidak dikenal '{0}' (info, low, medium, high, critical)")]
    UnknownSeverity(String),
}
