//! Mesin SAST untuk PHP: penelusur file, parser tree-sitter, pencocok query, taint ringan.

pub mod sca;
mod scan;
mod suppress;
pub mod taint;

pub use scan::scan;

use std::path::PathBuf;

#[derive(Debug)]
pub enum SastError {
    TargetNotFound(PathBuf),
    /// Query tree-sitter atau capture taint pada template tidak valid.
    Template {
        id: String,
        message: String,
    },
    Walk(String),
}

impl std::fmt::Display for SastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SastError::TargetNotFound(p) => write!(f, "path target tidak ada: {}", p.display()),
            SastError::Template { id, message } => write!(f, "template '{id}': {message}"),
            SastError::Walk(m) => write!(f, "gagal menelusuri target: {m}"),
        }
    }
}

impl std::error::Error for SastError {}
