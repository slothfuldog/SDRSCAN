//! Model dan utilitas yang dipakai bersama semua mesin (SAST sekarang, DAST kelak):
//! temuan, template, profil, SARIF, dan laporan.

pub mod error;
pub mod finding;
pub mod profile;
pub mod report;
pub mod sarif;
pub mod template;

pub use error::CoreError;
pub use finding::{
    base_evidence, Cvss, Finding, Location, ScanOutput, Severity, VulnTarget, Vulnerability,
    Warning, WarningKind, MULTI_PAGE_MARKER,
};
pub use profile::Profile;
pub use template::{load_templates, TaintRequire, TaintSpec, Template, TemplateType};
