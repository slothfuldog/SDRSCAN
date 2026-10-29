#![allow(dead_code)]
use std::path::{Path, PathBuf};

use sdrscan_core::{load_templates, Template};

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn all_templates() -> Vec<Template> {
    load_templates(&root().join("templates/php")).expect("template bawaan harus valid")
}

pub fn template(id: &str) -> Template {
    all_templates()
        .into_iter()
        .find(|t| t.id == id)
        .unwrap_or_else(|| panic!("template {id} tidak ada"))
}

/// Salinan basis data fixture (`tests/fixtures/vulndb`) dengan `updated_at` = sekarang agar tidak dianggap usang.
pub fn fixture_db() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    copy_tree(&root().join("tests/fixtures/vulndb"), tmp.path());
    let meta_path = tmp.path().join("meta.json");
    let mut meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    let now = sdrscan_vulndb::time::now_rfc3339();
    meta["updated_at"] = serde_json::json!(now);
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
    tmp
}

pub fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}
