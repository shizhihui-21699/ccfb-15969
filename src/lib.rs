//! `unsafe_lint` — a small syntax-directed static checker for two classes
//! of Rust memory-safety defects:
//!
//! 1. [`unwind_double_free`]: duplicated ownership inside `unsafe` blocks
//!    that is dropped twice when an intervening call unwinds.
//! 2. [`send_sync_without_bound`]: `unsafe impl Send/Sync` on generic
//!    containers without bounds on their type parameters.
//!
//! Both checks operate on a parsed [`syn::File`] and a simplified
//! linear/recursive control-flow walk. They never require type inference.
//!
//! [`unwind_double_free`]: model/constant.UNWIND_DOUBLE_FREE.html
//! [`send_sync_without_bound`]: model/constant.SEND_SYNC_WITHOUT_BOUND.html

pub mod model;
pub mod panic_config;
pub mod send_sync;
pub mod unwind;
pub mod util;

use std::path::{Path, PathBuf};

use syn::File;

use crate::model::{AnalysisConfig, Finding};

/// Parse a single source file and run both checks.
///
/// `config.panic_aborts` suppresses the unwind family entirely; per-file
/// `#![allow(...)]` attributes are honored in addition to
/// [`AnalysisConfig::allowed`].
pub fn analyze_source(path: &Path, source: &str, config: &AnalysisConfig) -> Vec<Finding> {
    let parsed = syn::parse_file(source);
    let Ok(file) = parsed else {
        return Vec::new(); // parse errors are reported by rustc, not by us
    };

    let mut findings = Vec::new();
    let file_name = path.display().to_string();

    let unwind = unwind::UnwindChecker::new(file_name.clone(), config);
    findings.extend(unwind.analyze_file(&file));

    findings.extend(send_sync::check_file(&file, &file_name, config));

    findings.sort_by_key(|f| (f.line, f.column));
    findings
}

/// Walk a directory tree and return every `.rs` file below it.
pub fn collect_rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" || name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// Locate `Cargo.toml` below `root` and determine whether the dev profile
/// aborts on panic.
pub fn discover_panic_abort(root: &Path) -> bool {
    let manifest = root.join("Cargo.toml");
    if manifest.exists() {
        return panic_config::manifest_panics_abort(&manifest);
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir()
            && p.file_name().and_then(|n| n.to_str()) != Some("target")
            && discover_panic_abort(&p)
        {
            return true;
        }
    }
    false
}

/// Convenience: analyze a whole crate root (file or directory) honoring the
/// panic strategy discovered from its manifests.
pub fn analyze_root(root: &Path) -> Vec<Finding> {
    let panic_aborts = root.is_dir() && discover_panic_abort(root);
    let config = AnalysisConfig {
        panic_aborts,
        ..Default::default()
    };
    let files = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        collect_rust_files(root)
    };
    let mut all = Vec::new();
    for file in files {
        if let Ok(source) = std::fs::read_to_string(&file) {
            all.extend(analyze_source(&file, &source, &config));
        }
    }
    all.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    all
}

/// Parse-only helper exposed for tests.
pub fn parse(source: &str) -> Result<File, syn::Error> {
    syn::parse_file(source)
}
