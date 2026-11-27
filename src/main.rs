//! Command-line entry point:
//!
//! ```text
//! unsafe-lint [--json] [--allow LINT]... <PATH>...
//! ```
//!
//! Each path may be a single `.rs` file or a crate directory (walked
//! recursively, skipping `target/` and hidden directories).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use unsafe_lint::model::{AnalysisConfig, Finding};
use unsafe_lint::{analyze_source, collect_rust_files, discover_panic_abort};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut json = false;
    let mut allowed: Vec<String> = Vec::new();
    let mut paths: Vec<PathBuf> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--allow" => {
                i += 1;
                if i < args.len() {
                    allowed.push(args[i].clone());
                }
            }
            "--help" | "-h" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other if other.starts_with("--allow=") => {
                allowed.push(other["--allow=".len()..].to_string());
            }
            other => paths.push(PathBuf::from(other)),
        }
        i += 1;
    }

    if paths.is_empty() {
        eprintln!("error: at least one file or directory path is required");
        print_help();
        return ExitCode::from(2);
    }

    // A directory root with `panic = "abort"` suppresses the unwind family
    // for every file below it.
    let mut findings: Vec<Finding> = Vec::new();
    for root in &paths {
        let panic_aborts = root.is_dir() && discover_panic_abort(root);
        let config = AnalysisConfig {
            panic_aborts,
            allowed: allowed.clone(),
        };
        let files = expand(root);
        for file in files {
            let source = match std::fs::read_to_string(&file) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("warning: cannot read {}: {}", file.display(), err);
                    continue;
                }
            };
            findings.extend(analyze_source(&file, &source, &config));
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });

    if json {
        match serde_json::to_string_pretty(&findings) {
            Ok(text) => println!("{}", text),
            Err(err) => {
                eprintln!("error: failed to serialize findings: {}", err);
                return ExitCode::from(2);
            }
        }
    } else {
        for f in &findings {
            print!("{}", f.render());
        }
        eprintln!(
            "{} finding(s) across {} path(s)",
            findings.len(),
            paths.len()
        );
    }

    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn expand(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        collect_rust_files(root)
    }
}

fn print_help() {
    eprintln!(
        "unsafe-lint — static checker for unwind double-free and boundless unsafe Send/Sync impls\n\n\
         USAGE:\n    \
         unsafe-lint [--json] [--allow <LINT>]... <PATH>...\n\n\
         LINTS:\n    \
         unwind_double_free       ownership copied out via raw pointers with an\n    \
                                  unwinding call before the write-back\n    \
         send_sync_without_bound  unsafe impl Send/Sync missing T: Send/T: Sync\n\n\
         SUPPRESSIONS:\n    \
         - #[allow(unwind_double_free)] / #[allow(send_sync_without_bound)]\n    \
         - ManuallyDrop / MaybeUninit wrappers and repair-guard Drop impls\n    \
         - panic = \"abort\" in [profile.dev] of Cargo.toml\n    \
         - spans originating from macro expansion are never reported"
    );
}
