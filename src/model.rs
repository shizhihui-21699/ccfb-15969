//! Shared data model for diagnostics produced by the checker.

use serde::Serialize;

/// Lint identifier for the unwind double-free family.
pub const UNWIND_DOUBLE_FREE: &str = "unwind_double_free";
/// Lint identifier for unsafe `Send`/`Sync` impls missing generic bounds.
pub const SEND_SYNC_WITHOUT_BOUND: &str = "send_sync_without_bound";

/// A single diagnostic.
///
/// The `trigger_path` is a human-readable chain describing how the reported
/// state is reached: which statement opened the duplicated-ownership window,
/// and which expression (or block exit) can trigger the unwind / why the
/// `Send`/`Sync` impl is unsound.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable lint name.
    pub lint: String,
    /// Source file the diagnostic refers to.
    pub file: String,
    /// 1-based line of the primary span.
    pub line: usize,
    /// 1-based column of the primary span.
    pub column: usize,
    /// Short headline.
    pub message: String,
    /// Ordered list describing the trigger path.
    pub trigger_path: Vec<String>,
}

impl Finding {
    pub fn new(
        lint: &str,
        file: &str,
        span: proc_macro2::Span,
        message: impl Into<String>,
        trigger_path: Vec<String>,
    ) -> Self {
        let start = span.start();
        Finding {
            lint: lint.to_string(),
            file: file.to_string(),
            line: start.line,
            column: start.column + 1,
            message: message.into(),
            trigger_path,
        }
    }

    /// Render the diagnostic the way the CLI prints it.
    pub fn render(&self) -> String {
        let mut out = format!(
            "{}:{}:{}: {} [{}]\n",
            self.file, self.line, self.column, self.message, self.lint
        );
        for (i, step) in self.trigger_path.iter().enumerate() {
            let mark = if i + 1 == self.trigger_path.len() {
                "=>"
            } else {
                "->"
            };
            out.push_str(&format!("  {} {}\n", mark, step));
        }
        out
    }
}

/// Per-file analysis configuration.
#[derive(Debug, Clone, Default)]
pub struct AnalysisConfig {
    /// When true, unwinding is impossible (`panic = "abort"`), so the
    /// double-free family is suppressed.
    pub panic_aborts: bool,
    /// Lints explicitly disabled by `#[allow(...)]` / `#![allow(...)]`.
    pub allowed: Vec<String>,
}

impl AnalysisConfig {
    pub fn allows(&self, lint: &str) -> bool {
        self.allowed
            .iter()
            .any(|name| name == lint || name == "warnings")
    }
}
