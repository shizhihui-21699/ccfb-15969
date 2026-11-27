//! Discovery of the crate's panic strategy.
//!
//! Under `panic = "abort"` a panicking call terminates the process without
//! unwinding, so a duplicated ownership slot can never run its destructor
//! twice: the unwind double-free family is impossible and must not be
//! reported.
//!
//! The strategy is read from `Cargo.toml`. `cargo check`/`cargo test` use the
//! `dev` profile by default, so a `panic = "abort"` in `[profile.dev]` is the
//! signal we honor; release-only abort settings are documented as a known
//! limitation in the README.

use std::path::Path;

/// Inspect a `Cargo.toml` and return true when the development profile is
/// configured with `panic = "abort"`.
pub fn manifest_panics_abort(manifest_path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(manifest_path) else {
        return false;
    };
    let Ok(value) = text.parse::<toml::Value>() else {
        return false;
    };
    let Some(profiles) = value.get("profile") else {
        return false;
    };
    profile_panics_abort(profiles, "dev")
}

fn profile_panics_abort(profiles: &toml::Value, name: &str) -> bool {
    profiles
        .get(name)
        .and_then(|p| p.get("panic"))
        .and_then(|v| v.as_str())
        .map(|v| v == "abort")
        .unwrap_or(false)
}
