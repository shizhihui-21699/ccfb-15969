//! Integration tests driven by the fixture files under `tests/fixtures`.
//!
//! The tests assert the *contract* of the two lints rather than exact
//! counts of individual panic sites: every buggy function must be reported,
//! every sanctioned repair pattern must stay silent.

use std::path::{Path, PathBuf};

use unsafe_lint::model::{AnalysisConfig, SEND_SYNC_WITHOUT_BOUND, UNWIND_DOUBLE_FREE};
use unsafe_lint::{analyze_root, analyze_source, discover_panic_abort};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn analyze(rel: &str) -> Vec<unsafe_lint::model::Finding> {
    let path = fixtures().join(rel);
    let source = std::fs::read_to_string(&path).unwrap();
    let config = AnalysisConfig::default();
    analyze_source(&path, &source, &config)
}

#[test]
fn canonical_unwind_bugs_are_all_reported() {
    let findings = analyze("unwind/bugs.rs");
    let lines: Vec<usize> = findings
        .iter()
        .filter(|f| f.lint == UNWIND_DOUBLE_FREE)
        .map(|f| f.line)
        .collect();
    // One finding per buggy function (line 58 legitimately surfaces several
    // distinct panic sites inside one window).
    for expected_line in [15u32, 24, 40, 49, 58] {
        assert!(
            lines.contains(&(expected_line as usize)),
            "expected a finding at line {} of bugs.rs, got {:?}",
            expected_line,
            lines
        );
    }
    assert!(findings.iter().all(|f| f.lint == UNWIND_DOUBLE_FREE));
    assert!(findings.iter().all(|f| !f.trigger_path.is_empty()));
}

#[test]
fn sanctioned_repair_patterns_are_silent() {
    let findings = analyze("unwind/correct.rs");
    assert!(
        findings.is_empty(),
        "correct patterns must not be reported:\n{}",
        findings.iter().map(|f| f.render()).collect::<String>()
    );
}

#[test]
fn macro_definition_bodies_are_not_analyzed() {
    let findings = analyze("unwind/macros.rs");
    // The only legitimate finding belongs to `window_then_macro` (lines
    // 36-42): a user-written `println!` sits in a window opened by user
    // code. The macro definition itself never shows up.
    let lines: Vec<usize> = findings.iter().map(|f| f.line).collect();
    assert!(
        lines.iter().all(|l| (36..=42).contains(l)),
        "findings outside the user-code window: {:?}",
        lines
    );
}

#[test]
fn guard_macro_protects_open_windows() {
    let findings = analyze("unwind/macros.rs");
    // `guard_macro` occupies lines 45-53 and must have no finding.
    assert!(
        !findings.iter().any(|f| (45..=53).contains(&f.line)),
        "guard macro pattern reported: {:?}",
        findings.iter().map(|f| f.line).collect::<Vec<_>>()
    );
}

#[test]
fn missing_send_sync_bounds_are_reported() {
    let findings = analyze("sendsync/impls.rs");
    let bad: Vec<&str> = findings
        .iter()
        .filter(|f| f.lint == SEND_SYNC_WITHOUT_BOUND)
        .map(|f| f.message.as_str())
        .collect();
    assert_eq!(bad.len(), 2, "only Wrapper's Send and Sync impls are bugs");
    assert!(bad.iter().any(|m| m.contains("Send for Wrapper")));
    assert!(bad.iter().any(|m| m.contains("Sync for Wrapper")));
    // Every finding carries a three-step trigger path.
    assert!(findings.iter().all(|f| f.trigger_path.len() == 3));
}

#[test]
fn phantom_raw_pointer_params_need_no_bound() {
    let source = r#"
        use std::marker::PhantomData;
        pub struct Unused<T> { raw: *const u8, marker: PhantomData<*const T> }
        unsafe impl<T> Send for Unused<T> {}
        pub struct Plain<T>(*const u8, PhantomData<T>);
        unsafe impl<T> Send for Plain<T> {}
    "#;
    let findings = analyze_source(Path::new("inline.rs"), source, &AnalysisConfig::default());
    let messages: Vec<String> = findings.iter().map(|f| f.message.clone()).collect();
    assert!(
        !messages.iter().any(|m| m.contains("Unused")),
        "PhantomData<*const T> must not require a bound: {:?}",
        messages
    );
    assert!(
        messages.iter().any(|m| m.contains("Plain")),
        "plain PhantomData<T> must still require a bound: {:?}",
        messages
    );
}

#[test]
fn panic_abort_suppresses_unwind_family() {
    let root = fixtures().join("abort_crate");
    assert!(
        discover_panic_abort(&root),
        "fixture manifest must be detected as panic=abort"
    );
    let findings = analyze_root(&root);
    assert!(
        findings.is_empty(),
        "no findings allowed under panic=abort, got: {:?}",
        findings
    );
}

#[test]
fn normal_panic_strategy_keeps_the_lint_active() {
    let root = fixtures().join("unwind");
    assert!(!discover_panic_abort(&root));
    let findings = analyze_root(&root);
    assert!(!findings.is_empty());
}

#[test]
fn allow_attribute_silences_lints() {
    let source = r#"
        use std::ptr;
        struct S(String);
        pub fn a(slot: *mut S, cb: impl FnOnce()) {
            #[allow(unwind_double_free)]
            unsafe {
                let v = ptr::read(slot);
                cb();
                ptr::write(slot, v);
            }
        }
        struct W<T>(*const u8, std::marker::PhantomData<T>);
        #[allow(send_sync_without_bound)]
        unsafe impl<T> Send for W<T> {}
    "#;
    let findings = analyze_source(Path::new("allowed.rs"), source, &AnalysisConfig::default());
    assert!(
        findings.is_empty(),
        "expected no findings, got {:?}",
        findings
    );
}

#[test]
fn manually_drop_and_maybe_uninit_are_not_flagged() {
    let source = r#"
        use std::mem::{ManuallyDrop, MaybeUninit};
        use std::ptr;
        pub fn md(slot: *mut String, cb: impl FnOnce()) {
            unsafe {
                let v = ManuallyDrop::new(ptr::read(slot));
                cb();
                ptr::write(slot, ManuallyDrop::into_inner(v));
            }
        }
        pub fn mu(slot: *mut MaybeUninit<String>, cb: impl FnOnce()) {
            unsafe {
                let v = MaybeUninit::new(String::new());
                cb();
                slot.write(MaybeUninit::into_inner(v));
            }
        }
    "#;
    let findings = analyze_source(Path::new("wrappers.rs"), source, &AnalysisConfig::default());
    assert!(findings.is_empty(), "got {:?}", findings);
}

#[test]
fn unwind_edge_cases_are_handled() {
    let findings = analyze("unwind/edge.rs");
    let lines: Vec<usize> = findings.iter().map(|f| f.line).collect();
    // Nested windows both report (14), branch (26), volatile (38),
    // method read (47), loop assert (55), closure drop (68/70), index (79).
    for expected in [14usize, 26, 38, 47, 55, 68, 70, 79] {
        assert!(
            lines.contains(&expected),
            "missing expected finding at line {}, got {:?}",
            expected,
            lines
        );
    }
    // The method-call write-back (`p.write(v)`) must close the window rather
    // than be reported as panicking.
    assert!(
        !lines.contains(&48),
        "p.write(v) wrongly flagged: {:?}",
        lines
    );
    assert!(
        !lines.contains(&45),
        "block-end false positive: {:?}",
        lines
    );
}

#[test]
fn send_sync_edge_cases() {
    let findings = analyze("sendsync/edge.rs");
    let bad: Vec<String> = findings.iter().map(|f| f.message.clone()).collect();
    // Exactly the six unsound impls documented in the fixture.
    assert_eq!(bad.len(), 6, "unexpected findings: {:#?}", bad);
    assert!(bad.iter().any(|m| m.contains("Pair<B>")));
    assert!(bad.iter().any(|m| m.contains("Pair<A>")));
    assert!(bad.iter().any(|m| m.contains("Nested<T>")));
    assert!(bad.iter().any(|m| m.contains("BothPhantom<T>")));
    assert!(bad.iter().any(|m| m.contains("BothPhantom<U>")));
    assert!(bad.iter().any(|m| m.contains("EnumWrap<T>")));
    // The sound impls stay silent.
    assert!(!bad.iter().any(|m| m.contains("WithLifetime")));
    assert!(!bad.iter().any(|m| m.contains("BehindPtr")));
}

#[test]
fn combined_real_world_scenario() {
    let findings = analyze("scenario.rs");
    assert_eq!(findings.len(), 4, "{:#?}", findings);
    let lints: Vec<&str> = findings.iter().map(|f| f.lint.as_str()).collect();
    assert_eq!(
        lints.iter().filter(|l| **l == UNWIND_DOUBLE_FREE).count(),
        2
    );
    assert_eq!(
        lints
            .iter()
            .filter(|l| **l == SEND_SYNC_WITHOUT_BOUND)
            .count(),
        2
    );
    // The ManuallyDrop-based correct helper and the bounded pointer type
    // must stay silent.
    assert!(!findings
        .iter()
        .any(|f| f.message.contains("take_with_correct")));
    assert!(!findings.iter().any(|f| f.message.contains("BoundedPtr")));
}

#[test]
fn findings_are_serializable_as_json() {
    let findings = analyze("sendsync/impls.rs");
    let text = serde_json::to_string(&findings).unwrap();
    assert!(text.contains("send_sync_without_bound"));
    assert!(text.contains("trigger_path"));
}

#[test]
fn parse_errors_do_not_panic_the_checker() {
    let broken = "fn broken( {";
    let findings = analyze_source(Path::new("broken.rs"), broken, &AnalysisConfig::default());
    assert!(findings.is_empty());
}
