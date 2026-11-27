//! Fixture: macro-related cases.
//!
//! Macro *definitions* are never analyzed (their bodies are templates), and
//! code whose tokens originate from expansion carries a line-0 span that the
//! checker suppresses. In a source file the only macro surface we see is the
//! invocation, which is treated as an opaque potentially-panicking call.
#![allow(dead_code)]

use std::ptr;

struct Boxed {
    value: String,
}

/// A macro definition: its body must not be analyzed at all.
macro_rules! helper_that_contains_unsafe {
    ($slot:expr, $cb:expr) => {{
        let value = ptr::read($slot);
        $cb;
        ptr::write($slot, value);
    }};
}

/// Invoking the macro: the bug lives in expanded tokens (span line 0 when
/// fed through `cargo expand`), and the invocation itself is opaque. A
/// source-level invocation is still conservatively flagged when an interval
/// opened *outside* the macro is live, but this function opens none outside.
pub fn via_macro(slot: *mut Boxed, callback: impl FnOnce()) {
    unsafe {
        helper_that_contains_unsafe!(slot, callback());
    }
}

/// A window opened in user code, then a macro invocation inside it: the
/// invocation is treated as potentially unwinding and reported.
pub fn window_then_macro(slot: *mut Boxed) {
    unsafe {
        let value = ptr::read(slot);
        println!("working: {}", value.value.len());
        ptr::write(slot, value);
    }
}

/// Guard macro: `scopeguard`-style defer repairs the slot before unwinding.
pub fn guard_macro(slot: *mut Boxed, callback: impl FnOnce()) {
    unsafe {
        let value = ptr::read(slot);
        // Emulates `defer_on_unwind! { ptr::write(slot, value); }`.
        defer_on_unwind! { value, slot }
        callback();
        ptr::write(slot, value);
    }
}

macro_rules! defer_on_unwind {
    ($binding:ident, $slot:expr) => {{
        // Real scopeguard crates install a drop guard here; the lint treats
        // the macro name itself as establishing protection.
        let _g = ($binding, $slot);
    }};
}
