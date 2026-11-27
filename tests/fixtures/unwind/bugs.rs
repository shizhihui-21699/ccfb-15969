//! Fixture: classic unwind double-free bug patterns.
//! Every function here must produce exactly one `unwind_double_free` finding.
#![allow(dead_code)]

use std::ptr;

struct Boxed {
    value: String,
}

/// ptr::read -> user closure -> ptr::write: the canonical bug.
pub fn bug_read_then_callback(slot: *mut Boxed, callback: impl FnOnce()) {
    unsafe {
        let value = ptr::read(slot);
        callback();
        ptr::write(slot, value);
    }
}

/// Raw pointer dereference copy with an intervening generic method call.
pub fn bug_deref_copy<T, F: FnOnce(&T)>(p: *mut T, f: F) {
    unsafe {
        let local = *p;
        f(&local);
        ptr::write(p, local);
    }
}

/// Field copy through a raw pointer; an assert in the window.
pub fn bug_field_assert(p: *mut Boxed) {
    unsafe {
        let v = (*p).value;
        assert!(!v.is_empty());
        ptr::write(&mut (*p).value, v);
    }
}

/// The window is never repaired: double free at block end regardless of panic.
pub fn bug_no_writeback(p: *mut String) {
    unsafe {
        let _v = ptr::read(p);
    }
}

/// Explicit drop of the duplicated value while the slot stays initialized.
pub fn bug_explicit_drop(p: *mut String) {
    unsafe {
        let v = ptr::read(p);
        drop(v);
        ptr::write(p, String::new());
    }
}

/// Early return through `?` while the slot is still duplicated.
pub fn bug_question_mark(p: *mut String) -> Result<(), ()> {
    unsafe {
        let v = ptr::read(p);
        let _ = std::fs::read("x").map_err(|e| ())?;
        ptr::write(p, v);
    }
    Ok(())
}
