//! Fixture: under `panic = "abort"` unwinding is impossible, so even the
//! canonical bug pattern must not be reported.
#![allow(dead_code)]

use std::ptr;

struct Boxed {
    value: String,
}

pub fn bug_but_aborting(slot: *mut Boxed, callback: impl FnOnce()) {
    unsafe {
        let value = ptr::read(slot);
        callback();
        ptr::write(slot, value);
    }
}
