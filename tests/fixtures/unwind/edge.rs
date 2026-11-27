//! Edge-case probes used interactively during development.
#![allow(dead_code)]

use std::ptr;

struct S(String);

/// Nested windows over two distinct slots.
pub fn nested_windows(a: *mut S, b: *mut S, cb: impl FnOnce()) {
    unsafe {
        let x = ptr::read(a);
        {
            let y = ptr::read(b);
            cb();
            ptr::write(b, y);
        }
        ptr::write(a, x);
    }
}

/// Window opened then closed inside an `if` branch.
pub fn repaired_in_branch(p: *mut S, flag: bool, cb: impl FnOnce()) {
    unsafe {
        let v = ptr::read(p);
        if flag {
            cb();
            ptr::write(p, v);
        } else {
            ptr::write(p, v);
        }
    }
}

/// Volatile read variant.
pub fn volatile(p: *mut S, cb: impl FnOnce()) {
    unsafe {
        let v = ptr::read_volatile(p);
        cb();
        ptr::write_volatile(p, v);
    }
}

/// Method-call form of raw pointer read.
pub fn method_read(p: *mut S, cb: impl FnOnce()) {
    unsafe {
        let v = p.read();
        cb();
        p.write(v);
    }
}

/// Loop body: a panic on any iteration while the window is open.
pub fn in_loop(p: *mut S, n: usize) {
    unsafe {
        let v = ptr::read(p);
        for i in 0..n {
            assert!(i < 100);
        }
        ptr::write(p, v);
    }
}

/// Closure that consumes the duplicated value by move; slot still duplicated.
pub fn moved_into_closure(p: *mut S) {
    unsafe {
        let v = ptr::read(p);
        let f = || {
            drop(v);
        };
        f();
        ptr::write(p, S(String::new()));
    }
}

/// Indexing panic inside the window.
pub fn indexing(p: *mut Vec<u8>) {
    unsafe {
        let v = ptr::read(p);
        let _ = v[1000];
        ptr::write(p, v);
    }
}
