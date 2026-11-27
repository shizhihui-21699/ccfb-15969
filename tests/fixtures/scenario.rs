//! Real-world style scenarios combining both lints in one file.
#![allow(dead_code)]

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::{mem, ptr};

// ---------------------------------------------------------------------------
// Scenario 1: a "take/restore" helper that calls a user closure while the
// value is out of the slot — the exact bug pattern behind several historical
// Rust CVEs in vec/map implementations.
// ---------------------------------------------------------------------------

pub fn take_with<T, R>(slot: *mut T, f: impl FnOnce(T) -> R) -> R {
    unsafe {
        let value = ptr::read(slot);
        let result = f(value); // <-- closure owns the value; panic here double-frees
        // (a correct impl would ManuallyDrop or guard the slot)
        result
    }
}

// Correct version of the same helper.
pub fn take_with_correct<T, R>(slot: *mut T, f: impl FnOnce(T) -> R) -> R {
    unsafe {
        let value = mem::ManuallyDrop::new(ptr::read(slot));
        let result = f(ManuallyDrop::into_inner(value));
        // On unwind the ManuallyDrop already neutralized the local owner;
        // f's panic means the slot is logically consumed, matching e.g.
        // Vec::push-style ownership transfer semantics.
        mem::forget(result);
        result
    }
}

// ---------------------------------------------------------------------------
// Scenario 2: a raw-pointer container whose Send/Sync impls must bound T.
// ---------------------------------------------------------------------------

pub struct OwningPtr<T> {
    ptr: *const T,
    _marker: PhantomData<T>,
}

// BUG: no T: Send.
unsafe impl<T> Send for OwningPtr<T> {}
// BUG: no T: Sync.
unsafe impl<T> Sync for OwningPtr<T> {}

// A sound sibling used as the control.
pub struct BoundedPtr<T> {
    ptr: *const T,
    _marker: PhantomData<T>,
}
unsafe impl<T: Send> Send for BoundedPtr<T> {}
unsafe impl<T: Sync> Sync for BoundedPtr<T> {}

// Compile-time demonstration that the unsound impl really would let Rc
// cross threads (kept as a type-level assertion, not executed):
fn _assert_rc_is_send() {
    fn needs_send<T: Send>() {}
    needs_send::<OwningPtr<Rc<RefCell<u8>>>>();
}
