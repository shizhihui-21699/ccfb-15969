//! Fixture: correct patterns that must NOT be reported.
#![allow(dead_code)]

use std::mem::{ManuallyDrop, MaybeUninit};
use std::ptr;

struct Boxed {
    value: String,
}

/// A repair guard: its Drop impl writes the duplicated value back.
struct RepairGuard<T> {
    slot: *mut T,
    value: Option<T>,
}

impl<T> Drop for RepairGuard<T> {
    fn drop(&mut self) {
        if let Some(v) = self.value.take() {
            unsafe { ptr::write(self.slot, v) };
        }
    }
}

/// The guard repairs the slot on unwind: no double free.
pub fn ok_guard_pattern(slot: *mut Boxed, callback: impl FnOnce()) {
    unsafe {
        let value = ptr::read(slot);
        let _guard = RepairGuard {
            slot,
            value: Some(value),
        };
        callback();
    }
}

/// ManuallyDrop suppresses the local destructor: nothing frees twice.
pub fn ok_manually_drop(slot: *mut String, callback: impl FnOnce()) {
    unsafe {
        let value = ManuallyDrop::new(ptr::read(slot));
        callback();
        ptr::write(slot, ManuallyDrop::into_inner(value));
    }
}

/// Explicit ManuallyDrop-typed binding.
pub fn ok_manually_drop_typed(slot: *mut String, callback: impl FnOnce()) {
    unsafe {
        let value: ManuallyDrop<String> = ManuallyDrop::new(ptr::read(slot));
        callback();
        let _ = &value;
        ptr::write(slot, ManuallyDrop::into_inner(value));
    }
}

/// MaybeUninit write path: the destination was never initialized, so a copy
/// out does not duplicate a live owner.
pub fn ok_maybe_uninit(slot: *mut MaybeUninit<String>, callback: impl FnOnce()) {
    unsafe {
        let value = MaybeUninit::new(String::from("x"));
        callback();
        slot.write(MaybeUninit::into_inner(value));
    }
}

/// mem::forget consumes the duplicated owner before any panic.
pub fn ok_forget(slot: *mut String, callback: impl FnOnce()) {
    unsafe {
        let value = ptr::read(slot);
        mem::forget(value);
        callback();
    }
}

/// ptr::replace performs the move and the write atomically, without unwind.
pub fn ok_ptr_replace(slot: *mut String, new: String) {
    unsafe {
        let _old = ptr::replace(slot, new);
    }
}

/// Non-panicking pointer primitives between read and write are fine.
pub fn ok_whitelisted_calls(slot: *mut String, other: *const String) {
    unsafe {
        let value = ptr::read(slot);
        let copied = ptr::read(other);
        ptr::copy_nonoverlapping(other, slot, 1);
        // `other`'s slot is repaired by the copy above (`slot` is a distinct
        // destination; the whitelisted primitives between read and write do
        // not unwind), and both windows get explicit write-backs below.
        ptr::write(other as *mut String, copied);
        ptr::write(slot, value);
    }
}

/// Explicit allow attribute silences the lint.
pub fn allowed_by_attribute(slot: *mut Boxed, callback: impl FnOnce()) {
    #[allow(unwind_double_free)]
    unsafe {
        let value = ptr::read(slot);
        callback();
        ptr::write(slot, value);
    }
}
