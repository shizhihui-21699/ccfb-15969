//! Fixture for the boundless `unsafe impl Send/Sync` check.
#![allow(dead_code)]

use std::marker::PhantomData;
use std::rc::Rc;

struct Wrapper<T> {
    raw: *const u8,
    marker: PhantomData<T>,
}

// BUG: T appears in the type but carries no Send bound.
unsafe impl<T> Send for Wrapper<T> {}

// BUG: same problem for Sync.
unsafe impl<T> Sync for Wrapper<T> {}

// OK: explicit inline bound.
struct Bounded<T>(*const u8, PhantomData<T>);
unsafe impl<T: Send> Send for Bounded<T> {}
unsafe impl<T: Sync> Sync for Bounded<T> {}

// OK: bound supplied through a where clause.
struct WhereBounded<T>(*const u8, PhantomData<T>);
unsafe impl<T> Send for WhereBounded<T>
where
    T: Send,
{
}
unsafe impl<T> Sync for WhereBounded<T>
where
    T: Sync,
{
}

// OK: no type parameters at all.
struct Raw(*const u8);
unsafe impl Send for Raw {}
unsafe impl Sync for Raw {}

// OK: T is not reachable from the implemented type.
struct Unused<T> {
    raw: *const u8,
    marker: PhantomData<*const T>,
}
unsafe impl<T> Send for Unused<T> {}

// Negative impls are fine and must be ignored.
struct ContainsRc(Rc<u8>);
impl !Send for ContainsRc {}

// #[allow] silences the lint.
struct Allowed<T>(*const u8, PhantomData<T>);
#[allow(send_sync_without_bound)]
unsafe impl<T> Send for Allowed<T> {}
