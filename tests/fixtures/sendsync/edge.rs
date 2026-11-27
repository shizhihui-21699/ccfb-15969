//! Send/Sync edge cases.
#![allow(dead_code)]

use std::marker::PhantomData;

// Two type parameters, only one bounded.
struct Pair<A, B>(*const u8, PhantomData<A>, PhantomData<B>);
unsafe impl<A: Send, B> Send for Pair<A, B> {} // B is missing the bound -> report
unsafe impl<A, B: Sync> Sync for Pair<A, B> {} // A is missing the bound -> report

// Lifetime and const parameters need no Send/Sync bound.
struct WithLifetime<'a, const N: usize, T>(*const u8, PhantomData<&'a T>);
unsafe impl<'a, const N: usize, T: Send> Send for WithLifetime<'a, N, T> {} // OK

// Nested generics: T reachable through Vec<T> requires the bound.
struct Nested<T>(*const u8, PhantomData<Vec<T>>);
unsafe impl<T> Send for Nested<T> {} // report

// T behind a raw pointer inside another generic is unreachable.
struct BehindPtr<T>(*const u8, PhantomData<*const Vec<T>>);
unsafe impl<T> Send for BehindPtr<T> {} // OK

// Multiple params where both appear in PhantomData<T>.
struct BothPhantom<T, U>(*const u8, PhantomData<T>, PhantomData<U>);
unsafe impl<T: Send, U: Send> Send for BothPhantom<T, U> {} // OK
unsafe impl<T, U> Sync for BothPhantom<T, U> {} // both missing -> two reports

// Enum support.
enum EnumWrap<T> {
    A(*const u8, PhantomData<T>),
    B { raw: *const u8, marker: PhantomData<T> },
}
unsafe impl<T> Send for EnumWrap<T> {} // report
