//! Check 2: `unsafe impl Send/Sync` for generic types without the matching
//! trait bounds on their type parameters.
//!
//! ```ignore
//! struct Wrapper<T>(*const T);
//!
//! unsafe impl<T> Send for Wrapper<T> {} // WRONG: T is not required to be Send
//! unsafe impl<T: Send> Sync for Wrapper<T> {} // OK
//! ```
//!
//! The check is purely syntactic:
//!
//! 1. Take every negative-free `unsafe impl` of exactly `Send` or `Sync`.
//! 2. For every generic *type* parameter that appears in the implemented
//!    type's arguments, require an explicit `T: Send` / `T: Sync` bound (or a
//!    lifetime/const parameter, which need no such bound).
//! 3. Bounds written on `where` clauses count; `?Sized` does not.

use std::collections::{HashMap, HashSet};

use syn::spanned::Spanned;
use syn::{
    AngleBracketedGenericArguments, Field, Fields, File, GenericArgument, Generics, Item, ItemImpl,
    Path, PathArguments, Type, TypeParam, TypePath,
};

use crate::model::{AnalysisConfig, Finding, SEND_SYNC_WITHOUT_BOUND};
use crate::util::{path_string, span_from_expansion, type_generic_args};

/// For each named type, the set of its declared type parameters that are
/// unreachable behind raw pointers / `PhantomData<*const T>` in *every*
/// field.
type ReachabilityMap = HashMap<String, HashSet<String>>;

pub fn check_file(file: &File, name: &str, config: &AnalysisConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    let file_allows = crate::unwind::collect_file_allows(file);
    if file_allows.contains(SEND_SYNC_WITHOUT_BOUND) || config.allows(SEND_SYNC_WITHOUT_BOUND) {
        return findings;
    }

    let reachability = build_reachability_map(file);

    for item in &file.items {
        if let Item::Impl(it) = item {
            check_impl(it, name, &reachability, &mut findings);
        }
    }
    findings
}

/// Walk every struct/enum definition and record which of its type
/// parameters occur only behind raw pointers or `PhantomData<*const T>`.
fn build_reachability_map(file: &File) -> ReachabilityMap {
    let mut map = ReachabilityMap::new();
    for item in &file.items {
        match item {
            Item::Struct(s) => {
                let params: HashSet<String> = s
                    .generics
                    .params
                    .iter()
                    .filter_map(|p| match p {
                        syn::GenericParam::Type(tp) => Some(tp.ident.to_string()),
                        _ => None,
                    })
                    .collect();
                if params.is_empty() {
                    continue;
                }
                let mut unreachable = params.clone();
                for field in fields_of_struct(&s.fields) {
                    let mut reachable_here = HashSet::new();
                    collect_reachable(&field.ty, &mut reachable_here);
                    unreachable.retain(|p| !reachable_here.contains(p));
                }
                map.insert(s.ident.to_string(), unreachable);
            }
            Item::Enum(e) => {
                let params: HashSet<String> = e
                    .generics
                    .params
                    .iter()
                    .filter_map(|p| match p {
                        syn::GenericParam::Type(tp) => Some(tp.ident.to_string()),
                        _ => None,
                    })
                    .collect();
                if params.is_empty() {
                    continue;
                }
                let mut unreachable = params.clone();
                for variant in &e.variants {
                    for field in fields_of_struct(&variant.fields) {
                        let mut reachable_here = HashSet::new();
                        collect_reachable(&field.ty, &mut reachable_here);
                        unreachable.retain(|p| !reachable_here.contains(p));
                    }
                }
                map.insert(e.ident.to_string(), unreachable);
            }
            _ => {}
        }
    }
    map
}

fn fields_of_struct(fields: &Fields) -> Vec<&Field> {
    match fields {
        Fields::Named(n) => n.named.iter().collect(),
        Fields::Unnamed(u) => u.unnamed.iter().collect(),
        Fields::Unit => Vec::new(),
    }
}

fn check_impl(
    it: &ItemImpl,
    file: &str,
    reachability: &ReachabilityMap,
    findings: &mut Vec<Finding>,
) {
    // Only `unsafe impl`, positive polarity, of Send/Sync.
    if it.unsafety.is_none() {
        return;
    }
    let Some((_, trait_path, _)) = &it.trait_ else {
        return;
    };
    let trait_name = match path_string(trait_path).as_str() {
        n if n.ends_with("Send") && !n.ends_with("msgtrace") => "Send",
        n if n.ends_with("Sync") => "Sync",
        _ => return,
    };
    // Reject anything with a trailing segment that isn't exactly Send/Sync.
    let last = trait_path
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default();
    if last != "Send" && last != "Sync" {
        return;
    }

    let allows = collect_allows(&it.attrs);
    if allows.contains(SEND_SYNC_WITHOUT_BOUND) {
        return;
    }

    // Generic parameters declared on the impl.
    let declared: Vec<&TypeParam> = it
        .generics
        .params
        .iter()
        .filter_map(|p| match p {
            syn::GenericParam::Type(tp) => Some(tp),
            _ => None,
        })
        .collect();
    if declared.is_empty() {
        return;
    }

    // Type parameters that appear in the implemented type at all.
    let syntactically_used = used_type_params(&it.self_ty);
    if syntactically_used.is_empty() {
        return;
    }

    // Refine using the target type's field definitions: parameters that are
    // reachable only through raw pointers / phantom raw pointers name no
    // owned value and need no bound.
    let base_name = self_type_base_name(&it.self_ty);
    let field_unreachable = reachability.get(&base_name).cloned().unwrap_or_default();
    let used: HashSet<String> = syntactically_used
        .difference(&field_unreachable)
        .cloned()
        .collect();
    if used.is_empty() {
        return;
    }

    let satisfied = satisfied_params(&it.generics, trait_name);

    for tp in declared {
        if !used.contains(&tp.ident.to_string()) {
            // Phantom/unused parameter: no value of that type can ever be
            // reached, so no bound is required.
            continue;
        }
        if satisfied.contains(&tp.ident.to_string()) {
            continue;
        }
        if span_from_expansion(tp.span()) {
            continue;
        }
        let message = format!(
            "`unsafe impl {} for {}<{}>` does not bound `{}` with `{}`, so the impl can be instantiated with non-thread-safe types",
            trait_name,
            self_type_base_name(&it.self_ty),
            tp.ident,
            tp.ident,
            trait_name
        );
        let trigger_path = vec![
            format!(
                "impl block declares generic parameter `{}` without a `{}: {}` bound",
                tp.ident, tp.ident, trait_name
            ),
            format!(
                "`{}` appears in the implemented type `{}` and its fields can be reached through the raw pointer",
                tp.ident,
                quote_type(&it.self_ty)
            ),
            format!(
                "a user can pick a non-`{}` type (e.g. `Rc<RefCell<_>>`) and obtain a `{}` impl automatically",
                trait_name, trait_name
            ),
        ];
        findings.push(Finding::new(
            SEND_SYNC_WITHOUT_BOUND,
            file,
            tp.span(),
            message,
            trigger_path,
        ));
    }
}

/// Collect identifiers of generic type parameters referenced anywhere in
/// `ty` (including nested generic arguments).
fn used_type_params(ty: &Type) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    collect_idents(ty, &mut out);
    out
}

/// Collect type parameters that name a *reachable* value in `ty`.
///
/// A parameter is skipped when the occurrence sits behind a raw pointer
/// (`*const T`, `*mut T`) or a `PhantomData` of such a pointer — no value of
/// that type is owned or referenced. Plain `PhantomData<T>` still counts.
fn collect_reachable(ty: &Type, out: &mut HashSet<String>) {
    match ty {
        Type::Ptr(_) => {
            // Everything behind a raw pointer is unreachable.
        }
        Type::Path(TypePath { qself, path }) => {
            if let Some(q) = qself {
                collect_reachable(&q.ty, out);
            }
            let is_phantom = path
                .segments
                .last()
                .map(|s| s.ident == "PhantomData")
                .unwrap_or(false);
            for (i, seg) in path.segments.iter().enumerate() {
                if let PathArguments::AngleBracketed(ab) = &seg.arguments {
                    for arg in &ab.args {
                        match arg {
                            GenericArgument::Type(t) => {
                                if is_phantom && matches!(t, Type::Ptr(_)) {
                                    // PhantomData<*const T>: unreachable.
                                } else {
                                    collect_reachable(t, out);
                                }
                            }
                            GenericArgument::AssocType(a) => collect_reachable(&a.ty, out),
                            _ => {}
                        }
                    }
                }
                // A bare single-segment identifier is a reachable parameter.
                if i == 0
                    && path.segments.len() == 1
                    && matches!(seg.arguments, PathArguments::None)
                {
                    out.insert(seg.ident.to_string());
                }
            }
        }
        Type::Tuple(t) => t.elems.iter().for_each(|e| collect_reachable(e, out)),
        Type::Array(a) => collect_reachable(&a.elem, out),
        Type::Slice(s) => collect_reachable(&s.elem, out),
        Type::Paren(p) => collect_reachable(&p.elem, out),
        Type::Group(g) => collect_reachable(&g.elem, out),
        _ => {}
    }
}

fn collect_idents(ty: &Type, out: &mut std::collections::HashSet<String>) {
    let Type::Path(TypePath { qself, path }) = ty else {
        return;
    };
    if let Some(q) = qself {
        collect_idents(&q.ty, out);
    }
    for (i, seg) in path.segments.iter().enumerate() {
        if let PathArguments::AngleBracketed(ab) = &seg.arguments {
            for arg in &ab.args {
                match arg {
                    GenericArgument::Type(t) => collect_idents(t, out),
                    GenericArgument::AssocType(a) => collect_idents(&a.ty, out),
                    _ => {}
                }
            }
        }
        // A single-segment path with no arguments is either a type parameter
        // or a bare local type name. Both are collected; only declared
        // parameters are later consulted, so concrete names are harmless.
        if i == 0 && path.segments.len() == 1 && matches!(seg.arguments, PathArguments::None) {
            out.insert(seg.ident.to_string());
        }
    }
}

/// Type parameters that carry the required bound either inline or in a
/// `where` clause. `?Sized`-only params do not qualify.
fn satisfied_params(generics: &Generics, trait_name: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();

    for p in &generics.params {
        if let syn::GenericParam::Type(tp) = p {
            if bounds_contain(tp.bounds.iter().collect::<Vec<_>>().as_slice(), trait_name) {
                out.insert(tp.ident.to_string());
            }
        }
    }
    if let Some(where_clause) = &generics.where_clause {
        for predicate in &where_clause.predicates {
            if let syn::WherePredicate::Type(wt) = predicate {
                if let Type::Path(TypePath { qself: None, path }) = &wt.bounded_ty {
                    if path.segments.len() == 1
                        && matches!(path.segments[0].arguments, PathArguments::None)
                    {
                        let ident = path.segments[0].ident.to_string();
                        if bounds_contain(
                            wt.bounds.iter().collect::<Vec<_>>().as_slice(),
                            trait_name,
                        ) {
                            out.insert(ident);
                        }
                    }
                }
            }
        }
    }
    out
}

fn bounds_contain(bounds: &[&syn::TypeParamBound], trait_name: &str) -> bool {
    bounds.iter().any(|b| match b {
        syn::TypeParamBound::Trait(t) => t
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == trait_name),
        _ => false,
    })
}

fn self_type_base_name(ty: &Type) -> String {
    if let Type::Path(TypePath { qself: None, path }) = ty {
        path.segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default()
    } else {
        "?".into()
    }
}

fn quote_type(ty: &Type) -> String {
    quote::quote!(#ty).to_string()
}

fn collect_allows(attrs: &[syn::Attribute]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for attr in attrs {
        if !attr.path().is_ident("allow") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if let Some(ident) = meta.path.get_ident() {
                out.insert(ident.to_string());
            }
            Ok(())
        });
    }
    out
}

// Re-exports used to keep the generic-argument path types referenced.
#[allow(dead_code)]
fn _types_used(_: &Path, _: AngleBracketedGenericArguments, _: GenericArgument, _: &TypePath) {
    let _ = type_generic_args;
}
