//! Small syntax helpers shared by both checks.

use syn::{Expr, GenericArgument, Path, PathArguments, Type, TypePath};

/// Render a [`Path`] without turbofish/angle-bracket arguments, e.g.
/// `<std::ptr::read as fn>::read` style qualified paths are reduced to the
/// plain segment chain.
pub fn path_string(path: &Path) -> String {
    path.segments
        .iter()
        .map(|seg| seg.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Last two segments joined by `::`, used for suffix matching against the
/// standard-library whitelist (`ptr::read`, `mem::forget`, ...).
pub fn path_suffix2(path: &Path) -> Option<String> {
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    if segs.len() >= 2 {
        Some(format!(
            "{}::{}",
            segs[segs.len() - 2],
            segs[segs.len() - 1]
        ))
    } else {
        segs.last().cloned()
    }
}

/// True when a span originates from macro expansion (including proc macros
/// such as `cargo expand` output and `include!`d tokens).
///
/// `proc_macro2` reports expanded tokens at line 0 / column 0. We use that as
/// the "not written by the user" signal and never report inside such spans,
/// because the user cannot fix code they did not author at that location.
pub fn span_from_expansion(span: proc_macro2::Span) -> bool {
    let start = span.start();
    start.line == 0
}

/// Extract the identifier of a [`TypePath`] that names a bare local type,
/// e.g. `Guard` or `crate::guard::Guard` -> `Some("Guard")`. Generic
/// arguments are ignored.
pub fn type_name(ty: &Type) -> Option<String> {
    let Type::Path(TypePath { qself: None, path }) = ty else {
        return None;
    };
    path.segments.last().map(|s| s.ident.to_string())
}

/// Return the generic arguments of the last segment of a type path, if any.
pub fn type_generic_args(ty: &Type) -> Vec<GenericArgument> {
    let Type::Path(TypePath { qself: None, path }) = ty else {
        return Vec::new();
    };
    match path.segments.last() {
        Some(seg) => match &seg.arguments {
            PathArguments::AngleBracketed(ab) => ab.args.iter().cloned().collect(),
            _ => Vec::new(),
        },
        None => Vec::new(),
    }
}

/// Walk every sub-expression of `expr`, including the expression itself.
pub fn visit_exprs<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    out.push(expr);
    match expr {
        Expr::Array(e) => e.elems.iter().for_each(|x| visit_exprs(x, out)),
        Expr::Assign(e) => {
            visit_exprs(&e.left, out);
            visit_exprs(&e.right, out);
        }
        Expr::Binary(e) => {
            // Covers both arithmetic and compound-assignment forms in syn 2.
            visit_exprs(&e.left, out);
            visit_exprs(&e.right, out);
        }
        Expr::Async(e) => e.block.stmts.iter().for_each(|s| visit_stmts(s, out)),
        Expr::Await(e) => visit_exprs(&e.base, out),
        Expr::Block(e) => e.block.stmts.iter().for_each(|s| visit_stmts(s, out)),
        Expr::Break(e) => {
            if let Some(x) = &e.expr {
                visit_exprs(x, out);
            }
        }
        Expr::Call(e) => {
            visit_exprs(&e.func, out);
            e.args.iter().for_each(|x| visit_exprs(x, out));
        }
        Expr::Cast(e) => visit_exprs(&e.expr, out),
        Expr::Closure(e) => visit_exprs(&e.body, out),
        Expr::Field(e) => visit_exprs(&e.base, out),
        Expr::ForLoop(e) => {
            visit_exprs(&e.expr, out);
            visit_stmts_inner(&e.body, out);
        }
        Expr::Group(e) => visit_exprs(&e.expr, out),
        Expr::If(e) => {
            visit_exprs(&e.cond, out);
            visit_stmts_inner(&e.then_branch, out);
            if let Some((_, x)) = &e.else_branch {
                visit_exprs(x, out);
            }
        }
        Expr::Index(e) => {
            visit_exprs(&e.expr, out);
            visit_exprs(&e.index, out);
        }
        Expr::Let(e) => visit_exprs(&e.expr, out),
        Expr::Loop(e) => visit_stmts_inner(&e.body, out),
        Expr::Macro(_) | Expr::Lit(_) | Expr::Path(_) | Expr::Const(_) => {}
        Expr::MethodCall(e) => {
            visit_exprs(&e.receiver, out);
            e.args.iter().for_each(|x| visit_exprs(x, out));
        }
        Expr::Paren(e) => visit_exprs(&e.expr, out),
        Expr::Range(e) => {
            if let Some(x) = &e.start {
                visit_exprs(x, out);
            }
            if let Some(x) = &e.end {
                visit_exprs(x, out);
            }
        }
        Expr::Reference(e) => visit_exprs(&e.expr, out),
        Expr::Repeat(e) => {
            visit_exprs(&e.expr, out);
            visit_exprs(&e.len, out);
        }
        Expr::Return(e) => {
            if let Some(x) = &e.expr {
                visit_exprs(x, out);
            }
        }
        Expr::Struct(e) => {
            if let Some(x) = &e.rest {
                visit_exprs(x, out);
            }
            e.fields.iter().for_each(|f| visit_exprs(&f.expr, out));
        }
        Expr::Try(e) => visit_exprs(&e.expr, out),
        Expr::TryBlock(e) => visit_stmts_inner(&e.block, out),
        Expr::Tuple(e) => e.elems.iter().for_each(|x| visit_exprs(x, out)),
        Expr::Unary(e) => visit_exprs(&e.expr, out),
        Expr::Unsafe(e) => visit_stmts_inner(&e.block, out),
        Expr::While(e) => {
            visit_exprs(&e.cond, out);
            visit_stmts_inner(&e.body, out);
        }
        Expr::Yield(e) => {
            if let Some(x) = &e.expr {
                visit_exprs(x, out);
            }
        }
        Expr::Verbatim(_) => {}
        _ => {}
    }
}

fn visit_stmts<'a>(stmt: &'a syn::Stmt, out: &mut Vec<&'a Expr>) {
    match stmt {
        syn::Stmt::Local(l) => {
            if let Some(init) = &l.init {
                visit_exprs(&init.expr, out);
                if let Some((_, diverge)) = &init.diverge {
                    visit_exprs(diverge, out);
                }
            }
        }
        // syn 2 folds expression and semicolon statements into `Stmt::Expr`.
        syn::Stmt::Expr(e, _) => visit_exprs(e, out),
        syn::Stmt::Item(_) => {}
        _ => {}
    }
}

fn visit_stmts_inner<'a>(block: &'a syn::Block, out: &mut Vec<&'a Expr>) {
    block.stmts.iter().for_each(|s| visit_stmts(s, out));
}

/// Names of functions/methods guaranteed not to unwind in practice.
/// Anything not listed is treated conservatively as potentially panicking.
pub const NON_PANICKING_SUFFIXES: &[&str] = &[
    // raw pointer / allocation primitives
    "ptr::read",
    "ptr::read_volatile",
    "ptr::read_unaligned",
    "ptr::write",
    "ptr::write_volatile",
    "ptr::write_unaligned",
    "ptr::write_bytes",
    "ptr::copy",
    "ptr::copy_nonoverlapping",
    "ptr::drop_in_place",
    "ptr::null",
    "ptr::null_mut",
    "ptr::addr_of",
    "ptr::addr_of_mut",
    "ptr::from_ref",
    "ptr::from_mut",
    "mem::forget",
    "mem::replace",
    "mem::swap",
    "mem::size_of",
    "mem::align_of",
    "mem::needs_drop",
    "mem::zeroed",
    "mem::transmute",
    "mem::ManuallyDrop::new",
    "MaybeUninit::new",
    "MaybeUninit::uninit",
    "MaybeUninit::assume_init",
    "MaybeUninit::assume_init_read",
    "MaybeUninit::write",
    "MaybeUninit::as_ptr",
    "MaybeUninit::as_mut_ptr",
    "MaybeUninit::as_ref",
    "MaybeUninit::as_mut",
    // box / slice pointer machinery (non-fallible operations)
    "Box::from_raw",
    "Box::into_raw",
    "Box::leak",
    "slice::from_raw_parts",
    "slice::from_raw_parts_mut",
    "str::from_utf8_unchecked",
    // pointer methods
    "as_ptr",
    "as_mut_ptr",
    "cast",
    "wrapping_offset",
    "wrapping_add",
    "wrapping_sub",
    "offset",
    "add",
    "sub",
    "is_null",
    "addr",
];

/// Macros whose expansion can unwind.
pub const PANICKING_MACROS: &[&str] = &["panic", "unreachable", "todo", "unimplemented"];

/// Methods on raw pointers that do not unwind.
pub const NON_PANICKING_PTR_METHODS: &[&str] = &[
    "read",
    "read_volatile",
    "read_unaligned",
    "write",
    "write_volatile",
    "write_unaligned",
    "write_bytes",
    "copy_from",
    "copy_to",
    "copy_from_nonoverlapping",
    "copy_to_nonoverlapping",
    "swap",
    "replace",
    "drop_in_place",
    "offset",
    "wrapping_offset",
    "add",
    "sub",
    "wrapping_add",
    "wrapping_sub",
    "cast",
    "is_null",
    "as_ptr",
    "as_mut_ptr",
    "addr",
];

/// Raw-pointer methods that repair a duplicated-ownership window.
pub const PTR_WRITE_METHODS: &[&str] = &[
    "write",
    "write_volatile",
    "write_unaligned",
    "write_bytes",
    "replace",
    "swap",
    "drop_in_place",
];

/// Enum variant constructors that only move their inputs and can never
/// unwind. User-defined tuple-struct constructors are *not* listed: their
/// construction may run arbitrary code in theory, so they stay conservative.
pub const NON_PANICKING_VARIANTS: &[&str] = &[
    "Some",
    "None",
    "Ok",
    "Err",
    "Poll",
    "Ready",
    "Pending",
    "Pin",
    "UnsafeCell",
];

/// Macros that expand to guarded cleanup and therefore make the surrounding
/// code unwind-safe by construction.
pub const GUARD_MACROS: &[&str] = &["scopeguard", "guard", "defer_on_unwind", "defer_on_success"];

/// Non-panicking standard-library macros (only these are treated as safe).
/// `assert!`, `debug_assert!`, `dbg!`, `eprintln!` etc. are intentionally
/// absent: their expansion can unwind.
pub fn is_non_panicking_macro(name: &str) -> bool {
    matches!(
        name,
        "format_args"
            | "concat"
            | "stringify"
            | "include"
            | "env"
            | "option_env"
            | "line"
            | "column"
            | "file"
            | "module_path"
            | "cfg"
    )
}
