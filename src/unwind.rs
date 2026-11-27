//! Check 1: duplicated ownership inside `unsafe` blocks that can be dropped
//! twice when an intervening call unwinds.
//!
//! The pattern looks like this:
//!
//! ```ignore
//! unsafe {
//!     let value = ptr::read(slot);        // ownership of `*slot` duplicated
//!     user_callback();                    // may panic -> unwinding drops `value`
//!     ptr::write(slot, value);            //   ...and the original slot too
//! }
//! ```
//!
//! The analysis is deliberately syntax-directed and conservative in the
//! *sound* direction: every call that is not on a small whitelist is assumed
//! able to unwind. Sound false negatives (missed cases) are acceptable;
//! false positives on the sanctioned repair patterns are not, and each one
//! has a dedicated suppression path:
//!
//! * `ManuallyDrop` / `MaybeUninit` wrappers (`protected = true`),
//! * types whose `Drop` impl writes the value back ("repair guards"),
//! * the `scopeguard` family and `defer_on_unwind!`/`defer!` guard macros,
//! * code whose span originates from macro expansion (line 0),
//! * crates built with `panic = "abort"` (no unwinding at all),
//! * explicit `#[allow(unwind_double_free)]`.

use std::collections::HashSet;

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::{
    Attribute, Block, Expr, File, GenericArgument, ImplItem, Item, Local, Pat, Path, Stmt, Type,
    TypePath,
};

use crate::model::{AnalysisConfig, Finding, UNWIND_DOUBLE_FREE};
use crate::util::{
    is_non_panicking_macro, path_string, path_suffix2, span_from_expansion, visit_exprs,
    GUARD_MACROS, NON_PANICKING_PTR_METHODS, NON_PANICKING_SUFFIXES, NON_PANICKING_VARIANTS,
    PANICKING_MACROS, PTR_WRITE_METHODS,
};

/// An open "ownership duplicated" window.
#[derive(Clone)]
struct Interval {
    /// Whitespace-stripped source text of the memory slot (`*p`, `(*p).field`).
    slot_sig: String,
    /// Name of the local holding the duplicated value, if it has one.
    binding: Option<String>,
    /// Span of the statement that opened the window.
    opened_at: Span,
    /// Text of the statement opening the window, for the trigger path.
    opened_text: String,
    /// Depth of the innermost block when the window opened.
    depth: usize,
    /// True when the duplicated value lives in `ManuallyDrop`/`MaybeUninit`
    /// or a repair-guard type, i.e. its destructor cannot free the slot.
    protected: bool,
}

/// Local variable known to hold a raw pointer.
struct PtrBinding {
    name: String,
    raw: bool,
}

/// An expression that copies an owned value out through a raw pointer,
/// leaving the original slot logically initialized.
struct OwnedRead {
    /// Whitespace-stripped source text of the memory slot (`*p`, `(*p).field`).
    slot_sig: String,
    description: String,
}

pub struct UnwindChecker<'a> {
    file: String,
    config: &'a AnalysisConfig,
    findings: Vec<Finding>,
    /// Type names with a user `Drop` impl that writes the duplicated value
    /// back (repair guards).
    repair_guard_types: HashSet<String>,
    /// Locals of raw-pointer type, collected while descending.
    ptr_bindings: Vec<PtrBinding>,
    /// Currently open duplication windows.
    intervals: Vec<Interval>,
    /// Block nesting depth.
    depth: usize,
    /// `#[allow(...)]` stack for blocks/functions currently being walked.
    allow_stack: Vec<HashSet<String>>,
}

impl<'a> UnwindChecker<'a> {
    pub fn new(file: String, config: &'a AnalysisConfig) -> Self {
        UnwindChecker {
            file,
            config,
            findings: Vec::new(),
            repair_guard_types: HashSet::new(),
            ptr_bindings: Vec::new(),
            intervals: Vec::new(),
            depth: 0,
            allow_stack: Vec::new(),
        }
    }

    pub fn analyze_file(mut self, file: &File) -> Vec<Finding> {
        // Pass 1: collect repair-guard type names (structs/enums whose Drop
        // impl contains a raw pointer write).
        self.collect_guards(file);
        // File-level inner attributes.
        let file_allows = collect_allows(&file.attrs);
        self.allow_stack.push(file_allows);
        for item in &file.items {
            self.check_item(item);
        }
        self.allow_stack.pop();
        self.findings
    }

    // ------------------------------------------------------------------
    // Pass 1: guard discovery
    // ------------------------------------------------------------------

    fn collect_guards(&mut self, file: &File) {
        // All named type definitions.
        let mut named: HashSet<String> = HashSet::new();
        for item in &file.items {
            match item {
                Item::Struct(s) => {
                    named.insert(s.ident.to_string());
                }
                Item::Enum(e) => {
                    named.insert(e.ident.to_string());
                }
                Item::Mod(m) => {
                    if let Some((_, items)) = &m.content {
                        for it in items {
                            if let Item::Struct(s) = it {
                                named.insert(s.ident.to_string());
                            } else if let Item::Enum(e) = it {
                                named.insert(e.ident.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        // Drop impls whose body writes through a raw pointer qualify the
        // implementor as a repair guard.
        for item in &file.items {
            if let Item::Impl(it) = item {
                if let Some((_, path, _)) = &it.trait_ {
                    if path_string(path).ends_with("Drop") {
                        if let Some(name) = self_type_name(&it.self_ty) {
                            if named.contains(&name) && drop_impl_repairs(&it.items) {
                                self.repair_guard_types.insert(name);
                            }
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Entry points
    // ------------------------------------------------------------------

    fn check_item(&mut self, item: &Item) {
        if self.config.panic_aborts {
            return;
        }
        // Macro definitions are never analyzed: their bodies are templates,
        // not executed code, and macro call sites are handled opaquely.
        if matches!(item, Item::Macro(_)) {
            return;
        }
        match item {
            Item::Fn(f) => {
                let allows = collect_allows(&f.attrs);
                self.allow_stack.push(allows);
                let saved = self.register_fn_args(&f.sig);
                let is_unsafe = f.sig.unsafety.is_some();
                if is_unsafe {
                    self.check_unsafe_block(&f.block);
                } else {
                    self.check_block(&f.block);
                }
                self.unregister_fn_args(saved);
                self.allow_stack.pop();
            }
            Item::Impl(it) => {
                for inner in &it.items {
                    if let ImplItem::Fn(f) = inner {
                        let allows = collect_allows(&f.attrs);
                        self.allow_stack.push(allows);
                        let saved = self.register_fn_args(&f.sig);
                        let is_unsafe = f.sig.unsafety.is_some();
                        if is_unsafe {
                            self.check_unsafe_block(&f.block);
                        } else {
                            self.check_block(&f.block);
                        }
                        self.unregister_fn_args(saved);
                        self.allow_stack.pop();
                    }
                }
            }
            Item::Trait(it) => {
                for inner in &it.items {
                    if let syn::TraitItem::Fn(f) = inner {
                        if let Some(default) = &f.default {
                            let allows = collect_allows(&f.attrs);
                            self.allow_stack.push(allows);
                            let saved = self.register_fn_args(&f.sig);
                            if f.sig.unsafety.is_some() {
                                self.check_unsafe_block(default);
                            } else {
                                self.check_block(default);
                            }
                            self.unregister_fn_args(saved);
                            self.allow_stack.pop();
                        }
                    }
                }
            }
            Item::Const(c) => {
                self.check_expr(&c.expr);
            }
            Item::Static(c) => {
                self.check_expr(&c.expr);
            }
            Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    for it in items {
                        self.check_item(it);
                    }
                }
            }
            _ => {}
        }
    }

    fn check_unsafe_block(&mut self, block: &Block) {
        // Every statement inside an unsafe context is analyzed; nested safe
        // blocks inherit the open intervals because the slot is still
        // duplicated across them. (syn's `Block` carries no attributes.)
        self.check_block_inner(block);
    }

    /// Walk an ordinary block. Statements inside it are only relevant while
    /// an interval opened in an enclosing unsafe context is live.
    fn check_block(&mut self, block: &Block) {
        self.check_block_inner(block);
    }

    fn check_block_inner(&mut self, block: &Block) {
        self.depth += 1;
        let depth = self.depth;
        for stmt in &block.stmts {
            self.check_stmt(stmt);
        }
        // Windows still open when the block ends: if the value is
        // unprotected it is dropped here while the slot still owns its
        // contents — a double free is guaranteed on the next drop.
        let leftovers: Vec<Interval> = self
            .intervals
            .iter()
            .filter(|iv| iv.depth == depth)
            .filter(|iv| !iv.protected)
            .cloned()
            .collect();
        for iv in leftovers {
            let slot_sig = iv.slot_sig.clone();
            self.report(
                block.span(),
                "duplicated ownership window closes without writing the value back; \
                 the local and the original slot will both be dropped",
                iv,
                format!(
                    "block ends without `ptr::write({}..)` / `mem::forget(..)` repairing the slot",
                    slot_sig
                ),
            );
        }
        self.intervals.retain(|iv| iv.depth < depth);
        self.ptr_bindings.retain(|_| true);
        self.depth -= 1;
    }

    // ------------------------------------------------------------------
    // Statement processing
    // ------------------------------------------------------------------

    fn check_stmt(&mut self, stmt: &Stmt) {
        // syn 2 represents statement-level macro invocations as `Stmt::Macro`,
        // distinct from expression-position macros.
        if let Stmt::Macro(m) = stmt {
            self.handle_statement_macro(m);
            return;
        }
        match stmt {
            Stmt::Local(local) => self.check_local(local),
            Stmt::Expr(expr, _) => {
                self.check_expr(expr);
            }
            Stmt::Item(_) => {}
            _ => {}
        }
    }

    fn handle_statement_macro(&mut self, m: &syn::StmtMacro) {
        let name = m
            .mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if GUARD_MACROS.contains(&name.as_str()) {
            let tokens = m.mac.tokens.to_string();
            for iv in self.intervals.iter_mut() {
                if let Some(b) = &iv.binding {
                    if tokens.contains(b) {
                        iv.protected = true;
                    }
                }
            }
            return;
        }
        if is_non_panicking_macro(&name) {
            return;
        }
        let reason = if PANICKING_MACROS.contains(&name.as_str()) {
            format!("`{}!` unconditionally panics", name)
        } else {
            format!("macro `{}!` may expand to panicking code", name)
        };
        let open: Vec<Interval> = self
            .intervals
            .iter()
            .filter(|iv| !iv.protected)
            .cloned()
            .collect();
        for iv in open {
            self.report(
                iv.opened_at,
                "a potentially unwinding macro sits between an ownership copy and the write-back",
                iv,
                format!(
                    "{} (unwind through macro statement while ownership is duplicated)",
                    reason
                ),
            );
        }
    }

    fn check_local(&mut self, local: &Local) {
        let allows = collect_allows(&local.attrs);
        self.allow_stack.push(allows);

        // Register raw-typed pointer bindings first so initializer analysis
        // can use earlier bindings only (order of `let`s is linear).
        let mut new_ptrs: Vec<PtrBinding> = Vec::new();
        if let Pat::Type(pt) = &local.pat {
            if let Some(name) = pat_ident(&pt.pat) {
                if is_raw_ptr_type(&pt.ty) {
                    new_ptrs.push(PtrBinding { name, raw: true });
                }
            }
        } else if let Some(name) = pat_ident(&local.pat) {
            // `let p = addr_of!(x)` / `let p = x as *const _`
            if let Some(init) = &local.init {
                if expr_is_raw(&init.expr) {
                    new_ptrs.push(PtrBinding { name, raw: true });
                }
            }
        }

        if let Some(init) = &local.init {
            // 1. A panic between the copy and its repair is the bug — but a
            //    repair-guard constructor itself is the repair, so building
            //    it must not count as an intervening panic.
            let guard_init = self.is_guard_constructor(&init.expr);
            if !guard_init {
                self.scan_for_panic(&init.expr, "initializer expression");
            }
            // 2. Open a window if the initializer duplicates ownership.
            if let Some(opening) = self.classify_owned_read(&init.expr) {
                let protected = self.is_protected_binding(local, &init.expr);
                let binding = pat_ident(&local.pat);
                self.open_interval(opening, binding, protected, local.span());
            }
            // 3. `else` diverging block (`let ... else { ... }`).
            if let Some((_, diverge)) = &init.diverge {
                self.check_expr(diverge);
            }
            // 4. A duplicated value moved into a repair-guard constructor
            //    (`let _g = Guard { value: v, .. }`) transfers the cleanup
            //    responsibility: the open window becomes protected.
            if guard_init {
                self.propagate_guard_protection(local, &init.expr);
            }
        }

        for pb in new_ptrs {
            self.ptr_bindings.push(pb);
        }
        self.allow_stack.pop();
    }

    fn check_expr(&mut self, expr: &Expr) {
        // Guard macros establish protection even though their tokens come
        // from an expansion, so they must run before the span filter.
        if let Expr::Macro(m) = expr {
            let name = m
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            if GUARD_MACROS.contains(&name.as_str()) {
                let tokens = m.mac.tokens.to_string();
                for iv in self.intervals.iter_mut() {
                    if let Some(b) = &iv.binding {
                        if tokens.contains(b) {
                            iv.protected = true;
                        }
                    }
                }
                return;
            }
        }
        if span_from_expansion(expr.span()) {
            return;
        }
        match expr {
            Expr::Block(e) => self.check_block(&e.block),
            Expr::Unsafe(e) => {
                let allows = collect_allows(&e.attrs);
                self.allow_stack.push(allows);
                self.check_unsafe_block(&e.block);
                self.allow_stack.pop();
            }
            Expr::If(e) => {
                self.scan_for_panic(&e.cond, "`if` condition");
                self.check_block(&e.then_branch);
                if let Some((_, alt)) = &e.else_branch {
                    self.check_expr(alt);
                }
            }
            Expr::While(e) => {
                self.scan_for_panic(&e.cond, "`while` condition");
                self.check_block(&e.body);
            }
            Expr::ForLoop(e) => {
                self.scan_for_panic(&e.expr, "`for` iterator expression");
                self.check_block(&e.body);
            }
            Expr::Loop(e) => self.check_block(&e.body),
            Expr::Match(e) => {
                self.scan_for_panic(&e.expr, "`match` scrutinee");
                for arm in &e.arms {
                    self.check_expr(&arm.body);
                }
            }
            Expr::Return(e) => {
                if let Some(v) = &e.expr {
                    self.scan_for_panic(v, "`return` value");
                }
                self.report_scope_leave("`return`");
            }
            Expr::Break(e) => {
                if let Some(v) = &e.expr {
                    self.scan_for_panic(v, "`break` value");
                }
                self.report_scope_leave("`break`");
            }
            Expr::Continue(_) => self.report_scope_leave("`continue`"),
            Expr::Try(e) => {
                self.scan_for_panic(&e.expr, "`?` operand");
                self.report_scope_leave("the `?` operator");
            }
            Expr::TryBlock(e) => self.check_block(&e.block),
            Expr::Async(e) => self.check_block(&e.block),
            Expr::Closure(e) => {
                // The closure body is a separate frame: duplicated slots
                // created outside it stay open, but windows created inside
                // must not leak out.
                self.depth += 1;
                let depth = self.depth;
                self.check_expr(&e.body);
                self.intervals.retain(|iv| iv.depth < depth);
                self.depth -= 1;
            }
            Expr::Assign(e) => {
                self.scan_for_panic(&e.right, "right-hand side of assignment");
                self.scan_for_panic(&e.left, "assignment target");
                self.handle_slot_write(&e.left);
            }
            Expr::Binary(e) => {
                // Compound assignment (`+=`, ...) both evaluates operands
                // (potentially unwinding) and writes the left-hand slot.
                use syn::BinOp;
                if matches!(
                    e.op,
                    BinOp::AddAssign(_)
                        | BinOp::SubAssign(_)
                        | BinOp::MulAssign(_)
                        | BinOp::DivAssign(_)
                        | BinOp::RemAssign(_)
                        | BinOp::BitXorAssign(_)
                        | BinOp::BitAndAssign(_)
                        | BinOp::BitOrAssign(_)
                        | BinOp::ShlAssign(_)
                        | BinOp::ShrAssign(_)
                ) {
                    self.scan_for_panic(&e.right, "right-hand side of compound assignment");
                    self.scan_for_panic(&e.left, "assignment target");
                    self.handle_slot_write(&e.left);
                }
            }
            Expr::Call(call) => {
                self.handle_call_expr(call, expr);
            }
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                if self.expr_is_known_raw(&call.receiver)
                    && PTR_WRITE_METHODS.contains(&method.as_str())
                {
                    // `p.write(v)` / `p.replace(v)` repair the slot.
                    let s = sig(&call.receiver);
                    self.intervals.retain(|iv| !slots_overlap(&iv.slot_sig, &s));
                    return;
                }
                self.scan_for_panic(expr, "method call");
                self.handle_binding_consumption(call);
            }
            Expr::Macro(m) => {
                self.handle_macro_expr(m, expr);
            }
            // Unary deref / field reads as *statements* do not duplicate
            // ownership into a binding; recurse generically for sub-exprs.
            other => {
                let mut all = Vec::new();
                visit_exprs(other, &mut all);
                for sub in all {
                    if !std::ptr::eq(sub, other) {
                        self.check_expr(sub);
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Interval lifecycle
    // ------------------------------------------------------------------

    /// Recognize an expression that copies an owned value out through a raw
    /// pointer, leaving the original slot logically initialized.
    fn classify_owned_read(&self, expr: &Expr) -> Option<OwnedRead> {
        match expr {
            Expr::Call(call) => {
                let func_path = call_func_path(&call.func)?;
                let suffix = path_suffix2(func_path)?;
                if matches!(
                    suffix.as_str(),
                    "ptr::read" | "ptr::read_volatile" | "ptr::read_unaligned"
                ) {
                    let slot = call.args.first()?;
                    return Some(OwnedRead {
                        slot_sig: sig(slot),
                        description: format!(
                            "`{}` duplicates ownership of `{}`",
                            suffix,
                            sig(slot)
                        ),
                    });
                }
                None
            }
            Expr::MethodCall(call) => {
                if call.method == "read" || call.method == "read_volatile" {
                    let recv = &call.receiver;
                    if self.expr_is_known_raw(recv) {
                        return Some(OwnedRead {
                            slot_sig: sig(recv),
                            description: format!(
                                "`<*const T>::{}` duplicates ownership of `{}`",
                                call.method,
                                sig(recv)
                            ),
                        });
                    }
                }
                None
            }
            Expr::Unary(u) if u.op == syn::UnOp::Deref(Default::default()) => {
                if self.expr_is_known_raw(&u.expr) {
                    return Some(OwnedRead {
                        slot_sig: sig(expr),
                        description: format!(
                            "raw pointer dereference copy of `{}` duplicates ownership",
                            sig(expr)
                        ),
                    });
                }
                None
            }
            Expr::Field(f) => {
                // `(*p).field` where `p` is a raw pointer.
                if let Expr::Unary(u) = &*f.base {
                    if u.op == syn::UnOp::Deref(Default::default())
                        && self.expr_is_known_raw(&u.expr)
                    {
                        return Some(OwnedRead {
                            slot_sig: sig(expr),
                            description: format!(
                                "field copy through raw pointer `{}` duplicates ownership",
                                sig(expr)
                            ),
                        });
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn open_interval(
        &mut self,
        read: OwnedRead,
        binding: Option<String>,
        protected: bool,
        span: Span,
    ) {
        self.intervals.push(Interval {
            slot_sig: read.slot_sig,
            binding,
            opened_at: span,
            opened_text: read.description,
            depth: self.depth,
            protected,
        });
    }

    /// Writes through `target` close every window whose slot matches.
    fn handle_slot_write(&mut self, target: &Expr) {
        let target_sig = sig(target);
        // A write to the exact slot, or to a field/deref of it, repairs the
        // duplicated owner (e.g. window slot `(*p).value`, write target
        // `(*p).value` / a field assignment `(*p).value = x`).
        self.intervals
            .retain(|iv| iv.slot_sig != target_sig && !slots_overlap(&iv.slot_sig, &target_sig));
    }

    fn handle_call_expr(&mut self, call: &syn::ExprCall, whole: &Expr) {
        if let Some(path) = call_func_path(&call.func) {
            let suffix = path_suffix2(path).unwrap_or_default();
            let full = path_string(path);

            // Repair / consumption primitives close windows.
            if matches!(
                suffix.as_str(),
                "ptr::write"
                    | "ptr::write_volatile"
                    | "ptr::write_unaligned"
                    | "ptr::drop_in_place"
            ) {
                if let Some(slot) = call.args.first() {
                    let s = sig(slot);
                    self.intervals.retain(|iv| !slots_overlap(&iv.slot_sig, &s));
                }
                return;
            }
            if suffix == "mem::forget" || full.ends_with("mem::forget") {
                #[allow(clippy::collapsible_match, clippy::collapsible_if)]
                if let Some(arg) = call.args.first() {
                    #[allow(clippy::collapsible_match, clippy::collapsible_if)]
                    if let Expr::Path(p) = arg {
                        let name = p.path.segments.last().map(|s| s.ident.to_string());
                        self.intervals.retain(|iv| iv.binding != name);
                    }
                }
                return;
            }
            if suffix == "mem::replace" || suffix == "ptr::replace" {
                // `mem::replace(dst, src)` moves `src` out and writes `dst`
                // atomically: if `dst` matches an open slot the window
                // closes, and the call itself cannot unwind.
                if let Some(dst) = call.args.first() {
                    let s = sig(dst);
                    self.intervals.retain(|iv| iv.slot_sig != s);
                }
                return;
            }
            if suffix == "drop" {
                // Explicit `drop(value)` while the slot is still initialized
                // is itself the double free (and also unwinds on the
                // value's destructor).
                #[allow(clippy::collapsible_match, clippy::collapsible_if)]
                if let Some(arg) = call.args.first() {
                    #[allow(clippy::collapsible_match, clippy::collapsible_if)]
                    if let Expr::Path(p) = arg {
                        let name = p.path.segments.last().map(|s| s.ident.to_string());
                        if let Some(iv) = self
                            .intervals
                            .iter()
                            .find(|iv| iv.binding == name && !iv.protected)
                            .cloned()
                        {
                            self.report(
                                whole.span(),
                                "explicit drop of the duplicated value while the original slot stays initialized",
                                iv,
                                "`drop(..)` runs the destructor here; the slot drops the same value again".to_string(),
                            );
                            self.intervals.retain(|x| x.binding != name);
                            return;
                        }
                    }
                }
            }
        }
        // Generic call: arguments and callee may unwind.
        self.scan_for_panic(whole, "function call");
        self.handle_binding_consumption_call(call);
    }

    /// `value.method(..)` where `value` is the duplicated binding.
    fn handle_binding_consumption(&mut self, call: &syn::ExprMethodCall) {
        if let Expr::Path(p) = &*call.receiver {
            let name = p.path.segments.last().map(|s| s.ident.to_string());
            // Consuming methods (`into_*`, `unwrap`, ...) move the value;
            // the window still exists until a write, and an unwinding method
            // was already reported by scan_for_panic. Nothing to close here.
            let _ = name;
        }
    }

    fn handle_binding_consumption_call(&mut self, _call: &syn::ExprCall) {
        // Moves into calls do not repair the slot: the slot remains
        // initialized, so the window stays open. Panic handling is done by
        // scan_for_panic.
    }

    fn handle_macro_expr(&mut self, m: &syn::ExprMacro, whole: &Expr) {
        let name = m
            .mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();

        if GUARD_MACROS.contains(&name.as_str()) {
            // `guard!(value, ...)` / scopeguard constructors establish a
            // destructor that repairs the slot: mark every currently open
            // window mentioned in the token stream as protected.
            let tokens = m.mac.tokens.to_string();
            for iv in self.intervals.iter_mut() {
                if let Some(b) = &iv.binding {
                    if tokens.contains(b) {
                        iv.protected = true;
                    }
                }
            }
            return;
        }
        if PANICKING_MACROS.contains(&name.as_str()) {
            self.scan_open(
                whole.span(),
                format!("the `{}!` macro expands to an unconditional panic", name),
                "panic while ownership is duplicated".to_string(),
            );
            return;
        }
        if is_non_panicking_macro(&name) {
            return;
        }
        // `assert!`, `debug_assert!`, `println!`, `vec!`, user macros ...
        // treated conservatively as potentially unwinding.
        self.scan_open(
            whole.span(),
            format!("macro invocation `{}!` may expand to panicking code", name),
            "unwind through macro expansion while ownership is duplicated".to_string(),
        );
    }

    fn report_scope_leave(&mut self, kind: &str) {
        let open: Vec<Interval> = self
            .intervals
            .iter()
            .filter(|iv| !iv.protected)
            .cloned()
            .collect();
        for iv in open {
            self.report(
                iv.opened_at,
                "scope leaves while ownership is duplicated; unwinding or the next slot drop frees the value twice",
                iv,
                format!("{} exits before the slot is repaired", kind),
            );
        }
        self.intervals.clear();
    }

    // ------------------------------------------------------------------
    // Panic classification
    // ------------------------------------------------------------------

    /// Walk every sub-expression of `root` and report the first unwinding
    /// construct found per open window.
    fn scan_for_panic(&mut self, root: &Expr, context: &str) {
        let mut exprs = Vec::new();
        visit_exprs(root, &mut exprs);
        for e in exprs {
            if span_from_expansion(e.span()) {
                continue;
            }
            if let Some(reason) = self.classify_panic(e) {
                self.scan_open(e.span(), reason, context.to_string());
            }
        }
    }

    /// Return a description when `expr` can unwind.
    fn classify_panic(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Index(_) => Some("indexing/slicing can panic on out-of-bounds access".into()),
            Expr::Try(_) => Some("the `?` operator returns early and may run destructors".into()),
            Expr::Macro(m) => {
                let name = m
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                if PANICKING_MACROS.contains(&name.as_str()) {
                    Some(format!("`{}!` unconditionally panics", name))
                } else if is_non_panicking_macro(&name) {
                    None
                } else {
                    Some(format!("macro `{}!` may expand to panicking code", name))
                }
            }
            Expr::Binary(b) => {
                use syn::{BinOp, Expr};
                match b.op {
                    BinOp::Add(_)
                    | BinOp::Sub(_)
                    | BinOp::Mul(_)
                    | BinOp::Div(_)
                    | BinOp::Rem(_) => {
                        // Integer arithmetic panics on overflow in debug
                        // builds and on division by zero. Raw pointer ops
                        // use method syntax, so binary operators here are
                        // plain arithmetic.
                        let _ = Expr::Binary;
                        Some("arithmetic operator can panic (overflow / division by zero)".into())
                    }
                    _ => None,
                }
            }
            Expr::Unary(u) => {
                if matches!(u.op, syn::UnOp::Neg(_)) {
                    Some("negation can panic on overflow".into())
                } else {
                    None
                }
            }
            Expr::Call(call) => {
                let Some(path) = call_func_path(&call.func) else {
                    // Calls through closures / function pointers: user code.
                    return Some(
                        "call through a closure or function pointer can invoke arbitrary panicking code"
                            .into(),
                    );
                };
                let suffix = path_suffix2(path)?;
                if NON_PANICKING_SUFFIXES.contains(&suffix.as_str())
                    || (path.segments.len() == 1
                        && NON_PANICKING_VARIANTS.contains(&suffix.as_str()))
                {
                    None
                } else if path.segments.len() == 1 {
                    // Single-segment name: local function, closure parameter,
                    // or imported item — conservatively treated as user code.
                    Some(format!(
                        "call to local/closure `{}` may panic or run a user `Drop`",
                        suffix
                    ))
                } else {
                    Some(format!(
                        "call to `{}` is not on the non-unwinding whitelist and may panic",
                        suffix
                    ))
                }
            }
            Expr::MethodCall(call) => {
                let name = call.method.to_string();
                if NON_PANICKING_SUFFIXES.contains(&name.as_str())
                    || NON_PANICKING_PTR_METHODS.contains(&name.as_str())
                {
                    None
                } else if name.starts_with("unwrap") || name == "expect" {
                    Some(format!("`{}` panics on the failure variant", name))
                } else {
                    Some(format!(
                        "method call `{}` may invoke a user `Drop`/generic code that panics",
                        name
                    ))
                }
            }
            Expr::Closure(_) => None,
            _ => None,
        }
    }

    /// Emit one finding per currently open, unprotected window.
    fn scan_open(&mut self, span: Span, reason: String, context: String) {
        let open: Vec<Interval> = self
            .intervals
            .iter()
            .filter(|iv| !iv.protected)
            .cloned()
            .collect();
        for iv in open {
            self.report(
                span,
                "a potentially unwinding call sits between an ownership copy and the write-back",
                iv,
                format!("{} ({})", reason, context),
            );
        }
    }

    // ------------------------------------------------------------------
    // Protection classification
    // ------------------------------------------------------------------

    /// True when the duplicated value's destructor cannot free the slot:
    /// `ManuallyDrop`/`MaybeUninit` wrappers or repair-guard types.
    fn is_protected_binding(&self, local: &Local, init: &Expr) -> bool {
        // Explicit type annotation.
        if let Pat::Type(pt) = &local.pat {
            if let Some(name) = type_path_name(&pt.ty) {
                if name == "ManuallyDrop" || name == "MaybeUninit" {
                    return true;
                }
                if self.repair_guard_types.contains(&name) {
                    return true;
                }
            }
        }
        if let Some(name) = pat_ident(&local.pat) {
            let _ = name;
        }
        // Wrapper constructor in the initializer.
        if let Expr::Call(call) = init {
            if let Some(path) = call_func_path(&call.func) {
                let full = path_string(path);
                if full.ends_with("mem::ManuallyDrop::new")
                    || full.ends_with("ManuallyDrop::new")
                    || full.ends_with("MaybeUninit::new")
                {
                    return true;
                }
                if let Some(last) = path.segments.last() {
                    let type_name = last.ident.to_string();
                    if self.repair_guard_types.contains(&type_name) {
                        return true;
                    }
                }
            }
        }
        // scopeguard-style constructor functions.
        if let Expr::Call(call) = init {
            if let Expr::Path(p) = &*call.func {
                let full = path_string(&p.path);
                if full.ends_with("guard") || full.ends_with("guard_on_unwind") {
                    return true;
                }
            }
        }
        false
    }

    /// True when `expr` constructs a repair-guard type (struct literal or
    /// tuple/function-call form) known from its repairing `Drop` impl.
    fn is_guard_constructor(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Struct(s) => self
                .path_last_name(&s.path)
                .map(|n| self.repair_guard_types.contains(&n))
                .unwrap_or(false),
            Expr::Call(call) => {
                let Some(path) = call_func_path(&call.func) else {
                    return false;
                };
                path.segments
                    .last()
                    .map(|s| self.repair_guard_types.contains(&s.ident.to_string()))
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    /// Mark open windows protected when their binding is moved into a
    /// repair-guard constructor expression.
    fn propagate_guard_protection(&mut self, local: &Local, init: &Expr) {
        let guard_name = match init {
            Expr::Struct(s) => self
                .path_last_name(&s.path)
                .filter(|n| self.repair_guard_types.contains(n)),
            Expr::Call(call) => {
                if let Some(path) = call_func_path(&call.func) {
                    let last = path.segments.last().map(|s| s.ident.to_string());
                    last.filter(|n| self.repair_guard_types.contains(n))
                } else {
                    None
                }
            }
            _ => None,
        };
        let Some(guard_name) = guard_name else {
            return;
        };
        let _local_binding = pat_ident(&local.pat);
        // Names referenced inside the guard's field/function arguments.
        let mut referenced: Vec<String> = Vec::new();
        match init {
            Expr::Struct(s) => {
                for field in &s.fields {
                    collect_path_idents(&field.expr, &mut referenced);
                }
                if let Some(rest) = &s.rest {
                    collect_path_idents(rest, &mut referenced);
                }
            }
            Expr::Call(call) => {
                for arg in &call.args {
                    collect_path_idents(arg, &mut referenced);
                }
            }
            _ => {}
        }
        for iv in self.intervals.iter_mut() {
            if let Some(b) = &iv.binding {
                if referenced.iter().any(|r| r == b) {
                    iv.protected = true;
                    let _ = &guard_name;
                }
            }
        }
    }

    fn path_last_name(&self, path: &Path) -> Option<String> {
        path.segments.last().map(|s| s.ident.to_string())
    }

    fn expr_is_known_raw(&self, expr: &Expr) -> bool {
        if expr_is_raw(expr) {
            return true;
        }
        if let Expr::Path(p) = expr {
            if let Some(name) = p.path.segments.last().map(|s| s.ident.to_string()) {
                return self.ptr_bindings.iter().any(|b| b.name == name && b.raw);
            }
        }
        false
    }

    /// Register function arguments of raw-pointer type. Returns how many
    /// bindings were pushed so the caller can pop them on exit.
    fn register_fn_args(&mut self, sig: &syn::Signature) -> usize {
        let mut pushed = 0;
        for arg in &sig.inputs {
            if let syn::FnArg::Typed(pt) = arg {
                if is_raw_ptr_type(&pt.ty) {
                    if let Some(name) = pat_ident(&pt.pat) {
                        self.ptr_bindings.push(PtrBinding { name, raw: true });
                        pushed += 1;
                    }
                }
            }
        }
        pushed
    }

    fn unregister_fn_args(&mut self, count: usize) {
        let len = self.ptr_bindings.len();
        if count <= len {
            self.ptr_bindings.truncate(len - count);
        }
    }

    // ------------------------------------------------------------------
    // Reporting
    // ------------------------------------------------------------------

    fn report(&mut self, span: Span, message: &str, iv: Interval, last_step: String) {
        if span_from_expansion(span) || span_from_expansion(iv.opened_at) {
            return;
        }
        if self
            .allow_stack
            .iter()
            .any(|a| a.contains(UNWIND_DOUBLE_FREE))
            || self.config.allows(UNWIND_DOUBLE_FREE)
        {
            return;
        }
        let path = vec![
            format!("window opened: {}", iv.opened_text),
            format!(
                "duplicated value binding: {}",
                iv.binding.clone().unwrap_or_else(|| "<temporary>".into())
            ),
            last_step,
            "on unwind the local drops, then the still-initialized slot drops the same allocation again".into(),
        ];
        self.findings.push(Finding::new(
            UNWIND_DOUBLE_FREE,
            &self.file,
            span,
            message,
            path,
        ));
    }
}

// ----------------------------------------------------------------------
// Free helpers
// ----------------------------------------------------------------------

/// Normalize an expression for slot matching: whitespace-insensitive source
/// text. A leading dereference is stripped so that a window opened through
/// `*p` is closed by a write to either `*p` or `p`.
fn sig(expr: &Expr) -> String {
    let raw = quote_to_compact(expr);
    strip_deref(raw)
}

fn strip_deref(s: String) -> String {
    // `*p` -> `p`, `(*p).f` -> `(*p).f` (field projections keep the parens).
    if let Some(rest) = s.strip_prefix('*') {
        rest.to_string()
    } else {
        s
    }
}

/// Two slot signatures overlap when one is the other or one names a
/// projection of the other (`p` vs `(*p).value`).
fn slots_overlap(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // Normalize parenthesized derefs: `(*p).value` vs `p.value` style.
    let na = normalize_projection(a);
    let nb = normalize_projection(b);
    na == nb || na.starts_with(&nb) || nb.starts_with(&na)
}

fn normalize_projection(s: &str) -> String {
    s.replace(['(', ')'], "")
}

fn quote_to_compact(expr: &Expr) -> String {
    let s = quote::quote!(#expr).to_string();
    s.split_whitespace().collect::<String>()
}

fn call_func_path(expr: &Expr) -> Option<&Path> {
    match expr {
        Expr::Path(p) => Some(&p.path),
        _ => None,
    }
}

fn pat_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Type(pt) => pat_ident(&pt.pat),
        Pat::Reference(pr) => pat_ident(&pr.pat),
        _ => None,
    }
}

/// All single-segment path identifiers mentioned inside an expression.
fn collect_path_idents(expr: &Expr, out: &mut Vec<String>) {
    let mut all = Vec::new();
    visit_exprs(expr, &mut all);
    for e in all {
        if let Expr::Path(p) = e {
            if p.path.segments.len() == 1 && p.qself.is_none() {
                out.push(p.path.segments[0].ident.to_string());
            }
        }
    }
}

fn type_path_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(TypePath { qself: None, path }) => {
            path.segments.last().map(|s| s.ident.to_string())
        }
        _ => None,
    }
}

fn is_raw_ptr_type(ty: &Type) -> bool {
    matches!(ty, Type::Ptr(_))
}

/// Syntactic raw-pointer recognition independent of local bindings:
/// `addr_of!(_)`, `addr_of_mut!(_)`, `x as *const _` / `x as *mut _`.
fn expr_is_raw(expr: &Expr) -> bool {
    match expr {
        Expr::Cast(cast) => matches!(cast.ty.as_ref(), Type::Ptr(_)),
        Expr::Macro(m) => {
            let name = m
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            name == "addr_of" || name == "addr_of_mut"
        }
        Expr::Call(call) => {
            if let Some(path) = call_func_path(&call.func) {
                let suffix = path_suffix2(path).unwrap_or_default();
                matches!(
                    suffix.as_str(),
                    "ptr::addr_of" | "ptr::addr_of_mut" | "ptr::from_ref" | "ptr::from_mut"
                )
            } else {
                false
            }
        }
        Expr::MethodCall(call) => {
            matches!(call.method.to_string().as_str(), "as_ptr" | "as_mut_ptr")
        }
        _ => false,
    }
}

fn self_type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(TypePath { qself: None, path }) => {
            path.segments.last().map(|s| s.ident.to_string())
        }
        _ => None,
    }
}

/// A Drop impl "repairs" when it writes through a raw pointer or calls
/// `ptr::write`/`ptr::drop_in_place`.
fn drop_impl_repairs(items: &[ImplItem]) -> bool {
    let mut text = String::new();
    for it in items {
        if let ImplItem::Fn(f) = it {
            text.push_str(&quote::quote!(#f).to_string());
        }
    }
    text.contains("ptr :: write")
        || text.contains("ptr::write")
        || text.contains("drop_in_place")
        || text.contains("write_volatile")
        || text.contains("write_unaligned")
}

fn collect_allows(attrs: &[Attribute]) -> HashSet<String> {
    let mut out = HashSet::new();
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

// Keep imports used only by generic-argument helpers referenced in docs.
#[allow(dead_code)]
fn _generic_args_used(_: GenericArgument) {}

/// File-level `#![allow(...)]` names.
pub fn collect_file_allows(file: &File) -> HashSet<String> {
    let mut out = HashSet::new();
    for attr in &file.attrs {
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
