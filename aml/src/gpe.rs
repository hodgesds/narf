//! AML GPE block discovery + handler dispatch.
//!
//! Scans the AML namespace for `\\_GPE._Lxx` (level-triggered) and
//! `\\_GPE._Exx` (edge-triggered) methods, registers one `GpeHandler`
//! per unique GPE number, and dispatches either the AML method or a
//! registered native handler when `dispatch(gpe_num)` is called.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::NodeKind;

// ── GpeHandler ────────────────────────────────────────────────────────────────

/// A registered GPE handler. Holds either an AML method path, a native
/// function pointer, or both. On `dispatch`, the native handler runs
/// first (when present) followed by the AML method (when present).
pub struct GpeHandler {
    pub gpe_num: u32,
    /// Fully-qualified AML path of the `_Lxx` or `_Exx` method, if any.
    pub aml_path: Option<String>,
    /// Native (kernel-side) handler function pointer, if any.
    pub native: Option<fn(u32)>,
}

impl core::fmt::Debug for GpeHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GpeHandler")
            .field("gpe_num", &self.gpe_num)
            .field("aml_path", &self.aml_path)
            .field("native", &self.native.map(|_| "<fn>"))
            .finish()
    }
}

// ── Global handler table ──────────────────────────────────────────────────────

static HANDLERS: IrqSafeSpinLock<Vec<GpeHandler>> = IrqSafeSpinLock::new(Vec::new());

/// Snapshot of a handler's dispatch targets: an optional native function
/// pointer and an optional fully-qualified AML method path.
type HandlerSnapshot = (Option<fn(u32)>, Option<String>);

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan the AML namespace for GPE handler methods and register them.
///
/// Looks for `Method` nodes whose path is under `\\_GPE` and whose
/// last segment matches `_L<hex><hex>` (level) or `_E<hex><hex>` (edge),
/// case-insensitive. Parses the two hex chars to obtain the GPE number
/// and registers or replaces the handler entry.
///
/// Returns the number of AML handlers installed.
pub fn install_aml_handlers() -> u32 {
    let mut nodes: Vec<crate::AmlNode> = Vec::new();
    crate::copy_nodes(&mut nodes);

    const GPE_PREFIX: &str = "\\_GPE.";
    let mut count = 0u32;

    for node in &nodes {
        if node.kind != NodeKind::Method {
            continue;
        }

        // Must be under \\_GPE.
        let path = node.path.as_str();
        let suffix = match path.strip_prefix(GPE_PREFIX) {
            Some(s) => s,
            None => continue,
        };

        // Must be exactly one segment of 4 chars: `_L<h><h>` or `_E<h><h>`
        // (with possible trailing underscores stripped by the AML parser,
        // so we handle both raw `_L01` and stripped forms with 2+ chars).
        //
        // The AML parser strips trailing underscores but keeps at least 1
        // character. The valid patterns after stripping are:
        //   _L<H><H>  or  _E<H><H>  (4 chars, no trailing underscores)
        //   _L<H>     or  _E<H>     (3 chars — one hex digit, low nibble only)
        //
        // We require exactly the 4-char form to avoid false positives.
        if suffix.contains('.') {
            continue;
        } // nested — not a direct _GPE child
        let sb = suffix.as_bytes();
        if sb.len() < 4 {
            continue;
        }
        // Take only the last 4 chars if the stripped name is longer
        // (shouldn't happen, but be safe).
        let seg = &sb[sb.len().saturating_sub(4)..];
        if seg.len() < 4 {
            continue;
        }
        if seg[0] != b'_' {
            continue;
        }
        let trigger = seg[1];
        if trigger != b'L' && trigger != b'l' && trigger != b'E' && trigger != b'e' {
            continue;
        }
        // seg[2] and seg[3] must be ASCII hex digits.
        fn is_hex(c: u8) -> bool {
            c.is_ascii_hexdigit()
        }
        fn hex_val(c: u8) -> u32 {
            if c.is_ascii_digit() {
                (c - b'0') as u32
            } else if c.is_ascii_lowercase() {
                (c - b'a') as u32 + 10
            } else {
                (c - b'A') as u32 + 10
            }
        }
        if !is_hex(seg[2]) || !is_hex(seg[3]) {
            continue;
        }
        let gpe_num = (hex_val(seg[2]) << 4) | hex_val(seg[3]);

        // Register / replace entry.
        let mut g = HANDLERS.lock();
        if let Some(existing) = g.iter_mut().find(|h| h.gpe_num == gpe_num) {
            existing.aml_path = Some(node.path.clone());
        } else {
            g.push(GpeHandler {
                gpe_num,
                aml_path: Some(node.path.clone()),
                native: None,
            });
            count += 1;
        }
    }

    count
}

/// Register a native (kernel-side) handler for a GPE number. If an
/// entry for `gpe_num` already exists, its `native` field is replaced;
/// otherwise a new entry with no AML path is created.
pub fn register_native_handler(gpe_num: u32, handler: fn(u32)) {
    let mut g = HANDLERS.lock();
    if let Some(existing) = g.iter_mut().find(|h| h.gpe_num == gpe_num) {
        existing.native = Some(handler);
    } else {
        g.push(GpeHandler {
            gpe_num,
            aml_path: None,
            native: Some(handler),
        });
    }
}

/// Dispatch a GPE event. Snapshot the registered handler under lock
/// (to avoid holding the lock across potentially slow AML evaluation),
/// then call the native handler (if present) and/or evaluate the AML
/// method (if present). No-op when no handler is registered.
pub fn dispatch(gpe_num: u32) {
    // Snapshot under lock.
    let (native, aml_path): HandlerSnapshot = {
        let g = HANDLERS.lock();
        match g.iter().find(|h| h.gpe_num == gpe_num) {
            Some(h) => (h.native, h.aml_path.clone()),
            None => return,
        }
    };

    if let Some(f) = native {
        f(gpe_num);
    }
    if let Some(ref path) = aml_path {
        let _ = crate::eval::evaluate_method(path, &[]);
    }
}

/// Return the total number of registered handlers (AML + native).
pub fn handler_count() -> usize {
    HANDLERS.lock().len()
}

/// Reset the handler table. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    HANDLERS.lock().clear();
}
