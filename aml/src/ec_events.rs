//! Embedded-Controller `_Qxx` event dispatch.
//!
//! When the EC fires the SCI line and the host issues `EC_CMD_QUERY`
//! (0x84), the EC returns a single byte naming the query handler to
//! invoke — `_Q33` for byte 0x33, etc. This module owns the
//! kernel-side registry mapping each `_Qxx` index (0-255) to a
//! Rust handler function. The SCI bottom-half calls
//! [`drain_ec_events`] which drains every pending query and
//! dispatches each to its registered handler.
//!
//! AML evaluation can register its own dispatchers (so platform-
//! supplied `_Qxx` methods in the EC scope run on the host); Rust
//! drivers can register directly (e.g., the AC adapter driver
//! claims `_Q41` if that's its standard event code per ACPI 6.5
//! Appendix E recommended naming).
//!
//! Reference: ACPI 6.5 §12.3 (Embedded Controller Interface).

extern crate alloc;

use narf_lib::sync::IrqSafeSpinLock;

/// A handler invoked when an `_Qxx` event fires. Runs in SCI
/// bottom-half context — must not block; can defer real work to
/// a sleep-pump.
pub type QxxHandler = fn(idx: u8);

/// 256 slots — one per possible `_Qxx` index (0-255). `None` means
/// "no handler registered; ignore the event".
static QXX_HANDLERS: IrqSafeSpinLock<[Option<QxxHandler>; 256]> = IrqSafeSpinLock::new([None; 256]);

/// Register `h` to fire whenever the EC reports query index `idx`.
/// Idempotent — registering a second time replaces the previous
/// handler (so the AML interpreter can claim a slot the boot path
/// stubbed out earlier).
pub fn register_qxx_handler(idx: u8, h: QxxHandler) {
    QXX_HANDLERS.lock()[idx as usize] = Some(h);
}

/// Clear a previously-registered handler.
pub fn unregister_qxx_handler(idx: u8) {
    QXX_HANDLERS.lock()[idx as usize] = None;
}

/// Look up the handler for `idx` without invoking it. Useful in
/// tests + diagnostics.
pub fn lookup_qxx_handler(idx: u8) -> Option<QxxHandler> {
    QXX_HANDLERS.lock()[idx as usize]
}

/// Drain every pending `_Qxx` event from the EC and dispatch each
/// to its registered handler. Called from the SCI bottom-half
/// when `EC_SC_SCI_EVT` is observed in the EC status byte.
///
/// The drain stops when `ec_query` returns 0 (no more events) or
/// when we've drained more than `max_events` (defensive against
/// a wedged EC that always returns a nonzero index).
///
/// Returns the number of events drained.
pub fn drain_ec_events(max_events: usize) -> usize {
    let mut drained = 0;
    while drained < max_events {
        match crate::oregion::ec_query() {
            Ok(0) => break, // EC says no more events
            Ok(idx) => {
                if let Some(h) = lookup_qxx_handler(idx) {
                    h(idx);
                }
                drained += 1;
            }
            Err(_) => break, // EC port not configured / wedged — stop draining
        }
    }
    drained
}

#[doc(hidden)]
pub fn __reset_for_test() {
    *QXX_HANDLERS.lock() = [None; 256];
}
