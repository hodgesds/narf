//! Trap text and the panic report still reach the UART when the console
//! lock cannot be had: held by this CPU (a trap or panic in the middle of
//! its own write), held by a CPU the panic stopped, or held by a holder
//! that makes no progress. The SMP whole-line test lives with the other
//! cross-CPU smokes (`interrupts`, `console/lines`).

use super::*;
use core::sync::atomic::AtomicU8;
use narf_kernel_test::{kernel_test_in, TestResult};

const CAPTURE_BYTES: usize = 4096;
static CAPTURE: [AtomicU8; CAPTURE_BYTES] = [const { AtomicU8::new(0) }; CAPTURE_BYTES];
static CAPTURED: AtomicUsize = AtomicUsize::new(0);

fn tap(bytes: &[u8]) {
    let at = CAPTURED.fetch_add(bytes.len(), Ordering::AcqRel);
    for (i, b) in bytes.iter().enumerate() {
        if let Some(slot) = CAPTURE.get(at + i) {
            slot.store(*b, Ordering::Relaxed);
        }
    }
}

fn captured_has(needle: &[u8]) -> bool {
    let len = CAPTURED.load(Ordering::Acquire).min(CAPTURE_BYTES);
    let mut hay = [0u8; CAPTURE_BYTES];
    for (dst, slot) in hay.iter_mut().zip(&CAPTURE[..len]) {
        *dst = slot.load(Ordering::Relaxed);
    }
    hay[..len].windows(needle.len()).any(|w| w == needle)
}

/// Time `f` on the record clock, in ns (0 when the clock is not installed).
fn timed(f: impl FnOnce()) -> u64 {
    let start = klog::now_ns();
    f();
    klog::now_ns().saturating_sub(start)
}

/// The panic path and trap text never wait for a console lock they cannot
/// get: with this CPU holding it, trap text and the panic report go out at
/// once; while panicking, trap text does not wait for a holder elsewhere; a
/// holder elsewhere that makes no progress costs one bounded wait, after
/// which trap text no longer waits until a writer takes the lock again.
fn smoke_console_panic_and_trap_text_print_without_the_lock() -> TestResult {
    CAPTURED.store(0, Ordering::Release);
    let previous = __test_set_uart_tap(Some(tap));
    let own = timed(|| {
        let _held = lock_console();
        trap_sink("console-test: trap text on the holding CPU\n");
        panic_uart_emit(b"console-test: panic report with the lock held\n");
    });
    // A holder on "another CPU": the lock is held and its owner is not us.
    let panicking = timed(|| {
        let _held = lock_console();
        CONSOLE_OWNER.store(usize::MAX, Ordering::Release);
        PANICKING.store(true, Ordering::Release);
        trap_sink("console-test: trap text while panicking\n");
        PANICKING.store(false, Ordering::Release);
    });
    let (stalled, after_stall, expired) = {
        let _held = lock_console();
        CONSOLE_OWNER.store(usize::MAX, Ordering::Release);
        let stalled = timed(|| trap_sink("console-test: trap text behind a stuck holder\n"));
        let after = timed(|| trap_sink("console-test: trap text after the expired wait\n"));
        (stalled, after, TRAP_CONSOLE_EXPIRED.load(Ordering::Relaxed))
    };
    // Any writer taking the lock ends the expired state.
    drop(lock_console());
    let cleared = !TRAP_CONSOLE_EXPIRED.load(Ordering::Relaxed);
    let _ = __test_set_uart_tap(previous);

    for line in [
        &b"console-test: trap text on the holding CPU\n"[..],
        b"console-test: panic report with the lock held\n",
        b"console-test: trap text while panicking\n",
        b"console-test: trap text behind a stuck holder\n",
        b"console-test: trap text after the expired wait\n",
    ] {
        if !captured_has(line) {
            return TestResult::Fail("trap or panic text did not reach the UART without the lock");
        }
    }
    // The clock may not be installed (0); then only the expiry flag speaks.
    let bound = TRAP_CONSOLE_STALL_NS;
    if own >= bound || panicking >= bound {
        return TestResult::Fail("trap or panic text waited for a lock it could never get");
    }
    if !expired || !cleared {
        return TestResult::Fail("a stuck holder's expired wait was not latched and released");
    }
    if stalled != 0 && (stalled < bound || after_stall >= bound) {
        return TestResult::Fail("trap text did not wait one stall bound for a stuck holder");
    }
    TestResult::Pass
}
kernel_test_in!(
    "console/panic",
    smoke_console_panic_and_trap_text_print_without_the_lock
);
