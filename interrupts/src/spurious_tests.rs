//! The unhandled-IRQ detector (Linux `kernel/irq/spurious.c`
//! `note_interrupt`, "irq N: nobody cared").

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::dispatch::{self, HwMask, IrqStatus, SpuriousState, SPURIOUS_WINDOW};

/// Linux's window arithmetic: a window of `SPURIOUS_WINDOW` interrupts with
/// more than `SPURIOUS_THRESHOLD` unhandled disables the vector, once, as
/// the window ends; one with fewer does not; unhandled interrupts more than
/// `HZ/10` apart restart the count, so a sparse unhandled stream never
/// disables; and a vector that is always handled is not even counted.
fn smoke_irq_spurious_window_matches_linux() -> TestResult {
    let gap = 1_000;
    let storm = SpuriousState::new();
    for i in 1..SPURIOUS_WINDOW as u64 {
        if storm.note(false, i, gap).is_some() {
            return TestResult::Fail("disabled before the window ended");
        }
    }
    if storm.note(false, SPURIOUS_WINDOW as u64, gap) != Some(SPURIOUS_WINDOW) {
        return TestResult::Fail("a window of unhandled interrupts did not disable");
    }
    // Mostly unhandled, but at the threshold: kept.
    let mixed = SpuriousState::new();
    let mut verdicts = 0;
    for i in 1..=SPURIOUS_WINDOW as u64 {
        let handled = i % 666 == 0; // 150 handled, 99,850 unhandled
        verdicts += mixed.note(handled, i, gap).is_some() as u32;
    }
    if verdicts != 0 {
        return TestResult::Fail("a window under the threshold disabled the vector");
    }
    let sparse = SpuriousState::new();
    for i in 1..=3 * SPURIOUS_WINDOW as u64 {
        if sparse.note(false, i * (gap + 1), gap).is_some() {
            return TestResult::Fail("sparse unhandled interrupts disabled the vector");
        }
    }
    let healthy = SpuriousState::new();
    for _ in 0..3 * SPURIOUS_WINDOW {
        if healthy.note(true, 0, gap).is_some() {
            return TestResult::Fail("a handled vector was disabled");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/spurious",
    smoke_irq_spurious_window_matches_linux
);

static UNCLAIMED_CALLS: AtomicU32 = AtomicU32::new(0);
static MASK_SET: AtomicU32 = AtomicU32::new(0);
static MASK_CLEAR: AtomicU32 = AtomicU32::new(0);
static MASK_COOKIE: AtomicU64 = AtomicU64::new(0);

fn unclaimed(_cookie: u64) -> IrqStatus {
    UNCLAIMED_CALLS.fetch_add(1, Ordering::Relaxed);
    IrqStatus::None
}

fn claimed(_cookie: u64) -> IrqStatus {
    IrqStatus::Handled
}

fn test_mask(cookie: u64, masked: bool) {
    MASK_COOKIE.store(cookie, Ordering::Relaxed);
    if masked {
        MASK_SET.fetch_add(1, Ordering::Relaxed);
    } else {
        MASK_CLEAR.fetch_add(1, Ordering::Relaxed);
    }
}

/// End to end through `on_irq`: a device vector whose only handler never
/// claims it is reported once ("irq N: nobody cared", with its handlers),
/// soft-masked and masked at its source through the registered hardware
/// mask; later arrivals are dropped and counted as masked arrivals on this
/// CPU; `enable_irq` unmasks the source again. A vector whose handler
/// claims every interrupt is never disabled.
fn smoke_irq_nobody_cared_disables_and_masks_source() -> TestResult {
    let (Ok(bad), Ok(good)) = (crate::vector::alloc(), crate::vector::alloc()) else {
        return TestResult::Fail("no free vectors");
    };
    UNCLAIMED_CALLS.store(0, Ordering::Relaxed);
    MASK_SET.store(0, Ordering::Relaxed);
    MASK_CLEAR.store(0, Ordering::Relaxed);
    dispatch::install_handler_named(bad, "nobody-cares", 7, unclaimed);
    dispatch::install_handler_named(good, "claims-all", 8, claimed);
    dispatch::set_hw_mask(
        bad,
        HwMask {
            kind: "test-mask",
            mask: test_mask,
            cookie: 0xC0FFEE,
        },
    );
    let seq = narf_console::klog::next_seq();
    for _ in 0..SPURIOUS_WINDOW {
        crate::on_irq(bad);
        crate::on_irq(good);
    }
    let text = narf_console::klog::text_since(seq);
    let cpu = narf_lib::percpu::current_cpu();
    let arrivals = dispatch::masked_arrivals_on_cpu(cpu);
    let dropped = dispatch::masked_fire_count(bad);
    let calls = UNCLAIMED_CALLS.load(Ordering::Relaxed);
    for _ in 0..10 {
        crate::on_irq(bad);
    }
    let late_calls = UNCLAIMED_CALLS.load(Ordering::Relaxed);
    let late_arrivals = dispatch::masked_arrivals_on_cpu(cpu) - arrivals;
    let late_dropped = dispatch::masked_fire_count(bad) - dropped;
    let disabled = dispatch::spurious_disabled(bad) && crate::is_masked(bad);
    let good_kept = !dispatch::spurious_disabled(good) && !crate::is_masked(good);
    let set = MASK_SET.load(Ordering::Relaxed);
    let cookie = MASK_COOKIE.load(Ordering::Relaxed);
    crate::enable_irq(bad);
    let cleared = MASK_CLEAR.load(Ordering::Relaxed);
    let reenabled = !crate::is_masked(bad) && !dispatch::spurious_disabled(bad);
    dispatch::remove_handler(bad, "nobody-cares", 7);
    dispatch::remove_handler(good, "claims-all", 8);
    let _ = crate::vector::free(bad);
    let _ = crate::vector::free(good);
    let freed_forgets = dispatch::hw_mask(bad).is_none();

    let has = |n: &[u8]| text.windows(n.len()).any(|w| w == n);
    let header = alloc::format!("irq {bad}: nobody cared");
    let disabling = alloc::format!("Disabling IRQ #{bad} (test-mask)");
    if !disabled || calls != SPURIOUS_WINDOW {
        return TestResult::Fail("a never-claimed vector was not disabled at the window's end");
    }
    if !good_kept {
        return TestResult::Fail("a vector whose handler claims every interrupt was disabled");
    }
    if !has(header.as_bytes()) || !has(b"] nobody-cares cookie=0x7") || !has(disabling.as_bytes()) {
        return TestResult::Fail(
            "the nobody-cared report did not name the vector, handler and mask",
        );
    }
    if set != 1 || cookie != 0xC0FFEE {
        return TestResult::Fail("the source was not masked in hardware exactly once");
    }
    if late_calls != calls || late_arrivals != 10 || late_dropped != 10 {
        return TestResult::Fail("arrivals on the disabled vector ran handlers or went uncounted");
    }
    if cleared != 1 || !reenabled {
        return TestResult::Fail("enable_irq did not unmask the disabled vector's source");
    }
    if !freed_forgets {
        return TestResult::Fail("a freed vector kept its hardware mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/spurious",
    smoke_irq_nobody_cared_disables_and_masks_source
);
