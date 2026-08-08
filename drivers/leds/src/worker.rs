//! The LED engine worker: a periodic task that advances the trigger engine
//! ([`crate::triggers::tick`]) and applies queued external commands.
//!
//! # Why a mailbox
//!
//! A BPF program cannot touch the LED devices directly. Resolving a device
//! allocates (a `Vec` snapshot of the registry) and driving a real multicolor
//! LED may sleep (I²C) — both forbidden in a program's atomic context
//! (`bpf/specification/spec.md` §4.6). So the `narf_led_submit` kfunc (in
//! `narf-bpf-leds`) only *enqueues* a packed command here, a lock-free
//! `compare_exchange` into a fixed mailbox with no allocation and no blocking,
//! and this worker drains it where sleeping is allowed.
//!
//! The worker also drives [`crate::triggers::tick`], which had no caller
//! before — so `Trigger::Timer` / `Heartbeat` blink now actually ticks.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::triggers::Trigger;

/// Set the LED at `idx` (into [`crate::class::led_devices`]) to brightness
/// `value`.
pub const ACTION_SET_BRIGHTNESS: u32 = 0;
/// Blink the LED at `idx`: `value = on_ms << 16 | off_ms` (a `Trigger::Timer`).
pub const ACTION_BLINK: u32 = 1;
/// Turn the LED at `idx` off and clear its trigger.
pub const ACTION_OFF: u32 = 2;
/// Set the multicolor LED at `idx` (into
/// [`crate::multicolor::rgb_led_devices`]) to `value = 0x00RRGGBB`.
pub const ACTION_SET_COLOR: u32 = 3;

/// Mailbox depth. Commands submitted while the worker is behind and the
/// mailbox is full are dropped. A later retry can submit the desired state.
const RING: usize = 32;

/// One slot in the bounded MPSC queue.
///
/// `sequence` is the ownership/publication word: producers may write a slot
/// when it equals their enqueue position, and the consumer may read it when it
/// equals its dequeue position plus one. The two payload atomics are relaxed;
/// the release/acquire transition on `sequence` publishes them together.
#[derive(Debug)]
struct Slot {
    sequence: AtomicUsize,
    idx_action: AtomicU64,
    value: AtomicU32,
}

impl Slot {
    const fn new(sequence: usize) -> Self {
        Self {
            sequence: AtomicUsize::new(sequence),
            idx_action: AtomicU64::new(0),
            value: AtomicU32::new(0),
        }
    }
}

static SLOTS: [Slot; RING] = [
    Slot::new(0),
    Slot::new(1),
    Slot::new(2),
    Slot::new(3),
    Slot::new(4),
    Slot::new(5),
    Slot::new(6),
    Slot::new(7),
    Slot::new(8),
    Slot::new(9),
    Slot::new(10),
    Slot::new(11),
    Slot::new(12),
    Slot::new(13),
    Slot::new(14),
    Slot::new(15),
    Slot::new(16),
    Slot::new(17),
    Slot::new(18),
    Slot::new(19),
    Slot::new(20),
    Slot::new(21),
    Slot::new(22),
    Slot::new(23),
    Slot::new(24),
    Slot::new(25),
    Slot::new(26),
    Slot::new(27),
    Slot::new(28),
    Slot::new(29),
    Slot::new(30),
    Slot::new(31),
];
static ENQUEUE_POS: AtomicUsize = AtomicUsize::new(0);
static DEQUEUE_POS: AtomicUsize = AtomicUsize::new(0);
static DRAINING: AtomicBool = AtomicBool::new(false);

/// Enqueue a command.
///
/// **Atomic-context safe**: no allocation, no sleep, no lock. The retry count
/// is bounded by the queue depth, so producer contention fails closed rather
/// than turning into an unbounded spin. Returns `false` if the mailbox is full
/// or too contended (the command is dropped).
#[must_use]
pub fn submit_command(idx: u32, action: u32, value: u32) -> bool {
    for _ in 0..RING {
        let pos = ENQUEUE_POS.load(Ordering::Relaxed);
        let slot = &SLOTS[pos % RING];
        let sequence = slot.sequence.load(Ordering::Acquire);
        let distance = sequence.wrapping_sub(pos) as isize;

        if distance < 0 {
            return false;
        }
        if distance == 0
            && ENQUEUE_POS
                .compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            slot.idx_action.store(
                (u64::from(idx) << 32) | u64::from(action),
                Ordering::Relaxed,
            );
            slot.value.store(value, Ordering::Relaxed);
            slot.sequence.store(pos.wrapping_add(1), Ordering::Release);
            return true;
        }
    }
    false
}

fn pop_command() -> Option<(u32, u32, u32)> {
    let pos = DEQUEUE_POS.load(Ordering::Relaxed);
    let slot = &SLOTS[pos % RING];
    if slot.sequence.load(Ordering::Acquire) != pos.wrapping_add(1) {
        return None;
    }

    let idx_action = slot.idx_action.load(Ordering::Relaxed);
    let value = slot.value.load(Ordering::Relaxed);
    slot.sequence
        .store(pos.wrapping_add(RING), Ordering::Release);
    DEQUEUE_POS.store(pos.wrapping_add(1), Ordering::Relaxed);
    Some(((idx_action >> 32) as u32, idx_action as u32, value))
}

/// Drain the mailbox and apply each command. Runs in the worker task, where
/// allocation and sleeping are permitted. Public so a test can drive it
/// without the async worker.
pub fn drain() {
    if DRAINING.swap(true, Ordering::AcqRel) {
        return;
    }
    while let Some((idx, action, value)) = pop_command() {
        apply(idx as usize, action, value);
    }
    DRAINING.store(false, Ordering::Release);
}

/// Discard queued commands so kernel smokes start from a hermetic mailbox.
#[doc(hidden)]
pub fn __reset_for_test() {
    if DRAINING.swap(true, Ordering::AcqRel) {
        return;
    }
    while pop_command().is_some() {}
    DRAINING.store(false, Ordering::Release);
}

fn apply(idx: usize, action: u32, value: u32) {
    match action {
        ACTION_SET_BRIGHTNESS => {
            if let Some(dev) = crate::class::led_devices().get(idx) {
                dev.set_brightness(value);
            }
        }
        ACTION_BLINK => {
            if let Some(dev) = crate::class::led_devices().get(idx) {
                dev.set_trigger(Trigger::Timer {
                    on_ms: value >> 16,
                    off_ms: value & 0xFFFF,
                });
            }
        }
        ACTION_OFF => {
            if let Some(dev) = crate::class::led_devices().get(idx) {
                dev.set_trigger(Trigger::None);
                dev.set_brightness(0);
            }
        }
        ACTION_SET_COLOR => {
            if let Some(dev) = crate::multicolor::rgb_led_devices().get(idx) {
                dev.set_color((value >> 16) as u8, (value >> 8) as u8, value as u8);
            }
        }
        // Unknown action: dropped. The kfunc validates before enqueue, so this
        // is only reachable through a raw `submit_command` caller.
        _ => {}
    }
}

/// The periodic worker: every 100 ms apply queued commands and advance the
/// trigger engine. Spawned once at boot by [`start_worker`].
async fn worker() {
    loop {
        let deadline = narf_time::Deadline::after_ms(100);
        narf_time::SleepUntil::new(deadline.as_instant()).await;
        drain();
        crate::triggers::tick();
    }
}

/// Spawn the engine worker. Idempotent — a repeated initcall (the kernel-test
/// harness runs initcalls more than once) does not stack workers.
pub fn start_worker() {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    narf_scheduler::spawn(worker());
}
