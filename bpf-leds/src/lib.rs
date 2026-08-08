//! `narf-bpf-leds` — the `narf_led_submit` BPF kfunc.
//!
//! Lets a BPF program drive an LED: set brightness, blink, turn off, or set an
//! RGB color. The kfunc is **atomic-context safe** — it only *enqueues* a
//! command into the LED engine's lock-free mailbox
//! (`narf_drivers_leds::worker`), with no allocation and no blocking — and a
//! background worker resolves the device and does the real work, where the slow
//! paths (a `Vec` snapshot of the registry, I²C color writes on real hardware)
//! are allowed to sleep. That mediation is what lets a program in atomic
//! context touch an LED at all (`bpf/specification/spec.md` §4.6); it is the
//! same shape the struct_ops committer and a Frame-mediated `probe_read` take.
//!
//! Like `narf-bpf-idle`, this crate is the seam: it depends on both `narf-bpf`
//! (for the `kfunc!` macro) and `narf-drivers-leds`, so neither has to know
//! about the other.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use narf_drivers_leds::{
    submit_command, ACTION_BLINK, ACTION_OFF, ACTION_SET_BRIGHTNESS, ACTION_SET_COLOR,
};

narf_bpf::kfunc! {
    /// Submit an LED command from a BPF program.
    ///
    /// `action`:
    /// - `0` set brightness — `value` is the level, `idx` into the LED class;
    /// - `1` blink — `value = on_ms << 16 | off_ms` (a `Trigger::Timer`);
    /// - `2` off — clear the trigger and drive to 0;
    /// - `3` set color — `value = 0x00RRGGBB`, `idx` into the multicolor class.
    ///
    /// Returns `0` on success, `-11` (EAGAIN) if the mailbox is full or
    /// contended (the caller may retry), or `-22`
    /// (EINVAL) for an unknown `action`. A bad `idx` is a no-op at drain time,
    /// not an error here — the kfunc does not resolve the device.
    #[context(Atomic)]
    pub fn narf_led_submit(idx: u32, action: u32, value: u32) -> i64 {
        match action {
            ACTION_SET_BRIGHTNESS | ACTION_BLINK | ACTION_OFF | ACTION_SET_COLOR => {
                if submit_command(idx, action, value) {
                    0
                } else {
                    -11
                }
            }
            _ => -22,
        }
    }
}

/// Register the LED engine worker initcall and anchor the kfunc.
///
/// The `kfunc!` entry is a `#[used]` static in the `narf.kfuncs` link section;
/// this crate must be linked (and referenced) for the verifier to resolve
/// `narf_led_submit`. `frame` (under the `bpf-leds` feature) and `verification`
/// reference this function. It registers a `Stage::Late` worker start so
/// device discovery precedes the first drain; `start_worker` is idempotent, so
/// repeated initcall registration cannot stack workers.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Late, "bpf-leds/worker", || {
        narf_drivers_leds::worker::start_worker();
        InitResult::Ok
    });
    // Touch the kfunc so its object — and the co-located `narf.kfuncs` entry —
    // is pulled in by anything that references this anchor.
    let _ = narf_led_submit as fn(u32, u32, u32) -> i64;
}

#[cfg(feature = "kernel-test")]
mod tests;
