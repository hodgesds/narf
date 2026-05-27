//! ACPI fixed-hardware events: lid switch + power/sleep buttons.
//!
//! ACPI declares three "fixed-feature" or "control-method" event
//! sources that the OS treats as input:
//!
//! - **Lid switch** (`PNP0C0D`, ACPI 6.5 §9.5.1) — a control-method
//!   device with a `_LID` method that returns 0 (closed) or non-zero
//!   (open). The EC fires `Notify(LID, 0x80)` when the state changes
//!   and the host re-evaluates `_LID`.
//!
//! - **Power button** (`PNP0C0C`, ACPI 6.5 §4.8) — the control-method
//!   form. When FADT.flags bit 4 (`PWR_BUTTON`) is *set*, the
//!   platform uses this form and `Notify(PWRBTN, 0x80)` fires on
//!   press. When the bit is *clear*, the platform exposes the
//!   *fixed-hardware* power button in `PM1A_STS` bit 8
//!   (`PWRBTN_STS`); the SCI handler decodes that bit and calls
//!   [`record_pwrbtn_sts`] from interrupt context.
//!
//! - **Sleep button** (`PNP0C0E`) — same dual-form pattern as the
//!   power button. Bit 5 (`SLP_BUTTON`) of FADT.flags controls
//!   which form is in use; the fixed-hardware form lives in
//!   `PM1A_STS` bit 9 (`SLPBTN_STS`).
//!
//! Many laptops use the control-method form for both buttons (so
//! AML can map an extra key on the keyboard to "power"). Bring-up
//! firmware on Renoir 4700U + Phoenix HawkPoint1 mixes the two —
//! we wire both paths so the typed [`ButtonEvent`] stream surfaces
//! either source.
//!
//! Adapted from Linux `drivers/acpi/button.c` (GPL-2.0+; NARF is
//! GPL-2.0-or-later as of 2026-05-20).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::Value;

// ── Spec constants ────────────────────────────────────────────────────────────

/// Lid device HID per ACPI 6.5 §9.5.1.
pub const PNP0C0D_LID: &str = "PNP0C0D";
/// Control-method power button HID per ACPI 6.5 §4.8.
pub const PNP0C0C_POWER: &str = "PNP0C0C";
/// Control-method sleep button HID per ACPI 6.5 §4.8.
pub const PNP0C0E_SLEEP: &str = "PNP0C0E";

/// Notify code emitted by the EC for "lid state changed",
/// "power button pressed", or "sleep button pressed" — all three
/// use the same per-spec subcode (ACPI 6.5 §5.6.6 Table 5.61).
pub const NOTIFY_BUTTON_OR_LID: u64 = 0x80;

/// PM1_STS bit positions for the fixed-hardware buttons
/// (ACPI 6.5 §4.8.3.1.1).
pub const PWRBTN_STS: u16 = 1 << 8;
pub const SLPBTN_STS: u16 = 1 << 9;

/// FADT.flags bit positions (ACPI 6.5 §5.2.9 Table 5.10).
/// When *set*, the corresponding button is a *control-method*
/// device (PNP0C0C / PNP0C0E) rather than fixed-hardware in PM1.
pub const FADT_FLAG_PWR_BUTTON_IS_CONTROL_METHOD: u32 = 1 << 4;
pub const FADT_FLAG_SLP_BUTTON_IS_CONTROL_METHOD: u32 = 1 << 5;

// ── ButtonEvent ───────────────────────────────────────────────────────────────

/// Typed button / lid event surfaced through [`subscribe`]. Subscribers
/// translate to whatever shape their layer wants (a power-policy
/// service, a console TTY mapping `KEY_POWER`, the framebuffer
/// switching off on `LidClosed`, etc.).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ButtonEvent {
    /// Lid moved from open → closed.
    LidClosed,
    /// Lid moved from closed → open.
    LidOpened,
    /// User pressed the power button (either form).
    PowerPressed,
    /// User pressed the sleep button (either form).
    SleepPressed,
}

// ── Subscriber registry ───────────────────────────────────────────────────────

/// Handler invoked on every dispatched event. Runs in the calling
/// context (Notify dispatch from AML eval, or SCI bottom-half for
/// fixed-hardware) — handlers must not block.
pub type ButtonHandler = fn(ButtonEvent);

/// Slot-based subscriber list. Capped so we don't grow unbounded
/// across module init calls; 8 slots are plenty for the OS-side
/// consumers we expect (power policy, FB blank, TTY, observability).
const MAX_SUBSCRIBERS: usize = 8;

static SUBSCRIBERS: IrqSafeSpinLock<[Option<ButtonHandler>; MAX_SUBSCRIBERS]> =
    IrqSafeSpinLock::new([None; MAX_SUBSCRIBERS]);

/// Register a handler to receive every [`ButtonEvent`]. Returns true
/// if the handler was installed; false when every slot is already
/// occupied (which usually means a buggy init flow is registering
/// the same handler dozens of times).
pub fn subscribe(handler: ButtonHandler) -> bool {
    let mut g = SUBSCRIBERS.lock();
    for slot in g.iter_mut() {
        if slot.is_none() {
            *slot = Some(handler);
            return true;
        }
    }
    false
}

/// Dispatch `ev` to every registered subscriber. Snapshots the
/// handler list under the lock and calls handlers with the lock
/// released so a subscriber that re-enters (e.g. logs through
/// `narf_console`) can't deadlock.
fn fan_out(ev: ButtonEvent) {
    let handlers: [Option<ButtonHandler>; MAX_SUBSCRIBERS] = {
        let g = SUBSCRIBERS.lock();
        *g
    };
    for h in handlers.iter().filter_map(|s| s.as_ref()) {
        h(ev);
    }
}

// ── Lid state ─────────────────────────────────────────────────────────────────

/// Cached AML path of the first `PNP0C0D` lid device found. `None`
/// until [`init`] runs and discovers one; remains `None` on platforms
/// without a lid (desktops, tablets without a clamshell).
static LID_PATH: IrqSafeSpinLock<Option<String>> = IrqSafeSpinLock::new(None);

/// Last observed lid state. `None` = no lid device or `_LID` not yet
/// evaluated. `Some(true)` = open; `Some(false)` = closed.
static LID_STATE: IrqSafeSpinLock<Option<bool>> = IrqSafeSpinLock::new(None);

/// Decode the integer return value of `_LID`. Per ACPI 6.5 §9.5.1
/// 0 = closed, non-zero = open. Pulled out so the smoke can pin
/// the bit-level decode.
pub fn decode_lid(v: u64) -> bool {
    v != 0
}

/// Current lid state, if a lid device was found at init.
/// `Some(true)` = open, `Some(false)` = closed.
pub fn current_lid_state() -> Option<bool> {
    *LID_STATE.lock()
}

/// Re-evaluate `_LID` on the discovered lid device, update cache,
/// and dispatch [`ButtonEvent::LidOpened`] / [`ButtonEvent::LidClosed`]
/// when the state changes. No-op when no lid device was found.
fn refresh_lid_state() {
    let path = {
        let g = LID_PATH.lock();
        match g.as_ref() {
            Some(p) => p.clone(),
            None => return,
        }
    };
    // _LID is a sibling of the lid device — path is "<dev>._LID".
    let mut lid_method = path;
    lid_method.push_str("._LID");
    let v = match crate::eval::evaluate_method(&lid_method, &[]) {
        Ok(Value::Integer(v)) => v,
        // Non-integer return — treat as "open" (Linux's button.c
        // does the same: any non-zero result is open, and a method
        // that fails to evaluate is treated as "no transition").
        Ok(other) => other.as_integer(),
        Err(_) => return,
    };
    let new_open = decode_lid(v);
    let prev = {
        let mut g = LID_STATE.lock();
        let prev = *g;
        *g = Some(new_open);
        prev
    };
    // Always dispatch on the FIRST evaluation (prev == None) so the
    // initial state is observable to subscribers that init AFTER us.
    let edge = match prev {
        None => true,
        Some(was_open) => was_open != new_open,
    };
    if edge {
        fan_out(if new_open {
            ButtonEvent::LidOpened
        } else {
            ButtonEvent::LidClosed
        });
    }
}

/// Notify handler installed on the lid device's namespace path.
/// Called by `narf_aml::sync::dispatch_notify` from AML evaluation.
fn lid_notify_handler(_target: &str, value: u64) {
    if value == NOTIFY_BUTTON_OR_LID {
        refresh_lid_state();
    }
}

// ── Power / sleep buttons ─────────────────────────────────────────────────────

/// Press counters for the fixed-hardware path (incremented from
/// the SCI bottom-half). Subscribers see the typed event on
/// each increment; counters are exposed for observability /
/// debounce by the userland power service.
static POWER_PRESSES: AtomicU8 = AtomicU8::new(0);
static SLEEP_PRESSES: AtomicU8 = AtomicU8::new(0);

/// Notify handler installed on every PNP0C0C device.
fn power_notify_handler(_target: &str, value: u64) {
    if value == NOTIFY_BUTTON_OR_LID {
        POWER_PRESSES.fetch_add(1, Ordering::AcqRel);
        fan_out(ButtonEvent::PowerPressed);
    }
}

/// Notify handler installed on every PNP0C0E device.
fn sleep_notify_handler(_target: &str, value: u64) {
    if value == NOTIFY_BUTTON_OR_LID {
        SLEEP_PRESSES.fetch_add(1, Ordering::AcqRel);
        fan_out(ButtonEvent::SleepPressed);
    }
}

/// Read accumulated power-button press count and clear it. The
/// userland power service drains this to debounce / batch.
pub fn drain_power_presses() -> u8 {
    POWER_PRESSES.swap(0, Ordering::AcqRel)
}

/// Read accumulated sleep-button press count and clear it.
pub fn drain_sleep_presses() -> u8 {
    SLEEP_PRESSES.swap(0, Ordering::AcqRel)
}

/// Called from the SCI bottom-half when `PM1A_STS` bit 8
/// (`PWRBTN_STS`) is observed set. Dispatches the typed event
/// the same way Notify(PWRBTN, 0x80) would.
///
/// Re-entrancy: safe to call from interrupt context. Bumps the
/// counter atomically and fans out to subscribers (which run with
/// SUBSCRIBERS released — see [`fan_out`]).
pub fn record_pwrbtn_sts() {
    POWER_PRESSES.fetch_add(1, Ordering::AcqRel);
    fan_out(ButtonEvent::PowerPressed);
}

/// Called from the SCI bottom-half when `PM1A_STS` bit 9
/// (`SLPBTN_STS`) is observed set.
pub fn record_slpbtn_sts() {
    SLEEP_PRESSES.fetch_add(1, Ordering::AcqRel);
    fan_out(ButtonEvent::SleepPressed);
}

// ── Initialisation ────────────────────────────────────────────────────────────

/// Discovery summary returned from [`init`] for diagnostics. The
/// counts reflect what was wired up; zero on a platform that simply
/// doesn't declare that device class.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ButtonsInit {
    pub lids: u32,
    pub power_buttons: u32,
    pub sleep_buttons: u32,
}

/// Track whether [`init`] has already run, so re-entrant boot paths
/// (the namespace gets rebuilt by tests) don't double-register
/// handlers.
static INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Walk the AML namespace, discover lid + power + sleep button
/// devices, register Notify handlers, and seed the lid-state cache.
///
/// Idempotent at boot — calling twice still produces correct
/// dispatch (the second pass replaces nothing since the underlying
/// sync::register_notify_handler appends, but we guard with a
/// boolean so a re-entry is a true no-op).
pub fn init() -> ButtonsInit {
    if INIT_DONE.swap(true, Ordering::AcqRel) {
        return ButtonsInit::default();
    }

    let mut out = ButtonsInit::default();

    // ── Lid devices (PNP0C0D) ────────────────────────────────────
    // Walk every device, match _HID OR any _CID entry — laptops
    // commonly attach a vendor _HID with PNP0C0D in _CID (Linux's
    // acpi_button.c does the same _HID/_CID dual-match).
    for path in matching_devices(PNP0C0D_LID) {
        // Register Notify handler.
        crate::sync::register_notify_handler(&path, lid_notify_handler);
        // Cache the first lid device's path + seed _LID.
        let mut g = LID_PATH.lock();
        if g.is_none() {
            *g = Some(path.clone());
        }
        out.lids += 1;
    }
    // Now that LID_PATH is set, do the initial _LID evaluation.
    refresh_lid_state();

    // ── Power buttons (PNP0C0C) ──────────────────────────────────
    for path in matching_devices(PNP0C0C_POWER) {
        crate::sync::register_notify_handler(&path, power_notify_handler);
        out.power_buttons += 1;
    }

    // ── Sleep buttons (PNP0C0E) ──────────────────────────────────
    for path in matching_devices(PNP0C0E_SLEEP) {
        crate::sync::register_notify_handler(&path, sleep_notify_handler);
        out.sleep_buttons += 1;
    }

    out
}

/// Walk every Device node and return paths whose `_HID` or any
/// `_CID` entry equals `target_hid`. Mirrors Linux's
/// `acpi_match_device_ids` which matches a driver against both.
fn matching_devices(target_hid: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let paths = crate::list_all_device_paths();
    for path in &paths {
        let mut matched = false;
        if let Some(h) = crate::device_hid(path) {
            if h == target_hid {
                matched = true;
            }
        }
        if !matched {
            for cid in crate::device_cids(path) {
                if cid == target_hid {
                    matched = true;
                    break;
                }
            }
        }
        if matched {
            out.push(path.clone());
        }
    }
    out
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Reset all per-module state. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    INIT_DONE.store(false, Ordering::Release);
    SUBSCRIBERS.lock().iter_mut().for_each(|s| *s = None);
    *LID_PATH.lock() = None;
    *LID_STATE.lock() = None;
    POWER_PRESSES.store(0, Ordering::Release);
    SLEEP_PRESSES.store(0, Ordering::Release);
}

// ── Smokes ────────────────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// `_LID` decode: 0 → closed (false), 1 / 0xFFFFFFFF → open (true).
fn smoke_buttons_decode_lid_zero_vs_one() -> TestResult {
    if decode_lid(0) {
        return TestResult::Fail("decode_lid(0) should be closed");
    }
    if !decode_lid(1) {
        return TestResult::Fail("decode_lid(1) should be open");
    }
    // Per spec, any non-zero is open — including weird vendor
    // sentinels like 0xFFFFFFFF that some Insyde firmware emits.
    if !decode_lid(0xFFFF_FFFF) {
        return TestResult::Fail("decode_lid(0xFFFFFFFF) should be open");
    }
    if !decode_lid(0xDEAD_BEEF) {
        return TestResult::Fail("decode_lid(0xDEADBEEF) should be open");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_buttons_decode_lid_zero_vs_one);

/// Bit-position smoke for the PM1_STS layout: PWRBTN_STS = bit 8,
/// SLPBTN_STS = bit 9. ACPI 6.5 §4.8.3.1.1.
fn smoke_buttons_pwrbtn_sts_bit_position() -> TestResult {
    if PWRBTN_STS != 0x0100 {
        return TestResult::Fail("PWRBTN_STS must be bit 8 (0x100)");
    }
    if SLPBTN_STS != 0x0200 {
        return TestResult::Fail("SLPBTN_STS must be bit 9 (0x200)");
    }
    // FADT flag bits (control-method form indicators).
    if FADT_FLAG_PWR_BUTTON_IS_CONTROL_METHOD != 0x10 {
        return TestResult::Fail("FADT PWR_BUTTON flag should be bit 4");
    }
    if FADT_FLAG_SLP_BUTTON_IS_CONTROL_METHOD != 0x20 {
        return TestResult::Fail("FADT SLP_BUTTON flag should be bit 5");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_buttons_pwrbtn_sts_bit_position);

/// Subscribe + dispatch round-trip with a fake notifier: register a
/// handler, fire the lid notify handler against a synthetic AML
/// namespace, observe the typed event.
fn smoke_buttons_subscribe_dispatch_round_trip() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    static SEEN: AtomicU32 = AtomicU32::new(0);
    static LAST: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
    fn h(ev: ButtonEvent) {
        SEEN.fetch_add(1, Ordering::Relaxed);
        LAST.store(
            match ev {
                ButtonEvent::LidClosed => 0,
                ButtonEvent::LidOpened => 1,
                ButtonEvent::PowerPressed => 2,
                ButtonEvent::SleepPressed => 3,
            },
            Ordering::Relaxed,
        );
    }

    __reset_for_test();
    SEEN.store(0, Ordering::Relaxed);
    LAST.store(0xFFFF_FFFF, Ordering::Relaxed);

    if !subscribe(h) {
        return TestResult::Fail("subscribe should succeed in a fresh state");
    }
    // Direct fan_out path — exercises the slot-based registry without
    // needing AML evaluation.
    fan_out(ButtonEvent::PowerPressed);
    if SEEN.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("subscriber not called for PowerPressed");
    }
    if LAST.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("subscriber saw wrong variant");
    }
    // Also exercise the SCI bottom-half entry point: this bumps
    // POWER_PRESSES (the fan_out path above does NOT — it bypasses
    // the counter so the test can keep the two paths separable).
    record_pwrbtn_sts();
    if SEEN.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("record_pwrbtn_sts didn't dispatch");
    }
    if drain_power_presses() != 1 {
        return TestResult::Fail("drain_power_presses should return 1 (single record_pwrbtn_sts)");
    }
    if drain_power_presses() != 0 {
        return TestResult::Fail("drain_power_presses should zero on re-drain");
    }
    // Multiple SCI events accumulate.
    record_pwrbtn_sts();
    record_pwrbtn_sts();
    record_pwrbtn_sts();
    if drain_power_presses() != 3 {
        return TestResult::Fail("3x record_pwrbtn_sts should drain as 3");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_buttons_subscribe_dispatch_round_trip);

/// Notify dispatch on a synthetic PNP0C0D device: build a tiny AML
/// namespace with `Device(\LID0)` and a `_HID` of "PNP0C0D" plus a
/// `_LID` method returning 1, run `init`, fire dispatch_notify, then
/// re-fire with a synthesized closed `_LID` to observe the closed
/// event.
fn smoke_buttons_notify_dispatch_on_pnp0c0d() -> TestResult {
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};
    static EVENTS: AtomicU32 = AtomicU32::new(0);
    fn handler(ev: ButtonEvent) {
        // Encode: bit0 = LidOpened seen, bit1 = LidClosed seen.
        match ev {
            ButtonEvent::LidOpened => {
                EVENTS.fetch_or(1, Ordering::Relaxed);
            }
            ButtonEvent::LidClosed => {
                EVENTS.fetch_or(2, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    crate::__reset_for_test();
    crate::sync::__reset_for_test();
    __reset_for_test();
    EVENTS.store(0, Ordering::Relaxed);

    // Synthetic AML blob:
    //   Device(\LID_) {
    //     Name(_HID, "PNP0C0D")
    //     Name(STAT, 1)            // backing state; _LID returns it
    //     Method(_LID, 0) { Return(\LID.STAT) }
    //   }
    //
    // We hand-encode the byte stream so the smoke doesn't depend
    // on the higher-level evaluator's StoreOp path. The `_LID`
    // method returns the value of \LID.STAT using a fully-qualified
    // NameString so the eval's name-resolver finds the sibling
    // without depending on scope-walk-up-from-method-scope.
    let mut body: Vec<u8> = Vec::new();

    // Inside-Device body:
    //   Name(_HID, String "PNP0C0D")
    let mut inside: Vec<u8> = Vec::new();
    inside.push(0x08); // NameOp
    inside.extend_from_slice(b"_HID");
    inside.push(0x0D); // StringPrefix
    inside.extend_from_slice(b"PNP0C0D");
    inside.push(0x00); // NUL terminator
                       //   Name(STAT, 1)
    inside.push(0x08);
    inside.extend_from_slice(b"STAT");
    inside.push(0x01); // OneOp = 1
                       //   Method(_LID, 0) { Return(\LID.STAT) }
    let method_body: Vec<u8> = {
        let mut v: Vec<u8> = Vec::new();
        v.push(0xA4); // ReturnOp
        // Fully-qualified NameString \LID.STAT:
        //   ROOT '\\' + DualNamePrefix 0x2E + "LID_" + "STAT"
        v.push(b'\\');
        v.push(0x2E);
        v.extend_from_slice(b"LID_");
        v.extend_from_slice(b"STAT");
        v
    };
    // Method header: MethodOp + PkgLen + NameSeg(_LID) + MethodFlags + body
    let method_pkg_total = 1 + 4 + 1 + method_body.len();
    inside.push(0x14); // MethodOp
    inside.push(method_pkg_total as u8);
    inside.extend_from_slice(b"_LID");
    inside.push(0x00); // 0 args, not serialised
    inside.extend_from_slice(&method_body);

    // Outer Device(\LID_): ExtOpPrefix(0x5B) DeviceOp(0x82) PkgLen
    // NameString body. The NameString is `\` + 1 seg of 4 chars.
    let outer_namestring_len = 1 + 4; // root + 1 seg
    let outer_pkg_total = 1 + outer_namestring_len + inside.len();
    body.push(0x5B);
    body.push(0x82);
    body.push(outer_pkg_total as u8); // 1-byte PkgLength fits since total < 0x40
    body.push(b'\\');
    body.extend_from_slice(b"LID_");
    body.extend_from_slice(&inside);

    if crate::__parse_body_for_test(&body, "\\").is_err() {
        return TestResult::Fail("synthetic LID device parse failed");
    }

    // Make sure the parser saw it.
    let h = crate::device_hid("\\LID");
    if h.as_deref() != Some("PNP0C0D") {
        return TestResult::Fail("\\LID device _HID didn't resolve to PNP0C0D");
    }

    // Subscribe and init — init evaluates _LID once and dispatches
    // the initial open state.
    if !subscribe(handler) {
        return TestResult::Fail("subscribe failed");
    }
    let summary = init();
    if summary.lids == 0 {
        return TestResult::Fail("init() didn't discover the lid device");
    }
    if current_lid_state() != Some(true) {
        return TestResult::Fail("initial _LID should evaluate to open (1)");
    }
    if EVENTS.load(Ordering::Relaxed) & 1 == 0 {
        return TestResult::Fail("initial LidOpened event not dispatched");
    }

    // Now flip the backing STAT to 0 via the crate-internal name
    // updater and fire a Notify — re-evaluation should see closed.
    // `update_name_value` is `pub(crate)` so we can mutate from
    // inside the same crate without going through the eval's
    // Store path.
    crate::update_name_value("\\LID.STAT", crate::NameValue::Integer(0));

    // Now fire the Notify dispatch as the AML interpreter would.
    crate::sync::dispatch_notify("\\LID", NOTIFY_BUTTON_OR_LID);
    if current_lid_state() != Some(false) {
        return TestResult::Fail("Notify did not transition lid to closed");
    }
    if EVENTS.load(Ordering::Relaxed) & 2 == 0 {
        return TestResult::Fail("LidClosed event not dispatched on notify");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_buttons_notify_dispatch_on_pnp0c0d);
