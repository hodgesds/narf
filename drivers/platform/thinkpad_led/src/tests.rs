//! Smoke tests for `narf-drivers-platform-thinkpad-led`.
//!
//! Coverage (all hardware-independent — QEMU emulates no ThinkPad):
//! - LED definitions: seven defs, unique names, maxima, default
//!   triggers, safe generic indices, HID table ↔ buffer.
//! - Quad codec: Integer encode/decode round-trip, malformed input.
//! - Shared driver logic against a fake backend: clamping,
//!   last-written cache, failed-set behavior, kbdlight re-seed,
//!   0x60C0 re-assert, availability per kind.
//! - Builtin probe on non-ThinkPad hardware: registers nothing and
//!   does not panic; builtin registration against the AML fixture
//!   publishes all seven LEDs with the `LED_DEFS` maxima and the
//!   default triggers (micmute's stays pending until the
//!   `audio-micmute` module trigger registers). The AML paths are
//!   DSDT-verified (2026-11-26, P14s `dsdt.aml`); Daniel
//!   hardware-tests registration on the P14s.
//!
//! The module backend's KABI calls are exercised by the `.ko` build
//! (`cargo narf build build-module` compiles + `nm -u` gate) and by the
//! KABI-side smokes in `modules/src/kabi_platform.rs`; there is no
//! fixture for a ThinkPad HKEY device.

use core::sync::atomic::{AtomicU32, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::defs::{
    GenericLed, HIDS, HID_TABLE, KBD_IDX, LED_DEFS, MICMUTE_IDX, MICMUTE_NOTIFY, MUTE_IDX,
    SAFE_GENERIC_LEDS,
};
use crate::driver::{self, Backend};
use crate::quad;

// ── Fake backend ─────────────────────────────────────────────────────

/// A test double for `Backend`: availability is a bitmask
/// (bit 0 kbdlight, 1 generic, 2 mute, 3 micmute), the "hardware"
/// kbdlight level is a cell, and every set is recorded.
struct FakeBackend {
    avail: AtomicU32,
    kbd_level: AtomicU32,
    last_kbd: AtomicU32,
    last_generic: AtomicU32,
    last_mute: AtomicU32,
    last_micmute: AtomicU32,
    fail_next: AtomicU32,
}

impl FakeBackend {
    const fn new(avail: u32, kbd_level: u32) -> Self {
        Self {
            avail: AtomicU32::new(avail),
            kbd_level: AtomicU32::new(kbd_level),
            last_kbd: AtomicU32::new(u32::MAX),
            last_generic: AtomicU32::new(u32::MAX),
            last_mute: AtomicU32::new(u32::MAX),
            last_micmute: AtomicU32::new(u32::MAX),
            fail_next: AtomicU32::new(0),
        }
    }

    fn fail_next_set(&self) {
        self.fail_next.store(1, Ordering::Release);
    }

    fn take_fail(&self) -> bool {
        self.fail_next.swap(0, Ordering::AcqRel) != 0
    }
}

impl Backend for FakeBackend {
    fn kbdlight_supported(&self) -> bool {
        self.avail.load(Ordering::Acquire) & 1 != 0
    }
    fn set_kbdlight(&self, level: u8) -> Result<(), ()> {
        if self.take_fail() {
            return Err(());
        }
        self.last_kbd.store(u32::from(level), Ordering::Release);
        Ok(())
    }
    fn get_kbdlight(&self) -> Result<u8, ()> {
        Ok(self.kbd_level.load(Ordering::Acquire) as u8)
    }
    fn generic_available(&self) -> bool {
        self.avail.load(Ordering::Acquire) & 2 != 0
    }
    fn set_generic(&self, index: u8, on: bool) -> Result<(), ()> {
        if self.take_fail() {
            return Err(());
        }
        self.last_generic
            .store((u32::from(index) << 8) | u32::from(on), Ordering::Release);
        Ok(())
    }
    fn mute_available(&self) -> bool {
        self.avail.load(Ordering::Acquire) & 4 != 0
    }
    fn set_mute(&self, on: bool) -> Result<(), ()> {
        if self.take_fail() {
            return Err(());
        }
        self.last_mute.store(u32::from(on), Ordering::Release);
        Ok(())
    }
    fn micmute_available(&self) -> bool {
        self.avail.load(Ordering::Acquire) & 8 != 0
    }
    fn set_micmute(&self, on: bool) -> Result<(), ()> {
        if self.take_fail() {
            return Err(());
        }
        self.last_micmute.store(u32::from(on), Ordering::Release);
        Ok(())
    }
}

fn reset() {
    driver::__reset_for_test();
    crate::builtin::__reset_for_test();
}

// ── defs ─────────────────────────────────────────────────────────────

fn smoke_thinkpad_led_defs() -> TestResult {
    if LED_DEFS.len() != 7 {
        return TestResult::Fail("LED_DEFS must hold exactly seven LEDs");
    }
    if LED_DEFS[KBD_IDX].name != "tpacpi::kbd_backlight"
        || LED_DEFS[KBD_IDX].max_brightness != 2
        || LED_DEFS[KBD_IDX].default_trigger.is_some()
    {
        return TestResult::Fail("kbdlight def is wrong (name/max 2/no default)");
    }
    if LED_DEFS[MUTE_IDX].name != "platform::mute"
        || LED_DEFS[MUTE_IDX].max_brightness != 1
        || LED_DEFS[MUTE_IDX].default_trigger != Some("audio-mute")
    {
        return TestResult::Fail("mute def is wrong (name/max 1/audio-mute default)");
    }
    if LED_DEFS[MICMUTE_IDX].name != "platform::micmute"
        || LED_DEFS[MICMUTE_IDX].max_brightness != 1
        || LED_DEFS[MICMUTE_IDX].default_trigger != Some("audio-micmute")
    {
        return TestResult::Fail("micmute def is wrong (name/max 1/audio-micmute default)");
    }
    // Names unique; generic indices are exactly the safe set.
    for (i, a) in LED_DEFS.iter().enumerate() {
        for b in &LED_DEFS[i + 1..] {
            if a.name == b.name {
                return TestResult::Fail("duplicate LED name in LED_DEFS");
            }
        }
        if let crate::defs::LedKind::Generic(index) = a.kind {
            if GenericLed::from_index(index).is_none() {
                return TestResult::Fail("generic def index is outside the safe set");
            }
            if SAFE_GENERIC_LEDS & (1u16 << index) == 0 {
                return TestResult::Fail("generic def index is not in TPACPI_SAFE_LEDS");
            }
        }
    }
    if GenericLed::from_index(1).is_some() || GenericLed::from_index(8).is_some() {
        return TestResult::Fail("restricted generic indices must not map (battery 1, kbdlight 8)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/thinkpad-led", smoke_thinkpad_led_defs);

fn smoke_thinkpad_led_hids_buffer() -> TestResult {
    // The NUL-separated buffer must spell exactly the HID table.
    let mut parts = HIDS.split(|b| *b == 0);
    for hid in HID_TABLE {
        match parts.next() {
            Some(part) if part == hid.as_bytes() => {}
            _ => return TestResult::Fail("HIDS buffer does not match HID_TABLE"),
        }
    }
    if parts.next() != Some(&[][..]) || parts.next().is_some() {
        return TestResult::Fail("HIDS buffer must end with exactly one trailing NUL");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_led_hids_buffer
);

// ── quad codec ───────────────────────────────────────────────────────

fn smoke_thinkpad_led_quad_codec() -> TestResult {
    // Encode MLCG(0): one quad, tag 0, value 0, reserved zero.
    let mut quads = [0u8; 64];
    let n = match quad::encode_integer_args(&[0], &mut quads) {
        Ok(n) => n,
        Err(()) => return TestResult::Fail("encode of one Integer arg must succeed"),
    };
    if n != quad::QUAD_LEN {
        return TestResult::Fail("one Integer arg must encode to exactly one quad");
    }
    if quads[0..4] != quad::TAG_INTEGER.to_le_bytes()
        || quads[4..8] != [0u8; 4]
        || quads[8..16] != [0u8; 8]
        || quads[16..32] != [0u8; 16]
    {
        return TestResult::Fail("encoded Integer quad layout is wrong");
    }
    // Two args: LED(index, value).
    let n = match quad::encode_integer_args(&[10, 0x80], &mut quads) {
        Ok(n) => n,
        Err(()) => return TestResult::Fail("encode of two Integer args must succeed"),
    };
    if n != 2 * quad::QUAD_LEN || u64::from_le_bytes(quads[40..48].try_into().unwrap()) != 0x80 {
        return TestResult::Fail("two-arg encode is wrong");
    }
    // Too-small buffer rejected.
    let mut small = [0u8; 32];
    if quad::encode_integer_args(&[1, 2], &mut small).is_ok() {
        return TestResult::Fail("encode into a too-small buffer must fail");
    }
    // Decode an Integer result.
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&quad::TAG_INTEGER.to_le_bytes());
    out[8..16].copy_from_slice(&0x60C0u64.to_le_bytes());
    if quad::decode_integer_result(&out) != Ok(0x60C0) {
        return TestResult::Fail("Integer result must decode");
    }
    // Wrong tag / short buffer rejected.
    out[0..4].copy_from_slice(&quad::TAG_STRING.to_le_bytes());
    if quad::decode_integer_result(&out).is_ok() {
        return TestResult::Fail("non-Integer result must be rejected");
    }
    if quad::decode_integer_result(&out[..31]).is_ok() {
        return TestResult::Fail("short result buffer must be rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_led_quad_codec
);

// ── shared driver logic (fake backend) ───────────────────────────────

fn smoke_thinkpad_led_driver_logic() -> TestResult {
    reset();
    let backend = FakeBackend::new(0xF, 2);
    // Availability per kind.
    if !LED_DEFS
        .iter()
        .all(|def| driver::def_available(&backend, def))
    {
        return TestResult::Fail("all defs must be available with a full fake backend");
    }
    let none = FakeBackend::new(0, 0);
    if LED_DEFS.iter().any(|def| driver::def_available(&none, def)) {
        return TestResult::Fail("no def must be available with an empty fake backend");
    }
    // Clamping: kbdlight level 5 clamps to max 2.
    driver::set_led(&backend, KBD_IDX, 5);
    if driver::get_led(KBD_IDX) != 2 || backend.last_kbd.load(Ordering::Acquire) != 2 {
        return TestResult::Fail("kbdlight set must clamp to max 2");
    }
    // Generic on/off through the index.
    driver::set_led(&backend, 3, 1);
    // Def index 3 is power, generic index 0; the backend records
    // (generic_index << 8 | value) = 1.
    if driver::get_led(3) != 1 || backend.last_generic.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("generic LED set must reach the backend as (index 0, on)");
    }
    // A failed set leaves the cache (and the readback) unchanged.
    backend.fail_next_set();
    driver::set_led(&backend, KBD_IDX, 1);
    if driver::get_led(KBD_IDX) != 2 {
        return TestResult::Fail("failed set must not update the last-written cache");
    }
    // Kbdlight re-seed from hardware: clear the cache first so the
    // seeded value can only have come from the backend's read.
    reset();
    driver::seed_kbdlight(&backend);
    if driver::get_led(KBD_IDX) != 2 {
        return TestResult::Fail("kbdlight seed must read the hardware level (2)");
    }
    // 0x60C0 re-asserts the last mic-mute state; other values ignore.
    driver::set_led(&backend, MICMUTE_IDX, 1);
    backend.last_micmute.store(u32::MAX, Ordering::Release);
    driver::on_notify(&backend, MICMUTE_NOTIFY);
    if backend.last_micmute.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("0x60C0 must re-assert micmute on");
    }
    backend.last_micmute.store(u32::MAX, Ordering::Release);
    driver::on_notify(&backend, 0x1001);
    if backend.last_micmute.load(Ordering::Acquire) != u32::MAX {
        return TestResult::Fail("a non-0x60C0 notify must not touch micmute");
    }
    // Unknown def index is a no-op, never a panic.
    driver::set_led(&backend, 99, 1);
    if driver::get_led(99) != 0 {
        return TestResult::Fail("unknown def index must read 0");
    }
    reset();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_led_driver_logic
);

// ── builtin probe on non-ThinkPad hardware ───────────────────────────

fn smoke_thinkpad_led_builtin_probe_no_hardware() -> TestResult {
    narf_drivers_leds::__reset_all_for_test();
    reset();
    crate::builtin::register();
    if !narf_drivers_leds::led_devices().is_empty() {
        return TestResult::Fail("builtin probe must register nothing without ThinkPad AML");
    }
    narf_drivers_leds::__reset_all_for_test();
    reset();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_led_builtin_probe_no_hardware
);

#[cfg(feature = "kernel-test")]
/// `builtin::register()` against the ThinkPad LED fixture publishes
/// all seven LEDs with the `LED_DEFS` maxima, resolves the builtin
/// `audio-mute` default trigger immediately, and leaves the
/// `platform::micmute` default pending until the `audio-micmute`
/// module trigger registers.
///
/// The micmute default stays `Trigger::None` at registration time
/// on purpose: `"audio-micmute"` is a module trigger, and no module
/// trigger is registered in this harness, so `set_led_default_trigger`
/// records it pending and `resolve_pending_defaults_for` only fires
/// when a module trigger of that name registers. A test asserting
/// micmute already carries a module trigger here would be wrong.
fn smoke_thinkpad_led_builtin_register_with_fixture() -> TestResult {
    use narf_drivers_leds::Trigger;
    // SAFETY: serialized test; the scope puts the boot namespace back
    // on drop, after the fixture replaced it (backlight idiom).
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    narf_drivers_leds::__reset_all_for_test();
    reset();
    if let Err(e) = install_thinkpad_led_fixture() {
        return TestResult::Fail(e);
    }

    crate::builtin::register();

    let devs = narf_drivers_leds::led_devices();
    if devs.len() != LED_DEFS.len() {
        return TestResult::Fail("builtin register must publish all seven LEDs on the fixture");
    }
    // Every def is present with its `LED_DEFS` maximum, and its
    // current trigger matches its default: the builtin `audio-mute`
    // default resolves immediately on `platform::mute`; the other
    // six stay `Trigger::None` — micmute's `audio-micmute` default
    // is pending (see the doc comment).
    for (idx, def) in LED_DEFS.iter().enumerate() {
        let dev = match devs.iter().find(|d| d.name() == def.name) {
            Some(dev) => dev,
            None => return TestResult::Fail("a LED_DEF LED is missing from the registry"),
        };
        if dev.max_brightness() != def.max_brightness {
            return TestResult::Fail("registered LED max_brightness does not match LED_DEFS");
        }
        let want = if idx == MUTE_IDX {
            Trigger::AudioMute
        } else {
            Trigger::None
        };
        if dev.current_trigger() != want {
            return TestResult::Fail("registered LED trigger does not match its default");
        }
    }
    // The pending default resolves when the module trigger registers.
    let handle = match narf_drivers_leds::triggers::register_module_trigger(
        "audio-micmute",
        alloc::sync::Arc::new(|max: u32, _ticks: u32| max),
    ) {
        Ok(handle) => handle,
        Err(_) => return TestResult::Fail("audio-micmute module-trigger registration failed"),
    };
    let micmute = match narf_drivers_leds::lookup_led_by_name(LED_DEFS[MICMUTE_IDX].name) {
        Some(dev) => dev,
        None => return TestResult::Fail("micmute LED is missing from the registry"),
    };
    if micmute.current_trigger() != Trigger::Module(handle) {
        return TestResult::Fail("micmute default did not resolve to the audio-micmute trigger");
    }
    narf_drivers_leds::__reset_all_for_test();
    reset();
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_led_builtin_register_with_fixture
);

// ── AML fixture helpers (moved from lane 2, drivers/platform/src/tests.rs) ──
// These build the nested ThinkPad LED fixture AML by hand. The
// shared byte builders (fx_wrap, fx_name_word, fx_name_byte,
// fx_name_int) are duplicated here from the platform tests —
// test-only builders, precedented by the backlight fixture's own
// copies — so the LED tests travel with the driver they test.

#[cfg(feature = "kernel-test")]
/// PkgLength + NameString(`\SEG`) + body wrapper for Device /
/// ThermalZone terms (ExtOpPrefix + ext op).
fn fx_wrap(ext_op: u8, seg: &[u8; 4], inside: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    // PkgLength counts the PkgLength field itself.
    let rest = 1 + 4 + inside.len(); // NameString (root + seg) + inside
    let value = if rest + 1 < 64 { rest + 1 } else { rest + 2 };
    let mut v = Vec::new();
    v.push(0x5B); // ExtOpPrefix
    v.push(ext_op);
    if value < 64 {
        v.push(value as u8);
    } else {
        v.push(0x40 | (value as u8 & 0x0F));
        v.push((value >> 4) as u8);
    }
    v.push(b'\\');
    v.extend_from_slice(seg);
    v.extend_from_slice(inside);
    v
}

#[cfg(feature = "kernel-test")]
/// Name(seg, WordPrefix value).
fn fx_name_word(seg: &[u8; 4], value: u16) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut v = Vec::new();
    v.push(0x08); // NameOp
    v.extend_from_slice(seg);
    v.push(0x0B); // WordPrefix
    v.extend_from_slice(&value.to_le_bytes());
    v
}

#[cfg(feature = "kernel-test")]
/// Name(seg, BytePrefix value).
fn fx_name_byte(seg: &[u8; 4], value: u8) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut v = Vec::new();
    v.push(0x08); // NameOp
    v.extend_from_slice(seg);
    v.push(0x0A); // BytePrefix
    v.push(value);
    v
}

#[cfg(feature = "kernel-test")]
/// Read an Integer Name node back out of the namespace.
fn fx_name_int(path: &str) -> Option<u64> {
    match narf_aml::find_node(path).and_then(|n| n.value) {
        Some(narf_aml::NameValue::Integer(v)) => Some(v),
        _ => None,
    }
}

#[cfg(feature = "kernel-test")]
fn fx_scope(seg: &[u8; 4], inside: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let rest = 1 + 4 + inside.len();
    let value = if rest + 1 < 64 { rest + 1 } else { rest + 2 };
    let mut v = Vec::new();
    v.push(0x10); // ScopeOp
    if value < 64 {
        v.push(value as u8);
    } else {
        v.push(0x40 | (value as u8 & 0x0F));
        v.push((value >> 4) as u8);
    }
    v.push(b'\\');
    v.extend_from_slice(seg);
    v.extend_from_slice(inside);
    v
}

#[cfg(feature = "kernel-test")]
/// Fully-qualified multi-segment NameString: root char +
/// MultiNamePrefix + segment count + segments (the backlight
/// fixture's `root_multi_name`).
fn fx_ref_multi(segs: &[&[u8; 4]]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut v = Vec::new();
    v.push(b'\\');
    v.push(0x2F); // MultiNamePrefix
    v.push(segs.len() as u8);
    for s in segs {
        v.extend_from_slice(*s);
    }
    v
}

#[cfg(feature = "kernel-test")]
/// MethodOp with a solved 1- or 2-byte PkgLength. The `fx_method`
/// helper assumes a 1-byte length, which breaks once a body with
/// two fully-qualified refs reaches 64 bytes — the LED method does
/// (58-byte body → length 64, which a 1-byte PkgLength would
/// mis-decode as a 2-byte form).
fn fx_method_wide(seg: &[u8; 4], flags: u8, body: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let content = 4 + 1 + body.len(); // name + flags + body
    let mut width = 1usize;
    let mut len = width + content;
    if len >= 64 {
        width = 2;
        len = width + content;
    }
    let mut v = Vec::new();
    v.push(0x14); // MethodOp
    if width == 1 {
        v.push(len as u8);
    } else {
        v.push(0x40 | (len as u8 & 0x0F));
        v.push((len >> 4) as u8);
    }
    v.extend_from_slice(seg);
    v.push(flags);
    v.extend_from_slice(body);
    v
}

#[cfg(feature = "kernel-test")]
/// Nested ThinkPad LED fixture (mechanism record §1):
///
/// ```asl
/// Scope (\_SB) {
///     Device (PCI0) {
///         Device (LPC0) {
///             Device (EC0) {
///                 Name (LEDI, 0xAA)   // sentinel: never written
///                 Name (LEDV, 0xAA)
///                 Method (LED, 2) {
///                     Store (Arg0, \_SB.PCI0.LPC0.EC0.LEDI)
///                     Store (Arg1, \_SB.PCI0.LPC0.EC0.LEDV)
///                 }
///                 Device (HKEY) {
///                     Name (MLVL, 0x200)  // bit 9 set, level 0
///                     Name (SMUT, 0xAA)
///                     Name (MMUT, 0xAA)
///                     Method (MLCS, 1) { Add (Arg0, 0x200, MLVL) }
///                     Method (MLCG, 1) { Return (MLVL) }
///                     Method (SSMS, 1) { Store (Arg0, SMUT) }
///                     Method (MMTS, 1) { Store (Arg0, MMUT) }
///                 }
///             }
///         }
///     }
/// }
/// ```
///
/// The paths are the production `HKEY_PATH` / `EC_PATH` constants,
/// so the tests drive the real call paths. `MLCS` folds the level
/// into `MLVL` with bit 9 set (the Linux kbdlight probe's
/// discriminator), so `MLCG` both proves support and round-trips
/// the level. Sentinels are values no setter can produce.
fn fx_thinkpad_leds() -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;

    /// Absolute path to a Name under the HKEY device.
    fn hkey_ref(name: &[u8; 4]) -> Vec<u8> {
        fx_ref_multi(&[b"_SB_", b"PCI0", b"LPC0", b"EC0_", b"HKEY", name])
    }
    /// Absolute path to a Name under the EC device.
    fn ec_ref(name: &[u8; 4]) -> Vec<u8> {
        fx_ref_multi(&[b"_SB_", b"PCI0", b"LPC0", b"EC0_", name])
    }

    // Device (HKEY) { MLVL/SMUT/MMUT, MLCS/MLCG/SSMS/MMTS }
    let mut hkey = Vec::new();
    // MLVL starts at 0x200: MLCG bit 9 set (probe passes), level 0.
    hkey.extend_from_slice(&fx_name_word(b"MLVL", 0x200));
    hkey.extend_from_slice(&fx_name_byte(b"SMUT", 0xAA));
    hkey.extend_from_slice(&fx_name_byte(b"MMUT", 0xAA));
    // Method (MLCS, 1) { Add (Arg0, 0x200, MLVL) }
    let mut mlcs = alloc::vec![0x72, 0x68, 0x0B, 0x00, 0x02]; // AddOp, Arg0, Word 0x200
    mlcs.extend_from_slice(&hkey_ref(b"MLVL"));
    hkey.extend_from_slice(&fx_method_wide(b"MLCS", 1, &mlcs));
    // Method (MLCG, 1) { Return (MLVL) }
    let mut mlcg = alloc::vec![0xA4]; // ReturnOp
    mlcg.extend_from_slice(&hkey_ref(b"MLVL"));
    hkey.extend_from_slice(&fx_method_wide(b"MLCG", 1, &mlcg));
    // Method (SSMS, 1) { Store (Arg0, SMUT) }
    let mut ssms = alloc::vec![0x70, 0x68]; // StoreOp, Arg0
    ssms.extend_from_slice(&hkey_ref(b"SMUT"));
    hkey.extend_from_slice(&fx_method_wide(b"SSMS", 1, &ssms));
    // Method (MMTS, 1) { Store (Arg0, MMUT) }
    let mut mmts = alloc::vec![0x70, 0x68]; // StoreOp, Arg0
    mmts.extend_from_slice(&hkey_ref(b"MMUT"));
    hkey.extend_from_slice(&fx_method_wide(b"MMTS", 1, &mmts));
    let hkey_dev = fx_wrap(0x82, b"HKEY", &hkey);

    // Device (EC0) { LEDI/LEDV, Method (LED, 2), HKEY }
    let mut ec = Vec::new();
    ec.extend_from_slice(&fx_name_byte(b"LEDI", 0xAA));
    ec.extend_from_slice(&fx_name_byte(b"LEDV", 0xAA));
    // Method (LED, 2) { Store (Arg0, LEDI); Store (Arg1, LEDV) }
    let mut led = alloc::vec![0x70, 0x68]; // StoreOp, Arg0
    led.extend_from_slice(&ec_ref(b"LEDI"));
    led.extend_from_slice(&[0x70, 0x69]); // StoreOp, Arg1
    led.extend_from_slice(&ec_ref(b"LEDV"));
    ec.extend_from_slice(&fx_method_wide(b"LED_", 2, &led));
    ec.extend_from_slice(&hkey_dev);
    let ec_dev = fx_wrap(0x82, b"EC0_", &ec);

    // Device (LPC0) { EC0 } → Device (PCI0) { LPC0 } → Scope (\_SB)
    let lpc0 = fx_wrap(0x82, b"LPC0", &ec_dev);
    let pci0 = fx_wrap(0x82, b"PCI0", &lpc0);
    fx_scope(b"_SB_", &pci0)
}

#[cfg(feature = "kernel-test")]
/// Parse the LED fixture into the (scoped) namespace; fail the
/// test if the parse or any expected node is missing. Exactly 15
/// nodes: Scope \_SB + Devices PCI0/LPC0/EC0/HKEY + Names
/// MLVL/SMUT/MMUT/LEDI/LEDV + Methods MLCS/MLCG/SSMS/MMTS/LED.
fn install_thinkpad_led_fixture() -> Result<(), &'static str> {
    use crate::defs::{
        EC_LED_PATH, HKEY_MLCG_PATH, HKEY_MLCS_PATH, HKEY_MMTS_PATH, HKEY_SSMS_PATH,
    };
    let blob = fx_thinkpad_leds();
    let parsed =
        narf_aml::__parse_body_for_test(&blob, "\\\\").map_err(|_| "LED fixture parse failed")?;
    if parsed != 15 {
        return Err("LED fixture parsed an unexpected node count");
    }
    for p in [
        EC_LED_PATH,
        HKEY_MLCS_PATH,
        HKEY_MLCG_PATH,
        HKEY_SSMS_PATH,
        HKEY_MMTS_PATH,
    ] {
        if narf_aml::find_node(p).is_none() {
            return Err("LED fixture method missing from the namespace");
        }
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
/// The LED fixture's methods resolve at the production paths.
fn smoke_thinkpad_led_fixture_paths() -> TestResult {
    // SAFETY: serialized test; the scope puts the boot namespace back
    // on drop, after the fixture replaced it (backlight idiom).
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    reset();
    match install_thinkpad_led_fixture() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_led_fixture_paths
);

#[cfg(feature = "kernel-test")]
/// Generic-LED sets write the exact Linux argument shapes
/// (`led_set_status`: index + 0x00/0x80/0xC0) and update the cache.
fn smoke_thinkpad_generic_led_set_writes_index_and_arg() -> TestResult {
    use crate::builtin::{generic_led_state, set_generic_led, LedState};
    // SAFETY: serialized test; the scope puts the boot namespace back
    // on drop, after the fixture replaced it (backlight idiom).
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    reset();
    if let Err(e) = install_thinkpad_led_fixture() {
        return TestResult::Fail(e);
    }

    // Power on: LED(0, 0x80).
    if set_generic_led(0, LedState::On).is_err() {
        return TestResult::Fail("set_generic_led(0, On) failed");
    }
    if fx_name_int("\\\\_SB.PCI0.LPC0.EC0.LEDI") != Some(0)
        || fx_name_int("\\\\_SB.PCI0.LPC0.EC0.LEDV") != Some(0x80)
    {
        return TestResult::Fail("LED(0, On) did not write index 0 / arg 0x80");
    }
    if generic_led_state(0) != Some(LedState::On) {
        return TestResult::Fail("cache did not record power On");
    }
    // Standby blink: LED(7, 0xC0).
    if set_generic_led(7, LedState::Blink).is_err() {
        return TestResult::Fail("set_generic_led(7, Blink) failed");
    }
    if fx_name_int("\\\\_SB.PCI0.LPC0.EC0.LEDI") != Some(7)
        || fx_name_int("\\\\_SB.PCI0.LPC0.EC0.LEDV") != Some(0xC0)
    {
        return TestResult::Fail("LED(7, Blink) did not write index 7 / arg 0xC0");
    }
    if generic_led_state(7) != Some(LedState::Blink) {
        return TestResult::Fail("cache did not record standby Blink");
    }
    // ThinkVantage off: LED(12, 0x00).
    if set_generic_led(12, LedState::Off).is_err() {
        return TestResult::Fail("set_generic_led(12, Off) failed");
    }
    if fx_name_int("\\\\_SB.PCI0.LPC0.EC0.LEDI") != Some(12)
        || fx_name_int("\\\\_SB.PCI0.LPC0.EC0.LEDV") != Some(0x00)
    {
        return TestResult::Fail("LED(12, Off) did not write index 12 / arg 0x00");
    }
    if generic_led_state(12) != Some(LedState::Off) {
        return TestResult::Fail("cache did not record thinkvantage Off");
    }
    // Lid-logo-dot on: LED(10, 0x80) — and the power cache entry
    // from the first set is untouched (per-index state).
    if set_generic_led(10, LedState::On).is_err() {
        return TestResult::Fail("set_generic_led(10, On) failed");
    }
    if generic_led_state(0) != Some(LedState::On) || generic_led_state(10) != Some(LedState::On) {
        return TestResult::Fail("per-index cache entries interfered");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_generic_led_set_writes_index_and_arg
);

#[cfg(feature = "kernel-test")]
/// Restricted and out-of-range generic-LED indices are rejected
/// without touching AML (the audit's trap: index 8 is dock_status1,
/// restricted — not the kbdlight; battery 1/2 are restricted too).
fn smoke_thinkpad_generic_led_rejects_restricted_and_oob() -> TestResult {
    use crate::builtin::{set_generic_led, LedError, LedState};
    use crate::defs::GenericLed;
    // SAFETY: serialized test; the scope puts the boot namespace back
    // on drop, after the fixture replaced it (backlight idiom).
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    reset();
    if let Err(e) = install_thinkpad_led_fixture() {
        return TestResult::Fail(e);
    }

    for idx in [1u8, 2, 3, 4, 5, 6, 8, 9, 11, 13, 14, 15] {
        if set_generic_led(idx, LedState::On) != Err(LedError::RestrictedIndex(idx)) {
            return TestResult::Fail("restricted generic-LED index was not rejected");
        }
    }
    for idx in [16u8, 255] {
        if set_generic_led(idx, LedState::On) != Err(LedError::InvalidIndex(idx)) {
            return TestResult::Fail("out-of-range generic-LED index was not rejected");
        }
    }
    // No AML call happened: the LED argument cells still hold their
    // sentinels.
    if fx_name_int("\\\\_SB.PCI0.LPC0.EC0.LEDI") != Some(0xAA)
        || fx_name_int("\\\\_SB.PCI0.LPC0.EC0.LEDV") != Some(0xAA)
    {
        return TestResult::Fail("rejected set still wrote to the LED method");
    }
    // The safe-index type only admits the four safe LEDs.
    if GenericLed::from_index(0) != Some(GenericLed::Power)
        || GenericLed::from_index(7) != Some(GenericLed::Standby)
        || GenericLed::from_index(10) != Some(GenericLed::LidLogoDot)
        || GenericLed::from_index(12) != Some(GenericLed::ThinkVantage)
    {
        return TestResult::Fail("GenericLed::from_index missed a safe LED");
    }
    if GenericLed::from_index(1).is_some() || GenericLed::from_index(8).is_some() {
        return TestResult::Fail("GenericLed::from_index admitted a restricted index");
    }
    if GenericLed::Power.linux_name() != "tpacpi::power"
        || GenericLed::ThinkVantage.linux_name() != "tpacpi::thinkvantage"
    {
        return TestResult::Fail("GenericLed Linux names wrong");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_generic_led_rejects_restricted_and_oob
);

#[cfg(feature = "kernel-test")]
/// Kbdlight set/get round-trips through MLCS/MLCG, the support
/// probe is the full Linux bit-9 test, and level 3 is rejected.
fn smoke_thinkpad_kbdlight_set_get_round_trip() -> TestResult {
    use crate::builtin::{get_kbdlight_level, kbdlight_supported, set_kbdlight_level, LedError};
    // SAFETY: serialized test; the scope puts the boot namespace back
    // on drop, after the fixture replaced it (backlight idiom).
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    reset();
    if let Err(e) = install_thinkpad_led_fixture() {
        return TestResult::Fail(e);
    }

    // Fixture MLVL starts at 0x200: bit 9 set, level 0.
    if !kbdlight_supported() {
        return TestResult::Fail("kbdlight probe failed on the fixture");
    }
    if get_kbdlight_level() != Ok(0) {
        return TestResult::Fail("initial kbdlight level != 0");
    }
    if set_kbdlight_level(2).is_err() || get_kbdlight_level() != Ok(2) {
        return TestResult::Fail("kbdlight set(2)/get did not round-trip");
    }
    if set_kbdlight_level(1).is_err() || get_kbdlight_level() != Ok(1) {
        return TestResult::Fail("kbdlight set(1)/get did not round-trip");
    }
    if set_kbdlight_level(0).is_err() || get_kbdlight_level() != Ok(0) {
        return TestResult::Fail("kbdlight set(0)/get did not round-trip");
    }
    // Level 3 is outside the classdev max (2): rejected, and the
    // firmware cell is untouched.
    if set_kbdlight_level(3) != Err(LedError::InvalidLevel(3)) {
        return TestResult::Fail("kbdlight level 3 was not rejected");
    }
    if fx_name_int("\\\\_SB.PCI0.LPC0.EC0.HKEY.MLVL") != Some(0x200) {
        return TestResult::Fail("rejected kbdlight set still wrote MLVL");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_kbdlight_set_get_round_trip
);

#[cfg(feature = "kernel-test")]
/// Mute/micmute sets write the exact Linux argument shapes
/// (SSMS 1/0, MMTS 2/0), and the 0x60C0 notify re-asserts the
/// cached mic-mute state through the shared handler. (The HKEY
/// dispatch that maps 0x60C0 to the handler lives in
/// `thinkpad_acpi.rs` and is covered by its decode tests plus
/// hardware; this smoke drives the handler itself.)
fn smoke_thinkpad_mute_micmute_set() -> TestResult {
    use crate::builtin::{micmute_available, micmute_state, mute_available, set_micmute, set_mute};
    // SAFETY: serialized test; the scope puts the boot namespace back
    // on drop, after the fixture replaced it (backlight idiom).
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    reset();
    if let Err(e) = install_thinkpad_led_fixture() {
        return TestResult::Fail(e);
    }

    if !mute_available() || !micmute_available() {
        return TestResult::Fail("mute/micmute methods not reported available");
    }
    if set_mute(true).is_err() || fx_name_int("\\\\_SB.PCI0.LPC0.EC0.HKEY.SMUT") != Some(1) {
        return TestResult::Fail("SSMS(1) did not write mute on");
    }
    if set_mute(false).is_err() || fx_name_int("\\\\_SB.PCI0.LPC0.EC0.HKEY.SMUT") != Some(0) {
        return TestResult::Fail("SSMS(0) did not write mute off");
    }
    if set_micmute(true).is_err() || fx_name_int("\\\\_SB.PCI0.LPC0.EC0.HKEY.MMUT") != Some(2) {
        return TestResult::Fail("MMTS(2) did not write micmute on");
    }
    if !micmute_state() {
        return TestResult::Fail("micmute cache did not record on");
    }
    // 0x60C0 re-asserts the cached state through the shared handler.
    driver::on_notify(&crate::builtin::BuiltinBackend, 0x60C0);
    if fx_name_int("\\\\_SB.PCI0.LPC0.EC0.HKEY.MMUT") != Some(2) {
        return TestResult::Fail("0x60C0 notify did not re-assert micmute on");
    }
    if set_micmute(false).is_err() || fx_name_int("\\\\_SB.PCI0.LPC0.EC0.HKEY.MMUT") != Some(0) {
        return TestResult::Fail("MMTS(0) did not write micmute off");
    }
    if micmute_state() {
        return TestResult::Fail("micmute cache did not record off");
    }
    driver::on_notify(&crate::builtin::BuiltinBackend, 0x60C0);
    if fx_name_int("\\\\_SB.PCI0.LPC0.EC0.HKEY.MMUT") != Some(0) {
        return TestResult::Fail("0x60C0 notify did not re-assert micmute off");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_mute_micmute_set
);

#[cfg(feature = "kernel-test")]
/// With no LED methods in the namespace, the probes report
/// unavailable and every setter fails closed without an AML call.
/// (No fixture is installed here — the scoped namespace starts
/// empty, so absence is exact, not order-dependent.)
fn smoke_thinkpad_led_methods_absent() -> TestResult {
    use crate::builtin::{
        get_kbdlight_level, kbdlight_supported, micmute_available, mute_available, set_generic_led,
        set_kbdlight_level, set_micmute, set_mute, LedError, LedState,
    };
    // SAFETY: serialized test; the scope puts the boot namespace back
    // on drop (backlight idiom). No fixture is installed.
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    reset();

    if kbdlight_supported() || mute_available() || micmute_available() {
        return TestResult::Fail("absent LED methods reported available");
    }
    if set_mute(true) != Err(LedError::MethodUnavailable("SSMS")) {
        return TestResult::Fail("set_mute did not fail closed on absent SSMS");
    }
    if set_micmute(true) != Err(LedError::MethodUnavailable("MMTS")) {
        return TestResult::Fail("set_micmute did not fail closed on absent MMTS");
    }
    if set_kbdlight_level(1) != Err(LedError::Aml(narf_aml::AmlError::MethodNotFound)) {
        return TestResult::Fail("set_kbdlight_level did not fail closed on absent MLCS");
    }
    if get_kbdlight_level() != Err(LedError::Aml(narf_aml::AmlError::MethodNotFound)) {
        return TestResult::Fail("get_kbdlight_level did not fail closed on absent MLCG");
    }
    if set_generic_led(0, LedState::On) != Err(LedError::Aml(narf_aml::AmlError::MethodNotFound)) {
        return TestResult::Fail("set_generic_led did not fail closed on absent LED");
    }
    // Index validation still precedes the AML call when absent.
    if set_generic_led(1, LedState::On) != Err(LedError::RestrictedIndex(1)) {
        return TestResult::Fail("restricted-index check did not precede the AML call");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/platform/thinkpad-led",
    smoke_thinkpad_led_methods_absent
);
