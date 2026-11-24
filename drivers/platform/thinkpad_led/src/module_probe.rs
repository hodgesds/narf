//! Loadable ThinkPad LED frontend (module build only).
//!
//! Registers the ACPI driver through the KABI (`narf_register_acpi_driver`),
//! evaluates AML methods through the quad stream
//! (`narf_aml_evaluate_method`, see `quad.rs`), and registers LEDs
//! through `narf_led_register`. The shared probe/register/set logic
//! lives in `driver.rs` behind the `Backend` trait; this file is the
//! KABI-shaped half.
//!
//! Availability is necessarily coarser than the builtin backend's:
//! there is no method-exists export, so `mute`/`micmute`/generic
//! availability is "the HKEY / EC device exists" (the methods live
//! on those devices; a missing method surfaces as a failed set,
//! which the driver tolerates — the LED stays registered but does
//! not drive hardware). The kbdlight probe is exact: `MLCG(0)` is
//! a read, so the bit-9 test runs unchanged. If a machine ever
//! needs per-method probing from a module, that is a new export
//! (`narf_aml_method_exists`), not a reason to write hardware at
//! probe time.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::defs::{
    EC_HID, EC_LED_PATH, HIDS, HKEY_MLCG_PATH, HKEY_MLCS_PATH, HKEY_MMTS_PATH, HKEY_SSMS_PATH,
    LED_DEFS,
};
use crate::driver::{self, Backend};
use crate::quad;

unsafe extern "C" {
    fn narf_register_acpi_driver(
        name: *const u8,
        name_len: usize,
        hids: *const u8,
        hids_len: usize,
        probe: usize,
        remove: usize,
        cookie: u64,
    ) -> i32;
    fn narf_unregister_acpi_driver() -> i32;
    #[allow(clippy::too_many_arguments)]
    fn narf_aml_evaluate_method(
        path: *const u8,
        path_len: usize,
        arg_quads: *const u8,
        arg_quads_len: usize,
        arg_payload: *const u8,
        arg_payload_len: usize,
        out: *mut u8,
        out_len: usize,
        out_needed: *mut usize,
    ) -> i32;
    fn narf_acpi_find_devices_by_hid(
        hid: *const u8,
        hid_len: usize,
        out_buf: *mut u8,
        out_buf_len: usize,
        out_count: *mut usize,
        out_needed: *mut usize,
    ) -> i32;
    fn narf_acpi_register_notify_handler(
        path: *const u8,
        path_len: usize,
        handler: usize,
        cookie: u64,
    ) -> i32;
    fn narf_acpi_unregister_notify_handler(path: *const u8, path_len: usize, handler: usize)
        -> i32;
    #[allow(clippy::too_many_arguments)]
    fn narf_led_register(
        name: *const u8,
        name_len: usize,
        max_brightness: u32,
        set_brightness: usize,
        get_brightness: usize,
        set_trigger: usize,
        cookie: u64,
        default_trigger: *const u8,
        default_trigger_len: usize,
    ) -> i32;
    fn narf_led_unregister(name: *const u8, name_len: usize) -> i32;
}

/// Driver name in the ACPI registry.
const DRIVER_NAME: &[u8] = b"thinkpad-led";

/// Whether probe() has run (LEDs register once, even if several
/// HKEY devices match).
static PROBED: AtomicBool = AtomicBool::new(false);

/// Bitmask of LED def indices registered with the LED class (for
/// `remove` / `exit`).
static REGISTERED: AtomicU32 = AtomicU32::new(0);

/// Whether an EC device (`PNP0C09`) was found at probe time
/// (generic-LED availability).
static EC_FOUND: AtomicBool = AtomicBool::new(false);

// ── AML evaluation ───────────────────────────────────────────────────

/// Evaluate an AML method that takes Integer arguments and returns
/// an Integer, through the KABI quad stream. Starts with a 256-byte
/// result scratch (design §4.3) and retries once on `-ENOSPC` with
/// a buffer sized to `out_needed` (up to 1024 bytes — an Integer
/// result needs 32, so the retry never fires for this driver's
/// methods, but the loop is implemented as designed). Returns the
/// Integer value, or the negative errno.
fn eval_int_method(path: &str, args: &[u64]) -> Result<u64, i32> {
    let mut quads = [0u8; 2 * quad::QUAD_LEN];
    let quads_len = quad::encode_integer_args(args, &mut quads).map_err(|_| -22)?;
    let mut out = [0u8; 256];
    let mut needed = 0usize;
    // SAFETY: the path and quad bytes are live for the call; `out`
    // names 256 writable bytes; `out_needed` names a live local.
    let rc = unsafe {
        narf_aml_evaluate_method(
            path.as_ptr(),
            path.len(),
            quads.as_ptr(),
            quads_len,
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut needed,
        )
    };
    if rc == -28 && needed > out.len() && needed <= 1024 {
        // `-ENOSPC`: retry once with the required size.
        let mut big = [0u8; 1024];
        let mut needed2 = 0usize;
        // SAFETY: same as above; `big` names 1024 writable bytes.
        let rc2 = unsafe {
            narf_aml_evaluate_method(
                path.as_ptr(),
                path.len(),
                quads.as_ptr(),
                quads_len,
                core::ptr::null(),
                0,
                big.as_mut_ptr(),
                big.len(),
                &mut needed2,
            )
        };
        if rc2 != 0 {
            return Err(rc2);
        }
        return quad::decode_integer_result(&big[..needed2]).map_err(|_| -22);
    }
    if rc != 0 {
        return Err(rc);
    }
    quad::decode_integer_result(&out[..needed]).map_err(|_| -22)
}

/// Size query: does any device with this HID exist? A null output
/// buffer is a size query — `-ENOSPC` with `out_needed > 0` means
/// devices exist, `0` with `out_needed == 0` means none.
fn any_device_with_hid(hid: &str) -> bool {
    let mut count = 0usize;
    let mut needed = 0usize;
    // SAFETY: the HID bytes are live; the output pointers are null
    // with length 0 (the size-query form); the count/needed locals
    // are live.
    let rc = unsafe {
        narf_acpi_find_devices_by_hid(
            hid.as_ptr(),
            hid.len(),
            core::ptr::null_mut(),
            0,
            &mut count,
            &mut needed,
        )
    };
    rc == 0 || (rc == -28 && needed > 0)
}

// ── Backend ──────────────────────────────────────────────────────────

/// The module backend: the same operations as the builtin backend,
/// through the KABI exports.
#[derive(Debug)]
pub struct ModuleBackend;

impl Backend for ModuleBackend {
    fn kbdlight_supported(&self) -> bool {
        match eval_int_method(HKEY_MLCG_PATH, &[0]) {
            Ok(v) => v & (1u64 << 9) != 0,
            Err(_) => false,
        }
    }

    fn set_kbdlight(&self, level: u8) -> Result<(), ()> {
        eval_int_method(HKEY_MLCS_PATH, &[u64::from(level)])
            .map(|_| ())
            .map_err(|_| ())
    }

    fn get_kbdlight(&self) -> Result<u8, ()> {
        eval_int_method(HKEY_MLCG_PATH, &[0])
            .map(|v| (v & 0x3) as u8)
            .map_err(|_| ())
    }

    fn generic_available(&self) -> bool {
        // No method-exists export: the EC device's presence stands
        // for the LED object's presence (see the module doc).
        EC_FOUND.load(Ordering::Acquire)
    }

    fn set_generic(&self, index: u8, on: bool) -> Result<(), ()> {
        eval_int_method(
            EC_LED_PATH,
            &[u64::from(index), if on { 0x80 } else { 0x00 }],
        )
        .map(|_| ())
        .map_err(|_| ())
    }

    fn mute_available(&self) -> bool {
        // The HKEY device's presence stands for `SSMS` (see the
        // module doc). Probe ran, so an HKEY device matched.
        PROBED.load(Ordering::Acquire)
    }

    fn set_mute(&self, on: bool) -> Result<(), ()> {
        eval_int_method(HKEY_SSMS_PATH, &[if on { 1 } else { 0 }])
            .map(|_| ())
            .map_err(|_| ())
    }

    fn micmute_available(&self) -> bool {
        PROBED.load(Ordering::Acquire)
    }

    fn set_micmute(&self, on: bool) -> Result<(), ()> {
        eval_int_method(HKEY_MMTS_PATH, &[if on { 2 } else { 0 }])
            .map(|_| ())
            .map_err(|_| ())
    }
}

/// The single module backend instance.
static BACKEND: ModuleBackend = ModuleBackend;

// ── C callbacks ──────────────────────────────────────────────────────

/// LED `set_brightness` callback: cookie is the def index.
extern "C" fn led_set_brightness(cookie: u64, level: u32) {
    driver::set_led(&BACKEND, cookie as usize, level);
}

/// LED `get_brightness` callback: cookie is the def index.
extern "C" fn led_get_brightness(cookie: u64) -> u32 {
    driver::get_led(cookie as usize)
}

/// HKEY notify callback: shared 0x60C0 re-assert. The target path
/// is the HKEY device this handler was subscribed on; the value is
/// what matters.
extern "C" fn notify_c(_cookie: u64, _path: *const u8, _path_len: usize, value: u64) {
    driver::on_notify(&BACKEND, value);
}

/// ACPI probe callback, called through the module call gate for
/// each already-enumerated device matching the HID table. The first
/// probe registers the LEDs; later probes (a second HKEY device)
/// return 0 without re-registering. Returns 0 to claim the device.
extern "C" fn probe_c(_cookie: u64, path_ptr: *const u8, path_len: usize) -> i32 {
    if PROBED.swap(true, Ordering::AcqRel) {
        return 0;
    }
    if path_ptr.is_null() || path_len == 0 {
        return -22;
    }
    EC_FOUND.store(any_device_with_hid(EC_HID), Ordering::Release);
    // Subscribe to HKEY notifies on this device (the 0x60C0 arm).
    // A failure leaves the LEDs working without the re-assert —
    // the probe still claims the device.
    // SAFETY: the path bytes are live for the call (they name the
    // device just probed); the handler stays mapped while
    // subscribed (unload removes it first).
    let _ = unsafe { narf_acpi_register_notify_handler(path_ptr, path_len, notify_c as usize, 0) };
    driver::seed_kbdlight(&BACKEND);
    for (idx, def) in LED_DEFS.iter().enumerate() {
        if !driver::def_available(&BACKEND, def) {
            continue;
        }
        let (trig_ptr, trig_len) = match def.default_trigger {
            Some(t) => (t.as_ptr(), t.len()),
            None => (core::ptr::null(), 0),
        };
        // SAFETY: the name/trigger bytes are static; the callbacks
        // stay mapped while registered (unload removes them first).
        let rc = unsafe {
            narf_led_register(
                def.name.as_ptr(),
                def.name.len(),
                def.max_brightness,
                led_set_brightness as usize,
                led_get_brightness as usize,
                0,
                idx as u64,
                trig_ptr,
                trig_len,
            )
        };
        if rc == 0 {
            REGISTERED.fetch_or(1u32 << idx, Ordering::AcqRel);
        }
    }
    0
}

/// ACPI remove callback: unregister every LED this probe
/// registered, and unsubscribe the notify handler for this device's
/// path. Invoked from `narf_unregister_acpi_driver` on the exit
/// path (module still Live), and from the loader backstop's
/// per-family sweep when it is not.
extern "C" fn remove_c(_cookie: u64, path_ptr: *const u8, path_len: usize) {
    let registered = REGISTERED.swap(0, Ordering::AcqRel);
    for (idx, def) in LED_DEFS.iter().enumerate() {
        if registered & (1u32 << idx) == 0 {
            continue;
        }
        // SAFETY: the name bytes are static.
        let _ = unsafe { narf_led_unregister(def.name.as_ptr(), def.name.len()) };
    }
    if !path_ptr.is_null() && path_len != 0 {
        // SAFETY: the path bytes are live for the call.
        let _ =
            unsafe { narf_acpi_unregister_notify_handler(path_ptr, path_len, notify_c as usize) };
    }
}

// ── Registration ─────────────────────────────────────────────────────

/// Register the ACPI driver (module init). The kernel re-matches
/// already-enumerated devices and calls [`probe_c`] for each match.
/// A registration failure means the driver does not bind; there is
/// no log channel from a module, so the failure is silent (the
/// loader reports the module as loaded but unbound).
pub fn register() {
    // SAFETY: the name and HID bytes are static; the callbacks stay
    // mapped while registered (unload removes them first).
    let _ = unsafe {
        narf_register_acpi_driver(
            DRIVER_NAME.as_ptr(),
            DRIVER_NAME.len(),
            HIDS.as_ptr(),
            HIDS.len(),
            probe_c as usize,
            remove_c as usize,
            0,
        )
    };
}

/// Unregister the ACPI driver (module exit). The kernel invokes
/// [`remove_c`] for each claimed device first, which unregisters
/// the LEDs and the notify handler.
pub fn exit() {
    // SAFETY: no pointers cross; the driver was registered by
    // `register` (or the call is a `-ENODEV` no-op).
    unsafe {
        narf_unregister_acpi_driver();
    }
}
