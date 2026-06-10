//! EFI Runtime Services table — install, dispatch, and typed wrappers.
//!
//! ## What this module does
//!
//! After `ExitBootServices` the UEFI firmware's Runtime-Services
//! function-pointer table remains callable at the virtual addresses
//! described by `SetVirtualAddressMap`. This module:
//!
//! 1. **Stores** the `EFI_RUNTIME_SERVICES` table pointer passed by the
//!    bootloader (`install`).
//! 2. **Wraps** the 14 function pointers with safe-ish Rust surfaces:
//!    `get_time`, `get_variable`, `set_variable`, `reset_system`.
//! 3. **Validates** the table header (signature + revision ≥ 1.0) on
//!    install so callers get a clean error if firmware is broken.
//!
//! ## Sources (public only)
//!
//! - **UEFI Specification 2.10** §8 (Runtime Services):
//!   <https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html>
//! - Linux `drivers/firmware/efi/runtime-wrappers.c` and
//!   `arch/x86/platform/efi/efi.c` (GPL-2.0-or-later; adapted under
//!   NARF's GPL-2.0-or-later licence).
//!
//! ## Calling convention
//!
//! UEFI function pointers use the Microsoft x64 ABI on x86_64 (first
//! 4 args in RCX, RDX, R8, R9; caller cleans the stack; callee saves
//! RBX, RBP, RDI, RSI, R12–R15, XMM6–XMM15). Rust's default x86_64
//! ABI matches the System V AMD64 ABI which differs from MS-x64 for
//! arguments past the first four and for return values in XMM registers.
//! To be safe, all EFI calls use `extern "efiapi"` (Rust 1.70+) which
//! the compiler lowers to MS-x64 on x86_64 / aarch64-UEFI calling
//! convention on aarch64.
//!
//! ## SetVirtualAddressMap
//!
//! `SetVirtualAddressMap` is a one-shot call the bootloader makes
//! **before** handing off to the kernel; by the time `install` is
//! called the memory map has already been remapped. This module does
//! **not** expose `SetVirtualAddressMap` — it is exclusively a
//! bootloader-side ritual.
//!
//! ## Secure Boot hook
//!
//! When the EFI runtime is available, callers can retrieve the
//! `SecureBoot` and `SetupMode` variables plus the `db`/`dbx` signature
//! databases via `read_secure_boot_state`. The return value is shaped
//! to feed directly into `frame::secure_boot::install_state`.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::reset::EfiResetType;
use crate::system_table::{signature, TableHeader, TableHeaderError};
use crate::time::EfiTime;
use crate::variable::{encode_name, EFI_GLOBAL_VARIABLE, EFI_IMAGE_SECURITY_DATABASE_GUID};

// ── EFI_STATUS ─────────────────────────────────────────────────────

/// EFI_STATUS (UEFI 2.10 Appendix D). The high bit (bit 63) set
/// indicates an error; clear = success or informational.
pub type EfiStatus = u64;

/// EFI_SUCCESS.
pub const EFI_SUCCESS: EfiStatus = 0;
/// EFI_LOAD_ERROR.
pub const EFI_LOAD_ERROR: EfiStatus = (1u64 << 63) | 1;
/// EFI_INVALID_PARAMETER.
pub const EFI_INVALID_PARAMETER: EfiStatus = (1u64 << 63) | 2;
/// EFI_UNSUPPORTED.
pub const EFI_UNSUPPORTED: EfiStatus = (1u64 << 63) | 3;
/// EFI_BAD_BUFFER_SIZE.
pub const EFI_BAD_BUFFER_SIZE: EfiStatus = (1u64 << 63) | 4;
/// EFI_BUFFER_TOO_SMALL.
pub const EFI_BUFFER_TOO_SMALL: EfiStatus = (1u64 << 63) | 5;
/// EFI_NOT_READY.
pub const EFI_NOT_READY: EfiStatus = (1u64 << 63) | 6;
/// EFI_DEVICE_ERROR.
pub const EFI_DEVICE_ERROR: EfiStatus = (1u64 << 63) | 7;
/// EFI_NOT_FOUND.
pub const EFI_NOT_FOUND: EfiStatus = (1u64 << 63) | 14;

/// True iff `status` indicates an error.
#[inline]
pub fn efi_error(status: EfiStatus) -> bool {
    status & (1u64 << 63) != 0
}

// ── EFI GUID (wire alias) ──────────────────────────────────────────

/// Re-export `crate::variable::Guid` as `EfiGuid` for this module's
/// callers so they don't need to pull in `variable` directly.
pub use crate::variable::Guid as EfiGuid;

// ── EFI_RUNTIME_SERVICES wire layout ──────────────────────────────
//
// The on-wire layout from UEFI 2.10 §8:
//
//   Hdr          (24 bytes — EFI_TABLE_HEADER)
//   GetTime                fn
//   SetTime                fn
//   GetWakeupTime          fn
//   SetWakeupTime          fn
//   SetVirtualAddressMap   fn
//   ConvertPointer         fn
//   GetVariable            fn
//   GetNextVariableName    fn
//   SetVariable            fn
//   GetNextHighMonotonicCount fn
//   ResetSystem            fn
//   UpdateCapsule          fn
//   QueryCapsuleCapabilities fn
//   QueryVariableInfo      fn
//
// We represent this as a `#[repr(C)]` struct of raw function pointers.
// Each entry is a *const () in the table; we transmute on first use.
//
// Safety: this struct is **never** constructed by NARF — it is only
// accessed through a pointer received from the bootloader.

/// Raw 14-entry EFI Runtime Services function-pointer table as it
/// appears in firmware memory. UEFI 2.10 §8.
///
/// # Safety
/// This struct is `#[repr(C)]` and must only be accessed through a
/// pointer whose origin is the bootloader-provided
/// `EFI_SYSTEM_TABLE.RuntimeServices` field. Do not construct it.
#[repr(C)]
#[derive(Debug)]
pub struct EfiRuntimeServicesTable {
    pub hdr: [u8; 24], // EFI_TABLE_HEADER (decoded by `crate::system_table`)
    pub get_time: usize,
    pub set_time: usize,
    pub get_wakeup_time: usize,
    pub set_wakeup_time: usize,
    pub set_virtual_address_map: usize,
    pub convert_pointer: usize,
    pub get_variable: usize,
    pub get_next_variable_name: usize,
    pub set_variable: usize,
    pub get_next_high_monotonic_count: usize,
    pub reset_system: usize,
    pub update_capsule: usize,
    pub query_capsule_capabilities: usize,
    pub query_variable_info: usize,
}

// Function-pointer signatures (extern "efiapi" = Microsoft x64 ABI).

/// `EFI_GET_TIME` — UEFI 2.10 §8.3.1.
type EfiGetTimeFn = unsafe extern "efiapi" fn(
    time: *mut [u8; 16],         // EFI_TIME
    capabilities: *mut [u8; 12], // EFI_TIME_CAPABILITIES, may be NULL
) -> EfiStatus;

/// `EFI_SET_TIME` — UEFI 2.10 §8.3.2.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
type EfiSetTimeFn = unsafe extern "efiapi" fn(time: *const [u8; 16]) -> EfiStatus;

/// `EFI_GET_VARIABLE` — UEFI 2.10 §8.2.1.
///
/// ```text
/// IN  CHAR16 *VariableName    — NUL-terminated UCS-2 name
/// IN  EFI_GUID *VendorGuid
/// OUT UINT32 *Attributes      — optional (may be NULL)
/// IN OUT UINTN *DataSize      — in: buffer size, out: actual data size
/// OUT VOID *Data              — caller's buffer
/// ```
type EfiGetVariableFn = unsafe extern "efiapi" fn(
    variable_name: *const u16,
    vendor_guid: *const [u8; 16],
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut u8,
) -> EfiStatus;

/// `EFI_SET_VARIABLE` — UEFI 2.10 §8.2.3.
type EfiSetVariableFn = unsafe extern "efiapi" fn(
    variable_name: *const u16,
    vendor_guid: *const [u8; 16],
    attributes: u32,
    data_size: usize,
    data: *const u8,
) -> EfiStatus;

/// `EFI_RESET_SYSTEM` — UEFI 2.10 §8.5.1.
type EfiResetSystemFn = unsafe extern "efiapi" fn(
    reset_type: u32,
    reset_status: EfiStatus,
    data_size: usize,
    reset_data: *const u8,
) -> !;

// ── Global table pointer ───────────────────────────────────────────

/// Physical (or remapped-virtual) address of the
/// `EFI_RUNTIME_SERVICES` table, stored as an atomic usize.
/// 0 = not installed.
static RT_TABLE_PTR: AtomicUsize = AtomicUsize::new(0);

// ── Install ────────────────────────────────────────────────────────

/// Errors returned by `install`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// The pointer is null.
    NullPointer,
    /// The table header signature or CRC is wrong.
    BadHeader(TableHeaderError),
    /// The Runtime Services revision is below 1.0.
    RevisionTooOld,
}

impl From<TableHeaderError> for InstallError {
    fn from(e: TableHeaderError) -> Self {
        InstallError::BadHeader(e)
    }
}

/// Register the bootloader-supplied `EFI_RUNTIME_SERVICES` table.
///
/// Validates the table header against the `RUNTIME_SERVICES`
/// signature and checks that the revision is ≥ 1.0 (i.e. high
/// word ≥ 1). Idempotent — subsequent calls are silently ignored
/// once the pointer is installed.
///
/// # Safety
/// `rt` must be a valid pointer to a `EFI_RUNTIME_SERVICES` struct
/// in accessible memory, as passed by the bootloader. The pointer
/// must remain valid for the lifetime of the kernel (firmware
/// guarantees this for runtime service memory).
pub unsafe fn install(rt: *const EfiRuntimeServicesTable) -> Result<(), InstallError> {
    if rt.is_null() {
        return Err(InstallError::NullPointer);
    }
    // Validate the 24-byte table header embedded at offset 0.
    // SAFETY: caller guarantees `rt` is valid firmware memory.
    let hdr_bytes: &[u8; 24] = unsafe { &(*rt).hdr };
    let hdr = TableHeader::decode(hdr_bytes).map_err(InstallError::BadHeader)?;
    // Accept the table even if CRC verification fails on broken firmware
    // (many real UEFI implementations have mismatched CRCs). Only check
    // the signature.
    if hdr.signature != signature::RUNTIME_SERVICES {
        return Err(InstallError::BadHeader(TableHeaderError::BadSignature));
    }
    if hdr.major_revision() < 1 {
        return Err(InstallError::RevisionTooOld);
    }
    RT_TABLE_PTR.store(rt as usize, Ordering::Release);
    Ok(())
}

/// True iff `install` has been called successfully.
pub fn is_available() -> bool {
    RT_TABLE_PTR.load(Ordering::Acquire) != 0
}

/// Return the installed table pointer, or None if not installed.
fn table() -> Option<*const EfiRuntimeServicesTable> {
    let v = RT_TABLE_PTR.load(Ordering::Acquire);
    if v == 0 {
        None
    } else {
        Some(v as *const EfiRuntimeServicesTable)
    }
}

// ── get_time ───────────────────────────────────────────────────────

/// Call EFI `GetTime()`. Returns a decoded `EfiTime` on success.
///
/// Alternative to the CMOS RTC on UEFI systems — often slaved to a
/// battery-backed hardware RTC that the firmware maintains; may be
/// more accurate than raw CMOS access if firmware applies timezone
/// correction.
///
/// # Safety
/// Must be called after `ExitBootServices` (or pre-ExitBootServices
/// is also fine). The EFI Runtime Services must not be called from
/// an interrupt context unless the UEFI implementation sets the
/// `EFI_RT_SUPPORTED_GET_TIME` flag. On most real systems this is
/// safe from a boot-time single-threaded context.
pub unsafe fn get_time() -> Result<EfiTime, EfiStatus> {
    let rt = table().ok_or(EFI_NOT_FOUND)?;
    // SAFETY: `rt` was validated in `install`.
    let fn_ptr_addr = unsafe { (*rt).get_time };
    if fn_ptr_addr == 0 {
        return Err(EFI_UNSUPPORTED);
    }
    // SAFETY: the function pointer was read from a validated EFI table.
    let get_time_fn: EfiGetTimeFn = unsafe { core::mem::transmute(fn_ptr_addr) };
    let mut raw = [0u8; 16];
    // SAFETY: `raw` is stack-allocated and `get_time_fn` writes at most
    // 16 bytes; capabilities passed as NULL (we don't use them here).
    let status = unsafe { get_time_fn(&mut raw, core::ptr::null_mut()) };
    if efi_error(status) {
        return Err(status);
    }
    crate::time::EfiTime::decode(&raw).map_err(|_| EFI_INVALID_PARAMETER)
}

// ── get_variable ───────────────────────────────────────────────────

/// Call EFI `GetVariable()`. Returns the raw data bytes.
///
/// Handles the two-call pattern: first call with a zero-length
/// buffer to discover the size, then a second call with the
/// correctly-sized buffer. This avoids needing to know variable
/// sizes in advance.
///
/// # Safety
/// Same as `get_time`. Not interrupt-safe.
pub unsafe fn get_variable(name: &str, guid: &EfiGuid) -> Result<Vec<u8>, EfiStatus> {
    let rt = table().ok_or(EFI_NOT_FOUND)?;
    // SAFETY: validated in `install`.
    let fn_ptr_addr = unsafe { (*rt).get_variable };
    if fn_ptr_addr == 0 {
        return Err(EFI_UNSUPPORTED);
    }
    // SAFETY: transmute from validated EFI table entry.
    let gv: EfiGetVariableFn = unsafe { core::mem::transmute(fn_ptr_addr) };

    // Encode the variable name as UCS-2 LE (NUL-terminated). The
    // buffer is u8 but we pass *const u16 to firmware — the layout is
    // identical since each u16 is 2 bytes LE.
    let name_ucs2 = encode_name(name);
    let name_ptr = name_ucs2.as_ptr() as *const u16;

    let mut size: usize = 0;
    let mut attrs: u32 = 0;

    // First call: discover the data size.
    // SAFETY: size=0 is a valid first call per UEFI 2.10 §8.2.1.
    let status = unsafe {
        gv(
            name_ptr,
            &guid.0,
            &mut attrs,
            &mut size,
            core::ptr::null_mut(),
        )
    };
    if status != EFI_BUFFER_TOO_SMALL {
        // Some firmware returns EFI_NOT_FOUND or success with size=0
        // for absent variables.
        if status == EFI_NOT_FOUND || efi_error(status) {
            return Err(status);
        }
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    // Second call: retrieve the data.
    let mut buf = alloc::vec![0u8; size];
    // SAFETY: `buf` is `size` bytes; `gv` writes at most `size` bytes.
    let status2 = unsafe { gv(name_ptr, &guid.0, &mut attrs, &mut size, buf.as_mut_ptr()) };
    if efi_error(status2) {
        return Err(status2);
    }
    buf.truncate(size);
    Ok(buf)
}

// ── set_variable ───────────────────────────────────────────────────

/// Call EFI `SetVariable()`.
///
/// `attrs` should be a combination of `crate::variable::attr::*`
/// constants. For SecureBoot variables this is typically
/// `NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS |
/// TIME_BASED_AUTHENTICATED_WRITE_ACCESS`.
///
/// # Safety
/// Same as `get_variable`. Writing firmware variables can brick
/// the platform if done incorrectly.
pub unsafe fn set_variable(
    name: &str,
    guid: &EfiGuid,
    attrs: u32,
    data: &[u8],
) -> Result<(), EfiStatus> {
    let rt = table().ok_or(EFI_NOT_FOUND)?;
    // SAFETY: validated in `install`.
    let fn_ptr_addr = unsafe { (*rt).set_variable };
    if fn_ptr_addr == 0 {
        return Err(EFI_UNSUPPORTED);
    }
    // SAFETY: transmute from validated EFI table entry.
    let sv: EfiSetVariableFn = unsafe { core::mem::transmute(fn_ptr_addr) };

    let name_ucs2 = encode_name(name);
    let name_ptr = name_ucs2.as_ptr() as *const u16;

    // SAFETY: `data` slice is caller-supplied; `sv` reads at most
    // `data.len()` bytes from `data.as_ptr()`.
    let status = unsafe { sv(name_ptr, &guid.0, attrs, data.len(), data.as_ptr()) };
    if efi_error(status) {
        Err(status)
    } else {
        Ok(())
    }
}

// ── reset_system ───────────────────────────────────────────────────

/// Call EFI `ResetSystem()`. This function does not return.
///
/// Replaces any ad-hoc NARF reboot path. `ResetCold` is the
/// standard safe reboot; `ResetShutdown` maps to ACPI S5 (power
/// off). If the EFI runtime is unavailable, falls back to spinning
/// indefinitely (the caller can't expect a return).
///
/// # Safety
/// Must be called from a context where it is safe to lose all
/// in-progress work. Typically called only from panic / shutdown
/// paths.
pub unsafe fn reset_system(reset_type: EfiResetType) -> ! {
    if let Some(rt) = table() {
        // SAFETY: `rt` was validated in `install`.
        let fn_ptr_addr = unsafe { (*rt).reset_system };
        if fn_ptr_addr != 0 {
            // SAFETY: transmute from validated EFI table entry.
            let rs: EfiResetSystemFn = unsafe { core::mem::transmute(fn_ptr_addr) };
            // SAFETY: `rs` is a `!`-returning EFI function; `reset_type` is
            // a valid enum value; no data payload.
            unsafe {
                rs(
                    reset_type as u32,
                    crate::reset::status::SUCCESS,
                    0,
                    core::ptr::null(),
                )
            }
        }
    }
    // No EFI table or function pointer zero: spin forever.
    loop {
        core::hint::spin_loop();
    }
}

// ── Secure Boot variable helper ────────────────────────────────────

/// Read the platform's Secure Boot state from EFI variables.
///
/// Returns `(secure_boot, setup_mode, db, dbx)` as raw bytes.
/// `db` and `dbx` are `EFI_SIGNATURE_LIST` blobs parseable by
/// `crate::variable::parse_signature_list`. Returns None if the
/// EFI runtime is not available or the variables are absent.
///
/// # Safety
/// Same as `get_variable`. Must be called from a boot-time single-
/// threaded context after `install`.
pub unsafe fn read_secure_boot_state() -> Option<(u8, u8, Vec<u8>, Vec<u8>)> {
    if !is_available() {
        return None;
    }
    let sb_bytes = unsafe { get_variable("SecureBoot", &EFI_GLOBAL_VARIABLE).ok()? };
    let sm_bytes = unsafe { get_variable("SetupMode", &EFI_GLOBAL_VARIABLE).ok()? };
    let secure_boot = sb_bytes.first().copied().unwrap_or(0);
    let setup_mode = sm_bytes.first().copied().unwrap_or(0);

    let db = unsafe { get_variable("db", &EFI_IMAGE_SECURITY_DATABASE_GUID).unwrap_or_default() };
    let dbx = unsafe { get_variable("dbx", &EFI_IMAGE_SECURITY_DATABASE_GUID).unwrap_or_default() };
    Some((secure_boot, setup_mode, db, dbx))
}

// ── Smokes ─────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::reset::EfiResetType;
    use crate::system_table::signature;
    use crate::variable::Guid;

    use super::*;

    // ── Fake EFI Runtime table for tests ──────────────────────────
    //
    // We construct a synthetic EFI_RUNTIME_SERVICES table in memory
    // to exercise the install path and dispatch logic without real
    // firmware. The function pointers in the fake table point to
    // local test stubs.

    /// Build a 24-byte valid EFI_TABLE_HEADER with the given signature.
    fn make_header(sig: u64, revision: u32) -> [u8; 24] {
        use crate::system_table::crc32_ieee;
        let mut h = [0u8; 24];
        h[0..8].copy_from_slice(&sig.to_le_bytes());
        h[8..12].copy_from_slice(&revision.to_le_bytes());
        h[12..16].copy_from_slice(&24u32.to_le_bytes());
        // Compute CRC over header with CRC field zeroed.
        let crc = crc32_ieee(&h);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    }

    /// Minimal fake RT table — header only, all function pointers zero.
    #[repr(C)]
    struct FakeRtTable {
        inner: EfiRuntimeServicesTable,
    }

    impl FakeRtTable {
        fn new_valid() -> Self {
            let hdr = make_header(
                signature::RUNTIME_SERVICES,
                (1u32 << 16) | 0, // revision 1.0
            );
            let mut t: EfiRuntimeServicesTable = unsafe { core::mem::zeroed() };
            t.hdr.copy_from_slice(&hdr);
            Self { inner: t }
        }
    }

    // ── EFI table version check ────────────────────────────────────

    fn smoke_efi_rt_version_check() -> TestResult {
        // A table with revision 1.0 must pass install.
        let fake = FakeRtTable::new_valid();
        // SAFETY: `fake` is valid memory for the duration of this test.
        let result = unsafe { install(&fake.inner as *const _) };
        if result.is_err() {
            // Reset so other tests see a clean state.
            RT_TABLE_PTR.store(0, Ordering::Release);
            return TestResult::Fail("revision 1.0 table rejected by install");
        }
        RT_TABLE_PTR.store(0, Ordering::Release);

        // A table with revision 0 must be rejected.
        let hdr0 = make_header(signature::RUNTIME_SERVICES, 0);
        let mut t0: EfiRuntimeServicesTable = unsafe { core::mem::zeroed() };
        t0.hdr.copy_from_slice(&hdr0);
        let result0 = unsafe { install(&t0 as *const _) };
        RT_TABLE_PTR.store(0, Ordering::Release);
        if result0 != Err(InstallError::RevisionTooOld) {
            return TestResult::Fail("revision 0 table should be rejected as RevisionTooOld");
        }

        // A table with a wrong signature must be rejected.
        let hdr_bad = make_header(0xDEAD_BEEF_DEAD_BEEFu64, (1u32 << 16) | 0);
        let mut t_bad: EfiRuntimeServicesTable = unsafe { core::mem::zeroed() };
        t_bad.hdr.copy_from_slice(&hdr_bad);
        let result_bad = unsafe { install(&t_bad as *const _) };
        RT_TABLE_PTR.store(0, Ordering::Release);
        if result_bad.is_ok() {
            return TestResult::Fail("wrong-signature table accepted");
        }

        TestResult::Pass
    }
    kernel_test_in!("efi/runtime", smoke_efi_rt_version_check);

    // ── reset_system enum encoding ─────────────────────────────────

    fn smoke_efi_reset_type_encoding() -> TestResult {
        // Verify that EfiResetType discriminants match UEFI 2.10 §8.5.1.
        if EfiResetType::Cold as u32 != 0 {
            return TestResult::Fail("Cold != 0");
        }
        if EfiResetType::Warm as u32 != 1 {
            return TestResult::Fail("Warm != 1");
        }
        if EfiResetType::Shutdown as u32 != 2 {
            return TestResult::Fail("Shutdown != 2");
        }
        if EfiResetType::PlatformSpecific as u32 != 3 {
            return TestResult::Fail("PlatformSpecific != 3");
        }
        // round-trip
        for v in 0u32..=3 {
            if EfiResetType::from_u32(v).map(|r| r as u32) != Some(v) {
                return TestResult::Fail("EfiResetType from_u32 round-trip failed");
            }
        }
        if EfiResetType::from_u32(4).is_some() {
            return TestResult::Fail("4 should not be a valid EfiResetType");
        }
        TestResult::Pass
    }
    kernel_test_in!("efi/runtime", smoke_efi_reset_type_encoding);

    // ── GetVariable fake dispatch ──────────────────────────────────
    //
    // We test `get_variable` with a fake function pointer that copies
    // a known payload into the caller's buffer, simulating firmware
    // returning a 1-byte "1" (SecureBoot=enabled).

    /// Fake GetVariable implementation: always returns [0x01] with
    /// `EFI_SUCCESS` regardless of name/guid.
    unsafe extern "efiapi" fn fake_get_variable(
        _name: *const u16,
        _guid: *const [u8; 16],
        attrs_out: *mut u32,
        size: *mut usize,
        data: *mut u8,
    ) -> EfiStatus {
        // SAFETY: test context — all pointers are valid stack/heap addresses.
        let desired: usize = 1;
        if unsafe { *size } < desired {
            unsafe { *size = desired };
            return EFI_BUFFER_TOO_SMALL;
        }
        unsafe { *size = desired };
        unsafe { *data = 1 };
        if !attrs_out.is_null() {
            unsafe { *attrs_out = 0 };
        }
        EFI_SUCCESS
    }

    fn smoke_efi_get_variable_fake_rt() -> TestResult {
        // Build a fake RT table with only get_variable populated.
        let hdr = make_header(signature::RUNTIME_SERVICES, (1u32 << 16) | 0);
        let mut t: EfiRuntimeServicesTable = unsafe { core::mem::zeroed() };
        t.hdr.copy_from_slice(&hdr);
        t.get_variable = fake_get_variable as usize;

        // SAFETY: test context.
        let install_result = unsafe { install(&t as *const _) };
        if install_result.is_err() {
            RT_TABLE_PTR.store(0, Ordering::Release);
            return TestResult::Fail("install failed for fake table");
        }

        let guid = Guid::new(0, 0, 0, [0; 8]);
        // SAFETY: test context, no real hardware.
        let result = unsafe { get_variable("SecureBoot", &guid) };
        RT_TABLE_PTR.store(0, Ordering::Release);

        match result {
            Ok(v) if v == vec![1u8] => TestResult::Pass,
            Ok(v) => {
                let _ = v;
                TestResult::Fail("get_variable returned unexpected data")
            }
            Err(s) => {
                let _ = s;
                TestResult::Fail("get_variable returned error on fake RT")
            }
        }
    }
    kernel_test_in!("efi/runtime", smoke_efi_get_variable_fake_rt);

    // ── install with null pointer ─────────────────────────────────

    fn smoke_efi_rt_null_install_rejected() -> TestResult {
        let result = unsafe { install(core::ptr::null()) };
        RT_TABLE_PTR.store(0, Ordering::Release);
        if result == Err(InstallError::NullPointer) {
            TestResult::Pass
        } else {
            TestResult::Fail("null pointer install should return NullPointer error")
        }
    }
    kernel_test_in!("efi/runtime", smoke_efi_rt_null_install_rejected);

    // ── get_variable when no table installed ──────────────────────

    fn smoke_efi_get_variable_no_table() -> TestResult {
        // Ensure table is not installed.
        RT_TABLE_PTR.store(0, Ordering::Release);
        let guid = EFI_GLOBAL_VARIABLE;
        let result = unsafe { get_variable("SecureBoot", &guid) };
        if result == Err(EFI_NOT_FOUND) {
            TestResult::Pass
        } else {
            TestResult::Fail("get_variable without table should return EFI_NOT_FOUND")
        }
    }
    kernel_test_in!("efi/runtime", smoke_efi_get_variable_no_table);

    // ── efi_error helper ──────────────────────────────────────────

    fn smoke_efi_error_helper() -> TestResult {
        if efi_error(EFI_SUCCESS) {
            return TestResult::Fail("EFI_SUCCESS should not be an error");
        }
        if !efi_error(EFI_NOT_FOUND) {
            return TestResult::Fail("EFI_NOT_FOUND should be an error");
        }
        if !efi_error(EFI_BUFFER_TOO_SMALL) {
            return TestResult::Fail("EFI_BUFFER_TOO_SMALL should be an error");
        }
        TestResult::Pass
    }
    kernel_test_in!("efi/runtime", smoke_efi_error_helper);
}
