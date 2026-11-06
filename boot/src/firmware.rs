//! Firmware-table pointers the bootloader handed over, kept for
//! consumers that run long after `parse_raw` (the SMBIOS / DMI scan in
//! `firmware/smbios/`).
//!
//! Linux's `dmi_scan_machine` finds the SMBIOS entry point through the
//! EFI configuration table (`efi.smbios3` / `efi.smbios`) on EFI
//! systems and the 0xF0000 anchor scan otherwise. NARF does not run as
//! an EFI stub; on x86_64 it is entered over multiboot2 (Limine, GRUB)
//! or PVH (QEMU `-kernel`). Multiboot2 carries the two pieces Linux's
//! EFI path needs:
//!
//! - tag 12 (`EFI 64-bit system table pointer`): the system table
//!   whose configuration table lists `SMBIOS3_TABLE_GUID` /
//!   `SMBIOS_TABLE_GUID`;
//! - tag 13 (`SMBIOS tables`): the loader's copy of the entry-point
//!   structure itself (Limine emits one tag per entry point it found,
//!   `_SM_` and/or `_SM3_`).
//!
//! The multiboot2 information structure is transient, so the
//! entry-point bytes are copied here during `parse_raw`.

/// One entry-point structure copied out of a multiboot2 SMBIOS tag.
/// `bytes[..len]` is the structure as the loader copied it; the rest
/// is zero (Linux reads entry points into a zeroed 32-byte buffer).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SmbiosEntryCopy {
    pub bytes: [u8; 32],
    pub len: u8,
}

impl SmbiosEntryCopy {
    /// Copy at most 32 bytes of `src`.
    pub fn new(src: &[u8]) -> Self {
        let n = src.len().min(32);
        let mut bytes = [0u8; 32];
        bytes[..n].copy_from_slice(&src[..n]);
        Self {
            bytes,
            len: n as u8,
        }
    }
}

/// What the loader told us about firmware tables. All `None` on a
/// protocol that carries none of it (PVH, aarch64 DTB entry).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FirmwareHandoff {
    /// Physical address of the EFI system table (multiboot2 tag 12).
    pub efi_system_table: Option<u64>,
    /// First multiboot2 SMBIOS tag whose payload starts `_SM3_`.
    pub smbios3_entry: Option<SmbiosEntryCopy>,
    /// First multiboot2 SMBIOS tag whose payload starts `_SM_`.
    pub smbios_entry: Option<SmbiosEntryCopy>,
}

impl FirmwareHandoff {
    pub const EMPTY: Self = Self {
        efi_system_table: None,
        smbios3_entry: None,
        smbios_entry: None,
    };
}

static mut HANDOFF: FirmwareHandoff = FirmwareHandoff::EMPTY;

/// Record the handoff. Called once from the per-arch `parse_raw`.
///
/// # Safety
/// Single-threaded boot path: no reader may run concurrently.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) unsafe fn store(h: FirmwareHandoff) {
    // SAFETY: caller contract — single writer before any reader.
    unsafe { core::ptr::addr_of_mut!(HANDOFF).write(h) };
}

/// The firmware tables the bootloader passed. [`FirmwareHandoff::EMPTY`]
/// before `parse_raw` runs and on protocols that carry none.
pub fn firmware_handoff() -> FirmwareHandoff {
    // SAFETY: written once in `parse_raw` before any other CPU or task
    // runs; every later access is a read of a `Copy` value.
    unsafe { core::ptr::addr_of!(HANDOFF).read() }
}

// ── EFI configuration-table lookup for the TPM event logs (#1071) ──

/// `EFI_SYSTEM_TABLE_SIGNATURE` ("IBI SYST", UEFI 2.10 §4).
pub const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;

/// NARF bound on EFI configuration-table entries walked (Linux
/// trusts `nr_tables`; a corrupt count must not make the walk read
/// unbounded memory). Same bound as `firmware/smbios`'s
/// `MAX_EFI_CONFIG_TABLES`, same rationale.
pub const MAX_EFI_CONFIG_TABLES: u64 = 1024;

/// Locate one EFI configuration-table entry by GUID.
///
/// Reads the EFI system table at `efi_system_table` through `read`
/// (`false` = the range cannot be read) and walks its configuration
/// table array, returning the entry's table address. Mirrors
/// `firmware/smbios`'s `efi_smbios_tables` (same systab layout:
/// signature check, `nr_tables` u64 @104, `tables` u64 @112,
/// 24-byte `{GUID, u64}` entries, entry count capped at
/// [`MAX_EFI_CONFIG_TABLES`]).
///
/// `guid` is compared in EFI wire byte order (data1/data2/data3
/// little-endian, tail verbatim) — pass a
/// `narf_efi::variable::Guid`'s `.0` bytes.
pub fn find_efi_config_table(
    efi_system_table: u64,
    guid: &[u8; 16],
    read: &dyn Fn(u64, &mut [u8]) -> bool,
) -> Option<u64> {
    let mut st = [0u8; 120];
    if !read(efi_system_table, &mut st) {
        return None;
    }
    if u64::from_le_bytes(st[0..8].try_into().unwrap()) != EFI_SYSTEM_TABLE_SIGNATURE {
        return None;
    }
    let nr = u64::from_le_bytes(st[104..112].try_into().unwrap());
    let tables = u64::from_le_bytes(st[112..120].try_into().unwrap());
    for i in 0..nr.min(MAX_EFI_CONFIG_TABLES) {
        // efi_config_table_64_t { efi_guid_t guid; u64 table; }
        let mut e = [0u8; 24];
        if !read(tables.wrapping_add(i * 24), &mut e) {
            break;
        }
        if e[0..16] == *guid {
            return Some(u64::from_le_bytes(e[16..24].try_into().unwrap()));
        }
    }
    None
}

/// The firmware TPM event-log tables visible through the EFI
/// configuration table, if any.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Tcg2LogTables {
    /// `LINUX_EFI_TPM_EVENT_LOG_GUID` table: the main TCG2 event
    /// log wrapped in a `linux_efi_tpm_eventlog` header (installed
    /// by an EFI stub or a bootloader following that convention).
    pub main_log: Option<u64>,
    /// `EFI_TCG2_FINAL_EVENTS_TABLE_GUID` table: the final-events
    /// table (events logged after the last `GetEventLog` call).
    pub final_events: Option<u64>,
}

/// Surface the firmware TCG2 event-log tables to `frame::measure`
/// (#1071): walk the EFI configuration table from the system-table
/// pointer the bootloader handed over
/// ([`FirmwareHandoff::efi_system_table`], multiboot2 tag 12) and
/// locate both log tables. `None` fields mean the table is absent
/// (non-EFI boot, or firmware/a bootloader that does not publish
/// that log) — never an error: the caller reports the absence and
/// the measured-boot cross-check surfaces the resulting gap
/// instead of assuming a log exists.
pub fn tcg2_log_tables(
    efi_system_table: u64,
    read: &dyn Fn(u64, &mut [u8]) -> bool,
) -> Tcg2LogTables {
    Tcg2LogTables {
        main_log: find_efi_config_table(
            efi_system_table,
            &narf_efi::tcg2::LINUX_EFI_TPM_EVENT_LOG_GUID.0,
            read,
        ),
        final_events: find_efi_config_table(
            efi_system_table,
            &narf_efi::tcg2::EFI_TCG2_FINAL_EVENTS_TABLE_GUID.0,
            read,
        ),
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_firmware_tcg2_log_tables_found() -> TestResult {
        // Fake physical memory: system table at 0x1000, config
        // table at 0x2000 with three entries.
        let mut mem = [0u8; 0x3000];
        mem[0x1000..0x1008].copy_from_slice(&EFI_SYSTEM_TABLE_SIGNATURE.to_le_bytes());
        mem[0x1000 + 104..0x1000 + 112].copy_from_slice(&3u64.to_le_bytes());
        mem[0x1000 + 112..0x1000 + 120].copy_from_slice(&0x2000u64.to_le_bytes());
        // Entry 0: an unrelated GUID (SMBIOS3) — must be skipped.
        let smbios3: [u8; 16] = [
            0x44, 0x15, 0xfd, 0xf2, 0x94, 0x97, 0x2c, 0x4a, 0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20,
            0xe3, 0x94,
        ];
        mem[0x2000..0x2010].copy_from_slice(&smbios3);
        mem[0x2010..0x2018].copy_from_slice(&0x5000u64.to_le_bytes());
        // Entry 1: the final-events table.
        mem[0x2018..0x2028].copy_from_slice(&narf_efi::tcg2::EFI_TCG2_FINAL_EVENTS_TABLE_GUID.0);
        mem[0x2028..0x2030].copy_from_slice(&0x3000u64.to_le_bytes());
        // Entry 2: the Linux main-log table.
        mem[0x2030..0x2040].copy_from_slice(&narf_efi::tcg2::LINUX_EFI_TPM_EVENT_LOG_GUID.0);
        mem[0x2040..0x2048].copy_from_slice(&0x4000u64.to_le_bytes());
        let read = |phys: u64, out: &mut [u8]| -> bool {
            let start = phys as usize;
            let Some(end) = start.checked_add(out.len()) else {
                return false;
            };
            if end > mem.len() {
                return false;
            }
            out.copy_from_slice(&mem[start..end]);
            true
        };
        let tables = tcg2_log_tables(0x1000, &read);
        if tables.main_log != Some(0x4000) {
            return TestResult::Fail("main log table not found");
        }
        if tables.final_events != Some(0x3000) {
            return TestResult::Fail("final-events table not found");
        }
        // An unknown GUID matches nothing.
        if find_efi_config_table(0x1000, &[0xAAu8; 16], &read).is_some() {
            return TestResult::Fail("unknown GUID matched");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/firmware", smoke_firmware_tcg2_log_tables_found);

    fn smoke_firmware_tcg2_log_tables_absent() -> TestResult {
        let mem = [0u8; 0x3000];
        let read = |phys: u64, out: &mut [u8]| -> bool {
            let start = phys as usize;
            let Some(end) = start.checked_add(out.len()) else {
                return false;
            };
            if end > mem.len() {
                return false;
            }
            out.copy_from_slice(&mem[start..end]);
            true
        };
        // All-zero memory: no "IBI SYST" signature.
        if tcg2_log_tables(0x1000, &read) != Tcg2LogTables::default() {
            return TestResult::Fail("zeroed memory yielded tables");
        }
        // Unreadable system table.
        if tcg2_log_tables(0x9000, &read) != Tcg2LogTables::default() {
            return TestResult::Fail("unreadable systab yielded tables");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/firmware", smoke_firmware_tcg2_log_tables_absent);
}
