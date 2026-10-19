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
