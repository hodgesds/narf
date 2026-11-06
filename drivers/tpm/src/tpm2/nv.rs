//! TPM 2.0 NV (Non-Volatile) index management.
//!
//! NV indices are persistent storage slots inside the TPM. They are
//! used for:
//!
//! - Storing sealed encryption keys or policy hashes.
//! - Persisting boot counters / monotonic counters.
//! - Storing UEFI Secure Boot databases (PK, KEK, db) when the TPM
//!   is used as the authoritative store.
//!
//! ## Index ranges (TCG Part 2 §7.8)
//!
//! ```text
//! 0x01000000–0x01FFFFFF  Platform manufacturer / OEM
//! 0x01400000–0x01BFFFFF  TCG sub-group assignments
//! 0x01500000–0x01500FFE  NARF-reserved range (per project convention)
//! 0x01C00000–0x01FFFFFF  Owner-defined (user applications)
//! ```
//!
//! ## TPMA_NV attribute bits — Part 2 §13.4
//!
//! Common combinations:
//!
//! | Use-case              | Attributes                              |
//! |-----------------------|-----------------------------------------|
//! | Platform-write / PP   | `PPWRITE | PPREAD | NO_DA`              |
//! | Owner-write / Owner-r | `OWNERWRITE | OWNERREAD | NO_DA`        |
//! | Write-once lock       | `WRITELOCKED | PLATFORMCREATE | NO_DA`  |
//! | Monotonic counter     | `COUNTER | PPREAD | NO_DA`              |
//!
//! ## Reference
//!
//! TCG TPM Library Spec, Part 2 §13 (NV storage) and
//! Part 3 §31 (NV commands).

// ── TPMA_NV attribute bits ────────────────────────────────────────────

/// Allow Platform to write this index (`TPMA_NV_PPWRITE`).
pub const NV_ATTR_PPWRITE: u32 = 1 << 0;
/// Allow Owner to write this index (`TPMA_NV_OWNERWRITE`).
pub const NV_ATTR_OWNERWRITE: u32 = 1 << 1;
/// Index is authorised by its own auth value (`TPMA_NV_AUTHWRITE`).
pub const NV_ATTR_AUTHWRITE: u32 = 1 << 2;
/// Index is authorised by policy (`TPMA_NV_POLICYWRITE`).
pub const NV_ATTR_POLICYWRITE: u32 = 1 << 3;
/// Index type: ordinary (default = 0).
pub const NV_ATTR_TYPE_ORDINARY: u32 = 0 << 4;
/// Index type: counter (bits[5:4] = 01).
pub const NV_ATTR_TYPE_COUNTER: u32 = 1 << 4;
/// Index type: bit field (bits[5:4] = 10).
pub const NV_ATTR_TYPE_BITS: u32 = 2 << 4;
/// Index type: extend (bits[5:4] = 11).
pub const NV_ATTR_TYPE_EXTEND: u32 = 3 << 4;
/// Allow Platform to read (`TPMA_NV_PPREAD`).
pub const NV_ATTR_PPREAD: u32 = 1 << 16;
/// Allow Owner to read (`TPMA_NV_OWNERREAD`).
pub const NV_ATTR_OWNERREAD: u32 = 1 << 17;
/// Allow authorised entity to read (`TPMA_NV_AUTHREAD`).
pub const NV_ATTR_AUTHREAD: u32 = 1 << 18;
/// Allow policy to read (`TPMA_NV_POLICYREAD`).
pub const NV_ATTR_POLICYREAD: u32 = 1 << 19;
/// Index is not subject to dictionary-attack logic (`TPMA_NV_NO_DA`).
pub const NV_ATTR_NO_DA: u32 = 1 << 25;
/// Index is created by platform hierarchy (`TPMA_NV_PLATFORMCREATE`).
pub const NV_ATTR_PLATFORMCREATE: u32 = 1 << 30;
/// Reads of the index are blocked until the next
/// `Startup(TPM_SU_CLEAR)` once set by `NV_ReadLock`
/// (`TPMA_NV_READLOCKED`, Part 2 §13.4 bit 28).
pub const NV_ATTR_READLOCKED: u32 = 1 << 28;
/// The index has been written (`TPMA_NV_WRITTEN`, Part 2 §13.4
/// bit 29). SET by a successful write / extend / set-bits /
/// increment; CLEAR at define time.
pub const NV_ATTR_WRITTEN: u32 = 1 << 29;
/// `NV_ReadLock` may SET `READLOCKED` on this index
/// (`TPMA_NV_READ_STCLEAR`, Part 2 §13.4 bit 31).
pub const NV_ATTR_READ_STCLEAR: u32 = 1 << 31;
/// Writes to the index are blocked once set by `NV_WriteLock` or
/// `NV_GlobalWriteLock` (`TPMA_NV_WRITELOCKED`, Part 2 §13.4
/// bit 11).
pub const NV_ATTR_WRITELOCKED: u32 = 1 << 11;
/// `NV_WriteLock` may SET `WRITELOCKED` on this index
/// (`TPMA_NV_WRITEDEFINE`, Part 2 §13.4 bit 13). A lock set under
/// this attribute survives `Startup(TPM_SU_CLEAR)` while the
/// index is written — only undefine clears it.
pub const NV_ATTR_WRITEDEFINE: u32 = 1 << 13;
/// `NV_WriteLock` may SET `WRITELOCKED` until the next TPM Reset
/// / Restart (`TPMA_NV_WRITE_STCLEAR`, Part 2 §13.4 bit 14).
pub const NV_ATTR_WRITE_STCLEAR: u32 = 1 << 14;
/// `NV_GlobalWriteLock` SETs `WRITELOCKED` on this index
/// (`TPMA_NV_GLOBALLOCK`, Part 2 §13.4 bit 15).
pub const NV_ATTR_GLOBALLOCK: u32 = 1 << 15;
/// `TPMA_NV_WRITTEN` is CLEARed by TPM Reset or Restart
/// (`TPMA_NV_CLEAR_STCLEAR`, Part 2 §13.4 bit 27).
pub const NV_ATTR_CLEAR_STCLEAR: u32 = 1 << 27;

// ── Convenience attribute sets ────────────────────────────────────────

/// Owner can read/write, no DA protection.
pub const NV_ATTR_OWNER_RW: u32 = NV_ATTR_OWNERWRITE | NV_ATTR_OWNERREAD | NV_ATTR_NO_DA;

/// Platform can read/write, no DA protection.
pub const NV_ATTR_PLATFORM_RW: u32 = NV_ATTR_PPWRITE | NV_ATTR_PPREAD | NV_ATTR_NO_DA;

/// Auth (self) can read/write, no DA protection.
pub const NV_ATTR_AUTH_RW: u32 = NV_ATTR_AUTHWRITE | NV_ATTR_AUTHREAD | NV_ATTR_NO_DA;

// ── NARF NV index allocations ─────────────────────────────────────────

/// NV index for the disk-encryption key seal (sealing object handle).
pub const NV_IDX_DISK_KEY: u32 = 0x0150_0000;
/// NV index for the measured-boot log pointer.
pub const NV_IDX_BOOT_LOG: u32 = 0x0150_0001;
/// NV index for the TPM self-test result cache.
pub const NV_IDX_SELFTEST: u32 = 0x0150_0002;
/// NV index for the suspend epoch counter (#1002): the
/// monotonic epoch source the TPM custody anchor reports
/// through `KeyCustodyAnchor::epoch` / `advance_epoch`
/// (power-suspend design §8.2/§9.2 — rollback evidence for
/// TPM-composed policies). A `TPMA_NV_COUNTER` index: eight
/// bytes, changed only by `TPM2_NV_Increment`.
pub const NV_IDX_SUSPEND_EPOCH: u32 = 0x0150_0003;

// ── NvIndex descriptor ────────────────────────────────────────────────

/// A descriptor for a single NV index — carries the index handle,
/// declared size, and attribute word.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NvIndex {
    /// The 32-bit NV index handle (e.g. `0x0150_0000`).
    pub handle: u32,
    /// Declared data capacity in bytes.
    pub size: u16,
    /// `TPMA_NV` attribute word.
    pub attributes: u32,
}

impl NvIndex {
    /// Create a new NV index descriptor.
    pub const fn new(handle: u32, size: u16, attributes: u32) -> Self {
        Self {
            handle,
            size,
            attributes,
        }
    }

    /// Build the `TPM2_NV_DefineSpace` command for this index.
    pub fn define_space_cmd(&self) -> alloc::vec::Vec<u8> {
        super::commands::nv_define_space(self.handle, self.size, self.attributes)
    }

    /// Build a `TPM2_NV_Read` command to read `len` bytes at `offset`.
    pub fn read_cmd(&self, len: u16, offset: u16) -> alloc::vec::Vec<u8> {
        super::commands::nv_read(self.handle, len, offset)
    }

    /// Build a `TPM2_NV_Write` command to write `data` at `offset`.
    pub fn write_cmd(&self, data: &[u8], offset: u16) -> alloc::vec::Vec<u8> {
        super::commands::nv_write(self.handle, data, offset)
    }

    /// Build a `TPM2_NV_UndefineSpace` command for this index.
    pub fn undefine_cmd(&self) -> alloc::vec::Vec<u8> {
        super::commands::nv_undefine_space(self.handle)
    }

    /// Build a `TPM2_NV_ReadPublic` command for this index
    /// (Part 3 §31.6): no authorization, returns the index's
    /// public area and its name.
    pub fn read_public_cmd(&self) -> alloc::vec::Vec<u8> {
        super::commands::nv_read_public(self.handle)
    }

    /// Build a `TPM2_NV_Extend` command for this index
    /// (Part 3 §31.9): the index must be a `TPMA_NV_TYPE_EXTEND`
    /// index; the new value is `H(nameAlg ‖ old ‖ data)`.
    pub fn extend_cmd(&self, data: &[u8]) -> alloc::vec::Vec<u8> {
        super::commands::nv_extend(self.handle, data)
    }

    /// Build a `TPM2_NV_SetBits` command for this index
    /// (Part 3 §31.10): the index must be a `TPMA_NV_TYPE_BITS`
    /// index; `bits` are ORed into its contents.
    pub fn set_bits_cmd(&self, bits: u64) -> alloc::vec::Vec<u8> {
        super::commands::nv_set_bits(self.handle, bits)
    }

    /// Build a `TPM2_NV_WriteLock` command for this index
    /// (Part 3 §31.11): requires `WRITEDEFINE` or `WRITE_STCLEAR`
    /// in the index attributes.
    pub fn write_lock_cmd(&self) -> alloc::vec::Vec<u8> {
        super::commands::nv_write_lock(self.handle)
    }

    /// Build a `TPM2_NV_ReadLock` command for this index
    /// (Part 3 §31.14): requires `READ_STCLEAR` in the index
    /// attributes.
    pub fn read_lock_cmd(&self) -> alloc::vec::Vec<u8> {
        super::commands::nv_read_lock(self.handle)
    }
}

/// Pre-built NARF disk-key NV index descriptor (32-byte slot).
pub const NARF_DISK_KEY_NV: NvIndex = NvIndex::new(NV_IDX_DISK_KEY, 32, NV_ATTR_AUTH_RW);

/// Attribute set for the suspend epoch counter: a counter index
/// the owner provisions and both owner and index-auth can read
/// and increment; no dictionary-attack throttling (increments
/// are not auth failures and must never lock out resume).
pub const NV_ATTR_SUSPEND_EPOCH: u32 = NV_ATTR_TYPE_COUNTER
    | NV_ATTR_OWNERWRITE
    | NV_ATTR_AUTHWRITE
    | NV_ATTR_OWNERREAD
    | NV_ATTR_AUTHREAD
    | NV_ATTR_NO_DA;

/// Pre-built suspend-epoch counter descriptor (#1002): 8-byte
/// `TPMA_NV_COUNTER` index at [`NV_IDX_SUSPEND_EPOCH`].
pub const NARF_SUSPEND_EPOCH_NV: NvIndex =
    NvIndex::new(NV_IDX_SUSPEND_EPOCH, 8, NV_ATTR_SUSPEND_EPOCH);
