//! SMN access through NBIO's `PCIE_INDEX2`/`PCIE_DATA2` pair on Raphael.
//!
//! An SMN register past the MMIO BAR is reached by writing its address to the
//! index and then reading or writing the data (`amdgpu_device_indirect_rreg` /
//! `_wreg`). The pair is one latch per device: two users interleaving the index
//! and data steps would each reach the other's register. Linux serializes every
//! user with `adev->pcie_idx_lock`; this is that lock, held across the whole
//! sequence and never across an await.
//!
//! Users on Raphael: the display clock manager's VBIOSSMC message
//! (`MP1_C2PMSG_3`) and the SMU 13.0.5 graphics mailbox (`MP1_C2PMSG_2/33/34`,
//! `MP1_FIRMWARE_FLAGS`).
use narf_bus::MmioRegion;
use narf_lib::sync::IrqSafeSpinLock;

/// `regBIF_BX0_PCIE_INDEX2` / `_DATA2` at NBIO `_BASE_IDX 0`, the same in
/// `nbio_7_2_0_offset.h` and `nbio_7_7_0_offset.h` (`nbio_v7_2/7_7`'s
/// `get_pcie_index_offset` / `get_pcie_data_offset`).
pub(crate) const PCIE_INDEX2: u64 = 0x0e; // linux: regBIF_BX0_PCIE_INDEX2
pub(crate) const PCIE_DATA2: u64 = 0x0f; // linux: regBIF_BX0_PCIE_DATA2
/// The NBIO revisions whose PCIE_INDEX2/DATA2 sit there: every version
/// `amdgpu_discovery.c` gives `nbio_v7_2` (all read `nbio_7_2_0_offset.h`),
/// and `nbio_v7_7`'s.
pub(crate) const NBIO_VERSIONS: &[(u8, u8, u8)] = &[
    (7, 2, 0),
    (7, 2, 1),
    (7, 3, 0),
    (7, 5, 0),
    (7, 5, 1),
    (7, 7, 0),
    (7, 7, 1),
];

static LATCH: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// `RREG32_PCIE(address)`.
///
/// # Safety
/// `nbio` is the byte offset of a bounded NBIO bank in `regs` reaching
/// `PCIE_DATA2`, and `regs` stays mapped.
pub(crate) unsafe fn read(regs: &MmioRegion, nbio: u64, address: u32) -> u32 {
    let _latch = LATCH.lock();
    // SAFETY: caller's bank bound; the latch excludes every other user.
    unsafe {
        // Index, read back to post it, then the data.
        regs.write32(nbio + PCIE_INDEX2 * 4, address);
        regs.read32(nbio + PCIE_INDEX2 * 4);
        regs.read32(nbio + PCIE_DATA2 * 4)
    }
}

/// `WREG32_PCIE(address, value)`.
///
/// # Safety
/// As [`read`].
pub(crate) unsafe fn write(regs: &MmioRegion, nbio: u64, address: u32, value: u32) {
    let _latch = LATCH.lock();
    // SAFETY: as read.
    unsafe {
        // Each write read back to post it.
        regs.write32(nbio + PCIE_INDEX2 * 4, address);
        regs.read32(nbio + PCIE_INDEX2 * 4);
        regs.write32(nbio + PCIE_DATA2 * 4, value);
        regs.read32(nbio + PCIE_DATA2 * 4);
    }
}
