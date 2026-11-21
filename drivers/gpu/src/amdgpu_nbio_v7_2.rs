//! NBIO 7.2 (`nbio_v7_2.c`) as Raphael's graphics needs it, against the
//! NBIO 2.3 (`nbio_v2_3.c`) the discrete RDNA2 backends were written for.
//!
//! `amdgpu_discovery.c` gives `nbio_v7_2` NBIO 7.2.0, 7.2.1, 7.3.0, 7.5.0 and
//! 7.5.1, all read from `nbio_7_2_0_offset.h`; its per-version branches touch
//! only clock gating, `init_registers`, the revision id and FB access. Linux
//! supported GC 10.3.6 (February 2022) before `nbio_v7_7` existed (May 2022,
//! added with SOC21's PCIe-port helpers), so Raphael's NBIO is one of these.
//! NBIO 7.7 moves the IH control pair to segment 5 and the IH doorbell range
//! off the port pair; it is refused here.
//!
//! On `_BASE_IDX` 2 every register the RDNA2 backends program keeps its NBIO 2.3
//! offset and field masks (checked against both headers): the doorbell
//! aperture enable, the self-ring aperture, `INTERRUPT_CNTL`/`2`, the GPU HDP
//! flush request/done pair and the HDP remap. Only the IH, SDMA and VCN doorbell
//! ranges move: NBIO 2.3's `BIF_*_DOORBELL_RANGE` on segment 2 become
//! `GDC0_BIF_*_DOORBELL_RANGE` on segment 3, which `nbio_v7_2` reaches through
//! the PCIe port pair (`RREG32_PCIE_PORT`), with the same field layout. And
//! `init_registers` reaches its read-request register through the port pair,
//! where NBIO 2.3's is an SMN register.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as discovery, amdgpu_psp_ring::bank};
use narf_bus::MmioRegion;

pub const VERSIONS: &[(u8, u8, u8)] = &[(7, 2, 0), (7, 2, 1), (7, 3, 0), (7, 5, 0), (7, 5, 1)];

// `_BASE_IDX` 2, at the same offsets as `nbio_2_3_offset.h`.
pub const DOORBELL_APER_EN: u32 = 0x00c0; // linux: regRCC_DEV0_EPF0_0_RCC_DOORBELL_APER_EN
pub const INTERRUPT_CNTL: u32 = 0x00f1; // linux: regBIF_BX0_INTERRUPT_CNTL
pub const INTERRUPT_CNTL2: u32 = 0x00f2; // linux: regBIF_BX0_INTERRUPT_CNTL2
pub const SELFRING_BASE_HIGH: u32 = 0x00f3; // linux: regBIF_BX_PF0_DOORBELL_SELFRING_GPA_APER_BASE_HIGH
pub const SELFRING_BASE_LOW: u32 = 0x00f4; // linux: regBIF_BX_PF0_DOORBELL_SELFRING_GPA_APER_BASE_LOW
pub const SELFRING_CNTL: u32 = 0x00f5; // linux: regBIF_BX_PF0_DOORBELL_SELFRING_GPA_APER_CNTL
pub const HDP_FLUSH_REQ: u32 = 0x0106; // linux: regBIF_BX_PF0_GPU_HDP_FLUSH_REQ
pub const HDP_FLUSH_DONE: u32 = 0x0107; // linux: regBIF_BX_PF0_GPU_HDP_FLUSH_DONE
pub const REMAP_HDP_MEM_FLUSH_CNTL: u32 = 0x012d; // linux: regBIF_BX0_REMAP_HDP_MEM_FLUSH_CNTL

// `_BASE_IDX` 3, reached only through the PCIe port pair.
pub const GDC0_SDMA0_DOORBELL_RANGE: u32 = 0x4f_0af0; // linux: regGDC0_BIF_SDMA0_DOORBELL_RANGE
pub const GDC0_IH_DOORBELL_RANGE: u32 = 0x4f_0af2; // linux: regGDC0_BIF_IH_DOORBELL_RANGE
pub const GDC0_VCN0_DOORBELL_RANGE: u32 = 0x4f_0af3; // linux: regGDC0_BIF_VCN0_DOORBELL_RANGE

// `_BASE_IDX` 5. `PCIE_CONFIG_CNTL` and `BIF1_PCIE_MST_CTRL_3` (the latter
// `nbio_v7_2.c`'s own define) through the port pair; `RCC_DEV2_EPF0_STRAP2`
// with `RREG32_SOC15`, which lands past the BAR and so goes through
// PCIE_INDEX2/DATA2.
pub const PCIE_CONFIG_CNTL: u32 = 0x42_0011; // linux: regPCIE_CONFIG_CNTL
pub const BIF1_PCIE_MST_CTRL_3: u32 = 0x46_01c6; // linux: n/a (nbio_v7_2.c: regBIF1_PCIE_MST_CTRL_3)
pub const RCC_DEV2_EPF0_STRAP2: u32 = 0xd802; // linux: regRCC_DEV2_EPF0_STRAP2
/// `CI_SWUS_MAX_READ_REQUEST_SIZE_MODE` and `_PRIV`, at the same bits in both
/// read-request registers.
const READ_REQUEST_MODE_MASK: u32 = 1 << 27; // linux: PCIE_CONFIG_CNTL__CI_SWUS_MAX_READ_REQUEST_SIZE_MODE_MASK
const READ_REQUEST_PRIV_MASK: u32 = 3 << 28; // linux: PCIE_CONFIG_CNTL__CI_SWUS_MAX_READ_REQUEST_SIZE_PRIV_MASK
pub const STRAP_NO_SOFT_RESET_DEV2_F0: u32 = 1 << 7; // linux: RCC_DEV2_EPF0_STRAP2__STRAP_NO_SOFT_RESET_DEV2_F0_MASK

/// `nbio_v7_2_init_registers`' read-request register: `BIF1_PCIE_MST_CTRL_3`
/// on 7.2.1, 7.3.0 and 7.5.0, `PCIE_CONFIG_CNTL` otherwise.
pub fn read_request_register(version: (u8, u8, u8)) -> u32 {
    match version {
        (7, 2, 1) | (7, 3, 0) | (7, 5, 0) => BIF1_PCIE_MST_CTRL_3,
        _ => PCIE_CONFIG_CNTL,
    }
}
/// Both fields set to 1, as `nbio_v7_2_init_registers` sets them.
pub const fn read_request_size(current: u32) -> u32 {
    (current & !(READ_REQUEST_MODE_MASK | READ_REQUEST_PRIV_MASK))
        | READ_REQUEST_MODE_MASK
        | 1 << 28
}
/// Whether `nbio_v7_2_init_registers` also clears DEV2's no-soft-reset strap.
pub fn clears_dev2_soft_reset_strap(version: (u8, u8, u8)) -> bool {
    matches!(version, (7, 3, 0) | (7, 5, 1))
}

// GDC0_BIF_{IH,SDMA0,VCN0}_DOORBELL_RANGE share one field layout.
const RANGE_OFFSET_SHIFT: u32 = 2; // linux: GDC0_BIF_IH_DOORBELL_RANGE__OFFSET__SHIFT
const RANGE_OFFSET_MASK: u32 = 0x0000_0ffc; // linux: GDC0_BIF_IH_DOORBELL_RANGE__OFFSET_MASK
const RANGE_SIZE_SHIFT: u32 = 16; // linux: GDC0_BIF_IH_DOORBELL_RANGE__SIZE__SHIFT
const RANGE_SIZE_MASK: u32 = 0x001f_0000; // linux: GDC0_BIF_IH_DOORBELL_RANGE__SIZE_MASK

const fn set_field(value: u32, mask: u32, shift: u32, field: u32) -> u32 {
    (value & !mask) | ((field << shift) & mask)
}
/// A doorbell range's new value: Linux sets OFFSET and SIZE to claim it, and
/// clears only SIZE to release it.
const fn range(current: u32, claim: Option<(u32, u32)>) -> u32 {
    match claim {
        Some((index, size)) => set_field(
            set_field(current, RANGE_OFFSET_MASK, RANGE_OFFSET_SHIFT, index),
            RANGE_SIZE_MASK,
            RANGE_SIZE_SHIFT,
            size,
        ),
        None => set_field(current, RANGE_SIZE_MASK, RANGE_SIZE_SHIFT, 0),
    }
}
/// `nbio_v7_2_ih_doorbell_range`: two doorbells from `index`.
pub const fn ih_doorbell_range(current: u32, index: Option<u32>) -> u32 {
    match index {
        Some(index) => range(current, Some((index, 2))),
        None => range(current, None),
    }
}
/// `nbio_v7_2_sdma_doorbell_range`: `size` doorbells from `index`. NBIO 7.2
/// has one SDMA range, which Linux programs for instance 0's doorbells.
pub const fn sdma_doorbell_range(current: u32, claim: Option<(u32, u32)>) -> u32 {
    range(current, claim)
}
/// `nbio_v7_2_vcn_doorbell_range`: eight doorbells from `index`.
pub const fn vcn_doorbell_range(current: u32, index: Option<u32>) -> u32 {
    match index {
        Some(index) => range(current, Some((index, 8))),
        None => range(current, None),
    }
}

/// The NBIO segments the graphics bring-up reaches, and its version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Banks {
    /// Segment 2, bounded through the HDP remap.
    pub bif: u64,
    /// Segment 0: PCIE_INDEX2/DATA2.
    pcie: u64,
    /// Segment 1: the PCIe port pair.
    rsmu: u64,
    /// Segment 3's and 5's dword bases. Their registers lie far past the BAR
    /// and are addressed only indirectly, so no bound applies to them.
    gdc0: u32,
    seg5: u32,
    pub version: (u8, u8, u8),
}
impl Banks {
    /// NBIO instance 0 when its version is `nbio_v7_2`'s and it has the
    /// segments these registers use.
    pub fn resolve(gpu: &AmdGpu) -> Option<Self> {
        let rsmu = bank(
            gpu,
            discovery::HW_ID_NBIF,
            VERSIONS,
            1,
            crate::amdgpu_smn::RSMU_DATA as u32,
        )
        .ok()?;
        let bif = bank(
            gpu,
            discovery::HW_ID_NBIF,
            VERSIONS,
            2,
            REMAP_HDP_MEM_FLUSH_CNTL,
        )
        .ok()?;
        let pcie = bank(
            gpu,
            discovery::HW_ID_NBIF,
            VERSIONS,
            0,
            crate::amdgpu_smn::PCIE_DATA2 as u32,
        )
        .ok()?;
        let ip = discovery::find_ip(&gpu.ip_blocks, discovery::HW_ID_NBIF, 0)?;
        if ip.num_bases < 6 {
            return None;
        }
        Some(Self {
            bif,
            pcie,
            rsmu,
            gdc0: ip.base_addrs[3],
            seg5: ip.base_addrs[5],
            version: (ip.major, ip.minor, ip.revision),
        })
    }
    /// BAR byte addresses of PCIE_INDEX2 and PCIE_DATA2.
    pub fn smn_pair(&self) -> (u64, u64) {
        (
            self.pcie + crate::amdgpu_smn::PCIE_INDEX2 * 4,
            self.pcie + crate::amdgpu_smn::PCIE_DATA2 * 4,
        )
    }
    /// BAR byte addresses of the port pair, RSMU_INDEX and RSMU_DATA.
    pub fn port_pair(&self) -> (u64, u64) {
        (
            self.rsmu + crate::amdgpu_smn::RSMU_INDEX * 4,
            self.rsmu + crate::amdgpu_smn::RSMU_DATA * 4,
        )
    }
    /// `reg * 4` for a segment-5 register: its port or SMN address.
    pub fn seg5_address(&self, reg: u32) -> Option<u32> {
        self.seg5.checked_add(reg)?.checked_mul(4)
    }
    /// BAR byte address of a segment-2 register.
    pub fn bif(&self, reg: u32) -> u64 {
        self.bif + u64::from(reg) * 4
    }
    /// `SOC15_REG_OFFSET(NBIO, 0, reg) * 4`, the address `RREG32_PCIE_PORT`
    /// writes to the port index, for a segment-3 register.
    pub fn port_address(&self, reg: u32) -> Option<u32> {
        self.gdc0.checked_add(reg)?.checked_mul(4)
    }
    /// `RREG32_PCIE_PORT` of a segment-3 register.
    ///
    /// # Safety
    /// `regs` is the mapping these banks were resolved against and stays
    /// mapped; the caller owns the register.
    pub unsafe fn port_read(&self, regs: &MmioRegion, reg: u32) -> Option<u32> {
        let address = self.port_address(reg)?;
        // SAFETY: rsmu was bounded through RSMU_DATA; forwarded contract.
        Some(unsafe { crate::amdgpu_smn::port_read(regs, self.rsmu, address) })
    }
    /// `WREG32_PCIE_PORT` of a segment-3 register.
    ///
    /// # Safety
    /// As [`Self::port_read`].
    pub unsafe fn port_write(&self, regs: &MmioRegion, reg: u32, value: u32) -> Option<()> {
        let address = self.port_address(reg)?;
        // SAFETY: as port_read.
        unsafe { crate::amdgpu_smn::port_write(regs, self.rsmu, address, value) };
        Some(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_nbio_v7_2_tests.rs"]
mod tests;
