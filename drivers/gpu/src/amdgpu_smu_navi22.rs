//! Discrete RDNA2 SMC preparation and a cold-start SMU11 version handshake. Linux
//! `smu_v11_0.c`, `sienna_cichlid_ppt.c`, `smu_v11_0_7_ppsmc.h` and
//! `mp_11_0_offset.h`: MP1 index 0, message=66, argument=82, response=90.
//! Board tables use a retained VRAM transfer buffer. Cold-boot power setup
//! enables a restricted GFX DPM and autonomous protection policy. After it,
//! the same buffer carries PMFW metrics (`smu_cmn_get_metrics_table`) and the
//! owner arms the SMU11 THM/MP1 alert sources (`smu_v11_0_set_irq_state`).
use crate::amdgpu_smu_navi22_telemetry::{self as telemetry, METRICS_BYTES, METRICS_TABLE};
pub use crate::amdgpu_smu_navi22_telemetry::{Layout, Limits, Metrics, Telemetry};
use crate::{amdgpu::AmdGpu, amdgpu_discovery as discovery, amdgpu_smc_firmware as firmware};
use alloc::vec::Vec;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};

// linux-ctx: hdr=mp seg=0
// linux: mmMP1_SMN_C2PMSG_66
const MESSAGE: u32 = 0x282;
// linux: mmMP1_SMN_C2PMSG_82
const ARGUMENT: u32 = 0x292;
// linux: mmMP1_SMN_C2PMSG_90
const RESPONSE: u32 = 0x29a;
// linux-ctx: reset
// linux: PPSMC_MSG_GetSmuVersion
const GET_VERSION: u32 = 2;
const GET_INTERFACE: u32 = 3; // linux: PPSMC_MSG_GetDriverIfVersion
const SET_DRIVER_HIGH: u32 = 0xe; // linux: PPSMC_MSG_SetDriverDramAddrHigh
const SET_DRIVER_LOW: u32 = 0xf; // linux: PPSMC_MSG_SetDriverDramAddrLow
const TRANSFER_TABLE: u32 = 0x13; // linux: PPSMC_MSG_TransferTableDram2Smu
const RUN_DC_BTC: u32 = 0x36; // linux: PPSMC_MSG_RunDcBtc
const ALLOWED_HIGH: u32 = 5; // linux: PPSMC_MSG_SetAllowedFeaturesMaskHigh
const ALLOWED_LOW: u32 = 4; // linux: PPSMC_MSG_SetAllowedFeaturesMaskLow
const ENABLE_FEATURES: u32 = 6; // linux: PPSMC_MSG_EnableAllSmuFeatures
const RUNNING_LOW: u32 = 0xc; // linux: PPSMC_MSG_GetRunningSmuFeaturesLow
const RUNNING_HIGH: u32 = 0xd; // linux: PPSMC_MSG_GetRunningSmuFeaturesHigh
/// GFXCLK performance levels, shared with the Navi48 owner.
pub use crate::amdgpu_smu_navi48::GfxLevel;
const SET_SOFT_MIN_BY_FREQ: u32 = 0x19; // linux: PPSMC_MSG_SetSoftMinByFreq
const SET_SOFT_MAX_BY_FREQ: u32 = 0x1a; // linux: PPSMC_MSG_SetSoftMaxByFreq
const MIN_DPM_FREQ: u32 = 0x1d; // linux: PPSMC_MSG_GetMinDpmFreq
const MAX_DPM_FREQ: u32 = 0x1e; // linux: PPSMC_MSG_GetMaxDpmFreq
const TRANSFER_TO_DRIVER: u32 = 0x12; // linux: PPSMC_MSG_TransferTableSmu2Dram
const GET_PPT_LIMIT: u32 = 0x33; // linux: PPSMC_MSG_GetPptLimit
const REENABLE_ACDC_INTERRUPT: u32 = 0x34; // linux: PPSMC_MSG_ReenableAcDcInterrupt
                                           // smu_v11_0_7_ppsmc.h runtime feature and GFXOFF messages.
const ENABLE_FEATURES_LOW: u32 = 0x8; // linux: PPSMC_MSG_EnableSmuFeaturesLow
const ENABLE_FEATURES_HIGH: u32 = 0x9; // linux: PPSMC_MSG_EnableSmuFeaturesHigh
const DISABLE_FEATURES_LOW: u32 = 0xa; // linux: PPSMC_MSG_DisableSmuFeaturesLow
const DISABLE_FEATURES_HIGH: u32 = 0xb; // linux: PPSMC_MSG_DisableSmuFeaturesHigh
const ALLOW_GFXOFF: u32 = 0x28; // linux: PPSMC_MSG_AllowGfxOff
const DISALLOW_GFXOFF: u32 = 0x29; // linux: PPSMC_MSG_DisallowGfxOff
/// The only feature bits the opt-in power-saving path may switch at runtime
/// (amdgpu_navi22_power_policy): UCLK/FCLK DPM with memory rail scaling,
/// DS_* and GFX ULV, GFXOFF and MMHUB/ATHUB PG. Never a protection bit.
pub(crate) const GATING_FEATURES: u64 = {
    use crate::amdgpu_navi22_power_policy as p;
    p::SMU_DPM_UCLK
        | p::SMU_DPM_FCLK
        | p::SMU_MEM_VDDCI_SCALING
        | p::SMU_MEM_MVDD_SCALING
        | p::SMU_DEEP_SLEEP
        | p::SMU_GFXOFF
        | p::SMU_HUB_PG
};
pub const DRIVER_INTERFACE: u32 = 0x0e; // linux: SMU11_DRIVER_IF_VERSION_Navy_Flounder
/// smu_v11_0.h: `MP1_Public | (smnMP1_FIRMWARE_FLAGS & 0xffffffff)`, read
/// through the NBIO PCIe index/data pair (nbio_v2_3 PCIE_INDEX2/PCIE_DATA2,
/// BASE_IDX 0, 0xe/0xf).
// linux: MP1_Public@ppsmc | (smnMP1_FIRMWARE_FLAGS@ppsmc & 0xffffffff)
const MP1_FIRMWARE_FLAGS: u32 = 0x03b0_0000 | 0x0301_0024;
// linux: MP1_FIRMWARE_FLAGS__INTERRUPTS_ENABLED_MASK
const FIRMWARE_FLAGS_INTERRUPTS_ENABLED: u32 = 1 << 0;
// linux-ctx: hdr=nbio seg=0
// linux: mmPCIE_INDEX2
const PCIE_INDEX2: u32 = 0xe;
// linux: mmPCIE_DATA2
const PCIE_DATA2: u32 = 0xf;
/// smu_cmn: `default_timeout = adev->usec_timeout * 20` polls of udelay(1),
/// i.e. at least 2 s per message.
// linux-ctx: reset
// linux: n/a (NARF bound for smu_cmn's usec_timeout * 20 polls)
const MESSAGE_TIMEOUT_MS: u64 = 2000;
/// Bound on PMFW raising MP1_FIRMWARE_FLAGS.INTERRUPTS_ENABLED after PSP's
/// LOAD_IP_FW. Linux checks it once in smu_start_smc_engine, much later in
/// hw_init; NARF asks right after the upload, so it polls (bounded).
// linux: n/a (NARF bound)
const FIRMWARE_READY_TIMEOUT_MS: u64 = 1000;
// mp_11_0_offset.h, MP1 base index 0: MP1_SMN_IH_SW_INT{,_CTRL}.
// linux-ctx: hdr=mp seg=0
// linux: mmMP1_SMN_IH_SW_INT
pub(crate) const MP1_SW_INT: u32 = 0x2c2;
// linux: mmMP1_SMN_IH_SW_INT_CTRL
pub(crate) const MP1_SW_INT_CTRL: u32 = 0x2c3;
// linux-ctx: reset
// linux: n/a (literal ID 0xFE in smu_v11_0.c:smu_v11_0_set_irq_state)
const SW_INT_ID_TO_DRIVER: u32 = 0xfe;
// linux: MP1_SMN_IH_SW_INT__VALID_MASK
const SW_INT_VALID: u32 = 1 << 8;
// linux: MP1_SMN_IH_SW_INT_CTRL__INT_MASK_MASK
const SW_INT_CTRL_MASK: u32 = 1 << 0;
// linux: MP1_SMN_IH_SW_INT_CTRL__INT_ACK_MASK
const SW_INT_CTRL_ACK: u32 = 1 << 8;
// thm_11_0_2_offset.h, THM base index 0.
// linux-ctx: hdr=thm seg=0
// linux: mmTHM_THERMAL_INT_ENA
pub(crate) const THM_INT_ENA: u32 = 0x0a;
// linux: mmTHM_THERMAL_INT_CTRL
pub(crate) const THM_INT_CTRL: u32 = 0x0b;
// linux: mmCG_FDO_CTRL1
pub(crate) const CG_FDO_CTRL1: u32 = 0x68;
// linux: mmCG_THERMAL_STATUS
pub(crate) const CG_THERMAL_STATUS: u32 = 0x6c;
// THM_THERMAL_INT_CTRL / _ENA fields (thm_11_0_2_sh_mask.h).
// linux-ctx: reset
// linux: THM_THERMAL_INT_CTRL__DIG_THERM_INTH_MASK
const INT_CTRL_INTH: u32 = 0xff;
// linux: THM_THERMAL_INT_CTRL__DIG_THERM_INTL_MASK
const INT_CTRL_INTL: u32 = 0xff << 8;
// linux: THM_THERMAL_INT_CTRL__THERM_INTH_MASK_MASK
const INT_CTRL_INTH_MASK: u32 = 1 << 24;
// linux: THM_THERMAL_INT_CTRL__THERM_INTL_MASK_MASK
const INT_CTRL_INTL_MASK: u32 = 1 << 25;
// linux: THM_THERMAL_INT_CTRL__THERM_TRIGGER_MASK_MASK
const INT_CTRL_TRIGGER_MASK: u32 = 1 << 26;
// linux: THM_THERMAL_INT_CTRL__THERM_IH_HW_ENA_MASK
const INT_CTRL_IH_HW_ENA: u32 = 1 << 28;
// linux: THM_THERMAL_INT_CTRL__MAX_IH_CREDIT_MASK
const INT_CTRL_MAX_IH_CREDIT: u32 = 7 << 29;
// linux: THM_THERMAL_INT_ENA__THERM_INTH_CLR_MASK | THM_THERMAL_INT_ENA__THERM_INTL_CLR_MASK | THM_THERMAL_INT_ENA__THERM_TRIGGER_CLR_MASK
const INT_ENA_CLEAR: u32 = (1 << 3) | (1 << 4) | (1 << 5);
// smuio_11_0_0_offset.h, SMUIO base index 0: SMUSVI0_TEL_PLANE0.
// linux-ctx: hdr=smuio0 seg=0
// linux: mmSMUSVI0_TEL_PLANE0
pub(crate) const SVI0_TEL_PLANE0: u32 = 0x04;
/// Protection features whose loss after boot is reported: PPT, TDC,
/// VR0HOT, FW_CTF, FAN_CONTROL and THERMAL.
// linux-ctx: reset
// linux: (1ULL << FEATURE_PPT_BIT) | (1ULL << FEATURE_TDC_BIT) | (1ULL << FEATURE_VR0HOT_BIT) | (1ULL << FEATURE_FW_CTF_BIT) | (1ULL << FEATURE_FAN_CONTROL_BIT) | (1ULL << FEATURE_THERMAL_BIT)
const PROTECTION: u64 = (1 << 24) | (1 << 25) | (1 << 29) | (1 << 31) | (1 << 32) | (1 << 33);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Allocation,
    Revoked,
    Busy,
    Timeout,
    DeviceGone,
    Rejected(u32),
    InterfaceMismatch(u32),
    Image(firmware::Error),
    Registry(narf_firmware::FirmwareError),
    PowerPolicy(u32),
    Features { allowed: u64, enabled: u64 },
}
pub(crate) fn mp1_bank(gpu: &AmdGpu) -> Result<u64, Error> {
    if gpu.chip.vid != crate::amdgpu::AMD_VENDOR || gpu.chip.did != crate::amdgpu::NAVI22 {
        return Err(Error::Unsupported);
    }
    let mut gc = gpu
        .ip_blocks
        .iter()
        .filter(|ip| ip.hw_id == discovery::HW_ID_GC && ip.instance == 0);
    let gc_ip = gc.next().ok_or(Error::Unsupported)?;
    if gc.next().is_some() || (gc_ip.major, gc_ip.minor, gc_ip.revision) != (10, 3, 2) {
        return Err(Error::Unsupported);
    }
    crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_MP1, &[(11, 0, 11)], 0, RESPONSE).map_err(
        |error| match error {
            crate::amdgpu_psp_ring::Error::Invalid => Error::Invalid,
            _ => Error::Unsupported,
        },
    )
}
/// SMU11's shared THM11/SMUIO11 register backend, after exact GPU/MP1
/// validation. Linux smu_v11_0.c uses thm_11_0_2 and smuio_11_0_0 on
/// every Sienna Cichlid-family MP1. Other generations are refused.
pub(crate) fn runtime_bank(gpu: &AmdGpu, id: u16, last: u32) -> Result<u64, Error> {
    let ip = gpu
        .ip_blocks
        .iter()
        .find(|b| b.hw_id == id && b.instance == 0)
        .ok_or(Error::Unsupported)?;
    if ip.major != 11
        || ip.minor != 0
        || !matches!(id, discovery::HW_ID_THM | discovery::HW_ID_SMUIO)
    {
        return Err(Error::Unsupported);
    }
    crate::amdgpu_psp_ring::bank(gpu, id, &[(ip.major, ip.minor, ip.revision)], 0, last)
        .map_err(|_| Error::Unsupported)
}

/// Immutable image read through registry/blob capabilities. No raw-byte
/// constructor is exposed to callers of the hardware loader.
#[derive(Debug)]
pub struct Firmware {
    profile: &'static crate::amdgpu_rdna2::Profile,
    bytes: Vec<u8>,
}
struct Open(&'static crate::amdgpu_rdna2::Profile);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(self.0.firmware.smc, cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(Error::Registry(error))),
        };
        blob.invoke(CopyImage)
    }
}
struct CopyImage;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyImage {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Registry)?;
            firmware::Image::parse(view.bytes).map_err(Error::Image)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
impl Firmware {
    pub fn open(
        gpu: &AmdGpu,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, Error> {
        mp1_bank(gpu)?;
        Self::open_rdna2(gpu, authority)
    }
    /// Prepare this discrete RDNA2 ASIC's SMC container without device I/O.
    /// Runtime policy retains this profile through metrics and thermal setup.
    pub fn open_rdna2(
        gpu: &AmdGpu,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, Error> {
        let profile = crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
            .ok_or(Error::Unsupported)?;
        for (id, version, last) in [
            (discovery::HW_ID_GC, profile.gc_version, 0),
            (discovery::HW_ID_MP1, profile.psp_version, RESPONSE),
        ] {
            crate::amdgpu_psp_ring::bank(gpu, id, &[version], 0, last)
                .map_err(|_| Error::Unsupported)?;
        }
        Ok(Self {
            profile,
            bytes: authority
                .invoke(Open(profile))
                .map_err(|_| Error::Revoked)??,
        })
    }
    pub fn profile(&self) -> &'static crate::amdgpu_rdna2::Profile {
        self.profile
    }
    pub fn image(&self) -> Result<firmware::Image<'_>, Error> {
        firmware::Image::parse(&self.bytes).map_err(Error::Image)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Querying,
    Ready,
    UploadingPowerTable,
    PowerTableReady,
    ConfiguringPower,
    PowerReady,
    EnablingDisplayPower,
    DisplayPowerReady,
    /// A runtime telemetry/thermal command is in flight; cancellation keeps it.
    Runtime,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions {
    pub firmware: u32,
    pub interface: u32,
}
/// Observed SMU policy and board frequency limits, not a clock override.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerStatus {
    pub allowed: u64,
    pub enabled: u64,
    pub gfx_min_mhz: u16,
    pub gfx_max_mhz: u16,
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
trait Io {
    fn read(&mut self, register: u32) -> u32;
    fn write(&mut self, register: u32, value: u32);
    /// Stage the PPTable into the transfer buffer; returns the PSP runtime
    /// DB SCPM status (0: disabled).
    fn stage_power(
        &mut self,
        memory: &crate::amdgpu_vram::Reservation,
        bytes: &[u8],
    ) -> Result<u32, Error>;
    /// CPU write into the retained transfer buffer, then the HDP flush
    /// (`amdgpu_asic_flush_hdp`) before the SMU reads it.
    fn write_table(
        &mut self,
        memory: &crate::amdgpu_vram::Reservation,
        bytes: &[u8],
    ) -> Result<(), Error>;
    /// HDP read-cache invalidate (`hdp_v5_0_invalidate_hdp`), then a CPU
    /// read of the SMU-written buffer.
    fn read_table(
        &mut self,
        memory: &crate::amdgpu_vram::Reservation,
        out: &mut [u8],
    ) -> Result<(), Error>;
    fn thm(&mut self, register: u32) -> Result<u32, Error>;
    fn set_thm(&mut self, register: u32, value: u32) -> Result<(), Error>;
    fn smuio(&mut self, register: u32) -> Result<u32, Error>;
    /// RREG32_PCIE(MP1_FIRMWARE_FLAGS) (`smu_v11_0_check_fw_status`).
    fn firmware_flags(&mut self) -> Result<u32, Error>;
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
    vram: MmioRegion,
    vram_size: u64,
    nbio: Option<u64>,
    /// NBIO base-0 bank holding PCIE_INDEX2/PCIE_DATA2.
    pcie: Option<u64>,
    /// HDP / THM / SMUIO banks; None refuses runtime telemetry and alerts.
    hdp: Option<u64>,
    thm: Option<u64>,
    smuio: Option<u64>,
}
impl Mmio {
    fn flush(&mut self) -> Result<(), Error> {
        let nbio = self.nbio.ok_or(Error::Unsupported)?;
        // PSP ring startup already installed this exact HDP flush remapping.
        // Refuse a changed mapping instead of racing another HDP owner.
        // SAFETY: nbio and remap hole were bounded at construction.
        // linux-lit: 0x12d=mmREMAP_HDP_MEM_FLUSH_CNTL
        // linux: n/a (0x7f000 = MMIO_REG_HOLE_OFFSET, nbio_v2_3.c, 4 KiB pages)
        if unsafe { self.regs.read32(nbio + 0x12d * 4) } != 0x7f000 {
            return Err(Error::Invalid);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: verified remap; MEMSIZE read drains the posted flush write.
        unsafe {
            // linux: n/a (MMIO_REG_HOLE_OFFSET + KFD_MMIO_REMAP_HDP_MEM_FLUSH_CNTL, amdgpu_hdp_generic_flush)
            self.regs.write32(0x7f000, 0);
            self.regs.read32(nbio + 0xc3 * 4); // linux-lit: 0xc3=mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    fn bank(bank: Option<u64>, register: u32, last: u32) -> Result<u64, Error> {
        let base = bank.ok_or(Error::Unsupported)?;
        if register > last {
            return Err(Error::Invalid);
        }
        Ok(base + u64::from(register) * 4)
    }
}
impl Io for Mmio {
    fn read(&mut self, register: u32) -> u32 {
        // SAFETY: exact MP1 window bounded through MP1_SW_INT_CTRL at
        // construction (every caller uses a constant register); permanent map.
        unsafe { self.regs.read32(self.base + u64::from(register) * 4) }
    }
    fn write(&mut self, register: u32, value: u32) {
        // SAFETY: same bounds, with exclusive ownership of this mailbox.
        unsafe {
            self.regs
                .write32(self.base + u64::from(register) * 4, value)
        };
    }
    fn write_table(
        &mut self,
        memory: &crate::amdgpu_vram::Reservation,
        bytes: &[u8],
    ) -> Result<(), Error> {
        if bytes.len() as u64 > memory.size() || bytes.len() % 4 != 0 {
            return Err(Error::Invalid);
        }
        let mapping = memory.mapping();
        for (index, word) in bytes.chunks_exact(4).enumerate() {
            // SAFETY: bounded by the retained reservation checked above.
            unsafe {
                mapping.write32(
                    index as u64 * 4,
                    u32::from_le_bytes(word.try_into().unwrap()),
                )
            };
        }
        self.flush()
    }
    fn read_table(
        &mut self,
        memory: &crate::amdgpu_vram::Reservation,
        out: &mut [u8],
    ) -> Result<(), Error> {
        if out.len() as u64 > memory.size() || out.len() % 4 != 0 {
            return Err(Error::Invalid);
        }
        // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
        let hdp = Self::bank(self.hdp, 0xd1, 0xd1)?;
        // SAFETY: HDP_READ_CACHE_INVALIDATE, bounded at construction.
        unsafe {
            self.regs.write32(hdp, 1);
            self.regs.read32(hdp);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let mapping = memory.mapping();
        for (index, word) in out.chunks_exact_mut(4).enumerate() {
            // SAFETY: completed transfer into the bounded retained buffer.
            word.copy_from_slice(&unsafe { mapping.read32(index as u64 * 4) }.to_le_bytes());
        }
        Ok(())
    }
    fn thm(&mut self, register: u32) -> Result<u32, Error> {
        let at = Self::bank(self.thm, register, CG_THERMAL_STATUS)?;
        // SAFETY: THM bank bounded through CG_THERMAL_STATUS at construction.
        Ok(unsafe { self.regs.read32(at) })
    }
    fn set_thm(&mut self, register: u32, value: u32) -> Result<(), Error> {
        let at = Self::bank(self.thm, register, CG_THERMAL_STATUS)?;
        // SAFETY: same bounds; the SMU owner exclusively owns THM alerts.
        unsafe { self.regs.write32(at, value) };
        Ok(())
    }
    fn smuio(&mut self, register: u32) -> Result<u32, Error> {
        let at = Self::bank(self.smuio, register, SVI0_TEL_PLANE0)?;
        // SAFETY: SMUIO bank bounded through SVI0_TEL_PLANE0; read-only.
        Ok(unsafe { self.regs.read32(at) })
    }
    fn firmware_flags(&mut self) -> Result<u32, Error> {
        let index = Self::bank(self.pcie, PCIE_INDEX2, PCIE_DATA2)?;
        let data = Self::bank(self.pcie, PCIE_DATA2, PCIE_DATA2)?;
        // SAFETY: NBIO PCIE_INDEX2/DATA2 bounded at construction; the cold
        // boot owner excludes every other indirect-register user. Like
        // amdgpu_device_indirect_rreg, the index write is posted by a read.
        unsafe {
            self.regs.write32(index, MP1_FIRMWARE_FLAGS);
            self.regs.read32(index);
            Ok(self.regs.read32(data))
        }
    }
    fn stage_power(
        &mut self,
        memory: &crate::amdgpu_vram::Reservation,
        bytes: &[u8],
    ) -> Result<u32, Error> {
        let nbio = self.nbio.ok_or(Error::Unsupported)?;
        // linux: n/a (1 << 20 = PSP_RUNTIME_DB_OFFSET below mc_vram_size, amdgpu_psp.c:psp_get_runtime_db_entry)
        let base = self.vram_size.checked_sub(1 << 20).ok_or(Error::Invalid)?;
        // SAFETY: exclusive GPU/index-latch ownership inherited from the SMU
        // constructor and uploader; this entire method runs in Cap::invoke.
        let mut reader =
            unsafe { crate::amdgpu_vram_access::MmioReader::new(&self.vram, &self.regs) };
        let scpm = power_policy(|offset, out| {
            crate::amdgpu_vram_access::read(&mut reader, self.vram_size, base + offset as u64, out)
                .map_err(|_| crate::amdgpu_gddr6::Error::Invalid)
        })?;
        // PSP ring startup already installed this exact HDP flush remapping.
        // Refuse a changed mapping instead of racing another HDP owner.
        // SAFETY: nbio and remap hole were bounded at construction.
        // linux-lit: 0x12d=mmREMAP_HDP_MEM_FLUSH_CNTL
        // linux: n/a (0x7f000 = MMIO_REG_HOLE_OFFSET, nbio_v2_3.c, 4 KiB pages)
        if unsafe { self.regs.read32(nbio + 0x12d * 4) } != 0x7f000 {
            return Err(Error::Invalid);
        }
        let mapping = memory.mapping();
        for (index, word) in bytes.chunks_exact(4).enumerate() {
            // SAFETY: the owned reservation is larger than this validated
            // table; its permanent mapping belongs to this GPU's VRAM pool.
            unsafe {
                mapping.write32(
                    index as u64 * 4,
                    u32::from_le_bytes(word.try_into().unwrap()),
                )
            };
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: verified remap; MEMSIZE read drains the posted flush write.
        unsafe {
            // linux: n/a (MMIO_REG_HOLE_OFFSET + KFD_MMIO_REMAP_HDP_MEM_FLUSH_CNTL, amdgpu_hdp_generic_flush)
            self.regs.write32(0x7f000, 0);
            self.regs.read32(nbio + 0xc3 * 4); // linux-lit: 0xc3=mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(scpm)
    }
}
/// psp_sw_init: the PSP runtime DB PPTABLE_ERR_STATUS entry (type 6). A
/// nonzero status is `adev->scpm_enabled`, which Linux does not treat as an
/// error ("TODO: stop gpu driver services"); it changes the SMU sequence.
fn power_policy(
    read: impl FnMut(usize, &mut [u8]) -> Result<(), crate::amdgpu_gddr6::Error>,
) -> Result<u32, Error> {
    Ok(crate::amdgpu_gddr6::runtime_entry::<4>(read, 6)
        .map_err(|_| Error::Invalid)?
        .map_or(0, u32::from_le_bytes))
}
#[derive(Debug)]
struct Engine<I: Io> {
    profile: &'static crate::amdgpu_rdna2::Profile,
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    state: State,
    // SMU retains DriverDramAddr even after acknowledgement. Keep this buffer
    // for the lifetime of the owner; Drop quarantines published allocations.
    power_memory: Option<crate::amdgpu_vram::Reservation>,
    power_policy: Option<crate::amdgpu_power_navi22::BootPolicy>,
    versions: Option<Versions>,
    limits: Option<Limits>,
    /// PROTECTION features running when boot power configuration completed.
    protection: Option<u64>,
    /// SCPM enabled (PSP runtime DB): PSP transfers the PPTable and the
    /// allowed-feature mask messages are not permitted (smu_smc_hw_setup).
    scpm: bool,
    /// Opt-in gating bits added to the allowed mask at runtime.
    gating_allowed: u64,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    /// I/O against the retained transfer buffer (`DriverDramAddr`).
    fn access_table<T>(
        &mut self,
        f: impl FnOnce(&mut I, &crate::amdgpu_vram::Reservation) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (io, memory) = (&mut self.io, self.power_memory.as_ref());
        let memory = memory.ok_or(Error::Invalid)?;
        self.authority
            .invoke(Op(|| f(io, memory)))
            .map_err(|_| Error::Revoked)?
    }
    async fn query(&mut self, message: u32) -> Result<u32, Error> {
        self.command(message, 0).await
    }
    async fn command(&mut self, message: u32, parameter: u32) -> Result<u32, Error> {
        self.access(|io| {
            if io.read(RESPONSE) == u32::MAX {
                return Err(Error::DeviceGone);
            }
            // A freshly loaded SMU may leave response=0. Linux's first message
            // skips pre-poll; after that we own and complete every command.
            io.write(RESPONSE, 0);
            io.write(ARGUMENT, parameter);
            io.write(MESSAGE, message);
            Ok(())
        })??;
        let deadline = narf_time::Deadline::after_ms(MESSAGE_TIMEOUT_MS);
        loop {
            let response = self.access(|io| io.read(RESPONSE))?;
            match response {
                u32::MAX => return Err(Error::DeviceGone),
                1 => return self.access(|io| io.read(ARGUMENT)), // linux-lit: 1=PPSMC_Result_OK
                0 => {}
                status => return Err(Error::Rejected(status)),
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    /// smu_v11_0_check_fw_status: PMFW must have enabled its interrupts before
    /// the first PPSMC message ("SMC is not ready" otherwise).
    async fn wait_firmware(&mut self) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(FIRMWARE_READY_TIMEOUT_MS);
        loop {
            match self.access(|io| io.firmware_flags())?? {
                u32::MAX => return Err(Error::DeviceGone),
                flags if flags & FIRMWARE_FLAGS_INTERRUPTS_ENABLED != 0 => return Ok(()),
                _ => {}
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    async fn verify_inner(&mut self) -> Result<Versions, Error> {
        self.wait_firmware().await?;
        let interface = self.query(GET_INTERFACE).await?;
        if interface == u32::MAX {
            return Err(Error::DeviceGone);
        }
        let firmware = self.query(GET_VERSION).await?;
        if firmware == u32::MAX {
            return Err(Error::DeviceGone);
        }
        if firmware == 0 {
            return Err(Error::Invalid);
        }
        // smu_cmn_check_fw_version (sienna_cichlid .check_fw_version) only
        // logs the driver/firmware interface pair: shipping Navi22 PMFW
        // 0x413f00 reports interface 0x12 against the driver's 0xe.
        let driver = self.profile.smu_driver_interface();
        if interface != driver {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: {} smu driver if version = {driver:#010x}, smu fw if version = {interface:#010x}, smu fw version = {firmware:#010x}", self.profile.asic
            );
        }
        Ok(Versions {
            firmware,
            interface,
        })
    }
    async fn verify(&mut self) -> Result<Versions, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Querying;
        let result = self.verify_inner().await;
        self.state = if result.is_ok() {
            State::Ready
        } else {
            State::Failed
        };
        self.versions = result.ok();
        result
    }
    async fn upload(&mut self, bytes: &[u8], pool: &crate::amdgpu_vram::Pool) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        if ![crate::amdgpu_power_navi22::SMC_BYTES, 1700, 1888].contains(&bytes.len()) {
            return Err(Error::Invalid);
        }
        let mut memory = pool
            .reserve(bytes.len() as u64)
            .map_err(|_| Error::Allocation)?;
        self.state = State::UploadingPowerTable;
        let result = async {
            let scpm = self.access(|io| io.stage_power(&memory, bytes))??;
            // linux-lit: 0=SCPM_DISABLE
            if scpm != 0 {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 SCPM enabled (status {scpm:#x}): PSP owns the PPTable"
                );
            }
            self.scpm = scpm != 0;
            let address = memory.address();
            memory.publish();
            self.power_memory = Some(memory);
            // smu_set_driver_table_location runs regardless of SCPM.
            self.command(SET_DRIVER_HIGH, (address >> 32) as u32)
                .await?;
            self.command(SET_DRIVER_LOW, address as u32).await?;
            // smu_smc_hw_setup: with SCPM, "PSP is responsible for the
            // PPTable transferring"; otherwise TABLE_PPTABLE == 0 (the upper
            // 16-bit table argument also zero).
            if !self.scpm {
                self.command(TRANSFER_TABLE, 0).await?; // linux-lit: 0=TABLE_PPTABLE
            }
            Ok(())
        }
        .await;
        self.state = if result.is_ok() {
            State::PowerTableReady
        } else {
            State::Failed
        };
        result
    }
    async fn configure_power(&mut self) -> Result<PowerStatus, Error> {
        if self.state != State::PowerTableReady {
            return Err(Error::Busy);
        }
        let policy = self.power_policy.ok_or(Error::Invalid)?;
        self.state = State::ConfiguringPower;
        let result = async {
            self.command(RUN_DC_BTC, 0).await?;
            // smu_feature_set_allowed_mask is skipped under SCPM ("not
            // needed and permitted"); the enabled set is still validated.
            if !self.scpm {
                self.command(ALLOWED_HIGH, (policy.allowed() >> 32) as u32)
                    .await?;
                self.command(ALLOWED_LOW, policy.allowed() as u32).await?;
            }
            self.command(ENABLE_FEATURES, 0).await?;
            let low = self.command(RUNNING_LOW, 0).await?;
            let high = self.command(RUNNING_HIGH, 0).await?;
            let enabled = u64::from(low) | (u64::from(high) << 32);
            if !policy.validate_enabled(enabled) {
                return Err(Error::Features {
                    allowed: policy.allowed(),
                    enabled,
                });
            }
            // PPCLK_GFXCLK == 0 in the upper 16 bits. Read only: leave the
            // board's frequency/voltage limits intact and use automatic DPM.
            let min = self.command(MIN_DPM_FREQ, 0).await?; // linux-lit: 0=PPCLK_GFXCLK
            let max = self.command(MAX_DPM_FREQ, 0).await?; // linux-lit: 0=PPCLK_GFXCLK
            if min == 0 || min > max || max > u32::from(u16::MAX) {
                return Err(Error::Invalid);
            }
            Ok(PowerStatus {
                allowed: policy.allowed(),
                enabled,
                gfx_min_mhz: min as u16,
                gfx_max_mhz: max as u16,
            })
        }
        .await;
        self.state = if result.is_ok() {
            State::PowerReady
        } else {
            State::Failed
        };
        self.protection = result.ok().map(|status| status.enabled & PROTECTION);
        result
    }
    fn begin_runtime(&mut self) -> Result<State, Error> {
        let resume = self.state;
        if !matches!(resume, State::PowerReady | State::DisplayPowerReady) {
            return Err(Error::Busy);
        }
        self.state = State::Runtime;
        Ok(resume)
    }
    /// A clean PMFW rejection leaves the mailbox idle and the owner reusable,
    /// as in Linux; timeout, revocation and device loss are terminal.
    fn end_runtime<T>(&mut self, resume: State, result: &Result<T, Error>) {
        self.state = match result {
            Ok(_) | Err(Error::Rejected(_)) => resume,
            Err(_) => State::Failed,
        };
    }
    fn protected(&self, enabled: u64) -> bool {
        self.protection
            .is_some_and(|protection| enabled & protection == protection)
    }
    async fn running(&mut self) -> Result<u64, Error> {
        let low = u64::from(self.command(RUNNING_LOW, 0).await?);
        Ok(low | u64::from(self.command(RUNNING_HIGH, 0).await?) << 32)
    }
    /// smu_v11_0_get_dpm_ultimate_freq: fixed boot MCLK when UCLK DPM
    /// is disabled, otherwise the PMFW UCLK range (PPCLK_UCLK == 2).
    async fn memory_range(&mut self, boot_khz: u64) -> Result<(u64, u64), Error> {
        let resume = self.begin_runtime()?;
        let result = async {
            let enabled = self.running().await?;
            if enabled & crate::amdgpu_navi22_power_policy::SMU_DPM_UCLK == 0 {
                return if boot_khz == 0 {
                    Err(Error::Invalid)
                } else {
                    Ok((boot_khz, boot_khz))
                };
            }
            let min = self.command(MIN_DPM_FREQ, 2 << 16).await?;
            let max = self.command(MAX_DPM_FREQ, 2 << 16).await?;
            if min == 0 || min > max || max > u32::from(u16::MAX) {
                return Err(Error::Invalid);
            }
            Ok((u64::from(min) * 1000, u64::from(max) * 1000))
        }
        .await;
        if result == Err(Error::Invalid) {
            // An absent boot clock or malformed read-only range is unknown
            // metadata. The acknowledged mailbox remains reusable.
            self.state = resume;
        } else {
            self.end_runtime(resume, &result);
        }
        result
    }
    /// Linux `smu_cmn_get_metrics_table` (SMU -> DRAM of TABLE_SMU_METRICS
    /// into the retained driver table), the running features,
    /// `sienna_cichlid_get_power_limit` (AC, PPT0) and the register sensors
    /// `smu_v11_0_get_gfx_vdd` / `smu_v11_0_get_fan_speed_pwm`.
    async fn read_telemetry(&mut self) -> Result<Telemetry, Error> {
        let layout =
            Layout::for_profile(self.profile, self.versions.ok_or(Error::Invalid)?.firmware);
        let limits = self.limits.ok_or(Error::Invalid)?;
        let resume = self.begin_runtime()?;
        let result = async {
            // Zeroed staging: an acknowledged but unwritten table reads as
            // zeros, never as the board table that shared this buffer.
            self.access_table(|io, memory| io.write_table(memory, &[0; METRICS_BYTES]))?;
            self.command(TRANSFER_TO_DRIVER, METRICS_TABLE).await?;
            let mut bytes = [0; METRICS_BYTES];
            self.access_table(|io, memory| io.read_table(memory, &mut bytes))?;
            let enabled = self.running().await?;
            // smu_v11_0_get_current_power_limit: PPT0, POWER_SOURCE_AC (0),
            // only while FEATURE_PPT runs; else the table's AC limit.
            let ppt_limit_w = if enabled & telemetry::FEATURE_PPT != 0 {
                match self.command(GET_PPT_LIMIT, 0).await {
                    Ok(watts) => watts,
                    Err(Error::Rejected(_)) => u32::from(limits.ppt_table_w),
                    Err(error) => return Err(error),
                }
            } else {
                u32::from(limits.ppt_table_w)
            };
            let (vid, fdo, status) = self.access(|io| {
                Ok::<_, Error>((
                    io.smuio(SVI0_TEL_PLANE0)?,
                    io.thm(CG_FDO_CTRL1)?,
                    io.thm(CG_THERMAL_STATUS)?,
                ))
            })??;
            if [vid, fdo, status].contains(&u32::MAX) {
                return Err(Error::DeviceGone);
            }
            Ok(Telemetry {
                layout,
                metrics: Metrics::decode(&bytes, layout),
                enabled,
                ppt_limit_w,
                vddgfx_mv: telemetry::vddgfx_mv(vid),
                fan_pwm: telemetry::fan_pwm(fdo, status),
            })
        }
        .await;
        self.end_runtime(resume, &result);
        result
    }
    /// `smu_v11_0_enable_thermal_alert`: when the board has a thermal
    /// controller, `smu_v11_0_set_irq_state(ENABLE)` programs the THM
    /// L2H/H2L window and unmasks the MP1 SMU-to-driver software interrupt;
    /// then `smu_v11_0_process_pending_interrupt` re-arms AC/DC delivery.
    async fn enable_thermal_alert(&mut self) -> Result<Alert, Error> {
        let limits = self.limits.ok_or(Error::Invalid)?;
        let resume = self.begin_runtime()?;
        let result = async {
            let mut alert = Alert {
                armed: false,
                window: limits.alert_window(),
                acdc_rearmed: false,
            };
            if limits.thermal_controller != 0 {
                let (low, high) = alert.window;
                self.access(|io| {
                    let ctrl = io.thm(THM_INT_CTRL)?;
                    if ctrl == u32::MAX {
                        return Err(Error::DeviceGone);
                    }
                    let ctrl = (ctrl
                        & !(INT_CTRL_INTH
                            | INT_CTRL_INTL
                            | INT_CTRL_INTH_MASK
                            | INT_CTRL_INTL_MASK
                            | INT_CTRL_TRIGGER_MASK
                            | INT_CTRL_MAX_IH_CREDIT))
                        | 5 << 29 // linux-lit: 29=THM_THERMAL_INT_CTRL__MAX_IH_CREDIT__SHIFT
                        | INT_CTRL_IH_HW_ENA
                        | u32::from(high)
                        // linux-lit: 8=THM_THERMAL_INT_CTRL__DIG_THERM_INTL__SHIFT
                        | u32::from(low) << 8;
                    io.set_thm(THM_INT_CTRL, ctrl)?;
                    io.set_thm(THM_INT_ENA, INT_ENA_CLEAR)?;
                    let sw = io.read(MP1_SW_INT);
                    io.write(
                        MP1_SW_INT,
                        // linux-lit: 0xff=MP1_SMN_IH_SW_INT__ID_MASK
                        (sw & !(0xff | SW_INT_VALID)) | SW_INT_ID_TO_DRIVER,
                    );
                    let ctrl = io.read(MP1_SW_INT_CTRL);
                    io.write(MP1_SW_INT_CTRL, ctrl & !SW_INT_CTRL_MASK);
                    Ok(())
                })??;
                alert.armed = true;
            }
            if limits.dc_by_gpio && self.running().await? & telemetry::FEATURE_ACDC != 0 {
                self.command(REENABLE_ACDC_INTERRUPT, 0).await?;
                alert.acdc_rearmed = true;
            }
            Ok(alert)
        }
        .await;
        self.end_runtime(resume, &result);
        result
    }
    /// `smu_v11_0_ack_ac_dc_interrupt` (AC/DC context of the SMU interrupt).
    async fn reenable_acdc(&mut self) -> Result<(), Error> {
        let resume = self.begin_runtime()?;
        let result = self.command(REENABLE_ACDC_INTERRUPT, 0).await.map(|_| ());
        self.end_runtime(resume, &result);
        result
    }
    /// `smu_cmn_feature_update_enable_state`: Enable/DisableSmuFeatures
    /// Low then High with `mask`. Linux allowed these bits at boot; NARF's
    /// boot policy did not, so an enable first re-sends the allowed mask with
    /// them added (as the display transition does). The running set is read
    /// back: the change must have taken effect and every boot protection
    /// feature must still run.
    async fn update_features(&mut self, mask: u64, enable: bool) -> Result<u64, Error> {
        if mask == 0 || mask & !GATING_FEATURES != 0 {
            return Err(Error::Invalid);
        }
        let policy = self.power_policy.ok_or(Error::Invalid)?;
        let resume = self.begin_runtime()?;
        let result = async {
            let base = if resume == State::DisplayPowerReady {
                policy.display_allowed().map_err(|_| Error::Unsupported)?
            } else {
                policy.allowed()
            };
            let allowed = base | self.gating_allowed | mask;
            if enable {
                // Under SCPM every feature is allowed and the mask messages
                // are not permitted (smu_init_driver_allowed_feature_mask).
                if !self.scpm {
                    self.command(ALLOWED_HIGH, (allowed >> 32) as u32).await?;
                    self.command(ALLOWED_LOW, allowed as u32).await?;
                }
                self.command(ENABLE_FEATURES_LOW, mask as u32).await?;
                // From here the Low half may run even if High fails
                // (smu_cmn_feature_update_enable_state returns between the
                // two): record it so the opt-in's removal switches it off.
                self.gating_allowed |= mask & 0xffff_ffff;
                self.command(ENABLE_FEATURES_HIGH, (mask >> 32) as u32)
                    .await?;
            } else {
                self.command(DISABLE_FEATURES_LOW, mask as u32).await?;
                self.command(DISABLE_FEATURES_HIGH, (mask >> 32) as u32)
                    .await?;
            }
            let running = self.running().await?;
            let changed = if enable {
                running & mask == mask
            } else {
                running & mask == 0
            };
            if !changed || !self.protected(running) {
                return Err(Error::Features {
                    allowed,
                    enabled: running,
                });
            }
            if enable {
                self.gating_allowed |= mask;
            }
            Ok(running)
        }
        .await;
        self.end_runtime(resume, &result);
        result
    }
    /// `smu_v11_0_gfx_off_control`: AllowGfxOff / DisallowGfxOff, only once
    /// the opt-in enabled FEATURE_GFXOFF through `update_features`.
    /// `smu_v11_0_set_performance_level` restricted to GFXCLK, through
    /// `smu_v11_0_set_soft_freq_limited_range`: SoftMax then SoftMin, with
    /// 0xffff/0 as PMFW's automatic bounds. Memory and SoC clocks stay with
    /// the display owner's admitted floors, so no admission reruns.
    async fn set_gfx_level(&mut self, level: GfxLevel) -> Result<(), Error> {
        let resume = self.begin_runtime()?;
        let result = async {
            let clk = 0u32 << 16; // linux-lit: 0=PPCLK_GFXCLK
            let (min, max) = match level {
                GfxLevel::Auto => (0, 0xffff),
                GfxLevel::Low | GfxLevel::High => {
                    let min = self.command(MIN_DPM_FREQ, clk).await?;
                    let max = self.command(MAX_DPM_FREQ, clk).await?;
                    if min == 0 || min > max || max > u32::from(u16::MAX) {
                        return Err(Error::Invalid);
                    }
                    let pinned = if level == GfxLevel::High { max } else { min };
                    (pinned, pinned)
                }
            };
            self.command(SET_SOFT_MAX_BY_FREQ, clk | max).await?;
            self.command(SET_SOFT_MIN_BY_FREQ, clk | min).await?;
            Ok(())
        }
        .await;
        self.end_runtime(resume, &result);
        result
    }
    /// The PMFW running feature mask (`smu_cmn_get_enabled_mask`).
    async fn running_features(&mut self) -> Result<u64, Error> {
        let resume = self.begin_runtime()?;
        let result = self.running().await;
        self.end_runtime(resume, &result);
        result
    }
    async fn gfx_off_control(&mut self, allow: bool) -> Result<(), Error> {
        if self.gating_allowed & crate::amdgpu_navi22_power_policy::SMU_GFXOFF == 0 {
            return Err(Error::Invalid);
        }
        let resume = self.begin_runtime()?;
        let message = if allow { ALLOW_GFXOFF } else { DISALLOW_GFXOFF };
        let result = self.command(message, 0).await.map(|_| ());
        self.end_runtime(resume, &result);
        result
    }
    async fn enable_display_power(&mut self) -> Result<(), Error> {
        if self.state == State::DisplayPowerReady {
            return self.access(|_| ());
        }
        if self.state != State::PowerReady {
            return Err(Error::Busy);
        }
        let policy = self.power_policy.ok_or(Error::Invalid)?;
        let allowed = policy.display_allowed().map_err(|_| Error::Unsupported)?;
        self.state = State::EnablingDisplayPower;
        let result = async {
            if !self.scpm {
                self.command(ALLOWED_HIGH, (allowed >> 32) as u32).await?;
                self.command(ALLOWED_LOW, allowed as u32).await?;
            }
            self.command(ENABLE_FEATURES, 0).await?;
            let low = self.command(RUNNING_LOW, 0).await?;
            let high = self.command(RUNNING_HIGH, 0).await?;
            let enabled = u64::from(low) | u64::from(high) << 32;
            if !policy.validate_display(enabled) {
                return Err(Error::Features { allowed, enabled });
            }
            Ok(())
        }
        .await;
        self.state = if result.is_ok() {
            State::DisplayPowerReady
        } else {
            State::Failed
        };
        result
    }
}
/// Result of arming the SMU11 alert sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alert {
    /// THM/MP1 sources were programmed (board has a thermal controller).
    pub armed: bool,
    /// DIG_THERM_INTL / DIG_THERM_INTH, in °C.
    pub window: (u8, u8),
    /// `ReenableAcDcInterrupt` was sent (GPIO-signalled DC with ACDC running).
    pub acdc_rearmed: bool,
}
/// `MP1_SMN_IH_SW_INT_CTRL.INT_ACK` from the SMU-to-driver handler. Only this
/// register is touched; it is independent of the PPSMC mailbox, as in Linux's
/// `smu_v11_0_irq_process`.
#[derive(Clone, Copy, Debug)]
pub struct InterruptAck {
    regs: MmioRegion,
    at: u64,
    authority: Cap<BusDeviceCap, Write>,
}
impl InterruptAck {
    pub fn ack(&self) -> Result<(), Error> {
        let (regs, at) = (self.regs, self.at);
        self.authority
            .invoke(Op(|| {
                // SAFETY: MP1_SW_INT_CTRL, bounded at SMU construction.
                let value = unsafe { regs.read32(at) };
                if value == u32::MAX {
                    return Err(Error::DeviceGone);
                }
                // SAFETY: same register; read-modify-write sets only INT_ACK.
                unsafe { regs.write32(at, value | SW_INT_CTRL_ACK) };
                Ok(())
            }))
            .map_err(|_| Error::Revoked)?
    }
}
#[derive(Debug)]
pub struct Smu {
    profile: &'static crate::amdgpu_rdna2::Profile,
    engine: Engine<Mmio>,
}
impl Smu {
    pub(crate) async fn memory_range(&mut self, boot_khz: u64) -> Result<(u64, u64), Error> {
        self.engine.memory_range(boot_khz).await
    }
    /// # Safety
    /// Every display pipe and stream on this physical GPU must be retired.
    /// The exclusive DCN owner must install memory/fabric/display floors before
    /// enabling another stream. Cancellation retains EnablingDisplayPower.
    pub(crate) async unsafe fn enable_display_power(&mut self) -> Result<(), Error> {
        self.engine.enable_display_power().await
    }
    /// # Safety
    /// Caller owns this physical GPU's MP1 mailbox and reset/power controls
    /// exclusively, with permanent mappings. PSP must have successfully loaded
    /// SMC for this cold boot, with no mailbox command outstanding. This is not
    /// an attach/resume or firmware-reload path. Exclude legacy SMU helpers.
    pub unsafe fn after_upload(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Error> {
        mp1_bank(gpu)?;
        // SAFETY: forwarded exclusive post-upload GPU ownership contract.
        unsafe { Self::after_upload_rdna2(gpu, authority) }
    }
    /// Claim the common Sienna Cichlid SMU mailbox after profile-matched upload.
    /// # Safety
    /// Same exclusive physical GPU/MP1/reset contract as `after_upload`; this
    /// cold boot must have loaded this profile's PMFW and matching board table.
    pub unsafe fn after_upload_rdna2(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Error> {
        let profile = crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
            .ok_or(Error::Unsupported)?;
        crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_GC, &[profile.gc_version], 0, 0)
            .map_err(|_| Error::Unsupported)?;
        let base = crate::amdgpu_psp_ring::bank(
            gpu,
            discovery::HW_ID_MP1,
            &[profile.psp_version],
            0,
            RESPONSE,
        )
        .map_err(|_| Error::Unsupported)?;
        // The alert registers extend the same MP1 window past RESPONSE.
        crate::amdgpu_psp_ring::bank(
            gpu,
            discovery::HW_ID_MP1,
            &[profile.psp_version],
            0,
            MP1_SW_INT_CTRL,
        )
        .map_err(|_| Error::Invalid)?;
        let optional = |id, versions: &[(u8, u8, u8)], last| {
            crate::amdgpu_psp_ring::bank(gpu, id, versions, 0, last).ok()
        };
        let nbio_versions = [
            (2, 3, 0),
            (2, 3, 1),
            (2, 3, 2),
            (3, 3, 0),
            (3, 3, 1),
            (3, 3, 2),
            (3, 3, 3),
        ];
        Ok(Self {
            profile,
            engine: Engine {
                profile,
                io: Mmio {
                    regs: gpu.regs,
                    base,
                    hdp: optional(
                        discovery::HW_ID_HDP,
                        &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
                        0xd1, // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
                    ),
                    thm: runtime_bank(gpu, discovery::HW_ID_THM, CG_THERMAL_STATUS).ok(),
                    smuio: runtime_bank(gpu, discovery::HW_ID_SMUIO, SVI0_TEL_PLANE0).ok(),
                    pcie: optional(discovery::HW_ID_NBIF, &nbio_versions, PCIE_DATA2),
                    vram: gpu.fb_bar,
                    vram_size: gpu.vram.size,
                    // linux: n/a (MMIO_REG_HOLE_OFFSET + 4, end of the remapped flush register)
                    nbio: if gpu.regs.len >= 0x7f004 {
                        crate::amdgpu_psp_ring::bank(
                            gpu,
                            discovery::HW_ID_NBIF,
                            &[
                                (2, 3, 0),
                                (2, 3, 1),
                                (2, 3, 2),
                                (3, 3, 0),
                                (3, 3, 1),
                                (3, 3, 2),
                                (3, 3, 3),
                            ],
                            2,     // linux-lit: 2=mmREMAP_HDP_MEM_FLUSH_CNTL_BASE_IDX
                            0x12d, // linux-lit: 0x12d=mmREMAP_HDP_MEM_FLUSH_CNTL
                        )
                        .ok()
                    } else {
                        None
                    },
                },
                authority,
                state: State::Prepared,
                power_memory: None,
                power_policy: None,
                versions: None,
                limits: None,
                protection: None,
                scpm: false,
                gating_allowed: 0,
            },
        })
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// Send the prepared board table once after the version handshake. This
    /// does not enable DPM or run BTC. Nonzero/invalid PSP SCPM policy refuses
    /// the transfer before publishing an address or writing SMU commands.
    ///
    /// # Safety
    /// Caller owns this GPU's CPU-visible pool, HDP remap and VRAM index latch,
    /// with trained VRAM and completed PSP startup. The pool must use this
    /// GPU's GMC addresses and permanent mappings with all clients excluded.
    /// The table must come from this GPU's VBIOS, SMC image and PCI identity.
    /// Retain the SMU owner through failure/cancellation; do not reset or
    /// reuse its transfer buffer without independent hardware recovery.
    pub async unsafe fn upload_power_table(
        &mut self,
        table: &crate::amdgpu_power_navi22::Prepared,
        pool: &crate::amdgpu_vram::Pool,
    ) -> Result<(), Error> {
        if table.profile != self.profile {
            return Err(Error::Unsupported);
        }
        let policy = table.boot_policy().map_err(|_| Error::Unsupported)?;
        let info = table.info();
        self.engine.upload(table.bytes(), pool).await?;
        self.engine.power_policy = Some(policy);
        self.engine.limits = Limits::from_table(
            table.bytes(),
            info.software_shutdown_celsius,
            info.thermal_controller,
            info.platform_caps,
        );
        Ok(())
    }
    /// Run board calibration and enable the uploaded table's restricted boot
    /// policy once. Retains the owner/buffer on error or cancellation.
    ///
    /// # Safety
    /// All upload ownership contracts still apply. RLC autoload must have
    /// completed and queues must remain idle. This must precede any workload.
    /// Native DCN clock policy and OS thermal interrupt handling are separate.
    pub async unsafe fn configure_power(&mut self) -> Result<PowerStatus, Error> {
        self.engine.configure_power().await
    }
    /// Query the interface and running firmware version once. Cancellation
    /// retains Querying and prevents replay. Success does not enable DPM.
    pub async fn verify(&mut self) -> Result<Versions, Error> {
        self.engine.verify().await
    }
    pub fn versions(&self) -> Option<Versions> {
        self.engine.versions
    }
    /// Board limits of the uploaded table; None without a valid table.
    pub fn limits(&self) -> Option<Limits> {
        self.engine.limits
    }
    /// Every protection feature running after boot setup still runs.
    pub fn protected(&self, enabled: u64) -> bool {
        self.engine.protected(enabled)
    }
    /// One PMFW metrics refresh after boot power setup. It shares the
    /// retained transfer buffer and the mailbox; a clean rejection leaves the
    /// owner reusable, timeouts/device loss are terminal.
    pub async fn read_telemetry(&mut self) -> Result<Telemetry, Error> {
        self.engine.read_telemetry().await
    }
    /// Arm the THM/MP1 alert sources once IH routes them (Linux enables them
    /// in smu_smc_hw_setup, after IH hw_init). Fan control stays automatic.
    pub async fn enable_thermal_alert(&mut self) -> Result<Alert, Error> {
        self.engine.enable_thermal_alert().await
    }
    /// Re-arm AC/DC notification after an AC/DC SMU-to-driver interrupt.
    pub async fn reenable_acdc_interrupt(&mut self) -> Result<(), Error> {
        self.engine.reenable_acdc().await
    }
    /// Switch opt-in power-saving feature bits (`GATING_FEATURES` only),
    /// returning the running set. Rejection leaves the owner reusable.
    ///
    /// # Safety
    /// `amdgpu_navi22_power_policy` admitted every feature these bits belong
    /// to (display admission and driver readiness) under the explicit opt-in,
    /// and the DCN owner holds whatever floors that admission assumed.
    pub(crate) async unsafe fn update_gating_features(
        &mut self,
        mask: u64,
        enable: bool,
    ) -> Result<u64, Error> {
        self.engine.update_features(mask, enable).await
    }
    /// AllowGfxOff/DisallowGfxOff for `amdgpu_navi22_gfxoff`.
    pub(crate) async fn gfx_off_control(&mut self, allow: bool) -> Result<(), Error> {
        self.engine.gfx_off_control(allow).await
    }
    /// `power_dpm_force_performance_level` for GFXCLK; see
    /// [`Engine::set_gfx_level`]. Rejection leaves the owner reusable.
    pub async fn set_gfx_level(&mut self, level: GfxLevel) -> Result<(), Error> {
        self.engine.set_gfx_level(level).await
    }
    /// The PMFW running feature mask, for `pp_features`.
    pub async fn running_features(&mut self) -> Result<u64, Error> {
        self.engine.running_features().await
    }
    /// Opt-in bits enabled at runtime through `update_gating_features`.
    pub fn gating_features(&self) -> u64 {
        self.engine.gating_allowed
    }
    /// The SMU-to-driver acknowledge register handle.
    pub fn interrupt_ack(&self) -> InterruptAck {
        InterruptAck {
            regs: self.engine.io.regs,
            at: self.engine.io.base + u64::from(MP1_SW_INT_CTRL) * 4,
            authority: self.engine.authority,
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_navi22_tests.rs"]
pub(crate) mod tests;
