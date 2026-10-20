//! Linux amdgpu_ras as it applies to Navi48 (MP0 14.0.3, GC 12.0.1, UMC 8.14,
//! NBIF 6.3.1, VCN/JPEG 5.0.0) on bare metal, nothing more.
//!
//! amdgpu_ras_asic_supported accepts MP0 14.0.3, PSP14 has no
//! get_ras_capability, so amdgpu_ras_check_supported takes its block mask
//! from the VBIOS (amdgpu_ras_query_ras_capablity_from_vbios): umc_info's
//! ECC-capable bit enables UMC and DF, firmware_info's SRAM_ECC enables every
//! other block except VCN/JPEG (VCN 5.0.0 is not listed) and XGMI. A consumer
//! board reporting neither leaves `ras_enabled == 0` and Linux frees the RAS
//! context: no poison or ECC vector does anything at all.
//!
//! Even with RAS enabled, Navi48's IPs register very little:
//! - gfx_v12_0, sdma_v7_0, gmc_v12_0's UTCL2 and jpeg_v5_0_0 register no
//!   poison/ECC source; KFD v11's ISR drops them too (it never accepts
//!   SDMA_ECC, and SQ errors only for KFD VMIDs 8..15).
//! - vcn_v5_0_0 registers UVD_POISON, but amdgpu_vcn_process_poison_irq
//!   returns without a VCN RAS object (only VCN 5.0.1 has one).
//! - gmc_v12_0's DF source 0 reaches amdgpu_umc_process_ecc_irq. With UMC RAS
//!   enabled (UMC 8.14 has no poison mode), amdgpu_ras_interrupt_umc_handler
//!   sets FED and amdgpu_umc_do_page_retirement queries/clears the UMC 8.14
//!   channel counters; an uncorrectable count requests a mode-1 reset.
//!   UMC 8.14 has no error-address query, so no page is retired.
//! - nbif_v6_3_1's ERREVENT_ATHUB IV handler is a dummy. With DF RAS enabled,
//!   amdgpu_ras_interrupt_fatal_error_handler polls BIF_DOORBELL_INT_CNTL
//!   after each IH pass; a set status is cleared and amdgpu_ras_global_ras_isr
//!   sets FED and requests a mode-1 reset.
//!
//! The reset itself is the platform's existing device recovery, reached by a
//! terminal dispatch error. The RAS TA feature-enable command is not sent:
//! amdgpu_ras_feature_enable_on_boot falls back to the same software object
//! when the TA refuses it.
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_ih7 as ih, amdgpu_navi48_sources as src,
    amdgpu_psp_ring::bank,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// `enum amdgpu_ras_block`.
pub mod block {
    pub const UMC: u32 = 0;
    pub const SDMA: u32 = 1;
    pub const GFX: u32 = 2;
    pub const MMHUB: u32 = 3;
    pub const ATHUB: u32 = 4;
    pub const PCIE_BIF: u32 = 5;
    pub const HDP: u32 = 6;
    pub const XGMI_WAFL: u32 = 7;
    pub const DF: u32 = 8;
    pub const VCN: u32 = 15;
    pub const JPEG: u32 = 16;
    pub const MMSCH: u32 = 19;
    pub const LAST: u32 = 20;
}
/// `AMDGPU_RAS_BLOCK_MASK`.
pub const BLOCK_MASK: u32 = (1 << block::LAST) - 1;
/// atomfirmware.h UMC_CONFIG__DEFAULT_MEM_ECC_ENABLE / UMC_CONFIG1__ENABLE_ECC_CAPABLE.
pub const UMC_CONFIG_DEFAULT_MEM_ECC: u8 = 0x02;
pub const UMC_CONFIG1_ECC_CAPABLE: u32 = 0x0001_0000;
pub const FIRMWARE_CAP_SRAM_ECC: u32 = crate::amdgpu_atom_fwinfo::ATOM_FIRMWARE_CAP_SRAM_ECC;

/// umc_8_14_0_offset.h (BASE_IDX 0) and umc_v8_14.h.
const GECC_ERR_CNT_SEL: u32 = 0x328;
const GECC_ERR_CNT: u32 = 0x329;
const GECC_ERR_INT_MASK: u32 = 0x3000;
/// GeccErrInt = 1: APIC-based correctable-error interrupt.
const GECC_ERR_INT_APIC: u32 = 0x1000;
const CHANNELS_PER_UMC: u32 = 2;
const PER_CHANNEL: u32 = 0x400;
const INST_DIST: u32 = 0x40000;
/// UMC_V8_14_CE_CNT_INIT: CE_CNT_MAX - CE_INT_THRESHOLD.
const CE_CNT_INIT: u32 = 0xffff - 0xffff;
pub const MAX_UMCS: usize = 16;
pub const MAX_CHANNELS: usize = MAX_UMCS * CHANNELS_PER_UMC as usize;
/// nbif_6_3_1_offset.h: RSMU index/data (BASE_IDX 1), BIF_DOORBELL_INT_CNTL
/// (BASE_IDX 2) and its RAS_ATHUB_ERR_EVENT fields.
const RSMU_INDEX: u32 = 0;
const RSMU_DATA: u32 = 1;
const DOORBELL_INT_CNTL: u32 = 0xfe;
const ATHUB_STATUS: u32 = 1 << 2;
const ATHUB_CLEAR: u32 = 1 << 18;
const ATHUB_DISABLE: u32 = 1 << 26;

/// VBIOS RAS capability bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    pub mem_ecc: bool,
    /// `ras_default_ecc_enabled`; informational only.
    pub default_mem_ecc: bool,
    pub sram_ecc: bool,
}
/// amdgpu_atomfirmware_mem_ecc_supported for one umc_info table:
/// `(mem_ecc, default_mem_ecc)`. Unknown revisions report no ECC.
pub fn umc_info_ecc(table: &[u8]) -> (bool, bool) {
    let byte = |at: usize| table.get(at).copied();
    let word = |at: usize| {
        table
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let (Some(frev), Some(crev)) = (byte(2), byte(3)) else {
        return (false, false);
    };
    // umc_config is byte 27 in v3.1..v4.0; umc_config1 is dword 52.
    let config = byte(27).unwrap_or(0);
    let config1 = word(52).unwrap_or(0);
    let default = config & UMC_CONFIG_DEFAULT_MEM_ECC != 0;
    match (frev, crev) {
        (3, 1 | 2) => (default, false),
        (3, 3) => (default || config1 & UMC_CONFIG1_ECC_CAPABLE != 0, default),
        (4, 0) => (config1 & UMC_CONFIG1_ECC_CAPABLE != 0, default),
        _ => (false, false),
    }
}
/// amdgpu_atomfirmware_query_firmware_capability (firmware_info 3.1+).
pub fn firmware_capability(table: &[u8]) -> u32 {
    match (table.get(2), table.get(3), table.get(0x10..0x14)) {
        (Some(&frev), Some(&crev), Some(b)) if (frev == 3 && crev >= 1) || frev > 3 => {
            u32::from_le_bytes(b.try_into().unwrap())
        }
        _ => 0,
    }
}
impl Caps {
    pub fn from_tables(firmware_info: Option<&[u8]>, umc_info: Option<&[u8]>) -> Self {
        let (mem_ecc, default_mem_ecc) = umc_info.map_or((false, false), umc_info_ecc);
        Self {
            mem_ecc,
            default_mem_ecc,
            sram_ecc: firmware_info
                .is_some_and(|t| firmware_capability(t) & FIRMWARE_CAP_SRAM_ECC != 0),
        }
    }
    /// Master data table entries 4 (firmwareinfo) and 24 (umc_info).
    pub fn from_vbios(vbios: &[u8]) -> Self {
        use crate::atombios::{header::parse_rom_header, tables::MasterDataTable};
        let Ok(header) = parse_rom_header(vbios) else {
            return Self::default();
        };
        let Ok(tables) = MasterDataTable::parse(vbios, &header) else {
            return Self::default();
        };
        Self::from_tables(tables.table_slice(4), tables.table_slice(24))
    }
}
/// amdgpu_ras_check_supported's `ras_hw_enabled` for bare-metal Navi48
/// (not CPU-attached, no XGMI, VCN 5.0.0), before the module-parameter mask.
pub const fn hw_enabled(caps: Caps) -> u32 {
    let mut mask = 0;
    if caps.mem_ecc {
        mask |= 1 << block::UMC | 1 << block::DF;
    }
    if caps.sram_ecc {
        mask |= !(1 << block::UMC | 1 << block::DF);
        mask &= !(1 << block::VCN | 1 << block::JPEG);
        mask &= !(1 << block::XGMI_WAFL);
    }
    mask & BLOCK_MASK
}
/// Linux's RAS state with default module parameters (`amdgpu_ras_enable`
/// -1, `amdgpu_ras_mask` all ones): `ras_enabled == ras_hw_enabled`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub caps: Caps,
    pub enabled: u32,
    /// UMC IP 8.14.0, so gmc_v12_0 installs umc_v8_14_ras.
    pub umc_8_14: bool,
    /// NBIO IP 6.3.1, so amdgpu_ras_init may install nbif_v6_3_1_ras.
    pub nbif_6_3_1: bool,
}
impl Policy {
    pub const fn new(caps: Caps, umc_8_14: bool, nbif_6_3_1: bool) -> Self {
        Self {
            caps,
            enabled: hw_enabled(caps),
            umc_8_14,
            nbif_6_3_1,
        }
    }
    /// amdgpu_ras_is_supported (poison mode is never supported here).
    pub const fn supported(self, block: u32) -> bool {
        block < block::LAST && self.enabled & (1 << block) != 0
    }
    /// The UMC RAS object exists and its ECC interrupt is handled.
    pub const fn umc(self) -> bool {
        self.umc_8_14 && self.supported(block::UMC)
    }
    /// nbif_v6_3_1_ras is installed: the ATHUB fatal-error status is polled.
    pub const fn fatal_polling(self) -> bool {
        self.nbif_6_3_1 && self.supported(block::DF)
    }
}
/// Why Linux does nothing for a poison/ECC vector on Navi48.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignored {
    /// No amdgpu source handler, and KFD v11's ISR does not accept it.
    Unregistered,
    /// A handler exists but returns without a RAS object for this IP.
    NoRasBlock,
    /// The UMC RAS object is not set up: RAS disabled or no UMC 8.14.
    Disabled,
    /// The IV is a dummy; the fatal error is found by register polling.
    Polled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Ignored(Ignored),
    /// Query and clear the UMC channel counters.
    UmcQuery,
}
pub const fn disposition(policy: Policy, poison: src::Poison) -> Disposition {
    use src::Poison as P;
    Disposition::Ignored(match poison {
        P::Utcl2
        | P::RlcFed
        | P::CpEcc
        | P::CpFue
        | P::SdmaEcc { .. }
        | P::SdmaSramEcc { .. }
        | P::Shader { .. } => Ignored::Unregistered,
        P::Media { source: 160, .. } => Ignored::NoRasBlock,
        P::Media { .. } => Ignored::Unregistered,
        P::Athub => Ignored::Polled,
        P::Umc if policy.umc() => return Disposition::UmcQuery,
        P::Umc => Ignored::Disabled,
    })
}
/// A RAS event after which Linux requests a mode-1 reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fatal {
    /// Uncorrectable UMC errors counted after an ECC interrupt.
    Umc { ce: u64, ue: u64 },
    /// ERREVENT_ATHUB: DF is frozen by a fatal error.
    Athub { raw: u32 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Revoked,
    DeviceGone,
    Readback,
    Busy,
}
/// Raw UMC counters as read, before they were cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UmcEvidence {
    /// The ECC IV, or `None` for the counts read while arming.
    pub event: Option<ih::Event>,
    pub raw: [u32; MAX_CHANNELS],
    pub channels: u8,
    pub ce: u64,
    pub ue: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub policy: Policy,
    pub armed: bool,
    /// amdgpu_ras_set_fed: a fatal-error-detected state was entered.
    pub fed: bool,
    /// Poison/ECC vectors Linux leaves unhandled on this board.
    pub ignored: u64,
    pub first_ignored: Option<(ih::Event, src::Poison, Ignored)>,
    pub last_ignored: Option<(ih::Event, src::Poison, Ignored)>,
    pub umc_interrupts: u64,
    pub ce: u64,
    pub ue: u64,
    pub boot: Option<UmcEvidence>,
    pub last_umc: Option<UmcEvidence>,
    pub fatal: Option<Fatal>,
    pub error: Option<Error>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    /// UMC instance-0 dword base in the indirect (SMN) space.
    umc: u32,
    umcs: u8,
    index: u64,
    data: u64,
    doorbell: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu, policy: Policy) -> Result<Self, Error> {
        let nbif = |index, last| {
            bank(gpu, ip::HW_ID_NBIF, &[(6, 3, 1)], index, last).map_err(|_| Error::Unsupported)
        };
        let mut umc = None;
        let mut umcs = 0usize;
        if policy.umc() {
            for b in gpu.ip_blocks.iter().filter(|b| b.hw_id == ip::HW_ID_UMC) {
                if b.instance == 0 {
                    umc = Some(b.base_addrs[0]);
                }
                umcs += 1;
            }
            if umc.is_none_or(|b| b == 0) || umcs > MAX_UMCS {
                return Err(Error::Unsupported);
            }
        }
        Ok(Self {
            umc: umc.unwrap_or(0),
            umcs: umcs as u8,
            index: nbif(1, RSMU_DATA)? + u64::from(RSMU_INDEX) * 4,
            data: nbif(1, RSMU_DATA)? + u64::from(RSMU_DATA) * 4,
            doorbell: nbif(2, DOORBELL_INT_CNTL)? + u64::from(DOORBELL_INT_CNTL) * 4,
        })
    }
    fn umc_addr(self, umc: u32, channel: u32, reg: u32) -> u32 {
        (self.umc + reg + PER_CHANNEL * channel + INST_DIST * umc) * 4
    }
    fn channels(self) -> impl Iterator<Item = (u32, u32)> {
        (0..u32::from(self.umcs)).flat_map(|u| (0..CHANNELS_PER_UMC).map(move |c| (u, c)))
    }
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: discovery-bounded NBIF registers on the retained mapping,
        // accessed under the monitor's live authority.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: same bounded, exclusively owned NBIF registers.
        unsafe { self.0.write32(at, value) }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn checked(v: u32) -> Result<u32, Error> {
    if v == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(v)
    }
}
/// amdgpu_device_indirect_rreg/wreg through nbif_v6_3_1's RSMU pair.
fn pcie_read(io: &mut impl Io, l: Layout, addr: u32) -> Result<u32, Error> {
    io.write(l.index, addr);
    if checked(io.read(l.index))? != addr {
        return Err(Error::Readback);
    }
    checked(io.read(l.data))
}
fn pcie_write(io: &mut impl Io, l: Layout, addr: u32, value: u32) -> Result<(), Error> {
    io.write(l.index, addr);
    if checked(io.read(l.index))? != addr {
        return Err(Error::Readback);
    }
    io.write(l.data, value);
    checked(io.read(l.data))?;
    Ok(())
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Option<Layout>,
    status: Status,
}
impl<I: Io> Engine<I> {
    fn new(
        io: I,
        authority: Cap<BusDeviceCap, Write>,
        layout: Option<Layout>,
        policy: Policy,
    ) -> Self {
        Self {
            io,
            authority,
            layout,
            status: Status {
                policy,
                armed: false,
                fed: false,
                ignored: 0,
                first_ignored: None,
                last_ignored: None,
                umc_interrupts: 0,
                ce: 0,
                ue: 0,
                boot: None,
                last_umc: None,
                fatal: None,
                error: None,
            },
        }
    }
    fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I, Layout) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let layout = self.layout.ok_or(Error::Unsupported)?;
        let io = &mut self.io;
        let result = self
            .authority
            .invoke(Op(|| f(io, layout)))
            .map_err(|_| Error::Revoked)
            .and_then(|r| r);
        if let Err(e) = result {
            self.status.error.get_or_insert(e);
        }
        result
    }
    /// umc_v8_14_query_ras_error_count: read every channel, then clear it.
    fn query(&mut self, event: Option<ih::Event>) -> Result<UmcEvidence, Error> {
        self.access(|io, l| {
            let mut e = UmcEvidence {
                event,
                raw: [0; MAX_CHANNELS],
                channels: 0,
                ce: 0,
                ue: 0,
            };
            for (i, (u, c)) in l.channels().enumerate() {
                let raw = pcie_read(io, l, l.umc_addr(u, c, GECC_ERR_CNT))?;
                e.raw[i] = raw;
                e.channels += 1;
                e.ce += u64::from((raw & 0xffff).wrapping_sub(CE_CNT_INIT) & 0xffff);
                e.ue += u64::from((raw >> 16).wrapping_sub(CE_CNT_INIT) & 0xffff);
            }
            // Evidence first; umc_v8_14_clear_error_count afterwards.
            for (u, c) in l.channels() {
                pcie_write(io, l, l.umc_addr(u, c, GECC_ERR_CNT), CE_CNT_INIT)?;
            }
            Ok(e)
        })
    }
    /// amdgpu_umc_ras_late_init (boot count query + umc_v8_14_err_cnt_init)
    /// and soc24_common_late_init's ATHUB error-event enable.
    fn arm(&mut self) -> Result<(), Error> {
        if self.status.armed {
            return Err(Error::Busy);
        }
        let policy = self.status.policy;
        if policy.umc() {
            self.status.boot = Some(self.query(None)?);
            self.access(|io, l| {
                for (u, c) in l.channels() {
                    let at = l.umc_addr(u, c, GECC_ERR_CNT_SEL);
                    let sel = pcie_read(io, l, at)?;
                    pcie_write(io, l, at, (sel & !GECC_ERR_INT_MASK) | GECC_ERR_INT_APIC)?;
                    pcie_write(io, l, l.umc_addr(u, c, GECC_ERR_CNT), CE_CNT_INIT)?;
                }
                Ok(())
            })?;
        }
        if policy.fatal_polling() {
            self.access(|io, l| {
                let v = checked(io.read(l.doorbell))?;
                io.write(l.doorbell, v & !ATHUB_DISABLE);
                if checked(io.read(l.doorbell))? & ATHUB_DISABLE != 0 {
                    return Err(Error::Readback);
                }
                Ok(())
            })?;
        }
        self.status.armed = true;
        Ok(())
    }
    fn fatal(&mut self, fatal: Fatal) -> Option<Fatal> {
        self.status.fed = true;
        // amdgpu_ras_in_intr: only the first fatal event resets.
        if self.status.fatal.is_some() {
            return None;
        }
        self.status.fatal = Some(fatal);
        Some(fatal)
    }
    /// One poison/ECC vector, after its IV has been recorded.
    fn handle(&mut self, event: ih::Event, poison: src::Poison) -> Result<Option<Fatal>, Error> {
        match disposition(self.status.policy, poison) {
            Disposition::Ignored(why) => {
                self.status.ignored = self.status.ignored.saturating_add(1);
                self.status
                    .first_ignored
                    .get_or_insert((event, poison, why));
                self.status.last_ignored = Some((event, poison, why));
                Ok(None)
            }
            Disposition::UmcQuery => {
                self.status.umc_interrupts = self.status.umc_interrupts.saturating_add(1);
                // amdgpu_ras_interrupt_umc_handler sets FED before the callback.
                self.status.fed = true;
                if !self.status.armed {
                    return Err(Error::Busy);
                }
                let e = self.query(Some(event))?;
                self.status.ce = self.status.ce.saturating_add(e.ce);
                self.status.ue = self.status.ue.saturating_add(e.ue);
                self.status.last_umc = Some(e);
                Ok(if e.ue != 0 {
                    self.fatal(Fatal::Umc { ce: e.ce, ue: e.ue })
                } else {
                    None
                })
            }
        }
    }
    /// amdgpu_ras_interrupt_fatal_error_handler, run after every IH pass.
    fn poll(&mut self) -> Result<Option<Fatal>, Error> {
        if !self.status.policy.fatal_polling() || !self.status.armed {
            return Ok(None);
        }
        let raw = self.access(|io, l| {
            let v = checked(io.read(l.doorbell))?;
            if v & ATHUB_STATUS != 0 {
                io.write(l.doorbell, v | ATHUB_CLEAR);
            }
            Ok(v)
        })?;
        Ok(if raw & ATHUB_STATUS != 0 {
            self.fatal(Fatal::Athub { raw })
        } else {
            None
        })
    }
}
#[derive(Debug)]
pub(crate) struct Monitor(Engine<Mmio>);
impl Monitor {
    /// # Safety
    /// Own this physical GPU and its permanent register mapping; exclude other
    /// NBIF doorbell-interrupt and UMC counter writers. Construction performs
    /// no device access.
    pub(crate) unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Error> {
        let caps = gpu
            .vbios
            .as_ref()
            .map_or(Caps::default(), |v| Caps::from_vbios(v.bytes()));
        let version = |id| {
            let mut blocks = gpu.ip_blocks.iter().filter(|b| b.hw_id == id).peekable();
            let first = blocks.peek().map(|b| (b.major, b.minor, b.revision));
            (
                first,
                blocks.all(|b| Some((b.major, b.minor, b.revision)) == first),
            )
        };
        let (umc, uniform) = version(ip::HW_ID_UMC);
        let policy = Policy::new(
            caps,
            uniform && umc == Some((8, 14, 0)),
            version(ip::HW_ID_NBIF).0 == Some((6, 3, 1)),
        );
        let layout = if policy.umc() || policy.fatal_polling() {
            Some(Layout::resolve(gpu, policy)?)
        } else {
            None
        };
        Ok(Self(Engine::new(Mmio(gpu.regs), authority, layout, policy)))
    }
    pub(crate) fn arm(&mut self) -> Result<(), Error> {
        self.0.arm()
    }
    pub(crate) fn handle(
        &mut self,
        event: ih::Event,
        poison: src::Poison,
    ) -> Result<Option<Fatal>, Error> {
        self.0.handle(event, poison)
    }
    pub(crate) fn poll(&mut self) -> Result<Option<Fatal>, Error> {
        self.0.poll()
    }
    pub(crate) fn status(&self) -> Status {
        self.0.status
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_ras_tests.rs"]
mod tests;
