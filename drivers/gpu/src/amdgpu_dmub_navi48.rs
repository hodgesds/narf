//! DCN4.0.1 DMUB lifecycle after PSP authentication. Linux dmub_dcn401.c reset,
//! dmub_dcn401.c windows and dmub_srv.c layout. No secure-window writes,
//! direct firmware loading, native modeset or implicit reset.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip, amdgpu_dmub_firmware as fw,
    amdgpu_psp_ring::{bank, Psp},
    amdgpu_vram::{Pool, Reservation},
};
use alloc::vec::Vec;
use core::{
    ops::Range,
    sync::atomic::{fence, Ordering},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
const CNTL: u32 = 0x1f6;
const CNTL2: u32 = 0x200;
const RESET: u32 = 1; // DCN401: separate CNTL2 reset
const ENABLE: u32 = 1 << 16;
const HUB: u32 = 0x341; // DCN31 instead uses 0x342
const GPINT: u32 = 0x1f8;
const STOP: u32 = 0x10020000;
const STATUS: u32 = 0x1e3;
const MASK: u32 = 0x1fffffff;
const NATIVE_CHANNELS: u8 = 4;
/// GPINT version replies must match the firmware header on this generation.
const STRICT_VERSION: bool = true;
#[allow(
    clippy::duplicate_mod,
    reason = "instantiate the shared protocol against each generation's private Engine and register accessors"
)]
#[path = "amdgpu_dmub_navi22_mailbox.rs"]
mod mailbox;
pub use mailbox::{FeatureCaps, MailboxState};
/// Signal supplied to native transmitter control, independent of HPO instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpSignal {
    Sst,
    Mst,
}
/// Legacy 8b/10b PHY request. The caller validates board/sink/cable limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpPhySettings {
    pub lanes: u8,
    pub rate: crate::dp_link_training::LinkRate,
    /// The link carries MST (8b/10b DP_MST: transmitter control digmode 5,
    /// DIG_BE_MODE 5).
    pub mst: bool,
}
impl DpPhySettings {
    pub(crate) fn validate(self) -> Result<(), Error> {
        if !matches!(self.lanes, 1 | 2 | 4) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
/// A DP 128b/132b (UHBR) per-lane rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UhbrRate {
    Uhbr10,
    Uhbr13_5,
    Uhbr20,
}
impl UhbrRate {
    /// Ascending, as Linux's increase_link_rate walks them.
    pub const ALL: [Self; 3] = [Self::Uhbr10, Self::Uhbr13_5, Self::Uhbr20];
    /// DC's link_rate: units of 10 Mbps per lane (LINK_RATE_UHBR10 = 1000).
    pub fn link_rate(self) -> u32 {
        match self {
            Self::Uhbr10 => 1000,
            Self::Uhbr13_5 => 1350,
            Self::Uhbr20 => 2000,
        }
    }
    /// LINK_BW_SET (0x100) for 128b/132b: get_dpcd_link_rate.
    pub fn dpcd_code(self) -> u8 {
        match self {
            Self::Uhbr10 => 0x01,
            Self::Uhbr20 => 0x02,
            Self::Uhbr13_5 => 0x04,
        }
    }
    /// The rate's bit in DP_128B132B_SUPPORTED_LINK_RATES (0x2215) and an
    /// LTTPR's 0xF0007, which share this layout.
    pub fn dpcd_bit(self) -> u8 {
        self.dpcd_code()
    }
}
/// Common drive level for all active legacy DP lanes, as required by native DC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DpDriveSettings {
    pub swing: u8,
    pub pre_emphasis: u8,
}
impl DpDriveSettings {
    pub(crate) fn validate(self) -> Result<(), Error> {
        if self.swing > 3 || self.pre_emphasis > 3 || self.swing + self.pre_emphasis > 3 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    StopTimeout,
    BootTimeout,
    CommandTimeout,
    Protocol,
    NotificationOverflow,
    CommandRejected(u32),
    Aux(u8),
    Readback,
    Firmware(fw::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Stopping,
    Reset,
    Starting,
    Running,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub firmware_version: u32,
    pub boot_status: u32,
    pub inbox: u64,
    pub outbox: u64,
    /// Present only when firmware acknowledges QUERY_FEATURE_CAPS.
    pub capabilities: Option<FeatureCaps>,
}
/// Immutable ordinary-RAM preparation. No device I/O or implied VRAM ownership.
#[derive(Debug)]
pub struct Prepared {
    layout: fw::Layout,
    bytes: Vec<u8>,
    version: u32,
    psp_version: u32,
}
impl Prepared {
    pub fn new(image: &[u8], vbios: &[u8], psp_version: u32) -> Result<Self, Error> {
        let image = fw::Image::parse(image).map_err(Error::Firmware)?;
        let version = image.metadata().version;
        let prepared = image.prepare_dcn401(vbios).map_err(Error::Firmware)?;
        let layout = prepared.layout();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(layout.size() as usize)
            .map_err(|_| Error::Allocation)?;
        bytes.resize(layout.size() as usize, 0);
        prepared.stage(&mut bytes).map_err(Error::Firmware)?;
        Ok(Self {
            layout,
            bytes,
            version,
            psp_version,
        })
    }
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    dcn: u64,
    nbio: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_none() || gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            dcn: bank(gpu, ip::HW_ID_DCN, &[(4, 0, 1), (4, 1, 0)], 2, 0x477)
                .map_err(|_| Error::Unsupported)?,
            nbio: bank(
                gpu,
                ip::HW_ID_NBIF,
                &[(7, 7, 0), (7, 7, 1), (6, 3, 1)],
                2,
                0x12d,
            )
            .map_err(|_| Error::Unsupported)?,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn upload(&mut self, map: MmioRegion, offset: u64, value: u32);
    fn download(&mut self, map: MmioRegion, offset: u64) -> u32;
    /// Read-driven register models can use a bounded number of cooperative
    /// polls instead of a wall-clock deadline. Real MMIO always uses time.
    /// (Required by the shared navi22 mailbox instantiation; no navi48
    /// fixture sets a limit, so navi48 waits stay deadline-bound.)
    #[cfg(feature = "kernel-test")]
    fn wait_poll_limit(&self) -> Option<u32> {
        None
    }
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: exact DCN401/NBIO banks and HDP hole bounded at construction;
        // the exclusive owner performs all accesses under live PCI authority.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same bounded permanent mapping and live authority.
        unsafe { self.0.write32(address, value) };
    }
    fn upload(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: prepared layout bounds these dwords to the retained owned
        // allocation. Firmware receives each mailbox slot only after flushing.
        unsafe { map.write32(offset, value) };
    }
    fn download(&mut self, map: MmioRegion, offset: u64) -> u32 {
        // SAFETY: fixed mailbox slots are bounded by the retained allocation;
        // live authority and HDP invalidation precede each reply read.
        unsafe { map.read32(offset) }
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
fn read(io: &mut impl Io, base: u64, reg: u32) -> Result<u32, Error> {
    checked(io.read(base + u64::from(reg) * 4))
}
fn update(io: &mut impl Io, base: u64, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
    let old = read(io, base, reg)?;
    io.write(base + u64::from(reg) * 4, (old & !mask) | value);
    Ok(())
}
fn is_reset(io: &mut impl Io, base: u64) -> Result<bool, Error> {
    Ok(read(io, base, CNTL2)? & RESET != 0
        && read(io, base, CNTL)? & ENABLE == 0
        && read(io, base, HUB)? & 0x100 != 0)
}
fn is_running(io: &mut impl Io, l: Layout) -> Result<bool, Error> {
    Ok(read(io, l.dcn, CNTL2)? & RESET == 0
        && read(io, l.dcn, CNTL)? & ENABLE != 0
        && read(io, l.dcn, HUB)? & 0x100 == 0
        && read(io, l.dcn, STATUS)? & 3 == 3)
}
fn invalidate(io: &mut impl Io, l: Layout) {
    // HDP6 generic flush; no HDP5 invalidate register exists on this profile.
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    io.read(l.nbio + 0xc3 * 4);
    fence(Ordering::SeqCst);
}
async fn tick() {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    prepared: Prepared,
    state: State,
    status: Option<Status>,
    mailbox: mailbox::Mailbox,
    /// A late inbox0 ACK must never satisfy a later strict FAMS2 lock.
    hw_lock_uncertain: bool,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    async fn quiesce(&mut self) -> Result<(), Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Stopping;
        let result = self.quiesce_inner().await;
        self.state = if result.is_ok() {
            State::Reset
        } else {
            State::Failed
        };
        result
    }
    async fn quiesce_inner(&mut self) -> Result<(), Error> {
        let base = self.layout.dcn;
        let control = self.access(|io| {
            if read(io, base, 0xca)? & (1 << 16) == 0 {
                return Err(Error::Unsupported);
            }
            read(io, base, CNTL)
        })?;
        let reset = self.access(|io| read(io, base, CNTL2))?;
        if reset & RESET == 0 && control & ENABLE != 0 {
            self.access(|io| {
                io.write(base + u64::from(GPINT) * 4, STOP);
                Ok(())
            })?;
            let deadline = narf_time::Deadline::after_ms(1000);
            loop {
                if self.access(|io| {
                    Ok(read(io, base, GPINT)? == STOP & !(1 << 28)
                        && read(io, base, 0x1ea)? == 0xdeaddead
                        && read(io, base, CNTL)? & (1 << 20) != 0)
                })? {
                    break;
                }
                if deadline.expired() {
                    return Err(Error::StopTimeout);
                }
                tick().await;
            }
        }
        self.access(|io| update(io, base, CNTL2, RESET, RESET))?;
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
        self.access(|io| {
            io.write(base + u64::from(GPINT) * 4, 0);
            update(io, base, CNTL, ENABLE, 0)?;
            update(io, base, HUB, 0x100, 0x100)?;
            if !is_reset(io, base)? {
                return Err(Error::Readback);
            }
            // Never touch SEC_CNTL or CW0/CW1: PSP owns their authentication.
            for reg in 0x1af..=0x1b4 {
                update(io, base, reg, 1 << 31, 0)?;
            }
            for reg in [0x1d6, 0x1d7, 0x1da, 0x1db, 0x1de, 0x1df, STATUS] {
                io.write(base + u64::from(reg) * 4, 0);
            }
            Ok(())
        })
    }
    async fn start(&mut self, tmr: Range<u64>) -> Result<Status, Error> {
        if self.state != State::Reset {
            return Err(Error::Busy);
        }
        self.state = State::Starting;
        let result = self.start_inner(tmr).await;
        self.state = if result.is_ok() {
            State::Running
        } else {
            State::Failed
        };
        if let Ok(status) = result {
            self.status = Some(status);
        }
        result
    }
    async fn start_inner(&mut self, tmr: Range<u64>) -> Result<Status, Error> {
        let l = self.layout;
        let address = self.memory.address();
        let shape = self.prepared.layout;
        let placement = self.access(|io| {
            if !is_reset(io, l.dcn)? || read(io, l.dcn, 0x1ce)? & (1 << 16) != 0 {
                return Err(Error::Busy);
            }
            let fb = u64::from(read(io, l.dcn, 0x475)? & 0xffffff) << 24;
            let end = (u64::from(read(io, l.dcn, 0x476)? & 0xffffff) + 1) << 24;
            let offset = u64::from(read(io, l.dcn, 0x477)? & 0xffffff) << 24;
            let place = shape.place(address, fb..end).map_err(Error::Firmware)?;
            if tmr.start < fb
                || tmr.start >= tmr.end
                || tmr.end > end
                || offset.checked_add(end - fb).is_none_or(|v| v > 1 << 48)
                || checked(io.read(l.nbio + 0x12d * 4))? != 0x7f000
            {
                return Err(Error::Invalid);
            }
            let physical = (tmr.start - fb + offset)..(tmr.end - fb + offset);
            // Validate PSP's authenticated instruction and stack windows, but
            // preserve them verbatim. They use GPU-physical VRAM addresses.
            for index in 0..2 {
                let base = read(io, l.dcn, 0x1a5 + index)? & MASK;
                let top = read(io, l.dcn, 0x1ad + index)?;
                let low = read(io, l.dcn, 0x1b5 + index * 2)?;
                let high = read(io, l.dcn, 0x1b6 + index * 2)?;
                let start = u64::from(low & 0xffffff00) | (u64::from(high & 0xffff) << 32);
                let size = (top & MASK)
                    .checked_sub(base)
                    .and_then(|n| n.checked_add(1))
                    .ok_or(Error::Invalid)?;
                if top & (1 << 31) == 0
                    || base != index << 24
                    || start < physical.start
                    || start
                        .checked_add(u64::from(size))
                        .is_none_or(|v| v > physical.end)
                {
                    return Err(Error::Invalid);
                }
            }
            Ok(place)
        })?;
        let map = self.memory.mapping();
        for (index, chunk) in self.prepared.bytes.chunks(4096).enumerate() {
            let io = &mut self.io;
            self.authority
                .invoke(Op(|| {
                    for (i, word) in chunk.chunks_exact(4).enumerate() {
                        io.upload(
                            map,
                            (index * 4096 + i * 4) as u64,
                            u32::from_le_bytes(word.try_into().unwrap()),
                        );
                    }
                }))
                .map_err(|_| Error::Revoked)?;
            narf_scheduler::yield_now().await;
        }
        self.access(|io| {
            fence(Ordering::SeqCst);
            io.write(0x7f000, 0);
            io.read(l.nbio + 0xc3 * 4);
            fence(Ordering::SeqCst);
            Ok(())
        })?;
        self.memory.publish();
        let psp_version = self.prepared.psp_version;
        self.access(|io| {
            // PSP loading may have changed scratch state after quiesce. Require
            // a fresh firmware-ready publication after releasing this reset.
            io.write(l.dcn + u64::from(STATUS) * 4, 0);
            // CW2/CW7 and uncached region4 are unused by this combined image.
            for reg in [0x1af, 0x1b4, 0x1a1] {
                io.write(l.dcn + reg * 4, 0);
            }
            for w in [
                fw::Window::Vbios,
                fw::Window::Mailbox,
                fw::Window::Trace,
                fw::Window::State,
            ] {
                let index = w as u32;
                let address = placement.address(w);
                let base = 0x60000000 + (index << 24);
                let size = shape.region(w).size;
                for (reg, value) in [
                    (0x1b5 + index * 2, address as u32),
                    (0x1b6 + index * 2, (address >> 32) as u32),
                    (0x1a5 + index, base),
                    (0x1ad + index, 0x80000000 | ((base + size) & MASK)),
                ] {
                    io.write(l.dcn + u64::from(reg) * 4, value);
                    let mask = if reg == 0x1a5 + index {
                        MASK
                    } else if reg == 0x1ad + index {
                        0x80000000 | MASK
                    } else {
                        u32::MAX
                    };
                    if read(io, l.dcn, reg)? & mask != value & mask {
                        return Err(Error::Readback);
                    }
                }
            }
            let shared = placement.address(fw::Window::SharedState);
            let shared_size = shape.region(fw::Window::SharedState).size;
            let trace = placement.address(fw::Window::Trace);
            let trace_size = shape.region(fw::Window::Trace).size;
            for (reg, value) in [
                (0x19a, shared as u32),
                (0x19b, (shared >> 32) as u32),
                (0x1a3, 0x80000000 | (shared_size - 1)),
                (0x198, trace as u32),
                (0x199, (trace >> 32) as u32),
                (0x1a2, 0x80000000 | (trace_size - 1)),
                (0x1d4, 0x64000000),
                (0x1d5, 8192),
                (0x1dc, 0x64002000),
                (0x1dd, 8192),
                (0x1d8, 0xa0000010),
                (0x1d9, trace_size - 16),
                (0x1f1, 0x1a0070),
                (0x1f2, psp_version & 0x001100ff),
            ] {
                io.write(l.dcn + u64::from(reg) * 4, value);
                if read(io, l.dcn, reg)? != value {
                    return Err(Error::Readback);
                }
            }
            update(io, l.dcn, HUB, 0x100, 0)?;
            update(io, l.dcn, CNTL, ENABLE | (1 << 19), ENABLE | (1 << 19))?;
            update(io, l.dcn, CNTL2, RESET, 0)?;
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            let status = self.access(|io| {
                let status = read(io, l.dcn, STATUS)?;
                Ok(is_running(io, l)?.then_some(status))
            })?;
            if let Some(boot_status) = status {
                return Ok(Status {
                    firmware_version: self.prepared.version,
                    boot_status,
                    inbox: placement.inbox(),
                    outbox: placement.outbox(),
                    capabilities: None,
                });
            }
            if deadline.expired() {
                return Err(Error::BootTimeout);
            }
            tick().await;
        }
    }
}
/// DMUB_CMD__VBIOS headers: type 128, sub_type, then `payload_bytes` as Linux
/// sets it, `sizeof(cmd) - sizeof(header)` of the atomfirmware.h payload.
/// DIGX_ENCODER_CONTROL (0) carries a 12-byte dig_encoder_control_parameters_v1_5;
/// DIG1_TRANSMITTER_CONTROL (1) a 16-byte dmub_dig_transmitter_control_data_v1_7;
/// SET_PIXEL_CLOCK (2) a 16-byte set_pixel_clock_parameter_v1_7.
const DIGX_ENCODER_CONTROL: [u8; 4] = [128, 0, 0, 12];
const TRANSMITTER_CONTROL: [u8; 4] = [128, 1, 0, 16];
const SET_PIXEL_CLOCK: [u8; 4] = [128, 2, 0, 16];
/// Linux rejects TMDS pixel clocks above 600 MHz (dcn401_program_pix_clk).
const TMDS_MAX_KHZ: u32 = 600_000;

/// RGB colour depth of a TMDS HDMI stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TmdsDepth {
    Bpc8,
    Bpc10,
    Bpc12,
}
impl TmdsDepth {
    /// SET_PIXEL_CLOCK v1.7 deep_color_ratio, PHYPLL DCCG_DEEP_COLOR_CNTL and
    /// HDMI_DEEP_COLOR_DEPTH: disabled, 5:4 or 3:2.
    pub fn code(self) -> u8 {
        match self {
            Self::Bpc8 => 0,
            Self::Bpc10 => 1,
            Self::Bpc12 => 2,
        }
    }
    /// The TMDS character clock in 100 Hz: dcn3_get_pix_clk_dividers'
    /// HDMI deep-colour scaling of the pixel clock (x5/4, x6/4, truncated).
    pub fn character_100hz(self, pixel_khz: u32) -> u64 {
        let p = u64::from(pixel_khz) * 10;
        match self {
            Self::Bpc8 => p,
            Self::Bpc10 => (p * 5) >> 2,
            Self::Bpc12 => (p * 6) >> 2,
        }
    }
    /// The TMDS character clock in kHz, as Linux's phy_pix_clk
    /// (get_norm_pix_clk / 10), or 0 if it does not fit.
    pub fn character_khz(self, pixel_khz: u32) -> u32 {
        u32::try_from(self.character_100hz(pixel_khz) / 10).unwrap_or(0)
    }
}

#[derive(Debug)]
pub struct Dmub {
    engine: Engine<Mmio>,
}
impl Dmub {
    /// Parse the first CTA extension through the same DMUB EDID_CEA
    /// command Linux uses, retaining one mailbox operation over all chunks.
    pub(crate) async fn amd_freesync_vsdb(
        &mut self,
        edid: &[u8],
    ) -> Result<Option<crate::amdgpu_freesync::AmdVsdb>, Error> {
        self.engine.amd_freesync_vsdb(edid).await
    }
    fn native_channels(&self) -> u8 {
        NATIVE_CHANNELS
    }
    pub(crate) fn matches_display(&self, regs: MmioRegion, base: u64) -> bool {
        let own = self.engine.io.0;
        own.phys == regs.phys
            && own.virt == regs.virt
            && own.len == regs.len
            && self.engine.layout.dcn == base
    }

    // Only the retained native display owner may issue these narrow VBIOS
    // operations. Inbox consumption alone cannot prove PHY readiness/shutdown.
    pub(crate) async fn set_dp_drive(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        settings: DpPhySettings,
        drive: DpDriveSettings,
    ) -> Result<(), Error> {
        self.engine.set_dp_drive(path, settings, drive).await
    }
    pub(crate) async fn enable_dp_sst(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        settings: DpPhySettings,
    ) -> Result<(), Error> {
        self.engine.enable_dp_sst(path, settings).await
    }
    pub(crate) async fn disable_dp_sst(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
    ) -> Result<(), Error> {
        self.engine.disable_dp_sst(path).await
    }
    /// dcn10_link_encoder_disable_output for a DP MST link (digmode 5).
    pub(crate) async fn disable_dp_mst(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
    ) -> Result<(), Error> {
        self.engine
            .disable_dp_transmitter(path, DpSignal::Mst, 19)
            .await
    }
    pub(crate) async fn enable_frl(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        lanes: u8,
        character_khz: u32,
    ) -> Result<(), Error> {
        self.engine.enable_frl(path, lanes, character_khz).await
    }
    pub(crate) async fn set_frl_ffe(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        lanes: u8,
        character_khz: u32,
        lane_set: u8,
    ) -> Result<(), Error> {
        self.engine
            .set_frl_ffe(path, lanes, character_khz, lane_set)
            .await
    }
    pub(crate) async fn enable_uhbr(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        lanes: u8,
        rate: UhbrRate,
        link: u8,
    ) -> Result<(), Error> {
        self.engine.enable_uhbr(path, lanes, rate, link).await
    }
    pub(crate) async fn set_uhbr_ffe(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        lanes: u8,
        rate: UhbrRate,
        preset: u8,
    ) -> Result<(), Error> {
        self.engine.set_uhbr_ffe(path, lanes, rate, preset).await
    }
    pub(crate) async fn disable_hpo_dp(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        signal: DpSignal,
    ) -> Result<(), Error> {
        self.engine.disable_hpo_dp(path, signal).await
    }
    pub(crate) async fn disable_tmds(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
    ) -> Result<(), Error> {
        self.engine.disable_tmds(path).await
    }
    pub(crate) async fn disable_frl(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
    ) -> Result<(), Error> {
        self.engine.disable_frl(path).await
    }
    pub(crate) async fn set_tmds_pixel_clock(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        otg: u8,
        pixel_khz: u32,
        depth: TmdsDepth,
    ) -> Result<(), Error> {
        self.engine
            .set_tmds_pixel_clock(path, otg, pixel_khz, depth)
            .await
    }
    pub(crate) async fn power_down_pixel_clock(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
    ) -> Result<(), Error> {
        self.engine.power_down_pixel_clock(path).await
    }
    pub(crate) async fn setup_hdmi_stream(
        &mut self,
        stream: u8,
        pixel_khz: u32,
    ) -> Result<(), Error> {
        self.engine.setup_hdmi_stream(stream, pixel_khz).await
    }
    pub(crate) async fn enable_tmds(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        pixel_khz: u32,
    ) -> Result<(), Error> {
        self.engine.enable_tmds(path, pixel_khz).await
    }
    /// Validate the VRAM pool and reserve nonsecure DMUB storage without writes.
    /// # Safety
    /// Caller exclusively owns this physical Navi48 GPU, DCN/PSP/PM/reset,
    /// permanent mappings and matching VRAM pool. The prepared firmware and
    /// VBIOS belong to this board. No competing firmware or display clients.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        prepared: Prepared,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        crate::amdgpu_psp_ring::navi48_layout(gpu)
            .and_then(|l| l.validate_pool(gpu, &authority, pool))
            .map_err(|e| match e {
                crate::amdgpu_psp_ring::Error::Revoked => Error::Revoked,
                crate::amdgpu_psp_ring::Error::DeviceGone => Error::DeviceGone,
                _ => Error::Invalid,
            })?;
        let memory = pool
            .reserve(u64::from(prepared.layout.size()))
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            engine: Engine {
                io: Mmio(gpu.regs),
                authority,
                layout,
                memory,
                prepared,
                state: State::Prepared,
                status: None,
                mailbox: mailbox::Mailbox::new(),
                hw_lock_uncertain: false,
            },
        })
    }
    /// Stop inherited firmware and hold DCN4.0.1 reset before PSP replaces CW0/1.
    /// A missing STOP acknowledgement fails without attempting forced recovery.
    pub async fn quiesce(&mut self) -> Result<(), Error> {
        self.engine.quiesce().await
    }
    /// # Safety
    /// Matching GPU's PSP authenticated DMCUB and retains TMR. Keep PSP/TMR
    /// alive while DMUB runs; both memory hubs and protected boot power are
    /// ready. The exclusive constructor contract still holds. No replay/reset
    /// after failure or cancellation without independent recovery.
    pub async unsafe fn start(&mut self, psp: &Psp) -> Result<Status, Error> {
        let tmr = psp.dmub_tmr().map_err(|_| Error::Invalid)?;
        self.engine.start(tmr).await?;
        if let Err(error) = self.engine.initialize_mailbox().await {
            self.engine.state = State::Failed;
            return Err(error);
        }
        self.engine.status.ok_or(Error::Invalid)
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn status(&self) -> Option<Status> {
        self.engine.status
    }
}

impl<I: Io> Engine<I> {
    async fn amd_freesync_vsdb(
        &mut self,
        edid: &[u8],
    ) -> Result<Option<crate::amdgpu_freesync::AmdVsdb>, Error> {
        let Some(base) = edid.get(..128) else {
            return Ok(None);
        };
        let Some(cta) = edid
            .chunks_exact(128)
            .skip(1)
            .take(usize::from(base[126]))
            .find(|b| b[0] == 2)
        else {
            return Ok(None);
        };
        self.begin_mailbox()?;
        let result = self.amd_freesync_cea(cta).await;
        self.finish_mailbox(result)
    }
    async fn amd_freesync_cea(
        &mut self,
        cta: &[u8],
    ) -> Result<Option<crate::amdgpu_freesync::AmdVsdb>, Error> {
        let mut found = None;
        for (i, chunk) in cta.chunks_exact(8).enumerate() {
            let offset = (i * 8) as u16;
            let mut request = [0; 64];
            request[..4].copy_from_slice(&[79, 0, 0, 16]);
            request[4..6].copy_from_slice(&offset.to_le_bytes());
            request[6] = 8;
            request[7..9].copy_from_slice(&128u16.to_le_bytes());
            request[9..17].copy_from_slice(chunk);
            let reply = self.command(request).await?;
            if reply == request {
                return Ok(None); // Firmware did not implement this optional query.
            }
            match reply[4] {
                1 => {
                    found =
                        (reply[5] != 0 && reply[6] != 0).then(|| crate::amdgpu_freesync::AmdVsdb {
                            version: u16::from_le_bytes(reply[7..9].try_into().unwrap()),
                            min_hz: u16::from_le_bytes(reply[9..11].try_into().unwrap()),
                            max_hz: u16::from_le_bytes(reply[11..13].try_into().unwrap()),
                            vcp_code: reply[13],
                        });
                }
                2 => {
                    if reply[5..7] != offset.to_le_bytes() || reply[7] == 0 {
                        return Err(Error::Protocol);
                    }
                }
                _ => return Err(Error::Protocol),
            }
        }
        Ok(found)
    }
}
impl<I: Io> Engine<I> {
    async fn set_dp_drive(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        settings: DpPhySettings,
        drive: DpDriveSettings,
    ) -> Result<(), Error> {
        settings.validate()?;
        drive.validate()?;
        if path.connector != crate::amdgpu_dcn_inventory::Connector::DisplayPort
            || path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
        {
            return Err(Error::Invalid);
        }
        // dcn10_link_encoder_dp_set_lane_settings: signal and HPO engine stay
        // zero, so v1.7 encodes HPO_0 subtraction (246), not HPO_DP_0 (244).
        // v1.7 has no legacy lane_select field. Native DC maximizes VS/PE across
        // lanes and issues the same native packet once per active lane.
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[5] = 11; // SET_VOLTAGE_AND_PREEMPASIS
        request[6] = drive.swing | drive.pre_emphasis << 3;
        request[7] = settings.lanes;
        request[8..12].copy_from_slice(&((settings.rate as u32) * 2700).to_le_bytes());
        request[12] = path.hpd;
        request[14] = 19;
        request[15] = 246;
        self.begin_mailbox()?;
        let result = async {
            for _ in 0..settings.lanes {
                self.command(request).await?;
            }
            Ok(())
        }
        .await;
        self.finish_mailbox(result)
    }
    async fn enable_dp_sst(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        settings: DpPhySettings,
    ) -> Result<(), Error> {
        settings.validate()?;
        if path.connector != crate::amdgpu_dcn_inventory::Connector::DisplayPort
            || path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
        {
            return Err(Error::Invalid);
        }
        // Native dcn10_link_encoder_enable_dp_output (or _enable_dp_mst_output)
        // -> transmitter_control_v1_7.
        // Unlike DISABLE, this zero-initialized caller leaves connector_obj_id
        // zero. DCE112+ digfe_sel is also zero; host programming owns routing.
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[5] = 1; // TRANSMITTER_CONTROL_ENABLE
                        // dcn10_link_encoder_enable_dp_mst_output's signal maps to
                        // ATOM_TRANSMITTER_DIGMODE_V6_DP_MST.
        request[6] = if settings.mst { 5 } else { 0 };
        request[7] = settings.lanes;
        let clock_10khz = (settings.rate as u32) * 2700;
        request[8..12].copy_from_slice(&clock_10khz.to_le_bytes());
        request[12] = path.hpd;
        request[15] = 244; // zero engine id minus HPO_DP_0(12), as u8
        self.begin_mailbox()?;
        let result = self.command(request).await.map(|_| ());
        self.finish_mailbox(result)
    }
    async fn disable_dp_sst(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
    ) -> Result<(), Error> {
        self.disable_dp_transmitter(path, DpSignal::Sst, 19).await
    }
    /// hpo_frl_link_enc3_enable_phy_output -> transmitter_control_v1_7:
    /// ENABLE in HDMI FRL mode (digmode 4) on 3 or 4 lanes, the FRL
    /// character clock in 10 kHz, the port's HPD, HPO instance 0, no
    /// connector object. The firmware brings up the PHY, HDMICHARCLK and
    /// the HPO FRL link encoder; DC writes none of them.
    async fn enable_frl(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        lanes: u8,
        character_khz: u32,
    ) -> Result<(), Error> {
        if path.connector != crate::amdgpu_dcn_inventory::Connector::HdmiTypeA
            || path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
            || !matches!(lanes, 3 | 4)
            || character_khz == 0
        {
            return Err(Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[5] = 1; // TRANSMITTER_CONTROL_ENABLE
        request[6] = 4; // ATOM_TRANSMITTER_DIGMODE_V6_HDMI_FRL
        request[7] = lanes;
        request[8..12].copy_from_slice(&(character_khz / 10).to_le_bytes());
        request[12] = path.hpd;
        request[15] = 0;
        self.begin_mailbox()?;
        let result = self.command(request).await.map(|_| ());
        self.finish_mailbox(result)
    }
    /// dpcs401_program_eq_setting: SET_VOLTAGE_AND_PREEMPASIS with the
    /// TxFFE lane set (FFE level, de-emphasis/pre-shoot only bits), as
    /// Linux sends it: the character clock divided by ten twice, the HDMI-A
    /// connector object, HPO engine DIGA - HPO_0 (0xF6).
    async fn set_frl_ffe(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        lanes: u8,
        character_khz: u32,
        lane_set: u8,
    ) -> Result<(), Error> {
        if path.connector != crate::amdgpu_dcn_inventory::Connector::HdmiTypeA
            || path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
            || !matches!(lanes, 3 | 4)
            || lane_set & !0x63 != 0
        {
            return Err(Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[5] = 11; // SET_VOLTAGE_AND_PREEMPASIS
        request[6] = lane_set;
        request[7] = lanes;
        request[8..12].copy_from_slice(&(character_khz / 10 / 10).to_le_bytes());
        request[12] = path.hpd;
        request[14] = 12; // CONNECTOR_OBJECT_ID_HDMI_TYPE_A
        request[15] = 0xf6;
        self.begin_mailbox()?;
        let result = self.command(request).await.map(|_| ());
        self.finish_mailbox(result)
    }
    /// dcn31_hpo_dp_link_enc_enable_dp_output -> transmitter_control_v1_7:
    /// ENABLE as DP_MST (digmode 5, even for SST), the 128b/132b symbol
    /// clock (link_rate x 1000 / 10 in 10 kHz), the port's HPD, the HPO link
    /// encoder's instance. The firmware brings up the PHY, routes it to that
    /// encoder and starts the encoder's DPHY and SYMCLK32_LE; DC writes none
    /// of those.
    async fn enable_uhbr(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        lanes: u8,
        rate: UhbrRate,
        link: u8,
    ) -> Result<(), Error> {
        if path.connector != crate::amdgpu_dcn_inventory::Connector::DisplayPort
            || path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
            || !matches!(lanes, 1 | 2 | 4)
            || link >= 4
        {
            return Err(Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[5] = 1; // TRANSMITTER_CONTROL_ENABLE
        request[6] = 5; // ATOM_TRANSMITTER_DIGMODE_V6_DP_MST
        request[7] = lanes;
        request[8..12].copy_from_slice(&(rate.link_rate() * 100).to_le_bytes());
        request[12] = path.hpd;
        request[15] = link;
        self.begin_mailbox()?;
        let result = self.command(request).await.map(|_| ());
        self.finish_mailbox(result)
    }
    /// dcn31_hpo_dp_link_enc_set_ffe: SET_VOLTAGE_AND_PREEMPASIS as DP_MST
    /// with the TX FFE preset in the lane-set byte. Linux leaves the HPD
    /// source (HPD1, selector 1) and HPO engine (instance 0 - HPO_DP_0, 244)
    /// unset here, unlike ENABLE.
    async fn set_uhbr_ffe(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        lanes: u8,
        rate: UhbrRate,
        preset: u8,
    ) -> Result<(), Error> {
        if path.connector != crate::amdgpu_dcn_inventory::Connector::DisplayPort
            || path.transmitter >= 4
            || !matches!(lanes, 1 | 2 | 4)
            || preset > 15
        {
            return Err(Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[5] = 11; // SET_VOLTAGE_AND_PREEMPASIS
        request[6] = preset;
        request[7] = lanes;
        request[8..12].copy_from_slice(&(rate.link_rate() * 100).to_le_bytes());
        request[12] = 1;
        request[15] = 244;
        self.begin_mailbox()?;
        let result = self.command(request).await.map(|_| ());
        self.finish_mailbox(result)
    }
    async fn disable_hpo_dp(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        signal: DpSignal,
    ) -> Result<(), Error> {
        // dcn31_hpo_dp_link_enc_disable_output leaves connector_obj_id zero.
        self.disable_dp_transmitter(path, signal, 0).await
    }
    async fn disable_dp_transmitter(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        signal: DpSignal,
        connector: u8,
    ) -> Result<(), Error> {
        if path.connector != crate::amdgpu_dcn_inventory::Connector::DisplayPort {
            return Err(Error::Invalid);
        }
        let mode = match signal {
            DpSignal::Sst => 0,
            DpSignal::Mst => 5,
        };
        self.disable_transmitter(path, mode, connector, 244).await
    }
    async fn disable_tmds(&mut self, path: crate::amdgpu_dcn_inventory::Path) -> Result<(), Error> {
        if path.connector != crate::amdgpu_dcn_inventory::Connector::HdmiTypeA {
            return Err(Error::Invalid);
        }
        self.disable_transmitter(path, 3, 12, 246).await
    }
    async fn disable_frl(&mut self, path: crate::amdgpu_dcn_inventory::Path) -> Result<(), Error> {
        if path.connector != crate::amdgpu_dcn_inventory::Connector::HdmiTypeA {
            return Err(Error::Invalid);
        }
        // DCE112+ signal_type_to_atom_dig_mode maps HDMI_FRL to literal 4.
        // dcn10_link_encoder_disable_output leaves the HPO engine id zero.
        self.disable_transmitter(path, 4, 12, 246).await
    }
    fn hdmi_path(path: crate::amdgpu_dcn_inventory::Path) -> Result<(), Error> {
        if path.connector != crate::amdgpu_dcn_inventory::Connector::HdmiTypeA
            || path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    async fn send(&mut self, request: [u8; 64]) -> Result<(), Error> {
        self.begin_mailbox()?;
        let result = self.command(request).await.map(|_| ());
        self.finish_mailbox(result)
    }
    /// Program the transmitter's PHY PLL for an RGB TMDS stream timed by OTG
    /// instance `otg` (controller_id = CONTROLLER_ID_D0 + tg->inst). Linux
    /// dcn401_program_pix_clk -> set_pixel_clock_v7, after the DP DTO is
    /// disabled: the deep-colour-scaled clock, PLL from
    /// find_matching_pll (COMBO_PHY_PLL0 + PHY), the UNIPHY pair's encoder
    /// object id, HDMI encoder mode, XTALIN reference (miscinfo 0) and the
    /// deep-colour ratio.
    async fn set_tmds_pixel_clock(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        otg: u8,
        pixel_khz: u32,
        depth: TmdsDepth,
    ) -> Result<(), Error> {
        Self::hdmi_path(path)?;
        let clock = depth.character_100hz(pixel_khz);
        if otg >= 4 || clock == 0 || clock > u64::from(TMDS_MAX_KHZ) * 10 {
            return Err(Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&SET_PIXEL_CLOCK);
        request[4..8].copy_from_slice(&(clock as u32).to_le_bytes());
        request[8] = 20 + path.transmitter; // ATOM_COMBOPHY_PLL0
                                            // ObjectID.h ENCODER_OBJECT_ID_INTERNAL_UNIPHY / UNIPHY1.
        request[9] = [0x1e, 0x20][usize::from(path.transmitter / 2)];
        request[10] = 3; // ATOM_ENCODER_MODE_HDMI
        request[12] = otg; // ATOM_CRTC1 + controller
        request[13] = depth.code(); // PIXEL_CLOCK_V7_DEEPCOLOR_RATIO_*
        self.send(request).await
    }
    /// Power the transmitter's combo PHY PLL down. Linux
    /// dce110_clock_source_power_down -> set_pixel_clock_v7: no pixel clock,
    /// ENCODER_OBJECT_ID_NONE, ATOM_ENCODER_MODE_CRT, FORCE_PROG_PPLL and
    /// ATOM_CRTC_INVALID.
    async fn power_down_pixel_clock(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
    ) -> Result<(), Error> {
        Self::hdmi_path(path)?;
        let mut request = [0; 64];
        request[..4].copy_from_slice(&SET_PIXEL_CLOCK);
        request[8] = 20 + path.transmitter; // ATOM_COMBOPHY_PLL0
        request[10] = 15; // ATOM_ENCODER_MODE_CRT
        request[11] = 0x01; // PIXEL_CLOCK_V7_MISC_FORCE_PROG_PPLL
        request[12] = 0xff; // ATOM_CRTC_INVALID
        self.send(request).await
    }
    /// DIG stream setup for TMDS HDMI. Linux
    /// enc401_stream_encoder_hdmi_set_stream_attribute -> encoder_control_digx_v1_5:
    /// DIG engine = stream, STREAM_SETUP, HDMI mode, four lanes, the PHY pixel
    /// clock in 10 kHz and an unset colour depth (the caller leaves it zero).
    async fn setup_hdmi_stream(&mut self, stream: u8, pixel_khz: u32) -> Result<(), Error> {
        if stream >= 4 || pixel_khz == 0 || pixel_khz > TMDS_MAX_KHZ {
            return Err(Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&DIGX_ENCODER_CONTROL);
        request[4] = stream; // ENGINE_ID_DIGA + stream
        request[5] = 0x0f; // ATOM_ENCODER_CMD_STREAM_SETUP
        request[6] = 3; // ATOM_ENCODER_MODE_HDMI
        request[7] = 4;
        request[8..12].copy_from_slice(&(pixel_khz / 10).to_le_bytes());
        self.send(request).await
    }
    /// Enable the TMDS transmitter. Linux dcn10_link_encoder_enable_tmds_output
    /// -> transmitter_control_v1_7: HDMI dig mode, four lanes, symclk in 10 kHz.
    /// The zero-initialized caller leaves connector and engine ids zero, so
    /// HPO_instance encodes DIGA minus HPO_0 (246), as for DISABLE.
    async fn enable_tmds(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        pixel_khz: u32,
    ) -> Result<(), Error> {
        Self::hdmi_path(path)?;
        if pixel_khz == 0 || pixel_khz > TMDS_MAX_KHZ {
            return Err(Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[5] = 1; // TRANSMITTER_CONTROL_ENABLE
        request[6] = 3; // ATOM_TRANSMITTER_DIGMODE_V6_HDMI
        request[7] = 4;
        request[8..12].copy_from_slice(&(pixel_khz / 10).to_le_bytes());
        request[12] = path.hpd;
        request[15] = 246;
        self.send(request).await
    }
    async fn disable_transmitter(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
        mode: u8,
        connector: u8,
        hpo_instance: u8,
    ) -> Result<(), Error> {
        if path.transmitter >= 4 || !(1..=4).contains(&path.hpd) {
            return Err(Error::Invalid);
        }
        // Linux command_table2.c, transmitter_control_v1_7. DISABLE has no
        // clock/lane arguments. DCE112+ always leaves digfe_sel zero: routing
        // belongs to the driver. Native DISABLE callers leave HPO id zero:
        // DIGA(0) - HPO_DP_0(12) for DP, or - HPO_0(10) for HDMI, as u8.
        // Do not substitute the selected link index; DISABLE resolves the
        // physical transmitter.
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[6] = mode;
        request[12] = path.hpd;
        request[14] = connector;
        request[15] = hpo_instance;
        self.begin_mailbox()?;
        let result = self.command(request).await.map(|_| ());
        self.finish_mailbox(result)
    }
    /// dmub_hw_lock_mgr_inbox0_cmd: clear the inbox0 acknowledgement
    /// (DMCUB_SCRATCH17), post the command to DMCUB_INBOX0_WPTR and wait
    /// up to 100 ms (MAX_WAIT_US) for firmware to acknowledge it. As
    /// dc_dmub_srv_wait_for_inbox0_ack, a missing acknowledgement is logged
    /// ("Error waiting for INBOX0 HW Lock Ack", without DMU recovery, which
    /// DC leaves off) and the caller goes on: `Ok(false)`, the mailbox left
    /// usable, since inbox0 is a register handshake beside the ring.
    async fn inbox0(&mut self, command: u32) -> Result<bool, Error> {
        self.begin_mailbox()?;
        let result = match self.inbox0_inner(command).await {
            Err(Error::CommandTimeout) => {
                let _ = core::fmt::Write::write_fmt(
                    &mut narf_console::Writer,
                    format_args!(
                        "amdgpu: navi48 DMUB inbox0 command {command:#x} not acknowledged\n"
                    ),
                );
                Ok(false)
            }
            r => r.map(|()| true),
        };
        self.finish_mailbox(result)
    }
    async fn inbox0_inner(&mut self, command: u32) -> Result<(), Error> {
        let (base, layout) = (self.layout.dcn, self.layout);
        self.access(|io| {
            if !is_running(io, layout)? {
                return Err(Error::Protocol);
            }
            io.write(base + u64::from(INBOX0_ACK) * 4, 0);
            io.write(base + u64::from(INBOX0_WPTR) * 4, command);
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            if self.access(|io| read(io, base, INBOX0_ACK))? != 0 {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::CommandTimeout);
            }
            tick().await;
        }
    }
}

/// DMCUB_INBOX0_WPTR and DMCUB_SCRATCH17, the inbox0 acknowledgement
/// (dmub_dcn401_send_inbox0_cmd / _read_inbox0_ack_register).
const INBOX0_WPTR: u32 = 0x1d2;
const INBOX0_ACK: u32 = 0x1f4;
/// `union dmub_inbox0_cmd_lock_hw`: DMUB_INBOX0_CMD__HW_LOCK from
/// HW_LOCK_CLIENT_DRIVER with no instance or lock flags, then the lock
/// (bit 23) or the release (should_release, bit 24).
const HW_LOCK: u32 = 1;
const HW_LOCK_LOCK: u32 = 1 << 23;
const HW_LOCK_RELEASE: u32 = 1 << 24;
/// DMUB_CMD__FW_ASSISTED_MCLK_SWITCH / DMUB_CMD__FAMS2_CONFIG.
const FW_ASSISTED_MCLK_SWITCH: u8 = 76;
const FAMS2_CONFIG: u8 = 4;
/// sizeof(struct dmub_rb_cmd_fams2) less its header.
const FAMS2_PAYLOAD: u8 = 60;

/// `union fw_assisted_mclk_switch_version` DCN401 runs FAMS2 with
/// (dc->debug.fams_version 2.1: minor 1, major 2).
pub const FAMS_VERSION: u8 = 2 << 5 | 1;

impl FeatureCaps {
    /// dmub_feature_caps.fw_assisted_mclk_switch_ver.
    pub fn fams_version(&self) -> u8 {
        self.0[1]
    }
    /// dcn401_init_hw: FAMS2 stays enabled only when firmware reports the
    /// driver's FAMS version.
    pub fn fams2(&self) -> bool {
        self.fams_version() == FAMS_VERSION
    }
}

/// `union dmub_fams2_global_feature_config` bits DC sets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fams2Features {
    pub enable: bool,
    pub enable_ppt_check: bool,
    pub enable_stall_recovery: bool,
    pub enable_debug: bool,
    pub enable_offload_flip: bool,
    pub enable_visual_confirm: bool,
    /// enum dmub_fams2_allow_delay_check_mode (two bits).
    pub allow_delay_check_mode: u8,
    pub legacy_method_no_fams2: bool,
}

impl Fams2Features {
    fn bits(self) -> u32 {
        u32::from(self.enable)
            | u32::from(self.enable_ppt_check) << 1
            | u32::from(self.enable_stall_recovery) << 2
            | u32::from(self.enable_debug) << 3
            | u32::from(self.enable_offload_flip) << 4
            | u32::from(self.enable_visual_confirm) << 5
            | u32::from(self.allow_delay_check_mode & 3) << 6
            | u32::from(self.legacy_method_no_fams2) << 8
    }
}

/// `struct dmub_cmd_fams2_global_config`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fams2Global {
    pub max_allow_delay_us: u32,
    pub lock_wait_time_us: u32,
    pub num_streams: u32,
    pub features: Fams2Features,
    pub recovery_timeout_us: u32,
    pub hwfq_flip_programming_delay_us: u32,
    pub max_allow_to_target_delta_us: u32,
}

/// One stream's FAMS2 v1 static base state with DC's OTG and pipe masks
/// (`struct dmub_fams2_cmd_stream_static_base_state`), and its legacy
/// sub-state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fams2StreamConfig {
    pub base: crate::amdgpu_dcn401_dml::pstate::Fams2Stream,
    pub drr: Option<crate::amdgpu_freesync::Drr>,
    pub otg_inst: u8,
    pub pipe_mask: u8,
    pub num_planes: u8,
    pub plane_pipe_masks: [u8; 6],
}

/// dc_dmub_srv_rb_based_fams2_update_config's command list for `global`
/// (DC's static feature overrides already applied) and `streams`: the
/// global command, then every stream's base, then every stream's sub-state,
/// all but the last marked multi_cmd_pending. Disabled (`enable` false) it
/// is the global command alone with only the dynamic feature bits.
pub fn fams2_config_commands(
    enable: bool,
    global: &Fams2Global,
    streams: &[Fams2StreamConfig],
) -> Vec<[u8; 64]> {
    let header = |pending: bool| {
        let mut c = [0u8; 64];
        c[0] = FW_ASSISTED_MCLK_SWITCH;
        c[1] = FAMS2_CONFIG;
        c[2] = u8::from(pending) << 1;
        c[3] = FAMS2_PAYLOAD;
        c
    };
    let mut first = header(false);
    let features = Fams2Features {
        // dc_dmub_srv_rb_based_fams2_update_config: visual confirm and the
        // PPT check from DC's debug defaults (off), enable only when both
        // asked and the configuration requires it.
        enable: enable && global.features.enable,
        enable_ppt_check: false,
        enable_visual_confirm: false,
        ..if enable {
            global.features
        } else {
            Fams2Features::default()
        }
    };
    let put = |c: &mut [u8; 64], at: usize, v: u32| c[at..at + 4].copy_from_slice(&v.to_le_bytes());
    if enable {
        for (i, v) in [
            global.max_allow_delay_us,
            global.lock_wait_time_us,
            global.num_streams,
            0,
            global.recovery_timeout_us,
            global.hwfq_flip_programming_delay_us,
            global.max_allow_to_target_delta_us,
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut first, 4 + 4 * i, v);
        }
    }
    put(&mut first, 4 + 12, features.bits());
    let mut out = Vec::with_capacity(1 + 2 * streams.len());
    if !enable || streams.is_empty() {
        out.push(first);
        return out;
    }
    first[2] |= 2;
    out.push(first);
    for s in streams {
        let b = &s.base;
        let mut c = header(true);
        let put16 = |c: &mut [u8; 64], at: usize, v: u16| {
            c[4 + at..4 + at + 2].copy_from_slice(&v.to_le_bytes())
        };
        c[4..8].copy_from_slice(&u32::from(b.kind).to_le_bytes());
        c[8..12].copy_from_slice(&b.otg_vline_time_ns.to_le_bytes());
        put16(&mut c, 12, b.htotal);
        put16(&mut c, 14, b.vtotal);
        put16(&mut c, 16, b.vblank_start);
        put16(&mut c, 18, b.vblank_end);
        put16(&mut c, 20, b.max_vtotal);
        put16(&mut c, 22, b.allow_start_otg_vline);
        put16(&mut c, 24, b.allow_end_otg_vline);
        put16(&mut c, 26, b.drr_keepout_otg_vline);
        put16(&mut c, 28, b.scheduling_delay_otg_vlines);
        put16(&mut c, 30, b.contention_delay_otg_vlines);
        put16(&mut c, 32, b.vline_int_ack_delay_otg_vlines);
        put16(&mut c, 34, b.allow_to_target_delay_otg_vlines);
        c[4 + 36] = u8::from(b.is_drr)
            | u8::from(b.clamp_vtotal_min) << 1
            | u8::from(b.min_ttu_vblank_usable) << 2;
        c[4 + 37] = s.otg_inst;
        c[4 + 38] = s.pipe_mask;
        c[4 + 39] = s.num_planes;
        c[4 + 40..4 + 46].copy_from_slice(&s.plane_pipe_masks);
        out.push(c);
    }
    for s in streams {
        // The legacy sub-state (dmub_fams2_cmd_legacy_stream_static_state):
        // the vactive fill delay; a vblank stream leaves it zero.
        let mut c = header(true);
        if let Some(drr) = s.base.drr_state {
            c[4..6].copy_from_slice(&drr.stretched_vtotal.to_le_bytes());
            c[6..8].copy_from_slice(&drr.programming_delay.to_le_bytes());
            c[8] = 1; // only_stretch_if_required
        } else {
            c[4..6].copy_from_slice(&s.base.vactive_det_fill_delay_otg_vlines.to_le_bytes());
        }
        out.push(c);
    }
    if let Some(last) = out.last_mut() {
        last[2] &= !2;
    }
    out
}

impl<I: Io> Engine<I> {
    async fn fams2_hw_lock(&mut self, lock: bool) -> Result<bool, Error> {
        if lock && self.hw_lock_uncertain {
            return Err(Error::Busy);
        }
        let result = self
            .inbox0(HW_LOCK | if lock { HW_LOCK_LOCK } else { HW_LOCK_RELEASE })
            .await;
        if result != Ok(true) {
            self.hw_lock_uncertain = true;
        }
        // Release is still attempted after a missing ACK, but its own ACK
        // can no longer prove exclusion: it might belong to an older command.
        if self.hw_lock_uncertain && result.is_ok() {
            return Ok(false);
        }
        result
    }
    /// FAMS2_CONFIG is one atomic command list, with a single publication.
    async fn fams2_update_config(&mut self, commands: &[[u8; 64]]) -> Result<(), Error> {
        if commands.is_empty()
            || commands.len() > 9
            || commands
                .iter()
                .any(|c| c[..2] != [FW_ASSISTED_MCLK_SWITCH, FAMS2_CONFIG] || c[3] != FAMS2_PAYLOAD)
        {
            return Err(Error::Invalid);
        }
        if commands.len() > 1
            && self
                .status
                .and_then(|s| s.capabilities)
                .is_none_or(|c| !c.fams2())
        {
            return Err(Error::Unsupported);
        }
        self.begin_mailbox()?;
        let result = self.command_list(commands).await;
        self.finish_mailbox(result)
    }
}

/// optc401_set_drr -> dc_dmub_srv_fams2_drr_update, including MID.
fn fams2_drr_command(
    otg: u8,
    drr: Option<crate::amdgpu_freesync::Drr>,
    mid: Option<crate::amdgpu_dcn401_otg::DrrMid>,
) -> Result<[u8; 64], Error> {
    if otg >= 4
        || mid.is_some_and(|m| {
            m.frames == 0
                || drr.is_none_or(|d| m.v_total < d.v_total_min || m.v_total > d.v_total_max)
        })
        || drr.is_some_and(|d| {
            d.v_total_min == 0 || d.v_total_min > d.v_total_max || d.v_total_max > 0x7fff
        })
    {
        return Err(Error::Invalid);
    }
    let mut command = [0; 64];
    command[..4].copy_from_slice(&[76, 5, 0, 20]);
    if let Some(d) = drr {
        command[4..8].copy_from_slice(&(d.v_total_min - 1).to_le_bytes());
        command[8..12].copy_from_slice(&(d.v_total_max - 1).to_le_bytes());
        command[20] = 1;
    }
    if let Some(m) = mid {
        command[12..16].copy_from_slice(&(m.v_total - 1).to_le_bytes());
        command[16..20].copy_from_slice(&u32::from(m.frames).to_le_bytes());
    }
    command[21] = otg;
    Ok(command)
}

impl Dmub {
    pub(crate) async fn fams2_drr_update(
        &mut self,
        otg: u8,
        drr: Option<crate::amdgpu_freesync::Drr>,
        mid: Option<crate::amdgpu_dcn401_otg::DrrMid>,
    ) -> Result<(), Error> {
        if self.fams2() != Some(true) {
            return Err(Error::Unsupported);
        }
        self.engine.send(fams2_drr_command(otg, drr, mid)?).await
    }
    /// Whether DC keeps FAMS2 enabled for this firmware (dcn401_init_hw's
    /// FAMS version check): `None` until QUERY_FEATURE_CAPS answered.
    pub fn fams2(&self) -> Option<bool> {
        self.engine
            .status
            .and_then(|s| s.capabilities)
            .map(|c| c.fams2())
    }
    /// False until a fresh owner replaces one with an unanswered inbox0 lock.
    pub(crate) fn fams2_lock_ready(&self) -> bool {
        !self.engine.hw_lock_uncertain
    }
    /// dcn401_dmub_hw_control_lock: the driver's inbox0 HW lock, taken
    /// (`lock`) or released. `Ok(false)`: firmware never acknowledged it,
    /// which Linux logs and goes on from.
    pub(crate) async fn hw_lock(&mut self, lock: bool) -> Result<bool, Error> {
        self.engine.fams2_hw_lock(lock).await
    }
    /// Post dc_dmub_srv_fams2_update_config's commands
    /// ([`fams2_config_commands`]).
    pub(crate) async fn fams2_update_config(&mut self, commands: &[[u8; 64]]) -> Result<(), Error> {
        self.engine.fams2_update_config(commands).await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dmub_navi48_tests.rs"]
mod tests;
