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
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI48
            || gpu.regs.len < 0x7f004
        {
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
#[derive(Debug)]
pub struct Dmub {
    engine: Engine<Mmio>,
}
impl Dmub {
    pub(crate) fn matches_display(&self, regs: MmioRegion, base: u64) -> bool {
        let own = self.engine.io.0;
        own.phys == regs.phys
            && own.virt == regs.virt
            && own.len == regs.len
            && self.engine.layout.dcn == base
    }

    // Only the retained native display owner may issue this narrow VBIOS
    // operation. Inbox consumption proves transport completion, not PHY-off.
    pub(crate) async fn disable_dp_sst(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
    ) -> Result<(), Error> {
        self.engine.disable_dp_sst(path).await
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
    async fn disable_dp_sst(
        &mut self,
        path: crate::amdgpu_dcn_inventory::Path,
    ) -> Result<(), Error> {
        self.disable_dp_transmitter(path, DpSignal::Sst, 19).await
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
        request[..4].copy_from_slice(&[128, 1, 0, 60]);
        request[4] = path.transmitter;
        request[6] = mode;
        request[12] = path.hpd;
        request[14] = connector;
        request[15] = hpo_instance;
        self.begin_mailbox()?;
        let result = self.command(request).await.map(|_| ());
        self.finish_mailbox(result)
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dmub_navi48_tests.rs"]
mod tests;
