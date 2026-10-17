//! DCN3.0 DMUB lifecycle after PSP authentication. Linux dmub_dcn20.c reset,
//! dmub_dcn30.c windows and dmub_srv.c layout. No secure-window writes,
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
const RESET: u32 = 1 << 17; // DCN30: CNTL bit 17, NOT DCN31 CNTL2 bit 0
const ENABLE: u32 = 1 << 16;
const HUB: u32 = 0x341; // DCN31 instead uses 0x342
const GPINT: u32 = 0x1f8;
const STOP: u32 = 0x10020000;
const STATUS: u32 = 0x1e3;
const MASK: u32 = 0x1fffffff;
const NATIVE_CHANNELS: u8 = 6;
/// Linux dm_dmub_hw_init never compares the GPINT version reply with the
/// firmware header on DCN3.0; a mismatch is only reported.
const STRICT_VERSION: bool = false;
#[allow(
    clippy::duplicate_mod,
    reason = "instantiate the shared protocol against each generation's private Engine and register accessors"
)]
#[path = "amdgpu_dmub_navi22_mailbox.rs"]
mod mailbox;
pub use mailbox::{FeatureCaps, MailboxState};
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
        let prepared = image.prepare_dcn30(vbios).map_err(Error::Firmware)?;
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
    hdp: u64,
}
/// The GMC-validated system aperture handed to DMUB, as Linux
/// dm_dmub_hw_init fills `soc_fb_info`: fb_base = `gmc.fb_start`,
/// fb_offset = `vm_manager.vram_base_offset` (MC_VM_FB_OFFSET). DCN's own
/// DCN_VM_FB_* copy is not programmed before DC init and is never read here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Aperture {
    base: u64,
    end: u64,
    offset: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI22
            || gpu.regs.len < 0x7f004
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            // Highest DCN register used: MMHUBBUB_SOFT_RESET (0x341).
            dcn: bank(gpu, ip::HW_ID_DCN, &[(3, 0, 0)], 2, HUB).map_err(|_| Error::Unsupported)?,
            nbio: bank(
                gpu,
                ip::HW_ID_NBIF,
                &[
                    (2, 3, 0),
                    (2, 3, 1),
                    (2, 3, 2),
                    (3, 3, 0),
                    (3, 3, 1),
                    (3, 3, 2),
                    (3, 3, 3),
                ],
                2,
                0x12d,
            )
            .map_err(|_| Error::Unsupported)?,
            hdp: bank(
                gpu,
                ip::HW_ID_HDP,
                &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
                0,
                0xd1,
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
        // SAFETY: exact DCN30/NBIO banks and HDP hole bounded at construction;
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
    Ok(read(io, base, CNTL)? & (RESET | ENABLE) == RESET && read(io, base, HUB)? & 0x100 != 0)
}
fn is_running(io: &mut impl Io, l: Layout) -> Result<bool, Error> {
    Ok(read(io, l.dcn, CNTL)? & (RESET | ENABLE) == ENABLE
        && read(io, l.dcn, HUB)? & 0x100 == 0
        && read(io, l.dcn, STATUS)? & 3 == 3)
}
/// The register half of dmub_dcn20_reset: clear GPINT, assert DMCUB soft
/// reset, disable, hold DMUIF reset and clear the mailbox pointers/SCRATCH0.
fn hold_reset(io: &mut impl Io, base: u64) -> Result<(), Error> {
    io.write(base + u64::from(GPINT) * 4, 0);
    update(io, base, CNTL, RESET, RESET)?;
    update(io, base, CNTL, ENABLE, 0)?;
    update(io, base, HUB, 0x100, 0x100)?;
    if !is_reset(io, base)? {
        return Err(Error::Readback);
    }
    // Never touch SEC_CNTL or CW0/CW1: PSP owns their authentication.
    for reg in [0x1d6, 0x1d7, 0x1da, 0x1db, 0x1de, 0x1df, STATUS] {
        io.write(base + u64::from(reg) * 4, 0);
    }
    Ok(())
}
fn invalidate(io: &mut impl Io, l: Layout) {
    io.write(l.hdp + 0xd1 * 4, 1);
    io.read(l.hdp + 0xd1 * 4);
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
        // dmub_dcn20_is_supported: CC_DC_PIPE_DIS.DC_DMCUB_ENABLE. A fused-off
        // DMCUB is "DMUB unsupported on ASIC" (dm_dmub_hw_init), not a fault.
        if self.access(|io| read(io, base, 0xca))? & (1 << 16) == 0 {
            return Err(Error::Unsupported);
        }
        self.reset().await
    }
    /// `dmub_dcn20_reset`, used both before PSP replaces CW0/1 and again by
    /// dmub_srv_hw_init after PSP loaded the firmware: STOP_FW unless held
    /// in reset, a bounded acknowledgement, clear GPINT, then a forced reset
    /// ("in case we timed out, DMCUB is likely hung").
    async fn reset(&mut self) -> Result<(), Error> {
        let base = self.layout.dcn;
        let control = self.access(|io| read(io, base, CNTL))?;
        if control & RESET == 0 {
            self.access(|io| {
                io.write(base + u64::from(GPINT) * 4, STOP);
                Ok(())
            })?;
            let deadline = narf_time::Deadline::after_ms(100);
            while !self.access(|io| {
                Ok(read(io, base, GPINT)? == STOP & !(1 << 28)
                    && read(io, base, 0x1ea)? == 0xdeaddead)
            })? {
                if deadline.expired() {
                    use core::fmt::Write;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi22 DMCUB STOP_FW not acknowledged; forcing reset"
                    );
                    break;
                }
                tick().await;
            }
        }
        self.access(|io| hold_reset(io, base))
    }
    async fn start(&mut self, tmr: Range<u64>, fb: Aperture) -> Result<Status, Error> {
        if self.state != State::Reset {
            return Err(Error::Busy);
        }
        self.state = State::Starting;
        let result = self.start_inner(tmr, fb).await;
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
    async fn start_inner(&mut self, tmr: Range<u64>, fb: Aperture) -> Result<Status, Error> {
        let l = self.layout;
        let address = self.memory.address();
        let shape = self.prepared.layout;
        if !self.access(|io| is_reset(io, l.dcn))? {
            self.reset().await?;
        }
        let placement = self.access(|io| {
            if !is_reset(io, l.dcn)? || read(io, l.dcn, 0x1ce)? & (1 << 16) != 0 {
                return Err(Error::Busy);
            }
            let Aperture {
                base: fb,
                end,
                offset,
            } = fb;
            if fb >= end {
                return Err(Error::Invalid);
            }
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
            // CW2/CW7 and uncached region4/6 are unused by this combined image.
            for reg in [0x1af, 0x1b4, 0x1a1, 0x1a3] {
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
            let trace = placement.address(fw::Window::Trace);
            let trace_size = shape.region(fw::Window::Trace).size;
            for (reg, value) in [
                (0x198, trace as u32),
                (0x199, (trace >> 32) as u32),
                (0x1a2, 0x80000000 | (trace_size - 1)),
                (0x1d4, 0x64000000),
                (0x1d5, 8192),
                (0x1dc, 0x64002000),
                (0x1dd, 8192),
                (0x1d8, 0xa0000010),
                (0x1d9, trace_size - 16),
                // dmub_dcn20_enable_dmub_boot_options: all-zero on DCN3.0.
                (0x1f1, 0),
                (0x1f2, psp_version & 0x001100ff),
            ] {
                io.write(l.dcn + u64::from(reg) * 4, value);
                if read(io, l.dcn, reg)? != value {
                    return Err(Error::Readback);
                }
            }
            update(io, l.dcn, HUB, 0x100, 0)?;
            update(io, l.dcn, CNTL, ENABLE | (1 << 19), ENABLE | (1 << 19))?;
            update(io, l.dcn, CNTL, RESET, 0)?;
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            let status = self.access(|io| {
                let status = read(io, l.dcn, STATUS)?;
                let control = read(io, l.dcn, CNTL)?;
                Ok((status & 3 == 3 && control & (RESET | ENABLE) == ENABLE).then_some(status))
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
/// `DMUB_CMD__VBIOS` (dmub_cmd.h `enum dmub_cmd_type` 128) sub-types: the
/// VBIOS command tables DC sends to DMCUB instead of the ATOM interpreter
/// when `dc->debug.dmub_command_table` is set (dcn30_resource.c), from
/// command_table2.c's `*_dmcub` helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VbiosCommand {
    /// `DMUB_CMD__VBIOS_DIGX_ENCODER_CONTROL`: `dig_encoder_control_parameters_v1_5`.
    DigxEncoderControl = 0, // linux: DMUB_CMD__VBIOS_DIGX_ENCODER_CONTROL dmub_cmd.h
    /// `DMUB_CMD__VBIOS_DIG1_TRANSMITTER_CONTROL`: the v1.6 parameters or
    /// `dmub_dig_transmitter_control_data_v1_7`.
    Dig1TransmitterControl = 1, // linux: DMUB_CMD__VBIOS_DIG1_TRANSMITTER_CONTROL dmub_cmd.h
    /// `DMUB_CMD__VBIOS_SET_PIXEL_CLOCK`: `set_pixel_clock_parameter_v1_7`.
    SetPixelClock = 2, // linux: DMUB_CMD__VBIOS_SET_PIXEL_CLOCK dmub_cmd.h
    /// `DMUB_CMD__VBIOS_ENABLE_DISP_POWER_GATING`:
    /// `enable_disp_power_gating_parameters_v2_1`.
    EnableDispPowerGating = 3, // linux: DMUB_CMD__VBIOS_ENABLE_DISP_POWER_GATING dmub_cmd.h
}
const DMUB_CMD_VBIOS: u8 = 128; // linux: DMUB_CMD__VBIOS dmub_cmd.h
/// dc_dmub_srv.c MAX_WAIT_US: dmub_srv_wait_for_idle's bound.
const VBIOS_WAIT_US: u64 = 100_000; // linux: MAX_WAIT_US dc_dmub_srv.c
impl VbiosCommand {
    /// `sizeof(cmd.X) - sizeof(cmd.X.header)` under dmub_cmd.h's
    /// `#pragma pack(1)`: the payload union/struct size.
    pub const fn payload_bytes(self) -> usize {
        match self {
            Self::DigxEncoderControl => 12,
            Self::Dig1TransmitterControl => 60,
            Self::SetPixelClock => 16,
            Self::EnableDispPowerGating => 4,
        }
    }
}
/// The 64-byte `union dmub_rb_cmd` command_table2.c builds: memset 0, then
/// header.type/sub_type/payload_bytes (ret_status, multi_cmd_pending and
/// is_reg_based stay 0) and the parameter block after the 4-byte header.
pub(crate) fn vbios_request(command: VbiosCommand, payload: &[u8]) -> Result<[u8; 64], Error> {
    let size = command.payload_bytes();
    if payload.len() != size {
        return Err(Error::Invalid);
    }
    let mut request = [0u8; 64];
    request[0] = DMUB_CMD_VBIOS;
    request[1] = command as u8;
    request[3] = size as u8;
    request[4..4 + size].copy_from_slice(payload);
    Ok(request)
}
impl<I: Io> Engine<I> {
    /// `dc_wake_and_execute_dmub_cmd(..., DM_DMUB_WAIT_TYPE_WAIT)`: queue,
    /// execute, then wait (bounded, 100 ms) for the inbox to drain. Callers
    /// are the synchronous VBIOS table paths, so the wait polls in place as
    /// dmub_srv_wait_for_idle does (udelay(1) per poll).
    fn vbios(&mut self, command: VbiosCommand, payload: &[u8]) -> Result<(), Error> {
        let request = vbios_request(command, payload)?;
        self.begin_mailbox()?;
        let result = (|| {
            let posted = self.post(&request)?;
            let deadline = narf_time::Deadline::after_us(VBIOS_WAIT_US);
            loop {
                if self.consumed(&request, posted)?.is_some() {
                    return Ok(());
                }
                if deadline.expired() {
                    return Err(Error::CommandTimeout);
                }
                let poll = narf_time::Deadline::after_us(1);
                while !poll.expired() {
                    core::hint::spin_loop();
                }
            }
        })();
        self.finish_mailbox(result)
    }
}
#[derive(Debug)]
pub struct Dmub {
    engine: Engine<Mmio>,
    /// RCC_CONFIG_MEMSIZE: the aperture end is fb_start + mc_vram_size.
    vram_size: u64,
}
impl Dmub {
    /// Reserve all nonsecure DMUB storage without I/O.
    /// # Safety
    /// Caller exclusively owns this physical Navi22 GPU, DCN/PSP/PM/reset,
    /// permanent mappings and matching VRAM pool. The prepared firmware and
    /// VBIOS belong to this board. No competing firmware or display clients.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        prepared: Prepared,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
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
            vram_size: gpu.vram.size,
        })
    }
    /// Stop inherited firmware and hold DCN3.0 reset before PSP replaces CW0/1.
    /// A missing STOP acknowledgement forces the reset (dmub_dcn20_reset);
    /// `Unsupported` means the DMCUB is fused off (no DMUB on this board).
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
        let (base, offset) = psp.fb_location();
        let end = base.checked_add(self.vram_size).ok_or(Error::Invalid)?;
        self.engine
            .start(tmr, Aperture { base, end, offset })
            .await?;
        if let Err(error) = self.engine.initialize_mailbox().await {
            self.engine.state = State::Failed;
            return Err(error);
        }
        self.engine.status.ok_or(Error::Invalid)
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// DC's `dc->ctx->dmub_srv` test: firmware running with an idle mailbox,
    /// so VBIOS display tables go to DMCUB rather than the ATOM interpreter.
    pub fn vbios_ready(&self) -> bool {
        self.engine.state == State::Running && self.engine.mailbox.state == MailboxState::Ready
    }
    /// Execute one VBIOS command table on DMCUB (command_table2.c
    /// `*_dmcub`). `payload` is exactly [`VbiosCommand::payload_bytes`].
    /// Synchronous and bounded (100 ms); a timeout fails the mailbox.
    pub fn execute_vbios(&mut self, command: VbiosCommand, payload: &[u8]) -> Result<(), Error> {
        self.engine.vbios(command, payload)
    }
    pub fn status(&self) -> Option<Status> {
        self.engine.status
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dmub_navi22_tests.rs"]
mod tests;
