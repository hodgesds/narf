//! Phoenix PSP13, Navi22 PSP11 and Navi48 PSP14 GPCOM rings. Wire layouts and
//! sequencing follow Linux psp_gfx_if.h, psp_v{11_0,13_0_4,14_0}.c, amdgpu_psp.c,
//! nbio_v2_3.c, gfxhub_v2_1.c and hdp_v5_0.c.
//! All addresses on the ring are GPU addresses, not host physical addresses.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as discovery,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

// linux-ctx: hdr=mp seg=0
// linux: mmMP0_SMN_C2PMSG_64
const CTRL: u32 = 0x80;
// linux: mmMP0_SMN_C2PMSG_67
const WPTR: u32 = 0x83;
// linux: mmMP0_SMN_C2PMSG_69
const RING_LO: u32 = 0x85;
// linux: mmMP0_SMN_C2PMSG_70
const RING_HI: u32 = 0x86;
// linux: mmMP0_SMN_C2PMSG_71
const RING_SIZE: u32 = 0x87;
// linux: mmMP0_SMN_C2PMSG_81
const SOS: u32 = 0x91;
// linux-ctx: reset
// linux: GFX_FLAG_RESPONSE
const RESPONSE: u32 = 1 << 31;
/// psp_v{11_0,13_0,13_0_4,14_0}_ring_create write `ring_type << 16` with
/// `PSP_RING_TYPE__KM` (2, formerly GPCOM), i.e. GFX_CTRL_CMD_ID_INIT_GPCOM_RING.
/// `1 << 16` would be INIT_RBI_RING, the user-mode ring.
const CREATE: u32 = crate::amdgpu_psp::gfx_ctrl_cmd_id::INIT_GPCOM_RING;
/// GFX_CTRL_CMD_ID_DESTROY_RINGS (psp_v*_ring_stop).
const DESTROY: u32 = crate::amdgpu_psp::gfx_ctrl_cmd_id::DESTROY_RINGS;
// linux: n/a (NARF buffer layout: cmd buffer after the 0x1000-byte KM ring)
const COMMAND: u64 = 4096;
// linux: n/a (NARF buffer layout: fence after the PSP_CMD_BUFFER_SIZE cmd buffer)
const FENCE: u64 = 8192;
// linux: n/a (NARF buffer layout: ring + cmd + fence)
const BUFFER_SIZE: u64 = 12288;
// linux: n/a (MMIO_REG_HOLE_OFFSET = 0x80000 - PAGE_SIZE in nbio_v2_3.c, 4 KiB pages)
const HDP_HOLE: u64 = 0x7f000;
// linux: n/a (NARF bound)
const MAX_IMAGE: usize = 16 * 1024 * 1024;
// linux: n/a (PSP_TMR_SIZE(adev) = 0x400000 for non-Aldebaran, amdgpu_psp.h)
const DEFAULT_TMR_SIZE: u64 = 4 * 1024 * 1024;

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
    Upload,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Starting,
    Ready,
    Pending,
    Failed,
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reply {
    address: u64,
    tmr_size: u32,
}

/// Linux leaves the size/version and RBI-only header fields zero for GPCOM.
// linux-lit: 256=sizeof(struct psp_gfx_cmd_resp) / 4
fn command(id: u32, args: &[u32]) -> [u32; 256] {
    // linux-lit: 256=sizeof(struct psp_gfx_cmd_resp) / 4
    let mut words = [0; 256];
    // linux-lit: 2=offsetof(struct psp_gfx_cmd_resp, cmd_id) / 4
    words[2] = id;
    // linux-lit: 7=offsetof(struct psp_gfx_cmd_resp, cmd) / 4
    words[7..7 + args.len()].copy_from_slice(args);
    words
}
fn load_command(id: u32, address: u64, size: u32, kind: u32) -> [u32; 256] {
    command(id, &[address as u32, (address >> 32) as u32, size, kind])
}

struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
trait Io {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
    fn read_mem(&mut self, offset: u64) -> u32;
    fn write_mem(&mut self, offset: u64, value: u32);
    fn write_payload(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: Session::stage supplies an exclusive, permanently mapped
        // reservation and bounds every aligned write to its page-rounded size.
        unsafe { map.write32(offset, value) };
    }
    fn setup_hdp(&mut self) -> bool;
    fn flush(&mut self);
    fn invalidate(&mut self);
    fn gfx_boot_status(&mut self) -> Result<GfxBootStatus, Error>;
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    mp0: u64,
    nbio: u64,
    invalidate_reg: Option<u64>,
    memory: MmioRegion,
    gfx_status_regs: Option<(u64, u64)>,
}
impl Io for Mmio {
    fn read(&mut self, reg: u32) -> u32 {
        // SAFETY: constructor bounds this MP0 register bank and retains mappings.
        unsafe { self.regs.read32(self.mp0 + reg as u64 * 4) }
    }
    fn write(&mut self, reg: u32, value: u32) {
        // SAFETY: same bounds; caller owns the sole PSP ring.
        unsafe { self.regs.write32(self.mp0 + reg as u64 * 4, value) };
    }
    fn read_mem(&mut self, offset: u64) -> u32 {
        // SAFETY: all offsets below BUFFER_SIZE are internal ring constants.
        unsafe { self.memory.read32(offset) }
    }
    fn write_mem(&mut self, offset: u64, value: u32) {
        // SAFETY: same permanently owned ring allocation.
        unsafe { self.memory.write32(offset, value) };
    }
    fn setup_hdp(&mut self) -> bool {
        // SAFETY: exact supported NBIO bank and the 4 KiB remap hole are bounded.
        unsafe {
            // linux-lit: 0x12d=mmREMAP_HDP_MEM_FLUSH_CNTL
            self.regs.write32(self.nbio + 0x12d * 4, HDP_HOLE as u32);
            // linux-lit: 0x12d=mmREMAP_HDP_MEM_FLUSH_CNTL
            self.regs.read32(self.nbio + 0x12d * 4) == HDP_HOLE as u32
        }
    }
    fn flush(&mut self) {
        fence(Ordering::SeqCst);
        // SAFETY: remap was verified before publishing any device memory.
        // Linux posts this write by reading MEMSIZE, not the remapped register.
        unsafe {
            self.regs.write32(HDP_HOLE, 0);
            // linux-lit: 0xc3=mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE
            self.regs.read32(self.nbio + 0xc3 * 4);
        }
        fence(Ordering::SeqCst);
    }
    fn invalidate(&mut self) {
        if let Some(reg) = self.invalidate_reg {
            // SAFETY: bounded HDP5.0/5.2.0 register. HDP5.2.1 has no such step.
            unsafe {
                self.regs.write32(reg, 1);
                self.regs.read32(reg);
            }
        }
        fence(Ordering::SeqCst);
    }
    fn gfx_boot_status(&mut self) -> Result<GfxBootStatus, Error> {
        let (cp, rlc) = self.gfx_status_regs.ok_or(Error::Unsupported)?;
        // SAFETY: Layout resolved/bounded the exact GC10/GC12 register banks. These
        // are read-only status samples, with reset/PM excluded by the owner.
        Ok(unsafe {
            GfxBootStatus {
                cp_stat: self.regs.read32(cp),
                rlc_bootload: self.regs.read32(rlc),
            }
        })
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    memory: Reservation,
    state: State,
    sequence: u32,
    /// Linux psp_cmd_submit_buf only warns on a nonzero response status on
    /// bare metal ("Some version of PSP FW doesn't write 0 to that field").
    /// Navi22 follows it for bring-up commands; DESTROY_TMR stays strict
    /// because a refused teardown must not recycle trusted memory.
    lenient: bool,
}
/// psp_cmd_submit_buf: `psp_timeout` (20000) polls of usleep_range(60, 100),
/// i.e. up to ~2 s before the fence is declared lost.
// linux: n/a (NARF bound for psp_cmd_submit_buf's psp_timeout polls)
const FENCE_TIMEOUT_MS: u64 = 2000;
const GFX_CMD_ID_DESTROY_TMR: u32 = 7; // linux: GFX_CMD_ID_DESTROY_TMR
async fn delay(ms: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    async fn response(&mut self, cleanup: bool) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(500);
        loop {
            let value = if cleanup {
                self.io.read(CTRL)
            } else {
                self.access(|io| io.read(CTRL))?
            };
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if value & RESPONSE != 0 {
                // linux-lit: 0xffff=GFX_CMD_STATUS_MASK
                return if value & 0xffff == 0 {
                    Ok(())
                } else {
                    Err(Error::Rejected(value & 0xffff)) // linux-lit: 0xffff=GFX_CMD_STATUS_MASK
                };
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(1).await;
        }
    }
    async fn start(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::Busy);
        }
        let alive = self.access(|io| io.read(SOS))?;
        if alive == 0 || alive == u32::MAX {
            return Err(Error::DeviceGone);
        }
        self.response(false).await?;
        self.state = State::Starting;
        let address = self.memory.address();
        let preparation = self.access(|io| {
            if !io.setup_hdp() {
                return Err(Error::Invalid);
            }
            for offset in (0..BUFFER_SIZE).step_by(4) {
                io.write_mem(offset, 0);
            }
            io.flush();
            Ok(())
        });
        if let Err(error) = preparation.and_then(|result| result) {
            self.state = State::Failed;
            return Err(error);
        }
        self.memory.publish();
        self.access(|io| {
            io.write(RING_LO, address as u32);
            io.write(RING_HI, (address >> 32) as u32);
            // linux: n/a (literal ring->ring_size = 0x1000 in amdgpu_psp.c:psp_ring_init)
            io.write(RING_SIZE, 4096);
            io.write(CTRL, CREATE);
        })?;
        // PSP11/13/14 require this delay, even for a fast response.
        delay(20).await;
        let result = self.response(false).await;
        self.state = if result.is_ok() {
            State::Ready
        } else {
            State::Failed
        };
        result
    }
    async fn submit(&mut self, words: &[u32; 256]) -> Result<Reply, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let wptr = self.access(|io| io.read(WPTR))?;
        // linux-lit: 16=sizeof(struct psp_gfx_rb_frame) / 4
        if wptr >= 1024 || wptr % 16 != 0 {
            return Err(Error::Invalid);
        }
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let seq = self.sequence;
        let address = self.memory.address();
        self.state = State::Pending;
        self.access(|io| {
            io.write_mem(FENCE, 0);
            for (i, value) in words.iter().enumerate() {
                io.write_mem(COMMAND + i as u64 * 4, *value);
            }
            // linux-lit: 16=sizeof(struct psp_gfx_rb_frame) / 4
            let mut frame = [0u32; 16];
            // linux-lit: 0=offsetof(struct psp_gfx_rb_frame, cmd_buf_addr_lo) / 4
            frame[0] = (address + COMMAND) as u32;
            // linux-lit: 1=offsetof(struct psp_gfx_rb_frame, cmd_buf_addr_hi) / 4
            frame[1] = ((address + COMMAND) >> 32) as u32;
            // linux-lit: 3=offsetof(struct psp_gfx_rb_frame, fence_addr_lo) / 4
            frame[3] = (address + FENCE) as u32;
            // linux-lit: 4=offsetof(struct psp_gfx_rb_frame, fence_addr_hi) / 4
            frame[4] = ((address + FENCE) >> 32) as u32;
            frame[5] = seq; // linux-lit: 5=offsetof(struct psp_gfx_rb_frame, fence_value) / 4
            for (i, value) in frame.iter().enumerate() {
                io.write_mem(wptr as u64 * 4 + i as u64 * 4, *value);
            }
            io.flush();
            io.write(WPTR, (wptr + 16) % 1024); // linux-lit: 16=sizeof(struct psp_gfx_rb_frame) / 4
        })?;
        let deadline = narf_time::Deadline::after_ms(FENCE_TIMEOUT_MS);
        loop {
            let done = self.access(|io| {
                io.invalidate();
                io.read_mem(FENCE) == seq
            })?;
            if done {
                break;
            }
            if deadline.expired() {
                self.state = State::Failed;
                return Err(Error::Timeout);
            }
            delay(1).await;
        }
        let (status, reply) = self.access(|io| {
            io.invalidate();
            (
                // linux-lit: 864=offsetof(struct psp_gfx_cmd_resp, resp.status)
                io.read_mem(COMMAND + 864),
                Reply {
                    // linux-lit: 872=offsetof(struct psp_gfx_cmd_resp, resp.fw_addr_lo)
                    address: io.read_mem(COMMAND + 872) as u64
                        // linux-lit: 876=offsetof(struct psp_gfx_cmd_resp, resp.fw_addr_hi)
                        | (io.read_mem(COMMAND + 876) as u64) << 32,
                    // linux-lit: 880=offsetof(struct psp_gfx_cmd_resp, resp.tmr_size)
                    tmr_size: io.read_mem(COMMAND + 880),
                },
            )
        })?;
        self.state = State::Ready;
        if status != 0 {
            if !self.lenient || words[2] == GFX_CMD_ID_DESTROY_TMR {
                return Err(Error::Rejected(status));
            }
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: psp gfx command {:#x} response status {status:#x}",
                words[2]
            );
        }
        Ok(reply)
    }
    async fn stop(&mut self) -> Result<(), Error> {
        if matches!(self.state, State::Prepared | State::Stopped) {
            self.state = State::Stopped;
            return Ok(());
        }
        self.state = State::Failed;
        // Teardown may remove existing DMA authority after cap revocation.
        self.io.write(CTRL, DESTROY);
        delay(20).await;
        self.response(true).await?;
        // SAFETY: PSP acknowledged ring destruction, so it cannot access buffers.
        unsafe {
            self.memory.stopped();
        }
        self.state = State::Stopped;
        Ok(())
    }
}

/// Owns a single PSP ring and any TMR installed through it. Dropping
/// without verified shutdown quarantines published memory, including payloads.
#[derive(Debug)]
pub struct Psp {
    session: Session<Mmio>,
    kind: Kind,
    navi48_target: Option<crate::amdgpu_navi48_firmware::Target>,
}
/// PSP-reported locations inside this session's retained trusted memory.
/// These are GPU addresses, not CPU mappings; consumers must keep TMR alive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MediaFirmware {
    /// VCN instance 0 image (`UCODE_ID_VCN`).
    pub vcn: Option<u64>,
    pub dmcub: Option<u64>,
    /// VCN instance 1 image (`UCODE_ID_VCN1`), absent when harvested.
    pub vcn1: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Phoenix,
    Navi22,
    Navi48(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmcState {
    Absent,
    Pending,
    Loaded,
    Failed,
}
/// Progress from PSP acknowledgement through GC's autoload status check.
/// BootComplete is not proof of functioning queues, SDMA or acceleration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GfxLoadState {
    Absent,
    Loading,
    Accepted,
    Checking,
    BootComplete,
    Failed,
}
/// Last paired GC status sample; useful even when boot times out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GfxBootStatus {
    pub cp_stat: u32,
    pub rlc_bootload: u32,
}
#[derive(Debug)]
struct Session<I: Io> {
    engine: Engine<I>,
    pool: Pool,
    payload: Option<Reservation>,
    tmr: Option<Reservation>,
    tmr_ready: bool,
    smc_state: SmcState,
    gfx_state: GfxLoadState,
    gfx_status: Option<GfxBootStatus>,
    media_firmware: MediaFirmware,
    fb_base: u64,
    fb_offset: u64,
}

/// Absolute BAR5 byte addresses, resolved before any MMIO or allocation.
#[derive(Debug)]
pub(crate) struct Layout {
    pub(crate) mp0: u64,
    pub(crate) nbio: u64,
    pub(crate) invalidate_reg: Option<u64>,
    fb_base: u64,
    fb_top: u64,
    fb_offset: u64,
    gfx_status_regs: Option<(u64, u64)>,
}
impl Layout {
    pub(crate) fn validate_pool(
        &self,
        gpu: &AmdGpu,
        authority: &Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<(u64, u64), Error> {
        let (base, top, offset) = authority
            .invoke(Op(|| {
                // SAFETY: constructor bounds the selected DCN/GMC register bank.
                unsafe {
                    (
                        gpu.regs.read32(self.fb_base),
                        gpu.regs.read32(self.fb_top),
                        gpu.regs.read32(self.fb_offset),
                    )
                }
            }))
            .map_err(|_| Error::Revoked)?;
        if [base, top, offset].contains(&u32::MAX) {
            return Err(Error::DeviceGone);
        }
        // linux-lit: 0xffffff=GCMC_VM_FB_LOCATION_BASE__FB_BASE_MASK
        let fb_base = (base as u64 & 0xffffff) << 24;
        // amdgpu_gmc_vram_location: vram_end = vram_start + mc_vram_size - 1
        // (RCC_CONFIG_MEMSIZE). FB_LOCATION_TOP is inherited 16 MiB-granular
        // state; it is read only to detect a removed device.
        let fb_end = fb_base.checked_add(gpu.vram.size).ok_or(Error::Invalid)?;
        // linux-lit: 0xffffff=GCMC_VM_FB_OFFSET__FB_OFFSET_MASK
        let fb_offset = (offset as u64 & 0xffffff) << 24;
        let pool_offset = pool.address().checked_sub(fb_base).ok_or(Error::Invalid)?;
        let mapping = pool.mapping();
        if fb_base >= fb_end
            || pool
                .address()
                .checked_add(mapping.len)
                .is_none_or(|end| end > fb_end)
            || pool_offset
                .checked_add(mapping.len)
                .is_none_or(|end| end > gpu.fb_bar.len.min(gpu.vram.visible_size))
            || gpu.fb_bar.virt.checked_add(pool_offset) != Some(mapping.virt)
            || gpu.fb_bar.phys.raw().checked_add(pool_offset) != Some(mapping.phys.raw())
        {
            return Err(Error::Invalid);
        }
        Ok((fb_base, fb_offset))
    }

    fn resolve(gpu: &AmdGpu, kind: Kind) -> Result<Self, Error> {
        if gpu.regs.len < HDP_HOLE + 4096 {
            return Err(Error::Invalid);
        }
        if let Kind::Navi48(revision) = kind {
            if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
                || gpu.chip.did != crate::amdgpu::NAVI48
                || !matches!(revision, 2 | 3)
            {
                return Err(Error::Unsupported);
            }
            let mp0 = bank(gpu, discovery::HW_ID_MP0, &[(14, 0, revision)], 0, SOS)?;
            let nbio = bank(
                gpu,
                discovery::HW_ID_NBIF,
                &[(7, 7, 0), (7, 7, 1), (6, 3, 1)],
                2,
                0x12d,
            )?;
            // HDP6 uses amdgpu_hdp_generic_flush, with no invalidate callback.
            // In particular HDP5's 0xd1 must never be written on this profile.
            bank(
                gpu,
                discovery::HW_ID_HDP,
                &[(6, 0, 0), (6, 0, 1), (6, 1, 0), (6, 1, 1), (6, 4, 0)],
                0,
                0,
            )?;
            let gc = bank(gpu, discovery::HW_ID_GC, &[(12, 0, 1)], 0, 0x1615)?;
            let rlc = bank(gpu, discovery::HW_ID_GC, &[(12, 0, 1)], 1, 0x4e7c)?;
            return Ok(Self {
                mp0,
                nbio,
                invalidate_reg: None,
                fb_base: gc + 0x1614 * 4,
                fb_top: gc + 0x1615 * 4,
                fb_offset: gc + 0x15a7 * 4,
                gfx_status_regs: Some((gc + 0xf40 * 4, rlc + 0x4e7c * 4)),
            });
        }
        let (mp0, nbio, fb_base, fb_top, fb_offset) = match kind {
            Kind::Navi48(_) => unreachable!(),
            Kind::Phoenix => {
                let mp0 = bank(gpu, discovery::HW_ID_MP0, &[(13, 0, 4)], 1, SOS)?;
                let nbio = bank(
                    gpu,
                    discovery::HW_ID_NBIF,
                    &[(4, 3, 0), (4, 3, 1), (7, 7, 0), (7, 7, 1)],
                    2,
                    0x12d,
                )?;
                let dcn = bank(gpu, discovery::HW_ID_DCN, &[(3, 1, 4)], 2, 0x477)?;
                (mp0, nbio, dcn + 0x475 * 4, dcn + 0x476 * 4, dcn + 0x477 * 4)
            }
            Kind::Navi22 => {
                if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
                    || gpu.chip.did != crate::amdgpu::NAVI22
                {
                    return Err(Error::Unsupported);
                }
                // linux-lit: 0=mmMP0_SMN_C2PMSG_81_BASE_IDX
                let mp0 = bank(gpu, discovery::HW_ID_MP0, &[(11, 0, 11)], 0, SOS)?;
                // Navi22's cold-boot SMC path requires this exact MP1 mailbox.
                // linux-lit: 0=mmMP1_SMN_C2PMSG_90_BASE_IDX; 0x29a=mmMP1_SMN_C2PMSG_90
                bank(gpu, discovery::HW_ID_MP1, &[(11, 0, 11)], 0, 0x29a)?;
                bank(gpu, discovery::HW_ID_SDMA0, &[(5, 2, 2)], 0, 0)?;
                // Linux nv.c uses nbio_v2_3 for these revisions; MEMSIZE and
                // REMAP_HDP_MEM_FLUSH_CNTL are at index 2, 0xc3 and 0x12d.
                let nbio = bank(
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
                )?;
                // GMC10 location/offset, not DCN314's similarly named registers.
                // This also pins the GC and works without an active display.
                // linux-lit: 0=mmGCMC_VM_FB_LOCATION_TOP_BASE_IDX; 0x16fd=mmGCMC_VM_FB_LOCATION_TOP
                let gc = bank(gpu, discovery::HW_ID_GC, &[(10, 3, 2)], 0, 0x16fd)?;
                // linux-lit: 0x16fc=mmGCMC_VM_FB_LOCATION_BASE; 0x16fd=mmGCMC_VM_FB_LOCATION_TOP; 0x16e7=mmGCMC_VM_FB_OFFSET
                (mp0, nbio, gc + 0x16fc * 4, gc + 0x16fd * 4, gc + 0x16e7 * 4)
            }
        };
        let hdp = bank(
            gpu,
            discovery::HW_ID_HDP,
            &[
                (5, 0, 0),
                (5, 0, 1),
                (5, 0, 2),
                (5, 0, 3),
                (5, 0, 4),
                (5, 2, 0),
                (5, 2, 1),
            ],
            0,    // linux-lit: 0=mmHDP_READ_CACHE_INVALIDATE_BASE_IDX
            0xd1, // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
        )?;
        let ip = discovery::find_ip(&gpu.ip_blocks, discovery::HW_ID_HDP, 0)
            .ok_or(Error::Unsupported)?;
        if kind == Kind::Navi22 && (ip.major, ip.minor) != (5, 0) {
            return Err(Error::Unsupported);
        }
        let gfx_status_regs = if kind == Kind::Navi22 {
            // Linux gc_10_1_0_offset.h: CP_STAT index 0, RLC status index 1.
            // linux-lit: 0=mmCP_STAT_BASE_IDX; 0xf40=mmCP_STAT
            let cp = bank(gpu, discovery::HW_ID_GC, &[(10, 3, 2)], 0, 0xf40)?;
            // linux-lit: 1=mmRLC_RLCS_BOOTLOAD_STATUS_BASE_IDX; 0x4e8d=mmRLC_RLCS_BOOTLOAD_STATUS
            let rlc = bank(gpu, discovery::HW_ID_GC, &[(10, 3, 2)], 1, 0x4e8d)?;
            // linux-lit: 0xf40=mmCP_STAT; 0x4e8d=mmRLC_RLCS_BOOTLOAD_STATUS
            Some((cp + 0xf40 * 4, rlc + 0x4e8d * 4))
        } else {
            None
        };
        Ok(Self {
            mp0,
            nbio,
            invalidate_reg: ((ip.major, ip.minor, ip.revision) != (5, 2, 1))
                .then_some(hdp + 0xd1 * 4), // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
            fb_base,
            fb_top,
            fb_offset,
            gfx_status_regs,
        })
    }
}
/// Preflight used by the coordinated Navi22 bootstrap before uploading SOS.
/// Resolves all banks without MMIO or allocating device-owned memory.
pub(crate) fn validate_navi22_layout(gpu: &AmdGpu) -> Result<(), Error> {
    Layout::resolve(gpu, Kind::Navi22).map(|_| ())
}
/// Re-read GMC10's live FB location and check the pool still lies inside it
/// (the same check `Psp::new_navi22` makes), e.g. after a reset-on-init and
/// before the bootloader is handed any pool GPU address.
pub(crate) fn validate_navi22_pool(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
    pool: &Pool,
) -> Result<(), Error> {
    Layout::resolve(gpu, Kind::Navi22)?
        .validate_pool(gpu, authority, pool)
        .map(|_| ())
}
/// Resolve the PSP14/GMC12/HDP6 transport without touching hardware.
pub(crate) fn navi48_layout(gpu: &AmdGpu) -> Result<Layout, Error> {
    let ip =
        discovery::find_ip(&gpu.ip_blocks, discovery::HW_ID_MP0, 0).ok_or(Error::Unsupported)?;
    Layout::resolve(gpu, Kind::Navi48(ip.revision))
}
/// One IP version's register window, for a caller whose register ids are only
/// valid on some of the versions an IP reports.
///
/// Sibling revisions of the same IP agree on neither their SOC15 `_BASE_IDX`
/// nor their offsets — MMHUB 3.0.0 and 3.0.1 put `regMMVM_CONTEXT0_CNTL` at
/// the same 0x0740 on different base indices, 3.0.2 moves it to 0x06c0, and
/// DCN 3.5 shifts `regHUBPREQ0_DCSURF_SURFACE_INUSE` one dword down from
/// 3.1.4's. So a window belongs to exactly one version, and widening a
/// version list without widening its register table turns a clean
/// `Unsupported` into a write to an unrelated register.
///
/// Implement this on a row type that carries whatever offsets the caller
/// needs, put one row per supported version in a table, and resolve it with
/// [`bank_for`]. Supporting another GPU is then adding rows.
pub(crate) trait RegWindow: Copy {
    /// Discovery-blob version this window describes: (major, minor, revision).
    fn version(&self) -> (u8, u8, u8);
    /// The `_BASE_IDX` every register in this window carries.
    fn base_idx(&self) -> usize;
    /// Highest dword the caller reads or writes through this base.
    fn last(&self) -> u32;
}

/// Resolve the instance-0 bank for `id` and return it with the window row
/// matching the version discovery reports.
///
/// `Unsupported` when no row covers that version — never a fallback to another
/// generation's row.
pub(crate) fn bank_for<W: RegWindow>(
    gpu: &AmdGpu,
    id: u16,
    windows: &[W],
) -> Result<(u64, W), Error> {
    let ip = discovery::find_ip(&gpu.ip_blocks, id, 0).ok_or(Error::Unsupported)?;
    let window = windows
        .iter()
        .find(|w| w.version() == (ip.major, ip.minor, ip.revision))
        .ok_or(Error::Unsupported)?;
    let base = bank(
        gpu,
        id,
        &[window.version()],
        window.base_idx(),
        window.last(),
    )?;
    Ok((base, *window))
}

pub(crate) fn bank(
    gpu: &AmdGpu,
    id: u16,
    versions: &[(u8, u8, u8)],
    index: usize,
    last: u32,
) -> Result<u64, Error> {
    let mut blocks = gpu
        .ip_blocks
        .iter()
        .filter(|ip| ip.hw_id == id && ip.instance == 0);
    let ip = blocks.next().ok_or(Error::Unsupported)?;
    if blocks.next().is_some()
        || !versions.contains(&(ip.major, ip.minor, ip.revision))
        || ip.num_bases as usize <= index
    {
        return Err(Error::Unsupported);
    }
    let base = ip.base_addrs[index] as u64 * 4;
    if base
        .checked_add((last as u64 + 1) * 4)
        .is_none_or(|end| end > gpu.regs.len)
    {
        return Err(Error::Invalid);
    }
    Ok(base)
}
impl Psp {
    /// Claim the Phoenix PSP13 ring. Navi22 uses `new_navi22` instead.
    /// # Safety
    /// Caller owns this physical GPU (not an SR-IOV VF), PSP/PM/HDP exclusively,
    /// with permanent mappings and this GPU's exclusively free VRAM pool. No
    /// legacy PSP helper may run concurrently. All firmware-consuming engines
    /// must be stopped before destroying or replacing their TMR.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        // SAFETY: forwarded exclusive device/mapping/pool contract.
        unsafe { Self::with_kind(gpu, authority, pool, Kind::Phoenix) }
    }
    /// Claim the Navi22 PSP11 ring after SOS bootstrap (or verified resident SOS).
    /// Validates GMC10 GPU VRAM addresses against the caller's BAR0 pool.
    ///
    /// # Safety
    /// `new`'s exclusive GPU, PSP, HDP, reset/PM and pool contract applies.
    /// VRAM must already be trained. This neither trains VRAM nor resets SOS.
    pub unsafe fn new_navi22(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        // SAFETY: same exclusive ownership and initialized VRAM contract.
        unsafe { Self::with_kind(gpu, authority, pool, Kind::Navi22) }
    }
    /// Claim Navi48's PSP14 ring using discovered MP0 and GMC12 addresses.
    ///
    /// # Safety
    /// Same exclusive physical GPU, PSP/HDP/reset ownership and trained-VRAM
    /// pool contract as `new_navi22`. SOS must already be running.
    pub unsafe fn new_navi48(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        navi48_layout(gpu)?;
        let revision = discovery::find_ip(&gpu.ip_blocks, discovery::HW_ID_MP0, 0)
            .ok_or(Error::Unsupported)?
            .revision;
        // SAFETY: caller supplies permanent mappings and exclusive ownership.
        unsafe { Self::with_kind(gpu, authority, pool, Kind::Navi48(revision)) }
    }
    unsafe fn with_kind(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        kind: Kind,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu, kind)?;
        let (fb_base, fb_offset) = layout.validate_pool(gpu, &authority, pool)?;
        let memory = pool.reserve(BUFFER_SIZE).map_err(|_| Error::Allocation)?;
        Ok(Self {
            kind,
            navi48_target: if matches!(kind, Kind::Navi48(_)) {
                crate::amdgpu_navi48_firmware::Target::resolve(gpu).ok()
            } else {
                None
            },
            session: Session {
                engine: Engine {
                    io: Mmio {
                        regs: gpu.regs,
                        mp0: layout.mp0,
                        nbio: layout.nbio,
                        invalidate_reg: layout.invalidate_reg,
                        memory: memory.mapping(),
                        gfx_status_regs: layout.gfx_status_regs,
                    },
                    authority,
                    memory,
                    state: State::Prepared,
                    sequence: 0,
                    lenient: kind == Kind::Navi22,
                },
                pool: pool.clone(),
                payload: None,
                tmr: None,
                tmr_ready: false,
                smc_state: SmcState::Absent,
                gfx_state: GfxLoadState::Absent,
                gfx_status: None,
                media_firmware: MediaFirmware::default(),
                fb_base,
                fb_offset,
            },
        })
    }
    pub fn state(&self) -> State {
        self.session.engine.state
    }
    pub async fn start(&mut self) -> Result<(), Error> {
        self.session.engine.start().await
    }
    /// Phoenix's standalone authenticated TOC container. Navi22 uses the
    /// embedded TOC from the SOS container through `setup_tmr_navi22`.
    pub async fn setup_tmr(&mut self, toc: &[u8]) -> Result<(), Error> {
        if self.kind != Kind::Phoenix {
            return Err(Error::Unsupported);
        }
        self.session
            .setup_tmr_payload(Some(toc_payload(toc)?))
            .await
    }
    /// `psp_tmr_init`: LOAD_TOC from the validated SOS container's embedded
    /// TOC (or PSP11's 4 MiB default) and reserve the TMR. MP0 11.0.11 has
    /// PMFW-centralized C-state management, so SETUP_TMR is deferred until
    /// `load_smc_navi22` has loaded PMFW (amdgpu_psp.c psp_hw_start: "TMR
    /// setup should be performed after PMFW loaded"). The allocation remains
    /// owned until verified stop.
    pub async fn setup_tmr_navi22(
        &mut self,
        firmware: &crate::amdgpu_psp_boot::Firmware,
    ) -> Result<(), Error> {
        if self.kind != Kind::Navi22 || !firmware.is_navi22() {
            return Err(Error::Unsupported);
        }
        let image = firmware.image().map_err(|_| Error::Invalid)?;
        self.session.init_tmr(image.toc()).await
    }
    /// Install the trusted region described by this PSP14 target's embedded
    /// TOC. A missing TOC is rejected; no size from another GPU is substituted.
    pub async fn setup_tmr_navi48(
        &mut self,
        firmware: &crate::amdgpu_psp_boot::Firmware,
    ) -> Result<(), Error> {
        let Kind::Navi48(revision) = self.kind else {
            return Err(Error::Unsupported);
        };
        if !firmware.is_psp14(revision) {
            return Err(Error::Unsupported);
        }
        let image = firmware.image().map_err(|_| Error::Invalid)?;
        let toc = image.toc().ok_or(Error::Invalid)?;
        self.session.setup_tmr_payload(Some(toc)).await
    }
    /// Load signed DMUB instructions through PSP (GFX_FW_TYPE_DMUB = 51).
    /// The DCN314 loader is the currently audited consumer of this operation.
    pub async fn load_dmub(&mut self, signed_instructions: &[u8]) -> Result<(), Error> {
        if self.kind != Kind::Phoenix {
            return Err(Error::Unsupported);
        }
        self.session
            .load_ip(signed_instructions, 51) // linux-lit: 51=GFX_FW_TYPE_DMUB
            .await
            .map(|_| ())
    }
    /// Load Navi22 SMC once during cold boot, after LOAD_TOC/TMR reservation
    /// and before other IP firmware, then SETUP_TMR (psp_hw_start's
    /// psp_load_smu_fw then psp_tmr_load for pmfw_centralized_cstate_management).
    /// Only microcode is sent, never the header/PPT. Completion means PSP
    /// accepted both; use Smu::after_upload/verify to check runtime
    /// responsiveness. This does not implement BACO/resume/reload.
    pub async fn load_smc_navi22(
        &mut self,
        firmware: &crate::amdgpu_smu_navi22::Firmware,
    ) -> Result<(), Error> {
        if self.kind != Kind::Navi22 {
            return Err(Error::Unsupported);
        }
        let image = firmware.image().map_err(|_| Error::Invalid)?;
        self.session.load_smc_centralized(image.payload()).await
    }
    /// Load the complete Navi22 SDMA/CP/RLC set once, after SMC. Successful
    /// return acknowledges AUTOLOAD_RLC; GC/SDMA readiness, reset/golden-register
    /// programming and queue setup remain separate hardware bring-up steps.
    pub async fn load_gfx_navi22(
        &mut self,
        firmware: &crate::amdgpu_gfx_navi22::Firmware,
    ) -> Result<(), Error> {
        if self.kind != Kind::Navi22 {
            return Err(Error::Unsupported);
        }
        let images = firmware.images().map_err(|_| Error::Invalid)?;
        self.session.load_gfx(&images).await
    }
    fn check_navi48_firmware(
        &self,
        firmware: &crate::amdgpu_navi48_firmware::Firmware,
    ) -> Result<(), Error> {
        if !matches!(self.kind, Kind::Navi48(_)) || self.navi48_target != Some(firmware.target()) {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    /// Load SMU14 before the board-power handshake and graphics autoload.
    pub async fn load_smc_navi48(
        &mut self,
        firmware: &crate::amdgpu_navi48_firmware::Firmware,
    ) -> Result<(), Error> {
        self.check_navi48_firmware(firmware)?;
        let images = firmware.images().map_err(|_| Error::Invalid)?;
        let smc = images[0].payloads().next().ok_or(Error::Invalid)?;
        self.session.load_smc(smc.bytes()).await
    }
    /// Load GC12 RS64, MES12, IMU, RLC, SDMA7 and media payloads in UCODE_ID
    /// order. Caller must have stopped DMUB and every replaced firmware consumer.
    /// Completion acknowledges upload/autoload; it does not enable queues.
    pub async fn load_gfx_navi48(
        &mut self,
        firmware: &crate::amdgpu_navi48_firmware::Firmware,
    ) -> Result<(), Error> {
        self.check_navi48_firmware(firmware)?;
        let images = firmware.images().map_err(|_| Error::Invalid)?;
        self.session.load_gfx12(&images).await
    }
    /// Check GC12's own RLC status register after the accepted autoload.
    pub async fn wait_gfx_boot_navi48(&mut self) -> Result<GfxBootStatus, Error> {
        if !matches!(self.kind, Kind::Navi48(_)) {
            return Err(Error::Unsupported);
        }
        self.session.wait_gfx_boot().await
    }
    /// Graphics upload state; remains Absent for Phoenix sessions.
    pub fn gfx_load_state(&self) -> GfxLoadState {
        self.session.gfx_state
    }
    pub fn gfx_boot_status(&self) -> Option<GfxBootStatus> {
        self.session.gfx_status
    }
    pub fn media_firmware(&self) -> MediaFirmware {
        self.session.media_firmware
    }
    /// The GMC system aperture validated against the pool at construction:
    /// (`gmc.fb_start`, `vm_manager.vram_base_offset`) in Linux terms.
    pub(crate) fn fb_location(&self) -> (u64, u64) {
        (self.session.fb_base, self.session.fb_offset)
    }
    pub(crate) fn dmub_tmr(&self) -> Result<core::ops::Range<u64>, Error> {
        if self.kind != Kind::Navi22
            || !self.session.tmr_ready
            || self.session.media_firmware.dmcub.is_none()
        {
            return Err(Error::Invalid);
        }
        let tmr = self.session.tmr.as_ref().ok_or(Error::Invalid)?;
        Ok(tmr.address()..tmr.address() + tmr.size())
    }
    /// Wait for idle CP and RLC BOOTLOAD_COMPLETE after this session's accepted
    /// autoload. No GC writes, queue initialization or fw_loaded publication.
    pub async fn wait_gfx_boot_navi22(&mut self) -> Result<GfxBootStatus, Error> {
        if self.kind != Kind::Navi22 {
            return Err(Error::Unsupported);
        }
        self.session.wait_gfx_boot().await
    }
    /// # Safety
    /// Every engine using the TMR must have verified reset. Ring destruction
    /// alone does not stop instruction fetches from trusted memory.
    pub async unsafe fn stop(&mut self) -> Result<(), Error> {
        // SAFETY: caller guarantees quiescence of every TMR consumer.
        unsafe { self.session.stop().await }
    }
}
impl<I: Io> Session<I> {
    async fn stage(&mut self, bytes: &[u8]) -> Result<(u64, u32), Error> {
        if self.engine.state != State::Ready || self.payload.is_some() {
            return Err(Error::Busy);
        }
        if bytes.is_empty() || bytes.len() > MAX_IMAGE {
            return Err(Error::Invalid);
        }
        let allocation = self
            .pool
            .reserve(bytes.len() as u64)
            .map_err(|_| Error::Allocation)?;
        let address = allocation.address();
        let map = allocation.mapping();
        self.payload = Some(allocation);
        for (index, chunk) in bytes.chunks(4096).enumerate() {
            self.engine.access(|io| {
                for (i, word) in chunk.chunks(4).enumerate() {
                    let mut padded = [0u8; 4];
                    padded[..word.len()].copy_from_slice(word);
                    io.write_payload(
                        map,
                        (index * 4096 + i * 4) as u64,
                        u32::from_le_bytes(padded),
                    );
                }
            })?;
            narf_scheduler::yield_now().await;
        }
        self.engine.access(|io| io.flush())?;
        self.payload.as_mut().unwrap().publish();
        Ok((address, bytes.len() as u32))
    }
    fn release_payload(&mut self) {
        if self.engine.state == State::Ready {
            if let Some(mut payload) = self.payload.take() {
                // SAFETY: exact fence completed the only command reading this image.
                unsafe {
                    payload.stopped();
                }
            }
        }
    }
    /// TOC bytes have already been selected from a validated firmware container.
    /// psp_tmr_init then psp_tmr_load, for PSPs without centralized C-states.
    async fn setup_tmr_payload(&mut self, toc: Option<&[u8]>) -> Result<(), Error> {
        self.init_tmr(toc).await?;
        self.load_tmr().await
    }
    /// psp_tmr_init: LOAD_TOC (size from PSP) and the TMR reservation. No
    /// address reaches PSP yet; an unloaded reservation is not published.
    async fn init_tmr(&mut self, toc: Option<&[u8]>) -> Result<(), Error> {
        if self.tmr.is_some() || self.payload.is_some() || self.engine.state != State::Ready {
            return Err(Error::Busy);
        }
        let size = if let Some(payload) = toc {
            let (address, size) = self.stage(payload).await?;
            let result = self
                .engine
                // linux-lit: 0x20=GFX_CMD_ID_LOAD_TOC
                .submit(&load_command(0x20, address, size, 0))
                .await;
            self.release_payload();
            result?.tmr_size as u64
        } else {
            DEFAULT_TMR_SIZE
        };
        if size == 0 || size > 64 * 1024 * 1024 || size % 4096 != 0 {
            return Err(Error::Invalid);
        }
        let tmr = self
            .pool
            // linux: n/a (1 << 20 is PSP_TMR_ALIGNMENT, amdgpu_psp.h)
            .reserve_aligned(size, 1 << 20)
            .map_err(|_| Error::Allocation)?;
        tmr.address()
            .checked_sub(self.fb_base)
            .and_then(|n| n.checked_add(self.fb_offset))
            .filter(|n| n.checked_add(size).is_some_and(|end| end <= 1 << 48))
            .ok_or(Error::Invalid)?;
        self.tmr = Some(tmr);
        Ok(())
    }
    /// psp_tmr_load: SETUP_TMR for the reserved region, published first.
    async fn load_tmr(&mut self) -> Result<(), Error> {
        if self.tmr_ready || self.payload.is_some() || self.engine.state != State::Ready {
            return Err(Error::Busy);
        }
        let (fb_base, fb_offset) = (self.fb_base, self.fb_offset);
        let tmr = self.tmr.as_mut().ok_or(Error::Busy)?;
        let (address, size) = (tmr.address(), tmr.size());
        let physical = address - fb_base + fb_offset;
        tmr.publish();
        self.engine
            .submit(&command(
                5, // linux-lit: 5=GFX_CMD_ID_SETUP_TMR
                &[
                    address as u32,
                    (address >> 32) as u32,
                    size as u32,
                    // linux: n/a (tmr_flags bitfield.virt_phy_addr = 1, bit 1; amdgpu_psp.c:psp_prep_tmr_cmd_buf)
                    2,
                    physical as u32,
                    (physical >> 32) as u32,
                ],
            ))
            .await?;
        self.tmr_ready = true;
        Ok(())
    }
    /// Shared LOAD_IP_FW transport; public entry points select the image/type.
    async fn load_ip(&mut self, bytes: &[u8], firmware_type: u32) -> Result<Reply, Error> {
        if !self.tmr_ready {
            return Err(Error::Busy);
        }
        self.load_ip_unchecked(bytes, firmware_type).await
    }
    async fn load_ip_unchecked(
        &mut self,
        bytes: &[u8],
        firmware_type: u32,
    ) -> Result<Reply, Error> {
        let (address, size) = self.stage(bytes).await?;
        let result = self
            .engine
            // linux-lit: 6=GFX_CMD_ID_LOAD_IP_FW
            .submit(&load_command(6, address, size, firmware_type))
            .await;
        self.release_payload();
        result
    }
    async fn load_smc(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.smc_state != SmcState::Absent
            || !self.tmr_ready
            || self.engine.state != State::Ready
            || self.payload.is_some()
        {
            return Err(Error::Busy);
        }
        self.smc_state = SmcState::Pending;
        let result = self.load_ip(bytes, 18).await.map(|_| ()); // GFX_FW_TYPE_SMU
        self.smc_state = if result.is_ok() {
            SmcState::Loaded
        } else {
            SmcState::Failed
        };
        result
    }
    /// PMFW-centralized C-state order (MP0 11.0.0..13, 13.0.0/2/7): SMC
    /// LOAD_IP_FW after LOAD_TOC/TMR reservation but before SETUP_TMR, which
    /// follows immediately (psp_hw_start).
    async fn load_smc_centralized(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.smc_state != SmcState::Absent
            || self.tmr.is_none()
            || self.tmr_ready
            || self.engine.state != State::Ready
            || self.payload.is_some()
        {
            return Err(Error::Busy);
        }
        self.smc_state = SmcState::Pending;
        // linux-lit: 18=GFX_FW_TYPE_SMU
        let result = self.load_ip_unchecked(bytes, 18).await.map(|_| ());
        self.smc_state = if result.is_ok() {
            SmcState::Loaded
        } else {
            SmcState::Failed
        };
        result?;
        self.load_tmr().await
    }
    async fn load_gfx(
        &mut self,
        images: &[Option<crate::amdgpu_gfx_firmware::Image<'_>>;
             crate::amdgpu_gfx_firmware::Source::ORDER.len()],
    ) -> Result<(), Error> {
        use crate::amdgpu_gfx_firmware::Source;
        if self.gfx_state != GfxLoadState::Absent
            || self.smc_state != SmcState::Loaded
            || !self.tmr_ready
            || self.engine.state != State::Ready
            || self.payload.is_some()
        {
            return Err(Error::Busy);
        }
        // Validate completeness/order before publishing any part of the set.
        for (image, source) in images.iter().zip(Source::ORDER) {
            match image {
                Some(image) if image.source() == source => {}
                None if source == Source::Mec2 => {}
                _ => return Err(Error::Invalid),
            }
        }
        self.gfx_state = GfxLoadState::Loading;
        let result = self.load_gfx_inner(images).await;
        self.gfx_state = if result.is_ok() {
            GfxLoadState::Accepted
        } else {
            GfxLoadState::Failed
        };
        result
    }
    async fn load_gfx12(
        &mut self,
        images: &[crate::amdgpu_navi48_ucode::Image<'_>; 11],
    ) -> Result<(), Error> {
        use crate::amdgpu_navi48_ucode::{Source, UPLOAD_ORDER};
        if self.gfx_state != GfxLoadState::Absent
            || self.smc_state != SmcState::Loaded
            || !self.tmr_ready
            || self.engine.state != State::Ready
            || self.payload.is_some()
        {
            return Err(Error::Busy);
        }
        if images
            .iter()
            .zip(Source::ALL)
            .any(|(image, source)| image.source() != source)
        {
            return Err(Error::Invalid);
        }
        self.gfx_state = GfxLoadState::Loading;
        let result = async {
            for kind in UPLOAD_ORDER.into_iter().skip(1) {
                // RLC restore-list payloads may be empty. The parsers require
                // every other payload, and Source::ALL is checked above.
                let payload = images
                    .iter()
                    .flat_map(|i| i.payloads())
                    .find(|p| p.firmware_type() == kind);
                let Some(payload) = payload else {
                    // linux-lit: 22=GFX_FW_TYPE_RLC_RESTORE_LIST_SRM_CNTL; 20=GFX_FW_TYPE_RLC_RESTORE_LIST_GPM_MEM; 21=GFX_FW_TYPE_RLC_RESTORE_LIST_SRM_MEM; 26=GFX_FW_TYPE_RLC_IRAM; 48=GFX_FW_TYPE_RLC_DRAM_BOOT
                    if matches!(kind, 22 | 20 | 21 | 26 | 48) {
                        continue;
                    }
                    return Err(Error::Invalid);
                };
                let reply = self.load_ip(payload.bytes(), kind).await?;
                // linux-lit: 13=GFX_FW_TYPE_VCN; 51=GFX_FW_TYPE_DMUB
                if matches!(kind, 13 | 51) {
                    self.record_media(reply, kind)?;
                }
                // linux-lit: 8=GFX_FW_TYPE_RLC_G
                if kind == 8 {
                    // linux-lit: 0x21=GFX_CMD_ID_AUTOLOAD_RLC
                    self.engine.submit(&command(0x21, &[])).await?;
                }
            }
            Ok(())
        }
        .await;
        self.gfx_state = if result.is_ok() {
            GfxLoadState::Accepted
        } else {
            GfxLoadState::Failed
        };
        result
    }
    fn record_media(&mut self, reply: Reply, kind: u32) -> Result<(), Error> {
        let tmr = self.tmr.as_ref().ok_or(Error::Invalid)?;
        let offset = reply
            .address
            .checked_sub(tmr.address())
            .ok_or(Error::Invalid)?;
        if reply.address % 4 != 0 || offset >= tmr.mapping().len {
            return Err(Error::Invalid);
        }
        match kind {
            13 => self.media_firmware.vcn = Some(reply.address), // linux-lit: 13=GFX_FW_TYPE_VCN
            crate::amdgpu_gfx_firmware::VCN1_TYPE => self.media_firmware.vcn1 = Some(reply.address),
            _ => self.media_firmware.dmcub = Some(reply.address),
        }
        Ok(())
    }
    async fn load_gfx_inner(
        &mut self,
        images: &[Option<crate::amdgpu_gfx_firmware::Image<'_>>;
             crate::amdgpu_gfx_firmware::Source::ORDER.len()],
    ) -> Result<(), Error> {
        for image in images.iter().flatten() {
            for payload in image.payloads() {
                let reply = self
                    .load_ip(payload.bytes(), payload.firmware_type())
                    .await?;
                if matches!(
                    image.source(),
                    crate::amdgpu_gfx_firmware::Source::Vcn
                        | crate::amdgpu_gfx_firmware::Source::Dmcub
                ) {
                    self.record_media(reply, payload.firmware_type())?;
                }
            }
            if image.source() == crate::amdgpu_gfx_firmware::Source::Rlc {
                // Linux starts RLC immediately after RLC_G, before the later
                // VCN and DMCUB uploads. Never delay/replay autoload for media.
                // linux-lit: 0x21=GFX_CMD_ID_AUTOLOAD_RLC
                self.engine.submit(&command(0x21, &[])).await?;
            }
        }
        Ok(())
    }
    async fn wait_gfx_boot(&mut self) -> Result<GfxBootStatus, Error> {
        if self.gfx_state != GfxLoadState::Accepted
            || self.engine.state != State::Ready
            || !self.tmr_ready
            || self.smc_state != SmcState::Loaded
        {
            return Err(Error::Busy);
        }
        self.gfx_state = GfxLoadState::Checking;
        let result = self.wait_gfx_boot_inner().await;
        self.gfx_state = if result.is_ok() {
            GfxLoadState::BootComplete
        } else {
            GfxLoadState::Failed
        };
        result
    }
    async fn wait_gfx_boot_inner(&mut self) -> Result<GfxBootStatus, Error> {
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            let status = self.engine.access(|io| io.gfx_boot_status())??;
            self.gfx_status = Some(status);
            if status.cp_stat == u32::MAX || status.rlc_bootload == u32::MAX {
                return Err(Error::DeviceGone);
            }
            // linux-lit: 31=RLC_RLCS_BOOTLOAD_STATUS__BOOTLOAD_COMPLETE__SHIFT
            if status.cp_stat == 0 && status.rlc_bootload & (1 << 31) != 0 {
                return Ok(status);
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(1).await;
        }
    }
    /// # Safety
    /// Every engine using this TMR (including DMUB) must have verified reset.
    /// Ring destruction alone does not stop instruction fetches from the TMR.
    async unsafe fn stop(&mut self) -> Result<(), Error> {
        if self.tmr.is_some() {
            if self.engine.state != State::Ready {
                return Err(Error::Busy);
            }
            self.engine.submit(&command(7, &[])).await?; // linux-lit: 7=GFX_CMD_ID_DESTROY_TMR
            self.tmr_ready = false;
            if let Some(mut tmr) = self.tmr.take() {
                // SAFETY: caller stopped all engines; PSP acknowledged TMR release.
                unsafe {
                    tmr.stopped();
                }
            }
        }
        self.engine.stop().await?;
        if let Some(mut payload) = self.payload.take() {
            // SAFETY: ring destruction acknowledged that PSP no longer reads it.
            unsafe {
                payload.stopped();
            }
        }
        self.smc_state = SmcState::Absent;
        self.gfx_state = GfxLoadState::Absent;
        self.gfx_status = None;
        Ok(())
    }
}
pub(crate) fn toc_payload(bytes: &[u8]) -> Result<&[u8], Error> {
    let h = crate::amdgpu_ucode_header::parse_common(bytes).map_err(|_| Error::Invalid)?;
    let end = h
        .ucode_array_offset_bytes
        .checked_add(h.ucode_size_bytes)
        .ok_or(Error::Invalid)?;
    if bytes.len() > MAX_IMAGE + 4096
        || h.size_bytes as usize != bytes.len()
        || h.header_size_bytes < 44 // linux-lit: 44=sizeof(struct psp_firmware_header_v1_0)
        || (h.header_version_major, h.header_version_minor) != (1, 0)
        || h.ucode_array_offset_bytes < h.header_size_bytes
        || h.ucode_size_bytes == 0
        || h.ucode_size_bytes as usize > MAX_IMAGE
    {
        return Err(Error::Invalid);
    }
    bytes
        .get(h.ucode_array_offset_bytes as usize..end as usize)
        .ok_or(Error::Invalid)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_psp_ring_tests.rs"]
mod tests;
