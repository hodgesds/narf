//! Navi48 VCN5 unified queue, Linux vcn_v5_0_0.c's static-power path.
//! PSP owns the image in TMR. This owner retains stack/context/shared/ring
//! memory across cancellation and failure; a successful stop proves retirement.
//! DPG and media deep sleep remain disabled during bring-up.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
#[path = "amdgpu_vcn_navi48_decode.rs"]
mod decode_proof;
#[path = "amdgpu_vcn_navi48_decode_words.rs"]
mod decode_words;
#[path = "amdgpu_vcn_navi48_ib.rs"]
mod ib_proof;
#[path = "amdgpu_vcn_navi48_ib_words.rs"]
mod ib_words;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Readback,
    Timeout,
    BootFailed,
    PowerPolicy(u64),
    DecodeChecksum(u64),
    Interrupts(crate::amdgpu_ih7::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Starting,
    Ready,
    Testing,
    Verified,
    InterruptTesting,
    InterruptVerified,
    IbTesting,
    IbVerified,
    DecodeTesting,
    DecodeVerified,
    Stopping,
    Stopped,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub sequence: u32,
    /// Observed dword ring pointer (the initial proofs do not wrap).
    pub read_pointer: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptProof {
    pub fence: Proof,
    pub msi_verified: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeProof {
    pub completion: InterruptProof,
    pub output_sum: u64,
}

// vcn_5_0_0_offset.h: all registers below are in VCN instance 0, bank 1.
mod regs {
    pub const DLDO_CONFIG: u32 = 0x000; // regUVD_IPX_DLDO_CONFIG
    pub const DLDO_STATUS: u32 = 0x001; // regUVD_IPX_DLDO_STATUS
    pub const POWER_STATUS: u32 = 0x002; // regUVD_POWER_STATUS
    pub const ADDR_CONFIG: u32 = 0x042; // regUVD_GFX10_ADDR_CONFIG
    pub const DB_CTRL: u32 = 0x072; // regVCN_RB1_DB_CTRL
    pub const RB_ENABLE: u32 = 0x085; // regVCN_RB_ENABLE
    pub const RPTR: u32 = 0x0ac; // regUVD_RB_RPTR
    pub const WPTR: u32 = 0x0ad; // regUVD_RB_WPTR
    pub const MASTINT: u32 = 0x121; // regUVD_MASTINT_EN
    pub const RB_LO: u32 = 0x12a; // regUVD_RB_BASE_LO
    pub const RB_HI: u32 = 0x12b; // regUVD_RB_BASE_HI
    pub const RB_SIZE: u32 = 0x12c; // regUVD_RB_SIZE
    pub const ARB: u32 = 0x146; // regUVD_RB_ARB_CTRL
    pub const STATUS: u32 = 0x183; // regUVD_STATUS
    pub const RESET: u32 = 0x187; // regUVD_SOFT_RESET
    pub const CACHE_OFFSET: [u32; 3] = [0x1c0, 0x1c2, 0x1c4]; // regUVD_VCPU_CACHE_OFFSET{0,1,2}
    pub const CACHE_SIZE: [u32; 3] = [0x1c1, 0x1c3, 0x1c5]; // regUVD_VCPU_CACHE_SIZE{0,1,2}
    pub const NC_OFFSET: u32 = 0x1d2; // regUVD_VCPU_NONCACHE_OFFSET0
    pub const NC_SIZE: u32 = 0x1d3; // regUVD_VCPU_NONCACHE_SIZE0
    pub const VCPU: u32 = 0x1d6; // regUVD_VCPU_CNTL
    pub const CACHE_LO: [u32; 3] = [0x2cf, 0x2fb, 0x2ff]; // regUVD_LMI_VCPU_CACHE{,1,2}_64BIT_BAR_LOW
    pub const NC_LO: u32 = 0x2cb; // regUVD_LMI_VCPU_NC0_64BIT_BAR_LOW
    pub const LMI2: u32 = 0x32e; // regUVD_LMI_CTRL2
    pub const LMI: u32 = 0x330; // regUVD_LMI_CTRL
    pub const LMI_STATUS: u32 = 0x331; // regUVD_LMI_STATUS
}
use regs::*;
const STACK_BYTES: u64 = 128 << 10;
const CONTEXT_BYTES: u64 = 512 << 10;
const SHARED: u64 = STACK_BYTES + CONTEXT_BYTES;
const RING: u64 = SHARED + 4096;
const FENCE: u64 = RING + 4096;
const WRITEBACK: u64 = FENCE + 4;
const BYTES: u64 = FENCE + 4096;
const DOORBELL_BASE: u32 = 0x310; // soc24: AMDGPU_NAVI10_DOORBELL64_VCN0_1 << 1
const DOORBELL: u32 = DOORBELL_BASE + 2; // vcn_v5_0_0_sw_init
const NBIO_RANGE: u32 = 0x1cf; // NBIF6.3.1 bank 2: GDC_S2A0_S2A_DOORBELL_ENTRY_4_CTRL
const VCPU_RESET: u32 = 1 << 28;
const VCPU_CLOCK: u32 = 1 << 9;
const RB1: u32 = 1 << 2;
const ALL_RBS: u32 = 0x3c;

#[derive(Clone, Copy, Debug)]
struct Layout {
    vcn: u64,
    nbio: u64,
    gc: u64,
    mm: u64,
    oss: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI48
            || gpu.regs.len < 0x7f004
            || gpu
                .ip_blocks
                .iter()
                .filter(|b| b.hw_id == ip::HW_ID_VCN)
                .count()
                != 1
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            vcn: bank(gpu, ip::HW_ID_VCN, &[(5, 0, 0)], 1, LMI_STATUS)
                .map_err(|_| Error::Unsupported)?,
            nbio: bank(gpu, ip::HW_ID_NBIF, &[(6, 3, 1)], 2, NBIO_RANGE)
                .map_err(|_| Error::Unsupported)?,
            gc: bank(gpu, ip::HW_ID_GC, &[(12, 0, 1)], 0, 0x263e)
                .map_err(|_| Error::Unsupported)?,
            mm: bank(gpu, ip::HW_ID_MMHUB, &[(4, 1, 0)], 0, 0x62e)
                .map_err(|_| Error::Unsupported)?,
            oss: bank(gpu, ip::HW_ID_OSSSYS, &[(7, 0, 0)], 0, 0x1f)
                .map_err(|_| Error::Unsupported)?,
        })
    }
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32;
    fn memory_write(&mut self, map: MmioRegion, at: u64, value: u32);
    fn memory_read8(&mut self, map: MmioRegion, at: u64) -> u8;
    fn memory_write8(&mut self, map: MmioRegion, at: u64, value: u8);
    fn doorbell(&mut self, at: u32, value: u32);
    async fn delay(&mut self, us: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
    }
}
#[derive(Clone, Copy, Debug)]
struct Mmio {
    regs: MmioRegion,
    doorbells: MmioRegion,
}
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: Layout bounds every register; Engine invokes live authority.
        unsafe { self.regs.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: the same bounded register map and live authority.
        unsafe { self.regs.write32(at, value) };
    }
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32 {
        // SAFETY: Engine uses dwords inside its retained allocation only.
        unsafe { map.read32(at) }
    }
    fn memory_write(&mut self, map: MmioRegion, at: u64, value: u32) {
        // SAFETY: the same retained allocation and bounded dword offsets.
        unsafe { map.write32(at, value) };
    }
    fn doorbell(&mut self, at: u32, value: u32) {
        // SAFETY: constructor bounds DOORBELL; caller owns this BAR2 range.
        unsafe { self.doorbells.write32(u64::from(at) * 4, value) };
    }
    fn memory_read8(&mut self, map: MmioRegion, at: u64) -> u8 {
        // SAFETY: the queue_mode byte belongs to this retained shared page.
        unsafe { map.read8(at) }
    }
    fn memory_write8(&mut self, map: MmioRegion, at: u64, value: u8) {
        // SAFETY: byte writes preserve adjacent firmware-owned queue_status.
        unsafe { map.write8(at, value) };
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
fn update<I: Io>(io: &mut I, at: u64, mask: u32, value: u32) -> Result<(), Error> {
    let old = checked(io.read(at))?;
    io.write(at, (old & !mask) | value);
    if checked(io.read(at))? & mask != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn flush<I: Io>(io: &mut I, l: Layout) -> Result<(), Error> {
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    checked(io.read(l.nbio + 0xc3 * 4))?;
    fence(Ordering::SeqCst);
    Ok(())
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    ib_pool: Pool,
    ib_memory: Option<Reservation>,
    decode_memory: Option<Reservation>,
    firmware_bytes: u32,
    state: State,
    proof: Option<Proof>,
    interrupt_result: Option<Result<InterruptProof, Error>>,
    ib_result: Option<Result<InterruptProof, Error>>,
    decode_result: Option<Result<DecodeProof, Error>>,
    wptr: u32,
    seq: u32,
}
impl<I: Io> Engine<I> {
    fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I, Layout) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let io = &mut self.io;
        let l = self.layout;
        self.authority
            .invoke(Op(|| f(io, l)))
            .map_err(|_| Error::Revoked)?
    }
    fn reg(&mut self, reg: u32) -> Result<u32, Error> {
        self.access(|io, l| checked(io.read(l.vcn + u64::from(reg) * 4)))
    }
    fn set(&mut self, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.access(|io, l| update(io, l.vcn + u64::from(reg) * 4, mask, value))
    }
    async fn wait(&mut self, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
        for _ in 0..2000 {
            if self.reg(reg)? & mask == value {
                return Ok(());
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
    async fn start(
        &mut self,
        image: u64,
        power: crate::amdgpu_smu_navi48::PowerStatus,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::Busy);
        }
        let fw_size = (u64::from(self.firmware_bytes) + 8 + 4095) & !4095;
        if image == 0
            || image & 0xfff != 0
            || image.checked_add(fw_size).is_none_or(|end| end > 1 << 48)
        {
            return Err(Error::Invalid);
        }
        // PMFW must not gate media clocks behind the static owner. The caller
        // issues PowerUpVcn first, as Linux's dGPU SMU14 path does.
        if power.enabled & ((1 << 20) | (1 << 44)) != 0 {
            return Err(Error::PowerPolicy(power.enabled));
        }
        if self.reg(RB_ENABLE)? & ALL_RBS != 0 || self.reg(VCPU)? & VCPU_RESET == 0 {
            return Err(Error::Busy);
        }
        if self.access(|io, l| checked(io.read(l.nbio + u64::from(NBIO_RANGE) * 4)))?
            & (1 | 0x1fe0000)
            != 0
        {
            return Err(Error::Busy);
        }
        self.state = State::Starting;
        self.proof = None;
        self.interrupt_result = None;
        self.ib_result = None;
        self.decode_result = None;
        self.memory.publish();
        let result = self
            .start_inner(image)
            .await
            .and_then(|()| self.access(|_, _| Ok(())));
        self.state = match result {
            Ok(()) => State::Ready,
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn start_inner(&mut self, image: u64) -> Result<(), Error> {
        let map = self.memory.mapping();
        // Yield between pages; cancellation conservatively retains the whole
        // allocation before even the first VCPU address is published.
        for page in (0..BYTES).step_by(4096) {
            self.access(|io, l| {
                for at in (page..page + 4096).step_by(4) {
                    io.memory_write(map, at, 0);
                }
                flush(io, l)
            })?;
            self.io.delay(1).await;
        }
        self.access(|io, l| {
            io.memory_write(map, SHARED, 0x804); // unified queue + dGPU SMU interface
            io.memory_write(map, SHARED + 16, 1); // sq.is_enabled, queue_mode=0
            flush(io, l)
        })?;
        // !AMD_PG_SUPPORT_VCN branch: power ONO2..5 on, no DPG script.
        for (config, status) in [(6, 3), (8, 4), (10, 5), (12, 6)] {
            self.set(DLDO_CONFIG, u32::MAX, 1 << config)?;
            self.wait(DLDO_STATUS, 1 << status, 0).await?;
        }
        self.set(POWER_STATUS, 0x103, 0)?;
        self.set(STATUS, 4, 4)?;
        self.set(VCPU, VCPU_CLOCK, VCPU_CLOCK)?;
        self.set(MASTINT, 2, 0)?;
        self.set(LMI2, 0x100, 0)?;
        self.set(RESET, 0x2004, 0)?;
        self.set(LMI, 0x203100, 0x203100)?;
        let base = self.memory.address();
        let bytes = self.firmware_bytes.checked_add(8).ok_or(Error::Invalid)?;
        let fw_size = bytes.checked_add(4095).ok_or(Error::Invalid)? & !4095;
        for (i, (addr, size)) in [
            (image, fw_size),
            (base, STACK_BYTES as u32),
            (base + STACK_BYTES, CONTEXT_BYTES as u32),
        ]
        .into_iter()
        .enumerate()
        {
            self.set(CACHE_LO[i], u32::MAX, addr as u32)?;
            self.set(CACHE_LO[i] + 1, u32::MAX, (addr >> 32) as u32)?;
            self.set(CACHE_OFFSET[i], u32::MAX, 0)?;
            self.set(CACHE_SIZE[i], u32::MAX, size)?;
        }
        self.set(NC_LO, u32::MAX, (base + SHARED) as u32)?;
        self.set(NC_LO + 1, u32::MAX, ((base + SHARED) >> 32) as u32)?;
        self.set(NC_OFFSET, u32::MAX, 0)?;
        self.set(NC_SIZE, u32::MAX, 4096)?;
        let addr_config = self.access(|io, l| checked(io.read(l.gc + 0x263e * 4)))?;
        self.set(ADDR_CONFIG, u32::MAX, addr_config)?;
        self.set(ARB, 8, 0)?;
        self.set(VCPU, VCPU_RESET, 0)?;
        let mut booted = false;
        for _ in 0..10 {
            for _ in 0..100 {
                if self.reg(STATUS)? & 2 != 0 {
                    booted = true;
                    break;
                }
                self.io.delay(10_000).await;
            }
            if booted {
                break;
            }
            self.set(VCPU, VCPU_RESET, VCPU_RESET)?;
            self.io.delay(10_000).await;
            self.set(VCPU, VCPU_RESET, 0)?;
            self.io.delay(10_000).await;
        }
        if !booted {
            return Err(Error::BootFailed);
        }
        // Master IRQ stays masked until an independent owner is registered.
        self.set(STATUS, 4, 0)?;
        self.set(DB_CTRL, 0x4fff_fffc, DOORBELL << 2 | 1 << 30)?;
        self.set(RB_LO, u32::MAX, (base + RING) as u32)?;
        self.set(RB_HI, u32::MAX, ((base + RING) >> 32) as u32)?;
        self.set(RB_SIZE, u32::MAX, 1024)?;
        self.set(RB_ENABLE, RB1, 0)?;
        self.shared_mode(1, 1)?;
        self.set(RPTR, u32::MAX, 0)?;
        self.set(WPTR, u32::MAX, 0)?;
        if self.reg(RPTR)? != 0 {
            return Err(Error::Readback);
        }
        self.wptr = 0;
        self.set(RB_ENABLE, RB1, RB1)?;
        self.shared_mode(3, 0)?;
        self.access(|io, l| {
            const MASK: u32 = 1 | 0x3e | 0x1ff80 | 0x1fe0000 | 0xf0000000;
            update(
                io,
                l.nbio + u64::from(NBIO_RANGE) * 4,
                MASK,
                1 | 4 << 1 | DOORBELL_BASE << 7 | 8 << 17 | 4 << 28,
            )?;
            checked(io.read(l.vcn + u64::from(STATUS) * 4))?;
            Ok(())
        })
    }
    fn shared_mode(&mut self, mask: u8, value: u8) -> Result<(), Error> {
        let map = self.memory.mapping();
        self.access(|io, l| {
            let old = io.memory_read8(map, SHARED + 17);
            io.memory_write8(map, SHARED + 17, (old & !mask) | value);
            flush(io, l)
        })
    }
    fn emit(&mut self, words: &[u32]) -> Result<u32, Error> {
        if !matches!(
            self.state,
            State::Ready
                | State::Testing
                | State::Verified
                | State::InterruptTesting
                | State::InterruptVerified
                | State::IbTesting
                | State::IbVerified
                | State::DecodeTesting
                | State::DecodeVerified
        ) {
            return Err(Error::Busy);
        }
        if words.is_empty() || words.len() > 960 {
            return Err(Error::Invalid);
        }
        let padded = (words.len() as u32 + 63) & !63;
        // VCN has no support_64bit_ptrs: amdgpu_ring's ptr_mask is its
        // buf_mask. Leave space so equal masked pointers mean empty.
        let pending = self.wptr.wrapping_sub(self.reg(RPTR)?) & 1023;
        if pending + padded >= 1024 {
            return Err(Error::Busy);
        }
        let next = self.wptr.wrapping_add(padded) & 1023;
        let map = self.memory.mapping();
        let wptr = self.wptr;
        self.access(|io, l| {
            for n in 0..padded {
                let at = RING + u64::from(wptr.wrapping_add(n) & 1023) * 4;
                io.memory_write(map, at, words.get(n as usize).copied().unwrap_or(0));
            }
            io.memory_write(map, WRITEBACK, next);
            flush(io, l)?;
            io.doorbell(DOORBELL, next);
            // Publication is the last operation. Client callers must receive
            // the sequence even if the device fails immediately afterwards,
            // so they retain job resources until retirement/error recovery.
            Ok(())
        })?;
        self.wptr = next;
        Ok(next)
    }
    async fn prove(&mut self) -> Result<Proof, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        self.state = State::Testing;
        let result = self
            .prove_inner()
            .await
            .and_then(|proof| self.access(|_, _| Ok(proof)));
        self.state = match result {
            Ok(_) => State::Verified,
            Err(e) => State::Failed(e),
        };
        if let Ok(proof) = result {
            self.proof = Some(proof);
        }
        result
    }
    async fn prove_inner(&mut self) -> Result<Proof, Error> {
        let map = self.memory.mapping();
        // Start clears the fence word; proof zero could match unwritten data.
        self.seq = self.seq.wrapping_add(1).max(1);
        let seq = self.seq;
        let at = self.memory.address() + FENCE;
        let next = self.emit(&[3, at as u32, (at >> 32) as u32, seq, 4, 1])?;
        for _ in 0..2000 {
            let rptr = self.reg(RPTR)?;
            if rptr.wrapping_sub(next) as i32 > 0 {
                return Err(Error::Readback);
            }
            let complete = self.access(|io, l| {
                flush(io, l)?;
                Ok(io.memory_read(map, FENCE) == seq)
            })?;
            if rptr == next && complete {
                self.fence_guards(next)?;
                return Ok(Proof {
                    sequence: seq,
                    read_pointer: rptr,
                });
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
    /// The fence is exactly one dword. A wider/stray firmware write must
    /// neither overwrite the CPU write-pointer word nor its page's guards.
    fn fence_guards(&mut self, next: u32) -> Result<(), Error> {
        let map = self.memory.mapping();
        self.access(|io, l| {
            flush(io, l)?;
            if io.memory_read(map, WRITEBACK) != next
                || (FENCE + 8..FENCE + 4096)
                    .step_by(4)
                    .any(|at| io.memory_read(map, at) != 0)
            {
                return Err(Error::Readback);
            }
            Ok(())
        })
    }
    async fn stop(&mut self) -> Result<(), Error> {
        if !matches!(
            self.state,
            State::Ready
                | State::Verified
                | State::InterruptVerified
                | State::IbVerified
                | State::DecodeVerified
        ) {
            return Err(Error::Busy);
        }
        self.state = State::Stopping;
        let result = self
            .stop_inner()
            .await
            .and_then(|()| self.access(|_, _| Ok(())));
        self.state = match result {
            Ok(()) => State::Stopped,
            Err(e) => State::Failed(e),
        };
        if result.is_ok() {
            // SAFETY: VCPU reset/clock and LMI resets follow drained ring,
            // VCPU/UMC write-clean checks; every address user is retired.
            unsafe {
                self.memory.stopped();
                if let Some(memory) = self.ib_memory.as_mut() {
                    memory.stopped();
                }
                if let Some(memory) = self.decode_memory.as_mut() {
                    memory.stopped();
                }
            }
        }
        result
    }
    async fn stop_inner(&mut self) -> Result<(), Error> {
        self.shared_mode(2, 2)?;
        self.wait(RPTR, 1023, self.wptr).await?;
        self.wait(STATUS, 7, 2).await?;
        self.wait(LMI_STATUS, 0xf, 0xf).await?;
        self.set(LMI2, 0x100, 0x100)?;
        self.wait(LMI_STATUS, 0x240, 0x240).await?;
        if self.reg(RB_ENABLE)? & (ALL_RBS & !RB1) != 0 {
            return Err(Error::Busy);
        }
        self.set(MASTINT, 2, 0)?;
        self.set(RB_ENABLE, RB1, 0)?;
        self.set(ARB, 8, 8)?;
        self.set(VCPU, VCPU_RESET, VCPU_RESET)?;
        self.set(VCPU, VCPU_CLOCK, 0)?;
        self.set(RESET, 0x2000, 0x2000)?;
        self.set(RESET, 4, 4)?;
        self.set(DB_CTRL, 1 << 30, 0)?;
        self.access(|io, l| update(io, l.nbio + u64::from(NBIO_RANGE) * 4, 1 | 0x1fe0000, 0))?;
        self.set(STATUS, u32::MAX, 0)?;
        self.reg(STATUS)?;
        Ok(())
    }
}

/// Native VCN5 instance 0, with an owned static-power VCPU and unified ring.
#[derive(Debug)]
pub struct Vcn {
    engine: Engine<Mmio>,
}
impl Vcn {
    /// # Safety
    /// Own this physical Navi48's VCN/JPEG, NBIF media range and BAR2
    /// doorbells exclusively. The permanent pool matches its boot inventory;
    /// retain PSP's VCN TMR, trained VRAM and ready MMHUB VMID0 throughout.
    /// Exclude reset/PM and competing VCPU/ring/clock writers. This is a cold
    /// owner, never an attach to firmware's running media engine.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: MmioRegion,
        firmware_bytes: usize,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        if firmware_bytes == 0
            || firmware_bytes > 4 << 20
            || doorbells.len < (u64::from(DOORBELL) + 1) * 4
        {
            return Err(Error::Invalid);
        }
        crate::amdgpu_psp_ring::navi48_layout(gpu)
            .and_then(|l| l.validate_pool(gpu, &authority, pool))
            .map_err(|e| match e {
                crate::amdgpu_psp_ring::Error::Revoked => Error::Revoked,
                crate::amdgpu_psp_ring::Error::DeviceGone => Error::DeviceGone,
                _ => Error::Invalid,
            })?;
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    doorbells,
                },
                authority,
                layout,
                memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
                ib_pool: pool.clone(),
                ib_memory: None,
                decode_memory: None,
                firmware_bytes: firmware_bytes as u32,
                state: State::Prepared,
                proof: None,
                interrupt_result: None,
                ib_result: None,
                decode_result: None,
                wptr: 0,
                seq: 0,
            },
        })
    }
    /// # Safety
    /// `new`'s exclusions hold; SMU14 PowerUpVcn(instance 0) has completed,
    /// `power` is its current policy, and `firmware` belongs to the retained
    /// PSP session. Keep this owner after error/cancellation until reset.
    pub async unsafe fn start(
        &mut self,
        firmware: crate::amdgpu_psp_ring::MediaFirmware,
        power: crate::amdgpu_smu_navi48::PowerStatus,
    ) -> Result<(), Error> {
        self.engine
            .start(firmware.vcn.ok_or(Error::Invalid)?, power)
            .await
    }
    /// Prove native unified-ring fence execution and complete RPTR drain.
    /// This proves transport, not codec execution or CPU MSI delivery.
    /// # Safety
    /// Keep `start`'s exclusions and every memory/firmware owner alive.
    pub async unsafe fn prove(&mut self) -> Result<Proof, Error> {
        self.engine.prove().await
    }
    /// # Safety
    /// The independent IH service has a retained VCN0 VMID0/PASID0 owner
    /// registered before master IRQs are enabled. Run from an executor task
    /// with CPU IRQs enabled when MSI is routed, retaining all start owners.
    /// Keep the registration and backing after cancellation/failure.
    pub async unsafe fn prove_interrupts(&mut self) -> Result<InterruptProof, Error> {
        self.engine
            .prove_interrupts(&mut crate::amdgpu_navi48_interrupts::NativeObserver)
            .await
    }
    /// # Safety
    /// Exclude all submissions and memory/firmware/PM writers. Only success
    /// permits PowerDownVcn or release of the retained allocation.
    pub async unsafe fn stop(&mut self) -> Result<(), Error> {
        self.engine.stop().await
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn proof(&self) -> Option<Proof> {
        self.engine.proof
    }
    pub fn interrupt_result(&self) -> Option<Result<InterruptProof, Error>> {
        self.engine.interrupt_result
    }
    /// Fixed Linux encode/decode session IBs with fresh interrupt evidence.
    /// # Safety
    /// Own the retained VCPU, firmware/GMC, kernel VMID0 and interrupt source;
    /// exclude clients/PM/reset and retain all storage after cancellation.
    pub async unsafe fn prove_ibs(&mut self) -> Result<InterruptProof, Error> {
        self.engine
            .prove_ibs(&mut crate::amdgpu_navi48_interrupts::NativeObserver)
            .await
    }
    pub fn ib_result(&self) -> Option<Result<InterruptProof, Error>> {
        self.engine.ib_result
    }
    /// Decode IGT's fixed AVC frame and verify its output checksum.
    /// # Safety
    /// Retain the exclusive VCPU/GMC/kernel-VMID0/IRQ owner with no clients,
    /// PM or reset, and keep all published memory after failure/cancellation.
    pub async unsafe fn prove_decode(&mut self) -> Result<DecodeProof, Error> {
        self.engine
            .prove_decode(&mut crate::amdgpu_navi48_interrupts::NativeObserver)
            .await
    }
    pub fn decode_result(&self) -> Option<Result<DecodeProof, Error>> {
        self.engine.decode_result
    }
    /// Queue a client frame on the verified unified ring.
    /// # Safety
    /// Own the client's MMHUB VMID/PASID/root and every IB/resource it reaches.
    /// Keep them pinned until this sequence completes or reset proves DMA
    /// retirement, including errors delivered after successful publication.
    /// Exclude concurrent ring/VMID/firmware/PM/reset writers.
    pub unsafe fn submit(&mut self, job: crate::amdgpu_gfx12_queue::Job) -> Result<u32, Error> {
        self.engine.submit(job)
    }
    /// The last physical sequence executed by this unified queue.
    pub fn completed_job(&mut self) -> Result<u32, Error> {
        self.engine.completed_job()
    }
    /// Retain this owner/backing and exclude reset/PM while using the reader.
    pub fn fence_reader(&self) -> Option<FenceReader> {
        matches!(
            self.engine.state,
            State::InterruptVerified | State::IbVerified | State::DecodeVerified
        )
        .then_some(FenceReader {
            io: self.engine.io,
            authority: self.engine.authority,
            layout: self.engine.layout,
            map: self.engine.memory.mapping(),
        })
    }
}

#[path = "amdgpu_vcn_navi48_irq.rs"]
mod irq;

#[path = "amdgpu_vcn_navi48_cs.rs"]
mod cs;

#[derive(Clone, Copy, Debug)]
pub struct FenceReader {
    io: Mmio,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    map: MmioRegion,
}
impl FenceReader {
    pub fn completed(&self) -> Result<u32, Error> {
        let mut io = self.io;
        let (l, map) = (self.layout, self.map);
        cs::client_fence(&mut io, self.authority, l, map)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_vcn_navi48_tests.rs"]
mod tests;
