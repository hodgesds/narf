// SPDX-License-Identifier: GPL-2.0-or-later
// Static-power sequence adapted from Linux jpeg_v5_0_0.c:
// Copyright 2023 Advanced Micro Devices, Inc. Full notice: ../JPEG-NOTICES.
//! JPEG5 JRBC owner. VCN retains the shared NBIO media range throughout this
//! owner's lifetime; JPEG never programs or disables that shared range.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::bank,
    amdgpu_vcn_navi48::{Io, Mmio},
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
#[path = "amdgpu_jpeg_navi48_cs.rs"]
mod cs;
#[path = "amdgpu_jpeg_navi48_decode.rs"]
mod decode_proof;
#[path = "amdgpu_jpeg_navi48_decode_words.rs"]
mod decode_words;
#[path = "amdgpu_jpeg_navi48_proof.rs"]
mod proof;
#[path = "amdgpu_jpeg_navi48_words.rs"]
mod words;

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
    DecodeTesting,
    DecodeVerified,
    /// Proofs drained; the wrapping ring now carries validated client frames.
    Clients,
    Stopping,
    Stopped,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub sequence: u32,
    pub read_pointer: u32,
    pub msi_verified: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeProof {
    pub completion: Proof,
    pub output_sum: u64,
}
const RING: u64 = 4096;
const FENCE: u64 = 8192;
// Reserve both GPCOM fence data dwords. Neither aliases the CPU shadow WPTR.
const WRITEBACK: u64 = FENCE + 8;
const IB: u64 = 12288;
const END_GUARD: u64 = 16384;
const BYTES: u64 = 20480;
const GUARD: u32 = 0xa3c57e91;
const DOORBELL: u32 = 0x311;
const RANGE: u32 = 0x1cf;
const RANGE_MASK: u32 = 1 | 0x3e | 0x1ff80 | 0x1fe0000 | 0xf0000000;
const RANGE_VALUE: u32 = 1 | 4 << 1 | 0x310 << 7 | 8 << 17 | 4 << 28;
mod regs {
    pub const DLDO_CONFIG: u32 = 0;
    pub const DLDO_STATUS: u32 = 1;
    pub const POWER: u32 = 3;
    pub const DB: u32 = 0x68;
    pub const PITCH: u32 = 0x603;
    pub const ADDR_CONFIG: u32 = 0x60a;
    pub const WPTR: u32 = 0x640;
    pub const CNTL: u32 = 0x641;
    pub const STATUS: u32 = 0x649;
    pub const RPTR: u32 = 0x64a;
    pub const SIZE: u32 = 0x653;
    pub const VMID: u32 = 0x665;
    pub const BASE_LO: u32 = 0x669;
    pub const BASE_HI: u32 = 0x66a;
    pub const CLEAN: u32 = 0x6cd;
    pub const JMI: u32 = 0x6ce;
    pub const IRQ: u32 = 0x701;
    pub const CG_GATE: u32 = 0x720;
    pub const CG_CTRL: u32 = 0x721;
    pub const CLEAN_MASK: u32 = 0x1011f;
    pub const CLEAN_VALUE: u32 = 0x1010f;
    pub const CG_MODES: u32 = 0x01010000;
    pub const CG_GATES: u32 = 0x701;
}
use regs::*;
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
        if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_none()
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
        // The start/end packets use MMHUB4.1's PCTL0 command format/address.
        let mm =
            bank(gpu, ip::HW_ID_MMHUB, &[(4, 1, 0)], 0, 0x62e).map_err(|_| Error::Unsupported)?;
        Ok(Self {
            mm,
            oss: bank(gpu, ip::HW_ID_OSSSYS, &[(7, 0, 0)], 0, 0x1f)
                .map_err(|_| Error::Unsupported)?,
            vcn: bank(gpu, ip::HW_ID_VCN, &[(5, 0, 0)], 1, CG_CTRL)
                .map_err(|_| Error::Unsupported)?,
            nbio: bank(gpu, ip::HW_ID_NBIF, &[(6, 3, 1)], 2, RANGE)
                .map_err(|_| Error::Unsupported)?,
            gc: bank(
                gpu,
                ip::HW_ID_GC,
                crate::amdgpu_rdna4::GC_VERSIONS,
                0,
                0x263e,
            )
            .map_err(|_| Error::Unsupported)?,
        })
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn checked(value: u32) -> Result<u32, Error> {
    if value == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(value)
    }
}
fn flush<I: Io>(io: &mut I, l: Layout) -> Result<(), Error> {
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    checked(io.read(l.nbio + 0xc3 * 4))?;
    fence(Ordering::SeqCst);
    Ok(())
}
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    pool: Pool,
    decode_memory: Option<Reservation>,
    /// Kernel VMID0 copies of validated client IBs (`cs::SLOTS` slots).
    client_memory: Option<Reservation>,
    state: State,
    result: Option<Result<Proof, Error>>,
    decode_result: Option<Result<DecodeProof, Error>>,
    seq: u32,
    wptr: u32,
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
        self.access(|io, l| {
            let at = l.vcn + u64::from(reg) * 4;
            let old = checked(io.read(at))?;
            io.write(at, (old & !mask) | value);
            if checked(io.read(at))? & mask != value {
                return Err(Error::Readback);
            }
            Ok(())
        })
    }
    fn shared_range(&mut self) -> Result<(), Error> {
        self.access(|io, l| {
            if checked(io.read(l.nbio + u64::from(RANGE) * 4))? & RANGE_MASK != RANGE_VALUE {
                return Err(Error::Busy);
            }
            Ok(())
        })
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
    async fn start(&mut self, power: crate::amdgpu_smu_navi48::PowerStatus) -> Result<(), Error> {
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::Busy);
        }
        if power.enabled & ((1 << 20) | (1 << 44)) != 0 {
            return Err(Error::PowerPolicy(power.enabled));
        }
        self.shared_range()?;
        if self.reg(DB)? & (1 << 30) != 0 {
            return Err(Error::Busy);
        }
        self.state = State::Starting;
        self.result = None;
        self.decode_result = None;
        self.memory.publish();
        let result = self
            .start_inner()
            .await
            .and_then(|()| self.access(|_, _| Ok(())));
        self.state = match result {
            Ok(()) => State::Ready,
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn start_inner(&mut self) -> Result<(), Error> {
        let map = self.memory.mapping();
        for page in (0..BYTES).step_by(4096) {
            self.access(|io, l| {
                let value = if page == 0 || page == END_GUARD {
                    GUARD
                } else {
                    0
                };
                for at in (page..page + 4096).step_by(4) {
                    io.memory_write(map, at, value);
                }
                flush(io, l)
            })?;
            self.io.delay(1).await;
        }
        self.set(DLDO_CONFIG, 3 << 4, 1 << 4)?;
        self.wait(DLDO_STATUS, 4, 0).await?;
        self.set(POWER, 1, 0)?;
        self.set(CG_GATE, u32::MAX, 0)?;
        self.set(CG_CTRL, CG_MODES, 0)?;
        let config = self.access(|io, l| checked(io.read(l.gc + 0x263e * 4)))?;
        self.set(ADDR_CONFIG, u32::MAX, config)?;
        self.set(IRQ, 0x100, 0)?;
        self.set(JMI, 1, 1)?;
        self.set(DB, 0x4ffffffc, DOORBELL << 2 | 1 << 30)?;
        self.set(VMID, u32::MAX, 0)?;
        self.set(CNTL, u32::MAX, 3)?;
        let base = self.memory.address() + RING;
        self.set(BASE_LO, u32::MAX, base as u32)?;
        self.set(BASE_HI, u32::MAX, (base >> 32) as u32)?;
        self.set(RPTR, u32::MAX, 0)?;
        self.set(WPTR, u32::MAX, 0)?;
        self.set(SIZE, u32::MAX, 1024)?;
        self.set(CNTL, u32::MAX, 2)?;
        self.set(JMI, 1, 0)?;
        self.wptr = 0;
        self.shared_range()
    }
    fn emit(&mut self, words: &[u32]) -> Result<u32, Error> {
        if !matches!(self.state, State::Testing | State::DecodeTesting)
            || words.is_empty()
            || words.len() % 2 != 0
        {
            return Err(Error::Invalid);
        }
        let count = (words.len() as u32 + 15) & !15;
        let next = self
            .wptr
            .checked_add(count)
            .filter(|n| *n < 1024)
            .ok_or(Error::Busy)?;
        self.shared_range()?;
        let map = self.memory.mapping();
        let start = self.wptr;
        self.access(|io, l| {
            for n in 0..count {
                let value = words.get(n as usize).copied().unwrap_or(if n % 2 == 0 {
                    words::NOP
                } else {
                    0
                });
                io.memory_write(map, RING + u64::from(start + n) * 4, value);
            }
            io.memory_write(map, WRITEBACK, next);
            flush(io, l)?;
            io.doorbell(DOORBELL, next);
            Ok(())
        })?;
        self.wptr = next;
        Ok(next)
    }
    async fn stop(&mut self) -> Result<(), Error> {
        if !matches!(
            self.state,
            State::Ready | State::Verified | State::DecodeVerified | State::Clients
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
            // SAFETY: JRBC drained, JMI/core reads/writes are clean with no MC
            // writes pending, then JMI reset and the JPEG doorbell were shut.
            unsafe {
                self.memory.stopped();
                if let Some(memory) = self.decode_memory.as_mut() {
                    memory.stopped();
                }
                if let Some(memory) = self.client_memory.as_mut() {
                    memory.stopped();
                }
            }
        }
        result
    }
    async fn stop_inner(&mut self) -> Result<(), Error> {
        self.shared_range()?;
        self.wait(RPTR, u32::MAX, self.wptr).await?;
        self.wait(STATUS, 1, 1).await?;
        self.wait(CLEAN, CLEAN_MASK, CLEAN_VALUE).await?;
        self.set(IRQ, 0x100, 0)?;
        self.set(JMI, 1, 1)?;
        self.wait(CLEAN, CLEAN_MASK, CLEAN_VALUE).await?;
        self.set(CNTL, 3, 3)?;
        self.set(DB, 1 << 30, 0)?;
        self.set(CG_CTRL, 1 << 16, 1 << 16)?;
        self.set(CG_GATE, CG_GATES, CG_GATES)?;
        self.set(POWER, 1, 1)?;
        self.set(DLDO_CONFIG, 3 << 4, 2 << 4)?;
        self.wait(DLDO_STATUS, 4, 4).await?;
        self.shared_range()
    }
}
impl<I: Io> Engine<I> {
    fn reserve_proofs(&mut self, decode: bool, clients: bool) -> Result<(), Error> {
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::Busy);
        }
        crate::amdgpu_media_reservation::reserve(
            &self.pool,
            [
                (&mut self.decode_memory, decode_words::BYTES, decode),
                (&mut self.client_memory, cs::CLIENT_BYTES, clients),
            ],
        )
        .map_err(|_| Error::Allocation)
    }
}
pub(crate) const fn proof_bytes(decode: bool, clients: bool) -> u64 {
    BYTES
        + if decode { decode_words::BYTES } else { 0 }
        + if clients { cs::CLIENT_BYTES } else { 0 }
}
pub struct Jpeg {
    engine: Engine<Mmio>,
}
impl core::fmt::Debug for Jpeg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Jpeg")
            .field("state", &self.engine.state)
            .field("result", &self.engine.result)
            .finish_non_exhaustive()
    }
}
impl Jpeg {
    /// Claim decode and staged-client arenas before any power/publication.
    pub(crate) fn reserve_proofs(&mut self, decode: bool, clients: bool) -> Result<(), Error> {
        self.engine.reserve_proofs(decode, clients)
    }

    /// # Safety
    /// Own this GPU's JPEG5, BAR2 slot 0x311 and backing/GMC exclusively.
    /// The retained VCN owner holds the matching NBIO media range until JPEG
    /// stops; exclude VCN power/stop and all shared register writers meanwhile.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: MmioRegion,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        if doorbells.len < (u64::from(DOORBELL) + 1) * 4 {
            return Err(Error::Invalid);
        }
        crate::amdgpu_psp_ring::navi48_layout(gpu)
            .and_then(|l| l.validate_pool(gpu, &authority, pool))
            .map_err(|e| match e {
                crate::amdgpu_psp_ring::Error::Revoked => Error::Revoked,
                crate::amdgpu_psp_ring::Error::DeviceGone => Error::DeviceGone,
                _ => Error::Invalid,
            })?;
        let memory = pool.reserve(BYTES).map_err(|_| Error::Allocation)?;
        if memory
            .address()
            .checked_add(BYTES)
            .is_none_or(|end| end > 1 << 48)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    doorbells,
                },
                authority,
                layout,
                memory,
                pool: pool.clone(),
                decode_memory: None,
                client_memory: None,
                state: State::Prepared,
                result: None,
                decode_result: None,
                seq: 0,
                wptr: 0,
            },
        })
    }
    /// # Safety
    /// A retained JPEG0 kernel-VMID0/PASID0 dispatch registration exists,
    /// SMU PowerUpJpeg completed and `new`'s exclusions stay valid. Keep the
    /// registration, this owner and shared VCN/GMC backing after cancellation.
    pub async unsafe fn start(
        &mut self,
        power: crate::amdgpu_smu_navi48::PowerStatus,
    ) -> Result<(), Error> {
        self.engine.start(power).await
    }
    /// # Safety
    /// Register JPEG0's kernel-VMID0/PASID0 owner before this call. Exclude
    /// clients and PM/reset while the independent IH worker and CPU IRQs run.
    pub async unsafe fn prove(&mut self) -> Result<Proof, Error> {
        self.engine
            .prove(&mut crate::amdgpu_navi48_interrupts::NativeObserver)
            .await
    }
    /// Decode IGT's fixed JPEG and check both active output planes.
    /// # Safety
    /// Keep the exclusive registered owner, shared range/GMC and CPU IRQs
    /// live, excluding clients/PM/reset. Retain all backing after cancellation.
    pub async unsafe fn prove_decode(&mut self) -> Result<DecodeProof, Error> {
        self.engine
            .prove_decode(&mut crate::amdgpu_navi48_interrupts::NativeObserver)
            .await
    }
    pub fn decode_result(&self) -> Option<Result<DecodeProof, Error>> {
        self.engine.decode_result
    }
    /// # Safety
    /// Exclude every publisher/PM/reset writer and retain VCN's shared range.
    /// Keep the dispatch registration until shutdown and SMU power-down finish.
    /// Only success permits PowerDownJpeg or releasing the backing allocation.
    pub async unsafe fn stop(&mut self) -> Result<(), Error> {
        self.engine.stop().await
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn result(&self) -> Option<Result<Proof, Error>> {
        self.engine.result
    }
    /// Turn the drained, verified transport into the client ring.
    /// # Safety
    /// Keep the registered JPEG0 owner, VCN's shared range and GMC live and
    /// exclude PM/reset; the client arena is retired only by a later stop.
    pub unsafe fn open_clients(&mut self) -> Result<(), Error> {
        self.engine.open_clients()
    }
    /// Copy validated client IB words into kernel `slot` and return their
    /// VMID0 addresses for [`Self::submit`].
    /// # Safety
    /// The slot's previous job completed (or a stop/reset proved retirement)
    /// and stays unused by any other job until this one completes.
    pub unsafe fn stage(
        &mut self,
        slot: usize,
        copies: &[alloc::vec::Vec<u32>],
    ) -> Result<alloc::vec::Vec<(u64, u32)>, Error> {
        self.engine.stage(slot, copies)
    }
    /// Queue a client frame whose IBs are staged kernel copies.
    /// # Safety
    /// Own the client's MMHUB VMID/PASID/root and every resource its IBs
    /// reach, plus the staged slot, until this sequence completes or reset
    /// proves retirement. Exclude ring/VMID/PM/reset writers.
    pub unsafe fn submit(&mut self, job: crate::amdgpu_gfx12_queue::Job) -> Result<u32, Error> {
        self.engine.submit(job)
    }
    /// Retire a possibly hung client ring before PowerDownJpeg.
    /// # Safety
    /// Exclude every publisher/PM writer and retain the dispatch registration,
    /// VCN's shared range and all backing through failure or cancellation.
    pub async unsafe fn reset_stop(&mut self) -> Result<(), Error> {
        self.engine.reset_stop().await
    }
    /// Retain this owner/backing and exclude reset/PM while using the reader.
    pub fn fence_reader(&self) -> Option<FenceReader> {
        (self.engine.state == State::Clients).then_some(FenceReader {
            io: self.engine.io,
            authority: self.engine.authority,
            layout: self.engine.layout,
            map: self.engine.memory.mapping(),
        })
    }
}
pub use cs::{validate_ib, SLOTS, SLOT_BYTES};
#[derive(Clone, Copy, Debug)]
pub struct FenceReader {
    io: Mmio,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    map: MmioRegion,
}
impl FenceReader {
    /// The last physical sequence the JPEG ring's GPCOM fence wrote.
    pub fn completed(&self) -> Result<u32, Error> {
        let mut io = self.io;
        cs::client_fence(&mut io, self.authority, self.layout, self.map)
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_jpeg_navi48_tests.rs"]
mod tests;
