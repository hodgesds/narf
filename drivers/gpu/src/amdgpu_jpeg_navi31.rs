// SPDX-License-Identifier: GPL-2.0-or-later
// Static-power sequence adapted from Linux jpeg_v4_0.c:
// Copyright 2023 Advanced Micro Devices, Inc. Full notice: ../JPEG-NOTICES.
//! JPEG 4.0 JRBC owner for Navi31.
//!
//! Grounded in Linux 7.4-rc2 `jpeg_v4_0.c` / `vcn_4_0_0_offset.h` /
//! `vcn_4_0_0_sh_mask.h`. The VCN owner retains the shared NBIO media range
//! throughout this owner's lifetime; JPEG never programs or disables that
//! shared range — it verifies the range is programmed before start. The
//! caller issues SMU 13.0.0 PowerUpJpeg (0x2C) before `start` and
//! PowerDownJpeg (0x2D) after `stop`; this owner never sends SMU messages.
//!
//! The fence proof is a ring-advance proof (NOP words + RPTR poll). The
//! PACKETJ fence program (`jpeg_v2_0_dec_ring_emit_fence`, shared by v4.0)
//! is a remainder: its `_INTERNAL_OFFSET` register constants were not
//! grounded in this lane's ref-tree pass, and are flagged, not invented.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::bank,
    amdgpu_vcn_navi31::{Io, Mmio},
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

// vcn_4_0_0_offset.h: JPEG registers live in the VCN bank (there is no
// separate JPEG HWIP in NARF's discovery model).
mod regs {
    pub const PGFSM_CONFIG: u32 = 0x0000; // regUVD_PGFSM_CONFIG (UVDJ field)
    pub const PGFSM_STATUS: u32 = 0x0001; // regUVD_PGFSM_STATUS
    pub const JPEG_POWER_STATUS: u32 = 0x0003; // regUVD_JPEG_POWER_STATUS
    pub const DB_CTRL: u32 = 0x0071; // regVCN_JPEG_DB_CTRL
    pub const ADDR_CONFIG: u32 = 0x05e6; // regJPEG_DEC_GFX10_ADDR_CONFIG
    pub const WPTR: u32 = 0x0640; // regUVD_JRBC_RB_WPTR
    pub const CNTL: u32 = 0x0641; // regUVD_JRBC_RB_CNTL
    pub const RPTR: u32 = 0x064a; // regUVD_JRBC_RB_RPTR
    pub const SIZE: u32 = 0x0653; // regUVD_JRBC_RB_SIZE
    pub const VMID: u32 = 0x0690; // regUVD_LMI_JRBC_RB_VMID
    pub const BASE_LO: u32 = 0x06a6; // regUVD_LMI_JRBC_RB_64BIT_BAR_LOW
    pub const BASE_HI: u32 = 0x06a7; // regUVD_LMI_JRBC_RB_64BIT_BAR_HIGH
    pub const JMI: u32 = 0x06d2; // regUVD_JMI_CNTL
    pub const SYS_INT_EN: u32 = 0x0701; // regJPEG_SYS_INT_EN
    pub const CGC_GATE: u32 = 0x0720; // regJPEG_CGC_GATE
    pub const CGC_CTRL: u32 = 0x0721; // regJPEG_CGC_CTRL
}
use regs::*;

const JMI_SOFT_RESET: u32 = 0x1;
const SYS_INT_DJRBC: u32 = 0x2;
const CGC_GATE_ALL: u32 = 0x1b; // JPEG_DEC|JPEG2_DEC|JMCIF|JRBBM
const CGC_CTRL_TIMERS: u32 = 0x82; // (1<<CLK_GATE_DLY_TIMER shift 1)|(4<<CLK_OFF_DELAY shift 5)
const CGC_CTRL_DYN: u32 = 0x1;
const CGC_CTRL_DEC_MODE: u32 = 0x10000;
const CGC_CTRL_DLY_TIMER_MASK: u32 = 0x1e; // JPEG_CGC_CTRL__CLK_GATE_DLY_TIMER_MASK
const CGC_CTRL_OFF_DELAY_MASK: u32 = 0x1fe0; // JPEG_CGC_CTRL__CLK_OFF_DELAY_MASK
const PGFSM_UVDJ_SHIFT: u32 = 0x16;
const PGFSM_UVDJ_MASK: u32 = 0x00c0_0000;
const JPEG_POWER_MASK: u32 = 0x1;
const JPEG_PG_MODE: u32 = 0x10;

const RING: u64 = 4096;
const FENCE: u64 = 8192;
const WRITEBACK: u64 = FENCE + 8;
const BYTES: u64 = 12288;
/// Linux `jpeg_v4_0_sw_init`: 512 dwords, doorbell index
/// `(vcn_ring0_1 << 1) + 1` (non-SRIOV).
const RING_SIZE_DW: u32 = 512;
const DOORBELL: u32 = 0x311;
/// The VCN owner programs this NBIO range (nbio_v7_0, bank 2,
/// `mmBIF_MMSCH0_DOORBELL_RANGE`); JPEG verifies it.
const NBIO_RANGE: u32 = 0x01d3;
const NBIO_RANGE_VALUE: u32 = (0x310 << 2) | (8 << 16);
const NBIO_RANGE_MASK: u32 = 0x1f0ffc;
/// PACKETJ NOP, as in the Navi48 JPEG words module (version-agnostic ring
/// packet encoding, shared since JPEG 2.0).
const NOP: u32 = 0x6000_0000;

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
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Starting,
    Ready,
    Testing,
    Verified,
    Stopping,
    Stopped,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub sequence: u32,
    pub read_pointer: u32,
}

/// VCN 4.0 versions this owner drives: (4,0,0) Navi31/32, (4,0,4) Navi33.
const VCN_VERSIONS: [(u8, u8, u8); 2] = [(4, 0, 0), (4, 0, 4)];
/// GC versions on Navi3x (`gfx_v11_0.c`; `regGB_ADDR_CONFIG` 0x13de comes
/// from the single `gc_11_0_0_offset.h` include, which covers all 11.0.x).
const GC_VERSIONS: [(u8, u8, u8); 3] = [(11, 0, 0), (11, 0, 2), (11, 0, 3)];
/// NBIF versions carrying `vcn_doorbell_range` (nbio_v7_0).
const NBIO_VERSIONS: [(u8, u8, u8); 2] = [(7, 0, 0), (7, 0, 1)];

#[derive(Clone, Copy, Debug)]
struct Layout {
    vcn: u64,
    nbio: u64,
    gc: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            vcn: bank(gpu, ip::HW_ID_VCN, &VCN_VERSIONS, 1, CGC_CTRL)
                .map_err(|_| Error::Unsupported)?,
            nbio: bank(gpu, ip::HW_ID_NBIF, &NBIO_VERSIONS, 2, NBIO_RANGE)
                .map_err(|_| Error::Unsupported)?,
            gc: bank(gpu, ip::HW_ID_GC, &GC_VERSIONS, 0, 0x13de).map_err(|_| Error::Unsupported)?,
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
    checked(io.read(l.nbio + u64::from(NBIO_RANGE) * 4))?;
    fence(Ordering::SeqCst);
    Ok(())
}
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    /// Device's `AMD_PG_SUPPORT_JPEG` flag (bringup input).
    pg: bool,
    /// Device's `AMD_CG_SUPPORT_JPEG_MGCG` flag (bringup input).
    mgcg: bool,
    state: State,
    addr_config: Option<u32>,
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
    async fn wait(&mut self, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
        for _ in 0..2000 {
            if self.reg(reg)? & mask == value {
                return Ok(());
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
    /// The VCN owner programs the shared NBIO media range; JPEG verifies it
    /// is programmed and never changes it.
    fn shared_range(&mut self) -> Result<(), Error> {
        self.access(|io, l| {
            if checked(io.read(l.nbio + u64::from(NBIO_RANGE) * 4))? & NBIO_RANGE_MASK
                != NBIO_RANGE_VALUE
            {
                return Err(Error::Busy);
            }
            Ok(())
        })
    }
    /// `jpeg_v4_0_disable_static_power_gating`.
    async fn disable_static_power_gating(&mut self) -> Result<(), Error> {
        if self.pg {
            self.set(PGFSM_CONFIG, u32::MAX, 1 << PGFSM_UVDJ_SHIFT)?;
            // UVD_PGFSM_STATUS_UVDJ_PWR_ON is 0.
            self.wait(PGFSM_STATUS, PGFSM_UVDJ_MASK, 0).await?;
        }
        // Disable anti-hang mechanism; keep JPEG in static PG mode.
        self.set(JPEG_POWER_STATUS, JPEG_POWER_MASK, 0)?;
        self.set(JPEG_POWER_STATUS, JPEG_PG_MODE, 0)?;
        Ok(())
    }
    /// `jpeg_v4_0_enable_static_power_gating`.
    async fn enable_static_power_gating(&mut self) -> Result<(), Error> {
        // Enable anti-hang mechanism.
        self.set(JPEG_POWER_STATUS, JPEG_POWER_MASK, JPEG_POWER_MASK)?;
        if self.pg {
            self.set(PGFSM_CONFIG, u32::MAX, 2 << PGFSM_UVDJ_SHIFT)?;
            self.wait(PGFSM_STATUS, PGFSM_UVDJ_MASK, 2 << PGFSM_UVDJ_SHIFT)
                .await?;
        }
        Ok(())
    }
    /// `jpeg_v4_0_disable_clock_gating`.
    fn disable_clock_gating(&mut self) -> Result<(), Error> {
        if self.mgcg {
            self.set(
                CGC_CTRL,
                CGC_CTRL_DYN
                    | CGC_CTRL_DLY_TIMER_MASK
                    | CGC_CTRL_OFF_DELAY_MASK
                    | CGC_CTRL_DEC_MODE,
                CGC_CTRL_TIMERS | CGC_CTRL_DYN,
            )?;
        } else {
            self.set(
                CGC_CTRL,
                CGC_CTRL_DLY_TIMER_MASK | CGC_CTRL_OFF_DELAY_MASK,
                CGC_CTRL_TIMERS,
            )?;
        }
        self.set(CGC_GATE, CGC_GATE_ALL, 0)?;
        Ok(())
    }
    /// `jpeg_v4_0_enable_clock_gating`.
    fn enable_clock_gating(&mut self) -> Result<(), Error> {
        if self.mgcg {
            self.set(
                CGC_CTRL,
                CGC_CTRL_DYN
                    | CGC_CTRL_DLY_TIMER_MASK
                    | CGC_CTRL_OFF_DELAY_MASK
                    | CGC_CTRL_DEC_MODE,
                CGC_CTRL_TIMERS | CGC_CTRL_DYN | CGC_CTRL_DEC_MODE,
            )?;
        } else {
            self.set(
                CGC_CTRL,
                CGC_CTRL_DLY_TIMER_MASK | CGC_CTRL_OFF_DELAY_MASK,
                CGC_CTRL_TIMERS,
            )?;
        }
        self.set(CGC_GATE, CGC_GATE_ALL, CGC_GATE_ALL)?;
        Ok(())
    }
    async fn start(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::Busy);
        }
        self.shared_range()?;
        if self.reg(DB_CTRL)? & (1 << 30) != 0 {
            return Err(Error::Busy);
        }
        self.state = State::Starting;
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
    /// `jpeg_v4_0_start`, with the doorbell control from `jpeg_v4_0_hw_init`
    /// folded in (Linux programs it in hw_init, before start).
    async fn start_inner(&mut self) -> Result<(), Error> {
        let map = self.memory.mapping();
        for page in (0..BYTES).step_by(4096) {
            self.access(|io, l| {
                for at in (page..page + 4096).step_by(4) {
                    io.memory_write(map, at, 0);
                }
                flush(io, l)
            })?;
            self.io.delay(1).await;
        }
        // Doorbell control (hw_init): doorbell_index 0x311.
        self.set(DB_CTRL, 0x4fff_fffc, DOORBELL << 2 | 1 << 30)?;
        self.disable_static_power_gating().await?;
        self.disable_clock_gating()?;
        let addr_config = {
            let value = self.access(|io, l| checked(io.read(l.gc + 0x13de * 4)))?;
            self.addr_config = Some(value);
            value
        };
        self.set(ADDR_CONFIG, u32::MAX, addr_config)?;
        // Enable JMI channel.
        self.set(JMI, JMI_SOFT_RESET, 0)?;
        // Enable System Interrupt for JRBC.
        self.set(SYS_INT_EN, SYS_INT_DJRBC, SYS_INT_DJRBC)?;
        self.set(VMID, u32::MAX, 0)?;
        self.set(CNTL, u32::MAX, 0x3)?;
        let base = self.memory.address() + RING;
        self.set(BASE_LO, u32::MAX, base as u32)?;
        self.set(BASE_HI, u32::MAX, (base >> 32) as u32)?;
        self.set(RPTR, u32::MAX, 0)?;
        self.set(WPTR, u32::MAX, 0)?;
        self.set(CNTL, u32::MAX, 0x2)?;
        self.set(SIZE, u32::MAX, RING_SIZE_DW)?;
        self.wptr = 0;
        self.shared_range()
    }
    fn emit(&mut self, words: &[u32]) -> Result<u32, Error> {
        if !matches!(self.state, State::Testing) || words.is_empty() || words.len() % 2 != 0 {
            return Err(Error::Invalid);
        }
        let count = (words.len() as u32 + 15) & !15;
        let next = self
            .wptr
            .checked_add(count)
            .filter(|n| *n < 512)
            .ok_or(Error::Busy)?;
        self.shared_range()?;
        let map = self.memory.mapping();
        let start = self.wptr;
        self.access(|io, l| {
            for n in 0..count {
                let value = words.get(n as usize).copied().unwrap_or(NOP);
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
    /// Ring-advance proof: NOP words through the JRBC ring, polled to RPTR.
    /// This proves ring transport, not JPEG decode or the PACKETJ fence
    /// (see the module header).
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
        result
    }
    async fn prove_inner(&mut self) -> Result<Proof, Error> {
        self.seq = self.seq.wrapping_add(1).max(1);
        let seq = self.seq;
        let next = self.emit(&[NOP; 16])?;
        for _ in 0..2000 {
            let pointer = self.reg(RPTR)?;
            if pointer > next {
                return Err(Error::Readback);
            }
            if pointer == next {
                return Ok(Proof {
                    sequence: seq,
                    read_pointer: pointer,
                });
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
    async fn stop(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Ready | State::Verified) {
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
            // SAFETY: JRBC drained, then JMI reset and the JPEG doorbell
            // were shut.
            unsafe {
                self.memory.stopped();
            }
        }
        result
    }
    /// `jpeg_v4_0_stop`, preceded by the NARF-owner drain check (RPTR must
    /// have caught the writer before the JMI reset).
    async fn stop_inner(&mut self) -> Result<(), Error> {
        self.wait(RPTR, u32::MAX, self.wptr).await?;
        // Reset JMI.
        self.set(JMI, JMI_SOFT_RESET, JMI_SOFT_RESET)?;
        self.enable_clock_gating()?;
        self.enable_static_power_gating().await?;
        Ok(())
    }
}
pub struct Jpeg {
    engine: Engine<Mmio>,
}
impl core::fmt::Debug for Jpeg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Jpeg")
            .field("state", &self.engine.state)
            .finish_non_exhaustive()
    }
}
impl Jpeg {
    /// # Safety
    /// Own this physical Navi31/32/33's JPEG block, the VCN bank's JPEG
    /// registers and the BAR2 doorbell exclusively, with the VCN owner
    /// retaining the shared NBIO media range. The permanent pool matches
    /// its boot inventory. `pg` is the device's `AMD_PG_SUPPORT_JPEG`
    /// flag; `mgcg` is `AMD_CG_SUPPORT_JPEG_MGCG`.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: MmioRegion,
        pg: bool,
        mgcg: bool,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        if doorbells.len < (u64::from(DOORBELL) + 1) * 4 {
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
                memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
                pg,
                mgcg,
                state: State::Prepared,
                addr_config: None,
                seq: 0,
                wptr: 0,
            },
        })
    }
    /// # Safety
    /// `new`'s exclusions hold; SMU 13.0.0 PowerUpJpeg has completed and
    /// the VCN owner has programmed the shared NBIO media range. Keep this
    /// owner after error/cancellation until reset.
    pub async unsafe fn start(&mut self) -> Result<(), Error> {
        self.engine.start().await
    }
    /// Prove JRBC ring transport (NOP advance + RPTR poll).
    /// # Safety
    /// Keep `start`'s exclusions and every memory owner alive.
    pub async unsafe fn prove(&mut self) -> Result<Proof, Error> {
        self.engine.prove().await
    }
    /// Stop the JRBC and retire the ring. The caller issues SMU 13.0.0
    /// PowerDownJpeg after this returns.
    /// # Safety
    /// Keep `start`'s exclusions; every client job is retired.
    pub async unsafe fn stop(&mut self) -> Result<(), Error> {
        self.engine.stop().await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_jpeg_navi31_tests.rs"]
mod tests;
