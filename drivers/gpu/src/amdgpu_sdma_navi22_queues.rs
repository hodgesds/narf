//! Production SDMA 5.2.2 gfx queues on both Navi22 engines (`sdma_v5_2_start`,
//! `sdma_v5_2_gfx_resume_instance`, ring/IB tests, doorbells through BAR2 and
//! the NBIF SDMA doorbell ranges). Any earlier SDMA owner (the cold-boot
//! SDMA0 proof) must be idle; its ring is stopped and halted first, the way
//! `sdma_v5_2_hw_fini` quiesces before `sdma_v5_2_start` reprograms.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_cp_navi22::{
        checked, delay, doorbell, flush, pm4, regs::*, update, wait_fence, Doorbells, Error, Hw,
        Io, Kind, Layout, Mmio, Queue, IB, REG_TIMEOUT_MS, RPTR, SCRATCH, WPTR,
    },
    amdgpu_fence_navi22 as fence,
    amdgpu_vram::Pool,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Write};

/// `rb_bufsz = order_base_2(8192 / 4)`.
const RB_SIZE: u32 = 11;
/// `amdgpu_sdma_phase_quantum = 32`: VALUE 32, UNIT 0.
const PHASE_QUANTUM: u32 = 32 << 8;
const RB_ENABLE: u32 = 1;
const RPTR_WRITEBACK_ENABLE: u32 = 1 << 12;
const AUTO_CTXSW_ENABLE: u32 = 1 << 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Stopping,
    Resetting,
    Programming(u8),
    Running,
    Testing,
    Verified,
    Failed,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Proof {
    /// An earlier idle ring was stopped before reprogramming (per engine).
    pub stopped: [bool; 2],
    pub ring: [bool; 2],
    pub ib_fence: [u32; 2],
}
#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    pub hw: Hw<I>,
    pub queues: [Queue; 2],
    pub state: State,
    pub proof: Proof,
}
fn reg(l: Layout, instance: u32, r: Reg) -> u64 {
    l.sdma(instance, r)
}
impl<I: Io> Engine<I> {
    pub(crate) async fn start(&mut self) -> Result<(), Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Stopping;
        let result = self.start_inner().await;
        self.state = if result.is_ok() {
            State::Running
        } else {
            State::Failed
        };
        result
    }
    async fn start_inner(&mut self) -> Result<(), Error> {
        let [q0, q1] = &mut self.queues;
        let stopped = self.hw.access(|io, l| {
            let reset = checked(io.read(l.reg(GRBM_SOFT_RESET)))?;
            if reset & (3 << 23) != 0 {
                return Err(Error::Busy);
            }
            let mut stopped = [false; 2];
            for i in 0..2 {
                let rb = checked(io.read(reg(l, i, SDMA0_GFX_RB_CNTL)))?;
                if rb & RB_ENABLE != 0 {
                    // Only an idle predecessor ring may be taken over.
                    let rptr =
                        [SDMA0_GFX_RB_RPTR, SDMA0_GFX_RB_RPTR_HI].map(|r| io.read(reg(l, i, r)));
                    let wptr =
                        [SDMA0_GFX_RB_WPTR, SDMA0_GFX_RB_WPTR_HI].map(|r| io.read(reg(l, i, r)));
                    if rptr.contains(&u32::MAX) || rptr != wptr {
                        return Err(Error::Busy);
                    }
                    stopped[i as usize] = true;
                }
            }
            q0.clear(io);
            q1.clear(io);
            flush(io, l);
            Ok(stopped)
        })?;
        // Published before any engine is pointed at these rings.
        for q in &mut self.queues {
            q.memory.publish();
        }
        self.proof.stopped = stopped;
        self.hw.access(|io, l| {
            for i in 0..2 {
                // sdma_v5_2_ctx_switch_enable(false) + sdma_v5_2_enable(false)
                update(io, reg(l, i, SDMA0_GFX_RB_CNTL), RB_ENABLE, 0)?;
                update(io, reg(l, i, SDMA0_GFX_IB_CNTL), 1, 0)?;
                update(io, reg(l, i, SDMA0_CNTL), AUTO_CTXSW_ENABLE, 0)?;
                update(io, reg(l, i, SDMA0_F32_CNTL), 1, 1)?;
            }
            Ok(())
        })?;
        self.state = State::Resetting;
        for i in 0..2u32 {
            // sdma_v5_2_soft_reset_engine
            let bit = 1 << (23 + i);
            self.hw.access(|io, l| {
                update(io, l.reg(GRBM_SOFT_RESET), bit, bit)?;
                checked(io.read(l.reg(GRBM_SOFT_RESET)))?;
                Ok(())
            })?;
            delay(50).await;
            self.hw.access(|io, l| {
                update(io, l.reg(GRBM_SOFT_RESET), bit, 0)?;
                checked(io.read(l.reg(GRBM_SOFT_RESET)))?;
                Ok(())
            })?;
            delay(50).await;
        }
        self.hw.access(|io, l| {
            for i in 0..2 {
                update(io, reg(l, i, SDMA0_F32_CNTL), 1, 0)?; // enable(true)
            }
            for i in 0..2 {
                // ctx_switch_enable(true) with the default phase quantum
                for r in [
                    SDMA0_PHASE0_QUANTUM,
                    SDMA0_PHASE1_QUANTUM,
                    SDMA0_PHASE2_QUANTUM,
                ] {
                    io.write(reg(l, i, r), PHASE_QUANTUM);
                }
                update(
                    io,
                    reg(l, i, SDMA0_CNTL),
                    AUTO_CTXSW_ENABLE,
                    AUTO_CTXSW_ENABLE,
                )?;
            }
            Ok(())
        })?;
        for i in 0..2u32 {
            self.state = State::Programming(i as u8);
            self.resume_instance(i).await?;
            self.proof.ring[i as usize] = true;
        }
        Ok(())
    }
    /// `sdma_v5_2_gfx_resume_instance(adev, i, false)` and its ring test.
    async fn resume_instance(&mut self, i: u32) -> Result<(), Error> {
        let q = &mut self.queues[i as usize];
        let (base, rptr, wptr, index) =
            (q.address(0), q.address(RPTR), q.address(WPTR), q.doorbell);
        self.hw.access(|io, l| {
            let r = |reg_: Reg| reg(l, i, reg_);
            io.write(r(SDMA0_SEM_WAIT_FAIL_TIMER_CNTL), 0);
            let mut rb = (checked(io.read(r(SDMA0_GFX_RB_CNTL)))? & !0x3e) | (RB_SIZE << 1);
            io.write(r(SDMA0_GFX_RB_CNTL), rb);
            for x in [
                SDMA0_GFX_RB_RPTR,
                SDMA0_GFX_RB_RPTR_HI,
                SDMA0_GFX_RB_WPTR,
                SDMA0_GFX_RB_WPTR_HI,
            ] {
                io.write(r(x), 0);
            }
            io.write(r(SDMA0_GFX_RB_WPTR_POLL_ADDR_LO), wptr as u32);
            io.write(r(SDMA0_GFX_RB_WPTR_POLL_ADDR_HI), (wptr >> 32) as u32);
            update(io, r(SDMA0_GFX_RB_WPTR_POLL_CNTL), 4, 4)?; // F32_POLL_ENABLE
            io.write(r(SDMA0_GFX_RB_RPTR_ADDR_HI), (rptr >> 32) as u32);
            io.write(r(SDMA0_GFX_RB_RPTR_ADDR_LO), rptr as u32 & !3);
            rb |= RPTR_WRITEBACK_ENABLE;
            io.write(r(SDMA0_GFX_RB_BASE), (base >> 8) as u32);
            io.write(r(SDMA0_GFX_RB_BASE_HI), (base >> 40) as u32);
            io.write(r(SDMA0_GFX_MINOR_PTR_UPDATE), 1);
            io.write(r(SDMA0_GFX_RB_WPTR), 0);
            io.write(r(SDMA0_GFX_RB_WPTR_HI), 0);
            update(io, r(SDMA0_GFX_DOORBELL), 1 << 28, 1 << 28)?;
            update(io, r(SDMA0_GFX_DOORBELL_OFFSET), 0x0fff_fffc, index << 2)?;
            // nbio_v2_3_sdma_doorbell_range: OFFSET[11:2], SIZE[20:16]
            let range = l.nbio([NBIO_SDMA0_DOORBELL_RANGE, NBIO_SDMA1_DOORBELL_RANGE][i as usize]);
            update(
                io,
                range,
                0x001f_0ffc,
                ((index << 2) & 0xffc) | (doorbell::SDMA_RANGE << 16),
            )?;
            io.write(r(SDMA0_GFX_MINOR_PTR_UPDATE), 0);
            update(io, r(SDMA0_CNTL), 0x22, 0x22)?; // UTC_L1_ENABLE | MIDCMD_PREEMPT
            update(io, r(SDMA0_UTCL1_CNTL), 0xe3e, (3 << 9) | (9 << 1))?;
            // CACHE_READ_POLICY_L2__DEFAULT (2) << 12, WRITE (3) << 14, LLC_NOALLOC
            let page = checked(io.read(r(SDMA0_UTCL1_PAGE)))? & 0xff0fff;
            io.write(r(SDMA0_UTCL1_PAGE), page | 0x2000 | 0xc000 | (1 << 24));
            update(io, r(SDMA0_F32_CNTL), 1, 0)?;
            io.write(r(SDMA0_GFX_RB_CNTL), rb | RB_ENABLE);
            update(io, r(SDMA0_GFX_IB_CNTL), 1, 1)?;
            Ok(())
        })?;
        // sdma_v5_2_ring_test_ring: WRITE_LINEAR into writeback memory.
        let q = &mut self.queues[i as usize];
        let target = q.address(SCRATCH);
        self.hw.access(|io, l| {
            q.write(io, SCRATCH, &[0xcafe_dead]);
            q.emit(io, &pm4::sdma_write(target, 0xdead_beef))?;
            q.commit(io, l);
            Ok(())
        })?;
        let q = &self.queues[i as usize];
        self.hw
            .poll(q.engine, REG_TIMEOUT_MS, |io, l| {
                Ok((q.read(io, l, SCRATCH) == 0xdead_beef).then_some(()))
            })
            .await
    }
    /// `sdma_v5_2_ring_test_ib` on both engines.
    pub(crate) async fn test_ib(&mut self) -> Result<(), Error> {
        if self.state != State::Running {
            return Err(Error::Busy);
        }
        self.state = State::Testing;
        let mut result = Ok(());
        for i in 0..2 {
            result = self.test_ib_instance(i).await;
            if result.is_err() {
                break;
            }
        }
        self.state = if result.is_ok() {
            State::Verified
        } else {
            State::Failed
        };
        result
    }
    async fn test_ib_instance(&mut self, i: usize) -> Result<(), Error> {
        let q = &mut self.queues[i];
        let seq = q.next_seq();
        let (target, ib, fence) = (
            q.address(SCRATCH),
            q.address(IB),
            q.address(crate::amdgpu_cp_navi22::FENCE),
        );
        self.hw.access(|io, l| {
            q.write(io, SCRATCH, &[0xcafe_dead]);
            q.write(io, IB, &pm4::sdma_write(target, 0xdead_beef));
            q.write(io, IB + 20, &[pm4::SDMA_NOP; 3]);
            // The 6-dword INDIRECT packet must end on an 8-dword boundary.
            let pad = (2u64.wrapping_sub(q.wptr)) & 7;
            for _ in 0..pad {
                q.emit(io, &[pm4::SDMA_NOP])?;
            }
            q.emit(io, &pm4::sdma_indirect(ib, 8))?;
            q.emit(io, &pm4::sdma_fence(fence, seq))?;
            q.commit(io, l);
            Ok(())
        })?;
        let q = &self.queues[i];
        wait_fence(&mut self.hw, q, seq).await?;
        self.hw.access(|io, l| match q.read(io, l, SCRATCH) {
            0xdead_beef => Ok(()),
            _ => Err(Error::DataMismatch),
        })?;
        self.proof.ib_fence[i] = seq;
        Ok(())
    }
}

/// Owner of the SDMA0 and SDMA1 gfx kernel queues.
#[derive(Debug)]
pub struct Sdma {
    engine: Engine<Mmio>,
}
impl Sdma {
    /// Reserve both rings without device I/O.
    ///
    /// # Safety
    /// Caller exclusively owns both SDMA engines, GRBM soft reset, HDP, the
    /// NBIF SDMA doorbell ranges, BAR2 doorbells and the permanent VRAM pool.
    /// Any earlier SDMA owner must stay alive (its memory remains published).
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: Doorbells,
    ) -> Result<Self, Error> {
        Ok(Self {
            engine: Engine {
                hw: Hw {
                    layout: Layout::resolve(gpu)?,
                    io: Mmio::new(gpu, doorbells),
                    authority,
                },
                queues: [
                    Queue::new(pool, Kind::Sdma, doorbell::SDMA0, fence::Engine::Sdma0)?,
                    Queue::new(pool, Kind::Sdma, doorbell::SDMA1, fence::Engine::Sdma1)?,
                ],
                state: State::Prepared,
                proof: Proof::default(),
            },
        })
    }
    /// # Safety
    /// Firmware is loaded, VMID0 is ready, gating is disabled, doorbell
    /// apertures are enabled and no SDMA work is outstanding.
    pub async unsafe fn start(&mut self) -> Result<(), Error> {
        self.engine.start().await
    }
    pub async fn test_ib(&mut self) -> Result<(), Error> {
        self.engine.test_ib().await
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// Client IBs on SDMA `instance` (0 or 1); see `Gfx::submit`.
    pub fn submit(
        &mut self,
        instance: u8,
        state: &mut crate::amdgpu_navi22_submit::RingState,
        vm: crate::amdgpu_navi22_submit::VmRef,
        context: u64,
        ibs: &[crate::amdgpu_navi22_submit::Ib],
    ) -> Result<u32, Error> {
        if self.engine.state != State::Verified || instance > 1 {
            return Err(Error::Busy);
        }
        let e = &mut self.engine;
        crate::amdgpu_navi22_submit::submit(
            &mut e.hw,
            &mut e.queues[usize::from(instance)],
            state,
            crate::amdgpu_navi22_submit::Ring::Sdma(instance),
            vm,
            context,
            ibs,
        )
    }
    /// See `Gfx::fences`.
    pub fn fences(&mut self, instance: u8) -> Result<(u32, u32), Error> {
        let e = &mut self.engine;
        let q = e.queues.get(usize::from(instance)).ok_or(Error::Invalid)?;
        Ok((
            crate::amdgpu_navi22_submit::completed(&mut e.hw, q)?,
            crate::amdgpu_navi22_submit::throttle_seq(q),
        ))
    }
    pub fn proof(&self) -> Proof {
        self.engine.proof
    }
    /// Fence progress of both engines (hang detection only).
    pub(crate) fn progress(&mut self) -> Result<[crate::amdgpu_navi22_tdr::Progress; 2], Error> {
        if self.engine.state != State::Verified {
            return Err(Error::Busy);
        }
        let e = &mut self.engine;
        Ok([
            crate::amdgpu_cp_navi22::progress(&mut e.hw, &e.queues[0])?,
            crate::amdgpu_cp_navi22::progress(&mut e.hw, &e.queues[1])?,
        ])
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_sdma_navi22_queues_tests.rs"]
mod tests;
