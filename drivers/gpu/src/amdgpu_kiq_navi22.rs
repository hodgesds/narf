//! Navi22 KIQ and one kernel compute queue (MEC1 pipe 0 queue 0), mapped
//! through the KIQ with `SET_RESOURCES` + `MAP_QUEUES` exactly as Linux does
//! without MES. Sources: gfx_v10_0.c (`kiq_setting`, `compute_mqd_init`,
//! `kiq_init_register`, `kiq_init_queue`, `kcq_init_queue`, `cp_compute_enable`),
//! amdgpu_gfx.c (`amdgpu_gfx_enable_kcq`, `amdgpu_gfx_kiq_acquire`) and
//! v10_structs.h (`struct v10_compute_mqd`). VMID0 only.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_cp_navi22::{
        checked, delay, doorbell, flush, grbm_select, ib_test, pm4, regs::*, ring_test, update,
        Doorbells, Error, Hw, Io, Kind, Layout, Mmio, Queue, EOP, MQD, REG_TIMEOUT_MS, RING_BYTES,
        RPTR, WPTR,
    },
    amdgpu_fence_navi22 as fence,
    amdgpu_vram::Pool,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Write};

/// `amdgpu_gfx_kiq_acquire` on GC 10.3 (2 MEC x 4 pipes x 4 queues): the
/// highest free queue-0 slot not on MEC2 pipes 2/3 is MEC2 pipe 1 queue 0.
pub const KIQ_QUEUE: (u32, u32, u32) = (2, 1, 0);
/// Single kernel compute ring: `compute_ring[0]` at MEC1 pipe 0 queue 0.
pub const COMPUTE_QUEUE: (u32, u32, u32) = (1, 0, 0);

/// `struct v10_compute_mqd` dword indices (v10_structs.h, 512 dwords).
pub(crate) mod mqd {
    pub const HEADER: usize = 0;
    pub const PIPELINESTAT_ENABLE: usize = 11;
    pub const STATIC_THREAD_MGMT: [usize; 4] = [23, 24, 26, 27];
    pub const MISC_RESERVED: usize = 32;
    pub const MQD_BASE_ADDR_LO: usize = 128;
    pub const MQD_BASE_ADDR_HI: usize = 129;
    pub const HQD_ACTIVE: usize = 130;
    pub const HQD_VMID: usize = 131;
    pub const PERSISTENT_STATE: usize = 132;
    pub const PIPE_PRIORITY: usize = 133;
    pub const QUEUE_PRIORITY: usize = 134;
    pub const PQ_BASE_LO: usize = 136;
    pub const PQ_BASE_HI: usize = 137;
    pub const PQ_RPTR: usize = 138;
    pub const RPTR_REPORT_LO: usize = 139;
    pub const RPTR_REPORT_HI: usize = 140;
    pub const WPTR_POLL_LO: usize = 141;
    pub const WPTR_POLL_HI: usize = 142;
    pub const PQ_DOORBELL_CONTROL: usize = 143;
    pub const PQ_CONTROL: usize = 145;
    pub const IB_CONTROL: usize = 149;
    pub const DEQUEUE_REQUEST: usize = 152;
    pub const MQD_CONTROL: usize = 162;
    pub const EOP_BASE_LO: usize = 165;
    pub const EOP_BASE_HI: usize = 166;
    pub const EOP_CONTROL: usize = 167;
    pub const PQ_WPTR_LO: usize = 182;
    pub const PQ_WPTR_HI: usize = 183;
    pub const DWORDS: usize = 512;
}

/// `gfx_v10_0_compute_mqd_init` for a kernel queue at the selected HQD.
/// Register reads must run with GRBM selecting that queue.
pub(crate) fn compute_mqd<I: Io>(
    io: &mut I,
    l: Layout,
    queue: &Queue,
    active: bool,
) -> Result<[u32; mqd::DWORDS], Error> {
    let mut m = [0u32; mqd::DWORDS];
    let read = |io: &mut I, r| checked(io.read(l.reg(r)));
    m[mqd::HEADER] = 0xc031_0800;
    m[mqd::PIPELINESTAT_ENABLE] = 1;
    for i in mqd::STATIC_THREAD_MGMT {
        m[i] = u32::MAX;
    }
    m[mqd::MISC_RESERVED] = 3;
    let eop = queue.address(EOP) >> 8;
    m[mqd::EOP_BASE_LO] = eop as u32;
    m[mqd::EOP_BASE_HI] = (eop >> 32) as u32;
    // EOP_SIZE = order_base_2(GFX10_MEC_HPD_SIZE / 4) - 1
    m[mqd::EOP_CONTROL] = (read(io, CP_HQD_EOP_CONTROL)? & !0x3f) | 8;
    m[mqd::PQ_DOORBELL_CONTROL] =
        (read(io, CP_HQD_PQ_DOORBELL_CONTROL)? & !0xdfff_fffc) | (queue.doorbell << 2) | (1 << 30);
    let address = queue.address(MQD);
    m[mqd::MQD_BASE_ADDR_LO] = address as u32 & !3;
    m[mqd::MQD_BASE_ADDR_HI] = (address >> 32) as u32;
    m[mqd::MQD_CONTROL] = read(io, CP_MQD_CONTROL)? & !0xf;
    let pq = queue.address(0) >> 8;
    m[mqd::PQ_BASE_LO] = pq as u32;
    m[mqd::PQ_BASE_HI] = (pq >> 32) as u32;
    // QUEUE_SIZE = order_base_2(8192 / 4) - 1, RPTR_BLOCK_SIZE = 9 (4 KiB),
    // UNORD_DISPATCH, PRIV_STATE, KMD_QUEUE; no tunneling (one compute ring).
    m[mqd::PQ_CONTROL] = (read(io, CP_HQD_PQ_CONTROL)? & !0xf000_3f3f)
        | 10
        | (9 << 8)
        | (1 << 28)
        | (1 << 30)
        | (1 << 31);
    let rptr = queue.address(RPTR);
    m[mqd::RPTR_REPORT_LO] = rptr as u32 & !3;
    m[mqd::RPTR_REPORT_HI] = (rptr >> 32) as u32 & 0xffff;
    let wptr = queue.address(WPTR);
    m[mqd::WPTR_POLL_LO] = wptr as u32 & !3;
    m[mqd::WPTR_POLL_HI] = (wptr >> 32) as u32 & 0xffff;
    m[mqd::PQ_RPTR] = read(io, CP_HQD_PQ_RPTR)?;
    m[mqd::PERSISTENT_STATE] = (read(io, CP_HQD_PERSISTENT_STATE)? & !0x3ff00) | (0x53 << 8);
    m[mqd::IB_CONTROL] = (read(io, CP_HQD_IB_CONTROL)? & !0x30_0000) | (3 << 20);
    // Static priority of a normal-priority kernel compute ring.
    m[mqd::PIPE_PRIORITY] = 0;
    m[mqd::QUEUE_PRIORITY] = 0;
    m[mqd::HQD_ACTIVE] = u32::from(active);
    Ok(m)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    KiqProgramming,
    KiqReady,
    Mapping,
    Mapped,
    Testing,
    Verified,
    Failed,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Proof {
    /// An inherited active KIQ HQD had to be dequeued first.
    pub dequeued: bool,
    /// KIQ ring test after MAP_QUEUES and compute ring test both passed.
    pub kiq_ring: bool,
    pub compute_ring: bool,
    pub ib_fence: u32,
}
#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    pub hw: Hw<I>,
    pub kiq: Queue,
    pub compute: Queue,
    pub state: State,
    pub proof: Proof,
}
impl<I: Io> Engine<I> {
    fn begin(&mut self, from: State, busy: State) -> Result<(), Error> {
        if self.state != from {
            return Err(Error::Busy);
        }
        self.state = busy;
        Ok(())
    }
    fn finish(&mut self, result: Result<(), Error>, done: State) -> Result<(), Error> {
        self.state = if result.is_ok() { done } else { State::Failed };
        result
    }
    /// `gfx_v10_0_kiq_resume`.
    pub(crate) async fn init_kiq(&mut self) -> Result<(), Error> {
        self.begin(State::Prepared, State::KiqProgramming)?;
        let result = self.init_kiq_inner().await;
        self.finish(result, State::KiqReady)
    }
    async fn init_kiq_inner(&mut self) -> Result<(), Error> {
        let (me, pipe, queue) = KIQ_QUEUE;
        let kiq = &mut self.kiq;
        let compute = &mut self.compute;
        let (m, active) = self.hw.access(|io, l| {
            kiq.clear(io);
            compute.clear(io);
            flush(io, l);
            // gfx_v10_0_kiq_setting: tell the RLC which queue is the KIQ.
            let old = checked(io.read(l.reg(RLC_CP_SCHEDULERS)))? & 0xffff_ff00;
            let id = (me << 5) | (pipe << 3) | queue;
            io.write(l.reg(RLC_CP_SCHEDULERS), old | id);
            io.write(l.reg(RLC_CP_SCHEDULERS), old | id | 0x80);
            grbm_select(io, l, me, pipe, queue, 0);
            let m = compute_mqd(io, l, kiq, true)?;
            for (i, &word) in m.iter().enumerate() {
                io.write_memory(kiq.map(), MQD + i as u64 * 4, word);
            }
            flush(io, l);
            // gfx_v10_0_kiq_init_register
            update(io, l.reg(CP_PQ_WPTR_POLL_CNTL), 1 << 31, 0)?;
            let active = checked(io.read(l.reg(CP_HQD_ACTIVE)))? & 1 != 0;
            if active {
                io.write(l.reg(CP_HQD_DEQUEUE_REQUEST), 1);
            }
            Ok((m, active))
        })?;
        // Published before the MEC can see the MQD/ring/EOP addresses.
        self.kiq.memory.publish();
        self.compute.memory.publish();
        if active {
            let waited = self
                .hw
                .poll(fence::Engine::Kiq, REG_TIMEOUT_MS, |io, l| {
                    Ok((checked(io.read(l.reg(CP_HQD_ACTIVE)))? & 1 == 0).then_some(()))
                })
                .await;
            // Linux continues after a dequeue timeout; reprogramming a live
            // HQD is unsafe, so this owner stops instead.
            if let Err(error) = waited {
                let _ = self.hw.access(|io, l| {
                    grbm_select(io, l, 0, 0, 0, 0);
                    Ok(())
                });
                return Err(error);
            }
            self.proof.dequeued = true;
        }
        self.hw.access(|io, l| {
            let w = |io: &mut I, r, v| io.write(l.reg(r), v);
            if active {
                w(io, CP_HQD_DEQUEUE_REQUEST, m[mqd::DEQUEUE_REQUEST]);
                w(io, CP_HQD_PQ_RPTR, m[mqd::PQ_RPTR]);
                w(io, CP_HQD_PQ_WPTR_LO, m[mqd::PQ_WPTR_LO]);
                w(io, CP_HQD_PQ_WPTR_HI, m[mqd::PQ_WPTR_HI]);
            }
            w(io, CP_HQD_PQ_DOORBELL_CONTROL, 0);
            w(io, CP_HQD_EOP_BASE_ADDR, m[mqd::EOP_BASE_LO]);
            w(io, CP_HQD_EOP_BASE_ADDR_HI, m[mqd::EOP_BASE_HI]);
            w(io, CP_HQD_EOP_CONTROL, m[mqd::EOP_CONTROL]);
            w(io, CP_MQD_BASE_ADDR, m[mqd::MQD_BASE_ADDR_LO]);
            w(io, CP_MQD_BASE_ADDR_HI, m[mqd::MQD_BASE_ADDR_HI]);
            w(io, CP_MQD_CONTROL, m[mqd::MQD_CONTROL]);
            w(io, CP_HQD_PQ_BASE, m[mqd::PQ_BASE_LO]);
            w(io, CP_HQD_PQ_BASE_HI, m[mqd::PQ_BASE_HI]);
            w(io, CP_HQD_PQ_CONTROL, m[mqd::PQ_CONTROL]);
            w(io, CP_HQD_PQ_RPTR_REPORT_ADDR, m[mqd::RPTR_REPORT_LO]);
            w(io, CP_HQD_PQ_RPTR_REPORT_ADDR_HI, m[mqd::RPTR_REPORT_HI]);
            w(io, CP_HQD_PQ_WPTR_POLL_ADDR, m[mqd::WPTR_POLL_LO]);
            w(io, CP_HQD_PQ_WPTR_POLL_ADDR_HI, m[mqd::WPTR_POLL_HI]);
            w(io, CP_MEC_DOORBELL_RANGE_LOWER, (doorbell::KIQ * 2) << 2);
            w(
                io,
                CP_MEC_DOORBELL_RANGE_UPPER,
                (doorbell::USERQUEUE_END * 2) << 2,
            );
            w(io, CP_HQD_PQ_DOORBELL_CONTROL, m[mqd::PQ_DOORBELL_CONTROL]);
            w(io, CP_HQD_PQ_WPTR_LO, m[mqd::PQ_WPTR_LO]);
            w(io, CP_HQD_PQ_WPTR_HI, m[mqd::PQ_WPTR_HI]);
            w(io, CP_HQD_VMID, m[mqd::HQD_VMID]);
            w(io, CP_HQD_PERSISTENT_STATE, m[mqd::PERSISTENT_STATE]);
            w(io, CP_HQD_ACTIVE, m[mqd::HQD_ACTIVE]);
            update(io, l.reg(CP_PQ_STATUS), 2, 2)?; // DOORBELL_ENABLE
            grbm_select(io, l, 0, 0, 0, 0);
            Ok(())
        })
    }
    /// `gfx_v10_0_kcq_resume` + `amdgpu_gfx_enable_kcq` + ring tests.
    pub(crate) async fn map_compute(&mut self) -> Result<(), Error> {
        self.begin(State::KiqReady, State::Mapping)?;
        let result = self.map_compute_inner().await;
        self.finish(result, State::Mapped)
    }
    async fn map_compute_inner(&mut self) -> Result<(), Error> {
        let (me, pipe, queue) = COMPUTE_QUEUE;
        let compute = &self.compute;
        self.hw.access(|io, l| {
            // gfx_v10_0_cp_compute_enable(true): CP_MEC_CNTL_Sienna_Cichlid = 0
            io.write(l.reg(CP_MEC_CNTL), 0);
            Ok(())
        })?;
        delay(50).await;
        let kiq = &mut self.kiq;
        self.hw.access(|io, l| {
            grbm_select(io, l, me, pipe, queue, 0);
            let m = compute_mqd(io, l, compute, false);
            grbm_select(io, l, 0, 0, 0, 0);
            let m = m?;
            for (i, &word) in m.iter().enumerate() {
                io.write_memory(compute.map(), MQD + i as u64 * 4, word);
            }
            flush(io, l);
            // amdgpu_queue_mask_bit_to_set_resource_bit: mec*32 + pipe*8 + queue
            let mask = 1u64 << ((me - 1) * 32 + pipe * 8 + queue);
            kiq.emit(io, &pm4::set_resources(mask))?;
            kiq.emit(
                io,
                &pm4::map_queues(
                    me,
                    pipe,
                    queue,
                    compute.doorbell,
                    compute.address(MQD),
                    compute.address(WPTR),
                ),
            )?;
            kiq.commit(io, l);
            Ok(())
        })?;
        // amdgpu_ring_test_helper(kiq_ring) proves MAP_QUEUES was consumed.
        ring_test(&mut self.hw, &mut self.kiq).await?;
        self.proof.kiq_ring = true;
        ring_test(&mut self.hw, &mut self.compute).await?;
        self.proof.compute_ring = true;
        Ok(())
    }
    pub(crate) async fn test_ib(&mut self) -> Result<(), Error> {
        self.begin(State::Mapped, State::Testing)?;
        let result = ib_test(&mut self.hw, &mut self.compute).await;
        if let Ok(seq) = result {
            self.proof.ib_fence = seq;
        }
        self.finish(result.map(|_| ()), State::Verified)
    }
}

/// Owner of the KIQ and the kernel compute queue.
#[derive(Debug)]
pub struct Compute {
    engine: Engine<Mmio>,
}
impl Compute {
    /// Reserve KIQ and compute storage without device I/O.
    ///
    /// # Safety
    /// Caller exclusively owns this Navi22 GPU's MEC/RLC/GRBM, HDP, BAR2
    /// doorbell page and the matching permanent VRAM pool; no other KIQ,
    /// MES or compute queue owner exists.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: Doorbells,
    ) -> Result<Self, Error> {
        const { assert!(RING_BYTES == 8192) };
        Ok(Self {
            engine: Engine {
                hw: Hw {
                    layout: Layout::resolve(gpu)?,
                    io: Mmio::new(gpu, doorbells),
                    authority,
                },
                kiq: Queue::new(pool, Kind::Cp, doorbell::KIQ, fence::Engine::Kiq)?,
                compute: Queue::new(pool, Kind::Cp, doorbell::MEC_RING0, fence::Engine::Compute)?,
                state: State::Prepared,
                proof: Proof::default(),
            },
        })
    }
    /// # Safety
    /// GFX constants/RLC setup completed, doorbell apertures are enabled
    /// and `new`'s contract holds. Failure/cancellation prevents replay.
    pub async unsafe fn init_kiq(&mut self) -> Result<(), Error> {
        self.engine.init_kiq().await
    }
    /// # Safety
    /// `init_kiq` succeeded under the same ownership contract.
    pub async unsafe fn map_compute(&mut self) -> Result<(), Error> {
        self.engine.map_compute().await
    }
    pub async fn test_ib(&mut self) -> Result<(), Error> {
        self.engine.test_ib().await
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn proof(&self) -> Proof {
        self.engine.proof
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_kiq_navi22_tests.rs"]
mod tests;
