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

// linux-ctx: hdr=gc101,pm4,amdgpu
/// `amdgpu_gfx_kiq_acquire` on GC 10.3 (2 MEC x 4 pipes x 4 queues): the
/// highest free queue-0 slot not on MEC2 pipes 2/3 is MEC2 pipe 1 queue 0.
pub const KIQ_QUEUE: (u32, u32, u32) = (2, 1, 0); // linux: n/a (amdgpu_gfx_kiq_acquire result)
/// Single kernel compute ring: `compute_ring[0]` at MEC1 pipe 0 queue 0.
pub const COMPUTE_QUEUE: (u32, u32, u32) = (1, 0, 0); // linux: n/a (NARF single compute ring)

/// `struct v10_compute_mqd` dword indices (v10_structs.h, 512 dwords).
pub(crate) mod mqd {
    pub const HEADER: usize = 0; // linux: offsetof(struct v10_compute_mqd, header) / 4
                                 // linux: offsetof(struct v10_compute_mqd, compute_pipelinestat_enable) / 4
    pub const PIPELINESTAT_ENABLE: usize = 11;
    // linux: offsetof(struct v10_compute_mqd, compute_static_thread_mgmt_se0) / 4; offsetof(struct v10_compute_mqd, compute_static_thread_mgmt_se1) / 4
    // linux: offsetof(struct v10_compute_mqd, compute_static_thread_mgmt_se2) / 4; offsetof(struct v10_compute_mqd, compute_static_thread_mgmt_se3) / 4
    pub const STATIC_THREAD_MGMT: [usize; 4] = [23, 24, 26, 27];
    // linux: offsetof(struct v10_compute_mqd, compute_misc_reserved) / 4
    pub const MISC_RESERVED: usize = 32;
    // linux: offsetof(struct v10_compute_mqd, cp_mqd_base_addr_lo) / 4
    pub const MQD_BASE_ADDR_LO: usize = 128;
    // linux: offsetof(struct v10_compute_mqd, cp_mqd_base_addr_hi) / 4
    pub const MQD_BASE_ADDR_HI: usize = 129;
    pub const HQD_ACTIVE: usize = 130; // linux: offsetof(struct v10_compute_mqd, cp_hqd_active) / 4
    pub const HQD_VMID: usize = 131; // linux: offsetof(struct v10_compute_mqd, cp_hqd_vmid) / 4
                                     // linux: offsetof(struct v10_compute_mqd, cp_hqd_persistent_state) / 4
    pub const PERSISTENT_STATE: usize = 132;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pipe_priority) / 4
    pub const PIPE_PRIORITY: usize = 133;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_queue_priority) / 4
    pub const QUEUE_PRIORITY: usize = 134;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_base_lo) / 4
    pub const PQ_BASE_LO: usize = 136;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_base_hi) / 4
    pub const PQ_BASE_HI: usize = 137;
    pub const PQ_RPTR: usize = 138; // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_rptr) / 4
                                    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_rptr_report_addr_lo) / 4
    pub const RPTR_REPORT_LO: usize = 139;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_rptr_report_addr_hi) / 4
    pub const RPTR_REPORT_HI: usize = 140;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_wptr_poll_addr_lo) / 4
    pub const WPTR_POLL_LO: usize = 141;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_wptr_poll_addr_hi) / 4
    pub const WPTR_POLL_HI: usize = 142;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_doorbell_control) / 4
    pub const PQ_DOORBELL_CONTROL: usize = 143;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_control) / 4
    pub const PQ_CONTROL: usize = 145;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_ib_control) / 4
    pub const IB_CONTROL: usize = 149;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_dequeue_request) / 4
    pub const DEQUEUE_REQUEST: usize = 152;
    // linux: offsetof(struct v10_compute_mqd, cp_mqd_control) / 4
    pub const MQD_CONTROL: usize = 162;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_eop_base_addr_lo) / 4
    pub const EOP_BASE_LO: usize = 165;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_eop_base_addr_hi) / 4
    pub const EOP_BASE_HI: usize = 166;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_eop_control) / 4
    pub const EOP_CONTROL: usize = 167;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_wptr_lo) / 4
    pub const PQ_WPTR_LO: usize = 182;
    // linux: offsetof(struct v10_compute_mqd, cp_hqd_pq_wptr_hi) / 4
    pub const PQ_WPTR_HI: usize = 183;
    pub const DWORDS: usize = 512; // linux: sizeof(struct v10_compute_mqd) / 4
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
    m[mqd::HEADER] = 0xc031_0800; // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_compute_mqd_init)
                                  // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_compute_mqd_init)
    m[mqd::PIPELINESTAT_ENABLE] = 1;
    for i in mqd::STATIC_THREAD_MGMT {
        m[i] = u32::MAX;
    }
    m[mqd::MISC_RESERVED] = 3; // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_compute_mqd_init)
    let eop = queue.address(EOP) >> 8;
    m[mqd::EOP_BASE_LO] = eop as u32;
    m[mqd::EOP_BASE_HI] = (eop >> 32) as u32;
    // EOP_SIZE = order_base_2(GFX10_MEC_HPD_SIZE / 4) - 1
    // linux-lit: 0x3f=CP_HQD_EOP_CONTROL__EOP_SIZE_MASK
    m[mqd::EOP_CONTROL] = (read(io, CP_HQD_EOP_CONTROL)? & !0x3f) | 8;
    m[mqd::PQ_DOORBELL_CONTROL] =
        // linux-lit: 2=CP_HQD_PQ_DOORBELL_CONTROL__DOORBELL_OFFSET__SHIFT; 30=CP_HQD_PQ_DOORBELL_CONTROL__DOORBELL_EN__SHIFT
        // linux-lit: 0xdffffffc=CP_HQD_PQ_DOORBELL_CONTROL__DOORBELL_OFFSET_MASK | CP_HQD_PQ_DOORBELL_CONTROL__DOORBELL_EN_MASK | CP_HQD_PQ_DOORBELL_CONTROL__DOORBELL_SOURCE_MASK | CP_HQD_PQ_DOORBELL_CONTROL__DOORBELL_HIT_MASK
        (read(io, CP_HQD_PQ_DOORBELL_CONTROL)? & !0xdfff_fffc) | (queue.doorbell << 2) | (1 << 30);
    let address = queue.address(MQD);
    // linux: n/a (literal 0xfffffffc in compute_mqd_init)
    m[mqd::MQD_BASE_ADDR_LO] = address as u32 & !3;
    m[mqd::MQD_BASE_ADDR_HI] = (address >> 32) as u32;
    // linux-lit: 0xf=CP_MQD_CONTROL__VMID_MASK
    m[mqd::MQD_CONTROL] = read(io, CP_MQD_CONTROL)? & !0xf;
    let pq = queue.address(0) >> 8;
    m[mqd::PQ_BASE_LO] = pq as u32;
    m[mqd::PQ_BASE_HI] = (pq >> 32) as u32;
    // QUEUE_SIZE = order_base_2(8192 / 4) - 1, RPTR_BLOCK_SIZE = 9 (4 KiB),
    // UNORD_DISPATCH, PRIV_STATE, KMD_QUEUE; no tunneling (one compute ring).
    // linux-lit: 0xf0003f3f=CP_HQD_PQ_CONTROL__QUEUE_SIZE_MASK | CP_HQD_PQ_CONTROL__RPTR_BLOCK_SIZE_MASK | CP_HQD_PQ_CONTROL__UNORD_DISPATCH_MASK | CP_HQD_PQ_CONTROL__TUNNEL_DISPATCH_MASK | CP_HQD_PQ_CONTROL__PRIV_STATE_MASK | CP_HQD_PQ_CONTROL__KMD_QUEUE_MASK
    m[mqd::PQ_CONTROL] = (read(io, CP_HQD_PQ_CONTROL)? & !0xf000_3f3f)
        | 10 // linux: n/a (order_base_2(NARF 8 KiB ring / 4) - 1)
        | (9 << 8) // linux-lit: 8=CP_HQD_PQ_CONTROL__RPTR_BLOCK_SIZE__SHIFT
        | (1 << 28) // linux-lit: 28=CP_HQD_PQ_CONTROL__UNORD_DISPATCH__SHIFT
        | (1 << 30) // linux-lit: 30=CP_HQD_PQ_CONTROL__PRIV_STATE__SHIFT
        | (1 << 31); // linux-lit: 31=CP_HQD_PQ_CONTROL__KMD_QUEUE__SHIFT
    let rptr = queue.address(RPTR);
    // linux: n/a (literal 0xfffffffc in compute_mqd_init)
    m[mqd::RPTR_REPORT_LO] = rptr as u32 & !3;
    // linux-lit: 0xffff=CP_HQD_PQ_RPTR_REPORT_ADDR_HI__RPTR_REPORT_ADDR_HI_MASK
    m[mqd::RPTR_REPORT_HI] = (rptr >> 32) as u32 & 0xffff;
    let wptr = queue.address(WPTR);
    m[mqd::WPTR_POLL_LO] = wptr as u32 & !3; // linux: n/a (literal 0xfffffffc in compute_mqd_init)
                                             // linux-lit: 0xffff=CP_HQD_PQ_WPTR_POLL_ADDR_HI__WPTR_ADDR_HI_MASK
    m[mqd::WPTR_POLL_HI] = (wptr >> 32) as u32 & 0xffff;
    m[mqd::PQ_RPTR] = read(io, CP_HQD_PQ_RPTR)?;
    // linux-lit: 0x3ff00=CP_HQD_PERSISTENT_STATE__PRELOAD_SIZE_MASK; 8=CP_HQD_PERSISTENT_STATE__PRELOAD_SIZE__SHIFT
    // 0x53: PRELOAD_SIZE literal in gfx_v10_0_compute_mqd_init
    m[mqd::PERSISTENT_STATE] = (read(io, CP_HQD_PERSISTENT_STATE)? & !0x3ff00) | (0x53 << 8);
    // linux-lit: 0x300000=CP_HQD_IB_CONTROL__MIN_IB_AVAIL_SIZE_MASK; 20=CP_HQD_IB_CONTROL__MIN_IB_AVAIL_SIZE__SHIFT
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
            // linux: n/a (literal in gfx_v10_0_kiq_setting)
            let old = checked(io.read(l.reg(RLC_CP_SCHEDULERS)))? & 0xffff_ff00;
            // linux: n/a (literal in gfx_v10_0_kiq_setting)
            let id = (me << 5) | (pipe << 3) | queue;
            io.write(l.reg(RLC_CP_SCHEDULERS), old | id);
            // linux: n/a (literal in gfx_v10_0_kiq_setting)
            io.write(l.reg(RLC_CP_SCHEDULERS), old | id | 0x80);
            grbm_select(io, l, me, pipe, queue, 0);
            let m = compute_mqd(io, l, kiq, true)?;
            for (i, &word) in m.iter().enumerate() {
                io.write_memory(kiq.map(), MQD + i as u64 * 4, word);
            }
            flush(io, l);
            // gfx_v10_0_kiq_init_register
            // linux-lit: 31=31 * (CP_PQ_WPTR_POLL_CNTL__EN_MASK >> 31)
            update(io, l.reg(CP_PQ_WPTR_POLL_CNTL), 1 << 31, 0)?;
            // linux-lit: 1=CP_HQD_ACTIVE__ACTIVE_MASK
            let active = checked(io.read(l.reg(CP_HQD_ACTIVE)))? & 1 != 0;
            if active {
                // linux: n/a (literal in gfx_v10_0_kiq_init_register)
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
                    // linux-lit: 1=CP_HQD_ACTIVE__ACTIVE_MASK
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
            // linux: n/a (literal in gfx_v10_0_kiq_init_register)
            w(io, CP_MEC_DOORBELL_RANGE_LOWER, (doorbell::KIQ * 2) << 2);
            w(
                io,
                CP_MEC_DOORBELL_RANGE_UPPER,
                // linux: n/a (literal in gfx_v10_0_kiq_init_register)
                (doorbell::USERQUEUE_END * 2) << 2,
            );
            w(io, CP_HQD_PQ_DOORBELL_CONTROL, m[mqd::PQ_DOORBELL_CONTROL]);
            w(io, CP_HQD_PQ_WPTR_LO, m[mqd::PQ_WPTR_LO]);
            w(io, CP_HQD_PQ_WPTR_HI, m[mqd::PQ_WPTR_HI]);
            w(io, CP_HQD_VMID, m[mqd::HQD_VMID]);
            w(io, CP_HQD_PERSISTENT_STATE, m[mqd::PERSISTENT_STATE]);
            w(io, CP_HQD_ACTIVE, m[mqd::HQD_ACTIVE]);
            // linux-lit: 2=CP_PQ_STATUS__DOORBELL_ENABLE_MASK
            update(io, l.reg(CP_PQ_STATUS), 2, 2)?;
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
        delay(50).await; // linux: n/a (udelay(50) in gfx_v10_0_cp_compute_enable)
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
            // linux: n/a (literal in amdgpu_gfx.c)
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
        Self::with_layout(gpu, authority, pool, doorbells, Layout::resolve(gpu)?)
    }
    /// Reserve KIQ and kernel-compute rings for a known discrete RDNA2 ASIC.
    /// No engine is started; the Linux GC10.3 MEC queue geometry is shared.
    ///
    /// # Safety
    /// Same exclusive physical GPU, MEC/RLC/GRBM/HDP, doorbell and permanent
    /// pool ownership as `new`, with no active KIQ, MES or compute owner.
    pub unsafe fn new_rdna2(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: Doorbells,
    ) -> Result<Self, Error> {
        Self::with_layout(gpu, authority, pool, doorbells, Layout::resolve_rdna2(gpu)?)
    }
    fn with_layout(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: Doorbells,
        layout: Layout,
    ) -> Result<Self, Error> {
        const { assert!(RING_BYTES == 8192) }; // linux: n/a (NARF ring size)
                                               // linux-ctx: reset
        Ok(Self {
            engine: Engine {
                hw: Hw {
                    layout,
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
    pub(crate) fn fence_map(&self) -> narf_bus::MmioRegion {
        self.engine.compute.map()
    }
    /// Client IBs on the kernel compute queue; see `Gfx::submit`.
    pub fn submit(
        &mut self,
        state: &mut crate::amdgpu_navi22_submit::RingState,
        vm: crate::amdgpu_navi22_submit::VmRef,
        context: u64,
        ibs: &[crate::amdgpu_navi22_submit::Ib],
    ) -> Result<u32, Error> {
        if self.engine.state != State::Verified {
            return Err(Error::Busy);
        }
        let e = &mut self.engine;
        crate::amdgpu_navi22_submit::submit(
            &mut e.hw,
            &mut e.compute,
            state,
            crate::amdgpu_navi22_submit::Ring::Compute,
            vm,
            context,
            ibs,
        )
    }
    /// See `Gfx::fences`.
    pub fn fences(&mut self) -> Result<(u32, u32), Error> {
        let e = &mut self.engine;
        Ok((
            crate::amdgpu_navi22_submit::completed(&mut e.hw, &e.compute)?,
            crate::amdgpu_navi22_submit::throttle_seq(&e.compute),
        ))
    }
    pub fn proof(&self) -> Proof {
        self.engine.proof
    }
    /// Fence progress of the KIQ and the compute queue (hang detection only).
    pub(crate) fn progress(&mut self) -> Result<[crate::amdgpu_navi22_tdr::Progress; 2], Error> {
        if self.engine.state != State::Verified {
            return Err(Error::Busy);
        }
        let e = &mut self.engine;
        Ok([
            crate::amdgpu_cp_navi22::progress(&mut e.hw, &e.kiq)?,
            crate::amdgpu_cp_navi22::progress(&mut e.hw, &e.compute)?,
        ])
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_kiq_navi22_tests.rs"]
mod tests;
