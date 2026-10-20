//! End-to-end register-model proof: a client IB queued under a user VMID on
//! each Navi22 kernel queue is fetched and executed through that VMID's
//! translation, after a ring-side TLB flush, and its fence signals.
use super::*;
use crate::amdgpu_cp_navi22::regs::RLC_CP_SCHEDULERS;
use crate::amdgpu_cp_navi22::{
    doorbell,
    tests::{enabled, hw, pool, r, run, Model},
    wait_fence, GfxEngine, GfxProof, GfxState,
};
use alloc::collections::BTreeMap;
use narf_kernel_test::{kernel_test_in, TestResult};

const VMID: u8 = 3;
const PTB: u64 = 0x0000_0001_2345_6001;
const IB_VA: u64 = 0x0000_7000_0010_0000;
const DST_VA: u64 = 0x0000_7000_0020_0000;
/// MC pages backing the two VAs (outside every queue reservation).
const IB_MC: u64 = 0x9_1000_0000;
const DST_MC: u64 = 0x9_2000_0000;

const PASID: u16 = 0x0042;

/// A grant that flushes and maps the PASID (a VMID's first use).
fn vm() -> VmRef {
    VmRef {
        vmid: VMID,
        page_table_base: PTB,
        pasid: PASID,
        flush: true,
        map_pasid: true,
    }
}
/// A grant reusing a VMID this space already owns (no flush, no LUT write).
fn reused() -> VmRef {
    VmRef {
        flush: false,
        map_pasid: false,
        ..vm()
    }
}
/// The client's address space and its IB: one WRITE_DATA (PM4) or
/// WRITE_LINEAR (SDMA) of `value` to `DST_VA`.
fn install(model: &mut Model, sdma: bool, value: u32) -> Ib {
    let mut space = BTreeMap::new();
    space.insert(u64::MAX, PTB);
    space.insert(IB_VA, IB_MC);
    space.insert(DST_VA, DST_MC);
    model.vms.insert(VMID, space);
    let words: alloc::vec::Vec<u32> = if sdma {
        let mut w = pm4::sdma_write(DST_VA, value).to_vec();
        w.extend([pm4::SDMA_NOP; 3]);
        w
    } else {
        pm4::write_data(DST_VA, value).to_vec()
    };
    for (k, w) in words.iter().enumerate() {
        model.mem.insert(IB_MC + k as u64 * 4, *w);
    }
    Ib {
        va: IB_VA,
        dwords: words.len() as u32,
    }
}

fn gfx_engine() -> (crate::amdgpu_vram::Pool, GfxEngine<Model>) {
    let pool = pool(1 << 20);
    let queue = Queue::new(&pool, Kind::Cp, doorbell::GFX_RING0, fence::Engine::Gfx).unwrap();
    let mut e = GfxEngine {
        hw: hw(enabled()),
        queue,
        state: GfxState::Prepared,
        proof: GfxProof::default(),
        golden: false,
    };
    assert!(run(e.configure()).is_ok() && run(e.start()).is_ok() && run(e.test_ib()).is_ok());
    (pool, e)
}

fn navi22_submit_gfx_user_vmid_ib_executes_and_fences() -> TestResult {
    let (_pool, mut e) = gfx_engine();
    let ib = install(&mut e.hw.io, false, 0x1234_5678);
    let mut state = RingState::default();
    let seq = match submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        vm(),
        1,
        &[ib],
    ) {
        Ok(seq) => seq,
        Err(_) => return TestResult::Fail("gfx user submission refused"),
    };
    if run(wait_fence(&mut e.hw, &e.queue, seq)).is_err()
        || e.hw.io.word(DST_MC) != 0x1234_5678
        || e.hw.io.user_ibs != [(0, VMID)]
        || e.hw.io.flushes != [(0, VMID)]
        || e.hw.io.reg(PTB_LO_ADDR + 8 * u64::from(VMID)) != PTB as u32
        || e.hw.io.reg(LUT_ADDR + 4 * u64::from(VMID)) != u32::from(PASID)
    {
        return TestResult::Fail("gfx user IB did not run under its flushed VMID");
    }
    // Same VM again: no second flush, no context switch, new fence.
    let ib = install(&mut e.hw.io, false, 0x9abc_def0);
    let next = submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        reused(),
        1,
        &[ib],
    )
    .unwrap();
    if run(wait_fence(&mut e.hw, &e.queue, next)).is_err()
        || next != seq.wrapping_add(1)
        || e.hw.io.word(DST_MC) != 0x9abc_def0
        || e.hw.io.flushes.len() != 1
    {
        return TestResult::Fail("same VM was re-flushed or second fence lost");
    }
    // A grant that moved the VMID to another space is flushed before use.
    let third = submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        vm(),
        2,
        &[ib],
    )
    .unwrap();
    if run(wait_fence(&mut e.hw, &e.queue, third)).is_err() || e.hw.io.flushes.len() != 2 {
        return TestResult::Fail("reassigned VMID not flushed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_submit_gfx_user_vmid_ib_executes_and_fences
);

const PTB_LO_ADDR: u64 = crate::amdgpu_cp_navi22::tests::GC0 + 0x1667 * 4;
/// IH_VMID_0_LUT at the live OSSSYS base.
const LUT_ADDR: u64 = crate::amdgpu_cp_navi22::tests::OSS;

fn navi22_submit_compute_and_sdma_user_vmid_ibs_execute() -> TestResult {
    // Compute (MEC1 pipe 0 queue 0, invalidation engine 4).
    let vram = pool(1 << 20);
    let mut model = enabled();
    model.regs.insert(r(RLC_CP_SCHEDULERS), 0x1234_5600);
    let mut c = crate::amdgpu_kiq_navi22::Engine {
        hw: hw(model),
        kiq: Queue::new(&vram, Kind::Cp, doorbell::KIQ, fence::Engine::Kiq).unwrap(),
        compute: Queue::new(&vram, Kind::Cp, doorbell::MEC_RING0, fence::Engine::Compute).unwrap(),
        state: crate::amdgpu_kiq_navi22::State::Prepared,
        proof: Default::default(),
    };
    if run(c.init_kiq()).is_err() || run(c.map_compute()).is_err() || run(c.test_ib()).is_err() {
        return TestResult::Fail("compute bring-up");
    }
    let ib = install(&mut c.hw.io, false, 0x00c0_ffee);
    let mut state = RingState::default();
    let seq = submit(
        &mut c.hw,
        &mut c.compute,
        &mut state,
        Ring::Compute,
        vm(),
        9,
        &[ib],
    );
    if !seq.is_ok_and(|s| run(wait_fence(&mut c.hw, &c.compute, s)).is_ok())
        || c.hw.io.word(DST_MC) != 0x00c0_ffee
        || c.hw.io.user_ibs != [(2, VMID)]
        || c.hw.io.flushes != [(4, VMID)]
    {
        return TestResult::Fail("compute user IB did not run under its flushed VMID");
    }
    // SDMA1 (engine 14), VA must be 32-byte aligned.
    let vram2 = pool(1 << 20);
    let mut s = crate::amdgpu_sdma_navi22_queues::Engine {
        hw: hw(enabled()),
        queues: [
            Queue::new(&vram2, Kind::Sdma, doorbell::SDMA0, fence::Engine::Sdma0).unwrap(),
            Queue::new(&vram2, Kind::Sdma, doorbell::SDMA1, fence::Engine::Sdma1).unwrap(),
        ]
        .into(),
        state: crate::amdgpu_sdma_navi22_queues::State::Prepared,
        proof: Default::default(),
    };
    if run(s.start()).is_err() || run(s.test_ib()).is_err() {
        return TestResult::Fail("SDMA bring-up");
    }
    let ib = install(&mut s.hw.io, true, 0x5d5d_0001);
    let mut state = RingState::default();
    let seq = submit(
        &mut s.hw,
        &mut s.queues[1],
        &mut state,
        Ring::Sdma(1),
        vm(),
        9,
        &[ib],
    );
    if !seq.is_ok_and(|q| run(wait_fence(&mut s.hw, &s.queues[1], q)).is_ok())
        || s.hw.io.word(DST_MC) != 0x5d5d_0001
        || s.hw.io.user_ibs != [(4, VMID)]
        || s.hw.io.flushes != [(14, VMID)]
    {
        return TestResult::Fail("SDMA user IB did not run under its flushed VMID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_submit_compute_and_sdma_user_vmid_ibs_execute
);

fn navi22_submit_validates_and_throttles() -> TestResult {
    let ib = Ib {
        va: 0x1000,
        dwords: 4,
    };
    let bad = [
        validate(Ring::Gfx, VmRef { vmid: 0, ..vm() }, &[ib]),
        validate(Ring::Gfx, VmRef { vmid: 16, ..vm() }, &[ib]),
        validate(Ring::Gfx, vm(), &[]),
        validate(Ring::Gfx, vm(), &[ib; MAX_IBS + 1]),
        validate(
            Ring::Gfx,
            vm(),
            &[Ib {
                va: 0x1002,
                dwords: 4,
            }],
        ),
        validate(
            Ring::Gfx,
            vm(),
            &[Ib {
                va: 0x1000,
                dwords: 0,
            }],
        ),
        validate(
            Ring::Sdma(0),
            vm(),
            &[Ib {
                va: 0x1010,
                dwords: 4,
            }],
        ),
    ];
    if bad.iter().any(|r| *r != Err(Error::Invalid)) || validate(Ring::Gfx, vm(), &[ib]).is_err() {
        return TestResult::Fail("IB/VMID validation");
    }
    // A stalled CP: two submissions may be outstanding, the third is Busy
    // and nothing is written to the ring for it.
    let (_pool, mut e) = gfx_engine();
    let ib = install(&mut e.hw.io, false, 1);
    e.hw.io.stalled[0] = true;
    let mut state = RingState::default();
    let first = submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        vm(),
        1,
        &[ib],
    );
    let second = submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        vm(),
        1,
        &[ib],
    );
    let wptr = e.queue.wptr;
    let third = submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        vm(),
        1,
        &[ib],
    );
    if first.is_err() || second.is_err() || third != Err(Error::Busy) || e.queue.wptr != wptr {
        return TestResult::Fail("hw_submission throttle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_submit_validates_and_throttles
);

fn navi22_submit_encodes_linux_vm_flush() -> TestResult {
    let l = crate::amdgpu_cp_navi22::tests::layout();
    let words = encode_cp(
        l,
        &Frame {
            gfx: true,
            engine: 0,
            sync: Some((0x1000, 5)),
            flush: Some(vm()),
            pasid_map: Some((0x10a0 + u32::from(VMID), PASID)),
            vm_fence: None,
            vmid: VMID,
            context_switch: true,
            ibs: &[],
            fence: 0x2000,
            seq: 6,
            wptr: 0,
        },
    );
    let base = 0x1260;
    // pipeline sync: WAIT_REG_MEM mem, wait, equal, PFP.
    let sync = [
        packet3(PACKET3_WAIT_REG_MEM, 5),
        0x113,
        0x1000,
        0,
        5,
        u32::MAX,
        4,
    ];
    let ptb = [
        packet3(PACKET3_WRITE_DATA, 3),
        (1 << 30) | (1 << 20),
        base + 0x1667 + 6,
        0,
        PTB as u32,
    ];
    let inv = [
        packet3(PACKET3_WAIT_REG_MEM, 5),
        0x143,
        base + 0x161f,
        base + 0x1631,
        (1 << VMID) | 0xf8_0000,
        1 << VMID,
        0x20,
    ];
    if words[..7] != sync
        || words[7..12] != ptb
        || words[17..24] != inv
        || words[24..26] != [packet3(PACKET3_PFP_SYNC_ME, 0), 0]
        // gmc_v10_0_emit_pasid_mapping after the flush, ENGINE_SEL(1).
        || words[26..31]
            != [
                packet3(PACKET3_WRITE_DATA, 3),
                (1 << 30) | (1 << 20),
                0x10a0 + u32::from(VMID),
                0,
                u32::from(PASID),
            ]
        || words[31..34] != [packet3(PACKET3_CONTEXT_CONTROL, 1), 0x8101_8003, 0]
    {
        return TestResult::Fail("gfx VM flush / PASID map / context control encoding");
    }
    // SDMA: the LUT write is an SRBM_WRITE after the invalidation.
    let words = encode_sdma(
        l,
        &Frame {
            gfx: false,
            engine: 13,
            sync: None,
            flush: Some(vm()),
            pasid_map: Some((0x10a0 + u32::from(VMID), PASID)),
            vm_fence: None,
            vmid: VMID,
            context_switch: false,
            ibs: &[],
            fence: 0x2000,
            seq: 1,
            wptr: 0,
        },
    );
    if words[10..13] != [14 | (0xf << 28), 0x10a0 + u32::from(VMID), u32::from(PASID)] {
        return TestResult::Fail("SDMA PASID map encoding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_submit_encodes_linux_vm_flush
);

// ── Per-client VMIDs (amdgpu_vmid_grab via amdgpu_vmid::VmidManager) ─────

/// One client of the fake engine: its address space, root and PASID, and
/// the private IB/destination pages its jobs use.
#[derive(Clone, Copy)]
struct Client {
    owner: u64,
    ptb: u64,
    pasid: u16,
    tlb_seq: u64,
    ib_mc: u64,
    dst_mc: u64,
}
const fn client(n: u64) -> Client {
    Client {
        owner: 100 + n,
        ptb: PTB + (n << 12),
        pasid: 0x100 + n as u16,
        tlb_seq: 0,
        ib_mc: IB_MC + (n << 16),
        dst_mc: DST_MC + (n << 16),
    }
}
/// The ring words emitted between two write pointers.
fn ring_words(e: &GfxEngine<Model>, from: u64, to: u64) -> alloc::vec::Vec<u32> {
    use crate::amdgpu_cp_navi22::RING_DW;
    (from..to)
        .map(|i| e.hw.io.word(e.queue.address((i % RING_DW) * 4)))
        .collect()
}
/// (pipeline syncs, IH LUT writes) among PM4 ring `words`.
fn syncs_and_lut_writes(words: &[u32]) -> (usize, usize) {
    let lut = (LUT_ADDR / 4) as u32..(LUT_ADDR / 4) as u32 + 16;
    let (mut syncs, mut luts, mut i) = (0, 0, 0);
    while i < words.len() {
        let h = words[i];
        let (op, n) = ((h >> 8) & 0xff, ((h >> 16) & 0x3fff) as usize);
        if op == 0x10 && n == 0x3fff {
            i += 1;
            continue;
        }
        if op == 0x3c && (words[i + 1] >> 4) & 3 == 1 {
            syncs += 1;
        }
        if op == 0x37 && words[i + 1] & 0xf00 == 0 && lut.contains(&words[i + 2]) {
            luts += 1;
        }
        i += 2 + n;
    }
    (syncs, luts)
}
/// The grab → submit → commit sequence `amdgpu_navi22_cs::Submitter`
/// runs, on the fake gfx ring (ticket ring index 0, recovery epoch 0).
/// Returns the job's ticket and grant, or None when no VMID is idle.
fn job(
    e: &mut GfxEngine<Model>,
    vmids: &mut crate::amdgpu_vmid::VmidManager,
    state: &mut RingState,
    c: Client,
    ctx: u32,
    value: u32,
) -> Option<(u64, crate::amdgpu_vmid::Grant)> {
    use crate::amdgpu_navi22_cs as cs;
    let done_seq = completed(&mut e.hw, &e.queue).unwrap();
    let done = |t| cs::job_done(0, [done_seq, 0, 0, 0], t);
    let request = crate::amdgpu_vmid::GrabRequest {
        owner: c.owner,
        pd_addr: c.ptb,
        tlb_seq: c.tlb_seq,
        pasid: c.pasid,
        ring: cs::ring_index(0, 0),
    };
    let grant = vmids.grab(request, &done)?;
    // The granted VMID translates through this client's tables.
    let mut space = BTreeMap::new();
    space.insert(u64::MAX, c.ptb);
    space.insert(IB_VA, c.ib_mc);
    space.insert(DST_VA, c.dst_mc);
    e.hw.io.vms.insert(grant.vmid, space);
    for (k, w) in pm4::write_data(DST_VA, value).iter().enumerate() {
        e.hw.io.mem.insert(c.ib_mc + k as u64 * 4, *w);
    }
    let ib = Ib {
        va: IB_VA,
        dwords: pm4::write_data(DST_VA, value).len() as u32,
    };
    let seq = submit(
        &mut e.hw,
        &mut e.queue,
        state,
        Ring::Gfx,
        cs::vm_ref(&request, grant),
        cs::entity(c.owner, ctx),
        &[ib],
    )
    .ok()?;
    let ticket = u64::from(cs::ring_index(0, 0)) << 32 | u64::from(seq);
    vmids.commit(request, grant, ticket);
    Some((ticket, grant))
}

fn navi22_vmid_clients_share_a_ring_and_flush_only_on_change() -> TestResult {
    let (_pool, mut e) = gfx_engine();
    let mut vmids = crate::amdgpu_vmid::VmidManager::new(1, 7);
    let mut state = RingState::default();
    let (mut a, b) = (client(1), client(2));
    // Both clients get a VMID while the other's job is still on the ring:
    // nothing waits for a shared context.
    e.hw.io.stalled[0] = true;
    let Some((_, ga)) = job(&mut e, &mut vmids, &mut state, a, 1, 0xa1) else {
        return TestResult::Fail("first client refused");
    };
    let Some((tb, gb)) = job(&mut e, &mut vmids, &mut state, b, 1, 0xb1) else {
        return TestResult::Fail("second client waited for the first's VMID");
    };
    if ga.vmid == gb.vmid
        || !(1..8).contains(&ga.vmid)
        || !(1..8).contains(&gb.vmid)
        || !ga.needs_flush
        || !ga.map_pasid
        || !gb.needs_flush
        || !gb.map_pasid
    {
        return TestResult::Fail("first jobs must flush and map distinct client VMIDs");
    }
    e.hw.io.stalled[0] = false;
    e.queue.commit(&mut e.hw.io, e.hw.layout);
    if run(wait_fence(&mut e.hw, &e.queue, tb as u32)).is_err()
        || e.hw.io.word(a.dst_mc) != 0xa1
        || e.hw.io.word(b.dst_mc) != 0xb1
        || e.hw.io.user_ibs != [(0, ga.vmid), (0, gb.vmid)]
        || e.hw.io.flushes != [(0, ga.vmid), (0, gb.vmid)]
        || e.hw.io.reg(LUT_ADDR + 4 * u64::from(ga.vmid)) != u32::from(a.pasid)
        || e.hw.io.reg(LUT_ADDR + 4 * u64::from(gb.vmid)) != u32::from(b.pasid)
    {
        return TestResult::Fail("clients' jobs did not run under their own VMIDs");
    }
    // A again after B: same VMID, no flush, no LUT write; the entity change
    // still syncs the pipeline (need_ctx_switch).
    let from = e.queue.wptr;
    let Some((_, again)) = job(&mut e, &mut vmids, &mut state, a, 1, 0xa2) else {
        return TestResult::Fail("reuse refused");
    };
    let switched = syncs_and_lut_writes(&ring_words(&e, from, e.queue.wptr));
    // A once more: same entity, nothing but the IB and its fence.
    let from = e.queue.wptr;
    let Some((ta, same)) = job(&mut e, &mut vmids, &mut state, a, 1, 0xa3) else {
        return TestResult::Fail("reuse refused");
    };
    let steady = syncs_and_lut_writes(&ring_words(&e, from, e.queue.wptr));
    if again.vmid != ga.vmid
        || again.needs_flush
        || again.map_pasid
        || same != again
        || switched != (1, 0)
        || steady != (0, 0)
        || e.hw.io.flushes.len() != 2
        || run(wait_fence(&mut e.hw, &e.queue, ta as u32)).is_err()
        || e.hw.io.word(a.dst_mc) != 0xa3
    {
        return TestResult::Fail("a VMID its space already owns was flushed or synced");
    }
    // A removes a mapping (tlb_seq): its VMID is flushed again, still its own.
    a.tlb_seq = 1;
    let from = e.queue.wptr;
    let Some((_, after_unmap)) = job(&mut e, &mut vmids, &mut state, a, 1, 0xa4) else {
        return TestResult::Fail("unmap reuse refused");
    };
    let flushed = syncs_and_lut_writes(&ring_words(&e, from, e.queue.wptr));
    let flush_count = e.hw.io.flushes.len();
    // A new root in the same space no longer matches its VMID's context:
    // it takes the most recently used idle VMID (grab_idle) and flushes.
    let moved = Client {
        ptb: a.ptb + (64 << 12),
        ..a
    };
    let Some((tm, new_root)) = job(&mut e, &mut vmids, &mut state, moved, 1, 0xa5) else {
        return TestResult::Fail("new root refused");
    };
    if after_unmap.vmid != ga.vmid
        || !after_unmap.needs_flush
        || flushed.0 != 1
        || flush_count != 3
        || e.hw.io.flushes.len() != 4
        || !new_root.needs_flush
        || e.hw.io.reg(PTB_LO_ADDR + 8 * u64::from(new_root.vmid)) != moved.ptb as u32
        || run(wait_fence(&mut e.hw, &e.queue, tm as u32)).is_err()
        || e.hw.io.word(a.dst_mc) != 0xa5
    {
        return TestResult::Fail("TLB sequence or root change not flushed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_vmid_clients_share_a_ring_and_flush_only_on_change
);

fn navi22_vmid_exhaustion_waits_then_reuses_the_idle_vmid() -> TestResult {
    use crate::amdgpu_navi22_cs::{job_done, ring_index};
    use crate::amdgpu_vmid::{GrabRequest, VmidManager};
    let (first, last) = (1, crate::amdgpu_gmc_navi22::FIRST_KFD_VMID - 1);
    let mut vmids = VmidManager::new(first, last);
    let request = |n: u64, ring: usize| GrabRequest {
        owner: 100 + n,
        pd_addr: PTB + (n << 12),
        tlb_seq: 0,
        pasid: 0x100 + n as u16,
        ring: ring_index(0, ring),
    };
    let ticket = |ring: usize, seq: u32| u64::from(ring_index(0, ring)) << 32 | u64::from(seq);
    // Seven clients, one unfinished job each, spread over gfx and SDMA1.
    let none = [0u32; 4];
    let mut granted = alloc::vec::Vec::new();
    let mut first_owner = 0;
    for n in 1..=7u64 {
        let ring = if n % 2 == 0 { 3 } else { 0 };
        let done = |t| job_done(0, none, t);
        let Some(grant) = vmids.grab(request(n, ring), &done) else {
            return TestResult::Fail("free VMID refused");
        };
        vmids.commit(request(n, ring), grant, ticket(ring, n as u32));
        granted.push(grant.vmid);
        if n == 1 {
            first_owner = grant.vmid;
        }
    }
    granted.sort_unstable();
    if granted != (first..=last).collect::<alloc::vec::Vec<_>>() {
        return TestResult::Fail("grants left VMIDs 1-7 or touched KFD's 8-15");
    }
    // An eighth client waits: every client VMID has an unfinished job.
    let done = |t| job_done(0, none, t);
    if vmids.grab(request(8, 0), &done).is_some() {
        return TestResult::Fail("grant while every VMID is busy");
    }
    // Client 1's gfx job (seq 1) completes: the eighth takes its VMID,
    // flushing and remapping the LUT to its own PASID.
    let progress = [1, 0, 0, 0];
    let done = |t| job_done(0, progress, t);
    let Some(eighth) = vmids.grab(request(8, 0), &done) else {
        return TestResult::Fail("idle VMID not reused");
    };
    vmids.commit(request(8, 0), eighth, ticket(0, 8));
    if eighth.vmid != first_owner || !eighth.needs_flush || !eighth.map_pasid {
        return TestResult::Fail("reused VMID not flushed and remapped");
    }
    // Client 1 lost its VMID: it waits too, then flushes into whatever
    // goes idle next (client 2's, on SDMA1).
    if vmids.grab(request(1, 0), &done).is_some() {
        return TestResult::Fail("client got a VMID another space now holds");
    }
    let progress = [1, 0, 0, 2];
    let done = |t| job_done(0, progress, t);
    match vmids.grab(request(1, 0), &done) {
        Some(g) if g.needs_flush && g.map_pasid && g.vmid != eighth.vmid => TestResult::Pass,
        _ => TestResult::Fail("evicted client not flushed into the next idle VMID"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_vmid_exhaustion_waits_then_reuses_the_idle_vmid
);

fn navi22_vmid_recovery_epoch_flushes_every_vmid_again() -> TestResult {
    use crate::amdgpu_navi22_cs::{job_done, ring_index};
    use crate::amdgpu_vmid::{GrabRequest, VmidManager};
    let request = |epoch| GrabRequest {
        owner: 7,
        pd_addr: PTB,
        tlb_seq: 0,
        pasid: 0x77,
        ring: ring_index(epoch, 0),
    };
    let mut before = VmidManager::new(1, 7);
    let done = |t| job_done(0, [5, 0, 0, 0], t);
    let grant = before.grab(request(0), &done).unwrap();
    before.commit(request(0), grant, u64::from(ring_index(0, 0)) << 32 | 6);
    // Still running in epoch 0: the space reuses its VMID unflushed.
    let reuse = before.grab(request(0), &done).unwrap();
    if reuse.vmid != grant.vmid || reuse.needs_flush {
        return TestResult::Fail("same-epoch reuse flushed");
    }
    // Recovery: the epoch-0 job was abandoned (reads complete in epoch 1,
    // whose rings restart at 0), and `register` builds a fresh manager, so
    // the same space at the same root flushes and remaps before reuse, as
    // amdgpu_vm_flush does after amdgpu_vmid_had_gpu_reset.
    let done = |t| job_done(1, [0; 4], t);
    if !done(u64::from(ring_index(0, 0)) << 32 | 6) {
        return TestResult::Fail("pre-recovery ticket not abandoned");
    }
    let after = VmidManager::new(1, 7);
    match after.grab(request(1), &done) {
        Some(g) if g.needs_flush && g.map_pasid => TestResult::Pass,
        _ => TestResult::Fail("post-recovery job did not flush and remap"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_vmid_recovery_epoch_flushes_every_vmid_again
);

/// The shared-context hazard per-client VMIDs remove: two processes' jobs
/// running at once on gfx and SDMA1 must not retarget each other's
/// translations. With one manager over both rings, the SDMA job cannot take
/// the VMID the unfinished gfx job runs in, and each ring's context points at
/// its own client's root.
fn navi22_vmid_clients_on_two_rings_keep_their_own_translations() -> TestResult {
    use crate::amdgpu_navi22_cs as cs;
    let (_pool, mut g) = gfx_engine();
    let vram = pool(1 << 20);
    let mut s = crate::amdgpu_sdma_navi22_queues::Engine {
        hw: hw(enabled()),
        queues: [
            Queue::new(&vram, Kind::Sdma, doorbell::SDMA0, fence::Engine::Sdma0).unwrap(),
            Queue::new(&vram, Kind::Sdma, doorbell::SDMA1, fence::Engine::Sdma1).unwrap(),
        ]
        .into(),
        state: crate::amdgpu_sdma_navi22_queues::State::Prepared,
        proof: Default::default(),
    };
    if run(s.start()).is_err() || run(s.test_ib()).is_err() {
        return TestResult::Fail("SDMA bring-up");
    }
    let mut vmids = crate::amdgpu_vmid::VmidManager::new(1, 7);
    let (x, y) = (client(1), client(2));
    // X's gfx job stays on the ring (stalled CP).
    g.hw.io.stalled[0] = true;
    let mut gfx_state = RingState::default();
    let Some((tx, gx)) = job(&mut g, &mut vmids, &mut gfx_state, x, 1, 0x0a) else {
        return TestResult::Fail("gfx client refused");
    };
    // Y on SDMA1 meanwhile: completed sequences as both rings report them.
    let gfx_done = completed(&mut g.hw, &g.queue).unwrap();
    let sdma_done = completed(&mut s.hw, &s.queues[1]).unwrap();
    let done = |t| cs::job_done(0, [gfx_done, 0, 0, sdma_done], t);
    let request = crate::amdgpu_vmid::GrabRequest {
        owner: y.owner,
        pd_addr: y.ptb,
        tlb_seq: 0,
        pasid: y.pasid,
        ring: cs::ring_index(0, 3),
    };
    if done(tx) {
        return TestResult::Fail("stalled gfx job reads complete");
    }
    let Some(gy) = vmids.grab(request, &done) else {
        return TestResult::Fail("SDMA client waited for the gfx client");
    };
    if gy.vmid == gx.vmid || !gy.needs_flush {
        return TestResult::Fail("SDMA job retargeted the running gfx job's VMID");
    }
    let mut space = BTreeMap::new();
    space.insert(u64::MAX, y.ptb);
    space.insert(IB_VA, y.ib_mc);
    space.insert(DST_VA, y.dst_mc);
    s.hw.io.vms.insert(gy.vmid, space);
    let mut words = pm4::sdma_write(DST_VA, 0x0b).to_vec();
    words.extend([pm4::SDMA_NOP; 3]);
    for (k, w) in words.iter().enumerate() {
        s.hw.io.mem.insert(y.ib_mc + k as u64 * 4, *w);
    }
    let mut sdma_state = RingState::default();
    let seq = submit(
        &mut s.hw,
        &mut s.queues[1],
        &mut sdma_state,
        Ring::Sdma(1),
        cs::vm_ref(&request, gy),
        cs::entity(y.owner, 1),
        &[Ib {
            va: IB_VA,
            dwords: words.len() as u32,
        }],
    );
    let Ok(seq) = seq else {
        return TestResult::Fail("SDMA submission refused");
    };
    vmids.commit(
        request,
        gy,
        u64::from(cs::ring_index(0, 3)) << 32 | u64::from(seq),
    );
    // X's job now runs, after Y's: its context still points at X's root.
    g.hw.io.stalled[0] = false;
    g.queue.commit(&mut g.hw.io, g.hw.layout);
    let ptb = |m: &Model, vmid: u8| m.reg(PTB_LO_ADDR + 8 * u64::from(vmid));
    if run(wait_fence(&mut g.hw, &g.queue, tx as u32)).is_err()
        || run(wait_fence(&mut s.hw, &s.queues[1], seq)).is_err()
        || g.hw.io.word(x.dst_mc) != 0x0a
        || s.hw.io.word(y.dst_mc) != 0x0b
        || ptb(&g.hw.io, gx.vmid) != x.ptb as u32
        || ptb(&s.hw.io, gy.vmid) != y.ptb as u32
        || s.hw.io.flushes != [(14, gy.vmid)]
        || s.hw.io.reg(LUT_ADDR + 4 * u64::from(gy.vmid)) != u32::from(y.pasid)
    {
        return TestResult::Fail("concurrent clients' translations crossed");
    }
    // Y next on gfx while its SDMA flush may still be pending elsewhere
    // (last_flush on another ring, not yet known complete): it keeps its
    // VMID but flushes again on this ring, as grab_used requires.
    let pending = |t| cs::job_done(0, [u32::MAX, 0, 0, 0], t);
    let again = crate::amdgpu_vmid::GrabRequest {
        ring: cs::ring_index(0, 0),
        ..request
    };
    match vmids.grab(again, &pending) {
        Some(gr) if gr.vmid == gy.vmid && gr.needs_flush => TestResult::Pass,
        _ => TestResult::Fail("cross-ring reuse without the pending flush"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_vmid_clients_on_two_rings_keep_their_own_translations
);

fn rdna2_vm_writeback_precedes_client_ib_and_job_fence() -> TestResult {
    use crate::amdgpu_pm4_defs::PACKET3_RELEASE_MEM;
    let l = crate::amdgpu_cp_navi22::tests::layout();
    let ibs = [Ib {
        va: IB_VA,
        dwords: 4,
    }];
    let frame = Frame {
        gfx: true,
        engine: 0,
        sync: None,
        flush: Some(vm()),
        pasid_map: Some((0x10a0 + u32::from(VMID), PASID)),
        vm_fence: Some((0x3000, 7)),
        vmid: VMID,
        context_switch: true,
        ibs: &ibs,
        fence: 0x4000,
        seq: 7,
        wptr: 0,
    };
    let cp = encode_cp(l, &frame);
    let releases: Vec<_> = cp
        .iter()
        .enumerate()
        .filter(|(_, w)| **w == packet3(PACKET3_RELEASE_MEM, 6))
        .map(|(i, _)| i)
        .collect();
    let indirect = cp
        .iter()
        .position(|&w| w == packet3(PACKET3_INDIRECT_BUFFER, 2))
        .unwrap();
    if releases.len() != 2
        || releases[0] >= indirect
        || releases[1] <= indirect
        || cp[releases[0] + 3] != 0x3000
        || cp[releases[1] + 3] != 0x4000
    {
        return TestResult::Fail("CP VM and job completion use wrong address/order");
    }
    let sdma = encode_sdma(l, &frame);
    let releases: Vec<_> = sdma
        .windows(4)
        .enumerate()
        .filter(|(_, w)| w[0] == 5 | 3 << 16)
        .map(|(i, _)| i)
        .collect();
    let indirect = sdma
        .iter()
        .position(|&w| w == 4 | u32::from(VMID) << 16)
        .unwrap();
    if releases.len() != 2
        || releases[0] >= indirect
        || releases[1] <= indirect
        || sdma[releases[0] + 1] != 0x3000
        || sdma[releases[1] + 1] != 0x4000
    {
        return TestResult::Fail("SDMA VM and job completion use wrong address/order");
    }
    use crate::amdgpu_vmid::{GrabRequest, VmidManager};
    let mut manager = VmidManager::new(1, 2);
    let request = GrabRequest {
        owner: 123,
        pd_addr: 0x1000,
        tlb_seq: 0,
        pasid: 1,
        ring: 0,
    };
    let grant = manager.grab(request, &|_| false).unwrap();
    manager.commit_with_flush(request, grant, 7, 7 | 1 << 63);
    let cross_ring = GrabRequest { ring: 1, ..request };
    let grant2 = manager
        .grab(cross_ring, &|ticket| ticket & (1 << 63) != 0)
        .unwrap();
    if grant2.vmid != grant.vmid || grant2.needs_flush || grant2.map_pasid {
        return TestResult::Fail("completed VM programming waited for unrelated job completion");
    }
    let foreign = manager
        .grab(
            GrabRequest {
                owner: 456,
                ..cross_ring
            },
            &|ticket| ticket & (1 << 63) != 0,
        )
        .unwrap();
    if foreign.vmid == grant.vmid {
        return TestResult::Fail("VM fence completion freed a VMID with a running job");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_vm_writeback_precedes_client_ib_and_job_fence
);

fn rdna2_sequences_wrap_without_zero_or_false_device_loss() -> TestResult {
    let (_pool, mut e) = gfx_engine();
    let ib = install(&mut e.hw.io, false, 0x1234_5678);
    let mut state = RingState::default();
    e.queue.seq = u32::MAX - 1;
    e.hw.io.mem.insert(e.queue.address(FENCE), u32::MAX - 1);
    if submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        vm(),
        1,
        &[ib],
    ) != Ok(u32::MAX)
        || completed(&mut e.hw, &e.queue) != Ok(u32::MAX)
        || e.hw
            .io
            .word(e.queue.address(crate::amdgpu_cp_navi22::VM_FENCE))
            != u32::MAX
    {
        return TestResult::Fail("all-ones fence value mistaken for a removed GPU");
    }
    if submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        reused(),
        1,
        &[ib],
    ) != Ok(1)
        || completed(&mut e.hw, &e.queue) != Ok(1)
    {
        return TestResult::Fail("wrapped queue emitted reserved zero sequence");
    }
    // Revoke between the progress sample and frame publication: rollback
    // must restore MAX, not zero (the predecessor of the skipped sequence).
    e.queue.seq = u32::MAX;
    e.hw.io.mem.insert(e.queue.address(FENCE), u32::MAX);
    e.hw.io.revoke = Some((
        crate::amdgpu_cp_navi22::tests::layout().hdp + 0xd1 * 4,
        1,
        e.hw.authority,
    ));
    let before = e.queue.wptr;
    if submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        reused(),
        1,
        &[ib],
    ) != Err(Error::Revoked)
        || e.queue.seq != u32::MAX
        || e.queue.wptr != before
    {
        return TestResult::Fail("failed wrapped submission changed sequence or ring");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_sequences_wrap_without_zero_or_false_device_loss
);

fn rdna2_kernel_sdma_fill_copy_and_validation() -> TestResult {
    let vram = pool(1 << 20);
    let mut engine = crate::amdgpu_sdma_navi22_queues::Engine {
        hw: hw(enabled()),
        queues: alloc::vec![
            Queue::new(&vram, Kind::Sdma, doorbell::SDMA0, fence::Engine::Sdma0).unwrap()
        ],
        state: crate::amdgpu_sdma_navi22_queues::State::Prepared,
        proof: Default::default(),
    };
    if run(engine.start()).is_err() || run(engine.test_ib()).is_err() {
        return TestResult::Fail("kernel SDMA setup");
    }
    let ops = [
        KernelOp::Fill {
            dst: IB_MC,
            bytes: 32,
            value: 0x1234_abcd,
        },
        KernelOp::Copy {
            src: IB_MC,
            dst: DST_MC,
            bytes: 32,
        },
    ];
    let seq = submit_kernel(&mut engine.hw, &mut engine.queues[0], &ops).unwrap();
    if run(wait_fence(&mut engine.hw, &engine.queues[0], seq)).is_err()
        || (0..8).any(|i| engine.hw.io.word(DST_MC + i * 4) != 0x1234_abcd)
    {
        return TestResult::Fail("kernel SDMA fill/copy/fence execution");
    }
    let before = (
        engine.queues[0].wptr,
        engine.queues[0].seq,
        engine.hw.io.writes.len(),
    );
    for ops in [
        alloc::vec![],
        alloc::vec![KernelOp::Fill {
            dst: 3,
            bytes: 4,
            value: 0
        }],
        alloc::vec![KernelOp::Copy {
            src: 0x1000,
            dst: 0x1004,
            bytes: 16
        }],
        alloc::vec![KernelOp::Copy {
            src: u64::MAX,
            dst: DST_MC,
            bytes: 4
        }],
        alloc::vec![KernelOp::Fill {
            dst: 0,
            bytes: 1 << 40,
            value: 0
        }],
    ] {
        if submit_kernel(&mut engine.hw, &mut engine.queues[0], &ops) != Err(Error::Invalid)
            || (
                engine.queues[0].wptr,
                engine.queues[0].seq,
                engine.hw.io.writes.len(),
            ) != before
        {
            return TestResult::Fail("invalid kernel job mutated ring or MMIO");
        }
    }
    let words = kernel_words(
        &[KernelOp::Fill {
            dst: IB_MC,
            bytes: MAX_PACKET_BYTES + 4,
            value: 7,
        }],
        DST_MC,
        9,
    )
    .unwrap();
    if words[..10]
        != [
            11,
            IB_MC as u32,
            (IB_MC >> 32) as u32,
            7,
            (MAX_PACKET_BYTES - 1) as u32,
            11,
            (IB_MC + MAX_PACKET_BYTES) as u32,
            ((IB_MC + MAX_PACKET_BYTES) >> 32) as u32,
            7,
            3,
        ]
    {
        return TestResult::Fail("SDMA5 multi-packet count/address encoding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_kernel_sdma_fill_copy_and_validation
);
