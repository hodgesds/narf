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

fn vm(generation: u64) -> VmRef {
    VmRef {
        vmid: VMID,
        generation,
        page_table_base: PTB,
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
        vm(7),
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
        vm(7),
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
    // A new owner of the VMID (generation) is flushed again before use.
    let third = submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        vm(8),
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
        vm(1),
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
        ],
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
        vm(1),
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
        validate(Ring::Gfx, VmRef { vmid: 0, ..vm(1) }, &[ib]),
        validate(Ring::Gfx, VmRef { vmid: 16, ..vm(1) }, &[ib]),
        validate(Ring::Gfx, vm(1), &[]),
        validate(Ring::Gfx, vm(1), &[ib; MAX_IBS + 1]),
        validate(
            Ring::Gfx,
            vm(1),
            &[Ib {
                va: 0x1002,
                dwords: 4,
            }],
        ),
        validate(
            Ring::Gfx,
            vm(1),
            &[Ib {
                va: 0x1000,
                dwords: 0,
            }],
        ),
        validate(
            Ring::Sdma(0),
            vm(1),
            &[Ib {
                va: 0x1010,
                dwords: 4,
            }],
        ),
    ];
    if bad.iter().any(|r| *r != Err(Error::Invalid)) || validate(Ring::Gfx, vm(1), &[ib]).is_err() {
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
        vm(1),
        1,
        &[ib],
    );
    let second = submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        vm(1),
        1,
        &[ib],
    );
    let wptr = e.queue.wptr;
    let third = submit(
        &mut e.hw,
        &mut e.queue,
        &mut state,
        Ring::Gfx,
        vm(1),
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
            flush: Some(vm(1)),
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
        || words[26..29] != [packet3(PACKET3_CONTEXT_CONTROL, 1), 0x8101_8003, 0]
    {
        return TestResult::Fail("gfx VM flush / context control encoding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_submit_encodes_linux_vm_flush
);
