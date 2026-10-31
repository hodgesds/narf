use super::*;
use crate::amdgpu_gfx12_queue::Job;

const SEM: u64 = MM + (0x575 + 1) * 4;
pub(super) fn mesa_ib() -> Vec<u32> {
    // radeon_vcn_dec_jpeg V3 shapes: a pitch write, IB-local condition
    // registers, a COND3 type-3 soft reset poll and NOP padding.
    vec![
        words::PITCH,
        0x1234,
        0x408e,
        0x01400200,
        0x408f,
        0x10000,
        0x33004051,
        0x10000,
        words::NOP,
        0,
    ]
}
pub(super) fn clients() -> (Pool, Engine<Fake>, Irqs) {
    let (pool, mut e, mut irq) = fixture_capacity(BYTES * 2 + cs::CLIENT_BYTES);
    e.io.regs.insert(SEM, 1);
    run(e.start(power())).unwrap();
    run(e.prove(&mut irq)).unwrap();
    e.open_clients().unwrap();
    assert_eq!(e.state, State::Clients);
    (pool, e, irq)
}
fn jpeg5_idle_keeps_slots_sequences_and_proof_without_gc_access() -> TestResult {
    let (_pool, mut e, _) = clients();
    let ibs = e.stage(0, &[mesa_ib()]).unwrap();
    let seq = e.submit(job(3, &ibs)).unwrap();
    assert!(run(e.idle()).unwrap());
    assert_eq!(e.state, State::Idle);
    assert!(!e.memory.reusable_for_test());
    assert!(!e.client_memory.as_ref().unwrap().reusable_for_test());
    e.io.regs.insert(GC + 0x13de * 4, u32::MAX);
    run(e.resume_idle(power(), &mut ())).unwrap();
    assert_eq!(e.state, State::Clients);
    assert_eq!(e.seq, seq);
    assert_eq!(e.io.regs[&(VCN + u64::from(IRQ) * 4)] & 0x100, 0x100);
    // Idle never discards the staged copies; reuse the original IB address.
    assert_eq!(e.submit(job(3, &ibs)), Ok(seq.wrapping_add(1)));
    assert!(run(e.idle()).unwrap());
    // Navi44 keeps static JPEG gating while board-admitted VCN/media clock
    // sleep runs. Static JPEG warm restore never uploads a DPG program.
    let mut clock_sleep = power();
    clock_sleep.enabled |= crate::amdgpu_navi48_media_power::FEATURES;
    clock_sleep.allowed |= crate::amdgpu_navi48_media_power::FEATURES;
    run(e.resume_idle(clock_sleep, &mut ())).unwrap();
    assert_eq!(e.seq, seq.wrapping_add(1));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-idle",
    jpeg5_idle_keeps_slots_sequences_and_proof_without_gc_access
);
fn jpeg5_idle_requires_completed_work_and_failed_resume_keeps_backing() -> TestResult {
    let (_pool, mut e, _) = clients();
    let ibs = e.stage(0, &[mesa_ib()]).unwrap();
    e.io.advance = false;
    e.submit(job(3, &ibs)).unwrap();
    let writes = e.io.writes.len();
    assert!(!run(e.idle()).unwrap());
    assert!(e.io.writes[writes..].iter().all(|&(at, _)| at == 0x7f000));
    // A separate drained owner exercises failed restoration.
    let (_pool, mut e, _) = clients();
    assert!(run(e.idle()).unwrap());
    e.io.ignored = Some(VCN + u64::from(DB) * 4);
    assert!(run(e.resume_idle(power(), &mut ())).is_err());
    let writes = e.io.writes.len();
    assert_eq!(run(e.resume_idle(power(), &mut ())), Err(Error::DeviceGone));
    assert_eq!(e.io.writes.len(), writes);
    assert!(!e.memory.reusable_for_test());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-idle",
    jpeg5_idle_requires_completed_work_and_failed_resume_keeps_backing
);
fn jpeg5_cancelled_idle_or_restore_never_replays_or_releases_backing() -> TestResult {
    for wake in [false, true] {
        let (_pool, mut e, _) = clients();
        if wake {
            assert!(run(e.idle()).unwrap());
            e.io.power_stuck = true;
            let mut sram = ();
            let mut future = core::pin::pin!(e.resume_idle(power(), &mut sram));
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        } else {
            e.io.regs.insert(VCN + u64::from(CLEAN) * 4, 0);
            let mut future = core::pin::pin!(e.idle());
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        let writes = e.io.writes.len();
        assert_eq!(run(e.idle()), Err(Error::DeviceGone));
        assert_eq!(run(e.resume_idle(power(), &mut ())), Err(Error::DeviceGone));
        assert_eq!(run(e.stop()), Err(Error::Busy));
        assert_eq!(e.io.writes.len(), writes);
        assert!(!e.memory.reusable_for_test());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-idle",
    jpeg5_cancelled_idle_or_restore_never_replays_or_releases_backing
);
fn job(vmid: u8, ibs: &[(u64, u32)]) -> Job {
    let mut job = Job::new(vmid, 0x8001, 0x1_2345_6000, ibs).unwrap();
    job.vmid = vmid;
    job
}

fn jpeg5_client_ib_validation_follows_linux_and_excludes_privileged_registers() -> TestResult {
    assert_eq!(cs::validate_ib(&mesa_ib()), Ok(()));
    for bad in [
        vec![],
        vec![words::PITCH],
        vec![0x3fff, 0],                 // below JPEG_REG_RANGE_START
        vec![0x41c3, 0],                 // past JPEG_REG_RANGE_END
        vec![0x4120, 0],                 // atomic range
        vec![words::PITCH | 1 << 18, 0], // reserved bits
        vec![0x20000000, 0],             // TYPE2 (IB launch)
        vec![0x70000000, 0],             // TYPE7 (trap)
        vec![0x13004043, 0],             // TYPE0 with COND3
    ] {
        assert_eq!(cs::validate_ib(&bad), Err(Error::Invalid), "{bad:x?}");
    }
    for reg in [
        0x404d, 0x404e, 0x404f, 0x4080, 0x4082, 0x4084, 0x4085, 0x4089, 0x408d, 0x4094, 0x40a0,
        0x40a4, 0x40a6, 0x40ab, 0x40ac, 0x40af, 0x40b6, 0x40b7, 0x40bf,
    ] {
        assert_eq!(cs::validate_ib(&[reg, 0]), Err(Error::Invalid), "{reg:x}");
        assert_eq!(
            cs::validate_ib(&[reg | 0x33000000, 0]),
            Err(Error::Invalid),
            "{reg:x}"
        );
    }
    // Neighbours Mesa programs remain writable.
    for reg in [
        0x404b, 0x4051, 0x4052, 0x408e, 0x408f, 0x40b2, 0x40b5, 0x40e0, 0x40e3, 0x41c2,
    ] {
        assert_eq!(cs::validate_ib(&[reg, 0]), Ok(()), "{reg:x}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_client_ib_validation_follows_linux_and_excludes_privileged_registers
);

fn jpeg5_client_frame_matches_linux_flush_pasid_and_vmid_split() -> TestResult {
    let mm = (MM / 4) as u32;
    let oss = (OSS / 4) as u32;
    let mut j = job(3, &[(0x8_0010_0000, 10), (0x8_0010_0100, 16)]);
    j.pasid = 0x8003;
    let words = cs::frame(&j, mm, oss, 0x8_0000_5000, 0x8_0000_6000, 7).unwrap();
    let ext = |reg: u32| (reg & 0x1ffff) << 2;
    let mut at = 0;
    let mut expect = |w: &[u32]| {
        assert_eq!(&words[at..at + w.len()], w, "at {at}");
        at += w.len();
    };
    // Semaphore acquire on engine 1, PTB lo/hi, request/ack, release, PTB wait.
    expect(&[
        0x4085,
        0x01400200,
        0x4084,
        1,
        0x1bfff,
        ext(mm + 0x576),
        0x30018000,
        1,
    ]);
    expect(&[0x1bfff, ext(mm + 0x5cf + 6), 0x18000, 0x2345_6000]);
    expect(&[0x1bfff, ext(mm + 0x5d0 + 6), 0x18000, 1]);
    expect(&[
        0x1bfff,
        ext(mm + 0x588),
        0x18000,
        crate::amdgpu_vmhub_regs::invalidate_req(3, 0),
    ]);
    expect(&[
        0x4085,
        0x01400200,
        0x4084,
        8,
        0x1bfff,
        ext(mm + 0x59a),
        0x30018000,
        8,
    ]);
    expect(&[0x1bfff, ext(mm + 0x576), 0x18000, 0]);
    expect(&[
        0x4085,
        0x01400200,
        0x4084,
        0x2345_6000,
        0x1bfff,
        ext(mm + 0x5cf + 6),
        0x30018000,
        u32::MAX,
    ]);
    // IH_VMID_0_LUT_MM, insert_start, HDP flush.
    expect(&[0x1bfff, ext(oss + 0x13), 0x18000, 0x8003]);
    expect(&[0x1bfff, 0x69004, 0x18000, 0x80010000]);
    expect(&[0x1bfff, 0x7f000, 0x18000, 0]);
    for (address, dwords) in [(0x8_0010_0000u64, 10), (0x8_0010_0100, 16)] {
        expect(&[0x40a4, 0, 0x40a6, 0x333, 0x40b6, address as u32, 0x40b7, 8]);
        expect(&[0x4082, dwords, 0x42d4, 0x5000, 0x42d5, 8, 0x20000000, 0]);
        expect(&[0x4085, 0x01400200, 0x4084, 2, 0x33004089, 2]);
    }
    expect(&[0x404e, 7, 0x404f, 7, 0x40ab, 0x6000, 0x40ac, 8, 0x404d, 8]);
    expect(&[0x4000404d, 0, words::NOP, 0, words::NOP, 0, 0x70000000, 0]);
    expect(&[0x1bfff, 0x69004, 0x18000, 0x10000]);
    assert_eq!(at, words.len());
    // Without flush/PASID the frame starts at insert_start.
    let (mut quiet, ibs) = (j, [(0x8_0010_0000u64, 2u32); 8]);
    quiet.flush = false;
    quiet.map_pasid = false;
    assert_eq!(
        cs::frame(&quiet, mm, oss, 0x8_0000_5000, 0x8_0000_6000, 1).unwrap()[1],
        0x69004
    );
    // Eight IBs with flush and PASID still fit the 256-dword frame budget.
    let full = job(1, &ibs);
    assert!(
        cs::frame(&full, mm, oss, 0x8_0000_5000, 0x8_0000_6000, 1)
            .unwrap()
            .len()
            <= 256
    );
    for bad in [0u8, 16] {
        let mut b = j;
        b.vmid = bad;
        assert_eq!(
            cs::frame(&b, mm, oss, 0x5000, 0x6000, 1),
            Err(Error::Invalid)
        );
    }
    let mut b = j;
    b.ibs[0].0 += 4; // amdgpu_ib_get places copies 256-byte aligned
    assert_eq!(
        cs::frame(&b, mm, oss, 0x5000, 0x6000, 1),
        Err(Error::Invalid)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_client_frame_matches_linux_flush_pasid_and_vmid_split
);

fn jpeg5_client_ring_wraps_and_runs_staged_copies_at_client_vmid() -> TestResult {
    let (_pool, mut e, _) = clients();
    let reader = |e: &mut Engine<Fake>| {
        let map = e.memory.mapping();
        cs::client_fence(&mut e.io, e.authority, e.layout, map).unwrap()
    };
    let start = e.seq;
    // Enough frames to wrap the 1024-dword ring several times.
    for n in 0..24u32 {
        let slot = n as usize % cs::SLOTS;
        let mut ib = mesa_ib();
        ib[1] = 0x1000 + n;
        let staged = e.stage(slot, &[ib.clone(), ib]).unwrap();
        assert_eq!(staged.len(), 2);
        assert_eq!(staged[1].0 - staged[0].0, 256);
        let base = e.client_memory.as_ref().unwrap().address();
        assert_eq!(staged[0].0, base + slot as u64 * cs::SLOT_BYTES);
        let mut j = job(1 + (n % 7) as u8, &staged);
        j.flush = n % 3 == 0;
        j.map_pasid = n % 5 == 0;
        let seq = e.submit(j).unwrap();
        assert_eq!(seq, start.wrapping_add(n + 1));
        assert_eq!(reader(&mut e), seq);
        assert_eq!(e.io.regs[&(VCN + u64::from(PITCH) * 4)], 0x1000 + n);
        let ran = &e.io.client_ibs[e.io.client_ibs.len() - 2..];
        assert!(ran
            .iter()
            .all(|&(vmid, _, dw)| vmid == u32::from(j.vmid) && dw == 10));
        assert_eq!(e.wptr, e.io.regs[&(VCN + u64::from(RPTR) * 4)]);
        assert!(e.wptr < 1024);
    }
    assert!(e.io.client_ibs.len() == 48);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_client_ring_wraps_and_runs_staged_copies_at_client_vmid
);

fn jpeg5_client_submission_rejects_unstaged_ibs_and_backpressures_full_ring() -> TestResult {
    let (_pool, mut e, _) = clients();
    // Only staged kernel copies may run at VMID0.
    let base = e.client_memory.as_ref().unwrap().address();
    for ib in [
        (0x8_0000_0000u64, 2u32),
        (base - 256, 2),
        (base + cs::CLIENT_BYTES, 2),
        (base + cs::SLOT_BYTES - 256, 128), // crosses into the next slot
    ] {
        assert_eq!(e.submit(job(1, &[ib])), Err(Error::Invalid), "{ib:x?}");
    }
    assert_eq!(e.state, State::Clients);
    // Staging validates again and bounds each slot.
    assert_eq!(e.stage(0, &[vec![0x40a6, 0]]), Err(Error::Invalid));
    assert_eq!(e.stage(cs::SLOTS, &[mesa_ib()]), Err(Error::Invalid));
    let huge = {
        let mut w = Vec::new();
        while (w.len() as u64) * 4 < cs::SLOT_BYTES {
            w.extend_from_slice(&[words::NOP, 0]);
        }
        w.extend_from_slice(&[words::NOP, 0]);
        w
    };
    assert_eq!(e.stage(0, &[huge]), Err(Error::Invalid));
    // A stalled decoder fills the ring; the next frame waits (Busy) without
    // writing, and no sequence is consumed.
    e.io.advance = false;
    let staged = e.stage(1, &[mesa_ib()]).unwrap();
    let mut accepted = 0;
    let before = e.seq;
    loop {
        match e.submit(job(2, &staged)) {
            Ok(_) => accepted += 1,
            Err(Error::Busy) => break,
            Err(other) => panic!("{other:?}"),
        }
    }
    assert!(accepted >= 3);
    assert_eq!(e.seq, before.wrapping_add(accepted));
    let wptr = e.wptr;
    assert_eq!(e.submit(job(2, &staged)), Err(Error::Busy));
    assert_eq!((e.wptr, e.state), (wptr, State::Clients));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_client_submission_rejects_unstaged_ibs_and_backpressures_full_ring
);

fn jpeg5_hung_client_ring_retires_by_jmi_reset_and_reopens_after_reproof() -> TestResult {
    let (pool, mut e, mut irq) = clients();
    e.io.advance = false;
    let staged = e.stage(0, &[mesa_ib()]).unwrap();
    let hung = e.submit(job(1, &staged)).unwrap();
    // Ordinary stop needs a drained ring; a hung one must use reset_stop.
    assert_eq!(run(e.stop()), Err(Error::Timeout));
    assert_eq!(e.state, State::Failed(Error::Timeout));
    assert!(!e.client_memory.as_ref().unwrap().reusable_for_test());
    run(e.reset_stop()).unwrap();
    assert_eq!(e.state, State::Stopped);
    assert!(e.memory.reusable_for_test());
    assert!(e.client_memory.as_ref().unwrap().reusable_for_test());
    assert_eq!(e.io.regs[&(VCN + u64::from(JMI) * 4)] & 1, 1);
    assert_eq!(e.io.regs[&(VCN + u64::from(DB) * 4)] & (1 << 30), 0);
    assert_eq!(e.io.regs[&(NBIO + u64::from(RANGE) * 4)], RANGE_VALUE);
    // Restart, re-prove and reopen; the retained arena keeps staged copies.
    e.io.advance = true;
    e.io.regs.insert(VCN + u64::from(RPTR) * 4, 0);
    run(e.start(power())).unwrap();
    let proof = run(e.prove(&mut irq)).unwrap();
    assert_eq!(proof.sequence, hung.wrapping_add(1).max(1));
    e.open_clients().unwrap();
    let replay = e.submit(job(1, &staged)).unwrap();
    assert_eq!(replay, proof.sequence.wrapping_add(1));
    let map = e.memory.mapping();
    assert_eq!(
        cs::client_fence(&mut e.io, e.authority, e.layout, map),
        Ok(replay)
    );
    run(e.stop()).unwrap();
    assert!(e.client_memory.as_ref().unwrap().reusable_for_test());
    let available = pool.available();
    drop(e);
    assert_eq!(pool.available(), available + BYTES + cs::CLIENT_BYTES);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_hung_client_ring_retires_by_jmi_reset_and_reopens_after_reproof
);

fn jpeg5_reset_stop_without_clean_dma_keeps_every_arena_published() -> TestResult {
    for missing in [1, 0x100, 0x10000] {
        let (pool, mut e, _) = clients();
        e.io.advance = false;
        let staged = e.stage(2, &[mesa_ib()]).unwrap();
        e.submit(job(4, &staged)).unwrap();
        e.io.regs
            .insert(VCN + u64::from(CLEAN) * 4, 0x1010f & !missing);
        assert_eq!(run(e.reset_stop()), Err(Error::Timeout));
        assert_eq!(e.state, State::Failed(Error::Timeout));
        assert!(!e.memory.reusable_for_test());
        assert!(!e.client_memory.as_ref().unwrap().reusable_for_test());
        // Neither restart nor ordinary submission is possible now.
        assert_eq!(run(e.start(power())), Err(Error::Busy));
        assert_eq!(e.submit(job(4, &staged)), Err(Error::Busy));
        let available = pool.available();
        drop(e);
        assert_eq!(pool.available(), available);
    }
    // Cancellation inside reset_stop also retains everything.
    let (_pool, mut e, _) = clients();
    e.io.regs.insert(VCN + u64::from(CLEAN) * 4, 0);
    {
        let mut f = core::pin::pin!(e.reset_stop());
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.state, State::Stopping);
    assert!(!e.client_memory.as_ref().unwrap().reusable_for_test());
    assert_eq!(run(e.reset_stop()), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_reset_stop_without_clean_dma_keeps_every_arena_published
);
