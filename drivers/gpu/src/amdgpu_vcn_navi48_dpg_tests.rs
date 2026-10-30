use super::*;
use crate::amdgpu_navi48_media_power::tests::Transport;
pub(super) fn replay(io: &mut Fake) {
    let program = io.sram.lock().take();
    let Some(words) = program else {
        return;
    };
    // The fake aperture is outside SOC24's translated windows. Model PSP's
    // indirect firmware/stack patching and restore into the hardware registers.
    for pair in words.chunks_exact(2) {
        let reg = pair[0] - (VCN / 4) as u32;
        let value = match reg {
            0x2cf => IMAGE as u32,
            0x2d0 => (IMAGE >> 32) as u32,
            0x1c1 => 0x2000,
            0x2fb => GPU as u32,
            0x2fc => (GPU >> 32) as u32,
            _ => pair[1],
        };
        io.regs.insert(VCN + u64::from(reg) * 4, value);
    }
    io.regs.insert(VCN + 0x183 * 4, 2);
}
fn ready() -> (Pool, Engine<Fake>, Transport) {
    let (pool, mut e, mut irq) = ib_ready();
    run(e.prove_ibs(&mut irq)).unwrap();
    let sram = Transport::new(e.io.sram.clone());
    (pool, e, sram)
}
fn vcn5_dpg_sram_ack_requires_a_new_physical_execution_witness() -> TestResult {
    let (_pool, mut e, mut sram) = ready();
    let sequence = e.seq;
    e.io.fence = false;
    assert_eq!(run(e.enable_dpg(&mut sram)), Err(Error::Timeout));
    assert_eq!(e.state, State::Failed(Error::Timeout));
    assert_eq!(sram.images.len(), 1);
    assert_eq!(e.seq, sequence);
    assert!(!e.memory.reusable_for_test());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-dpg",
    vcn5_dpg_sram_ack_requires_a_new_physical_execution_witness
);
fn vcn5_dpg_program_uses_soc24_addresses_and_psp_placeholders() -> TestResult {
    assert_eq!(dpg::offset(0x1f800, 0x1d6), 0xd6);
    assert_eq!(dpg::offset(0x1f800, 0x42), 0xc042);
    assert_eq!(dpg::offset(0x1f800, 0x330), 0x230);
    assert_eq!(dpg::offset(0x48000, 0xc0), 0);
    assert_eq!(dpg::offset(0x48000, 0x14), 0xc014);
    let (_pool, mut e, mut sram) = ready();
    let seq = e.seq;
    assert!(run(e.enable_dpg(&mut sram)).unwrap());
    let expected = [
        0x41d6,
        0x1ff00200,
        0x4121,
        0,
        0x4330,
        0x307308,
        0x42cf,
        0,
        0x42d0,
        0,
        0x41c0,
        0,
        0x41c1,
        0,
        0x42fb,
        0,
        0x42fc,
        0,
        0x41c2,
        0,
        0x41c3,
        0x20000,
        0x42ff,
        (GPU + 0x20000) as u32,
        0x4300,
        ((GPU + 0x20000) >> 32) as u32,
        0x41c4,
        0,
        0x41c5,
        0x80000,
        0x42cb,
        (GPU + 0xa0000) as u32,
        0x42cc,
        ((GPU + 0xa0000) >> 32) as u32,
        0x41d2,
        0,
        0x41d3,
        0x1000,
        0x4042,
        0x545,
        0x41d6,
        0xff00200,
        0x432e,
        0x3e0000,
        0x4121,
        2,
    ];
    assert_eq!(sram.images, vec![(false, expected.to_vec())]);
    assert_eq!(e.state, State::IbVerified);
    assert_eq!(e.seq, seq);
    assert!(!e.memory.reusable_for_test());
    assert_eq!(e.io.regs[&(VCN + 0x2cf * 4)], IMAGE as u32);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-dpg",
    vcn5_dpg_program_uses_soc24_addresses_and_psp_placeholders
);

fn vcn5_dpg_idle_reloads_sram_preserving_sessions_and_client_fences() -> TestResult {
    let (_pool, mut e, mut sram) = ready();
    e.io.store(0x20080, 0xdead1234);
    run(e.enable_dpg(&mut sram)).unwrap();
    e.io.regs.insert(GC + 0x13de * 4, u32::MAX);
    let seq = e.seq;
    for cycle in 0..2 {
        // DPG may remove STATUS between client submissions; VRAM is retained.
        e.io.regs.insert(VCN + 0x183 * 4, u32::MAX);
        assert_eq!(e.completed_job(), Ok(seq + cycle));
        e.io.regs.insert(VCN + 0x183 * 4, 2);
        assert!(run(e.idle()).unwrap());
        assert_eq!(e.state, State::Idle);
        assert_eq!(e.io.word(0x20080), 0xdead1234);
        assert!(!e.memory.reusable_for_test());
        let mut power = power();
        power.enabled |= crate::amdgpu_navi48_media_power::FEATURES;
        power.allowed |= crate::amdgpu_navi48_media_power::FEATURES;
        run(e.resume_idle(IMAGE, power, &mut sram)).unwrap();
        let job =
            crate::amdgpu_gfx12_queue::Job::new(3, 0x42, 0x1_0000_8001, &[(0x2_0000_1000, 64)])
                .unwrap();
        assert_eq!(e.submit(job), Ok(seq + cycle + 1));
    }
    assert_eq!(sram.images.len(), 3);
    // A full stop adds DPG pause/ACK, then the existing LMI drain/reset.
    run(e.stop()).unwrap();
    assert!(e.memory.reusable_for_test());
    assert!(e
        .io
        .writes
        .iter()
        .all(|&(at, value)| at != VCN + 0x14 * 4 || value & 8 == 0));
    assert_eq!(e.io.regs[&(VCN + 0x1d6 * 4)] & VCPU_RESET, VCPU_RESET);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-dpg",
    vcn5_dpg_idle_reloads_sram_preserving_sessions_and_client_fences
);

fn vcn5_dpg_sram_failure_cancellation_and_revocation_close_publication() -> TestResult {
    for kind in 0..3 {
        let (_pool, mut e, mut sram) = ready();
        if kind == 0 {
            sram.stall = true;
            let mut future = core::pin::pin!(e.enable_dpg(&mut sram));
            let mut cx = Context::from_waker(Waker::noop());
            // Static shutdown has no waits in this fixture; the pending SRAM
            // transaction is the first yield and must quarantine publication.
            assert!(future.as_mut().poll(&mut cx).is_pending());
        } else {
            if kind == 1 {
                sram.error = Some(crate::amdgpu_psp_ring::Error::Timeout);
            } else {
                sram.revoke = Some(e.authority);
            }
            assert!(run(e.enable_dpg(&mut sram)).is_err());
        }
        assert!(matches!(e.state, State::IdleStarting | State::Failed(_)));
        assert!(!e.memory.reusable_for_test());
        let writes = e.io.writes.len();
        assert_eq!(run(e.enable_dpg(&mut sram)), Err(Error::DeviceGone));
        assert!(run(e.stop()).is_err());
        assert_eq!(e.io.writes.len(), writes);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-dpg",
    vcn5_dpg_sram_failure_cancellation_and_revocation_close_publication
);
