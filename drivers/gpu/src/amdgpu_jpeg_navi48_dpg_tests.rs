use super::*;
use crate::amdgpu_navi48_media_power::tests::Transport;
pub(super) fn replay(io: &mut Fake) {
    let program = io.sram.lock().take();
    let Some(words) = program else {
        return;
    };
    for pair in words.chunks_exact(2) {
        let reg = match pair[0] {
            0x4161 => CG_CTRL,
            0x4160 => CG_GATE,
            0x404a => ADDR_CONFIG,
            0x4141 => IRQ,
            0x29 => continue,
            _ => panic!("invalid JPEG5 internal SRAM address"),
        };
        io.regs.insert(VCN + u64::from(reg) * 4, pair[1]);
    }
}
fn jpeg5_dpg_sram_ack_does_not_replace_the_physical_fence_witness() -> TestResult {
    let (_pool, mut e, _) = cs_tests::clients();
    let mut sram = Transport::new(e.io.sram.clone());
    let sequence = e.seq;
    e.io.fence = false;
    assert_eq!(run(e.enable_dpg(&mut sram)), Err(Error::Timeout));
    assert_eq!(e.seq, sequence);
    assert_eq!(e.state, State::Failed(Error::Timeout));
    assert!(!e.memory.reusable_for_test());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-dpg",
    jpeg5_dpg_sram_ack_does_not_replace_the_physical_fence_witness
);
fn jpeg5_dpg_uses_jpeg_internal_sram_addresses_and_keeps_copy_slots() -> TestResult {
    let (_pool, mut e, _) = cs_tests::clients();
    let mut sram = Transport::new(e.io.sram.clone());
    let ibs = e.stage(0, &[cs_tests::mesa_ib()]).unwrap();
    let saved = e.io.client.clone();
    let seq = e.seq;
    assert!(run(e.enable_dpg(&mut sram)).unwrap());
    assert_eq!(
        sram.images,
        vec![(
            true,
            vec![0x4161, 0x83, 0x4160, 0, 0x404a, 0x545, 0x4141, 0x100, 0x29, 0]
        )]
    );
    assert_eq!(e.state, State::Clients);
    assert_eq!(e.seq, seq);
    assert_eq!(e.io.client, saved);
    assert!(!e.client_memory.as_ref().unwrap().reusable_for_test());
    e.io.regs.insert(GC + 0x13de * 4, u32::MAX);
    for n in 0..2 {
        e.io.regs.insert(VCN + u64::from(STATUS) * 4, u32::MAX);
        let map = e.memory.mapping();
        assert_eq!(
            cs::retained_fence(&mut e.io, e.authority, e.layout, map, false),
            Ok(seq + n)
        );
        e.io.regs.insert(VCN + u64::from(STATUS) * 4, 1);
        assert!(run(e.idle()).unwrap());
        run(e.resume_idle(power(), &mut sram)).unwrap();
        let job = crate::amdgpu_gfx12_queue::Job::new(3, 0x42, 0x1_0000_8001, &ibs).unwrap();
        assert_eq!(e.submit(job), Ok(seq + n + 1));
    }
    assert_eq!(sram.images.len(), 3);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-dpg",
    jpeg5_dpg_uses_jpeg_internal_sram_addresses_and_keeps_copy_slots
);

fn jpeg5_dpg_hung_recovery_performs_static_jmi_reset_and_power_cycle() -> TestResult {
    let (_pool, mut e, _) = cs_tests::clients();
    let mut sram = Transport::new(e.io.sram.clone());
    run(e.enable_dpg(&mut sram)).unwrap();
    e.io.advance = false;
    let ibs = e.stage(0, &[cs_tests::mesa_ib()]).unwrap();
    let job = crate::amdgpu_gfx12_queue::Job::new(3, 0x42, 0x1_0000_8001, &ibs).unwrap();
    e.submit(job).unwrap();
    assert!(!run(e.idle()).unwrap());
    e.io.writes.clear();
    run(e.reset_stop()).unwrap();
    let find = |reg, mask, value| {
        e.io.writes
            .iter()
            .position(|&(at, v)| at == VCN + u64::from(reg) * 4 && v & mask == value)
            .unwrap()
    };
    assert!(find(POWER, 0x10, 0) < find(JMI, 1, 1));
    assert!(find(JMI, 1, 1) < find(DLDO_CONFIG, 0x30, 0x20));
    assert!(e.client_memory.as_ref().unwrap().reusable_for_test());
    assert_eq!(e.state, State::Stopped);
    run(e.start(power())).unwrap();
    assert!(!e.dpg);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-dpg",
    jpeg5_dpg_hung_recovery_performs_static_jmi_reset_and_power_cycle
);

fn jpeg5_dpg_sram_cancellation_and_failure_cannot_resume_or_publish() -> TestResult {
    for fail in [false, true] {
        let (_pool, mut e, _) = cs_tests::clients();
        let mut sram = Transport::new(e.io.sram.clone());
        if fail {
            sram.error = Some(crate::amdgpu_psp_ring::Error::Timeout);
            assert!(run(e.enable_dpg(&mut sram)).is_err());
        } else {
            sram.stall = true;
            let mut future = core::pin::pin!(e.enable_dpg(&mut sram));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
        }
        assert!(!e.memory.reusable_for_test());
        assert!(!e.client_memory.as_ref().unwrap().reusable_for_test());
        let writes = e.io.writes.len();
        assert_eq!(run(e.enable_dpg(&mut sram)), Err(Error::DeviceGone));
        assert!(e.stage(0, &[cs_tests::mesa_ib()]).is_err());
        assert_eq!(e.io.writes.len(), writes);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-dpg",
    jpeg5_dpg_sram_cancellation_and_failure_cannot_resume_or_publish
);
