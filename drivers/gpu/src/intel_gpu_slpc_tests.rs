// Independent MIT Linux b90c984d vectors: xe_guc_pc.c pc_action_*,
// pc_init_fused_rp_values, pc_adjust_freq_bounds; abi/guc_actions_slpc_abi.h
// task_state_data offset 128, frequency offset 132 and 50/3 MHz units.
use crate::intel_gpu_slpc::{FrequencyRange, PowerProfile, SlpcState};

fn response(memory: &Words, fence: u16, hxg: u32) {
    let mut words = memory.borrow_mut();
    let tail = words[513];
    words[2048 + (tail & 4095) as usize] = 1 | u32::from(fence) << 16;
    words[2048 + ((tail + 1) & 4095) as usize] = hxg;
    words[513] = (tail + 2) & 4095;
}

pub(super) fn service(w: &Window, memory: &Words, control_fence: u16, request: &[u32]) {
    let mode = SLPC_FIXTURE_MODE.load(core::sync::atomic::Ordering::Relaxed);
    assert_eq!(request.len(), 4);
    if request[1] == 2 {
        assert_eq!((control_fence, request[3]), (0xfffe, 0));
        let shared = w.0.borrow().memory[&request[2]].clone();
        assert_eq!(shared.borrow().len(), 2048);
        assert_eq!(shared.borrow()[0], 8192);
        // Firmware defaults may exceed RP0. Source requires querying, then
        // clamping to fused limits rather than trusting these defaults.
        shared.borrow_mut()[33] = (54 << 8) | 210; // 900/3500 MHz.
        match mode {
            1 => shared.borrow_mut()[1] = 5,
            2 => failure_response(memory, control_fence),
            3 => {}
            _ => shared.borrow_mut()[1] = 3,
        }
        return;
    }
    assert!((0x8000..0xfffe).contains(&control_fence));
    let shared =
        w.0.borrow()
            .memory
            .values()
            .find(|m| m.borrow().len() == 2048 && m.borrow()[0] == 8192)
            .expect("SLPC backing")
            .clone();
    match request[1] {
        0x502 => {
            let address =
                w.0.borrow()
                    .memory
                    .iter()
                    .find(|(_, m)| Rc::ptr_eq(m, &shared))
                    .map(|(a, _)| *a)
                    .unwrap();
            assert_eq!(&request[2..], &[address, 0]);
            if mode == 5 {
                return;
            } // Published query never ACKed.
            if mode == 6 {
                shared.borrow_mut()[33] = 0;
            }
            if mode == 10 {
                shared.borrow_mut()[33] ^= 1;
            }
        }
        0x602 => {
            match request[2] {
                6 => {
                    let raw = (request[3] * 3 + 25) / 50;
                    let old = shared.borrow()[33];
                    shared.borrow_mut()[33] = (old & !0xff00) | raw << 8;
                }
                7 => {
                    let raw = (request[3] * 3 + 25) / 50;
                    let old = shared.borrow()[33];
                    shared.borrow_mut()[33] = (old & !255) | raw;
                }
                27 | 28 => assert!(request[3] <= 1),
                _ => panic!("unknown SLPC parameter"),
            }
            if mode == 4 {
                failure_response(memory, control_fence);
                return;
            }
        }
        _ => panic!("bad SLPC event"),
    }
    if mode == 7 {
        // A stale response cannot complete a later command.
        response(memory, control_fence - 1, 0xf0000000);
    } else if mode == 9 {
        response(memory, control_fence, 0xb0000001); // BUSY, progress only.
    } else if mode == 8 {
        SLPC_FIXTURE_MODE.store(0, core::sync::atomic::Ordering::Relaxed);
        response(memory, control_fence, 0xd0000000); // RETRY, no success yet.
    } else {
        response(memory, control_fence, 0xf0000000);
    }
}

fn drive(gt: &mut GuCGt<Window, Arena>, w: &Window, now: u64) {
    let mut registered = BTreeMap::new();
    for n in now..now + 32 {
        service_contexts(w, &mut registered, true);
        assert_eq!(gt.poll(n), Poll::Ready(Ok(GtState::SchedulingReady)));
    }
}

fn smoke_slpc_fused_bounds_and_acknowledged_controls() -> TestResult {
    for (platform, ack) in [
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
        ),
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        hardware_discovery(&mut gt, &w, ack);
        hardware_scheduling(&mut gt, &w);
        SLPC_FIXTURE_MODE.store(0, core::sync::atomic::Ordering::Relaxed);
        gt.begin_slpc(30).unwrap();
        assert!(gt.slpc_status().is_none());
        drive(&mut gt, &w, 31);
        assert_eq!(gt.slpc(), SlpcState::Running);
        let status = gt.slpc_status().unwrap();
        let bmg = platform == GtPlatform::Battlemage;
        assert_eq!(
            (
                status.limits.rpn_mhz,
                status.limits.rpe_mhz,
                status.limits.rp0_mhz
            ),
            (300, 1500, 3000)
        );
        assert_eq!(
            status.range,
            FrequencyRange {
                min_mhz: if bmg { 1200 } else { 900 },
                max_mhz: if bmg { 2133 } else { 3000 }
            }
        );
        assert_eq!(status.profile, PowerProfile::Base);
        for range in [
            FrequencyRange {
                min_mhz: 0,
                max_mhz: 2000,
            },
            FrequencyRange {
                min_mhz: 1800,
                max_mhz: 1700,
            },
            FrequencyRange {
                min_mhz: 1200,
                max_mhz: 3001,
            },
        ] {
            assert!(gt.begin_slpc_frequency_range(range, 100).is_err());
            assert_eq!(gt.slpc_status(), Some(status));
        }
        gt.begin_slpc_frequency_range(
            FrequencyRange {
                min_mhz: 1250,
                max_mhz: 2000,
            },
            100,
        )
        .unwrap();
        assert_eq!(gt.slpc(), SlpcState::Updating);
        assert!(gt.slpc_status().is_none());
        assert!(gt
            .begin_slpc_power_profile(PowerProfile::PowerSaving, 101)
            .is_err());
        drive(&mut gt, &w, 101);
        assert_eq!(
            gt.slpc_status().unwrap().range,
            FrequencyRange {
                min_mhz: 1250,
                max_mhz: 2000
            }
        );
        gt.begin_slpc_power_profile(PowerProfile::PowerSaving, 150)
            .unwrap();
        assert!(gt.slpc_status().is_none());
        assert_eq!(gt.poll(151), Poll::Ready(Ok(GtState::SchedulingReady)));
        assert!(
            gt.slpc_status().is_none(),
            "CT enqueue must not publish success"
        );
        drive(&mut gt, &w, 152);
        assert_eq!(gt.slpc_status().unwrap().profile, PowerProfile::PowerSaving);
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_slpc_fused_bounds_and_acknowledged_controls
);

fn smoke_slpc_refusal_stale_reply_timeout_and_retry() -> TestResult {
    for mode in [4, 5, 6, 7, 8, 9, 10] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        hardware_scheduling(&mut gt, &w);
        SLPC_FIXTURE_MODE.store(0, core::sync::atomic::Ordering::Relaxed);
        gt.begin_slpc(30).unwrap();
        drive(&mut gt, &w, 31);
        let before = arena.live_allocations();
        SLPC_FIXTURE_MODE.store(mode, core::sync::atomic::Ordering::Relaxed);
        gt.begin_slpc_frequency_range(
            FrequencyRange {
                min_mhz: 1250,
                max_mhz: 2000,
            },
            100,
        )
        .unwrap();
        drive(&mut gt, &w, 101);
        if mode == 5 || mode == 9 {
            assert_eq!(gt.slpc(), SlpcState::Updating);
            assert_eq!(
                gt.poll(1_005_000_100),
                Poll::Ready(Ok(GtState::SchedulingReady))
            );
        }
        assert_eq!(
            gt.slpc(),
            if mode == 8 {
                SlpcState::Running
            } else {
                SlpcState::Unavailable
            }
        );
        assert_eq!(
            arena.live_allocations(),
            before,
            "uncertain shared buffer retained"
        );
        if mode != 8 {
            assert!(gt.slpc_status().is_none());
        }
        assert!(gt.submit_kernel_probe(2_000_000_000).is_ok());
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    SLPC_FIXTURE_MODE.store(0, core::sync::atomic::Ordering::Relaxed);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_slpc_refusal_stale_reply_timeout_and_retry
);

fn smoke_slpc_unavailable_fuses_refuse_before_allocation() -> TestResult {
    for (register, value) in [
        (0x138000, u32::MAX),
        (0x138000, 0),
        (0x13800c, 1),
        (0x13800c, 511),
    ] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        hardware_scheduling(&mut gt, &w);
        let before = arena.live_allocations();
        w.0.borrow_mut().regs.insert(register, value);
        assert!(gt.begin_slpc(30).is_err());
        assert_eq!(gt.slpc(), SlpcState::Off);
        assert_eq!(arena.live_allocations(), before);
        assert!(gt.submit_kernel_probe(100).is_ok());
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_slpc_unavailable_fuses_refuse_before_allocation
);

fn smoke_slpc_ct_full_retries_without_publishing_success() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    SLPC_FIXTURE_MODE.store(0, core::sync::atomic::Ordering::Relaxed);
    gt.begin_slpc(30).unwrap();
    drive(&mut gt, &w, 31);
    gt.begin_slpc_power_profile(PowerProfile::PowerSaving, 100)
        .unwrap();
    let memory = ct_memory(&w);
    let tail = memory.borrow()[1];
    memory.borrow_mut()[0] = (tail + 1) & 1023; // No free H2G slots.
    for now in 101..105 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        assert_eq!(gt.slpc(), SlpcState::Updating);
        assert!(gt.slpc_status().is_none());
        assert_eq!(memory.borrow()[1], tail);
    }
    memory.borrow_mut()[0] = tail;
    drive(&mut gt, &w, 105);
    assert_eq!(gt.slpc_status().unwrap().profile, PowerProfile::PowerSaving);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_slpc_ct_full_retries_without_publishing_success
);

fn smoke_slpc_stable_ip_qualified_fused_vectors() -> TestResult {
    use crate::intel_gpu_slpc::Limits;
    let (w, _) = model();
    for (version, device, expected_min, expected_max) in [
        (2001, 0xe20b, 1200, 2133),
        (2002, 0xe20b, 1200, 3000),
        (2001, 0xe220, 300, 2133),
        (2002, 0xe220, 300, 3000),
    ] {
        {
            let mut d = w.0.borrow_mut();
            d.regs
                .insert(0xd8c, ((version / 100) << 22) | ((version % 100) << 14));
            d.regs.insert(0x138000, (18 << 16) | 180);
            d.regs.insert(0x13800c, 90);
        }
        let limits = Limits::read(&w, GtPlatform::Battlemage, device).unwrap();
        assert_eq!(
            (limits.min_mhz, limits.max_mhz),
            (expected_min, expected_max)
        );
    }
    struct Changing<'a> {
        base: &'a Window,
        reads: core::cell::Cell<u32>,
    }
    impl MmioWindow for Changing<'_> {
        fn read32(&self, reg: u64) -> u32 {
            if reg == 0x138000 {
                let n = self.reads.get();
                self.reads.set(n + 1);
                self.base.read32(reg) + n
            } else {
                self.base.read32(reg)
            }
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("fuse discovery wrote MMIO")
        }
    }
    let unstable = Changing {
        base: &w,
        reads: core::cell::Cell::new(0),
    };
    assert!(Limits::read(&unstable, GtPlatform::Battlemage, 0xe20b).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_slpc_stable_ip_qualified_fused_vectors
);

fn smoke_slpc_buffer_remains_disjoint_from_later_contexts() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    SLPC_FIXTURE_MODE.store(0, core::sync::atomic::Ordering::Relaxed);
    gt.begin_slpc(30).unwrap();
    drive(&mut gt, &w, 31);
    let before = arena.live_allocations();
    let original_next = w.0.borrow().next;
    let shared_address =
        w.0.borrow()
            .memory
            .iter()
            .find(|(_, m)| m.borrow().len() == 2048 && m.borrow()[0] == 8192)
            .map(|(address, _)| *address)
            .unwrap();
    // The next LRC overlaps the second SLPC page without reusing its base.
    w.0.borrow_mut().next = shared_address + 4096;
    assert!(matches!(
        gt.submit_kernel_probe(100),
        Err(GtError::Scheduling(
            crate::intel_gpu_guc_sched::SchedulingError::Address
        ))
    ));
    assert_eq!(arena.live_allocations(), before);
    assert_eq!(gt.slpc(), SlpcState::Running);
    w.0.borrow_mut().next = original_next;
    assert!(gt.submit_kernel_probe(101).is_ok());
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_slpc_buffer_remains_disjoint_from_later_contexts
);
