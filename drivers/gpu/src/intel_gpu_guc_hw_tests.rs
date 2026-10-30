// Native Rust hardware conversations over the real GuCGt/CT/scheduler owners.
// Reference vectors: MIT Linux xe_guc_submit.c, xe_lrc.c, xe_guc_ads.c,
// xe_mocs.c at b90c984d615e8ce2af96f5b1411a962d83fed2ad.

fn hardware_model(platform: GtPlatform, ack: u64) -> (Window, Arena, GuCGt<Window, Arena>) {
    hardware_model_with_interface(platform, ack, 1)
}
fn hardware_model_with_interface(
    platform: GtPlatform,
    ack: u64,
    version: u8,
) -> (Window, Arena, GuCGt<Window, Arena>) {
    let (window, arena) = model();
    {
        let mut d = window.0.borrow_mut();
        d.regs.insert(ack, 0);
        d.regs.insert(0xa188, 2);
        d.regs.insert(0xa278, 2);
        d.regs.insert(0xd84, 0);
        d.regs.insert(0xfd0, 1);
        d.regs.insert(0x913c, 5);
        d.regs.insert(0x9144, 6);
        d.regs.insert(0x9134, 5);
        d.regs.insert(0x9114, 0x10);
        d.regs.insert(0x9118, 1);
        d.regs.insert(
            0xd8c,
            if platform == GtPlatform::Battlemage {
                (20 << 22) | (1 << 14)
            } else {
                (12 << 22) | (70 << 14)
            },
        );
    }
    let mut boot = stage(window.clone(), arena.clone(), platform);
    boot.submission_version = (version, 0, 0);
    if platform == GtPlatform::Battlemage {
        boot.config.uncached_mocs = Some(3);
    }
    let gt = GuCGt::from_staged_hardware(boot).unwrap();
    (window, arena, gt)
}

fn hardware_discovery(gt: &mut GuCGt<Window, Arena>, w: &Window, ack: u64) {
    gt.begin(0).unwrap();
    assert!(gt.poll(1).is_pending());
    w.0.borrow_mut().regs.insert(ack, 1);
    assert!(gt.poll(2).is_pending());
    assert_eq!(gt.state(), GtState::PreparingHardware);
    assert_eq!(w.0.borrow().regs.get(&0xa278), Some(&3));
    w.0.borrow_mut().regs.insert(0xd84, 1);
    assert!(gt.poll(3).is_pending());
    reset_done(w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(4).is_pending());
    assert_eq!(w.0.borrow().regs.get(&0x941c), Some(&1));
    reset_done(w);
    assert!(gt.poll(5).is_pending());
    reset_done(w);
    assert!(gt.poll(6).is_pending());
    w.0.borrow_mut().regs.insert(0xc314, 0x10);
    assert!(gt.poll(7).is_pending());
    w.0.borrow_mut().regs.insert(0xc000, 0x8000f000);
    assert_eq!(gt.poll(8), Poll::Ready(Ok(GtState::Ready)));
    gt.begin_hwconfig(9).unwrap();
    w.0.borrow_mut().regs.insert(0x190240, 0xf000000c);
    assert!(gt.poll(10).is_pending());
    hwconfig_device_write(w, &[7, 1, 8]);
    w.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
    assert_eq!(gt.poll(11), Poll::Ready(Ok(GtState::Ready)));
}

fn smoke_hardware_topology_publication_and_card_queries() -> TestResult {
    use crate::drm_devfs_bridge::IntelGpuCard;
    use crate::intel_gpu_render::{tests::check_card_topology, DeviceInfo};
    for (platform, device, ack) in [
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0x7d55,
            0xdfc,
        ),
        (GtPlatform::Alchemist, 0x56a0, 0x130044),
        (GtPlatform::Battlemage, 0xe20b, 0xdfc),
    ] {
        let card = Arc::new(IntelGpuCard::new(
            alloc::string::String::new(),
            0x8086,
            device,
            0,
            0,
        ));
        let other = Arc::new(IntelGpuCard::new(
            alloc::string::String::new(),
            0x8086,
            device,
            0,
            0,
        ));
        let index = crate::drm_registry::register_drm_card(card.clone());
        let other_index = crate::drm_registry::register_drm_card(other.clone());
        let before = DeviceInfo::for_card(index).unwrap();
        check_card_topology(index, None, None).unwrap();
        let (w, arena, mut gt) = hardware_model(platform, ack);
        assert!(card.publish_gt_topology(&mut gt).is_err());
        hardware_discovery(&mut gt, &w, ack);
        card.publish_gt_topology(&mut gt).unwrap();
        card.publish_gt_topology(&mut gt).unwrap(); // identical resume observation
        assert!(before.topology.is_none());
        assert!(DeviceInfo::for_card(other_index)
            .unwrap()
            .topology
            .is_none());
        let snapshot = DeviceInfo::for_card(index).unwrap().topology.unwrap();
        assert_eq!((snapshot.geometry_dss(), snapshot.compute_dss()), (5, 6));

        let (w2, arena2, mut gt2) = hardware_model(platform, ack);
        w2.0.borrow_mut()
            .regs
            .extend([(0x913c, 2), (0x9144, 0), (0x9134, 3)]);
        hardware_discovery(&mut gt2, &w2, ack);
        assert_eq!(
            card.publish_gt_topology(&mut gt2),
            Err(GtError::Topology(
                crate::intel_gpu_topology::TopologyError::Unstable
            ))
        );
        other.publish_gt_topology(&mut gt2).unwrap();
        let wrong = IntelGpuCard::new(alloc::string::String::new(), 0x8086, 0xffff, 0, 0);
        assert!(wrong.publish_gt_topology(&mut gt).is_err());
        hardware_stop(&mut gt, &w, ack);
        hardware_stop(&mut gt2, &w2, ack);
        drop(gt);
        drop(gt2);
        assert_eq!(
            (arena.live_allocations(), arena2.live_allocations()),
            (0, 0)
        );
        assert_eq!((snapshot.geometry_dss(), snapshot.compute_dss()), (5, 6));

        let mut expected = if platform == GtPlatform::Battlemage {
            let mut bytes = alloc::vec![0;53];
            bytes[..16].copy_from_slice(&[0, 0, 1, 0, 32, 0, 8, 0, 1, 0, 4, 0, 5, 0, 1, 0]);
            bytes[16..24].copy_from_slice(&[1, 7, 0, 0, 0, 5, 5, 5]);
            bytes
        } else {
            let mut bytes = alloc::vec![0;85];
            bytes[..16].copy_from_slice(&[0, 0, 1, 0, 32, 0, 16, 0, 1, 0, 4, 0, 5, 0, 2, 0]);
            bytes[16..27].copy_from_slice(&[1, 7, 0, 0, 0, 0x33, 0, 0x33, 0, 0x33, 0]);
            bytes
        };
        let mut geometry = expected.clone();
        geometry[17] = 5;
        if platform == GtPlatform::Battlemage {
            geometry[22] = 0;
        } else {
            geometry[23..25].fill(0);
        }
        check_card_topology(index, Some(&expected), Some(&geometry)).unwrap();
        expected[17] = 2;
        expected[21..].fill(0);
        if platform == GtPlatform::Battlemage {
            expected[22] = 3;
        } else {
            expected[23] = 0xf;
        }
        check_card_topology(other_index, Some(&expected), Some(&expected)).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_topology_publication_and_card_queries
);

fn smoke_hardware_fuse_admission_before_dma_and_scheduling() -> TestResult {
    use crate::intel_gpu_topology::TopologyError;
    for fuses in [[0, 0, 1], [1, 0, 0], [1, 1, u32::MAX]] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
        w.0.borrow_mut()
            .regs
            .extend([(0x913c, fuses[0]), (0x9144, fuses[1]), (0x9134, fuses[2])]);
        gt.begin(0).unwrap();
        w.0.borrow_mut().regs.insert(0x130044, 1);
        assert!(gt.poll(1).is_pending());
        w.0.borrow_mut().regs.insert(0xd84, 1);
        assert!(gt.poll(2).is_pending());
        reset_done(&w);
        assert!(gt.poll(3).is_pending());
        reset_done(&w);
        assert!(matches!(gt.poll(4), Poll::Ready(Err(GtError::Topology(_)))));
        assert_eq!(gt.state(), GtState::Lost);
        assert!(gt.topology().is_none());
        assert!(!w
            .0
            .borrow()
            .writes
            .iter()
            .any(|&(r, v)| (r == 0xc314 && v == 0x00110011) || r == 0x2080));
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    w.0.borrow_mut().regs.insert(0x913c, 0); // valid compute-only GT
    hardware_discovery(&mut gt, &w, 0x130044);
    assert!(!gt.topology().unwrap().has_render());
    let count = arena.live_allocations();
    assert_eq!(
        gt.begin_scheduling(12),
        Err(GtError::Topology(TopologyError::NoRender))
    );
    assert_eq!(arena.live_allocations(), count);
    assert!(!w.0.borrow().writes.iter().any(|(r, _)| *r == 0x2080));
    let card = crate::drm_devfs_bridge::IntelGpuCard::new(
        alloc::string::String::new(),
        0x8086,
        0x56a0,
        0,
        0,
    );
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(card.publish_gt_topology(&mut gt), Err(GtError::WakeLost));
    assert_eq!(gt.state(), GtState::Lost);
    gt.begin_stop(20).unwrap();
    w.0.borrow_mut().regs.insert(0x130044, 1);
    assert!(gt.poll(21).is_pending());
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(22).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(23).is_pending());
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(gt.poll(24), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_fuse_admission_before_dma_and_scheduling
);

fn hardware_scheduling(gt: &mut GuCGt<Window, Arena>, w: &Window) {
    gt.begin_scheduling(12).unwrap();
    assert_eq!(gt.state(), GtState::PreparingScheduling);
    assert!(gt.poll(12).is_pending());
    assert_eq!(gt.state(), GtState::StartingScheduling);
    assert!(gt.poll(13).is_pending());
    reset_done(w);
    assert!(gt.poll(14).is_pending()); // stop, ADS rewrite, reset for reload
    reset_done(w);
    assert!(gt.poll(15).is_pending());
    w.0.borrow_mut().regs.insert(0xc314, 0x10);
    assert!(gt.poll(16).is_pending());
    w.0.borrow_mut().regs.insert(0xc000, 0x8000f000);
    assert_eq!(gt.poll(17), Poll::Ready(Ok(GtState::Ready)));
    gt.begin_ct(18).unwrap();
    for now in 19..25 {
        w.0.borrow_mut().regs.insert(0x190240, 0xf0000001);
        assert!(gt.poll(now).is_pending());
    }
    w.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
    assert_eq!(gt.poll(25), Poll::Ready(Ok(GtState::SchedulingReady)));
}

fn smoke_hardware_register_initialization_gates_scheduling() -> TestResult {
    use crate::intel_gpu_gt_registers::RegisterError;
    for failure in 0..4 {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        let before = arena.live_allocations();
        if failure == 0 {
            w.0.borrow_mut().regs.insert(0xd8c, (20 << 22) | (4 << 14));
            assert!(matches!(
                gt.begin_scheduling(12),
                Err(GtError::Registers(_))
            ));
            assert_eq!(gt.state(), GtState::Ready);
            assert_eq!(arena.live_allocations(), before);
        } else {
            gt.begin_scheduling(12).unwrap();
            let count = arena.live_allocations();
            assert_eq!(count, before + 2);
            if failure == 1 {
                w.0.borrow_mut().regs.insert(0xe7cc, u32::MAX);
                assert_eq!(
                    gt.poll(13),
                    Poll::Ready(Err(GtError::Registers(RegisterError::Unavailable)))
                );
                assert_eq!(gt.state(), GtState::Lost);
                assert_eq!(w.0.borrow().regs[&0xfd0], 1);
                assert!(!w.0.borrow().writes.iter().any(|p| p.0 == 0xb0c8));
            } else {
                w.0.borrow_mut().regs.insert(0xfd0, 0);
                for now in 13..17 {
                    assert!(gt.poll(now).is_pending());
                }
                assert_eq!(gt.state(), GtState::PreparingScheduling);
                if failure == 2 {
                    assert_eq!(
                        gt.poll(50_000_012),
                        Poll::Ready(Err(GtError::Registers(RegisterError::Timeout)))
                    );
                    assert_eq!(gt.state(), GtState::Lost);
                }
            }
            assert_eq!(arena.live_allocations(), count);
        }
        assert!(!w.0.borrow().writes.iter().any(|p| p.0 == 0x2080));
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_register_initialization_gates_scheduling
);

fn hardware_stop(gt: &mut GuCGt<Window, Arena>, w: &Window, ack: u64) {
    gt.begin_stop(10_000_000_000).unwrap();
    assert!(gt.poll(10_000_000_001).is_pending());
    reset_done(w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(10_000_000_002).is_pending());
    if gt.state() == GtState::ResettingEngines {
        assert_eq!(w.0.borrow().regs.get(&0x941c), Some(&1));
        assert!(gt.poll(10_000_000_003).is_pending());
        reset_done(w);
        assert!(gt.poll(10_000_000_004).is_pending());
    }
    assert_eq!(gt.state(), GtState::ReleasingRender);
    assert_eq!(w.0.borrow().regs.get(&0xa278), Some(&2));
    assert!(gt.poll(10_000_000_005).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(10_000_000_006).is_pending());
    w.0.borrow_mut().regs.insert(ack, 0);
    assert_eq!(gt.poll(10_000_000_007), Poll::Ready(Ok(GtState::Stopped)));
}

fn ct_memory(w: &Window) -> Words {
    w.0.borrow()
        .memory
        .values()
        .find(|b| b.borrow().len() == 6144)
        .expect("CT")
        .clone()
}
fn event(memory: &Words, action: u32, payload: &[u32]) {
    let mut words = memory.borrow_mut();
    let tail = words[513];
    words[2048 + (tail & 4095) as usize] = 1 + payload.len() as u32;
    words[2048 + ((tail + 1) & 4095) as usize] = 0x90000000 | action;
    for (i, word) in payload.iter().enumerate() {
        words[2048 + ((tail + 2 + i as u32) & 4095) as usize] = *word;
    }
    words[513] = (tail + 2 + payload.len() as u32) & 4095;
}
fn service_contexts(w: &Window, registered: &mut BTreeMap<u32, u32>, execute: bool) -> Vec<u16> {
    let memory = ct_memory(w);
    let mut requests = Vec::new();
    {
        let mut words = memory.borrow_mut();
        let mut head = words[0];
        let tail = words[1];
        while head != tail {
            let count = words[1024 + head as usize] & 0xff;
            let mut request = Vec::new();
            for i in 1..=count {
                request.push(words[1024 + ((head + i) & 1023) as usize]);
            }
            assert_eq!(request[0] >> 28, 2, "fast request");
            requests.push(request);
            head = (head + count + 1) & 1023;
        }
        words[0] = head;
    }
    let mut actions = Vec::new();
    for request in requests {
        let action = request[0] as u16;
        actions.push(action);
        match action {
            0x7000 => {
                assert_eq!(request.len(), 3);
                assert_eq!(request[2], 0x80000003);
                event(&memory, 0x7001, &[request[1]]);
            }
            0x4502 => {
                assert_eq!(&request[1..10], &[1, request[2], 0, 1, 0, 0, 0, 0, 0]);
                assert_eq!(request.len(), 12);
                assert!(matches!(request[10] & 0xfff, 0x19 | 0x119));
                let image = w.0.borrow().memory[&(request[10] & !0xfff)].clone();
                assert_eq!(image.borrow()[1024 + 0x33] != 0, request[10] & 0x100 != 0);
                assert_eq!(request[11], 0);
                assert!(registered
                    .insert(request[2], request[10] & !0xfff)
                    .is_none());
            }
            0x100b => assert_eq!(
                &request[2..],
                &[0x20030001, 3, 0x20010001, 1000, 0x20020001, 500000]
            ),
            0x1001 => {
                let id = request[1];
                let base = registered[&id];
                if request[2] == 1 && execute {
                    let mut d = w.0.borrow_mut();
                    assert!(d.synced.contains(&base));
                    let image = d.memory[&base].clone();
                    let ring_base = image.borrow()[1024 + 9];
                    {
                        let data = image.borrow();
                        assert_eq!(
                            &data[1024..1031],
                            &[0, 0x1108101d, 0x2244, data[1027], 0x2034, 0, 0x2030]
                        );
                        assert!(matches!(data[1027], 0x00090009 | 0x00090008));
                        assert_eq!(data[1032], 0x2038);
                        assert_eq!(data[1024 + 33], 0x11081011);
                        assert_eq!(data[1024 + 65], 0x11080001);
                        assert_eq!(data[1024 + 68], 0x05000001);
                        // xe_lrc.c::reset_stop_ring, graphics IP >= 12.50.
                        assert_eq!(data[1024 + 0x71], 0x01000000);
                        assert_eq!(data[1024 + 0x72], 0);
                    }
                    assert!(d.synced.contains(&ring_base));
                    let ring_backing = d.memory[&ring_base].clone();
                    let ring = ring_backing.borrow();
                    let tail = image.borrow()[1024 + 7];
                    if image.borrow()[1024 + 0x33] != 0 {
                        execute_ppgtt_probe(&d.regs, &image.borrow(), &ring, id, base);
                    } else if tail != 32 {
                        let (_, used) =
                            crate::intel_gpu_context::tests::execute(&ring[1..], &mut d.regs);
                        assert_eq!(ring[0], 0x04000001);
                        assert_eq!(ring[used + 1] & 0xfffffdff, 0x7a000004);
                        // Opaque device-saved state, outside the hand-written
                        // register restore groups. The driver must copy it.
                        image.borrow_mut()[0x2000 / 4] = 0xc01dcafe;
                        image.borrow_mut()[0x2004 / 4] = d.regs[&0x7044];
                    } else {
                        assert_eq!(
                            &ring[..8],
                            &[
                                0x04000001,
                                0,
                                0x10400002,
                                base + 0x800,
                                0,
                                id,
                                0x01000000,
                                0
                            ]
                        );
                        assert_eq!(tail, 32);
                    }
                    image.borrow_mut()[0x800 / 4] = id;
                    image.borrow_mut()[1024 + 5] = tail;
                }
                event(&memory, 0x1002, &[id, request[2]]);
            }
            0x4503 => {
                assert!(registered.remove(&request[1]).is_some());
                event(&memory, 0x4600, &[request[1]]);
            }
            _ => panic!("unexpected action {action:x}"),
        }
    }
    actions
}

// Independent fixed-command device model. It follows the actual production
// table pages, verifies their PAT/permissions, fetches the private batch via
// four hardware-style reads and writes the translated destination page.
fn execute_ppgtt_probe(regs: &BTreeMap<u64, u32>, image: &[u32], ring: &[u32], id: u32, base: u32) {
    let pat = if regs.get(&0x480c) == Some(&2) {
        3
    } else if regs.get(&0x4808) == Some(&0xf) {
        2
    } else {
        0
    };
    let table_pat = if pat == 3 {
        assert_eq!(regs.get(&0x4808), Some(&0xc));
        2
    } else {
        pat
    };
    let root = (u64::from(image[1024 + 0x31]) << 32) | u64::from(image[1024 + 0x33]);
    assert_eq!(root & 0xfff, 3 | table_pat << 3);
    let walk = |va: u64, writable: bool| -> u64 {
        let mut page = root & 0x0000_3fff_ffff_f000;
        for shift in [39, 30, 21, 12] {
            let address = narf_memory::PhysAddr::new(page).kernel_ptr::<u64>();
            // SAFETY: this fixture built and retains all four physical tables;
            // the independent walk never uses an external/raw user pointer.
            let entry =
                unsafe { core::ptr::read_volatile(address.add(((va >> shift) & 511) as usize)) };
            assert_eq!(entry & 1, 1);
            assert_eq!(
                entry & 0x18,
                (if shift == 12 { pat } else { table_pat }) << 3
            );
            assert_eq!(entry & 2 != 0, shift != 12 || writable);
            page = entry & 0x0000_3fff_ffff_f000;
        }
        page | (va & 4095)
    };
    let mut expected = alloc::vec![0x04000001, 0x02800101, 0x7a000404, 0x20344c1c, 0xd0, 0, 0, 0,];
    if pat == 3 {
        expected.extend_from_slice(&[0x11020001, 0x4208, 1, 0]);
    }
    expected.extend_from_slice(&[0x02800100, 0x18800101, 0, 0x1234, 0x04000000]);
    if pat == 0 {
        expected.extend_from_slice(&[0x7a000004, 1, 0xd0, 0, 0, 0]);
    }
    expected.extend_from_slice(&[
        0x7a000204,
        0x101010a1,
        0,
        0,
        0,
        0,
        0x7a000004,
        0x01104080,
        base + 0x800,
        0,
        id,
        0,
        0x01000000,
        0x04000001,
        0x02800000,
    ]);
    assert_eq!(image[1031] as usize, expected.len() * 4);
    assert_eq!(&ring[..expected.len()], expected.as_slice());
    // Literal batch from xe_mi_commands.h, independent of the producer's codec.
    let code = narf_memory::PhysAddr::new(walk(0x1234_0000_0000, false)).kernel_ptr::<u32>();
    for (i, word) in [0x10000002, 0x80, 0x2345, 0x4e415246, 0x05000000, 0]
        .into_iter()
        .enumerate()
    {
        // SAFETY: translated page is owned by the resident fixture.
        assert_eq!(unsafe { core::ptr::read_volatile(code.add(i)) }, word);
    }
    let target = narf_memory::PhysAddr::new(walk(0x2345_0000_0080, true)).kernel_mut_ptr::<u32>();
    // SAFETY: the validated writable leaf is an owned private result page.
    unsafe { core::ptr::write_volatile(target, 0x4e415246) };
}

fn golden_memory(w: &Window) -> Words {
    let d = w.0.borrow();
    let base = d.memory[&0x20001000].borrow()[0x1014 / 4];
    d.memory[&base].clone()
}

fn smoke_hardware_default_context_capture_and_clone() -> TestResult {
    for (platform, ack, gmd) in [
        (GtPlatform::Alchemist, 0x130044, 0),
        (GtPlatform::Battlemage, 0xdfc, (20 << 22) | (1 << 14)),
        (GtPlatform::Battlemage, 0xdfc, (20 << 22) | (2 << 14)),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
            (12 << 22) | (74 << 14),
        ),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        if gmd != 0 {
            w.0.borrow_mut().regs.insert(0xd8c, gmd);
        }
        hardware_discovery(&mut gt, &w, ack);
        hardware_scheduling(&mut gt, &w);
        let count = arena.live_allocations();
        let golden = golden_memory(&w);
        assert!(golden.borrow().iter().all(|word| *word == 0));
        let completion = gt.begin_context_defaults(26).unwrap();
        assert!(!gt.context_defaults_ready());
        assert!(matches!(gt.begin_context_defaults(26), Err(GtError::Busy)));
        assert!(matches!(
            gt.submit_kernel_probe(26),
            Err(GtError::Scheduling(
                crate::intel_gpu_guc_sched::SchedulingError::Busy
            ))
        ));
        {
            use core::{
                future::Future,
                task::{Context, Waker},
            };
            let mut wait = core::pin::pin!(completion.wait());
            assert!(wait
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        let mut registered = BTreeMap::new();
        let mut registrations = 0;
        for now in 27..90 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            if completion.result().is_some() {
                break;
            }
            assert!(!gt.context_defaults_ready());
            assert!(golden.borrow().iter().all(|word| *word == 0));
            registrations += service_contexts(&w, &mut registered, true)
                .iter()
                .filter(|a| **a == 0x4502)
                .count();
        }
        assert_eq!(registrations, 2);
        assert_eq!(completion.result(), Some(Ok(())));
        assert!(gt.context_defaults_ready());
        assert_eq!(arena.live_allocations(), count);
        {
            let data = golden.borrow();
            assert!(data[..1024].iter().all(|word| *word == 0));
            assert_eq!(data[1027], 0x00090008);
            assert_eq!((data[1029], data[1031], data[1033]), (0, 0, 0));
            assert_eq!(data[0x2000 / 4], 0xc01dcafe);
            assert_ne!(data[0x2004 / 4] & 0x20, 0);
        }
        // A fresh PPGTT context must inherit the device's saved opaque state,
        // restore it rather than inhibit, and receive its own ring and root.
        let probe = gt.submit_ppgtt_probe(100).unwrap();
        for now in 101..125 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            for base in registered.values() {
                let image = w.0.borrow().memory[base].clone();
                assert_eq!(image.borrow()[1027], 0x00090008);
                assert_eq!(image.borrow()[0x2000 / 4], 0xc01dcafe);
                assert_ne!(image.borrow()[1033], 0);
            }
            if probe.completion.result().is_some() {
                break;
            }
        }
        assert_eq!(probe.completion.result(), Some(Ok(())));
        assert_eq!(probe.result.verify(), Ok(()));
        hardware_stop(&mut gt, &w, ack);
        assert!(!gt.context_defaults_ready());
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_default_context_capture_and_clone
);

fn smoke_hardware_defaults_failures_wait_for_full_reset() -> TestResult {
    for cpu_sync in [false, true] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
        hardware_discovery(&mut gt, &w, 0x130044);
        hardware_scheduling(&mut gt, &w);
        let count = arena.live_allocations();
        let completion = gt.begin_context_defaults(26).unwrap();
        let mut registered = BTreeMap::new();
        let mut corrupted = false;
        let mut lost = false;
        for now in 27..90 {
            if let Poll::Ready(Err(GtError::Scheduling(_))) = gt.poll(now) {
                lost = true;
                break;
            }
            service_contexts(&w, &mut registered, true);
            if !corrupted {
                for base in registered.values() {
                    let image = w.0.borrow().memory[base].clone();
                    if image.borrow()[0x2000 / 4] == 0xc01dcafe {
                        if cpu_sync {
                            w.0.borrow_mut().fail_cpu_sync = true;
                        } else {
                            image.borrow_mut()[1025] = u32::MAX;
                        }
                        corrupted = true;
                        break;
                    }
                }
            }
        }
        assert!(corrupted && lost);
        assert_eq!(gt.state(), GtState::Lost);
        assert!(completion.result().is_none());
        assert!(!gt.context_defaults_ready());
        assert!(arena.live_allocations() > count);
        hardware_stop(&mut gt, &w, 0x130044);
        assert_eq!(
            completion.result(),
            Some(Err(crate::intel_gpu_fence::JobError::Reset))
        );
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_defaults_failures_wait_for_full_reset
);

fn smoke_hardware_default_switch_cancel_requires_full_reset() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    hardware_discovery(&mut gt, &w, 0x130044);
    hardware_scheduling(&mut gt, &w);
    let baseline = arena.live_allocations();
    let completion = gt.begin_context_defaults(26).unwrap();
    let mut registered = BTreeMap::new();
    for now in 27..60 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if arena.live_allocations() == baseline + 3 {
            break;
        }
        service_contexts(&w, &mut registered, true);
    }
    // The seed is fully retired but deliberately retained; the second
    // context has been allocated. A GuC-only reset cannot free either one.
    assert_eq!(arena.live_allocations(), baseline + 3);
    assert!(completion.result().is_none());
    gt.begin_stop(10_000_000_000).unwrap();
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(10_000_000_001).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert!(completion.result().is_none());
    assert!(arena.live_allocations() >= baseline + 2);
    assert!(gt.poll(10_000_000_002).is_pending());
    reset_done(&w);
    assert!(gt.poll(10_000_000_003).is_pending());
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(10_000_000_004).is_pending());
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(gt.poll(10_000_000_005), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_default_switch_cancel_requires_full_reset
);

fn smoke_hardware_ppgtt_store_and_retirement() -> TestResult {
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
        let count = arena.live_allocations();
        let probe = gt.submit_ppgtt_probe(26).unwrap();
        assert!(probe.result.verify().is_err());
        let weak = probe.result.weak_objects();
        assert!(weak.iter().all(|o| o.strong_count() == 2));
        let mut registered = BTreeMap::new();
        for now in 27..48 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            if probe.completion.result().is_some() {
                break;
            }
        }
        assert_eq!(probe.completion.result(), Some(Ok(())));
        assert_eq!(probe.result.verify(), Ok(()));
        assert_eq!(arena.live_allocations(), count);
        // Priming after a resident job could capture that job's graphics
        // state, even after complete retirement. It requires a fresh GT.
        assert!(matches!(gt.begin_context_defaults(100), Err(GtError::Busy)));
        assert!(weak.iter().all(|o| o.strong_count() == 1));
        drop(probe);
        assert!(weak.iter().all(|o| o.upgrade().is_none()));
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_ppgtt_store_and_retirement
);

fn smoke_hardware_ppgtt_cancel_and_reset() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    let probe = gt.submit_ppgtt_probe(26).unwrap();
    let weak = probe.result.weak_objects();
    let completion = probe.completion.clone();
    // Dropping the result and cancelling a waiter never abandons DMA owners.
    {
        use core::{
            future::Future,
            task::{Context, Waker},
        };
        let mut wait = core::pin::pin!(completion.wait());
        assert!(wait
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    drop(probe);
    let mut registered = BTreeMap::new();
    for now in 27..32 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    let count = arena.live_allocations();
    assert!(weak.iter().all(|o| o.strong_count() == 1));
    assert!(matches!(
        gt.poll(5_000_000_026),
        Poll::Ready(Err(GtError::Scheduling(_)))
    ));
    assert!(completion.result().is_none());
    gt.begin_stop(10_000_000_000).unwrap();
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(10_000_000_001).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert_eq!(arena.live_allocations(), count);
    assert!(weak.iter().all(|o| o.strong_count() == 1));
    assert!(gt.poll(10_000_000_002).is_pending());
    reset_done(&w);
    assert!(gt.poll(10_000_000_003).is_pending());
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak.iter().all(|o| o.upgrade().is_none()));
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(10_000_000_004).is_pending());
    w.0.borrow_mut().regs.insert(0xdfc, 0);
    assert_eq!(gt.poll(10_000_000_005), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_ppgtt_cancel_and_reset
);

fn smoke_hardware_ppgtt_admission_and_lost_proof() -> TestResult {
    use crate::{intel_gpu_exec::PpgttProbeResult, intel_gpu_guc_sched::SchedulingError};
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    hardware_discovery(&mut gt, &w, 0x130044);
    hardware_scheduling(&mut gt, &w);
    let count = arena.live_allocations();
    let (batch, result) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
    let foreign = result.weak_objects();
    // SAFETY: this is the fixed, private kernel probe; the mismatch must fail
    // before publication and release its private page-table residency.
    let admission = unsafe { gt.submit_kernel_batch(26, batch) };
    assert!(matches!(
        admission,
        Err(GtError::Scheduling(SchedulingError::Address))
    ));
    assert_eq!(arena.live_allocations(), count);
    assert!(foreign.iter().all(|o| o.strong_count() == 1));
    drop(result);
    assert!(foreign.iter().all(|o| o.upgrade().is_none()));
    let probe = gt.submit_ppgtt_probe(26).unwrap();
    let weak = probe.result.weak_objects();
    let completion = probe.completion.clone();
    drop(probe);
    let mut registered = BTreeMap::new();
    // Reach disable acknowledgment, before consuming deregistration.
    for now in 27..34 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, true);
        if let Some(base) = registered.values().next() {
            let image = w.0.borrow().memory[base].clone();
            if image.borrow()[0x800 / 4] != 0 {
                // Corrupt only the saved head after device completion. The
                // breadcrumb and GuC ACK still cannot authorize retirement.
                image.borrow_mut()[1024 + 5] = 0;
                break;
            }
        }
    }
    let mut lost = false;
    for now in 34..45 {
        match gt.poll(now) {
            Poll::Ready(Err(GtError::Scheduling(SchedulingError::Protocol))) => {
                lost = true;
                break;
            }
            Poll::Ready(Ok(GtState::SchedulingReady)) => {
                service_contexts(&w, &mut registered, false);
            }
            other => panic!("unexpected retirement state {other:?}"),
        }
    }
    assert!(lost);
    assert!(completion.result().is_none());
    assert!(weak.iter().all(|o| o.strong_count() == 1));
    hardware_stop(&mut gt, &w, 0x130044);
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak.iter().all(|o| o.upgrade().is_none()));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_ppgtt_admission_and_lost_proof
);

fn smoke_hardware_gt_reload_and_context_execution() -> TestResult {
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
        {
            let d = w.0.borrow();
            let expected = match platform {
                GtPlatform::Alchemist => (0xb020, 0x00d00090),
                GtPlatform::Battlemage => (0x400c, 0x13c),
                _ => (0xb030, 0x00500050),
            };
            assert!(d.writes.contains(&expected));
            assert!(
                d.writes.iter().position(|(r, _)| *r == expected.0).unwrap()
                    < d.writes
                        .iter()
                        .position(|p| *p == (0xc314, 0x00110011))
                        .unwrap()
            );
        }
        hardware_scheduling(&mut gt, &w);
        assert_eq!(w.0.borrow().regs.get(&0xc18c), Some(&16));
        assert_eq!(
            w.0.borrow().memory[&0x20001000].borrow()[0x1054 / 4],
            if platform == GtPlatform::Battlemage {
                0x2e80
            } else {
                0xce80
            }
        );
        let count = arena.live_allocations();
        let (id, completion) = gt.submit_kernel_probe(26).unwrap();
        let (_, other) = gt.submit_kernel_probe(26).unwrap();
        assert_eq!(id, 1);
        assert_eq!(arena.live_allocations(), count + 4);
        {
            use core::{
                future::Future,
                task::{Context, Waker},
            };
            let mut wait = core::pin::pin!(completion.wait());
            assert!(wait
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert!(completion.result().is_none());
        let mut registered = BTreeMap::new();
        let mut actions = Vec::new();
        for now in 27..44 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            actions.extend(service_contexts(&w, &mut registered, true));
            if completion.result().is_some() && other.result().is_some() {
                break;
            }
        }
        assert_eq!(completion.result(), Some(Ok(())));
        assert_eq!(other.result(), Some(Ok(())));
        assert_eq!(arena.live_allocations(), count);
        assert_eq!(
            &actions[..8],
            &[0x7000, 0x7000, 0x4502, 0x4502, 0x100b, 0x100b, 0x1001, 0x1001]
        );
        assert!(registered.is_empty());
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_gt_reload_and_context_execution
);

fn smoke_hardware_context_faults_require_full_reset() -> TestResult {
    for malformed in [false, true] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        hardware_scheduling(&mut gt, &w);
        let (_, completion) = gt.submit_kernel_probe(26).unwrap();
        let mut registered = BTreeMap::new();
        for now in 27..32 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        let count = arena.live_allocations();
        if malformed {
            event(&ct_memory(&w), 0x1002, &[0xffff, 1]);
        }
        let now = if malformed { 32 } else { 5_000_000_026 };
        assert!(matches!(
            gt.poll(now),
            Poll::Ready(Err(GtError::Scheduling(_)))
        ));
        assert_eq!(gt.state(), GtState::Lost);
        assert!(completion.result().is_none());
        assert_eq!(arena.live_allocations(), count);
        gt.begin_stop(10_000_000_000).unwrap();
        reset_done(&w);
        w.0.borrow_mut().regs.insert(0xc314, 0);
        assert!(gt.poll(10_000_000_001).is_pending());
        assert_eq!(gt.state(), GtState::ResettingEngines);
        assert_eq!(arena.live_allocations(), count);
        assert!(completion.result().is_none());
        assert!(gt.poll(10_000_000_002).is_pending());
        reset_done(&w);
        assert!(gt.poll(10_000_000_003).is_pending());
        assert_eq!(
            completion.result(),
            Some(Err(crate::intel_gpu_fence::JobError::Reset))
        );
        assert_eq!(arena.live_allocations(), 4);
        w.0.borrow_mut().regs.insert(0xd84, 0);
        assert!(gt.poll(10_000_000_004).is_pending());
        w.0.borrow_mut().regs.insert(0xdfc, 0);
        assert_eq!(gt.poll(10_000_000_005), Poll::Ready(Ok(GtState::Stopped)));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_context_faults_require_full_reset
);

fn smoke_hardware_boot_failure_and_cancelled_reload() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    hardware_discovery(&mut gt, &w, 0x130044);
    gt.begin_scheduling(12).unwrap();
    gt.begin_stop(13).unwrap();
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(14).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert_eq!(
        w.0.borrow()
            .writes
            .iter()
            .filter(|p| **p == (0xc314, 0x00110011))
            .count(),
        1
    );
    reset_done(&w);
    assert!(gt.poll(15).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(16).is_pending());
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(gt.poll(17), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);

    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    let (_, completion) = gt.submit_kernel_probe(26).unwrap();
    assert_eq!(gt.poll(27), Poll::Ready(Ok(GtState::SchedulingReady)));
    let weak = Rc::downgrade(&w.0);
    let count = arena.live_allocations();
    drop(w);
    drop(arena);
    drop(gt);
    assert_eq!(weak.upgrade().unwrap().borrow().memory.len(), count);
    assert!(completion.result().is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_boot_failure_and_cancelled_reload
);

fn smoke_hardware_context_pressure_and_identity() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    hardware_discovery(&mut gt, &w, 0x130044);
    hardware_scheduling(&mut gt, &w);
    let baseline = arena.live_allocations();
    let mut fences = Vec::new();
    for expected in 1..=64 {
        let (id, fence) = gt.submit_kernel_probe(26).unwrap();
        assert_eq!(id, expected);
        fences.push(fence);
    }
    assert!(gt.submit_kernel_probe(26).is_err());
    let mut registered = BTreeMap::new();
    assert_eq!(gt.poll(27), Poll::Ready(Ok(GtState::SchedulingReady)));
    service_contexts(&w, &mut registered, true);
    for now in 28..31 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
    }
    // Registrations and policies occupy the real H2G ring. Full leaves
    // unsent phases intact and does not poison a healthy GT.
    assert!(fences.iter().all(|f| f.result().is_none()));
    for now in 31..60 {
        service_contexts(&w, &mut registered, true);
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if fences.iter().all(|f| f.result().is_some()) {
            break;
        }
    }
    assert!(fences.iter().all(|f| f.result() == Some(Ok(()))));
    assert_eq!(arena.live_allocations(), baseline);
    let (id, _) = gt.submit_kernel_probe(61).unwrap();
    assert_eq!(id, 65);
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_context_pressure_and_identity
);

fn smoke_hardware_cache_policy_and_current_authority() -> TestResult {
    use crate::intel_gpu_gt_hw::{AuthorizedWindow, HardwareInit};
    use crate::intel_gpu_rcs::{GgttArena, SharedArena};
    use narf_capabilities::Cap;
    let mut memory = alloc::vec![0u32; 4*1024*1024];
    let bar = narf_bus::bar::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xdead0000),
        virt: memory.as_mut_ptr() as u64,
        len: 16 * 1024 * 1024,
        kind: narf_bus::bar::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    let cap: Cap<narf_bus::BusDeviceCap, narf_capabilities::Write> = Cap::bootstrap();
    let window = AuthorizedWindow::new(bar, cap);
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let mut arena = SharedArena::new(GgttArena::for_gt(bar, cap, platform));
    let mut backing = arena.alloc(1).unwrap();
    let pte = (0x800000 + u64::from(backing.ggtt_offset() / 4096) * 8) as usize / 4;
    assert_eq!(memory[pte], 0, "staging wrote live GGTT before reset");
    let mut hardware = HardwareInit::new(platform).unwrap();
    hardware.begin(&window, 0).unwrap();
    memory[0xd84 / 4] = 1;
    assert!(hardware.poll(&window, 1).is_pending());
    memory[0x941c / 4] = 0;
    memory[0xc000 / 4] = 1;
    assert!(hardware.poll(&window, 2).is_pending());
    memory[0x941c / 4] = 0;
    memory[0xfd0 / 4] = 1;
    let Poll::Ready(Ok(policy)) = hardware.poll(&window, 3) else {
        panic!("cache initialization")
    };
    assert_eq!(memory[pte], 0);
    arena.configure_cache(&mut backing, policy).unwrap();
    let entry = u64::from(memory[pte]) | u64::from(memory[pte + 1]) << 32;
    assert_eq!(entry & 0xfff0000000000fff, 0x0030000000000001);
    assert_eq!(backing.coherent_for_device(), cfg!(target_arch = "x86_64"));
    arena.free(backing);
    assert_eq!(memory[pte], 0);
    let old = memory[0x4000 / 4];
    cap.revoke();
    assert_eq!(window.read32(0x4000), u32::MAX);
    window.write32(0x4000, 0xaabbccdd);
    assert_eq!(memory[0x4000 / 4], old, "revoked authority wrote MMIO");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_cache_policy_and_current_authority
);

fn smoke_hardware_admission_and_boot_failure() -> TestResult {
    for compatibility in [true, false] {
        let (w, arena, mut gt) = hardware_model_with_interface(
            GtPlatform::Battlemage,
            0xdfc,
            if compatibility { 0 } else { 1 },
        );
        hardware_discovery(&mut gt, &w, 0xdfc);
        let count = arena.live_allocations();
        if !compatibility {
            w.0.borrow_mut().coherent = false;
        }
        assert!(gt.begin_scheduling(12).is_err());
        assert_eq!(gt.state(), GtState::Ready);
        assert_eq!(arena.live_allocations(), count);
        assert!(!w.0.borrow().writes.iter().any(|(reg, _)| *reg == 0x2080));
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    gt.begin(0).unwrap();
    w.0.borrow_mut().regs.insert(0x130044, 1);
    assert!(gt.poll(1).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 1);
    assert!(gt.poll(2).is_pending());
    assert!(matches!(
        gt.poll(5_000_002),
        Poll::Ready(Err(GtError::Hardware(_)))
    ));
    assert_eq!(gt.state(), GtState::Lost);
    assert!(!w
        .0
        .borrow()
        .writes
        .iter()
        .any(|(reg, _)| *reg == 0xc314 || *reg == 0xb020));
    gt.begin_stop(5_000_003).unwrap();
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(5_000_004).is_pending());
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(gt.poll(5_000_005), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_admission_and_boot_failure
);
