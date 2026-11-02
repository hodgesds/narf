// Native production GuC/ADS/CT reset conversations. Expected register names
// and flags are independent literals from MIT Linux b90c984d xe_guc_ads.c,
// xe_wa.c engine_was, xe_tuning.c engine_tunings and xe_hw_engine.c.
use super::*;
use crate::{
    intel_gpu_engine::Engine,
    intel_gpu_exec::PpgttProbeResult,
    intel_gpu_fence::JobError,
    intel_gpu_gt::Gen12Platform,
    intel_gpu_user::{UserBatch, UserContext},
};

fn expected_saves(
    platform: GtPlatform,
    device: u16,
    release: u32,
    engine: Engine,
) -> BTreeMap<u32, u32> {
    let base = engine.base();
    let mut entries = BTreeMap::from([
        (base + 0x80, 0),
        (base + 0xa8, 0),
        (base + 0xc4, 1),
        (base + 0x29c, 0),
    ]);
    // The hardware resets every FORCE_TO_NONPRIV slot, including unused
    // slots whose NOPID deny fill is part of NARF's verified access policy.
    for offset in (0x4d0..=0x4fc).step_by(4) {
        entries.insert(base + offset, 0);
    }
    if platform == GtPlatform::Battlemage {
        entries.extend([(base + 0x50, 1), (base + 0xd4, 1)]);
    }
    if engine != Engine::Rcs0 {
        return entries;
    }
    entries.insert(0x14800, 1);
    // The fixture has two physical CCSs on both discrete profiles, including
    // sparse CCS1/CCS3. Their selected count and dense identities are separate.
    if platform.is_discrete() {
        entries.insert(0x14804, 1);
    }
    // Sparse live DSS10 -> group2/instance2 for modern, DSS2 ->0/2 for Gen12.
    let mcr = if platform.is_gen12() {
        0x00200002
    } else {
        0x00202002
    };
    let shared: &[(u32, u32)] = match platform {
        GtPlatform::Gen12(_) => &[
            (0x20a0, 0),
            (0x20e0, 1),
            (0x20ec, 1),
            (0xb004, 0),
            (0xe18c, 1),
            (0xe48c, 1),
            (0xe4f4, 1),
        ],
        GtPlatform::Alchemist => &[
            (0x20ec, 1),
            (0x83b4, 1),
            (0xe18c, 1),
            (0xe48c, 1),
            (0xe4f4, 1),
            (0xe5f0, 1),
            (0xe7c8, 0),
            (0xe7cc, 0),
        ],
        GtPlatform::Integrated(_) => &[(0xe18c, 1), (0xe49c, 1), (0xe4f4, 1)],
        GtPlatform::Battlemage => &[
            (0xe194, 1),
            (0xe48c, 1),
            (0xe49c, 1),
            (0xe4c4, 1),
            (0xe4f0, 1),
            (0xe530, 0),
            (0xe5f4, 1),
            (0xe7c8, 0),
            (0xe7cc, 0),
        ],
    };
    for &(register, masked) in shared {
        entries.insert(
            register,
            masked
                | if (0xde80..=0xe8ff).contains(&register) {
                    mcr
                } else {
                    0
                },
        );
    }
    match platform {
        GtPlatform::Gen12(family) => {
            if matches!(family, Gen12Platform::TigerLake | Gen12Platform::AlderLakeP) {
                entries.insert(0x2050, 1);
            }
            for register in (0xb020..=0xb09c).step_by(4) {
                entries.insert(register, 0);
            }
        }
        GtPlatform::Alchemist if device == 0x56a5 => {
            entries.insert(0xe420, mcr | 1);
        }
        GtPlatform::Integrated(_) if release <= 71 => {
            entries.insert(0xe5f0, mcr | 1);
        }
        _ => {}
    }
    entries
}

/// Firmware reads the actual production ADS, captures current register words
/// into its value scratch, resets independently specified engine state, then
/// restores through the flags/steering ABI. No host WA replay can hide a hole.
fn firmware_reset(w: &Window, engine: Engine, expected: &BTreeMap<u32, u32>) {
    let wire = ads_registers(w, engine);
    let mut d = w.0.borrow_mut();
    let ads_memory = d.memory[&0x20001000].clone();
    let mut ads = ads_memory.borrow_mut();
    let header = (engine.guc_class() * 256 + engine.physical_instance() * 8) as usize / 4;
    let first = (ads[header] - 0x20001000) as usize / 4;
    let count = ads[header + 1] as usize;
    let captured: BTreeMap<_, _> = expected
        .iter()
        .map(|(reg, flags)| {
            let value = *d.regs.get(&u64::from(*reg)).unwrap_or(&0);
            (
                *reg,
                if flags & 1 != 0 {
                    value & 0xffff
                } else {
                    value
                },
            )
        })
        .collect();
    for index in 0..count {
        let word = first + index * 4;
        let reg = ads[word];
        let value = *d.regs.get(&u64::from(reg)).unwrap_or(&0);
        ads[word + 1] = value;
    }
    // Reset erases the independently enumerated hardware state even when a
    // save entry is accidentally omitted. GT-only policy is outside this set.
    for register in expected.keys() {
        d.regs.insert(u64::from(*register), 0);
    }
    for index in 0..count {
        let word = first + index * 4;
        let reg = ads[word];
        let flags = ads[word + 2];
        let value = ads[word + 1];
        let old = *d.regs.get(&u64::from(reg)).unwrap_or(&0);
        d.regs.insert(
            u64::from(reg),
            if flags & 1 != 0 {
                (old & !0xffff) | (value & 0xffff)
            } else {
                value
            },
        );
    }
    for (register, value) in captured {
        assert_eq!(
            d.regs[&u64::from(register)],
            value,
            "reset lost register {register:#x}"
        );
    }
    assert_eq!(
        wire.iter()
            .map(|(r, (_, f))| (*r, *f))
            .collect::<BTreeMap<_, _>>(),
        *expected
    );
}

fn smoke_guc_source_engine_saves_survive_actual_isolated_reset() -> TestResult {
    use crate::intel_gpu::Generation;
    let lpg = GtPlatform::Integrated(Generation::MeteorLake);
    for (platform, device, release) in [
        (GtPlatform::Gen12(Gen12Platform::TigerLake), 0x9a49, 0),
        (GtPlatform::Gen12(Gen12Platform::AlderLakeP), 0x46a6, 0),
        (GtPlatform::Gen12(Gen12Platform::AlderLakeS), 0x4680, 0),
        (GtPlatform::Gen12(Gen12Platform::AlderLakeN), 0x46d1, 0),
        (GtPlatform::Alchemist, 0x56a0, 55),
        (GtPlatform::Alchemist, 0x56a5, 55),
        (GtPlatform::Alchemist, 0x56a3, 55),
        (lpg, 0x7d55, 70),
        (lpg, 0x7d55, 71),
        (lpg, 0x7d55, 74),
        (GtPlatform::Battlemage, 0xe20b, 1),
        (GtPlatform::Battlemage, 0xe20b, 2),
    ] {
        let ack = platform.guc_forcewake_ack().unwrap();
        let (w, arena, mut gt) = hardware_model_with_identity(platform, ack, 1, Some(device));
        {
            let mut d = w.0.borrow_mut();
            d.regs.insert(
                0x913c,
                if platform.is_gen12() {
                    1 << 2
                } else {
                    (1 << 10) | (1 << 24)
                },
            );
            d.regs.insert(0x9144, 0);
            if platform == GtPlatform::Battlemage {
                d.regs.insert(0x9114, 0x10 | 10 << 16);
            }
            if !platform.is_gen12() && platform != GtPlatform::Alchemist {
                d.regs.insert(
                    0xd8c,
                    if platform == GtPlatform::Battlemage {
                        20 << 22 | release << 14
                    } else {
                        12 << 22 | release << 14
                    },
                );
            }
        }
        hardware_discovery(&mut gt, &w, ack);
        hardware_scheduling_reload_mode(&mut gt, &w, if platform.is_discrete() { 2 } else { 1 });
        hardware_enable_ct(&mut gt, &w);
        let completion = gt.begin_context_defaults(10_000_000).unwrap();
        let mut registered = BTreeMap::new();
        for now in 10_000_001..10_000_501 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            if completion.result().is_some() {
                break;
            }
        }
        assert_eq!(completion.result(), Some(Ok(())));
        let epoch = gt.user_epoch();
        assert!(epoch.is_some());
        let baseline = arena.live_allocations();
        for (index, engine) in gt.engines().unwrap().iter().enumerate() {
            let start = 20_000_000 + index as u64 * 1_000_000;
            let context = UserContext::for_engine(engine);
            let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
            let (id, fence) = gt
                .submit_user_batch(start, context.clone(), UserBatch(batch))
                .unwrap();
            for now in start + 1..start + 30 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, false);
            }
            assert!(registered.contains_key(&u32::from(id)) && fence.result().is_none());
            let expected = expected_saves(platform, device, release, engine);
            firmware_reset(&w, engine, &expected);
            let writes = w.0.borrow().writes.len();
            event(&ct_memory(&w), 0x1008, &[u32::from(id)]);
            for now in start + 30..start + 100 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, false);
                if fence.result().is_some() {
                    break;
                }
            }
            assert_eq!(fence.result(), Some(Err(JobError::Hang)));
            assert!(context.banned() && !context.busy());
            assert!(result.verify().is_err() && registered.is_empty());
            assert_eq!(gt.user_epoch(), epoch);
            // Isolated recovery cannot replay host workarounds or reset the
            // whole GT. A fresh private PPGTT job executes on the same engine.
            assert!(
                !w.0.borrow().writes[writes..]
                    .iter()
                    .any(|(r, _)| *r == 0x941c || expected.contains_key(&(*r as u32)))
            );
            let probe = gt.submit_ppgtt_probe_on(start + 200, engine).unwrap();
            for now in start + 201..start + 300 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, true);
                if probe.completion.result().is_some() {
                    break;
                }
            }
            assert_eq!(probe.completion.result(), Some(Ok(())));
            assert_eq!(probe.result.verify(), Ok(()));
            drop((probe, result));
            assert_eq!(arena.live_allocations(), baseline);
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_guc_source_engine_saves_survive_actual_isolated_reset
);
