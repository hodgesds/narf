//! RCS default-context commands and non-terminated command-streamer steering.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_wa.c lrc_was,
//! xe_tuning.c lrc_tunings, xe_hw_engine_setup_default_lrc_state,
//! xe_gt_mcr.c, xe_gt.c emit_wa_job and xe_lrc.c xe_hpg_svg_state.
//! This seeds context state; it is not the global GT/engine workaround table.

use crate::{
    intel_gpu_aux::MmioWindow, intel_gpu_gt::GtPlatform, intel_gpu_hwconfig::HardwareConfig,
    intel_gpu_topology::GtTopology,
};
use alloc::{vec, vec::Vec};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ContextError {
    Unsupported,
    Unavailable,
    Unstable,
    Topology,
    Hwconfig,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct ContextSeed {
    platform: GtPlatform,
    dss: u32,
    l3: u32,
    disable_wmtp: bool,
    graphics: u16,
}

impl ContextSeed {
    pub(crate) fn read(
        mmio: &impl MmioWindow,
        platform: GtPlatform,
        topology: &GtTopology,
        config: &HardwareConfig,
    ) -> Result<Self, ContextError> {
        platform.guc().ok_or(ContextError::Unsupported)?;
        if topology.platform() != platform || !topology.has_render() {
            return Err(ContextError::Topology);
        }
        let graphics = if platform == GtPlatform::Alchemist {
            1255
        } else {
            let a = mmio.read32(0xd8c);
            let b = mmio.read32(0xd8c);
            if a == u32::MAX || b == u32::MAX {
                return Err(ContextError::Unavailable);
            }
            if a != b {
                return Err(ContextError::Unstable);
            }
            let version = (a >> 22) * 100 + ((a >> 14) & 255);
            let supported = match platform {
                GtPlatform::Battlemage => matches!(version, 2001 | 2002),
                _ => matches!(version, 1270 | 1271 | 1274),
            };
            if !supported {
                return Err(ContextError::Unsupported);
            }
            version as u16
        };
        let slices = config.lookup_u32(1).map_err(|_| ContextError::Hwconfig)?;
        let subs = config.lookup_u32(70).map_err(|_| ContextError::Hwconfig)?;
        // xe_gt_mcr.c uses the physical layout maxima, not live DSS counts.
        let per_group = match (slices, subs) {
            (Some(s), Some(d)) if s != 0 && d != 0 => d.div_ceil(s),
            _ => 4,
        };
        if per_group == 0 || per_group > 32 {
            return Err(ContextError::Hwconfig);
        }
        let first = (topology.geometry_dss() | topology.compute_dss()).trailing_zeros();
        let dss = steering(first / per_group, first % per_group)?;
        let a = [mmio.read32(0x9114), mmio.read32(0x9118)];
        let b = [mmio.read32(0x9114), mmio.read32(0x9118)];
        if a.contains(&u32::MAX) || b.contains(&u32::MAX) {
            return Err(ContextError::Unavailable);
        }
        if a != b {
            return Err(ContextError::Unstable);
        }
        let l3 = if platform == GtPlatform::Battlemage {
            0 // no L3SQCREG5 tuning on Xe2
        } else {
            let mslices = a[1] & 15;
            if mslices == 0 {
                return Err(ContextError::Topology);
            }
            let slice = mslices.trailing_zeros();
            if platform == GtPlatform::Alchemist {
                let bank = slice * 8;
                steering((bank >> 2) & 7, bank & 3)?
            } else {
                // Bank zero is terminated only for exclusion mask 010b.
                steering(slice, if a[0] & 0x10 != 0 { 0 } else { 2 })?
            }
        };
        Ok(Self {
            platform,
            dss,
            l3,
            disable_wmtp: a[0] & (1 << 20) != 0,
            graphics,
        })
    }

    /// Direct privileged ring commands, only while priming owns RCS0.
    pub(crate) fn commands(self) -> Vec<u32> {
        let mut masked = match self.platform {
            GtPlatform::Alchemist => vec![
                (0x6208, 0x00200020), // TBIMR tuning
                (0x7004, 0x08000800), // 18019271663
                (0x703c, 0x00200020), // 18018764978
                (0x7044, 0x00200020), // 14019877138
                (0x731c, 0x40004000), // 16013271637
                (0x83a4, 0xffff4000), // 14014947963
            ],
            GtPlatform::Battlemage => vec![
                (
                    0x6204,
                    if self.graphics == 2001 {
                        0x01400140
                    } else {
                        0x00400040
                    },
                ),
                (0x6208, 0x00200020), // 14021567978
                (0x7044, 0x04200420), // 14019988906, 14019877138
                (0x7300, 0x10001000), // 22021007897
                (0x83a8, 0x20002000), // 14019386621
            ],
            _ => vec![(0x7004, 0x08000800), (0x7044, 0x00200020)],
        };
        if self.graphics == 2001 {
            masked.extend_from_slice(&[
                (0x5588, 0x04000400), // 14020756599
                (0x62a8, 0x02400240), // 14021490052
                (0x7010, 0x40004000), // 18033852989
            ]);
            masked.sort_unstable_by_key(|pair| pair.0);
        }
        if self.platform == GtPlatform::Battlemage && self.disable_wmtp {
            masked.insert(0, (0x2580, 0x00060002));
        }
        let mut words = vec![0, 0x11000000 | (masked.len() as u32 * 2 - 1)];
        for (reg, value) in masked {
            words.extend_from_slice(&[reg, value]);
        }
        if self.graphics == 2001 {
            // FF_MODE is NOT a masked register; preserve all unrelated bits.
            rmw(&mut words, 0x6210, 0x03f18000, 0x03f18000, self.dss);
        } else if self.platform != GtPlatform::Battlemage {
            if self.platform == GtPlatform::Alchemist {
                rmw(&mut words, 0x6604, 0x00ff0000, 0x00040000, self.dss);
            }
            rmw(&mut words, 0xb158, 0x3ff, 0x7f, self.l3);
        }
        // Reset all scratch registers and selective-read steering.
        words.extend_from_slice(&[
            0, 0x11080005, 0x600, 0, 0x608, 0, 0x610, 0, 0, 0x11000001, 0x20cc, 0,
        ]);
        if self.platform == GtPlatform::Alchemist {
            // Wa_14019789679: explicitly create every SVG restore header.
            for &(subopcode, size) in SVG {
                words.push(0x78000000 | u32::from(subopcode) << 16 | (size - 2));
                words.resize(words.len() + size as usize - 1, 0);
            }
        }
        words
    }
}

fn steering(group: u32, instance: u32) -> Result<u32, ContextError> {
    if group > 127 || instance > 127 {
        return Err(ContextError::Topology);
    }
    Ok(0x40000000 | group << 23 | instance << 16)
}

fn rmw(words: &mut Vec<u32>, reg: u32, clear: u32, set: u32, steer: u32) {
    // xe_gt.c::emit_wa_job, including CS-relative GPR access. Selective reads
    // target a live instance; the LRR write remains multicast.
    words.extend_from_slice(&[
        0, 0x11000001, 0x20cc, steer, 0x15080001, reg, 0x600, 0, 0x11080003, 0x608, clear, 0x610,
        set, 0x0d000007, 0x08008000, 0x48008401, 0x10200000, 0x18000031, 0x08008000, 0x08008402,
        0x10300000, 0x18000031, 0x15040001, 0x600, reg,
    ]);
}

// xe_lrc.c xe_hpg_svg_state, in hardware save order. Subopcode 0x100 is
// non-pipelined 3DSTATE_DRAWING_RECTANGLE (opcode 1, subopcode 0).
const SVG: &[(u16, u32)] = &[
    (0x15, 11),
    (0x19, 11),
    (0x1a, 11),
    (0x16, 11),
    (0x09, 69),
    (0x55, 5),
    (0x4a, 2),
    (0x56, 3),
    (0x10, 9),
    (0x26, 2),
    (0x2b, 2),
    (0x58, 3),
    (0x1e, 5),
    (0x60, 8),
    (0x61, 8),
    (0x62, 8),
    (0x63, 8),
    (0x12, 4),
    (0x6c, 6),
    (0x81, 2),
    (0x13, 4),
    (0x0f, 2),
    (0x21, 2),
    (0x50, 5),
    (0x6e, 4),
    (0x52, 6),
    (0x0d, 2),
    (0x1b, 9),
    (0x27, 2),
    (0x2c, 2),
    (0x59, 3),
    (0x7c, 3),
    (0x7d, 7),
    (0x7e, 10),
    (0x80, 3),
    (0x1c, 5),
    (0x79, 2),
    (0x1d, 11),
    (0x28, 2),
    (0x2d, 2),
    (0x5a, 3),
    (0x11, 10),
    (0x29, 2),
    (0x2e, 2),
    (0x5b, 3),
    (0x77, 3),
    (0x7b, 10),
    (0x7f, 3),
    (0x7a, 8),
    (0x100, 4),
];

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use core::cell::Cell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Window {
        regs: BTreeMap<u64, u32>,
        reads: Cell<u32>,
        unstable: bool,
    }
    impl MmioWindow for Window {
        fn read32(&self, offset: u64) -> u32 {
            let reads = self.reads.get();
            self.reads.set(reads + 1);
            self.regs.get(&offset).copied().unwrap_or(0)
                ^ if self.unstable && reads >= 8 && offset == 0x9118 {
                    1
                } else {
                    0
                }
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("seed planning wrote hardware");
        }
    }
    fn window() -> Window {
        Window {
            regs: BTreeMap::from([
                (0x913c, 1 << 18),
                (0x9144, 0),
                (0x9134, 1),
                (0x9114, 0x100020),
                (0x9118, 8),
            ]),
            reads: Cell::new(0),
            unstable: false,
        }
    }
    fn hwconfig() -> HardwareConfig {
        let bytes: Vec<_> = [1u32, 1, 4, 70, 1, 32]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        HardwareConfig::parse(bytes).unwrap()
    }

    /// Independent MI interpreter for the source-defined default-state stream.
    /// Registers are the device's live state, not values computed by the driver.
    pub(crate) fn execute(words: &[u32], regs: &mut BTreeMap<u64, u32>) -> (Vec<u32>, usize) {
        let mut i = 0;
        let mut svg = Vec::new();
        while i < words.len() {
            let cmd = words[i];
            if cmd == 0 {
                i += 1;
            } else if cmd & 0xff000000 == 0x11000000 {
                let count = (cmd & 255).div_ceil(2);
                for pair in 0..count as usize {
                    let reg = u64::from(words[i + 1 + pair * 2])
                        + if cmd & 0x80000 != 0 { 0x2000 } else { 0 };
                    let value = words[i + 2 + pair * 2];
                    let masked = matches!(
                        reg,
                        0x2580
                            | 0x5588
                            | 0x6204
                            | 0x6208
                            | 0x62a8
                            | 0x7004
                            | 0x7010
                            | 0x703c
                            | 0x7044
                            | 0x7300
                            | 0x731c
                            | 0x83a4
                            | 0x83a8
                    );
                    let old = regs.get(&reg).copied().unwrap_or(0);
                    regs.insert(
                        reg,
                        if masked {
                            (old & !(value >> 16)) | (value & (value >> 16))
                        } else {
                            value
                        },
                    );
                }
                i += count as usize * 2 + 1;
            } else if cmd == 0x15080001 || cmd == 0x15040001 {
                let src = u64::from(words[i + 1]) + if cmd == 0x15040001 { 0x2000 } else { 0 };
                let dst = u64::from(words[i + 2]) + if cmd == 0x15080001 { 0x2000 } else { 0 };
                let value = regs.get(&src).copied().unwrap_or(0);
                regs.insert(dst, value);
                i += 3;
            } else if cmd == 0x0d000007 {
                assert_eq!(
                    &words[i + 1..i + 9],
                    &[
                        0x08008000, 0x48008401, 0x10200000, 0x18000031, 0x08008000, 0x08008402,
                        0x10300000, 0x18000031,
                    ]
                );
                let value = (regs[&0x2600] & !regs[&0x2608]) | regs[&0x2610];
                regs.insert(0x2600, value);
                i += 9;
            } else if cmd & 0xff000000 == 0x78000000 || cmd & 0xff000000 == 0x79000000 {
                let len = (cmd & 255) as usize + 2;
                assert!(words[i + 1..i + len].iter().all(|word| *word == 0));
                svg.push(cmd);
                i += len;
            } else {
                break;
            }
        }
        (svg, i)
    }

    fn smoke_context_workaround_and_steering_vectors() -> TestResult {
        for platform in [
            GtPlatform::Alchemist,
            GtPlatform::Battlemage,
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
        ] {
            let mut window = window();
            window.regs.insert(
                0xd8c,
                if platform == GtPlatform::Battlemage {
                    (20 << 22) | (1 << 14)
                } else {
                    (12 << 22) | (70 << 14)
                },
            );
            let topology = GtTopology::read(&window, platform).unwrap();
            let seed = ContextSeed::read(&window, platform, &topology, &hwconfig()).unwrap();
            assert_eq!(seed.dss, 0x41020000); // DSS18 / 8 per physical group
            let words = seed.commands();
            let mut regs = BTreeMap::from([
                (0x6210, 0xa4000001),
                (0xb158, 0xa50003aa),
                (0x6604, 0xa5ff1234),
            ]);
            let (svg, count) = execute(&words, &mut regs);
            assert_eq!(count, words.len());
            assert_eq!(regs[&0x7044] & 0x20, 0x20);
            assert_eq!(
                (regs[&0x2600], regs[&0x2608], regs[&0x2610], regs[&0x20cc]),
                (0, 0, 0, 0)
            );
            if platform == GtPlatform::Battlemage {
                assert_eq!(regs[&0x6210], 0xa7f18001);
                assert_eq!(regs[&0x2580], 2);
                assert_eq!(regs[&0x6204], 0x140);
                assert_eq!(regs[&0x7044], 0x420);
                assert!(svg.is_empty());
            } else {
                assert_eq!(regs[&0xb158], 0xa500007f);
                assert_eq!(
                    seed.l3,
                    if platform == GtPlatform::Alchemist {
                        0x43000000
                    } else {
                        0x41820000
                    }
                );
                if platform == GtPlatform::Alchemist {
                    assert_eq!(regs[&0x6604], 0xa5041234);
                    assert_eq!(regs[&0x83a4], 0x4000);
                    assert_eq!(svg.len(), 50);
                    assert_eq!(
                        &svg[..5],
                        &[0x78150009, 0x78190009, 0x781a0009, 0x78160009, 0x78090043]
                    );
                    assert_eq!(
                        &svg[svg.len() - 5..],
                        &[0x78770001, 0x787b0008, 0x787f0001, 0x787a0006, 0x79000002]
                    );
                } else {
                    assert!(svg.is_empty());
                }
            }
        }
        let mut w = window();
        w.regs.insert(0xd8c, (20 << 22) | (2 << 14));
        let topo = GtTopology::read(&w, GtPlatform::Battlemage).unwrap();
        let words = ContextSeed::read(&w, GtPlatform::Battlemage, &topo, &hwconfig())
            .unwrap()
            .commands();
        let mut regs = BTreeMap::from([(0x6210, 0xa4000001)]);
        execute(&words, &mut regs);
        assert_eq!(regs[&0x6204], 0x40);
        assert_eq!(regs[&0x6210], 0xa4000001);
        assert!(!regs.contains_key(&0x5588) && !regs.contains_key(&0x62a8));
        w.regs.insert(0xd8c, (20 << 22) | (4 << 14));
        assert_eq!(
            ContextSeed::read(&w, GtPlatform::Battlemage, &topo, &hwconfig()).unwrap_err(),
            ContextError::Unsupported
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_context",
        smoke_context_workaround_and_steering_vectors
    );

    fn smoke_context_seed_refuses_bad_fuses_and_layout() -> TestResult {
        for (reg, value, error) in [
            (0x9118, 0, ContextError::Topology),
            (0x9114, u32::MAX, ContextError::Unavailable),
            (0x9118, u32::MAX, ContextError::Unavailable),
        ] {
            let mut w = window();
            w.regs.insert(reg, value);
            let topo = GtTopology::read(&w, GtPlatform::Alchemist).unwrap();
            assert_eq!(
                ContextSeed::read(&w, GtPlatform::Alchemist, &topo, &hwconfig()).unwrap_err(),
                error
            );
        }
        let mut w = window();
        w.unstable = true;
        let topo = GtTopology::read(&w, GtPlatform::Alchemist).unwrap();
        assert_eq!(
            ContextSeed::read(&w, GtPlatform::Alchemist, &topo, &hwconfig()).unwrap_err(),
            ContextError::Unstable
        );
        for words in [vec![1u32, 2, 4, 4], vec![1u32, 1, 1, 70, 1, 256]] {
            let w = window();
            let topo = GtTopology::read(&w, GtPlatform::Alchemist).unwrap();
            let config =
                HardwareConfig::parse(words.into_iter().flat_map(u32::to_le_bytes).collect())
                    .unwrap();
            assert_eq!(
                ContextSeed::read(&w, GtPlatform::Alchemist, &topo, &config).unwrap_err(),
                ContextError::Hwconfig
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_context",
        smoke_context_seed_refuses_bad_fuses_and_layout
    );
}
