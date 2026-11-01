//! Graphics-GT and RCS0 MMIO workarounds, separate from saved LRC state.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_wa.c gt_was /
//! engine_was, xe_tuning.c, xe_hw_engine.c and xe_gt_mcr.c. Media GT and
//! non-render engine admission require their own initialization tables.

use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_context::{ContextError, ContextSeed},
    intel_gpu_gt::GtPlatform,
    intel_gpu_hwconfig::HardwareConfig,
    intel_gpu_topology::GtTopology,
};
use alloc::vec::Vec;
use core::task::Poll;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegisterError {
    Identity,
    Context(ContextError),
    Unavailable,
    Timeout,
    Verify(u64),
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Window {
        regs: RefCell<BTreeMap<u64, u32>>,
        writes: RefCell<Vec<(u64, u32)>>,
        reject: Cell<u64>,
        unavailable: Cell<u64>,
        selector: u64,
        dss: u32,
    }
    impl MmioWindow for Window {
        fn read32(&self, reg: u64) -> u32 {
            assert_ne!(reg, 0xe420, "DG2 CACHE_MODE_SS readback is forbidden");
            if reg == self.unavailable.get() {
                return u32::MAX;
            }
            if matches!(reg, 0xe7c8 | 0xe7cc | 0xe530) {
                assert_eq!(self.regs.borrow().get(&self.selector), Some(&self.dss));
            }
            *self.regs.borrow().get(&reg).unwrap_or(&0xa5a55a5a)
        }
        fn write32(&self, reg: u64, value: u32) {
            self.writes.borrow_mut().push((reg, value));
            if reg == self.reject.get() {
                return;
            }
            let mut regs = self.regs.borrow_mut();
            let old = *regs.get(&reg).unwrap_or(&0xa5a55a5a);
            let masked = matches!(
                reg,
                0x20ec
                    | 0x83b4
                    | 0xe48c
                    | 0xe18c
                    | 0xe4f4
                    | 0xe5f0
                    | 0xe420
                    | 0xe49c
                    | 0xe4f0
                    | 0x20d4
                    | 0xe194
                    | 0xe4c4
                    | 0xe5f4
                    | 0x2050
                    | 0x220d4
                    | 0x22050
            );
            regs.insert(
                reg,
                if masked {
                    (old & !(value >> 16)) | (value & (value >> 16))
                } else {
                    value
                },
            );
        }
    }
    fn fixture(
        platform: GtPlatform,
        device: u16,
        release: u32,
        step: u32,
        flat: bool,
        live: u32,
    ) -> (Window, RegisterInit) {
        let modern = platform != GtPlatform::Alchemist;
        let first = live.trailing_zeros();
        let dss = 0x80000000
            | if modern {
                (first / 8) << 8 | (first % 8)
            } else {
                (first / 8) << 27 | (first % 8) << 24
            };
        let window = Window {
            regs: RefCell::new(BTreeMap::from([
                (0xfd0, 1),
                (0xfd4, 0x80000101),
                (0xfdc, 0x81000000),
                (0x913c, live),
                (0x9144, 0),
                (0x9134, 1),
                (0x9114, 0x10),
                (0x9118, 4),
                (
                    0xd8c,
                    (if platform == GtPlatform::Battlemage {
                        20
                    } else {
                        12
                    }) << 22
                        | release << 14
                        | step,
                ),
                (0x8800, u32::from(flat)),
            ])),
            writes: RefCell::new(Vec::new()),
            reject: Cell::new(0),
            unavailable: Cell::new(0),
            selector: if modern { 0xfd4 } else { 0xfdc },
            dss,
        };
        let topology = GtTopology::read(&window, platform).unwrap();
        let bytes = [1u32, 1, 4, 70, 1, 32]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let config = HardwareConfig::parse(bytes).unwrap();
        let init = RegisterInit::new(&window, platform, device, &topology, &config, 10).unwrap();
        (window, init)
    }

    fn smoke_global_register_dg2_subplatform_vectors() -> TestResult {
        for (device, g10, g11) in [
            (0x56a0, true, false),
            (0x56a5, false, true),
            (0x56a3, false, false),
        ] {
            let (w, init) = fixture(GtPlatform::Alchemist, device, 55, 0, false, 1 << 18);
            w.regs.borrow_mut().insert(0xe7cc, 0x12345678);
            assert_eq!(init.poll(&w, 11), Poll::Ready(Ok(None)));
            let r = w.regs.borrow();
            assert_eq!(r[&0xfdc], 0x81000000);
            assert_eq!((r[&0xfd0], r[&0xfd8]), (0x02000000, 0x02000000));
            assert_eq!(r[&0xe7cc], if g11 { 0x16b45658 } else { 0x16b45678 });
            assert_eq!(
                r[&0xe7c8],
                0xa5a55a5a | if g11 { 0x40008000 } else { 0x40000000 }
            );
            assert_eq!(r[&0xe5f0], (0xa5a55a5a & !0x3808) | 8);
            assert_eq!(r[&0xe18c], 0xa5a55a5a | 0x201);
            assert_eq!(r[&0xe90c], 0xa5a55a5a & !0x60000000);
            assert_eq!(w.writes.borrow().contains(&(0xe420, 0x00080008)), g11);
            assert_eq!(r.contains_key(&0x9434), g10);
            assert_eq!(r.contains_key(&0x9524), g10);
            for reg in [0xcf2c, 0xcf30, 0xcf34, 0xcf38] {
                assert_eq!(r[&reg], 0xa5a55a5a | 8);
            }
            assert!(w.writes.borrow().contains(&(0xfdc, 0x90000000))); // MSLICE2
            assert!(w.writes.borrow().contains(&(0xfdc, 0xa0000000))); // L3 group4
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt_registers",
        smoke_global_register_dg2_subplatform_vectors
    );

    fn smoke_global_register_xelpg_stepping_vectors() -> TestResult {
        for (release, step, clock, atomic) in [
            (70, 0, true, true),
            (71, 3, true, true),
            (71, 4, false, true),
            (74, 0, false, false),
        ] {
            let (w, init) = fixture(
                GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
                0x7d55,
                release,
                step,
                false,
                1 << 18,
            );
            assert!(matches!(init.poll(&w, 11), Poll::Ready(Ok(_))));
            let r = w.regs.borrow();
            assert_eq!(r.contains_key(&0x9424), clock);
            assert_eq!(r.contains_key(&0xe5f0), atomic);
            assert_eq!(r[&0xe49c], 0xa5a55a5a | 0x200);
            assert_eq!(r[&0xe4f4], 0xa5a55a5a | 2);
            assert_eq!(r[&0xcf30], 0xa5a55a5a | 8);
            assert_eq!(r[&0x8718], 0xa5a55a5a | 0x800000);
            assert_eq!((r[&0xfd4], r[&0xfd0]), (0x80000101, 1));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt_registers",
        smoke_global_register_xelpg_stepping_vectors
    );

    fn smoke_global_register_xe2_fuse_and_ip_vectors() -> TestResult {
        for (release, flat, live, gap) in [
            (1, true, 1, false),
            (2, false, 1 | (1 << 16), true),
            (1, false, 1 << 8, true),
        ] {
            let (w, init) = fixture(GtPlatform::Battlemage, 0xe20b, release, 0, flat, live);
            let Poll::Ready(Ok(Some(vram))) = init.poll(&w, 11) else {
                return TestResult::Fail("BMG did not capture local-memory registers");
            };
            assert_eq!(vram.ccs_lower & 1 != 0, flat);
            let r = w.regs.borrow();
            assert_eq!(r.contains_key(&0xb0c8), release == 1);
            if release == 1 {
                assert_eq!(r[&0xb0c8], 0x11111a5a);
            }
            assert_eq!(r.contains_key(&0x8828), flat);
            assert_eq!(r.contains_key(&0xb104), flat);
            assert_eq!(r.contains_key(&0xe5f4), gap);
            assert_eq!(
                r[&0xe7c8],
                0xa5a55a5a | if release == 1 { 0x04002000 } else { 0x2000 }
            );
            assert_eq!(r[&0xe7cc], 0xa5a55a5a | 0x9000);
            assert_eq!(r[&0x20d4], 0xa5a55a5a | 0xc080);
            assert_eq!(r[&0xe4c4], 0xa5a55a5a | 0x1040);
            assert_eq!(r[&0xb158], 0xa5a5587f);
            assert_eq!(r[&0x4148], 0xa5a55a50);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt_registers",
        smoke_global_register_xe2_fuse_and_ip_vectors
    );

    // xe_hw_engine.c compute fuses and __xe_gt_apply_ccs_mode(ccs_mode 1).
    fn smoke_global_register_ccs_inventory_and_mode() -> TestResult {
        use crate::intel_gpu_engine::Engine;
        // DG2 quadrants are 8 DSS: CCSn exists iff quadrant n has a DSS.
        for (live, ccs0, multi) in [
            (0x0101_0101, true, true),
            (0x0000_00ff, true, false),
            (0x0000_0100, false, false),
        ] {
            let (w, init) = fixture(GtPlatform::Alchemist, 0x56a0, 0, 0, false, live);
            assert_eq!(init.engines().contains(Engine::Ccs0), ccs0);
            assert!(matches!(init.poll(&w, 11), Poll::Ready(Ok(None))));
            let writes = w.writes.borrow();
            assert_eq!(writes.contains(&(0x14800, 0x0002_0002)), multi);
            assert_eq!(writes.contains(&(0x14804, 0x0fff_0000)), multi);
            // CCS0 receives the OAG grants only when published.
            assert_eq!(writes.contains(&(0x1a4d0, 0x1000_dafc)), ccs0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt_registers",
        smoke_global_register_ccs_inventory_and_mode
    );

    fn smoke_global_register_wait_and_failure_cleanup() -> TestResult {
        for failure in 0..4 {
            let (w, init) = fixture(GtPlatform::Battlemage, 0xe20b, 1, 0, false, 1);
            if failure == 0 {
                w.regs.borrow_mut().insert(0xfd0, 0);
                for now in 11..15 {
                    assert!(init.poll(&w, now).is_pending());
                }
                assert!(w.writes.borrow().is_empty());
                assert_eq!(
                    init.poll(&w, 50_000_010),
                    Poll::Ready(Err(RegisterError::Timeout))
                );
                assert!(w.writes.borrow().is_empty());
                continue;
            }
            if failure == 1 {
                w.unavailable.set(0xe7cc);
            }
            if failure == 2 {
                w.reject.set(0xe48c);
            }
            if failure == 3 {
                w.reject.set(0xfd4);
            }
            assert!(matches!(init.poll(&w, 11), Poll::Ready(Err(_))));
            assert_eq!(w.regs.borrow()[&0xfd4], 0x80000101);
            assert_eq!(w.writes.borrow().last(), Some(&(0xfd0, 1)));
            if failure == 1 {
                assert!(!w.writes.borrow().iter().any(|p| p.0 == 0xb0c8));
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt_registers",
        smoke_global_register_wait_and_failure_cleanup
    );
}

#[derive(Copy, Clone, Debug)]
enum Target {
    Direct,
    Dss,
    L3,
    Mslice,
    Instance0,
    Implicit,
}

#[derive(Copy, Clone, Debug)]
struct Entry {
    reg: u64,
    clear: u32,
    set: u32,
    masked: bool,
    verify: bool,
    target: Target,
}

/// The enclosing GT owns both forcewake wells and serializes host users.
/// A busy firmware steering semaphore yields without any register mutation.
pub(crate) struct RegisterInit {
    platform: GtPlatform,
    device: u16,
    seed: ContextSeed,
    discontiguous: bool,
    /// Physically present CCS instances (bit n = CCSn).
    compute: u8,
    deadline: u64,
}

impl RegisterInit {
    pub(crate) fn new(
        mmio: &impl MmioWindow,
        platform: GtPlatform,
        device: u16,
        topology: &GtTopology,
        config: &HardwareConfig,
        now: u64,
    ) -> Result<Self, RegisterError> {
        if GtPlatform::from_pci(0x8086, device) != Some(platform) {
            return Err(RegisterError::Identity);
        }
        let seed =
            ContextSeed::read(mmio, platform, topology, config).map_err(RegisterError::Context)?;
        // xe_gt_has_discontiguous_dss_groups: include the gap before the
        // first live group, and use the union of render/compute DSS fuses.
        let mut last = None;
        let mut discontiguous = false;
        let live = topology.geometry_dss() | topology.compute_dss();
        for i in 0..32 {
            if live & (1 << i) == 0 {
                continue;
            }
            let group = i / u32::from(seed.per_group);
            if last != Some(group) {
                discontiguous |= group > last.map_or(0, |v| v + 1);
                last = Some(group);
            }
        }
        let compute = crate::intel_gpu_engine::compute_instances(
            platform,
            topology.geometry_dss() | topology.compute_dss(),
            seed.fuse4,
        );
        Ok(Self {
            platform,
            device,
            seed,
            discontiguous,
            compute,
            deadline: now.checked_add(50_000_000).ok_or(RegisterError::Timeout)?,
        })
    }

    /// RCS0 and BCS0 always; CCS0 when its instance is fused present.
    pub(crate) fn engines(&self) -> crate::intel_gpu_engine::EngineSet {
        use crate::intel_gpu_engine::{Engine, EngineSet};
        if self.compute & 1 != 0 {
            EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Ccs0])
        } else {
            EngineSet::of(&[Engine::Rcs0, Engine::Bcs0])
        }
    }

    /// Ready(Ok(Some)) also returns BMG's local-memory layout registers,
    /// read under the same steering semaphore as the workaround writes.
    pub(crate) fn poll(
        &self,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> Poll<Result<Option<crate::intel_gpu_vram::Xe2VramRegisters>, RegisterError>> {
        if now >= self.deadline {
            return Poll::Ready(Err(RegisterError::Timeout));
        }
        let modern = self.platform != GtPlatform::Alchemist;
        if modern {
            let semaphore = mmio.read32(0xfd0);
            if semaphore == u32::MAX {
                return Poll::Ready(Err(RegisterError::Unavailable));
            }
            if semaphore & 1 == 0 {
                return Poll::Pending;
            }
        }
        let selector = if modern { 0xfd4 } else { 0xfdc };
        let saved = mmio.read32(selector);
        let result = if saved == u32::MAX {
            Err(RegisterError::Unavailable)
        } else {
            // No await or early return can escape the semaphore scope.
            let result = self.apply(mmio, selector);
            mmio.write32(selector, saved);
            result
        };
        if modern {
            mmio.write32(0xfd0, 1);
        }
        Poll::Ready(result)
    }

    fn steer(
        &self,
        mmio: &impl MmioWindow,
        selector: u64,
        target: Target,
    ) -> Result<(), RegisterError> {
        let modern = self.platform != GtPlatform::Alchemist;
        let (group, instance) = match target {
            Target::Direct | Target::Implicit => return Ok(()),
            Target::Dss => ((self.seed.dss >> 23) & 127, (self.seed.dss >> 16) & 127),
            Target::L3 => ((self.seed.l3 >> 23) & 127, (self.seed.l3 >> 16) & 127),
            Target::Mslice => (u32::from(self.seed.mslice), 0),
            Target::Instance0 => (0, 0),
        };
        if group > 15 || instance > if modern { 15 } else { 7 } {
            return Err(RegisterError::Identity);
        }
        let value = 0x80000000
            | if modern {
                group << 8 | instance
            } else {
                group << 27 | instance << 24
            };
        mmio.write32(selector, value);
        if mmio.read32(selector) != value {
            return Err(RegisterError::Verify(selector));
        }
        Ok(())
    }

    fn apply(
        &self,
        mmio: &impl MmioWindow,
        selector: u64,
    ) -> Result<Option<crate::intel_gpu_vram::Xe2VramRegisters>, RegisterError> {
        if self.platform == GtPlatform::Alchemist {
            // DG2 SF/SQIDI implicit ranges use instance two. GAM ranges
            // retain their separate hardware-default instance-one selector.
            mmio.write32(0xfd0, 0x02000000);
            mmio.write32(0xfd8, 0x02000000);
            if mmio.read32(0xfd0) != 0x02000000 || mmio.read32(0xfd8) != 0x02000000 {
                return Err(RegisterError::Verify(0xfd0));
            }
        }
        let mut vram = None;
        let flat = if self.platform == GtPlatform::Battlemage {
            self.steer(mmio, selector, Target::Instance0)?;
            let a = mmio.read32(0x8800);
            let b = mmio.read32(0x8800);
            if a == u32::MAX || b == u32::MAX {
                return Err(RegisterError::Unavailable);
            }
            if a != b {
                return Err(RegisterError::Verify(0x8800));
            }
            // xe_vram.c: flat-CCS upper range (MCR), MIRROR_FUSE3, GSMBASE
            // as a stable 2x32 read, and SG_TILE_ADDR_RANGE(0).
            let upper = mmio.read32(0x8804);
            let gsm = || u64::from(mmio.read32(0x108104)) << 32 | u64::from(mmio.read32(0x108100));
            let gsm_base = gsm();
            if gsm_base != gsm() {
                return Err(RegisterError::Verify(0x108100));
            }
            vram = Some(crate::intel_gpu_vram::Xe2VramRegisters {
                tile_range: mmio.read32(0x1083a0),
                ccs_lower: a,
                ccs_upper: upper,
                fuse3: mmio.read32(0x9118),
                gsm_base,
            });
            a & 1 != 0
        } else {
            false
        };
        let entries = self.entries(flat);
        // Preflight every readable register before publishing any WA. Masked
        // writes never use the read value; ordinary writes preserve its bits.
        let mut values = Vec::with_capacity(entries.len());
        for entry in &entries {
            self.steer(mmio, selector, entry.target)?;
            let old = if entry.verify || !entry.masked {
                mmio.read32(entry.reg)
            } else {
                0
            };
            if old == u32::MAX {
                return Err(RegisterError::Unavailable);
            }
            values.push(if entry.masked {
                entry.clear << 16 | entry.set
            } else {
                (old & !entry.clear) | entry.set
            });
        }
        for (entry, value) in entries.iter().zip(values) {
            self.steer(mmio, selector, entry.target)?;
            // Selectors always remain multicast for these host writes.
            mmio.write32(entry.reg, value);
            if entry.verify {
                let observed = mmio.read32(entry.reg);
                if observed == u32::MAX || observed & entry.clear != entry.set {
                    return Err(RegisterError::Verify(entry.reg));
                }
            }
        }
        crate::intel_gpu_nonpriv::EnginePolicy::new(self.platform, self.engines())?
            .install(mmio)?;
        Ok(vram)
    }

    fn entries(&self, flat: bool) -> Vec<Entry> {
        use Target::*;
        let mut entries = Vec::new();
        let mut add = |reg, clear, set, masked, target| {
            entries.push(Entry {
                reg,
                clear,
                set,
                masked,
                verify: true,
                target,
            })
        };
        // Multi-CCS parts: fixed-slice RCU mode and all slices on CCS0
        // (xe_hw_engine_match_fixed_cslice_mode, __xe_gt_apply_ccs_mode).
        if let Some(mode) = crate::intel_gpu_engine::ccs_mode(self.compute) {
            add(0x14800, 2, 2, true, Direct);
            add(0x14804, 0xfff, mode & 0xfff, true, Direct);
        }
        match self.platform {
            GtPlatform::Alchemist => {
                add(0x9424, 2, 0, false, Direct); // 14015795083
                if matches!(
                    self.device,
                    0x56a0 | 0x56a1 | 0x56a2 | 0x56be | 0x56bf | 0x5690 | 0x5691 | 0x5692
                ) {
                    add(0x9434, 0x20000, 0x20000, false, Direct); // 22010523718 G10
                    add(0x9524, 0x10000000, 0x10000000, false, Dss); // 14011006942 G10
                }
                add(0xe90c, 0x60000000, 0, false, Mslice); // 14014830051
                for reg in [0xcf2c, 0xcf30, 0xcf34, 0xcf38] {
                    add(reg, 8, 8, false, Implicit); // 18018781329
                }
                add(0xcf54, 0x1004, 0x1004, false, Implicit); // 1509235366
                add(0xb188, 8, 8, false, L3); // blend-fill tuning
                add(0x8724, 0x40000000, 0x40000000, false, Implicit); // 32B access tuning
                add(0x20ec, 2, 2, true, Direct); // 18019627453
                let g11 = matches!(
                    self.device,
                    0x56a5
                        | 0x56a6
                        | 0x56b0
                        | 0x56b1
                        | 0x56ba
                        | 0x56bb
                        | 0x56bc
                        | 0x56bd
                        | 0x5693
                        | 0x5694
                        | 0x5695
                );
                add(
                    0xe7cc,
                    if g11 { 0x048000f0 } else { 0x04800010 },
                    if g11 { 0x04800050 } else { 0x04800010 },
                    false,
                    Dss,
                );
                add(
                    0xe7c8,
                    if g11 { 0x40008000 } else { 0x40000000 },
                    if g11 { 0x40008000 } else { 0x40000000 },
                    false,
                    Dss,
                );
                add(0x83b4, 0x10, 0x10, true, Direct); // 18017747507
                add(0xe48c, 0x800, 0x800, true, Dss); // 14015227452
                add(0xe18c, 0x201, 0x201, true, Dss); // EBB WA + indirect state tuning
                add(0xe4f4, 0x8000, 0x8000, true, Dss); // 22012856258
                add(0xe5f0, 0x3808, 8, true, Dss); // flush events + typed atomic WA
                if g11 {
                    entries.push(Entry {
                        reg: 0xe420,
                        clear: 8,
                        set: 8,
                        masked: true,
                        verify: false,
                        target: Dss,
                    }); // Wa_14012342262 forbids readback
                }
            }
            GtPlatform::Integrated(_) => {
                if self.seed.graphics <= 1271 && self.seed.step < 4 {
                    add(0x9424, 2, 0, false, Direct); // 14015795083 before B0
                }
                add(0xcf30, 8, 8, false, Instance0); // 14018575942
                add(0x8718, 0x800000, 0x800000, false, Instance0); // 22016670082
                add(0xe49c, 0x200, 0x200, true, Dss); // 14017856879
                if self.seed.graphics <= 1271 {
                    add(0xe5f0, 8, 8, true, Dss); // 14015150844
                }
                add(0xe4f4, 2, 2, true, Dss); // 14020495402
                add(0xe18c, 1, 1, true, Dss); // indirect state tuning
            }
            GtPlatform::Battlemage => {
                if self.seed.graphics == 2001 {
                    add(0xb0c8, 0xfffff000, 0x11111000, false, Instance0); // 16025250150
                }
                add(0xb158, 0x3ff, 0x7f, false, Instance0); // L3 timer tuning
                if flat {
                    add(0x8828, 0x840000, 0x800000, false, Instance0); // compression overfetch
                    add(0xb104, 0x100000, 0x100000, false, Instance0);
                }
                add(0xb108, 0x10000000, 0x10000000, false, Instance0);
                add(0x4148, 15, 0, false, Instance0);
                add(0xe48c, 0x8000, 0x8000, true, Dss); // 18034896535
                add(0xe7cc, 0x9000, 0x9000, false, Dss); // 16018712365 + 14018471104
                add(0xe4f0, 2, 2, true, Dss); // 16018737384
                add(0xe49c, 0x4000, 0x4000, true, Dss); // 14020338487
                let lsc = if self.seed.graphics == 2001 {
                    0x04002000
                } else {
                    0x2000
                };
                add(0xe7c8, lsc, lsc, false, Dss); // 18032247524 + 14019811474 (20.01 only)
                add(0x20d4, 0xc080, 0xc080, true, Direct); // 16021639441 + priority reads
                add(0xe194, 0x40, 0x40, true, Dss); // 14021402888
                add(0xe4c4, 0x1040, 0x1040, true, Dss); // 14021821874 + 13012615864
                if self.discontiguous {
                    add(0xe5f4, 0x20, 0x20, true, Dss); // 18041344222 PF only
                }
                add(0x2050, 0x1000, 0x1000, true, Direct); // 16023105232
                                                           // FOREACH_ENGINE/ENGINE_BASE entries reach BCS0 as well.
                add(0x220d4, 0xc080, 0xc080, true, Direct); // 16021639441 + priority reads
                add(0x22050, 0x1000, 0x1000, true, Direct); // 16023105232
                if self.compute & 1 != 0 {
                    add(0x1a0d4, 0xc080, 0xc080, true, Direct); // 16021639441 + priority reads
                    add(0x1a050, 0x1000, 0x1000, true, Direct); // 16023105232
                }
                add(0xe530, 0x400, 0x400, false, Dss); // AnyHit null-query tuning
            }
        }
        entries
    }
}
