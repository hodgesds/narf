//! Native register-model tests for the MTL/Arrow standalone media GT owner.
//! The model carries a live GT0 (graphics) register image next to the media
//! GSI window; every test proves GT0 is never written or changed.

use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, kt_assert_ne, TestResult};

const MTL: GtPlatform = GtPlatform::Integrated(Generation::MeteorLake);
/// GMD_ID 13.00 step A0 (arch 13 in 31:22, release 0 in 21:14).
const MEDIA_1300: u32 = 13 << 22;
/// VCS0, VCS2 and VECS1 present: positive polarity, sparse instances.
const SPARSE_FUSE: u32 = 0b101 | 0b10 << 16;

/// GT0 registers sharing offsets with the media GT's pre-GSI view.
const GT0: [(u64, u32); 14] = [
    (0xd8c, (1274 / 100) << 22 | (1274 % 100) << 14),
    (0xa188, 0x1),
    (0xdfc, 0x1),
    (0x941c, 0),
    (0xc000, 0x8000_f000),
    (0xfd0, 0),
    (0xfd4, 0x5a5a),
    (0x4800, 0x3),
    (0x4804, 0x4),
    (0x4000, 0x1234),
    (0xb020, 0x5678),
    (0x8718, 0x2),
    (0x9140, 0x0003_0003),
    (0x1900e8, 0x8000_0000),
];

struct Soc {
    regs: RefCell<BTreeMap<u64, u32>>,
    log: RefCell<Vec<(bool, u64, u32)>>,
    wake_ack: Cell<bool>,
    release_ack: Cell<bool>,
    guc_reset_stuck: Cell<bool>,
    full_reset_stuck: Cell<bool>,
    mia_in_reset: Cell<bool>,
    /// The media steering semaphore is free (a read grants it).
    semaphore_free: Cell<bool>,
    semaphore_held: Cell<bool>,
    /// Every read returns all-ones (lost BAR / D3).
    lost: Cell<bool>,
    /// A full GT reset drops the GT wake acknowledgement.
    reset_drops_wake: Cell<bool>,
    /// The second GMD_ID sample differs from the first.
    flip_gmd_after: Cell<Option<usize>>,
    gmd_reads: Cell<usize>,
}

fn is_request(reg: u64) -> bool {
    reg == 0x38a188 || (0x38a540..0x38a560).contains(&reg) || (0x38a560..0x38a570).contains(&reg)
}

fn ack_of(reg: u64) -> u64 {
    match reg {
        0x38a188 => 0x380dfc,
        0x38a540..=0x38a55c => 0x380d50 + (reg - 0x38a540),
        _ => 0x380d70 + (reg - 0x38a560),
    }
}

impl Soc {
    fn new(gmd: u32, fuse: u32) -> Self {
        let mut regs = BTreeMap::from(GT0);
        regs.insert(0x380d8c, gmd);
        regs.insert(0x389140, fuse);
        regs.insert(0x38941c, 0);
        regs.insert(0x38c000, 0);
        regs.insert(0x388718, 0x0000_0101);
        regs.insert(0x380fd4, 0x0000_0020);
        for vcs in 0..8u64 {
            regs.insert(vcs_base(vcs) + 0x3f1c, 0x10);
        }
        Self {
            regs: RefCell::new(regs),
            log: RefCell::new(Vec::new()),
            wake_ack: Cell::new(true),
            release_ack: Cell::new(true),
            guc_reset_stuck: Cell::new(false),
            full_reset_stuck: Cell::new(false),
            mia_in_reset: Cell::new(true),
            semaphore_free: Cell::new(true),
            semaphore_held: Cell::new(false),
            lost: Cell::new(false),
            reset_drops_wake: Cell::new(false),
            flip_gmd_after: Cell::new(None),
            gmd_reads: Cell::new(0),
        }
    }
    fn get(&self, reg: u64) -> u32 {
        *self.regs.borrow().get(&reg).unwrap_or(&0)
    }
    fn set(&self, reg: u64, value: u32) {
        self.regs.borrow_mut().insert(reg, value);
    }
    fn writes(&self) -> Vec<(u64, u32)> {
        self.log
            .borrow()
            .iter()
            .filter(|(write, _, _)| *write)
            .map(|(_, reg, value)| (*reg, *value))
            .collect()
    }
    fn reads(&self) -> usize {
        self.log
            .borrow()
            .iter()
            .filter(|(write, _, _)| !*write)
            .count()
    }
    fn first_write(&self, reg: u64, value: u32) -> Option<usize> {
        self.log
            .borrow()
            .iter()
            .position(|entry| *entry == (true, reg, value))
    }
    fn first_read(&self, reg: u64) -> Option<usize> {
        self.log
            .borrow()
            .iter()
            .position(|(write, r, _)| !*write && *r == reg)
    }
    /// GT0 registers are byte-identical and none was ever written.
    fn gt0_untouched(&self) -> bool {
        GT0.iter().all(|(reg, value)| self.get(*reg) == *value)
            && self.writes().iter().all(|(reg, _)| media_owned(*reg))
    }
    fn held_requests(&self) -> u32 {
        self.regs
            .borrow()
            .iter()
            .filter(|(reg, value)| is_request(**reg) && **value & 1 != 0)
            .count() as u32
    }
}

fn vcs_base(instance: u64) -> u64 {
    [
        0x1c0000, 0x1c4000, 0x1d0000, 0x1d4000, 0x1e0000, 0x1e4000, 0x1f0000, 0x1f4000,
    ][instance as usize]
}

/// The only writable registers: GSI-translated media GT registers, media
/// VDBOX engine registers and the media GSC HECI2 workaround registers.
fn media_owned(reg: u64) -> bool {
    (GSI_OFFSET..GSI_OFFSET + GSI_LENGTH).contains(&reg)
        || (0..8).any(|vcs| reg == vcs_base(vcs) + 0x3f1c)
        || matches!(reg, 0x117c4c | 0x117004)
}

impl MmioWindow for Soc {
    fn read32(&self, reg: u64) -> u32 {
        let value = if self.lost.get() {
            u32::MAX
        } else if reg == 0x380fd0 {
            if self.semaphore_free.get() && !self.semaphore_held.get() {
                self.semaphore_held.set(true);
                1
            } else {
                0
            }
        } else if reg == 0x380d8c {
            let reads = self.gmd_reads.get() + 1;
            self.gmd_reads.set(reads);
            let gmd = self.get(reg);
            match self.flip_gmd_after.get() {
                Some(after) if reads > after => gmd ^ 1,
                _ => gmd,
            }
        } else {
            self.get(reg)
        };
        self.log.borrow_mut().push((false, reg, value));
        value
    }
    fn write32(&self, reg: u64, value: u32) {
        self.log.borrow_mut().push((true, reg, value));
        if is_request(reg) {
            let old = self.get(reg);
            let new = (old & !(value >> 16)) | (value & (value >> 16));
            self.set(reg, new & 0xffff);
            let ack = ack_of(reg);
            if new & 1 != 0 && self.wake_ack.get() {
                self.set(ack, self.get(ack) | 1);
            }
            if new & 1 == 0 && self.release_ack.get() {
                self.set(ack, self.get(ack) & !1);
            }
            return;
        }
        match reg {
            0x38941c if value & 8 != 0 => {
                if self.guc_reset_stuck.get() {
                    self.set(reg, 8);
                } else {
                    self.set(reg, 0);
                    self.set(0x38c000, u32::from(self.mia_in_reset.get()));
                }
            }
            0x38941c if value & 1 != 0 => {
                if self.full_reset_stuck.get() {
                    self.set(reg, 1);
                } else {
                    self.set(reg, 0);
                    if self.reset_drops_wake.get() {
                        self.set(0x380dfc, 0);
                    }
                }
            }
            0x380fd0 => {
                if value == 1 {
                    self.semaphore_held.set(false);
                }
            }
            _ => self.set(reg, value),
        }
    }
}

/// Poll until terminal, advancing `step` nanoseconds per poll.
fn drive(
    owner: &mut MediaGt,
    soc: &Soc,
    start: u64,
    step: u64,
) -> (Result<MediaFacts, MediaError>, u64) {
    let mut now = start;
    for _ in 0..1000 {
        if let Poll::Ready(result) = owner.poll(soc, now, || true) {
            return (result, now);
        }
        now += step;
    }
    (Err(MediaError::State), now)
}

fn smoke_media_gt_gsi_window_translates_only_the_media_range() -> TestResult {
    kt_assert_eq!(gsi(0), 0x380000);
    kt_assert_eq!(gsi(0xd8c), 0x380d8c);
    kt_assert_eq!(gsi(0xa188), 0x38a188);
    kt_assert_eq!(gsi(0x3fffc), 0x3bfffc);
    // xe_mmio_adjusted_addr: addr < adj_limit only.
    kt_assert_eq!(gsi(0x40000), 0x40000);
    kt_assert_eq!(gsi(0x1c3f1c), 0x1c3f1c);
    kt_assert_eq!(gsi(0x116c40), 0x116c40);
    kt_assert_eq!(gsi(0x1900e8), 0x1900e8);
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    let window = MediaWindow::new(&soc);
    kt_assert!(!window.display_access_ok());
    kt_assert_eq!(window.read32(0xd8c), MEDIA_1300);
    window.write32(0x4800, 7);
    kt_assert_eq!(soc.get(0x384800), 7);
    kt_assert_eq!(soc.get(0x4800), 0x3);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_gsi_window_translates_only_the_media_range
);

fn smoke_media_gt_identity_qualifies_only_mtl_xelpm_plus_13_00() -> TestResult {
    let ip = qualify(MTL, 1270, MEDIA_1300 | 5);
    kt_assert_eq!(
        ip,
        Ok(MediaIp {
            gmd: MEDIA_1300 | 5,
            version: 1300,
            step: 5
        })
    );
    for graphics in [1270, 1271, 1274] {
        kt_assert!(qualify(MTL, graphics, MEDIA_1300).is_ok());
    }
    // Media fused off is the source's legitimate "not present".
    kt_assert_eq!(qualify(MTL, 1274, 0), Err(MediaError::Absent));
    kt_assert_eq!(qualify(MTL, 1274, u32::MAX), Err(MediaError::Unavailable));
    // Other media IPs (BMG 13.01, LNL 20.00, PTL 30.00) are not this profile.
    for other in [13 << 22 | 1 << 14, 20 << 22, 30 << 22, 12 << 22 | 55 << 14] {
        kt_assert_eq!(qualify(MTL, 1274, other), Err(MediaError::Unsupported));
    }
    kt_assert_eq!(qualify(MTL, 2004, MEDIA_1300), Err(MediaError::Unsupported));
    kt_assert_eq!(qualify(MTL, 1255, MEDIA_1300), Err(MediaError::Unsupported));
    for platform in [
        GtPlatform::Integrated(Generation::LunarLake),
        GtPlatform::Integrated(Generation::PantherLake),
        GtPlatform::Battlemage,
        GtPlatform::Alchemist,
        GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake),
    ] {
        kt_assert!(!profile_eligible(platform));
        kt_assert_eq!(
            qualify(platform, 1274, MEDIA_1300),
            Err(MediaError::Unsupported)
        );
    }
    kt_assert!(profile_eligible(MTL));
    // Arrow Lake classifies as Generation::MeteorLake (xe binds mtl_desc).
    kt_assert_eq!(GtPlatform::from_pci(0x8086, 0x7d67), Some(MTL));
    kt_assert_eq!(GtPlatform::from_pci(0x8086, 0x7d55), Some(MTL));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_identity_qualifies_only_mtl_xelpm_plus_13_00
);

fn smoke_media_gt_fuse_inventory_is_positive_polarity_and_sparse() -> TestResult {
    let engines = inventory(SPARSE_FUSE);
    kt_assert_eq!(
        engines,
        EngineSet::of(&[Engine::Vcs0, Engine::Vcs2, Engine::Vecs1])
    );
    // Dense logical numbering over sparse physical instances.
    kt_assert_eq!(engines.logical_instance(Engine::Vcs2), Some(1));
    kt_assert_eq!(engines.logical_instance(Engine::Vecs1), Some(0));
    // Bits outside VDBOX 7:0 / VEBOX 19:16 never create engines.
    kt_assert_eq!(inventory(0xfff0_ff00), EngineSet::default());
    kt_assert_eq!(
        inventory(0x000f_00ff).iter().count(),
        12,
        "media_xelpmp: VCS0-7 and VECS0-3"
    );
    kt_assert!(inventory(0x000f_00ff)
        .iter()
        .all(|engine| engine.is_media()));
    // Forcewake domains follow present engines only.
    kt_assert_eq!(engine_domains(engines), 1 << 1 | 1 << 3 | 1 << 10);
    kt_assert_eq!(domain_registers(0), (0xa188, 0xdfc));
    kt_assert_eq!(domain_registers(3), (0xa548, 0xd58));
    kt_assert_eq!(domain_registers(10), (0xa564, 0xd74));
    kt_assert_eq!(domain_registers(12), (0xa56c, 0xd7c));
    // xelpg_pat_table: WB, WT, UC, WB|1W, WB|2W.
    kt_assert_eq!(XELPG_PAT, [0, 1 << 2, 3 << 2, 2, 3]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_fuse_inventory_is_positive_polarity_and_sparse
);

fn smoke_media_gt_start_programs_media_only_and_releases_every_wake() -> TestResult {
    let soc = Soc::new(MEDIA_1300 | 4, SPARSE_FUSE);
    // Loaded GSC firmware must not make probe touch the GSC or reset the GT.
    soc.set(0x116c40, 1 << 9);
    let mut owner = MediaGt::new(MTL, 1274);
    let (result, _) = drive(&mut owner, &soc, 1_000, 100_000);
    let Ok(facts) = result else {
        return TestResult::Fail("qualified media GT did not initialize");
    };
    kt_assert_eq!(facts.ip.version, 1300);
    kt_assert_eq!(facts.ip.step, 4);
    kt_assert_eq!(facts.fuse, SPARSE_FUSE);
    kt_assert_eq!(facts.engines, inventory(SPARSE_FUSE));
    kt_assert_eq!(owner.facts(), Some(facts));
    // Linux media-GT probe order: GT wake, identity and fuses, engine wells,
    // PAT/WA/MOCS, then only the GuC sanitize reset
    // (xe_uc_sanitize_reset -> xe_guc_reset); release last.
    let gt_wake = soc.first_write(0x38a188, 0x0001_0001);
    let fuse = soc.first_read(0x389140);
    let vcs2_wake = soc.first_write(0x38a548, 0x0001_0001);
    let pat = soc.first_write(0x384800, 0);
    let guc_reset = soc.first_write(0x38941c, 8);
    let release = soc.first_write(0x38a188, 0x0001_0000);
    kt_assert!(gt_wake.is_some() && gt_wake < fuse);
    kt_assert!(fuse < vcs2_wake && vcs2_wake < pat);
    kt_assert!(pat < guc_reset && guc_reset < release);
    // do_gt_reset runs only from gt_reset_worker and xe_gt_shutdown: probe
    // writes no GRDOM_FULL and no Wa_14015076503 GSC notification.
    kt_assert!(soc.first_write(0x38941c, 1).is_none());
    kt_assert!(soc
        .writes()
        .iter()
        .all(|(reg, _)| !matches!(reg, 0x117c4c | 0x117004)));
    // Fused-off VCS1/VECS0 wells are never requested.
    kt_assert!(soc.first_write(0x38a544, 0x0001_0001).is_none());
    kt_assert!(soc.first_write(0x38a560, 0x0001_0001).is_none());
    kt_assert!(soc.first_write(0x38a564, 0x0001_0001).is_some());
    // PAT through the media steering semaphore with multicast selected.
    for (index, value) in XELPG_PAT.into_iter().enumerate() {
        kt_assert_eq!(soc.get(0x384800 + index as u64 * 4), value);
    }
    let selector = soc.first_write(0x380fd4, 0x8000_0020);
    let restore = soc.first_write(0x380fd4, 0x0000_0020);
    let unlock = soc.first_write(0x380fd0, 1);
    kt_assert!(selector.is_some() && selector < pat && pat < restore && restore < unlock);
    kt_assert!(!soc.semaphore_held.get());
    kt_assert_eq!(soc.get(0x380fd4), 0x20);
    // mtl_mocs_desc global and LNCF tables.
    for (index, value) in MTL_GLOBAL_MOCS.into_iter().enumerate() {
        kt_assert_eq!(soc.get(0x384000 + index as u64 * 4), value);
    }
    kt_assert_eq!(soc.get(0x38b020), 0x00b0_00b0);
    kt_assert_eq!(soc.get(0x38b024), 0x0090_0090);
    kt_assert_eq!(soc.get(0x38b03c), 0x0050_00b0);
    // Wa_22016670082 preserves other bits; Wa_16021867713 per present VCS.
    kt_assert_eq!(soc.get(0x388718), 0x0080_0101);
    kt_assert_eq!(soc.get(0x1c3f1c), 0x18);
    kt_assert_eq!(soc.get(0x1d3f1c), 0x18);
    kt_assert_eq!(soc.get(0x1c7f1c), 0x10, "fused-off VCS1 untouched");
    kt_assert!(soc.gt0_untouched());
    kt_assert_eq!(soc.held_requests(), 0);
    kt_assert_eq!(owner.outstanding_wake(), 0);
    // Terminal: further polls perform no MMIO.
    let before = soc.log.borrow().len();
    kt_assert!(matches!(
        owner.poll(&soc, u64::MAX / 2, || true),
        Poll::Ready(Ok(_))
    ));
    kt_assert_eq!(soc.log.borrow().len(), before);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_start_programs_media_only_and_releases_every_wake
);

fn smoke_media_gt_absent_or_unqualified_refuses_before_any_write() -> TestResult {
    // Fused-off media: two identity reads, no write.
    let soc = Soc::new(0, SPARSE_FUSE);
    let mut owner = MediaGt::new(MTL, 1270);
    kt_assert_eq!(drive(&mut owner, &soc, 0, 1000).0, Err(MediaError::Absent));
    kt_assert!(soc.writes().is_empty());
    kt_assert_eq!(soc.reads(), 2);
    // Another media IP: refused after identity, no write.
    let soc = Soc::new(13 << 22 | 1 << 14, SPARSE_FUSE);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 1000).0,
        Err(MediaError::Unsupported)
    );
    kt_assert!(soc.writes().is_empty());
    // Unqualified platform or graphics IP: not even a read.
    for (platform, graphics) in [
        (GtPlatform::Integrated(Generation::LunarLake), 2004),
        (GtPlatform::Battlemage, 2001),
        (MTL, 2004),
    ] {
        let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
        let mut owner = MediaGt::new(platform, graphics);
        kt_assert_eq!(
            drive(&mut owner, &soc, 0, 1000).0,
            Err(MediaError::Unsupported)
        );
        kt_assert!(soc.log.borrow().is_empty());
    }
    // Unstable or lost identity and lost current authority never write.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.flip_gmd_after.set(Some(1));
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 1000).0,
        Err(MediaError::Unstable)
    );
    kt_assert!(soc.writes().is_empty());
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.lost.set(true);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 1000).0,
        Err(MediaError::Unavailable)
    );
    kt_assert!(soc.writes().is_empty());
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        owner.poll(&soc, 0, || false),
        Poll::Ready(Err(MediaError::Unavailable))
    );
    kt_assert!(soc.log.borrow().is_empty());
    // No engines: GT wake is taken for the fuse read and then released.
    let soc = Soc::new(MEDIA_1300, 0);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 1000).0,
        Err(MediaError::NoEngines)
    );
    kt_assert!(soc.first_write(0x38941c, 8).is_none());
    kt_assert_eq!(soc.held_requests(), 0);
    kt_assert!(soc.gt0_untouched());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_absent_or_unqualified_refuses_before_any_write
);

fn smoke_media_gt_wake_refusals_and_timeouts_release_and_spare_gt0() -> TestResult {
    // An inherited media GT kernel request belongs to someone else.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.set(0x38a188, 1);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(drive(&mut owner, &soc, 0, 1000).0, Err(MediaError::Busy));
    kt_assert!(soc.writes().is_empty());
    // GT acknowledgement never arrives: timeout after 50 ms, then release.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.wake_ack.set(false);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert!(owner.poll(&soc, 0, || true).is_pending());
    kt_assert!(owner.poll(&soc, 49_999_999, || true).is_pending());
    kt_assert!(owner.poll(&soc, 50_000_000, || true).is_pending());
    kt_assert_eq!(
        owner.poll(&soc, 50_000_001, || true),
        Poll::Ready(Err(MediaError::Timeout))
    );
    kt_assert!(soc.first_write(0x38a188, 0x0001_0000).is_some());
    kt_assert!(
        soc.first_read(0x389140).is_none(),
        "no fuse read without wake"
    );
    kt_assert_eq!(soc.held_requests(), 0);
    kt_assert_eq!(owner.outstanding_wake(), 0);
    kt_assert!(soc.gt0_untouched());
    // An engine well never acknowledges: GT and requested wells released.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert!(owner.poll(&soc, 0, || true).is_pending());
    kt_assert_eq!(soc.get(0x380dfc) & 1, 1, "GT domain acknowledged");
    soc.wake_ack.set(false);
    let (result, _) = drive(&mut owner, &soc, 1000, 10_000_000);
    kt_assert_eq!(result, Err(MediaError::Timeout));
    kt_assert!(
        soc.first_write(0x384800, 0).is_none(),
        "no PAT without wells"
    );
    kt_assert!(soc.first_write(0x38a540, 0x0001_0000).is_some());
    kt_assert!(soc.first_write(0x38a564, 0x0001_0000).is_some());
    kt_assert_eq!(soc.held_requests(), 0);
    kt_assert!(soc.gt0_untouched());
    // A release whose acknowledgement never clears keeps the original error
    // and reports the still-outstanding requests for a later abandon.
    let soc = Soc::new(MEDIA_1300, 0);
    soc.release_ack.set(false);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 10_000_000).0,
        Err(MediaError::NoEngines)
    );
    kt_assert_eq!(owner.outstanding_wake(), 1);
    owner.abandon(&soc);
    kt_assert_eq!(owner.outstanding_wake(), 0);
    kt_assert_eq!(
        owner.poll(&soc, 1, || true),
        Poll::Ready(Err(MediaError::State))
    );
    kt_assert!(soc.gt0_untouched());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_wake_refusals_and_timeouts_release_and_spare_gt0
);

fn smoke_media_gt_reset_failures_are_typed_and_release_wake() -> TestResult {
    // A reset already in flight is not ours to own, at probe or recovery.
    for recovery in [false, true] {
        let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
        soc.set(0x38941c, 1);
        let mut owner = if recovery {
            MediaGt::for_recovery(MTL, 1274)
        } else {
            MediaGt::new(MTL, 1274)
        };
        kt_assert_eq!(drive(&mut owner, &soc, 0, 1000).0, Err(MediaError::Busy));
        kt_assert!(soc.writes().iter().all(|(reg, _)| *reg != 0x38941c));
        kt_assert_eq!(soc.held_requests(), 0);
        kt_assert!(soc.gt0_untouched());
    }
    // GRDOM_GUC never self-clears within 5 ms.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.guc_reset_stuck.set(true);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 1_000_000).0,
        Err(MediaError::Timeout)
    );
    kt_assert!(soc.first_write(0x38941c, 1).is_none());
    kt_assert_eq!(soc.held_requests(), 0);
    // The GuC MIA core is not reported in reset.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.mia_in_reset.set(false);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(drive(&mut owner, &soc, 0, 1000).0, Err(MediaError::Reset));
    kt_assert!(soc.first_write(0x38941c, 1).is_none());
    kt_assert_eq!(soc.held_requests(), 0);
    // GRDOM_FULL is never issued at probe, so a stuck full reset is moot.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.full_reset_stuck.set(true);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert!(drive(&mut owner, &soc, 0, 1_000_000).0.is_ok());
    kt_assert!(soc.first_write(0x38941c, 1).is_none());
    // Recovery: GRDOM_FULL never self-clears within 5 ms.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.full_reset_stuck.set(true);
    let mut owner = MediaGt::for_recovery(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 1_000_000).0,
        Err(MediaError::Timeout)
    );
    kt_assert!(soc.first_write(0x38a540, 0x0001_0001).is_none());
    kt_assert_eq!(soc.held_requests(), 0);
    // Recovery: a full reset that drops the GT wake is a lost wake.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.reset_drops_wake.set(true);
    let mut owner = MediaGt::for_recovery(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 1000).0,
        Err(MediaError::WakeLost)
    );
    kt_assert!(soc.first_write(0x384800, 0).is_none());
    kt_assert_eq!(soc.held_requests(), 0);
    kt_assert!(soc.gt0_untouched());
    // Identity changing under wake refuses before any reset.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.flip_gmd_after.set(Some(2));
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 1000).0,
        Err(MediaError::Unstable)
    );
    kt_assert!(soc.first_write(0x38941c, 8).is_none());
    kt_assert_eq!(soc.held_requests(), 0);
    kt_assert!(soc.gt0_untouched());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_reset_failures_are_typed_and_release_wake
);

/// Recovery only (xe_gt.c::gt_reset_worker -> do_gt_reset): loaded GSC
/// firmware is alerted, 200 ms elapse, GRDOM_FULL completes, the alert is
/// cleared, and do_gt_restart reprograms the GT and sanitizes the GuC.
fn smoke_media_gt_loaded_gsc_reset_follows_wa_14015076503() -> TestResult {
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.set(0x116c40, 1 << 9); // HECI1 FWSTS1 INIT_COMPLETE
    soc.set(0x117004, 0x1d); // CSR with RST set
    soc.set(0x117c4c, 0x40);
    let mut owner = MediaGt::for_recovery(MTL, 1274);
    let mut now = 0;
    loop {
        kt_assert!(owner.poll(&soc, now, || true).is_pending());
        if soc.first_write(0x117004, 0x0d).is_some() {
            break;
        }
        now += 1000;
        kt_assert!(now < 10_000_000);
    }
    let prepared = now;
    kt_assert_eq!(soc.get(0x117c4c), 0x41);
    kt_assert!(soc.first_write(0x117c4c, 0x41) < soc.first_write(0x117004, 0x0d));
    // The full reset waits the source's 200 ms after alerting the GSC.
    kt_assert!(owner
        .poll(&soc, prepared + 199_999_000, || true)
        .is_pending());
    kt_assert!(soc.first_write(0x38941c, 1).is_none());
    let (result, _) = drive(&mut owner, &soc, prepared + 200_000_000, 100_000);
    kt_assert!(result.is_ok());
    let full = soc.first_write(0x38941c, 1);
    let cleared = soc.first_write(0x117c4c, 0x40);
    let wells = soc.first_write(0x38a540, 0x0001_0001);
    let pat = soc.first_write(0x384800, 0);
    let sanitize = soc.first_write(0x38941c, 8);
    kt_assert!(full.is_some() && full < cleared);
    kt_assert!(cleared < wells && wells < pat && pat < sanitize);
    kt_assert_eq!(soc.get(0x117c4c), 0x40);
    kt_assert_eq!(soc.held_requests(), 0);
    kt_assert!(soc.gt0_untouched());
    // Recovery without loaded GSC firmware: no GSC notification at all.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    let mut owner = MediaGt::for_recovery(MTL, 1274);
    kt_assert!(drive(&mut owner, &soc, 0, 100_000).0.is_ok());
    kt_assert!(soc.first_write(0x38941c, 1).is_some());
    kt_assert!(soc
        .writes()
        .iter()
        .all(|(reg, _)| !matches!(reg, 0x117c4c | 0x117004)));
    // A failed reset still clears the GSC notification.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.set(0x116c40, 1 << 9);
    soc.full_reset_stuck.set(true);
    let mut owner = MediaGt::for_recovery(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 50_000_000).0,
        Err(MediaError::Timeout)
    );
    kt_assert_eq!(soc.get(0x117c4c) & 1, 0);
    kt_assert_eq!(soc.held_requests(), 0);
    kt_assert!(soc.gt0_untouched());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_loaded_gsc_reset_follows_wa_14015076503
);

fn smoke_media_gt_steering_semaphore_is_never_held_across_returns() -> TestResult {
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.semaphore_free.set(false);
    let mut owner = MediaGt::new(MTL, 1274);
    let mut now = 0;
    while soc.first_read(0x380fd0).is_none() {
        kt_assert!(owner.poll(&soc, now, || true).is_pending());
        now += 1000;
        kt_assert!(now < 10_000_000);
    }
    // Contended: no selector, PAT or semaphore write while waiting.
    for _ in 0..3 {
        kt_assert!(owner.poll(&soc, now, || true).is_pending());
        now += 1000;
    }
    kt_assert!(soc
        .writes()
        .iter()
        .all(|(reg, _)| !matches!(reg, 0x380fd4 | 0x380fd0 | 0x384800)));
    soc.semaphore_free.set(true);
    let (result, _) = drive(&mut owner, &soc, now, 100_000);
    kt_assert!(result.is_ok());
    kt_assert_eq!(
        soc.writes()
            .iter()
            .filter(|(reg, _)| *reg == 0x380fd0)
            .count(),
        1
    );
    kt_assert!(!soc.semaphore_held.get());
    // A semaphore never granted within the bound refuses and releases wake.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.semaphore_free.set(false);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        drive(&mut owner, &soc, 0, 1_000_000).0,
        Err(MediaError::Timeout)
    );
    kt_assert!(soc.first_write(0x384800, 0).is_none());
    kt_assert_eq!(soc.held_requests(), 0);
    kt_assert!(soc.gt0_untouched());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_steering_semaphore_is_never_held_across_returns
);

fn smoke_media_gt_abandon_and_next_incarnation_settle_stale_acks() -> TestResult {
    // Teardown mid-start (a GT0 stop/park/suspend): release without waiting.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.release_ack.set(false);
    let mut owner = MediaGt::new(MTL, 1274);
    let mut now = 0;
    while soc.first_write(0x38a540, 0x0001_0001).is_none() {
        kt_assert!(owner.poll(&soc, now, || true).is_pending());
        now += 1000;
        kt_assert!(now < 10_000_000);
    }
    let before = soc.writes().len();
    owner.abandon(&soc);
    let released: Vec<_> = soc.writes()[before..].to_vec();
    kt_assert_eq!(
        released,
        [
            (0x38a564, 0x0001_0000),
            (0x38a548, 0x0001_0000),
            (0x38a540, 0x0001_0000),
            (0x38a188, 0x0001_0000)
        ]
    );
    kt_assert_eq!(owner.outstanding_wake(), 0);
    kt_assert_eq!(
        owner.poll(&soc, now, || true),
        Poll::Ready(Err(MediaError::State))
    );
    kt_assert_eq!(soc.held_requests(), 0);
    // The next incarnation waits for the stale acknowledgements to clear.
    let mut next = MediaGt::new(MTL, 1274);
    let wakes = |soc: &Soc| {
        soc.writes()
            .iter()
            .filter(|entry| **entry == (0x38a188, 0x0001_0001))
            .count()
    };
    kt_assert!(next.poll(&soc, now, || true).is_pending());
    kt_assert!(next.poll(&soc, now + 1000, || true).is_pending());
    kt_assert_eq!(wakes(&soc), 1, "no new request while the old ACK is set");
    for ack in [0x380dfc, 0x380d50, 0x380d58, 0x380d74] {
        soc.set(ack, 0);
    }
    soc.release_ack.set(true);
    let (result, _) = drive(&mut next, &soc, now + 2000, 100_000);
    kt_assert!(result.is_ok());
    kt_assert_eq!(wakes(&soc), 2);
    kt_assert_eq!(soc.held_requests(), 0);
    // A stale ACK that never settles refuses without a new request.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    soc.set(0x380dfc, 1);
    let mut stuck = MediaGt::new(MTL, 1274);
    kt_assert_eq!(
        drive(&mut stuck, &soc, 0, 10_000_000).0,
        Err(MediaError::Timeout)
    );
    kt_assert!(soc.writes().is_empty());
    // Abandoning an initialized owner writes nothing: no wake is held.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    let mut done = MediaGt::new(MTL, 1274);
    kt_assert!(drive(&mut done, &soc, 0, 100_000).0.is_ok());
    let writes = soc.writes().len();
    done.abandon(&soc);
    kt_assert_eq!(soc.writes().len(), writes);
    kt_assert_eq!(done.facts(), None);
    kt_assert!(soc.gt0_untouched());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_abandon_and_next_incarnation_settle_stale_acks
);

fn smoke_media_gt_current_loss_mid_start_retains_original_refusal() -> TestResult {
    // Authority disappears after the GT wake: the release is attempted and the
    // outcome is Unavailable, never a fabricated success.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    let mut owner = MediaGt::new(MTL, 1274);
    kt_assert!(owner.poll(&soc, 0, || true).is_pending());
    kt_assert_eq!(owner.outstanding_wake(), 1);
    kt_assert!(owner.poll(&soc, 1000, || false).is_pending());
    kt_assert!(soc.first_write(0x38a188, 0x0001_0000).is_some());
    kt_assert_eq!(
        owner.poll(&soc, 2000, || true),
        Poll::Ready(Err(MediaError::Unavailable))
    );
    kt_assert_eq!(owner.outstanding_wake(), 0);
    // All-ones reads mid-programming: no further programming, typed loss.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    let mut owner = MediaGt::new(MTL, 1274);
    let mut now = 0;
    while soc.first_write(0x38a564, 0x0001_0001).is_none() {
        kt_assert!(owner.poll(&soc, now, || true).is_pending());
        now += 1000;
        kt_assert!(now < 10_000_000);
    }
    soc.lost.set(true);
    let (result, _) = drive(&mut owner, &soc, now, 1000);
    kt_assert_eq!(result, Err(MediaError::Unavailable));
    kt_assert!(soc.first_write(0x384800, 0).is_none());
    kt_assert!(owner.facts().is_none());
    kt_assert!(soc.gt0_untouched());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_current_loss_mid_start_retains_original_refusal
);

/// The real shared GGTT arena over a RAM-backed 16 MiB BAR0 with current
/// capability authority: GT0 flushes are unchanged until the media GuC
/// registers, then every PTE publication and clear also invalidates the
/// media GuC's GGTT TLB (xe_ggtt.c::xe_ggtt_invalidate, both GTs).
fn smoke_media_gt_shared_ggtt_invalidates_media_guc_tlb_only_while_registered() -> TestResult {
    use crate::intel_gpu_rcs::{GgttArena, GpuAllocator, GpuBacking, SharedArena};
    use narf_capabilities::{Cap, Write};
    const SENTINEL: u32 = 0x5a5a_5a5a;
    const MEDIA_INV: u64 = 0x38cee8;
    const GT0_INV: u64 = 0xcee8;
    let mut words = alloc::vec![0u32; 4 * 1024 * 1024];
    let bar = narf_bus::bar::MmioRegion {
        // Fixture-unique GGTT ledger key; no real device sits here.
        phys: narf_memory::PhysAddr::new(0x6_f400_0000),
        virt: words.as_mut_ptr() as u64,
        len: 16 << 20,
        kind: narf_bus::bar::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    let load = |reg: u64| {
        // SAFETY: `words` backs the whole fixture BAR for this test; the
        // aligned offset selects an in-bounds dword.
        unsafe { core::ptr::read_volatile((bar.virt + reg) as *const u32) }
    };
    let store = |reg: u64, value: u32| {
        // SAFETY: as above; no arena operation runs concurrently.
        unsafe { core::ptr::write_volatile((bar.virt + reg) as *mut u32, value) }
    };
    store(MEDIA_INV, SENTINEL);
    store(GT0_INV, SENTINEL);
    let cap = Cap::<narf_bus::BusDeviceCap, Write>::bootstrap();
    let arena = SharedArena::new(GgttArena::for_gt(bar, cap, MTL));
    let mut alloc = arena.clone();
    let policy = crate::intel_gpu_gt_hw::CachePolicy {
        platform: MTL,
        ggtt_pat: 3,
        media: None,
    };
    let pte = |backing: &crate::intel_gpu_rcs::FrameBacking| {
        crate::intel_gpu_gtt::GGTT_ARRAY_BASE + u64::from(backing.ggtt_offset()) / 4096 * 8
    };
    // No media GuC: GT0's publication path writes PTEs but never the media
    // TLB, and the arena never writes either GuC's invalidation register.
    let Ok(mut first) = alloc.alloc(1) else {
        return TestResult::Fail("fixture arena refused its first page");
    };
    kt_assert!(arena.configure_cache(&mut first, policy).is_ok());
    kt_assert_ne!(load(pte(&first)), 0);
    kt_assert_eq!(load(MEDIA_INV), SENTINEL);
    kt_assert_eq!(load(GT0_INV), SENTINEL);
    kt_assert!(!arena.media_guc_tlb());
    // Registered media GuC: publication and clear both invalidate GT1 only.
    kt_assert!(arena.set_media_guc_tlb(true).is_ok());
    let Ok(second) = alloc.alloc(2) else {
        return TestResult::Fail("fixture arena refused a mapped allocation");
    };
    kt_assert_ne!(load(pte(&second)), 0);
    kt_assert_eq!(load(MEDIA_INV), 1);
    kt_assert_eq!(load(GT0_INV), SENTINEL);
    store(MEDIA_INV, SENTINEL);
    let cleared = pte(&second);
    alloc.free(second);
    kt_assert_eq!(load(cleared), 0);
    kt_assert_eq!(load(MEDIA_INV), 1);
    kt_assert_eq!(load(GT0_INV), SENTINEL);
    // Unregistered after the media GuC's proven stop: identical GT0 path.
    kt_assert!(arena.set_media_guc_tlb(false).is_ok());
    store(MEDIA_INV, SENTINEL);
    let Ok(third) = alloc.alloc(1) else {
        return TestResult::Fail("fixture arena refused a later allocation");
    };
    alloc.free(third);
    alloc.free(first);
    kt_assert_eq!(load(MEDIA_INV), SENTINEL);
    kt_assert_eq!(load(GT0_INV), SENTINEL);
    kt_assert_eq!(arena.live_allocations(), 0);
    // Only an authorized MTL-classified arena can host a media GuC TLB.
    let other = SharedArena::new(GgttArena::for_gt(bar, cap, GtPlatform::Battlemage));
    kt_assert!(other.set_media_guc_tlb(true).is_err());
    let bare = SharedArena::new(GgttArena::new(bar));
    kt_assert!(bare.set_media_guc_tlb(true).is_err());
    drop((arena, alloc, other, bare));
    drop(words);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_shared_ggtt_invalidates_media_guc_tlb_only_while_registered
);

/// `narf.intel.media_gt=1` is default-off with the shared pre-`--` grammar.
/// Absent the option the runtime constructs no media owner, so every GT0
/// teardown hook retires nothing without MMIO and the shared GGTT arena
/// flushes exactly as before: no second TLB, no GuC invalidation write.
fn smoke_media_gt_default_off_gate_and_absent_option_leave_gt0_unchanged() -> TestResult {
    use crate::intel_gpu_rcs::{GgttArena, GpuAllocator, GpuBacking, SharedArena};
    use narf_boot::args::KernelCmdline;
    use narf_capabilities::{Cap, Write};
    const REFUSED: [&str; 10] = [
        "",
        "quiet",
        "narf.intel.media_gt",
        "narf.intel.media_gt=",
        "narf.intel.media_gt=0",
        "narf.intel.media_gt=01",
        "-- narf.intel.media_gt=1",
        "narf.intel.media_gt=1 narf.intel.media_gt=1",
        "narf.intel.media_gt=1 narf.intel.media_gt",
        "narf.intel.media_gt_x=1",
    ];
    const ACCEPTED: [&str; 3] = [
        "narf.intel.media_gt=1",
        "quiet narf.intel.media_gt=1 -- narf.intel.media_gt",
        "narf.intel.media_gt=1 -- narf.intel.media_gt=0 narf.intel.media_gt=1",
    ];
    for line in REFUSED {
        kt_assert!(!requested(KernelCmdline::new(line)));
        kt_assert!(!admitted(Some(MTL), KernelCmdline::new(line)));
    }
    for line in ACCEPTED {
        kt_assert!(requested(KernelCmdline::new(line)));
        kt_assert!(admitted(Some(MTL), KernelCmdline::new(line)));
    }
    // The shared grammar decides the HuC and BMG small-BAR options exactly
    // as their own parsers did.
    for line in REFUSED.iter().chain(ACCEPTED.iter()) {
        let expect = requested(KernelCmdline::new(line));
        let huc = line.replace("narf.intel.media_gt", "narf.intel.huc");
        kt_assert_eq!(
            crate::intel_gpu_huc::opted_in(KernelCmdline::new(&huc)),
            expect
        );
        let smallbar = line.replace("narf.intel.media_gt", "narf.intel.bmg_smallbar");
        kt_assert_eq!(
            crate::intel_gpu_gt::smallbar::requested(KernelCmdline::new(&smallbar)),
            expect
        );
    }
    // Opting in admits only MTL-classified devices (Meteor and Arrow Lake).
    let on = KernelCmdline::new("narf.intel.media_gt=1");
    kt_assert!(admitted(GtPlatform::from_pci(0x8086, 0x7d67), on));
    for platform in [
        None,
        Some(GtPlatform::Integrated(Generation::LunarLake)),
        Some(GtPlatform::Integrated(Generation::PantherLake)),
        Some(GtPlatform::Battlemage),
        Some(GtPlatform::Alchemist),
        Some(GtPlatform::Gen12(
            crate::intel_gpu_gt::Gen12Platform::TigerLake,
        )),
    ] {
        kt_assert!(!admitted(platform, on));
    }
    // No media owner: the retire hook used before a GT0 restart, park,
    // suspend or fault cleanup is Done and touches no register.
    let soc = Soc::new(MEDIA_1300, SPARSE_FUSE);
    let mut media = None;
    let mut guc: Option<
        MediaGuc<crate::intel_gpu_gt_hw::AuthorizedWindow, crate::intel_gpu_rcs::SharedArena>,
    > = None;
    kt_assert_eq!(retire(&mut media, &mut guc, &soc, 0, || true), Retire::Done);
    kt_assert!(soc.log.borrow().is_empty());
    // A never-registered arena: GT0 publication/clear write PTEs only.
    const SENTINEL: u32 = 0x5a5a_5a5a;
    let mut words = alloc::vec![0u32; 4 * 1024 * 1024];
    let bar = narf_bus::bar::MmioRegion {
        // Fixture-unique GGTT ledger key; no real device sits here.
        phys: narf_memory::PhysAddr::new(0x6_f800_0000),
        virt: words.as_mut_ptr() as u64,
        len: 16 << 20,
        kind: narf_bus::bar::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    let load = |reg: u64| {
        // SAFETY: `words` backs the whole fixture BAR for this test.
        unsafe { core::ptr::read_volatile((bar.virt + reg) as *const u32) }
    };
    for reg in [0x38cee8u64, 0xcee8] {
        // SAFETY: as above; nothing else accesses the fixture BAR here.
        unsafe { core::ptr::write_volatile((bar.virt + reg) as *mut u32, SENTINEL) };
    }
    let arena = SharedArena::new(GgttArena::for_gt(
        bar,
        Cap::<narf_bus::BusDeviceCap, Write>::bootstrap(),
        MTL,
    ));
    let mut alloc = arena.clone();
    kt_assert!(!arena.media_guc_tlb());
    let Ok(mut first) = alloc.alloc(1) else {
        return TestResult::Fail("fixture arena refused its first page");
    };
    let policy = crate::intel_gpu_gt_hw::CachePolicy {
        platform: MTL,
        ggtt_pat: 3,
        media: None,
    };
    kt_assert!(arena.configure_cache(&mut first, policy).is_ok());
    let Ok(second) = alloc.alloc(2) else {
        return TestResult::Fail("fixture arena refused a mapped allocation");
    };
    let pte = crate::intel_gpu_gtt::GGTT_ARRAY_BASE + u64::from(second.ggtt_offset()) / 4096 * 8;
    kt_assert_ne!(load(pte), 0);
    alloc.free(second);
    alloc.free(first);
    kt_assert_eq!(load(pte), 0);
    kt_assert_eq!(load(0x38cee8), SENTINEL);
    kt_assert_eq!(load(0xcee8), SENTINEL);
    kt_assert_eq!(arena.live_allocations(), 0);
    kt_assert!(!arena.media_guc_tlb());
    drop((arena, alloc));
    drop(words);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_default_off_gate_and_absent_option_leave_gt0_unchanged
);
