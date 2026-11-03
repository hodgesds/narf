// GSCCS0 as a kernel-only engine of the MTL/Arrow standalone media GuC,
// through the production MediaGuc/GuCGt/GuCBoot/scheduler owners on the GuC
// model. Literal identities follow MIT Linux b90c984d: xe_hw_engine.c
// (engine_infos[XE_HW_ENGINE_GSCCS0], hw_engine_setup_default_state's "MTL
// GSCCS IDLE MSG enable", hw_engine_init_early's 600 ms preempt floor,
// xe_hw_engine_is_reserved), xe_force_wake.c (XE_FW_GSC), xe_guc_ads.c
// (GUC_GSC_OTHER_CLASS mapping/enable masks, golden LRC, regsets), xe_lrc.c
// dg2_xcs_offsets, xe_ring_ops.c emit_job_gen12_gsc and
// instructions/xe_gsc_commands.h.
use super::media_gt_sched::{media_tick, media_until, start_media, Hw};
use super::*;
use crate::intel_gpu_engine::{Engine, EngineSet};
use crate::intel_gpu_gt::media::gsc::load::{Gsccs, LoadError};
use crate::intel_gpu_gt::media::{GscQueue, MediaGucState, GSI_OFFSET};

const GSCCS: u64 = 0x11a000;

fn gsccs_reg(offset: u64) -> bool {
    (GSCCS..GSCCS + 0x2000).contains(&offset)
}

/// Engine identity, policy tables and the reserved-class exclusions, without
/// a GuC: every value is the xe_hw_engine.c / regs literal.
fn smoke_media_gt_gsccs_identity_policy_and_reserved_exclusion() -> TestResult {
    let gsc = Engine::Gsccs0;
    assert_eq!(Engine::COUNT, 20);
    assert_eq!(Engine::ALL[19], gsc);
    assert_eq!(gsc.index(), 19);
    // GSCCS_RING_BASE, GUC_GSC_OTHER_CLASS, XE_ENGINE_CLASS_OTHER,
    // OTHER_GSC_INSTANCE.
    assert_eq!(
        (
            gsc.base(),
            gsc.guc_class(),
            gsc.hw_class(),
            gsc.physical_instance()
        ),
        (0x11a000, 5, 4, 6)
    );
    // ENGINE_ID class for the other engines is unchanged by the GSC entry.
    for (engine, class) in [
        (Engine::Rcs0, 0),
        (Engine::Vcs3, 1),
        (Engine::Vecs1, 2),
        (Engine::Bcs8, 3),
        (Engine::Ccs2, 5),
    ] {
        assert_eq!(engine.hw_class(), class);
    }
    // xe_gt_lrc_size: PPHWSP plus one page; dg2_xcs_offsets on MTL.
    assert_eq!(gsc.lrc_pages(MTL), 2);
    assert_eq!(gsc.first_lri(MTL), 0x1108101d);
    assert!(gsc.simple_ring() && gsc.reserved() && gsc.is_gsc());
    assert!(!gsc.is_media() && !gsc.is_copy() && !gsc.is_compute());
    assert_eq!(gsc.xe_class(), crate::intel_gpu_engine::RESERVED_CLASS);
    // No UAPI lookup resolves a reserved engine, even in a set holding it.
    let set = EngineSet::of(&[Engine::Vcs0, Engine::Vecs0, gsc]);
    for class in [0, 1, 2, 3, 4, 5, crate::intel_gpu_engine::RESERVED_CLASS] {
        for logical in 0..2 {
            assert_ne!(set.from_class_instance(class, logical), Some(gsc));
        }
    }
    assert_eq!(set.from_class_instance(2, 0), Some(Engine::Vcs0));
    assert_eq!(set.logical_mask(EngineSet::of(&[gsc])), None);
    assert_eq!(set.logical_instance(gsc), Some(0));
    // ENGINE_ID class OTHER (4), instance 6; never confused with COMPUTE (5).
    assert_eq!(set.decode_hardware_id(4 | 6 << 4), Some(gsc));
    assert_eq!(set.decode_hardware_id(5 | 6 << 4), None);
    // XE_FW_GSC: FORCEWAKE_GSC / FORCEWAKE_ACK_GSC, GSI-translated on GT1.
    let gsc_domain = crate::intel_gpu_gt::media::GSC_DOMAIN;
    assert_eq!(gsc_domain, 13);
    assert_eq!(
        crate::intel_gpu_gt::media::domain_registers(gsc_domain),
        (0xa618, 0xdf8)
    );
    assert_eq!(
        crate::intel_gpu_gt::media::engine_domains(set),
        1 << 1 | 1 << 9 | 1 << 13
    );
    // The 600 ms preempt floor for class OTHER only.
    assert_eq!(crate::intel_gpu_guc_sched::preemption_timeout_us(gsc), 600_000);
    for engine in [Engine::Rcs0, Engine::Vcs0, Engine::Vecs0, Engine::Bcs0] {
        assert_eq!(
            crate::intel_gpu_guc_sched::preemption_timeout_us(engine),
            500_000
        );
    }
    // The kernel queue admits only the worker's two GSC instruction shapes.
    use crate::intel_gpu_gt::media::gsc::{fw_load, heci_packet};
    assert!(crate::intel_gpu_engine::gsc_job_valid(&fw_load(
        0x0100_0000,
        4 << 20
    )));
    assert!(crate::intel_gpu_engine::gsc_job_valid(
        &heci_packet(0x0050_0000, 40, 0x0050_1000, 4096).unwrap()
    ));
    for refused in [
        &[][..],
        &[0x0500_0000][..],
        &[0x4040_0002, 0x0100_0000, 0, 0x400][..],
        &[0x4040_0002, 0x0100_0000, 1, 0x8000_0400][..],
        &[0x4040_0002, 0x0100_0000, 0, 0x8000_0000][..],
        &[0x4000_0006, 0x0050_0000, 0, 35, 0x0050_1000, 0, 4096, 0][..],
        &[0x4000_0006, 0x0050_0000, 0, 40, 0x0050_1000, 0, 4096, 0x0500_0000][..],
        &[0x4000_0006, 0x0050_0000, 0, 40, 0x0050_1000, 0, 4096][..],
    ] {
        assert!(!crate::intel_gpu_engine::gsc_job_valid(refused));
    }
    // reg_sr adds the masked RING_PSMI_CTL and RING_PWRCTX_MAXCNT; no
    // whitelist grant, so every NONPRIV slot is the GSC engine's NOPID.
    let policy = crate::intel_gpu_reset_policy::ResetPolicy::media(MTL, 0x7d55, set).unwrap();
    let saves = policy.registers(gsc).unwrap();
    let flags = |offset: u32| {
        saves
            .iter()
            .find(|save| save.offset == 0x11a000 + offset)
            .map(|save| save.flags)
    };
    assert_eq!(
        [0x50, 0x54, 0x80, 0xa8, 0xc4, 0x29c].map(flags),
        [Some(1), Some(0), Some(0), Some(0), Some(1), Some(0)]
    );
    assert!((0..12).all(|slot| flags(0x4d0 + slot * 4) == Some(0)));
    assert!(policy
        .registers(Engine::Vcs0)
        .unwrap()
        .iter()
        .all(|save| save.offset != 0x1c0050 && save.offset != 0x1c0054));
    // A media set needs a VCS/VECS: GSCCS0 alone, or with a GT0 engine, is
    // refused by every media policy.
    for refused in [
        EngineSet::of(&[gsc]),
        EngineSet::of(&[Engine::Vcs0, gsc, Engine::Rcs0]),
    ] {
        assert!(crate::intel_gpu_reset_policy::ResetPolicy::media(MTL, 0x7d55, refused).is_none());
        assert!(crate::intel_gpu_nonpriv::EnginePolicy::media(MTL, refused).is_err());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_gsccs_identity_policy_and_reserved_exclusion
);

/// Drive ticks until the GSC queue's job finishes.
fn finish_gsc_job(
    guc: &mut crate::intel_gpu_gt::media::MediaGuc<Window, Arena>,
    w: &Window,
    hw: &mut Hw,
    from: u64,
) -> (u64, Result<(), LoadError>) {
    for tick in 0..2000 {
        let now = from + tick * 1_000_000;
        let polled = media_tick(guc, w, hw, now);
        assert!(!matches!(polled, Poll::Ready(Err(_))), "{polled:?}");
        assert_eq!(guc.state(), MediaGucState::Running);
        if let Some(result) = GscQueue::new(guc, now).finished() {
            return (now, result);
        }
    }
    panic!("GSC job never retired");
}

/// `narf.intel.gsc=1` with available firmware: GSCCS0 is scheduled beside
/// the fused VCS/VECS under its own XE_FW_GSC wake, gets its idle-message
/// pair, ring enable, NOPID-only NONPRIV, ADS class entry, regsets and
/// golden LRC (an empty WA job), and executes exactly the GSC instructions
/// the kernel queue admits. It is never published, placed or sampled, and
/// the verified stop releases its wake with the others. Without the option
/// no GSCCS register or GSC wake is ever written.
fn smoke_media_gt_gsccs_schedules_primes_and_executes_gsc_jobs() -> TestResult {
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    assert!(!guc.gsccs_scheduled());
    guc.schedule_gsccs().unwrap();
    assert!(guc.gsccs_scheduled());
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    // Too late once scheduling started.
    assert_eq!(
        guc.schedule_gsccs(),
        Err(crate::intel_gpu_gt::media::MediaGucError::State)
    );
    let publication = guc.publication().expect("published GT1");
    assert_eq!(
        publication.engines,
        EngineSet::of(&[Engine::Vcs0, Engine::Vcs2, Engine::Vecs0])
    );
    // Priming ran GSCCS0's empty WA job; no GSC instruction yet.
    assert!(hw.gsc_jobs.is_empty());
    assert_eq!(hw.gsc_empty, 1);
    {
        let d = w.0.borrow();
        let fw = GSI_OFFSET + 0xa618;
        assert!(d.writes.contains(&(fw, 0x0001_0001)), "XE_FW_GSC requested");
        let idle = d.writes.iter().position(|w| *w == (GSCCS + 0x50, 0x0001_0000));
        let maxcnt = d.writes.iter().position(|w| *w == (GSCCS + 0x54, 0xa));
        let mode = d.writes.iter().position(|w| *w == (GSCCS + 0x29c, 0x0008_0008));
        assert!(idle.unwrap() < maxcnt.unwrap() && maxcnt.unwrap() < mode.unwrap());
        assert_eq!(d.regs[&(GSCCS + 0xc4)], 0x3f7e_0000 | 9 << 8 | 9 << 1);
        assert_eq!(d.regs[&(GSCCS + 0xa8)], u32::MAX);
        assert_ne!(d.regs[&(GSCCS + 0x80)], 0);
        for slot in 0..12u64 {
            assert_eq!(d.regs[&(GSCCS + 0x4d0 + slot * 4)], 0x11a094);
        }
        let ads = d.memory[&0x20001000].borrow();
        // GUC_GSC_OTHER_CLASS logical 0 -> OTHER_GSC_INSTANCE, enable bit 6,
        // its own golden LRC and size (one page minus the 96-dword header).
        assert_eq!(ads[(0x123c + 5 * 32) / 4] & 0xff, 6);
        assert_eq!(ads[(0x123c + 512 + 5 * 4) / 4], 1 << 6);
        assert_ne!(ads[0x1014 / 4 + 5], 0);
        assert_eq!(ads[0x1054 / 4 + 5], 4096 - 96 * 4);
        // The VCS/VECS entries are those of the GSC-less media GT.
        assert_eq!(ads[(0x123c + 516) / 4], 0b101);
        assert_eq!(ads[(0x123c + 520) / 4], 0b1);
    }
    let saves = ads_registers(&w, Engine::Gsccs0);
    let expected: Vec<u32> = [0x50, 0x54, 0x80, 0xa8, 0xc4, 0x29c]
        .into_iter()
        .chain((0..12).map(|slot| 0x4d0 + slot * 4))
        .map(|offset| 0x11a000 + offset)
        .collect();
    assert_eq!(saves.keys().copied().collect::<Vec<_>>(), expected);
    assert_eq!(
        [0x11a050, 0x11a054, 0x11a0c4].map(|reg| saves[&reg].1),
        [1, 0, 1]
    );
    // GT1's user surfaces never reach GSCCS0.
    let live = arena.live_allocations();
    let (batch, _) = crate::intel_gpu_exec::PpgttProbeResult::prepare(MTL).unwrap();
    assert!(guc
        .submit_user(
            now,
            crate::intel_gpu_user::UserContext::for_engine(Engine::Gsccs0),
            crate::intel_gpu_user::UserBatch(batch),
            None
        )
        .is_err());
    assert!(guc.engine_cycles(now, Engine::Gsccs0, 1).is_err());
    // A command stream the queue does not admit allocates nothing.
    {
        let mut queue = GscQueue::new(&mut guc, now);
        assert!(queue.holds_wake());
        assert_eq!(queue.submit(&[0x0500_0000]), Err(LoadError::Invalid));
        assert_eq!(queue.finished(), None);
    }
    assert_eq!(arena.live_allocations(), live);
    // GSC_FW_LOAD, then a GSC_HECI_CMD_PKT, each inline on GSCCS0.
    let load = crate::intel_gpu_gt::media::gsc::fw_load(0x0100_0000, 4 << 20);
    {
        let mut queue = GscQueue::new(&mut guc, now + 1);
        queue.submit(&load).unwrap();
        // One job at a time: the worker never queues behind an unretired job.
        assert_eq!(queue.submit(&load), Err(LoadError::Queue));
    }
    let (now, result) = finish_gsc_job(&mut guc, &w, &mut hw, now + 2);
    assert_eq!(result, Ok(()));
    let packet =
        crate::intel_gpu_gt::media::gsc::heci_packet(0x0050_0000, 40, 0x0050_1000, 4096).unwrap();
    GscQueue::new(&mut guc, now + 1).submit(&packet).unwrap();
    let (now, result) = finish_gsc_job(&mut guc, &w, &mut hw, now + 2);
    assert_eq!(result, Ok(()));
    assert_eq!(hw.gsc_jobs, [load.to_vec(), packet.to_vec()]);
    // Verified stop: GuC reset, media GRDOM_FULL, then every well, GSC's
    // included, released; nothing is published meanwhile.
    let from = w.0.borrow().writes.len();
    guc.begin_stop(now + 1);
    assert!(GscQueue::new(&mut guc, now + 1).submit(&load).is_err());
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert!(guc.reclaimable());
    {
        let d = w.0.borrow();
        let writes = &d.writes[from..];
        let full = writes.iter().position(|w| *w == (0x38941c, 1)).unwrap();
        let sleep = writes
            .iter()
            .position(|w| *w == (GSI_OFFSET + 0xa618, 0x0001_0000))
            .unwrap();
        assert!(full < sleep);
        assert!(d
            .writes
            .iter()
            .all(|(reg, _)| gsccs_reg(*reg) || (0x380000..0x3c0000).contains(reg)
                || (0x1c0000..0x200000).contains(reg)
                || (0x190304..=0x19031c).contains(reg)
                || matches!(*reg, 0x13816c | 0x1900e8)));
        assert_eq!(d.regs[&0xa188], 1, "GT0 wake untouched");
    }
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // Option off: the same GT1 never touches GSCCS0 or XE_FW_GSC.
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    assert!(GscQueue::new(&mut guc, now).submit(&load).is_err());
    guc.begin_stop(now + 1);
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    {
        let d = w.0.borrow();
        assert!(!d
            .writes
            .iter()
            .any(|(reg, _)| gsccs_reg(*reg) || *reg == GSI_OFFSET + 0xa618));
        let ads = d.memory[&0x20001000].borrow();
        assert_eq!(ads[(0x123c + 512 + 5 * 4) / 4], 0);
    }
    assert_eq!((hw.gsc_jobs.len(), hw.gsc_empty), (0, 0));
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_gsccs_schedules_primes_and_executes_gsc_jobs
);

// ---- The production GSC owner on the media GuC model -----------------------

use crate::intel_gpu_gt::media::gsc::load::Status;
use crate::intel_gpu_gt::media::gsc::owner::{DsmPort, GscOwner};
use crate::intel_gpu_stolen::{self as dsm, Layout, DSM_GSM_OFFSET, GSC_GGTT};

const MIB: u64 = 1 << 20;
const FWSTS1: u64 = 0x116c40;
const FWSTS5: u64 = 0x116c68;
const HECI2_CSR: u64 = 0x117004;
const MARKER: u32 = 0xa578_875a;

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// A parse_gsc_layout-shaped `i915/mtl_gsc_1.bin`: boot1 BPDT whose RBE
/// entry's CPD names RBEP.man (release 102.0.10.1499, SVN 3), recognizable
/// bytes after the headers and an odd length.
fn gsc_image() -> Vec<u8> {
    let mut image = alloc::vec![0u8; 0x1003];
    put32(&mut image, 32, 0x100);
    put32(&mut image, 36, 0x400);
    put32(&mut image, 0x100, 0x55aa);
    put16(&mut image, 0x104, 1);
    put32(&mut image, 0x100 + 24, 0x0001);
    put32(&mut image, 0x100 + 28, 0x80);
    put32(&mut image, 0x180, 0x4450_4324);
    put32(&mut image, 0x184, 1);
    image[0x188] = 2;
    image[0x189] = 1;
    image[0x18a] = 20;
    image[0x180 + 20..0x180 + 28].copy_from_slice(b"RBEP.man");
    put32(&mut image, 0x180 + 20 + 12, 0x100);
    for (field, value) in [102u16, 0, 10, 1499].into_iter().enumerate() {
        put16(&mut image, 0x280 + 36 + field * 2, value);
    }
    put32(&mut image, 0x280 + 44, 3);
    for (index, byte) in image[0x400..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(7) | 1;
    }
    image
}

/// BAR2 over the 4 MiB the GSC object occupies at DSM 4 MiB (above the boot
/// framebuffer): io_base (8 MiB) + 4 MiB.
#[derive(Clone)]
struct Cpu(alloc::rc::Rc<RefCell<Vec<u32>>>);
const CPU_AT: u64 = DSM_GSM_OFFSET + 4 * MIB;
impl crate::intel_gpu_aux::MmioWindow for Cpu {
    fn read32(&self, offset: u64) -> u32 {
        offset
            .checked_sub(CPU_AT)
            .and_then(|at| self.0.borrow().get(at as usize / 4).copied())
            .unwrap_or(u32::MAX)
    }
    fn write32(&self, offset: u64, value: u32) {
        if let Some(at) = offset.checked_sub(CPU_AT) {
            if let Some(word) = self.0.borrow_mut().get_mut(at as usize / 4) {
                *word = value;
            }
        }
    }
}

/// 64 MiB DSM, 4 MiB WOPCM, no GSC carve; the boot framebuffer in DSM
/// 0..4 MiB is mapped in the aperture. `dw1` keeps the claim registry's key
/// unique to the fixture.
struct Port {
    layout: Layout,
    ptes: Vec<u64>,
    cpu: Cpu,
}
impl Port {
    fn new(dw1: u32) -> Self {
        let layout = dsm::layout(dsm::Facts {
            ggc: (0x02 << dsm::GMS_SHIFT) | dsm::GGMS_MASK,
            stolen_reserved_lo: 2 << dsm::WOPCM_SIZE_SHIFT,
            media_gmd_id: MEDIA_GMD,
            gscpsmi_base: 0,
            gmadr_base: 0x40_0000_0000,
            gmadr_len: 256 * MIB,
            bsm_dw0: 0x6C00_0000,
            bsm_dw1: dw1,
        })
        .unwrap();
        let mut ptes: Vec<u64> = (0..2048u64)
            .map(|i| (0x8000_0000 + i * 4096) | dsm::GGTT_PTE_PRESENT)
            .collect();
        for i in 0..1024u64 {
            ptes[512 + i as usize] =
                (DSM_GSM_OFFSET + i * 4096) | dsm::GGTT_PTE_DM | dsm::GGTT_PTE_PRESENT;
        }
        Self {
            layout,
            ptes,
            cpu: Cpu(alloc::rc::Rc::new(RefCell::new(alloc::vec![0; 1 << 20]))),
        }
    }
}
impl DsmPort for Port {
    type Cpu = Cpu;
    fn layout(&self) -> Option<(Layout, u64)> {
        Some((self.layout, self.ptes.len() as u64))
    }
    fn pte(&self, index: u64) -> u64 {
        self.ptes[index as usize]
    }
    fn system_ram(&self, _: u64) -> bool {
        false
    }
    fn cpu(&self) -> Cpu {
        self.cpu.clone()
    }
}

/// GSC firmware behind GSCCS0 on the model: GSC_FW_LOAD (after checking
/// memcpy_fw's copy in DSM) sets INIT_COMPLETE; MKHI, PXP and proxy packets
/// get replies in their output halves. Every recorded job is served once.
#[derive(Default)]
struct Firmware {
    served: usize,
    image: Vec<u8>,
    /// Hold GSC_FW_LOAD forever (no INIT_COMPLETE).
    hang_load: bool,
}

fn memory_at(w: &Window, address: u32) -> (Words, usize) {
    let d = w.0.borrow();
    let (base, words) = d
        .memory
        .iter()
        .rev()
        .find(|(base, words)| {
            **base <= address && address - **base < words.borrow().len() as u32 * 4
        })
        .expect("GGTT address of an owned object");
    (words.clone(), (address - base) as usize)
}

fn read_bytes(words: &Words, at: usize, len: usize) -> Vec<u8> {
    let words = words.borrow();
    let mut out = Vec::new();
    for word in &words[at / 4..(at + len).div_ceil(4)] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn write_bytes(words: &Words, at: usize, bytes: &[u8]) {
    let mut words = words.borrow_mut();
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let mut word = words[at / 4 + index].to_le_bytes();
        word[..chunk.len()].copy_from_slice(chunk);
        words[at / 4 + index] = u32::from_le_bytes(word);
    }
}

fn reply(client: u8, payload: &[u8]) -> Vec<u8> {
    let mut header = alloc::vec![0u8; 36];
    put32(&mut header, 0, MARKER);
    header[4] = client;
    put16(&mut header, 6, 1);
    put32(&mut header, 24, (36 + payload.len()) as u32);
    header.extend_from_slice(payload);
    header
}

impl Firmware {
    fn serve(&mut self, w: &Window, hw: &Hw, port: &Port) {
        while self.served < hw.gsc_jobs.len() {
            let job = hw.gsc_jobs[self.served].clone();
            self.served += 1;
            let set = |reg: u64, bits: u32| {
                let mut d = w.0.borrow_mut();
                let value = d.regs.get(&reg).copied().unwrap_or(0) | bits;
                d.regs.insert(reg, value);
            };
            if job[0] == 0x4040_0002 {
                assert_eq!(job, [0x4040_0002, GSC_GGTT as u32, 0, 1024 | 1 << 31]);
                // memcpy_fw: the image, then zeroes, in DSM through BAR2.
                let cpu = port.cpu.0.borrow();
                let copied: Vec<u8> = cpu[..self.image.len().div_ceil(4)]
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .take(self.image.len())
                    .collect();
                assert_eq!(copied, self.image);
                assert_eq!(cpu[(1 << 20) - 1], 0);
                drop(cpu);
                if !self.hang_load {
                    set(FWSTS1, 1 << 9);
                }
                continue;
            }
            assert_eq!(job[0], 0x4000_0006);
            let (input, at) = memory_at(w, job[1]);
            let message = read_bytes(&input, at, job[3] as usize);
            assert_eq!(
                u32::from_le_bytes(message[..4].try_into().unwrap()),
                MARKER
            );
            let (output, out_at) = memory_at(w, job[4]);
            let answer = match message[4] {
                // MKHI GET_HOST_COMPATIBILITY_VERSION: 102.1.0.
                7 => {
                    let mut payload = alloc::vec![0u8; 20];
                    payload[..2].copy_from_slice(&[0x30, 0xc2]);
                    put16(&mut payload, 4, 102);
                    put16(&mut payload, 6, 1);
                    reply(7, &payload)
                }
                // PXP 4.3 NEW_HUC_AUTH of the whole HuC object.
                17 => {
                    set(FWSTS5, 1 << 19);
                    let mut payload = alloc::vec![0u8; 16];
                    put32(&mut payload, 0, 0x0004_0003);
                    reply(17, &payload)
                }
                // Proxy QUERY from the KMD: END at once, proxy state NORMAL.
                10 => {
                    set(FWSTS1, 5);
                    let mut payload = alloc::vec![0u8; 16];
                    put32(&mut payload, 0, 3);
                    put32(&mut payload, 4, 0x20000);
                    put32(&mut payload, 8, 0x10000);
                    reply(10, &payload)
                }
                client => panic!("unexpected HECI client {client}"),
            };
            write_bytes(&output, out_at, &answer);
        }
    }
}

type Owner = GscOwner<Arena, Cpu>;

/// Ticks of the model with the owner beside the media GuC until `done`.
#[allow(clippy::too_many_arguments)]
fn gsc_until(
    owner: &mut Owner,
    guc: &mut crate::intel_gpu_gt::media::MediaGuc<Window, Arena>,
    w: &Window,
    hw: &mut Hw,
    port: &Port,
    fw: &mut Firmware,
    headers: bool,
    from: u64,
    done: impl Fn(&Owner, &Hw) -> bool,
) -> u64 {
    for tick in 0..4000 {
        let now = from + tick * 1_000_000;
        let polled = media_tick(guc, w, hw, now);
        assert!(!matches!(polled, Poll::Ready(Err(_))), "{polled:?}");
        let _ = owner.poll(now, guc, w, port, headers, 0);
        fw.serve(w, hw, port);
        if done(owner, hw) {
            return now;
        }
    }
    panic!("GSC made no progress");
}

fn media_guc_with_huc(
    w: &Window,
    arena: &Arena,
    huc: &crate::intel_gpu_huc::Firmware,
    adopt: bool,
) -> crate::intel_gpu_gt::media::MediaGuc<Window, Arena> {
    let mut guc = super::media_huc::start(w, arena, Some((huc, adopt)));
    guc.honour_gsc_reset_workaround().unwrap();
    guc.schedule_gsccs().unwrap();
    guc
}

fn stop_and_end(
    owner: &mut Owner,
    mut guc: crate::intel_gpu_gt::media::MediaGuc<Window, Arena>,
    w: &Window,
    arena: &Arena,
    hw: &mut Hw,
    from: u64,
) -> u64 {
    // xe_gsc_stop_prepare: nothing runs once the owner is idle.
    assert!(owner.quiesce(from, Some(&mut guc), w));
    guc.begin_stop(from);
    let (now, polled) = media_until(&mut guc, w, hw, from + 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert!(guc.reclaimable());
    owner.end_session(w, true);
    drop(guc);
    super::media_huc::reclaimed(w, arena);
    now
}

/// Linux without CONFIG_INTEL_MEI_GSC_PROXY, end to end through the
/// production owner: the claimed DSM object is DM-mapped and receives the
/// firmware, GSC_FW_LOAD reaches INIT_COMPLETE, the compatibility query
/// answers 102, the HuC the media GuC authenticated is authenticated via
/// the GSC too, then xe_gsc_proxy_start fails with ENODEV after toggling the
/// proxy interrupt and the GSC is LOAD_FAIL. A GT reset (a new media GuC)
/// rewrites the same DM window, never reloads the failed GSC, and every
/// arena object is freed after each verified stop.
fn smoke_media_gsc_owner_without_mei_loads_auths_huc_and_ends_load_fail() -> TestResult {
    let (w, arena) = media_model();
    let huc =
        crate::intel_gpu_huc::Firmware::from_fixture(MTL, &super::media_huc::huc_gsc()).unwrap();
    let mut guc = media_guc_with_huc(&w, &arena, &huc, false);
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    assert_eq!(guc.huc_outcome(), Some(true));
    let image = gsc_image();
    let mut owner = Owner::new(Some(&image));
    assert!(owner.available());
    assert_eq!(owner.status(), Status::Available);
    let port = Port::new(0x61);
    let mut fw = Firmware {
        image: image.clone(),
        ..Firmware::default()
    };
    let now = gsc_until(
        &mut owner,
        &mut guc,
        &w,
        &mut hw,
        &port,
        &mut fw,
        true,
        now + 1,
        |o, _| o.idle() && o.status() != Status::Available && o.status() != Status::Loadable,
    );
    assert_eq!(owner.status(), Status::LoadFail(LoadError::NoDevice));
    assert_eq!(
        owner.compatibility(),
        Some(crate::intel_gpu_gt::media::gsc::Version::new(102, 1, 0, 0))
    );
    assert_eq!(owner.huc(), Some(true));
    assert!(!owner.wedged());
    // GSC_FW_LOAD, the MKHI query, then NEW_HUC_AUTH; no proxy packet.
    assert_eq!(hw.gsc_jobs.len(), 3);
    assert_eq!(hw.gsc_jobs[0][0], 0x4040_0002);
    assert!(hw.gsc_jobs[1..].iter().all(|job| job[0] == 0x4000_0006));
    {
        let d = w.0.borrow();
        assert_eq!(d.gsc_maps, [(4 * MIB, 1024)]);
        assert_eq!(dsm::gsc_claim(port.layout), Some((4 * MIB, dsm::GSC_BYTES)));
        // Proxy start enabled the HECI2 interrupt, then disabled it again.
        let csr: Vec<u32> = d
            .writes
            .iter()
            .filter(|(reg, _)| *reg == HECI2_CSR)
            .map(|(_, value)| *value)
            .collect();
        assert_eq!(csr, [1, 0]);
        assert_eq!(d.regs[&FWSTS5] & 1 << 19, 1 << 19);
        // XE_FW_GSC stayed the media GuC's: the worker wrote no request.
        assert_eq!(
            d.writes
                .iter()
                .filter(|(reg, _)| *reg == GSI_OFFSET + 0xa618)
                .count(),
            1
        );
    }
    // The HuC stays RUNNING for query7 (its GSC authentication succeeded).
    assert!(guc.huc_version(|| true).is_some());

    // GT reset: a new media GuC adopts the HuC; the failed GSC never reloads.
    let now = stop_and_end(&mut owner, guc, &w, &arena, &mut hw, now + 1);
    assert_eq!(arena.live_allocations(), 0);
    let mut guc = media_guc_with_huc(&w, &arena, &huc, true);
    let (now, polled) = media_until(&mut guc, &w, &mut hw, now + 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    let jobs = hw.gsc_jobs.len();
    let now = gsc_until(
        &mut owner,
        &mut guc,
        &w,
        &mut hw,
        &port,
        &mut fw,
        true,
        now + 1,
        |o, _| o.huc().is_some(),
    );
    assert!(owner.idle());
    assert_eq!(owner.status(), Status::LoadFail(LoadError::NoDevice));
    assert_eq!(hw.gsc_jobs.len(), jobs);
    assert_eq!(w.0.borrow().gsc_maps, [(4 * MIB, 1024), (4 * MIB, 1024)]);
    stop_and_end(&mut owner, guc, &w, &arena, &mut hw, now + 1);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_owner_without_mei_loads_auths_huc_and_ends_load_fail
);

/// A CSME end that the GSC never needs (its first proxy reply is END).
struct Unused;
impl crate::intel_gpu_gt::CsmeProxy for Unused {
    fn send(&mut self, _: &[u8]) -> Result<usize, i32> {
        panic!("no CSME message in this conversation")
    }
    fn recv(&mut self, _: &mut [u8]) -> Result<usize, i32> {
        panic!("no CSME message in this conversation")
    }
}

/// GSC_FW_LOAD was submitted and executed.
fn fw_served(hw: &Hw) -> bool {
    hw.gsc_jobs
        .first()
        .is_some_and(|job| job[0] == 0x4040_0002)
}

/// With a bound CSME component the proxy channel exists and the GSC reaches
/// RUNNING (PROXY_STATE_NORMAL). Resume after D3hot re-classifies the GSC
/// with no job; after the GSC lost its state (D3cold) it reloads in full.
/// A load interrupted by a stop that cannot wait is LOAD_FAIL, and an
/// unavailable image leaves GSCCS0 out.
fn smoke_media_gsc_owner_proxy_resume_reload_and_interrupted_load() -> TestResult {
    use crate::intel_gpu_gt::{register_csme_proxy, unregister_csme_proxy};
    assert!(unregister_csme_proxy().is_none());
    assert!(register_csme_proxy(alloc::boxed::Box::new(Unused)).is_ok());
    assert!(register_csme_proxy(alloc::boxed::Box::new(Unused)).is_err());
    let (w, arena) = media_model();
    let image = gsc_image();
    let mut owner = Owner::new(Some(&image));
    let port = Port::new(0x62);
    let mut fw = Firmware {
        image: image.clone(),
        ..Firmware::default()
    };
    let mut hw = Hw::default();
    let run = |owner: &mut Owner, hw: &mut Hw, fw: &mut Firmware, from: u64| {
        let mut guc = start_media(&w, &arena);
        guc.honour_gsc_reset_workaround().unwrap();
        guc.schedule_gsccs().unwrap();
        let (now, polled) = media_until(&mut guc, &w, hw, from, |p| p.is_ready());
        assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
        let now = gsc_until(owner, &mut guc, &w, hw, &port, fw, false, now + 1, |o, _| {
            o.idle() && matches!(o.status(), Status::Running | Status::LoadFail(_))
        });
        // The proxy channel (16 pages) lives beside the version packet.
        assert!(w
            .0
            .borrow()
            .memory
            .values()
            .any(|words| words.borrow().len() == 16 * 1024));
        stop_and_end(owner, guc, &w, &arena, hw, now + 1)
    };
    let now = run(&mut owner, &mut hw, &mut fw, 1);
    assert_eq!(owner.status(), Status::Running);
    assert_eq!(hw.gsc_jobs.len(), 3, "load, MKHI, proxy QUERY");
    assert_eq!(arena.live_allocations(), 0);
    // D3hot: the GSC kept its firmware and proxy state.
    let now = run(&mut owner, &mut hw, &mut fw, now + 1);
    assert_eq!(owner.status(), Status::Running);
    assert_eq!(hw.gsc_jobs.len(), 3);
    // D3cold: the GSC lost everything; the same DSM object reloads.
    w.0.borrow_mut().regs.insert(FWSTS1, 0);
    run(&mut owner, &mut hw, &mut fw, now + 1);
    assert_eq!(owner.status(), Status::Running);
    assert_eq!(hw.gsc_jobs.len(), 6);
    assert_eq!(hw.gsc_jobs[3], hw.gsc_jobs[0]);
    assert!(w
        .0
        .borrow()
        .gsc_maps
        .iter()
        .all(|map| *map == (4 * MIB, 1024)));
    assert!(unregister_csme_proxy().is_some());

    // A fault stop that cannot wait interrupts a load: LOAD_FAIL, objects
    // freed after the verified stop.
    let (w, arena) = media_model();
    let mut owner = Owner::new(Some(&image));
    let port = Port::new(0x63);
    let mut fw = Firmware {
        image: image.clone(),
        hang_load: true,
        ..Firmware::default()
    };
    let mut hw = Hw::default();
    let mut guc = start_media(&w, &arena);
    guc.schedule_gsccs().unwrap();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    let now = gsc_until(
        &mut owner,
        &mut guc,
        &w,
        &mut hw,
        &port,
        &mut fw,
        false,
        now + 1,
        |_, hw| fw_served(hw),
    );
    assert!(!owner.idle());
    guc.begin_stop(now + 1);
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    owner.end_session(&w, true);
    assert_eq!(owner.status(), Status::LoadFail(LoadError::Io));
    assert!(owner.idle());
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // No image, or a malformed one: GSC unavailable, so GSCCS0 stays out.
    assert!(!Owner::new(None).available());
    assert_eq!(Owner::new(None).status(), Status::Missing);
    assert!(!Owner::new(Some(&image[..0x200])).available());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_owner_proxy_resume_reload_and_interrupted_load
);
