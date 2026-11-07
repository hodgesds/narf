//! Native GuC error-capture conversations: ADS list bytes, STATE_CAPTURE
//! extraction and matching, the manual fallback and snapshot text. Vectors
//! are from MIT Linux b90c984d xe_guc_capture.c and abi/guc_capture_abi.h.
use super::*;
use alloc::{string::String, vec};
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Memory {
    base: u32,
    words: RefCell<Vec<u32>>,
    coherent: bool,
}
impl Memory {
    fn new(base: u32, bytes: usize) -> Self {
        Self {
            base,
            words: RefCell::new(vec![0; bytes / 4]),
            coherent: true,
        }
    }
    fn word(&self, offset: usize) -> u32 {
        self.words.borrow()[offset / 4]
    }
    fn put(&self, offset: usize, words: &[u32]) {
        let mut memory = self.words.borrow_mut();
        let len = memory.len();
        for (index, word) in words.iter().enumerate() {
            memory[(offset / 4 + index) % len] = *word;
        }
    }
}
impl GpuBacking for Memory {
    fn coherent_for_device(&self) -> bool {
        self.coherent
    }
    fn ggtt_offset(&self) -> u32 {
        self.base
    }
    fn size_pages(&self) -> u32 {
        (self.words.borrow().len() * 4 / PAGE) as u32
    }
    fn read32(&self, offset: u64) -> u32 {
        assert_eq!(offset % 4, 0);
        self.words.borrow()[offset as usize / 4]
    }
    fn write32(&self, offset: u64, value: u32) {
        assert_eq!(offset % 4, 0);
        self.words.borrow_mut()[offset as usize / 4] = value;
    }
}

const ADS_BASE: u32 = 0x2000_0000;
const LISTS_BASE: u32 = 0x3000_0000;

fn slot(field: u64, owner: usize, class: usize) -> usize {
    field as usize + (owner * 16 + class) * 4
}

fn smoke_guc_capture_ads_lists_follow_prep_lists_per_family() -> TestResult {
    // xe_guc_capture_ads_input_worst_size: 11 pages on 12.55+, 9 before.
    assert_eq!(Family::XeHpg.worst_size(), 11 * PAGE);
    assert_eq!(Family::XeLp.worst_size(), 9 * PAGE);
    assert_eq!(
        Family::for_platform(GtPlatform::Battlemage),
        Some(Family::XeHpg)
    );
    assert_eq!(
        Family::for_platform(GtPlatform::Gen12(
            crate::intel_gpu_gt::Gen12Platform::TigerLake
        )),
        Some(Family::XeLp)
    );
    for (engine, class) in [
        (Engine::Rcs0, 0),
        (Engine::Ccs3, 0),
        (Engine::Vcs1, 1),
        (Engine::Vecs0, 2),
        (Engine::Bcs8, 3),
    ] {
        assert_eq!(capture_class(engine), class);
    }
    // DSS 0, 1 and 5 fused in; four DSS per steering group.
    let lists = Lists::new(Family::XeHpg, true, 0b10_0011, 0b10_0011, 4).unwrap();
    assert_eq!(lists.steered().len(), 18);
    assert_eq!(lists.max_regs(), 27);
    let ads = Memory::new(ADS_BASE, 0x2000);
    let out = Memory::new(LISTS_BASE, lists.bytes());
    out.put(0, &[0xffff_ffff; 4]);
    // Render+compute, video, video-enhance and blitter present; no GSC.
    let total = lists.write_ads(&ads, &out, [0b11, 0b1, 0b1, 0b1_0000_0001, 0]);
    // Null page, RC class, RC instance, VCS instance, VECS class/instance,
    // BCS instance and the global list.
    assert_eq!(total, 8 * PAGE);
    assert_eq!(&out.words.borrow()[..4], &[0; 4]);
    let pointer = |field, owner, class| ads.word(slot(field, owner, class));
    assert_eq!(pointer(ADS_CLASS, 0, 0), LISTS_BASE + 0x1000);
    assert_eq!(pointer(ADS_INSTANCE, 0, 0), LISTS_BASE + 0x2000);
    assert_eq!(pointer(ADS_CLASS, 0, 1), LISTS_BASE, "empty VCS class list");
    assert_eq!(pointer(ADS_INSTANCE, 0, 1), LISTS_BASE + 0x3000);
    assert_eq!(pointer(ADS_CLASS, 0, 2), LISTS_BASE + 0x4000);
    assert_eq!(pointer(ADS_INSTANCE, 0, 2), LISTS_BASE + 0x5000);
    assert_eq!(pointer(ADS_CLASS, 0, 3), LISTS_BASE);
    assert_eq!(pointer(ADS_INSTANCE, 0, 3), LISTS_BASE + 0x6000);
    assert_eq!(pointer(ADS_CLASS, 0, 4), LISTS_BASE, "no GSC engine");
    assert_eq!(pointer(ADS_INSTANCE, 0, 4), LISTS_BASE);
    assert_eq!(ads.word(ADS_GLOBAL as usize), LISTS_BASE + 0x7000);
    // VF owns no list: every pointer names the zero-descriptor page.
    for class in 0..5 {
        assert_eq!(pointer(ADS_CLASS, 1, class), LISTS_BASE);
        assert_eq!(pointer(ADS_INSTANCE, 1, class), LISTS_BASE);
    }
    assert_eq!(ads.word(ADS_GLOBAL as usize + 4), LISTS_BASE);
    // Class slots 5..15 stay zero, as the memset ADS leaves them.
    for class in 5..16 {
        assert_eq!(pointer(ADS_CLASS, 0, class), 0);
        assert_eq!(pointer(ADS_INSTANCE, 1, class), 0);
    }
    // RC class: RCU_MODE then per DSS SAMPLER/ROW + four XeHPG INSTDONEs.
    assert_eq!(out.word(0x1000), 19);
    assert_eq!(
        (0..4).map(|i| out.word(0x1004 + i * 4)).collect::<Vec<_>>(),
        [0x14800, 0xdeadf00d, 0, 0]
    );
    let steered = |index: usize| -> [u32; 3] {
        let at = 0x1004 + (1 + index) * 16;
        [out.word(at), out.word(at + 4), out.word(at + 8)]
    };
    assert_eq!(steered(0), [0xe160, 0xdeadf00d, 2]);
    assert_eq!(steered(5), [0x666c, 0xdeadf00d, 2]);
    assert_eq!(steered(6), [0xe160, 0xdeadf00d, 2 | 1 << 20]);
    // DSS 5: group 1, instance 1.
    assert_eq!(steered(12), [0xe160, 0xdeadf00d, 2 | 1 << 12 | 1 << 20]);
    assert_eq!(steered(17), [0x666c, 0xdeadf00d, 2 | 1 << 12 | 1 << 20]);
    assert_eq!(
        out.word(0x1004 + 19 * 16),
        0,
        "no descriptor past the count"
    );
    // Instance lists carry engine-relative offsets in table order.
    for page in [0x2000, 0x3000, 0x5000, 0x6000] {
        assert_eq!(out.word(page), 27);
        for (index, descr) in INSTANCE_REGS.iter().enumerate() {
            assert_eq!(out.word(page + 4 + index * 16), descr.offset);
            assert_eq!(out.word(page + 8 + index * 16), 0xdeadf00d);
        }
    }
    assert_eq!(out.word(0x4000), 4);
    assert_eq!(out.word(0x4004 + 3 * 16), 0x1cf000);
    assert_eq!(
        (0..5).map(|i| out.word(0x7000 + i * 4)).collect::<Vec<_>>(),
        [1, 0xa188, 0xdeadf00d, 0, 0]
    );

    // XeLP: SC_INSTDONE triple in the class list, SAMPLER/ROW per DSS only.
    let lp = Lists::new(Family::XeLp, true, 0b1, 0b1, 6).unwrap();
    let ads = Memory::new(ADS_BASE, 0x2000);
    let out = Memory::new(LISTS_BASE, lp.bytes());
    lp.write_ads(&ads, &out, [1, 0, 0, 1, 0]);
    assert_eq!(out.word(0x1000), 6);
    assert_eq!(out.word(0x1004 + 3 * 16), 0x7108);
    assert_eq!(out.word(0x1004 + 5 * 16), 0xe164);

    // A short list object refuses lists past its end (the capture_size
    // overflow check) and points them at the zero page.
    let short = Memory::new(LISTS_BASE, 3 * PAGE);
    let ads = Memory::new(ADS_BASE, 0x2000);
    lists.write_ads(&ads, &short, [1, 0, 0, 1, 0]);
    assert_eq!(pointer_of(&ads, ADS_CLASS, 0, 0), LISTS_BASE + 0x1000);
    assert_eq!(pointer_of(&ads, ADS_INSTANCE, 0, 0), LISTS_BASE + 0x2000);
    assert_eq!(pointer_of(&ads, ADS_INSTANCE, 0, 3), LISTS_BASE);
    assert_eq!(ads.word(ADS_GLOBAL as usize), LISTS_BASE);

    // Compute DSS beyond the geometry-sized allocation are never written.
    let clamped = Lists::new(Family::XeHpg, true, 0b1, 0b11, 4).unwrap();
    assert_eq!(clamped.steered().len(), 6);
    assert!(clamped.steered().iter().all(|descr| descr.dss == 0));
    // No render/compute engine: no steered list (guc_capture_alloc_steered_lists).
    let media = Lists::new(Family::XeHpg, false, 0b1, 0b1, 4).unwrap();
    assert!(media.steered().is_empty());
    assert!(Lists::new(Family::XeHpg, true, 1, 1, 0).is_err());
    TestResult::Pass
}
fn pointer_of(ads: &Memory, field: u64, owner: usize, class: usize) -> u32 {
    ads.word(slot(field, owner, class))
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_guc_capture_ads_lists_follow_prep_lists_per_family
);

const REGION: usize = LOG_REGION as usize;

/// Write `words` into the capture ring from byte `start`, wrapping at its end.
fn put_ring(log: &Memory, start: u32, words: &[u32]) {
    for (index, word) in words.iter().enumerate() {
        let at = (start + index as u32 * 4) % LOG_REGION_BYTES;
        log.put(REGION + at as usize, &[*word]);
    }
}

fn log() -> Memory {
    Memory::new(0x4000_0000, LOG_REGION as usize + LOG_REGION_BYTES as usize)
}
/// guc_log_buffer_state for GUC_LOG_TYPE_STATE_CAPTURE.
fn state(log: &Memory, read: u32, write: u32, flags: u32) {
    log.put(
        LOG_STATE as usize,
        &[0, 0, read, write, LOG_REGION_BYTES, write, 0, flags, 0],
    );
}
fn header(ty: u32, class: u32, instance: u32, lrca: u32, guc_id: u32, count: u32) -> [u32; 5] {
    [0, ty | class << 4 | instance << 8, lrca, guc_id, count]
}
fn reg(offset: u32, value: u32) -> [u32; 4] {
    [offset, value, 0, 0]
}
/// One engine's full group: global, render/compute class and instance.
fn group(guc_class: u32, instance: u32, lrca: u32, guc_id: u32, seed: u32) -> Vec<u32> {
    let mut words = vec![0, 3];
    words.extend(header(GLOBAL as u32, 0, 0, !0, !0, 1));
    words.extend(reg(0xa188, seed));
    words.extend(header(CLASS as u32, guc_class, 0, !0, !0, 1));
    words.extend(reg(0x14800, seed + 1));
    words.extend(header(
        INSTANCE as u32,
        guc_class,
        instance,
        lrca,
        guc_id,
        27,
    ));
    for (index, descr) in INSTANCE_REGS.iter().enumerate() {
        words.extend(reg(descr.offset, seed + 0x100 + index as u32));
    }
    words
}
fn lists() -> Lists {
    Lists::new(Family::XeHpg, true, 0b1, 0b1, 4).unwrap()
}

fn smoke_guc_capture_extracts_groups_matches_and_acknowledges() -> TestResult {
    let lists = lists();
    let mut pool = Pool::new(&lists).unwrap();
    let log = log();
    let stream = group(0, 0, 0x1234_5000, 7, 0x10);
    let bytes = stream.len() as u32 * 4;
    log.put(REGION + 0x100, &stream);
    state(&log, 0x100, 0x100 + bytes, 1);
    assert!(pool.process(&log, || true));
    // read_ptr = sampled write pointer; flush_to_file cleared.
    assert_eq!(log.word(LOG_STATE as usize + 8), 0x100 + bytes);
    assert_eq!(log.word(LOG_STATE as usize + 28), 0);
    assert_eq!(pool.outlist().len(), 1);
    assert_eq!(
        pool.find_match(0, |instance| instance == 1, 7, 0x1234_5000),
        None
    );
    assert_eq!(
        pool.find_match(4, |instance| instance == 0, 7, 0x1234_5000),
        None
    );
    assert_eq!(pool.find_match(0, |_| true, 8, 0x1234_5000), None);
    assert_eq!(pool.find_match(0, |_| true, 7, 0x1234_6000), None);
    let index = pool
        .find_match(0, |instance| instance == 0, 7, 0x1234_5000)
        .unwrap();
    let node = pool.node(index);
    assert_eq!(
        (node.source, node.partial, node.guc_id),
        (Source::GuC, false, 7)
    );
    assert_eq!(node.list(GLOBAL), &[reg32(0xa188, 0x10)]);
    assert_eq!(node.list(CLASS), &[reg32(0x14800, 0x11)]);
    assert_eq!(node.list(INSTANCE).len(), 27);
    assert_eq!(node.list(INSTANCE)[16], reg32(0x5c, 0x120));

    let mut text = String::new();
    print(
        &mut text,
        Facts {
            engine: Engine::Rcs0,
            logical: 0,
            wake_ref: 1,
        },
        node,
        &lists,
    )
    .unwrap();
    assert!(text.starts_with(
        "rcs0 (physical), logical instance=0\n\tCapture_source: GuC\n\tCoverage: full-capture\n\tForcewake: domain 0x2, ref 1\n\tReserved: no\n\tFORCEWAKE_GT: 0x00000010\n\tRCU_MODE: 0x00000011\n\tHWSTAM: 0x00000110\n"
    ));
    // ACTHD = UDW(0x5c, index 16) << 32 | LDW(0x74, index 15).
    assert!(text.contains("\tACTHD: 0x000001200000011f\n"));
    assert!(text.contains("\tRING_EXECLIST_SQ_CONTENTS: 0x0000012a00000129\n"));
    assert!(
        !text.contains("SAMPLER_INSTDONE"),
        "steered regs absent from node"
    );
    assert!(text.ends_with("\n\n"));

    // A newer capture for the same GuC id replaces the stale node.
    let again = group(0, 0, 0x1234_5000, 7, 0x20);
    log.put(REGION, &again);
    state(&log, 0, again.len() as u32 * 4, 0);
    assert!(pool.process(&log, || true));
    assert_eq!(pool.outlist().len(), 1);
    let index = pool.find_match(0, |_| true, 7, 0x1234_5000).unwrap();
    assert_eq!(pool.node(index).list(GLOBAL)[0].value, 0x20);
    pool.put_matched(index);
    assert!(pool.outlist().is_empty());
    assert_eq!(pool.find_match(0, |_| true, 7, 0x1234_5000), None);

    // Access loss before publication leaves read_ptr untouched (no ack).
    log.put(REGION, &again);
    state(&log, 0, again.len() as u32 * 4, 1);
    let mut calls = 0;
    assert!(!pool.process(&log, || {
        calls += 1;
        calls < 3
    }));
    assert_eq!(log.word(LOG_STATE as usize + 8), 0);
    assert_eq!(log.word(LOG_STATE as usize + 28), 1);
    let mut incoherent = log;
    incoherent.coherent = false;
    assert!(!pool.process(&incoherent, || true));
    TestResult::Pass
}
fn reg32(offset: u32, value: u32) -> Reg {
    Reg {
        offset,
        value,
        flags: 0,
        mask: 0,
    }
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_guc_capture_extracts_groups_matches_and_acknowledges
);

fn smoke_guc_capture_dependent_resets_wrap_overflow_and_reuse() -> TestResult {
    let lists = lists();
    let mut pool = Pool::new(&lists).unwrap();
    let log = log();
    // One partial group: global, class, then two dependent instances. The
    // second instance clones the global and class lists.
    let mut stream = vec![0, 4 | 1 << 8];
    stream.extend(header(GLOBAL as u32, 0, 0, !0, !0, 1));
    stream.extend(reg(0xa188, 0x51));
    stream.extend(header(CLASS as u32, 4, 0, !0, !0, 1));
    stream.extend(reg(0x14800, 0x52));
    stream.extend(header(INSTANCE as u32, 4, 0, 0xa000, 3, 1));
    stream.extend(reg(0x34, 0x53));
    stream.extend(header(INSTANCE as u32, 4, 2, 0xb000, 4, 1));
    stream.extend(reg(0x34, 0x54));
    // An unknown capture type is skipped with its registers.
    stream.extend([0, 1]);
    stream.extend(header(9, 0, 0, 0, 0, 2));
    stream.extend(reg(1, 1));
    stream.extend(reg(2, 2));
    // Straddle the ring end: GuC writes the stream across the wrap.
    let start = LOG_REGION_BYTES - 40;
    put_ring(&log, start, &stream);
    let end = (start + stream.len() as u32 * 4) % LOG_REGION_BYTES;
    state(&log, start, end, 0);
    assert!(pool.process(&log, || true));
    assert_eq!(log.word(LOG_STATE as usize + 8), end);
    let first = pool.find_match(4, |i| i == 0, 3, 0xa000).unwrap();
    let second = pool.find_match(4, |i| i == 2, 4, 0xb000).unwrap();
    for (index, value) in [(first, 0x53), (second, 0x54)] {
        let node = pool.node(index);
        assert!(node.partial);
        assert_eq!(node.list(GLOBAL)[0].value, 0x51);
        assert_eq!(node.list(CLASS)[0].value, 0x52);
        assert_eq!(node.list(INSTANCE), &[reg32(0x34, value)]);
    }
    assert_eq!(
        pool.outlist().len(),
        2,
        "the unknown-type group adds no node"
    );
    assert_eq!(pool.errors, 0);

    // A full counter change re-reads the whole region from offset zero.
    let mut fresh = Pool::new(&lists).unwrap();
    let log = self::log();
    log.put(REGION, &group(0, 0, 0xc000, 9, 0x60));
    state(&log, 0x8000, 0x8000, 1 << 1);
    assert!(fresh.process(&log, || true));
    assert_eq!(log.word(LOG_STATE as usize + 8), LOG_REGION_BYTES);
    assert!(fresh.find_match(0, |_| true, 9, 0xc000).is_some());
    // Offsets past the region are untrusted: whole-region read as well.
    let mut invalid = Pool::new(&lists).unwrap();
    state(&log, LOG_REGION_BYTES + 4, 8, 0);
    assert!(invalid.process(&log, || true));
    assert!(invalid.find_match(0, |_| true, 9, 0xc000).is_some());

    // A misaligned byte count is an extraction error, not a guess.
    let mut misaligned = Pool::new(&lists).unwrap();
    let log = self::log();
    log.put(REGION, &group(0, 0, 0xd000, 10, 0x70));
    state(&log, 0, 6, 0);
    assert!(misaligned.process(&log, || true));
    assert_eq!(misaligned.errors, 1);
    assert!(misaligned.outlist().is_empty());

    // NODES nodes: further captures reuse the newest unlocked node, as
    // guc_capture_get_prealloc_node's reverse walk does.
    let mut full = Pool::new(&lists).unwrap();
    let log = self::log();
    let mut stream = Vec::new();
    for id in 0..NODES as u32 + 1 {
        stream.extend(group(0, 0, 0xe000 + id, 20 + id, id));
    }
    log.put(REGION, &stream);
    state(&log, 0, stream.len() as u32 * 4, 0);
    assert!(full.process(&log, || true));
    assert_eq!(full.outlist().len(), NODES);
    assert!(full
        .find_match(0, |_| true, 20 + NODES as u32, 0xe000 + NODES as u32)
        .is_some());
    assert!(
        full.find_match(0, |_| true, 20, 0xe000).is_some(),
        "oldest kept"
    );

    // A register count beyond the node bound is clipped; extraction stops
    // reading there, as guc_capture_extract_reglists does.
    let mut clipped = Pool::new(&lists).unwrap();
    let log = self::log();
    let mut stream = vec![0, 1];
    stream.extend(header(INSTANCE as u32, 0, 0, 0xf000, 30, 0x3ff));
    for index in 0..lists.max_regs() as u32 {
        stream.extend(reg(index * 4, index));
    }
    log.put(REGION, &stream);
    state(&log, 0, stream.len() as u32 * 4, 0);
    assert!(clipped.process(&log, || true));
    let index = clipped.find_match(0, |_| true, 30, 0xf000).unwrap();
    assert_eq!(clipped.node(index).list(INSTANCE).len(), lists.max_regs());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_guc_capture_dependent_resets_wrap_overflow_and_reuse
);

fn smoke_guc_capture_manual_fallback_reads_source_lists() -> TestResult {
    let lists = lists();
    let mut node = Node::new(lists.max_regs()).unwrap();
    let mut reads = Vec::new();
    node.capture_manual(Family::XeHpg, Engine::Ccs1, |offset| {
        reads.push(offset);
        Some(offset as u32 ^ 0x5a5a_0000)
    });
    let base = u64::from(Engine::Ccs1.base());
    let mut expected = vec![0xa188, 0x14800];
    expected.extend(INSTANCE_REGS.iter().map(|d| base + u64::from(d.offset)));
    assert_eq!(reads, expected, "global, class, then instance; no steering");
    assert_eq!(
        (
            node.source,
            node.class,
            node.instance,
            node.guc_id,
            node.lrca
        ),
        (Source::Manual, 4, 1, 0, 0)
    );
    assert!(!node.lost && !node.partial);
    assert_eq!(
        node.list(INSTANCE)[2],
        reg32(0x34, (base + 0x34) as u32 ^ 0x5a5a_0000)
    );
    let mut text = String::new();
    print(
        &mut text,
        Facts {
            engine: Engine::Ccs1,
            logical: 1,
            wake_ref: 1,
        },
        &node,
        &lists,
    )
    .unwrap();
    assert!(text.starts_with(
        "ccs1 (physical), logical instance=1\n\tCapture_source: Manual\n\tCoverage: full-capture\n\tForcewake: domain 0x2, ref 1\n"
    ));
    assert!(text.contains("\tRCU_MODE: 0x5a5b4800\n"));

    // VECS reads the SFC_DONE class list; GT1 media domains name the box.
    let mut reads = Vec::new();
    node.capture_manual(Family::XeHpg, Engine::Vecs1, |offset| {
        reads.push(offset);
        Some(1)
    });
    assert_eq!(&reads[1..5], &[0x1cc000, 0x1cd000, 0x1ce000, 0x1cf000]);
    assert_eq!(forcewake_domain(Engine::Vecs1), 1 << 12);
    assert_eq!(forcewake_domain(Engine::Vcs3), 1 << 6);
    assert_eq!(forcewake_domain(Engine::Bcs8), 1 << 1);

    // Lost wake/authority ends the capture; nothing past it is read.
    let mut count = 0;
    node.capture_manual(Family::XeLp, Engine::Rcs0, |offset| {
        count += 1;
        (count <= 7).then_some(offset as u32)
    });
    assert!(node.lost);
    assert_eq!(count, 8);
    assert_eq!(node.list(GLOBAL).len(), 1);
    assert_eq!(
        node.list(CLASS).len(),
        4,
        "XeLP class list incl. SC_INSTDONE"
    );
    assert_eq!(node.list(INSTANCE).len(), 2);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_guc_capture_manual_fallback_reads_source_lists
);

fn smoke_guc_capture_manual_steered_and_dss_formatting() -> TestResult {
    let lists = Lists::new(Family::XeHpg, true, 0x23, 0, 4).unwrap();
    let mut node = Node::new(lists.max_regs()).unwrap();
    let mut regular_reads = Vec::new();
    let mut steered_reads = Vec::new();

    node.capture_manual_steered(
        Family::XeHpg,
        Engine::Rcs0,
        Some(lists.steered()),
        |offset| {
            regular_reads.push(offset);
            Some(0x1000_0000 | offset as u32)
        },
        |offset, group, instance| {
            steered_reads.push((offset, group, instance));
            Some(0x2000_0000 | (group << 8) | instance)
        },
    );

    assert_eq!(node.source, Source::Manual);
    assert!(!node.lost);
    assert!(!node.partial);
    assert_eq!(steered_reads.len(), lists.steered().len());

    // Verify print output contains DSS headings:
    let facts = Facts {
        engine: Engine::Rcs0,
        logical: 0,
        wake_ref: 1,
    };
    let mut out = String::new();
    print(&mut out, facts, &node, &lists).unwrap();

    assert!(out.contains("\tDSS_0:\n"));
    assert!(out.contains("\t\tSAMPLER_INSTDONE: 0x20000000\n"));
    assert!(out.contains("\t\tROW_INSTDONE: 0x20000000\n"));
    assert!(out.contains("\tDSS_1:\n"));
    assert!(out.contains("\t\tSAMPLER_INSTDONE: 0x20000001\n"));
    assert!(out.contains("\tDSS_5:\n"));
    assert!(out.contains("\t\tSAMPLER_INSTDONE: 0x20000101\n"));

    // Non-render/compute engine ignores steered registers:
    let mut non_rc_node = Node::new(lists.max_regs()).unwrap();
    let mut non_rc_steered = Vec::new();
    non_rc_node.capture_manual_steered(
        Family::XeHpg,
        Engine::Vecs1,
        Some(lists.steered()),
        |offset| Some(offset as u32),
        |offset, group, instance| {
            non_rc_steered.push((offset, group, instance));
            Some(1)
        },
    );
    assert!(non_rc_steered.is_empty(), "Vecs1 ignores steered extension");

    // Steered read failure triggers node.lost:
    let mut fail_node = Node::new(lists.max_regs()).unwrap();
    fail_node.capture_manual_steered(
        Family::XeHpg,
        Engine::Rcs0,
        Some(lists.steered()),
        |offset| Some(offset as u32),
        |_offset, _group, _instance| None,
    );
    assert!(fail_node.lost);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_guc_capture_manual_steered_and_dss_formatting
);
