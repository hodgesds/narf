use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::AtomicU32,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
const GC: u64 = 0x10000;
const HYP: u64 = 0x40000;
const NBIO: u64 = 0x60000;
const GPU: u64 = 0x8_0000_4000;
const INDEX: u64 = 0x42400;

struct Fake {
    index: u32,
    regs: BTreeMap<(u32, u64), u32>,
    memory: Vec<u32>,
    writes: Vec<(u32, u64, u32)>,
    frames: Vec<(usize, u8)>,
    tails: [u64; 2],
    dirty: bool,
    active: [bool; 2],
    complete: bool,
    reject: bool,
    reject_opcode: Option<u8>,
    hold_opcode: Option<u8>,
    hung: [u32; 8],
    drain_only: bool,
    rptr_stuck: bool,
    bad_version: bool,
    refuse: Option<u64>,
    progress: Arc<AtomicU32>,
    revoke: Option<Cap<BusDeviceCap, Write>>,
}
impl Fake {
    fn slot(&self, address: u64) -> usize {
        match address {
            0x17ea4..=0x17f2c | 0x4a000 | 0x4a274 => self.index as usize,
            _ => 0,
        }
    }
    fn put(&mut self, address: u64, value: u64) {
        assert!((GPU..GPU + 40960 - 7).contains(&address));
        assert_eq!(address % 8, 0);
        let n = ((address - GPU) / 4) as usize;
        self.memory[n] = value as u32;
        self.memory[n + 1] = (value >> 32) as u32;
    }
    fn get(&self, at: usize) -> u64 {
        u64::from(self.memory[at]) | (u64::from(self.memory[at + 1]) << 32)
    }
    fn execute(&mut self, pipe: usize, tail: u64) {
        assert!(self.active[pipe], "doorbell before queue activation");
        assert!(!self.dirty, "doorbell before HDP flush");
        let off = pipe * 5120;
        assert_eq!(self.get(off + 3074), tail, "writeback before doorbell");
        assert_eq!(tail - self.tails[pipe], 128);
        for frame in 0..2 {
            let n = off + ((self.tails[pipe] as usize + frame * 64) % 1024);
            let words: [u32; 64] = self.memory[n..n + 64].try_into().unwrap();
            assert_eq!(words[0] & 0xfffff00f, 0x40001);
            let op = ((words[0] >> 4) & 0xff) as u8;
            let ptr = |at| u64::from(words[at]) | (u64::from(words[at + 1]) << 32);
            let status = match op {
                0 => {
                    assert_eq!(
                        &words[1..17],
                        &[0; 16],
                        "must not delegate application resources"
                    );
                    assert_eq!(words[54], 0x100447);
                    assert_eq!(words[55], 50);
                    assert_eq!(ptr(22), GPU + pipe as u64 * 20480 + 12320);
                    assert_eq!(ptr(24), GPU + pipe as u64 * 20480 + 12328);
                    50
                }
                19 => {
                    assert_eq!(words[13], 10);
                    assert_eq!(ptr(16), GPU + pipe as u64 * 20480 + 16384);
                    2
                }
                2 => {
                    assert_eq!(pipe, usize::from(words[28] == 3));
                    assert_eq!(
                        words[18],
                        match words[28] {
                            0 => 0x116,
                            1 => 6,
                            3 => 22,
                            _ => panic!("unknown kernel queue"),
                        }
                    );
                    assert_eq!(words[19], 0);
                    assert_eq!(ptr(20), GPU + 4096);
                    assert_eq!(ptr(22), GPU + 12296);
                    assert_eq!(words[37], 1 << 13);
                    assert_eq!(&words[50..52], &[0, 0]);
                    self.active[0] = true;
                    38
                }
                // RESET: a legacy graphics HQD by its fields, any other
                // kernel queue by doorbell.
                8 => {
                    if words[1] == 4 {
                        assert_eq!(words[8], 1);
                        assert_eq!(ptr(6), GPU + HUNG);
                        let at = (HUNG / 4) as usize;
                        assert_eq!(&self.memory[at..at + 8], &[u32::MAX; 8]);
                        self.memory[at..at + 8].copy_from_slice(&self.hung);
                    } else if words[8] == 0 {
                        assert_eq!(&words[1..2], &[8]);
                        assert_eq!(&words[9..11], &[0, 0]);
                        assert!(words[11] < 16);
                        assert_eq!(ptr(12), GPU + 4096);
                        assert_eq!(words[14], 0x116);
                        assert_eq!(ptr(16), GPU + 12296);
                    } else {
                        assert_eq!((words[1], words[4], words[8]), (1, 6, 1));
                    }
                    28
                }
                // REMOVE_QUEUE of the compute queue after its MMIO reset:
                // unmap_legacy_queue and remove_queue_after_reset (this
                // firmware is 0x8b).
                3 => {
                    assert_eq!((words[1], words[4], words[15]), (6, 0x18, 1));
                    assert_eq!(&words[10..12], &[0, 0]);
                    6
                }
                // SUSPEND / RESUME of all gangs.
                6 => {
                    assert_eq!(&words[1..8], &[1, 0, 0, 0, 0, 0, 0]);
                    8
                }
                7 => {
                    assert_eq!(&words[1..4], &[1, 0, 0]);
                    4
                }
                11 => 2,
                _ => panic!("unexpected MES12 opcode"),
            };
            if frame == 1 {
                assert_eq!(op, 11);
            }
            if frame == 0 {
                self.frames.push((pipe, op));
                assert_eq!(ptr(status + 2), 1);
                if !self.drain_only {
                    self.put(
                        ptr(status),
                        if self.reject || self.reject_opcode == Some(op) {
                            0x800b020300000000
                        } else {
                            1
                        },
                    );
                }
            } else {
                assert!(ptr(status + 2) > self.get(off + (DRAIN / 4) as usize));
                self.put(ptr(status), ptr(status + 2));
            }
        }
        if !self.rptr_stuck {
            self.put(GPU + pipe as u64 * 20480 + 12288, tail);
        }
        self.tails[pipe] = tail;
    }
}
impl Io for Fake {
    fn read(&mut self, address: u64) -> u32 {
        match address {
            INDEX => self.index,
            0x15850 => 0x800,
            0x15854 => 0xbff,
            0x604b4 => 0x7f000,
            0x4a124 => {
                assert!(self.index == 12 || self.index == 13);
                assert!(self.active[(self.index - 12) as usize]);
                if self.bad_version {
                    0x2040
                } else {
                    0x308b
                }
            }
            _ => *self
                .regs
                .get(&(self.slot(address) as u32, address))
                .unwrap_or(&0),
        }
    }
    fn write(&mut self, address: u64, value: u32) {
        // HDP flushes are not logged: the firmware-timeout case polls for the
        // full 2.1 s deadline with a yielding delay, and a fast host would
        // otherwise grow this log until the kernel heap is exhausted.
        if address == 0x7f000 {
            self.dirty = false;
            return;
        }
        self.writes.push((self.index, address, value));
        if self.refuse == Some(address) {
            return;
        }
        if address == INDEX {
            self.index = value;
            return;
        }
        assert!(
            matches!(address, 0x60300 | 0x6072c | 0x60738 | 0x177e8..=0x177f4 | 0x42628 |
            0x4a000 | 0x4a274 | 0x4a01c | 0x17ea4..=0x17f2c |
            0x42200 | 0x4a0f0..=0x4a100 | 0x17a7c),
            "unexpected register write {address:x}"
        );
        self.regs
            .insert((self.slot(address) as u32, address), value);
        if address == 0x17eac && value == 1 {
            assert_eq!(self.index, 13);
            assert_eq!(self.regs[&(13, 0x17f2c)], 0);
            assert_eq!(self.regs[&(13, 0x17ea4)], (GPU + 20480 + 4096) as u32);
            assert_eq!(self.regs[&(13, 0x17ec4)], ((GPU + 20480) >> 8) as u32);
            assert_eq!(self.regs[&(13, 0x17ee0)], 0x40000060);
            self.active[1] = true;
        }
    }
    fn memory_write(&mut self, _: MmioRegion, offset: u64, value: u32) {
        self.dirty = true;
        self.memory[(offset / 4) as usize] = value;
    }
    fn memory_read64(&mut self, _: MmioRegion, offset: u64) -> u64 {
        assert!(!self.dirty);
        self.get((offset / 4) as usize)
    }
    fn doorbell(&mut self, _: MmioRegion, dword: u32, value: u64) {
        assert!(dword == 22 || dword == 24);
        self.progress.store(2, Ordering::SeqCst);
        let pipe = ((dword - 22) / 2) as usize;
        let at = pipe * 5120 + self.tails[pipe] as usize % 1024;
        let opcode = ((self.memory[at] >> 4) & 255) as u8;
        if self.complete && self.hold_opcode != Some(opcode) {
            self.execute(pipe, value);
        }
        if let Some(cap) = self.revoke {
            cap.revoke();
        }
    }
    async fn delay(&mut self, _: u64) {
        assert_eq!(self.index, 0x32, "GRBM selector held across await");
        if self.progress.load(Ordering::SeqCst) == 0 {
            self.progress.store(1, Ordering::SeqCst);
        }
        narf_scheduler::yield_now().await;
    }
}
fn fixture() -> (Pool, Engine<Fake>) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90004000),
        virt: 0,
        len: 40960,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model intercepts all memory accesses; this mapping is bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(map, GPU) }.unwrap();
    let io = Fake {
        index: 0x32,
        regs: BTreeMap::new(),
        memory: vec![u32::MAX; 10240],
        writes: Vec::new(),
        frames: Vec::new(),
        tails: [0; 2],
        dirty: false,
        active: [false; 2],
        complete: true,
        reject: false,
        reject_opcode: None,
        hold_opcode: None,
        hung: [u32::MAX; 8],
        drain_only: false,
        rptr_stuck: false,
        bad_version: false,
        refuse: None,
        progress: Arc::new(AtomicU32::new(0)),
        revoke: None,
    };
    let engine = Engine {
        io,
        authority: Cap::bootstrap(),
        layout: Layout {
            gc: GC,
            hyp: HYP,
            nbio: NBIO,
            nbif_routing: false,
            bases: api::Bases {
                gc: [0x4000, 0x10000, 0, 0, 0],
                mmhub: [0x8000, 0, 0, 0, 0],
                osssys: [0xc000, 0, 0, 0, 0],
            },
        },
        doorbells: map,
        memory: pool.reserve(40960).unwrap(),
        starts: [0x100_00004000, 0x100_00004000],
        state: State::Prepared,
        versions: [0; 2],
        tails: [0; 2],
        completed: [0; 2],
    };
    (pool, engine)
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn mes12_hw_starts_both_pipes_and_wraps_native_commands() -> TestResult {
    let (pool, mut e) = fixture();
    assert_eq!(
        run(e.start()),
        Ok(Report {
            versions: [0x308b; 2],
            completed: [3, 3]
        })
    );
    assert_eq!(e.state, State::Ready);
    assert_eq!(
        e.io.frames,
        [(1, 0), (1, 19), (1, 2), (0, 0), (0, 19), (0, 11)]
    );
    assert_eq!(e.io.index, 0x32);
    for pipe in [12, 13] {
        assert_eq!(e.io.regs[&(pipe, 0x4a000)], 0x1000);
        assert_eq!(e.io.regs[&(pipe, 0x4a274)], 0x40);
    }
    assert_eq!(e.io.regs[&(0, 0x42628)], 0xe8);
    assert_eq!(e.io.regs[&(0, 0x60300)], 1);
    for _ in 0..18 {
        assert_eq!(run(e.submit(0, api::query_status())), Ok(()));
    }
    assert_eq!(e.completed, [21, 3]);
    assert_eq!(e.tails, [2688, 384]);
    assert_eq!(run(e.start()), Err(Error::Busy));
    drop(e);
    assert_eq!(pool.available(), 0, "live queues released");
    let (_, mut e) = fixture();
    e.layout.nbif_routing = true;
    assert!(run(e.start()).is_ok());
    assert_eq!(e.io.regs[&(0, 0x6072c)], 0x30000007);
    assert_eq!(e.io.regs[&(0, 0x60738)], 0x3000000d);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_hw_starts_both_pipes_and_wraps_native_commands
);

fn mes12_hw_refuses_inherited_execution_before_publication() -> TestResult {
    for pipe in [None, Some(12), Some(13)] {
        let (pool, mut e) = fixture();
        match pipe {
            None => {
                e.io.regs.insert((0, 0x4a01c), 0x04000000);
            }
            Some(p) => {
                e.io.regs.insert((p, 0x17eac), 1);
            }
        }
        assert_eq!(run(e.start()), Err(Error::Busy));
        assert_eq!(e.io.index, 0x32);
        assert!(e.io.writes.iter().all(|w| w.1 == INDEX));
        assert!(e.memory.reusable_for_test());
        drop(e);
        assert_eq!(pool.available(), 40960);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_hw_refuses_inherited_execution_before_publication
);

fn mes12_hw_retains_failed_queues_and_requires_both_fences_and_rptr() -> TestResult {
    for case in 0..6 {
        let (pool, mut e) = fixture();
        let expected = match case {
            0 => {
                e.io.reject = true;
                Error::FirmwareRejected(api::Rejection {
                    code: 3,
                    opcode: 2,
                    misc: 11,
                    category: 0,
                })
            }
            1 => {
                e.io.drain_only = true;
                Error::Protocol
            }
            2 => {
                e.io.revoke = Some(e.authority);
                Error::Revoked
            }
            3 => {
                e.io.rptr_stuck = true;
                Error::Timeout
            }
            4 => {
                e.io.bad_version = true;
                Error::Unsupported
            }
            _ => {
                e.io.refuse = Some(0x4a274);
                Error::Readback
            }
        };
        assert_eq!(run(e.start()), Err(expected));
        assert_eq!(e.state, State::Failed(expected));
        assert_eq!(e.io.index, 0x32);
        let writes = e.io.writes.len();
        assert_eq!(run(e.start()), Err(Error::Busy));
        assert_eq!(e.io.writes.len(), writes);
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_hw_retains_failed_queues_and_requires_both_fences_and_rptr
);

fn mes12_hw_cancellation_cannot_replay_or_reclaim_firmware_memory() -> TestResult {
    for phase in [1, 2] {
        let (pool, mut e) = fixture();
        e.io.complete = false;
        let progress = e.io.progress.clone();
        {
            let mut f = core::pin::pin!(e.start());
            let mut cx = Context::from_waker(Waker::noop());
            while progress.load(Ordering::SeqCst) < phase {
                assert!(f.as_mut().poll(&mut cx).is_pending());
            }
        }
        assert_ne!(e.state, State::Prepared);
        assert_ne!(e.state, State::Ready);
        assert_eq!(run(e.start()), Err(Error::Busy));
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_hw_cancellation_cannot_replay_or_reclaim_firmware_memory
);

fn mes12_hw_validates_discovery_and_refuses_separate_kiq_firmware() -> TestResult {
    let mut regs = vec![0; 0x80000 / 4];
    let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(&mut regs);
    gpu.ip_blocks[0].base_addrs[1] = 0x10000;
    let mut ih = gpu.ip_blocks[0];
    ih.hw_id = ip::HW_ID_OSSSYS;
    ih.major = 7;
    ih.minor = 0;
    ih.revision = 0;
    ih.num_bases = 1;
    ih.base_addrs = [0x12000, 0, 0, 0, 0];
    gpu.ip_blocks.push(ih);
    assert!(Layout::resolve(&gpu).is_ok());
    (
        gpu.ip_blocks[2].major,
        gpu.ip_blocks[2].minor,
        gpu.ip_blocks[2].revision,
    ) = (6, 3, 1);
    assert!(Layout::resolve(&gpu).unwrap().nbif_routing);
    (
        gpu.ip_blocks[2].major,
        gpu.ip_blocks[2].minor,
        gpu.ip_blocks[2].revision,
    ) = (7, 7, 0);
    for case in 0..7 {
        let mut g = gpu.ip_blocks.clone();
        match case {
            0 => g[0].major = 11,
            1 => g[0].num_bases = 1,
            2 => g[0].base_addrs[1] = 0x20000 - 0x289d,
            3 => g[1].minor = 0,
            4 => g[2].revision = 2,
            5 => g[5].num_bases = 6,
            _ => g.push(ih),
        }
        core::mem::swap(&mut gpu.ip_blocks, &mut g);
        assert!(Layout::resolve(&gpu).is_err());
        core::mem::swap(&mut gpu.ip_blocks, &mut g);
    }
    let (pool, e) = fixture();
    let authority = e.authority;
    let doorbells = e.doorbells;
    drop(e);
    // SAFETY: preparation must reject the wrong firmware ABI before mapping
    // access or allocation; neither bookkeeping-only mapping is dereferenced.
    let result = unsafe { Mes::new(&gpu, authority, &pool, &fw::fixture(), doorbells) };
    assert!(matches!(result, Err(Error::Unsupported)));
    assert_eq!(pool.available(), 40960);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_hw_validates_discovery_and_refuses_separate_kiq_firmware
);

fn mes12_hw_maps_bootstrap_kernel_queues_on_scheduler_pipe() -> TestResult {
    let (_, mut e) = fixture();
    let mut q = api::KernelQueue {
        kind: api::QueueType::Graphics,
        pipe: 0,
        queue: 0,
        doorbell: 0x116,
        mqd: GPU + 4096,
        write_pointer: GPU + 12296,
    };
    assert_eq!(run(e.map_bootstrap_queue(q)), Err(Error::Busy));
    run(e.start()).unwrap();
    assert_eq!(run(e.map_bootstrap_queue(q)), Ok(()));
    q.kind = api::QueueType::Compute;
    q.doorbell = 6;
    assert_eq!(run(e.map_bootstrap_queue(q)), Ok(()));
    assert_eq!(e.completed, [5, 3]);
    assert_eq!(&e.io.frames[6..], &[(0, 2), (0, 2)]);
    q.doorbell = 0x116;
    assert_eq!(run(e.map_bootstrap_queue(q)), Err(Error::Invalid));
    assert_eq!(e.state, State::Ready);
    q.doorbell = 6;
    e.io.reject = true;
    assert!(matches!(
        run(e.map_bootstrap_queue(q)),
        Err(Error::FirmwareRejected(_))
    ));
    assert!(matches!(e.state, State::Failed(_)));
    assert_eq!(run(e.map_bootstrap_queue(q)), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_hw_maps_bootstrap_kernel_queues_on_scheduler_pipe
);

/// A hung bootstrap queue is reset on the scheduler pipe (opcode 8); a
/// firmware rejection leaves MES ready, and only the two bootstrap HQDs
/// may be named.
fn mes12_hw_resets_bootstrap_kernel_queues() -> TestResult {
    let (_, mut e) = fixture();
    let mut q = api::KernelQueue {
        kind: api::QueueType::Graphics,
        pipe: 0,
        queue: 0,
        doorbell: 0x116,
        mqd: GPU + 4096,
        write_pointer: GPU + 12296,
    };
    assert_eq!(run(e.reset_kernel_queue(q, 3)), Err(Error::Busy));
    run(e.start()).unwrap();
    assert_eq!(run(e.reset_kernel_queue(q, 3)), Ok(()));
    assert_eq!(e.io.frames.last(), Some(&(0, 8)));
    q.doorbell = 6;
    assert_eq!(run(e.reset_kernel_queue(q, 3)), Err(Error::Invalid));
    q.kind = api::QueueType::Compute;
    assert_eq!(run(e.reset_kernel_queue(q, 16)), Err(Error::Invalid));
    assert_eq!(e.state, State::Ready);
    e.io.reject = true;
    assert!(matches!(
        run(e.reset_kernel_queue(q, 3)),
        Err(Error::FirmwareRejected(_))
    ));
    assert_eq!(e.state, State::Ready);
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/mes12", mes12_hw_resets_bootstrap_kernel_queues);

/// The compute reset's MES half: every gang suspended, the reset queue
/// removed with remove_queue_after_reset and mapped again, the gangs
/// resumed; each needs a ready MES, and a rejection keeps it ready.
fn mes12_hw_remaps_a_reset_compute_queue_around_suspended_gangs() -> TestResult {
    let (_, mut e) = fixture();
    let q = api::KernelQueue {
        kind: api::QueueType::Compute,
        pipe: 0,
        queue: 0,
        doorbell: 6,
        mqd: GPU + 4096,
        write_pointer: GPU + 12296,
    };
    assert_eq!(run(e.all_gangs(true)), Err(Error::Busy));
    assert_eq!(run(e.unmap_reset_queue(q)), Err(Error::Busy));
    run(e.start()).unwrap();
    let before = e.io.frames.len();
    assert_eq!(run(e.all_gangs(true)), Ok(()));
    assert_eq!(run(e.unmap_reset_queue(q)), Ok(()));
    assert_eq!(run(e.map_bootstrap_queue(q)), Ok(()));
    assert_eq!(run(e.all_gangs(false)), Ok(()));
    assert_eq!(e.io.frames[before..], [(0, 6), (0, 3), (0, 2), (0, 7)]);
    assert_eq!(
        run(e.unmap_reset_queue(api::KernelQueue { doorbell: 8, ..q })),
        Err(Error::Invalid)
    );
    e.io.reject = true;
    assert!(matches!(
        run(e.all_gangs(false)),
        Err(Error::FirmwareRejected(_))
    ));
    assert_eq!(e.state, State::Ready);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_hw_remaps_a_reset_compute_queue_around_suspended_gangs
);

fn compute_queue() -> api::KernelQueue {
    api::KernelQueue {
        kind: api::QueueType::Compute,
        pipe: 0,
        queue: 0,
        doorbell: 6,
        mqd: GPU + 4096,
        write_pointer: GPU + 12296,
    }
}

fn mes12_hw_detects_owned_hangs_after_drained_suspend_rejection() -> TestResult {
    let (_, mut e) = fixture();
    run(e.start()).unwrap();
    e.io.reject_opcode = Some(6);
    e.io.hung[2] = 6; // Pair a noncontiguous doorbell with its HQD, not slot 0.
    e.io.hung[6] = 1;
    let before = e.io.frames.len();
    let sequence = e.completed[0];
    assert_eq!(run(e.prepare_compute_reset(compute_queue())), Ok(()));
    assert_eq!(e.io.frames[before..], [(0, 6), (0, 8)]);
    assert_eq!(e.completed[0], sequence + 2);
    assert_eq!(run(e.all_gangs(false)), Ok(()));
    // A second detection must initialize the output and use fresh fences.
    e.io.hung = [u32::MAX; 8];
    assert_eq!(run(e.prepare_compute_reset(compute_queue())), Ok(()));
    assert_eq!(e.state, State::Ready);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_hw_detects_owned_hangs_after_drained_suspend_rejection
);

fn mes12_hw_detection_refuses_foreign_malformed_and_undrained_hangs() -> TestResult {
    for malformed in [false, true] {
        let (_, mut e) = fixture();
        run(e.start()).unwrap();
        e.io.reject_opcode = Some(6);
        e.io.hung[0] = 8;
        e.io.hung[4] = if malformed { 1 << 15 } else { 1 | (1 << 7) };
        assert_eq!(
            run(e.prepare_compute_reset(compute_queue())),
            Err(if malformed {
                Error::Protocol
            } else {
                Error::Unsupported
            })
        );
        assert_eq!(
            e.state,
            if malformed {
                State::Failed(Error::Protocol)
            } else {
                State::Ready
            }
        );
    }
    for opcode in [6, 8] {
        let (pool, mut e) = fixture();
        run(e.start()).unwrap();
        e.io.reject_opcode = Some(6);
        e.io.hold_opcode = Some(opcode);
        {
            let mut future = core::pin::pin!(e.prepare_compute_reset(compute_queue()));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(e.state, State::Submitting { pipe: 0, opcode });
        let before = e.io.frames.len();
        assert_eq!(
            run(e.prepare_compute_reset(compute_queue())),
            Err(Error::Busy)
        );
        assert_eq!(run(e.all_gangs(false)), Err(Error::Busy));
        assert_eq!(e.io.frames.len(), before);
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_hw_detection_refuses_foreign_malformed_and_undrained_hangs
);
