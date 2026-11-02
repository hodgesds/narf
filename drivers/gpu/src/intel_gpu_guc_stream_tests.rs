use super::*;
use core::{
    future::Future,
    sync::atomic::{AtomicU32, AtomicUsize},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Memory {
    words: Vec<AtomicU32>,
    reads: AtomicUsize,
    mutate: AtomicBool,
    coherent: bool,
}
impl Memory {
    fn new() -> Self {
        let m = Self {
            words: (0..super::super::LOG_BYTES / 4)
                .map(|i| {
                    AtomicU32::new(u32::from_le_bytes(core::array::from_fn(|j| {
                        (i * 4 + j) as u8
                    })))
                })
                .collect(),
            reads: AtomicUsize::new(0),
            mutate: AtomicBool::new(false),
            coherent: true,
        };
        for (i, values) in [
            [0xcabba9e6, 0xdeadfeed, 0, 8, 65536, 8, 65536, 1, 2],
            [0xcabba9e6, 0x8086dead, 0, 4, 16384, 4, 16384, 1, 2],
        ]
        .into_iter()
        .enumerate()
        {
            for (w, v) in values.into_iter().enumerate() {
                m.put(i * 36 + w * 4, v);
            }
        }
        m
    }
    fn put(&self, at: usize, value: u32) {
        self.words[at / 4].store(value, Ordering::Release);
    }
}
impl GpuBacking for Memory {
    fn coherent_for_device(&self) -> bool {
        self.coherent
    }
    fn ggtt_offset(&self) -> u32 {
        panic!("stream must not expose addresses")
    }
    fn size_pages(&self) -> u32 {
        0x115
    }
    fn read32(&self, at: u64) -> u32 {
        assert!(at & 3 == 0 && at < super::super::LOG_BYTES as u64);
        self.reads.fetch_add(1, Ordering::Relaxed);
        let value = self.words[at as usize / 4].load(Ordering::Acquire);
        if at == 4096 && self.mutate.swap(false, Ordering::AcqRel) {
            self.put(20, 12);
        }
        value
    }
    fn write32(&self, _: u64, _: u32) {
        panic!("copy must not acknowledge firmware")
    }
}
fn identity() -> Identity {
    Identity {
        epoch: 42,
        incarnation: 99,
        now_ns: 1234,
        platform: crate::intel_gpu_gt::GtPlatform::Battlemage,
        firmware_version: (70, 54, 1),
        firmware_digest: [0xa5; 32],
    }
}
fn dword(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn qword(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn ready<T>(f: impl Future<Output = T>) -> T {
    let mut f = Box::pin(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("expected ready"),
    }
}

fn smoke_guc_stream_fixed_wire_linear_wrapped_and_source_immutability() -> TestResult {
    let m = Memory::new();
    let states = read_states(&m);
    let mut b = Buffer::new().unwrap();
    copy_frame(&m, &mut b, states, identity(), 7, 3, None, &mut || true).unwrap();
    assert_eq!(&b.bytes[..8], b"NARFGSTR");
    assert_eq!(
        (dword(&b.bytes, 8), dword(&b.bytes, 12), dword(&b.bytes, 16)),
        (2, 256, 268)
    );
    assert_eq!(
        (
            dword(&b.bytes, 20),
            dword(&b.bytes, 24),
            dword(&b.bytes, 28)
        ),
        (DATA | FW_MODULO_BOUND, 3, 7)
    );
    assert_eq!(
        (
            qword(&b.bytes, 32),
            qword(&b.bytes, 40),
            qword(&b.bytes, 48),
            qword(&b.bytes, 56)
        ),
        (3, 42, 99, 1234)
    );
    assert_eq!(dword(&b.bytes, 64), 0x13646);
    assert_eq!(
        (
            dword(&b.bytes, 72),
            dword(&b.bytes, 76),
            dword(&b.bytes, 80),
            dword(&b.bytes, 84)
        ),
        (256, 8, 264, 4)
    );
    assert_eq!(&b.bytes[160..192], &[0xa5; 32]);
    assert_eq!(&b.bytes[256..268], &[0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3]);
    m.put(4096, 0xffff_ffff);
    assert_eq!(&b.bytes[256..260], &[0, 1, 2, 3]);
    let m = Memory::new();
    m.put(8, 65532);
    m.put(12, 4);
    m.put(20, 4);
    m.put(36 + 8, 4);
    copy_frame(
        &m,
        &mut b,
        read_states(&m),
        identity(),
        7,
        4,
        Some([65532, 4]),
        &mut || true,
    )
    .unwrap();
    assert_eq!(b.len, 264);
    assert_eq!(&b.bytes[256..264], &[252, 253, 254, 255, 0, 1, 2, 3]);
    assert!(b.bytes[264..].iter().all(|v| *v == 0));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_fixed_wire_linear_wrapped_and_source_immutability
);

fn smoke_guc_stream_invalid_headers_overflow_coherence_and_loss_refuse() -> TestResult {
    for case in 0..10 {
        let mut m = Memory::new();
        let mut b = Buffer::new().unwrap();
        match case {
            0 => m.put(0, 0),
            1 => m.put(16, 65540),
            2 => m.put(8, 65537),
            3 => m.put(28, 0x21),
            4 => m.put(28, 1 << 31),
            5 => {
                m.put(8, 65532);
                m.put(20, 4);
                m.put(24, 65528);
            }
            6 => m.coherent = false,
            7 => {}
            8 => m.mutate.store(true, Ordering::Release),
            _ => {}
        }
        let states = read_states(&m);
        m.reads.store(0, Ordering::Relaxed);
        let result = copy_frame(
            &m,
            &mut b,
            states,
            identity(),
            0,
            0,
            if case == 9 { Some([4, 0]) } else { None },
            &mut || case != 7,
        );
        assert_eq!(
            result,
            Err(if case == 6 {
                FsError::Unsupported
            } else if case == 7 {
                FsError::NoDevice
            } else if case == 8 {
                FsError::WouldBlock
            } else {
                FsError::InvalidData
            }),
            "case={case}"
        );
        if case != 8 {
            assert_eq!(m.reads.load(Ordering::Relaxed), 0, "case={case}");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_invalid_headers_overflow_coherence_and_loss_refuse
);

fn smoke_guc_stream_two_slot_fifo_quota_readiness_and_retained_error() -> TestResult {
    let s = StreamSession::reserve(61).unwrap();
    assert!(matches!(StreamSession::reserve(61), Err(FsError::Busy)));
    let m = Memory::new();
    for sequence in 0..2 {
        let mut b = s.fanout_spare.lock().take().unwrap();
        copy_frame(
            &m,
            &mut b,
            read_states(&m),
            identity(),
            61,
            sequence,
            None,
            &mut || true,
        )
        .unwrap();
        let spare = s.publish(b);
        *s.fanout_spare.lock() = Some(spare);
    }
    assert!(s.take_free().is_none());
    assert_eq!(s.ready.mask(), POLL_IN);
    s.fail(FsError::InvalidData);
    assert_eq!(s.ready.mask(), POLL_IN | POLL_ERR | POLL_HUP);
    for sequence in 0..2 {
        let mut frame = alloc::vec![0;268];
        let mut at = 0;
        while at < frame.len() {
            let n = s.read(&mut frame[at..at + 1]).unwrap();
            assert_eq!(n, 1);
            at += n;
        }
        assert_eq!(qword(&frame, 32), sequence);
    }
    assert_eq!(s.read(&mut [0; 1]), Err(FsError::InvalidData));
    assert_eq!(s.ready.mask(), POLL_ERR | POLL_HUP);
    drop(s);
    assert!(StreamSession::reserve(61).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_two_slot_fifo_quota_readiness_and_retained_error
);

static ALLOWED: AtomicBool = AtomicBool::new(true);
fn yes() -> bool {
    true
}
fn allowed() -> bool {
    ALLOWED.load(Ordering::Acquire)
}
fn smoke_guc_stream_descriptor_cached_authority_dup_and_worker_request() -> TestResult {
    ALLOWED.store(true, Ordering::Release);
    let publication = Arc::new(Publication::new());
    publish(&publication, 42);
    register_owner(62, identity().platform, &publication);
    let node = Node {
        index: 62,
        gate: Gate {
            enabled: yes,
            capable: allowed,
        },
    };
    assert!(matches!(
        node.open_instance_checked(true),
        Err(FsError::ReadOnly)
    ));
    let file = node.open_instance_checked(false).unwrap().unwrap();
    let duplicate = file.clone();
    assert_eq!(ready(file.read(0, &mut [])), Ok(0));
    assert_eq!(ready(file.read(0, &mut [0; 8])), Err(FsError::WouldBlock));
    assert_eq!(file.poll_readiness(), 0);
    // Reads/poll did not claim attachment; the ordinary worker claims once.
    let request = take_requested(62).expect("queued at open, no backend read");
    assert!(take_requested(62).is_none());
    ALLOWED.store(false, Ordering::Release);
    assert_eq!(
        ready(file.read(123, &mut [0; 8])),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(
        ready(duplicate.read(0, &mut [])),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(file.poll_readiness(), POLL_ERR | POLL_HUP);
    assert!(file.readiness().is_none());
    drop(file);
    drop(duplicate);
    assert!(
        ACTIVE[62].load(Ordering::Acquire),
        "worker request retains source quota"
    );
    drop(request);
    assert!(!ACTIVE[62].load(Ordering::Acquire));
    ALLOWED.store(true, Ordering::Release);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_descriptor_cached_authority_dup_and_worker_request
);

fn smoke_guc_stream_opt_in_and_bounded_disjoint_ct_demultiplexing() -> TestResult {
    use narf_boot::args::KernelCmdline;
    for text in [
        "",
        "narf.intel.guc_stream",
        "narf.intel.guc_stream=0",
        "narf.intel.guc_stream=1 narf.intel.guc_stream=1",
        "narf.intel.guc_stream=1 narf.intel.guc_stream",
    ] {
        assert!(!opted_in(KernelCmdline::new(text)));
    }
    assert!(opted_in(KernelCmdline::new(
        "quiet narf.intel.guc_stream=1"
    )));
    let mut side = Sideband::new();
    for _ in 0..128 {
        assert_eq!(
            side.route(GuCMessage {
                fence: 0,
                kind: 1,
                auxiliary: 0x8003,
                payload: Vec::new()
            }),
            Ok(None)
        );
    }
    assert!(side.flush);
    let ordinary = GuCMessage {
        fence: 1,
        kind: 1,
        auxiliary: 0x1002,
        payload: alloc::vec![1, 0],
    };
    assert_eq!(side.route(ordinary).unwrap().unwrap().fence, 1);
    for fence in FIRST_FENCE..FIRST_FENCE + 4 {
        assert_eq!(
            side.route(GuCMessage {
                fence,
                kind: 7,
                auxiliary: 0,
                payload: Vec::new()
            }),
            Ok(None)
        );
    }
    assert!(side
        .route(GuCMessage {
            fence: FIRST_FENCE + 4,
            kind: 7,
            auxiliary: 0,
            payload: Vec::new()
        })
        .is_err());
    for fence in FIRST_FENCE..FIRST_FENCE + 4 {
        assert_eq!(side.reply().unwrap().fence, fence);
    }
    assert!(side.reply().is_none());
    assert!(side
        .route(GuCMessage {
            fence: 0,
            kind: 1,
            auxiliary: 0x8003,
            payload: alloc::vec![1]
        })
        .is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_opt_in_and_bounded_disjoint_ct_demultiplexing
);

fn cached_frame(session: &StreamSession, mut prefix: Vec<u8>) -> Vec<u8> {
    while prefix.len() < 24 {
        let mut out = [0; 24];
        let n = session.read(&mut out[..24 - prefix.len()]).unwrap();
        assert_ne!(n, 0);
        prefix.extend_from_slice(&out[..n]);
    }
    let len = dword(&prefix, 16) as usize;
    while prefix.len() < len {
        let mut out = [0; 4096];
        let n = session
            .read(&mut out[..4096.min(len - prefix.len())])
            .unwrap();
        assert_ne!(n, 0);
        prefix.extend_from_slice(&out[..n]);
    }
    prefix
}
fn relay_frame(root: &Arc<StreamSession>, memory: &Memory, sequence: u64) {
    let mut buffer = root.take_staging().unwrap();
    copy_frame(
        memory,
        &mut buffer,
        read_states(memory),
        identity(),
        root.index(),
        sequence,
        None,
        &mut || true,
    )
    .unwrap();
    root.relay_publish(buffer);
}
fn smoke_guc_stream_v2_reader_overwrite_partial_record_and_retained_quota() -> TestResult {
    let root = StreamSession::reserve(60).unwrap();
    let fast = root.subscribe().unwrap();
    let unused0 = root.subscribe().unwrap();
    let unused1 = root.subscribe().unwrap();
    assert!(matches!(root.subscribe(), Err(FsError::Busy)));
    // Closing/revoking a retained reader does not release its bounded memory
    // quota or revoke another reader's ability to consume copies.
    unused0.fail_reader(FsError::OperationNotPermitted);
    assert!(matches!(root.subscribe(), Err(FsError::Busy)));
    drop(unused0);
    let late = root.subscribe().unwrap();
    let m = Memory::new();
    relay_frame(&root, &m, 0);
    let mut prefix = [0; 8];
    assert_eq!(root.read(&mut prefix), Ok(8));
    let fast0 = cached_frame(&fast, Vec::new());
    relay_frame(&root, &m, 1);
    let fast1 = cached_frame(&fast, Vec::new());
    relay_frame(&root, &m, 2);
    let fast2 = cached_frame(&fast, Vec::new());
    let slow0 = cached_frame(&root, prefix.to_vec());
    let slow2 = cached_frame(&root, Vec::new());
    assert_eq!((qword(&slow0, 32), qword(&slow2, 32)), (0, 2));
    assert_eq!(
        slow0, fast0,
        "a partially read record changed after overwrite"
    );
    assert_eq!(qword(&slow2, 208), 1);
    assert_eq!(qword(&slow2, 216), fast1.len() as u64);
    assert_ne!(dword(&slow2, 20) & HOST_LOSS, 0);
    assert_eq!(qword(&fast2, 208), 0);
    assert_eq!(fast.ready.mask(), 0);
    assert_eq!(fast.read(&mut [0; 8]), Err(FsError::WouldBlock));
    root.close_reader();
    assert!(
        !root.stop.load(Ordering::Acquire),
        "followers retain the shared source"
    );
    fast.close_reader();
    late.close_reader();
    unused1.close_reader();
    assert!(root.stop.load(Ordering::Acquire));
    root.fail(FsError::NoDevice);
    assert_eq!(fast.read(&mut [0; 8]), Err(FsError::NoDevice));
    assert!(matches!(root.subscribe(), Err(FsError::Busy)));
    drop(fast);
    drop(late);
    drop(unused1);
    drop(root);
    assert!(!ACTIVE[60].load(Ordering::Acquire));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_v2_reader_overwrite_partial_record_and_retained_quota
);

fn smoke_guc_stream_v2_firmware_counter_wrap_lower_bound_and_ring_images() -> TestResult {
    let m = Memory::new();
    m.put(28, 3); // one observed event overflow, with flush set
    let mut b = Buffer::new().unwrap();
    copy_frame_with_loss(
        &m,
        &mut b,
        read_states(&m),
        identity(),
        0,
        10,
        None,
        [15, 0],
        [7, 0],
        &mut || true,
    )
    .unwrap();
    assert_eq!(dword(&b.bytes, 8), 2);
    assert_eq!(
        qword(&b.bytes, 192),
        2,
        "15->1 means at least two overflows"
    );
    assert_eq!(qword(&b.bytes, 224), 9);
    assert_eq!(dword(&b.bytes, 76), 65536);
    assert_eq!(dword(&b.bytes, 84), 4);
    assert_eq!(
        dword(&b.bytes, 20) & (FW_LOSS | EVENT_RING_IMAGE | FW_MODULO_BOUND),
        FW_LOSS | EVENT_RING_IMAGE | FW_MODULO_BOUND
    );
    copy_frame_with_loss(
        &m,
        &mut b,
        read_states(&m),
        identity(),
        0,
        11,
        None,
        [1, 0],
        [9, 0],
        &mut || true,
    )
    .unwrap();
    assert_eq!(qword(&b.bytes, 192), 0);
    assert_ne!(
        dword(&b.bytes, 20) & FW_MODULO_BOUND,
        0,
        "zero cannot exclude sixteen hidden wraps"
    );
    assert_eq!(dword(&b.bytes, 76), 8);
    assert!(!supported(identity().platform, (71, 0, 0)));
    assert!(!supported(
        crate::intel_gpu_gt::GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake),
        (70, 54, 1)
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_v2_firmware_counter_wrap_lower_bound_and_ring_images
);

struct CountWake(AtomicUsize);
impl alloc::task::Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn smoke_guc_stream_cached_readiness_terminal_wakes_every_duplicate() -> TestResult {
    let root = StreamSession::reserve(59).unwrap();
    let a = Arc::new(CountWake(AtomicUsize::new(0)));
    let b = Arc::new(CountWake(AtomicUsize::new(0)));
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    assert!(root
        .ready
        .arm_exclusive(1, POLL_IN | POLL_ERR | POLL_HUP, &wa)
        .is_pending());
    assert!(root
        .ready
        .arm_exclusive(2, POLL_IN | POLL_ERR | POLL_HUP, &wb)
        .is_pending());
    relay_frame(&root, &Memory::new(), 0);
    assert_eq!(
        (a.0.load(Ordering::Relaxed), b.0.load(Ordering::Relaxed)),
        (1, 0)
    );
    assert_eq!(root.read(&mut [0; 8]), Ok(8));
    assert_eq!(
        b.0.load(Ordering::Relaxed),
        1,
        "remaining bytes must relay the exclusive wake"
    );
    cached_frame(&root, b"NARFGSTR".to_vec());
    assert!(root
        .ready
        .arm_exclusive(1, POLL_IN | POLL_ERR | POLL_HUP, &wa)
        .is_pending());
    assert!(root
        .ready
        .arm_exclusive(2, POLL_IN | POLL_ERR | POLL_HUP, &wb)
        .is_pending());
    let before = (a.0.load(Ordering::Relaxed), b.0.load(Ordering::Relaxed));
    root.fail(FsError::NoDevice);
    assert_eq!(
        (a.0.load(Ordering::Relaxed), b.0.load(Ordering::Relaxed)),
        (before.0 + 1, before.1 + 1)
    );
    root.ready.disarm(1);
    root.ready.disarm(2);
    let mut late = root.fanout_spare.lock().take().unwrap();
    let memory = Memory::new();
    copy_frame(
        &memory,
        &mut late,
        read_states(&memory),
        identity(),
        root.index(),
        1,
        None,
        &mut || true,
    )
    .unwrap();
    let spare = root.publish(late);
    *root.fanout_spare.lock() = Some(spare);
    assert_eq!(
        root.read(&mut [0; 8]),
        Err(FsError::NoDevice),
        "fanout cannot publish after terminal wins"
    );
    assert_eq!(root.ready.mask(), POLL_ERR | POLL_HUP);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_cached_readiness_terminal_wakes_every_duplicate
);

fn smoke_guc_stream_fanout_copy_terminal_orders_loss_with_commit() -> TestResult {
    for terminal_first in [true, false] {
        let root = StreamSession::reserve(57).unwrap();
        let memory = Memory::new();
        relay_frame(&root, &memory, 0);
        relay_frame(&root, &memory, 1);
        // The external spare is copied while both reader records remain
        // intact. Model reset winning immediately before/after the commit.
        let mut incoming = root.fanout_spare.lock().take().unwrap();
        copy_frame(
            &memory,
            &mut incoming,
            read_states(&memory),
            identity(),
            root.index(),
            2,
            None,
            &mut || true,
        )
        .unwrap();
        if terminal_first {
            root.fail(FsError::NoDevice);
        }
        let spare = root.publish(incoming);
        *root.fanout_spare.lock() = Some(spare);
        if !terminal_first {
            root.fail(FsError::NoDevice);
        }
        let first = cached_frame(&root, Vec::new());
        let second = cached_frame(&root, Vec::new());
        if terminal_first {
            assert_eq!((qword(&first, 32), qword(&second, 32)), (0, 1));
            assert_eq!(qword(&second, 208), 0);
            assert_eq!(root.queue.lock().lost_frames, 0);
        } else {
            assert_eq!((qword(&first, 32), qword(&second, 32)), (1, 2));
            assert_eq!(qword(&second, 208), 1);
            assert_eq!(qword(&second, 216), first.len() as u64);
            assert_ne!(dword(&second, 20) & HOST_LOSS, 0);
        }
        assert_eq!(root.read(&mut [0; 8]), Err(FsError::NoDevice));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_fanout_copy_terminal_orders_loss_with_commit
);

fn smoke_guc_stream_queued_open_cannot_replay_after_park_reset_or_new_upload() -> TestResult {
    let publication = Arc::new(Publication::new());
    publish(&publication, 7);
    register_owner(58, identity().platform, &publication);
    let node = Node {
        index: 58,
        gate: Gate {
            enabled: yes,
            capable: yes,
        },
    };
    let old = node.open_instance_checked(false).unwrap().unwrap();
    let follower = node.open_instance_checked(false).unwrap().unwrap();
    assert_eq!(ready(old.read(0, &mut [0; 8])), Err(FsError::WouldBlock));
    // Production park/reset closure: publication zero and queued-root
    // invalidation serialize with the same actual Node/open insertion.
    close_publication(58, &publication);
    assert!(matches!(
        node.open_instance_checked(false),
        Err(FsError::NoDevice)
    ));
    assert_eq!(old.poll_readiness(), POLL_ERR | POLL_HUP);
    assert_eq!(ready(follower.read(0, &mut [0; 8])), Err(FsError::NoDevice));
    // A runtime resume can preserve the exec user_epoch while uploading a
    // different firmware incarnation. The old open cannot migrate to it.
    publish(&publication, 9);
    assert!(take_requested(58).is_none());
    assert_eq!(ready(old.read(0, &mut [0; 8])), Err(FsError::NoDevice));
    drop(old);
    drop(follower);
    let new = node.open_instance_checked(false).unwrap().unwrap();
    let request = take_requested(58).unwrap();
    assert_eq!(request.requested_incarnation(), Some(9));
    // Even a claimed request is revalidated before the reset-owner attaches.
    close_publication(58, &publication);
    publish(&publication, 9); // same upload, fresh publication serial still forbids ABA
    assert_eq!(request.requested_incarnation(), None);
    assert!(!request.matches_incarnation(9));
    publish(&publication, 11);
    assert_eq!(request.requested_incarnation(), None);
    assert_eq!(ready(new.read(0, &mut [0; 8])), Err(FsError::NoDevice));
    drop(new);
    drop(request);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_queued_open_cannot_replay_after_park_reset_or_new_upload
);
