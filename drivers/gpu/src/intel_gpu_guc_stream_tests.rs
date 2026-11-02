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
        (1, 192, 204)
    );
    assert_eq!(
        (
            dword(&b.bytes, 20),
            dword(&b.bytes, 24),
            dword(&b.bytes, 28)
        ),
        (1, 3, 7)
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
        (192, 8, 200, 4)
    );
    assert_eq!(&b.bytes[160..192], &[0xa5; 32]);
    assert_eq!(&b.bytes[192..204], &[0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3]);
    m.put(4096, 0xffff_ffff);
    assert_eq!(&b.bytes[192..196], &[0, 1, 2, 3]);
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
    assert_eq!(b.len, 200);
    assert_eq!(&b.bytes[192..200], &[252, 253, 254, 255, 0, 1, 2, 3]);
    assert!(b.bytes[200..].iter().all(|v| *v == 0));
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
            3 => m.put(28, 3),
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
        let mut b = s.take_free().unwrap();
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
        s.publish(b);
    }
    assert!(s.take_free().is_none());
    assert_eq!(s.ready.mask(), POLL_IN);
    s.fail(FsError::InvalidData);
    assert_eq!(s.ready.mask(), POLL_IN | POLL_ERR | POLL_HUP);
    for sequence in 0..2 {
        let mut frame = alloc::vec![0;204];
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
#[derive(Debug)]
struct Backend {
    calls: AtomicUsize,
    pending: AtomicBool,
    revoke: AtomicBool,
}
impl UserBackend for Backend {
    fn status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
        None
    }
    fn submit<'a>(
        &'a self,
        _: Arc<crate::intel_gpu_user::UserContext>,
        _: crate::intel_gpu_user::UserBatch,
    ) -> FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn guc_log_stream(&self, _: Arc<StreamSession>) -> FsFuture<'_, ()> {
        Box::pin(async move {
            if self.pending.load(Ordering::Acquire) {
                core::future::pending::<()>().await;
            }
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.revoke.load(Ordering::Acquire) {
                ALLOWED.store(false, Ordering::Release);
            }
            Ok(())
        })
    }
}
fn smoke_guc_stream_descriptor_live_authority_dup_cancel_and_lazy_attach() -> TestResult {
    ALLOWED.store(true, Ordering::Release);
    let backend = Arc::new(Backend {
        calls: AtomicUsize::new(0),
        pending: AtomicBool::new(false),
        revoke: AtomicBool::new(false),
    });
    let node = Node {
        index: 62,
        backend: backend.clone(),
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
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    backend.pending.store(true, Ordering::Release);
    {
        let mut bytes = [0; 8];
        let mut waiting = Box::pin(file.read(0, &mut bytes));
        assert!(waiting
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert!(ACTIVE[62].load(Ordering::Acquire));
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    backend.pending.store(false, Ordering::Release);
    backend.revoke.store(true, Ordering::Release);
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
    assert!(ACTIVE[62].load(Ordering::Acquire));
    drop(duplicate);
    assert!(!ACTIVE[62].load(Ordering::Acquire));
    ALLOWED.store(true, Ordering::Release);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_descriptor_live_authority_dup_cancel_and_lazy_attach
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
