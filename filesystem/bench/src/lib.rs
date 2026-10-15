#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use narf_bpf_bench::{measure, observe, Benchmark, Sample};
use narf_filesystem::memfs::MemFs;
use narf_filesystem::{FileType, FsInstance};

const LOOKUP_ITERS: u32 = 1000;
const DELTA_PCT: f64 = 3.0;
const TARGET_N: u32 = 60;

fn sync_poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VT)
    }
    static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: No-op waker with a null pointer
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is local to this function and will not be moved before it is dropped
    let pinned = unsafe { core::pin::Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(val) => Some(val),
        Poll::Pending => None,
    }
}

// ---------------------------------------------------------
// Existing Basic Lookup Benches
// ---------------------------------------------------------

fn sample_memfs_lookup_hit(iters: u32) -> Option<Sample> {
    let fs = MemFs::new("bench");
    let root = fs.root();
    let _ = sync_poll_once(root.mknod("testfile", FileType::File, 0o644));
    let (cycles, ok) = measure(|| {
        for _ in 0..iters {
            observe(root.lookup("testfile"));
        }
        true
    });
    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: iters as u64,
    })
}

fn sample_memfs_lookup_miss(iters: u32) -> Option<Sample> {
    let fs = MemFs::new("bench");
    let root = fs.root();
    let (cycles, ok) = measure(|| {
        for _ in 0..iters {
            observe(root.lookup("missingfile"));
        }
        true
    });
    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: iters as u64,
    })
}

fn sample_memfs_mknod_unlink(iters: u32) -> Option<Sample> {
    let fs = MemFs::new("bench");
    let root = fs.root();
    let (cycles, ok) = measure(|| {
        for _ in 0..iters {
            observe(sync_poll_once(root.mknod("file", FileType::File, 0o644)));
            observe(sync_poll_once(root.unlink("file")));
        }
        true
    });
    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: iters as u64,
    })
}

// ---------------------------------------------------------
// Added Thorough Benches
// ---------------------------------------------------------

fn sample_memfs_mkdir_rmdir(iters: u32) -> Option<Sample> {
    let fs = MemFs::new("bench");
    let root = fs.root();
    let (cycles, ok) = measure(|| {
        for _ in 0..iters {
            observe(sync_poll_once(root.mkdir("dir")));
            observe(sync_poll_once(root.rmdir("dir")));
        }
        true
    });
    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: iters as u64,
    })
}

fn sample_memfs_lookup_dir(iters: u32) -> Option<Sample> {
    let fs = MemFs::new("bench");
    let root = fs.root();
    let _ = sync_poll_once(root.mkdir("testdir"));
    let (cycles, ok) = measure(|| {
        for _ in 0..iters {
            observe(root.lookup_dir("testdir"));
        }
        true
    });
    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: iters as u64,
    })
}

fn sample_memfs_enumerate(iters: u32) -> Option<Sample> {
    let fs = MemFs::new("bench");
    let root = fs.root();
    // Pre-populate some entries to make enumeration work harder
    for i in 0..10 {
        let name = alloc::format!("file{}", i);
        let _ = sync_poll_once(root.mknod(&name, FileType::File, 0o644));
    }

    // We limit iters for enumerate to not take too long since it enumerates multiple things
    let run_iters = iters.max(1) / 10;
    let run_iters = if run_iters == 0 { 1 } else { run_iters };

    let (cycles, ok) = measure(|| {
        for _ in 0..run_iters {
            observe(root.enumerate(0, 10));
        }
        true
    });

    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: run_iters as u64,
    })
}

fn sample_memfs_rename(iters: u32) -> Option<Sample> {
    let fs = MemFs::new("bench");
    let root = fs.root();
    let _ = sync_poll_once(root.mknod("fileA", FileType::File, 0o644));

    let (cycles, ok) = measure(|| {
        for i in 0..iters {
            if i % 2 == 0 {
                observe(sync_poll_once(root.rename("fileA", "fileB")));
            } else {
                observe(sync_poll_once(root.rename("fileB", "fileA")));
            }
        }
        true
    });

    if !ok {
        return None;
    }
    // Ensure we clean up by unlinking wherever it ended up, just to be safe but MemFs is volatile.

    Some(Sample {
        value: cycles,
        work: iters as u64,
    })
}

static FS_BENCHES: &[Benchmark] = &[
    Benchmark {
        name: "fs.memfs.lookup.hit",
        subsystem: "filesystem",
        unit: "cycles",
        lower_is_better: true,
        warmup: 3,
        iters: LOOKUP_ITERS,
        target_n: TARGET_N,
        delta_pct: DELTA_PCT,
        compare_with: None,
        sample: sample_memfs_lookup_hit,
        skip_reason: "none",
    },
    Benchmark {
        name: "fs.memfs.lookup.miss",
        subsystem: "filesystem",
        unit: "cycles",
        lower_is_better: true,
        warmup: 3,
        iters: LOOKUP_ITERS,
        target_n: TARGET_N,
        delta_pct: DELTA_PCT,
        compare_with: None,
        sample: sample_memfs_lookup_miss,
        skip_reason: "none",
    },
    Benchmark {
        name: "fs.memfs.mknod_unlink",
        subsystem: "filesystem",
        unit: "cycles",
        lower_is_better: true,
        warmup: 3,
        iters: LOOKUP_ITERS,
        target_n: TARGET_N,
        delta_pct: DELTA_PCT,
        compare_with: None,
        sample: sample_memfs_mknod_unlink,
        skip_reason: "none",
    },
    Benchmark {
        name: "fs.memfs.mkdir_rmdir",
        subsystem: "filesystem",
        unit: "cycles",
        lower_is_better: true,
        warmup: 3,
        iters: LOOKUP_ITERS,
        target_n: TARGET_N,
        delta_pct: DELTA_PCT,
        compare_with: None,
        sample: sample_memfs_mkdir_rmdir,
        skip_reason: "none",
    },
    Benchmark {
        name: "fs.memfs.lookup.dir",
        subsystem: "filesystem",
        unit: "cycles",
        lower_is_better: true,
        warmup: 3,
        iters: LOOKUP_ITERS,
        target_n: TARGET_N,
        delta_pct: DELTA_PCT,
        compare_with: None,
        sample: sample_memfs_lookup_dir,
        skip_reason: "none",
    },
    Benchmark {
        name: "fs.memfs.enumerate",
        subsystem: "filesystem",
        unit: "cycles",
        lower_is_better: true,
        warmup: 3,
        iters: 100, // Reduced iterations since it does more work
        target_n: TARGET_N,
        delta_pct: DELTA_PCT,
        compare_with: None,
        sample: sample_memfs_enumerate,
        skip_reason: "none",
    },
    Benchmark {
        name: "fs.memfs.rename",
        subsystem: "filesystem",
        unit: "cycles",
        lower_is_better: true,
        warmup: 3,
        iters: LOOKUP_ITERS,
        target_n: TARGET_N,
        delta_pct: DELTA_PCT,
        compare_with: None,
        sample: sample_memfs_rename,
        skip_reason: "none",
    },
];

pub fn register_initcalls() {
    narf_init::register(narf_init::Stage::Late, "filesystem-bench", || {
        if narf_bpf_bench::requested() {
            narf_bpf_bench::register_group(FS_BENCHES);
        }
        narf_init::InitResult::Ok
    });
}
