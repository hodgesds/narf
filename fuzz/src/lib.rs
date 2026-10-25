//! Shared support for the NARF fuzz targets.
//!
//! Two pieces, both modelled directly on `verification/btrfs-host`
//! (the existing host harness for the fs stack — this crate is the
//! fuzzing sibling of that harness, not a new invention):
//!
//! - [`host`]: the host stand-ins a kernel crate graph needs to run
//!   inside a std process — inert linker anchors the kernel linker
//!   script would otherwise define, a 1 GiB identity-mapped "physical
//!   RAM" arena backing `narf_memory`'s frame allocator, and a
//!   busy-poll `block_on` for the drivers' async surface.
//! - [`fswalk`]: the bounded mount-walk both filesystem-image
//!   targets share: enumerate a directory, recurse a few levels,
//!   read the files found. Every bound is a defence against the
//!   *harness* looping forever on a hostile image; a hang inside
//!   the driver itself is a finding, and libFuzzer's `-timeout`
//!   (set by the nightly workflow) is what reports it.

pub mod host {
    use std::future::Future;
    use std::sync::Once;
    use std::task::{Context, Poll, Waker};

    // Symbols the kernel linker scripts (`build/linker/*.ld`) and
    // `frame/src/bare_main.rs` define. Kernel crates reference them
    // on paths a host harness never executes (KASLR, /sys build-id,
    // NUMA topology); the host link still needs definitions. Same
    // technique — and same symbol set — as
    // `verification/btrfs-host/src/host.rs`.
    #[no_mangle]
    static __kernel_phys_bounds: [u64; 2] = [0; 2];
    #[no_mangle]
    static __text_start: u8 = 0;
    #[no_mangle]
    static __build_id_note_start: u8 = 0;
    #[no_mangle]
    static __build_id_note_end: u8 = 0;

    /// Inert NUMA topology (one node), as `frame/src/bare_main.rs`
    /// reports when ACPI has no SRAT.
    #[no_mangle]
    extern "Rust" fn narf_cpu_node_opt(_cpu: u32) -> u32 {
        0
    }
    #[no_mangle]
    extern "Rust" fn narf_node_distance(from: u32, to: u32) -> u32 {
        if from == to {
            10
        } else {
            20
        }
    }
    #[no_mangle]
    extern "Rust" fn narf_numa_node_count() -> u32 {
        1
    }

    /// Base of the identity-mapped "physical" arena. On x86_64 the
    /// kernel reaches a frame through its physical address
    /// (`PhysAddr::kernel_mut_ptr` is the identity until the direct
    /// map is activated, which the host never does), so the arena
    /// must sit at a virtual address that is also a plausible
    /// physical one: low, below the frame allocator's tracked
    /// range. 1 GiB up keeps it clear of the executable and the
    /// heap. Mirrors btrfs-host.
    const ARENA_BASE: u64 = 0x4000_0000;
    /// Frames for DMA bounce buffers and page-sized kernel
    /// allocations. Reserved with `MAP_NORESERVE`: only pages the
    /// driver touches cost memory.
    const ARENA_LEN: usize = 1 << 30;

    static INIT: Once = Once::new();

    /// Bring up the kernel services the filesystem drivers use: the
    /// frame allocator (over the host arena) and the scheduler's
    /// queues. Idempotent — libFuzzer runs the target function
    /// thousands of times in one process, so this must be a
    /// once-per-process ritual, never per-input work.
    ///
    /// Note `narf_scheduler::init()` panics on a second call (repo
    /// AGENTS.md, "Stage::Late spawn rule"); the `Once` is what
    /// makes repeated target invocations safe.
    pub fn init() {
        INIT.call_once(|| {
            // SAFETY: a fresh private anonymous mapping at a fixed
            // address that MAP_FIXED_NOREPLACE refuses to place over
            // anything existing.
            let p = unsafe {
                libc::mmap(
                    ARENA_BASE as *mut _,
                    ARENA_LEN,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE
                        | libc::MAP_ANONYMOUS
                        | libc::MAP_FIXED_NOREPLACE
                        | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            assert_eq!(p as u64, ARENA_BASE, "mmap of the host frame arena failed");
            // SAFETY: called once; the region is mapped read-write,
            // reachable at its "physical" address, and owned by
            // nothing else.
            unsafe {
                narf_memory::frame::init_from_map(
                    &[narf_memory::frame::UsableRegion {
                        start: narf_memory::addr::PhysAddr::new(ARENA_BASE),
                        len: ARENA_LEN as u64,
                    }],
                    &[],
                );
            }
            narf_scheduler::init();
        });
    }

    /// Poll `f` to completion on this thread. Block I/O against the
    /// RAM disk completes synchronously, so a pending poll only ever
    /// means "yielded"; re-polling is the whole executor. A future
    /// that never finishes (one waiting on a task nobody runs) is a
    /// harness bug: fail loudly, like btrfs-host does.
    pub fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        let mut spins = 0u64;
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
            spins += 1;
            if spins == 50_000_000 {
                panic!("future still pending after {spins} polls (waiting on an unrun task?)");
            }
            std::hint::spin_loop();
        }
    }
}

pub mod fswalk {
    use std::sync::Arc;

    use narf_filesystem::{DirOps, FileOps, FileType};

    use crate::host;

    /// Harness bounds. These exist so a hostile image cannot make
    /// the *walk* unbounded (a million-entry directory, a deep
    /// tree, a sparse terabyte file); they are not driver limits
    /// and hitting one is not a failure.
    const MAX_DEPTH: usize = 4;
    const MAX_ENTRIES_PER_DIR: usize = 256;
    const MAX_FILES: usize = 64;
    const READ_WINDOW: usize = 16 * 1024;

    /// Walk a mounted filesystem's root: enumerate each directory,
    /// recurse into subdirectories, and read the head and tail of
    /// every regular file found. All driver errors are ignored —
    /// the invariant under fuzz is *never panic, never hang in the
    /// harness, never read out of bounds*, and a structured
    /// `FsError` is a perfectly good outcome for a corrupt image.
    pub fn walk(root: Arc<dyn DirOps>) {
        let mut files = 0usize;
        walk_dir(&root, 0, &mut files);
    }

    fn walk_dir(dir: &Arc<dyn DirOps>, depth: usize, files: &mut usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let Ok(entries) = host::block_on(dir.enumerate_async(0, MAX_ENTRIES_PER_DIR)) else {
            return;
        };
        for (name, kind) in entries {
            if name == "." || name == ".." {
                continue;
            }
            match kind {
                FileType::File => {
                    if *files >= MAX_FILES {
                        return;
                    }
                    *files += 1;
                    if let Ok(file) = host::block_on(dir.lookup_async(&name)) {
                        read_file(&file);
                    }
                }
                FileType::Dir => {
                    if let Ok(sub) = host::block_on(dir.lookup_dir_async(&name)) {
                        walk_dir(&sub, depth + 1, files);
                    }
                }
                // Symlinks are deliberately not followed: a link
                // loop is the image's business, and chasing one
                // would measure the harness, not the driver. The
                // link itself was still parsed by enumerate.
                _ => {}
            }
        }
    }

    fn read_file(file: &Arc<dyn FileOps>) {
        let size = file.stat().size;
        let head = (size.min(READ_WINDOW as u64)) as usize;
        if head > 0 {
            let mut buf = vec![0u8; head];
            let _ = host::block_on(file.read(0, &mut buf));
        }
        // A second read straddling EOF exercises the short-read /
        // zero-fill path with attacker-chosen sizes.
        if size > 0 {
            let off = size.saturating_sub(1);
            let mut buf = vec![0u8; 8192];
            let _ = host::block_on(file.read(off, &mut buf));
        }
    }
}
