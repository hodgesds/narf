//! The host stand-ins a kernel crate graph needs to run in a std process.
//!
//! None of this is a shim inside a kernel crate: it is what the harness
//! process provides *around* them — "physical RAM" for the frame allocator,
//! inert linker anchors the kernel linker script would otherwise define, and
//! a busy-polling executor. The only kernel-crate change the host path needs
//! is `narf_lib::sync`'s IRQ save/restore, which is a no-op off
//! `target_os = "none"` (user mode cannot `cli`).

use std::future::Future;
use std::sync::Once;
use std::task::{Context, Poll, Waker};

// Symbols the kernel linker scripts (`build/linker/*.ld`) and
// `frame/src/bare_main.rs` define. Kernel crates reference them on paths this
// harness never executes (KASLR, `/sys` build-id, NUMA topology); the host
// link still needs a definition. Same technique as `block/src/luks2.rs`'s
// host tests.
#[no_mangle]
static __kernel_phys_bounds: [u64; 2] = [0; 2];
#[no_mangle]
static __text_start: u8 = 0;
#[no_mangle]
static __build_id_note_start: u8 = 0;
#[no_mangle]
static __build_id_note_end: u8 = 0;

/// Inert NUMA topology (one node), as `frame/src/bare_main.rs` reports when
/// ACPI has no SRAT.
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

/// Base of the identity-mapped "physical" arena. On x86_64 the kernel reaches
/// a frame through its physical address (`PhysAddr::kernel_mut_ptr` is the
/// identity until the direct map is activated, which the host never does), so
/// the arena must sit at a virtual address that is also a plausible physical
/// one: low, below the frame allocator's tracked range. 1 GiB up keeps it
/// clear of the executable and the heap.
const ARENA_BASE: u64 = 0x4000_0000;
/// Frames for DMA bounce buffers and page-sized kernel allocations. Reserved
/// with `MAP_NORESERVE`: only pages the driver touches cost memory.
const ARENA_LEN: usize = 1 << 30;

static INIT: Once = Once::new();

/// Bring up the kernel services the btrfs driver uses: the frame allocator
/// (over a host arena) and the scheduler's queues (for the commit timer it
/// spawns; the harness never runs it, so every commit is one it asked for).
pub fn init() {
    INIT.call_once(|| {
        // SAFETY: a fresh private anonymous mapping at a fixed address that
        // `MAP_FIXED_NOREPLACE` refuses to place over anything existing.
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
        // SAFETY: called once; the region is mapped read-write, reachable at
        // its "physical" address, and owned by nothing else.
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

/// Poll `f` to completion on this thread. Every block I/O the driver issues
/// completes synchronously (`SyncBlock`), so a pending poll only ever means
/// "yielded"; re-polling is the whole executor. A future that never finishes
/// (one waiting for a task nobody runs) is a harness bug: fail loudly.
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

/// Kernel log text recorded since the previous call (the driver's
/// `narf_console::Writer` output; the host never initialises a UART, so the
/// in-memory log store is the console).
pub fn klog_take() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEEN: AtomicU64 = AtomicU64::new(0);
    let next = narf_console::klog::next_seq();
    let from = SEEN.swap(next, Ordering::Relaxed);
    String::from_utf8_lossy(&narf_console::klog::text_since(from)).into_owned()
}

/// [`klog_take`] without the disk-policy banners every mount prints.
pub fn klog_take_filtered() -> String {
    klog_take()
        .lines()
        .filter(|l| !l.starts_with("disks:"))
        .collect::<Vec<_>>()
        .join("\n")
}
