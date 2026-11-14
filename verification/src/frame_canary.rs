//! SMP allocator canary churn: every live CPU allocates frames (order 0, 1
//! and 3) and 32 KiB heap buffers (the size of a kernel stack), fills each
//! with a pattern derived from the word's own address, and checks the pattern
//! before freeing. Half the frees happen on another CPU, handed over through
//! per-CPU mailboxes, as task stacks and pages are freed in the kernel. A
//! block handed to two owners at once, or written by anyone after its free
//! and handed out again, breaks some owner's pattern.
//!
//! With `frame-poison-check` the allocator also verifies every free frame as
//! it hands it out, so a write into a block while it sits free is caught too.
use alloc::boxed::Box;
use alloc::vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use narf_console::Writer;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::percpu::MAX_CPUS;
use narf_memory::{PhysAddr, PhysFrame};
use narf_scheduler::{Affinity, CpuId, TaskSpec};

/// Workers taking part: the boot CPU plus up to this many minus one APs.
const MAX_WORKERS: usize = 16;
/// Allocate/free rounds per worker.
const ROUNDS: usize = 4000;
/// Blocks a worker keeps live at once.
const LIVE: usize = 8;
/// Mailbox entries per worker.
const MAILBOX: usize = 8;
/// Words in a heap buffer (32 KiB, a kernel stack).
const BUF_WORDS: usize = 4096;
/// How long the boot CPU waits for the APs' workers.
const WAIT_NS: u64 = 20_000_000_000;

/// Mixed into every pattern word so a zeroed or poisoned word never matches.
const SALT: u64 = 0xA5C3_0F1E_5A3C_F0E1;

type Buf = Box<[u64; BUF_WORDS]>;

/// One live block: frames (`phys | order`, bit 63 clear) or a heap buffer
/// (its kernel virtual address, bit 63 set).
#[derive(Copy, Clone)]
struct Block(u64);

impl Block {
    fn frames(frame: PhysFrame, order: u8) -> Self {
        Block(frame.start_address().raw() | u64::from(order))
    }

    /// `None` (the buffer freed) if its address does not have bit 63 set,
    /// which tells buffers from frames.
    fn buf(buf: Buf) -> Option<Self> {
        let raw = Box::into_raw(buf);
        if (raw as u64) >> 63 == 0 {
            // SAFETY: just made by `Box::into_raw`, not shared.
            drop(unsafe { Box::from_raw(raw) });
            return None;
        }
        Some(Block(raw as u64))
    }

    fn is_buf(self) -> bool {
        self.0 >> 63 != 0
    }

    /// The block's words.
    fn words(self) -> (*mut u64, usize) {
        if self.is_buf() {
            (self.0 as *mut u64, BUF_WORDS)
        } else {
            let order = (self.0 & 0xF) as u32;
            let base = PhysAddr::new(self.0 & !0xFFF).kernel_mut_ptr::<u64>();
            (base, (narf_memory::PAGE_SIZE as usize / 8) << order)
        }
    }

    fn fill(self) {
        let (base, len) = self.words();
        for i in 0..len {
            // SAFETY: the block is owned by this worker (just allocated), and
            // `words` covers exactly its memory.
            unsafe {
                let word = base.add(i);
                core::ptr::write_volatile(word, word as u64 ^ SALT);
            }
        }
    }

    /// Check the pattern; on a mismatch record it and return `false`.
    fn check(self) -> bool {
        let (base, len) = self.words();
        for i in 0..len {
            // SAFETY: as in `fill`; the block is still owned, not yet freed.
            let (word, value) = unsafe {
                let word = base.add(i);
                (word, core::ptr::read_volatile(word))
            };
            let want = word as u64 ^ SALT;
            if value != want {
                record_mismatch(self, i, value, want);
                return false;
            }
        }
        true
    }

    fn free(self) {
        if self.is_buf() {
            // SAFETY: made by `Block::buf` from a `Box<[u64; BUF_WORDS]>`,
            // freed once (a block is in exactly one slot or mailbox entry).
            drop(unsafe { Box::from_raw(self.0 as *mut [u64; BUF_WORDS]) });
        } else {
            let frame = PhysFrame::new(PhysAddr::new(self.0 & !0xFFF));
            narf_memory::free_pages(frame, (self.0 & 0xF) as u8);
        }
    }
}

static FAILED: AtomicBool = AtomicBool::new(false);
static FAIL_BLOCK: AtomicU64 = AtomicU64::new(0);
static FAIL_WORD: AtomicU64 = AtomicU64::new(0);
static FAIL_VALUE: AtomicU64 = AtomicU64::new(0);
static FAIL_WANT: AtomicU64 = AtomicU64::new(0);
static FAIL_CPU: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
static ALLOC_MISSES: AtomicUsize = AtomicUsize::new(0);
static HANDED_OVER: AtomicUsize = AtomicUsize::new(0);
static MAILBOXES: [[AtomicU64; MAILBOX]; MAX_WORKERS] =
    [const { [const { AtomicU64::new(0) }; MAILBOX] }; MAX_WORKERS];

fn record_mismatch(block: Block, word: usize, value: u64, want: u64) {
    if FAILED.swap(true, Ordering::AcqRel) {
        return;
    }
    FAIL_BLOCK.store(block.0, Ordering::Relaxed);
    FAIL_WORD.store(word as u64, Ordering::Relaxed);
    FAIL_VALUE.store(value, Ordering::Relaxed);
    FAIL_WANT.store(want, Ordering::Relaxed);
    FAIL_CPU.store(narf_lib::percpu::current_cpu() as u64, Ordering::Relaxed);
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn alloc_block(rng: &mut u64) -> Option<Block> {
    let block = match xorshift(rng) % 5 {
        0 => {
            let words = vec![0u64; BUF_WORDS].into_boxed_slice();
            Block::buf(words.try_into().ok()?)?
        }
        pick => {
            let order = [0u8, 0, 1, 3][pick as usize - 1];
            let node = narf_memory::current_cpu_node();
            Block::frames(narf_memory::alloc_pages_on(node, order).ok()?, order)
        }
    };
    block.fill();
    Some(block)
}

/// Check and free whatever other workers handed to `me`.
fn drain_mailbox(me: usize) {
    for entry in &MAILBOXES[me] {
        let raw = entry.swap(0, Ordering::AcqRel);
        if raw != 0 {
            let block = Block(raw);
            if block.check() {
                block.free();
            }
        }
    }
}

/// Hand `block` to `to` for freeing; frees it here when that mailbox is full.
fn hand_over(block: Block, to: usize) {
    for entry in &MAILBOXES[to] {
        if entry
            .compare_exchange(0, block.0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            HANDED_OVER.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    block.free();
}

fn worker(me: usize, workers: usize) {
    let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ ((me as u64 + 1) << 32);
    let mut live: [Option<Block>; LIVE] = [None; LIVE];
    for round in 0..ROUNDS {
        if FAILED.load(Ordering::Relaxed) {
            break;
        }
        drain_mailbox(me);
        let slot = round % LIVE;
        if let Some(block) = live[slot].take() {
            if !block.check() {
                break;
            }
            if workers > 1 && xorshift(&mut rng) & 1 == 0 {
                let to = (me + 1 + (xorshift(&mut rng) as usize % (workers - 1))) % workers;
                hand_over(block, to);
            } else {
                block.free();
            }
        }
        match alloc_block(&mut rng) {
            Some(block) => live[slot] = Some(block),
            None => {
                ALLOC_MISSES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    for block in live.into_iter().flatten() {
        if block.check() {
            block.free();
        }
    }
    drain_mailbox(me);
    DONE.fetch_add(1, Ordering::AcqRel);
}

fn wait_for(ns: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(ns));
    loop {
        if done() {
            return true;
        }
        if narf_time::now_cycles() >= deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Every live CPU churns the frame allocator and the heap with canaried
/// blocks, freeing half of them on another CPU; no pattern may change while
/// its block is owned.
fn smoke_frame_smp_canary_churn() -> TestResult {
    let me = narf_lib::percpu::current_cpu();
    let live = narf_lib::smp::ever_online_bitmap() & narf_lib::smp::online_bitmap();
    let aps: alloc::vec::Vec<usize> = (0..MAX_CPUS)
        .filter(|cpu| *cpu != me && live & (1u64 << cpu) != 0)
        .take(MAX_WORKERS - 1)
        .collect();
    if aps.is_empty() {
        return TestResult::Skip("needs a second CPU that really came up");
    }
    let workers = aps.len() + 1;
    FAILED.store(false, Ordering::Release);
    DONE.store(0, Ordering::Release);
    ALLOC_MISSES.store(0, Ordering::Relaxed);
    HANDED_OVER.store(0, Ordering::Relaxed);
    for (index, &cpu) in aps.iter().enumerate() {
        narf_scheduler::spawn_with_spec(
            async move { worker(index + 1, workers) },
            TaskSpec {
                affinity: Affinity::pinned(CpuId(cpu as u32)),
                ..TaskSpec::kernel_any()
            },
        );
    }
    worker(0, workers);
    let finished = wait_for(WAIT_NS, || DONE.load(Ordering::Acquire) == workers);
    // Blocks handed over after their recipient finished.
    for index in 0..workers {
        drain_mailbox(index);
    }
    let _ = writeln!(
        Writer,
        "  frame canary: {} workers x {} rounds, {} cross-CPU frees, {} allocation misses",
        workers,
        ROUNDS,
        HANDED_OVER.load(Ordering::Relaxed),
        ALLOC_MISSES.load(Ordering::Relaxed),
    );
    if FAILED.load(Ordering::Acquire) {
        let block = Block(FAIL_BLOCK.load(Ordering::Relaxed));
        let word = FAIL_WORD.load(Ordering::Relaxed);
        let _ = writeln!(
            Writer,
            "  frame canary: {} {:#x} word {} (+{:#x}) is {:#x}, expected {:#x} (cpu {})",
            if block.is_buf() { "buffer" } else { "frames" },
            block.0,
            word,
            word * 8,
            FAIL_VALUE.load(Ordering::Relaxed),
            FAIL_WANT.load(Ordering::Relaxed),
            FAIL_CPU.load(Ordering::Relaxed),
        );
        return TestResult::Fail("a canary changed while its block was owned");
    }
    if !finished {
        return TestResult::Fail("an AP's canary worker did not finish");
    }
    TestResult::Pass
}
kernel_test_in!("memory/frame/smp", smoke_frame_smp_canary_churn);
