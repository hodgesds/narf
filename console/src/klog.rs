//! Kernel log ring — bounded, IRQ-safe, line-oriented snapshot of
//! every byte that went through `console::write_str`.
//!
//! Why
//! ---
//! The FB console has no scrollback and serial capture isn't always
//! available (real-HW laptops without exposed UART pins). Without a
//! captive log, debugging a stuck boot means staring at whatever
//! 80×100 characters happened to be on screen when the kernel
//! halted. klog gives us a snapshot: drivers + the eventual debugger
//! REPL can call `snapshot()` to read the last N kilobytes of
//! console output verbatim.
//!
//! Storage
//! -------
//! Static byte ring of 64 KiB (`.bss`, no heap) so klog works
//! before the slab promotes — every panic / OOM / pre-promotion
//! diagnostic still lands in the buffer. Writes wrap; reads
//! linearise the live region into a fresh `Vec<u8>`.
//!
//! Concurrency
//! -----------
//! Single `IrqSafeSpinLock` guards the head pointer + the buffer.
//! `record()` is called from inside `console::write_str` *before*
//! that function takes the console-backend lock, so klog and the
//! console hold disjoint locks; a panic-time write that already
//! holds the console lock can still record. Lock-free ring designs
//! are an option later but the contention here is microscopic and
//! the spinlock keeps reads atomic w.r.t. concurrent writes.
//!
//! Line indexing
//! -------------
//! Bytes are stored verbatim, including embedded `\n`. Callers that
//! want line-by-line access use `for_each_line` which scans the
//! snapshot and yields each `\n`-terminated chunk.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Total ring capacity in bytes. 64 KiB ≈ 800 lines of typical
/// boot output (~80 cols), comfortably covers a full boot
/// sequence + post-boot driver chatter without unbounded growth.
pub const RING_CAPACITY: usize = 64 * 1024;

struct Ring {
    /// Backing storage. Wrapping byte buffer.
    buf: [u8; RING_CAPACITY],
    /// Write head — next byte to write goes here.
    head: usize,
    /// Total bytes ever written. Used by readers to detect whether
    /// the ring has wrapped (`written > capacity`) and to compute
    /// the live region's start.
    written: u64,
}

static RING: IrqSafeSpinLock<Ring> = IrqSafeSpinLock::new(Ring {
    buf: [0u8; RING_CAPACITY],
    head: 0,
    written: 0,
});

/// Re-entry guard. `record()` hot-path is called from inside
/// `write_str`; if a klog write itself triggers a write_str (e.g.
/// the lock contention assertion's writeln), we'd recurse. The
/// guard short-circuits the inner call.
static IN_RECORD: AtomicBool = AtomicBool::new(false);

/// Append bytes to the ring. Called from `console::write_str`
/// before the console-backend lock is taken. Cheap — the only
/// cost is one `IrqSafeSpinLock::lock` + a memcpy that's bounded
/// by the input slice length.
pub fn record(s: &str) {
    if IN_RECORD.swap(true, Ordering::Acquire) {
        return; // re-entrant write; skip to avoid deadlock
    }
    let bytes = s.as_bytes();
    {
        let mut g = RING.lock();
        for &b in bytes {
            let idx = g.head;
            g.buf[idx] = b;
            g.head = (idx + 1) % RING_CAPACITY;
            g.written = g.written.saturating_add(1);
        }
    }
    IN_RECORD.store(false, Ordering::Release);
}

/// Snapshot the live region of the ring into a fresh `Vec<u8>`,
/// in chronological order (oldest byte first). Allocates — caller
/// is responsible for the cost.
///
/// When the ring hasn't wrapped (`written <= RING_CAPACITY`) the
/// snapshot is just `buf[..written]`. After wrap, it's the two
/// segments stitched in order: `buf[head..]` then `buf[..head]`.
pub fn snapshot() -> Vec<u8> {
    let g = RING.lock();
    let written = g.written;
    let head = g.head;
    let live_len = if written < RING_CAPACITY as u64 {
        written as usize
    } else {
        RING_CAPACITY
    };
    let mut out = Vec::with_capacity(live_len);
    if (written as usize) < RING_CAPACITY {
        // Pre-wrap: live region is buf[..head] (head == written).
        out.extend_from_slice(&g.buf[..head]);
    } else {
        // Post-wrap: oldest byte sits at `head`; wrap point is
        // RING_CAPACITY.
        out.extend_from_slice(&g.buf[head..]);
        out.extend_from_slice(&g.buf[..head]);
    }
    out
}

/// Iterate every `\n`-terminated line in the live ring, oldest
/// first. Bytes between newlines are passed verbatim (no UTF-8
/// validation — caller decides). Trailing partial line (no
/// terminating `\n`) is yielded as the final entry.
pub fn for_each_line<F: FnMut(&[u8])>(mut f: F) {
    let snap = snapshot();
    let mut start = 0usize;
    for (i, &b) in snap.iter().enumerate() {
        if b == b'\n' {
            f(&snap[start..i]);
            start = i + 1;
        }
    }
    if start < snap.len() {
        f(&snap[start..]);
    }
}

/// Read the last `n` lines (oldest first within the returned
/// slice). Useful for the FB status panel. Allocating: the result
/// is owned strings to keep the snapshot lifetime contained.
pub fn tail(n: usize) -> Vec<alloc::string::String> {
    use alloc::string::String;
    let mut all: Vec<String> = Vec::new();
    for_each_line(|line| {
        all.push(String::from_utf8_lossy(line).into_owned());
    });
    let len = all.len();
    if len <= n {
        all
    } else {
        all.split_off(len - n)
    }
}

/// Total bytes ever recorded. Diagnostic — lets a caller detect
/// whether the ring has wrapped (compare to `RING_CAPACITY`).
pub fn bytes_written() -> u64 {
    RING.lock().written
}

/// Test-only: clear the ring. Hermetic isolation between smokes.
#[doc(hidden)]
pub fn __reset_for_test() {
    let mut g = RING.lock();
    g.buf = [0u8; RING_CAPACITY];
    g.head = 0;
    g.written = 0;
}
