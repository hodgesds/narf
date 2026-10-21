//! In-kernel tests for the chunked console write path.

use super::*;
use core::sync::atomic::AtomicUsize;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A console write longer than [`MASKED_CHUNK`] reaches the UART in chunks
/// of at most that many bytes, each ending early after a line feed, and
/// services masked work (pending TLB shootdowns) between chunks. Without
/// it a CPU writing console text with `CONSOLE.lock` held could not answer
/// a shootdown IPI until the whole UART + framebuffer write finished, and
/// a page-faulting peer waited on its acknowledgement for that long.
fn smoke_console_write_services_masked_work_between_chunks() -> TestResult {
    static HOOK_CALLS: AtomicUsize = AtomicUsize::new(0);
    fn hook() {
        HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
    }
    let mut text = [b'a'; 33];
    text[30] = b'\n';
    text[31] = b'b';
    text[32] = b'b';
    let mut chunks = [0usize; 4];
    let mut n = 0usize;
    HOOK_CALLS.store(0, Ordering::Relaxed);
    let previous = narf_lib::sync::__test_swap_lock_spin_hook(Some(hook));
    // The framebuffer hook is left as installed: it parses byte by byte, so
    // the chunks it receives draw the same text.
    write_chunked(&text, |chunk| {
        if n < chunks.len() {
            chunks[n] = chunk.len();
        }
        n += 1;
    });
    let _ = narf_lib::sync::__test_swap_lock_spin_hook(previous);
    if n != 3 || chunks[..3] != [16, 15, 2] {
        return TestResult::Fail("console write not split at 16 bytes and after the line feed");
    }
    if HOOK_CALLS.load(Ordering::Relaxed) < 2 {
        return TestResult::Fail("masked work not serviced between console chunks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "console/write",
    smoke_console_write_services_masked_work_between_chunks
);
