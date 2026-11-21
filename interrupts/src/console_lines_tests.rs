//! Console output from several CPUs reaches the UART one whole line at a
//! time. Linux commits each printk as one record and its consoles emit
//! records whole (`console_lock` / nbcon ownership); NARF's trap sink —
//! the stall watchdog, CPU samples, fatal reports — and its ordinary
//! console writer must not mix bytes of each other's lines. A UART tap
//! (`narf_console::__test_set_uart_tap`) sees the byte runs in the order the
//! UART would; a CPU's line split by another's is a torn line.

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::percpu::MAX_CPUS;
use narf_scheduler::{Affinity, CpuId, TaskSpec};

const CAPTURE_BYTES: usize = 64 * 1024;
static CAPTURE: [AtomicU8; CAPTURE_BYTES] = [const { AtomicU8::new(0) }; CAPTURE_BYTES];
static CAPTURED: AtomicUsize = AtomicUsize::new(0);

/// Append one run as the UART receives it: runs from concurrent writers
/// land in the order they were handed over, each contiguous.
fn tap(bytes: &[u8]) {
    let at = CAPTURED.fetch_add(bytes.len(), Ordering::AcqRel);
    for (i, b) in bytes.iter().enumerate() {
        if let Some(slot) = CAPTURE.get(at + i) {
            slot.store(*b, Ordering::Relaxed);
        }
    }
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

fn live_peer() -> Option<usize> {
    let me = narf_lib::percpu::current_cpu();
    let live = narf_lib::smp::ever_online_bitmap() & narf_lib::smp::online_bitmap();
    (0..MAX_CPUS).find(|cpu| *cpu != me && live & (1u64 << cpu) != 0)
}

const LINES: usize = 300;
const PAD_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PAD_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static PEER_READY: AtomicBool = AtomicBool::new(false);
static GO: AtomicBool = AtomicBool::new(false);
static PEER_DONE: AtomicBool = AtomicBool::new(false);

/// `(index, writer)` of a line that is exactly one of the two this test
/// prints, `None` for any other text.
fn whole_line(line: &[u8]) -> Option<(usize, u8)> {
    let text = core::str::from_utf8(line).ok()?;
    let mut parts = text.split(' ');
    let (tag, index, pad, rest) = (parts.next()?, parts.next()?, parts.next()?, parts.next());
    let writer = match (tag, pad) {
        ("WHOLE-LINE-A", PAD_A) => b'A',
        ("WHOLE-LINE-B", PAD_B) => b'B',
        _ => return None,
    };
    if rest.is_some() || index.len() != 4 {
        return None;
    }
    Some((index.parse().ok()?, writer))
}

/// Two CPUs print distinct whole lines at once — the boot CPU through the
/// console writer, an AP through the trap writer the stall watchdog uses —
/// and every line reaches the UART whole, each exactly once.
fn smoke_console_lines_from_two_cpus_stay_whole() -> TestResult {
    let Some(ap) = live_peer() else {
        return TestResult::Skip("needs a second CPU that really came up");
    };
    PEER_READY.store(false, Ordering::Release);
    GO.store(false, Ordering::Release);
    PEER_DONE.store(false, Ordering::Release);
    CAPTURED.store(0, Ordering::Release);
    narf_scheduler::spawn_with_spec(
        async {
            PEER_READY.store(true, Ordering::Release);
            while !GO.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
            for i in 0..LINES {
                let _ = writeln!(narf_console::TrapWriter, "WHOLE-LINE-B {i:04} {PAD_B}");
            }
            PEER_DONE.store(true, Ordering::Release);
        },
        TaskSpec {
            affinity: Affinity::pinned(CpuId(ap as u32)),
            ..TaskSpec::kernel_any()
        },
    );
    if !wait_for(1_000_000_000, || PEER_READY.load(Ordering::Acquire)) {
        GO.store(true, Ordering::Release);
        return TestResult::Fail("the peer CPU did not start its writer");
    }
    let previous = narf_console::__test_set_uart_tap(Some(tap));
    GO.store(true, Ordering::Release);
    for i in 0..LINES {
        let _ = writeln!(narf_console::Writer, "WHOLE-LINE-A {i:04} {PAD_A}");
    }
    let finished = wait_for(10_000_000_000, || PEER_DONE.load(Ordering::Acquire));
    let _ = narf_console::__test_set_uart_tap(previous);
    if !finished {
        return TestResult::Fail("the peer CPU's writer did not finish");
    }

    let len = CAPTURED.load(Ordering::Acquire).min(CAPTURE_BYTES);
    let mut seen = [[false; LINES]; 2];
    let mut torn = 0usize;
    let mut line = [0u8; 256];
    let mut n = 0usize;
    let mut overlong = false;
    for slot in &CAPTURE[..len] {
        let b = slot.load(Ordering::Relaxed);
        if b != b'\n' {
            if n < line.len() {
                line[n] = b;
                n += 1;
            } else {
                overlong = true;
            }
            continue;
        }
        let text = &line[..n];
        let ours = text.windows(11).any(|w| w == b"WHOLE-LINE-");
        match whole_line(text) {
            Some((i, w)) if !overlong && i < LINES => {
                let seen_it = &mut seen[(w - b'A') as usize][i];
                torn += *seen_it as usize;
                *seen_it = true;
            }
            _ if ours => torn += 1,
            _ => {}
        }
        n = 0;
        overlong = false;
    }
    if len == CAPTURE_BYTES {
        return TestResult::Fail("capture buffer overflowed");
    }
    if torn != 0 {
        return TestResult::Fail("a line reached the UART torn by another CPU's output");
    }
    if seen.iter().any(|w| w.iter().any(|s| !s)) {
        return TestResult::Fail("a printed line never reached the UART whole");
    }
    TestResult::Pass
}
kernel_test_in!(
    "console/lines",
    smoke_console_lines_from_two_cpus_stay_whole
);
