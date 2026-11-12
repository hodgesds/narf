//! How much stack each initcall takes.
//!
//! The initcalls run on the kernel init stack (`run_on_kernel_stack`). Before
//! each one, [`hook`] paints the dead part of that stack — everything below
//! the current stack pointer — and afterwards finds the deepest word that is
//! no longer paint: the initcall's own depth, from its call point. The stale
//! words left there are the frames of its deepest call chain; the kernel-image
//! addresses among them, printed at link-time values, are what `addr2line`
//! needs to name the functions responsible.
//!
//! Linux runs every initcall on `kernel_init`'s 16 KiB stack; an initcall here
//! has [`INITCALL_STACK_BUDGET`], and `smoke_initcalls_fit_their_stack_budget`
//! fails when one goes past it.

use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Stack an initcall may use, from its call point.
pub const INITCALL_STACK_BUDGET: usize = 32 * 1024;

/// What `run_on_kernel_stack` paints with, a byte at a time.
const PAINT: u64 = 0xA5A5_A5A5_A5A5_A5A5;
/// Left untouched below the hook's own stack pointer: room for its frame and
/// for an interrupt taken on this stack while it paints.
const MARGIN: usize = 1024;
/// The kernel task's canary words at the stack's low end.
const CANARY_BYTES: usize = 64;
/// Image addresses kept from each initcall's deepest frames.
const CHAIN: usize = 12;
const TOP: usize = 10;

#[derive(Clone, Copy)]
struct Record {
    stage: &'static str,
    name: &'static str,
    depth: usize,
    chain: [u64; CHAIN],
}

static TOP_TEN: IrqSafeSpinLock<[Option<Record>; TOP]> = IrqSafeSpinLock::new([None; TOP]);
/// Stack pointer at the call point of the initcall in progress.
static ENTRY_SP: AtomicUsize = AtomicUsize::new(0);
static MEASURED: AtomicUsize = AtomicUsize::new(0);
/// Deepest point any initcall reached, in bytes from the init stack's top.
static PEAK_FROM_TOP: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
fn stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: reads the stack pointer register; no memory access.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: as above.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    sp
}

/// `narf_init`'s per-initcall hook (installed by `bare_main`).
pub fn hook(stage: narf_init::Stage, name: &'static str, entering: bool) {
    let Some((bottom, top)) = narf_scheduler::stackful::current_stack_range() else {
        return;
    };
    let low = bottom + CANARY_BYTES;
    if entering {
        narf_lib::sync::without_interrupts(|| {
            let sp = stack_pointer();
            ENTRY_SP.store(sp, Ordering::Relaxed);
            let high = sp.saturating_sub(MARGIN) & !7;
            let mut at = low;
            while at < high {
                // SAFETY: inside this task's own stack, below every live
                // frame (under the stack pointer, less a margin), with
                // interrupts masked so nothing else uses that space now.
                unsafe { core::ptr::write_volatile(at as *mut u64, PAINT) };
                at += 8;
            }
        });
        return;
    }
    let entry = ENTRY_SP.load(Ordering::Relaxed);
    if entry == 0 {
        return;
    }
    let word = |at: usize| -> u64 {
        // SAFETY: inside this task's own stack; read only.
        unsafe { core::ptr::read_volatile(at as *const u64) }
    };
    let mut deepest = low;
    while deepest < entry && word(deepest) == PAINT {
        deepest += 8;
    }
    let depth = entry.saturating_sub(deepest);
    MEASURED.fetch_add(1, Ordering::Relaxed);
    PEAK_FROM_TOP.fetch_max(top.saturating_sub(deepest), Ordering::Relaxed);

    // The deepest frames' stale words: keep the ones that point into the
    // kernel image, as link-time addresses.
    let (image_start, image_end) = narf_memory::kaslr::image_link_bounds();
    let base = narf_memory::kaslr::kernel_virt_base();
    // The applied slide (`kernel_slide()` draws a fresh random one).
    let slide = narf_memory::kaslr::KERNEL_SLIDE.load(Ordering::Relaxed);
    let mut chain = [0u64; CHAIN];
    let mut found = 0;
    let mut at = deepest;
    while found < CHAIN && at < entry {
        let w = word(at);
        if w >= base + image_start && w < base + image_end {
            chain[found] = w - slide;
            found += 1;
        }
        at += 8;
    }

    let record = Record {
        stage: stage.name(),
        name,
        depth,
        chain,
    };
    let mut top = TOP_TEN.lock();
    if let Some(slot) = top.iter().position(|r| r.is_none_or(|r| r.depth < depth)) {
        top.copy_within(slot..TOP - 1, slot + 1);
        top[slot] = Some(record);
    }
}

/// Deepest the init stack went across all initcalls, in bytes from its top
/// (the repainting before each initcall hides this from the stack's own
/// end-of-run scan).
pub fn peak_from_top() -> usize {
    PEAK_FROM_TOP.load(Ordering::Relaxed)
}

/// The deepest initcall measured: `(stage, name, bytes)`.
pub fn deepest() -> Option<(&'static str, &'static str, usize)> {
    TOP_TEN.lock()[0].map(|r| (r.stage, r.name, r.depth))
}

/// Print the ten deepest initcalls with the image addresses left in their
/// deepest frames (link-time values, deepest first, for `addr2line -e
/// narf-frame`).
pub fn print_top(w: &mut impl Write) {
    let top = *TOP_TEN.lock();
    let _ = writeln!(
        w,
        "  initcall stack depth, top {TOP} of {} (budget {INITCALL_STACK_BUDGET}):",
        MEASURED.load(Ordering::Relaxed)
    );
    for r in top.iter().flatten() {
        let _ = write!(w, "    {:>6}  {}/{}  deepest:", r.depth, r.stage, r.name);
        for a in r.chain.iter().filter(|a| **a != 0) {
            let _ = write!(w, " {a:#x}");
        }
        let _ = writeln!(w);
    }
}

/// Every initcall stays within [`INITCALL_STACK_BUDGET`] of stack.
#[cfg(feature = "kernel-test")]
fn smoke_initcalls_fit_their_stack_budget() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let Some((stage, name, depth)) = deepest() else {
        return TestResult::Skip("no initcall was measured on the init stack");
    };
    if depth > INITCALL_STACK_BUDGET {
        let _ = writeln!(
            narf_console::Writer,
            "  initcall {stage}/{name} used {depth} bytes of stack (budget {INITCALL_STACK_BUDGET})"
        );
        return TestResult::Fail("an initcall used more stack than its budget");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!("frame/init_stack", smoke_initcalls_fit_their_stack_budget);
