//! Kernel Address Sanitizer (KASAN) runtime — freed-slab-block
//! write-after-free hunt, software-shadow / outline variant.
//!
//! # Why outline + software shadow (not inline)
//!
//! `-Zsanitizer=kernel-address` normally emits an INLINE shadow check
//! (`shadow = (addr >> 3) | 0x100000000000; if *shadow != 0 { report }`).
//! That mapping is only canonical for LOW addresses: NARF reaches data both
//! through the low identity map (phys == VA) AND the high-half kernel image
//! (globals via RIP-relative, image-resident stacks), and no single linear
//! shadow offset keeps both halves canonical — a high-half `addr >> 3 ≈ 2⁶¹`
//! ORed with the offset is non-canonical and faults `#GP`.
//!
//! So the build forces OUTLINE instrumentation
//! (`-asan-instrumentation-with-call-threshold=0`, see `build/xtask`): every
//! instrumented access calls `__asan_{load,store}N` with the RAW address, and
//! we resolve the shadow in software here. Only the low identity map matters —
//! freed slab blocks are heap objects (phys == VA, `< ram_top`); every other
//! address (high-half image, MMIO, user) is skipped as "accessible".
//!
//! # Shadow
//!
//! A flat byte array covering `[0, ram_top)` at 1 byte / 8 memory bytes,
//! physically reserved out of the buddy at boot and identity-mapped. `0` =
//! accessible, `0xFF` = poisoned. The slab poisons a block's shadow on free
//! and clears it on alloc; a dangling write from *instrumented* (non-slab)
//! code then trips the outline check, whose panic backtrace names the WRITING
//! frame — the corruptor — instead of the victim the free-block canary blames.
//!
//! # Self-instrumentation
//!
//! Every function here is `#[sanitize(address = "off")]`: the callbacks READ
//! the shadow, and if those reads were themselves instrumented each shadow
//! read would re-enter `__asan_loadN` → unbounded recursion. The slab module
//! is likewise exempt (`memory/src/slab.rs`) so its intrusive free-list /
//! canary writes into freed blocks don't self-report.
#![cfg(feature = "kasan")]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One shadow byte per 8 memory bytes.
pub const KASAN_SHADOW_SCALE: u64 = 3;

/// Poison value written to a freed block's shadow (all 8 bytes of the granule
/// inaccessible).
const POISON_FREED: u8 = 0xFF;

/// VA of `shadow[0]`. Zero until [`init`] runs; a zero base makes every check
/// a no-op (so instrumented code that runs before the shadow exists is safe).
static SHADOW_BASE: AtomicU64 = AtomicU64::new(0);

/// Exclusive top of the tracked (low identity) address range. Addresses `>=`
/// this are skipped — they can't be slab blocks.
static RAM_TOP: AtomicU64 = AtomicU64::new(0);

/// Poisoning + checking armed. Off until the shadow is mapped AND zeroed.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Report count (boot digest / tests).
static REPORTS: AtomicU64 = AtomicU64::new(0);

/// Shadow byte address for `addr`, or null if `addr` is outside the tracked
/// range (high-half image, MMIO, user, or shadow-not-yet-mapped).
#[sanitize(address = "off")]
#[inline(never)]
fn shadow_slot(addr: u64) -> *mut u8 {
    let base = SHADOW_BASE.load(Ordering::Relaxed);
    if base == 0 || addr >= RAM_TOP.load(Ordering::Relaxed) {
        return core::ptr::null_mut();
    }
    (base + (addr >> KASAN_SHADOW_SCALE)) as *mut u8
}

/// Record the shadow region and zero it. `shadow_base` must point at
/// `ram_top >> 3` bytes of writable, identity-mapped memory reserved out of
/// the frame allocator. Call once at boot after the MMU is live; follow with
/// [`arm`].
///
/// # Safety
/// `[shadow_base, shadow_base + (ram_top >> 3))` must be a valid, exclusively
/// owned, writable kernel mapping.
#[sanitize(address = "off")]
pub unsafe fn init(ram_top: u64, shadow_base: u64) {
    let len = (ram_top >> KASAN_SHADOW_SCALE) as usize;
    // SAFETY: caller guarantees the reserved shadow span is writable.
    unsafe { core::ptr::write_bytes(shadow_base as *mut u8, 0u8, len) };
    RAM_TOP.store(ram_top, Ordering::Release);
    SHADOW_BASE.store(shadow_base, Ordering::Release);
}

/// Arm poisoning + checking. Call once, after [`init`].
#[sanitize(address = "off")]
pub fn arm() {
    ARMED.store(true, Ordering::Release);
}

/// True once [`arm`] has run.
#[sanitize(address = "off")]
pub fn is_armed() -> bool {
    ARMED.load(Ordering::Relaxed)
}

/// Poison `[addr, addr+size)` — mark it inaccessible. `size` is rounded down
/// to the 8-byte granule (slab classes are ≥ 16 B, so this is exact).
///
/// # Safety
/// `addr` names real kernel memory; the shadow span is mapped (post-[`init`]).
#[sanitize(address = "off")]
#[inline]
pub unsafe fn poison(addr: u64, size: usize) {
    if !ARMED.load(Ordering::Relaxed) {
        return;
    }
    let sh = shadow_slot(addr);
    if sh.is_null() {
        return;
    }
    // SAFETY: shadow span is mapped; `n` bytes cover `size` memory bytes and
    // stay within the reserved shadow region (addr < ram_top).
    unsafe { core::ptr::write_bytes(sh, POISON_FREED, size >> KASAN_SHADOW_SCALE) };
}

/// Unpoison `[addr, addr+size)` — mark it accessible. Called when the slab
/// hands a block out.
///
/// # Safety
/// Same contract as [`poison`].
#[sanitize(address = "off")]
#[inline]
pub unsafe fn unpoison(addr: u64, size: usize) {
    if !ARMED.load(Ordering::Relaxed) {
        return;
    }
    let sh = shadow_slot(addr);
    if sh.is_null() {
        return;
    }
    // SAFETY: as in `poison`.
    unsafe { core::ptr::write_bytes(sh, 0u8, size >> KASAN_SHADOW_SCALE) };
}

/// Number of KASAN reports fired so far.
#[sanitize(address = "off")]
pub fn report_count() -> u64 {
    REPORTS.load(Ordering::Relaxed)
}

// ── The check + report ──────────────────────────────────────────────

/// Panic naming the faulting access. Disarms first so the panic path (which
/// is instrumented) can't recursively re-report if it touches poisoned bytes.
#[sanitize(address = "off")]
#[inline(never)]
#[cold]
fn report(kind: &str, addr: u64, size: u64) -> ! {
    ARMED.store(false, Ordering::Release);
    REPORTS.fetch_add(1, Ordering::Relaxed);
    panic!(
        "KASAN: {kind} of {size} byte(s) at poisoned addr {addr:#x} — \
         the frame ABOVE this panic is the use-after-free corruptor"
    );
}

/// The one check both the store callbacks and (optionally) load callbacks run.
#[sanitize(address = "off")]
#[inline(never)]
fn check(kind: &str, addr: u64, size: u64) {
    // Fast path: unarmed or out-of-range → nothing. Ordering::Relaxed is fine;
    // arm() happens-before any poison so a visible poison implies visible arm.
    if !ARMED.load(Ordering::Relaxed) {
        return;
    }
    let sh = shadow_slot(addr);
    if sh.is_null() {
        return;
    }
    // SAFETY: shadow span is mapped for every addr < ram_top.
    if unsafe { *sh } != 0 {
        report(kind, addr, size);
    }
}

// ── Sanitizer runtime callbacks (LLVM ASan/KASAN ABI) ───────────────
//
// Under `-asan-instrumentation-with-call-threshold=0` the compiler emits a
// call to one of these before every instrumented access, passing the RAW
// memory address (the `N` forms also pass the size). We check STORES — the
// corruptor is a write — and let LOADS pass (halves the overhead and keeps the
// hunt focused on the write-after-free).

macro_rules! asan_store {
    ($($name:ident => $sz:literal),* $(,)?) => {
        $(
            #[no_mangle]
            #[sanitize(address = "off")]
            pub extern "C" fn $name(addr: u64) {
                check("store", addr, $sz);
            }
        )*
    };
}
macro_rules! asan_load {
    ($($name:ident),* $(,)?) => {
        $(
            #[no_mangle]
            #[sanitize(address = "off")]
            pub extern "C" fn $name(_addr: u64) {}
        )*
    };
}

asan_store! {
    __asan_store1 => 1, __asan_store2 => 2, __asan_store4 => 4,
    __asan_store8 => 8, __asan_store16 => 16,
}
asan_load! {
    __asan_load1, __asan_load2, __asan_load4, __asan_load8, __asan_load16,
}

#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_storeN(addr: u64, size: u64) {
    check("store", addr, size);
}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_loadN(_addr: u64, _size: u64) {}

// Inline-check report entry points. Outline mode emits none of these (the
// check lives in the `__asan_{load,store}N` bodies above), but keep them so a
// stray inline check from build-std can't leave an undefined symbol; each just
// reports its poisoned address.
macro_rules! asan_report {
    ($($name:ident => $sz:literal),* $(,)?) => {
        $(
            #[no_mangle]
            #[sanitize(address = "off")]
            pub extern "C" fn $name(addr: u64) {
                report("store", addr, $sz);
            }
        )*
    };
}
asan_report! {
    __asan_report_store1 => 1, __asan_report_store2 => 2, __asan_report_store4 => 4,
    __asan_report_store8 => 8, __asan_report_store16 => 16,
    __asan_report_load1 => 1, __asan_report_load2 => 2, __asan_report_load4 => 4,
    __asan_report_load8 => 8, __asan_report_load16 => 16,
}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_report_store_n(addr: u64, size: u64) {
    report("store", addr, size);
}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_report_load_n(addr: u64, size: u64) {
    report("load", addr, size);
}

// Module bring-up hooks the compiler-emitted `asan.module_ctor` calls. We run
// no global-redzone tracking, so these are no-ops.
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_init() {}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_version_mismatch_check_v8() {}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_handle_no_return() {}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_register_globals(_globals: u64, _n: u64) {}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_unregister_globals(_globals: u64, _n: u64) {}

/// Test-only: would an instrumented access to `addr` report right now? A
/// non-panicking mirror of [`check`]'s decision, so a self-test can exercise
/// the poison → shadow → decision path without tripping the panic.
#[sanitize(address = "off")]
pub fn _would_report(addr: u64) -> bool {
    if !ARMED.load(Ordering::Relaxed) {
        return false;
    }
    let sh = shadow_slot(addr);
    // SAFETY: shadow span is mapped for every addr < ram_top; null otherwise.
    !sh.is_null() && unsafe { *sh } != 0
}

/// Poison → check → unpoison round-trip over a real low-identity heap block:
/// the flat software shadow must read poisoned after `poison`, clear after
/// `unpoison`, and a high-half kernel address must never be tracked. Only
/// present in `kasan` builds (the whole module is feature-gated).
fn smoke_kasan_poison_roundtrip() -> narf_kernel_test::TestResult {
    use alloc::boxed::Box;
    use narf_kernel_test::TestResult;
    if !is_armed() {
        return TestResult::Skip("kasan not armed");
    }
    // A heap block is a low-identity address (phys == VA) → tracked range. The
    // slab already unpoisoned it on alloc, so it must read accessible.
    let b = Box::new([0u8; 32]);
    let addr = b.as_ptr() as u64;
    if _would_report(addr) {
        return TestResult::Fail("fresh alloc reads poisoned");
    }
    // SAFETY: `b` is a live 32-byte block; poisoning touches only the shadow
    // view, not the bytes, and we unpoison before every return + drop.
    unsafe { poison(addr, 32) };
    if !_would_report(addr) {
        unsafe { unpoison(addr, 32) };
        return TestResult::Fail("poison did not set shadow");
    }
    // SAFETY: same block.
    unsafe { unpoison(addr, 32) };
    if _would_report(addr) {
        return TestResult::Fail("unpoison did not clear shadow");
    }
    // High-half kernel addresses are outside the tracked range → never report.
    if _would_report(0xffff_ffff_8010_0000) {
        return TestResult::Fail("high-half addr tracked");
    }
    drop(b);
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("memory", smoke_kasan_poison_roundtrip);
