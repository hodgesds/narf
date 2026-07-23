//! Kernel Address Sanitizer (KASAN) runtime for the freed-slab-block
//! write-after-free hunt.
//!
//! Built only under the `kasan` feature, which ALSO adds
//! `-Zsanitizer=kernel-address` to the kernel target's rustflags (see
//! `.cargo/config.toml`). With that flag rustc emits an INLINE shadow check
//! before every memory access in instrumented crates:
//!
//! ```asm
//!   shr   rax, 3                     ; addr >> 3
//!   movabs rcx, 0x100000000000       ; + KASAN_SHADOW_OFFSET
//!   cmpb  [rcx], 0                   ; shadow byte 0 == fully accessible?
//!   jne   __asan_report_storeN       ; poisoned → report
//! ```
//!
//! Shadow layout (verified from the emitted codegen for
//! `x86_64-unknown-none`): `shadow(addr) = (addr >> 3) + 0x100000000000`.
//! One shadow byte covers 8 bytes of memory; `0` = all 8 accessible,
//! `0xFF` = all 8 poisoned (a partial-granule value `1..=7` means the first
//! N bytes are accessible — unused here, the slab granularity is ≥ 16 B).
//!
//! The corruptor hunt: the slab poisons a block's shadow to `0xFF` on free
//! and clears it to `0` on alloc. A dangling cross-CPU write to a freed
//! block then trips the inline check and lands in `__asan_report_storeN`,
//! whose panic backtrace names the WRITING instruction — the corruptor —
//! instead of the victim the free-block canary can only blame.
//!
//! Shadow memory is populated ON DEMAND: the first read of any shadow byte
//! faults, and the page-fault handler maps a zeroed page there (so every
//! address reads "accessible" by default), matching Linux's KASAN_VMALLOC.
//! Only freed slab blocks are ever explicitly poisoned.
#![cfg(feature = "kasan")]

use core::sync::atomic::{AtomicU64, Ordering};

/// Shadow-map base for `x86_64-unknown-none` under `-Zsanitizer=
/// kernel-address`. `shadow(addr) = (addr >> 3) + KASAN_SHADOW_OFFSET`.
/// Taken from the compiler's emitted inline check — do NOT change without
/// re-reading the codegen (`movabs` immediate in an instrumented store).
pub const KASAN_SHADOW_OFFSET: u64 = 0x1000_0000_0000;

/// Shadow-scale shift: one shadow byte per 8 memory bytes.
pub const KASAN_SHADOW_SCALE: u64 = 3;

/// Poison value written to a freed block's shadow (all 8 bytes of the
/// granule inaccessible).
const POISON_FREED: u8 = 0xFF;

/// Whether poisoning is armed. Off until `init()` has mapped the shadow for
/// the slab region, so early boot (before the shadow fault handler is live)
/// doesn't poison into unmapped shadow.
static ARMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Diagnostics: report count + last faulting (addr, rip).
static REPORTS: AtomicU64 = AtomicU64::new(0);

/// Compute the shadow byte address for a memory address.
#[inline(always)]
pub fn shadow_of(addr: u64) -> *mut u8 {
    ((addr >> KASAN_SHADOW_SCALE) + KASAN_SHADOW_OFFSET) as *mut u8
}

/// Arm KASAN poisoning. Call once at boot AFTER the shadow-fault handler is
/// installed (so a poison write into not-yet-populated shadow faults in a
/// zero page rather than triple-faulting).
pub fn arm() {
    ARMED.store(true, Ordering::Release);
}

/// Poison `[addr, addr+size)` — mark it inaccessible so any later load/store
/// through instrumented code reports. `addr` and `size` should be 8-byte
/// aligned/multiples (slab granularity is ≥ 16 B, so this holds).
///
/// # Safety
/// Writes into the shadow region, which the on-demand fault handler backs
/// with real pages. Caller passes a real kernel memory range.
#[inline]
pub unsafe fn poison(addr: u64, size: usize) {
    if !ARMED.load(Ordering::Relaxed) {
        return;
    }
    let n = size >> KASAN_SHADOW_SCALE;
    let sh = shadow_of(addr);
    // SAFETY: shadow range is fault-populated; `n` bytes cover `size` memory.
    unsafe { core::ptr::write_bytes(sh, POISON_FREED, n) };
}

/// Unpoison `[addr, addr+size)` — mark it fully accessible (shadow 0). Called
/// when a block is handed out by the slab.
///
/// # Safety
/// Same contract as [`poison`].
#[inline]
pub unsafe fn unpoison(addr: u64, size: usize) {
    if !ARMED.load(Ordering::Relaxed) {
        return;
    }
    let n = size >> KASAN_SHADOW_SCALE;
    let sh = shadow_of(addr);
    // SAFETY: shadow range is fault-populated; `n` bytes cover `size` memory.
    unsafe { core::ptr::write_bytes(sh, 0u8, n) };
}

/// Number of KASAN reports fired so far (for tests / boot digest).
pub fn report_count() -> u64 {
    REPORTS.load(Ordering::Relaxed)
}

// ── Sanitizer runtime callbacks (LLVM ASan/KASAN ABI) ───────────────
//
// The inline check jumps to `__asan_report_{load,store}{1,2,4,8,16}` (and
// the `_n` variants for odd sizes) on a poisoned access. `addr` is the
// faulting memory address; the RETURN ADDRESS on the stack is the corruptor
// instruction. We panic — NARF's panic handler walks the frame and prints
// the return addresses, so the corruptor's RIP appears in the backtrace.

#[inline(never)]
fn report(kind: &str, addr: u64) -> ! {
    REPORTS.fetch_add(1, Ordering::Relaxed);
    // Panic here: the backtrace names the caller (the corruptor). cr-style
    // free-block canary blames the victim; this blames the WRITER.
    panic!(
        "KASAN: {kind} to poisoned addr {addr:#x} (shadow {:#x} != 0) — \
         the frame above IS the use-after-free corruptor",
        shadow_of(addr) as u64,
    );
}

macro_rules! asan_report {
    ($($name:ident => ($kind:literal)),* $(,)?) => {
        $(
            #[no_mangle]
            pub extern "C" fn $name(addr: u64) -> () {
                report($kind, addr);
            }
        )*
    };
}

asan_report! {
    __asan_report_load1 => ("load1"),
    __asan_report_load2 => ("load2"),
    __asan_report_load4 => ("load4"),
    __asan_report_load8 => ("load8"),
    __asan_report_load16 => ("load16"),
    __asan_report_store1 => ("store1"),
    __asan_report_store2 => ("store2"),
    __asan_report_store4 => ("store4"),
    __asan_report_store8 => ("store8"),
    __asan_report_store16 => ("store16"),
}

#[no_mangle]
pub extern "C" fn __asan_report_load_n(addr: u64, _size: u64) {
    report("load_n", addr);
}
#[no_mangle]
pub extern "C" fn __asan_report_store_n(addr: u64, _size: u64) {
    report("store_n", addr);
}

// Outline access-check variants (emitted when instrumentation can't inline,
// e.g. dynamically-sized accesses). They perform the shadow check themselves
// and call the matching report on failure.
macro_rules! asan_check {
    ($($name:ident => ($sz:expr, $kind:literal)),* $(,)?) => {
        $(
            #[no_mangle]
            pub extern "C" fn $name(addr: u64) {
                // SAFETY: shadow is fault-populated for every address.
                let s = unsafe { *shadow_of(addr) };
                if s != 0 {
                    report($kind, addr);
                }
            }
        )*
    };
}

asan_check! {
    __asan_load1 => (1, "load1"),
    __asan_load2 => (2, "load2"),
    __asan_load4 => (4, "load4"),
    __asan_load8 => (8, "load8"),
    __asan_load16 => (16, "load16"),
    __asan_store1 => (1, "store1"),
    __asan_store2 => (2, "store2"),
    __asan_store4 => (4, "store4"),
    __asan_store8 => (8, "store8"),
    __asan_store16 => (16, "store16"),
}

#[no_mangle]
pub extern "C" fn __asan_loadN(addr: u64, _size: u64) {
    let s = unsafe { *shadow_of(addr) };
    if s != 0 {
        report("loadN", addr);
    }
}
#[no_mangle]
pub extern "C" fn __asan_storeN(addr: u64, _size: u64) {
    let s = unsafe { *shadow_of(addr) };
    if s != 0 {
        report("storeN", addr);
    }
}

// Module bring-up hooks called by the compiler-emitted `asan.module_ctor`.
// We don't track globals or run the full ASan init — no-op stubs keep the
// ctor happy.
#[no_mangle]
pub extern "C" fn __asan_init() {}
#[no_mangle]
pub extern "C" fn __asan_version_mismatch_check_v8() {}
#[no_mangle]
pub extern "C" fn __asan_handle_no_return() {}
#[no_mangle]
pub extern "C" fn __asan_register_globals(_globals: u64, _n: u64) {}
#[no_mangle]
pub extern "C" fn __asan_unregister_globals(_globals: u64, _n: u64) {}
