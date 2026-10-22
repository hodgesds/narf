//! Page Attribute Table (PAT) — per-page memory-type selection.
//!
//! Reference: **Intel SDM Vol 3 §12.12** ("Page Attribute Table").
//! AMD APM Vol 2 §7.8 matches. The boot/CPU sequencing mirrors Linux
//! `arch/x86/mm/pat/memtype.c` (`pat_bp_init`, `pat_cpu_init`,
//! `init_cache_modes`) and `arch/x86/kernel/cpu/cacheinfo.c`
//! (`cache_disable`, `cache_enable`, `cache_cpu_init`).
//!
//! ## PTE → PAT index decoding
//!
//! The PAT entry selector for a leaf is a 3-bit index:
//!
//! ```text
//!   index = (PTE.PAT << 2) | (PTE.PCD << 1) | PTE.PWT
//! ```
//!
//! - `PTE.PWT` = bit 3 (Write-Through)
//! - `PTE.PCD` = bit 4 (Cache-Disable)
//! - `PTE.PAT` = bit 7 for 4 KiB pages, bit 12 for 2 MiB / 1 GiB
//!   pages (since bit 7 is `HUGE_PAGE` for big pages)
//!
//! Each `IA32_PAT` entry is a 3-bit memory-type code:
//!   0 = UC, 1 = WC, 4 = WT, 5 = WP, 6 = WB, 7 = UC-
//!
//! ## NARF layout (= Linux `pat_bp_init`, full-PAT branch)
//!
//! ```text
//!   PAT|PCD|PWT  slot  type
//!   0   0   0    0     WB   (default, every pre-PAT mapping)
//!   0   0   1    1     WC
//!   0   1   0    2     UC-
//!   0   1   1    3     UC
//!   1   0   0    4     WB   (reserved)
//!   1   0   1    5     WP
//!   1   1   0    6     UC-  (reserved)
//!   1   1   1    7     WT
//! ```
//!
//! WT sits in slot 7 so a CPU erratum that ignores the PAT bit lands on
//! slot 3 (UC): slower, never less ordered. Intel Pentium 4 / Pentium M
//! parts with the upper-four-entries erratum get Linux's reduced layout
//! `WB, WC, UC-, UC, WB, WC, UC-, UC` instead. When the CPU has no PAT, or
//! firmware left `IA32_PAT` at zero, PAT stays disabled and the cache-mode
//! table emulates the PWT/PCD-only reset layout `WB, WT, UC-, UC` — exactly
//! Linux's `pat_disable` path.
//!
//! ## Cache-mode → PTE table
//!
//! [`cachemode2pte`] answers which PWT/PCD/PAT bits select a requested
//! [`CacheMode`] under the *programmed* layout (Linux
//! `__cachemode2pte_tbl`, filled by `init_cache_modes`). A mode the layout
//! does not contain falls back to UC- (PCD), never to something more
//! cacheable than requested. WB is always "no bits": slot 0 is WB in every
//! layout, so default mappings are bit-identical whatever PAT does.

#![cfg(target_arch = "x86_64")]

use core::arch::asm;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, AtomicU8, Ordering};

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr_or_gp};

/// MSR index for `IA32_PAT`.
pub const MSR_IA32_PAT: u32 = 0x277;

/// Memory-type codes for PAT entries (Intel SDM Vol 3 §12.12.4).
pub mod ty {
    pub const UC: u8 = 0x00;
    pub const WC: u8 = 0x01;
    pub const WT: u8 = 0x04;
    pub const WP: u8 = 0x05;
    pub const WB: u8 = 0x06;
    pub const UC_MINUS: u8 = 0x07;
}

/// PTE bit PWT (bit 3, 4 KiB and large leaves alike).
pub const PTE_PWT: u64 = 1 << 3;
/// PTE bit PCD (bit 4, 4 KiB and large leaves alike).
pub const PTE_PCD: u64 = 1 << 4;
/// PAT bit of a 4 KiB PTE (bit 7). Linux `_PAGE_PAT`.
pub const PTE_PAT_4K: u64 = 1 << 7;
/// PAT bit of a 2 MiB / 1 GiB leaf (bit 12). Linux `_PAGE_PAT_LARGE`.
pub const PTE_PAT_LARGE: u64 = 1 << 12;

/// Linux `enum page_cache_mode`: the memory types a mapping can ask for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheMode {
    Wb = 0,
    Wc = 1,
    UcMinus = 2,
    Uc = 3,
    Wt = 4,
    Wp = 5,
}

impl CacheMode {
    pub const ALL: [CacheMode; 6] = [
        CacheMode::Wb,
        CacheMode::Wc,
        CacheMode::UcMinus,
        CacheMode::Uc,
        CacheMode::Wt,
        CacheMode::Wp,
    ];

    /// Linux `pat_get_cache_mode`: the cache mode a PAT type code selects.
    pub const fn from_pat_type(code: u8) -> Option<CacheMode> {
        match code {
            ty::UC => Some(CacheMode::Uc),
            ty::WC => Some(CacheMode::Wc),
            ty::WT => Some(CacheMode::Wt),
            ty::WP => Some(CacheMode::Wp),
            ty::WB => Some(CacheMode::Wb),
            ty::UC_MINUS => Some(CacheMode::UcMinus),
            _ => None,
        }
    }
}

/// `true` iff PAT is supported (per `CPUID.01h:EDX[16]`).
pub fn supported() -> bool {
    // SAFETY: leaf 1 is always defined on long-mode x86_64.
    let (_, _, _, edx) = unsafe { cpuid(1, 0) };
    edx & (1 << 16) != 0
}

/// `CPUID.01h:EDX[27]` SS: caches snoop themselves, so the WBINVD in the
/// cache-disable sequence is unnecessary (Linux `maybe_flush_caches`).
fn self_snoop() -> bool {
    // SAFETY: leaf 1 is always defined on long-mode x86_64.
    let (_, _, _, edx) = unsafe { cpuid(1, 0) };
    edx & (1 << 27) != 0
}

/// Build the 8-byte PAT value from the eight PA entry type codes
/// (`pa[0]` = PA0 type, in the low byte). Encoded as one u64 — that's
/// exactly the `IA32_PAT` MSR layout. Linux `PAT_VALUE`.
pub const fn encode(pa: [u8; 8]) -> u64 {
    (pa[0] as u64)
        | (pa[1] as u64) << 8
        | (pa[2] as u64) << 16
        | (pa[3] as u64) << 24
        | (pa[4] as u64) << 32
        | (pa[5] as u64) << 40
        | (pa[6] as u64) << 48
        | (pa[7] as u64) << 56
}

/// The PAT type code in slot `index` (0..8) of an `IA32_PAT` value.
pub const fn slot_type(pat: u64, index: u32) -> u8 {
    ((pat >> (index * 8)) & 0x7) as u8
}

/// Linux's full-PAT layout: `PAT_VALUE(WB, WC, UC_MINUS, UC, WB, WP, UC_MINUS, WT)`.
pub const NARF_PAT: u64 = encode([
    ty::WB,
    ty::WC,
    ty::UC_MINUS,
    ty::UC,
    ty::WB,
    ty::WP,
    ty::UC_MINUS,
    ty::WT,
]);

/// Linux's layout for CPUs whose upper four PAT entries are unusable
/// (Pentium Pro .. Pentium M, Pentium 4): the PAT bit is never relied on.
pub const NARF_PAT_ERRATA: u64 = encode([
    ty::WB,
    ty::WC,
    ty::UC_MINUS,
    ty::UC,
    ty::WB,
    ty::WC,
    ty::UC_MINUS,
    ty::UC,
]);

/// The table emulated when PAT is disabled: PWT/PCD only, the hardware
/// reset layout. Linux `PAT_VALUE(WB, WT, UC_MINUS, UC, WB, WT, UC_MINUS, UC)`.
pub const PAT_DISABLED_EMULATION: u64 = encode([
    ty::WB,
    ty::WT,
    ty::UC_MINUS,
    ty::UC,
    ty::WB,
    ty::WT,
    ty::UC_MINUS,
    ty::UC,
]);

/// The value every CPU programs (Linux `pat_msr_val`). Zero until
/// [`bp_init`] decided to enable PAT.
static PAT_MSR_VAL: AtomicU64 = AtomicU64::new(0);
/// Linux `memory_caching_control & CACHE_PAT`.
static PAT_ENABLED: AtomicBool = AtomicBool::new(false);
/// `IA32_PAT` read back on each CPU right after its [`cpu_init`]; 0 for a
/// CPU that never ran it. Evidence that APs, not just the boot CPU, carry
/// the layout the page tables assume.
static CPU_PAT: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];

/// Linux `__cachemode2pte_tbl` default: before `init_cache_modes` runs, and
/// for any mode the programmed layout lacks, WC/WT/WP/UC- all degrade to
/// UC- (PCD) and UC is PCD|PWT. Never more cacheable than requested.
const fn default_pte_bits(mode: CacheMode) -> u8 {
    match mode {
        CacheMode::Wb => 0,
        CacheMode::Uc => (PTE_PWT | PTE_PCD) as u8,
        CacheMode::Wc | CacheMode::UcMinus | CacheMode::Wt | CacheMode::Wp => PTE_PCD as u8,
    }
}

static CACHEMODE2PTE: [AtomicU8; 6] = [
    AtomicU8::new(default_pte_bits(CacheMode::Wb)),
    AtomicU8::new(default_pte_bits(CacheMode::Wc)),
    AtomicU8::new(default_pte_bits(CacheMode::UcMinus)),
    AtomicU8::new(default_pte_bits(CacheMode::Uc)),
    AtomicU8::new(default_pte_bits(CacheMode::Wt)),
    AtomicU8::new(default_pte_bits(CacheMode::Wp)),
];

/// Linux `__cm_idx2pte`: the 4 KiB PTE bits selecting PAT slot `index`.
pub const fn idx2pte(index: u32) -> u64 {
    (if index & 1 != 0 { PTE_PWT } else { 0 })
        | (if index & 2 != 0 { PTE_PCD } else { 0 })
        | (if index & 4 != 0 { PTE_PAT_4K } else { 0 })
}

/// Pure form of Linux `init_cache_modes`: the 4 KiB PTE bits for `mode`
/// under the PAT value `pat`. Slots are scanned 7 → 0 so the lowest slot
/// holding a type wins, as in Linux; a mode no slot holds keeps the
/// conservative default.
pub const fn pte_bits_for(pat: u64, mode: CacheMode) -> u64 {
    let mut result = default_pte_bits(mode) as u64;
    let mut i: i32 = 7;
    while i >= 0 {
        if let Some(found) = CacheMode::from_pat_type(slot_type(pat, i as u32)) {
            if found as u8 == mode as u8 {
                result = idx2pte(i as u32);
            }
        }
        i -= 1;
    }
    result
}

fn init_cache_modes(pat: u64) {
    for mode in CacheMode::ALL {
        CACHEMODE2PTE[mode as usize].store(pte_bits_for(pat, mode) as u8, Ordering::Release);
    }
}

/// Linux `cachemode2protval` for a **4 KiB** leaf: the PWT/PCD/PAT(bit 7)
/// bits that select `mode` under the layout this kernel programmed. Large
/// leaves move bit 7 to bit 12 ([`protval_4k_2_large`]).
#[inline]
pub fn cachemode2pte(mode: CacheMode) -> u64 {
    CACHEMODE2PTE[mode as usize].load(Ordering::Acquire) as u64
}

/// Linux `protval_4k_2_large`: move the 4 KiB PAT bit (7) to the large-leaf
/// PAT bit (12). Bits other than 7 and 12 pass through unchanged.
#[inline]
pub const fn protval_4k_2_large(bits: u64) -> u64 {
    (bits & !(PTE_PAT_4K | PTE_PAT_LARGE)) | ((bits & PTE_PAT_4K) << 5)
}

/// Linux `protval_large_2_4k`: the inverse of [`protval_4k_2_large`].
#[inline]
pub const fn protval_large_2_4k(bits: u64) -> u64 {
    (bits & !(PTE_PAT_4K | PTE_PAT_LARGE)) | ((bits & PTE_PAT_LARGE) >> 5)
}

/// Whether [`bp_init`] enabled PAT (Linux `pat_enabled()`).
pub fn enabled() -> bool {
    PAT_ENABLED.load(Ordering::Acquire)
}

/// The `IA32_PAT` value every CPU is programmed with; 0 when disabled.
pub fn programmed_value() -> u64 {
    PAT_MSR_VAL.load(Ordering::Acquire)
}

/// Read the currently-programmed `IA32_PAT`.
pub fn read() -> u64 {
    // SAFETY: PAT is unconditional on long-mode x86_64; rdmsr is
    // always legal at CPL=0.
    unsafe { rdmsr(MSR_IA32_PAT) }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PatError {
    /// The CPU has no PAT, or firmware left `IA32_PAT` zero; PAT is
    /// disabled and WC requests degrade to UC- (Linux `pat_disable`).
    Disabled,
    /// PAT is enabled on the boot CPU but this CPU cannot take it — the
    /// case Linux `pat_cpu_init` panics on.
    UnsupportedOnThisCpu,
    /// `WRMSR IA32_PAT` raised #GP.
    WriteFaulted,
    /// Hardware did not retain the requested layout.
    ReadbackMismatch,
}

/// Linux `pat_bp_init` errata check: Intel Pentium Pro .. Pentium M
/// (family 6, models 1..=0xD) and Pentium 4 Willamette .. Cedar Mill
/// (family 15, models 0..=6).
fn upper_pat_entries_unusable() -> bool {
    let id = crate::x86_64::ident::read();
    if id.vendor != crate::x86_64::ident::Vendor::Intel {
        return false;
    }
    (id.family == 6 && (1..=0xD).contains(&id.model)) || (id.family == 15 && id.model <= 6)
}

/// Linux `pat_bp_init` + the boot CPU's `cache_cpu_init`.
///
/// Decides the layout once, fills the cache-mode table, and programs the
/// boot CPU. Application processors then call [`cpu_init`].
///
/// # Safety
/// CPL=0, boot CPU, before any application processor is started and
/// before any mapping selects a PAT slot other than 0.
pub unsafe fn bp_init() -> Result<(), PatError> {
    let firmware = if supported() { read() } else { 0 };
    if firmware == 0 {
        PAT_ENABLED.store(false, Ordering::Release);
        PAT_MSR_VAL.store(0, Ordering::Release);
        init_cache_modes(PAT_DISABLED_EMULATION);
        return Err(PatError::Disabled);
    }
    let value = if upper_pat_entries_unusable() {
        NARF_PAT_ERRATA
    } else {
        NARF_PAT
    };
    PAT_MSR_VAL.store(value, Ordering::Release);
    PAT_ENABLED.store(true, Ordering::Release);
    init_cache_modes(value);
    // SAFETY: forwarded boot-CPU contract.
    unsafe { cpu_init() }
}

/// RAII state for the SDM §12.11.8 cache-disable window.
struct CacheDisabled {
    cr4: u64,
    flush_caches: bool,
}

#[inline]
unsafe fn wbinvd() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: WBINVD is legal at CPL=0; it writes back and invalidates the
    // caches and has no register operands.
    unsafe { asm!("wbinvd", options(nostack, preserves_flags)) };
    compiler_fence(Ordering::SeqCst);
}

/// Local TLB flush of the current context, as Linux `flush_tlb_local`.
#[inline]
unsafe fn flush_tlb_local() {
    // SAFETY: rewriting the live CR3 value (PCID bits included, bit 63
    // clear) only invalidates this context's non-global translations.
    unsafe { crate::x86_64::cr::write_cr3(crate::x86_64::cr::read_cr3() & !(1 << 63)) };
}

/// Linux `native_flush_tlb_global`: toggling CR4.PGE invalidates every TLB
/// entry, global ones included, for every PCID.
#[inline]
unsafe fn flush_tlb_all_local() {
    use crate::x86_64::cr::{read_cr4, write_cr4, CR4_PGE};
    // SAFETY: each write differs from the previous value only in PGE.
    unsafe {
        let cr4 = read_cr4();
        write_cr4(cr4 ^ CR4_PGE);
        write_cr4(cr4);
    }
}

/// Linux `cache_disable`: enter no-fill mode (CD=1, NW=0), flush caches,
/// clear CR4.PGE (flushing global translations) and flush the TLB.
unsafe fn cache_disable() -> CacheDisabled {
    use crate::x86_64::cr::{read_cr0, read_cr4, write_cr0, write_cr4, CR0_CD, CR0_NW, CR4_PGE};
    let flush_caches = !self_snoop();
    // SAFETY: CPL=0, IRQs masked by the caller; the sequence is SDM
    // Vol 3 §12.11.8 steps 1-5.
    unsafe {
        write_cr0((read_cr0() | CR0_CD) & !CR0_NW);
        if flush_caches {
            wbinvd();
        }
        let cr4 = read_cr4();
        if cr4 & CR4_PGE != 0 {
            write_cr4(cr4 & !CR4_PGE);
        }
        flush_tlb_local();
        if flush_caches {
            wbinvd();
        }
        CacheDisabled { cr4, flush_caches }
    }
}

/// Linux `cache_enable`: flush the TLB, re-enable caches, restore CR4.PGE.
unsafe fn cache_enable(state: CacheDisabled) {
    use crate::x86_64::cr::{read_cr0, write_cr0, write_cr4, CR0_CD, CR4_PGE};
    let _ = state.flush_caches;
    // SAFETY: closes the window `cache_disable` opened on this CPU.
    unsafe {
        flush_tlb_local();
        write_cr0(read_cr0() & !CR0_CD);
        if state.cr4 & CR4_PGE != 0 {
            write_cr4(state.cr4);
        }
    }
}

/// Linux `pat_cpu_init` (reached through `cache_cpu_init`): program this
/// CPU's `IA32_PAT` with the value [`bp_init`] chose.
///
/// The write is bracketed by the SDM §12.11.8 sequence — CR0.CD=1,
/// WBINVD (skipped on self-snooping CPUs), CR4.PGE cleared and the TLB
/// flushed, the MSR write, WBINVD, TLB flush, CR0.CD=0, PGE restored — with
/// interrupts masked, then followed by Linux's `__flush_tlb_all`, so no
/// cache line or TLB entry filled under the old layout survives it.
///
/// A no-op returning `Ok` while PAT is disabled. Every CPU — boot, each AP,
/// and the boot CPU again after S3 (Linux `cache_bp_restore`) — calls this.
///
/// # Safety
/// CPL=0 on the CPU being programmed, which must not yet be running
/// scheduler work that maps memory with a non-zero PAT slot.
pub unsafe fn cpu_init() -> Result<(), PatError> {
    if !enabled() {
        return Ok(());
    }
    if !supported() {
        return Err(PatError::UnsupportedOnThisCpu);
    }
    let value = programmed_value();
    let irqs_were_on = crate::x86_64::asm::interrupts_enabled();
    // SAFETY: CPL=0. IRQs are masked across the whole cache-disable window
    // (Linux `local_irq_save` in `cache_cpu_init`).
    unsafe {
        crate::x86_64::asm::disable_interrupts();
        let state = cache_disable();
        let written = wrmsr_or_gp(MSR_IA32_PAT, value);
        cache_enable(state);
        flush_tlb_all_local();
        if irqs_were_on {
            crate::x86_64::asm::enable_interrupts();
        }
        written.map_err(|_| PatError::WriteFaulted)?;
    }
    let live = read();
    if live != value {
        return Err(PatError::ReadbackMismatch);
    }
    let cpu = crate::current_cpu_id().raw() as usize;
    if let Some(slot) = CPU_PAT.get(cpu) {
        slot.store(live, Ordering::Release);
    }
    Ok(())
}

/// `IA32_PAT` as read back on `cpu` after its last [`cpu_init`], or 0 if
/// that CPU never programmed PAT.
pub fn recorded_cpu_value(cpu: usize) -> u64 {
    CPU_PAT
        .get(cpu)
        .map_or(0, |slot| slot.load(Ordering::Acquire))
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pat_encode_round_trips() -> TestResult {
        let v = encode([
            ty::WB,
            ty::WC,
            ty::UC_MINUS,
            ty::UC,
            ty::WB,
            ty::WP,
            ty::UC_MINUS,
            ty::WT,
        ]);
        for (i, want) in [
            ty::WB,
            ty::WC,
            ty::UC_MINUS,
            ty::UC,
            ty::WB,
            ty::WP,
            ty::UC_MINUS,
            ty::WT,
        ]
        .into_iter()
        .enumerate()
        {
            if slot_type(v, i as u32) != want {
                return TestResult::Fail("encode/slot_type disagree");
            }
        }
        TestResult::Pass
    }

    /// The constant is exactly Linux's full-PAT `pat_msr_val`.
    fn smoke_pat_narf_layout_is_linux() -> TestResult {
        // PAT_VALUE(WB, WC, UC_MINUS, UC, WB, WP, UC_MINUS, WT)
        if NARF_PAT != 0x0407_0506_0007_0106 {
            return TestResult::Fail("NARF_PAT is not Linux's full-PAT layout");
        }
        if NARF_PAT_ERRATA != 0x0007_0106_0007_0106 {
            return TestResult::Fail("NARF_PAT_ERRATA is not Linux's reduced layout");
        }
        if PAT_DISABLED_EMULATION != 0x0007_0406_0007_0406 {
            return TestResult::Fail("disabled emulation is not the reset layout");
        }
        TestResult::Pass
    }

    /// `init_cache_modes` on each layout gives Linux's encodings.
    fn smoke_pat_cachemode_tables() -> TestResult {
        let full = |m| pte_bits_for(NARF_PAT, m);
        if full(CacheMode::Wb) != 0
            || full(CacheMode::Wc) != PTE_PWT
            || full(CacheMode::UcMinus) != PTE_PCD
            || full(CacheMode::Uc) != PTE_PCD | PTE_PWT
            || full(CacheMode::Wp) != PTE_PAT_4K | PTE_PWT
            || full(CacheMode::Wt) != PTE_PAT_4K | PTE_PCD | PTE_PWT
        {
            return TestResult::Fail("full layout cache-mode bits wrong");
        }
        let errata = |m| pte_bits_for(NARF_PAT_ERRATA, m);
        if errata(CacheMode::Wc) != PTE_PWT
            || errata(CacheMode::Wt) != PTE_PCD
            || errata(CacheMode::Wp) != PTE_PCD
        {
            return TestResult::Fail("errata layout must not use the PAT bit");
        }
        let off = |m| pte_bits_for(PAT_DISABLED_EMULATION, m);
        if off(CacheMode::Wb) != 0 || off(CacheMode::Wc) != PTE_PCD || off(CacheMode::Wt) != PTE_PWT
        {
            return TestResult::Fail("disabled layout: WC must degrade to UC-, WT is PWT");
        }
        // WB is "no bits" under every layout: default leaves never change.
        for pat in [NARF_PAT, NARF_PAT_ERRATA, PAT_DISABLED_EMULATION] {
            if pte_bits_for(pat, CacheMode::Wb) != 0 {
                return TestResult::Fail("WB selected a non-zero slot");
            }
        }
        TestResult::Pass
    }

    fn smoke_pat_large_bit_moves() -> TestResult {
        let wt = PTE_PAT_4K | PTE_PCD | PTE_PWT;
        if protval_4k_2_large(wt) != PTE_PAT_LARGE | PTE_PCD | PTE_PWT {
            return TestResult::Fail("4K->large did not move PAT to bit 12");
        }
        if protval_large_2_4k(protval_4k_2_large(wt)) != wt {
            return TestResult::Fail("large->4K is not the inverse");
        }
        if protval_4k_2_large(PTE_PWT) != PTE_PWT {
            return TestResult::Fail("4K->large touched a bit other than PAT");
        }
        TestResult::Pass
    }

    /// The *live* `IA32_PAT` on this CPU is the value `bp_init` chose.
    ///
    /// The constant tests prove the table is well-formed and nothing about
    /// the CPU: if `cpu_init` never ran here — the AP gap this replaced —
    /// PA1 keeps its reset value WT and every WC mapping silently becomes
    /// write-through. Only the MSR itself is evidence.
    fn smoke_pat_live_msr_matches_programmed() -> TestResult {
        if !enabled() {
            return TestResult::Skip("PAT disabled on this machine");
        }
        if read() != programmed_value() {
            return TestResult::Fail("live IA32_PAT differs from the programmed value");
        }
        if slot_type(read(), 0) != ty::WB || slot_type(read(), 1) != ty::WC {
            return TestResult::Fail("live IA32_PAT PA0/PA1 is not WB/WC");
        }
        if cachemode2pte(CacheMode::Wc) != PTE_PWT || cachemode2pte(CacheMode::Wb) != 0 {
            return TestResult::Fail("live cache-mode table disagrees with the layout");
        }
        TestResult::Pass
    }

    /// Every online CPU — each AP as well as the boot CPU — programmed the
    /// same layout. PAT is per logical processor; a CPU that skipped
    /// `cpu_init` would decode the shared page tables' PWT bit as WT while
    /// its peers decode WC, aliasing one page under two memory types.
    fn smoke_pat_every_online_cpu_programmed() -> TestResult {
        if !enabled() {
            return TestResult::Skip("PAT disabled on this machine");
        }
        let want = programmed_value();
        for cpu in 0..narf_lib::percpu::MAX_CPUS {
            if narf_lib::smp::is_online(cpu as u32) && recorded_cpu_value(cpu) != want {
                return TestResult::Fail("an online CPU did not program IA32_PAT");
            }
        }
        TestResult::Pass
    }

    /// Re-running `cpu_init` (the S3 / hot-add path) is idempotent.
    fn smoke_pat_cpu_init_is_idempotent() -> TestResult {
        if !enabled() {
            return TestResult::Skip("PAT disabled on this machine");
        }
        let before = read();
        // SAFETY: CPL=0; rewrites the identical value under the full SDM
        // sequence, so no live mapping changes type.
        if unsafe { cpu_init() }.is_err() {
            return TestResult::Fail("cpu_init failed on a PAT-capable CPU");
        }
        if read() != before {
            return TestResult::Fail("cpu_init changed IA32_PAT");
        }
        TestResult::Pass
    }

    kernel_test_in!("arch/pat", smoke_pat_encode_round_trips);
    kernel_test_in!("arch/pat", smoke_pat_narf_layout_is_linux);
    kernel_test_in!("arch/pat", smoke_pat_cachemode_tables);
    kernel_test_in!("arch/pat", smoke_pat_large_bit_moves);
    kernel_test_in!("arch", smoke_pat_live_msr_matches_programmed);
    kernel_test_in!("arch/pat", smoke_pat_cpu_init_is_idempotent);
    kernel_test_in!("arch/pat", smoke_pat_every_online_cpu_programmed);
}
