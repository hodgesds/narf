//! KASLR — kernel + userspace ASLR.
//!
//! Picks a random virtual-address slot for the kernel image base
//! and for each fresh user-mode AS's stack / mmap / brk arenas.
//!
//! Entropy sources, in priority order:
//!
//!   1. **RDRAND** (x86_64 only) — Intel CPRNG, AMD also implements
//!      it. Hardware reports CPUID(1).ECX[30]; the instruction itself
//!      sets CF on success. We loop up to [`RAND_RETRIES`] times on
//!      CF=0.
//!   2. **RDSEED** as a higher-quality alternative on the same path
//!      (CPUID(7, 0).EBX[18]).
//!   3. **TSC mix** — read the timestamp counter, splat-and-mix with
//!      a known-prime multiplier. Last resort; entropy is only
//!      "boot-time jitter," which is enough for ASLR slot picking
//!      but not for crypto.
//!
//! The "more secure than Linux" framing for KASLR is per-AS: each
//! new user-mode address space gets a fresh randomisation. Linux's
//! per-process mmap randomisation drains entropy at exec; NARF re-
//! seeds at every AS creation including kernel thread stacks
//! (a kernel ROP target leaks address layout that's pure-noise to a
//! second kernel thread).
//!
//! References:
//!   * Linux `arch/x86/boot/compressed/kaslr.c` for the boot-time
//!     slot picker (different problem — KASLR before paging).
//!   * Linux `arch/x86/mm/mmap.c::arch_pick_mmap_base` for per-task
//!     mmap randomisation.
//!   * Intel SDM Vol 1 §7.3.17 (RDRAND), §7.3.18 (RDSEED).

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

/// Number of RDRAND/RDSEED retries before falling back to TSC.
/// Intel guarantees success within 10 retries; we use 32 for margin.
const RAND_RETRIES: u32 = 32;

/// User-mode mmap-arena randomisation slack — number of low bits to
/// randomise. 24 bits = 16 MiB of slack. 39-bit user VA gives plenty
/// of headroom for both slack and arena.
pub const USER_MMAP_RANDOM_BITS: u32 = 24;

/// Load-base randomisation slack for user ELF images — the ET_DYN
/// program base and the PT_INTERP base. 24 bits = 16 MiB of slack at
/// 4 KiB granularity, the same order as [`USER_MMAP_RANDOM_BITS`].
/// Linux's equivalent is `arch_mmap_rnd()` added to `ELF_ET_DYN_BASE`.
pub const USER_ELF_RANDOM_BITS: u32 = 24;

/// Stack-top jitter, mirroring Linux's `randomize_stack_top()`: the
/// stack's high end is pushed *down* by a random amount rather than the
/// whole region being moved, so the arena keeps its nominal bounds.
/// 20 bits = up to 1 MiB of jitter at 4 KiB granularity, which fits
/// inside the reserved RLIMIT_STACK window with room to spare.
pub const USER_STACK_RANDOM_BITS: u32 = 20;

/// Kernel-image randomisation slack. The kernel-half mapping is fixed
/// at 0xFFFF_FF80_0000_0000 (aarch64) / 0xFFFF_FFFF_8000_0000 (x86_64);
/// the random offset is added to that. 30 bits = 1 GiB of slack on
/// x86_64's narrow kernel slot — same shape as Linux's KASLR.
pub const KERNEL_RANDOM_BITS: u32 = 30;

/// Slide applied to the kernel image's virtual base, in bytes.
///
/// Written by the relocation pass in `boot.S` before paging, through the
/// `__kernel_slide_phys` alias the linker script provides, and read by every
/// conversion that turns an in-image virtual address into a physical one.
///
/// It exists because relocations cannot fix arithmetic. The apply pass patches
/// symbol REFERENCES, so `&some_static` carries the slide automatically — but
/// an integer literal spelled `0xFFFF_FFFF_8000_0000` in a subtraction has no
/// relocation record and keeps its link-time value. Subtracting the unslid
/// constant from a slid address yields `phys + slide`, not `phys`. Linux has
/// the same problem and the same answer: a runtime `phys_base` the boot path
/// sets, which every conversion goes through.
///
/// Zero until the slide is turned on, so reading it is correct in either case.
#[no_mangle]
pub static KERNEL_SLIDE: AtomicU64 = AtomicU64::new(0);

/// Base the kernel image is linked at, before any slide.
pub const KERNEL_LINK_BASE: u64 = if cfg!(target_arch = "aarch64") {
    // `KIMAGE_VOFFSET` in `build/linker/aarch64.ld`, NOT `KERNEL_VIRT_BASE`.
    //
    // The image has its own virtual offset, separate from the linear map at
    // `KERNEL_VIRT_BASE`, so that it can slide without disturbing the map of
    // RAM. `phys = va - KERNEL_LINK_BASE` for an in-image address on both
    // arches; on aarch64 the linear map's conversion is the different one
    // (`PhysAddr::kernel_ptr`, `phys | KERNEL_PHYS_OFFSET`).
    //
    // Linux keeps the same two: `kimage_voffset` for `__pa_symbol()` and
    // `PAGE_OFFSET` for the linear map, with `__virt_to_phys` dispatching on
    // which range an address is in.
    0xFFFF_FF7F_8000_0000
} else {
    0xFFFF_FFFF_8000_0000
};

/// VA span reserved for the kernel image, and the offset at which the module
/// text window begins.
///
/// Linux spells the same relationship
/// `MODULES_VADDR = __START_KERNEL_map + KERNEL_IMAGE_SIZE`
/// (arch/x86/include/asm/pgtable_64_types.h), and bounds its own slide by it.
/// `module_text::MODULE_VA_BASE` is derived from this rather than written out
/// as an address, and `build/linker/x86_64.ld` asserts at link time that
/// `__kernel_end + KASLR_SLIDE_MASK` fits inside it — the image plus its
/// widest slide must not reach the module window.
///
/// x86_64 only: on aarch64 the module window sits *below* the kernel base
/// rather than above the image, so no such span exists. See the placement
/// rationale on `MODULE_VA_BASE`.
#[cfg(target_arch = "x86_64")]
pub const KERNEL_IMAGE_SIZE: u64 = 1 << 30;

/// The kernel image's live virtual base — link base plus the applied slide.
#[inline]
pub fn kernel_virt_base() -> u64 {
    KERNEL_LINK_BASE + KERNEL_SLIDE.load(Ordering::Relaxed)
}

/// Physical bounds of the loaded image: `[start, end)`.
///
/// Reads a high-half word the linker populated, NOT the addresses of
/// `__kernel_start` / `__kernel_end`. Those symbols hold physical values
/// because `.boot` is linked low, and taking their address from kernel-half
/// code emits a PC-relative page reference across ~512 GiB — beyond aarch64
/// ADRP's range, which is what forces `code-model=large` there. Linux keeps
/// the same information in a runtime word (`kimage_voffset`) for the same
/// reason; the linker can fill this one in directly.
///
/// See `.kernel_bounds` in `build/linker/*.ld`.
#[inline]
pub fn image_phys_bounds() -> (u64, u64) {
    unsafe extern "C" {
        static __kernel_phys_bounds: [u64; 2];
    }
    // SAFETY: two linker-populated words inside the image, read-only.
    let b = unsafe { core::ptr::addr_of!(__kernel_phys_bounds).read() };
    // The linker filled these with the LINK-TIME physical bounds; if the image
    // was relocated they describe where it used to be. The frame allocator
    // reserves this range, so a stale answer leaves the running image
    // unreserved and hands it to the buddy.
    let d = IMAGE_PHYS_DELTA.load(Ordering::Relaxed);
    (b[0].wrapping_add(d), b[1].wrapping_add(d))
}

/// How far the image was physically relocated from its link-time load address,
/// or 0 if it runs where the loader put it.
///
/// The VA slide (`KERNEL_SLIDE`) randomizes where the image appears; this
/// randomizes where it actually IS. Both matter: a leaked physical address is
/// as useful to an attacker as a leaked virtual one, and the loader puts the
/// image at a fixed physical address that no VA randomization changes.
///
/// Written by `boot.S` after it copies the image and before any conversion
/// runs, so no caller can observe a stale value. Zero is the correct answer
/// when relocation is disabled or no suitable target was found, and it makes
/// both conversions below reduce to their pre-relocation form.
#[no_mangle]
pub static IMAGE_PHYS_DELTA: AtomicU64 = AtomicU64::new(0);

/// How far the running image sits from its link-time load address.
///
/// Prefer [`image_virt_to_phys`] or [`image_phys_bounds`]; this exists for the
/// one caller that has to undo the displacement rather than apply it — the
/// kernel window, which is indexed by VIRTUAL offset but maps PHYSICAL frames,
/// so it needs the two apart. See `x86_64::mmu::kernel_window_va`.
#[inline]
pub fn image_phys_delta() -> u64 {
    IMAGE_PHYS_DELTA.load(Ordering::Relaxed)
}

/// Size of the image as laid out by the linker, in bytes.
///
/// Deliberately delta-free, unlike [`image_phys_bounds`]. The image's VA extent
/// does not change when it is physically relocated: the image is linked at
/// `KERNEL_VIRT_BASE + <link-time phys>`, so the window that maps it needs this
/// many bytes wherever the bytes actually live. Using the relocated physical
/// end here would inflate the window by the delta — at a 256 MiB delta that is
/// 176 leaves instead of 49, which overruns the PD the slide has to fit in.
#[inline]
pub fn image_virt_extent() -> u64 {
    image_link_bounds().1
}

/// The image's LINK-TIME physical bounds — where the linker put it, not where
/// it runs.
///
/// This is [`image_phys_bounds`] without the relocation delta applied, which
/// makes it the image's offsets within its own virtual window: the image is
/// linked at `KERNEL_VIRT_BASE + <link-time phys>`, so these double as the VA
/// offsets of its first and last byte. The window that maps it is indexed by
/// those offsets while mapping the relocated frames.
#[inline]
pub fn image_link_bounds() -> (u64, u64) {
    unsafe extern "C" {
        static __kernel_phys_bounds: [u64; 2];
    }
    // SAFETY: as `image_phys_bounds` — two linker-populated words in-image.
    let b = unsafe { core::ptr::addr_of!(__kernel_phys_bounds).read() };
    (b[0], b[1])
}

/// Physical address of an in-image kernel-virtual address.
///
/// Use this instead of subtracting a hardcoded base: the constant is right
/// only while the slide is zero, and wrong by exactly the slide otherwise.
#[inline]
pub fn image_virt_to_phys(virt: u64) -> u64 {
    // Two independent displacements: the VA slide, undone by subtracting the
    // live virtual base, and the physical relocation, added back on. They are
    // separate because the image can move in one, the other, or both.
    virt.wrapping_sub(kernel_virt_base())
        .wrapping_add(IMAGE_PHYS_DELTA.load(Ordering::Relaxed))
}

#[cfg(feature = "kernel-test")]
mod kaslr_slide_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The kernel image really is slid, and the recorded slide agrees with
    /// where the image actually sits.
    ///
    /// This is the guard against the whole mechanism silently reverting to a
    /// no-op. Every piece of it fails soft: the apply pass skips when the
    /// table's magic is missing, `KERNEL_SLIDE` reads zero when nothing wrote
    /// it, and a zero slide maps and boots exactly like an unslid kernel. A
    /// clean boot is therefore not evidence that any of it ran.
    fn smoke_kaslr_kernel_image_is_slid() -> TestResult {
        let slide = KERNEL_SLIDE.load(Ordering::Relaxed);
        if slide == 0 {
            // `KASLR_SLIDE_MASK` is 0 in the linker script, so the machinery
            // is built and exercised but deliberately inert.
            //
            // A Skip rather than a Pass on purpose: an inert KASLR must not
            // read as a working one.
            return TestResult::Skip("KASLR_SLIDE_MASK is 0 — the image is not slid");
        }
        // 2 MiB pages back the window, so anything finer cannot be mapped.
        if slide & 0x1F_FFFF != 0 {
            return TestResult::Fail("the slide is not 2 MiB aligned");
        }
        // Where the slide must stop is the module window, and
        // `smoke_kaslr_slid_image_clears_module_window` asserts exactly that
        // against `MODULE_VA_BASE`. This used to hardcode `>= 1 GiB` and call
        // it "the module text window one GiB above the link base", which is
        // true on x86_64 and only coincidentally true on aarch64, where the
        // window sits at a different offset and the slack is 825 MiB.

        // The live base has to match where code actually is. Taking the
        // address of a function goes through a relocation, so this compares
        // the patched world against the recorded slide.
        let here = smoke_kaslr_kernel_image_is_slid as usize as u64;
        if here < kernel_virt_base() {
            return TestResult::Fail("kernel code sits below the slid base");
        }
        if here < KERNEL_LINK_BASE + slide {
            return TestResult::Fail("code address disagrees with the recorded slide");
        }
        // And the conversion has to undo it: a text address minus the live base
        // is a physical address inside the loaded image.
        //
        // Containment, not an absolute bound. This read `>= (1 << 30)`, which
        // is an x86_64 assumption: `KERNEL_LOAD_BASE` is 16 MiB there but
        // 0x40080000 on aarch64, where RAM *starts* at 1 GiB, so a perfectly
        // correct conversion tripped it. It stayed hidden because the case
        // Skips while `KASLR_SLIDE_MASK` is 0, and aarch64's was — enabling
        // the slide is what first ran this line. The same absolute bound had
        // already been fixed once, in `smoke_kaslr_image_bounds_stay_physical`.
        let phys = image_virt_to_phys(here);
        let (kstart, kend) = image_phys_bounds();
        if phys < kstart || phys >= kend {
            return TestResult::Fail("image_virt_to_phys did not land inside the loaded image");
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/kaslr", smoke_kaslr_kernel_image_is_slid);

    /// The image-bounding linker symbols are PHYSICAL and must not be slid.
    ///
    /// `__kernel_start` and `__kernel_end` are defined outside the virtual
    /// window (before `. += KERNEL_VIRT_BASE`, and as `. - KERNEL_VIRT_BASE`
    /// respectively), so they already hold physical addresses. The linker
    /// nonetheless emits them with a real section index rather than
    /// `SHN_ABS`, which makes them indistinguishable from ordinary pointers
    /// to a relocation-table builder that keys only on the field's location.
    ///
    /// Adding the slide to them is silent and catastrophic. It moved the
    /// frame allocator's reserved range to `[start + slide, end + slide)`,
    /// leaving the image's first `slide` bytes free for the buddy to hand
    /// out — the kernel allocating its own code as scratch — and it pushed
    /// `kernel_exec_phys_range`'s start past the real start of text, mapping
    /// that text NX so instruction fetch faulted inside the fault handler.
    ///
    /// Neither shows up as a wrong slide, so the sibling test above passes
    /// throughout. The invariant that does catch it is containment: text lies
    /// inside the image, in physical terms, at every slide.
    fn smoke_kaslr_image_bounds_stay_physical() -> TestResult {
        unsafe extern "C" {
            static __text_start: u8;
            static __text_end: u8;
        }
        let (kstart, kend) = image_phys_bounds();
        // These two are virtual and SHOULD move, so convert them.
        let tstart = image_virt_to_phys(core::ptr::addr_of!(__text_start) as u64);
        let tend = image_virt_to_phys(core::ptr::addr_of!(__text_end) as u64);

        // A size bound, not an address bound. `KERNEL_LOAD_BASE` is 16 MiB on
        // x86_64 but 0x40080000 on aarch64, where RAM starts at 1 GiB, so
        // "under 1 GiB" is an x86 assumption and not an invariant. The size is
        // one on both.
        if kend <= kstart || kend - kstart > (1 << 30) {
            return TestResult::Fail("image bounds are not a sane physical range");
        }
        if tstart < kstart {
            return TestResult::Fail(
                "kernel text starts below __kernel_start — a physical linker symbol was slid",
            );
        }
        if tend > kend {
            return TestResult::Fail(
                "kernel text ends above __kernel_end — a physical linker symbol was slid",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/kaslr", smoke_kaslr_image_bounds_stay_physical);

    /// The slid image must stay clear of the module text window.
    ///
    /// The slide moves the image *up*, toward `MODULE_VA_BASE`, so the window
    /// is what bounds it. `build/linker/x86_64.ld` asserts the same thing at
    /// link time against `KASLR_SLIDE_MASK`, which is the stronger check
    /// because it covers every slide the mask can produce rather than the one
    /// this boot drew. This case covers what that cannot: that the slide
    /// actually applied is inside the mask, i.e. that `boot.S` masked it.
    ///
    /// Overlap here would not fault. The image would quietly share addresses
    /// with module text, and the first module load would corrupt the kernel.
    fn smoke_kaslr_slid_image_clears_module_window() -> TestResult {
        // Physical, and deliberately not converted — see
        // `smoke_kaslr_image_bounds_stay_physical`.
        let image_end_phys = image_phys_bounds().1;
        let top = kernel_virt_base().wrapping_add(image_end_phys);
        if top > crate::module_text::MODULE_VA_BASE {
            return TestResult::Fail("the slid kernel image reaches the module text window");
        }
        #[cfg(target_arch = "x86_64")]
        if KERNEL_SLIDE.load(Ordering::Relaxed) + image_end_phys > KERNEL_IMAGE_SIZE {
            return TestResult::Fail("slide + image exceeds KERNEL_IMAGE_SIZE");
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/kaslr", smoke_kaslr_slid_image_clears_module_window);
}

/// Pull one 64-bit value of randomness using the best available source.
///
/// Returns the value plus a tag identifying the source so observability
/// can confirm we aren't always falling back to TSC.
#[inline]
pub fn random_u64() -> (u64, EntropySource) {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(v) = try_rdseed_x86() {
            return (v, EntropySource::Rdseed);
        }
        if let Some(v) = try_rdrand_x86() {
            return (v, EntropySource::Rdrand);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(v) = try_rndr_aarch64() {
            return (v, EntropySource::Rndr);
        }
    }
    (tsc_mix(), EntropySource::TscMix)
}

/// Pick a virtual-address slot for a user-mode mmap or stack arena.
///
/// `base` is the arena's nominal base; the returned address is
/// `base + (random & mask)` where `mask` is the low
/// [`USER_MMAP_RANDOM_BITS`] bits, aligned down to 4 KiB.
#[inline]
pub fn user_mmap_slot(base: u64) -> u64 {
    let (r, _) = random_u64();
    let mask = ((1u64 << USER_MMAP_RANDOM_BITS) - 1) & !0xFFF;
    base + (r & mask)
}

/// Master switch for user-mode address randomisation, mirroring Linux's
/// `randomize_va_space` sysctl / `norandmaps` boot flag.
///
/// On by default. It exists so a caller that must see the canonical,
/// unrandomised layout can pin it — the kernel-test suite asserts exact
/// load addresses in places, and a test that wants to prove *what* the
/// randomisation does needs to be able to turn it off to compare.
static USER_ASLR: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);

/// Enable/disable user-mode ASLR. Returns the previous setting, so a
/// caller can restore it (see `UserAslrGuard` in the userspace tests).
#[inline]
pub fn set_user_aslr(on: bool) -> bool {
    USER_ASLR.swap(on, core::sync::atomic::Ordering::AcqRel)
}

/// Whether user-mode ASLR is in force.
#[inline]
pub fn user_aslr_enabled() -> bool {
    USER_ASLR.load(core::sync::atomic::Ordering::Acquire)
}

/// Pick the load base for a user ELF image (ET_DYN program or
/// PT_INTERP) above `base`.
///
/// The offset is always at least one page, so `base` itself is never
/// mapped by the image. That costs a bit of entropy at the bottom of the
/// range and buys a guarantee callers rely on: the nominal base stays a
/// reliably-unmapped address, which is what makes it usable as a
/// known-bad pointer (several ABI tests use it that way).
#[inline]
pub fn user_elf_slot(base: u64) -> u64 {
    if !user_aslr_enabled() {
        return base;
    }
    let (r, _) = random_u64();
    let mask = ((1u64 << USER_ELF_RANDOM_BITS) - 1) & !0xFFF;
    // `| 0x1000` rather than `+ 0x1000`: keeps the result inside the
    // masked window instead of letting the maximum draw overflow past it.
    base + ((r & mask) | 0x1000)
}

/// Lower a user stack's top end by a random, page-aligned amount.
///
/// Returns a value in `(top - 2^USER_STACK_RANDOM_BITS, top]`, so the
/// result is never above `top` and callers that bound-check against the
/// nominal top stay correct.
#[inline]
pub fn user_stack_top(top: u64) -> u64 {
    if !user_aslr_enabled() {
        return top;
    }
    let (r, _) = random_u64();
    let mask = ((1u64 << USER_STACK_RANDOM_BITS) - 1) & !0xFFF;
    top - (r & mask)
}

/// Pick a *candidate* kernel-image slide by drawing fresh entropy.
///
/// NOT an accessor for the slide in force — read [`KERNEL_SLIDE`] for that.
/// Every call returns a different number, so using this where the applied
/// slide was meant yields a plausible-looking wrong answer rather than an
/// error; it has already done so once, in the boot log.
///
/// `boot.S` picks the live slide itself, long before Rust runs, because the
/// relocations must be applied before any slid address is dereferenced. That
/// leaves this function with no caller on the boot path.
#[inline]
pub fn kernel_slide() -> u64 {
    let (r, _) = random_u64();
    let mask = ((1u64 << KERNEL_RANDOM_BITS) - 1) & !0xFFF;
    r & mask
}

/// Source of the most recently returned random value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EntropySource {
    Rdrand,
    Rdseed,
    Rndr,
    TscMix,
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn try_rdrand_x86() -> Option<u64> {
    use core::arch::asm;
    // CPUID(1).ECX[30] would be the right gate but a CPUID call costs
    // 100+ cycles per random; we just try RDRAND and let CF=0 indicate
    // unavailability. On a CPU that doesn't support RDRAND the
    // instruction is #UD — but every x86_64 CPU shipped post-2012 has
    // it, and we never run on anything earlier (Renoir + Phoenix
    // categorically support it).
    for _ in 0..RAND_RETRIES {
        let v: u64;
        let ok: u8;
        // SAFETY: RDRAND is always legal on supported parts; encoded
        // via the explicit `rdrand` mnemonic so the assembler picks the
        // right opcode for 64-bit operand.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            asm!(
                "rdrand {v}",
                "setc {ok}",
                v = out(reg) v,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok != 0 {
            return Some(v);
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn try_rdseed_x86() -> Option<u64> {
    use core::arch::asm;
    for _ in 0..RAND_RETRIES {
        let v: u64;
        let ok: u8;
        // SAFETY: RDSEED is available on Broadwell+ (Intel) / Zen+
        // (AMD). Renoir + Phoenix both support it. CF=0 means try
        // again. If the CPU doesn't have RDSEED the opcode is #UD,
        // but the boot-time security init never calls this without
        // first checking CPUID(7, 0).EBX[18].
        // SAFETY: Valid memory or trusted environment
        unsafe {
            asm!(
                "rdseed {v}",
                "setc {ok}",
                v = out(reg) v,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok != 0 {
            return Some(v);
        }
    }
    None
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn try_rndr_aarch64() -> Option<u64> {
    use core::arch::asm;
    // FEAT_RNG (8.5+). Reads RNDR / RNDRRS through MRS. NZCV.Z=1
    // means a value was returned; NZCV.Z=0 (with V=0) means the
    // RNG isn't ready.
    for _ in 0..RAND_RETRIES {
        let v: u64;
        let nzcv: u64;
        // SAFETY: MRS RNDR_EL0 / RNDRRS_EL0 is a v8.5+ encoding;
        // unsupported parts #UD. The boot security-init gates on
        // ID_AA64ISAR0_EL1.RNDR != 0 before calling this. The
        // assembler raw encoding works on any v8 toolchain.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            asm!(
                "mrs {v}, s3_3_c2_c4_0", // RNDR_EL0
                "mrs {nzcv}, nzcv",
                v = out(reg) v,
                nzcv = out(reg) nzcv,
                options(nomem, nostack),
            );
        }
        // NZCV.Z is bit 30. Z=0 means valid (Arm ARM D7.4.10).
        if nzcv & (1 << 30) == 0 {
            return Some(v);
        }
    }
    None
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
fn try_rdrand_x86() -> Option<u64> {
    None
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
fn try_rdseed_x86() -> Option<u64> {
    None
}

/// Reentrant TSC mixer. Reads the cycle counter, multiplies by a
/// 64-bit prime, and XORs against a running accumulator. Not
/// cryptographic; sufficient for ASLR slot picking on parts where
/// RDRAND/RDSEED/RNDR aren't available (i.e. exotic QEMU TCG configs
/// and one virtualisation host vendor).
#[inline]
pub fn tsc_mix() -> u64 {
    static ACC: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let t = read_cycle_counter();
    // Mix: t * golden ratio prime, XORed into the accumulator.
    let v = t.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    ACC.fetch_xor(v.rotate_left(13), Ordering::Relaxed) ^ v
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn read_cycle_counter() -> u64 {
    use core::arch::asm;
    // RDTSC: lo in EAX, hi in EDX.
    let lo: u32;
    let hi: u32;
    // SAFETY: RDTSC at CPL=0 is always defined.
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn read_cycle_counter() -> u64 {
    use core::arch::asm;
    // CNTVCT_EL0 — virtual count register. Always readable from EL1.
    let v: u64;
    // SAFETY: MRS of the virtual count is legal at EL1.
    unsafe {
        asm!("mrs {v}, cntvct_el0", v = out(reg) v, options(nomem, nostack));
    }
    v
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
fn read_cycle_counter() -> u64 {
    0xDEAD_BEEF_CAFE_F00D
}
