//! `module_text` — the executable-image allocator for runtime-loaded kernel
//! modules (`narf-modules`).
//!
//! A loaded module needs three things the kernel heap cannot give it:
//!
//!   1. **Executable pages.** Every kernel window `mmu::init_mmu` builds is NX
//!      apart from the kernel's own text and the AP trampoline (see
//!      `x86_64/mmu.rs`, and `frame/src/aarch64/boot.S` for the PXN|UXN twin).
//!      A module relocated into a `Vec<u8>` is unreachable by the instruction
//!      fetcher — its first instruction faults.
//!   2. **A virtual address inside the arch's call range.** x86_64 modules are
//!      compiled with `R_X86_64_PLT32` call relocations whose displacement is a
//!      signed 32-bit field: a module more than 2 GiB from the kernel symbol it
//!      calls cannot be relocated at all, only rejected. [`MODULE_VA_BASE`] is
//!      chosen to make that impossible rather than unlikely — see below.
//!   3. **Per-section permissions.** Text must end up RX, rodata RO, data RW,
//!      and no page may ever be both writable and executable — including
//!      through the linear-map alias of its backing frames.
//!
//! ## Window placement, and why it is not next to the BPF windows
//!
//! `bpf_text` puts JIT text at `0xFFFF_8880_0000_0000` (PML4 slot 273) and can
//! afford to: the BPF JIT emits its own calls as absolute `mov rax, imm64` +
//! `call rax`, so distance to the kernel is irrelevant. A module is different —
//! it is compiled by rustc/LLVM as an ordinary relocatable object, and every
//! call it makes to an exported kernel symbol arrives as a PC-relative 32-bit
//! displacement. From slot 273 the kernel image is ~131 TiB away and *every*
//! such relocation overflows.
//!
//! So modules go immediately above the kernel image instead:
//!
//! ```text
//!   x86_64   PML4[511] PDPT[510]  0xFFFF_FFFF_8000_0000  kernel image (1 GiB)
//!            PML4[511] PDPT[511]  0xFFFF_FFFF_C000_0000  module images  ← here
//! ```
//!
//! The whole module window is within +1.25 GiB of any kernel symbol, so PC32
//! and PLT32 resolve directly and no GOT or PLT synthesis is needed on x86_64.
//! Linux places its module region the same way and for the same reason
//! (`arch/x86/include/asm/pgtable_64_types.h::MODULES_VADDR`).
//!
//! PML4[511] is already present in every address space — `init_mmu` installs it
//! at boot and `new_user_pml4_on` snapshot-copies PML4[256..512] **by value**,
//! so every root holds the same PDPT frame *by pointer*. Populating PDPT[511]
//! inside that shared frame therefore propagates to every address space with no
//! reservation step, which is why this module has no `reserve_kernel_slots`
//! twin and no §4.1 boot-ordering hazard. It only borrows `bpf_text`'s record
//! of the kernel root, exactly as `vmalloc` does.
//!
//! ```text
//!   aarch64  L0[510] L1[511] 0xFFFF_FF7F_F800_0000  module images  ← here
//!            L0[511] L1[0]   0xFFFF_FF80_0000_0000  linear map: phys 0-1 GiB
//!            L0[511] L1[1]   0xFFFF_FF80_4000_0000  linear map: phys 1-2 GiB
//!            L0[511] L1[2]   0xFFFF_FF80_8000_0000  linear map: phys 2-3 GiB
//! ```
//!
//! aarch64 goes **below** `KERNEL_VIRT_BASE`, not above. Everything at or
//! above it is the linear map: `PhysAddr::kernel_mut_ptr` is
//! `phys | KERNEL_PHYS_OFFSET` for every physical address, so the L1 slots
//! boot.S leaves empty are images of RAM it has not had to map, not free
//! address space. A window in slot 2 aliases live frames on any machine with
//! over 2 GiB. Below the base the linear map cannot reach, because it only
//! ever adds.
//!
//! aarch64 gets no equivalent free lunch on *range*, though: the window is
//! ~1.1 GiB from kernel text and `R_AARCH64_CALL26` reaches ±128 MiB, so
//! aarch64 modules need PLT veneers in the relocator. Nowhere in the address
//! space is close enough — the GiB adjacent to the kernel image *is* the
//! linear map. Linux arm64 reaches the same conclusion from the same
//! constraint (`CONFIG_ARM64_MODULE_PLTS`,
//! `arch/arm64/kernel/module-plts.c`). This allocator is arch-neutral and does
//! not care which way it resolves; the relocator does.
//!
//! ## W^X
//!
//! Pages come back RW+NX so the loader can copy sections in and apply
//! relocations against their final addresses. [`protect`] then flips text to RX
//! and rodata to RO, and — this is the half that is easy to forget — asks
//! [`crate::text_poke`] to make every *other* kernel alias of those frames
//! read-only too. Without that second step the linear map still offers a
//! writable window onto memory that is executable at its module VA, which is
//! precisely the primitive W^X exists to deny. [`free`] restores the aliases
//! before the frames go back to the buddy; skipping that would hand the next
//! owner memory it cannot write.
//!
//! On aarch64 `text_poke::can_protect` refuses sub-2-MiB ranges (making one
//! 4 KiB frame of a live 2 MiB linear-map block read-only would need
//! break-before-make on the kernel's own map). We record that the alias stayed
//! writable rather than failing the load, matching `bpf_text`'s fallback-pack
//! behaviour and Linux arm64's identical refusal.
//!
//! ## Mappings are not GLOBAL
//!
//! Module pages are unmapped at `rmmod`, so they must never carry the GLOBAL
//! bit: several TLB-flush paths deliberately retain global entries, and a
//! global module mapping would leave a stale executable translation on an idle
//! peer after unload. `vmalloc.rs::kernel_leaf_flags` documents the same
//! constraint for the same reason. `bpf_text` *does* set GLOBAL, and may,
//! because its VA is never recycled.

use alloc::vec;
use alloc::vec::Vec;

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{PhysAddr, PhysFrame, VirtAddr};

// ── Window ─────────────────────────────────────────────────────────────

/// Base kernel VA of the module image window.
#[cfg(target_arch = "x86_64")]
pub const MODULE_VA_BASE: u64 = 0xFFFF_FFFF_C000_0000;
/// Base kernel VA of the module image window: the top 128 MiB of the L0 slot
/// **below** `KERNEL_VIRT_BASE`, ending exactly where it begins.
///
/// Placing it *above* `KERNEL_VIRT_BASE` is what an empty L1 slot tempts you
/// into, and it is wrong. `PhysAddr::kernel_mut_ptr` is
/// `phys | KERNEL_PHYS_OFFSET` for **every** physical address, so the entire
/// range from `KERNEL_VIRT_BASE` upward is the linear map's image of RAM. The
/// L1 slots `frame/src/aarch64/boot.S` leaves empty are not free addresses —
/// they are the images of physical memory the boot map has not needed to
/// populate yet. Slot 2 is the image of physical 2–3 GiB, so on a machine
/// with more than 2 GiB (QEMU is configured with 2048 MiB, RAM
/// 0x4000_0000..0xC000_0000) a window there aliases live frames.
///
/// Below `KERNEL_VIRT_BASE` the linear map cannot reach by construction: it
/// only ever adds. L0[510] is untouched by boot.S, by the BPF windows
/// (L0[273], L0[275]) and by vmalloc (L0[384]).
///
/// Still within ADRP's ±4 GiB of kernel text — about 1.1 GiB — so the veneers
/// in `narf_modules::plt` continue to resolve.
#[cfg(target_arch = "aarch64")]
pub const MODULE_VA_BASE: u64 = 0xFFFF_FF7F_F800_0000;
/// Base kernel VA of the module image window.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const MODULE_VA_BASE: u64 = 0;

/// Bytes of window handed out. 128 MiB is Linux arm64's module-region size and
/// is far more than a NARF module set will use; the bound exists so the VA
/// bitmap stays a fixed 4 KiB static rather than a growable allocation that the
/// load path would have to fail on.
pub const MODULE_VA_USABLE: u64 = 128 * 1024 * 1024;

/// Pages in the window; one bit each in `VA_MAP`.
pub const MODULE_VA_PAGES: usize = (MODULE_VA_USABLE / 4096) as usize;
const VA_WORDS: usize = MODULE_VA_PAGES / 64;

/// Byte that fills a freshly-allocated page, so a jump into module space the
/// loader never wrote traps instead of executing whatever the buddy last had
/// there. Matches `bpf_text`'s `TRAP_FILL` rationale.
#[cfg(target_arch = "x86_64")]
const TRAP_FILL: u8 = 0xCC; // int3
#[cfg(not(target_arch = "x86_64"))]
const TRAP_FILL: u8 = 0x00;

// ── Errors ─────────────────────────────────────────────────────────────

/// Failure modes of the module image allocator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ModuleTextError {
    /// Zero pages requested, or more than the window holds.
    BadLen,
    /// The window has no free run of the requested length.
    VaExhausted,
    /// The frame allocator could not back the request.
    NoFrame,
    /// A page-table walk failed.
    MapFailed,
    /// `bpf_text::reserve_kernel_slots` has not run, so the kernel root the
    /// shared kernel mappings must be installed through is unknown.
    RootUnavailable,
    /// A page index outside the image was passed to [`protect`].
    OutOfRange,
}

// ── Protection classes ─────────────────────────────────────────────────

/// The three protections a module page can hold. There is deliberately no
/// writable-and-executable variant: `narf-modules`' loader rejects an ELF
/// section carrying `SHF_WRITE | SHF_EXECINSTR`, and this type is the reason
/// that rejection cannot be quietly undone downstream.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Prot {
    /// Read + execute. Module `.text`.
    Rx,
    /// Read only, never executable. Module `.rodata`.
    Ro,
    /// Read + write, never executable. Module `.data` / `.bss`. The state
    /// every page is allocated in.
    Rw,
}

impl Prot {
    /// True for the classes whose backing frames must lose their writable
    /// linear-map alias.
    #[inline]
    const fn alias_must_be_ro(self) -> bool {
        matches!(self, Prot::Rx | Prot::Ro)
    }

    #[cfg(target_arch = "x86_64")]
    fn leaf_flags(self, domain: DomainId) -> crate::paging::PtFlags {
        use crate::paging::PtFlags;
        // No GLOBAL — see the module docs.
        let base = match self {
            Prot::Rx => PtFlags::PRESENT,
            Prot::Ro => PtFlags::PRESENT | PtFlags::NO_EXEC,
            Prot::Rw => PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_EXEC,
        };
        base | protection_key(domain)
    }

    #[cfg(target_arch = "aarch64")]
    fn leaf_flags(self, domain: DomainId) -> crate::paging::PtFlags {
        use crate::paging::PtFlags;
        // aarch64 carries no per-page domain key. Its `DomainPrimitive`
        // backend is MTE, which tags by allocation rather than by page-table
        // field, so the domain does not travel in the leaf here. The loader
        // still records the module's DomainId; what is missing is the
        // enforcement side, not the bookkeeping.
        let _ = domain;
        // UXN on every class: module text executes at EL1 only. Clearing PXN
        // is what makes it fetchable there.
        match self {
            Prot::Rx => PtFlags::AP_RO_EL1 | PtFlags::ATTR_NORMAL | PtFlags::UXN,
            Prot::Ro => PtFlags::AP_RO_EL1 | PtFlags::ATTR_NORMAL | PtFlags::UXN | PtFlags::PXN,
            Prot::Rw => PtFlags::AP_RW_EL1 | PtFlags::ATTR_NORMAL | PtFlags::UXN | PtFlags::PXN,
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn leaf_flags(self, _domain: DomainId) -> crate::paging::PtFlags {
        crate::paging::PtFlags::PRESENT
    }
}

/// The protection-key field for `domain`, as it sits in a leaf PTE.
///
/// x86_64 PTE bits 59..=62 hold a 4-bit key selecting which of the 16 PKS
/// domains a page belongs to (SDM Vol 3 §4.6.2). `IA32_PKRS` carries two
/// rights bits per domain, so `pks::enter_domain` can deny fourteen of them
/// in a single MSR write while leaving the kernel's domain and the running
/// module's reachable.
///
/// Until this, `PtFlags::PK_MASK` existed and nothing ever set it: every
/// module page carried key 0, so all sixteen domains were the same domain
/// and `target_domain=` selected nothing. DESIGN.md described the isolation
/// as real; it was bookkeeping.
#[cfg(target_arch = "x86_64")]
#[inline]
fn protection_key(domain: DomainId) -> crate::paging::PtFlags {
    // `PtFlags::pk` masks to the low 4 bits, so a `DomainId` outside 0..=15
    // cannot spill into the NX bit at 63.
    crate::paging::PtFlags::pk(domain.raw())
}

// ── VA bitmap ──────────────────────────────────────────────────────────

struct VaMap {
    words: [u64; VA_WORDS],
}

impl VaMap {
    const fn new() -> Self {
        Self {
            words: [0; VA_WORDS],
        }
    }

    #[inline]
    fn is_set(&self, page: usize) -> bool {
        self.words[page / 64] & (1u64 << (page % 64)) != 0
    }

    /// First-fit run of `n` free pages. Linear, which is fine: this runs once
    /// per `insmod`, and the map is 512 words.
    fn alloc_run(&mut self, n: usize) -> Option<usize> {
        let mut start = 0usize;
        let mut run = 0usize;
        for page in 0..MODULE_VA_PAGES {
            if self.is_set(page) {
                run = 0;
                start = page + 1;
                continue;
            }
            run += 1;
            if run == n {
                for p in start..start + n {
                    self.words[p / 64] |= 1u64 << (p % 64);
                }
                return Some(start);
            }
        }
        None
    }

    fn free_run(&mut self, base: usize, n: usize) {
        for p in base..base + n {
            self.words[p / 64] &= !(1u64 << (p % 64));
        }
    }

    fn used(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }
}

static VA_MAP: IrqSafeSpinLock<VaMap> = IrqSafeSpinLock::new(VaMap::new());

// ── Handle ─────────────────────────────────────────────────────────────

/// A mapped, contiguous run of module image pages.
///
/// Not `Copy` and not `Drop`: releasing an image is `unsafe` (a CPU may be
/// executing out of it) and must be an explicit [`free`], so there is no
/// implicit path that could retire live text.
#[derive(Debug)]
pub struct ModuleImage {
    /// Kernel VA of the first byte. Relocations are computed against this.
    pub base: u64,
    /// Mapped pages, excluding the trailing guard page.
    pub pages: usize,
    /// First page index in the window bitmap, including the guard page.
    va_page: usize,
    /// Isolation domain every page of this image is tagged with. Fixed at
    /// allocation: re-tagging a live image would need every mapping rewritten
    /// and a shootdown, and nothing wants to.
    pub domain: DomainId,
    /// Current protection of each mapped page.
    prot: Vec<Prot>,
    /// Whether each page's linear-map alias was successfully made read-only.
    /// `false` either because the page is still RW or because
    /// `text_poke::can_protect` refused (aarch64 sub-block granularity).
    alias_ro: Vec<bool>,
}

impl ModuleImage {
    /// Byte span of the image.
    #[inline]
    pub fn len(&self) -> usize {
        self.pages * 4096
    }

    /// True when the image maps no pages. Never true for an image this module
    /// hands out — [`alloc`] rejects a zero-page request — but clippy asks for
    /// it wherever `len` exists.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pages == 0
    }

    /// Kernel VA of page `i`.
    #[inline]
    pub fn page_va(&self, i: usize) -> u64 {
        self.base + (i as u64) * 4096
    }

    /// Writable view of the whole image. Valid only while every page is still
    /// [`Prot::Rw`]; after [`protect`] has sealed a range, writing through the
    /// returned slice faults on any page that left `Rw`.
    ///
    /// # Safety
    /// The caller must not retain the slice across a [`protect`] call, and must
    /// not alias it with another live reference to the same image.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `[base, base + pages*4096)` is mapped by `alloc` and stays
        // mapped for the image's lifetime; the caller's contract covers
        // writability and aliasing.
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, self.len()) }
    }
}

/// True when `addr` lies in the module image window. Used by diagnostic paths
/// that need to attribute a kernel address to a loaded module.
#[inline]
pub fn is_module_va(addr: u64) -> bool {
    (MODULE_VA_BASE..MODULE_VA_BASE + MODULE_VA_USABLE).contains(&addr)
}

// ── Root ───────────────────────────────────────────────────────────────

#[inline]
fn kernel_root() -> Result<PhysAddr, ModuleTextError> {
    crate::bpf_text::kernel_root_for_mapping().ok_or(ModuleTextError::RootUnavailable)
}

/// Top-level page-table slot the module window lives in.
#[inline]
pub const fn kernel_top_slot() -> usize {
    ((MODULE_VA_BASE >> 39) & 0x1FF) as usize
}

/// Pre-populate the module window's top-level page-table entry in the live
/// kernel root.
///
/// Must run at boot, after `init_mmu` installs the final kernel root and
/// BEFORE the first user address space is created. `bpf_text` and `vmalloc`
/// both do this for their own windows and neither relies on `map_4kb`'s lazy
/// `ensure_next_table` to create a top-level entry, for two reasons:
///
///   * On x86_64, `new_user_pml4_on` snapshot-copies PML4[256..512] **by
///     value**. A slot first populated after an address space exists is
///     absent from that address space's root, and the first kernel access to
///     the window while it is current faults on a not-present PML4 entry
///     inside the fault handler's own working set — `bpf_text`'s §4.1 triple
///     fault.
///   * On aarch64 the kernel half lives in TTBR1 and is not copied, so the
///     propagation hazard does not apply — but creating the entry once, at a
///     known point, is still preferable to doing it under whatever lock and
///     context the first `insmod` happens to arrive with.
///
/// Idempotent. On x86_64 this is normally a no-op: the window lives under
/// PML4[511], which `init_mmu` has already built for the kernel image.
pub fn reserve_kernel_slot() -> Result<(), ModuleTextError> {
    debug_assert_eq!(
        ((MODULE_VA_BASE >> 39) & 0x1FF) as usize,
        kernel_top_slot(),
        "MODULE_VA_BASE does not decode to kernel_top_slot()"
    );
    let root = kernel_root()?;
    // SAFETY: `root` is the live kernel root and this runs single-threaded on
    // the BSP at boot, so the read-modify-write of one entry cannot race.
    unsafe { reserve_top_slot(root, kernel_top_slot()) }
}

/// Install a present, kernel-only next-level table at `root[slot]` if one is
/// not already there.
///
/// # Safety
/// `root` must be the live kernel root and the caller must have exclusive
/// access to it (boot BSP).
#[cfg(target_arch = "x86_64")]
unsafe fn reserve_top_slot(root: PhysAddr, slot: usize) -> Result<(), ModuleTextError> {
    use crate::x86_64::paging::{PageTable, PageTableEntry, PtFlags};
    // SAFETY: caller's contract — live kernel PML4, identity-reachable.
    let pml4 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    if pml4.entries[slot].is_present() {
        return Ok(());
    }
    let frame = crate::frame::alloc_frame().map_err(|_| ModuleTextError::NoFrame)?;
    let phys = frame.start_address();
    crate::frame::__pagetable_register(phys.raw());
    // SAFETY: fresh frame, exclusively ours until published below.
    unsafe { core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096) };
    pml4.entries[slot] = PageTableEntry::new(phys, PtFlags::PRESENT | PtFlags::WRITABLE);
    Ok(())
}

/// aarch64 twin.
///
/// # Safety
/// Same contract as the x86_64 version.
#[cfg(target_arch = "aarch64")]
unsafe fn reserve_top_slot(root: PhysAddr, slot: usize) -> Result<(), ModuleTextError> {
    use crate::aarch64::paging::{PageTable, PageTableEntry};
    // SAFETY: caller's contract — live TTBR1 L0.
    let l0 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    if l0.entries[slot].is_valid() {
        return Ok(());
    }
    let frame = crate::frame::alloc_frame().map_err(|_| ModuleTextError::NoFrame)?;
    let phys = frame.start_address();
    // SAFETY: fresh frame, exclusively ours until published below.
    unsafe { core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096) };
    // Table descriptor: bits[1:0] = 0b11 (valid + table); leaf entries carry
    // the real permissions.
    l0.entries[slot] = PageTableEntry::from_raw(phys.raw() | 0b11);
    // Publish the descriptor before anything can walk it.
    // SAFETY: barriers at EL1 are always legal.
    unsafe {
        core::arch::asm!("dsb ishst", "isb", options(nostack, preserves_flags));
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn reserve_top_slot(_root: PhysAddr, _slot: usize) -> Result<(), ModuleTextError> {
    Err(ModuleTextError::MapFailed)
}

// ── Public API ─────────────────────────────────────────────────────────

/// Map `pages` fresh, zeroed, **RW+NX** pages in the module window, plus one
/// unmapped guard page after them.
///
/// The image comes back writable so the loader can copy sections in and apply
/// relocations against the final addresses. Nothing is executable until
/// [`protect`] says so.
///
/// The guard page costs one VA slot and turns a module that runs off the end of
/// its own image into a page fault with a diagnosable address, rather than a
/// silent walk into the next module's text.
pub fn alloc(pages: usize, domain: DomainId) -> Result<ModuleImage, ModuleTextError> {
    if pages == 0 || pages >= MODULE_VA_PAGES {
        return Err(ModuleTextError::BadLen);
    }
    let root = kernel_root()?;

    // +1 for the guard page: reserved in the bitmap, never mapped.
    let want = pages + 1;
    let va_page = VA_MAP
        .lock()
        .alloc_run(want)
        .ok_or(ModuleTextError::VaExhausted)?;
    let base = MODULE_VA_BASE + (va_page as u64) * 4096;

    let mut mapped = 0usize;
    while mapped < pages {
        let va = VirtAddr::new(base + (mapped as u64) * 4096);
        let frame = match crate::frame::alloc_frame() {
            Ok(f) => f,
            Err(_) => {
                // SAFETY: exactly `mapped` pages were installed above.
                unsafe { unmap_and_free(base, mapped) };
                VA_MAP.lock().free_run(va_page, want);
                return Err(ModuleTextError::NoFrame);
            }
        };
        // SAFETY: `va` is in the module window under the already-present
        // PML4[511]/L0[511] entry, and `frame` is a fresh, exclusively-owned
        // frame. `root` is the recorded live kernel root.
        let r = unsafe {
            crate::paging::map_4kb(root, va, frame.start_address(), Prot::Rw.leaf_flags(domain))
        };
        if r.is_err() {
            crate::frame::free_frame(frame);
            // SAFETY: exactly `mapped` pages were installed above; this one
            // was not.
            unsafe { unmap_and_free(base, mapped) };
            VA_MAP.lock().free_run(va_page, want);
            return Err(ModuleTextError::MapFailed);
        }

        // Read the leaf back before touching the page. `map_4kb` reporting
        // success is not the same as the translation being installed, and the
        // difference between those two is otherwise a hard fault at the first
        // write with no indication of which page or why.
        if page_phys(root, va.as_u64()) != Some(frame.start_address().raw()) {
            // SAFETY: `mapped` pages were installed; this one may have been
            // partially installed and is covered by the same teardown.
            unsafe { unmap_and_free(base, mapped + 1) };
            VA_MAP.lock().free_run(va_page, want);
            return Err(ModuleTextError::MapFailed);
        }

        // Trap-fill this page now, while we know it is mapped. Filling the
        // whole run afterwards means one memset spans every page, so a single
        // bad mapping faults somewhere inside a 128 KiB store with nothing to
        // say which page was missing.
        //
        // Trap-fill rather than zero-fill: a stray call into a page the loader
        // leaves untouched should stop, not decode zeros as instructions.
        // SAFETY: the page was just mapped RW and its translation verified.
        unsafe {
            core::ptr::write_bytes(va.as_u64() as *mut u8, TRAP_FILL, 4096);
        }
        mapped += 1;
    }

    Ok(ModuleImage {
        base,
        pages,
        va_page,
        domain,
        prot: vec![Prot::Rw; pages],
        alias_ro: vec![false; pages],
    })
}

/// Set pages `[first, first + count)` of `image` to `prot`.
///
/// For [`Prot::Rx`] and [`Prot::Ro`] this also drops the writable linear-map
/// alias of the backing frames, and for `Rx` it makes the newly-published
/// bytes fetchable (a serialising instruction on x86_64, an icache sweep on
/// aarch64). Call it once per contiguous section run after relocations are
/// applied; it is the point of no return for writing to those pages.
///
/// Ordering note: the alias is closed **before** the module VA is made
/// executable. `bpf_text::seal` documents why — the alias flip is the step that
/// can fail structurally, and doing it first means a failure leaves nothing
/// executable and the caller's `Err` truthful. The other order would publish
/// executable text and only then discover the alias could not be closed.
pub fn protect(
    image: &mut ModuleImage,
    first: usize,
    count: usize,
    prot: Prot,
) -> Result<(), ModuleTextError> {
    if count == 0 {
        return Ok(());
    }
    if first >= image.pages || first + count > image.pages {
        return Err(ModuleTextError::OutOfRange);
    }
    let root = kernel_root()?;

    if prot.alias_must_be_ro() {
        for i in first..first + count {
            if image.alias_ro[i] {
                continue;
            }
            let Some(phys) = page_phys(root, image.page_va(i)) else {
                return Err(ModuleTextError::MapFailed);
            };
            if !crate::text_poke::can_protect(phys, 4096) {
                // Architectural refusal, not a transient one — see the module
                // docs. Leave the alias writable and record that so `free`
                // does not try to restore something it never took.
                continue;
            }
            // SAFETY: the frame belongs to this image alone — `alloc` took it
            // from the buddy and nothing else holds a pointer to it. No other
            // CPU can be mutating this image: it is mid-load and unpublished.
            if unsafe { crate::text_poke::protect_ro(phys, 4096) }.is_err() {
                return Err(ModuleTextError::MapFailed);
            }
            image.alias_ro[i] = true;
        }
    }

    for i in first..first + count {
        let va = VirtAddr::new(image.page_va(i));
        // SAFETY: `va` is a page this module mapped through `root`; changing
        // its permissions preserves the translation.
        if unsafe { crate::paging::protect_4kb(root, va, prot.leaf_flags(image.domain)) }.is_err() {
            return Err(ModuleTextError::MapFailed);
        }
        image.prot[i] = prot;
    }

    if prot == Prot::Rx {
        serialize_after_publish(image.page_va(first), (count as u64) * 4096);
    }
    Ok(())
}

/// Unmap an image, return its frames to the buddy, and release its VA.
///
/// # Safety
/// No CPU may be executing out of, or hold a pointer into, `image`. The module
/// loader satisfies this by running `narf_module_exit`, sweeping the image's
/// KSYMTAB exports, and waiting out an RCU grace period first.
pub unsafe fn free(image: ModuleImage) {
    // Restore every alias we took. This has to happen before the frames go
    // back: the next owner will expect to be able to write them.
    if let Ok(root) = kernel_root() {
        for i in 0..image.pages {
            if !image.alias_ro[i] {
                continue;
            }
            if let Some(phys) = page_phys(root, image.page_va(i)) {
                // SAFETY: exactly the extents `protect` made read-only, still
                // owned exclusively by this image.
                unsafe {
                    let _ = crate::text_poke::protect_rw(phys, 4096);
                }
            }
        }
    }

    // SAFETY: these are this image's own pages, and the caller's contract says
    // nothing is executing from them.
    unsafe { unmap_and_free(image.base, image.pages) };
    VA_MAP.lock().free_run(image.va_page, image.pages + 1);
}

/// Pages currently handed out, including guard pages. For `/proc` and smokes.
pub fn pages_used() -> usize {
    VA_MAP.lock().used()
}

// ── Internals ──────────────────────────────────────────────────────────

/// Physical frame currently backing `va`, or `None` if it is not mapped.
///
/// Always a 4 KiB leaf here — this module only ever installs 4 KiB pages — so
/// `translate`'s huge-page base-address caveat does not apply. A `None` means
/// the leaf vanished under us, which is a bug rather than a condition, so
/// callers surface it as `MapFailed`.
fn page_phys(root: PhysAddr, va: u64) -> Option<u64> {
    // SAFETY: `root` is the recorded kernel root, identity-reachable like
    // every page table; `translate` only reads.
    unsafe { crate::paging::translate(root, VirtAddr::new(va)) }.map(|p| p.raw() & !0xFFFu64)
}

/// Unmap and release the first `count` pages of the run at `base`, then free
/// any last-level page table the range leaves empty.
///
/// # Safety
/// `[base, base + count*4096)` must be pages this module mapped.
unsafe fn unmap_and_free(base: u64, count: usize) {
    let Ok(root) = kernel_root() else { return };
    for i in 0..count {
        let va = VirtAddr::new(base + (i as u64) * 4096);
        // SAFETY: mapped by `alloc` through this root.
        if let Ok(phys) = unsafe { crate::paging::unmap_4kb(root, va) } {
            if phys.raw() != 0 {
                crate::frame::free_frame(PhysFrame::new(phys));
            }
        }
    }
    // Reclaim now-empty last-level tables, once per 2 MiB granule. Every leaf
    // above was unmapped with a broadcast invalidation, so no CPU can still
    // walk a table we free here. The shared PDPT/PD levels are kept.
    if count != 0 {
        let end = base + (count as u64) * 4096;
        let mut granule = base & !0x1F_FFFFu64;
        while granule < end {
            // SAFETY: the range's leaves were unmapped and flushed above.
            let _ = unsafe { crate::paging::free_empty_pt(root, VirtAddr::new(granule)) };
            granule += 0x20_0000;
        }
    }
}

/// Make bytes just published as text fetchable on this CPU.
///
/// Peer CPUs need no equivalent: a module is never entered before its `protect`
/// returns, and the rest of its window is trap-filled, so a peer that somehow
/// lands in module space faults rather than executing something stale. This is
/// the same argument `bpf_text::seal` makes.
#[cfg(target_arch = "x86_64")]
fn serialize_after_publish(_base: u64, _len: u64) {
    // Via `narf_arch`'s wrapper, not a hand-rolled `cpuid`: the obvious inline
    // form clobbers the red zone under `nostack`. `arch/src/x86_64/cpuid.rs`
    // carries the post-mortem.
    // SAFETY: CPUID is always legal at CPL=0.
    let _ = unsafe { narf_arch::x86_64::cpuid::cpuid(0, 0) };
}

/// aarch64 twin — a real cache-maintenance sweep, since the icache is not
/// coherent with the data side.
#[cfg(target_arch = "aarch64")]
fn serialize_after_publish(base: u64, len: u64) {
    // SAFETY: maintenance-by-VA over a mapped, readable kernel range.
    unsafe {
        narf_arch::aarch64::asm::flush_icache_range(base, len);
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn serialize_after_publish(_base: u64, _len: u64) {}

// ── In-kernel smokes ───────────────────────────────────────────────────
//
// Everything worth testing here needs a live MMU: whether the window is
// reachable, whether sealed text actually executes, whether the writable alias
// is really gone. A host test could only re-check the arithmetic.

use narf_kernel_test::{kernel_test_in, TestResult};

/// Physical frame backing page `i` of `image`. Smokes only — the alias checks
/// need the phys the loader never has to care about.
#[doc(hidden)]
pub fn __page_phys_for_test(image: &ModuleImage, i: usize) -> Option<u64> {
    let root = kernel_root().ok()?;
    page_phys(root, image.page_va(i))
}

/// `mov eax, 42; ret` — the smallest thing that proves the page is genuinely
/// executable rather than merely mapped.
#[cfg(target_arch = "x86_64")]
const RET42: &[u8] = &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
/// `mov w0, #42; ret`, little-endian.
#[cfg(target_arch = "aarch64")]
const RET42: &[u8] = &[0x40, 0x05, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];

/// The window must decode to the slots the module docs claim, and — on
/// x86_64 — every byte of it must be within a signed 32-bit displacement of
/// kernel text, because that is the whole reason it is not next to the BPF
/// windows. If someone moves `MODULE_VA_BASE`, this fails at boot instead of
/// surfacing as "every module with a kernel call fails to relocate".
fn smoke_module_text_window_placement() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    {
        if (MODULE_VA_BASE >> 39) & 0x1FF != 511 || (MODULE_VA_BASE >> 30) & 0x1FF != 511 {
            return TestResult::Fail("module window is not at PML4[511] PDPT[511]");
        }
        // The kernel image is linked at -2 GiB. Both ends of the module window
        // must sit within i32 range of it in both directions.
        const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
        let far = (MODULE_VA_BASE + MODULE_VA_USABLE) as i64 - KERNEL_VIRT_BASE as i64;
        if far > i32::MAX as i64 {
            return TestResult::Fail("module window top is out of PC32 range of kernel text");
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        const KERNEL_VIRT_BASE: u64 = 0xFFFF_FF80_0000_0000;
        // THE invariant. `PhysAddr::kernel_mut_ptr` is
        // `phys | KERNEL_PHYS_OFFSET` for every physical address, so
        // everything from KERNEL_VIRT_BASE upward is the linear map's image
        // of RAM — including the L1 slots boot.S has not populated, which are
        // merely the images of memory it has not needed to map. A window
        // there aliases live frames on any machine large enough to reach it.
        //
        // Checking "which L1 slots does boot.S write" instead of this is
        // what put the window on top of the image of physical 2-3 GiB, where
        // it corrupted the module image on a 2 GiB QEMU machine.
        if MODULE_VA_BASE + MODULE_VA_USABLE > KERNEL_VIRT_BASE {
            return TestResult::Fail("module window overlaps the RAM linear map");
        }
        if MODULE_VA_BASE >> 48 != 0xFFFF {
            return TestResult::Fail("module window is not a TTBR1 address");
        }
        let l1 = (MODULE_VA_BASE >> 30) & 0x1FF;
        let end_l1 = ((MODULE_VA_BASE + MODULE_VA_USABLE - 1) >> 30) & 0x1FF;
        if end_l1 != l1 {
            return TestResult::Fail("module window straddles an L1 slot boundary");
        }
        // ADRP reaches +/-4 GiB and the veneers rely on it.
        let to_kernel = KERNEL_VIRT_BASE - MODULE_VA_BASE;
        if to_kernel > (4u64 << 30) {
            return TestResult::Fail("module window is beyond ADRP reach of kernel text");
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory/module_text", smoke_module_text_window_placement);

/// The core claim of this file: bytes written into a module image and sealed
/// `Rx` actually execute. Before this allocator existed the loader relocated
/// into a `Vec<u8>` on the NX heap, and this is the test that would have
/// caught it.
fn smoke_module_text_alloc_seal_execute() -> TestResult {
    let mut img = match alloc(1, DomainId::SCRATCH) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("module_text::alloc(1) failed"),
    };
    if !is_module_va(img.base) {
        // SAFETY: nothing was ever executed from this image.
        unsafe { free(img) };
        return TestResult::Fail("allocation landed outside the module window");
    }
    // SAFETY: every page is still `Rw`; the slice is dropped before `protect`.
    unsafe { img.as_mut_slice()[..RET42.len()].copy_from_slice(RET42) };

    if protect(&mut img, 0, 1, Prot::Rx).is_err() {
        // SAFETY: never executed.
        unsafe { free(img) };
        return TestResult::Fail("protect(.., Rx) failed");
    }

    // SAFETY: the page is mapped RX and holds a complete, self-contained
    // `extern "C" fn() -> u32` that touches no memory.
    let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(img.base as *const ()) };
    let got = f();

    // SAFETY: `f` has returned; nothing is executing from the image.
    unsafe { free(img) };
    if got == 42 {
        TestResult::Pass
    } else {
        TestResult::Fail("sealed module text returned the wrong value")
    }
}
kernel_test_in!("memory/module_text", smoke_module_text_alloc_seal_execute);

/// W^X, stated as a property rather than a comment: once a page is executable
/// at its module VA, no kernel window may still offer a writable alias of the
/// frame behind it.
fn smoke_module_text_alias_closed_after_seal() -> TestResult {
    let mut img = match alloc(1, DomainId::SCRATCH) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("module_text::alloc(1) failed"),
    };
    let Some(phys) = __page_phys_for_test(&img, 0) else {
        // SAFETY: never executed.
        unsafe { free(img) };
        return TestResult::Fail("freshly mapped page has no translation");
    };
    if !crate::text_poke::can_protect(phys, 4096) {
        // SAFETY: never executed.
        unsafe { free(img) };
        // aarch64: making one 4 KiB frame of a live 2 MiB linear-map block
        // read-only needs break-before-make on the kernel's own map, which
        // `text_poke` refuses by design. Asserting the alias is closed here
        // would be asserting something the architecture does not offer.
        return TestResult::Skip("text_poke::can_protect refuses this granularity");
    }
    if protect(&mut img, 0, 1, Prot::Rx).is_err() {
        // SAFETY: never executed.
        unsafe { free(img) };
        return TestResult::Fail("protect(.., Rx) failed");
    }
    let writable = crate::text_poke::alias_is_writable(phys);
    // SAFETY: never executed.
    unsafe { free(img) };
    match writable {
        Some(false) => TestResult::Pass,
        Some(true) => TestResult::Fail("executable module page still has a writable alias"),
        None => TestResult::Fail("alias_is_writable could not find the frame"),
    }
}
kernel_test_in!(
    "memory/module_text",
    smoke_module_text_alias_closed_after_seal
);

/// `free` must give back both the VA and the alias. The second half is the
/// one with teeth: a frame returned to the buddy still marked read-only is a
/// fault in whatever allocates it next, arbitrarily far from here.
fn smoke_module_text_free_restores_va_and_alias() -> TestResult {
    let before = pages_used();
    let mut img = match alloc(2, DomainId::SCRATCH) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("module_text::alloc(2) failed"),
    };
    // 2 pages + 1 guard.
    if pages_used() != before + 3 {
        // SAFETY: never executed.
        unsafe { free(img) };
        return TestResult::Fail("alloc did not reserve pages + guard");
    }
    let phys0 = __page_phys_for_test(&img, 0);
    let sealed = protect(&mut img, 0, 1, Prot::Rx).is_ok();
    // SAFETY: never executed.
    unsafe { free(img) };

    if pages_used() != before {
        return TestResult::Fail("free did not release the VA run");
    }
    if !sealed {
        return TestResult::Fail("protect(.., Rx) failed");
    }
    match phys0.and_then(crate::text_poke::alias_is_writable) {
        // The frame is back in the buddy — it must be writable again.
        Some(true) => TestResult::Pass,
        Some(false) => TestResult::Fail("freed frame went back to the buddy read-only"),
        None => TestResult::Skip("alias tracking unavailable on this arch"),
    }
}
kernel_test_in!(
    "memory/module_text",
    smoke_module_text_free_restores_va_and_alias
);

/// A module image's pages must carry its domain's protection key.
///
/// This is the half of driver isolation that lives in the page tables. PKS
/// selects a domain from PTE bits 59..=62 and `IA32_PKRS` holds two rights
/// bits per domain; if every module page carries key 0 then all sixteen
/// domains ARE one domain, `target_domain=` selects nothing, and
/// `enter_domain` narrows rights around pages it cannot distinguish.
///
/// That was the state before: `PtFlags::pk` existed and no caller ever used
/// it, while DESIGN.md described the isolation as real.
#[cfg(target_arch = "x86_64")]
fn smoke_module_text_pages_carry_their_domain_key() -> TestResult {
    use crate::x86_64::paging::{PageTable, PtFlags, WalkIndices};

    // Two different domains, so a pass cannot come from every page happening
    // to carry the same key.
    for domain in [DomainId::SCRATCH, DomainId::DRIVER_2] {
        let mut img = match alloc(2, domain) {
            Ok(i) => i,
            Err(_) => return TestResult::Fail("module_text::alloc failed"),
        };
        // Seal one page so the check also covers `protect`, which rewrites
        // the leaf and could drop the key on the way through.
        let sealed = protect(&mut img, 0, 1, Prot::Rx).is_ok();
        let Ok(root) = kernel_root() else {
            // SAFETY: never executed.
            unsafe { free(img) };
            return TestResult::Fail("kernel root unavailable");
        };

        let mut wrong = None;
        for i in 0..img.pages {
            let va = VirtAddr::new(img.page_va(i));
            let idx = WalkIndices::from_virt(va);
            // SAFETY: read-only walk of the live kernel root; every level was
            // installed by `alloc` through this same root.
            let key = unsafe {
                let pml4 = &*root.kernel_ptr::<PageTable>();
                let pdpt = &*pml4.entries[idx.pml4].addr().kernel_ptr::<PageTable>();
                let pd = &*pdpt.entries[idx.pdpt].addr().kernel_ptr::<PageTable>();
                let pt = &*pd.entries[idx.pd].addr().kernel_ptr::<PageTable>();
                PtFlags::pk_of(pt.entries[idx.pt].flags())
            };
            if key != domain.raw() {
                wrong = Some(i);
                break;
            }
        }
        // SAFETY: never executed.
        unsafe { free(img) };

        if !sealed {
            return TestResult::Fail("protect(.., Rx) failed");
        }
        if wrong.is_some() {
            return TestResult::Fail("a module page does not carry its domain's protection key");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory/module_text",
    smoke_module_text_pages_carry_their_domain_key
);

/// An alloc/free cycle must return exactly the frames it took — no more.
///
/// A page-table reclaim that frees a table twice pushes frames onto the
/// buddy's free list that were never allocated, so the accounted total GROWS
/// across cycles. Honest activity cannot do that, which makes this a sharp
/// detector: `aarch64`'s `free_empty_pt` cascade freed the L3 a second time in
/// place of the L2 (it took the address from an entry *inside* the L2 rather
/// than from the parent entry naming it), and the frame was then handed to two
/// owners at once. That surfaced arbitrarily far away as a slab free-block
/// canary of 0x0 with a page-table descriptor sitting in the block — a
/// diagnosis with nothing pointing back here.
///
/// Bracketed on `free + slab::frames_held()` rather than raw `free`: the slab
/// draws frames from the buddy when a size class runs dry, so a bare `free`
/// delta moves for reasons that have nothing to do with this path.
fn smoke_module_text_alloc_free_conserves_frames() -> TestResult {
    fn accounted() -> usize {
        crate::frame::stats().free + crate::slab::frames_held()
    }

    // Two warm-up cycles: the first builds the window's intermediate page
    // tables and the bookkeeping Vecs, and neither cost repeats.
    for _ in 0..2 {
        match alloc(2, DomainId::SCRATCH) {
            // SAFETY: nothing was executed from the image.
            Ok(img) => unsafe { free(img) },
            Err(_) => return TestResult::Fail("module_text::alloc(2) failed"),
        }
    }

    let before = accounted();
    for _ in 0..8 {
        match alloc(2, DomainId::SCRATCH) {
            // SAFETY: nothing was executed from the image.
            Ok(img) => unsafe { free(img) },
            Err(_) => return TestResult::Fail("module_text::alloc(2) failed"),
        }
    }
    let after = accounted();

    if after > before {
        // More frames accounted for than we started with: the free path put
        // something back that it never took.
        return TestResult::Fail("alloc/free cycle released more frames than it allocated");
    }
    if after < before {
        return TestResult::Fail("alloc/free cycle leaked frames");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/module_text",
    smoke_module_text_alloc_free_conserves_frames
);

/// The guard page must be genuinely absent, not merely reserved in the
/// bitmap — a module running off the end of its own text should fault with a
/// diagnosable address rather than walk into the next module.
fn smoke_module_text_guard_page_unmapped() -> TestResult {
    let img = match alloc(1, DomainId::SCRATCH) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("module_text::alloc(1) failed"),
    };
    let mapped = __page_phys_for_test(&img, 0).is_some();
    let root = match kernel_root() {
        Ok(r) => r,
        Err(_) => {
            // SAFETY: never executed.
            unsafe { free(img) };
            return TestResult::Fail("kernel root unavailable");
        }
    };
    let guard = page_phys(root, img.base + 4096);
    // SAFETY: never executed.
    unsafe { free(img) };
    if !mapped {
        return TestResult::Fail("image page is not mapped");
    }
    if guard.is_some() {
        return TestResult::Fail("guard page is mapped");
    }
    TestResult::Pass
}
kernel_test_in!("memory/module_text", smoke_module_text_guard_page_unmapped);
