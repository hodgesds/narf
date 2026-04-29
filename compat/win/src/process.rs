//! `WinProcess` — Win32 personality wrapping a NARF address space.
//!
//! M0 loader pipeline:
//!
//! 1. Parse PE32+ via `pe::parse` (header + sections + imports +
//!    DIR64 relocs).
//! 2. Pick a runtime image base. M0 honours the image's preferred
//!    `ImageBase`; ASLR lands in M1.
//! 3. Materialize each section into freshly-allocated frames, copy
//!    `raw_size` bytes from the file blob into them, and `map_region`
//!    them at `(chosen_base + virt_addr)` with PE-derived perms.
//! 4. Apply DIR64 base relocs (write `chosen_base + (existing - image_base)`
//!    at every reloc target — no-op when chosen_base == image_base, but
//!    the apply path is exercised regardless so M1 can drop ASLR in
//!    without re-plumbing the loader).
//! 5. Resolve every import via the supplied `ImportResolver`, patching
//!    the IAT slot with the resolver's returned address (the M0
//!    resolver returns trampoline VAs — not the raw `Thunk` pointer
//!    — once `thunks::abi` lands).
//!
//! `resolve_imports` and `compute_relocs` are pure helpers exposed
//! for unit testing without any kernel-mode plumbing. The full
//! `load_pe` pipeline is `unsafe` and only callable from inside the
//! kernel (it touches the frame allocator + activates page tables).

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_capabilities::{Cap, CapKind, CapType, Invoke};
#[allow(unused_imports)]
use narf_capabilities as _;
use narf_memory::{
    alloc_frame, AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr,
};

use crate::pe::{self, BaseRelocKind, PeError, PeImage, Section};
use crate::personality::{self, Layout};

// ── cap-typing ────────────────────────────────────────────────────

/// Spawn-authority alias for a loaded Win32 image.
///
/// Per `capabilities/src/lib.rs`, `Invoke` is the right tag for
/// "execute / activate / trigger an object's behavior" — exactly
/// the semantic we want here ("may turn this loaded image into a
/// running thread"). The `Rights` trait is sealed so we reuse
/// `Invoke` rather than mint a new tag; downstream code reads
/// `Cap<WinProcess, Spawn>` to make the intent self-documenting.
pub type Spawn = Invoke;

/// A loaded Win32 process. `address_space` is the underlying NARF
/// address space with every PE section mapped + relocated +
/// IAT-patched, plus a user-RW PEB page at `peb_va` and a user-RW
/// TEB page at `teb_va`. SEH dispatch tables and the ldr-data /
/// process-parameters blocks land in M1.
///
/// On entry to user mode the per-arch trampoline programs the
/// segment / system register that holds the TEB pointer:
///
/// - **amd64:** `IA32_GS_BASE` ← `teb_va`. Win32 code reaches the
///   PEB via `gs:[0x60]`, the TEB self-pointer via `gs:[0x30]`,
///   and the stack range via `gs:[0x08]` / `gs:[0x10]`.
/// - **aarch64:** `TPIDR_EL0` ← `teb_va`. Same layout.
///
/// `entry` is the ImageBase-adjusted entry point — `image_base +
/// PE.AddressOfEntryPoint`.
#[derive(Debug)]
pub struct WinProcess {
    pub address_space: Arc<AddressSpace>,
    pub entry:         VirtAddr,
    pub image_base:    u64,
    pub size_of_image: u32,
    pub peb_va:        VirtAddr,
    pub teb_va:        VirtAddr,
    pub stack_base:    VirtAddr,
    pub stack_top:     VirtAddr,
}

impl CapType for WinProcess {
    // Reuse the canonical Process kind — a Win32 process is still a
    // process from the object-table's perspective. The personality
    // (PE-based vs. ELF-based) is encoded in the cap-type marker
    // type, not in the object-table kind tag.
    const KIND: CapKind = CapKind::Process;
}

// ── error type ────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    Pe(PeError),
    /// The image imports a `(module, symbol)` we have no thunk for.
    /// We refuse the image rather than installing a silent stub —
    /// see spec §4.
    UnresolvedImport,
    /// A reloc / import / IAT slot points at an RVA that does not
    /// land inside any mapped section. Indicates a malformed image
    /// the parser missed.
    BadFixupRva,
    /// Frame allocator returned `Err` while materializing a section.
    NoFrame,
    /// `AddressSpace::map_region` rejected the region — overlap,
    /// alignment, or backing-list mismatch.
    AddressSpace,
    /// Section perms parser produced `WRITE | EXEC`. Same fingerprint
    /// the PE parser already rejects, but re-checked here so the
    /// invariant survives a bug in the parser path.
    WritableExecutableSection,
    NotImplemented,
}

impl From<PeError> for LoadError {
    fn from(e: PeError) -> Self { LoadError::Pe(e) }
}

/// Address resolved by an import handler — the runtime VA the IAT
/// slot will be patched to. Distinct from `&'static dyn Thunk`
/// because the value the CPU actually loads is the per-arch
/// trampoline entry, not the trait-object pointer.
pub type ImportResolver = fn(module: &str, symbol: &str) -> Option<u64>;

// ── pure helpers (testable on host) ───────────────────────────────

/// Translate a PE section's `Characteristics` into a `RegionPerms`,
/// re-checking the W^X invariant. Returns `WritableExecutableSection`
/// if both `MEM_WRITE` and `MEM_EXECUTE` are set — defence in depth
/// against a parser bug.
pub fn perms_of(characteristics: u32) -> Result<RegionPerms, LoadError> {
    const MEM_READ:    u32 = 0x4000_0000;
    const MEM_WRITE:   u32 = 0x8000_0000;
    const MEM_EXECUTE: u32 = 0x2000_0000;
    let w = characteristics & MEM_WRITE   != 0;
    let x = characteristics & MEM_EXECUTE != 0;
    if w && x {
        return Err(LoadError::WritableExecutableSection);
    }
    // Read is implicit on every PE section in practice; honour the
    // bit when set, default to readable when clear (no PE toolchain
    // emits a section with READ off).
    let _r = characteristics & MEM_READ != 0;
    let mut p = RegionPerms::READ;
    if w { p = p | RegionPerms::WRITE; }
    if x { p = p | RegionPerms::EXEC; }
    Ok(p)
}

/// Resolve every PE import to a (iat_rva, address) pair using
/// `resolve`. Returns `UnresolvedImport` on the first miss — silent
/// stubs are out per spec §4.
pub fn resolve_imports(
    image: &PeImage<'_>,
    resolve: ImportResolver,
) -> Result<Vec<(u32, u64)>, LoadError> {
    let mut out = Vec::with_capacity(image.imports.len());
    for imp in &image.imports {
        match resolve(&imp.module, &imp.symbol) {
            Some(addr) => out.push((imp.iat_rva, addr)),
            None       => return Err(LoadError::UnresolvedImport),
        }
    }
    Ok(out)
}

/// For each DIR64 base reloc, produce `(rva, value_to_write)` where
/// `value_to_write` is the existing in-image u64 (the link-time VA)
/// adjusted by the runtime delta `chosen_base - image.image_base`.
///
/// This reads the existing u64 from the *file bytes* via the PE's
/// section table, which is correct because the loader has not yet
/// modified them — every reloc target is a u64 in some `PT_LOAD`-
/// equivalent section, populated by the linker, that the loader
/// will memcpy into a fresh frame before this fixup runs.
pub fn compute_relocs(
    image: &PeImage<'_>,
    chosen_base: u64,
) -> Result<Vec<(u32, u64)>, LoadError> {
    let delta = chosen_base.wrapping_sub(image.image_base);
    let mut out = Vec::with_capacity(image.relocs.len());
    for r in &image.relocs {
        match r.kind {
            BaseRelocKind::Dir64 => {
                let off = rva_to_file(&image.sections, r.rva)
                    .ok_or(LoadError::BadFixupRva)?;
                if image.bytes.len() < off + 8 {
                    return Err(LoadError::BadFixupRva);
                }
                let existing = u64::from_le_bytes(
                    image.bytes[off..off + 8].try_into().unwrap()
                );
                out.push((r.rva, existing.wrapping_add(delta)));
            }
        }
    }
    Ok(out)
}

fn rva_to_file(sections: &[Section], rva: u32) -> Option<usize> {
    for s in sections {
        let start = s.virt_addr;
        let end = s.virt_addr.checked_add(s.virt_size)?;
        if rva >= start && rva < end {
            let delta = rva - start;
            if delta >= s.raw_size { return None; }
            return Some(s.raw_offset as usize + delta as usize);
        }
    }
    None
}

/// Find the section + page-relative offset for an RVA among the
/// loaded sections' frame backings. Returns `(phys_frame, byte_off
/// within frame)`. Used by the kernel-mode loader to write fixups
/// into already-materialized pages.
pub fn rva_to_phys<'a>(
    sections: &[Section],
    section_frames: &'a [Vec<PhysAddr>],
    rva: u32,
) -> Option<(PhysAddr, usize)> {
    for (s, frames) in sections.iter().zip(section_frames.iter()) {
        let start = s.virt_addr;
        let end = s.virt_addr.checked_add(s.virt_size)?;
        if rva >= start && rva < end {
            let delta = (rva - start) as usize;
            let page = delta >> 12;
            let off  = delta & 0xFFF;
            return Some((*frames.get(page)?, off));
        }
    }
    None
}

// ── full pipeline (kernel-mode only) ──────────────────────────────

/// Parse a PE32+ blob, allocate a fresh user `AddressSpace`, map
/// every section, apply base relocs, resolve imports + patch IAT,
/// and return a `Cap<WinProcess, Spawn>`.
///
/// Honours `image.image_base` as the runtime base. ASLR (random
/// base + reloc-driven adjustment) lands in M1; the loader exercises
/// the reloc-apply path regardless so M1 is a one-line change.
///
/// # Safety
/// - `bytes` lives for the duration of the call.
/// - The kernel runs with the low 4 GiB identity-mapped so
///   `PhysAddr::raw() as *mut u8` writes reach the backing storage.
/// - Frame allocator is initialised.
/// - The caller has authority to spawn user processes (the returned
///   cap is unconditionally minted; cap-checking on the *call site*
///   is the existing `userspace::handlers::sys_exec`-style path,
///   which is what eventually invokes this).
pub unsafe fn load_pe(
    bytes:   &[u8],
    resolve: ImportResolver,
) -> Result<WinProcess, LoadError> {
    let image = pe::parse(bytes)?;
    let chosen_base = image.image_base;

    // SAFETY: kernel-mode contract documented above.
    let address_space = unsafe { AddressSpace::new_for_user() }
        .map_err(|_| LoadError::AddressSpace)?;

    // Materialize each section into freshly-allocated frames.
    let mut section_frames: Vec<Vec<PhysAddr>> =
        Vec::with_capacity(image.sections.len());
    for s in &image.sections {
        let pages = ((s.virt_size as u64 + 0xFFF) >> 12) as usize;
        let mut frames = Vec::with_capacity(pages);
        for _ in 0..pages {
            let f = alloc_frame().map_err(|_| LoadError::NoFrame)?;
            frames.push(f.start_address());
        }
        // Zero every page so the virt_size > raw_size tail is BSS-zero.
        for &p in &frames {
            // SAFETY: identity-mapped low-4-GiB frames.
            unsafe { core::ptr::write_bytes(p.raw() as *mut u8, 0, 4096); }
        }
        // Copy raw_size bytes from the file blob into the frames,
        // page by page.
        if s.raw_size != 0 {
            let raw_off  = s.raw_offset as usize;
            let raw_size = s.raw_size as usize;
            if bytes.len() < raw_off + raw_size {
                return Err(LoadError::Pe(PeError::BadSection));
            }
            let src = &bytes[raw_off..raw_off + raw_size];
            let mut written = 0;
            for &frame in &frames {
                if written >= src.len() { break; }
                let chunk = core::cmp::min(4096, src.len() - written);
                // SAFETY: identity-mapped freshly-allocated frame; chunk <= 4 KiB.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src.as_ptr().add(written),
                        frame.raw() as *mut u8,
                        chunk,
                    );
                }
                written += chunk;
            }
        }
        // Map the region at chosen_base + virt_addr with PE perms.
        let perms = perms_of(s.characteristics)?;
        address_space.map_region(Region {
            base:  VirtAddr::new(chosen_base.wrapping_add(s.virt_addr as u64)),
            len:   (pages as u64) << 12,
            perms,
            phys:  frames.clone(),
        }).map_err(|_| LoadError::AddressSpace)?;
        section_frames.push(frames);
    }

    // Apply DIR64 relocs.
    for (rva, value) in compute_relocs(&image, chosen_base)? {
        let (frame, off) = rva_to_phys(&image.sections, &section_frames, rva)
            .ok_or(LoadError::BadFixupRva)?;
        // Reloc must not straddle a page boundary — DIR64 is 8 bytes,
        // 8-byte-aligned in well-formed images, but a malicious image
        // can name an unaligned RVA. Refuse it.
        if off + 8 > 4096 {
            return Err(LoadError::BadFixupRva);
        }
        // SAFETY: identity-mapped, page-resident, bounds checked above.
        unsafe {
            let p = (frame.raw() as *mut u8).add(off) as *mut u64;
            p.write_unaligned(value);
        }
    }

    // Patch the IAT.
    for (rva, addr) in resolve_imports(&image, resolve)? {
        let (frame, off) = rva_to_phys(&image.sections, &section_frames, rva)
            .ok_or(LoadError::BadFixupRva)?;
        if off + 8 > 4096 {
            return Err(LoadError::BadFixupRva);
        }
        // SAFETY: identity-mapped, page-resident, bounds checked.
        unsafe {
            let p = (frame.raw() as *mut u8).add(off) as *mut u64;
            p.write_unaligned(addr);
        }
    }

    // Materialize the PEB + TEB. One frame each, mapped user-RW at
    // the layout-defined VAs. Population is byte-level to dodge
    // having to maintain full PEB / TEB Rust structs.
    let layout = Layout::defaults(chosen_base, /*pid=*/ 1, /*tid=*/ 1);

    let peb_frame = alloc_frame().map_err(|_| LoadError::NoFrame)?.start_address();
    let teb_frame = alloc_frame().map_err(|_| LoadError::NoFrame)?.start_address();

    // SAFETY: identity-mapped low-4-GiB frames; we just allocated
    // them so no concurrent reader exists.
    unsafe {
        core::ptr::write_bytes(peb_frame.raw() as *mut u8, 0, 4096);
        core::ptr::write_bytes(teb_frame.raw() as *mut u8, 0, 4096);

        // Build the page contents on the kernel side, then they'll
        // be visible to user mode through the user-VA mapping.
        let peb_page = &mut *(peb_frame.raw() as *mut [u8; personality::PAGE]);
        let teb_page = &mut *(teb_frame.raw() as *mut [u8; personality::PAGE]);
        personality::init_peb(peb_page, layout);
        personality::init_teb(teb_page, layout);
    }

    address_space.map_region(Region {
        base:  VirtAddr::new(layout.peb_va),
        len:   4096,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys:  alloc::vec![peb_frame],
    }).map_err(|_| LoadError::AddressSpace)?;
    address_space.map_region(Region {
        base:  VirtAddr::new(layout.teb_va),
        len:   4096,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys:  alloc::vec![teb_frame],
    }).map_err(|_| LoadError::AddressSpace)?;

    Ok(WinProcess {
        address_space: Arc::new(address_space),
        entry:         VirtAddr::new(chosen_base.wrapping_add(image.entry)),
        image_base:    chosen_base,
        size_of_image: image.size_of_image,
        peb_va:        VirtAddr::new(layout.peb_va),
        teb_va:        VirtAddr::new(layout.teb_va),
        stack_base:    VirtAddr::new(layout.stack_base),
        stack_top:     VirtAddr::new(layout.stack_top),
    })
}

impl WinProcess {
    /// Mint a fresh `Cap<WinProcess, Spawn>` authorising the holder
    /// to spawn this image into a runnable thread. Object-table
    /// allocation lives entirely in `Cap::bootstrap` — see
    /// `capabilities/src/lib.rs` §"Safe mint".
    pub fn mint_spawn_cap(&self) -> Cap<WinProcess, Spawn> {
        Cap::<WinProcess, Spawn>::bootstrap()
    }
}

// ── tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec;
    use super::*;
    use crate::pe::{BaseReloc, BaseRelocKind, Import, Machine, PeImage};

    fn dummy_image<'a>(bytes: &'a [u8]) -> PeImage<'a> {
        PeImage {
            bytes,
            machine:    Machine::Amd64,
            entry:      0x1000,
            image_base: 0x1_4000_0000,
            size_of_image: 0x3000,
            sections:   vec![Section {
                name: *b".text\0\0\0",
                virt_addr: 0x1000,
                virt_size: 0x100,
                raw_offset: 0,
                raw_size:   0x10,
                characteristics: 0x6000_0000, // R+X
            }],
            imports:    vec![],
            relocs:     vec![],
        }
    }

    #[test]
    fn perms_of_translates_pe_chars() {
        // R+X
        let p = perms_of(0x6000_0000).unwrap();
        assert!(p.contains(RegionPerms::READ));
        assert!(p.contains(RegionPerms::EXEC));
        assert!(!p.contains(RegionPerms::WRITE));
        // R+W
        let p = perms_of(0xC000_0000).unwrap();
        assert!(p.contains(RegionPerms::READ));
        assert!(p.contains(RegionPerms::WRITE));
        assert!(!p.contains(RegionPerms::EXEC));
        // W+X — refused.
        assert_eq!(perms_of(0xA000_0000).unwrap_err(),
                   LoadError::WritableExecutableSection);
    }

    #[test]
    fn resolve_imports_succeeds() {
        let bytes = vec![0u8; 0x100];
        let mut img = dummy_image(&bytes);
        img.imports = vec![Import {
            module:  "kernel32.dll".into(),
            symbol:  "exitprocess".into(),
            iat_rva: 0x20A0,
        }];
        fn r(_m: &str, _s: &str) -> Option<u64> { Some(0xDEAD_BEEF) }
        let v = resolve_imports(&img, r).unwrap();
        assert_eq!(v, vec![(0x20A0, 0xDEAD_BEEF)]);
    }

    #[test]
    fn resolve_imports_unresolved() {
        let bytes = vec![0u8; 0x100];
        let mut img = dummy_image(&bytes);
        img.imports = vec![Import {
            module:  "kernel32.dll".into(),
            symbol:  "createfilew".into(),
            iat_rva: 0x20A0,
        }];
        fn r(_m: &str, _s: &str) -> Option<u64> { None }
        assert_eq!(resolve_imports(&img, r).unwrap_err(),
                   LoadError::UnresolvedImport);
    }

    #[test]
    fn compute_relocs_zero_delta_preserves_value() {
        // Build a 0x20-byte file with a u64 at file offset 8 (= RVA
        // 0x1008 given .text at virt_addr 0x1000, raw_offset 0).
        let mut bytes = vec![0u8; 0x20];
        bytes[8..16].copy_from_slice(&0x1_4000_2000u64.to_le_bytes());
        let mut img = dummy_image(&bytes);
        img.sections[0].raw_size = 0x20;
        img.sections[0].virt_size = 0x20;
        img.relocs = vec![BaseReloc { rva: 0x1008, kind: BaseRelocKind::Dir64 }];
        let v = compute_relocs(&img, img.image_base).unwrap();
        // Delta is zero, so value is preserved.
        assert_eq!(v, vec![(0x1008, 0x1_4000_2000)]);
    }

    #[test]
    fn compute_relocs_applies_delta() {
        let mut bytes = vec![0u8; 0x20];
        bytes[8..16].copy_from_slice(&0x1_4000_2000u64.to_le_bytes());
        let mut img = dummy_image(&bytes);
        img.sections[0].raw_size = 0x20;
        img.sections[0].virt_size = 0x20;
        img.relocs = vec![BaseReloc { rva: 0x1008, kind: BaseRelocKind::Dir64 }];
        // Choose a base 0x1_0000_0000 above the preferred — every
        // reloc target shifts by exactly that.
        let v = compute_relocs(&img, 0x2_4000_0000).unwrap();
        assert_eq!(v, vec![(0x1008, 0x2_4000_2000)]);
    }

    #[test]
    fn compute_relocs_rejects_bad_rva() {
        let bytes = vec![0u8; 0x20];
        let mut img = dummy_image(&bytes);
        img.relocs = vec![BaseReloc { rva: 0x9000, kind: BaseRelocKind::Dir64 }];
        assert_eq!(compute_relocs(&img, img.image_base).unwrap_err(),
                   LoadError::BadFixupRva);
    }

    #[test]
    fn rva_to_phys_resolves_within_section() {
        let bytes = vec![0u8; 0x20];
        let mut img = dummy_image(&bytes);
        img.sections[0].virt_size = 0x2000;
        let frames = vec![
            vec![PhysAddr::new(0x10_0000), PhysAddr::new(0x20_0000)],
        ];
        // RVA 0x1500: section 0, page 0, offset 0x500.
        let (frame, off) = rva_to_phys(&img.sections, &frames, 0x1500).unwrap();
        assert_eq!(frame.raw(), 0x10_0000);
        assert_eq!(off, 0x500);
        // RVA 0x2500: section 0 (virt_size = 0x2000 covers
        // 0x1000..0x3000), delta = 0x1500, page = 1, offset 0x500.
        let (frame, off) = rva_to_phys(&img.sections, &frames, 0x2500).unwrap();
        assert_eq!(frame.raw(), 0x20_0000);
        assert_eq!(off, 0x500);
        // RVA outside any section → None.
        assert!(rva_to_phys(&img.sections, &frames, 0x9000).is_none());
    }
}
