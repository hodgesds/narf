//! Top-level module loader: parse → verify → allocate → relocate →
//! resolve init/exit → register in registry.
//!
//! Linux ref: `linux/kernel/module/main.c::load_module` (`main.c:3358`)
//! — overall lifecycle.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::module_text::{self, ModuleTextError, Prot};

use crate::domain;
use crate::elf::{
    enumerate_sections, parse_header, parse_section, sections::SECT_MODINFO,
    sections::SECT_NARF_KPARAMS, Elf64Header, HeaderError, SymbolTable, SHF_ALLOC, SHF_EXECINSTR,
    SHF_WRITE, SHT_NOBITS, SHT_PROGBITS, SHT_STRTAB, SHT_SYMTAB,
};
use crate::lifecycle::{ModuleExitFn, ModuleInitFn, ModuleState};
use crate::manifest::{Manifest, ManifestError};
use crate::params::{self, ParamSlot};
use crate::refcount::RefCount;
use crate::relocator::{apply_all_relas, RelocatorError, SectionPlacement};
use crate::sign;
use crate::symbols::{kernel_abi, ModuleId};

/// Errors raised at any step of the load pipeline. Each variant
/// carries enough context to surface a meaningful diagnostic to
/// userspace.
#[derive(Debug, PartialEq, Eq)]
pub enum LoadError {
    /// Signature verification rejected the image.
    SignatureRejected(&'static str),
    /// ELF header decode failed.
    Header(HeaderError),
    /// `.modinfo` parse failed.
    Manifest(ManifestError),
    /// `target_domain=` references an unknown domain.
    Domain(crate::domain::DomainError),
    /// Symbol table missing or empty.
    NoSymbols,
    /// Required modular ELF invariants violated (e.g. SHF_EXECINSTR +
    /// SHF_WRITE in the same section).
    BadSection(&'static str),
    /// A relocation couldn't be applied.
    Relocator(RelocatorError),
    /// A module with that name is already registered.
    AlreadyLoaded(String),
    /// The mandatory `narf_module_init` symbol is missing.
    MissingInit,
    /// The module image could not be mapped, or its regions could not be
    /// given their final permissions.
    Image(ModuleTextError),
}

impl From<HeaderError> for LoadError {
    fn from(e: HeaderError) -> Self {
        LoadError::Header(e)
    }
}

impl From<ManifestError> for LoadError {
    fn from(e: ManifestError) -> Self {
        LoadError::Manifest(e)
    }
}

impl From<RelocatorError> for LoadError {
    fn from(e: RelocatorError) -> Self {
        LoadError::Relocator(e)
    }
}

impl From<crate::domain::DomainError> for LoadError {
    fn from(e: crate::domain::DomainError) -> Self {
        LoadError::Domain(e)
    }
}

/// A fully-loaded module.
///
/// Storage in `text` / `rodata` / `data` / `bss` is owned by this
/// struct; dropping the Module frees the memory. Live modules sit in
/// the registry inside an `Arc<ModuleHandle>` so multiple consumers
/// can observe state + refcount.
#[derive(Debug)]
pub struct Module {
    /// Unique per-session identifier used for KSYMTAB ownership tracking
    /// (DESIGN.md §6).  Assigned by `symbols::alloc_module_id()` during
    /// `load_image` and is stable for the module's lifetime.  Never
    /// reused within a boot session.
    pub id: ModuleId,
    pub manifest: Manifest,
    pub domain: DomainId,
    /// The full image we were loaded from. Kept so /sys can serve
    /// `.modinfo` and signature data on demand. Could be dropped
    /// once init returns; we keep it for diagnostics.
    pub image_size: usize,
    /// The mapped image — text RX, rodata RO, data + bss RW — as handed
    /// out by `narf_memory::module_text`. Taken and unmapped by
    /// [`release_image`] at unload, which is the only thing that makes it
    /// `None`.
    pub image: IrqSafeSpinLock<Option<module_text::ModuleImage>>,
    /// Where each loadable section landed inside [`Module::image`]. Address
    /// and size only; the bytes live in the image.
    pub placements: Vec<SectionPlacement>,
    /// Resolved init address — set during loading.
    pub init_addr: usize,
    /// Resolved exit address — `None` if module has no exit.
    pub exit_addr: Option<usize>,
    /// Module parameters from `.narf_kparams`.
    pub params: Vec<ParamSlot>,
    /// Reference count.
    pub refcount: RefCount,
    /// Current lifecycle state.
    pub state: narf_lib::sync::IrqSafeSpinLock<ModuleState>,
}

impl Module {
    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    /// Aggregate byte size (text + rodata + data + bss).
    pub fn total_size(&self) -> usize {
        self.placements.iter().map(|p| p.size).sum()
    }

    /// Base address of the module image. Used by `/proc/modules`. Zero once
    /// the image has been released.
    pub fn base_addr(&self) -> u64 {
        self.image.lock().as_ref().map(|m| m.base).unwrap_or(0)
    }
}

/// Top-level load entry point. Walks the image through every stage
/// and returns the populated Module on success.
pub fn load_image(image: &[u8]) -> Result<Arc<Module>, LoadError> {
    // 1. Signature verification first — Linux model.
    if let crate::sign::VerifyDecision::Reject(reason) = sign::verify(image) {
        return Err(LoadError::SignatureRejected(reason));
    }

    // 2. ELF header validation.
    let hdr = parse_header(image)?;

    // 3. Find `.modinfo` and parse the manifest.
    let modinfo_section = find_section_by_name(image, &hdr, SECT_MODINFO)
        .ok_or(LoadError::Manifest(ManifestError::Missing))?;
    let modinfo_bytes = section_data(image, &modinfo_section);
    let abi = kernel_abi();
    let manifest = Manifest::parse(modinfo_bytes, abi)?;

    // 4. Resolve target domain.
    let domain_id = domain::resolve(&manifest.target_domain)?;

    // 5. W^X invariant check on every loadable section.
    for (i, shdr, name) in enumerate_sections(image, &hdr) {
        let _ = i;
        if (shdr.sh_flags & SHF_ALLOC) == 0 {
            continue;
        }
        if (shdr.sh_flags & SHF_EXECINSTR) != 0 && (shdr.sh_flags & SHF_WRITE) != 0 {
            let _ = name;
            return Err(LoadError::BadSection("W^X violation in section"));
        }
    }

    // 6. Symbol table.
    let symtab_pair = find_symtab(image, &hdr).ok_or(LoadError::NoSymbols)?;

    // 7. Plan the image layout, then map it. Sections are grouped by the
    //    permission they will end up with so each region is page-aligned and
    //    can be sealed with a single `protect` call.
    let layout = plan_layout(image, &hdr)?;
    let mut mem = module_text::alloc(layout.total_pages).map_err(LoadError::Image)?;

    // 8. Everything past this point can fail with the image already mapped,
    //    so it runs in a helper whose `Err` unmaps before propagating —
    //    otherwise a failed load leaks both frames and module VA.
    let built = build_image(image, &hdr, &manifest, &layout, &mut mem, symtab_pair);
    let BuiltImage {
        placements,
        init_addr,
        exit_addr,
        params,
    } = match built {
        Ok(v) => v,
        Err(e) => {
            // SAFETY: the load failed before `invoke_init`, so nothing has
            // ever executed from this image and nothing holds a pointer into
            // it.
            unsafe { module_text::free(mem) };
            return Err(e);
        }
    };

    Ok(Arc::new(Module {
        id: crate::symbols::alloc_module_id(),
        manifest,
        domain: domain_id,
        image_size: image.len(),
        image: IrqSafeSpinLock::new(Some(mem)),
        placements,
        init_addr,
        exit_addr,
        params,
        refcount: RefCount::new(),
        state: IrqSafeSpinLock::new(ModuleState::Loading),
    }))
}

// ── Image layout ────────────────────────────────────────────────────

/// Which of the image's three permission regions a section belongs to.
///
/// Linux splits the same space seven ways (`enum mod_mem_type` in
/// `include/linux/module.h`), separating `ro_after_init` from plain rodata and
/// giving `.init.*` its own text/data/rodata trio so the whole init region can
/// be **freed** once `narf_module_init` returns. Both are worth having and
/// neither is here yet; the layout is a loop over [`REGION_ORDER`] precisely so
/// adding them is more entries rather than a rewrite.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Region {
    /// `SHF_EXECINSTR` — sealed RX.
    Text,
    /// Neither executable nor writable — sealed RO.
    Rodata,
    /// `SHF_WRITE`, plus `.bss` (`SHT_NOBITS`) — stays RW.
    Data,
}

/// Layout order. Also the order the regions are sealed in.
const REGION_ORDER: [Region; 3] = [Region::Text, Region::Rodata, Region::Data];

const PAGE: u64 = 4096;

#[inline]
fn page_up(v: u64) -> u64 {
    (v + PAGE - 1) & !(PAGE - 1)
}

fn region_of(sh_flags: u64) -> Region {
    if (sh_flags & SHF_EXECINSTR) != 0 {
        Region::Text
    } else if (sh_flags & SHF_WRITE) != 0 {
        Region::Data
    } else {
        Region::Rodata
    }
}

/// What [`build_image`] produces once the image is populated and sealed.
#[derive(Debug)]
struct BuiltImage {
    placements: Vec<SectionPlacement>,
    init_addr: usize,
    exit_addr: Option<usize>,
    params: Vec<ParamSlot>,
}

/// A page-aligned plan for the module image.
#[derive(Debug)]
struct ImageLayout {
    /// `(section_idx, offset_from_image_base, size)` in layout order.
    sections: Vec<(usize, u64, usize)>,
    text_pages: usize,
    rodata_pages: usize,
    total_pages: usize,
}

/// Group every loadable section by permission and give each an offset in the
/// image.
///
/// Linux ref: `kernel/module/main.c::layout_sections`, which groups by
/// `mod_mem_type` for the same reason — so a whole permission class can be
/// flipped in one operation instead of per section.
fn plan_layout(bytes: &[u8], hdr: &Elf64Header) -> Result<ImageLayout, LoadError> {
    let mut sections = Vec::new();
    let mut cursor = 0u64;
    let mut region_start = [0u64; REGION_ORDER.len()];
    let mut region_end = [0u64; REGION_ORDER.len()];

    for (ri, region) in REGION_ORDER.iter().enumerate() {
        cursor = page_up(cursor);
        region_start[ri] = cursor;
        for i in 0..hdr.e_shnum as usize {
            let Ok(shdr) = parse_section(bytes, hdr, i) else {
                continue;
            };
            if (shdr.sh_flags & SHF_ALLOC) == 0 {
                continue;
            }
            if shdr.sh_type != SHT_PROGBITS && shdr.sh_type != SHT_NOBITS {
                continue;
            }
            if region_of(shdr.sh_flags) != *region {
                continue;
            }
            // The image base is page-aligned, so cursor arithmetic satisfies
            // any alignment up to a page. A stricter request would need the
            // allocator to over-allocate and shift; nothing rustc emits for a
            // kernel module asks for it, so reject it loudly rather than
            // silently mis-aligning the section.
            let align = shdr.sh_addralign.max(1);
            if align > PAGE {
                return Err(LoadError::BadSection("section alignment exceeds a page"));
            }
            cursor = (cursor + align - 1) & !(align - 1);
            sections.push((i, cursor, shdr.sh_size as usize));
            cursor = cursor.wrapping_add(shdr.sh_size);
        }
        region_end[ri] = cursor;
    }

    let total = page_up(cursor);
    if total == 0 {
        return Err(LoadError::BadSection("no loadable sections"));
    }
    Ok(ImageLayout {
        sections,
        text_pages: ((page_up(region_end[0]) - region_start[0]) / PAGE) as usize,
        rodata_pages: ((page_up(region_end[1]) - region_start[1]) / PAGE) as usize,
        total_pages: (total / PAGE) as usize,
    })
}

/// Copy sections to their final addresses, relocate them there, seal the
/// read-only regions, and resolve the lifecycle symbols.
///
/// Split out of [`load_image`] so every failure that happens with the image
/// already mapped funnels through one `module_text::free`.
///
/// Relocation happens **in place**, against the addresses the code will
/// actually execute at — same as Linux's `move_module` + `apply_relocations`
/// pair (`kernel/module/main.c:2731`, `:1591`).
fn build_image(
    bytes: &[u8],
    hdr: &Elf64Header,
    manifest: &Manifest,
    layout: &ImageLayout,
    mem: &mut module_text::ModuleImage,
    symtab_pair: (
        crate::elf::Elf64SectionHeader,
        crate::elf::Elf64SectionHeader,
    ),
) -> Result<BuiltImage, LoadError> {
    let mut placements: Vec<SectionPlacement> = Vec::with_capacity(layout.sections.len());
    for &(idx, off, size) in &layout.sections {
        let shdr = parse_section(bytes, hdr, idx)
            .map_err(|_| LoadError::BadSection("unreadable section"))?;
        let va = mem.base + off;
        // SAFETY: `plan_layout` sized the image to cover `[off, off + size)`,
        // and every page is still `Rw` — nothing has been sealed yet.
        let dst = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, size) };
        if shdr.sh_type == SHT_PROGBITS && size > 0 {
            let src = shdr.sh_offset as usize;
            let end = src
                .checked_add(size)
                .ok_or(LoadError::BadSection("section offset overflows"))?;
            if end > bytes.len() {
                return Err(LoadError::BadSection("section extends past end of image"));
            }
            dst.copy_from_slice(&bytes[src..end]);
        } else {
            // `module_text::alloc` trap-fills, so `.bss` has to be zeroed
            // explicitly rather than left as it came.
            dst.fill(0);
        }
        placements.push(SectionPlacement {
            section_idx: idx,
            target_addr: va,
            size,
        });
    }

    let symbols = SymbolTable::new(bytes, symtab_pair.0, symtab_pair.1);
    let _ = apply_all_relas(bytes, hdr, &symbols, &mut placements, manifest)?;

    // Resolved before sealing so that every step which can fail is on the
    // writable side of the seal.
    let (init_addr, exit_addr) = find_lifecycle_symbols(&symbols, &placements)?;

    let params = match find_section_by_name(bytes, hdr, SECT_NARF_KPARAMS) {
        Some(s) => params::parse_section(section_data(bytes, &s)),
        None => Vec::new(),
    };

    // Seal. `protect` closes each region's writable linear-map alias before
    // publishing the new permissions, so a failure here leaves nothing
    // executable. Data + bss keep the `Rw` they were allocated with.
    module_text::protect(mem, 0, layout.text_pages, Prot::Rx).map_err(LoadError::Image)?;
    module_text::protect(mem, layout.text_pages, layout.rodata_pages, Prot::Ro)
        .map_err(LoadError::Image)?;

    Ok(BuiltImage {
        placements,
        init_addr,
        exit_addr,
        params,
    })
}

/// Helper: find a section by exact name.
fn find_section_by_name(
    bytes: &[u8],
    hdr: &Elf64Header,
    target: &str,
) -> Option<crate::elf::Elf64SectionHeader> {
    for (_i, shdr, name) in enumerate_sections(bytes, hdr) {
        if name == target {
            return Some(shdr);
        }
    }
    None
}

/// Helper: return the file-bytes for a section.
fn section_data<'a>(bytes: &'a [u8], shdr: &crate::elf::Elf64SectionHeader) -> &'a [u8] {
    let off = shdr.sh_offset as usize;
    let end = off.saturating_add(shdr.sh_size as usize).min(bytes.len());
    &bytes[off..end]
}

/// Find the SYMTAB + paired STRTAB.
fn find_symtab(
    bytes: &[u8],
    hdr: &Elf64Header,
) -> Option<(
    crate::elf::Elf64SectionHeader,
    crate::elf::Elf64SectionHeader,
)> {
    let mut symtab = None;
    for i in 0..hdr.e_shnum as usize {
        let s = parse_section(bytes, hdr, i).ok()?;
        if s.sh_type == SHT_SYMTAB {
            symtab = Some(s);
            break;
        }
    }
    let symtab = symtab?;
    // sh_link of a SYMTAB points at the matching STRTAB.
    let strtab_idx = symtab.sh_link as usize;
    let strtab = parse_section(bytes, hdr, strtab_idx).ok()?;
    if strtab.sh_type != SHT_STRTAB {
        return None;
    }
    Some((symtab, strtab))
}

/// Locate `narf_module_init` (required) and `narf_module_exit`
/// (optional) within the module's local symbols.
///
/// Both `SHN_ABS` symbols (absolute address baked into `st_value` —
/// commonly used by build-time tooling that knows the function's
/// final VA) and section-relative symbols are honoured. Linux's
/// `find_module_sections` does the same in `kernel/module/main.c`
/// (`main.c:2606`); ABS symbols there land at their `st_value`
/// unchanged.
fn find_lifecycle_symbols(
    symbols: &SymbolTable,
    placements: &[SectionPlacement],
) -> Result<(usize, Option<usize>), LoadError> {
    let mut init = None;
    let mut exit = None;
    for i in 0..symbols.len() {
        let s = match symbols.get(i) {
            Some(s) => s,
            None => continue,
        };
        if s.is_undefined() {
            continue;
        }
        let name = symbols.name(&s);
        if name == "narf_module_init" {
            init = resolve_local_address(&s, placements);
        } else if name == "narf_module_exit" {
            exit = resolve_local_address(&s, placements);
        }
    }
    let init = init.ok_or(LoadError::MissingInit)?;
    Ok((init, exit))
}

/// Resolve a defined symbol to a runtime address. Handles ABS
/// (st_shndx == SHN_ABS) and section-relative symbols. Returns
/// `None` if the symbol references a section we didn't lay out.
fn resolve_local_address(
    sym: &crate::elf::Elf64Symbol,
    placements: &[SectionPlacement],
) -> Option<usize> {
    if sym.st_shndx == crate::elf::symbols::SHN_ABS {
        // Absolute symbol — the value is the runtime address.
        return Some(sym.st_value as usize);
    }
    let p = placements
        .iter()
        .find(|p| p.section_idx == sym.st_shndx as usize)?;
    Some((p.target_addr.wrapping_add(sym.st_value)) as usize)
}

/// Call the module's init function, transitioning to Live on success.
///
/// Sets `symbols::CURRENT_INIT_MODULE_ID` to `module.id` for the
/// duration of the call so that any `register_export` / `export` /
/// `export_with_cap` calls from inside the module's init are
/// automatically attributed to the right owner (DESIGN.md §6).
/// The context is always restored to `KERNEL_MODULE_ID` on return,
/// even on error.
///
/// # Safety
/// The caller must have just relocated the module via `load_image`
/// AND must be calling this on a freshly-loaded module in state
/// `Loading`.
pub unsafe fn invoke_init(module: &Module) -> Result<(), crate::lifecycle::LifecycleError> {
    // Arm the init-attribution context so exports registered during
    // init are tagged with this module's id.
    crate::symbols::set_init_context(module.id);
    // SAFETY: `module.init_addr` is the runtime address of the module's
    // `init_module` symbol, resolved from the relocated image by
    // `find_lifecycle_symbols` during `load_image`. The caller's contract
    // guarantees the module was just relocated, so that code is mapped and
    // executable at this address. `ModuleInitFn` is `unsafe extern "C"
    // fn() -> i32`, matching the C ABI the module was compiled with, so the
    // pointer-to-fn-pointer transmute is layout-compatible (both are a
    // single non-null code pointer).
    // SAFETY: Valid memory or trusted environment
    let init: ModuleInitFn = unsafe { core::mem::transmute(module.init_addr) };
    // SAFETY: `init` points at the module's relocated init routine (see
    // above). It is the module's documented entry point and is sound to call
    // here because we are running in the kernel context with the
    // init-attribution context armed and the module in state `Loading`.
    // SAFETY: Valid memory or trusted environment
    let rc = unsafe { init() };
    // Restore unconditionally — even on failure the next init call
    // must start clean.
    crate::symbols::set_init_context(crate::symbols::KERNEL_MODULE_ID);
    if rc != 0 {
        return Err(crate::lifecycle::LifecycleError::InitFailed(rc));
    }
    *module.state.lock() = ModuleState::Live;
    Ok(())
}

/// Call the module's exit function (if present) and transition to
/// Dead. Returns Busy if the refcount is still non-zero.
///
/// # Safety
/// The module must be in state Live (or Going if a previous attempt
/// re-entered this function partway).
pub unsafe fn invoke_exit(module: &Module) -> Result<(), crate::lifecycle::LifecycleError> {
    if !module.refcount.is_zero() {
        return Err(crate::lifecycle::LifecycleError::Busy(
            module.refcount.snapshot(),
        ));
    }
    *module.state.lock() = ModuleState::Going;
    if let Some(exit_addr) = module.exit_addr {
        // SAFETY: `exit_addr` is the runtime address of the module's
        // `cleanup_module` symbol, resolved from the relocated image during
        // `load_image` and stored in `module.exit_addr`. The module is in
        // state `Going` (set just above) with a zero refcount, so its code
        // is still mapped. `ModuleExitFn` is `unsafe extern "C" fn()`,
        // matching the module's C ABI, so the transmute between two
        // single code pointers is layout-compatible.
        // SAFETY: Valid memory or trusted environment
        let exit: ModuleExitFn = unsafe { core::mem::transmute(exit_addr) };
        // SAFETY: `exit` points at the module's relocated cleanup routine
        // (see above). The module is Live/Going with refcount zero, so no
        // other code holds references into it; calling its documented exit
        // entry point here is sound.
        // SAFETY: Valid memory or trusted environment
        unsafe { exit() };
    }
    *module.state.lock() = ModuleState::Dead;
    Ok(())
}

/// Unmap the module's image and return its frames.
///
/// # Safety
/// The module must be `Dead`: `invoke_exit` has returned, its KSYMTAB exports
/// have been swept by `symbols::unregister_exports_of`, and no CPU may still
/// be executing its code or holding a pointer into it. `sys_delete_module` is
/// the only intended caller.
pub unsafe fn release_image(module: &Module) {
    // `take()` in its own statement so the image lock is released before
    // `module_text::free` runs — freeing walks page tables and takes the
    // window's VA lock, and holding an unrelated lock across that is how
    // lock-order inversions start.
    let taken = module.image.lock().take();
    if let Some(mem) = taken {
        // SAFETY: forwarded from this function's contract.
        unsafe { module_text::free(mem) };
    }
}

/// Format placement diagnostics for /sys/module/<name>/sections/.
pub fn placement_addr_string(p: &SectionPlacement) -> String {
    let mut s = String::new();
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("0x{:016x}\n", p.target_addr));
    s
}
