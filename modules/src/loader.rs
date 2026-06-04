//! Top-level module loader: parse → verify → allocate → relocate →
//! resolve init/exit → register in registry.
//!
//! Linux ref: `linux/kernel/module/main.c::load_module` (`main.c:3358`)
//! — overall lifecycle.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::id::DomainId;

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
    /// Section placements (text, rodata, data, bss). Each carries
    /// its in-memory buffer and resolved address.
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
        self.placements.iter().map(|p| p.bytes.len()).sum()
    }

    /// Base address (text section, if any; falls back to first
    /// placement). Used by `/proc/modules`.
    pub fn base_addr(&self) -> u64 {
        for p in &self.placements {
            if p.target_addr != 0 {
                return p.target_addr;
            }
        }
        0
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

    // 7. Allocate in-memory buffers for every PROGBITS/NOBITS+ALLOC
    //    section. We synthesize a flat layout where text starts at
    //    a deterministic base offset; the loader's actual VA
    //    placement will come from a future PKS HAL hookup. For now
    //    we use the buffer's own address so relocations land inside
    //    a real allocation that we can hand to a test.
    let mut placements: Vec<SectionPlacement> = Vec::new();
    let mut cursor: u64 = 0;
    for i in 0..hdr.e_shnum as usize {
        let shdr = match parse_section(image, &hdr, i) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if (shdr.sh_flags & SHF_ALLOC) == 0 {
            continue;
        }
        if shdr.sh_type != SHT_PROGBITS && shdr.sh_type != SHT_NOBITS {
            continue;
        }
        // Align cursor.
        let align = shdr.sh_addralign.max(1);
        if align > 1 {
            cursor = (cursor + align - 1) & !(align - 1);
        }
        let size = shdr.sh_size as usize;
        let mut bytes = alloc::vec![0u8; size];
        if shdr.sh_type == SHT_PROGBITS && size > 0 {
            let off = shdr.sh_offset as usize;
            if off + size <= image.len() {
                bytes.copy_from_slice(&image[off..off + size]);
            }
        }
        // Use the buffer's actual address as the runtime target.
        // This makes self-referential relocations land in the
        // correct place even without a separate VA map.
        let addr = if !bytes.is_empty() {
            bytes.as_ptr() as u64
        } else {
            cursor
        };
        placements.push(SectionPlacement {
            section_idx: i,
            target_addr: addr,
            bytes,
        });
        cursor = cursor.wrapping_add(size as u64);
    }

    // 8. Apply relocations.
    let symbols = SymbolTable::new(image, symtab_pair.0, symtab_pair.1);
    let _ = apply_all_relas(image, &hdr, &symbols, &mut placements, &manifest)?;

    // 9. Find init / exit symbols.
    let (init_addr, exit_addr) = find_lifecycle_symbols(&symbols, &placements)?;

    // 10. Parse module parameters.
    let params = match find_section_by_name(image, &hdr, SECT_NARF_KPARAMS) {
        Some(s) => params::parse_section(section_data(image, &s)),
        None => Vec::new(),
    };

    Ok(Arc::new(Module {
        id: crate::symbols::alloc_module_id(),
        manifest,
        domain: domain_id,
        image_size: image.len(),
        placements,
        init_addr,
        exit_addr,
        params,
        refcount: RefCount::new(),
        state: narf_lib::sync::IrqSafeSpinLock::new(ModuleState::Loading),
    }))
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
    let init: ModuleInitFn = unsafe { core::mem::transmute(module.init_addr) };
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
        let exit: ModuleExitFn = unsafe { core::mem::transmute(exit_addr) };
        unsafe { exit() };
    }
    *module.state.lock() = ModuleState::Dead;
    Ok(())
}

/// Format placement diagnostics for /sys/module/<name>/sections/.
pub fn placement_addr_string(p: &SectionPlacement) -> String {
    let mut s = String::new();
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("0x{:016x}\n", p.target_addr));
    s
}
