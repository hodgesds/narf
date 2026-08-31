//! Per-section relocator: walks `.rela.<section>` entries, resolves
//! each referenced symbol, and patches the target bytes.
//!
//! Linux refs:
//!   * `linux/kernel/module/main.c::simplify_symbols` (`main.c:2261`)
//!     — fills in `st_value` for undefined symbols (resolves them
//!     via `find_symbol`).
//!   * `linux/arch/x86/kernel/module.c::apply_relocate_add`
//!     (`module.c:219`).
//!   * `linux/arch/arm64/kernel/module.c::apply_relocate_add`
//!     (`module.c:231`).
//!
//! NARF adds cap-gating at the symbol-resolution step: if a
//! kernel export declares a `required_cap`, the module must
//! list that CapKind in its manifest.

use crate::elf::reloc::{R_AARCH64_CALL26, R_AARCH64_JUMP26};
use crate::elf::{
    apply_aarch64, apply_x86_64, parse_rela, parse_section, section_name, Elf64Header, RelocError,
    SymbolTable, EM_AARCH64, EM_X86_64,
};
use crate::manifest::Manifest;
use crate::plt::Plt;
use crate::symbols::{resolve, ResolveError};

/// Everything the relocator needs beyond the ELF itself.
///
/// Bundled rather than passed as separate arguments because the PLT has to
/// reach two levels down, and a growing argument list is how the veneer
/// arena would end up being silently skipped on one path.
#[derive(Debug)]
pub struct RelocContext<'a> {
    /// The loading module's manifest, consulted for cap-gated exports.
    pub manifest: &'a Manifest,
    /// aarch64 veneer arena. `None` for an x86_64 image, whose module window
    /// is inside PC32 range of every kernel symbol by construction — see
    /// `crate::plt`.
    pub plt: Option<&'a mut Plt>,
    /// Modules this image resolved a symbol from, deduplicated. The kernel's
    /// own exports are excluded — it never unloads. The loader takes a
    /// reference on each of these so a provider cannot be unloaded out from
    /// under a consumer holding a relocated pointer into its text.
    pub deps: alloc::vec::Vec<crate::symbols::ModuleId>,
}

/// Errors raised by the relocator.
#[derive(Debug, PartialEq, Eq)]
pub enum RelocatorError {
    /// Underlying ELF reloc apply failed.
    ApplyFailed(RelocError),
    /// Symbol referenced by a relocation wasn't found in the kernel
    /// ksymtab or in the module's local symbols.
    SymbolNotFound(alloc::string::String),
    /// Cap requirement: the export wants a cap the module didn't declare.
    CapMissing(alloc::string::String),
    /// Section index referenced by a rela wasn't classified as a
    /// loadable section (no in-memory copy to patch).
    NoTargetSection,
    /// Architecture in the ELF header doesn't match the runtime.
    ArchMismatch { runtime: &'static str, elf: u16 },
    /// An aarch64 branch overflowed ±128 MiB and no veneer could be emitted:
    /// either the arena the layout pass sized is full, or the target is
    /// beyond ADRP's reach. Both mean the module cannot be relocated.
    PltExhausted(alloc::string::String),
}

/// Per-section layout — where the loader put one section in the module
/// image.
///
/// Holds no bytes of its own. `target_addr` is the address the section will
/// actually execute at, inside the mapping `narf_memory::module_text` handed
/// the loader, and the relocator patches it there. It used to own a
/// `Vec<u8>` staging copy that the loader relocated and then kept for the
/// module's entire lifetime — a permanent second copy of every loaded module,
/// for no one's benefit.
#[derive(Debug)]
pub struct SectionPlacement {
    pub section_idx: usize,
    pub target_addr: u64,
    /// Section size in bytes.
    pub size: usize,
}

impl SectionPlacement {
    /// The section's bytes as mapped, for the relocator to patch.
    ///
    /// # Safety
    /// The module image must still be mapped and **writable** at
    /// `target_addr` — that is, this must be called before
    /// `module_text::protect` seals the section's region. After the seal the
    /// returned slice is a write to read-only memory.
    pub unsafe fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: `target_addr` names `size` bytes inside the module image,
        // which the caller guarantees is mapped writable.
        unsafe { core::slice::from_raw_parts_mut(self.target_addr as *mut u8, self.size) }
    }
}

/// Module-local symbol resolution: for a non-undefined symbol, find
/// the address it occupies in memory by looking up the section it
/// lives in.
///
/// Linux ref: `simplify_symbols` (`main.c:2261`).
fn resolve_local_symbol(
    sym: &crate::elf::Elf64Symbol,
    placements: &[SectionPlacement],
) -> Option<u64> {
    let p = placements
        .iter()
        .find(|p| p.section_idx == sym.st_shndx as usize)?;
    Some(p.target_addr.wrapping_add(sym.st_value))
}

/// Apply every relocation in section `rela_idx` against the placement
/// table. The relocation target section is `sh_info` of the rela
/// section header.
pub fn apply_one_rela_section(
    bytes: &[u8],
    hdr: &Elf64Header,
    rela_idx: usize,
    symbols: &SymbolTable,
    placements: &mut [SectionPlacement],
    ctx: &mut RelocContext<'_>,
) -> Result<usize, RelocatorError> {
    let rela_shdr = parse_section(bytes, hdr, rela_idx)
        .map_err(|_| RelocatorError::ApplyFailed(RelocError::OutOfBounds))?;
    let target_section = rela_shdr.sh_info as usize;
    let entsize = rela_shdr.sh_entsize as usize;
    let count = if entsize == 0 {
        0
    } else {
        (rela_shdr.sh_size as usize) / entsize
    };

    let target_addr = placements
        .iter()
        .find(|p| p.section_idx == target_section)
        .map(|p| p.target_addr)
        .ok_or(RelocatorError::NoTargetSection)?;

    let mut applied = 0usize;
    for i in 0..count {
        let off = rela_shdr.sh_offset as usize + i * entsize;
        let r = match parse_rela(bytes, off) {
            Some(r) => r,
            None => continue,
        };
        let sym = match symbols.get(r.sym() as usize) {
            Some(s) => s,
            None => return Err(RelocatorError::SymbolNotFound(alloc::string::String::new())),
        };

        let sym_value = if sym.is_undefined() {
            let name = symbols.name(&sym);
            match resolve(name, None, ctx.manifest) {
                Ok(res) => {
                    if res.owner != crate::symbols::KERNEL_MODULE_ID
                        && !ctx.deps.contains(&res.owner)
                    {
                        ctx.deps.push(res.owner);
                    }
                    res.addr as u64
                }
                Err(ResolveError::Unknown) => {
                    return Err(RelocatorError::SymbolNotFound(name.into()));
                }
                Err(ResolveError::CapMissing(_)) => {
                    return Err(RelocatorError::CapMissing(name.into()));
                }
                Err(ResolveError::CrcMismatch { .. }) => {
                    return Err(RelocatorError::SymbolNotFound(name.into()));
                }
            }
        } else {
            resolve_local_symbol(&sym, placements).unwrap_or(sym.st_value)
        };

        let loc = r.r_offset as usize;

        // aarch64 long branches: when the direct displacement will not fit
        // the 26-bit field, route the call through a veneer in the module's
        // own text. Resolved BEFORE `dest` is borrowed below, because
        // emitting a veneer writes elsewhere in the same image.
        //
        // The veneer is keyed on the fully-resolved target (symbol value plus
        // addend), so the addend is folded in here and passed on as zero —
        // applying it a second time would branch past the callee.
        let (sym_value, addend) = if hdr.e_machine == EM_AARCH64
            && matches!(r.ty(), R_AARCH64_CALL26 | R_AARCH64_JUMP26)
        {
            let target = (sym_value as i64).wrapping_add(r.r_addend) as u64;
            let place = target_addr.wrapping_add(loc as u64);
            let words = (target as i64).wrapping_sub(place as i64) >> 2;
            // Same ±128 MiB bound `apply_aarch64` enforces, checked here so
            // an overflow can be fixed instead of failing the load.
            if !(-(1 << 25)..(1 << 25)).contains(&words) {
                let name = symbols.name(&sym);
                let plt = ctx
                    .plt
                    .as_deref_mut()
                    .ok_or_else(|| RelocatorError::PltExhausted(name.into()))?;
                // SAFETY: relocation runs before `module_text::protect` seals
                // the text region, so the arena is still mapped writable.
                let veneer = unsafe { plt.veneer_for(target) }
                    .ok_or_else(|| RelocatorError::PltExhausted(name.into()))?;
                (veneer, 0)
            } else {
                (sym_value, r.r_addend)
            }
        } else {
            (sym_value, r.r_addend)
        };

        // Find the placement holding the patched section.
        let dest = placements
            .iter_mut()
            .find(|p| p.section_idx == target_section)
            .ok_or(RelocatorError::NoTargetSection)?;
        // SAFETY: relocation runs between `module_text::alloc` and the
        // `protect` calls that seal the image, so every section is still
        // mapped RW.
        let dest_bytes = unsafe { dest.bytes_mut() };
        let result = match hdr.e_machine {
            EM_X86_64 => apply_x86_64(dest_bytes, loc, target_addr, sym_value, addend, r.ty()),
            EM_AARCH64 => apply_aarch64(dest_bytes, loc, target_addr, sym_value, addend, r.ty()),
            other => {
                return Err(RelocatorError::ArchMismatch {
                    runtime: current_runtime_arch_name(),
                    elf: other,
                });
            }
        };
        result.map_err(RelocatorError::ApplyFailed)?;
        applied += 1;
    }
    Ok(applied)
}

/// Walk every `.rela.*` section in `bytes` and apply each. Returns
/// the total number of relocations applied.
pub fn apply_all_relas(
    bytes: &[u8],
    hdr: &Elf64Header,
    symbols: &SymbolTable,
    placements: &mut [SectionPlacement],
    ctx: &mut RelocContext<'_>,
) -> Result<usize, RelocatorError> {
    let mut total = 0usize;
    for i in 0..hdr.e_shnum as usize {
        let shdr = match parse_section(bytes, hdr, i) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if shdr.sh_type != crate::elf::SHT_RELA {
            continue;
        }
        let name = section_name(bytes, hdr, &shdr);
        // Skip relas for sections we didn't load (e.g. debug).
        if !placements
            .iter()
            .any(|p| p.section_idx == shdr.sh_info as usize)
        {
            // Linux silently skips relas for unloaded sections too.
            let _ = name;
            continue;
        }
        total += apply_one_rela_section(bytes, hdr, i, symbols, placements, ctx)?;
    }
    Ok(total)
}

#[inline]
fn current_runtime_arch_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unknown"
    }
}
