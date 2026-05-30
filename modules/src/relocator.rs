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

use alloc::vec::Vec;

use crate::elf::{
    apply_aarch64, apply_x86_64, parse_rela, parse_section, section_name, Elf64Header,
    EM_AARCH64, EM_X86_64, RelocError, SymbolTable,
};
use crate::manifest::Manifest;
use crate::symbols::{resolve, ResolveError};

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
}

/// Per-section layout — what the loader allocated. Maps section index
/// to the address + writable buffer it landed in.
#[derive(Debug)]
pub struct SectionPlacement {
    pub section_idx: usize,
    pub target_addr: u64,
    pub bytes: alloc::vec::Vec<u8>,
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
    manifest: &Manifest,
) -> Result<usize, RelocatorError> {
    let rela_shdr = parse_section(bytes, hdr, rela_idx).map_err(|_| {
        RelocatorError::ApplyFailed(RelocError::OutOfBounds)
    })?;
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
            match resolve(name, None, manifest) {
                Ok(res) => res.addr as u64,
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

        // Find the placement holding the patched section.
        let dest = placements
            .iter_mut()
            .find(|p| p.section_idx == target_section)
            .ok_or(RelocatorError::NoTargetSection)?;
        let loc = r.r_offset as usize;
        let result = match hdr.e_machine {
            EM_X86_64 => apply_x86_64(
                &mut dest.bytes,
                loc,
                target_addr,
                sym_value,
                r.r_addend,
                r.ty(),
            ),
            EM_AARCH64 => apply_aarch64(
                &mut dest.bytes,
                loc,
                target_addr,
                sym_value,
                r.r_addend,
                r.ty(),
            ),
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
    placements: &mut Vec<SectionPlacement>,
    manifest: &Manifest,
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
        if !placements.iter().any(|p| p.section_idx == shdr.sh_info as usize) {
            // Linux silently skips relas for unloaded sections too.
            let _ = name;
            continue;
        }
        total += apply_one_rela_section(bytes, hdr, i, symbols, placements, manifest)?;
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
