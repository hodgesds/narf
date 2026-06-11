//! ELF64 relocation decoding + arch-specific application.
//!
//! Linux refs:
//!   * `linux/arch/x86/kernel/module.c::__write_relocate_add`
//!     (`module.c:82`) — x86_64 R_X86_64_* handling.
//!   * `linux/arch/arm64/kernel/module.c::apply_relocate_add`
//!     (`module.c:231`) — aarch64 R_AARCH64_* handling.
//!
//! We support the core relocation types every kernel module
//! routinely emits — enough for a Rust no_std module compiled
//! with -fno-PIE / -mcmodel=kernel on x86_64 and -fpic on aarch64.

use core::convert::TryInto;

/// Decoded Elf64 RELA entry.
#[derive(Copy, Clone, Debug)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Elf64Rela {
    /// Symbol-table index portion of `r_info`.
    #[inline]
    pub fn sym(&self) -> u32 {
        (self.r_info >> 32) as u32
    }
    /// Relocation type portion of `r_info`.
    #[inline]
    pub fn ty(&self) -> u32 {
        self.r_info as u32
    }
}

/// Parse one RELA entry at byte offset `off` in `bytes`.
pub fn parse_rela(bytes: &[u8], off: usize) -> Option<Elf64Rela> {
    if off + 24 > bytes.len() {
        return None;
    }
    Some(Elf64Rela {
        r_offset: u64::from_le_bytes(bytes[off..off + 8].try_into().ok()?),
        r_info: u64::from_le_bytes(bytes[off + 8..off + 16].try_into().ok()?),
        r_addend: i64::from_le_bytes(bytes[off + 16..off + 24].try_into().ok()?),
    })
}

// ── x86_64 relocation types ──────────────────────────────────────────

pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;
pub const R_X86_64_PC64: u32 = 24;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;

// ── aarch64 relocation types ─────────────────────────────────────────

pub const R_AARCH64_NONE: u32 = 0;
pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_ABS32: u32 = 258;
pub const R_AARCH64_PREL64: u32 = 260;
pub const R_AARCH64_PREL32: u32 = 261;
pub const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
pub const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
pub const R_AARCH64_LDST64_ABS_LO12_NC: u32 = 286;
pub const R_AARCH64_JUMP26: u32 = 282;
pub const R_AARCH64_CALL26: u32 = 283;

/// Errors raised while applying relocations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RelocError {
    /// Symbol referenced by relocation could not be resolved.
    UnresolvedSymbol,
    /// Relocation type isn't implemented for this arch.
    UnsupportedType(u32),
    /// Computed value overflows the destination field width.
    Overflow,
    /// Target offset is outside the section bytes.
    OutOfBounds,
    /// Architecture mismatch between elf and runtime.
    ArchMismatch,
}

/// Apply one relocation to the byte at `loc` in `dest`.
///
/// Inputs:
///   * `dest` — the in-memory copy of the section being relocated.
///   * `loc` — offset into `dest` (== rela.r_offset).
///   * `target_addr` — virtual address at which `dest` will live.
///   * `sym_value` — fully-resolved value of the referenced symbol.
///   * `addend` — `r_addend` from the RELA entry.
///   * `ty` — relocation type (R_X86_64_* / R_AARCH64_*).
///
/// Returns `Ok(())` on success.
///
/// Linux refs: `arch/x86/kernel/module.c:82` and
/// `arch/arm64/kernel/module.c:231`.
pub fn apply_x86_64(
    dest: &mut [u8],
    loc: usize,
    target_addr: u64,
    sym_value: u64,
    addend: i64,
    ty: u32,
) -> Result<(), RelocError> {
    let val = (sym_value as i64).wrapping_add(addend) as u64;
    let place = target_addr.wrapping_add(loc as u64);
    match ty {
        R_X86_64_NONE => Ok(()),
        R_X86_64_64 => write_u64(dest, loc, val),
        R_X86_64_32 => {
            if val != (val as u32) as u64 {
                return Err(RelocError::Overflow);
            }
            write_u32(dest, loc, val as u32)
        }
        R_X86_64_32S => {
            let s = val as i64;
            if s != (s as i32) as i64 {
                return Err(RelocError::Overflow);
            }
            write_u32(dest, loc, val as u32)
        }
        R_X86_64_PC32 | R_X86_64_PLT32 | R_X86_64_GOTPCREL | R_X86_64_REX_GOTPCRELX => {
            let diff = (val as i64).wrapping_sub(place as i64);
            if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
                return Err(RelocError::Overflow);
            }
            write_u32(dest, loc, diff as u32)
        }
        R_X86_64_PC64 => {
            let diff = (val as i64).wrapping_sub(place as i64);
            write_u64(dest, loc, diff as u64)
        }
        other => Err(RelocError::UnsupportedType(other)),
    }
}

/// Apply one aarch64 relocation.
pub fn apply_aarch64(
    dest: &mut [u8],
    loc: usize,
    target_addr: u64,
    sym_value: u64,
    addend: i64,
    ty: u32,
) -> Result<(), RelocError> {
    let val = (sym_value as i64).wrapping_add(addend) as u64;
    let place = target_addr.wrapping_add(loc as u64);
    match ty {
        R_AARCH64_NONE => Ok(()),
        R_AARCH64_ABS64 => write_u64(dest, loc, val),
        R_AARCH64_ABS32 => {
            if val > u32::MAX as u64 {
                return Err(RelocError::Overflow);
            }
            write_u32(dest, loc, val as u32)
        }
        R_AARCH64_PREL64 => {
            let diff = (val as i64).wrapping_sub(place as i64);
            write_u64(dest, loc, diff as u64)
        }
        R_AARCH64_PREL32 => {
            let diff = (val as i64).wrapping_sub(place as i64);
            if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
                return Err(RelocError::Overflow);
            }
            write_u32(dest, loc, diff as u32)
        }
        R_AARCH64_CALL26 | R_AARCH64_JUMP26 => {
            // PC-relative ±128 MiB branch with 26-bit immediate, low
            // 2 bits implicit-zero (4-byte aligned).
            // Linux ref: `arch/arm64/kernel/module.c:415`.
            let diff = (val as i64).wrapping_sub(place as i64);
            if (diff & 0x3) != 0 {
                return Err(RelocError::Overflow);
            }
            let imm = diff >> 2;
            if !(-(1 << 25)..(1 << 25)).contains(&imm) {
                return Err(RelocError::Overflow);
            }
            let imm_bits = (imm as u32) & 0x03FF_FFFF;
            let cur = read_u32_in(dest, loc)?;
            let new = (cur & !0x03FF_FFFF) | imm_bits;
            write_u32(dest, loc, new)
        }
        R_AARCH64_ADR_PREL_PG_HI21 => {
            // ADRP-style: high 21 bits of the page diff.
            // Linux ref: `arch/arm64/kernel/module.c:376`.
            let page_val = val & !0xFFF;
            let page_place = place & !0xFFF;
            let diff = (page_val as i64).wrapping_sub(page_place as i64) >> 12;
            if !(-(1 << 20)..(1 << 20)).contains(&diff) {
                return Err(RelocError::Overflow);
            }
            let imm = diff as u32;
            let immlo = (imm & 0x3) << 29;
            let immhi = ((imm >> 2) & 0x7FFFF) << 5;
            let cur = read_u32_in(dest, loc)?;
            // Mask: clear bits 29..30 (immlo) and bits 5..23 (immhi).
            let new = (cur & !(0x60000000 | 0x00FFFFE0)) | immlo | immhi;
            write_u32(dest, loc, new)
        }
        R_AARCH64_ADD_ABS_LO12_NC => {
            // 12-bit low slot of an ADD-imm or LDR-imm.
            // Linux ref: `arch/arm64/kernel/module.c:381`.
            let imm = (val & 0xFFF) as u32;
            let cur = read_u32_in(dest, loc)?;
            // Imm12 field is bits 10..21.
            let new = (cur & !(0xFFF << 10)) | (imm << 10);
            write_u32(dest, loc, new)
        }
        R_AARCH64_LDST64_ABS_LO12_NC => {
            // 12-bit low slot, scaled by 8 for LDR/STR (64-bit).
            let imm = ((val & 0xFFF) >> 3) as u32;
            let cur = read_u32_in(dest, loc)?;
            let new = (cur & !(0x1FF << 10)) | (imm << 10);
            write_u32(dest, loc, new)
        }
        other => Err(RelocError::UnsupportedType(other)),
    }
}

#[inline]
fn write_u32(dest: &mut [u8], off: usize, val: u32) -> Result<(), RelocError> {
    if off + 4 > dest.len() {
        return Err(RelocError::OutOfBounds);
    }
    dest[off..off + 4].copy_from_slice(&val.to_le_bytes());
    Ok(())
}

#[inline]
fn write_u64(dest: &mut [u8], off: usize, val: u64) -> Result<(), RelocError> {
    if off + 8 > dest.len() {
        return Err(RelocError::OutOfBounds);
    }
    dest[off..off + 8].copy_from_slice(&val.to_le_bytes());
    Ok(())
}

#[inline]
fn read_u32_in(dest: &[u8], off: usize) -> Result<u32, RelocError> {
    if off + 4 > dest.len() {
        return Err(RelocError::OutOfBounds);
    }
    Ok(u32::from_le_bytes(
        dest[off..off + 4].try_into().expect("len 4"),
    ))
}
