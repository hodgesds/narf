//! `NARF_KASLR_SLIDE`: pin the aarch64 kernel's KASLR slide in a linked image.
//!
//! The boot stub draws the slide from entropy unless the image's
//! `kaslr_slide_override` word is non-zero (`frame/src/aarch64/boot.S`). This
//! writes that word, so a failure seen at one slide reproduces at will, on the
//! same build. The stub masks and 2 MiB-aligns the value like a drawn one.
use anyhow::{bail, Context, Result};
use std::path::Path;

const SYMBOL: &str = "kaslr_slide_override";

/// The slide `NARF_KASLR_SLIDE` asks for (hex with `0x`, or decimal); 0 when
/// unset.
pub fn slide_from_env() -> Result<u64> {
    let Ok(raw) = std::env::var("NARF_KASLR_SLIDE") else {
        return Ok(0);
    };
    let raw = raw.trim();
    let value = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse(),
    }
    .with_context(|| format!("NARF_KASLR_SLIDE={raw:?} is not a number"))?;
    if value & 0x1F_FFFF != 0 {
        bail!("NARF_KASLR_SLIDE={value:#x} is not 2 MiB aligned");
    }
    Ok(value)
}

/// Write `slide` into the image's `kaslr_slide_override` word.
pub fn set_slide(elf: &Path, slide: u64) -> Result<()> {
    let mut bytes = std::fs::read(elf)?;
    let addr = symbol_value(&bytes, SYMBOL)?
        .with_context(|| format!("{} has no `{SYMBOL}` symbol", elf.display()))?;
    let offset = file_offset(&bytes, addr)?
        .with_context(|| format!("`{SYMBOL}` at {addr:#x} is not in a loaded file range"))?;
    let word = bytes
        .get_mut(offset..offset + 8)
        .context("slide word runs past the end of the file")?;
    if word == slide.to_le_bytes() {
        return Ok(());
    }
    word.copy_from_slice(&slide.to_le_bytes());
    std::fs::write(elf, &bytes)?;
    Ok(())
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// `st_value` of the first `.symtab` symbol named `name`.
fn symbol_value(bytes: &[u8], name: &str) -> Result<Option<u64>> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 {
        bail!("not an ELF64 image");
    }
    let shoff = u64_at(bytes, 0x28) as usize;
    let shentsize = u16_at(bytes, 0x3A) as usize;
    let shnum = u16_at(bytes, 0x3C) as usize;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if u32_at(bytes, sh + 4) != 2 {
            continue; // SHT_SYMTAB only
        }
        let off = u64_at(bytes, sh + 0x18) as usize;
        let size = u64_at(bytes, sh + 0x20) as usize;
        let link = u32_at(bytes, sh + 0x28) as usize;
        let strtab = u64_at(bytes, shoff + link * shentsize + 0x18) as usize;
        for sym in (off..off + size).step_by(24) {
            let start = strtab + u32_at(bytes, sym) as usize;
            let end = start
                + bytes[start..]
                    .iter()
                    .position(|b| *b == 0)
                    .context("unterminated symbol name")?;
            if &bytes[start..end] == name.as_bytes() {
                return Ok(Some(u64_at(bytes, sym + 8)));
            }
        }
    }
    Ok(None)
}

/// File offset of virtual address `addr`, from the PT_LOAD that holds it.
fn file_offset(bytes: &[u8], addr: u64) -> Result<Option<usize>> {
    let phoff = u64_at(bytes, 0x20) as usize;
    let phentsize = u16_at(bytes, 0x36) as usize;
    let phnum = u16_at(bytes, 0x38) as usize;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if u32_at(bytes, ph) != 1 {
            continue; // PT_LOAD
        }
        let offset = u64_at(bytes, ph + 0x08);
        let vaddr = u64_at(bytes, ph + 0x10);
        let filesz = u64_at(bytes, ph + 0x20);
        if addr >= vaddr && addr + 8 <= vaddr + filesz {
            return Ok(Some((offset + (addr - vaddr)) as usize));
        }
    }
    Ok(None)
}
