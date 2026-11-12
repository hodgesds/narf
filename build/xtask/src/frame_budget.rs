//! Kernel stack-frame budget: Linux's `-Wframe-larger-than`, for a linked
//! Rust kernel.
//!
//! Kernel task stacks are a fixed size with a guard page below. A function
//! whose frame alone is many KiB — typically an async state machine or a
//! large struct kept by value — makes any call chain through it a stack
//! overflow waiting for the deepest caller. Rust has no per-function frame
//! warning, so this measures the linked x86_64 image instead: each function's
//! frame is the sum of its prologue's `sub $imm,%rsp` (the stack-probe
//! sequence for frames past a page is a run of them).
//!
//! Every non-test function must fit [`BUDGET`]. Exceptions are listed in
//! `build/frame-budget.txt` with their measured size, and the list may only
//! shrink: a listed function that grows, that now fits the budget, or that no
//! longer exists fails the build until its entry is lowered or removed.
//! `NARF_FRAME_BUDGET_WRITE=1` rewrites the list from the image (the diff is
//! what review looks at).
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

/// Largest frame a kernel function may have without an allowlist entry.
pub const BUDGET: u64 = 8 * 1024;

/// A single prologue adjustment larger than this is a misdecode (bytes of
/// another instruction that happen to look like `sub $imm32,%rsp`).
const MAX_PLAUSIBLE: u64 = 4 << 20;

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Test code runs on the same stacks but is not shipped behaviour; it is
/// left out of the budget.
fn is_test(name: &str) -> bool {
    name.contains("::tests::")
        || name.contains("_tests::")
        || name.contains("::test::")
        || name.contains("smoke_")
        || name.contains("kernel_test")
}

/// Readable, hash-free form of a legacy Rust symbol (`_ZN..17h<hash>E`), so
/// monomorphizations and rebuilds share one key.
fn demangle(sym: &str) -> String {
    let Some(mut rest) = sym.strip_prefix("_ZN") else {
        return sym.to_string();
    };
    let mut parts = Vec::new();
    while let Some(c) = rest.chars().next() {
        if !c.is_ascii_digit() {
            break;
        }
        let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        let Ok(len) = rest[..digits].parse::<usize>() else {
            break;
        };
        rest = &rest[digits..];
        if rest.len() < len {
            break;
        }
        let part = &rest[..len];
        rest = &rest[len..];
        if part.len() == 17
            && part.starts_with('h')
            && part[1..].chars().all(|c| c.is_ascii_hexdigit())
        {
            continue;
        }
        // A component starting with an escape carries a leading `_`.
        let part = if part.starts_with("_$") {
            &part[1..]
        } else {
            part
        };
        parts.push(
            part.replace("$LT$", "<")
                .replace("$GT$", ">")
                .replace("$u20$", " ")
                .replace("$u7b$", "{")
                .replace("$u7d$", "}")
                .replace("$RF$", "&")
                .replace("$C$", ",")
                .replace("$BP$", "*")
                .replace("..", "::"),
        );
    }
    parts.join("::")
}

/// `(name, frame bytes)` for every function in the image, largest frame per
/// name.
pub fn frames(elf: &Path) -> Result<BTreeMap<String, u64>> {
    let b = std::fs::read(elf).with_context(|| format!("reading {}", elf.display()))?;
    if b.len() < 64 || &b[..4] != b"\x7fELF" || b[4] != 2 || u16_at(&b, 18) != 62 {
        bail!("{} is not an x86_64 ELF64 image", elf.display());
    }
    let phoff = u64_at(&b, 0x20) as usize;
    let phentsize = u16_at(&b, 0x36) as usize;
    let phnum = u16_at(&b, 0x38) as usize;
    let mut loads = Vec::new();
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if u32_at(&b, ph) == 1 {
            loads.push((
                u64_at(&b, ph + 0x10),
                u64_at(&b, ph + 0x08),
                u64_at(&b, ph + 0x20),
            ));
        }
    }
    let file_offset = |va: u64| {
        loads
            .iter()
            .find(|(vaddr, _, filesz)| va >= *vaddr && va < vaddr + filesz)
            .map(|(vaddr, off, _)| (off + (va - vaddr)) as usize)
    };
    let shoff = u64_at(&b, 0x28) as usize;
    let shentsize = u16_at(&b, 0x3A) as usize;
    let shnum = u16_at(&b, 0x3C) as usize;
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if u32_at(&b, sh + 4) != 2 {
            continue; // SHT_SYMTAB
        }
        let off = u64_at(&b, sh + 0x18) as usize;
        let size = u64_at(&b, sh + 0x20) as usize;
        let strtab = u64_at(
            &b,
            shoff + u32_at(&b, sh + 0x28) as usize * shentsize + 0x18,
        ) as usize;
        for sym in (off..off + size).step_by(24) {
            if b[sym + 4] & 0xF != 2 {
                continue; // STT_FUNC
            }
            let value = u64_at(&b, sym + 8);
            let fsize = u64_at(&b, sym + 16) as usize;
            let Some(code) = file_offset(value) else {
                continue;
            };
            let name_at = strtab + u32_at(&b, sym) as usize;
            let name_end = name_at + b[name_at..].iter().position(|c| *c == 0).unwrap_or(0);
            let name = demangle(&String::from_utf8_lossy(&b[name_at..name_end]));
            if is_test(&name) {
                continue;
            }
            let code = &b[code..(code + fsize.min(256)).min(b.len())];
            let mut frame = 0u64;
            let mut at = 0;
            while at + 4 <= code.len() {
                if code[at..at + 3] == [0x48, 0x81, 0xEC] && at + 7 <= code.len() {
                    let imm = u64::from(u32_at(code, at + 3));
                    if imm <= MAX_PLAUSIBLE {
                        frame += imm;
                    }
                    at += 7;
                } else if code[at..at + 3] == [0x48, 0x83, 0xEC] {
                    frame += u64::from(code[at + 3]);
                    at += 4;
                } else {
                    at += 1;
                }
            }
            let entry = out.entry(name).or_insert(0);
            *entry = (*entry).max(frame);
        }
    }
    Ok(out)
}

/// Check `elf` against the budget and the allowlist at `list`.
pub fn check(elf: &Path, list: &Path) -> Result<()> {
    let frames = frames(elf)?;
    let over: BTreeMap<&String, u64> = frames
        .iter()
        .filter(|(_, size)| **size > BUDGET)
        .map(|(name, size)| (name, *size))
        .collect();
    if std::env::var_os("NARF_FRAME_BUDGET_WRITE").is_some() {
        let mut sorted: Vec<_> = over.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let mut text = String::from(
            "# Kernel functions whose stack frame exceeds the 8 KiB budget\n\
             # (build/xtask/src/frame_budget.rs). <bytes> <function>. This list\n\
             # may only shrink: lower an entry when its frame shrinks, remove it\n\
             # when the function fits. Regenerate: NARF_FRAME_BUDGET_WRITE=1.\n",
        );
        for (name, size) in sorted {
            text.push_str(&format!("{size} {name}\n"));
        }
        std::fs::write(list, text)?;
        println!(
            "xtask: frame budget: wrote {} entries to {}",
            over.len(),
            list.display()
        );
        return Ok(());
    }
    let text = std::fs::read_to_string(list).unwrap_or_default();
    let mut allowed: BTreeMap<String, u64> = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (size, name) = line
            .split_once(' ')
            .with_context(|| format!("frame-budget.txt: malformed line {line:?}"))?;
        allowed.insert(
            name.to_string(),
            size.parse().context("frame-budget.txt size")?,
        );
    }
    let mut problems = Vec::new();
    for (name, size) in &over {
        match allowed.get(*name) {
            None => problems.push(format!("  {size:>7}  {name}  (new; budget {BUDGET})")),
            Some(limit) if size > limit => {
                problems.push(format!("  {size:>7}  {name}  (grew from {limit})"))
            }
            _ => {}
        }
    }
    for (name, limit) in &allowed {
        match frames.get(name) {
            None => problems.push(format!(
                "  {limit:>7}  {name}  (listed, no longer in the image: remove)"
            )),
            Some(size) if *size <= BUDGET => problems.push(format!(
                "  {size:>7}  {name}  (now fits the budget: remove)"
            )),
            Some(size) if size < limit => problems.push(format!(
                "  {size:>7}  {name}  (shrank from {limit}: lower the entry)"
            )),
            _ => {}
        }
    }
    if !problems.is_empty() {
        bail!(
            "kernel stack-frame budget ({BUDGET} bytes) — {} problem(s):\n{}\n\
             Move large locals and futures to the heap (Box), or update {} \
             (NARF_FRAME_BUDGET_WRITE=1) — it may only shrink.",
            problems.len(),
            problems.join("\n"),
            list.display()
        );
    }
    println!(
        "xtask: frame budget: {} function(s) over {BUDGET} bytes, all listed",
        over.len()
    );
    Ok(())
}
