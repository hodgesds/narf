//! The kernel's own symbol table, read from the image.
//!
//! `cargo narf build kallsyms` fills the linker-reserved `.kallsyms` section after the
//! link (`build/cargo-narf/src/kallsyms.rs`); this is the in-kernel side —
//! Linux's `kernel/kallsyms.c` decoder. The table stores offsets from the
//! link-time `_text`, and every runtime address is the RUNTIME `_text` plus
//! that offset, so the KASLR slide is applied by taking `_text`'s address
//! (the relocation pass patches that reference like any other) rather than
//! by rewriting the table.
//!
//! Exposing these addresses defeats KASLR for whoever reads them. Nothing
//! here decides who may: the policy is Linux's `kallsyms_show_value`, applied
//! by each presenter (`/proc/kallsyms` in `narf-filesystem`) against the
//! credentials of the file's opener.

pub use narf_kallsyms::{Entry, Error, NameBuf, Table, KSYM_NAME_LEN, MAX_NAME};

use narf_lib::sync::OnceLock;

extern "C" {
    /// Bounds of the `.kallsyms` reservation (`build/linker/*.ld`).
    static __kallsyms_start: u8;
    static __kallsyms_end: u8;
    /// Start of the kernel image's text, the base every offset is relative to.
    static _text: u8;
}

/// The reservation's bytes.
fn reservation() -> &'static [u8] {
    let start = core::ptr::addr_of!(__kallsyms_start);
    let end = core::ptr::addr_of!(__kallsyms_end) as usize;
    let len = end.saturating_sub(start as usize);
    // SAFETY: the linker script reserves `[__kallsyms_start, __kallsyms_end)`
    // as one PROGBITS section in the read-only image segment, mapped for the
    // kernel's whole lifetime and never written after `cargo narf` patched it, so
    // the range is valid, initialised and immutable for `'static`.
    unsafe { core::slice::from_raw_parts(start, len) }
}

/// The image's symbol table, validated on first use.
///
/// `Err(Error::BadMagic)` when the image was linked without the `cargo narf`
/// patch step (a bare `cargo build`): the reservation is still zero, and
/// there is simply no table — not a corrupt one.
pub fn table() -> Result<Table<'static>, Error> {
    static TABLE: OnceLock<Result<Table<'static>, Error>> = OnceLock::new();
    *TABLE.get_or_init(|| Table::parse(reservation()))
}

/// Runtime address of `_text`: its link-time address plus the KASLR slide.
pub fn text_base() -> u64 {
    core::ptr::addr_of!(_text) as u64
}

/// Runtime address of a table entry.
pub fn address(entry: &Entry) -> u64 {
    text_base() + entry.offset as u64
}

/// The symbol covering runtime address `addr`, with `addr`'s offset into it
/// and the symbol's size when known (Linux's `kallsyms_lookup_size_offset`).
/// Decodes the name into `name`.
pub fn lookup(addr: u64, name: &mut NameBuf) -> Option<(Entry, u64, Option<u32>)> {
    let table = table().ok()?;
    let rel = addr.checked_sub(text_base())?;
    let (entry, size) = table.lookup(rel)?;
    table.name(entry.name_index, name).ok()?;
    Some((entry, rel - entry.offset as u64, size))
}
