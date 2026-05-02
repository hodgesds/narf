//! narf-firmware-fw-cfg — QEMU `fw_cfg` driver.
//!
//! Clean-room implementation from QEMU's published `docs/specs/fw_cfg.rst`.
//!
//! x86_64 path uses the legacy I/O ports (selector 0x510, data 0x511 —
//! spec §2 "I/O Port Interface"). DMA-channel access (port 0x514, spec
//! §3) is not implemented; byte-stream read off the data port suffices
//! for `bootorder` / `cmdline` / `etc/*` / `opt/*` entries.
//!
//! aarch64 MMIO support is a TODO — the interface there is a
//! DTB-discovered MMIO window (`qemu,fw-cfg` compatible string) and we
//! don't need it yet.

#![no_std]
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

#[cfg(target_arch = "x86_64")]
use narf_arch::x86_64::io_port::{inb, outw};

// ── spec §2 / §4 constants ─────────────────────────────────────────

/// x86_64 selector port (16-bit write). Spec §2.
pub const SELECTOR_PORT: u16 = 0x510;
/// x86_64 data port (8-bit read). Spec §2.
pub const DATA_PORT: u16 = 0x511;

/// Selector key — signature. Spec §4 "FW_CFG_SIGNATURE = 0x0000".
pub const FW_CFG_SIGNATURE: u16 = 0x0000;
/// Selector key — file directory. Spec §4 "FW_CFG_FILE_DIR = 0x0019".
pub const FW_CFG_FILE_DIR: u16 = 0x0019;

/// Magic bytes returned by `FW_CFG_SIGNATURE`. Spec §4: "QEMU" (LE).
pub const MAGIC: [u8; 4] = *b"QEMU";

/// File-directory entry on-the-wire size. Spec §4 "File Transfer
/// Interface": `{u32 size, u16 select, u16 reserved, [u8; 56] name}`,
/// big-endian numerics.
pub const FILE_ENTRY_SIZE: usize = 64;
/// Maximum length (bytes) of an entry name, including the trailing NUL.
pub const FILE_NAME_LEN: usize = 56;

// ── public types ───────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FwCfgFile {
    pub size:     u32,
    pub select:   u16,
    pub name_len: u8,
    pub name_buf: [u8; FILE_NAME_LEN],
}

impl FwCfgFile {
    pub fn name(&self) -> &str {
        // SAFETY: `name_len` was set to a NUL-search result over ASCII
        // bytes during decode; `name_buf[..name_len]` is valid UTF-8.
        unsafe { core::str::from_utf8_unchecked(&self.name_buf[..self.name_len as usize]) }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwCfgError {
    /// `FW_CFG_SIGNATURE` did not return `MAGIC` — fw_cfg absent.
    NotPresent,
    /// File-directory entry under that name not found.
    NotFound,
    /// Directory bytes shorter than the announced count requires.
    DirTruncated,
}

// ── port-IO primitives ─────────────────────────────────────────────

/// Write `key` to the selector port. Spec §2: 16-bit write, host byte
/// order on x86_64 ports (the LE-vs-BE ambiguity from §4 only applies
/// to *file-directory contents*, not the selector write itself).
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn select(key: u16) {
    // SAFETY: writing to a fixed PIO port with no memory effect.
    unsafe { outw(SELECTOR_PORT, key); }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn select(_key: u16) { /* aarch64 MMIO TODO */ }

/// Stream-read `buf.len()` bytes from the data port. Spec §2: each
/// `inb` returns the next byte for the currently-selected key.
#[cfg(target_arch = "x86_64")]
pub fn read_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: PIO read of a benign port.
        *b = unsafe { inb(DATA_PORT) };
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn read_bytes(_buf: &mut [u8]) { /* aarch64 MMIO TODO */ }

// ── presence + directory ───────────────────────────────────────────

/// `true` if writing `FW_CFG_SIGNATURE` and reading 4 bytes returns
/// the `MAGIC`. Spec §4.
pub fn is_present() -> bool {
    #[cfg(target_arch = "x86_64")] {
        select(FW_CFG_SIGNATURE);
        let mut sig = [0u8; 4];
        read_bytes(&mut sig);
        sig == MAGIC
    }
    #[cfg(not(target_arch = "x86_64"))] { false }
}

/// Decode a single 64-byte directory entry per spec §4.
///
/// All numeric fields are big-endian; `name` is NUL-terminated ASCII
/// inside the 56-byte field.
pub fn decode_file_entry(raw: &[u8; FILE_ENTRY_SIZE]) -> FwCfgFile {
    let size   = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let select = u16::from_be_bytes([raw[4], raw[5]]);
    // raw[6..8] is the reserved u16; ignore.
    let mut name_buf = [0u8; FILE_NAME_LEN];
    name_buf.copy_from_slice(&raw[8..64]);
    let name_len = name_buf.iter().position(|&c| c == 0).unwrap_or(FILE_NAME_LEN) as u8;
    FwCfgFile { size, select, name_len, name_buf }
}

/// Read the file directory at `FW_CFG_FILE_DIR`. Spec §4: u32 BE entry
/// count, then N × 64-byte entries.
pub fn read_directory() -> Result<Vec<FwCfgFile>, FwCfgError> {
    if !is_present() { return Err(FwCfgError::NotPresent); }
    select(FW_CFG_FILE_DIR);
    let mut count_buf = [0u8; 4];
    read_bytes(&mut count_buf);
    let count = u32::from_be_bytes(count_buf) as usize;
    let mut out = Vec::with_capacity(count);
    let mut entry = [0u8; FILE_ENTRY_SIZE];
    for _ in 0..count {
        read_bytes(&mut entry);
        out.push(decode_file_entry(&entry));
    }
    Ok(out)
}

// ── lookup + read ──────────────────────────────────────────────────

/// Look up `name` in the file directory. Walks the directory each
/// call — the result count is small (tens) so a cache would buy
/// little. Returns `None` when fw_cfg is absent or the entry is
/// missing.
pub fn find(name: &str) -> Option<FwCfgFile> {
    let dir = read_directory().ok()?;
    dir.into_iter().find(|f| f.name() == name)
}

/// Read up to `out.len()` bytes of the named blob into `out`. The
/// number actually copied equals `min(out.len(), file.size)`. Per
/// spec §2 the data port is a stream, so issuing the select then
/// `inb` per byte yields the entry's contents from offset 0.
pub fn read(file: &FwCfgFile, out: &mut [u8]) -> usize {
    select(file.select);
    let n = (file.size as usize).min(out.len());
    read_bytes(&mut out[..n]);
    n
}

/// Read `name`'s entry as a `String`. Drops a single trailing NUL if
/// present (the kernel cmdline blob carries one). Returns `None` when
/// the entry isn't found or the bytes aren't valid UTF-8.
pub fn read_string(name: &str) -> Option<String> {
    let f = find(name)?;
    let mut buf = vec![0u8; f.size as usize];
    let n = read(&f, &mut buf);
    buf.truncate(n);
    if buf.last() == Some(&0) { buf.pop(); }
    String::from_utf8(buf).ok()
}

// ── boot integration ───────────────────────────────────────────────

/// Cached presence flag. Set on the first `register_initcalls` run.
static PRESENT: IrqSafeSpinLock<Option<bool>> = IrqSafeSpinLock::new(None);

/// `Stage::Subsys` initcall: probe for fw_cfg and cache the result.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "fw_cfg-probe", || {
        let p = is_present();
        *PRESENT.lock() = Some(p);
        if p { InitResult::Ok } else { InitResult::NotPresent }
    });
}

/// Cached probe outcome. `None` until `register_initcalls`'s
/// `Subsys` slot has run.
pub fn cached_present() -> Option<bool> { *PRESENT.lock() }

#[doc(hidden)]
pub fn __reset_for_test() { *PRESENT.lock() = None; }

mod tests;
