//! SMBIOS / DMI table parser.
//!
//! Spec: `firmware/smbios/specification/spec.md`.
//!
//! The parser consumes a slice spanning the SMBIOS structure
//! stream (everything that follows the entry point's header).
//! Callers pick the obtain-bytes path that matches the platform
//! — QEMU `fw_cfg`'s `etc/smbios/smbios-tables` key, the EFI
//! configuration table, or the legacy 0xF0000–0xFFFFF anchor
//! scan. The output lives in static tables guarded by an
//! `IrqSafeSpinLock` so the parser is callable from any
//! pre-userspace context.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![allow(dead_code)]

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

mod tests;

/// Force-link hook. The crate has no boot-time initcalls of its own
/// (parsing happens on demand from the entry-point discovery code),
/// but `frame/` calls this to keep the linker from dropping the
/// `kernel_test_in!` registrations in `tests.rs`.
pub fn register_initcalls() {}

pub const MAX_BIOS:           usize = 1;
pub const MAX_SYSTEM:         usize = 1;
pub const MAX_BASEBOARD:      usize = 4;
pub const MAX_PROCESSORS:     usize = 16;
pub const MAX_MEMORY_DEVICES: usize = 16;

#[derive(Copy, Clone, Debug)]
pub struct SmbiosBios {
    pub vendor:       [u8; 64],
    pub version:      [u8; 64],
    pub release_date: [u8; 16],
    pub rom_size:     u8,
}

impl SmbiosBios {
    pub const ZERO: Self = Self {
        vendor: [0; 64], version: [0; 64],
        release_date: [0; 16], rom_size: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosSystem {
    pub manufacturer: [u8; 64],
    pub product_name: [u8; 64],
    pub version:      [u8; 64],
    pub serial_number:[u8; 64],
    pub uuid:         [u8; 16],
    pub wake_up_type: u8,
}

impl SmbiosSystem {
    pub const ZERO: Self = Self {
        manufacturer: [0; 64], product_name: [0; 64],
        version: [0; 64], serial_number: [0; 64],
        uuid: [0; 16], wake_up_type: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosBaseboard {
    pub manufacturer: [u8; 64],
    pub product:      [u8; 64],
    pub version:      [u8; 64],
    pub serial:       [u8; 64],
}

impl SmbiosBaseboard {
    pub const ZERO: Self = Self {
        manufacturer: [0; 64], product: [0; 64],
        version: [0; 64], serial: [0; 64],
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosProcessor {
    pub socket_designation: [u8; 32],
    pub processor_type:     u8,
    pub family:             u8,
    pub max_speed_mhz:      u16,
    pub current_speed_mhz:  u16,
    pub status:             u8,
    pub core_count:         u8,
    pub thread_count:       u8,
}

impl SmbiosProcessor {
    pub const ZERO: Self = Self {
        socket_designation: [0; 32],
        processor_type: 0, family: 0,
        max_speed_mhz: 0, current_speed_mhz: 0,
        status: 0, core_count: 0, thread_count: 0,
    };
}

#[derive(Copy, Clone, Debug)]
pub struct SmbiosMemoryDevice {
    pub size_mb:        u32,
    pub form_factor:    u8,
    pub device_locator: [u8; 32],
    pub bank_locator:   [u8; 32],
    pub memory_type:    u8,
    pub speed_mts:      u16,
    pub manufacturer:   [u8; 64],
    pub serial_number:  [u8; 32],
}

impl SmbiosMemoryDevice {
    pub const ZERO: Self = Self {
        size_mb: 0, form_factor: 0,
        device_locator: [0; 32], bank_locator: [0; 32],
        memory_type: 0, speed_mts: 0,
        manufacturer: [0; 64], serial_number: [0; 32],
    };
}

struct Tables {
    bios:        [SmbiosBios; MAX_BIOS],
    system:      [SmbiosSystem; MAX_SYSTEM],
    baseboards:  [SmbiosBaseboard; MAX_BASEBOARD],
    processors:  [SmbiosProcessor; MAX_PROCESSORS],
    memory:      [SmbiosMemoryDevice; MAX_MEMORY_DEVICES],
    n_bios:      usize,
    n_system:    usize,
    n_baseboard: usize,
    n_processor: usize,
    n_memory:    usize,
}

impl Tables {
    const EMPTY: Self = Self {
        bios:        [SmbiosBios {
                         vendor: [0; 64], version: [0; 64],
                         release_date: [0; 16], rom_size: 0
                     }; MAX_BIOS],
        system:      [SmbiosSystem {
                         manufacturer: [0; 64], product_name: [0; 64],
                         version: [0; 64], serial_number: [0; 64],
                         uuid: [0; 16], wake_up_type: 0
                     }; MAX_SYSTEM],
        baseboards:  [SmbiosBaseboard {
                         manufacturer: [0; 64], product: [0; 64],
                         version: [0; 64], serial: [0; 64]
                     }; MAX_BASEBOARD],
        processors:  [SmbiosProcessor {
                         socket_designation: [0; 32],
                         processor_type: 0, family: 0,
                         max_speed_mhz: 0, current_speed_mhz: 0,
                         status: 0, core_count: 0, thread_count: 0
                     }; MAX_PROCESSORS],
        memory:      [SmbiosMemoryDevice {
                         size_mb: 0, form_factor: 0,
                         device_locator: [0; 32], bank_locator: [0; 32],
                         memory_type: 0, speed_mts: 0,
                         manufacturer: [0; 64], serial_number: [0; 32]
                     }; MAX_MEMORY_DEVICES],
        n_bios:      0,
        n_system:    0,
        n_baseboard: 0,
        n_processor: 0,
        n_memory:    0,
    };
}

static DATA:   IrqSafeSpinLock<Tables> = IrqSafeSpinLock::new(Tables::EMPTY);
static PARSED: AtomicBool = AtomicBool::new(false);

/// Locate the n-th NUL-terminated string in the pool that
/// starts at `pool[0]`. SMBIOS uses 1-based string indices;
/// returns `&[]` for index 0 or when the pool is exhausted.
fn lookup_string(pool: &[u8], idx: u8) -> &[u8] {
    if idx == 0 { return &[]; }
    let mut start = 0usize;
    let mut count = 0u8;
    while start < pool.len() {
        let end = match pool[start..].iter().position(|&b| b == 0) {
            Some(off) => start + off,
            None      => return &[],
        };
        count += 1;
        if count == idx {
            return &pool[start..end];
        }
        start = end + 1;
    }
    &[]
}

fn copy_truncated(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    for slot in &mut dst[n..] { *slot = 0; }
}

fn pool_end(pool: &[u8]) -> usize {
    // String pool ends at the first double-NUL (or single NUL when
    // the pool has zero strings — in which case the body is just
    // \0\0).
    let mut i = 0;
    while i + 1 < pool.len() {
        if pool[i] == 0 && pool[i + 1] == 0 { return i + 2; }
        i += 1;
    }
    pool.len()
}

fn parse_bios(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 9 || t.n_bios >= MAX_BIOS { return; }
    let mut rec = SmbiosBios::ZERO;
    copy_truncated(&mut rec.vendor,       lookup_string(pool, fmt[4]));
    copy_truncated(&mut rec.version,      lookup_string(pool, fmt[5]));
    copy_truncated(&mut rec.release_date, lookup_string(pool, fmt[8]));
    rec.rom_size = if fmt.len() > 9 { fmt[9] } else { 0 };
    let i = t.n_bios;
    t.bios[i] = rec;
    t.n_bios = i + 1;
}

fn parse_system(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 25 || t.n_system >= MAX_SYSTEM { return; }
    let mut rec = SmbiosSystem::ZERO;
    copy_truncated(&mut rec.manufacturer,  lookup_string(pool, fmt[4]));
    copy_truncated(&mut rec.product_name,  lookup_string(pool, fmt[5]));
    copy_truncated(&mut rec.version,       lookup_string(pool, fmt[6]));
    copy_truncated(&mut rec.serial_number, lookup_string(pool, fmt[7]));
    rec.uuid.copy_from_slice(&fmt[8..24]);
    rec.wake_up_type = fmt[24];
    let i = t.n_system;
    t.system[i] = rec;
    t.n_system = i + 1;
}

fn parse_baseboard(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 9 || t.n_baseboard >= MAX_BASEBOARD { return; }
    let mut rec = SmbiosBaseboard::ZERO;
    copy_truncated(&mut rec.manufacturer, lookup_string(pool, fmt[4]));
    copy_truncated(&mut rec.product,      lookup_string(pool, fmt[5]));
    copy_truncated(&mut rec.version,      lookup_string(pool, fmt[6]));
    copy_truncated(&mut rec.serial,       lookup_string(pool, fmt[7]));
    let i = t.n_baseboard;
    t.baseboards[i] = rec;
    t.n_baseboard = i + 1;
}

fn parse_processor(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    if fmt.len() < 36 || t.n_processor >= MAX_PROCESSORS { return; }
    let mut rec = SmbiosProcessor::ZERO;
    copy_truncated(&mut rec.socket_designation, lookup_string(pool, fmt[4]));
    rec.processor_type    = fmt[5];
    rec.family            = fmt[6];
    rec.max_speed_mhz     = u16::from_le_bytes([fmt[20], fmt[21]]);
    rec.current_speed_mhz = u16::from_le_bytes([fmt[22], fmt[23]]);
    rec.status            = fmt[24];
    rec.core_count        = if fmt.len() > 35 { fmt[35] } else { 0 };
    rec.thread_count      = if fmt.len() > 37 { fmt[37] } else { 0 };
    let i = t.n_processor;
    t.processors[i] = rec;
    t.n_processor = i + 1;
}

fn parse_memory_device(t: &mut Tables, fmt: &[u8], pool: &[u8]) {
    // Type 17 fixed section is at least 28 bytes for SMBIOS 2.1.
    if fmt.len() < 28 || t.n_memory >= MAX_MEMORY_DEVICES { return; }
    let mut rec = SmbiosMemoryDevice::ZERO;
    let size_raw = u16::from_le_bytes([fmt[12], fmt[13]]);
    rec.size_mb = if size_raw == 0x7FFF && fmt.len() >= 32 {
        // Extended size encoding at fmt[28..32] — value is in MB.
        u32::from_le_bytes([fmt[28], fmt[29], fmt[30], fmt[31]]) & 0x7FFF_FFFF
    } else if size_raw & 0x8000 != 0 {
        // bit 15 set ⇒ KB granularity
        ((size_raw & 0x7FFF) as u32) / 1024
    } else {
        size_raw as u32
    };
    rec.form_factor = fmt[14];
    copy_truncated(&mut rec.device_locator, lookup_string(pool, fmt[16]));
    copy_truncated(&mut rec.bank_locator,   lookup_string(pool, fmt[17]));
    rec.memory_type = fmt[18];
    if fmt.len() >= 23 {
        rec.speed_mts = u16::from_le_bytes([fmt[21], fmt[22]]);
    }
    if fmt.len() >= 24 {
        copy_truncated(&mut rec.manufacturer,
                       lookup_string(pool, fmt[23]));
    }
    if fmt.len() >= 25 {
        copy_truncated(&mut rec.serial_number,
                       lookup_string(pool, fmt[24]));
    }
    let i = t.n_memory;
    t.memory[i] = rec;
    t.n_memory = i + 1;
}

/// Parse a structure-stream slice. Returns the number of
/// structures observed (recognised + skipped).
pub fn parse_stream(bytes: &[u8]) -> u32 {
    let mut tables = DATA.lock();
    *tables = Tables::EMPTY;

    let mut cur = 0usize;
    let mut count = 0u32;
    while cur + 4 <= bytes.len() {
        let kind = bytes[cur];
        let len = bytes[cur + 1] as usize;
        // Type 127 is the end-of-table marker.
        if kind == 127 { count += 1; break; }
        if len < 4 || cur + len > bytes.len() { break; }
        let fmt  = &bytes[cur..cur + len];
        let pool = &bytes[cur + len..];
        let pool_len = pool_end(pool);

        match kind {
            0  => parse_bios(&mut tables, fmt, pool),
            1  => parse_system(&mut tables, fmt, pool),
            2  => parse_baseboard(&mut tables, fmt, pool),
            4  => parse_processor(&mut tables, fmt, pool),
            17 => parse_memory_device(&mut tables, fmt, pool),
            _  => {}
        }

        cur += len + pool_len;
        count += 1;
        if count > 1024 { break; }   // sanity cap
    }
    drop(tables);
    PARSED.store(true, Ordering::Release);
    count
}

pub fn is_known() -> bool { PARSED.load(Ordering::Acquire) }

pub fn copy_bios(out: &mut [SmbiosBios]) -> usize {
    let t = DATA.lock();
    let n = t.n_bios.min(out.len());
    out[..n].copy_from_slice(&t.bios[..n]);
    n
}

pub fn copy_system(out: &mut [SmbiosSystem]) -> usize {
    let t = DATA.lock();
    let n = t.n_system.min(out.len());
    out[..n].copy_from_slice(&t.system[..n]);
    n
}

pub fn copy_baseboard(out: &mut [SmbiosBaseboard]) -> usize {
    let t = DATA.lock();
    let n = t.n_baseboard.min(out.len());
    out[..n].copy_from_slice(&t.baseboards[..n]);
    n
}

pub fn copy_processors(out: &mut [SmbiosProcessor]) -> usize {
    let t = DATA.lock();
    let n = t.n_processor.min(out.len());
    out[..n].copy_from_slice(&t.processors[..n]);
    n
}

pub fn copy_memory_devices(out: &mut [SmbiosMemoryDevice]) -> usize {
    let t = DATA.lock();
    let n = t.n_memory.min(out.len());
    out[..n].copy_from_slice(&t.memory[..n]);
    n
}
