//! Intel Interrupt Remapping — IRTE encode/decode + IR enable.
//!
//! Spec: `arch/specification/irq-cache-numa.md` §1.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::ptr::write_volatile;

pub const VTD_IRTAR: usize = 0xB8;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Irte {
    pub present: bool,
    pub fault_disable: bool,
    pub dest_logical: bool,
    pub vector: u8,
    pub delivery_mode: u8,
    pub destination: u16,
}

pub fn encode_irte(e: Irte) -> [u64; 2] {
    let mut q0: u64 = 0;
    if e.present {
        q0 |= 1 << 0;
    }
    if e.fault_disable {
        q0 |= 1 << 1;
    }
    if e.dest_logical {
        q0 |= 1 << 2;
    }
    q0 |= ((e.delivery_mode as u64) & 0x7) << 5;
    q0 |= ((e.vector as u64) & 0xF) << 12;
    q0 |= ((e.destination as u64) & 0xFFFF) << 32;
    // qword[1] = SVT data; left zero in v0.1.
    [q0, 0]
}

pub fn decode_irte(raw: [u64; 2]) -> Irte {
    let q0 = raw[0];
    Irte {
        present: q0 & (1 << 0) != 0,
        fault_disable: q0 & (1 << 1) != 0,
        dest_logical: q0 & (1 << 2) != 0,
        delivery_mode: ((q0 >> 5) & 0x7) as u8,
        vector: ((q0 >> 12) & 0xF) as u8,
        destination: ((q0 >> 32) & 0xFFFF) as u16,
    }
}

/// Program IRTAR with `(table_pa | size_log2)`. `size_log2 - 1`
/// goes in bits[3:0] per SDM §10.4.30; `table_pa` carries the
/// page-aligned base.
///
/// # Safety
/// `reg_base` is a strong-uncacheable MMIO mapping of a VT-d
/// engine register block; `table_pa` is a 4 KiB-aligned
/// physical address whose backing has at least `1 << size_log2`
/// IRTEs (16 bytes each).
pub unsafe fn write_irtar(reg_base: usize, table_pa: u64, log2_size: u8) {
    let v = (table_pa & !0xFFF) | ((log2_size as u64 - 1) & 0xF);
    // SAFETY: caller-asserted.
    unsafe {
        write_volatile((reg_base + VTD_IRTAR) as *mut u64, v);
    }
}
