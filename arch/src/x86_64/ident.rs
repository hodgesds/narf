//! x86_64 CPU identification — vendor + brand + family/model/stepping.
//!
//! Spec: `arch/specification/cpu-info-errata.md` §1.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Vendor {
    Intel,
    Amd,
    Hygon,
    Centaur,
    Via,
    Zhaoxin,
    Other([u8; 12]),
}

impl Vendor {
    fn classify(s: [u8; 12]) -> Vendor {
        match &s {
            b"GenuineIntel" => Vendor::Intel,
            b"AuthenticAMD" => Vendor::Amd,
            b"HygonGenuine" => Vendor::Hygon,
            b"CentaurHauls" => Vendor::Centaur,
            b"VIA VIA VIA " => Vendor::Via,
            b"  Shanghai  " => Vendor::Zhaoxin,
            _ => Vendor::Other(s),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct CpuId {
    pub vendor:    Vendor,
    pub family:    u16,
    pub model:     u16,
    pub stepping:  u8,
    pub signature: u32,
    pub brand:     [u8; 48],
}

fn write_le_u32(buf: &mut [u8], at: usize, v: u32) {
    let bytes = v.to_le_bytes();
    buf[at..at+4].copy_from_slice(&bytes);
}

pub fn read() -> CpuId {
    // Vendor — CPUID(0).EBX:EDX:ECX
    // SAFETY: leaf 0 always defined.
    let (max_basic, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    let mut vendor_bytes = [0u8; 12];
    vendor_bytes[0..4].copy_from_slice(&ebx.to_le_bytes());
    vendor_bytes[4..8].copy_from_slice(&edx.to_le_bytes());
    vendor_bytes[8..12].copy_from_slice(&ecx.to_le_bytes());
    let vendor = Vendor::classify(vendor_bytes);

    // Signature — CPUID(1).EAX
    let (sig, _, _, _) = if max_basic >= 1 {
        // SAFETY: leaf 1 valid.
        unsafe { cpuid(1, 0) }
    } else {
        (0, 0, 0, 0)
    };
    let stepping     = (sig & 0xF) as u8;
    let base_model   = ((sig >> 4) & 0xF) as u16;
    let base_family  = ((sig >> 8) & 0xF) as u16;
    let ext_model    = ((sig >> 16) & 0xF) as u16;
    let ext_family   = ((sig >> 20) & 0xFF) as u16;
    let family = base_family + if base_family == 0xF { ext_family } else { 0 };
    let model  = if base_family >= 0x6 || base_family == 0xF {
        base_model | (ext_model << 4)
    } else {
        base_model
    };

    // Brand — CPUID(0x8000_0002..4)
    let mut brand = [0u8; 48];
    // SAFETY: leaf 0x8000_0000 always defined.
    let (max_ext, _, _, _) = unsafe { cpuid(0x8000_0000, 0) };
    if max_ext >= 0x8000_0004 {
        for (i, leaf) in [0x8000_0002u32, 0x8000_0003, 0x8000_0004].iter().enumerate() {
            // SAFETY: gated.
            let (a, b, c, d) = unsafe { cpuid(*leaf, 0) };
            let off = i * 16;
            write_le_u32(&mut brand, off,      a);
            write_le_u32(&mut brand, off + 4,  b);
            write_le_u32(&mut brand, off + 8,  c);
            write_le_u32(&mut brand, off + 12, d);
        }
    }

    CpuId { vendor, family, model, stepping, signature: sig, brand }
}

/// Trim the brand string to its NUL-terminated, leading-space-stripped
/// form. Returns an empty `&str` if no leaf-0x8000_0002 data was
/// available.
pub fn brand_str(c: &CpuId) -> &str {
    let end = c.brand.iter().position(|&b| b == 0).unwrap_or(c.brand.len());
    let mut start = 0;
    while start < end && c.brand[start] == b' ' {
        start += 1;
    }
    core::str::from_utf8(&c.brand[start..end]).unwrap_or("")
}
