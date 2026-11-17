//! GSP RPC payloads — `GspSystemInfo` and `PACKED_REGISTRY_TABLE`.
//!
//! These are the two RPCs the host fire-and-forgets at the GSP during
//! the init handshake ([`crate::gsp::GSP_INIT_SEQUENCE`]):
//! `GSP_SET_SYSTEM_INFO` (fn 72) and `SET_REGISTRY` (fn 73). Both are
//! built here as byte-exact wire payloads, grounded against
//! `/usr/src/linux`:
//!
//! - `GspSystemInfo` — `rm/r535/nvrm/gsp.h:311`, filled per
//!   `rm/r535/gsp.c::r535_gsp_set_system_info`.
//! - `PACKED_REGISTRY_TABLE` — `rm/r535/nvrm/gsp.h:227`, built per
//!   `rm/r535/gsp.c::build_registry` with the default
//!   `r535_registry_entries[]`.
//!
//! All pure CPU work (no hardware), fully unit-tested.

#![allow(dead_code)]

use alloc::vec::Vec;

// ── GspSystemInfo (GSP_SET_SYSTEM_INFO, fn 72) ───────────────────

/// `sizeof(GspSystemInfo)` — the struct is 664 bytes with natural C
/// alignment (verified field-by-field against `gsp.h:311` and its
/// nested sub-structs; it is not `__packed`).
pub const GSP_SYSTEM_INFO_SIZE: usize = 664;

/// `pciConfigMirrorBase` for Turing (the `gp100_pci_func` BAR0-
/// relative mirror of PCI config space). Cite `device->pci->func->
/// cfg.addr`.
pub const PCI_CONFIG_MIRROR_BASE: u32 = 0x0008_8000;
/// `pciConfigMirrorSize` for Turing. Cite `...cfg.size`.
pub const PCI_CONFIG_MIRROR_SIZE: u32 = 0x0000_1000;

/// Default `maxUserVa` = x86-64 `TASK_SIZE` with 4-level paging (the
/// user/kernel split). The live caller should pass the running
/// kernel's actual user-VA limit; this is the conventional value.
pub const GSP_DEFAULT_MAX_USER_VA: u64 = 0x0000_8000_0000_0000;

/// Build the `GspSystemInfo` payload for a bare Turing bring-up.
///
/// Only the fields `r535_gsp_set_system_info` populates are non-zero;
/// everything else (ACPI data, bridge/chipset info, VF info, sim/
/// hypervisor/timer fields) is left zero — Nouveau ships those zero
/// and GSP still reaches `INIT_DONE`. Field offsets are the verified
/// C layout.
///
/// - `bar0_phys` / `bar1_phys` / `bar2_phys` — physical base
///   addresses of BAR0 (PRI), BAR1 (FB), BAR2 (INST).
/// - `pci_bus` / `pci_devfn` — `nvDomainBusDeviceFunc = (bus<<8) | devfn`.
/// - `max_user_va` — the kernel's user-VA limit (`maxUserVa`).
pub fn build_system_info(
    bar0_phys: u64,
    bar1_phys: u64,
    bar2_phys: u64,
    pci_bus: u8,
    pci_devfn: u8,
    max_user_va: u64,
) -> [u8; GSP_SYSTEM_INFO_SIZE] {
    let mut b = [0u8; GSP_SYSTEM_INFO_SIZE];
    let put64 =
        |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    let put32 =
        |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    put64(&mut b, 0x00, bar0_phys); // gpuPhysAddr
    put64(&mut b, 0x08, bar1_phys); // gpuPhysFbAddr
    put64(&mut b, 0x10, bar2_phys); // gpuPhysInstAddr
    put64(&mut b, 0x18, ((pci_bus as u64) << 8) | pci_devfn as u64); // nvDomainBusDeviceFunc
    put64(&mut b, 0x38, max_user_va); // maxUserVa
    put32(&mut b, 0x40, PCI_CONFIG_MIRROR_BASE); // pciConfigMirrorBase
    put32(&mut b, 0x44, PCI_CONFIG_MIRROR_SIZE); // pciConfigMirrorSize
    b
}

// ── PACKED_REGISTRY_TABLE (SET_REGISTRY, fn 73) ──────────────────

/// Registry-entry value types. Cite `gsp.c:350` `enum registry_type`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryValue<'a> {
    /// 32-bit value stored inline in the entry's `data` field.
    Dword(u32),
    /// Binary blob stored in the data section; `data` is its offset.
    Binary(&'a [u8]),
    /// NUL-terminated string stored in the data section.
    Str(&'a str),
}

impl RegistryValue<'_> {
    const fn type_tag(&self) -> u8 {
        match self {
            RegistryValue::Dword(_) => 1,
            RegistryValue::Binary(_) => 2,
            RegistryValue::Str(_) => 3,
        }
    }
}

/// Size of a `PACKED_REGISTRY_ENTRY` (natural C layout: `nameOffset`
/// u32, `type` u8 + 3 pad, `data` u32, `length` u32). Cite `gsp.h:227`.
pub const REGISTRY_ENTRY_SIZE: usize = 16;
/// Size of the `PACKED_REGISTRY_TABLE` header (`size` + `numEntries`).
pub const REGISTRY_HEADER_SIZE: usize = 8;

/// The default registry keys Nouveau installs for a baseline boot,
/// all DWORD = 1, in order. Cite `gsp.c:588 r535_registry_entries[]`.
pub fn default_registry_entries() -> [(&'static str, RegistryValue<'static>); 3] {
    [
        ("RMSecBusResetEnable", RegistryValue::Dword(1)),
        ("RMForcePcieConfigSave", RegistryValue::Dword(1)),
        ("RMDevidCheckIgnore", RegistryValue::Dword(1)),
    ]
}

/// Build a `PACKED_REGISTRY_TABLE` into a flat byte buffer. Layout:
/// an 8-byte header (`size`, `numEntries`), then one 16-byte entry
/// per key, then a dense data section holding, for each entry in
/// order, the NUL-terminated key name followed by its value blob
/// (DWORD values live inline in the entry, not in the data section).
/// Offsets in `nameOffset`/`data` are absolute from the buffer start.
/// Mirrors `gsp.c::build_registry` exactly.
pub fn build_registry(entries: &[(&str, RegistryValue)]) -> Vec<u8> {
    // Phase 1 — total size.
    let mut data_size = 0usize;
    for (key, val) in entries {
        data_size += key.len() + 1; // name + NUL
        data_size += match val {
            RegistryValue::Dword(_) => 0,
            RegistryValue::Binary(blob) => blob.len(),
            RegistryValue::Str(s) => s.len() + 1,
        };
    }
    let total = REGISTRY_HEADER_SIZE + entries.len() * REGISTRY_ENTRY_SIZE + data_size;

    let mut buf = alloc::vec![0u8; total];
    buf[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    buf[4..8].copy_from_slice(&(entries.len() as u32).to_le_bytes());

    // Phase 2 — entries + interleaved data.
    let mut str_off = REGISTRY_HEADER_SIZE + entries.len() * REGISTRY_ENTRY_SIZE;
    for (i, (key, val)) in entries.iter().enumerate() {
        let e = REGISTRY_HEADER_SIZE + i * REGISTRY_ENTRY_SIZE;
        buf[e..e + 4].copy_from_slice(&(str_off as u32).to_le_bytes()); // nameOffset
        buf[e + 4] = val.type_tag(); // type (+3 pad bytes stay zero)
                                     // key name + NUL
        buf[str_off..str_off + key.len()].copy_from_slice(key.as_bytes());
        str_off += key.len() + 1;
        match val {
            RegistryValue::Dword(v) => {
                buf[e + 8..e + 12].copy_from_slice(&v.to_le_bytes()); // data = value
                buf[e + 12..e + 16].copy_from_slice(&4u32.to_le_bytes()); // length = 4
            }
            RegistryValue::Binary(blob) => {
                buf[e + 8..e + 12].copy_from_slice(&(str_off as u32).to_le_bytes());
                buf[e + 12..e + 16].copy_from_slice(&(blob.len() as u32).to_le_bytes());
                buf[str_off..str_off + blob.len()].copy_from_slice(blob);
                str_off += blob.len();
            }
            RegistryValue::Str(s) => {
                buf[e + 8..e + 12].copy_from_slice(&(str_off as u32).to_le_bytes());
                let slen = s.len() + 1;
                buf[e + 12..e + 16].copy_from_slice(&(slen as u32).to_le_bytes());
                buf[str_off..str_off + s.len()].copy_from_slice(s.as_bytes());
                str_off += slen;
            }
        }
    }
    debug_assert_eq!(str_off, total);
    buf
}

/// Build the default baseline `PACKED_REGISTRY_TABLE`.
pub fn build_default_registry() -> Vec<u8> {
    build_registry(&default_registry_entries())
}
