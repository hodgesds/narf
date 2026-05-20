//! AMDGPU IP Discovery binary parser.
//!
//! Modern AMD GPUs (Navi2+, Phoenix/Strix APUs, every chip from
//! roughly 2020 onward) publish their on-die IP block layout as a
//! binary "IP discovery" table living in the top of VRAM. Instead
//! of the driver knowing per-family which MMIO offset hosts MP0,
//! GC, SDMA, DCN, VCN, etc., it reads the discovery blob and gets
//! a complete enumeration of every IP block + per-instance MMIO
//! base address straight from the silicon.
//!
//! This module parses that blob into a flat `Vec<IpBlock>` that
//! every other subsystem (PSP loader, SMU client, DCN modeset,
//! GFX/SDMA ring bring-up, VCN codec) consumes via the
//! `find_ip(blocks, hw_id, instance)` helper.
//!
//! ## Reference
//!
//! NARF is GPL-2.0-or-later as of 2026-05-20, so the parser is
//! adapted directly from Linux:
//!
//! - `drivers/gpu/drm/amd/include/discovery.h` — wire-format
//!   binary header / IP discovery header / die header / ip_v4
//!   structs and the four magic table-id constants.
//! - `drivers/gpu/drm/amd/include/soc15_hw_ip.h` — the
//!   `<NAME>_HWID` constants exposed as `HW_ID_*` here.
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c` — the
//!   reference parser. Specifically:
//!     - `amdgpu_discovery_verify_binary_signature` (lines
//!       400-406): the `BINARY_SIGNATURE = 0x28211407` outer-frame
//!       check.
//!     - `amdgpu_discovery_calculate_checksum` (lines 372-381):
//!       16-bit sum-of-bytes that secures every sub-table.
//!     - `amdgpu_discovery_init` (lines 494-700): the read +
//!       outer-signature + outer-checksum + per-table signature
//!       and checksum verification.
//!     - `amdgpu_discovery_reg_base_init` (lines 1384-1582): the
//!       die-walk + IP-walk that emits `(hw_id, instance,
//!       base_address[])` tuples — the part this module
//!       reproduces.
//!
//! ## Wire format (little-endian throughout)
//!
//! ```text
//! offset 0:   binary_header {
//!   u32 binary_signature  (0x28211407)
//!   u16 version_major
//!   u16 version_minor
//!   u16 binary_checksum   (sum-of-bytes over everything after this field)
//!   u16 binary_size
//!   table_info[6] {
//!     u16 offset           // byte offset into the blob
//!     u16 checksum         // sum-of-bytes over `size` bytes
//!     u16 size             // table byte length
//!     u16 padding
//!   }
//! }
//! ```
//!
//! Table indices: 0=IP_DISCOVERY, 1=GC, 2=HARVEST_INFO,
//! 3=VCN_INFO, 4=MALL_INFO, 5=NPS_INFO.
//!
//! At `binary_header.table_list[IP_DISCOVERY].offset`:
//!
//! ```text
//! ip_discovery_header {
//!   u32 signature   (DISCOVERY_TABLE_SIGNATURE = 0x53445049 "IPDS")
//!   u16 version
//!   u16 size
//!   u32 id
//!   u16 num_dies
//!   die_info[16] {
//!     u16 die_id
//!     u16 die_offset       // points at a `die_header` in this blob
//!   }
//!   union {
//!     u16 padding;         // version <= 3
//!     struct {             // version == 4
//!       u8 flags;          // bit0 = base_addr_64_bit
//!       u8 reserved;
//!     };
//!   }
//! }
//! ```
//!
//! At each `die_info[i].die_offset`:
//!
//! ```text
//! die_header { u16 die_id, u16 num_ips }
//! ip_v4 ip_list[num_ips] {
//!   u16 hw_id
//!   u8  instance_number
//!   u8  num_base_address
//!   u8  major
//!   u8  minor
//!   u8  revision
//!   u8  packed_variant_subrev   // (variant<<4) | sub_revision
//!   union {
//!     u32 base_address[num_base_address]; // 32-bit form
//!     u64 base_address_64[num_base_address]; // when flags.bit0 set
//!   }
//! }
//! ```
//!
//! When `base_addr_64_bit` is set the parser truncates the low 32
//! bits of each 64-bit base (with the top 2 bits cleared, matching
//! `amdgpu_discovery_reg_base_init` line 1529).
//!
//! ## What this module returns
//!
//! A flat `Vec<IpBlock>` — one entry per `(die, ip, instance)`
//! tuple. Callers index with `find_ip(blocks, HW_ID_MP0, 0)`,
//! etc. Per-IP base addresses live in `base_addrs[0..]`; index 0
//! is the canonical register window. `num_base_address` is
//! capped at 5 to match Linux's `MAX_IP_BASE_ADDR` (the four
//! aperture types plus an XCC-specific extension).

#![allow(clippy::module_name_repetitions)]

extern crate alloc;

use alloc::vec::Vec;
use core::convert::TryInto;

// ── Constants from Linux include/discovery.h ───────────────────────

/// `BINARY_SIGNATURE` per `discovery.h` line 28 — the outer-frame
/// "IPDS" magic encoded as the bytes `0x07 0x14 0x21 0x28`.
pub const BINARY_SIGNATURE: u32 = 0x2821_1407;
/// `DISCOVERY_TABLE_SIGNATURE` per `discovery.h` line 29 — the
/// "IPDS" ASCII signature on the IP-discovery sub-table.
pub const DISCOVERY_TABLE_SIGNATURE: u32 = 0x5344_5049;

/// Indices into `binary_header.table_list[]`. Match the `enum
/// table` from `discovery.h` lines 36-44.
pub const TABLE_IP_DISCOVERY: usize = 0;
pub const TABLE_GC: usize = 1;
pub const TABLE_HARVEST_INFO: usize = 2;
pub const TABLE_VCN_INFO: usize = 3;
pub const TABLE_MALL_INFO: usize = 4;
pub const TABLE_NPS_INFO: usize = 5;
pub const TOTAL_TABLES: usize = 6;

// ── HW_ID constants from soc15_hw_ip.h ────────────────────────────
//
// Subset of the full list — only the IPs NARF subsystems currently
// consume (PSP, SMU, GFX, SDMA, DCN, VCN, MMHUB/ATHUB for VRAM
// translation, OSSSYS for interrupts, BIF/NBIF for PCIe doorbells).
// Anything missing here is still in the discovery blob and can be
// fetched by raw `hw_id`; the named constants are convenience.

pub const HW_ID_MP1: u16 = 1;
pub const HW_ID_MP2: u16 = 2;
pub const HW_ID_THM: u16 = 3;
pub const HW_ID_SMUIO: u16 = 4;
pub const HW_ID_PWR: u16 = 10;
pub const HW_ID_GC: u16 = 11;
pub const HW_ID_UVD: u16 = 12;
pub const HW_ID_VCN: u16 = HW_ID_UVD; // VCN_HWID alias of UVD_HWID
pub const HW_ID_DCI: u16 = 15;
pub const HW_ID_DCO: u16 = 16;
pub const HW_ID_DCE: u16 = HW_ID_DCO; // Pre-DCN display path
pub const HW_ID_DMU: u16 = 271;
pub const HW_ID_DCN: u16 = HW_ID_DMU; // Display Core Next
pub const HW_ID_MMHUB: u16 = 34;
pub const HW_ID_ATHUB: u16 = 35;
pub const HW_ID_OSSSYS: u16 = 40; // Interrupt source
pub const HW_ID_HDP: u16 = 41;
pub const HW_ID_SDMA0: u16 = 42;
pub const HW_ID_SDMA1: u16 = 43;
pub const HW_ID_SDMA2: u16 = 68;
pub const HW_ID_SDMA3: u16 = 69;
pub const HW_ID_DF: u16 = 46;
pub const HW_ID_PCIE: u16 = 70;
pub const HW_ID_UMC: u16 = 150;
pub const HW_ID_NBIF: u16 = 108;
pub const HW_ID_BIF: u16 = HW_ID_NBIF; // PCIe interface
pub const HW_ID_XGMI: u16 = 200;
pub const HW_ID_MP0: u16 = 255;
pub const HW_ID_VPE: u16 = 21;

// ── Discovery TMR placement constants ─────────────────────────────
//
// Per `amdgpu_discovery.c` line 332:
//
//   uint64_t pos = vram_size - DISCOVERY_TMR_OFFSET;
//
// — the discovery blob lives at the very top of the VRAM aperture,
// `DISCOVERY_TMR_OFFSET` bytes below the end. Linux's
// `amdgpu_discovery.h` defines `DISCOVERY_TMR_OFFSET = 64 << 10`
// (64 KiB) and `DISCOVERY_TMR_SIZE = 10 << 10` (10 KiB — the
// driver allocates a larger 4 KiB-multiple buffer up to a few MiB
// in practice). We keep both names so the wire-up site can pick.

/// Offset from end of VRAM where the discovery blob starts.
pub const DISCOVERY_TMR_OFFSET: u64 = 64 * 1024;
/// Maximum useful discovery blob size — the binary itself is
/// well under 10 KiB on every chip Linux currently knows about.
/// We over-allocate to 4 MiB to match the way `amdgpu_discovery.c`
/// allocates its scratch buffer.
pub const DISCOVERY_TMR_SIZE: usize = 4 * 1024 * 1024;

// ── Errors ────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    /// Blob is shorter than the binary header.
    Truncated,
    /// `BINARY_SIGNATURE` field of the outer header didn't match.
    /// Typical on QEMU + garbage reads from non-AMD silicon.
    BadSignature,
    /// 16-bit sum-of-bytes over the outer header (post-checksum
    /// field) didn't match `binary_checksum`.
    BadOuterChecksum,
    /// IP-discovery sub-table's `signature` field didn't match
    /// `DISCOVERY_TABLE_SIGNATURE` ("IPDS").
    BadIpTableSignature,
    /// IP-discovery sub-table's per-table checksum didn't match.
    BadIpTableChecksum,
    /// A `die_offset` / `ip_offset` walked off the end of the blob.
    OffsetOutOfBounds,
    /// `num_dies > 16` (the wire format caps it at 16 — see
    /// `die_info[16]` in `discovery.h` line 81).
    TooManyDies,
    /// `num_base_address > 16` — sanity bound. Real chips use 1-5.
    TooManyBaseAddresses,
}

// ── Output shape ──────────────────────────────────────────────────

/// Up to this many 32-bit MMIO bases per IP. Matches Linux's
/// `MAX_IP_BASE_ADDR` (drivers/gpu/drm/amd/include/amdgpu_socinfo.h
/// uses 5 — the four aperture types AID/XCD/MMHUB/SOC plus a
/// per-XCC extension on MI300).
pub const MAX_BASE_ADDRS: usize = 5;

/// One IP block enumerated by the discovery table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IpBlock {
    /// HW ID (one of the `HW_ID_*` constants in this module, or
    /// any other ID present in `soc15_hw_ip.h`).
    pub hw_id: u16,
    /// Per-IP instance number — e.g. `(HW_ID_SDMA0, 0)`,
    /// `(HW_ID_SDMA0, 1)` for a chip with two SDMA0 engines.
    pub instance: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u8,
    /// HCID sub-revision (low nibble of the packed byte; 0 on
    /// `ip_discovery_header.version < 3`).
    pub sub_revision: u8,
    /// HW variant (high nibble of the packed byte; 0 on
    /// `ip_discovery_header.version < 3`).
    pub variant: u8,
    /// MMIO base addresses in BAR5 register-bus dword space. The
    /// first `num_bases` entries are populated; the rest are
    /// zero. Index 0 is the canonical register window for the
    /// IP — that's what `Family::mp0_base()` returns and what the
    /// per-subsystem bring-up paths consume.
    pub base_addrs: [u32; MAX_BASE_ADDRS],
    /// Number of populated entries in `base_addrs`.
    pub num_bases: u8,
}

/// Find the first IP block matching `(hw_id, instance)`. Most
/// callers pass `instance = 0`; multi-instance lookups
/// (`SDMA0/0`, `SDMA0/1`) iterate by re-querying with each
/// instance number.
pub fn find_ip(blocks: &[IpBlock], hw_id: u16, instance: u8) -> Option<&IpBlock> {
    blocks
        .iter()
        .find(|b| b.hw_id == hw_id && b.instance == instance)
}

// ── Parser ────────────────────────────────────────────────────────

/// Outer binary header size in bytes:
///   binary_signature   u32 = 4
///   version_major      u16 = 2
///   version_minor      u16 = 2
///   binary_checksum    u16 = 2
///   binary_size        u16 = 2
///   table_list[6]      6 * 8 = 48
/// — total 60 bytes.
const BINARY_HEADER_SIZE: usize = 4 + 2 + 2 + 2 + 2 + TOTAL_TABLES * 8;

/// Offset of `binary_checksum` inside the outer header (per
/// `amdgpu_discovery.c` line 538 — `offsetof(struct binary_header,
/// binary_checksum)`).
const BINARY_CHECKSUM_FIELD_OFFSET: usize = 4 + 2 + 2;

/// IP-discovery sub-table header size:
///   signature   u32 = 4
///   version     u16 = 2
///   size        u16 = 2
///   id          u32 = 4
///   num_dies    u16 = 2
///   die_info[16] u32 * 16 = 64
///   union      u16 = 2
/// — total 80 bytes.
const IP_DISCOVERY_HEADER_SIZE: usize = 4 + 2 + 2 + 4 + 2 + 16 * 4 + 2;

/// `die_header` size: `u16 die_id + u16 num_ips`.
const DIE_HEADER_SIZE: usize = 4;

/// Fixed-size prefix of one `ip_v4` entry — everything before
/// the variable-length `base_address[]` tail:
///   hw_id u16 + instance u8 + num_base u8 + major u8 + minor u8 +
///   revision u8 + packed (variant<<4|sub_rev) u8 = 8 bytes.
const IP_V4_FIXED_SIZE: usize = 8;

/// Sum-of-bytes checksum (16-bit wrapping). Matches
/// `amdgpu_discovery_calculate_checksum` (`amdgpu_discovery.c`
/// lines 372-381).
fn sum_bytes(data: &[u8]) -> u16 {
    let mut s: u16 = 0;
    for &b in data {
        s = s.wrapping_add(b as u16);
    }
    s
}

fn u16_at(blob: &[u8], off: usize) -> Result<u16, DiscoveryError> {
    blob.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .ok_or(DiscoveryError::OffsetOutOfBounds)
}

fn u32_at(blob: &[u8], off: usize) -> Result<u32, DiscoveryError> {
    blob.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or(DiscoveryError::OffsetOutOfBounds)
}

fn u64_at(blob: &[u8], off: usize) -> Result<u64, DiscoveryError> {
    blob.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or(DiscoveryError::OffsetOutOfBounds)
}

/// Top-level entry point. `blob` is the raw bytes read from VRAM
/// at `vram_top - DISCOVERY_TMR_OFFSET`; on chips without a
/// discovery table (older silicon, garbage on QEMU) this returns
/// `BadSignature` and the caller silently falls back to the
/// hardcoded `Family::mp0_base()` table.
pub fn parse_discovery(blob: &[u8]) -> Result<Vec<IpBlock>, DiscoveryError> {
    if blob.len() < BINARY_HEADER_SIZE {
        return Err(DiscoveryError::Truncated);
    }

    // Outer signature.
    let sig = u32_at(blob, 0)?;
    if sig != BINARY_SIGNATURE {
        return Err(DiscoveryError::BadSignature);
    }

    let binary_checksum = u16_at(blob, BINARY_CHECKSUM_FIELD_OFFSET)?;
    let binary_size = u16_at(blob, BINARY_CHECKSUM_FIELD_OFFSET + 2)? as usize;

    // Sum-of-bytes over [binary_checksum_field_end .. binary_size].
    // Matches `amdgpu_discovery.c` lines 538-548.
    let csum_start = BINARY_CHECKSUM_FIELD_OFFSET + 2; // step over checksum field
    if binary_size < csum_start || binary_size > blob.len() {
        return Err(DiscoveryError::OffsetOutOfBounds);
    }
    let csum_region = &blob[csum_start..binary_size];
    if sum_bytes(csum_region) != binary_checksum {
        return Err(DiscoveryError::BadOuterChecksum);
    }

    // Walk to the IP-discovery sub-table.
    let table_list_base = 4 + 2 + 2 + 2 + 2;
    let ip_info_base = table_list_base + TABLE_IP_DISCOVERY * 8;
    let ip_offset = u16_at(blob, ip_info_base)? as usize;
    let ip_checksum = u16_at(blob, ip_info_base + 2)?;
    // `info->size` field is ignored by the reference parser
    // (`amdgpu_discovery.c` uses the sub-table's own `size` field
    // for verification, line 564); we mirror that.

    if ip_offset == 0 || ip_offset + IP_DISCOVERY_HEADER_SIZE > blob.len() {
        return Err(DiscoveryError::OffsetOutOfBounds);
    }

    // IP-discovery sub-table.
    let ip_sig = u32_at(blob, ip_offset)?;
    if ip_sig != DISCOVERY_TABLE_SIGNATURE {
        return Err(DiscoveryError::BadIpTableSignature);
    }
    let ip_version = u16_at(blob, ip_offset + 4)?;
    let ip_size = u16_at(blob, ip_offset + 6)? as usize;
    if ip_offset + ip_size > blob.len() {
        return Err(DiscoveryError::OffsetOutOfBounds);
    }
    if sum_bytes(&blob[ip_offset..ip_offset + ip_size]) != ip_checksum {
        return Err(DiscoveryError::BadIpTableChecksum);
    }

    let num_dies = u16_at(blob, ip_offset + 12)?;
    if num_dies > 16 {
        return Err(DiscoveryError::TooManyDies);
    }

    // `base_addr_64_bit` lives in the union at the end of the
    // header on `version == 4` — at offset
    // `IP_DISCOVERY_HEADER_SIZE - 2`. On v<4 the field is
    // padding; treat as zero.
    let base_addr_64_bit = if ip_version >= 4 {
        (blob[ip_offset + IP_DISCOVERY_HEADER_SIZE - 2] & 0x01) != 0
    } else {
        false
    };

    let mut blocks = Vec::new();

    // Walk each die.
    for die_idx in 0..num_dies as usize {
        // die_info[i] = { u16 die_id, u16 die_offset } at offset
        // 14 + i*4 inside the IP-discovery header.
        let die_info_off = ip_offset + 14 + die_idx * 4;
        let die_offset = u16_at(blob, die_info_off + 2)? as usize;
        if die_offset == 0 || die_offset + DIE_HEADER_SIZE > blob.len() {
            return Err(DiscoveryError::OffsetOutOfBounds);
        }
        let num_ips = u16_at(blob, die_offset + 2)?;
        let mut cursor = die_offset + DIE_HEADER_SIZE;

        // Walk each IP block on this die.
        for _ in 0..num_ips {
            if cursor + IP_V4_FIXED_SIZE > blob.len() {
                return Err(DiscoveryError::OffsetOutOfBounds);
            }
            let hw_id = u16_at(blob, cursor)?;
            let instance = blob[cursor + 2];
            let num_base = blob[cursor + 3];
            let major = blob[cursor + 4];
            let minor = blob[cursor + 5];
            let revision = blob[cursor + 6];
            let packed = blob[cursor + 7];
            // LE host: sub_revision in low nibble, variant in high.
            // See `ip_v4` LITTLEENDIAN_CPU branch (discovery.h lines
            // 135-140).
            let sub_revision = packed & 0x0F;
            let variant = (packed >> 4) & 0x0F;

            if num_base as usize > 16 {
                return Err(DiscoveryError::TooManyBaseAddresses);
            }

            // Read base addresses. `base_addr_64_bit` widens each
            // slot from 4 to 8 bytes; we truncate to the low 32
            // bits (with the top 2 bits cleared) the same way
            // Linux does on line 1529.
            let bases_off = cursor + IP_V4_FIXED_SIZE;
            let slot_bytes = if base_addr_64_bit { 8 } else { 4 };
            let bases_len = num_base as usize * slot_bytes;
            if bases_off + bases_len > blob.len() {
                return Err(DiscoveryError::OffsetOutOfBounds);
            }

            let mut base_addrs = [0u32; MAX_BASE_ADDRS];
            let kept = (num_base as usize).min(MAX_BASE_ADDRS);
            for k in 0..kept {
                base_addrs[k] = if base_addr_64_bit {
                    let raw = u64_at(blob, bases_off + k * 8)?;
                    (raw as u32) & 0x3FFF_FFFF
                } else {
                    u32_at(blob, bases_off + k * 4)?
                };
            }

            blocks.push(IpBlock {
                hw_id,
                instance,
                major,
                minor,
                revision,
                // On `ip_discovery_header.version < 3` the packed
                // byte is reserved (see `amdgpu_discovery.c` lines
                // 1552-1557); zero it out for older blobs.
                sub_revision: if ip_version >= 3 { sub_revision } else { 0 },
                variant: if ip_version >= 3 { variant } else { 0 },
                base_addrs,
                num_bases: kept as u8,
            });

            cursor += IP_V4_FIXED_SIZE + bases_len;
        }
    }

    Ok(blocks)
}
