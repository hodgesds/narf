//! Native HDA controllers and PCM. Register definitions follow the HDA spec;
//! sequencing and AMD quirks follow /usr/src/linux/sound/hda/{core,controllers}.

mod routing;
mod runtime;
mod stream;
pub use runtime::*;
pub use stream::play_buffer;

// ── PCI device ids ─────────────────────────────────────────────────

/// AMD Ryzen / Phoenix Family-19h HD Audio Controller.
pub const HDA_AMD_PHOENIX_VENDOR: u16 = 0x1022;
pub const HDA_AMD_PHOENIX_DEVICE: u16 = 0x15e3;

/// AMD Radeon HD Audio Controller — found on integrated Radeon GPUs.
pub const HDA_AMD_RADEON_VENDOR: u16 = 0x1002;
pub const HDA_AMD_RADEON_DEVICE: u16 = 0x1640;

/// Intel ICH6 HD Audio.
pub const HDA_INTEL_ICH6_VENDOR: u16 = 0x8086;
pub const HDA_INTEL_ICH6_DEVICE: u16 = 0x2668;

/// Intel ICH7 HD Audio.
pub const HDA_INTEL_ICH7_VENDOR: u16 = 0x8086;
pub const HDA_INTEL_ICH7_DEVICE: u16 = 0x27D8;

/// Intel ICH9 HD Audio (QEMU default).
pub const HDA_INTEL_ICH9_VENDOR: u16 = 0x8086;
pub const HDA_INTEL_ICH9_DEVICE: u16 = 0x293E;

// ── Intel PCH HDA controller PCI device ids ───────────────────────
//
// Every Intel PCH HDA controller speaks the standard Intel HDA
// programming model (same BAR0 layout, CORB/RIRB, stream descriptors,
// codec verbs) — only the PCI ID changes. The IDs below cover the
// modern PCH era (Skylake → Meteor Lake). All share the Intel vendor
// ID 0x8086 and the same `probe` entry as the legacy ICH path.
//
// Reference: Linux `sound/pci/hda/hda_intel.c` `azx_ids[]` and
// `pci.ids`. We deliberately keep each ID in its own named constant
// so it is grep-able and the registration site is a flat enumeration.

/// Sunrise Point-LP HD Audio (Skylake / Kaby Lake PCH-LP).
pub const HDA_INTEL_SUNRISE_POINT_LP_DEVICE: u16 = 0x9D70;
/// Sunrise Point-LP HD Audio — variant.
pub const HDA_INTEL_SUNRISE_POINT_LP_DEVICE_B: u16 = 0x9D71;

/// Cannon Lake PCH HD Audio.
pub const HDA_INTEL_CANNON_LAKE_DEVICE: u16 = 0xA348;

/// Comet Lake HD Audio — variant A.
pub const HDA_INTEL_COMET_LAKE_DEVICE: u16 = 0xA171;
/// Comet Lake HD Audio — variant B.
pub const HDA_INTEL_COMET_LAKE_DEVICE_B: u16 = 0x43C8;

/// Tiger Lake PCH-LP HD Audio — variant A.
pub const HDA_INTEL_TIGER_LAKE_LP_DEVICE: u16 = 0xA0C8;
/// Tiger Lake PCH-LP HD Audio — variant B.
pub const HDA_INTEL_TIGER_LAKE_LP_DEVICE_B: u16 = 0xA0C9;

/// Alder Lake-P / Alder Lake-S HD Audio — variant A.
pub const HDA_INTEL_ALDER_LAKE_DEVICE: u16 = 0x7AD0;
/// Alder Lake-P / Alder Lake-S HD Audio — variant B.
pub const HDA_INTEL_ALDER_LAKE_DEVICE_B: u16 = 0x51C8;
/// Alder Lake-P / Alder Lake-S HD Audio — variant C.
pub const HDA_INTEL_ALDER_LAKE_DEVICE_C: u16 = 0x51CD;

/// Meteor Lake HD Audio.
pub const HDA_INTEL_METEOR_LAKE_DEVICE: u16 = 0x7E28;
// Names below track Linux's `PCI_DEVICE_ID_INTEL_HDA_*` in
// `include/linux/pci_ids.h` so the two tables can be diffed directly.

/// Arrow Lake HD Audio (`PCI_DEVICE_ID_INTEL_HDA_ARL`).
pub const HDA_INTEL_ARROW_LAKE_DEVICE: u16 = 0x7728;
/// Arrow Lake-S HD Audio (`PCI_DEVICE_ID_INTEL_HDA_ARL_S`).
pub const HDA_INTEL_ARROW_LAKE_S_DEVICE: u16 = 0x7F50;
/// Lunar Lake-P HD Audio (`PCI_DEVICE_ID_INTEL_HDA_LNL_P`).
pub const HDA_INTEL_LUNAR_LAKE_P_DEVICE: u16 = 0xA828;
/// Panther Lake-H HD Audio (`PCI_DEVICE_ID_INTEL_HDA_PTL_H`) — the
/// controller on the Minisforum MS-03 at `00:1f.3`.
pub const HDA_INTEL_PANTHER_LAKE_H_DEVICE: u16 = 0xE328;
/// Panther Lake HD Audio (`PCI_DEVICE_ID_INTEL_HDA_PTL`).
pub const HDA_INTEL_PANTHER_LAKE_DEVICE: u16 = 0xE428;

// ── Intel iGPU display-audio PCI device ids ───────────────────────
//
// On Intel platforms a second HDA-class controller lives on the
// graphics PCI function and carries HDMI / DisplayPort audio. The
// programming model is identical to the PCH HDA controller — same
// CORB/RIRB, same codec verbs — only the BAR layout and bus
// location differ. We register the same `probe` entry so both lines
// bind out of the same code path.

/// Tiger Lake-H iGPU HD Audio.
pub const HDA_INTEL_TIGER_LAKE_GFX_DEVICE: u16 = 0x4F90;
/// Tiger Lake-H iGPU HD Audio — variant B.
pub const HDA_INTEL_TIGER_LAKE_GFX_DEVICE_B: u16 = 0x4F92;
/// Tiger Lake-LP iGPU HD Audio.
pub const HDA_INTEL_TIGER_LAKE_GFX_DEVICE_C: u16 = 0x9A09;
/// Tiger Lake-LP iGPU HD Audio — variant.
pub const HDA_INTEL_TIGER_LAKE_GFX_DEVICE_D: u16 = 0x9A0C;

// ── Global register offsets (HDA 1.0a §3.3) ────────────────────────

const REG_GCAP: u64 = 0x00;
#[allow(dead_code)]
const REG_VMIN: u64 = 0x02;
#[allow(dead_code)]
const REG_VMAJ: u64 = 0x03;
#[allow(dead_code)]
const REG_OUTPAY: u64 = 0x04;
#[allow(dead_code)]
const REG_INPAY: u64 = 0x06;
const REG_GCTL: u64 = 0x08;
#[allow(dead_code)]
const REG_WAKEEN: u64 = 0x0C;
const REG_STATESTS: u64 = 0x0E;
/// INTCTL — controller IRQ enables (§3.3.14). 32-bit at 0x20.
const REG_INTCTL: u64 = 0x20;

// CORB block (§3.3.21–§3.3.27).
const REG_CORBLBASE: u64 = 0x40;
const REG_CORBUBASE: u64 = 0x44;
const REG_CORBWP: u64 = 0x48;
const REG_CORBRP: u64 = 0x4A;
const REG_CORBCTL: u64 = 0x4C;
#[allow(dead_code)]
const REG_CORBSTS: u64 = 0x4D;
#[allow(dead_code)]
const REG_CORBSIZE: u64 = 0x4E;

// RIRB block (§3.3.28–§3.3.34).
const REG_RIRBLBASE: u64 = 0x50;
const REG_RIRBUBASE: u64 = 0x54;
const REG_RIRBWP: u64 = 0x58;
const REG_RINTCNT: u64 = 0x5A;
const REG_RIRBCTL: u64 = 0x5C;
/// RIRBSTS — Response Interrupt Status (§3.3.37). Byte at 0x5D.
/// Bits are write-1-to-clear; clearing deasserts the controller's
/// RIRB IRQ source (CIS in INTSTS).
const REG_RIRBSTS: u64 = 0x5D;
#[allow(dead_code)]
const REG_RIRBSIZE: u64 = 0x5E;

// GCTL bits.
const GCTL_CRST: u32 = 1 << 0; // controller reset (1 = leave reset)
#[allow(dead_code)]
const GCTL_FCNTRL: u32 = 1 << 1; // flush control
const GCTL_UNSOL: u32 = 1 << 8; // accept unsolicited responses

// CORBCTL bits (§3.3.21).
const CORBCTL_CMEIE: u8 = 1 << 0; // memory-error interrupt enable
const CORBCTL_RUN: u8 = 1 << 1; // CORBRUN — start DMA engine

// RIRBCTL bits (§3.3.36).
const RIRBCTL_RINTCTL: u8 = 1 << 0; // response interrupt enable
const RIRBCTL_RUN: u8 = 1 << 1; // RIRBDMAEN
const RIRBCTL_OIC: u8 = 1 << 2; // overrun interrupt enable

// RIRBSTS bits (§3.3.37) — write-1-to-clear.
const RIRBSTS_RIRBOIS: u8 = 1 << 2; // response overrun interrupt status

// CORBSIZE / RIRBSIZE: bits[1:0] select size, bits[7:4] are SZCAP.
// Encoding: 0=2 entries (8 B), 1=16 entries (64 B), 2=256 entries
// (1024 B for CORB / 2048 B for RIRB).
const CORBSIZE_256: u8 = 2;
const RIRBSIZE_256: u8 = 2;

// INTCTL bits (§3.3.14).
#[allow(dead_code)]
const INTCTL_SIE_MASK: u32 = 0x3FFF_FFFF; // per-stream IRQ enables (bits 0..29)
const INTCTL_CIE: u32 = 1 << 30; // controller IRQ enable (RIRB + STATESTS)
const INTCTL_GIE: u32 = 1 << 31; // global IRQ enable

// INTSTS bits (§3.3.13) — read-only summary; clear underlying source.
#[allow(dead_code)]
const INTSTS_GIS: u32 = 1 << 31; // global IRQ status (any source)

// CORB / RIRB sizing: at least 256 entries by spec (§3.3.24, §3.3.31).
// CORB entries are 4 B → 1024 B ring. RIRB entries are 8 B → 2048 B.
const CORB_ENTRIES: usize = 256;
#[allow(dead_code)]
const RIRB_ENTRIES: usize = 256;
#[allow(dead_code)]
const CORB_BYTES: usize = CORB_ENTRIES * 4; // 1024
#[allow(dead_code)]
const RIRB_BYTES: usize = RIRB_ENTRIES * 8; // 2048

// ── Codec verbs (HDA 1.0a §7.3) ────────────────────────────────────

/// Get Parameter (verb 0xF00). Parameter is in low 8 bits of payload.
const VERB_GET_PARAMETER: u32 = 0xF00 << 8;

// Parameter ids (§7.3.4).
#[allow(dead_code)]
const PARAM_AUDIO_GROUP_CAPS: u8 = 0x08;

// Widget types (HDA §7.3.4.6 Audio Widget Capabilities, bits 20..23).
pub const WIDGET_TYPE_AUDIO_OUTPUT: u8 = 0x0;
pub const WIDGET_TYPE_PIN_COMPLEX: u8 = 0x4;

// Other useful verbs (§7.3.3).
/// Set Converter Format. Payload: 16-bit format word (matches SD_FMT).
const VERB_SET_CONVERTER_FORMAT: u32 = 0x2 << 16;
/// Set Converter Stream/Channel. Payload bits: stream tag (4..7),
/// channel (0..3).
const VERB_SET_CONVERTER_STREAM: u32 = 0x706 << 8;
/// Set Pin Widget Control. Payload bit 6 (out-enable), bit 7 (HP-amp).
const VERB_SET_PIN_WIDGET_CONTROL: u32 = 0x707 << 8;
/// Set Amp Gain/Mute. Payload encodes output(15)/input(14)/L(13)/R(12)
/// + index (8..11) + mute (7) + gain (0..6).
const VERB_SET_AMP_GAIN_MUTE: u32 = 0x3 << 16;

/// Encode a 32-bit codec command word: CAd (4) | NID (8) | Verb+Payload (20).
#[inline]
const fn make_verb(cad: u8, nid: u8, verb: u32) -> u32 {
    ((cad as u32) << 28) | ((nid as u32) << 20) | (verb & 0x000F_FFFF)
}

// ── Stream descriptor regs ─────────────────────────────────────────

/// Compute SDnCTL register offset for stream descriptor `idx`. Per
/// §3.3.35, descriptor 0 is at 0x80; each subsequent descriptor is
/// 0x20 bytes further.
#[inline]
const fn sd_base(idx: u8) -> u64 {
    0x80 + (idx as u64) * 0x20
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const SD_STS: u64 = 0x03;
const SD_LPIB: u64 = 0x04;
const SD_CBL: u64 = 0x08; // cyclic buffer length, 32-bit
const SD_LVI: u64 = 0x0C; // last valid index, 16-bit
#[allow(dead_code)]
const SD_FIFOS: u64 = 0x10;
const SD_FMT: u64 = 0x12; // format, 16-bit
const SD_BDPL: u64 = 0x18; // BDL phys, low 32
const SD_BDPU: u64 = 0x1C; // BDL phys, high 32

// SDnCTL bits (low 24).
const SDCTL_RUN: u32 = 1 << 1;
#[allow(dead_code)]
const SDCTL_IOCE: u32 = 1 << 2; // interrupt on completion enable

// SDnSTS bits (§3.3.36) — write-1-clear. We poll BCIS to observe a
// completed Buffer-Completion-Interrupt-on-Sync round.
#[allow(dead_code)]
const SDSTS_BCIS: u8 = 1 << 2;
#[allow(dead_code)]
const SDSTS_FIFOE: u8 = 1 << 3;
#[allow(dead_code)]
const SDSTS_DESE: u8 = 1 << 4;

// ── Driver state ───────────────────────────────────────────────────

/// Per-codec identity, revision and first audio function group.
/// Full widget topology is maintained by the controller's codec graph.
#[derive(Copy, Clone, Debug, Default)]
pub struct CodecInfo {
    pub addr: u8,
    pub vendor_id: u32,
    pub revision_id: u32,
    pub afg_node_id: Option<u8>,
}

const HDA_PCI_IDS: &[(&str, u16, u16)] = &[
    // AMD — Family-19h Phoenix HD Audio + Radeon HD Audio iGPU.
    (
        "hda-amd-phoenix",
        HDA_AMD_PHOENIX_VENDOR,
        HDA_AMD_PHOENIX_DEVICE,
    ),
    (
        "hda-amd-radeon",
        HDA_AMD_RADEON_VENDOR,
        HDA_AMD_RADEON_DEVICE,
    ),
    // Intel legacy ICH HD Audio.
    (
        "hda-intel-ich6",
        HDA_INTEL_ICH6_VENDOR,
        HDA_INTEL_ICH6_DEVICE,
    ),
    (
        "hda-intel-ich7",
        HDA_INTEL_ICH7_VENDOR,
        HDA_INTEL_ICH7_DEVICE,
    ),
    (
        "hda-intel-ich9",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ICH9_DEVICE,
    ),
    // Intel PCH HDA (Skylake → Meteor Lake).
    (
        "hda-intel-sunrise-point-lp",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_SUNRISE_POINT_LP_DEVICE,
    ),
    (
        "hda-intel-sunrise-point-lp-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_SUNRISE_POINT_LP_DEVICE_B,
    ),
    (
        "hda-intel-cannon-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_CANNON_LAKE_DEVICE,
    ),
    (
        "hda-intel-comet-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_COMET_LAKE_DEVICE,
    ),
    (
        "hda-intel-comet-lake-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_COMET_LAKE_DEVICE_B,
    ),
    (
        "hda-intel-tiger-lake-lp",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_LP_DEVICE,
    ),
    (
        "hda-intel-tiger-lake-lp-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_LP_DEVICE_B,
    ),
    (
        "hda-intel-alder-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ALDER_LAKE_DEVICE,
    ),
    (
        "hda-intel-alder-lake-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ALDER_LAKE_DEVICE_B,
    ),
    (
        "hda-intel-alder-lake-c",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ALDER_LAKE_DEVICE_C,
    ),
    (
        "hda-intel-meteor-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_METEOR_LAKE_DEVICE,
    ),
    (
        "hda-intel-arrow-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ARROW_LAKE_DEVICE,
    ),
    (
        "hda-intel-arrow-lake-s",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ARROW_LAKE_S_DEVICE,
    ),
    (
        "hda-intel-lunar-lake-p",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_LUNAR_LAKE_P_DEVICE,
    ),
    (
        "hda-intel-panther-lake-h",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_PANTHER_LAKE_H_DEVICE,
    ),
    (
        "hda-intel-panther-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_PANTHER_LAKE_DEVICE,
    ),
    // Intel iGPU display-audio (TGL / TGL-LP graphics function).
    (
        "hda-intel-tgl-gfx",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_GFX_DEVICE,
    ),
    (
        "hda-intel-tgl-gfx-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_GFX_DEVICE_B,
    ),
    (
        "hda-intel-tgl-gfx-c",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_GFX_DEVICE_C,
    ),
    (
        "hda-intel-tgl-gfx-d",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_GFX_DEVICE_D,
    ),
];

/// Register every supported HDA controller PCI id with the bus match
/// table. Every entry binds the same `probe` function — the HDA
/// programming model is vendor-agnostic.
pub fn register_pci_driver() {
    for &(name, vendor, device) in HDA_PCI_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,
        });
    }
}

extern crate alloc;
