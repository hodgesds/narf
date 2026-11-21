//! Native HDA controllers and PCM. Register definitions follow the HDA spec;
//! sequencing and AMD quirks follow /usr/src/linux/sound/hda/{core,controllers}.

mod hdmi;
pub mod quirks;
mod routing;
mod runtime;
mod stream;
pub use runtime::*;
pub use stream::play_buffer;

pub use crate::ids::*;

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
/// `AC_VERB_SET_UNSOLICITED_ENABLE` with `AC_USRSP_EN`; the tag goes in bits 5:0.
const VERB_SET_UNSOLICITED_ENABLE: u32 = (0x708 << 8) | 0x80;
/// `AC_PINCAP_PRES_DETECT`.
const PINCAP_PRES_DETECT: u32 = 1 << 2;
/// `AC_DEFCFG_MISC_NO_PRESENCE` (pin config Misc bit 0).
const DEFCFG_MISC_NO_PRESENCE: u8 = 1;
/// `AZX_RIRB_EX_UNSOL_EV`: the response is unsolicited.
const RIRB_EX_UNSOL: u32 = 1 << 4;
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
    /// Codec subsystem ID (`subvendor << 16 | subdevice`, HDA
    /// §7.3.3.2 verb 0xF01 on the root node) read at probe (#776).
    /// `None` when the codec reports 0 or the read fails — unknown
    /// subsystems fail open to generic behavior, never a quirk.
    pub subsystem_id: Option<u32>,
}

/// Whether this controller needs explicit cache maintenance (Linux's
/// `AZX_DCAPS_SNOOP_OFF` for the ATI HDMI NS preset).
pub fn ati_hdmi_noncoherent(vendor: u16, device: u16) -> bool {
    vendor == HDA_AMD_RADEON_VENDOR && HDA_ATI_HDMI_NS_DEVICES.contains(&device)
}

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
    for &device in HDA_ATI_HDMI_NS_DEVICES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "hda-ati-hdmi",
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: HDA_AMD_RADEON_VENDOR,
                device,
            },
            probe,
        });
    }
}

extern crate alloc;

#[cfg(feature = "kernel-test")]
mod renoir_bind_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The Renoir APU audio function (1002:1637) binds through the ATI
    /// HDMI NS table: the table membership is what registers the PCI
    /// match, and the predicate is what the probe feeds the runtime's
    /// non-coherent DMA setup — both halves of the bind are pinned.
    /// (Lives in this module, not `hda_tests`, so the pin survives
    /// alongside the tables it checks.)
    fn native_hda_renoir_function_binds_ns() -> TestResult {
        if !HDA_ATI_HDMI_NS_DEVICES.contains(&HDA_AMD_RENOIR_HDMI_DEVICE) {
            return TestResult::Fail("Renoir 1002:1637 missing from ATI HDMI NS table");
        }
        if !ati_hdmi_noncoherent(HDA_AMD_RADEON_VENDOR, HDA_AMD_RENOIR_HDMI_DEVICE) {
            return TestResult::Fail("Renoir function must get the no-snoop treatment");
        }
        // The vendor gate matters: the same device id under another
        // vendor is not an ATI HDMI function.
        if ati_hdmi_noncoherent(0x8086, HDA_AMD_RENOIR_HDMI_DEVICE) {
            return TestResult::Fail("noncoherent predicate must be vendor-gated");
        }
        // The Phoenix APU function (1002:1640) deliberately stays on
        // the named coherent path — it must not drift into the NS set.
        if ati_hdmi_noncoherent(HDA_AMD_RADEON_VENDOR, 0x1640) {
            return TestResult::Fail("Phoenix 1002:1640 must stay off the NS path");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/hda", native_hda_renoir_function_binds_ns);
}
