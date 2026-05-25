//! Intel HDA (High Definition Audio) controller driver — clean-room.
//!
//! Targets the AMD Ryzen HD Audio Controller (`1022:15e3`) and the
//! Radeon HD Audio Controller (`1002:1640`) on integrated GPUs, both
//! of which expose the standard Intel HDA programming model.
//!
//! Reference: **Intel "High Definition Audio Specification" rev 1.0a**
//! (<https://www.intel.com/content/www/us/en/standards/intel-high-definition-audio-specification.html>).
//! Section numbers in comments below refer to that document. Codec
//! verb encodings come from the same spec (§7.3) and the codec
//! vendor's datasheet.
//!
//! Spec sections used for IRQ wiring:
//! - §3.3.13 INTSTS — global / controller / per-stream IRQ summary.
//!   Bits are RO; clear underlying source registers to deassert.
//! - §3.3.14 INTCTL — GIE (bit 31), CIE (bit 30), SIE per-stream.
//! - §3.3.21 CORBCTL — CMEIE (bit 0), CORBRUN (bit 1).
//! - §3.3.36 RIRBCTL — RINTCTL (bit 0), RIRBDMAEN (bit 1),
//!   RIRBOIC (bit 2).
//! - §3.3.37 RIRBSTS — RINTFL (bit 0), RIRBOIS (bit 2). W1C.
//!
//! Live surface: bring the controller out of reset, allocate CORB +
//! RIRB rings, walk STATESTS for live codec slots, fetch each
//! codec's vendor / sub-system / function-group descriptor via Get
//! Parameter verbs, pick one output stream descriptor, allocate a
//! BDL + a 4-KiB cyclic period buffer, and program the stream for
//! 48 kHz / 16-bit / 2-ch. `start_output` / `stop_output` set
//! SDnCTL.RUN so loaded samples reach the analog output, and
//! `load_period` / `load_sine_test_tone` populate the cyclic buffer.
//!
//! # Layout
//!
//! ```text
//! BAR0 (memory-mapped, identity-mapped through narf-arch::mmio):
//!   0x00..0x80    global regs (GCAP, GCTL, INTCTL, CORB, RIRB, ...)
//!   0x80..        stream descriptor block, 0x20 bytes per stream
//!     SDnCTL  +0x00 (24-bit), SDnSTS +0x03,
//!     SDnLPIB +0x04, SDnCBL +0x08, SDnLVI +0x0C,
//!     SDnFIFOS +0x10, SDnFMT +0x12,
//!     SDnBDPL +0x18, SDnBDPU +0x1C
//! ```
//!
//! Each input / output stream descriptor is 0x20 bytes; the spec's
//! GCAP NISS / NOSS / NBSS counts say how many of each the
//! controller exposes. Output streams start at `0x80 + 0x20 *
//! GCAP.iss`.

use core::sync::atomic::{compiler_fence, AtomicU64, Ordering};

use narf_bus::{bar, enable_msix, BusDevice, BusDeviceCap, MsixTable};
#[cfg(target_arch = "x86_64")]
use narf_bus::BusKind;
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

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
/// INTSTS — controller IRQ summary (§3.3.13). 32-bit at 0x24, RO.
const REG_INTSTS: u64 = 0x24;

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
const RIRBSTS_RINTFL: u8 = 1 << 0; // response interrupt flag
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
const INTSTS_CIS: u32 = 1 << 30; // controller IRQ status (RIRB / wake)

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
const PARAM_VENDOR_ID: u8 = 0x00;
const PARAM_REVISION_ID: u8 = 0x02;
const PARAM_SUBORDINATE_NODE: u8 = 0x04;
const PARAM_FUNCTION_GROUP: u8 = 0x05;
#[allow(dead_code)]
const PARAM_AUDIO_GROUP_CAPS: u8 = 0x08;
/// Audio Widget Capabilities (§7.3.4.6). Bits 20..23 = widget type.
const PARAM_AUDIO_WIDGET_CAPS: u8 = 0x09;
/// Pin Capabilities (§7.3.4.9). Bit 4 = output capable.
const PARAM_PIN_CAPS: u8 = 0x0C;
/// Connection List Length (§7.3.4.11).
const PARAM_CONN_LIST_LEN: u8 = 0x0E;

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
/// Get Configuration Default (§7.3.3.31).
const VERB_GET_CONFIG_DEFAULT: u32 = 0xF1C << 8;
/// Get Connection List Entry (§7.3.3.2). Payload bits 0..7 = list index.
const VERB_GET_CONNECTION_LIST_ENTRY: u32 = 0xF02 << 8;

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

const SD_CTL: u64 = 0x00; // 24-bit
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
const SDCTL_SRST: u32 = 1 << 0;
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
const SDCTL_STREAM_TAG_SHIFT: u32 = 20; // bits 20..23

// Format encoding (§3.7.1).
//   bit15 = (rsvd 0)
//   bits[14:11] BASE 0=48k, 1=44.1k base
//   bits[10:8]  MULT (1×, 2×, ...)
//   bits[7:4]   DIV
//   bits[6:4]   BITS (0=8, 1=16, 2=20, 3=24, 4=32)
//   bits[3:0]   CHAN (chan_count - 1)
//
// 48 kHz / 16-bit / 2-ch:
//   BASE=0, MULT=000 (1×), DIV=000 (÷1), BITS=001 (16-bit), CHAN=0001
const FMT_48K_S16_STEREO: u16 = (0b0_0000_000 << 8) // base 48k, mult 1×, div 1
    | (0b001 << 4)       // 16-bit
    | 0b0001; // 2 channels (chan_count - 1 == 1)

// ── Driver state ───────────────────────────────────────────────────

/// Per-codec discovery snapshot. Stage-4: vendor/device id +
/// subsystem id + first audio function group node id. Verb space
/// walk lands when codec parsing grows beyond enumeration.
#[derive(Copy, Clone, Debug, Default)]
pub struct CodecInfo {
    pub addr: u8,
    pub vendor_id: u32,
    pub revision_id: u32,
    pub afg_node_id: Option<u8>,
}

/// Probed live HDA controller.
pub struct IntelHda {
    /// BAR0 memory window.
    bar0: bar::MmioRegion,
    /// CORB DMA buffer (1 KiB ring, page-aligned).
    _corb: DmaBuffer,
    /// RIRB DMA buffer (2 KiB ring, page-aligned).
    _rirb: DmaBuffer,
    corb_phys: u64,
    rirb_phys: u64,
    /// Software write pointer for CORB (mirrors CORBWP).
    corb_wp: IrqSafeSpinLock<u16>,
    /// Software read pointer for RIRB (chases RIRBWP).
    rirb_rp: IrqSafeSpinLock<u16>,

    /// GCAP-derived counts.
    n_iss: u8, // input streams
    n_oss: u8, // output streams
    n_bss: u8, // bidirectional streams

    /// Live codec slots discovered via STATESTS.
    codecs: [CodecInfo; 16],
    n_codecs: u8,

    /// Stream descriptor we picked for the playback stream.
    out_stream_idx: u8,
    /// BDL backing for that stream (one entry, one 4 KiB silence period).
    _bdl: DmaBuffer,
    /// Audio period buffer — initialised to zero (silence) at bring-up.
    /// `load_period` writes samples here so the engine plays them on
    /// the next cycle.
    period: DmaBuffer,

    /// IDT vector wired to this controller's IRQ source — MSI-X
    /// table entry 0 when MSI-X negotiation succeeds, otherwise the
    /// GSI routed via PCI _PRT + IOAPIC. `None` only when both
    /// negotiation paths fail (driver then falls back to polled
    /// `send_verb` callers, which still work).
    pub irq_vector: Option<u8>,

    /// MSI-X table handle owned by this controller. `Some` when
    /// `bring_up` successfully programmed table entry 0; `None`
    /// for the legacy INTx fallback. Held for ownership / lifetime
    /// — the IRQ delivery path doesn't poke the table after init.
    #[allow(dead_code)]
    msix: Option<MsixTable>,

    pub ready: bool,
}

/// BAR0 physical base for the bound HDA controller, set in `bring_up`
/// and read by the sync ISR. Stored as a raw `u64` so the IRQ handler
/// can clear RIRBSTS without going through the `IrqSafeSpinLock`
/// guarding the controller (which a CORB submitter may be holding).
///
/// Zero means "no controller bound yet" — the ISR returns early.
static HDA_BAR0_PHYS: AtomicU64 = AtomicU64::new(0);

/// Sync IRQ handler — runs in IRQ context. Reads INTSTS to confirm
/// our line, then clears RIRBSTS bits W1C so the level-triggered INTx
/// line deasserts (HDA spec §3.3.13: INTSTS is RO, deassert by
/// clearing the source register; §3.3.37: RIRBSTS is W1C). The
/// awaiting task drains the RIRB ring itself — keeping this handler
/// minimal lets it coexist with `IrqSafeSpinLock`-protected senders.
fn hda_isr() {
    let base = HDA_BAR0_PHYS.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    // SAFETY: `base` was set from a live, identity-mapped BAR0
    // mapping that lives as long as the controller. We only touch
    // INTSTS (RO) and RIRBSTS (W1C byte) — both fixed offsets within
    // the spec-mandated 0x80-byte global register window.
    unsafe {
        let intsts = narf_arch::mmio::read32(base + REG_INTSTS);
        if intsts & INTSTS_CIS != 0 {
            // RIRB is the only CIS source we currently enable
            // (CMEIE in CORBCTL also routes to CIS when triggered).
            // Clear both RINTFL + RIRBOIS in one byte W1C write.
            narf_arch::mmio::write8(base + REG_RIRBSTS, RIRBSTS_RINTFL | RIRBSTS_RIRBOIS);
        }
    }
}

impl core::fmt::Debug for IntelHda {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelHda")
            .field("ready", &self.ready)
            .field("n_iss", &self.n_iss)
            .field("n_oss", &self.n_oss)
            .field("n_bss", &self.n_bss)
            .field("n_codecs", &self.n_codecs)
            .field("out_stream_idx", &self.out_stream_idx)
            .finish_non_exhaustive()
    }
}

/// Bring-up / runtime errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdaError {
    BarMapFailed,
    ResetTimeout,
    NoCodecs,
    NoOutputStream,
    DmaAllocFailed,
    CommandTimeout,
    /// `narf-firmware` had no entry for the requested codec patch.
    FirmwareMissing,
    /// Patch payload size isn't a multiple of 4 (one u32 verb per
    /// 4-byte word).
    FirmwarePatchMalformed,
}

impl IntelHda {
    /// Bring the controller out of reset, install CORB / RIRB rings,
    /// walk STATESTS, and pick one output stream.
    ///
    /// # Safety
    /// Caller owns the device's BAR window exclusively for the
    /// duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, HdaError> {
        // 1. Map BAR0 — the HDA register window.
        // SAFETY: caller-asserted exclusive ownership.
        let bar0 = unsafe { bar::map_bar(device, 0) }.map_err(|_| HdaError::BarMapFailed)?;

        // 2. Reset (§4.2.2): clear GCTL.CRST, poll until CRST reads
        //    0, set CRST again, poll until CRST reads 1.
        // SAFETY: BAR0 mapped, identity-mapped MMIO.
        unsafe {
            let g = bar0.read32(REG_GCTL);
            bar0.write32(REG_GCTL, g & !GCTL_CRST);
        }
        // Wait for reset to take effect. responsive_spin_until
        // ticks sleep_pumps so cursor/FB stay alive across the
        // deassert. 10 ms wedge threshold (HDA §4.2.2: CRST clears
        // in <1 ms on healthy controllers).
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { bar0.read32(REG_GCTL) } & GCTL_CRST == 0,
            narf_time::Deadline::after_ms(10),
        );
        // SAFETY: same.
        unsafe {
            bar0.write32(REG_GCTL, GCTL_CRST | GCTL_UNSOL);
        }
        // responsive_spin_until keeps cursor/FB alive while the
        // controller comes out of reset. 50 ms wedge threshold.
        let crst_ok = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { bar0.read32(REG_GCTL) } & GCTL_CRST != 0,
            narf_time::Deadline::after_ms(50),
        );
        if !crst_ok {
            return Err(HdaError::ResetTimeout);
        }

        // §4.3: after CRST, hardware must hold off codec enumeration
        // for at least 521 µs. We don't have a sub-ms time source on
        // every arch, so spin for ~30 000 cycles which dominates that
        // window on every realistic clock.
        for _ in 0..30_000 {
            core::hint::spin_loop();
        }

        // 3. Read GCAP (§3.3.1) to learn stream counts.
        // SAFETY: BAR0 mapped.
        let gcap = unsafe { bar0.read16(REG_GCAP) };
        // GCAP layout: NSDO[15:14] | NSS[14:11 wait — re-check spec]
        // Actual per HDA 1.0a §3.3.1:
        //   bit0      = OK64BIT
        //   bits3:1   = NSDO (serial-data-out signals, 0=1, 1=2, 2=4)
        //   bits7:4   = BSS  (bidirectional streams)
        //   bits11:8  = ISS  (input streams)
        //   bits15:12 = OSS  (output streams)
        let n_oss = ((gcap >> 12) & 0xF) as u8;
        let n_iss = ((gcap >> 8) & 0xF) as u8;
        let n_bss = ((gcap >> 4) & 0xF) as u8;

        // 4. Allocate CORB + RIRB DMA buffers. alloc_coherent
        //    returns ZEROED frames per the io/ contract; we don't
        //    re-zero. Each ring is a single 4 KiB page (CORB needs
        //    1 KiB, RIRB needs 2 KiB; pages are abundant).
        let corb =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| HdaError::DmaAllocFailed)?;
        let rirb =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| HdaError::DmaAllocFailed)?;
        let corb_phys = corb.phys_addr().raw();
        let rirb_phys = rirb.phys_addr().raw();
        // Spec mandates 128-byte alignment for both (§3.3.18,
        // §3.3.25); 4 KiB pages trivially satisfy that.
        debug_assert_eq!(corb_phys & 0x7F, 0);
        debug_assert_eq!(rirb_phys & 0x7F, 0);

        // 5. Stop CORB / RIRB DMA before reprogramming addresses.
        // SAFETY: BAR0 mapped.
        unsafe {
            bar0.write32(
                REG_CORBCTL as u64 & !0x3, // word-aligned write below
                bar0.read32(REG_CORBCTL & !0x3),
            ); // no-op; placeholder for clarity
        }
        // The above pattern is weird — we want byte writes to
        // CORBCTL/RIRBCTL. Use the 32-bit window at 0x4C: the layout
        // packs CORBCTL @ 0x4C, CORBSTS @ 0x4D, [reserved] @ 0x4E,
        // CORBSIZE @ 0x4E. Easier path: read 32-bit, mask, write 32-bit.
        // SAFETY: BAR0 mapped.
        unsafe {
            // Stop the engines (clear CORBCTL.RUN and RIRBCTL.RUN).
            // Read-modify-write the 32-bit windows that contain them.
            let corb_blk = bar0.read32(REG_CORBCTL & !0x3);
            // CORBCTL is byte at 0x4C (bits 0..7 of the 0x4C dword).
            bar0.write32(REG_CORBCTL & !0x3, corb_blk & !0xFF);
            let rirb_blk = bar0.read32(REG_RIRBCTL & !0x3);
            // RIRBCTL is byte at 0x5C (bits 0..7 of the 0x5C dword).
            bar0.write32(REG_RIRBCTL & !0x3, rirb_blk & !0xFF);
        }

        // 6. Program CORB / RIRB base addresses.
        // SAFETY: BAR0 mapped.
        unsafe {
            bar0.write32(REG_CORBLBASE, (corb_phys & 0xFFFF_FFFF) as u32);
            bar0.write32(REG_CORBUBASE, (corb_phys >> 32) as u32);
            bar0.write32(REG_RIRBLBASE, (rirb_phys & 0xFFFF_FFFF) as u32);
            bar0.write32(REG_RIRBUBASE, (rirb_phys >> 32) as u32);
        }

        // 7. Set CORBSIZE / RIRBSIZE = 256-entry ring (§3.3.24,
        //    §3.3.34). The size field is the low 2 bits of an 8-bit
        //    register; SZCAP in the upper nibble must advertise
        //    support — every modern controller advertises 256-entry.
        // SAFETY: BAR0 mapped.
        unsafe {
            // CORBSIZE @ 0x4E (byte). The 0x4C dword holds:
            //   [7:0]   CORBCTL
            //   [15:8]  CORBSTS
            //   [23:16] reserved
            //   [31:24] CORBSIZE
            let blk = bar0.read32(REG_CORBCTL & !0x3);
            let with_size = (blk & 0x00FF_FFFF) | ((CORBSIZE_256 as u32) << 24);
            bar0.write32(REG_CORBCTL & !0x3, with_size);
            // RIRBSIZE @ 0x5E (byte) — same layout in the 0x5C dword.
            let blk = bar0.read32(REG_RIRBCTL & !0x3);
            let with_size = (blk & 0x00FF_FFFF) | ((RIRBSIZE_256 as u32) << 24);
            bar0.write32(REG_RIRBCTL & !0x3, with_size);
        }

        // 8. Reset CORB read pointer (§3.3.21): write CORBRPRST=1 to
        //    bit15 of CORBRP, poll until reads back as 1, write 0,
        //    poll until reads back as 0.
        // SAFETY: BAR0 mapped.
        unsafe {
            bar0.write16(REG_CORBRP, 1 << 15);
        }
        // responsive_spin_until ticks sleep_pumps across the
        // read-pointer reset handshake. 10 ms wedge threshold
        // (CORBRPRST handshake completes in microseconds on
        // healthy controllers).
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { bar0.read16(REG_CORBRP) } & (1 << 15) != 0,
            narf_time::Deadline::after_ms(10),
        );
        // SAFETY: same.
        unsafe {
            bar0.write16(REG_CORBRP, 0);
        }
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { bar0.read16(REG_CORBRP) } & (1 << 15) == 0,
            narf_time::Deadline::after_ms(10),
        );
        // CORBWP starts at 0; software writes the *next* slot's
        // index, hardware advances CORBRP to it.
        // SAFETY: same.
        unsafe {
            bar0.write16(REG_CORBWP, 0);
        }

        // 9. Reset RIRB write pointer (§3.3.30): bit15 of RIRBWP is
        //    a write-1-to-clear self-resetting bit.
        // SAFETY: BAR0 mapped.
        unsafe {
            bar0.write16(REG_RIRBWP, 1 << 15);
        }

        // 10. RINTCNT: response interrupt count. Stage-4 uses polling
        //    so the value is informational; set to 1 so that *if* we
        //    later enable RINTCTL, the controller IRQs after every
        //    response.
        // SAFETY: BAR0 mapped.
        unsafe {
            bar0.write16(REG_RINTCNT, 1);
        }

        // 11. Start the DMA engines: CORBCTL.RUN + CMEIE +
        //     RIRBCTL.RUN + RINTCTL + OIC. RINTCTL (§3.3.36 bit 0)
        //     turns RIRB-completion delivery on; the controller
        //     latches RINTFL after each `RINTCNT` responses
        //     (§3.3.32 — we set RINTCNT=1 above so every response
        //     fires). The IRQ side is gated globally further down
        //     by INTCTL.GIE | INTCTL.CIE.
        // SAFETY: BAR0 mapped.
        unsafe {
            let blk = bar0.read32(REG_CORBCTL & !0x3);
            bar0.write32(
                REG_CORBCTL & !0x3,
                (blk & 0xFFFF_FF00) | (CORBCTL_RUN | CORBCTL_CMEIE) as u32,
            );
            let blk = bar0.read32(REG_RIRBCTL & !0x3);
            bar0.write32(
                REG_RIRBCTL & !0x3,
                (blk & 0xFFFF_FF00)
                    | (RIRBCTL_RUN | RIRBCTL_RINTCTL | RIRBCTL_OIC) as u32,
            );
        }

        // 12. Discover live codecs from STATESTS (§3.3.9). Each set
        //     bit 0..14 represents a codec at that codec address.
        // SAFETY: BAR0 mapped.
        let statests = unsafe { bar0.read16(REG_STATESTS) };
        // Clear it (write-1-to-clear).
        // SAFETY: same.
        unsafe {
            bar0.write16(REG_STATESTS, statests);
        }

        let mut codecs = [CodecInfo::default(); 16];
        let mut n_codecs = 0u8;

        // Build a controller stub so we can issue verbs while still
        // mid-bring-up. We construct the IrqSafeSpinLock pointers
        // up front and reuse them via a closure.
        let corb_wp = IrqSafeSpinLock::new(0u16);
        let rirb_rp = IrqSafeSpinLock::new(0u16);

        for cad in 0..15u8 {
            if statests & (1u16 << cad) == 0 {
                continue;
            }
            // Vendor / device id (param 0x00) — required.
            // SAFETY: BAR0 mapped, ring DMA buffers programmed.
            let vendor = unsafe {
                send_verb_polled(
                    &bar0,
                    corb_phys,
                    rirb_phys,
                    &corb_wp,
                    &rirb_rp,
                    make_verb(cad, 0, VERB_GET_PARAMETER | PARAM_VENDOR_ID as u32),
                )
            }
            .unwrap_or(0);
            if vendor == 0 || vendor == 0xFFFF_FFFF {
                continue;
            }
            // SAFETY: same.
            let revision = unsafe {
                send_verb_polled(
                    &bar0,
                    corb_phys,
                    rirb_phys,
                    &corb_wp,
                    &rirb_rp,
                    make_verb(cad, 0, VERB_GET_PARAMETER | PARAM_REVISION_ID as u32),
                )
            }
            .unwrap_or(0);
            // Sub-node range (param 0x04): low 16 = total node count,
            // high 16 = starting node id of the function group(s).
            // SAFETY: same.
            let sub = unsafe {
                send_verb_polled(
                    &bar0,
                    corb_phys,
                    rirb_phys,
                    &corb_wp,
                    &rirb_rp,
                    make_verb(cad, 0, VERB_GET_PARAMETER | PARAM_SUBORDINATE_NODE as u32),
                )
            }
            .unwrap_or(0);
            let starting = ((sub >> 16) & 0xFF) as u8;
            let total = (sub & 0xFF) as u8;
            // Walk function-group children — find the first AFG (type 0x01).
            let mut afg = None;
            for nid in starting..starting.saturating_add(total) {
                // SAFETY: same.
                let fg = unsafe {
                    send_verb_polled(
                        &bar0,
                        corb_phys,
                        rirb_phys,
                        &corb_wp,
                        &rirb_rp,
                        make_verb(cad, nid, VERB_GET_PARAMETER | PARAM_FUNCTION_GROUP as u32),
                    )
                }
                .unwrap_or(0);
                // Function group type is bits 0..7. 0x01 = AFG, 0x02 = MFG.
                if fg & 0xFF == 0x01 {
                    afg = Some(nid);
                    break;
                }
            }
            codecs[n_codecs as usize] = CodecInfo {
                addr: cad,
                vendor_id: vendor,
                revision_id: revision,
                afg_node_id: afg,
            };
            n_codecs += 1;
        }

        if n_codecs == 0 {
            return Err(HdaError::NoCodecs);
        }
        if n_oss == 0 {
            return Err(HdaError::NoOutputStream);
        }

        // 13. Pick stream descriptor 0 of the output bank (descriptor
        //     index = NISS, since input streams come first per
        //     §3.3.35).
        let out_idx = n_iss;

        // Reset that stream descriptor: SDnCTL.SRST=1, poll for 1,
        // SRST=0, poll for 0 (§3.3.35).
        // SAFETY: BAR0 mapped.
        let sd = sd_base(out_idx);
        unsafe {
            bar0.write32(sd + SD_CTL, SDCTL_SRST);
        }
        // responsive_spin_until ticks sleep_pumps across the
        // per-stream SRST handshake. 10 ms wedge threshold (HDA
        // §3.3.35: SRST settles in microseconds on healthy
        // controllers).
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { bar0.read32(sd + SD_CTL) } & SDCTL_SRST != 0,
            narf_time::Deadline::after_ms(10),
        );
        // SAFETY: same.
        unsafe {
            bar0.write32(sd + SD_CTL, 0);
        }
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { bar0.read32(sd + SD_CTL) } & SDCTL_SRST == 0,
            narf_time::Deadline::after_ms(10),
        );

        // 14. Allocate BDL (must be 128-byte aligned, §3.6.2; a 4 KiB
        //     page satisfies that) + a single 4 KiB silence period.
        let bdl = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| HdaError::DmaAllocFailed)?;
        let silence =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| HdaError::DmaAllocFailed)?;
        let bdl_phys = bdl.phys_addr().raw();
        let silence_phys = silence.phys_addr().raw();

        // BDL entry layout (§3.6.2): 16 B = (u64 addr, u32 len, u32 ioc).
        // Write entry 0 pointing at the silence buffer; entry 1 is a
        // mirror so LVI=1 produces a 2-period wraparound (the
        // controller refuses LVI < 1).
        // SAFETY: identity-mapped DMA, 4 KiB page.
        unsafe {
            let p = bdl_phys as *mut u32;
            // entry 0
            p.add(0).write_volatile((silence_phys & 0xFFFF_FFFF) as u32);
            p.add(1).write_volatile((silence_phys >> 32) as u32);
            p.add(2).write_volatile(4096);
            p.add(3).write_volatile(0); // no IOC
                                        // entry 1 — same buffer, makes the engine valid even
                                        // though we won't run it.
            p.add(4).write_volatile((silence_phys & 0xFFFF_FFFF) as u32);
            p.add(5).write_volatile((silence_phys >> 32) as u32);
            p.add(6).write_volatile(4096);
            p.add(7).write_volatile(0);
        }

        // 15. Program stream descriptor.
        // SAFETY: BAR0 mapped.
        unsafe {
            // Cyclic Buffer Length: total bytes the engine sees as
            // one wraparound = 2 × 4 KiB.
            bar0.write32(sd + SD_CBL, (4096 * 2) as u32);
            // Last Valid Index: 1 (entries 0..1, inclusive).
            bar0.write16(sd + SD_LVI, 1);
            // Format: 48 kHz / 16-bit / 2-ch.
            bar0.write16(sd + SD_FMT, FMT_48K_S16_STEREO);
            // BDL physical pointer.
            bar0.write32(sd + SD_BDPL, (bdl_phys & 0xFFFF_FFFF) as u32);
            bar0.write32(sd + SD_BDPU, (bdl_phys >> 32) as u32);
            // SDnCTL: stream tag = 1 (tag 0 is reserved per §3.3.35).
            // RUN bit deliberately NOT set — Stage-4 stops here.
            bar0.write32(sd + SD_CTL, 1u32 << SDCTL_STREAM_TAG_SHIFT);
        }

        // 16. Wire the controller-summary IRQ. Try MSI-X (HDA spec
        //     §6.2.5 — controllers expose MSI-X cap with at least
        //     one vector); fall back to legacy INTx via PCI _PRT.
        //     Per HDA spec §3.3.13/§3.3.14, the global IRQ enable
        //     (INTCTL.GIE) and controller-class enable (INTCTL.CIE)
        //     gate RIRB delivery once RINTCTL is on.
        //
        // Publish BAR0 phys for the sync ISR *before* any path that
        // unmasks the line. The ISR returns early on a zero base,
        // but once a route is live the next IRQ must find a valid
        // base to W1C RIRBSTS (otherwise INTx storms).
        HDA_BAR0_PHYS.store(bar0.phys.raw(), Ordering::Release);

        // Clear any latched RIRBSTS state from bring-up so the first
        // armed IRQ reflects only fresh activity.
        // SAFETY: BAR0 mapped, byte W1C at fixed spec offset.
        unsafe {
            bar0.write8(REG_RIRBSTS, RIRBSTS_RINTFL | RIRBSTS_RIRBOIS);
        }

        let (msix, irq_vector) = match Self::try_enable_msix(cap, device) {
            Ok((tbl, v)) => (Some(tbl), Some(v)),
            Err(_) => match Self::try_install_intx(cap, device) {
                Some(v) => (None, Some(v)),
                None => (None, None),
            },
        };

        if irq_vector.is_some() {
            // Arm INTCTL last: GIE | CIE. SIE bits stay 0 (no
            // playback stream subscribed yet). SAFETY: BAR0 mapped.
            unsafe {
                bar0.write32(REG_INTCTL, INTCTL_GIE | INTCTL_CIE);
            }
        }

        Ok(Self {
            bar0,
            _corb: corb,
            _rirb: rirb,
            corb_phys,
            rirb_phys,
            corb_wp,
            rirb_rp,
            n_iss,
            n_oss,
            n_bss,
            codecs,
            n_codecs,
            out_stream_idx: out_idx,
            _bdl: bdl,
            period: silence,
            irq_vector,
            msix,
            ready: true,
        })
    }

    /// Walk the controller's MSI-X capability, allocate an IDT
    /// vector + table slot, program slot 0 to deliver to BSP, and
    /// flip the global MSI-X enable. Returns `(table, vector)` on
    /// success. Failure propagates to the bring-up path which falls
    /// back to INTx via `try_install_intx`. Mirrors xhci's identical
    /// negotiation (drivers/usb/src/xhci.rs::try_enable_msix).
    fn try_enable_msix(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(MsixTable, u8), HdaError> {
        let mut msix = enable_msix(cap, device).map_err(|_| HdaError::DmaAllocFailed)?;
        let v = narf_interrupts::vector::alloc().map_err(|_| HdaError::DmaAllocFailed)?;
        let _ = msix.alloc_vector().ok_or(HdaError::DmaAllocFailed)?;
        // Install our handler before any path that can fire `v` —
        // MSI-X is edge-triggered so a missed handler wouldn't
        // storm, but the dispatch table must exist before the wake.
        narf_interrupts::install_handler(v, hda_isr);
        // Deliver to APIC id 0 (BSP). On aarch64 this routes through
        // the GIC ITS doorbell with EventID=v.
        // SAFETY: caller holds the BusDeviceCap; we own the MSI-X
        // table (no other writer); we issue this write before the
        // global enable so the device can't fire stale data.
        let _ = unsafe { msix.program_vector(0, 0, v) }
            .map_err(|_| HdaError::DmaAllocFailed)?;
        // SAFETY: cfg-space write to a known cap-list offset.
        let _ = unsafe { msix.enable() }.map_err(|_| HdaError::DmaAllocFailed)?;
        Ok((msix, v))
    }

    /// Legacy INTx fallback: read PCI INTERRUPT_PIN, look up the
    /// (bridge, slot, pin) triple in the AML `_PRT` routing table,
    /// allocate an IDT vector, install the HDA sync handler, and
    /// program the IOAPIC redirection-table entry for the resolved
    /// GSI. PCI INTx is level-triggered, active-low (PCI Local Bus
    /// Spec §2.2.6); the ISR clears RIRBSTS to deassert.
    ///
    /// Mirrors drivers/usb/src/xhci.rs::try_install_intx — same
    /// _PRT walk + IOAPIC routing path. We don't yet evaluate
    /// `_PRT.source` (interrupt-link devices); entries with a
    /// named link source return `None` and the caller falls
    /// through to the polled `send_verb` path.
    #[cfg(target_arch = "x86_64")]
    fn try_install_intx(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Option<u8> {
        let pin = narf_bus::pci::read_intx_pin(cap, device).ok()?;
        if pin == 0 || pin > 4 {
            return None;
        }
        let slot = match device.kind {
            BusKind::Pcie { addr, .. } => addr.device,
            _ => return None,
        };
        // PCI _PRT pin is 0-based (0=INTA..3=INTD); cfg-space pin
        // is 1-based.
        let prt_pin = pin - 1;
        let route = narf_aml::irq_routing::route_for("\\_SB.PCI0", slot, prt_pin)?;
        if route.entry.source.is_some() {
            return None;
        }
        let gsi = route.entry.source_index;
        let v = narf_interrupts::vector::alloc().ok()?;
        // BAR0_PHYS was published by the caller before we got here,
        // so the ISR can W1C RIRBSTS on the first IRQ that lands.
        narf_interrupts::install_handler(v, hda_isr);
        // PCI INTx is level / active-low.
        // SAFETY: vector + handler set above before the route.
        let ok = unsafe {
            narf_acpi::ioapic::route_gsi_to_vector(
                gsi,
                v,
                0, // dest = BSP
                narf_acpi::ioapic::POLARITY_LOW | narf_acpi::ioapic::TRIGGER_LEVEL,
            )
        };
        if !ok {
            return None;
        }
        Some(v)
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn try_install_intx(
        _cap: &Cap<BusDeviceCap, Write>,
        _device: &BusDevice,
    ) -> Option<u8> {
        None
    }

    /// `(input_streams, output_streams, bidir_streams)` from GCAP.
    pub fn stream_counts(&self) -> (u8, u8, u8) {
        (self.n_iss, self.n_oss, self.n_bss)
    }

    /// Walk the AFG and program the first speaker / line-out path.
    ///
    /// Algorithm (HDA §7.3):
    /// 1. From the AFG node, enumerate subordinate widgets. For each
    ///    Pin Complex (type 0x4), read its Configuration Default
    ///    (verb 0xF1C). Bits 20..23 are the *default device*; we
    ///    pick Speaker (1) first, then Line-Out (0), then Headphone
    ///    (2) — the laptop convention. Skip pins whose connectivity
    ///    nibble (bits 30..31) is "no physical connection".
    /// 2. Read the chosen pin's Connection List (verb 0xF02 idx 0)
    ///    to find the Audio Output Converter (type 0x0) feeding it.
    ///    If the connection target is a mixer, recurse one hop.
    /// 3. Program the converter:
    ///    - Format = `FMT_48K_S16_STEREO` (matches stream descriptor).
    ///    - Stream/Channel = `(1 << 4) | 0` (stream tag 1, channel 0).
    /// 4. Unmute the converter's output amp (set 0xB000) and the
    ///    pin's output amp (same). 0xB000 = output side + L+R + index 0
    ///    + unmute + max gain.
    /// 5. Enable pin output: VERB_SET_PIN_WIDGET_CONTROL = 0x40
    ///    (out-enable).
    ///
    /// Returns the pair `(converter_nid, pin_nid)` on success.
    ///
    /// # Safety
    /// Caller owns the BAR0 mapping. Idempotent — programming the
    /// same path twice is a no-op at the codec level.
    pub unsafe fn setup_default_output_path(&self) -> Result<(u8, u8), HdaError> {
        let codec = self.codecs.first().ok_or(HdaError::NoCodecs)?;
        let cad = codec.addr;
        let afg = codec.afg_node_id.ok_or(HdaError::NoCodecs)?;

        // Subordinate Node Count: bits 0..7 = first NID, bits 16..23 = count.
        // SAFETY: caller-asserted exclusive ownership.
        let sub = unsafe {
            self.send_verb(make_verb(
                cad,
                afg,
                VERB_GET_PARAMETER | PARAM_SUBORDINATE_NODE as u32,
            ))?
        };
        let first_nid = (sub & 0xFF) as u8;
        let count = ((sub >> 16) & 0xFF) as u8;

        // First pass: rank pins by default-device preference.
        let mut best_pin: Option<(u8, u8)> = None; // (nid, pref) — lower pref wins
        for i in 0..count {
            let nid = first_nid + i;
            // SAFETY: same.
            let caps = unsafe {
                self.send_verb(make_verb(
                    cad,
                    nid,
                    VERB_GET_PARAMETER | PARAM_AUDIO_WIDGET_CAPS as u32,
                ))?
            };
            let wtype = ((caps >> 20) & 0xF) as u8;
            if wtype != WIDGET_TYPE_PIN_COMPLEX {
                continue;
            }
            // SAFETY: same.
            let cfg = unsafe { self.send_verb(make_verb(cad, nid, VERB_GET_CONFIG_DEFAULT))? };
            // bits 30..31 = port connectivity. 0=jack, 1=no conn, 2=fixed, 3=both.
            let conn = (cfg >> 30) & 0x3;
            if conn == 1 {
                continue;
            }
            // bits 20..23 = default device.
            let default_dev = ((cfg >> 20) & 0xF) as u8;
            // bit 4 of pin caps = output capable.
            // SAFETY: same.
            let pin_caps = unsafe {
                self.send_verb(make_verb(
                    cad,
                    nid,
                    VERB_GET_PARAMETER | PARAM_PIN_CAPS as u8 as u32,
                ))?
            };
            if pin_caps & (1 << 4) == 0 {
                continue;
            }
            // Preference: 0=line out, 1=speaker, 2=headphone — our
            // priority for laptop is speaker then line-out then HP.
            let pref = match default_dev {
                0x1 => 0u8, // Speaker
                0x0 => 1u8, // Line Out
                0x2 => 2u8, // HP Out
                _ => continue,
            };
            match best_pin {
                Some((_, p)) if p <= pref => {}
                _ => best_pin = Some((nid, pref)),
            }
        }
        let pin_nid = match best_pin {
            Some((nid, _)) => nid,
            None => return Err(HdaError::NoOutputStream),
        };

        // Find the converter that feeds this pin via its connection
        // list. SAFETY: same.
        let conn_len = unsafe {
            self.send_verb(make_verb(
                cad,
                pin_nid,
                VERB_GET_PARAMETER | PARAM_CONN_LIST_LEN as u32,
            ))?
        };
        let n_conn = (conn_len & 0x7F) as u8;
        if n_conn == 0 {
            return Err(HdaError::NoOutputStream);
        }
        // Get connection list entry 0. The response packs four 8-bit
        // entries (or two 16-bit entries when bit 7 of conn_len is
        // set). For laptop codecs the first entry is almost always
        // the AOC; we only walk one hop deeper if it's a mixer.
        // SAFETY: same.
        let entry = unsafe {
            self.send_verb(make_verb(cad, pin_nid, VERB_GET_CONNECTION_LIST_ENTRY))?
        };
        let mut conv_nid = (entry & 0xFF) as u8;
        // SAFETY: same.
        let conv_caps = unsafe {
            self.send_verb(make_verb(
                cad,
                conv_nid,
                VERB_GET_PARAMETER | PARAM_AUDIO_WIDGET_CAPS as u32,
            ))?
        };
        let conv_type = ((conv_caps >> 20) & 0xF) as u8;
        if conv_type != WIDGET_TYPE_AUDIO_OUTPUT {
            // One-hop recursion: assume entry is a mixer; pick its
            // first input.
            // SAFETY: same.
            let inner = unsafe {
                self.send_verb(make_verb(cad, conv_nid, VERB_GET_CONNECTION_LIST_ENTRY))?
            };
            conv_nid = (inner & 0xFF) as u8;
            // SAFETY: same.
            let inner_caps = unsafe {
                self.send_verb(make_verb(
                    cad,
                    conv_nid,
                    VERB_GET_PARAMETER | PARAM_AUDIO_WIDGET_CAPS as u32,
                ))?
            };
            if ((inner_caps >> 20) & 0xF) as u8 != WIDGET_TYPE_AUDIO_OUTPUT {
                return Err(HdaError::NoOutputStream);
            }
        }

        // Program converter format. SAFETY: same.
        unsafe {
            self.send_verb(make_verb(
                cad,
                conv_nid,
                VERB_SET_CONVERTER_FORMAT | FMT_48K_S16_STEREO as u32,
            ))?;
        }
        // Stream tag 1, channel 0.
        // SAFETY: same.
        unsafe {
            self.send_verb(make_verb(
                cad,
                conv_nid,
                VERB_SET_CONVERTER_STREAM | (1 << 4),
            ))?;
        }
        // Unmute output amp on the converter (apply to L+R, max gain).
        // 0xB000 = output(15) | left(13) | right(12) | mute=0 | gain=0x7F.
        // SAFETY: same.
        unsafe {
            self.send_verb(make_verb(cad, conv_nid, VERB_SET_AMP_GAIN_MUTE | 0xB07F))?;
        }
        // Unmute output amp on the pin.
        // SAFETY: same.
        unsafe {
            self.send_verb(make_verb(cad, pin_nid, VERB_SET_AMP_GAIN_MUTE | 0xB07F))?;
        }
        // Enable pin output (bit 6 = OUT_EN, bit 7 = HP_AMP_EN — set
        // both on a headphone pin so it drives.).
        // SAFETY: same.
        unsafe {
            self.send_verb(make_verb(cad, pin_nid, VERB_SET_PIN_WIDGET_CONTROL | 0xC0))?;
        }
        Ok((conv_nid, pin_nid))
    }

    /// Convenience: set up the default output path, load a 1 kHz sine
    /// test tone, and start the engine. Used by the platform "is
    /// audio working?" probe.
    ///
    /// # Safety
    /// Caller owns the BAR0 mapping.
    pub unsafe fn play_test_tone(&self, freq_hz: u32) -> Result<(), HdaError> {
        // SAFETY: caller-asserted exclusive ownership.
        unsafe {
            self.setup_default_output_path()?;
        }
        let _ = self.load_sine_test_tone(freq_hz);
        // SAFETY: same.
        let started = unsafe { self.start_output() };
        if !started {
            return Err(HdaError::CommandTimeout);
        }
        Ok(())
    }

    /// Slice over discovered codecs.
    pub fn codecs(&self) -> &[CodecInfo] {
        &self.codecs[..self.n_codecs as usize]
    }

    /// Stream descriptor index used for the Stage-4 prepared output
    /// stream.
    pub fn output_stream_idx(&self) -> u8 {
        self.out_stream_idx
    }

    /// Start the prepared output stream. Sets SDnCTL.RUN — the
    /// engine begins fetching BDL entries and pushing samples to
    /// the codec at the programmed format. Returns `false` if the
    /// engine doesn't acknowledge RUN within the spin budget.
    ///
    /// At Stage-5 this is the audible-playback gate: with the BDL
    /// loaded with real samples (caller's job — see
    /// [`Hda::load_period`]) and the codec's pin widget unmuted /
    /// connected, samples reach the analog output.
    ///
    /// # Safety
    /// Caller owns the BAR0 mapping (the singleton driver does for
    /// the controller's lifetime).
    pub unsafe fn start_output(&self) -> bool {
        let sd = sd_base(self.out_stream_idx);
        // SAFETY: BAR0 mapped, exclusive owner.
        let cur = unsafe { self.bar0.read32(sd + SD_CTL) };
        // Preserve stream-tag (bits 20:23) + any other vendor-set
        // fields; OR in RUN.
        // SAFETY: same.
        unsafe {
            self.bar0.write32(sd + SD_CTL, cur | SDCTL_RUN);
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB
        // stay alive while the engine acks RUN. 100 ms wedge
        // threshold (RUN ack is microseconds on healthy
        // controllers).
        narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { self.bar0.read32(sd + SD_CTL) } & SDCTL_RUN != 0,
            narf_time::Deadline::after_ms(100),
        )
    }

    /// Stop the prepared output stream by clearing SDnCTL.RUN.
    /// Returns `false` if the engine doesn't acknowledge the stop
    /// within the spin budget. Idempotent.
    ///
    /// # Safety
    /// Caller owns the BAR0 mapping.
    pub unsafe fn stop_output(&self) -> bool {
        let sd = sd_base(self.out_stream_idx);
        // SAFETY: BAR0 mapped, exclusive owner.
        let cur = unsafe { self.bar0.read32(sd + SD_CTL) };
        // SAFETY: same.
        unsafe {
            self.bar0.write32(sd + SD_CTL, cur & !SDCTL_RUN);
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB
        // stay alive while the engine acks the stop. 100 ms wedge
        // threshold.
        narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { self.bar0.read32(sd + SD_CTL) } & SDCTL_RUN == 0,
            narf_time::Deadline::after_ms(100),
        )
    }

    /// Read SDnLPIB — the linear position in the cyclic buffer at
    /// which the engine is currently fetching. The kernel uses this
    /// to know how far ahead the device has consumed samples (so
    /// the audio mixer knows when each period has been played).
    ///
    /// # Safety
    /// Caller owns the BAR0 mapping.
    pub unsafe fn output_position(&self) -> u32 {
        let sd = sd_base(self.out_stream_idx);
        // SAFETY: BAR0 mapped.
        unsafe { self.bar0.read32(sd + SD_LPIB) }
    }

    /// `true` once the engine reports SDnCTL.RUN set.
    ///
    /// # Safety
    /// Caller owns the BAR0 mapping.
    pub unsafe fn output_running(&self) -> bool {
        let sd = sd_base(self.out_stream_idx);
        // SAFETY: BAR0 mapped.
        let v = unsafe { self.bar0.read32(sd + SD_CTL) };
        v & SDCTL_RUN != 0
    }

    /// Period size in bytes — the engine cycles through this many
    /// bytes per BDL entry; with two entries pointing at the same
    /// page the cyclic length is `2 × period_bytes()`.
    pub fn period_bytes(&self) -> u32 {
        4096
    }

    /// Capacity in i16 sample slots. The Stage-4 stream descriptor
    /// is configured for 48 kHz / 16-bit / 2-channel (S16_LE
    /// stereo) so each frame is 2 × i16 = 4 bytes; capacity is
    /// `period_bytes() / 2` i16 slots = 2048 — half left, half
    /// right (interleaved).
    pub fn period_samples(&self) -> usize {
        (self.period_bytes() as usize) / 2
    }

    /// Write `samples` (interleaved L/R i16) into the period
    /// buffer. Truncates to `period_samples()`; pads the tail with
    /// zeroes if `samples` is shorter. Safe to call while the
    /// engine is running — writes land in the cyclic period before
    /// the next time the engine wraps around.
    ///
    /// Returns the number of i16 sample slots written.
    pub fn load_period(&self, samples: &[i16]) -> usize {
        let n = samples.len().min(self.period_samples());
        let phys = self.period.phys_addr().raw();
        // SAFETY: identity-mapped DMA page; n × 2 ≤ period_bytes().
        unsafe {
            for i in 0..n {
                core::ptr::write_volatile((phys + (i * 2) as u64) as *mut i16, samples[i]);
            }
            // Pad the tail with zeroes so a short load doesn't leak
            // stale samples from a prior period.
            for i in n..self.period_samples() {
                core::ptr::write_volatile((phys + (i * 2) as u64) as *mut i16, 0);
            }
        }
        n
    }

    /// Generate a sine-wave test period at `freq_hz` and load it.
    /// Useful for smoke tests / bring-up validation: a 1 kHz tone
    /// at half-amplitude (`0x4000`) is the convention.
    ///
    /// Sample rate is the controller's programmed 48 kHz.
    pub fn load_sine_test_tone(&self, freq_hz: u32) -> usize {
        const SAMPLE_RATE: u32 = 48_000;
        const AMPL_Q15: i32 = 0x4000; // half full-scale
        let frames = self.period_samples() / 2;
        // Using a minimal fixed-point sin via a small table to keep
        // this no_std-friendly without pulling in libm. 16 entries
        // around the unit circle is enough for the smoke test.
        const SIN_TABLE: [i16; 16] = [
            0, 12539, 23170, 30273, 32767, 30273, 23170, 12539, 0, -12539, -23170, -30273, -32767,
            -30273, -23170, -12539,
        ];
        let phys = self.period.phys_addr().raw();
        let mut buf = alloc::vec::Vec::with_capacity(frames * 2);
        for n in 0..frames {
            // phase = (n * freq_hz / sample_rate) * 16 indices
            let idx = ((n as u64) * (freq_hz as u64) * 16 / SAMPLE_RATE as u64) as usize & 0xF;
            let s = ((SIN_TABLE[idx] as i32) * AMPL_Q15 / 32768) as i16;
            buf.push(s); // left
            buf.push(s); // right
        }
        // SAFETY: identity-mapped DMA page; buf length matches
        // period_samples by construction.
        unsafe {
            for (i, &s) in buf.iter().enumerate() {
                core::ptr::write_volatile((phys + (i * 2) as u64) as *mut i16, s);
            }
        }
        buf.len()
    }

    /// Synchronous Get-Parameter for the post-bring-up codec walker.
    /// Polls the RIRB for a single response.
    ///
    /// Load a codec firmware patch via the kernel firmware registry.
    ///
    /// Looks `blob_name` up through `narf-firmware`, walks the
    /// payload as a stream of 32-bit verbs (little-endian), sends
    /// each one through the polled CORB/RIRB path, records the
    /// firmware-version coupling for the bound driver. Used to
    /// stage codec-specific quirk patches that vendor BIOSes
    /// would otherwise apply via DSDT _DSM methods (see HDA spec
    /// §7.3 and the Realtek / Conexant codec datasheets).
    ///
    /// # Safety
    /// Caller owns the BAR0 mapping. The blob's `view().bytes`
    /// must remain valid for the duration of the call (the cap
    /// stays alive until this function returns).
    pub unsafe fn load_codec_patch(
        &self,
        blob_name: &str,
        fw_authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
    ) -> Result<u32, HdaError> {
        let cap =
            narf_firmware::open(blob_name, fw_authority).map_err(|_| HdaError::FirmwareMissing)?;
        let view = narf_firmware::view_of(&cap).map_err(|_| HdaError::FirmwareMissing)?;
        let bytes = view.bytes;
        if bytes.len() % 4 != 0 {
            return Err(HdaError::FirmwarePatchMalformed);
        }
        let mut sent = 0u32;
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let verb = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            // SAFETY: caller-asserted exclusive ownership.
            let _ = unsafe { self.send_verb(verb)? };
            sent += 1;
            i += 4;
        }
        // Record the firmware coupling on the bound driver.
        narf_drivers::set_bound_firmware(
            "hda0",
            narf_drivers::BoundFirmware {
                blob_name: alloc::string::String::from(blob_name),
                sha256: view.sha256,
                signer: view.signer,
                version: None,
            },
        );
        Ok(sent)
    }

    /// # Safety
    /// Caller owns the BAR0 mapping (the post-bring-up driver does,
    /// because we hold the only `bar0` for the controller's lifetime).
    pub unsafe fn send_verb(&self, verb: u32) -> Result<u32, HdaError> {
        // SAFETY: caller-asserted exclusive ownership.
        unsafe {
            send_verb_polled(
                &self.bar0,
                self.corb_phys,
                self.rirb_phys,
                &self.corb_wp,
                &self.rirb_rp,
                verb,
            )
        }
    }

    /// IRQ-driven verb dispatch — async sibling to [`Self::send_verb`].
    /// Posts the verb to CORB, kicks CORBWP, then awaits the next
    /// RIRB-completion IRQ (RINTCTL set in `bring_up`, RINTCNT=1 so
    /// every response fires) before reading the response slot.
    ///
    /// Falls back to the polled path if MSI-X / INTx negotiation
    /// failed during `bring_up` — this keeps `irq_vector == None`
    /// callers working without branching at every call site.
    ///
    /// Race-safety: `wait_for_irq(v)` snapshots `fire_count(v)` on
    /// construction. We construct it *before* writing CORBWP so an
    /// IRQ that fires between the write and the future's first poll
    /// still flips the future Ready (see
    /// `interrupts/src/wait.rs` race-safety doc + the matching
    /// pattern in `drivers/nvme/src/lib.rs::submit_io_irq`).
    ///
    /// # Safety
    /// Caller owns the BAR0 mapping (the post-bring-up driver does).
    pub async unsafe fn send_verb_async(&self, verb: u32) -> Result<u32, HdaError> {
        let v = match self.irq_vector {
            Some(v) => v,
            None => {
                // SAFETY: caller-asserted exclusive ownership.
                return unsafe { self.send_verb(verb) };
            }
        };

        // 1. Reserve the RIRB slot we expect the response in. Locking
        //    `corb_wp` for the whole submit + slot-publish sequence
        //    keeps multiple concurrent senders from racing on the
        //    write pointer.
        let next = {
            let mut g = self.corb_wp.lock();
            let n = (*g + 1) % CORB_ENTRIES as u16;
            *g = n;
            n
        };

        // 2. Place verb in CORB[next]. SAFETY: identity-mapped DMA,
        //    slot inside the 1 KiB ring.
        unsafe {
            let slot = (self.corb_phys + (next as u64) * 4) as *mut u32;
            slot.write_volatile(verb);
        }
        compiler_fence(Ordering::SeqCst);

        // 3. Construct the IRQ future BEFORE poking CORBWP — the
        //    future captures `fire_count(v)` as its baseline, so any
        //    IRQ that lands after this point is guaranteed to flip
        //    it Ready on poll. 200 ms per-verb deadline matches
        //    Linux HDA's azx_send_cmd timeout pattern; on expiry
        //    the loop re-checks RIRBWP (often we won the race) and
        //    re-arms.
        loop {
            let waiter = narf_interrupts::wait_for_irq_until(
                v,
                narf_time::Deadline::after_ms(200),
            );

            // 4. Kick CORBWP — controller fetches the new verb,
            //    sends it down the link, and on the codec response
            //    raises RINTFL → INTSTS.CIS → our IRQ vector.
            // SAFETY: BAR0 mapped.
            unsafe {
                self.bar0.write16(REG_CORBWP, next);
            }

            let _ = waiter.await;

            // 5. After the wake, RIRBWP may have advanced past
            //    `next` (if multiple verbs were in flight). Confirm
            //    our slot is filled before reading; if not, re-arm
            //    (a different IRQ source on this vector woke us).
            // SAFETY: BAR0 mapped.
            let rwp = unsafe { self.bar0.read16(REG_RIRBWP) };
            if !rirb_advanced_past(rwp, next, RIRB_ENTRIES as u16) {
                continue;
            }
            {
                let mut g = self.rirb_rp.lock();
                *g = next;
            }
            // SAFETY: identity-mapped DMA, slot inside 2 KiB ring.
            let resp = unsafe {
                let slot = (self.rirb_phys + (next as u64) * 8) as *const u32;
                slot.read_volatile()
            };
            return Ok(resp);
        }
    }

    /// Out-of-IRQ controller-event drain — clears INTSTS-summarised
    /// source registers (RIRBSTS via W1C). The sync ISR also clears
    /// RIRBSTS to deassert level INTx; this method exists for
    /// quiescence sweeps where we want a synchronous bookkeeping
    /// pass without armed delivery.
    ///
    /// # Safety
    /// Caller owns the BAR0 window exclusively.
    pub unsafe fn drain_irq(&self) {
        // SAFETY: BAR0 mapped.
        let intsts = unsafe { self.bar0.read32(REG_INTSTS) };
        if intsts == 0 {
            return;
        }
        // CIS (bit 30) — RIRB / CMEI / wake. RIRBSTS bits are W1C
        // at byte 0x5D; clear both response-side bits in one write.
        if intsts & INTSTS_CIS != 0 {
            // SAFETY: BAR0 mapped, byte W1C at fixed spec offset.
            unsafe {
                self.bar0
                    .write8(REG_RIRBSTS, RIRBSTS_RINTFL | RIRBSTS_RIRBOIS);
            }
        }
    }
}

/// True when `rwp` has reached or crossed `target` in a `size`-entry
/// RIRB ring (modulo wrap). Used by `send_verb_async` to confirm
/// hardware filled the slot we claim before reading it. The CORB+RIRB
/// advance in lockstep (HDA spec §3.3.30), so reaching `target` means
/// our slot is filled.
#[inline]
fn rirb_advanced_past(rwp: u16, target: u16, size: u16) -> bool {
    // Treat the ring symmetrically across wrap: any rwp inside the
    // half-window starting at `target` counts as "past".
    let dist = (rwp.wrapping_sub(target)) % size;
    dist < (size / 2)
}

/// Single-step verb dispatch over CORB/RIRB. Submits one verb,
/// kicks CORBWP, and polls RIRBWP until a new response arrives.
///
/// # Safety
/// Caller owns the BAR0 mapping + the CORB/RIRB DMA buffers.
unsafe fn send_verb_polled(
    bar0: &bar::MmioRegion,
    corb_phys: u64,
    rirb_phys: u64,
    corb_wp: &IrqSafeSpinLock<u16>,
    rirb_rp: &IrqSafeSpinLock<u16>,
    verb: u32,
) -> Result<u32, HdaError> {
    // 1. Advance write pointer + place verb in CORB[next].
    let next = {
        let mut g = corb_wp.lock();
        let n = (*g + 1) % CORB_ENTRIES as u16;
        *g = n;
        n
    };
    // SAFETY: identity-mapped DMA, slot inside the 1 KiB ring.
    unsafe {
        let slot = (corb_phys + (next as u64) * 4) as *mut u32;
        slot.write_volatile(verb);
    }
    compiler_fence(Ordering::SeqCst);
    // 2. Tell hardware about the new write pointer.
    // SAFETY: BAR0 mapped.
    unsafe {
        bar0.write16(REG_CORBWP, next);
    }

    // 3. Poll RIRBWP for the matching response. RIRB entries are
    //    8 bytes: u32 response + u32 response_extended.
    //    responsive_spin_until ticks sleep_pumps so cursor/FB/
    //    serial stay alive across a slow codec response. 100 ms
    //    wedge threshold (HDA §3.4: codec response is bounded by
    //    a few ms in practice).
    let target = next; // RIRB and CORB advance in lockstep
    let done = narf_scheduler::responsive_spin_until(
        // SAFETY: BAR0 mapped.
        || unsafe { bar0.read16(REG_RIRBWP) } == target,
        narf_time::Deadline::after_ms(100),
    );
    if !done {
        return Err(HdaError::CommandTimeout);
    }
    // SAFETY: BAR0 mapped.
    let rwp = unsafe { bar0.read16(REG_RIRBWP) };
    let mut g = rirb_rp.lock();
    *g = rwp;
    // SAFETY: identity-mapped DMA, slot inside the 2 KiB ring.
    let resp = unsafe {
        let slot = (rirb_phys + (rwp as u64) * 8) as *const u32;
        slot.read_volatile()
    };
    Ok(resp)
}

// ── Driver-match registration ──────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<IntelHda>> = IrqSafeSpinLock::new(None);

/// `true` once `probe` has installed a controller.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Snapshot of the GCAP-derived stream counts. `None` when unprobed.
pub fn stream_counts() -> Option<(u8, u8, u8)> {
    CONTROLLER.lock().as_ref().map(|c| c.stream_counts())
}

/// Number of live codecs discovered at probe. `None` when unprobed.
pub fn codec_count() -> Option<u8> {
    CONTROLLER.lock().as_ref().map(|c| c.n_codecs)
}

/// Run `f` against the probed controller. Returns `None` when the
/// driver hasn't bound — analogous to `xhci::with_controller`.
pub fn with_controller<R>(f: impl FnOnce(&IntelHda) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

#[doc(hidden)]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller-authority over the device + its BAR window.
    let dev = match unsafe { IntelHda::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("hda0"),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
    });
    Ok(())
}

/// Static `(name, vendor, device)` triples for every HDA controller
/// PCI id we bind. The bus probe walker iterates the match table in
/// registration order — every entry routes to the same `probe`
/// function because the HDA programming model is identical across
/// vendors. Per-chip behavioural quirks (when they appear) land in
/// `VendorQuirk` lookup keyed off `(vendor, device)`, not a branch
/// inside `probe`.
const HDA_PCI_IDS: &[(&str, u16, u16)] = &[
    // AMD — Family-19h Phoenix HD Audio + Radeon HD Audio iGPU.
    ("hda-amd-phoenix", HDA_AMD_PHOENIX_VENDOR, HDA_AMD_PHOENIX_DEVICE),
    ("hda-amd-radeon", HDA_AMD_RADEON_VENDOR, HDA_AMD_RADEON_DEVICE),
    // Intel legacy ICH HD Audio.
    ("hda-intel-ich6", HDA_INTEL_ICH6_VENDOR, HDA_INTEL_ICH6_DEVICE),
    ("hda-intel-ich7", HDA_INTEL_ICH7_VENDOR, HDA_INTEL_ICH7_DEVICE),
    ("hda-intel-ich9", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_ICH9_DEVICE),
    // Intel PCH HDA (Skylake → Meteor Lake).
    ("hda-intel-sunrise-point-lp", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_SUNRISE_POINT_LP_DEVICE),
    ("hda-intel-sunrise-point-lp-b", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_SUNRISE_POINT_LP_DEVICE_B),
    ("hda-intel-cannon-lake", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_CANNON_LAKE_DEVICE),
    ("hda-intel-comet-lake", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_COMET_LAKE_DEVICE),
    ("hda-intel-comet-lake-b", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_COMET_LAKE_DEVICE_B),
    ("hda-intel-tiger-lake-lp", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_TIGER_LAKE_LP_DEVICE),
    ("hda-intel-tiger-lake-lp-b", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_TIGER_LAKE_LP_DEVICE_B),
    ("hda-intel-alder-lake", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_ALDER_LAKE_DEVICE),
    ("hda-intel-alder-lake-b", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_ALDER_LAKE_DEVICE_B),
    ("hda-intel-alder-lake-c", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_ALDER_LAKE_DEVICE_C),
    ("hda-intel-meteor-lake", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_METEOR_LAKE_DEVICE),
    // Intel iGPU display-audio (TGL / TGL-LP graphics function).
    ("hda-intel-tgl-gfx", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_TIGER_LAKE_GFX_DEVICE),
    ("hda-intel-tgl-gfx-b", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_TIGER_LAKE_GFX_DEVICE_B),
    ("hda-intel-tgl-gfx-c", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_TIGER_LAKE_GFX_DEVICE_C),
    ("hda-intel-tgl-gfx-d", HDA_INTEL_ICH9_VENDOR, HDA_INTEL_TIGER_LAKE_GFX_DEVICE_D),
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
