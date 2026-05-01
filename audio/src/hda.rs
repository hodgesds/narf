//! Intel HDA (High Definition Audio) controller driver — clean-room.
//!
//! Targets the AMD Ryzen HD Audio Controller (`1022:15e3`) and the
//! Radeon HD Audio Controller (`1002:1640`) on integrated GPUs, both
//! of which expose the standard Intel HDA programming model.
//!
//! Reference: **Intel "High Definition Audio Specification" rev 1.0a**
//! (free PDF, intel.com). Section numbers in comments below refer to
//! that document. Codec verb encodings come from the same spec
//! (§7.3) and the codec vendor's datasheet.
//!
//! Stage-4 cut: bring the controller out of reset, allocate CORB +
//! RIRB rings, walk STATESTS for live codec slots, fetch each
//! codec's vendor / sub-system / function-group descriptor via Get
//! Parameter verbs, pick one output stream descriptor, allocate a
//! BDL + a single 4-KiB silence period, and program the stream for
//! 48 kHz / 16-bit / 2-ch. **No audible playback** — RUN bit is not
//! set; that lands once the audio mixer / submission API is wired.
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

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{bar, BusDevice, BusDeviceCap};
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

// ── Global register offsets (HDA 1.0a §3.3) ────────────────────────

const REG_GCAP:      u64 = 0x00;
#[allow(dead_code)]
const REG_VMIN:      u64 = 0x02;
#[allow(dead_code)]
const REG_VMAJ:      u64 = 0x03;
#[allow(dead_code)]
const REG_OUTPAY:    u64 = 0x04;
#[allow(dead_code)]
const REG_INPAY:     u64 = 0x06;
const REG_GCTL:      u64 = 0x08;
#[allow(dead_code)]
const REG_WAKEEN:    u64 = 0x0C;
const REG_STATESTS:  u64 = 0x0E;
#[allow(dead_code)]
const REG_INTCTL:    u64 = 0x20;
const REG_INTSTS:    u64 = 0x24;

// CORB block (§3.3.21–§3.3.27).
const REG_CORBLBASE: u64 = 0x40;
const REG_CORBUBASE: u64 = 0x44;
const REG_CORBWP:    u64 = 0x48;
const REG_CORBRP:    u64 = 0x4A;
const REG_CORBCTL:   u64 = 0x4C;
#[allow(dead_code)]
const REG_CORBSTS:   u64 = 0x4D;
#[allow(dead_code)]
const REG_CORBSIZE:  u64 = 0x4E;

// RIRB block (§3.3.28–§3.3.34).
const REG_RIRBLBASE: u64 = 0x50;
const REG_RIRBUBASE: u64 = 0x54;
const REG_RIRBWP:    u64 = 0x58;
const REG_RINTCNT:   u64 = 0x5A;
const REG_RIRBCTL:   u64 = 0x5C;
#[allow(dead_code)]
const REG_RIRBSTS:   u64 = 0x5D;
#[allow(dead_code)]
const REG_RIRBSIZE:  u64 = 0x5E;

// GCTL bits.
const GCTL_CRST:   u32 = 1 << 0; // controller reset (1 = leave reset)
#[allow(dead_code)]
const GCTL_FCNTRL: u32 = 1 << 1; // flush control
const GCTL_UNSOL:  u32 = 1 << 8; // accept unsolicited responses

// CORBCTL / RIRBCTL bits.
const CORBCTL_CMEIE:  u8 = 1 << 0; // memory-error interrupt enable
const CORBCTL_RUN:    u8 = 1 << 1; // CORBRUN — start DMA engine
#[allow(dead_code)]
const RIRBCTL_RINTCTL: u8 = 1 << 0; // response interrupt enable
const RIRBCTL_RUN:     u8 = 1 << 1; // RIRBDMAEN
const RIRBCTL_OIC:     u8 = 1 << 2; // overrun interrupt enable

// CORBSIZE / RIRBSIZE: bits[1:0] select size, bits[7:4] are SZCAP.
// Encoding: 0=2 entries (8 B), 1=16 entries (64 B), 2=256 entries
// (1024 B for CORB / 2048 B for RIRB).
const CORBSIZE_256: u8 = 2;
const RIRBSIZE_256: u8 = 2;

// INTCTL bits (§3.3.14).
#[allow(dead_code)]
const INTCTL_SIE_MASK: u32 = 0x3FFF_FFFF; // per-stream IRQ enables (bits 0..29)
#[allow(dead_code)]
const INTCTL_CIE:      u32 = 1 << 30;     // controller IRQ enable
#[allow(dead_code)]
const INTCTL_GIE:      u32 = 1 << 31;     // global IRQ enable

// CORB / RIRB sizing: at least 256 entries by spec (§3.3.24, §3.3.31).
// CORB entries are 4 B → 1024 B ring. RIRB entries are 8 B → 2048 B.
const CORB_ENTRIES: usize = 256;
#[allow(dead_code)]
const RIRB_ENTRIES: usize = 256;
#[allow(dead_code)]
const CORB_BYTES:   usize = CORB_ENTRIES * 4;   // 1024
#[allow(dead_code)]
const RIRB_BYTES:   usize = RIRB_ENTRIES * 8;   // 2048

// ── Codec verbs (HDA 1.0a §7.3) ────────────────────────────────────

/// Get Parameter (verb 0xF00). Parameter is in low 8 bits of payload.
const VERB_GET_PARAMETER: u32 = 0xF00 << 8;

// Parameter ids (§7.3.4).
const PARAM_VENDOR_ID:        u8 = 0x00;
const PARAM_REVISION_ID:      u8 = 0x02;
const PARAM_SUBORDINATE_NODE: u8 = 0x04;
const PARAM_FUNCTION_GROUP:   u8 = 0x05;
#[allow(dead_code)]
const PARAM_AUDIO_GROUP_CAPS: u8 = 0x08;

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
const fn sd_base(idx: u8) -> u64 { 0x80 + (idx as u64) * 0x20 }

const SD_CTL:   u64 = 0x00; // 24-bit
const SD_STS:   u64 = 0x03;
const SD_LPIB:  u64 = 0x04;
const SD_CBL:   u64 = 0x08; // cyclic buffer length, 32-bit
const SD_LVI:   u64 = 0x0C; // last valid index, 16-bit
#[allow(dead_code)]
const SD_FIFOS: u64 = 0x10;
const SD_FMT:   u64 = 0x12; // format, 16-bit
const SD_BDPL:  u64 = 0x18; // BDL phys, low 32
const SD_BDPU:  u64 = 0x1C; // BDL phys, high 32

// SDnCTL bits (low 24).
const SDCTL_SRST: u32 = 1 << 0;
const SDCTL_RUN:  u32 = 1 << 1;
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
const FMT_48K_S16_STEREO: u16 =
    (0b0_0000_000 << 8) // base 48k, mult 1×, div 1
    | (0b001 << 4)       // 16-bit
    | 0b0001;            // 2 channels (chan_count - 1 == 1)

// ── Driver state ───────────────────────────────────────────────────

/// Per-codec discovery snapshot. Stage-4: vendor/device id +
/// subsystem id + first audio function group node id. Verb space
/// walk lands when codec parsing grows beyond enumeration.
#[derive(Copy, Clone, Debug, Default)]
pub struct CodecInfo {
    pub addr:         u8,
    pub vendor_id:    u32,
    pub revision_id:  u32,
    pub afg_node_id:  Option<u8>,
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
    corb_wp:   IrqSafeSpinLock<u16>,
    /// Software read pointer for RIRB (chases RIRBWP).
    rirb_rp:   IrqSafeSpinLock<u16>,

    /// GCAP-derived counts.
    n_iss:     u8, // input streams
    n_oss:     u8, // output streams
    n_bss:     u8, // bidirectional streams

    /// Live codec slots discovered via STATESTS.
    codecs:    [CodecInfo; 16],
    n_codecs:  u8,

    /// Stream descriptor we picked for the playback stream.
    out_stream_idx: u8,
    /// BDL backing for that stream (one entry, one 4 KiB silence period).
    _bdl:           DmaBuffer,
    /// Audio period buffer — initialised to zero (silence) at bring-up.
    /// `load_period` writes samples here so the engine plays them on
    /// the next cycle.
    period:         DmaBuffer,

    /// IDT vector if MSI-X is wired, `None` for polled mode (Stage-4
    /// default — playback isn't running, so no IRQ load).
    pub irq_vector: Option<u8>,

    pub ready: bool,
}

impl core::fmt::Debug for IntelHda {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelHda")
            .field("ready",     &self.ready)
            .field("n_iss",     &self.n_iss)
            .field("n_oss",     &self.n_oss)
            .field("n_bss",     &self.n_bss)
            .field("n_codecs",  &self.n_codecs)
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
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, HdaError> {
        // 1. Map BAR0 — the HDA register window.
        // SAFETY: caller-asserted exclusive ownership.
        let bar0 = unsafe { bar::map_bar(device, 0) }
            .map_err(|_| HdaError::BarMapFailed)?;

        // 2. Reset (§4.2.2): clear GCTL.CRST, poll until CRST reads
        //    0, set CRST again, poll until CRST reads 1.
        // SAFETY: BAR0 mapped, identity-mapped MMIO.
        unsafe {
            let g = bar0.read32(REG_GCTL);
            bar0.write32(REG_GCTL, g & !GCTL_CRST);
        }
        // Wait for reset to take effect.
        for _ in 0..10_000 {
            // SAFETY: same.
            let g = unsafe { bar0.read32(REG_GCTL) };
            if g & GCTL_CRST == 0 { break; }
            core::hint::spin_loop();
        }
        // SAFETY: same.
        unsafe { bar0.write32(REG_GCTL, GCTL_CRST | GCTL_UNSOL); }
        let mut crst_ok = false;
        for _ in 0..50_000 {
            // SAFETY: same.
            let g = unsafe { bar0.read32(REG_GCTL) };
            if g & GCTL_CRST != 0 { crst_ok = true; break; }
            core::hint::spin_loop();
        }
        if !crst_ok { return Err(HdaError::ResetTimeout); }

        // §4.3: after CRST, hardware must hold off codec enumeration
        // for at least 521 µs. We don't have a sub-ms time source on
        // every arch, so spin for ~30 000 cycles which dominates that
        // window on every realistic clock.
        for _ in 0..30_000 { core::hint::spin_loop(); }

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
        let n_iss = ((gcap >> 8)  & 0xF) as u8;
        let n_bss = ((gcap >> 4)  & 0xF) as u8;

        // 4. Allocate CORB + RIRB DMA buffers. alloc_coherent
        //    returns ZEROED frames per the io/ contract; we don't
        //    re-zero. Each ring is a single 4 KiB page (CORB needs
        //    1 KiB, RIRB needs 2 KiB; pages are abundant).
        let corb = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| HdaError::DmaAllocFailed)?;
        let rirb = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| HdaError::DmaAllocFailed)?;
        let corb_phys = corb.phys_addr().raw();
        let rirb_phys = rirb.phys_addr().raw();
        // Spec mandates 128-byte alignment for both (§3.3.18,
        // §3.3.25); 4 KiB pages trivially satisfy that.
        debug_assert_eq!(corb_phys & 0x7F, 0);
        debug_assert_eq!(rirb_phys & 0x7F, 0);

        // 5. Stop CORB / RIRB DMA before reprogramming addresses.
        // SAFETY: BAR0 mapped.
        unsafe {
            bar0.write32(REG_CORBCTL as u64 & !0x3, // word-aligned write below
                bar0.read32(REG_CORBCTL & !0x3));   // no-op; placeholder for clarity
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
            bar0.write32(REG_CORBUBASE, (corb_phys >> 32)         as u32);
            bar0.write32(REG_RIRBLBASE, (rirb_phys & 0xFFFF_FFFF) as u32);
            bar0.write32(REG_RIRBUBASE, (rirb_phys >> 32)         as u32);
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
        for _ in 0..10_000 {
            // SAFETY: same.
            let v = unsafe { bar0.read16(REG_CORBRP) };
            if v & (1 << 15) != 0 { break; }
            core::hint::spin_loop();
        }
        // SAFETY: same.
        unsafe { bar0.write16(REG_CORBRP, 0); }
        for _ in 0..10_000 {
            // SAFETY: same.
            let v = unsafe { bar0.read16(REG_CORBRP) };
            if v & (1 << 15) == 0 { break; }
            core::hint::spin_loop();
        }
        // CORBWP starts at 0; software writes the *next* slot's
        // index, hardware advances CORBRP to it.
        // SAFETY: same.
        unsafe { bar0.write16(REG_CORBWP, 0); }

        // 9. Reset RIRB write pointer (§3.3.30): bit15 of RIRBWP is
        //    a write-1-to-clear self-resetting bit.
        // SAFETY: BAR0 mapped.
        unsafe { bar0.write16(REG_RIRBWP, 1 << 15); }

        // 10. RINTCNT: response interrupt count. Stage-4 uses polling
        //    so the value is informational; set to 1 so that *if* we
        //    later enable RINTCTL, the controller IRQs after every
        //    response.
        // SAFETY: BAR0 mapped.
        unsafe { bar0.write16(REG_RINTCNT, 1); }

        // 11. Start the DMA engines: CORBCTL.RUN + RIRBCTL.RUN.
        //     Leave CMEIE / RINTCTL / OIC off — Stage-4 polls.
        // SAFETY: BAR0 mapped.
        unsafe {
            let blk = bar0.read32(REG_CORBCTL & !0x3);
            bar0.write32(REG_CORBCTL & !0x3,
                (blk & 0xFFFF_FF00) | (CORBCTL_RUN | CORBCTL_CMEIE) as u32);
            let blk = bar0.read32(REG_RIRBCTL & !0x3);
            bar0.write32(REG_RIRBCTL & !0x3,
                (blk & 0xFFFF_FF00) | (RIRBCTL_RUN | RIRBCTL_OIC) as u32);
        }

        // 12. Discover live codecs from STATESTS (§3.3.9). Each set
        //     bit 0..14 represents a codec at that codec address.
        // SAFETY: BAR0 mapped.
        let statests = unsafe { bar0.read16(REG_STATESTS) };
        // Clear it (write-1-to-clear).
        // SAFETY: same.
        unsafe { bar0.write16(REG_STATESTS, statests); }

        let mut codecs = [CodecInfo::default(); 16];
        let mut n_codecs = 0u8;

        // Build a controller stub so we can issue verbs while still
        // mid-bring-up. We construct the IrqSafeSpinLock pointers
        // up front and reuse them via a closure.
        let corb_wp = IrqSafeSpinLock::new(0u16);
        let rirb_rp = IrqSafeSpinLock::new(0u16);

        for cad in 0..15u8 {
            if statests & (1u16 << cad) == 0 { continue; }
            // Vendor / device id (param 0x00) — required.
            // SAFETY: BAR0 mapped, ring DMA buffers programmed.
            let vendor = unsafe {
                send_verb_polled(
                    &bar0, corb_phys, rirb_phys, &corb_wp, &rirb_rp,
                    make_verb(cad, 0, VERB_GET_PARAMETER | PARAM_VENDOR_ID as u32))
            }.unwrap_or(0);
            if vendor == 0 || vendor == 0xFFFF_FFFF { continue; }
            // SAFETY: same.
            let revision = unsafe {
                send_verb_polled(
                    &bar0, corb_phys, rirb_phys, &corb_wp, &rirb_rp,
                    make_verb(cad, 0, VERB_GET_PARAMETER | PARAM_REVISION_ID as u32))
            }.unwrap_or(0);
            // Sub-node range (param 0x04): low 16 = total node count,
            // high 16 = starting node id of the function group(s).
            // SAFETY: same.
            let sub = unsafe {
                send_verb_polled(
                    &bar0, corb_phys, rirb_phys, &corb_wp, &rirb_rp,
                    make_verb(cad, 0, VERB_GET_PARAMETER | PARAM_SUBORDINATE_NODE as u32))
            }.unwrap_or(0);
            let starting = ((sub >> 16) & 0xFF) as u8;
            let total    = (sub & 0xFF) as u8;
            // Walk function-group children — find the first AFG (type 0x01).
            let mut afg = None;
            for nid in starting..starting.saturating_add(total) {
                // SAFETY: same.
                let fg = unsafe {
                    send_verb_polled(
                        &bar0, corb_phys, rirb_phys, &corb_wp, &rirb_rp,
                        make_verb(cad, nid,
                                  VERB_GET_PARAMETER | PARAM_FUNCTION_GROUP as u32))
                }.unwrap_or(0);
                // Function group type is bits 0..7. 0x01 = AFG, 0x02 = MFG.
                if fg & 0xFF == 0x01 { afg = Some(nid); break; }
            }
            codecs[n_codecs as usize] = CodecInfo {
                addr:        cad,
                vendor_id:   vendor,
                revision_id: revision,
                afg_node_id: afg,
            };
            n_codecs += 1;
        }

        if n_codecs == 0 { return Err(HdaError::NoCodecs); }
        if n_oss == 0    { return Err(HdaError::NoOutputStream); }

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
        for _ in 0..10_000 {
            // SAFETY: same.
            let v = unsafe { bar0.read32(sd + SD_CTL) };
            if v & SDCTL_SRST != 0 { break; }
            core::hint::spin_loop();
        }
        // SAFETY: same.
        unsafe { bar0.write32(sd + SD_CTL, 0); }
        for _ in 0..10_000 {
            // SAFETY: same.
            let v = unsafe { bar0.read32(sd + SD_CTL) };
            if v & SDCTL_SRST == 0 { break; }
            core::hint::spin_loop();
        }

        // 14. Allocate BDL (must be 128-byte aligned, §3.6.2; a 4 KiB
        //     page satisfies that) + a single 4 KiB silence period.
        let bdl     = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| HdaError::DmaAllocFailed)?;
        let silence = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| HdaError::DmaAllocFailed)?;
        let bdl_phys     = bdl.phys_addr().raw();
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
            p.add(1).write_volatile((silence_phys >> 32)         as u32);
            p.add(2).write_volatile(4096);
            p.add(3).write_volatile(0); // no IOC
            // entry 1 — same buffer, makes the engine valid even
            // though we won't run it.
            p.add(4).write_volatile((silence_phys & 0xFFFF_FFFF) as u32);
            p.add(5).write_volatile((silence_phys >> 32)         as u32);
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
            bar0.write32(sd + SD_BDPU, (bdl_phys >> 32)         as u32);
            // SDnCTL: stream tag = 1 (tag 0 is reserved per §3.3.35).
            // RUN bit deliberately NOT set — Stage-4 stops here.
            bar0.write32(sd + SD_CTL, 1u32 << SDCTL_STREAM_TAG_SHIFT);
        }

        // 16. INTCTL: leave global IRQ disabled until the playback /
        //     capture data plane wires MSI-X. Stage-4 keeps the
        //     polling path; smoke tests don't exercise IRQs here.

        Ok(Self {
            bar0,
            _corb: corb,
            _rirb: rirb,
            corb_phys, rirb_phys,
            corb_wp, rirb_rp,
            n_iss, n_oss, n_bss,
            codecs, n_codecs,
            out_stream_idx: out_idx,
            _bdl: bdl,
            period: silence,
            irq_vector: None,
            ready: true,
        })
    }

    /// `(input_streams, output_streams, bidir_streams)` from GCAP.
    pub fn stream_counts(&self) -> (u8, u8, u8) {
        (self.n_iss, self.n_oss, self.n_bss)
    }

    /// Slice over discovered codecs.
    pub fn codecs(&self) -> &[CodecInfo] {
        &self.codecs[..self.n_codecs as usize]
    }

    /// Stream descriptor index used for the Stage-4 prepared output
    /// stream.
    pub fn output_stream_idx(&self) -> u8 { self.out_stream_idx }

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
        unsafe { self.bar0.write32(sd + SD_CTL, cur | SDCTL_RUN); }
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let v = unsafe { self.bar0.read32(sd + SD_CTL) };
            if v & SDCTL_RUN != 0 { return true; }
            core::hint::spin_loop();
        }
        false
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
        unsafe { self.bar0.write32(sd + SD_CTL, cur & !SDCTL_RUN); }
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let v = unsafe { self.bar0.read32(sd + SD_CTL) };
            if v & SDCTL_RUN == 0 { return true; }
            core::hint::spin_loop();
        }
        false
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
    pub fn period_bytes(&self) -> u32 { 4096 }

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
                core::ptr::write_volatile(
                    (phys + (i * 2) as u64) as *mut i16,
                    samples[i]);
            }
            // Pad the tail with zeroes so a short load doesn't leak
            // stale samples from a prior period.
            for i in n..self.period_samples() {
                core::ptr::write_volatile(
                    (phys + (i * 2) as u64) as *mut i16, 0);
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
        const AMPL_Q15:    i32 = 0x4000; // half full-scale
        let frames = self.period_samples() / 2;
        // Using a minimal fixed-point sin via a small table to keep
        // this no_std-friendly without pulling in libm. 16 entries
        // around the unit circle is enough for the smoke test.
        const SIN_TABLE: [i16; 16] = [
            0,     12539, 23170, 30273,
            32767, 30273, 23170, 12539,
            0,    -12539,-23170,-30273,
           -32767,-30273,-23170,-12539,
        ];
        let phys = self.period.phys_addr().raw();
        let mut buf = alloc::vec::Vec::with_capacity(frames * 2);
        for n in 0..frames {
            // phase = (n * freq_hz / sample_rate) * 16 indices
            let idx = ((n as u64) * (freq_hz as u64) * 16
                     / SAMPLE_RATE as u64) as usize & 0xF;
            let s = ((SIN_TABLE[idx] as i32) * AMPL_Q15 / 32768) as i16;
            buf.push(s); // left
            buf.push(s); // right
        }
        // SAFETY: identity-mapped DMA page; buf length matches
        // period_samples by construction.
        unsafe {
            for (i, &s) in buf.iter().enumerate() {
                core::ptr::write_volatile(
                    (phys + (i * 2) as u64) as *mut i16, s);
            }
        }
        buf.len()
    }

    /// Synchronous Get-Parameter for the post-bring-up codec walker.
    /// Polls the RIRB for a single response.
    ///
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

    /// IRQ-driven controller-event drain. Reads and clears
    /// INTSTS / RIRBSTS / per-stream STS bits. Stage-4 stub —
    /// callers don't yet exist; this is the surface the data
    /// plane will hook into.
    ///
    /// # Safety
    /// Caller owns the BAR0 window exclusively.
    pub unsafe fn drain_irq(&self) {
        // SAFETY: BAR0 mapped.
        let intsts = unsafe { self.bar0.read32(REG_INTSTS) };
        if intsts == 0 { return; }
        // GIS bit 31 is the global summary; per-stream bits 0..29.
        // Clear RIRB status (write-1-to-clear) when CIS bit 30 set.
        if intsts & (1 << 30) != 0 {
            // SAFETY: same.
            unsafe {
                let cur = self.bar0.read32(REG_RIRBCTL & !0x3);
                // RIRBSTS @ byte 0x5D — bit pattern (RINTFL=0,
                // RIRBOIS=2). Clear by writing 1s to those bits.
                self.bar0.write32(REG_RIRBCTL & !0x3,
                    (cur & 0xFFFF_00FF) | (0x05 << 8));
            }
        }
    }
}

/// Single-step verb dispatch over CORB/RIRB. Submits one verb,
/// kicks CORBWP, and polls RIRBWP until a new response arrives.
///
/// # Safety
/// Caller owns the BAR0 mapping + the CORB/RIRB DMA buffers.
unsafe fn send_verb_polled(
    bar0:      &bar::MmioRegion,
    corb_phys: u64,
    rirb_phys: u64,
    corb_wp:   &IrqSafeSpinLock<u16>,
    rirb_rp:   &IrqSafeSpinLock<u16>,
    verb:      u32,
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
    unsafe { bar0.write16(REG_CORBWP, next); }

    // 3. Poll RIRBWP for the matching response. RIRB entries are
    //    8 bytes: u32 response + u32 response_extended.
    let target = next; // RIRB and CORB advance in lockstep
    let mut spins = 0u32;
    loop {
        // SAFETY: BAR0 mapped.
        let rwp = unsafe { bar0.read16(REG_RIRBWP) };
        if rwp == target {
            let mut g = rirb_rp.lock();
            *g = rwp;
            // SAFETY: identity-mapped DMA, slot inside the 2 KiB ring.
            let resp = unsafe {
                let slot = (rirb_phys + (rwp as u64) * 8) as *const u32;
                slot.read_volatile()
            };
            return Ok(resp);
        }
        spins += 1;
        if spins > 1_000_000 { return Err(HdaError::CommandTimeout); }
        core::hint::spin_loop();
    }
}

// ── Driver-match registration ──────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<IntelHda>> =
    IrqSafeSpinLock::new(None);

/// `true` once `probe` has installed a controller.
pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

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
pub fn probe(
    device: BusDevice,
    cap:    Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() { return Ok(()); }
    narf_bus::pci::set_command(
        &cap, &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    ).map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller-authority over the device + its BAR window.
    let dev = match unsafe { IntelHda::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("hda0"),
        kind:    narf_drivers::BoundKind::Audio,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain:  narf_drivers::BoundKind::Audio.default_domain(),
    });
    Ok(())
}

/// Register both supported PCI ids with the bus match table.
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "hda-amd-phoenix",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: HDA_AMD_PHOENIX_VENDOR,
            device: HDA_AMD_PHOENIX_DEVICE,
        },
        probe,
    });
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "hda-amd-radeon",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: HDA_AMD_RADEON_VENDOR,
            device: HDA_AMD_RADEON_DEVICE,
        },
        probe,
    });
}

extern crate alloc;
