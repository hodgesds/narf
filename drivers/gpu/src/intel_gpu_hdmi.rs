//! Intel external HDMI — full path (#1019).
//!
//! Everything an external HDMI sink needs that the DP path
//! does not have: EDID over DDC (GMBUS), TMDS modeset to HDMI
//! 2.0 rates with SCDC scrambling, AVI infoframe emission over
//! the transcoder DIP banks, and HDMI audio publication. The
//! register sequence runs through
//! [`Modeset::modeset_hdmi`](crate::intel_gpu_modeset::Modeset::modeset_hdmi) —
//! this module is the session layer around it, symmetric with
//! `intel_gpu_dp`.
//!
//! ## Seams consumed (built by other lanes — not re-implemented)
//!
//! - **GMBUS codec** (`intel_gpu_gmbus`, lane 1 / Q3 #1018):
//!   the base-block EDID read runs the codec's own
//!   [`build_edid_read`] program verbatim, and every other DDC
//!   transfer is composed from the codec's documented field
//!   encodings and caller sequence (write GMBUS0, write
//!   GMBUS1, poll GMBUS2 via [`GmbusStatus::classify`], drain /
//!   fill GMBUS3, restore GMBUS0 = 0). Q3 owns the transport
//!   hardening (and the `GMBUS_BASE` / `GMBUS2_HW_DONE`
//!   corrections); when its transport lands, the transfer
//!   engine below is the swap-out point — the session logic
//!   above it does not change.
//! - **Shared display-audio sink**
//!   (`narf_drivers_sound::display_audio`, built by Q4 #1092):
//!   this lane is its second publisher, with
//!   [`DisplayConnector::Hdmi`]. The codec-side programming is
//!   the HDMI branch in [`crate::intel_gpu_audio`].
//! - **HPD** (`intel_gpu_dp::{HpdMonitor, hotplug_bit}`): the
//!   combo-DDI hotplug block is shared with DP; the production
//!   glue in `intel_gpu` routes a connect to whichever session
//!   answers (a DP sink answers AUX, an HDMI sink answers
//!   DDC).
//!
//! ## Protocol sources (fixtures are pinned against these)
//!
//! - HDMI 2.0 / CTA-861: infoframe packing + checksum
//!   (HDMI 1.4 §5.3.5 frame shape as implemented by Linux
//!   `drivers/video/hdmi.c`), AVI/audio infoframe data-byte
//!   layouts, CTA data-block iteration, HF-VSDB (OUI
//!   0xC45DD8) SCDC capability bits.
//! - HDMI SCDC: register map and semantics from the Linux
//!   `drm_scdc_helper` (`include/drm/display/
//!   drm_scdc_helper.h`): slave 0x54, TMDS_CONFIG 0x20
//!   (bit 0 scrambling enable, bit 1 clock ratio 1/40),
//!   SCRAMBLER_STATUS 0x21 bit 0; >340 Mcsc requires ratio
//!   1/40 + scrambling, <=340 Mcsc requires neither.
//! - Intel PRM Vol. 2c (TRANS_DDI_FUNC_CTL HDMI bits), Vol. 11
//!   (WRPLL — see `intel_gpu_pll::hdmi_wrpll_coeffs`), Vol. 12
//!   (VIDEO_DIP_* HSW bank map + the hsw_write_infoframe
//!   protocol in i915 `intel_hdmi.c`): the DIP buffer carries
//!   the infoframe with a 1-byte ECC hole at position 3 and is
//!   zero-padded to 32 bytes. There is no audio DIP bank — on
//!   this hardware the audio infoframe is synthesised by the
//!   HDA codec from the published ELD; the display side packs
//!   the frame ([`pack_audio_infoframe`]) and carries it on
//!   the connection for that consumer.
//!
//! ## Character-rate rule
//!
//! The TMDS character rate of an 8-bpc mode is its pixel
//! clock. Above 340 Mcsc the HDMI spec requires SCDC
//! scrambling + the 1/40 clock ratio, and the PRM requires
//! the TRANS_DDI_FUNC_CTL scrambling + high-char-rate bits;
//! at or below 340 Mcsc the sink must not be touched over
//! SCDC at all. A >340 Mcsc mode against a sink that does not
//! declare SCDC in its HF-VSDB is refused, not degraded.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_drivers_sound::display_audio::{
    build_eld, clear_display_audio, publish_display_audio, DisplayConnector,
};

use crate::intel_gpu_audio;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_dp::sink_id_for;
use crate::intel_gpu_gmbus::{
    build_edid_read, gmbus1_byte_count, gmbus1_slave_addr, GmbusError, GmbusStatus, PinPair,
    DDC_SLAVE_EDID, DDC_SLAVE_SEGMENT, GMBUS0, GMBUS0_RATE_100KHZ, GMBUS1, GMBUS1_DIR_READ,
    GMBUS1_ENT, GMBUS1_STO, GMBUS1_SW_CLR_INT, GMBUS1_SW_RDY, GMBUS2, GMBUS3, GMBUS5,
};
use crate::intel_gpu_modeset::{Framebuffer, Mode, Modeset, ModesetError};
use crate::intel_gpu_pipes::Transcoder;

// ── DDC over GMBUS ─────────────────────────────────────────────

/// Poll budget for one GMBUS transaction phase. Poll-counted,
/// not time-based (the #879 discipline: aarch64 cycle counters
/// crawl and x86 TSC leaps under TCG, so wall-clock budgets
/// misfire; the GMBUS ENT bit also bounds a wedged transfer at
/// ~30 ms on silicon).
const GMBUS_POLL_BUDGET: u32 = 100_000;

/// Errors from the DDC transfer engine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DdcError {
    /// The GMBUS codec rejected the program shape.
    Gmbus(GmbusError),
    /// The addressed slave NACKed (no sink, or not that slave).
    SlaveNack,
    /// The poll budget ran out before the transfer completed.
    Timeout,
    /// The transfer completed with fewer bytes than requested.
    ShortTransfer,
    /// The DDI has no GMBUS pin pair (Type-C DDIs D+ on the
    /// GEN11 HPD path are not GMBUS-addressable here).
    NoPinPair,
}

impl From<GmbusError> for DdcError {
    fn from(e: GmbusError) -> Self {
        DdcError::Gmbus(e)
    }
}

/// The GMBUS pin pair a DDI's DDC lines hang off (PRM Vol. 12
/// GMBUS0 pin-pair table: DDI A..F = pairs 2..7).
pub fn pin_pair_for(ddi: Ddi) -> Option<PinPair> {
    Some(match ddi {
        Ddi::A => PinPair::DdiA,
        Ddi::B => PinPair::DdiB,
        Ddi::C => PinPair::DdiC,
        Ddi::D => PinPair::DdiD,
        Ddi::E => PinPair::DdiE,
        Ddi::F => PinPair::DdiF,
        _ => return None,
    })
}

fn gmbus_idle<M: MmioWindow + ?Sized>(mmio: &M) {
    mmio.write32(GMBUS0, 0);
    compiler_fence(Ordering::SeqCst);
}

/// Run one read transfer whose GMBUS0/GMBUS1 program the
/// caller composed (the codec's EDID program, or the generic
/// shape in [`gmbus_read`]). Drains GMBUS3 little-endian —
/// the PRM packs the first-received byte in bits[7:0].
fn run_read_program<M: MmioWindow + ?Sized>(
    mmio: &M,
    gmbus0: u32,
    gmbus1: u32,
    out: &mut [u8],
) -> Result<(), DdcError> {
    mmio.write32(GMBUS0, gmbus0);
    mmio.write32(GMBUS1, gmbus1);
    compiler_fence(Ordering::SeqCst);
    let mut received = 0usize;
    let mut budget = GMBUS_POLL_BUDGET;
    let result = loop {
        if budget == 0 {
            break Err(DdcError::Timeout);
        }
        budget -= 1;
        match GmbusStatus::classify(mmio.read32(GMBUS2)) {
            GmbusStatus::SlaveNack => break Err(DdcError::SlaveNack),
            GmbusStatus::DataReady => {
                let dword = mmio.read32(GMBUS3);
                for b in 0..4 {
                    if received < out.len() {
                        out[received] = (dword >> (8 * b)) as u8;
                        received += 1;
                    }
                }
            }
            GmbusStatus::Done => {
                if received == out.len() {
                    break Ok(());
                }
                break Err(DdcError::ShortTransfer);
            }
            GmbusStatus::Pending => core::hint::spin_loop(),
        }
    };
    gmbus_idle(mmio);
    result
}

/// Read `out.len()` bytes from DDC `slave`, starting at byte
/// `index` (programmed into GMBUS5, the block's byte-index
/// register — this is both the EDID block offset mechanism and
/// the SCDC register-address mechanism).
pub fn gmbus_read<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
    slave: u8,
    index: u16,
    out: &mut [u8],
) -> Result<(), DdcError> {
    if out.is_empty() || out.len() > 0x1FF {
        return Err(DdcError::Gmbus(GmbusError::TooManyBytes));
    }
    mmio.write32(GMBUS5, index as u32);
    compiler_fence(Ordering::SeqCst);
    let gmbus0 = GMBUS0_RATE_100KHZ | pin.encode();
    let gmbus1 = GMBUS1_SW_CLR_INT
        | GMBUS1_SW_RDY
        | GMBUS1_ENT
        | GMBUS1_STO
        | gmbus1_byte_count(out.len() as u16)
        | gmbus1_slave_addr(slave)
        | GMBUS1_DIR_READ;
    run_read_program(mmio, gmbus0, gmbus1, out)
}

/// Write `data` to DDC `slave` (an SCDC register write is
/// `[register, value]`; the E-DDC segment pointer is one
/// byte). Data leaves through GMBUS3 little-endian as the
/// controller raises HW_RDY per 4-byte chunk.
pub fn gmbus_write<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
    slave: u8,
    data: &[u8],
) -> Result<(), DdcError> {
    if data.is_empty() || data.len() > 0x1FF {
        return Err(DdcError::Gmbus(GmbusError::TooManyBytes));
    }
    let gmbus0 = GMBUS0_RATE_100KHZ | pin.encode();
    let gmbus1 = GMBUS1_SW_CLR_INT
        | GMBUS1_SW_RDY
        | GMBUS1_ENT
        | GMBUS1_STO
        | gmbus1_byte_count(data.len() as u16)
        | gmbus1_slave_addr(slave);
    mmio.write32(GMBUS0, gmbus0);
    mmio.write32(GMBUS1, gmbus1);
    compiler_fence(Ordering::SeqCst);
    let mut sent = 0usize;
    let mut budget = GMBUS_POLL_BUDGET;
    let result = loop {
        if budget == 0 {
            break Err(DdcError::Timeout);
        }
        budget -= 1;
        match GmbusStatus::classify(mmio.read32(GMBUS2)) {
            GmbusStatus::SlaveNack => break Err(DdcError::SlaveNack),
            GmbusStatus::DataReady => {
                let mut dword = 0u32;
                for b in 0..4 {
                    if sent < data.len() {
                        dword |= (data[sent] as u32) << (8 * b);
                        sent += 1;
                    }
                }
                mmio.write32(GMBUS3, dword);
                compiler_fence(Ordering::SeqCst);
            }
            GmbusStatus::Done => {
                if sent == data.len() {
                    break Ok(());
                }
                break Err(DdcError::ShortTransfer);
            }
            GmbusStatus::Pending => core::hint::spin_loop(),
        }
    };
    gmbus_idle(mmio);
    result
}

// ── EDID over DDC ──────────────────────────────────────────────

/// Largest EDID this session buffers: base + 3 extensions —
/// the same capacity as the DP session.
pub const EDID_CAPACITY: usize = 512;

/// Read the sink's complete EDID: the base block runs the
/// GMBUS codec's own [`build_edid_read`] program; extension
/// blocks are byte-indexed reads, crossing the 256-byte
/// boundary with the E-DDC segment pointer (slave 0x30)
/// exactly as VESA E-EDID prescribes. Returns the buffer and
/// the valid byte count.
pub fn read_edid<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
) -> Result<([u8; EDID_CAPACITY], usize), DdcError> {
    let mut edid = [0u8; EDID_CAPACITY];
    let program = build_edid_read(pin, 128)?;
    run_read_program(mmio, program.gmbus0, program.gmbus1, &mut edid[..128])?;
    let extensions = (edid[126] as usize).min(EDID_CAPACITY / 128 - 1);
    for block in 1..=extensions {
        let offset = block * 128;
        if offset >= 256 {
            gmbus_write(mmio, pin, DDC_SLAVE_SEGMENT, &[(offset / 256) as u8])?;
        }
        gmbus_read(
            mmio,
            pin,
            DDC_SLAVE_EDID,
            (offset % 256) as u16,
            &mut edid[offset..offset + 128],
        )?;
    }
    Ok((edid, (extensions + 1) * 128))
}

// ── CTA HF-VSDB (SCDC capability discovery) ────────────────────

/// HDMI Forum Vendor-Specific Data Block OUI 0xC45DD8, on the
/// wire little-endian (D8 5D C4).
const HF_VSDB_OUI: [u8; 3] = [0xD8, 0x5D, 0xC4];

/// The SCDC-relevant capabilities a sink declares in its
/// CTA-861 HDMI Forum VSDB (payload layout: OUI[3], version,
/// max TMDS character rate in 5 MHz units, then the feature
/// byte: bit 7 SCDC_Present, bit 6 SCDC read-request capable,
/// bit 3 LTE_340Mcsc_scramble).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HfVsdb {
    /// An HF-VSDB was present at all.
    pub present: bool,
    /// The sink implements SCDC (required above 340 Mcsc).
    pub scdc_present: bool,
    /// The sink can raise SCDC read requests.
    pub scdc_read_request_capable: bool,
    /// The sink accepts scrambling at/below 340 Mcsc too.
    pub lte_340mcsc_scramble: bool,
    /// Max TMDS character rate in kHz (5 MHz units on the
    /// wire); 0 when the block carries no rate byte.
    pub max_tmds_char_rate_khz: u32,
}

/// Scan a complete EDID's CTA extensions for the HF-VSDB.
/// Data blocks are iterated per CTA-861: each extension's
/// block collection starts at byte 4 and ends at the DTD
/// offset (byte 2; 0 means the collection runs to the block
/// end). Other vendor blocks (including the HDMI Licensing
/// VSDB, OUI 0x000C03) are walked past, never matched.
pub fn parse_hf_vsdb(edid: &[u8]) -> HfVsdb {
    let mut out = HfVsdb::default();
    for block in edid.chunks_exact(128).skip(1) {
        if block[0] != 0x02 {
            continue; // not a CTA extension
        }
        let limit = match block[2] {
            0 => 127usize,
            n => (n as usize).min(127),
        };
        let mut pos = 4usize;
        while pos < limit {
            let header = block[pos];
            let tag = header >> 5;
            let len = (header & 0x1F) as usize;
            if pos + 1 + len > 128 {
                break;
            }
            let payload = &block[pos + 1..pos + 1 + len];
            if tag == 3 && len >= 5 && payload[..3] == HF_VSDB_OUI {
                out.present = true;
                out.max_tmds_char_rate_khz = (payload[4] as u32) * 5_000;
                if len >= 6 {
                    let features = payload[5];
                    out.scdc_present = features & 0x80 != 0;
                    out.scdc_read_request_capable = features & 0x40 != 0;
                    out.lte_340mcsc_scramble = features & 0x08 != 0;
                }
            }
            pos += 1 + len;
        }
    }
    out
}

// ── SCDC ───────────────────────────────────────────────────────

/// SCDC DDC slave address (HDMI spec; `drm_scdc_helper.h`).
pub const DDC_SLAVE_SCDC: u8 = 0x54;
/// SCDC sink version register.
pub const SCDC_SINK_VERSION: u8 = 0x01;
/// SCDC source version register (write 1 = SCDC revision 1).
pub const SCDC_SOURCE_VERSION: u8 = 0x02;
/// SCDC TMDS_CONFIG register.
pub const SCDC_TMDS_CONFIG: u8 = 0x20;
/// TMDS_CONFIG bit 0 — scrambling enable.
pub const TMDS_CONFIG_SCRAMBLING_ENABLE: u8 = 1 << 0;
/// TMDS_CONFIG bit 1 — TMDS bit clock ratio: set = 1/40,
/// clear = 1/10.
pub const TMDS_CONFIG_CLOCK_RATIO_1_40: u8 = 1 << 1;
/// SCDC SCRAMBLER_STATUS register; bit 0 = scrambling active.
pub const SCDC_SCRAMBLER_STATUS: u8 = 0x21;

/// The character rate above which the HDMI spec mandates
/// SCDC scrambling + the 1/40 clock ratio (340 Mcsc).
pub const SCRAMBLING_THRESHOLD_KHZ: u32 = 340_000;

/// Read one SCDC register (byte-indexed read at slave 0x54).
pub fn scdc_read<M: MmioWindow + ?Sized>(mmio: &M, pin: PinPair, reg: u8) -> Result<u8, DdcError> {
    let mut byte = [0u8; 1];
    gmbus_read(mmio, pin, DDC_SLAVE_SCDC, reg as u16, &mut byte)?;
    Ok(byte[0])
}

/// Write one SCDC register (`[register, value]`).
pub fn scdc_write<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
    reg: u8,
    value: u8,
) -> Result<(), DdcError> {
    gmbus_write(mmio, pin, DDC_SLAVE_SCDC, &[reg, value])
}

/// Configure SCDC scrambling for a >340 Mcsc stream:
/// read-modify-write TMDS_CONFIG with scrambling enabled and
/// the 1/40 clock ratio, observe the spec's settle window
/// (1 ms minimum after the ratio write, poll-counted), then
/// verify the sink reports scrambling active in
/// SCRAMBLER_STATUS. Callers driving <=340 Mcsc must not call
/// this at all — SCDC stays untouched there.
pub fn configure_scdc<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
    hf_vsdb: &HfVsdb,
) -> Result<(), HdmiError> {
    if !hf_vsdb.scdc_present {
        return Err(HdmiError::ScramblingUnsupported);
    }
    let config = scdc_read(mmio, pin, SCDC_TMDS_CONFIG)?;
    scdc_write(
        mmio,
        pin,
        SCDC_TMDS_CONFIG,
        config | TMDS_CONFIG_SCRAMBLING_ENABLE | TMDS_CONFIG_CLOCK_RATIO_1_40,
    )?;
    // The sink needs 1 ms (spec minimum) to apply the clock
    // ratio before the status is meaningful.
    for _ in 0..100_000 {
        core::hint::spin_loop();
    }
    let status = scdc_read(mmio, pin, SCDC_SCRAMBLER_STATUS)?;
    if status & TMDS_CONFIG_SCRAMBLING_ENABLE == 0 {
        return Err(HdmiError::ScramblingVerifyFailed);
    }
    Ok(())
}

// ── Infoframes ─────────────────────────────────────────────────

/// Infoframe checksum (HDMI 1.4 §5.3.5): the byte that makes
/// the whole frame — header included — sum to 0 mod 256.
fn infoframe_checksum(frame: &[u8], checksum_index: usize) -> u8 {
    let sum: u32 = frame
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != checksum_index)
        .map(|(_, b)| *b as u32)
        .sum();
    ((256 - (sum % 256)) % 256) as u8
}

/// The CEA-861 VIC for a mode, from its resolution + clock
/// band. 0 ("no VIC — timings govern") for modes outside the
/// table this driver pins; sinks accept VIC 0 with explicit
/// timings, and guessing a VIC for an unlisted mode would be
/// worse than none.
pub fn vic_for_mode(mode: &Mode) -> u8 {
    match (mode.h_active, mode.v_active) {
        (640, 480) => 1,
        // 720x480 is anamorphic (4:3 or 16:9 over the same
        // storage); the VIC split needs the pixel aspect,
        // which this mode shape does not carry — pin the 4:3
        // VIC, the sink still gets exact timings.
        (720, 480) => 2,
        (1280, 720) => 4,
        (1920, 1080) => {
            if mode.pixel_clock_khz >= 140_000 {
                16 // 1080p60
            } else if mode.pixel_clock_khz >= 70_000 {
                34 // 1080p30
            } else {
                0
            }
        }
        (3840, 2160) => {
            if mode.pixel_clock_khz >= 500_000 {
                97 // 2160p60
            } else {
                95 // 2160p30
            }
        }
        _ => 0,
    }
}

/// Pack the AVI infoframe for `mode` (17 bytes: 4 header +
/// 13 data), per CTA-861 / HDMI 1.4 §5.3.5 as Linux
/// `drivers/video/hdmi.c::hdmi_avi_infoframe_pack` lays it
/// out: RGB colorspace, active-format aspect present and
/// "same as picture", colorimetry by mode class (ITU-709 for
/// HD VICs, ITU-601 for SD), full quantization range for RGB,
/// the mode's VIC, no bars.
pub fn pack_avi_infoframe(mode: &Mode) -> [u8; 17] {
    let vic = vic_for_mode(mode);
    let picture_aspect: u8 = if mode.v_active != 0 && mode.h_active * 9 == mode.v_active * 16 {
        2 // 16:9
    } else if mode.h_active * 3 == mode.v_active * 4 || (mode.h_active, mode.v_active) == (720, 480)
    {
        1 // 4:3
    } else {
        0
    };
    let colorimetry: u8 = if vic >= 16 || vic == 4 {
        2 // ITU-709 (HD formats)
    } else if vic != 0 {
        1 // ITU-601 (SD formats)
    } else {
        0
    };
    let mut frame = [0u8; 17];
    frame[0] = 0x82; // AVI infoframe type
    frame[1] = 2; // version
    frame[2] = 13; // length
                   // DB1: colorspace RGB (0) << 5 | active-aspect present.
    frame[4] = 1 << 4;
    // DB2: colorimetry << 6 | picture aspect << 4 | active
    // aspect (8 = same as picture aspect ratio).
    frame[5] = (colorimetry << 6) | (picture_aspect << 4) | 8;
    // DB3: quantization range full (2) << 2 for RGB.
    frame[6] = 2 << 2;
    // DB4: the VIC.
    frame[7] = vic & 0x7F;
    frame[3] = infoframe_checksum(&frame, 3);
    frame
}

/// Pack the audio infoframe for a stream of `channels`
/// channels (14 bytes: 4 header + 10 data), per CTA-861 as
/// `hdmi_audio_infoframe_pack` lays it out: coding type and
/// sample frequency refer to the stream header (0) — they are
/// the HDA stream's facts, not the display's; the channel
/// count (channels - 1) and the channel allocation for the
/// standard 2.0 / 5.1 / 7.1 layouts are the display-side
/// facts the ELD established.
pub fn pack_audio_infoframe(channels: u8) -> [u8; 14] {
    let mut frame = [0u8; 14];
    frame[0] = 0x84; // audio infoframe type
    frame[1] = 1; // version
    frame[2] = 10; // length
                   // DB1: coding type 0 (stream header) << 4 | channel count.
    frame[4] = if channels >= 2 {
        (channels - 1) & 0x7
    } else {
        0
    };
    // DB4: channel allocation (CTA-861 speaker layouts).
    frame[7] = match channels {
        6 => 0x0B, // 5.1: FL FR LFE FC RL RR
        8 => 0x13, // 7.1: + RLC RRC
        _ => 0x00, // stereo / other: FL FR
    };
    frame[3] = infoframe_checksum(&frame, 3);
    frame
}

// ── DIP (Data Island Packet) banks ─────────────────────────────
//
// Per-transcoder banks at stride 0x1000 from the transcoder
// timing base (HSW map, i915 `intel_hdmi.c` / `i915_reg.h`):
// VIDEO_DIP_CTL +0x200, VIDEO_DIP_AVI_DATA +0x220. The write
// protocol is `hsw_write_infoframe`: clear the type's enable
// bit, write the data bank, set the enable bit. The DIP
// buffer is the frame with a 1-byte ECC hole at position 3
// (the checksum moves to position 4), zero-padded to the
// 32-byte VIDEO_DIP_DATA_SIZE so the hardware ECC covers the
// whole bank.

/// `VIDEO_DIP_CTL` offset from the transcoder timing base.
pub const VIDEO_DIP_CTL_OFFSET: u64 = 0x200;
/// `VIDEO_DIP_AVI_DATA` offset from the transcoder timing base.
pub const VIDEO_DIP_AVI_DATA_OFFSET: u64 = 0x220;
/// VIDEO_DIP_CTL AVI enable bit (HSW encoding).
pub const VIDEO_DIP_ENABLE_AVI: u32 = 1 << 12;
/// VIDEO_DIP_CTL GCP enable bit (HSW encoding).
pub const VIDEO_DIP_ENABLE_GCP: u32 = 1 << 16;
/// Total DIP data-bank size in bytes (8 dwords).
pub const VIDEO_DIP_DATA_SIZE: usize = 32;

/// Emit the AVI infoframe through the transcoder's DIP bank.
pub fn write_avi_infoframe<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder, frame: &[u8; 17]) {
    // DIP image: header bytes 0..2, ECC hole at 3, then the
    // frame from its checksum byte on.
    let mut image = [0u8; VIDEO_DIP_DATA_SIZE];
    image[0] = frame[0];
    image[1] = frame[1];
    image[2] = frame[2];
    image[4..4 + 14].copy_from_slice(&frame[3..17]);
    let ctl_off = trans.base() + VIDEO_DIP_CTL_OFFSET;
    let data_off = trans.base() + VIDEO_DIP_AVI_DATA_OFFSET;
    let cur = mmio.read32(ctl_off);
    mmio.write32(ctl_off, cur & !VIDEO_DIP_ENABLE_AVI);
    compiler_fence(Ordering::SeqCst);
    for (i, chunk) in image.chunks_exact(4).enumerate() {
        mmio.write32(
            data_off + (i as u64) * 4,
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
        );
    }
    compiler_fence(Ordering::SeqCst);
    mmio.write32(ctl_off, cur | VIDEO_DIP_ENABLE_AVI);
    // Posting read: the enable write must land before the
    // stream's first data island.
    let _ = mmio.read32(ctl_off);
    compiler_fence(Ordering::SeqCst);
}

/// Disable the DIP infoframes this session emits (AVI + GCP)
/// ahead of teardown.
pub fn disable_infoframes<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder) {
    let ctl_off = trans.base() + VIDEO_DIP_CTL_OFFSET;
    let cur = mmio.read32(ctl_off);
    mmio.write32(
        ctl_off,
        cur & !(VIDEO_DIP_ENABLE_AVI | VIDEO_DIP_ENABLE_GCP),
    );
    compiler_fence(Ordering::SeqCst);
}

// ── Session ────────────────────────────────────────────────────

/// Errors the HDMI session can return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HdmiError {
    /// DDC transfer failed.
    Ddc(DdcError),
    /// EDID parse failed.
    Edid(narf_graphics::edid::EdidError),
    /// The modeset orchestrator failed.
    Modeset(ModesetError),
    /// A >340 Mcsc mode was requested against a sink whose
    /// HF-VSDB does not declare SCDC — the mode cannot be
    /// driven legally, and is refused rather than degraded.
    ScramblingUnsupported,
    /// SCDC was configured but the sink did not report
    /// scrambling active in SCRAMBLER_STATUS.
    ScramblingVerifyFailed,
}

impl From<DdcError> for HdmiError {
    fn from(e: DdcError) -> Self {
        HdmiError::Ddc(e)
    }
}

impl From<GmbusError> for HdmiError {
    fn from(e: GmbusError) -> Self {
        HdmiError::Ddc(DdcError::Gmbus(e))
    }
}

impl From<ModesetError> for HdmiError {
    fn from(e: ModesetError) -> Self {
        HdmiError::Modeset(e)
    }
}

/// The result of the DDC-side sink probe: everything
/// [`activate`] needs, plus the raw EDID.
#[derive(Clone, Debug)]
pub struct HdmiSinkProbe {
    /// The DDI the sink hangs off.
    pub ddi: Ddi,
    /// The sink's preferred mode (first detailed timing).
    pub mode: Mode,
    /// The complete EDID bytes (`edid_len` valid).
    pub edid: [u8; EDID_CAPACITY],
    /// Valid byte count in `edid`.
    pub edid_len: usize,
    /// The sink's HF-VSDB capabilities.
    pub hf_vsdb: HfVsdb,
    /// The mode's character rate exceeds 340 Mcsc, so SCDC
    /// scrambling is mandatory for this stream.
    pub scrambling_required: bool,
}

/// A live HDMI connection.
#[derive(Clone, Debug)]
pub struct HdmiConnection {
    /// The DDI the sink hangs off.
    pub ddi: Ddi,
    /// The mode being scanned out.
    pub mode: Mode,
    /// Whether an ELD was published for this connection.
    pub audio_published: bool,
    /// Whether SCDC scrambling is active for this stream.
    pub scrambling: bool,
    /// The audio infoframe for this stream, packed for the
    /// HDA-side consumer that synthesises it on this hardware
    /// (see the module docs); `None` when the sink reported
    /// no audio.
    pub audio_infoframe: Option<[u8; 14]>,
}

/// Convert the EDID's preferred detailed timing into the
/// modeset's `Mode` shape (the same field mapping the DP
/// session uses).
fn mode_from_edid(edid_raw: &[u8]) -> Result<Mode, HdmiError> {
    let edid = narf_graphics::edid::Edid::parse(&edid_raw[..128]).map_err(HdmiError::Edid)?;
    let d = edid.preferred_timing().map_err(HdmiError::Edid)?;
    Ok(Mode {
        pixel_clock_khz: d.pixel_clock_khz,
        h_active: d.h_active,
        h_total: d.h_active + d.h_blanking,
        h_sync_start: d.h_active + d.h_sync_offset,
        h_sync_end: d.h_active + d.h_sync_offset + d.h_sync_width,
        v_active: d.v_active,
        v_total: d.v_active + d.v_blanking,
        v_sync_start: d.v_active + d.v_sync_offset,
        v_sync_end: d.v_active + d.v_sync_offset + d.v_sync_width,
        h_sync_positive: d.h_sync_positive,
        v_sync_positive: d.v_sync_positive,
    })
}

/// Phase 1 of a connect: run the DDC conversation — read the
/// complete EDID over GMBUS and derive the mode and the
/// sink's SCDC capabilities. No display registers are touched
/// beyond the GMBUS block.
pub fn probe_sink<M: MmioWindow + ?Sized>(mmio: &M, ddi: Ddi) -> Result<HdmiSinkProbe, HdmiError> {
    let pin = pin_pair_for(ddi).ok_or(DdcError::NoPinPair)?;
    let (edid, edid_len) = read_edid(mmio, pin)?;
    let mode = mode_from_edid(&edid[..edid_len])?;
    let hf_vsdb = parse_hf_vsdb(&edid[..edid_len]);
    Ok(HdmiSinkProbe {
        ddi,
        mode,
        edid,
        edid_len,
        hf_vsdb,
        scrambling_required: mode.pixel_clock_khz > SCRAMBLING_THRESHOLD_KHZ,
    })
}

/// Phase 2 of a connect: SCDC (when the rate demands it),
/// the TMDS modeset, the AVI infoframe, and audio
/// publication. Ordering follows the hardware rules: SCDC is
/// programmed while the port is still disabled (the
/// TRANS_DDI_FUNC_CTL scrambling bits are written inside the
/// modeset and must not change while the port is enabled),
/// and the ELD lands in the shared sink *before* the codec
/// path enables and ELD_VALID rises — the same invariant the
/// DP session keeps.
pub fn activate<M: MmioWindow + ?Sized>(
    mmio: &M,
    probe: &HdmiSinkProbe,
    fb: &Framebuffer,
) -> Result<HdmiConnection, HdmiError> {
    let pin = pin_pair_for(probe.ddi).ok_or(DdcError::NoPinPair)?;
    let mut scrambling = false;
    if probe.scrambling_required {
        configure_scdc(mmio, pin, &probe.hf_vsdb)?;
        scrambling = true;
    }
    let mut modeset = Modeset::new(mmio, probe.ddi);
    let mode = modeset.modeset_hdmi(fb, &probe.mode, scrambling, scrambling)?;

    let frame = pack_avi_infoframe(&mode);
    write_avi_infoframe(mmio, Transcoder::A, &frame);

    let mut audio_published = false;
    let mut audio_infoframe = None;
    if let Some(publication) = build_eld(
        &probe.edid[..probe.edid_len],
        DisplayConnector::Hdmi,
        (probe.ddi as u64) + 1,
    ) {
        let channels = publication.lpcm_max_channels;
        publish_display_audio(sink_id_for(probe.ddi), publication);
        intel_gpu_audio::hdmi_audio_codec_enable(mmio, Transcoder::A, mode.pixel_clock_khz);
        intel_gpu_audio::set_eld_valid(mmio, Transcoder::A, true);
        audio_published = true;
        audio_infoframe = Some(pack_audio_infoframe(channels));
    }

    Ok(HdmiConnection {
        ddi: probe.ddi,
        mode,
        audio_published,
        scrambling,
        audio_infoframe,
    })
}

/// Full connect: [`probe_sink`] + [`activate`] composed, for
/// callers that already hold a framebuffer.
pub fn connect<M: MmioWindow + ?Sized>(
    mmio: &M,
    ddi: Ddi,
    fb: &Framebuffer,
) -> Result<HdmiConnection, HdmiError> {
    let probe = probe_sink(mmio, ddi)?;
    activate(mmio, &probe, fb)
}

/// Disconnect: silence audio (codec disable + sink clear) and
/// stop the infoframes before the pipeline comes down — the
/// DP session's ordering, for the same reason: no consumer
/// may act on an ELD whose display is already gone.
pub fn disconnect<M: MmioWindow + ?Sized>(mmio: &M, conn: &HdmiConnection) {
    if conn.audio_published {
        intel_gpu_audio::hdmi_audio_codec_disable(mmio, Transcoder::A);
        clear_display_audio(sink_id_for(conn.ddi));
    }
    disable_infoframes(mmio, Transcoder::A);
    let mut modeset = Modeset::new(mmio, conn.ddi);
    modeset.teardown();
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Sink-side fixtures for the HDMI-full lane (#1019).
    //!
    //! `HdmiSinkMmio` models the Gen12 display register block
    //! (same hardware behaviour rules as the DP lane's model:
    //! power-well STATE mirrors REQUEST, PIPECONF STATE mirrors
    //! ENABLE, DDI_BUF IDLE mirrors !ENABLE, the DPLL reads
    //! locked) plus a GMBUS block running real transactions
    //! against `GmbusSink` — an EDID store + SCDC register file
    //! that decodes the GMBUS1 program fields itself.
    //!
    //! Every protocol constant the sink speaks (GMBUS1 field
    //! positions, the SCDC register map, the CTA/HF-VSDB byte
    //! layout, the infoframe bytes) is written here from the
    //! HDMI/CTA specifications, not copied from the production
    //! side — the two are independent parties to the same
    //! conversation, and the byte-for-byte pins fail if either
    //! drifts.

    extern crate alloc;

    use super::*;
    use crate::intel_gpu_ddi::DDI_BUF_CTL_OFFSET;
    use crate::intel_gpu_gmbus::{GMBUS2_ACTIVE, GMBUS2_HW_RDY, GMBUS2_SATOER};
    use crate::intel_gpu_modeset::PixelFormat;
    use crate::intel_gpu_pipes::{Pipe as PipeIdx, PIPECONF_OFFSET, TRANS_DDI_FUNC_CTL_OFFSET};
    use crate::intel_gpu_pll::{dpll_cfgcr1, DPLL_CFGCR0_DPLL0};
    use alloc::collections::{BTreeMap, VecDeque};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── The sink ────────────────────────────────────────────────

    #[derive(Debug)]
    struct GmbusSink {
        edid: Vec<u8>,
        /// SCDC register file; SCRAMBLER_STATUS (0x21) mirrors
        /// TMDS_CONFIG bit 0 as a locking sink's does, unless
        /// `ignore_scrambling` is set.
        scdc: [u8; 256],
        segment: u8,
        index: u16,
        nack_all: bool,
        ignore_scrambling: bool,
        /// Active read: bytes still to deliver.
        read_queue: VecDeque<u8>,
        reading: bool,
        /// Active write: bytes collected so far.
        write_slave: u8,
        write_buf: Vec<u8>,
        write_expected: usize,
        writing: bool,
        nack: bool,
        /// Every GMBUS1 program, in order.
        programs: Vec<u32>,
        /// SCDC writes actually applied: (register, value).
        scdc_applied: Vec<(u8, u8)>,
        /// Every GMBUS5 index write.
        gmbus5_log: Vec<u32>,
    }

    impl GmbusSink {
        fn new(edid: Vec<u8>) -> Self {
            Self {
                edid,
                scdc: [0u8; 256],
                segment: 0,
                index: 0,
                nack_all: false,
                ignore_scrambling: false,
                read_queue: VecDeque::new(),
                reading: false,
                write_slave: 0,
                write_buf: Vec::new(),
                write_expected: 0,
                writing: false,
                nack: false,
                programs: Vec::new(),
                scdc_applied: Vec::new(),
                gmbus5_log: Vec::new(),
            }
        }

        fn on_gmbus5(&mut self, v: u32) {
            self.index = v as u16;
            self.gmbus5_log.push(v);
        }

        /// Decode a GMBUS1 program (fields per the PRM layout:
        /// slave [7:1], direction [0], byte count [24:16]) and
        /// stage the transfer.
        fn on_gmbus1(&mut self, program: u32) {
            self.programs.push(program);
            let slave = ((program >> 1) & 0x7F) as u8;
            let dir_read = program & 1 != 0;
            let count = ((program >> 16) & 0x1FF) as usize;
            self.nack = self.nack_all || !matches!(slave, 0x50 | 0x54 | 0x30);
            self.reading = false;
            self.writing = false;
            if self.nack {
                return;
            }
            if dir_read {
                self.read_queue.clear();
                match slave {
                    0x50 => {
                        let start = (self.segment as usize) * 256 + (self.index as usize);
                        for i in 0..count {
                            self.read_queue
                                .push_back(self.edid.get(start + i).copied().unwrap_or(0));
                        }
                    }
                    0x54 => {
                        let start = self.index as usize;
                        for i in 0..count {
                            self.read_queue
                                .push_back(self.scdc.get(start + i).copied().unwrap_or(0));
                        }
                    }
                    _ => {}
                }
                self.reading = true;
            } else {
                self.write_slave = slave;
                self.write_buf.clear();
                self.write_expected = count;
                self.writing = true;
                if count == 0 {
                    self.apply_write();
                }
            }
        }

        fn gmbus2(&self) -> u32 {
            if self.nack {
                return GMBUS2_SATOER | GMBUS2_ACTIVE;
            }
            if self.reading && !self.read_queue.is_empty() {
                return GMBUS2_HW_RDY | GMBUS2_ACTIVE;
            }
            if self.writing && self.write_buf.len() < self.write_expected {
                return GMBUS2_HW_RDY | GMBUS2_ACTIVE;
            }
            0 // ACTIVE clear: done
        }

        fn on_gmbus3_read(&mut self) -> u32 {
            let mut v = 0u32;
            for b in 0..4 {
                if let Some(byte) = self.read_queue.pop_front() {
                    v |= (byte as u32) << (8 * b);
                }
            }
            v
        }

        fn on_gmbus3_write(&mut self, v: u32) {
            if !self.writing {
                return;
            }
            for b in 0..4 {
                if self.write_buf.len() < self.write_expected {
                    self.write_buf.push((v >> (8 * b)) as u8);
                }
            }
            if self.write_buf.len() == self.write_expected {
                self.apply_write();
            }
        }

        fn apply_write(&mut self) {
            match self.write_slave {
                0x54 => {
                    if self.write_buf.len() >= 2 {
                        let (reg, value) = (self.write_buf[0], self.write_buf[1]);
                        self.scdc[reg as usize] = value;
                        self.scdc_applied.push((reg, value));
                        if reg == 0x20 && !self.ignore_scrambling {
                            // A locking sink: SCRAMBLER_STATUS
                            // bit 0 follows the enable.
                            self.scdc[0x21] = value & 1;
                        }
                    }
                }
                0x30 => {
                    if !self.write_buf.is_empty() {
                        self.segment = self.write_buf[0];
                    }
                }
                _ => {}
            }
        }

        /// Slave addresses of every staged program, in order.
        fn slaves_touched(&self) -> Vec<u8> {
            self.programs
                .iter()
                .map(|p| ((p >> 1) & 0x7F) as u8)
                .collect()
        }
    }

    // ── The MMIO register model ─────────────────────────────────

    const PWR_WELL_CTL2: u64 = 0x4_5404;
    const DPLL0_ENABLE: u64 = 0x4_6010;
    const PLL_POWER_STATE: u32 = 1 << 26;
    const PLL_LOCK: u32 = 1 << 30;

    #[derive(Debug)]
    pub struct HdmiSinkMmio {
        regs: RefCell<BTreeMap<u64, u32>>,
        pub writes: RefCell<Vec<(u64, u32)>>,
        sink: RefCell<GmbusSink>,
        ddi: Ddi,
    }

    impl HdmiSinkMmio {
        fn new(ddi: Ddi, sink: GmbusSink) -> Self {
            // DSSM strap: 19.2 MHz (field 1), so the modeset's
            // reference-family read (Q6, #1024) selects the
            // 19.2/38.4 family the WRPLL pins below assume.
            let mut regs = BTreeMap::new();
            regs.insert(crate::intel_gpu_pll::DSSM, 1u32 << 29);
            Self {
                regs: RefCell::new(regs),
                writes: RefCell::new(Vec::new()),
                sink: RefCell::new(sink),
                ddi,
            }
        }

        fn stored(&self, off: u64) -> u32 {
            self.regs.borrow().get(&off).copied().unwrap_or(0)
        }

        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }

        fn write_position(&self, off: u64) -> Option<usize> {
            self.writes.borrow().iter().position(|(o, _)| *o == off)
        }
    }

    impl MmioWindow for HdmiSinkMmio {
        fn read32(&self, off: u64) -> u32 {
            if off == GMBUS2 {
                return self.sink.borrow().gmbus2();
            }
            if off == GMBUS3 {
                return self.sink.borrow_mut().on_gmbus3_read();
            }
            let v = self.stored(off);
            if off == PWR_WELL_CTL2 {
                return v | ((v & 0xAAAA_AAAA) >> 1);
            }
            if off == DPLL0_ENABLE {
                return v | PLL_POWER_STATE | PLL_LOCK;
            }
            let pipeconf_offs = [
                PipeIdx::A.base() + PIPECONF_OFFSET,
                Transcoder::A.conf_base() + PIPECONF_OFFSET,
            ];
            if pipeconf_offs.contains(&off) {
                use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_STATE};
                let state = if v & PIPECONF_ENABLE != 0 {
                    PIPECONF_STATE
                } else {
                    0
                };
                return (v & !PIPECONF_STATE) | state;
            }
            if off == self.ddi.base() + DDI_BUF_CTL_OFFSET {
                use crate::intel_gpu_ddi::{DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS};
                let idle = if v & DDI_BUF_CTL_ENABLE != 0 {
                    0
                } else {
                    DDI_BUF_CTL_IDLE_STATUS
                };
                return (v & !DDI_BUF_CTL_IDLE_STATUS) | idle;
            }
            v
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            self.regs.borrow_mut().insert(off, val);
            match off {
                GMBUS5 => self.sink.borrow_mut().on_gmbus5(val),
                GMBUS1 => self.sink.borrow_mut().on_gmbus1(val),
                GMBUS3 => self.sink.borrow_mut().on_gmbus3_write(val),
                _ => {}
            }
        }
    }

    // ── EDID fixtures ───────────────────────────────────────────

    /// One detailed-timing descriptor, E-EDID §3.10 field
    /// layout (the same independent transcription the DP
    /// lane's fixture carries).
    #[allow(clippy::too_many_arguments)]
    fn detailed_timing(
        out: &mut [u8],
        pclk_khz: u32,
        h_active: u16,
        h_blank: u16,
        h_sync_off: u16,
        h_sync_w: u16,
        v_active: u16,
        v_blank: u16,
        v_sync_off: u16,
        v_sync_w: u16,
    ) {
        let pclk_10k = (pclk_khz / 10) as u16;
        out[0] = pclk_10k as u8;
        out[1] = (pclk_10k >> 8) as u8;
        out[2] = h_active as u8;
        out[3] = h_blank as u8;
        out[4] = (((h_active >> 8) as u8 & 0xF) << 4) | ((h_blank >> 8) as u8 & 0xF);
        out[5] = v_active as u8;
        out[6] = v_blank as u8;
        out[7] = (((v_active >> 8) as u8 & 0xF) << 4) | ((v_blank >> 8) as u8 & 0xF);
        out[8] = h_sync_off as u8;
        out[9] = h_sync_w as u8;
        out[10] = ((v_sync_off as u8 & 0xF) << 4) | (v_sync_w as u8 & 0xF);
        out[11] = (((h_sync_off >> 8) as u8 & 0x3) << 6)
            | (((h_sync_w >> 8) as u8 & 0x3) << 4)
            | (((v_sync_off >> 4) as u8 & 0x3) << 2)
            | ((v_sync_w >> 4) as u8 & 0x3);
        out[12] = 52;
        out[13] = 29;
        out[17] = 0x1E; // digital separate sync, +H +V
    }

    #[derive(Copy, Clone, PartialEq, Eq)]
    enum HfFixture {
        /// No HF-VSDB block at all.
        Absent,
        /// HF-VSDB present, SCDC_Present clear.
        NoScdc,
        /// HF-VSDB present with SCDC_Present set.
        Scdc,
    }

    /// Build a complete EDID (base + CTA extension) for an
    /// HDMI sink. The CTA carries, in order: an audio data
    /// block (LPCM + AC-3 SADs), the HDMI Licensing VSDB
    /// (OUI 0x000C03 — a decoy the HF parser must walk past),
    /// a speaker-allocation block, and (unless `hf` is
    /// Absent) the HDMI Forum VSDB LAST, so capability
    /// discovery has to iterate the whole collection.
    fn fixture_edid_hdmi(
        pclk_khz: u32,
        h_active: u16,
        h_blank: u16,
        v_active: u16,
        v_blank: u16,
        hf: HfFixture,
    ) -> Vec<u8> {
        let mut e = alloc::vec![0u8; 256];
        e[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        let mfr: u16 = (14 << 10) | (1 << 5) | 18; // "NAR"
        e[8] = (mfr >> 8) as u8;
        e[9] = mfr as u8;
        e[10] = 0x34;
        e[11] = 0x12;
        e[18] = 1;
        e[19] = 4;
        e[126] = 1;
        detailed_timing(
            &mut e[0x36..0x36 + 18],
            pclk_khz,
            h_active,
            h_blank,
            88,
            44,
            v_active,
            v_blank,
            4,
            5,
        );
        let cta = 128usize;
        e[cta] = 0x02;
        e[cta + 1] = 3;
        e[cta + 3] = 0x40; // basic audio
        let mut p = cta + 4;
        // Audio data block: LPCM 2ch SAD + AC-3 6ch SAD.
        e[p] = (1 << 5) | 6;
        p += 1;
        e[p] = (1 << 3) | 1;
        e[p + 1] = 0x7F;
        e[p + 2] = 0x07;
        p += 3;
        e[p] = (2 << 3) | 5;
        e[p + 1] = 0x07;
        e[p + 2] = 0x00;
        p += 3;
        p += 1;
        // HDMI Licensing VSDB (tag 3, OUI 03 0C 00 LSB-first).
        e[p] = (3 << 5) | 5;
        e[p + 1] = 0x03;
        e[p + 2] = 0x0C;
        e[p + 3] = 0x00;
        e[p + 4] = 0x10; // source physical address 1.0.0.0
        e[p + 5] = 0x00;
        p += 6;
        // Speaker allocation block.
        e[p] = (4 << 5) | 3;
        e[p + 1] = 0x01;
        p += 1 + 3;
        if hf != HfFixture::Absent {
            // HDMI Forum VSDB (tag 3, OUI D8 5D C4): version 1,
            // max TMDS char rate 118 x 5 MHz = 590 MHz, feature
            // byte with SCDC_Present per the fixture kind.
            e[p] = (3 << 5) | 6;
            e[p + 1] = 0xD8;
            e[p + 2] = 0x5D;
            e[p + 3] = 0xC4;
            e[p + 4] = 1; // version
            e[p + 5] = 118; // max TMDS character rate
            e[p + 6] = if hf == HfFixture::Scdc { 0x80 } else { 0x00 };
            p += 7;
        }
        e[cta + 2] = (p - cta) as u8;
        for block in 0..2 {
            let start = block * 128;
            let sum: u32 = e[start..start + 127].iter().map(|&b| b as u32).sum();
            e[start + 127] = ((256 - (sum % 256)) % 256) as u8;
        }
        e
    }

    fn test_fb(stride_bytes: u32) -> Framebuffer {
        Framebuffer {
            phys_addr: 0x40_0000,
            stride_bytes,
            format: PixelFormat::Xrgb8888,
        }
    }

    fn mode_1080p() -> Mode {
        Mode {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_sync_start: 2008,
            h_sync_end: 2052,
            v_active: 1080,
            v_total: 1125,
            v_sync_start: 1084,
            v_sync_end: 1089,
            h_sync_positive: true,
            v_sync_positive: true,
        }
    }

    // ── Smokes ──────────────────────────────────────────────────

    fn smoke_hdmi_infoframe_packing() -> TestResult {
        // AVI for 1080p60 (VIC 16), pinned byte-for-byte
        // against the CTA-861 layout worked by hand:
        // DB1 = 0x10 (active aspect present), DB2 = 0xA8
        // (ITU-709 | 16:9 | same-as-picture), DB3 = 0x08
        // (full range), DB4 = 16, checksum 0x9F.
        let avi = pack_avi_infoframe(&mode_1080p());
        let want: [u8; 17] = [
            0x82, 0x02, 0x0D, 0x9F, 0x10, 0xA8, 0x08, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        if avi != want {
            return TestResult::Fail("AVI infoframe bytes must match the spec layout");
        }
        if avi.iter().map(|&b| b as u32).sum::<u32>() % 256 != 0 {
            return TestResult::Fail("AVI frame must sum to 0 mod 256");
        }
        // 4K60: VIC 97, checksum 0x4E.
        let mut mode4k = mode_1080p();
        mode4k.pixel_clock_khz = 594_000;
        mode4k.h_active = 3840;
        mode4k.v_active = 2160;
        let avi4k = pack_avi_infoframe(&mode4k);
        if avi4k[7] != 97 || avi4k[3] != 0x4E {
            return TestResult::Fail("4K60 AVI must carry VIC 97 + its checksum");
        }
        // Audio infoframes, byte-for-byte: stereo (CC=1,
        // CA=0x00, checksum 0x70) and 5.1 (CC=5, CA=0x0B,
        // checksum 0x61).
        let a2 = pack_audio_infoframe(2);
        if a2 != [0x84, 0x01, 0x0A, 0x70, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
            return TestResult::Fail("stereo audio infoframe bytes mismatch");
        }
        let a6 = pack_audio_infoframe(6);
        if a6 != [0x84, 0x01, 0x0A, 0x61, 0x05, 0, 0, 0x0B, 0, 0, 0, 0, 0, 0] {
            return TestResult::Fail("5.1 audio infoframe bytes mismatch");
        }
        if a6.iter().map(|&b| b as u32).sum::<u32>() % 256 != 0 {
            return TestResult::Fail("audio frame must sum to 0 mod 256");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hdmi_infoframe_packing);

    fn smoke_hf_vsdb_parse() -> TestResult {
        let edid = fixture_edid_hdmi(594_000, 3840, 560, 2160, 90, HfFixture::Scdc);
        let hf = parse_hf_vsdb(&edid);
        if !hf.present || !hf.scdc_present {
            return TestResult::Fail("HF-VSDB with SCDC must parse past the decoy VSDB");
        }
        if hf.max_tmds_char_rate_khz != 590_000 {
            return TestResult::Fail("max TMDS rate must decode 118 x 5 MHz");
        }
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::NoScdc);
        let hf = parse_hf_vsdb(&edid);
        if !hf.present || hf.scdc_present {
            return TestResult::Fail("HF-VSDB without the SCDC bit must report no SCDC");
        }
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Absent);
        if parse_hf_vsdb(&edid).present {
            return TestResult::Fail("no HF-VSDB must report absent");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hf_vsdb_parse);

    fn smoke_hdmi_1080p_connect_no_scdc_traffic() -> TestResult {
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Scdc);
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        let conn = match connect(&mmio, Ddi::B, &test_fb(8192)) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("1080p connect over the sink model must succeed"),
        };
        if conn.mode.h_active != 1920 || conn.mode.v_active != 1080 || conn.scrambling {
            return TestResult::Fail("1080p connection must carry the EDID mode, unscrambled");
        }
        // The base-block read ran the GMBUS codec's own
        // program for DDI B / 128 bytes, byte-for-byte:
        // SW_CLR_INT|SW_RDY|ENT|STO|count 128|slave 0x50|read.
        let sink = mmio.sink.borrow();
        if sink.programs.first() != Some(&0xE880_00A1) {
            return TestResult::Fail("first GMBUS program must be the codec EDID read");
        }
        // A <=340 Mcsc mode must not touch SCDC at all.
        if sink.slaves_touched().contains(&DDC_SLAVE_SCDC) || !sink.scdc_applied.is_empty() {
            return TestResult::Fail("HDMI 1.4-rate mode must not touch SCDC");
        }
        // The extension read was byte-indexed at 128.
        if !sink.gmbus5_log.contains(&128) {
            return TestResult::Fail("extension EDID read must program GMBUS5 index 128");
        }
        drop(sink);
        // TRANS_DDI_FUNC_CTL: HDMI binding for DDI B, no
        // scrambling / high-rate bits at 148.5 Mcsc.
        let func_ctl_off = Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        if mmio.writes_to(func_ctl_off) != alloc::vec![0x9000_0006] {
            return TestResult::Fail("TRANS_DDI_FUNC_CTL must be the plain HDMI binding");
        }
        // No M/N programming and no AUX traffic on an HDMI
        // modeset.
        use crate::intel_gpu_pipes::PIPE_DATA_M1_OFFSET;
        if !mmio
            .writes_to(Transcoder::A.base() + PIPE_DATA_M1_OFFSET)
            .is_empty()
        {
            return TestResult::Fail("HDMI modeset must not program DP M/N");
        }
        // The WRPLL rows for 148.5 MHz (19.2 MHz family):
        // CFGCR0 = int 0x173 | frac 0x2000, CFGCR1 = 0xE87.
        if mmio.writes_to(DPLL_CFGCR0_DPLL0) != alloc::vec![0x0080_0173] {
            return TestResult::Fail("CFGCR0 must carry the 148.5 MHz WRPLL solution");
        }
        if mmio.writes_to(dpll_cfgcr1(DPLL_CFGCR0_DPLL0)) != alloc::vec![0xE87] {
            return TestResult::Fail("CFGCR1 must carry the 148.5 MHz WRPLL dividers");
        }
        // DIP: AVI bank dwords pinned (hole at byte 3), CTL
        // written disable-then-enable.
        let dip_data = Transcoder::A.base() + VIDEO_DIP_AVI_DATA_OFFSET;
        let dwords = mmio.writes_to(dip_data);
        if dwords.first() != Some(&0x000D_0282) {
            return TestResult::Fail("DIP dword 0 must be the AVI header with the ECC hole");
        }
        let dwords1 = mmio.writes_to(dip_data + 4);
        if dwords1.first() != Some(&0x08A8_109F) {
            return TestResult::Fail("DIP dword 1 must carry checksum + DB1..DB3");
        }
        let ctl_writes = mmio.writes_to(Transcoder::A.base() + VIDEO_DIP_CTL_OFFSET);
        if ctl_writes.len() != 2
            || ctl_writes[0] & VIDEO_DIP_ENABLE_AVI != 0
            || ctl_writes[1] & VIDEO_DIP_ENABLE_AVI == 0
        {
            return TestResult::Fail("DIP CTL must clear, then set, the AVI enable");
        }
        // Audio: ELD published with the HDMI connection type
        // (byte 5 bits[3:2] == 0) and the fixture's LPCM SAD.
        if !conn.audio_published {
            return TestResult::Fail("1080p sink with SADs must publish audio");
        }
        match narf_drivers_sound::display_audio::current_display_audio(sink_id_for(Ddi::B)) {
            Some(p) => {
                if p.eld_bytes()[5] & 0x0C != 0 {
                    return TestResult::Fail("ELD connection type must be HDMI (0)");
                }
                if p.lpcm_max_channels != 2 || p.sad_count != 2 {
                    return TestResult::Fail("ELD must carry the fixture SADs");
                }
            }
            None => return TestResult::Fail("connect must publish the ELD"),
        }
        if conn.audio_infoframe != Some(pack_audio_infoframe(2)) {
            return TestResult::Fail("connection must carry the stereo audio infoframe");
        }
        // AUD_CFG carries the 148.5 MHz pixel-clock code (9)
        // latched with N_PROG_ENABLE.
        let cfg_writes = mmio.writes_to(intel_gpu_audio::aud_cfg_off(Transcoder::A));
        if !cfg_writes.contains(&((9 << 16) | intel_gpu_audio::AUD_CONFIG_N_PROG_ENABLE)) {
            return TestResult::Fail("AUD_CFG must carry pixel-clock 9 + PROG_ENABLE");
        }
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_1080p_connect_no_scdc_traffic
    );

    fn smoke_hdmi_4k60_scdc_scrambling() -> TestResult {
        let edid = fixture_edid_hdmi(594_000, 3840, 560, 2160, 90, HfFixture::Scdc);
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        let probe = match probe_sink(&mmio, Ddi::B) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("4K60 probe must succeed"),
        };
        if !probe.scrambling_required || !probe.hf_vsdb.scdc_present {
            return TestResult::Fail("594 MHz against an SCDC sink must require scrambling");
        }
        let conn = match activate(&mmio, &probe, &test_fb(16384)) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("4K60 activate must succeed"),
        };
        if !conn.scrambling {
            return TestResult::Fail("4K60 connection must record scrambling");
        }
        // SCDC: TMDS_CONFIG written once with scrambling +
        // 1/40 ratio (0x03), before the modeset bound the
        // transcoder.
        let sink = mmio.sink.borrow();
        if sink.scdc_applied != alloc::vec![(SCDC_TMDS_CONFIG, 0x03)] {
            return TestResult::Fail("SCDC TMDS_CONFIG must be written 0x03 exactly once");
        }
        drop(sink);
        let scdc_pos = mmio
            .writes
            .borrow()
            .iter()
            .position(|(o, v)| *o == GMBUS1 && ((*v >> 1) & 0x7F) == DDC_SLAVE_SCDC as u32);
        let func_pos = mmio.write_position(Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET);
        match (scdc_pos, func_pos) {
            (Some(s), Some(f)) if s < f => {}
            _ => return TestResult::Fail("SCDC must be configured before TRANS_DDI_FUNC_CTL"),
        }
        // Func ctl carries both HDMI high-rate bits.
        let func_ctl_off = Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        if mmio.writes_to(func_ctl_off) != alloc::vec![0x9000_0017] {
            return TestResult::Fail("TRANS_DDI_FUNC_CTL must set scrambling + high char rate");
        }
        // WRPLL for 594 MHz: CFGCR0 int 0x1D0 frac 0x0800,
        // CFGCR1 0x44B.
        if mmio.writes_to(DPLL_CFGCR0_DPLL0) != alloc::vec![0x0020_01D0] {
            return TestResult::Fail("CFGCR0 must carry the 594 MHz WRPLL solution");
        }
        if mmio.writes_to(dpll_cfgcr1(DPLL_CFGCR0_DPLL0)) != alloc::vec![0x44B] {
            return TestResult::Fail("CFGCR1 must carry the 594 MHz WRPLL dividers");
        }
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_4k60_scdc_scrambling
    );

    fn smoke_hdmi_4k60_without_scdc_refused() -> TestResult {
        let edid = fixture_edid_hdmi(594_000, 3840, 560, 2160, 90, HfFixture::NoScdc);
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        match connect(&mmio, Ddi::B, &test_fb(16384)) {
            Err(HdmiError::ScramblingUnsupported) => {}
            _ => return TestResult::Fail(">340 Mcsc without SCDC must be refused"),
        }
        // Nothing was programmed: no SCDC traffic, no func
        // ctl, no DIP.
        let sink = mmio.sink.borrow();
        if sink.slaves_touched().contains(&DDC_SLAVE_SCDC) {
            return TestResult::Fail("a refused mode must not touch SCDC");
        }
        drop(sink);
        if !mmio
            .writes_to(Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET)
            .is_empty()
        {
            return TestResult::Fail("a refused mode must not reach the modeset");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_4k60_without_scdc_refused
    );

    fn smoke_hdmi_scdc_verify_failure() -> TestResult {
        let edid = fixture_edid_hdmi(594_000, 3840, 560, 2160, 90, HfFixture::Scdc);
        let mut sink = GmbusSink::new(edid);
        sink.ignore_scrambling = true; // never reports status
        let mmio = HdmiSinkMmio::new(Ddi::B, sink);
        match connect(&mmio, Ddi::B, &test_fb(16384)) {
            Err(HdmiError::ScramblingVerifyFailed) => {}
            _ => return TestResult::Fail("unverified scrambling must fail the connect"),
        }
        if mmio.sink.borrow().scdc_applied != alloc::vec![(SCDC_TMDS_CONFIG, 0x03)] {
            return TestResult::Fail("the config write must have been attempted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hdmi_scdc_verify_failure);

    fn smoke_hdmi_sink_nack() -> TestResult {
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Scdc);
        let mut sink = GmbusSink::new(edid);
        sink.nack_all = true;
        let mmio = HdmiSinkMmio::new(Ddi::B, sink);
        match probe_sink(&mmio, Ddi::B) {
            Err(HdmiError::Ddc(DdcError::SlaveNack)) => TestResult::Pass,
            _ => TestResult::Fail("a NACKing sink must surface SlaveNack"),
        }
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hdmi_sink_nack);

    fn smoke_hdmi_edid_segment_pointer() -> TestResult {
        // A 4-block EDID (base + CTA + two filler extensions):
        // blocks past 256 bytes ride the E-DDC segment
        // pointer.
        let mut edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Scdc);
        edid[126] = 3;
        edid.resize(512, 0);
        // Byte 126 lives in block 0, so its checksum moves
        // with the extension count; blocks 2/3 are new.
        for block in [0usize, 2, 3] {
            let start = block * 128;
            if block >= 2 {
                edid[start] = 0x00; // filler extension tag
                edid[start + 1] = block as u8;
            }
            let sum: u32 = edid[start..start + 127].iter().map(|&b| b as u32).sum();
            edid[start + 127] = ((256 - (sum % 256)) % 256) as u8;
        }
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid.clone()));
        let probe = match probe_sink(&mmio, Ddi::B) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("4-block EDID probe must succeed"),
        };
        if probe.edid_len != 512 || probe.edid[..512] != edid[..] {
            return TestResult::Fail("all four EDID blocks must arrive verbatim");
        }
        if mmio.sink.borrow().segment != 1 {
            return TestResult::Fail("reads past 256 bytes must set segment pointer 1");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_edid_segment_pointer
    );

    fn smoke_hdmi_disconnect_tears_down() -> TestResult {
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Scdc);
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        let conn = match connect(&mmio, Ddi::B, &test_fb(8192)) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("connect must succeed"),
        };
        disconnect(&mmio, &conn);
        if narf_drivers_sound::display_audio::current_display_audio(sink_id_for(Ddi::B)).is_some() {
            return TestResult::Fail("disconnect must clear the ELD");
        }
        // DIP disabled: the last DIP CTL write has AVI clear.
        let ctl_writes = mmio.writes_to(Transcoder::A.base() + VIDEO_DIP_CTL_OFFSET);
        let last = ctl_writes[ctl_writes.len() - 1];
        if last & VIDEO_DIP_ENABLE_AVI != 0 {
            return TestResult::Fail("disconnect must disable the AVI DIP");
        }
        // The HDMI audio disable latched without N_VALUE_INDEX.
        let cfg_writes = mmio.writes_to(intel_gpu_audio::aud_cfg_off(Transcoder::A));
        let last = cfg_writes[cfg_writes.len() - 1];
        if last & intel_gpu_audio::AUD_CONFIG_N_PROG_ENABLE == 0
            || last & intel_gpu_audio::AUD_CONFIG_N_VALUE_INDEX != 0
        {
            return TestResult::Fail("HDMI audio disable must latch PROG_ENABLE only");
        }
        // DDI buffer disabled last by the teardown.
        let buf_writes = mmio.writes_to(Ddi::B.base() + DDI_BUF_CTL_OFFSET);
        use crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE;
        let last = buf_writes[buf_writes.len() - 1];
        if last & DDI_BUF_CTL_ENABLE != 0 {
            return TestResult::Fail("teardown must clear DDI_BUF_CTL ENABLE last");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_disconnect_tears_down
    );
}
