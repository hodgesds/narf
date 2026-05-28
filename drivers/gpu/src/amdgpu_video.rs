//! AMD VCN (Video Core Next) decode + encode scaffold.
//!
//! VCN is the unified video block on Vega+ APUs and modern Navi
//! discrete cards. It carries decode (H.264, HEVC, AV1, VP9) +
//! encode (H.264, HEVC, AV1) IP plus a JPEG decoder. Firmware-
//! driven: the host stages a frame's bitstream + reference
//! frames in VRAM, hands a packet pointing at them through a
//! ring, and the VCN engine writes the decoded frame back.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/amd/amdgpu/vcn_v4_0.c` — VCN 4.0
//!   (Phoenix / Strix family) ring + decode-buffer setup
//! - Linux `drivers/gpu/drm/amd/amdgpu/vcn_v3_0.c` — VCN 3.0
//!   (Navi2, RDNA2)
//! - Linux `drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c` — VCN 2.0
//!   (Renoir family)
//! - Linux `drivers/gpu/drm/amd/include/asic_reg/vcn/` — register
//!   offsets per IP version
//!
//! Linux is GPL-2.0-or-later (matches NARF); we adapt structural
//! patterns and register layouts.
//!
//! ## Codec coverage
//!
//! Codec   | Renoir  | Phoenix | Notes
//! --------|---------|---------|------------------------------
//! H.264   | dec+enc | dec+enc | baseline / main / high
//! HEVC    | dec+enc | dec+enc | main / main10
//! VP9     | dec     | dec     | profile 0 + profile 2
//! AV1     | -       | dec+enc | Phoenix is first AMD APU with AV1 enc
//! JPEG    | dec     | dec     | baseline
//!
//! ## Scope (Stage-4)
//!
//! - **IP-version table**: VCN per-family register windows + the
//!   ucode entry the PSP loaded.
//! - **Decode session**: per-stream state (codec, profile, ref
//!   frame list, sps/pps cache).
//! - **Submit packet codec**: emit the bitstream-buffer-descriptor
//!   packet (`VCN_DEC_CMD_DECODE`) the engine expects.
//! - **No MMIO**: pure codec + state machine. The driver core
//!   submits through `amdgpu_ring::Ring::submit`.

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu::Family;

// ── IP version table ─────────────────────────────────────────────

/// VCN IP version. Determines register offsets + codec coverage.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VcnVersion {
    /// VCN 2.0 — Renoir, Lucienne. H.264/HEVC/VP9 dec; H.264/HEVC
    /// enc. No AV1.
    V2_0,
    /// VCN 2.5 — Cezanne / Barcelo refresh. Same codecs as 2.0
    /// but a different firmware blob (green_sardine).
    V2_5,
    /// VCN 3.0 — Navi2 RDNA2.
    V3_0,
    /// VCN 4.0.5 — Phoenix / HawkPoint. AV1 dec + enc. Strix
    /// also uses this revision.
    V4_0_5,
}

impl VcnVersion {
    /// Resolve from a chip family. APU families map 1:1.
    pub fn from_family(f: Family) -> Option<Self> {
        match f {
            Family::Renoir => Some(VcnVersion::V2_0),
            Family::Navi2 => Some(VcnVersion::V3_0),
            Family::Navi3 => Some(VcnVersion::V4_0_5),
            Family::Phoenix => Some(VcnVersion::V4_0_5),
            // Vega has no VCN — it carries the older VCE / UVD
            // blocks; this scaffold doesn't cover them.
            Family::Vega => None,
            Family::Navi1 => Some(VcnVersion::V2_0),
        }
    }

    /// Codec coverage flags. Bitmask of [`CodecBits`].
    pub fn codec_caps(self) -> u32 {
        match self {
            VcnVersion::V2_0 => {
                CodecBits::H264_DEC | CodecBits::H264_ENC | CodecBits::HEVC_DEC
                    | CodecBits::HEVC_ENC | CodecBits::VP9_DEC | CodecBits::JPEG_DEC
            }
            VcnVersion::V2_5 => {
                CodecBits::H264_DEC | CodecBits::H264_ENC | CodecBits::HEVC_DEC
                    | CodecBits::HEVC_ENC | CodecBits::VP9_DEC | CodecBits::JPEG_DEC
            }
            VcnVersion::V3_0 => {
                CodecBits::H264_DEC | CodecBits::H264_ENC | CodecBits::HEVC_DEC
                    | CodecBits::HEVC_ENC | CodecBits::VP9_DEC | CodecBits::AV1_DEC
                    | CodecBits::JPEG_DEC
            }
            VcnVersion::V4_0_5 => {
                CodecBits::H264_DEC | CodecBits::H264_ENC | CodecBits::HEVC_DEC
                    | CodecBits::HEVC_ENC | CodecBits::VP9_DEC | CodecBits::AV1_DEC
                    | CodecBits::AV1_ENC | CodecBits::JPEG_DEC
            }
        }
    }

    /// `true` if this IP version can decode `codec`.
    pub fn supports_decode(self, codec: Codec) -> bool {
        let bit = codec.dec_bit();
        bit != 0 && (self.codec_caps() & bit) != 0
    }

    /// `true` if this IP version can encode `codec`.
    pub fn supports_encode(self, codec: Codec) -> bool {
        let bit = codec.enc_bit();
        bit != 0 && (self.codec_caps() & bit) != 0
    }
}

/// Codec capability bits.
#[derive(Debug)]
pub struct CodecBits;
impl CodecBits {
    pub const H264_DEC: u32 = 1 << 0;
    pub const H264_ENC: u32 = 1 << 1;
    pub const HEVC_DEC: u32 = 1 << 2;
    pub const HEVC_ENC: u32 = 1 << 3;
    pub const VP9_DEC: u32 = 1 << 4;
    pub const AV1_DEC: u32 = 1 << 5;
    pub const AV1_ENC: u32 = 1 << 6;
    pub const JPEG_DEC: u32 = 1 << 7;
}

/// One codec the VCN engine handles.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Codec {
    H264,
    Hevc,
    Vp9,
    Av1,
    Jpeg,
}

impl Codec {
    pub fn dec_bit(self) -> u32 {
        match self {
            Codec::H264 => CodecBits::H264_DEC,
            Codec::Hevc => CodecBits::HEVC_DEC,
            Codec::Vp9 => CodecBits::VP9_DEC,
            Codec::Av1 => CodecBits::AV1_DEC,
            Codec::Jpeg => CodecBits::JPEG_DEC,
        }
    }

    pub fn enc_bit(self) -> u32 {
        match self {
            Codec::H264 => CodecBits::H264_ENC,
            Codec::Hevc => CodecBits::HEVC_ENC,
            Codec::Av1 => CodecBits::AV1_ENC,
            // VP9 + JPEG decode-only on AMD VCN.
            _ => 0,
        }
    }
}

// ── Decode session ───────────────────────────────────────────────

/// Reference-frame slot. AV1 / HEVC keep up to 16 reference
/// frames around; H.264 keeps 8 max. We allocate a fixed-size
/// pool sized for AV1 + reuse.
pub const MAX_REF_FRAMES: usize = 16;

/// One reference-frame slot in the DPB (Decoded Picture Buffer).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RefFrameSlot {
    /// Phys address of the frame data in VRAM. 0 = unused.
    pub frame_phys: u64,
    /// Frame's display order (PTS-equivalent). Used by the
    /// post-decode reorder buffer.
    pub poc: i32,
    /// Is this slot a long-term reference (true) or short-term
    /// (false)? AV1 doesn't use this distinction; HEVC does.
    pub long_term: bool,
}

impl RefFrameSlot {
    pub const fn empty() -> Self {
        Self {
            frame_phys: 0,
            poc: 0,
            long_term: false,
        }
    }

    pub fn is_used(&self) -> bool {
        self.frame_phys != 0
    }
}

/// Decode session state. One per in-flight video stream.
#[derive(Clone, Debug)]
pub struct DecodeSession {
    pub codec: Codec,
    pub ip: VcnVersion,
    /// Coded width (samples).
    pub width: u32,
    /// Coded height (samples).
    pub height: u32,
    /// Reference-frame DPB.
    pub dpb: [RefFrameSlot; MAX_REF_FRAMES],
    /// Submitted-but-not-retired frame count. Used by the
    /// flow-controller to throttle decode submissions.
    pub in_flight: u32,
    /// Per-session sequence number for retire matching.
    pub next_seq: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VideoError {
    /// VCN IP doesn't support the requested codec.
    UnsupportedCodec,
    /// DPB is full — caller must wait for retire before
    /// submitting more frames.
    DpbFull,
    /// Bitstream buffer alignment violates VCN's 16-byte rule.
    BadAlignment,
    /// IP block isn't present on this family (VCN-less SoC).
    NoVcn,
}

impl DecodeSession {
    /// Open a new decode session against `ip`.
    pub fn new(ip: VcnVersion, codec: Codec, width: u32, height: u32) -> Result<Self, VideoError> {
        if !ip.supports_decode(codec) {
            return Err(VideoError::UnsupportedCodec);
        }
        Ok(Self {
            codec,
            ip,
            width,
            height,
            dpb: [RefFrameSlot::empty(); MAX_REF_FRAMES],
            in_flight: 0,
            next_seq: 1,
        })
    }

    /// Add a frame to the DPB. Returns the slot index. Fails if
    /// no slot is free.
    pub fn admit_ref(&mut self, phys: u64, poc: i32, long_term: bool) -> Result<usize, VideoError> {
        for (i, slot) in self.dpb.iter_mut().enumerate() {
            if !slot.is_used() {
                *slot = RefFrameSlot {
                    frame_phys: phys,
                    poc,
                    long_term,
                };
                return Ok(i);
            }
        }
        Err(VideoError::DpbFull)
    }

    /// Retire a reference frame by slot index — frees the DPB
    /// slot. Out-of-bounds is a no-op.
    pub fn retire_ref(&mut self, slot: usize) {
        if let Some(s) = self.dpb.get_mut(slot) {
            *s = RefFrameSlot::empty();
        }
    }

    /// How many DPB slots are currently used.
    pub fn dpb_used(&self) -> usize {
        self.dpb.iter().filter(|s| s.is_used()).count()
    }

    /// Allocate next per-session sequence id (used by the
    /// driver to match decode-complete fences).
    pub fn allocate_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        s
    }
}

// ── Decode submit packet ─────────────────────────────────────────

/// One decode-submit packet to write to the VCN ring. Linux uses
/// a struct of `IB_PACKET` headers + per-codec payloads; we
/// emit the dword stream directly.
///
/// Packet shape (all VCN versions; payload size varies by codec):
///
/// ```text
/// dw 0  : VCN_DEC_CMD_HEADER (PACKET_TYPE = 0x4, CMD = DECODE)
/// dw 1  : seq (host counter)
/// dw 2  : codec | profile
/// dw 3  : width (samples)
/// dw 4  : height (samples)
/// dw 5  : bitstream_phys_lo
/// dw 6  : bitstream_phys_hi
/// dw 7  : bitstream_size
/// dw 8  : output_phys_lo
/// dw 9  : output_phys_hi
/// dw10  : dpb_count
/// dw11..: dpb_phys[0..dpb_count] (lo / hi pairs)
/// ```
///
/// The actual VCN firmware reads its packet layout from an
/// SPS/PPS-resolved descriptor pointed to by the bitstream
/// header; this format is the *host-side* shape that the
/// kernel-mode driver hands to the firmware-driven decoder.
pub fn build_decode_packet(
    session: &mut DecodeSession,
    bitstream_phys: u64,
    bitstream_size: u32,
    output_phys: u64,
) -> Result<DecodePacket, VideoError> {
    if !session.ip.supports_decode(session.codec) {
        return Err(VideoError::UnsupportedCodec);
    }
    // VCN requires 16-byte bitstream / output alignment.
    if bitstream_phys & 0xF != 0 || output_phys & 0xF != 0 {
        return Err(VideoError::BadAlignment);
    }
    let seq = session.allocate_seq();
    let codec_word = codec_word_for(session.codec);
    let mut dws = Vec::with_capacity(11 + session.dpb_used() * 2);
    dws.push(VCN_DEC_CMD_HEADER);
    dws.push(seq as u32);
    dws.push(codec_word);
    dws.push(session.width);
    dws.push(session.height);
    dws.push(bitstream_phys as u32);
    dws.push((bitstream_phys >> 32) as u32);
    dws.push(bitstream_size);
    dws.push(output_phys as u32);
    dws.push((output_phys >> 32) as u32);
    let used_dpb: Vec<&RefFrameSlot> = session.dpb.iter().filter(|s| s.is_used()).collect();
    dws.push(used_dpb.len() as u32);
    for s in &used_dpb {
        dws.push(s.frame_phys as u32);
        dws.push((s.frame_phys >> 32) as u32);
    }
    session.in_flight += 1;
    Ok(DecodePacket { dws, seq })
}

/// Built decode packet ready for `amdgpu_ring::Ring::submit`.
#[derive(Clone, Debug)]
pub struct DecodePacket {
    pub dws: Vec<u32>,
    /// Host sequence — match against the retire interrupt.
    pub seq: u64,
}

/// Retire a decode packet. Caller's decode-complete IRQ matched
/// `seq`; we decrement the in-flight counter.
pub fn retire_decode(session: &mut DecodeSession, _seq: u64) {
    if session.in_flight > 0 {
        session.in_flight -= 1;
    }
}

/// VCN packet header — PACKET_TYPE=4 (IB), CMD=0x0 (DECODE).
/// VCN firmware reads this constant on every packet.
pub const VCN_DEC_CMD_HEADER: u32 = 0x4000_0000;

fn codec_word_for(c: Codec) -> u32 {
    // Per Linux `vcn_dec.h` codec enumeration (one byte each for
    // codec + profile + level + reserved).
    match c {
        Codec::H264 => 0x01, // AVC
        Codec::Hevc => 0x02, // HEVC
        Codec::Vp9 => 0x03,
        Codec::Av1 => 0x04,
        Codec::Jpeg => 0x05,
    }
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_vcn_version_per_family() -> TestResult {
        if VcnVersion::from_family(Family::Renoir) != Some(VcnVersion::V2_0) {
            return TestResult::Fail("Renoir VCN version wrong");
        }
        if VcnVersion::from_family(Family::Phoenix) != Some(VcnVersion::V4_0_5) {
            return TestResult::Fail("Phoenix VCN version wrong");
        }
        if VcnVersion::from_family(Family::Navi2) != Some(VcnVersion::V3_0) {
            return TestResult::Fail("Navi2 VCN version wrong");
        }
        if VcnVersion::from_family(Family::Vega) != None {
            return TestResult::Fail("Vega should report no VCN");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vcn_version_per_family);

    fn smoke_vcn_codec_capability_matrix() -> TestResult {
        // Phoenix has AV1 encode.
        if !VcnVersion::V4_0_5.supports_encode(Codec::Av1) {
            return TestResult::Fail("Phoenix should support AV1 enc");
        }
        // Renoir does NOT have AV1.
        if VcnVersion::V2_0.supports_decode(Codec::Av1) {
            return TestResult::Fail("Renoir wrongly claims AV1 dec");
        }
        // Navi2 has AV1 decode but no AV1 encode.
        if !VcnVersion::V3_0.supports_decode(Codec::Av1) {
            return TestResult::Fail("Navi2 should support AV1 dec");
        }
        if VcnVersion::V3_0.supports_encode(Codec::Av1) {
            return TestResult::Fail("Navi2 should not support AV1 enc");
        }
        // VP9 is decode-only everywhere.
        if VcnVersion::V4_0_5.supports_encode(Codec::Vp9) {
            return TestResult::Fail("VP9 enc not supported by VCN");
        }
        // H.264 dec everywhere.
        for v in [VcnVersion::V2_0, VcnVersion::V2_5, VcnVersion::V3_0, VcnVersion::V4_0_5] {
            if !v.supports_decode(Codec::H264) {
                return TestResult::Fail("missing H.264 dec on a version");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vcn_codec_capability_matrix);

    fn smoke_decode_session_rejects_unsupported() -> TestResult {
        // Renoir doesn't support AV1.
        match DecodeSession::new(VcnVersion::V2_0, Codec::Av1, 1920, 1080) {
            Err(VideoError::UnsupportedCodec) => {}
            _ => return TestResult::Fail("Renoir+AV1 should reject"),
        }
        // Phoenix + AV1 succeeds.
        let s = DecodeSession::new(VcnVersion::V4_0_5, Codec::Av1, 1920, 1080);
        if s.is_err() {
            return TestResult::Fail("Phoenix+AV1 should succeed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_decode_session_rejects_unsupported);

    fn smoke_dpb_admit_retire_round_trip() -> TestResult {
        let mut s = DecodeSession::new(VcnVersion::V4_0_5, Codec::Hevc, 3840, 2160).unwrap();
        // Admit 3 frames; check round-trip.
        let s1 = s.admit_ref(0x1_0000_0000, 0, false).expect("admit 1");
        let s2 = s.admit_ref(0x2_0000_0000, 1, false).expect("admit 2");
        let _s3 = s.admit_ref(0x3_0000_0000, 2, true).expect("admit 3");
        if s.dpb_used() != 3 {
            return TestResult::Fail("dpb_used after 3 admits");
        }
        // Retire middle; lifo-fill on next admit (slot 1 free).
        s.retire_ref(s2);
        if s.dpb_used() != 2 {
            return TestResult::Fail("dpb_used after retire");
        }
        let s4 = s.admit_ref(0x4_0000_0000, 3, false).expect("admit 4");
        if s4 != s2 {
            return TestResult::Fail("admit didn't reuse freed slot");
        }
        // Fill up DPB.
        for i in 0..(MAX_REF_FRAMES - 3) {
            s.admit_ref(0x5000_0000 + (i as u64) * 0x1000_0000, (i + 10) as i32, false)
                .expect("admit fill");
        }
        if s.admit_ref(0xFFFF_F000, 100, false) != Err(VideoError::DpbFull) {
            return TestResult::Fail("DPB-full not flagged");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpb_admit_retire_round_trip);

    fn smoke_build_decode_packet_layout() -> TestResult {
        let mut s = DecodeSession::new(VcnVersion::V4_0_5, Codec::Hevc, 1920, 1080).unwrap();
        s.admit_ref(0xA_0000_0000, 0, false).unwrap();
        s.admit_ref(0xB_0000_0000, 1, false).unwrap();
        let p = build_decode_packet(&mut s, 0x1000_0000, 1024, 0x2000_0000).expect("pkt");
        if p.dws.len() != 11 + 2 * 2 {
            return TestResult::Fail("packet length wrong");
        }
        if p.dws[0] != VCN_DEC_CMD_HEADER {
            return TestResult::Fail("header dword wrong");
        }
        if p.dws[2] != 0x02 {
            return TestResult::Fail("HEVC codec word wrong");
        }
        if p.dws[3] != 1920 || p.dws[4] != 1080 {
            return TestResult::Fail("dims wrong");
        }
        if p.dws[5] != 0x1000_0000 || p.dws[6] != 0 {
            return TestResult::Fail("bitstream phys wrong");
        }
        if p.dws[7] != 1024 {
            return TestResult::Fail("bitstream size wrong");
        }
        if p.dws[10] != 2 {
            return TestResult::Fail("dpb count wrong");
        }
        if s.in_flight != 1 {
            return TestResult::Fail("in_flight didn't advance");
        }
        retire_decode(&mut s, p.seq);
        if s.in_flight != 0 {
            return TestResult::Fail("in_flight didn't retire");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_build_decode_packet_layout);

    fn smoke_decode_packet_rejects_misaligned() -> TestResult {
        let mut s = DecodeSession::new(VcnVersion::V4_0_5, Codec::H264, 1280, 720).unwrap();
        // 1-byte misalignment.
        match build_decode_packet(&mut s, 0x1000_0001, 4096, 0x2000_0000) {
            Err(VideoError::BadAlignment) => {}
            _ => return TestResult::Fail("misaligned bitstream not rejected"),
        }
        match build_decode_packet(&mut s, 0x1000_0000, 4096, 0x2000_0001) {
            Err(VideoError::BadAlignment) => {}
            _ => return TestResult::Fail("misaligned output not rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_decode_packet_rejects_misaligned);
}
