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
                CodecBits::H264_DEC
                    | CodecBits::H264_ENC
                    | CodecBits::HEVC_DEC
                    | CodecBits::HEVC_ENC
                    | CodecBits::VP9_DEC
                    | CodecBits::JPEG_DEC
            }
            VcnVersion::V2_5 => {
                CodecBits::H264_DEC
                    | CodecBits::H264_ENC
                    | CodecBits::HEVC_DEC
                    | CodecBits::HEVC_ENC
                    | CodecBits::VP9_DEC
                    | CodecBits::JPEG_DEC
            }
            VcnVersion::V3_0 => {
                CodecBits::H264_DEC
                    | CodecBits::H264_ENC
                    | CodecBits::HEVC_DEC
                    | CodecBits::HEVC_ENC
                    | CodecBits::VP9_DEC
                    | CodecBits::AV1_DEC
                    | CodecBits::JPEG_DEC
            }
            VcnVersion::V4_0_5 => {
                CodecBits::H264_DEC
                    | CodecBits::H264_ENC
                    | CodecBits::HEVC_DEC
                    | CodecBits::HEVC_ENC
                    | CodecBits::VP9_DEC
                    | CodecBits::AV1_DEC
                    | CodecBits::AV1_ENC
                    | CodecBits::JPEG_DEC
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

/// VCN can drive up to 8K input frames (encode + decode). H.264
/// caps at 4K, HEVC at 8K, AV1 at 8K — per spec. We pin the
/// driver max here to flag silly inputs in `EncodeSession::new`.
pub const MAX_PIC_WIDTH: u32 = 8192;
pub const MAX_PIC_HEIGHT: u32 = 4320;

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
    /// Encode session got a reserved (zero) handle.
    BadHandle,
    /// Encode dimensions out of legal range or zero.
    BadDimensions,
    /// Encode ring has no room for the packet — caller must
    /// drain (via IH cookie + drain()) before pushing more.
    RingFull,
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

// ── VCN encoder session ───────────────────────────────────────────
//
// The encode path uses the same Falcon firmware as decode but a
// disjoint submission class. The encode ring (UVD_RB / VCN_ENC) is
// a separate write-pointer register from the decode ring; it carries
// PACKET_TYPE messages with the `VCN_ENC_CMD_*` opcodes:
//
//   VCN_ENC_CMD_NO_OP      = 0x00
//   VCN_ENC_CMD_END        = 0x01   end-of-IB sentinel
//   VCN_ENC_CMD_IB         = 0x02   indirect-buffer chain
//   VCN_ENC_CMD_FENCE      = 0x03   write fence + value at addr
//   VCN_ENC_CMD_TRAP       = 0x04   raise interrupt
//   VCN_ENC_CMD_REG_WRITE  = 0x0B   write a UVD/VCN MMIO reg from ring
//   VCN_ENC_CMD_REG_WAIT   = 0x0C   poll a UVD/VCN MMIO reg from ring
//
// References:
//   - Linux drivers/gpu/drm/amd/amdgpu/amdgpu_vcn.h:60-66 (opcodes)
//   - Linux drivers/gpu/drm/amd/amdgpu/amdgpu_vcn.c:923-980
//     (amdgpu_vcn_enc_get_create_msg — the firmware session-init IB)
//   - Linux drivers/gpu/drm/amd/amdgpu/vcn_v4_0.c:1768-1798
//     (vcn_v4_0_unified_ring_{get,set}_wptr)

pub const VCN_ENC_CMD_NO_OP: u32 = 0x0000_0000;
pub const VCN_ENC_CMD_END: u32 = 0x0000_0001;
pub const VCN_ENC_CMD_IB: u32 = 0x0000_0002;
pub const VCN_ENC_CMD_FENCE: u32 = 0x0000_0003;
pub const VCN_ENC_CMD_TRAP: u32 = 0x0000_0004;
pub const VCN_ENC_CMD_REG_WRITE: u32 = 0x0000_000B;
pub const VCN_ENC_CMD_REG_WAIT: u32 = 0x0000_000C;

/// One encode session: codec, dimensions, rate-control state, +
/// firmware-side handle the kernel obtained from CREATE_MSG.
#[derive(Clone, Debug)]
pub struct EncodeSession {
    pub ip: VcnVersion,
    pub codec: Codec,
    pub width: u32,
    pub height: u32,
    /// Target bitrate in bits per second (rate-control hint).
    pub bitrate_bps: u32,
    /// Firmware session handle. Assigned by the kernel before
    /// CREATE_MSG. The IB sent to the firmware echoes this back as
    /// `*ib_ptr[2]` (handle field).
    pub handle: u32,
    /// Next host-sequence to embed in a fence packet.
    next_seq: u64,
    /// In-flight encode packets (host hasn't yet seen the matching
    /// retire IH cookie).
    pub in_flight: u32,
    /// Whether the unified ring (decode+encode on the same ring)
    /// is in use (vcn_v4+) vs separate ring_enc[0] / ring_dec.
    pub unified_ring: bool,
}

impl EncodeSession {
    pub fn new(
        ip: VcnVersion,
        codec: Codec,
        width: u32,
        height: u32,
        bitrate_bps: u32,
        handle: u32,
    ) -> Result<Self, VideoError> {
        if !ip.supports_encode(codec) {
            return Err(VideoError::UnsupportedCodec);
        }
        if width == 0 || height == 0 || width > MAX_PIC_WIDTH || height > MAX_PIC_HEIGHT {
            return Err(VideoError::BadDimensions);
        }
        if handle == 0 {
            // Linux uses handles starting at 1; 0 is reserved.
            return Err(VideoError::BadHandle);
        }
        // vcn_v4+ uses a unified queue (one ring for both dec + enc).
        let unified_ring = matches!(ip, VcnVersion::V4_0_5);
        Ok(Self {
            ip,
            codec,
            width,
            height,
            bitrate_bps,
            handle,
            next_seq: 1,
            in_flight: 0,
            unified_ring,
        })
    }

    fn allocate_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        s
    }
}

/// Build the encode session-create IB. This is the first IB the
/// kernel sends after firmware bring-up; the firmware allocates
/// per-session state keyed by `handle` and signals success via the
/// fence packet at the end.
///
/// Adapted from `amdgpu_vcn.c::amdgpu_vcn_enc_get_create_msg`
/// (lines 923-980). Layout per Linux on a unified-queue VCN:
///
/// ```text
///   header: 0x18 0x00000001  ← session info
///   handle, addr_hi, addr_lo, 0
///   header: 0x14 0x00000002  ← task info
///   0x1c, 0, 0
///   header: 0x08 0x08000001  ← op initialize
///   (padding to ib_size_dw)
/// ```
///
/// When `with_checksum` is true the IB is wrapped in unified-ring
/// header + checksum bytes (vcn_v4+); the wrapper here just keeps
/// the dword layout faithful to Linux's IB construction.
pub fn build_encode_create_msg(
    session: &mut EncodeSession,
    feedback_phys: u64,
) -> Result<EncodePacket, VideoError> {
    if !session.ip.supports_encode(session.codec) {
        return Err(VideoError::UnsupportedCodec);
    }
    if feedback_phys & 0xF != 0 {
        return Err(VideoError::BadAlignment);
    }
    let mut dws: Vec<u32> = Vec::with_capacity(16);
    // session-info block (6 dws).
    dws.push(0x0000_0018);
    dws.push(0x0000_0001);
    dws.push(session.handle);
    dws.push((feedback_phys >> 32) as u32);
    dws.push(feedback_phys as u32);
    dws.push(0);
    // task-info block (5 dws).
    dws.push(0x0000_0014);
    dws.push(0x0000_0002);
    dws.push(0x0000_001c);
    dws.push(0);
    dws.push(0);
    // op-initialize block (2 dws).
    dws.push(0x0000_0008);
    dws.push(0x0800_0001);
    // Pad to 16 dws (Linux's `ib_size_dw = 16` baseline).
    while dws.len() < 16 {
        dws.push(0);
    }
    let seq = session.allocate_seq();
    session.in_flight += 1;
    Ok(EncodePacket {
        dws,
        seq,
        kind: EncodePacketKind::Create,
    })
}

/// Build an encode-frame IB. Carries the input raw frame phys
/// addr, target bitstream output, and rate-control parameters.
///
/// Layout adapted from `vcn_v4_0_enc_ring_emit_ib` /
/// `amdgpu_vcn_enc_get_destroy_msg` patterns — this is the
/// "encode one frame" subcommand the firmware accepts after a
/// successful CREATE_MSG. The dword shape here is the kernel-mode
/// host layout; the firmware's internal packet layout is opaque.
pub fn build_encode_frame_packet(
    session: &mut EncodeSession,
    raw_input_phys: u64,
    output_phys: u64,
    output_max_size: u32,
) -> Result<EncodePacket, VideoError> {
    if !session.ip.supports_encode(session.codec) {
        return Err(VideoError::UnsupportedCodec);
    }
    if raw_input_phys & 0xF != 0 || output_phys & 0xF != 0 {
        return Err(VideoError::BadAlignment);
    }
    if output_max_size == 0 {
        return Err(VideoError::BadDimensions);
    }
    let seq = session.allocate_seq();
    let codec_word = codec_word_for(session.codec);
    let mut dws = Vec::with_capacity(14);
    // session-info echo so the firmware can route the packet.
    dws.push(0x0000_0018);
    dws.push(session.handle);
    dws.push(codec_word);
    dws.push(session.width);
    dws.push(session.height);
    dws.push(session.bitrate_bps);
    // Input frame.
    dws.push(raw_input_phys as u32);
    dws.push((raw_input_phys >> 32) as u32);
    // Output buffer.
    dws.push(output_phys as u32);
    dws.push((output_phys >> 32) as u32);
    dws.push(output_max_size);
    // Op tag — encode_frame = 0x0800_0002.
    dws.push(0x0800_0002);
    // Fence dword pair — VCN_ENC_CMD_FENCE writes `seq` to a host
    // sysmem address. Caller fills the wptr-side fence target in a
    // separate envelope; we just record `seq` for completion match.
    dws.push(VCN_ENC_CMD_FENCE);
    dws.push(seq as u32);
    session.in_flight += 1;
    Ok(EncodePacket {
        dws,
        seq,
        kind: EncodePacketKind::Frame,
    })
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncodePacketKind {
    Create,
    Frame,
    Destroy,
}

/// Built encode packet ready for the encode ring.
#[derive(Clone, Debug)]
pub struct EncodePacket {
    pub dws: Vec<u32>,
    pub seq: u64,
    pub kind: EncodePacketKind,
}

/// Retire one encode packet. The IH dispatch matched `seq` so
/// the in-flight count drops by one.
pub fn retire_encode(session: &mut EncodeSession, _seq: u64) {
    if session.in_flight > 0 {
        session.in_flight -= 1;
    }
}

/// Build an encode session-destroy IB. Required before tearing
/// down the session so the firmware can release its per-session
/// state. The packet is a minimal sentinel pointing at the
/// session's handle + the op-destroy code.
pub fn build_encode_destroy_msg(session: &mut EncodeSession) -> Result<EncodePacket, VideoError> {
    if !session.ip.supports_encode(session.codec) {
        return Err(VideoError::UnsupportedCodec);
    }
    let mut dws = Vec::with_capacity(8);
    dws.push(0x0000_0018);
    dws.push(0x0000_0001);
    dws.push(session.handle);
    dws.push(0);
    dws.push(0);
    dws.push(0x0000_0008);
    dws.push(0x0800_0003); // op destroy
    dws.push(VCN_ENC_CMD_END);
    let seq = session.allocate_seq();
    session.in_flight += 1;
    Ok(EncodePacket {
        dws,
        seq,
        kind: EncodePacketKind::Destroy,
    })
}

// ── VCN encode ring (UVD_RB) ───────────────────────────────────────
//
// The encode ring is a circular buffer in GPU-visible sysmem; the
// driver writes packets at `wptr` and the firmware advances `rptr`.
// Hardware-side the `UVD_RB_WPTR` register holds the host-committed
// wptr; doorbell mode replaces it with a doorbell write that the
// FW polls.

/// Encode ring registers — offsets relative to the VCN0 IP block
/// base. Multiple rings exist (`UVD_RB_WPTR` .. `UVD_RB_WPTR4`);
/// the unified-queue VCNs (v4+) use ring 0 for both decode + encode.
pub const VCN_ENC_RING_RPTR_REL: u32 = 0x0;
pub const VCN_ENC_RING_WPTR_REL: u32 = 0x4;
pub const VCN_ENC_RING_BASE_LO_REL: u32 = 0x8;
pub const VCN_ENC_RING_BASE_HI_REL: u32 = 0xC;
pub const VCN_ENC_RING_SIZE_REL: u32 = 0x10;

/// One encode ring. Tracks the (rptr, wptr) head-tail pair the
/// firmware reads; the driver mirrors them in CPU memory so it
/// can wake-from-interrupt without re-reading MMIO.
#[derive(Clone, Debug)]
pub struct EncodeRing {
    /// Base GPU phys of the ring buffer (4 KiB aligned).
    pub ring_base_phys: u64,
    /// Ring size in bytes (must be power of two).
    pub ring_size_bytes: u32,
    /// Mirror of UVD_RB_WPTR in dwords.
    pub wptr_dw: u32,
    /// Mirror of UVD_RB_RPTR in dwords.
    pub rptr_dw: u32,
    /// `true` when doorbell mode is set up (UVD writes to a
    /// per-ring doorbell page instead of the host writing
    /// UVD_RB_WPTR).
    pub use_doorbell: bool,
}

impl EncodeRing {
    pub fn new(ring_base_phys: u64, ring_size_bytes: u32) -> Result<Self, VideoError> {
        if ring_base_phys & 0xFFF != 0 {
            return Err(VideoError::BadAlignment);
        }
        if ring_size_bytes == 0 || !ring_size_bytes.is_power_of_two() {
            return Err(VideoError::BadDimensions);
        }
        Ok(Self {
            ring_base_phys,
            ring_size_bytes,
            wptr_dw: 0,
            rptr_dw: 0,
            use_doorbell: false,
        })
    }

    /// Count of in-flight ring dwords (committed by host, not yet
    /// drained by firmware).
    pub fn in_flight_dw(&self) -> u32 {
        let mask = (self.ring_size_bytes / 4) - 1;
        self.wptr_dw.wrapping_sub(self.rptr_dw) & mask
    }

    /// Push a packet to the ring buffer (host-visible mirror).
    /// Real silicon writes the dwords into the ring's GPU phys
    /// page; this mirror tracks the wptr advance for tests.
    pub fn push(&mut self, packet: &EncodePacket) -> Result<(), VideoError> {
        let need = packet.dws.len() as u32;
        let mask = (self.ring_size_bytes / 4) - 1;
        let free = mask.wrapping_sub(self.in_flight_dw());
        if need > free {
            return Err(VideoError::RingFull);
        }
        self.wptr_dw = self.wptr_dw.wrapping_add(need) & mask;
        Ok(())
    }

    /// Mark `n_dw` dwords as drained — caller does this after the
    /// firmware bumps UVD_RB_RPTR (visible via an IH cookie + an
    /// RB_RPTR re-read).
    pub fn drain(&mut self, n_dw: u32) {
        let mask = (self.ring_size_bytes / 4) - 1;
        self.rptr_dw = self.rptr_dw.wrapping_add(n_dw) & mask;
    }
}

/// MMIO trait for the encode ring — same pattern as the PSP +
/// VMHUB Mmio traits.
pub trait VcnEncMmio {
    fn read(&mut self, vcn_base_plus_offset: u32) -> u32;
    fn write(&mut self, vcn_base_plus_offset: u32, value: u32);
}

/// Set up the encode ring registers — programs UVD_RB_BASE_LO/HI
/// + UVD_RB_SIZE so the firmware reads packets from the right
/// place. Adapted from `vcn_v4_0.c::vcn_v4_0_pause_dpg_mode`
/// register-init block (around line 1100-1108).
pub fn setup_encode_ring_regs<M: VcnEncMmio>(mmio: &mut M, vcn_base: u32, ring: &EncodeRing) {
    mmio.write(
        vcn_base + VCN_ENC_RING_BASE_LO_REL,
        ring.ring_base_phys as u32,
    );
    mmio.write(
        vcn_base + VCN_ENC_RING_BASE_HI_REL,
        (ring.ring_base_phys >> 32) as u32,
    );
    mmio.write(vcn_base + VCN_ENC_RING_SIZE_REL, ring.ring_size_bytes);
    // Reset rptr/wptr to 0 — firmware reads from there.
    mmio.write(vcn_base + VCN_ENC_RING_RPTR_REL, 0);
    mmio.write(vcn_base + VCN_ENC_RING_WPTR_REL, 0);
}

/// Commit the encode ring's wptr to silicon. Mirrors
/// `vcn_v4_0.c::vcn_v4_0_unified_ring_set_wptr` (line 1785-1798).
pub fn commit_encode_wptr<M: VcnEncMmio>(mmio: &mut M, vcn_base: u32, ring: &EncodeRing) {
    mmio.write(vcn_base + VCN_ENC_RING_WPTR_REL, ring.wptr_dw);
}

/// Read the firmware's current rptr — mirrors
/// `vcn_v4_0_unified_ring_get_wptr` but for the rptr-side. The
/// host calls this on an IH dispatch to figure out how many
/// dwords are now drainable.
pub fn read_encode_rptr<M: VcnEncMmio>(mmio: &mut M, vcn_base: u32) -> u32 {
    mmio.read(vcn_base + VCN_ENC_RING_RPTR_REL)
}

// Add error variant for the encode-ring path.
//
// VideoError already has `BadAlignment`, `BadDimensions`,
// `DpbFull`, `UnsupportedCodec`. We need `BadHandle` + `RingFull`.

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
        for v in [
            VcnVersion::V2_0,
            VcnVersion::V2_5,
            VcnVersion::V3_0,
            VcnVersion::V4_0_5,
        ] {
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
        let _s1 = s.admit_ref(0x1_0000_0000, 0, false).expect("admit 1");
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
            s.admit_ref(
                0x5000_0000 + (i as u64) * 0x1000_0000,
                (i + 10) as i32,
                false,
            )
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

    // ── Encode-path smokes ─────────────────────────────────────

    /// Mock MMIO that just records every write + responds 0 to every read.
    struct MockVcnMmio {
        writes: Vec<(u32, u32)>,
    }
    impl VcnEncMmio for MockVcnMmio {
        fn read(&mut self, _off: u32) -> u32 {
            0
        }
        fn write(&mut self, off: u32, val: u32) {
            self.writes.push((off, val));
        }
    }

    fn smoke_encode_session_rejects_av1_on_renoir() -> TestResult {
        match EncodeSession::new(VcnVersion::V2_0, Codec::Av1, 1920, 1080, 5_000_000, 1) {
            Err(VideoError::UnsupportedCodec) => {}
            _ => return TestResult::Fail("Renoir AV1 enc must reject"),
        }
        // Phoenix + AV1 succeeds.
        if EncodeSession::new(VcnVersion::V4_0_5, Codec::Av1, 1920, 1080, 5_000_000, 1).is_err() {
            return TestResult::Fail("Phoenix AV1 enc must succeed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_encode_session_rejects_av1_on_renoir);

    fn smoke_encode_session_rejects_zero_handle() -> TestResult {
        match EncodeSession::new(VcnVersion::V4_0_5, Codec::H264, 1920, 1080, 5_000_000, 0) {
            Err(VideoError::BadHandle) => {}
            _ => return TestResult::Fail("handle 0 must be rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_encode_session_rejects_zero_handle);

    fn smoke_build_encode_create_msg_layout() -> TestResult {
        let mut s = EncodeSession::new(VcnVersion::V4_0_5, Codec::H264, 1920, 1080, 5_000_000, 42)
            .expect("session");
        let p = build_encode_create_msg(&mut s, 0x1000_0000).expect("create");
        if p.dws.len() != 16 {
            return TestResult::Fail("create msg should be 16 dws");
        }
        // dw[2] is the session handle.
        if p.dws[2] != 42 {
            return TestResult::Fail("handle not echoed");
        }
        // dw[0] is the session-info length header.
        if p.dws[0] != 0x0000_0018 {
            return TestResult::Fail("session info header wrong");
        }
        if p.kind != EncodePacketKind::Create {
            return TestResult::Fail("packet kind wrong");
        }
        if s.in_flight != 1 {
            return TestResult::Fail("in_flight not bumped");
        }
        retire_encode(&mut s, p.seq);
        if s.in_flight != 0 {
            return TestResult::Fail("in_flight not drained");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_build_encode_create_msg_layout);

    fn smoke_build_encode_frame_packet_layout() -> TestResult {
        let mut s = EncodeSession::new(VcnVersion::V4_0_5, Codec::Hevc, 3840, 2160, 25_000_000, 7)
            .expect("session");
        let p =
            build_encode_frame_packet(&mut s, 0xCAFE_0000, 0xBEEF_0000, 0x10_0000).expect("frame");
        // dw[1] = handle, dw[2] = codec word, dw[3] = width, dw[4] = height.
        if p.dws[1] != 7 {
            return TestResult::Fail("handle wrong");
        }
        if p.dws[2] != 0x02 {
            return TestResult::Fail("HEVC codec word wrong");
        }
        if p.dws[3] != 3840 || p.dws[4] != 2160 {
            return TestResult::Fail("dims wrong");
        }
        // Last dword pair must be the fence cmd.
        let n = p.dws.len();
        if p.dws[n - 2] != VCN_ENC_CMD_FENCE {
            return TestResult::Fail("missing fence cmd");
        }
        if p.kind != EncodePacketKind::Frame {
            return TestResult::Fail("packet kind wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_build_encode_frame_packet_layout);

    fn smoke_encode_frame_rejects_misaligned() -> TestResult {
        let mut s = EncodeSession::new(VcnVersion::V4_0_5, Codec::H264, 1920, 1080, 5_000_000, 1)
            .expect("session");
        match build_encode_frame_packet(&mut s, 0xCAFE_0001, 0xBEEF_0000, 1024) {
            Err(VideoError::BadAlignment) => {}
            _ => return TestResult::Fail("misaligned input not rejected"),
        }
        match build_encode_frame_packet(&mut s, 0xCAFE_0000, 0xBEEF_0001, 1024) {
            Err(VideoError::BadAlignment) => {}
            _ => return TestResult::Fail("misaligned output not rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_encode_frame_rejects_misaligned);

    fn smoke_encode_ring_push_advances_wptr() -> TestResult {
        let mut r = EncodeRing::new(0x10_0000, 4096).expect("ring");
        if r.in_flight_dw() != 0 {
            return TestResult::Fail("ring not empty at init");
        }
        let mut s = EncodeSession::new(VcnVersion::V4_0_5, Codec::H264, 1280, 720, 1_000_000, 1)
            .expect("session");
        let p = build_encode_create_msg(&mut s, 0x2000_0000).expect("create");
        r.push(&p).expect("push");
        if r.in_flight_dw() != 16 {
            return TestResult::Fail("in_flight after push");
        }
        r.drain(16);
        if r.in_flight_dw() != 0 {
            return TestResult::Fail("drained back to 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_encode_ring_push_advances_wptr);

    fn smoke_encode_ring_full_rejects() -> TestResult {
        // Ring of 8 dwords (32 bytes). Push 7-dword packets twice
        // — second must fail (mask = 7).
        let mut r = EncodeRing::new(0x10_0000, 32).expect("ring");
        let pkt = EncodePacket {
            dws: alloc::vec![0; 6],
            seq: 1,
            kind: EncodePacketKind::Frame,
        };
        r.push(&pkt).expect("first push");
        // Now in_flight = 6, free = 7-6 = 1. A 2-dw packet fails.
        let pkt2 = EncodePacket {
            dws: alloc::vec![0; 2],
            seq: 2,
            kind: EncodePacketKind::Frame,
        };
        match r.push(&pkt2) {
            Err(VideoError::RingFull) => {}
            _ => return TestResult::Fail("ring-full not flagged"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_encode_ring_full_rejects);

    fn smoke_setup_encode_ring_writes_regs() -> TestResult {
        let mut m = MockVcnMmio {
            writes: alloc::vec![],
        };
        let r = EncodeRing::new(0xDEAD_0000, 4096).expect("ring");
        setup_encode_ring_regs(&mut m, 0x100, &r);
        // 5 writes: BASE_LO, BASE_HI, SIZE, RPTR=0, WPTR=0.
        if m.writes.len() != 5 {
            return TestResult::Fail("expected 5 ring-setup writes");
        }
        if m.writes[0] != (0x100 + VCN_ENC_RING_BASE_LO_REL, 0xDEAD_0000) {
            return TestResult::Fail("base lo wrong");
        }
        if m.writes[2] != (0x100 + VCN_ENC_RING_SIZE_REL, 4096) {
            return TestResult::Fail("size wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_setup_encode_ring_writes_regs);

    fn smoke_commit_encode_wptr_writes_uvd_rb_wptr() -> TestResult {
        let mut m = MockVcnMmio {
            writes: alloc::vec![],
        };
        let mut r = EncodeRing::new(0xDEAD_0000, 4096).expect("ring");
        r.wptr_dw = 0x42;
        commit_encode_wptr(&mut m, 0x100, &r);
        if m.writes.len() != 1 {
            return TestResult::Fail("expected 1 wptr write");
        }
        if m.writes[0] != (0x100 + VCN_ENC_RING_WPTR_REL, 0x42) {
            return TestResult::Fail("wptr write wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_commit_encode_wptr_writes_uvd_rb_wptr);

    fn smoke_build_encode_destroy_msg_layout() -> TestResult {
        let mut s = EncodeSession::new(VcnVersion::V4_0_5, Codec::H264, 1920, 1080, 5_000_000, 99)
            .expect("session");
        let p = build_encode_destroy_msg(&mut s).expect("destroy");
        // dw[2] = handle, dw[6] = op-destroy, last = END sentinel.
        if p.dws[2] != 99 {
            return TestResult::Fail("destroy handle wrong");
        }
        if p.dws[6] != 0x0800_0003 {
            return TestResult::Fail("destroy op wrong");
        }
        if *p.dws.last().unwrap() != VCN_ENC_CMD_END {
            return TestResult::Fail("END sentinel missing");
        }
        if p.kind != EncodePacketKind::Destroy {
            return TestResult::Fail("packet kind wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_build_encode_destroy_msg_layout);
}
