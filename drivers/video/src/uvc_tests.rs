//! UVC driver smoke tests.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` under the
//! `"drivers/video/uvc"` group so they appear in the boot-smoke summary.
//! Every test is self-contained — no USB hardware required.
//!
//! Test coverage:
//! 1.  VC header descriptor decode
//! 2.  Input Terminal (CAMERA) descriptor decode + controls bitmap
//! 3.  Processing Unit descriptor decode + controls bitmap
//! 4.  VS_FORMAT_MJPEG + VS_FRAME_MJPEG descriptor decode
//! 5.  VS_FORMAT_UNCOMPRESSED (YUYV) descriptor decode
//! 6.  Probe control encode: SET_CUR(PROBE) 26-byte payload (UVC 1.0)
//! 7.  Probe control encode: SET_CUR(PROBE) 34-byte payload (UVC 1.5)
//! 8.  UVC payload header decode: FID flip, EOF bit
//! 9.  Frame reassembly: 3 payloads same FID → one frame, EOF closes it
//!     9b. Frame-based (1.5) header decode + H.264 reassembly (mirrored
//!     in the drivers/usb tests, including GET_CUR version validation)
//!     9c. Stream-based (#1334) length completion, no EOF (buffer
//!     fullness at the negotiated dwMaxVideoFrameSize)
//!     9d. Stream-based (#1334) accumulation cap (clamp + drop count)
//!     9e. Stream-based (#1334) bmFramingInfo gating (D0/D1)
//!     9f. Frame-based bound (#1334): EOF machine unchanged, length
//!     completion as safety net; legacy `new()` unbounded
//!     9g. Stream-based format descriptor parse + walker
//!     9h. StreamHandle with a stream-based config completes on length
//! 10. Brightness control GET_MIN/MAX/RES round-trip
//! 11. Format negotiation: 1280×720 MJPEG @ 30 fps → nearest supported
//! 12. Probe UVC: config blob with VC + VS interfaces
//! 13. YUYV frame size calculation
//! 14. NV12 frame size calculation
//! 15. MJPEG validity check
//! 16. Control routing: PU/CT unit selection, missing-unit rejection

#![cfg(target_arch = "x86_64")]

use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

// ── Smoke 1: VC header descriptor decode ────────────────────────────

fn smoke_uvc_vc_header_decode() -> TestResult {
    use crate::uvc::descriptor::{VcHeader, CS_INTERFACE, VC_HEADER};

    // Synthesise a valid VC_HEADER with bcdUVC=0x0150, wTotalLength=0x0027,
    // dwClockFrequency=48_000_000, bInCollection=1, baInterfaceNr=0x01.
    // Total: bLength=13, bDescriptorType=CS_INTERFACE, bDescriptorSubtype=VC_HEADER.
    let buf: &[u8] = &[
        13,           // bLength
        CS_INTERFACE, // bDescriptorType
        VC_HEADER,    // bDescriptorSubtype
        0x50,
        0x01, // bcdUVC = 0x0150 (UVC 1.5)
        0x27,
        0x00, // wTotalLength = 39
        0x00,
        0x6C,
        0xDC,
        0x02, // dwClockFrequency = 48_000_000
        0x01, // bInCollection = 1
        0x01, // baInterfaceNr[0] = 1
    ];
    let h = match VcHeader::parse(buf) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("VcHeader::parse failed"),
    };
    if h.bcd_uvc != 0x0150 {
        return TestResult::Fail("bcdUVC should be 0x0150");
    }
    if h.clock_frequency != 48_000_000 {
        return TestResult::Fail("dwClockFrequency wrong");
    }
    if h.in_collection != [1u8] {
        return TestResult::Fail("baInterfaceNr wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_vc_header_decode);

// ── Smoke 2: Input Terminal (CAMERA) descriptor + controls ──────────

fn smoke_uvc_camera_input_terminal() -> TestResult {
    use crate::uvc::descriptor::{InputTerminal, CS_INTERFACE, ITT_CAMERA, VC_INPUT_TERMINAL};

    // Table 3-6 minimal Camera Terminal: total 17 bytes.
    // bLength=17, bDescriptorType=CS_INTERFACE, bDescriptorSubtype=VC_INPUT_TERMINAL,
    // bTerminalID=1, wTerminalType=ITT_CAMERA (0x0201), bAssocTerminal=0, iTerminal=0,
    // wObjectiveFocalLengthMin=0, wObjectiveFocalLengthMax=0,
    // wOcularFocalLength=0, bControlSize=3, bmControls[3]=0x0E, 0x00, 0x00.
    let buf: &[u8] = &[
        17,
        CS_INTERFACE,
        VC_INPUT_TERMINAL,
        1, // bTerminalID
        0x01,
        0x02, // wTerminalType = ITT_CAMERA
        0,    // bAssocTerminal
        0,    // iTerminal
        0x00,
        0x00, // wObjectiveFocalLengthMin
        0x00,
        0x00, // wObjectiveFocalLengthMax
        0x00,
        0x00, // wOcularFocalLength
        3,    // bControlSize = 3
        0x0E,
        0x00,
        0x00, // bmControls: bits 1,2,3 set
    ];
    let it = match InputTerminal::parse(buf) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("InputTerminal::parse failed"),
    };
    if it.terminal_type != ITT_CAMERA {
        return TestResult::Fail("terminal_type should be ITT_CAMERA");
    }
    let cam = match it.camera {
        Some(c) => c,
        None => return TestResult::Fail("camera-specific fields absent"),
    };
    // controls bitmap: first byte = 0x0E → bits 1,2,3
    if cam.controls & 0x0E != 0x0E {
        return TestResult::Fail("controls bitmap bits 1-3 should be set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_camera_input_terminal);

// ── Smoke 3: Processing Unit descriptor + controls ───────────────────

fn smoke_uvc_processing_unit() -> TestResult {
    use crate::uvc::descriptor::{ProcessingUnit, CS_INTERFACE, VC_PROCESSING_UNIT};

    // bLength=11, CS_INTERFACE, VC_PROCESSING_UNIT,
    // bUnitID=2, bSourceID=1, wMaxMultiplier=0,
    // bControlSize=2, bmControls[2]=0x5F, 0x17, iProcessing=0.
    let buf: &[u8] = &[
        11,
        CS_INTERFACE,
        VC_PROCESSING_UNIT,
        2, // bUnitID
        1, // bSourceID
        0x00,
        0x00, // wMaxMultiplier
        2,    // bControlSize
        0x5F,
        0x17, // bmControls: brightness(bit1)+contrast(bit2)+gain(bit3) etc.
        0,    // iProcessing
    ];
    let pu = match ProcessingUnit::parse(buf) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("ProcessingUnit::parse failed"),
    };
    if pu.unit_id != 2 {
        return TestResult::Fail("unit_id should be 2");
    }
    if pu.source_id != 1 {
        return TestResult::Fail("source_id should be 1");
    }
    // bmControls first byte = 0x5F → bits 0,1,2,3,4,6 set.
    if pu.controls & 0x5F != 0x5F {
        return TestResult::Fail("controls bitmap low byte wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_processing_unit);

// ── Smoke 4: VS_FORMAT_MJPEG + VS_FRAME_MJPEG decode ────────────────

fn smoke_uvc_mjpeg_format_and_frame() -> TestResult {
    use crate::uvc::descriptor::{
        FormatMjpeg, FrameMjpeg, CS_INTERFACE, VS_FORMAT_MJPEG, VS_FRAME_MJPEG,
    };

    // VS_FORMAT_MJPEG: 11 bytes, format_index=1, num_frames=1.
    let fmt_buf: &[u8] = &[
        11,
        CS_INTERFACE,
        VS_FORMAT_MJPEG,
        1,    // bFormatIndex
        1,    // bNumFrameDescriptors
        0x01, // bmFlags
        1,    // bDefaultFrameIndex
        0,    // bAspectRatioX
        0,    // bAspectRatioY
        0,    // bmInterlaceFlags
        0,    // bCopyProtect
    ];
    let fmt = match FormatMjpeg::parse(fmt_buf) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("FormatMjpeg::parse failed"),
    };
    if fmt.format_index != 1 {
        return TestResult::Fail("FormatMjpeg.format_index should be 1");
    }
    if fmt.num_frame_descriptors != 1 {
        return TestResult::Fail("FormatMjpeg.num_frames should be 1");
    }

    // VS_FRAME_MJPEG for 1280×720 @ 30fps (one discrete interval = 333_333).
    let frame_buf: &[u8] = &[
        30,
        CS_INTERFACE,
        VS_FRAME_MJPEG,
        1, // bFrameIndex
        0, // bmCapabilities
        0x00,
        0x05, // wWidth  = 1280
        0xD0,
        0x02, // wHeight = 720
        0x00,
        0x00,
        0xC2,
        0x01, // dwMinBitRate
        0x00,
        0x00,
        0x48,
        0x03, // dwMaxBitRate
        0x00,
        0x80,
        0x3E,
        0x00, // dwMaxVideoFrameBufferSize
        0x15,
        0x16,
        0x05,
        0x00, // dwDefaultFrameInterval = 333_333
        1,    // bFrameIntervalType = 1 (discrete)
        0x15,
        0x16,
        0x05,
        0x00, // dwFrameInterval[0] = 333_333
    ];
    let frm = match FrameMjpeg::parse(frame_buf) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("FrameMjpeg::parse failed"),
    };
    if frm.width != 1280 || frm.height != 720 {
        return TestResult::Fail("FrameMjpeg resolution wrong");
    }
    if frm.frame_intervals != [333_333] {
        return TestResult::Fail("FrameMjpeg discrete interval wrong");
    }
    let fps = FrameMjpeg::fps_from_interval(333_333);
    if fps != 30 {
        return TestResult::Fail("fps_from_interval(333333) should be 30");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_mjpeg_format_and_frame);

// ── Smoke 5: VS_FORMAT_UNCOMPRESSED (YUYV) ───────────────────────────

fn smoke_uvc_format_uncompressed_yuyv() -> TestResult {
    use crate::uvc::descriptor::{
        FormatUncompressed, CS_INTERFACE, GUID_FORMAT_YUY2, VS_FORMAT_UNCOMPRESSED,
    };

    let mut buf = [0u8; 27];
    buf[0] = 27;
    buf[1] = CS_INTERFACE;
    buf[2] = VS_FORMAT_UNCOMPRESSED;
    buf[3] = 1; // format_index
    buf[4] = 2; // num_frame_descriptors
    buf[5..21].copy_from_slice(&GUID_FORMAT_YUY2);
    buf[21] = 16; // bits_per_pixel
    buf[22] = 1; // default_frame_index

    let f = match FormatUncompressed::parse(&buf) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("FormatUncompressed::parse failed"),
    };
    if f.format_index != 1 {
        return TestResult::Fail("format_index should be 1");
    }
    if f.bits_per_pixel != 16 {
        return TestResult::Fail("bits_per_pixel should be 16 for YUYV");
    }
    if !f.is_yuyv() {
        return TestResult::Fail("GUID should be detected as YUYV");
    }
    if f.is_nv12() {
        return TestResult::Fail("YUYV GUID should not match NV12");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_format_uncompressed_yuyv);

// ── Smoke 8: UVC payload header decode: FID / EOF ───────────────────

fn smoke_uvc_payload_header_fid_eof() -> TestResult {
    use crate::uvc::payload::{PayloadHeader, BFH_EOF, BFH_EOH, BFH_FID};

    // Minimal 2-byte header: FID=1, EOF=1, EOH=1.
    let bfh_byte: u8 = BFH_FID | BFH_EOF | BFH_EOH;
    let buf = [2u8, bfh_byte];
    let (hdr, off) = match PayloadHeader::decode(&buf) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("PayloadHeader::decode failed"),
    };
    if !hdr.fid() {
        return TestResult::Fail("FID bit should be set");
    }
    if !hdr.is_eof() {
        return TestResult::Fail("EOF bit should be set");
    }
    if off != 2 {
        return TestResult::Fail("payload offset should be 2 for minimal header");
    }

    // Check FID=0, no EOF.
    let buf2 = [2u8, BFH_EOH]; // FID=0, EOF=0, EOH=1
    let (hdr2, _) = match PayloadHeader::decode(&buf2) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("PayloadHeader::decode (2) failed"),
    };
    if hdr2.fid() {
        return TestResult::Fail("FID should be 0 in second header");
    }
    if hdr2.is_eof() {
        return TestResult::Fail("EOF should be 0 in second header");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_payload_header_fid_eof);

// ── Smoke 9: Frame reassembly: 3 payloads → one complete frame ───────

fn smoke_uvc_frame_reassembly_three_payloads() -> TestResult {
    use crate::uvc::payload::{FrameReassembler, PushResult, BFH_EOF, BFH_EOH};

    let mut r = FrameReassembler::new();

    // First payload: FID=0, no EOF, data = [0xAA, 0xBB].
    let p1 = [2u8, BFH_EOH, 0xAA, 0xBB];
    match r.push(&p1) {
        PushResult::FidReset | PushResult::Appended => {}
        _ => return TestResult::Fail("first push should be Appended or FidReset"),
    }

    // Second payload: FID=0, no EOF, data = [0xCC].
    let p2 = [2u8, BFH_EOH, 0xCC];
    match r.push(&p2) {
        PushResult::Appended => {}
        _ => return TestResult::Fail("second push should be Appended"),
    }

    // Third payload: FID=0, EOF=1, data = [0xDD].
    let p3 = [2u8, BFH_EOF | BFH_EOH, 0xDD];
    match r.push(&p3) {
        PushResult::FrameComplete => {}
        _ => return TestResult::Fail("third push should be FrameComplete"),
    }

    let frame = r.take_frame();
    if frame != [0xAA, 0xBB, 0xCC, 0xDD] {
        return TestResult::Fail("reassembled frame data wrong");
    }
    if r.frames_completed != 1 {
        return TestResult::Fail("frames_completed should be 1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/video/uvc",
    smoke_uvc_frame_reassembly_three_payloads
);

// ── Smoke 9b: Frame-based (1.5) header decode + H.264 reassembly ─────
// UVC 1.5 §2.4.3.3 (shared header) + §2.4.3.7 (frame-based class
// requires FID; temporally-encoded requires EOF). A spec-shaped
// H.264 stream — 12-byte PTS+SCR headers, Annex-B-style NAL payload
// — must reassemble byte-for-byte through the same header machine,
// with D4 surfacing as payload-specific and STI as intra-coded.

fn uvc_frame_based_packet(bfh: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![12, bfh];
    packet.extend_from_slice(&0x0010_0000u32.to_le_bytes());
    packet.extend_from_slice(&0x0020_0000u32.to_le_bytes());
    packet.extend_from_slice(&0x0123u16.to_le_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn smoke_uvc_frame_based_header_decode() -> TestResult {
    use crate::uvc::payload::{
        PayloadHeader, BFH_EOH, BFH_FID, BFH_PAYLOAD_SPECIFIC, BFH_PTS, BFH_SCR, BFH_STI,
    };

    // FID=1, D4 + STI set, PTS+SCR present, no EOF.
    let packet = uvc_frame_based_packet(
        BFH_EOH | BFH_FID | BFH_PTS | BFH_SCR | BFH_PAYLOAD_SPECIFIC | BFH_STI,
        &[0xAA],
    );
    let (hdr, off) = match PayloadHeader::decode(&packet) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("frame-based header must decode"),
    };
    if hdr.length != 12 || off != 12 {
        return TestResult::Fail("header length / payload offset must be 12");
    }
    if !hdr.fid() || hdr.is_eof() {
        return TestResult::Fail("FID/EOF bits must decode");
    }
    if hdr.pts != Some(0x0010_0000) {
        return TestResult::Fail("PTS must decode LE from the header");
    }
    if hdr.scr != Some((0x0020_0000, 0x123)) {
        return TestResult::Fail("SCR must decode as (STC, 11-bit SOF)");
    }
    if !hdr.payload_specific() {
        return TestResult::Fail("D4 must surface as payload-specific, not reserved");
    }
    if !hdr.is_intra_coded() {
        return TestResult::Fail("STI must surface as intra-coded for frame-based streams");
    }
    // Masking-defeating: a header lying about its length, a PTS flag
    // with no timestamp room, and an empty packet must all fail.
    if PayloadHeader::decode(&[12, BFH_EOH | BFH_PTS, 0x00, 0x00]).is_ok() {
        return TestResult::Fail("truncated 12-byte header must not decode");
    }
    if PayloadHeader::decode(&[2, BFH_EOH | BFH_PTS, 0xAA]).is_ok() {
        return TestResult::Fail("PTS flag with no timestamp room must not decode");
    }
    if PayloadHeader::decode(&[]).is_ok() {
        return TestResult::Fail("empty packet must not decode");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_frame_based_header_decode);

fn smoke_uvc_frame_based_h264_reassembly() -> TestResult {
    use crate::uvc::payload::{
        FrameReassembler, PushResult, BFH_EOF, BFH_EOH, BFH_FID, BFH_PAYLOAD_SPECIFIC, BFH_PTS,
        BFH_SCR, BFH_STI,
    };

    let mut r = FrameReassembler::new();

    // Frame 1 (IDR, FID=0): two packets, 12-byte PTS+SCR headers.
    let p1 = uvc_frame_based_packet(
        BFH_EOH | BFH_PTS | BFH_SCR,
        &[0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21],
    );
    if r.push(&p1) != PushResult::Appended {
        return TestResult::Fail("first frame-based packet must Append");
    }
    let p2 = uvc_frame_based_packet(BFH_EOH | BFH_PTS | BFH_SCR | BFH_EOF, &[0xAA, 0xBB, 0xCC]);
    if r.push(&p2) != PushResult::FrameComplete {
        return TestResult::Fail("EOF packet must complete the frame");
    }
    let frame1 = r.take_frame();
    if frame1
        != vec![
            0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21, 0xAA, 0xBB, 0xCC,
        ]
    {
        return TestResult::Fail("frame 1 must reassemble byte-for-byte");
    }

    // Frame 2 (non-IDR, FID=1, intra-coded + D4 set): D4 must not
    // disturb framing, and the FID flip must start a new frame.
    let p3 = uvc_frame_based_packet(
        BFH_EOH | BFH_FID | BFH_PTS | BFH_SCR | BFH_PAYLOAD_SPECIFIC | BFH_STI,
        &[0x00, 0x00, 0x00, 0x01, 0x41, 0x9A],
    );
    if r.push(&p3) != PushResult::FidReset {
        return TestResult::Fail("FID-flipped packet must FidReset");
    }
    let p4 = uvc_frame_based_packet(
        BFH_EOH | BFH_FID | BFH_PTS | BFH_SCR | BFH_EOF,
        &[0xDE, 0xAD],
    );
    if r.push(&p4) != PushResult::FrameComplete {
        return TestResult::Fail("EOF packet must complete frame 2");
    }
    let frame2 = r.take_frame();
    if frame2 != vec![0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, 0xDE, 0xAD] {
        return TestResult::Fail("frame 2 must reassemble byte-for-byte");
    }
    if r.frames_completed != 2 {
        return TestResult::Fail("frames_completed should be 2");
    }

    // FID flip mid-frame drops the partial frame's bytes. After frame
    // 2 the reassembler sits at FID=1, so the partial packet keeps
    // FID=1 and the completing packet flips to FID=0.
    let q1 = [2u8, BFH_EOH | BFH_FID, 0x11, 0x22];
    if r.push(&q1) != PushResult::Appended {
        return TestResult::Fail("partial packet must Append");
    }
    let q2 = [2u8, BFH_EOH | BFH_EOF, 0x33];
    if r.push(&q2) != PushResult::FrameComplete {
        return TestResult::Fail("flipped EOF packet must complete");
    }
    if r.take_frame() != vec![0x33] {
        return TestResult::Fail("FID flip must drop the partial frame's bytes");
    }

    // Truncated / malformed packets are skipped, never appended.
    if r.push(&[12, BFH_EOH | BFH_PTS, 0x00, 0x00]) != PushResult::Skipped {
        return TestResult::Fail("truncated header must Skip");
    }
    if r.push(&[2, BFH_EOH | BFH_PTS, 0xAA]) != PushResult::Skipped {
        return TestResult::Fail("PTS flag without timestamp room must Skip");
    }
    if r.push(&[]) != PushResult::Skipped {
        return TestResult::Fail("empty packet must Skip");
    }
    TestResult::Pass
}
// ── Smoke 9c: Stream-based (#1334) length completion, no EOF ────────
// UVC 1.5 §2.4.3.7: stream-based boundaries are in-band, FID/EOF
// optional; with bmFramingInfo = 0 neither bit is meaningful, so the
// frame must complete on buffer fullness alone at the negotiated
// dwMaxVideoFrameSize — never at EOF, never unbounded.

fn smoke_uvc_stream_based_completes_on_length_no_eof() -> TestResult {
    use crate::uvc::payload::{FrameReassembler, PushResult, ReassemblyConfig, BFH_EOH, BFH_FID};

    let mut r = FrameReassembler::with_config(ReassemblyConfig::stream_based(16, 0));

    // Four 4-byte payloads, constant FID=0, no EOF anywhere.
    let p1 = [2u8, BFH_EOH, 0xA0, 0xA1, 0xA2, 0xA3];
    if r.push(&p1) != PushResult::Appended {
        return TestResult::Fail("first stream packet must Append");
    }
    if r.buffer.len() != 4 {
        return TestResult::Fail("buffer must hold 4 bytes after first packet");
    }
    let p2 = [2u8, BFH_EOH, 0xA4, 0xA5, 0xA6, 0xA7];
    if r.push(&p2) != PushResult::Appended {
        return TestResult::Fail("second stream packet must Append");
    }
    // Masking-defeating: 8 of 16 bytes is NOT a frame — no early
    // completion, and a FID flip mid-segment must NOT reset the
    // accumulation when bmFramingInfo D0 is clear (FID ignored).
    if r.frames_completed != 0 {
        return TestResult::Fail("no frame may complete before the bound");
    }
    let p3 = [2u8, BFH_EOH | BFH_FID, 0xA8, 0xA9, 0xAA, 0xAB];
    if r.push(&p3) != PushResult::Appended {
        return TestResult::Fail("FID flip must be ignored (D0 clear), not reset");
    }
    if r.buffer.len() != 12 || r.buffer[0] != 0xA0 {
        return TestResult::Fail("FID flip must not drop accumulated bytes");
    }
    let p4 = [2u8, BFH_EOH, 0xAC, 0xAD, 0xAE, 0xAF];
    if r.push(&p4) != PushResult::FrameComplete {
        return TestResult::Fail("16th byte must complete the frame on length");
    }
    let frame = r.take_frame();
    if frame
        != [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ]
    {
        return TestResult::Fail("length-completed frame bytes wrong");
    }
    if r.frames_completed != 1 {
        return TestResult::Fail("frames_completed should be 1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/video/uvc",
    smoke_uvc_stream_based_completes_on_length_no_eof
);

// ── Smoke 9d: Stream-based (#1334) accumulation cap ─────────────────
// A push past the negotiated max is clamped to the bound, the frame
// completes at the bound, and the excess bytes are dropped + counted.

fn smoke_uvc_stream_based_buffer_cap() -> TestResult {
    use crate::uvc::payload::{FrameReassembler, PushResult, ReassemblyConfig, BFH_EOH};

    let mut r = FrameReassembler::with_config(ReassemblyConfig::stream_based(8, 0));

    let p1 = [2u8, BFH_EOH, 1, 2, 3, 4, 5, 6];
    if r.push(&p1) != PushResult::Appended {
        return TestResult::Fail("first packet must Append");
    }
    if r.buffer.len() != 6 || r.bytes_dropped_overflow != 0 {
        return TestResult::Fail("no bytes may drop below the bound");
    }
    // 6 more bytes would take the buffer to 12; only 2 fit.
    let p2 = [2u8, BFH_EOH, 7, 8, 9, 10, 11, 12];
    if r.push(&p2) != PushResult::FrameComplete {
        return TestResult::Fail("push past the bound must complete the frame");
    }
    if r.buffer.len() != 8 {
        return TestResult::Fail("buffer must never exceed the bound");
    }
    if r.take_frame() != [1, 2, 3, 4, 5, 6, 7, 8] {
        return TestResult::Fail("capped frame must hold exactly the bound bytes");
    }
    if r.bytes_dropped_overflow != 4 {
        return TestResult::Fail("4 excess bytes must be counted as dropped");
    }
    // The next packet starts a fresh frame.
    let p3 = [2u8, BFH_EOH, 0xAA, 0xBB];
    if r.push(&p3) != PushResult::Appended {
        return TestResult::Fail("packet after a capped frame must Append");
    }
    if r.buffer != [0xAA, 0xBB] {
        return TestResult::Fail("new frame must start clean after the cap");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_stream_based_buffer_cap);

// ── Smoke 9e: Stream-based (#1334) bmFramingInfo gating ─────────────
// With D0|D1 set, FID flips and EOF are the low-latency path and
// length completion is only the fallback; with D1 alone, EOF is
// honoured but FID ignored; with D0 alone, EOF is ignored.

fn smoke_uvc_stream_based_framing_bits() -> TestResult {
    use crate::uvc::payload::{
        FrameReassembler, PushResult, ReassemblyConfig, BFH_EOF, BFH_EOH, BFH_FID, FRAMING_EOF,
        FRAMING_FID,
    };

    // D0|D1: FID flip drops the partial, EOF completes early.
    let mut r = FrameReassembler::with_config(ReassemblyConfig::stream_based(
        64,
        FRAMING_FID | FRAMING_EOF,
    ));
    if r.push(&[2u8, BFH_EOH, 0x11, 0x22]) != PushResult::Appended {
        return TestResult::Fail("D0|D1: first packet must Append");
    }
    if r.push(&[2u8, BFH_EOH | BFH_FID, 0x33]) != PushResult::FidReset {
        return TestResult::Fail("D0|D1: FID flip must FidReset");
    }
    if r.buffer != [0x33] {
        return TestResult::Fail("D0|D1: flip must drop the partial frame");
    }
    if r.push(&[2u8, BFH_EOH | BFH_FID | BFH_EOF, 0x44]) != PushResult::FrameComplete {
        return TestResult::Fail("D0|D1: EOF must complete before the bound");
    }
    if r.take_frame() != [0x33, 0x44] {
        return TestResult::Fail("D0|D1: EOF-completed frame bytes wrong");
    }

    // D1 alone (D0 clear): FID ignored, EOF honoured.
    let mut r = FrameReassembler::with_config(ReassemblyConfig::stream_based(64, FRAMING_EOF));
    if r.push(&[2u8, BFH_EOH, 0x11]) != PushResult::Appended {
        return TestResult::Fail("D1-only: first packet must Append");
    }
    if r.push(&[2u8, BFH_EOH | BFH_FID, 0x22]) != PushResult::Appended {
        return TestResult::Fail("D1-only: FID flip must be ignored, not reset");
    }
    if r.push(&[2u8, BFH_EOH | BFH_FID | BFH_EOF, 0x33]) != PushResult::FrameComplete {
        return TestResult::Fail("D1-only: EOF must complete");
    }
    if r.take_frame() != [0x11, 0x22, 0x33] {
        return TestResult::Fail("D1-only: frame must hold all three payloads");
    }

    // D0 alone: EOF ignored, FID flip resets, length is the fallback.
    let mut r = FrameReassembler::with_config(ReassemblyConfig::stream_based(64, FRAMING_FID));
    if r.push(&[2u8, BFH_EOH, 0x11, 0x22]) != PushResult::Appended {
        return TestResult::Fail("D0-only: first packet must Append");
    }
    if r.push(&[2u8, BFH_EOH | BFH_EOF, 0x33, 0x44]) != PushResult::Appended {
        return TestResult::Fail("D0-only: EOF must be ignored, not complete");
    }
    if r.buffer.len() != 4 {
        return TestResult::Fail("D0-only: ignored EOF must still accumulate");
    }
    // 60-byte flip packet: drops the 4-byte partial, accumulates 60.
    let mut p3 = alloc::vec![2u8, BFH_EOH | BFH_FID];
    p3.extend([0x55u8; 60]);
    if r.push(&p3) != PushResult::FidReset {
        return TestResult::Fail("D0-only: FID flip must FidReset");
    }
    if r.buffer.len() != 60 {
        return TestResult::Fail("D0-only: flipped frame must hold 60 bytes");
    }
    if r.push(&[2u8, BFH_EOH | BFH_FID, 0x66, 0x77, 0x88, 0x99]) != PushResult::FrameComplete {
        return TestResult::Fail("D0-only: 64th byte must complete on length");
    }
    if r.frames_completed != 1 {
        return TestResult::Fail("D0-only: frames_completed should be 1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_stream_based_framing_bits);

// ── Smoke 9f: Frame-based bound (#1334) is a safety net, not a change ─
// The legacy FID/EOF machine is unchanged when a bound is configured:
// EOF still completes early, and length completion only fires when
// EOF never arrives. `new()` (no bound) never completes on length.

fn smoke_uvc_frame_based_bound_caps_legacy_machine() -> TestResult {
    use crate::uvc::payload::{FrameReassembler, PushResult, ReassemblyConfig, BFH_EOF, BFH_EOH};

    let mut r = FrameReassembler::with_config(ReassemblyConfig::bounded(8));
    if r.push(&[2u8, BFH_EOH, 1, 2, 3]) != PushResult::Appended {
        return TestResult::Fail("bounded: first packet must Append");
    }
    if r.push(&[2u8, BFH_EOH | BFH_EOF, 4, 5, 6]) != PushResult::FrameComplete {
        return TestResult::Fail("bounded: EOF must still complete early");
    }
    if r.take_frame() != [1, 2, 3, 4, 5, 6] {
        return TestResult::Fail("bounded: EOF-completed frame bytes wrong");
    }

    let mut r = FrameReassembler::with_config(ReassemblyConfig::bounded(8));
    if r.push(&[2u8, BFH_EOH, 1, 2, 3, 4, 5]) != PushResult::Appended {
        return TestResult::Fail("bounded: 5 bytes must Append");
    }
    if r.push(&[2u8, BFH_EOH, 6, 7, 8, 9, 10]) != PushResult::FrameComplete {
        return TestResult::Fail("bounded: 8th byte must complete without EOF");
    }
    if r.take_frame() != [1, 2, 3, 4, 5, 6, 7, 8] {
        return TestResult::Fail("bounded: length-completed frame bytes wrong");
    }
    if r.bytes_dropped_overflow != 2 {
        return TestResult::Fail("bounded: 2 excess bytes must be counted");
    }

    // Legacy `new()`: no bound, no length completion.
    let mut r = FrameReassembler::new();
    let mut big = alloc::vec![2u8, BFH_EOH];
    big.extend([0xAAu8; 20]);
    if r.push(&big) != PushResult::Appended {
        return TestResult::Fail("legacy: 20 bytes without EOF must Append");
    }
    if r.buffer.len() != 20 {
        return TestResult::Fail("legacy: unbounded buffer must hold 20 bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/video/uvc",
    smoke_uvc_frame_based_bound_caps_legacy_machine
);

// ── Smoke 9g: Stream-based format descriptor (#1334) ────────────────
// VS_FORMAT_STREAM_BASED (0x12, Stream Based Payload §3.1.1 Table 3-1):
// 24-byte descriptor, guidFormat + dwPacketLength; the walker yields
// a StreamBased format with no frame modes (frame size is negotiated).

fn smoke_uvc_stream_based_format_descriptor() -> TestResult {
    use crate::uvc::{parse_streaming_descriptors, FormatStreamBased, PixelFmt};

    let mut blob = alloc::vec![24u8, 0x24, 0x12, 1];
    blob.extend_from_slice(b"STREAM-BASED-FIX");
    blob.extend_from_slice(&188u32.to_le_bytes());
    let f = match FormatStreamBased::parse(&blob) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("stream-based format descriptor must parse"),
    };
    if f.format_index != 1 {
        return TestResult::Fail("format_index must be 1");
    }
    if f.guid_format != *b"STREAM-BASED-FIX" {
        return TestResult::Fail("guid_format must round-trip");
    }
    if f.packet_length != 188 {
        return TestResult::Fail("dwPacketLength must be 188 (packet-oriented)");
    }
    // Masking-defeating: short blob and wrong subtype must fail.
    if FormatStreamBased::parse(&blob[..23]).is_ok() {
        return TestResult::Fail("23-byte descriptor must not parse");
    }
    let mut wrong = blob.clone();
    wrong[2] = 0x06;
    if FormatStreamBased::parse(&wrong).is_ok() {
        return TestResult::Fail("MJPEG subtype must not parse as stream-based");
    }

    // The walker: VS_INPUT_HEADER + the stream-based format descriptor.
    let mut vs_blob = alloc::vec![14u8, 0x24, 0x01, 1, 38, 0, 0x81, 0, 1, 0, 0, 0, 1, 0];
    vs_blob.extend_from_slice(&blob);
    let formats = match parse_streaming_descriptors(&vs_blob) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("walker must accept a stream-based blob"),
    };
    if formats.len() != 1 {
        return TestResult::Fail("walker must yield exactly one format");
    }
    if formats[0].pixel_fmt != PixelFmt::StreamBased {
        return TestResult::Fail("format must classify as StreamBased");
    }
    if formats[0].format_index != 1 || !formats[0].frames.is_empty() {
        return TestResult::Fail("stream-based format must have no frame modes");
    }
    if formats[0].find_frame(640, 480, 30).is_some() {
        return TestResult::Fail("stream-based format must match no frame mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/video/uvc",
    smoke_uvc_stream_based_format_descriptor
);

// ── Smoke 9h: StreamHandle with a stream-based config (#1334) ───────
// The video-side pump path completes on length through `ingest_packet`.

fn smoke_uvc_stream_handle_completes_on_length() -> TestResult {
    use crate::uvc::payload::BFH_EOH;
    use crate::uvc::{ReassemblyConfig, StreamHandle, TransferMode};

    let mut h = StreamHandle::new_with_config(
        TransferMode::Bulk,
        7,
        3,
        ReassemblyConfig::stream_based(8, 0),
    );
    h.ingest_packet(&[2u8, BFH_EOH, 1, 2, 3, 4]);
    if h.pending_frames() != 0 {
        return TestResult::Fail("4 of 8 bytes must not deliver a frame");
    }
    h.ingest_packet(&[2u8, BFH_EOH, 5, 6, 7, 8]);
    if h.pending_frames() != 1 {
        return TestResult::Fail("8th byte must deliver exactly one frame");
    }
    let frame = match h.take_frame() {
        Some(f) => f,
        None => return TestResult::Fail("completed frame must be dequeueable"),
    };
    if frame.data != [1, 2, 3, 4, 5, 6, 7, 8] || frame.sequence != 1 {
        return TestResult::Fail("delivered frame bytes / sequence wrong");
    }
    if h.stats.frames_delivered != 1 {
        return TestResult::Fail("frames_delivered should be 1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/video/uvc",
    smoke_uvc_stream_handle_completes_on_length
);

kernel_test_in!("drivers/video/uvc", smoke_uvc_frame_based_h264_reassembly);

// ── Smoke 10: Brightness control GET_MIN/MAX/RES round-trip ─────────

fn smoke_uvc_brightness_control_range() -> TestResult {
    use crate::uvc::control::{ControlRange, PU_BRIGHTNESS_CONTROL};

    // Simulate GET_MIN returning -128 (0xFF80 LE), GET_MAX returning 127
    // (0x007F LE), GET_RES returning 1.
    let min_buf = [0x80u8, 0xFF]; // i16 = -128
    let max_buf = [0x7Fu8, 0x00]; // i16 = 127
    let res_buf = [0x01u8, 0x00]; // i16 = 1

    let min_val = match ControlRange::parse_i16(&min_buf) {
        Some(v) => v,
        None => return TestResult::Fail("parse_i16(min) failed"),
    };
    let max_val = match ControlRange::parse_i16(&max_buf) {
        Some(v) => v,
        None => return TestResult::Fail("parse_i16(max) failed"),
    };
    let res_val = match ControlRange::parse_i16(&res_buf) {
        Some(v) => v,
        None => return TestResult::Fail("parse_i16(res) failed"),
    };

    if min_val != -128 {
        return TestResult::Fail("min value wrong");
    }
    if max_val != 127 {
        return TestResult::Fail("max value wrong");
    }
    if res_val != 1 {
        return TestResult::Fail("res value wrong");
    }
    if PU_BRIGHTNESS_CONTROL != 0x02 {
        return TestResult::Fail("PU_BRIGHTNESS_CONTROL selector should be 0x02");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_brightness_control_range);

// ── Smoke 11: Format negotiation 1280×720 MJPEG @ 30fps ─────────────

fn smoke_uvc_format_negotiation_720p_30fps() -> TestResult {
    use crate::uvc::streaming::{FrameMode, PixelFmt, StreamFormat};
    use alloc::vec;

    // Device supports MJPEG: 1280×720 @ 30fps and 640×480 @ 30fps.
    let formats = [StreamFormat {
        format_index: 1,
        pixel_fmt: PixelFmt::Mjpeg,
        default_frame_index: 1,
        frames: vec![
            FrameMode {
                frame_index: 1,
                width: 1280,
                height: 720,
                frame_intervals: vec![333_333],
                continuous_min: None,
                continuous_max: None,
                continuous_step: None,
                default_frame_interval: 333_333,
            },
            FrameMode {
                frame_index: 2,
                width: 640,
                height: 480,
                frame_intervals: vec![333_333, 666_666],
                continuous_min: None,
                continuous_max: None,
                continuous_step: None,
                default_frame_interval: 333_333,
            },
        ],
    }];

    // Request 1280×720 @ 30fps → should match frame_index=1, interval=333_333.
    let fmt = &formats[0];
    let (frame_idx, interval) = match fmt.find_frame(1280, 720, 30) {
        Some(r) => r,
        None => return TestResult::Fail("find_frame(1280, 720, 30) returned None"),
    };
    if frame_idx != 1 {
        return TestResult::Fail("frame_index should be 1 for 1280×720");
    }
    if interval != 333_333 {
        return TestResult::Fail("interval should be 333_333 for 30fps");
    }

    // Request 640×480 @ 30fps → should get interval=333_333.
    let (fi2, iv2) = match fmt.find_frame(640, 480, 30) {
        Some(r) => r,
        None => return TestResult::Fail("find_frame(640, 480, 30) returned None"),
    };
    if fi2 != 2 {
        return TestResult::Fail("frame_index should be 2 for 640×480");
    }
    if iv2 != 333_333 {
        return TestResult::Fail("should pick 30fps for 640×480");
    }

    // Request a resolution that doesn't exist → None.
    if fmt.find_frame(1920, 1080, 30).is_some() {
        return TestResult::Fail("1920×1080 should not be found");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_format_negotiation_720p_30fps);

// ── Smoke 12: probe_uvc() config blob walk ───────────────────────────

fn smoke_uvc_probe_config_blob() -> TestResult {
    use crate::uvc::probe::probe_uvc;

    // Synthesise a minimal config descriptor with:
    //   Configuration (9 bytes) +
    //   VC interface (9 bytes, class=0x0E, subclass=0x01) +
    //   CS_INTERFACE VC_HEADER blob (13 bytes) +
    //   VS interface (9 bytes, class=0x0E, subclass=0x02) +
    //   CS_INTERFACE VS_INPUT_HEADER blob (13 bytes) +
    //   Endpoint iso-IN (7 bytes)
    let cfg: &[u8] = &[
        // Configuration descriptor (9 bytes)
        9, 0x02, 0x3E, 0x00, 1, 1, 0, 0x80, 0xFA, // VC interface (9 bytes)
        9, 0x04, 1,    // bInterfaceNumber
        0,    // bAlternateSetting
        0,    // bNumEndpoints
        0x0E, // bInterfaceClass = VIDEO
        0x01, // bInterfaceSubClass = VIDEOCONTROL
        0x00, 0x00, // VC CS_INTERFACE VC_HEADER (13 bytes)
        13, 0x24, 0x01, // VC_HEADER
        0x50, 0x01, // bcdUVC = 0x0150
        0x27, 0x00, // wTotalLength
        0x80, 0x8D, 0x5B, 0x02, // dwClockFrequency
        0x01, // bInCollection
        0x02, // baInterfaceNr[0] = 2
        // VS interface alt-setting 0 (9 bytes)
        9, 0x04, 2,    // bInterfaceNumber
        0,    // bAlternateSetting
        1,    // bNumEndpoints
        0x0E, // bInterfaceClass = VIDEO
        0x02, // bInterfaceSubClass = VIDEOSTREAMING
        0x00, 0x00, // VS CS_INTERFACE VS_INPUT_HEADER (13 bytes)
        13, 0x24, 0x01, // VS_INPUT_HEADER
        0x01, // bNumFormats
        0x1E, 0x00, // wTotalLength
        0x81, // bEndpointAddress (IN ep 1)
        0x00, // bmInfo
        0x01, // bTerminalLink
        0x00, // bStillCaptureMethod
        0x00, // bTriggerSupport
        0x00, // bTriggerUsage
        0x00, // bControlSize
        // Endpoint descriptor: iso IN ep 0x81 (7 bytes)
        7, 0x05, 0x81, // bEndpointAddress: IN, ep 1
        0x01, // bmAttributes: isochronous
        0x00, 0x04, // wMaxPacketSize = 1024
        0x01, // bInterval
    ];

    let result = match probe_uvc(cfg) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("probe_uvc failed on valid config"),
    };
    if result.vc_interface != 1 {
        return TestResult::Fail("vc_interface should be 1");
    }
    if result.vs_interface != 2 {
        return TestResult::Fail("vs_interface should be 2");
    }
    if result.iso_in.is_none() {
        return TestResult::Fail("iso_in endpoint should be detected");
    }
    let ep = result.iso_in.unwrap();
    if ep.address != 0x81 {
        return TestResult::Fail("iso_in endpoint address should be 0x81");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_probe_config_blob);

// ── Smoke 13: YUYV frame size ────────────────────────────────────────

fn smoke_uvc_yuyv_frame_size() -> TestResult {
    use crate::uvc::format::yuyv_frame_size;

    // 1280×720 @ 16 bpp = 1280 * 720 * 2 = 1_843_200 bytes.
    if yuyv_frame_size(1280, 720) != 1_843_200 {
        return TestResult::Fail("yuyv_frame_size(1280, 720) should be 1_843_200");
    }
    if yuyv_frame_size(640, 480) != 614_400 {
        return TestResult::Fail("yuyv_frame_size(640, 480) should be 614_400");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_yuyv_frame_size);

// ── Smoke 14: NV12 frame size ────────────────────────────────────────

fn smoke_uvc_nv12_frame_size() -> TestResult {
    use crate::uvc::format::nv12_frame_size;

    // 1280×720: Y=921_600, UV=460_800 → total 1_382_400.
    if nv12_frame_size(1280, 720) != 1_382_400 {
        return TestResult::Fail("nv12_frame_size(1280, 720) should be 1_382_400");
    }
    if nv12_frame_size(640, 480) != 460_800 {
        return TestResult::Fail("nv12_frame_size(640, 480) should be 460_800");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_nv12_frame_size);

// ── Smoke 15: MJPEG validity check ──────────────────────────────────

fn smoke_uvc_mjpeg_validity() -> TestResult {
    use crate::uvc::format::is_valid_mjpeg;

    // Valid JPEG starts with SOI marker 0xFF 0xD8.
    if !is_valid_mjpeg(&[0xFF, 0xD8, 0xAA, 0xBB]) {
        return TestResult::Fail("should detect valid MJPEG SOI marker");
    }
    // Invalid: starts with wrong bytes.
    if is_valid_mjpeg(&[0x00, 0x00]) {
        return TestResult::Fail("should reject non-JPEG header");
    }
    // Edge: empty buffer.
    if is_valid_mjpeg(&[]) {
        return TestResult::Fail("should reject empty buffer");
    }
    // Edge: single byte.
    if is_valid_mjpeg(&[0xFF]) {
        return TestResult::Fail("should reject single-byte buffer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_mjpeg_validity);

// ── Smoke 16: Control routing (migrated from v4l2::Camera, #810) ────

fn smoke_uvc_control_routing_units() -> TestResult {
    use crate::uvc::control::{
        route_control, ControlId, CT_FOCUS_ABSOLUTE_CONTROL, CT_ZOOM_ABSOLUTE_CONTROL,
        PU_BRIGHTNESS_CONTROL, PU_GAIN_CONTROL,
    };

    // PU controls route to the Processing Unit with the PU selector.
    match route_control(ControlId::Brightness, 5, 7) {
        Some((unit, selector)) if unit == 5 && selector == PU_BRIGHTNESS_CONTROL => {}
        _ => return TestResult::Fail("brightness must route to (pu, PU_BRIGHTNESS)"),
    }
    match route_control(ControlId::Gain, 5, 7) {
        Some((unit, selector)) if unit == 5 && selector == PU_GAIN_CONTROL => {}
        _ => return TestResult::Fail("gain must route to (pu, PU_GAIN)"),
    }
    // CT controls route to the Camera Terminal with the CT selector.
    match route_control(ControlId::Focus, 5, 7) {
        Some((unit, selector)) if unit == 7 && selector == CT_FOCUS_ABSOLUTE_CONTROL => {}
        _ => return TestResult::Fail("focus must route to (ct, CT_FOCUS_ABSOLUTE)"),
    }
    match route_control(ControlId::Zoom, 5, 7) {
        Some((unit, selector)) if unit == 7 && selector == CT_ZOOM_ABSOLUTE_CONTROL => {}
        _ => return TestResult::Fail("zoom must route to (ct, CT_ZOOM_ABSOLUTE)"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_control_routing_units);

fn smoke_uvc_control_routing_missing_unit() -> TestResult {
    use crate::uvc::control::{route_control, ControlId};

    // A PU control with no Processing Unit (id 0) must not route —
    // issuing a transfer to unit 0 would address the wrong entity.
    if route_control(ControlId::Brightness, 0, 7).is_some() {
        return TestResult::Fail("PU control with pu_unit_id 0 must not route");
    }
    // A CT control with no Camera Terminal (id 0) must not route.
    if route_control(ControlId::Focus, 5, 0).is_some() {
        return TestResult::Fail("CT control with ct_unit_id 0 must not route");
    }
    // The absent *other* unit does not block routing.
    if route_control(ControlId::Brightness, 5, 0).is_none() {
        return TestResult::Fail("PU control must route when only the CT is absent");
    }
    if route_control(ControlId::Focus, 0, 7).is_none() {
        return TestResult::Fail("CT control must route when only the PU is absent");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_control_routing_missing_unit);
