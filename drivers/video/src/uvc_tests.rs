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
//! 10. Brightness control GET_MIN/MAX/RES round-trip
//! 11. Format negotiation: 1280×720 MJPEG @ 30 fps → nearest supported
//! 12. Probe UVC: config blob with VC + VS interfaces
//! 13. YUYV frame size calculation
//! 14. NV12 frame size calculation
//! 15. MJPEG validity check

#![cfg(target_arch = "x86_64")]

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

// ── Smoke 6: Probe control encode (26-byte UVC 1.0) ──────────────────

fn smoke_uvc_probe_commit_encode_v10() -> TestResult {
    use crate::uvc::control::{ProbeCommit, PROBE_COMMIT_LEN_V10};

    let pc = ProbeCommit {
        hint: 0x0001,
        format_index: 2,
        frame_index: 1,
        frame_interval: 333_333,
        max_video_frame_size: 1_843_200,
        max_payload_transfer_size: 3072,
        ..ProbeCommit::default()
    };
    let encoded = pc.encode_v10();
    assert_eq!(encoded.len(), PROBE_COMMIT_LEN_V10);

    // hint at [0..2]
    if u16::from_le_bytes([encoded[0], encoded[1]]) != 0x0001 {
        return TestResult::Fail("hint field wrong");
    }
    // format_index at [2]
    if encoded[2] != 2 {
        return TestResult::Fail("format_index field wrong");
    }
    // frame_index at [3]
    if encoded[3] != 1 {
        return TestResult::Fail("frame_index field wrong");
    }
    // frame_interval at [4..8]
    if u32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]) != 333_333 {
        return TestResult::Fail("frame_interval field wrong");
    }

    // Round-trip through decode.
    let decoded = match ProbeCommit::decode_v10(&encoded) {
        Some(d) => d,
        None => return TestResult::Fail("decode_v10 returned None"),
    };
    if decoded != pc {
        return TestResult::Fail("encode/decode round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_probe_commit_encode_v10);

// ── Smoke 7: Probe control encode (34-byte UVC 1.5) ──────────────────

fn smoke_uvc_probe_commit_encode_v15() -> TestResult {
    use crate::uvc::control::{ProbeCommit, PROBE_COMMIT_LEN_V15};

    let pc = ProbeCommit {
        hint: 0x0001,
        format_index: 1,
        frame_index: 1,
        frame_interval: 333_333,
        clock_frequency: 48_000_000,
        framing_info: 0x03,
        preferred_version: 1,
        min_version: 1,
        max_version: 1,
        ..ProbeCommit::default()
    };
    let encoded = pc.encode_v15();
    assert_eq!(encoded.len(), PROBE_COMMIT_LEN_V15);

    // clock_frequency at [26..30]
    if u32::from_le_bytes([encoded[26], encoded[27], encoded[28], encoded[29]]) != 48_000_000 {
        return TestResult::Fail("clock_frequency field wrong in 34-byte encoding");
    }
    if encoded[30] != 0x03 {
        return TestResult::Fail("framing_info field wrong");
    }

    // Round-trip.
    let decoded = match ProbeCommit::decode_v15(&encoded) {
        Some(d) => d,
        None => return TestResult::Fail("decode_v15 returned None"),
    };
    if decoded != pc {
        return TestResult::Fail("v15 round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video/uvc", smoke_uvc_probe_commit_encode_v15);

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
