use super::*;
use alloc::string::String;
use core::fmt::Write;
use narf_kernel_test::{kernel_test_in, TestResult};

const VECTORS: &str = include_str!("../tests/dcn401_hdr/vectors.txt");

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn encoding(v: u32) -> Option<PixelEncoding> {
    Some(match v {
        1 => PixelEncoding::Rgb,
        2 => PixelEncoding::Ycbcr422,
        3 => PixelEncoding::Ycbcr444,
        4 => PixelEncoding::Ycbcr420,
        _ => return None,
    })
}

/// One vector's answer, in the harness's output format.
fn answer(input: &str) -> Option<String> {
    let w: alloc::vec::Vec<&str> = input.split_whitespace().collect();
    let num = |i: usize| w.get(i).and_then(|s| s.parse::<u32>().ok());
    let mut out = String::new();
    match *w.first()? {
        "meta" => {
            let blob = match (w[1], w[2]) {
                ("n", _) | (_, "-") => None,
                (_, b) => Some(unhex(b)?),
            };
            let m = match blob {
                // The harness hands over property-valid (32-byte) blobs only.
                Some(b) => Some(HdrOutputMetadata::from_blob(&b).ok()?),
                None => None,
            };
            let conn = if w[1] == "d" {
                HdrConnector::DisplayPort
            } else {
                HdrConnector::Hdmi
            };
            let p = hdr_info_packet(m.as_ref(), conn);
            let _ = write!(out, "ret 0 valid {} {}", u8::from(p.valid), hex(&p.bytes()));
        }
        "eq" => {
            let side = |s: &str| {
                if s == "-" {
                    Some(None)
                } else {
                    unhex(s).map(Some)
                }
            };
            let (a, b) = (side(w[1])?, side(w[2])?);
            let eq = metadata_equal(a.as_deref(), b.as_deref());
            let _ = write!(out, "eq {}", u8::from(eq));
        }
        "edid" => {
            let mut edid = alloc::vec![0u8; 128];
            edid.extend(unhex(w[1])?);
            match hdr_sink_metadata(&edid) {
                None => out.push_str("none"),
                Some(h) => {
                    let _ = write!(
                        out,
                        "hdr {} {} {} {} {} lum {} {}",
                        h.eotf,
                        h.metadata_type,
                        h.max_cll,
                        h.max_fall,
                        h.min_cll,
                        h.min_luminance,
                        h.max_luminance
                    );
                }
            }
        }
        "cs" => {
            let cs = output_color_space(
                num(1)?,
                num(2)? != 0,
                num(3)? != 0,
                num(4)?,
                num(5)? == 2, // DRM_HDMI_BROADCAST_RGB_LIMITED
            );
            let _ = write!(out, "{}", cs as u8);
        }
        "sig" => {
            let cs = DcColorSpace::from_linux(num(1)?)?;
            let enc = encoding(num(2)?)?;
            let bpc = u8::try_from(num(3)?).ok()?;
            let (qs, g22, vsc) = (num(4)? != 0, num(5)? != 0, num(6)? != 0);
            let misc1 = u32::from_str_radix(w.get(7)?, 16).ok()?;
            let a = avi_colorimetry(cs, enc, qs, g22);
            let (m0, m1) = msa_misc(cs, enc, bpc, vsc, misc1);
            let v = vsc_sdp(vsc, cs, enc, bpc, g22).map_or(String::from("-"), |p| hex(&p.bytes()));
            let _ = write!(
                out,
                "avi {} {} {} {} msa {m0} {m1} vsc {v}",
                a.c, a.ec, a.q, a.yq
            );
        }
        "hpo" => {
            let cs = DcColorSpace::from_linux(num(1)?)?;
            let enc = encoding(num(2)?)?;
            let bpc = u8::try_from(num(3)?).ok()?;
            let (m0, m1) = hpo_msa_misc(cs, enc, bpc, num(4)? != 0);
            let _ = write!(out, "msa {m0} {m1}");
        }
        _ => return None,
    }
    Some(out)
}

fn hdr_vectors_match_linux() -> TestResult {
    let mut n = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("vector format");
        };
        let Some(got) = answer(input) else {
            return TestResult::Fail("vector input");
        };
        if got != want {
            let _ = writeln!(
                narf_console::Writer,
                "hdr vector mismatch: {input}\n  want {want}\n  got  {got}"
            );
            return TestResult::Fail("output differs from Linux");
        }
        n += 1;
    }
    if n < 2000 {
        return TestResult::Fail("too few vectors");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/hdr", hdr_vectors_match_linux);

/// Only exactly sizeof(struct hdr_output_metadata) bytes decode.
fn hdr_blob_size_is_exact() -> TestResult {
    for len in [0, 1, 26, 30, 31, 33, 64] {
        if HdrOutputMetadata::from_blob(&alloc::vec![0u8; len]).is_ok() {
            return TestResult::Fail("wrong-size blob accepted");
        }
    }
    let mut b = [0u8; HDR_OUTPUT_METADATA_SIZE];
    b[4] = HDMI_EOTF_SMPTE_ST2084;
    b[22..24].copy_from_slice(&1000u16.to_le_bytes());
    b[26..28].copy_from_slice(&800u16.to_le_bytes());
    let Ok(m) = HdrOutputMetadata::from_blob(&b) else {
        return TestResult::Fail("valid blob refused");
    };
    let f = m.hdmi_metadata_type1;
    if f.eotf != 2 || f.max_display_mastering_luminance != 1000 || f.max_cll != 800 {
        return TestResult::Fail("field decode");
    }
    // A PQ InfoFrame: header 87 01 1a, checksum making the sum zero.
    let p = drm_infoframe(&m);
    if p[..3] != [0x87, 1, 0x1a] || p.iter().fold(0u8, |s, x| s.wrapping_add(*x)) != 0 {
        return TestResult::Fail("infoframe header/checksum");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/hdr", hdr_blob_size_is_exact);

/// No metadata gives an empty invalid packet; words follow bytes.
fn hdr_packet_absent_and_words() -> TestResult {
    if hdr_info_packet(None, HdrConnector::Hdmi) != InfoPacket::default() {
        return TestResult::Fail("absent metadata");
    }
    let m = HdrOutputMetadata::default();
    let p = hdr_info_packet(Some(&m), HdrConnector::DisplayPort);
    if !p.valid || p.words()[0] != 0x4c1d_8700 || p.words()[1] & 0xffff != 0x1a01 {
        return TestResult::Fail("DP SDP header words");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/hdr", hdr_packet_absent_and_words);

/// Empty, short and malformed EDIDs never panic and parse nothing.
fn hdr_sink_metadata_edge_cases() -> TestResult {
    if hdr_sink_metadata(&[]).is_some()
        || hdr_sink_metadata(&[0u8; 127]).is_some()
        || hdr_sink_metadata(&[0u8; 128]).is_some()
        || hdr_sink_metadata(&[0xffu8; 256]).is_some()
        || hdr_sink_metadata(&[0u8; 200]).is_some()
    {
        return TestResult::Fail("block parsed from nothing");
    }
    // Revision 2 CTA with a valid HDR block: DRM skips revisions below 3.
    let mut e = [0u8; 256];
    e[128..136].copy_from_slice(&[0x02, 2, 8, 0, 0xe3, 6, 0x05, 0x01]);
    let sum = e[128..255].iter().fold(0u8, |s, b| s.wrapping_add(*b));
    e[255] = 0u8.wrapping_sub(sum);
    if hdr_sink_metadata(&e).is_some() {
        return TestResult::Fail("revision 2 parsed");
    }
    e[129] = 3;
    e[255] = e[255].wrapping_sub(1);
    let Some(h) = hdr_sink_metadata(&e) else {
        return TestResult::Fail("revision 3 refused");
    };
    if h.eotf != 0x05 || h.metadata_type != 1 || h.max_cll != 0 {
        return TestResult::Fail("minimal block fields");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/hdr", hdr_sink_metadata_edge_cases);

/// The property lists amdgpu_dm's Colorspace enum carries.
fn hdr_colorspace_property_values() -> TestResult {
    let names: alloc::vec::Vec<&str> = hdmi_colorspaces().iter().map(|&(_, n)| n).collect();
    if names != ["Default", "BT709_YCC", "opRGB", "BT2020_RGB", "BT2020_YCC"]
        || dp_colorspaces() != hdmi_colorspaces()
        || !colorspace_valid(9)
        || colorspace_valid(1)
        || colorspace_valid(u64::from(u32::MAX) + 2)
    {
        return TestResult::Fail("colorspace enum");
    }
    if !use_vsc_sdp_for_colorimetry(0x14, 0x08)
        || use_vsc_sdp_for_colorimetry(0x12, 0x08)
        || use_vsc_sdp_for_colorimetry(0x14, 0xf7)
    {
        return TestResult::Fail("VSC colorimetry capability");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/hdr", hdr_colorspace_property_values);
