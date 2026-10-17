//! Register-, DDC- and EDID-model tests for the DCN3.0 HDMI owner. Literal
//! offsets are the `dcn_3_0_0_offset.h` ids of the instance under test.
use super::*;
use crate::amdgpu_navi22_modeset::Error as M;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    regs: Vec<u32>,
    data: Vec<u32>,
    conflict: bool,
}
impl Io for Fake {
    fn read(&mut self, reg: u64) -> u32 {
        let v = self.regs[reg as usize];
        if reg % STRIDE == VPG_GENERIC_STATUS % STRIDE && self.conflict {
            return v | VPG_GENERIC_CONFLICT_OCCURED;
        }
        v
    }
    fn write(&mut self, reg: u64, value: u32) {
        if reg % STRIDE == VPG_GENERIC_PACKET_DATA % STRIDE && reg > 0x2000 {
            self.data.push(value);
        }
        self.regs[reg as usize] = value;
    }
}
fn engine(dig: u8, transmitter: u8) -> Engine<Fake> {
    Engine::new_with(
        Fake {
            regs: vec![0; LAST_REG as usize + 1],
            data: Vec::new(),
            conflict: false,
        },
        Cap::bootstrap(),
        dig,
        transmitter,
    )
}
fn run<T>(f: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

fn dcn30_hdmi_routes_and_programs_tmds_stream() -> TestResult {
    let mut e = engine(1, 3);
    // GOP left HDMI_CONTROL with deep colour and scrambling set.
    e.io.regs[(HDMI_CONTROL + STRIDE) as usize] =
        HDMI_DEEP_COLOR_ENABLE | HDMI_DATA_SCRAMBLE_EN | 0x1000_0000;
    if e.check_idle().is_err()
        || e.connect_to_otg(2).is_err()
        || e.setup(DigMode::Hdmi).is_err()
        || e.connect_be_to_fe(true).is_err()
        || e.stream_attribute(148_500).is_err()
    {
        return TestResult::Fail("HDMI stream setup");
    }
    let r = &e.io.regs;
    // DIG3_DIG_BE_CNTL 0x23b0, DIG1_DIG_FE_CNTL 0x218b, DIG1_HDMI_CONTROL
    // 0x2193, DIG1_HDMI_VBI_PACKET_CONTROL 0x2197.
    if r[0x23b0] != 3 << 16 | 1 << 9
        || r[0x218b] & 7 != 2
        || r[0x2193]
            != HDMI_PACKET_GEN_VERSION | HDMI_KEEPOUT_MODE | HDMI_NO_EXTRA_NULL_PACKET_FILLED
        || r[0x2197] != HDMI_GC_CONT | HDMI_GC_SEND | HDMI_NULL_SEND
    {
        return TestResult::Fail("HDMI registers");
    }
    if e.stream_attribute(340_000) != Err(Error::Unsupported) {
        return TestResult::Fail("scrambled rate admitted unscrambled");
    }
    e.io.regs[0x23b1] = 1;
    if e.check_idle() != Err(Error::Busy) {
        return TestResult::Fail("live backend claimed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_routes_and_programs_tmds_stream
);

fn dcn30_hdmi_deep_colour_and_scrambler_bits() -> TestResult {
    let mut e = engine(0, 0);
    let ten = Format {
        depth: Depth::Bpc10,
        ..Format::RGB8
    };
    // 10 bpc at 371.25 MHz: depth 1 + enable, scrambler + 1/4 clock channel.
    if e.hdmi_stream_attribute(ten, 371_250, Scramble::Above340)
        .is_err()
    {
        return TestResult::Fail("10-bpc scrambled attribute");
    }
    let base = HDMI_PACKET_GEN_VERSION | HDMI_KEEPOUT_MODE | HDMI_NO_EXTRA_NULL_PACKET_FILLED;
    if e.io.regs[0x2093]
        != base | HDMI_DEEP_COLOR_ENABLE | 1 << 28 | HDMI_DATA_SCRAMBLE_EN | HDMI_CLOCK_CHANNEL_RATE
    {
        return TestResult::Fail("HDMI_CONTROL 10 bpc / >340");
    }
    // 12 bpc LTE_340MCSC: depth 2, scrambled at the character rate.
    let twelve = Format {
        depth: Depth::Bpc12,
        ..Format::RGB8
    };
    if e.hdmi_stream_attribute(twelve, 222_750, Scramble::LowRate)
        .is_err()
        || e.io.regs[0x2093] != base | HDMI_DEEP_COLOR_ENABLE | 2 << 28 | HDMI_DATA_SCRAMBLE_EN
    {
        return TestResult::Fail("HDMI_CONTROL 12 bpc low-rate");
    }
    // Back to 8 bpc clears depth, enable and scrambler.
    if e.hdmi_stream_attribute(Format::RGB8, 148_500, Scramble::Off)
        .is_err()
        || e.io.regs[0x2093] != base
    {
        return TestResult::Fail("HDMI_CONTROL reset");
    }
    // The scrambling decision must agree with the character clock.
    if e.hdmi_stream_attribute(Format::RGB8, 594_000, Scramble::Off) != Err(Error::Unsupported)
        || e.hdmi_stream_attribute(Format::RGB8, 297_000, Scramble::Above340)
            != Err(Error::Unsupported)
        || e.hdmi_stream_attribute(Format::RGB8, 600_001, Scramble::Above340)
            != Err(Error::Unsupported)
    {
        return TestResult::Fail("inconsistent scrambling admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_deep_colour_and_scrambler_bits
);

fn dcn30_hdmi_sends_avi_and_vendor_infoframes_and_stops() -> TestResult {
    let mut e = engine(0, 0);
    let mut avi = [0u8; 36];
    avi[..4].copy_from_slice(&[0x82, 2, 13, 0]);
    avi[8] = 16;
    if run(e.info_packets(&avi)).is_err() {
        return TestResult::Fail("AVI packet");
    }
    let r = &e.io.regs;
    // Nine VPG words for generic packet 0, immediate update, then
    // GENERIC0 CONT/SEND on line 2 and every other managed packet off.
    if e.io.data.len() != 9
        || e.io.data[0] != u32::from_le_bytes([0x82, 2, 13, 0])
        || r[VPG_GENERIC_PACKET_ACCESS_CTRL as usize] != 0
        || r[VPG_GSP_IMMEDIATE_UPDATE_CTRL as usize] & 1 == 0
        || r[HDMI_GENERIC_PACKET_CONTROL0 as usize] != 3
        || r[0x209e] != 2
        || r[HDMI_DB_CONTROL as usize] & HDMI_DB_DISABLE == 0
    {
        return TestResult::Fail("AVI programming");
    }
    // The HDMI vendor InfoFrame rides generic packet 1 (data index 9).
    let mut vendor = [0u8; 36];
    vendor[..3].copy_from_slice(&[0x81, 1, 5]);
    e.io.data.clear();
    if run(e.hdmi_info_packets(&avi, Some(&vendor))).is_err()
        || e.io.data.len() != 18
        || e.io.data[9] != u32::from_le_bytes([0x81, 1, 5, 0])
        || e.io.regs[VPG_GENERIC_PACKET_ACCESS_CTRL as usize] != 9
        || e.io.regs[VPG_GSP_IMMEDIATE_UPDATE_CTRL as usize] & 3 != 3
        || e.io.regs[HDMI_GENERIC_PACKET_CONTROL0 as usize] != 0x33
        || e.io.regs[0x209e] != 2 | 2 << 16
    {
        return TestResult::Fail("vendor InfoFrame");
    }
    // vpg3_update_generic_info_packet's REG_WAIT only logs: a conflict that
    // never clears still writes the packet.
    e.io.conflict = true;
    e.io.data.clear();
    if run(e.info_packets(&avi)).is_err() || e.io.data.len() != 9 {
        return TestResult::Fail("VPG conflict stopped the packet");
    }
    e.io.conflict = false;
    if run(e.info_packets(&[0; 36])) != Err(Error::Invalid)
        || run(e.hdmi_info_packets(&avi, Some(&[0; 36]))) != Err(Error::Invalid)
    {
        return TestResult::Fail("malformed packet");
    }
    e.io.regs[DIG_BE_CNTL as usize] = 3 << 16 | 1 << 8;
    if e.stop_info_packets().is_err()
        || e.set_avmute(true).is_err()
        || e.connect_be_to_fe(false).is_err()
        || e.io.regs[HDMI_GENERIC_PACKET_CONTROL0 as usize] != 0
        || e.io.regs[0x209e] != 0
        || e.io.regs[HDMI_GC as usize] & HDMI_GC_AVMUTE == 0
        || e.io.regs[DIG_BE_CNTL as usize] & DIG_FE_SOURCE_SELECT != 0
    {
        return TestResult::Fail("stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_sends_avi_and_vendor_infoframes_and_stops
);

// ── EDID model ───────────────────────────────────────────────────────

/// 640x480@60 (25.17 MHz), 720p60 (VIC 4), 1080p60 (VIC 16), 1080p120
/// (VIC 63), 2160p30 (VIC 95, HDMI VIC 1) and 2160p60 (VIC 97).
pub(super) const DTD_640X480: [u8; 18] = [
    0xd5, 0x09, 0x80, 0xa0, 0x20, 0xe0, 0x2d, 0x10, 0x10, 0x60, 0xa2, 0x00, 0, 0, 0, 0, 0, 0x18,
];
pub(super) const DTD_720P: [u8; 18] = [
    0x01, 0x1d, 0x00, 0x72, 0x51, 0xd0, 0x1e, 0x20, 0x6e, 0x28, 0x55, 0x00, 0, 0, 0, 0, 0, 0x1e,
];
const DTD_1080P: [u8; 18] = [
    0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c, 0x45, 0x00, 0, 0, 0, 0, 0, 0x1e,
];
const DTD_2160P30: [u8; 18] = [
    0x04, 0x74, 0x00, 0x30, 0xf2, 0x70, 0x5a, 0x80, 0xb0, 0x58, 0x8a, 0x00, 0, 0, 0, 0, 0, 0x1e,
];
const DTD_2160P60: [u8; 18] = [
    0x08, 0xe8, 0x00, 0x30, 0xf2, 0x70, 0x5a, 0x80, 0xb0, 0x58, 0x8a, 0x00, 0, 0, 0, 0, 0, 0x1e,
];
/// HDMI VSDB: DC_36/DC_30 flags and Max_TMDS_Clock (5 MHz units).
pub(super) fn vsdb(flags: u8, max_5mhz: u8) -> Vec<u8> {
    vec![0x67, 0x03, 0x0c, 0x00, 0x10, 0x00, flags, max_5mhz]
}
/// HF-VSDB: version 1, Max_TMDS_Character_Rate, SCDC_Present/LTE flags.
pub(super) fn hf_vsdb(rate_5mhz: u8, flags: u8) -> Vec<u8> {
    vec![0x67, 0xd8, 0x5d, 0xc4, 0x01, rate_5mhz, flags, 0x00]
}
/// A base block whose preferred mode is `dtd`, and one CTA extension
/// carrying `blocks`.
pub(super) fn edid(dtd: [u8; 18], blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut e = vec![0u8; 256];
    e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    e[18] = 1;
    e[19] = 4;
    e[54..72].copy_from_slice(&dtd);
    e[126] = 1;
    let ext = &mut e[128..];
    ext[0] = 2;
    ext[1] = 3;
    let mut p = 4;
    for b in blocks {
        ext[p..p + b.len()].copy_from_slice(b);
        p += b.len();
    }
    ext[2] = p as u8;
    for block in e.chunks_exact_mut(128) {
        let sum = block[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        block[127] = 0u8.wrapping_sub(sum);
    }
    e
}
fn first(edid: &[u8]) -> Timing {
    crate::amdgpu_navi48_boot::edid_timings(edid)[0]
}
fn stream(edid: &[u8], max_bpc: u8, limited: bool, limits: Limits) -> Option<Stream> {
    stream_for(edid, &first(edid), max_bpc, limited, limits)
}

fn dcn30_hdmi_scrambles_above_340_only_with_scdc() -> TestResult {
    // 2160p60 on an HDMI 2.0 sink (SCDC, 600 MHz): RGB 8 bpc, scrambled.
    let hdmi20 = edid(
        DTD_2160P60,
        &[vsdb(0, 68), hf_vsdb(120, 0x80), vec![0x41, 97]],
    );
    let Some(s) = stream(&hdmi20, 8, false, Limits::DEFAULT) else {
        return TestResult::Fail("2160p60 on HDMI 2.0");
    };
    if s.format != Format::RGB8
        || s.character_khz != 594_000
        || s.character_100hz != 5_940_000
        || s.scramble != Scramble::Above340
        || s.scramble.tmds_config() != 3
        || !s.scdc
        || s.avi.is_none_or(|a| a[8] != 97)
        || s.vendor.is_some()
    {
        return TestResult::Fail("HDMI 2.0 stream");
    }
    // Without SCDC (an HDMI 1.4 sink) the same mode does not fit.
    let hdmi14 = edid(DTD_2160P60, &[vsdb(0, 68), vec![0x41, 97]]);
    if stream(&hdmi14, 8, false, Limits::DEFAULT).is_some() {
        return TestResult::Fail("scrambled mode without SCDC");
    }
    // HDMI_6GB_EN clear or a PHYCLK below 594 MHz: refused.
    let no6g = Limits {
        hdmi6g: false,
        ..Limits::DEFAULT
    };
    let slow_phy = Limits {
        max_phy_khz: 540_000,
        ..Limits::DEFAULT
    };
    if stream(&hdmi20, 8, false, no6g).is_some() || stream(&hdmi20, 8, false, slow_phy).is_some() {
        return TestResult::Fail("board ceiling ignored");
    }
    // LTE_340Mcsc_scramble: 1080p scrambles at the character rate.
    let lte = edid(
        DTD_1080P,
        &[vsdb(0, 68), hf_vsdb(120, 0x88), vec![0x41, 16]],
    );
    if stream(&lte, 8, false, Limits::DEFAULT).map(|s| (s.scramble, s.scramble.tmds_config()))
        != Some((Scramble::LowRate, 1))
    {
        return TestResult::Fail("LTE_340MCSC");
    }
    // ... but not without SCDC_Present.
    let lte_no_scdc = edid(DTD_1080P, &[vsdb(0, 68), hf_vsdb(120, 0x08)]);
    if stream(&lte_no_scdc, 8, false, Limits::DEFAULT).map(|s| (s.scramble, s.scdc))
        != Some((Scramble::Off, false))
    {
        return TestResult::Fail("LTE without SCDC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_scrambles_above_340_only_with_scdc
);

fn dcn30_hdmi_deep_colour_follows_max_bpc_and_the_vsdb() -> TestResult {
    // 1080p60 on a DC_36/DC_30 sink.
    let deep = edid(DTD_1080P, &[vsdb(0x30 | 0x08, 68), vec![0x41, 16]]);
    let depth =
        |bpc| stream(&deep, bpc, false, Limits::DEFAULT).map(|s| (s.format.depth, s.character_khz));
    // Opt-in: 8 bpc unless amdgpu.max_bpc raises it.
    if depth(8) != Some((Depth::Bpc8, 148_500))
        || depth(10) != Some((Depth::Bpc10, 185_625))
        || depth(12) != Some((Depth::Bpc12, 222_750))
    {
        return TestResult::Fail("depth choice");
    }
    // A sink declaring only DC_30 never gets 12 bpc.
    let dc30 = edid(DTD_1080P, &[vsdb(0x10 | 0x08, 68), vec![0x41, 16]]);
    if stream(&dc30, 12, false, Limits::DEFAULT).map(|s| s.format.depth) != Some(Depth::Bpc10) {
        return TestResult::Fail("undeclared 12 bpc");
    }
    // Steps down by 2 bpc when the deeper clock exceeds the VSDB's 220 MHz.
    let tight = edid(DTD_1080P, &[vsdb(0x30 | 0x08, 44), vec![0x41, 16]]);
    if stream(&tight, 12, false, Limits::DEFAULT).map(|s| s.format.depth) != Some(Depth::Bpc10) {
        return TestResult::Fail("depth step-down");
    }
    // 1080p120 at 12 bpc is 445.5 MHz: scrambled on HDMI 2.0.
    let fast = edid(
        [
            0x04, 0x74, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c, 0x45, 0x00, 0, 0, 0, 0, 0,
            0x1e,
        ],
        &[vsdb(0x30 | 0x08, 68), hf_vsdb(120, 0x80)],
    );
    if stream(&fast, 12, false, Limits::DEFAULT)
        .map(|s| (s.format.depth, s.character_khz, s.scramble))
        != Some((Depth::Bpc12, 445_500, Scramble::Above340))
    {
        return TestResult::Fail("12-bpc scrambled");
    }
    // Deep colour truncates in 100 Hz as dcn3_get_pix_clk_dividers does.
    if Depth::Bpc10.character_100hz(25_175) != 314_687
        || Depth::Bpc12.character_khz(25_175) != 37_762
    {
        return TestResult::Fail("deep-colour clock rounding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_deep_colour_follows_max_bpc_and_the_vsdb
);

fn dcn30_hdmi_ycbcr420_for_420_only_and_420_also_modes() -> TestResult {
    // Y420VDB (VIC 97): 2160p60 only as 4:2:0, even on an HDMI 2.0 sink.
    let only = edid(
        DTD_2160P60,
        &[vsdb(0, 68), hf_vsdb(120, 0x80), vec![0xe2, 14, 97]],
    );
    let Some(s) = stream(&only, 12, true, Limits::DEFAULT) else {
        return TestResult::Fail("4:2:0-only mode");
    };
    if !s.format.ycbcr420
        || s.format.depth != Depth::Bpc8
        || s.format.limited
        || s.pixel_khz != 297_000
        || s.character_khz != 297_000
        || s.scramble != Scramble::Off
    {
        return TestResult::Fail("4:2:0 stream");
    }
    // AVI: Y = 4:2:0 (3), C = BT.709 (2), VIC 97.
    let Some(avi) = s.avi else {
        return TestResult::Fail("4:2:0 AVI");
    };
    if (avi[5] >> 5) & 3 != 3 || avi[6] >> 6 != 2 || avi[8] != 97 {
        return TestResult::Fail("4:2:0 AVI fields");
    }
    // Y420CMDB covering every SVD on an HDMI 1.4-rate sink: RGB does not
    // fit 594 MHz, so 4:2:0 at 297 MHz.
    let also = edid(DTD_2160P60, &[vsdb(0, 68), vec![0x41, 97], vec![0xe1, 15]]);
    if stream(&also, 8, false, Limits::DEFAULT).map(|s| (s.format.ycbcr420, s.pixel_khz))
        != Some((true, 297_000))
    {
        return TestResult::Fail("4:2:0-also fallback");
    }
    // Without HDMI_6GB_EN 4:2:0 still fits under 300 MHz.
    let no6g = Limits {
        hdmi6g: false,
        ..Limits::DEFAULT
    };
    if stream(&also, 8, false, no6g).is_none_or(|s| !s.format.ycbcr420) {
        return TestResult::Fail("4:2:0 without 6G");
    }
    // An RGB-capable mode never subsamples.
    let rgb = edid(DTD_1080P, &[vsdb(0, 68), vec![0x41, 16], vec![0xe1, 15]]);
    if stream(&rgb, 8, false, Limits::DEFAULT).is_none_or(|s| s.format.ycbcr420) {
        return TestResult::Fail("4:2:0 where RGB fits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_ycbcr420_for_420_only_and_420_also_modes
);

fn dcn30_hdmi_broadcast_rgb_vic_and_vendor_infoframe() -> TestResult {
    // A VCDB with QS: "Broadcast RGB" Limited signals Q = limited (1).
    let qs = edid(
        DTD_1080P,
        &[vsdb(0, 68), vec![0x41, 16], vec![0xe2, 0, 0x40]],
    );
    let (Some(full), Some(limited)) = (
        stream(&qs, 8, false, Limits::DEFAULT),
        stream(&qs, 8, true, Limits::DEFAULT),
    ) else {
        return TestResult::Fail("1080p");
    };
    let q = |s: &Stream| s.avi.map(|a| (a[7] >> 2) & 3);
    if full.format.limited
        || !limited.format.limited
        || q(&full) != Some(2)
        || q(&limited) != Some(1)
        || limited.avi.map(|a| a[8]) != Some(16)
    {
        return TestResult::Fail("Broadcast RGB / VIC 16");
    }
    // 2160p30 on an HDMI 1.4 sink: HDMI VIC 1 in the vendor InfoFrame, no
    // CTA VIC in the AVI.
    let uhd = edid(DTD_2160P30, &[vsdb(0, 68), vec![0x41, 95]]);
    let Some(s) = stream(&uhd, 8, false, Limits::DEFAULT) else {
        return TestResult::Fail("2160p30");
    };
    let Some(vendor) = s.vendor else {
        return TestResult::Fail("no vendor InfoFrame");
    };
    if s.avi.map(|a| a[8]) != Some(0)
        || vendor[..3] != [0x81, 1, 5]
        || vendor[5..8] != [0x03, 0x0c, 0x00]
        || vendor[8] != 1 << 5
        || vendor[9] != 1
        || s.scramble != Scramble::Off
    {
        return TestResult::Fail("HDMI VIC vendor InfoFrame");
    }
    // A DVI sink: no data islands, RGB 8 bpc.
    let dvi = edid(DTD_1080P, &[vec![0x41, 16]]);
    if stream(&dvi, 12, true, Limits::DEFAULT)
        .is_none_or(|s| s.avi.is_some() || s.vendor.is_some() || s.format != Format::RGB8)
    {
        return TestResult::Fail("DVI");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_broadcast_rgb_vic_and_vendor_infoframe
);

// ── SCDC over a DDC model ────────────────────────────────────────────

/// An SCDC sink on the DDC: its register file, every transaction, and an
/// optional NACK on everything.
pub(super) struct Scdc {
    pub regs: [u8; 256],
    pub log: Vec<(bool, u8, u8)>,
    pub nack: bool,
    /// NACK reads only (a sink that will not answer Sink_Version).
    pub nack_reads: bool,
}
impl Scdc {
    pub fn new(sink_version: u8) -> Self {
        let mut regs = [0; 256];
        regs[usize::from(scdc::SINK_VERSION)] = sink_version;
        Self {
            regs,
            log: Vec::new(),
            nack: false,
            nack_reads: false,
        }
    }
}
impl Aux for Scdc {
    async fn read(&mut self, _: u32, _: &mut [u8]) -> Result<(), M> {
        Err(M::Aux)
    }
    async fn write(&mut self, _: u32, _: &[u8]) -> Result<(), M> {
        Err(M::Aux)
    }
    async fn scdc_read(&mut self, offset: u8) -> Result<u8, M> {
        if self.nack || self.nack_reads {
            return Err(M::Hdmi(Error::Scdc));
        }
        let v = self.regs[usize::from(offset)];
        self.log.push((false, offset, v));
        Ok(v)
    }
    async fn scdc_write(&mut self, offset: u8, value: u8) -> Result<(), M> {
        if self.nack {
            return Err(M::Hdmi(Error::Scdc));
        }
        self.regs[usize::from(offset)] = value;
        self.log.push((true, offset, value));
        Ok(())
    }
}

fn dcn30_hdmi_scdc_protocol_matches_link_ddc() -> TestResult {
    let hdmi20 = edid(
        DTD_2160P60,
        &[vsdb(0, 68), hf_vsdb(120, 0x80), vec![0x41, 97]],
    );
    let s = stream(&hdmi20, 8, false, Limits::DEFAULT).unwrap();
    // Sink version 1: Source_Version 1, then TMDS_Config 3.
    let mut ddc = Scdc::new(1);
    if run(write_scdc_data(&mut ddc, &s)).is_err()
        || ddc.log != [(false, 0x01, 1), (true, 0x02, 1), (true, 0x20, 3)]
    {
        return TestResult::Fail("write_scdc_data v1");
    }
    // read_scdc_data: TMDS_Config, then scrambler status and flags.
    ddc.regs[0x21] = 1;
    ddc.regs[0x40] = 0x0f;
    ddc.log.clear();
    let status = run(read_scdc_data(&mut ddc, &s));
    if status
        != Some(ScdcStatus {
            tmds_config: 3,
            scrambler_status: Some(1),
            status_flags: Some(0x0f),
        })
        || ddc.log.len() != 3
    {
        return TestResult::Fail("read_scdc_data");
    }
    // Any other sink version: no Source_Version write.
    let mut v0 = Scdc::new(0);
    if run(write_scdc_data(&mut v0, &s)).is_err() || v0.log != [(false, 1, 0), (true, 0x20, 3)] {
        return TestResult::Fail("write_scdc_data v0");
    }
    // A Sink_Version read that fails is `sink_version = 0` in link_ddc.c:
    // no Source_Version, and TMDS_Config is still written (the old code
    // aborted, leaving a scrambled stream the sink was never told about).
    let mut mute = Scdc::new(1);
    mute.nack_reads = true;
    if run(write_scdc_data(&mut mute, &s)).is_err() || mute.log != [(true, 0x20, 3)] {
        return TestResult::Fail("failed Sink_Version read must still write TMDS_Config");
    }
    // A scrambled stream whose SCDC fails fails the link.
    let mut nack = Scdc::new(1);
    nack.nack = true;
    if run(write_scdc_data(&mut nack, &s)) != Err(Error::Scdc) {
        return TestResult::Fail("scrambled SCDC failure ignored");
    }
    // An unscrambled stream to an SCDC sink writes TMDS_Config 0 (a GOP or
    // warm reboot may have left it scrambled), and ignores failures.
    let legacy = edid(
        DTD_1080P,
        &[vsdb(0, 68), hf_vsdb(120, 0x80), vec![0x41, 16]],
    );
    let s14 = stream(&legacy, 8, false, Limits::DEFAULT).unwrap();
    let mut left_scrambled = Scdc::new(1);
    left_scrambled.regs[0x20] = 3;
    if run(write_scdc_data(&mut left_scrambled, &s14)).is_err()
        || left_scrambled.regs[0x20] != 0
        || run(write_scdc_data(&mut nack, &s14)).is_err()
    {
        return TestResult::Fail("legacy TMDS_Config");
    }
    // No SCDC declared: no traffic at all.
    let none = edid(DTD_1080P, &[vsdb(0, 68), vec![0x41, 16]]);
    let s_none = stream(&none, 8, false, Limits::DEFAULT).unwrap();
    let mut quiet = Scdc::new(1);
    run(write_scdc_legacy(&mut quiet, s_none.scdc));
    if run(write_scdc_data(&mut quiet, &s_none)).is_err()
        || run(read_scdc_data(&mut quiet, &s_none)).is_some()
        || !quiet.log.is_empty()
    {
        return TestResult::Fail("SCDC traffic to a non-SCDC sink");
    }
    // Disable/unplug: Source_Version again, then TMDS_Config 0, best effort.
    let mut down = Scdc::new(1);
    down.regs[0x20] = 3;
    run(write_scdc_legacy(&mut down, true));
    run(write_scdc_legacy(&mut nack, true));
    if down.log != [(false, 1, 1), (true, 2, 1), (true, 0x20, 0)] {
        return TestResult::Fail("write_scdc_legacy");
    }
    // The default (DP AUX) channel has no SCDC.
    let mut aux = crate::amdgpu_navi22_modeset::NoAux;
    if run(write_scdc_data(&mut aux, &s)) != Err(Error::Scdc) {
        return TestResult::Fail("SCDC over AUX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_scdc_protocol_matches_link_ddc
);

// ── Output format stages ─────────────────────────────────────────────

struct Banks(BTreeMap<(format::Bank, u64), u32>);
impl format::Io for Banks {
    fn read(&mut self, bank: format::Bank, reg: u64) -> u32 {
        *self.0.get(&(bank, reg)).unwrap_or(&0)
    }
    fn write(&mut self, bank: format::Bank, reg: u64, value: u32) {
        self.0.insert((bank, reg), value);
    }
}
fn formatter(pipe: u8) -> format::Engine<Banks> {
    format::Engine::new_with(Banks(BTreeMap::new()), Cap::bootstrap(), pipe)
}
fn two(f: &format::Engine<Banks>, reg: u64) -> u32 {
    *f.io.0.get(&(format::Bank::Two, reg)).unwrap_or(&0)
}
fn three(f: &format::Engine<Banks>, reg: u64) -> u32 {
    *f.io.0.get(&(format::Bank::Three, reg)).unwrap_or(&0)
}

fn dcn30_hdmi_fmt_dither_clamp_and_420() -> TestResult {
    // Pipe 1: FMT1_* at 0x1899.. (stride 0x5a).
    let mut f = formatter(1);
    // GOP leftovers: truncation, temporal dither, 4:2:2 encoding.
    f.io.0.insert((format::Bank::Two, 0x189b), 0x0001_0031);
    f.io.0.insert((format::Bank::Two, 0x189a), 0x0005_0000);
    if f.program_fmt(Format::RGB8).is_err() {
        return TestResult::Fail("8-bpc FMT");
    }
    // SPATIAL8: dither depth 1, high-pass and RGB random; dynamic expansion
    // 8->12; clamp full range; RGB encoding.
    if two(&f, 0x189b) != 0x100 | 1 << 11 | 1 << 15 | 1 << 14
        || two(&f, 0x1899) != 0x11
        || two(&f, 0x189f) != 1
        || two(&f, 0x189a) & 0x2f_0000 != 0
        || two(&f, 0x18a3) != 0
    {
        return TestResult::Fail("SPATIAL8");
    }
    let ten = Format {
        depth: Depth::Bpc10,
        ..Format::RGB8
    };
    if f.program_fmt(ten).is_err()
        || two(&f, 0x189b) != 0x100 | 2 << 11 | 1 << 15 | 1 << 14
        || two(&f, 0x1899) != 0x01
    {
        return TestResult::Fail("SPATIAL10");
    }
    let twelve = Format {
        depth: Depth::Bpc12,
        ..Format::RGB8
    };
    if f.program_fmt(twelve).is_err() || two(&f, 0x189b) != 0 || two(&f, 0x1899) != 0x01 {
        return TestResult::Fail("12 bpc: no dither");
    }
    // 4:2:0: encoding 2, subsampling 2, CbCr bypass; MAP420 memory forced on;
    // no RGB random.
    f.io.0.insert((format::Bank::Two, 0x18a1), 0x3);
    let yuv = Format {
        ycbcr420: true,
        ..Format::RGB8
    };
    if f.program_fmt(yuv).is_err()
        || two(&f, 0x189a) & 0x2f_0000 != 0x2a_0000
        || two(&f, 0x18a1) & 3 != 0
        || two(&f, 0x189b) != 0x100 | 1 << 11 | 1 << 15
    {
        return TestResult::Fail("4:2:0 FMT");
    }
    // OTG 2: ODM2_OPTC_DATA_FORMAT_CONTROL 0x1aec, OTG2_OTG_H_TIMING_CNTL 0x1c2e.
    let mut g = formatter(2);
    if g.program_otg(yuv).is_err() || two(&g, 0x1aec) != 2 || two(&g, 0x1c2e) != 1 {
        return TestResult::Fail("4:2:0 OTG");
    }
    if g.program_otg(Format::RGB8).is_err() || two(&g, 0x1aec) != 0 || two(&g, 0x1c2e) != 0 {
        return TestResult::Fail("RGB OTG");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_fmt_dither_clamp_and_420
);

fn dcn30_hdmi_ocsc_and_blank_black_per_colour_space() -> TestResult {
    let mut f = formatter(1);
    let yuv = Format {
        ycbcr420: true,
        ..Format::RGB8
    };
    // MPC_OUT1_CSC_MODE 0x5a6, MPC_OUT1_CSC_C11_C12_A 0x5a7..0x5ac,
    // MPCC1_MPCC_MEM_PWR_CTRL 0x2c.
    if run(f.program_ocsc(yuv)).is_err()
        || three(&f, 0x2c) & 4 == 0
        || three(&f, 0x598) != 0
        || three(&f, 0x5a6) != 1
        || three(&f, 0x5a7) != 0xf345 << 16 | 0xe04
        || three(&f, 0x5ac) != 0x1004 << 16 | 0xe04
    {
        return TestResult::Fail("YCbCr709 OCSC");
    }
    let limited = Format {
        limited: true,
        ..Format::RGB8
    };
    if run(f.program_ocsc(limited)).is_err()
        || three(&f, 0x5a7) != 0x1b67
        || three(&f, 0x5a8) != 0x201 << 16
    {
        return TestResult::Fail("sRGB limited OCSC");
    }
    if run(f.program_ocsc(Format::RGB8)).is_err()
        || three(&f, 0x5a7) != 0x2000
        || three(&f, 0x5a9) != 0x2000 << 16
    {
        return TestResult::Fail("sRGB OCSC");
    }
    // The OGAM memory that never powers on is logged, not fatal (REG_WAIT).
    f.io.0.insert((format::Bank::Three, 0x2c), 0x300);
    if run(f.program_ocsc(Format::RGB8)).is_err() {
        return TestResult::Fail("memory power timeout fatal");
    }
    // DPG1 colours 0x18b1..0x18b3: YUV_CV black, both colours, << 6.
    let dup = |c: u32| (c << 6) << 16 | c << 6;
    if f.set_blank_color(yuv).is_err()
        || two(&f, 0x18b1) != dup(0x1f4)
        || two(&f, 0x18b2) != dup(0x40)
        || two(&f, 0x18b3) != dup(0x1f4)
    {
        return TestResult::Fail("YCbCr black");
    }
    if f.set_blank_color(limited).is_err() || two(&f, 0x18b1) != dup(0x40) {
        return TestResult::Fail("limited black");
    }
    if f.set_blank_color(Format::RGB8).is_err() || two(&f, 0x18b2) != 0 {
        return TestResult::Fail("full-range black");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_ocsc_and_blank_black_per_colour_space
);

#[path = "amdgpu_dcn30_hdmi_modeset_tests.rs"]
mod modeset_tests;
