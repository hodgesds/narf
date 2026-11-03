//! Native tests for the VBT parser: synthetic VBT, OpRegion and option
//! ROM images built from the `intel_vbt_defs.h` / `intel_opregion.c`
//! layouts (offsets transcribed independently of the parser and checked
//! against a host compile of the Linux header).
extern crate alloc;

use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

// ── Builders ─────────────────────────────────────────────────────────

/// A VBT image: 48-byte VBT header, 22-byte BDB header, blocks.
#[derive(Debug)]
pub struct VbtImage {
    version: u16,
    blocks: Vec<(u8, Vec<u8>)>,
}

impl VbtImage {
    pub fn new(version: u16) -> Self {
        Self {
            version,
            blocks: Vec::new(),
        }
    }

    pub fn block(mut self, id: u8, data: Vec<u8>) -> Self {
        self.blocks.push((id, data));
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut bdb = Vec::new();
        bdb.extend_from_slice(b"BIOS_DATA_BLOCK ");
        bdb.extend_from_slice(&self.version.to_le_bytes());
        bdb.extend_from_slice(&22u16.to_le_bytes());
        bdb.extend_from_slice(&0u16.to_le_bytes());
        for (id, data) in &self.blocks {
            bdb.push(*id);
            bdb.extend_from_slice(&(data.len() as u16).to_le_bytes());
            bdb.extend_from_slice(data);
        }
        let bdb_size = bdb.len() as u16;
        bdb[20..22].copy_from_slice(&bdb_size.to_le_bytes());
        let mut vbt = Vec::new();
        let mut sig = [0u8; 20];
        sig[..15].copy_from_slice(b"$VBT METEORLAKE");
        vbt.extend_from_slice(&sig);
        vbt.extend_from_slice(&100u16.to_le_bytes());
        vbt.extend_from_slice(&48u16.to_le_bytes());
        let vbt_size = (48 + bdb.len()) as u16;
        vbt.extend_from_slice(&vbt_size.to_le_bytes());
        vbt.push(0);
        vbt.push(0);
        vbt.extend_from_slice(&48u32.to_le_bytes());
        vbt.extend_from_slice(&[0u8; 16]);
        vbt.extend_from_slice(&bdb);
        vbt
    }
}

/// A 44-byte `child_device_config`.
#[derive(Clone, Copy, Debug)]
pub struct Child {
    raw: [u8; 44],
}

impl Child {
    pub fn new(device_type: u16, dvo_port: u8) -> Self {
        let mut raw = [0u8; 44];
        raw[0..2].copy_from_slice(&0x0004u16.to_le_bytes());
        raw[2..4].copy_from_slice(&device_type.to_le_bytes());
        raw[16] = dvo_port;
        Self { raw }
    }
    pub fn ddc(mut self, code: u8) -> Self {
        self.raw[19] = code;
        self
    }
    pub fn aux(mut self, code: u8) -> Self {
        self.raw[25] = code;
        self
    }
    pub fn typec(mut self) -> Self {
        self.raw[33] |= 1;
        self
    }
    pub fn tbt(mut self) -> Self {
        self.raw[33] |= 2;
        self
    }
    pub fn dedicated_external(mut self) -> Self {
        self.raw[33] |= 4;
        self
    }
    pub fn lane_reversal(mut self) -> Self {
        self.raw[23] |= 2;
        self
    }
    pub fn byte(mut self, off: usize, value: u8) -> Self {
        self.raw[off] = value;
        self
    }
}

/// A general-definitions block with `size`-byte children.
pub fn general_definitions(size: u8, children: &[Child]) -> Vec<u8> {
    let mut block = alloc::vec![0u8, 0, 0, 0, size];
    for child in children {
        let n = (size as usize).min(44);
        block.extend_from_slice(&child.raw[..n]);
        block.resize(block.len() + (size as usize - n), 0);
    }
    block
}

/// A general-features block with `enable_ssc`.
pub fn general_features(enable_ssc: bool) -> Vec<u8> {
    let mut g = alloc::vec![0u8; 7];
    if enable_ssc {
        g[1] |= 1 << 1;
    }
    g
}

/// The MTL reference board used by the policy tests: eDP on DDI A,
/// DP++ on DDI B (VBT DDC "dpb"), USB-C DP-alt TC1, legacy HDMI TC2 (VBT
/// DDC "tc2"), USB-C/TBT TC3 declared with HDMI too, and TC4 absent.
pub fn mtl_reference_children() -> Vec<Child> {
    use device_type::*;
    alloc::vec![
        Child::new(EDP, dvo_port::DPA).aux(dp_aux::A),
        Child::new(DP_DUAL_MODE, dvo_port::DPB)
            .aux(dp_aux::B)
            .ddc(2),
        Child::new(DP, dvo_port::DPF).aux(dp_aux::F).typec(),
        Child::new(HDMI, dvo_port::HDMIG).aux(dp_aux::G).ddc(4),
        Child::new(DP_DUAL_MODE, dvo_port::DPH)
            .aux(dp_aux::H)
            .ddc(5)
            .typec()
            .tbt(),
    ]
}

pub fn mtl_reference_vbt(version: u16, enable_ssc: bool) -> Vec<u8> {
    VbtImage::new(version)
        .block(block::GENERAL_FEATURES, general_features(enable_ssc))
        .block(
            block::GENERAL_DEFINITIONS,
            general_definitions(44, &mtl_reference_children()),
        )
        .build()
}

// ── Header and block walk ────────────────────────────────────────────

fn vbt_header_validation_refusals() -> TestResult {
    let image = mtl_reference_vbt(250, true);
    let mut padded = image.clone();
    padded.extend_from_slice(&[0xAA; 64]);
    match validate_vbt(&padded) {
        Ok(vbt) if vbt.len() == image.len() => {}
        _ => return TestResult::Fail("a valid VBT must validate to exactly vbt_size bytes"),
    }
    if validate_vbt(&image[..47]) != Err(VbtError::HeaderIncomplete) {
        return TestResult::Fail("47 bytes is an incomplete VBT header");
    }
    let mut bad = image.clone();
    bad[1] = b'X';
    if validate_vbt(&bad) != Err(VbtError::BadSignature) {
        return TestResult::Fail("a non-$VBT signature must refuse");
    }
    // vbt_size one byte larger than the buffer.
    let mut over = image.clone();
    let size = (image.len() as u16 + 1).to_le_bytes();
    over[24..26].copy_from_slice(&size);
    if validate_vbt(&over) != Err(VbtError::VbtSizeOverflow) {
        return TestResult::Fail("vbt_size past the buffer must refuse");
    }
    // bdb_offset leaving fewer than 22 bytes for the BDB header.
    let mut bdb_hdr = image.clone();
    let off = (image.len() as u32 - 21).to_le_bytes();
    bdb_hdr[28..32].copy_from_slice(&off);
    if validate_vbt(&bdb_hdr) != Err(VbtError::BdbHeaderIncomplete) {
        return TestResult::Fail("a BDB header past vbt_size must refuse");
    }
    // bdb_offset at vbt_size exactly (range_overflows: start >= max).
    let mut at_end = image.clone();
    at_end[28..32].copy_from_slice(&(image.len() as u32).to_le_bytes());
    if validate_vbt(&at_end) != Err(VbtError::BdbHeaderIncomplete) {
        return TestResult::Fail("bdb_offset == vbt_size must refuse");
    }
    // bdb_size running one byte past vbt_size.
    let mut bdb_over = image.clone();
    let bdb_size = (image.len() as u16 - 48 + 1).to_le_bytes();
    bdb_over[48 + 20..48 + 22].copy_from_slice(&bdb_size);
    if validate_vbt(&bdb_over) != Err(VbtError::BdbIncomplete) {
        return TestResult::Fail("bdb_size past vbt_size must refuse");
    }
    if Vbt::parse(&bdb_over).is_ok() || Vbt::parse(&image[..60]).is_ok() {
        return TestResult::Fail("parse must refuse what validation refuses");
    }
    // Every truncation of the image refuses rather than panicking.
    for cut in 0..image.len() {
        if Vbt::parse(&image[..cut]).is_ok() {
            return TestResult::Fail("a truncated VBT must never parse");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_vbt", vbt_header_validation_refusals);

fn vbt_block_walk_bounds_padding_and_mipi_size() -> TestResult {
    // A short general-features block (2 bytes) is zero padded to 7 and
    // still yields enable_ssc (init_bdb_block's max(min_size, size)).
    let short = VbtImage::new(250)
        .block(block::GENERAL_FEATURES, alloc::vec![0, 1 << 1])
        .build();
    match Vbt::parse(&short).map(|v| v.general_features()) {
        Ok(Some(g)) if g.enable_ssc && !g.dp_ssc_enable => {}
        _ => return TestResult::Fail("a short block must parse zero padded"),
    }
    // A block whose size runs past bdb_size ends the walk: the block
    // after it is not found (find_raw_section returns NULL).
    let mut cut = VbtImage::new(250)
        .block(block::DRIVER_FEATURES, alloc::vec![0u8; 19])
        .block(block::GENERAL_FEATURES, general_features(false))
        .build();
    let id_at = 48 + 22;
    cut[id_at + 1..id_at + 3].copy_from_slice(&0x0400u16.to_le_bytes());
    match Vbt::parse(&cut) {
        Ok(v) if v.driver_features().is_none() && v.general_features().is_none() => {}
        _ => return TestResult::Fail("an overrunning block must end the walk"),
    }
    // The walk honours header_size: a larger BDB header skips bytes.
    let mut skip = VbtImage::new(250)
        .block(0x7F, alloc::vec![0u8; 4])
        .block(block::GENERAL_FEATURES, general_features(false))
        .build();
    skip[48 + 18..48 + 20].copy_from_slice(&(22u16 + 7).to_le_bytes());
    match Vbt::parse(&skip) {
        Ok(v) if v.general_features().is_some_and(|g| !g.enable_ssc) => {}
        _ => return TestResult::Fail("blocks after header_size must be found"),
    }
    // MIPI sequence v3+: the u32 at +4 is the size the walk skips
    // (_get_blocksize), so the general-features block after it is found;
    // the u16 size field (rewritten to 1) is ignored. Walking by it would
    // land inside the block and end the walk on its 0xEE bytes.
    let mut mipi = alloc::vec![3u8];
    mipi.extend_from_slice(&11u32.to_le_bytes());
    mipi.extend_from_slice(&[0xEE; 6]);
    let mut img = VbtImage::new(250)
        .block(block::MIPI_SEQUENCE, mipi)
        .block(block::GENERAL_FEATURES, general_features(true))
        .build();
    let m = 48 + 22;
    img[m + 1..m + 3].copy_from_slice(&1u16.to_le_bytes());
    match Vbt::parse(&img) {
        Ok(v) if v.general_features().is_some_and(|g| g.enable_ssc) => {}
        _ => return TestResult::Fail("MIPI v3 u32 block size must drive the walk"),
    }
    // A MIPI v3 u32 size that overruns ends the walk.
    img[m + 4..m + 8].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    match Vbt::parse(&img) {
        Ok(v) if v.general_features().is_none() => {}
        _ => return TestResult::Fail("an overrunning MIPI v3 size must end the walk"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_block_walk_bounds_padding_and_mipi_size
);

fn vbt_general_features_ssc_bits_and_default() -> TestResult {
    let mut g = alloc::vec![0u8; 7];
    g[1] = (1 << 1) | (1 << 2) | (1 << 6);
    g[4] = (1 << 3) | (1 << 4) | (1 << 5);
    let vbt = match Vbt::parse(&VbtImage::new(250).block(block::GENERAL_FEATURES, g).build()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("general features VBT must parse"),
    };
    let want = GeneralFeatures {
        enable_ssc: true,
        ssc_freq: true,
        dp_ssc_enable: true,
        dp_ssc_freq: true,
        dp_ssc_dongle_supported: true,
        display_clock_mode: true,
    };
    if vbt.general_features() != Some(want) || !vbt.use_ssc() {
        return TestResult::Fail("BDB_GENERAL_FEATURES bits decode per intel_vbt_defs.h");
    }
    // init_vbt_defaults: lvds_use_ssc = 1 without the block.
    let none = Vbt::parse(&VbtImage::new(250).build()).unwrap();
    if none.general_features().is_some() || !none.use_ssc() {
        return TestResult::Fail("no general-features block keeps the SSC default on");
    }
    let off = Vbt::parse(&mtl_reference_vbt(250, false)).unwrap();
    if off.use_ssc() {
        return TestResult::Fail("enable_ssc clear must disable SSC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_general_features_ssc_bits_and_default
);

// ── Child devices ───────────────────────────────────────────────────

fn vbt_child_devices_sizes_and_flags() -> TestResult {
    use device_type::*;
    let children = [
        Child::new(HDMI, dvo_port::HDMIB).byte(7, 0x6A),
        Child::new(0, dvo_port::DPC),
        Child::new(DP_DUAL_MODE, dvo_port::DPB).aux(dp_aux::B),
    ];
    // 44-byte children: the zero device_type is skipped.
    let vbt = Vbt::parse(
        &VbtImage::new(250)
            .block(
                block::GENERAL_DEFINITIONS,
                general_definitions(44, &children),
            )
            .build(),
    )
    .unwrap();
    if vbt.children().len() != 2 || vbt.children()[1].dvo_port() != dvo_port::DPB {
        return TestResult::Fail("children with device_type 0 must be skipped");
    }
    // 39-byte (BDB 216) and legacy 33-byte children copy what exists.
    for size in [39u8, 33] {
        let v = Vbt::parse(
            &VbtImage::new(216)
                .block(
                    block::GENERAL_DEFINITIONS,
                    general_definitions(size, &children),
                )
                .build(),
        )
        .unwrap();
        if v.children().len() != 2 || v.children()[1].aux_channel() != dp_aux::B {
            return TestResult::Fail("smaller valid child sizes must parse");
        }
    }
    // Below the legacy 33 bytes (or zero) no child is parsed.
    for size in [32u8, 0] {
        let mut block = general_definitions(44, &children);
        block[4] = size;
        let v = Vbt::parse(
            &VbtImage::new(250)
                .block(block::GENERAL_DEFINITIONS, block)
                .build(),
        )
        .unwrap();
        if !v.children().is_empty() {
            return TestResult::Fail("child_dev_size below 33 must yield no devices");
        }
    }
    // A block smaller than its 5-byte header yields none.
    let v = Vbt::parse(
        &VbtImage::new(250)
            .block(block::GENERAL_DEFINITIONS, alloc::vec![0, 0, 0, 0])
            .build(),
    )
    .unwrap();
    if !v.children().is_empty() {
        return TestResult::Fail("a short general-definitions block yields no devices");
    }
    // A trailing partial child is not read.
    let mut partial = general_definitions(44, &children[..1]);
    partial.extend_from_slice(&[0x12; 20]);
    let v = Vbt::parse(
        &VbtImage::new(250)
            .block(block::GENERAL_DEFINITIONS, partial)
            .build(),
    )
    .unwrap();
    if v.children().len() != 1 {
        return TestResult::Fail("a partial trailing child must not be parsed");
    }
    if child_device_expected_size(263) != Some(44)
        || child_device_expected_size(256) != Some(40)
        || child_device_expected_size(216) != Some(39)
        || child_device_expected_size(196) != Some(38)
        || child_device_expected_size(195) != Some(37)
        || child_device_expected_size(155) != Some(33)
        || child_device_expected_size(265).is_some()
    {
        return TestResult::Fail("child_device_expected_size differs from intel_bios.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_child_devices_sizes_and_flags
);

fn vbt_child_support_flags_follow_versions() -> TestResult {
    use device_type::*;
    let hdmi = ChildDevice::from_raw(&Child::new(HDMI, dvo_port::HDMIB).byte(7, 0x6A).raw, 250);
    if !hdmi.supports_hdmi() || !hdmi.supports_dvi() || hdmi.supports_dp() || hdmi.supports_edp() {
        return TestResult::Fail("DEVICE_TYPE_HDMI is TMDS + HDMI, not DP");
    }
    // hdmi_level_shifter_value 10, hdmi_max_data_rate 3 (594 MHz).
    if hdmi.hdmi_level_shift(12) != Some(10)
        || hdmi.hdmi_level_shift(14).is_some()
        || hdmi.hdmi_max_tmds_clock_khz() != 594_000
    {
        return TestResult::Fail("level shifter and max TMDS must decode by version");
    }
    let old = ChildDevice::from_raw(hdmi.raw(), 203);
    if old.hdmi_max_tmds_clock_khz() != 0
        || ChildDevice::from_raw(hdmi.raw(), 157)
            .hdmi_level_shift(12)
            .is_some()
    {
        return TestResult::Fail("max TMDS needs 204+, level shift 158+");
    }
    for (code, khz) in [
        (1u8, 297_000),
        (2, 165_000),
        (4, 340_000),
        (5, 300_000),
        (0, 0),
        (7, 0),
    ] {
        let c = ChildDevice::from_raw(&Child::new(HDMI, 1).byte(7, code << 5).raw, 250);
        if c.hdmi_max_tmds_clock_khz() != khz {
            return TestResult::Fail("HDMI_MAX_DATA_RATE_* decode differs from Linux");
        }
    }
    let dvi = ChildDevice::from_raw(&Child::new(HDMI | NOT_HDMI_OUTPUT, 1).raw, 250);
    if !dvi.supports_dvi() || dvi.supports_hdmi() {
        return TestResult::Fail("NOT_HDMI_OUTPUT keeps DVI and drops HDMI");
    }
    let edp = ChildDevice::from_raw(&Child::new(EDP, dvo_port::DPA).raw, 250);
    if !edp.supports_edp() || !edp.supports_dp() {
        return TestResult::Fail("DEVICE_TYPE_eDP is DP + internal");
    }
    let dsi = ChildDevice::from_raw(&Child::new(MIPI_OUTPUT, dvo_port::MIPIA).raw, 250);
    if !dsi.supports_dsi() {
        return TestResult::Fail("MIPI output is DSI");
    }
    // Type-C bits are version gated: typec 195+, tbt 209+, dedicated 264+.
    let tc = Child::new(DP, dvo_port::DPF)
        .typec()
        .tbt()
        .dedicated_external();
    let at = |v: u16| ChildDevice::from_raw(&tc.raw, v);
    if at(194).supports_typec_usb()
        || !at(195).supports_typec_usb()
        || at(208).supports_tbt()
        || !at(209).supports_tbt()
        || at(263).dedicated_external()
        || !at(264).dedicated_external()
    {
        return TestResult::Fail("Type-C bits must follow their BDB versions");
    }
    // sanitize_dedicated_external clears typec/tbt/dyn on 264+ only.
    let s = at(264).sanitized();
    if s.supports_typec_usb() || s.supports_tbt() || !s.dedicated_external() {
        return TestResult::Fail("dedicated external must drop Type-C/TBT");
    }
    if !at(263).sanitized().supports_tbt() {
        return TestResult::Fail("sanitize must not act before BDB 264");
    }
    // DP dual mode: DP + HDMI on a DP dvo port, or an HDMI dvo port with
    // an AUX channel.
    let dpp = |dvo: u8, aux: u8| {
        ChildDevice::from_raw(&Child::new(DP_DUAL_MODE, dvo).aux(aux).raw, 250)
            .supports_dp_dual_mode()
    };
    if !dpp(dvo_port::DPB, 0) || !dpp(dvo_port::HDMIB, dp_aux::B) || dpp(dvo_port::HDMIB, 0) {
        return TestResult::Fail("dual mode must follow intel_bios_encoder_supports_dp_dual_mode");
    }
    // Lane reversal, DP max link rate (216 vs 230 encodings), lane count.
    let c = Child::new(DP, dvo_port::DPB)
        .lane_reversal()
        .byte(38, 2)
        .byte(23, 0x40 | 2);
    let at = |v: u16| ChildDevice::from_raw(&c.raw, v);
    if !at(250).lane_reversal()
        || at(215).dp_max_link_rate_khz() != 0
        || at(216).dp_max_link_rate_khz() != 270_000
        || at(230).dp_max_link_rate_khz() != 270_000
        || at(243).dp_max_lane_count() != 0
        || at(244).dp_max_lane_count() != 2
    {
        return TestResult::Fail("lane reversal / DP rate / lane count decode wrong");
    }
    let rate = |code: u8, v: u16| {
        ChildDevice::from_raw(&Child::new(DP, 7).byte(38, code).raw, v).dp_max_link_rate_khz()
    };
    if rate(0, 216) != 810_000
        || rate(3, 216) != 162_000
        || rate(0, 230) != 0
        || rate(4, 230) != 810_000
        || rate(7, 230) != 2_000_000
    {
        return TestResult::Fail("BDB 216/230 max link rate tables differ from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_child_support_flags_follow_versions
);

fn vbt_platform_tables_match_linux() -> TestResult {
    use VbtPlatform::*;
    // Port masks (intel_display_device.c).
    if TigerLake.port_mask() != 0b1_1111_1011
        || AlderLakeS.port_mask() != 0b111_1001
        || AlderLakeP.port_mask() != 0b111_1011
        || MeteorLake.port_mask() != 0b111_1011
    {
        return TestResult::Fail("port masks differ from intel_display_device.c");
    }
    // dvo_port_to_port: xelpd (display 13+), adls, direct.
    let xelpd = [
        (dvo_port::DPA, 0),
        (dvo_port::HDMIB, 1),
        (dvo_port::DPC, 2),
        (dvo_port::DPD, 7),
        (dvo_port::HDMIE, 8),
        (dvo_port::DPF, 3),
        (dvo_port::HDMIG, 4),
        (dvo_port::DPH, 5),
        (dvo_port::HDMII, 6),
    ];
    for (dvo, port) in xelpd {
        if MeteorLake.dvo_port_to_port(dvo) != Some(port)
            || AlderLakeP.dvo_port_to_port(dvo) != Some(port)
        {
            return TestResult::Fail("xelpd_port_mapping differs from intel_bios.c");
        }
    }
    if AlderLakeS.dvo_port_to_port(dvo_port::DPB) != Some(3)
        || AlderLakeS.dvo_port_to_port(dvo_port::HDMIE) != Some(6)
        || AlderLakeS.dvo_port_to_port(dvo_port::DPF).is_some()
        || TigerLake.dvo_port_to_port(dvo_port::DPD) != Some(3)
        || TigerLake.dvo_port_to_port(dvo_port::CRT) != Some(4)
        || TigerLake.dvo_port_to_port(dvo_port::HDMII) != Some(8)
        || MeteorLake.dvo_port_to_port(dvo_port::MIPIC) != Some(1)
        || MeteorLake.dvo_port_to_port(dvo_port::CRT).is_some()
    {
        return TestResult::Fail("adls/direct/DSI port mapping differs from intel_bios.c");
    }
    // map_aux_ch.
    if MeteorLake.map_aux_ch(dp_aux::F) != Some(3)
        || MeteorLake.map_aux_ch(dp_aux::I) != Some(6)
        || MeteorLake.map_aux_ch(dp_aux::D) != Some(7)
        || AlderLakeS.map_aux_ch(dp_aux::B) != Some(3)
        || AlderLakeS.map_aux_ch(dp_aux::F).is_some()
        || TigerLake.map_aux_ch(dp_aux::D) != Some(3)
        || TigerLake.map_aux_ch(0x11).is_some()
    {
        return TestResult::Fail("aux channel maps differ from intel_bios.c");
    }
    // map_ddc_pin and the default pins (intel_hdmi_default_ddc_pin).
    if MeteorLake.map_ddc_pin(3) != 9
        || MeteorLake.map_ddc_pin(6) != 12
        || MeteorLake.map_ddc_pin(7) != 0
        || AlderLakeS.map_ddc_pin(2) != 9
        || TigerLake.map_ddc_pin(4) != 9
        || TigerLake.map_ddc_pin(9) != 14
        || TigerLake.map_ddc_pin(10) != 0
    {
        return TestResult::Fail("DDC pin maps differ from intel_bios.c");
    }
    let mtl_defaults: Vec<u8> = [0u8, 1, 3, 4, 5, 6]
        .iter()
        .map(|&p| MeteorLake.default_ddc_pin(p))
        .collect();
    if mtl_defaults != [1, 2, 6, 7, 8, 9]
        || TigerLake.default_ddc_pin(1) != 2
        || TigerLake.default_ddc_pin(8) != 14
        || AlderLakeP.default_ddc_pin(6) != 12
        || AlderLakeS.default_ddc_pin(0) != 1
        || AlderLakeS.default_ddc_pin(4) != 10
    {
        return TestResult::Fail("default DDC pins differ from intel_hdmi.c");
    }
    // intel_phy_is_tc.
    if !MeteorLake.port_is_tc(3)
        || MeteorLake.port_is_tc(1)
        || AlderLakeS.port_is_tc(3)
        || !TigerLake.port_is_tc(8)
        || TigerLake.port_is_tc(2)
    {
        return TestResult::Fail("Type-C PHY classification differs from intel_display.c");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_vbt", vbt_platform_tables_match_linux);

fn vbt_encoders_follow_intel_ddi_init() -> TestResult {
    use device_type::*;
    let mut children = mtl_reference_children();
    // A second child for DDI B is ignored (port_in_use).
    children.push(Child::new(HDMI, dvo_port::HDMIB).ddc(1));
    // DPC maps to port C, which MTL's port mask lacks.
    children.push(Child::new(DP, dvo_port::DPC).aux(dp_aux::C));
    // TC4 claims TC1's AUX channel: the port is dropped.
    children.push(Child::new(DP, dvo_port::DPI).aux(dp_aux::F).typec());
    let vbt = Vbt::parse(
        &VbtImage::new(250)
            .block(
                block::GENERAL_DEFINITIONS,
                general_definitions(44, &children),
            )
            .build(),
    )
    .unwrap();
    let enc = vbt.encoders(VbtPlatform::MeteorLake);
    let ports: Vec<u8> = enc.iter().map(|e| e.port).collect();
    if ports != [0, 1, 3, 4, 5] {
        return TestResult::Fail("encoder set must follow port claims, masks and AUX claims");
    }
    let a = enc[0];
    if !a.edp || a.hdmi_ddc.is_some() || a.aux_ch != Some(0) {
        return TestResult::Fail("DDI A is the eDP encoder on AUX A");
    }
    let b = enc[1];
    if !b.dp || b.hdmi_ddc != Some(PinPair::Pin2Bxt) || !b.dp_dual_mode || b.type_c {
        return TestResult::Fail("DDI B is DP++ with VBT DDC dpb");
    }
    let tc1 = enc[2];
    if !tc1.type_c || tc1.tc_legacy || !tc1.dp || tc1.hdmi_ddc.is_some() || tc1.aux_ch != Some(3) {
        return TestResult::Fail("TC1 is a non-legacy USB-C DP port");
    }
    let tc2 = enc[3];
    if !tc2.type_c || !tc2.tc_legacy || tc2.dp || tc2.hdmi_ddc != Some(PinPair::Pin10Tc2) {
        return TestResult::Fail("TC2 is a legacy HDMI port on VBT DDC tc2");
    }
    let tc3 = enc[4];
    if tc3.tc_legacy || !tc3.dp || tc3.hdmi_ddc != Some(PinPair::Pin11Tc3) {
        return TestResult::Fail("a USB-C/TBT port with DP and HDMI stays non-legacy");
    }
    // Non-legacy (no USB-C/TBT bits but HDMI) with no DP becomes legacy;
    // a VBT DDC code invalid for the platform falls back to the default
    // (TC1 default PHY F + 1 = 6, not in gmbus_pins_mtp: no HDMI).
    let v = Vbt::parse(
        &VbtImage::new(250)
            .block(
                block::GENERAL_DEFINITIONS,
                general_definitions(
                    44,
                    &[
                        Child::new(HDMI, dvo_port::HDMIF).ddc(9),
                        Child::new(HDMI, dvo_port::HDMII),
                        Child::new(HDMI, dvo_port::HDMIG).ddc(6),
                    ],
                ),
            )
            .build(),
    )
    .unwrap();
    let e = v.encoders(VbtPlatform::MeteorLake);
    if e.len() != 3
        || !e[0].tc_legacy
        || e[0].hdmi_ddc.is_some()
        || !e[0].tmds
        // TC4 default: PHY I + 1 = 9 ("tc1" in gmbus_pins_mtp).
        || e[1].hdmi_ddc != Some(PinPair::Pin9Tc1)
        // TC2 asks for tc4's pin (code 6 -> pin 12).
        || e[2].hdmi_ddc != Some(PinPair::Pin12Tc4)
    {
        return TestResult::Fail("legacy rule, invalid VBT pin and default pin follow Linux");
    }
    // A DDC pin already claimed by an earlier HDMI connector is refused.
    let v = Vbt::parse(
        &VbtImage::new(250)
            .block(
                block::GENERAL_DEFINITIONS,
                general_definitions(
                    44,
                    &[
                        Child::new(HDMI, dvo_port::HDMIG).ddc(3),
                        Child::new(HDMI, dvo_port::HDMIH).ddc(3),
                    ],
                ),
            )
            .build(),
    )
    .unwrap();
    let e = v.encoders(VbtPlatform::MeteorLake);
    if e.len() != 2 || e[0].hdmi_ddc != Some(PinPair::Pin9Tc1) || e[1].hdmi_ddc.is_some() {
        return TestResult::Fail("a claimed DDC pin must leave the later port without HDMI");
    }
    // DSI claims its port; dedicated-external TC is not Type-C.
    let v = Vbt::parse(
        &VbtImage::new(264)
            .block(
                block::GENERAL_DEFINITIONS,
                general_definitions(
                    44,
                    &[
                        Child::new(MIPI_OUTPUT, dvo_port::MIPIC),
                        Child::new(DP, dvo_port::DPB),
                        Child::new(DP, dvo_port::DPF).typec().dedicated_external(),
                    ],
                ),
            )
            .build(),
    )
    .unwrap();
    let e = v.encoders(VbtPlatform::MeteorLake);
    if e.len() != 2 || !e[0].dsi || e[0].port != 1 || e[1].type_c || !e[1].dedicated_external {
        return TestResult::Fail("DSI claims DDI B; dedicated external is not Type-C");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_encoders_follow_intel_ddi_init
);

// ── Panel blocks ─────────────────────────────────────────────────────

fn vbt_driver_features_and_panel_type() -> TestResult {
    let mut d = alloc::vec![0u8; 19];
    // lvds_config = INT_LVDS (bits 11-12 of the u16 at 7), psr + drrs +
    // dmrrs flags in the u16 at 17.
    d[7..9].copy_from_slice(&(1u16 << 11).to_le_bytes());
    d[17..19].copy_from_slice(&((1u16 << 9) | (1 << 5) | (1 << 12)).to_le_bytes());
    let mut o = alloc::vec![0u8; 34];
    o[0] = 3;
    o[1] = 9;
    let vbt = Vbt::parse(
        &VbtImage::new(227)
            .block(block::DRIVER_FEATURES, d.clone())
            .block(block::LFP_OPTIONS, o.clone())
            .build(),
    )
    .unwrap();
    let want = DriverFeatures {
        lvds_config: 1,
        drrs_enabled: true,
        psr_enabled: true,
        dmrrs_enabled: true,
    };
    if vbt.driver_features() != Some(want) || !vbt.int_lvds_support() {
        return TestResult::Fail("driver features decode per intel_vbt_defs.h");
    }
    if vbt.panel_type(false) != PanelType::Index(3) || vbt.panel_type(true) != PanelType::Index(9) {
        return TestResult::Fail("panel_type / panel_type2 come from the LFP options");
    }
    d[7..9].copy_from_slice(&(3u16 << 11).to_le_bytes());
    o[0] = 0xFF;
    let v = Vbt::parse(
        &VbtImage::new(227)
            .block(block::DRIVER_FEATURES, d)
            .block(block::LFP_OPTIONS, o.clone())
            .build(),
    )
    .unwrap();
    if v.int_lvds_support() || v.panel_type(false) != PanelType::PnpId {
        return TestResult::Fail("INT_SDVO_LVDS clears int_lvds; 0xFF is PnP-ID selection");
    }
    o[0] = 0x10;
    let v = Vbt::parse(&VbtImage::new(227).block(block::LFP_OPTIONS, o).build()).unwrap();
    if v.panel_type(false) != PanelType::Unknown || v.panel_type(true) != PanelType::Unknown {
        return TestResult::Fail("an invalid primary panel type invalidates both");
    }
    let none = Vbt::parse(&VbtImage::new(227).build()).unwrap();
    if none.panel_type(false) != PanelType::Unknown
        || none.panel_type(false).index_or_fallback() != 0
        || !none.int_lvds_support()
    {
        return TestResult::Fail("no LFP options: unknown panel type, fallback 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_driver_features_and_panel_type
);

fn edp_block(panel: usize) -> Vec<u8> {
    let mut e = alloc::vec![0u8; 848];
    // power_seqs[panel]: t1_t3, t8, t9, t10, t11_t12.
    for (i, v) in [2100u16, 500, 200, 5000, 5100].iter().enumerate() {
        e[10 * panel + 2 * i..10 * panel + 2 * i + 2].copy_from_slice(&v.to_le_bytes());
    }
    // color_depth: panel → EDP_30BPP.
    e[160..164].copy_from_slice(&(2u32 << (2 * panel)).to_le_bytes());
    // fast_link_params: rate 2.7 (1), lanes 4 (3); preemph 6 dB (2),
    // vswing 0.8 V (2).
    e[164 + 2 * panel] = 1 | (3 << 4);
    e[165 + 2 * panel] = 2 | (2 << 4);
    // sdrrs_msa_timing_delay = 3.
    e[196..200].copy_from_slice(&(3u32 << (2 * panel)).to_le_bytes());
    // edp_vswing_preemph: panel nibble 0 → low vswing; others 1.
    let vp: u64 = !(0xFu64 << (4 * panel)) & 0x1111_1111_1111_1111;
    e[204..212].copy_from_slice(&vp.to_le_bytes());
    // edp_fast_link_training_rate (224+): 8100 * 20 = 162000.
    e[748 + 2 * panel..750 + 2 * panel].copy_from_slice(&8100u16.to_le_bytes());
    // edp_max_port_link_rate (244+): 27000 * 20 = 540000.
    e[780 + 2 * panel..782 + 2 * panel].copy_from_slice(&27000u16.to_le_bytes());
    // edp_dsc_disable (251+).
    e[812..814].copy_from_slice(&(1u16 << panel).to_le_bytes());
    e
}

fn vbt_edp_block_per_panel_and_versions() -> TestResult {
    let panel = 5usize;
    let v223 = Vbt::parse(
        &VbtImage::new(223)
            .block(block::EDP, edp_block(panel))
            .build(),
    )
    .unwrap();
    let want = EdpPanel {
        bpp: Some(30),
        pps: VbtPpsDelays {
            power_up: 2100,
            backlight_on: 500,
            backlight_off: 200,
            power_down: 5000,
            power_cycle: 5100,
        },
        rate_khz: Some(270_000),
        lanes: Some(4),
        preemphasis: Some(2),
        vswing: Some(2),
        low_vswing: Some(true),
        drrs_msa_timing_delay: 3,
        max_link_rate_khz: None,
        dsc_disable: None,
    };
    if v223.edp_panel(panel as u8) != Some(want) {
        return TestResult::Fail("BDB 223 eDP panel must decode per parse_edp");
    }
    // 251+: the training rate field, max port link rate and DSC disable.
    let v251 = Vbt::parse(
        &VbtImage::new(251)
            .block(block::EDP, edp_block(panel))
            .build(),
    )
    .unwrap();
    match v251.edp_panel(panel as u8) {
        Some(p)
            if p.rate_khz == Some(162_000)
                && p.max_link_rate_khz == Some(540_000)
                && p.dsc_disable == Some(true) => {}
        _ => return TestResult::Fail("BDB 224/244/251 eDP fields must decode"),
    }
    // Another panel index reads its own (zero) entries.
    match v223.edp_panel(0) {
        Some(p)
            if p.bpp == Some(18)
                && p.pps == VbtPpsDelays::default()
                && p.lanes == Some(1)
                && p.low_vswing == Some(false) => {}
        _ => return TestResult::Fail("panel indices must not alias"),
    }
    // Reserved encodings report None; 172 has no low_vswing.
    let mut bad = edp_block(panel);
    bad[164 + 2 * panel] = 0xF | (2 << 4);
    bad[165 + 2 * panel] = 0x9 | (0x9 << 4);
    bad[160..164].copy_from_slice(&(3u32 << (2 * panel)).to_le_bytes());
    let v = Vbt::parse(&VbtImage::new(172).block(block::EDP, bad).build()).unwrap();
    match v.edp_panel(panel as u8) {
        Some(p)
            if p.bpp.is_none()
                && p.rate_khz.is_none()
                && p.lanes.is_none()
                && p.preemphasis.is_none()
                && p.vswing.is_none()
                && p.low_vswing.is_none() => {}
        _ => return TestResult::Fail("unknown eDP encodings must stay unset"),
    }
    if Vbt::parse(&VbtImage::new(250).build())
        .unwrap()
        .edp_panel(0)
        .is_some()
    {
        return TestResult::Fail("no eDP block, no eDP panel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_edp_block_per_panel_and_versions
);

fn vbt_psr_block_and_enable_sources() -> TestResult {
    let panel = 2usize;
    let mut s = alloc::vec![0u8; 100];
    s[6 * panel] = 0b11;
    s[6 * panel + 1] = 6 | (5 << 4);
    s[6 * panel + 2..6 * panel + 4].copy_from_slice(&1u16.to_le_bytes());
    s[6 * panel + 4..6 * panel + 6].copy_from_slice(&7u16.to_le_bytes());
    s[96..100].copy_from_slice(&(3u32 << (2 * panel)).to_le_bytes());
    // BDB 226, driver features PSR on: new wakeup encodings, PSR2 from
    // the per-panel 2-bit field.
    let mut d = alloc::vec![0u8; 19];
    d[17..19].copy_from_slice(&(1u16 << 9).to_le_bytes());
    let v = Vbt::parse(
        &VbtImage::new(226)
            .block(block::PSR, s.clone())
            .block(block::DRIVER_FEATURES, d.clone())
            .build(),
    )
    .unwrap();
    let want = PsrTable {
        full_link: true,
        require_aux_wakeup: true,
        idle_frames: 6,
        tp1_wakeup_time_us: 100,
        tp2_tp3_wakeup_time_us: 2500,
        psr2_tp2_tp3_wakeup_time_us: 50,
    };
    let got = v.psr_panel(panel as u8);
    if !got.enable || got.table != Some(want) {
        return TestResult::Fail("BDB 226 PSR must decode per parse_psr");
    }
    // BDB 204: wake-up times are ×100 µs and PSR2 reuses TP2/TP3.
    let v = Vbt::parse(&VbtImage::new(204).block(block::PSR, s.clone()).build()).unwrap();
    match v.psr_panel(panel as u8) {
        PsrPanel {
            enable: false,
            table: Some(t),
        } if t.tp1_wakeup_time_us == 100
            && t.tp2_tp3_wakeup_time_us == 700
            && t.psr2_tp2_tp3_wakeup_time_us == 700 => {}
        _ => return TestResult::Fail("pre-205 PSR wake times are ×100 µs"),
    }
    // BDB 228+: the enable comes from the LFP power block, not the
    // driver-features flag.
    let mut w = alloc::vec![0u8; 136];
    w[24..26].copy_from_slice(&(1u16 << panel).to_le_bytes());
    let on = Vbt::parse(
        &VbtImage::new(228)
            .block(block::DRIVER_FEATURES, alloc::vec![0u8; 19])
            .block(block::LFP_POWER, w)
            .build(),
    )
    .unwrap();
    let off = Vbt::parse(&VbtImage::new(228).block(block::DRIVER_FEATURES, d).build()).unwrap();
    if !on.psr_panel(panel as u8).enable
        || on.psr_panel(panel as u8).table.is_some()
        || off.psr_panel(panel as u8).enable
        || on.psr_panel(0).enable
    {
        return TestResult::Fail("BDB 228+ PSR enable comes from the LFP power bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_psr_block_and_enable_sources
);

fn vbt_backlight_block_by_version() -> TestResult {
    let panel = 1usize;
    let mut b = alloc::vec![0u8; 305];
    b[0] = 6;
    let e = 1 + 6 * panel;
    b[e] = 2 | (1 << 2);
    b[e + 1..e + 3].copy_from_slice(&200u16.to_le_bytes());
    b[e + 3] = 12;
    b[113 + panel] = 3 | (1 << 4);
    b[129 + 4 * panel..131 + 4 * panel].copy_from_slice(&65535u16.to_le_bytes());
    b[193 + 4 * panel..195 + 4 * panel].copy_from_slice(&2550u16.to_le_bytes());
    b[257 + panel] = 16;
    b[273 + 2 * panel..275 + 2 * panel].copy_from_slice(&250u16.to_le_bytes());
    let at = |v: u16, block: &Vec<u8>| {
        Vbt::parse(
            &VbtImage::new(v)
                .block(block::LFP_BACKLIGHT, block.clone())
                .build(),
        )
        .unwrap()
        .backlight_panel(panel as u8)
    };
    match at(190, &b) {
        Some(p)
            if p.present
                && p.active_low_pwm
                && p.pwm_freq_hz == 200
                && p.control_type == 2
                && p.controller == 0
                && p.min_brightness == 12
                && p.hdr_dpcd_refresh_timeout == 30 => {}
        _ => return TestResult::Fail("pre-191 backlight is DISPLAY_DDI with entry min"),
    }
    match at(239, &b) {
        Some(p)
            if p.control_type == 3
                && p.controller == 1
                && p.min_brightness == 10
                && p.brightness_precision_bits == 16
                && p.hdr_dpcd_refresh_timeout == 3 => {}
        _ => return TestResult::Fail("BDB 236+ 16-bit levels scale the minimum"),
    }
    // 234/235: scale when the level exceeds 255.
    match at(234, &b) {
        Some(p) if p.min_brightness == 10 && p.hdr_dpcd_refresh_timeout == 30 => {}
        _ => return TestResult::Fail("BDB 234 scales by level > 255"),
    }
    let mut not_pwm = b.clone();
    not_pwm[e] = 0;
    if at(239, &not_pwm).is_some_and(|p| p.present) {
        return TestResult::Fail("a non-PWM entry has no backlight");
    }
    let mut bad = b.clone();
    bad[0] = 7;
    if at(239, &bad).is_some() {
        return TestResult::Fail("entry_size other than 6 must refuse the block");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_vbt", vbt_backlight_block_by_version);

// ── OpRegion and option ROM ──────────────────────────────────────────

fn opregion(major: u8, minor: u8, mboxes: u32) -> Vec<u8> {
    let mut r = alloc::vec![0u8; OPREGION_SIZE];
    r[..16].copy_from_slice(b"IntelGraphicsMem");
    r[16..20].copy_from_slice(&8u32.to_le_bytes());
    r[22] = minor;
    r[23] = major;
    r[88..92].copy_from_slice(&mboxes.to_le_bytes());
    r
}

fn set_rvda(r: &mut [u8], rvda: u64, rvds: u32) {
    let asle = 0x300;
    r[asle + 186..asle + 194].copy_from_slice(&rvda.to_le_bytes());
    r[asle + 194..asle + 198].copy_from_slice(&rvds.to_le_bytes());
}

fn vbt_opregion_mailbox_rvda_and_refusals() -> TestResult {
    let image = mtl_reference_vbt(250, true);
    let asls = 0x7A10_0000u64;
    // Mailbox #4 VBT, OpRegion 2.0 without RVDA.
    let mut r = opregion(2, 0, MBOX_ASLE);
    r[0x400..0x400 + image.len()].copy_from_slice(&image);
    let mut never = |_: u64, _: usize| -> Option<Vec<u8>> { None };
    match opregion_vbt(&r, asls, &mut never) {
        Ok((v, VbtSource::OpRegionMailbox)) if v == image => {}
        _ => return TestResult::Fail("mailbox #4 VBT must be found"),
    }
    // OpRegion 2.1: RVDA is relative to ASLS and wins over the mailbox.
    let mut rv = image.clone();
    rv[20] = 0xBB;
    let mut r21 = r.clone();
    r21[22] = 1;
    set_rvda(&mut r21, 0x2000, rv.len() as u32 + 0x100);
    let mut seen = None;
    let mut fetch = |phys: u64, len: usize| {
        seen = Some((phys, len));
        let mut out = rv.clone();
        out.resize(len, 0);
        Some(out)
    };
    match opregion_vbt(&r21, asls, &mut fetch) {
        Ok((v, VbtSource::OpRegionRvda)) if v == rv => {}
        _ => return TestResult::Fail("a valid RVDA VBT must win"),
    }
    if seen != Some((asls + 0x2000, rv.len() + 0x100)) {
        return TestResult::Fail("2.1+ RVDA must be ASLS-relative with RVDS bytes");
    }
    // OpRegion 2.0: RVDA is physical.
    let mut r20 = r.clone();
    set_rvda(&mut r20, 0x8000_0000, 0x1000);
    if opregion_rvda(&r20, asls) != Some((0x8000_0000, 0x1000)) {
        return TestResult::Fail("2.0 RVDA is a physical address");
    }
    // RVDS is clamped to the 16-bit VBT size; ASLE absent → no RVDA.
    let mut big = r21.clone();
    set_rvda(&mut big, 0x2000, 0x40_0000);
    if opregion_rvda(&big, asls).map(|(_, len)| len) != Some(MAX_VBT_SIZE) {
        return TestResult::Fail("RVDS reads are bounded by the VBT size field");
    }
    let mut no_asle = r21.clone();
    no_asle[88..92].copy_from_slice(&0u32.to_le_bytes());
    if opregion_rvda(&no_asle, asls).is_some()
        || opregion_rvda(&opregion(1, 9, MBOX_ASLE), asls).is_some()
    {
        return TestResult::Fail("RVDA needs OpRegion 2.0+ and the ASLE mailbox");
    }
    // An invalid RVDA VBT falls back to the mailbox.
    let mut junk = |_: u64, len: usize| Some(alloc::vec![0x5Au8; len]);
    match opregion_vbt(&r21, asls, &mut junk) {
        Ok((v, VbtSource::OpRegionMailbox)) if v == image => {}
        _ => return TestResult::Fail("an invalid RVDA VBT must fall back to mailbox #4"),
    }
    // MBOX_ASLE_EXT bounds the mailbox at 0x1C00: a VBT reaching past it
    // is refused there and accepted without the extension mailbox.
    let mut long = image.clone();
    long.resize(0x1C00 - 0x400 + 0x10, 0);
    let n = long.len() as u16;
    long[24..26].copy_from_slice(&n.to_le_bytes());
    let mut ext = opregion(2, 0, MBOX_ASLE | MBOX_ASLE_EXT);
    ext[0x400..0x400 + long.len()].copy_from_slice(&long);
    if opregion_vbt(&ext, asls, &mut never) != Err(OpRegionError::NoVbt) {
        return TestResult::Fail("ASLE_EXT must bound the mailbox VBT");
    }
    ext[88..92].copy_from_slice(&MBOX_ASLE.to_le_bytes());
    if !matches!(
        opregion_vbt(&ext, asls, &mut never),
        Ok((_, VbtSource::OpRegionMailbox))
    ) {
        return TestResult::Fail("without ASLE_EXT the mailbox runs to the OpRegion end");
    }
    // Refusals.
    if opregion_vbt(&r, 0, &mut never) != Err(OpRegionError::NotSupported)
        || opregion_vbt(&r[..OPREGION_SIZE - 1], asls, &mut never) != Err(OpRegionError::Truncated)
        || opregion_vbt(&opregion(2, 0, 0)[..], asls, &mut never) != Err(OpRegionError::NoVbt)
    {
        return TestResult::Fail("ASLS 0, a short region and an empty mailbox refuse");
    }
    let mut sig = r.clone();
    sig[0] = b'i';
    if opregion_vbt(&sig, asls, &mut never) != Err(OpRegionError::BadSignature) {
        return TestResult::Fail("an OpRegion signature mismatch must refuse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_opregion_mailbox_rvda_and_refusals
);

fn rom_image(vbt_at: usize, vbt: &[u8], blocks: u16, last: bool) -> Vec<u8> {
    let mut rom = alloc::vec![0u8; blocks as usize * 512];
    rom[0] = 0x55;
    rom[1] = 0xAA;
    rom[24..26].copy_from_slice(&0x40u16.to_le_bytes());
    rom[0x40..0x44].copy_from_slice(b"PCIR");
    rom[0x40 + 16..0x40 + 18].copy_from_slice(&blocks.to_le_bytes());
    rom[0x40 + 21] = if last { 0x80 } else { 0 };
    rom[vbt_at..vbt_at + vbt.len()].copy_from_slice(vbt);
    rom
}

fn vbt_pci_rom_scan_and_image_size() -> TestResult {
    let vbt = mtl_reference_vbt(250, true);
    let rom = rom_image(0x200, &vbt, 4, true);
    if pci_rom_size(&rom) != rom.len() {
        return TestResult::Fail("a one-image ROM spans its length field");
    }
    match pci_rom_vbt(&rom) {
        Some(v) if v == vbt => {}
        _ => return TestResult::Fail("a 4-byte aligned $VBT must be found"),
    }
    // The ROM window is trimmed to the image chain: a VBT after the last
    // image is outside the ROM.
    let mut window = rom_image(0x200, &[], 2, true);
    window.resize(4 * 512, 0);
    window[3 * 512..3 * 512 + vbt.len()].copy_from_slice(&vbt);
    if pci_rom_size(&window) != 1024 || pci_rom_vbt(&window).is_some() {
        return TestResult::Fail("the scan must stop at pci_get_rom_size");
    }
    // A chained second image extends the size.
    let mut chained = rom_image(0x200, &[], 1, false);
    let second = rom_image(0x100, &vbt, 3, true);
    chained.extend_from_slice(&second);
    if pci_rom_size(&chained) != 4 * 512 {
        return TestResult::Fail("chained images must add up");
    }
    // An unaligned signature is not found (intel_rom_find steps by 4).
    let mut odd = alloc::vec![0u8; 0x400];
    odd[0x102..0x102 + vbt.len()].copy_from_slice(&vbt);
    if rom_find_vbt(&odd).is_some() {
        return TestResult::Fail("an unaligned $VBT must not be found");
    }
    // A VBT header cut by the ROM end, a vbt_size past it, and a bad ROM
    // header all refuse.
    let mut cut = alloc::vec![0u8; 0x100];
    cut[0xF0..0xF4].copy_from_slice(b"$VBT");
    let mut size_over = alloc::vec![0u8; 0x200];
    size_over[0x100..0x100 + 48].copy_from_slice(&vbt[..48]);
    size_over[0x100 + 24..0x100 + 26].copy_from_slice(&0x200u16.to_le_bytes());
    let mut bad_hdr = rom.clone();
    bad_hdr[0] = 0;
    if rom_find_vbt(&cut).is_some()
        || rom_find_vbt(&size_over).is_some()
        || pci_rom_vbt(&bad_hdr).is_some()
        || pci_rom_size(&bad_hdr) != 0
    {
        return TestResult::Fail("truncated or invalid ROM VBTs must refuse");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_vbt", vbt_pci_rom_scan_and_image_size);

// ── Consumers ────────────────────────────────────────────────────────

fn vbt_dp_ssc_decision_needs_vbt_and_downspread() -> TestResult {
    // intel_cx0pll_update_ssc: intel_panel_use_ssc && DP_MAX_DOWNSPREAD_0_5.
    let rows = [
        (true, 0x01u8, true),
        (true, 0x41, true),
        (true, 0x00, false),
        (true, 0x40, false),
        (false, 0x01, false),
        (false, 0x00, false),
    ];
    for (vbt, downspread, want) in rows {
        if dp_ssc_enabled(vbt, downspread) != want {
            return TestResult::Fail("SSC needs both the VBT and the sink downspread");
        }
    }
    if DP_MAX_DOWNSPREAD != 3 || DP_MAX_DOWNSPREAD_0_5 != 1 {
        return TestResult::Fail("DP_MAX_DOWNSPREAD constants differ from drm_dp.h");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_dp_ssc_decision_needs_vbt_and_downspread
);

fn vbt_gen12_ddc_overrides_follow_map_ddc_pin() -> TestResult {
    use crate::intel_gpu_ddi::Ddi;
    use crate::intel_gpu_gt::Gen12Platform;
    use device_type::*;
    // Tiger Lake: TC1 (DVO HDMID → port 3) declares ICL_DDC_BUS_PORT_2
    // (code 5 → pin 10) instead of its default pin 9; DDI B keeps the
    // default (dpb); TC2 is DP-only (no HDMI connector, default kept).
    let vbt = Vbt::parse(
        &VbtImage::new(250)
            .block(
                block::GENERAL_DEFINITIONS,
                general_definitions(
                    44,
                    &[
                        Child::new(DP_DUAL_MODE, dvo_port::HDMIB).aux(dp_aux::B),
                        Child::new(HDMI, dvo_port::HDMID).aux(dp_aux::D).ddc(5),
                        Child::new(DP, dvo_port::DPE).aux(dp_aux::E),
                    ],
                ),
            )
            .build(),
    )
    .unwrap();
    let o = Gen12DdcOverrides::from_vbt(&vbt, Gen12Platform::TigerLake);
    if o.pin(Gen12Platform::TigerLake, Ddi::D) != Some(PinPair::Pin10Tc2)
        || o.pin(Gen12Platform::TigerLake, Ddi::B) != Some(PinPair::Pin2Bxt)
        || o.pin(Gen12Platform::TigerLake, Ddi::E) != Some(PinPair::Pin10Tc2)
    {
        return TestResult::Fail("TGL VBT DDC override must map through icp_ddc_pin_map");
    }
    // Overrides resolved for another family are ignored.
    if o.pin(Gen12Platform::AlderLakeP, Ddi::D) != Some(PinPair::Pin9Tc1) {
        return TestResult::Fail("overrides apply only to their family");
    }
    if Gen12DdcOverrides::NONE.pin(Gen12Platform::TigerLake, Ddi::D) != Some(PinPair::Pin9Tc1)
        || Gen12DdcOverrides::NONE
            .pin(Gen12Platform::AlderLakeS, Ddi::B)
            .is_some()
    {
        return TestResult::Fail("no VBT keeps gen12_ddc_pin");
    }
    // ADL-S: TC1 on DVO HDMIB; code 3 is ADLS_DDC_BUS_PORT_TC2 (pin 10).
    let vbt = Vbt::parse(
        &VbtImage::new(250)
            .block(
                block::GENERAL_DEFINITIONS,
                general_definitions(44, &[Child::new(HDMI, dvo_port::HDMIB).ddc(3)]),
            )
            .build(),
    )
    .unwrap();
    let o = Gen12DdcOverrides::from_vbt(&vbt, Gen12Platform::AlderLakeS);
    if o.pin(Gen12Platform::AlderLakeS, Ddi::D) != Some(PinPair::Pin10Tc2) {
        return TestResult::Fail("ADL-S VBT DDC override must map through adls_ddc_pin_map");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vbt",
    vbt_gen12_ddc_overrides_follow_map_ddc_pin
);
