use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const DIR: usize = 0x200;
const DISPLAY_OBJECT: usize = 0x400;
const DCE: usize = 0x500;
const INTEGRATED: usize = 0x600;
const RECORDS: usize = 0x700;
const ENTRIES: usize = 31;

/// A synthetic VBIOS carrying only the three tables the inventory reads.
struct Image(Vec<u8>);
impl Image {
    fn new() -> Self {
        let mut image = vec![0u8; 0x800];
        image[..2].copy_from_slice(&[0x55, 0xaa]);
        image[0x48..0x4a].copy_from_slice(&0x0100u16.to_le_bytes());
        // ROM header with the ATOM signature and the directory pointer.
        image[0x100..0x104].copy_from_slice(&[36, 0, 1, 1]);
        image[0x104..0x108].copy_from_slice(b"ATOM");
        image[0x120..0x122].copy_from_slice(&(DIR as u16).to_le_bytes());
        // Master data table directory, format 2.1 with 31 entries.
        let size = 4 + ENTRIES * 2;
        image[DIR..DIR + 2].copy_from_slice(&(size as u16).to_le_bytes());
        image[DIR + 2] = 2;
        image[DIR + 3] = 1;
        let mut this = Self(image);
        this.point(TABLE_DISPLAY_OBJECT_INFO, DISPLAY_OBJECT);
        this.point(TABLE_DCE_INFO, DCE);
        this.point(TABLE_INTEGRATED_SYSTEM_INFO, INTEGRATED);
        this.dce(2_700);
        this.integrated(MEM_TYPE_DDR5, 4);
        this.paths(&[(0x3505, 0x2101), (0x3606, 0x2202)]);
        this
    }
    fn point(&mut self, index: u16, offset: usize) {
        let at = DIR + 4 + index as usize * 2;
        self.0[at..at + 2].copy_from_slice(&(offset as u16).to_le_bytes());
    }
    fn unpoint(&mut self, index: u16) {
        let at = DIR + 4 + index as usize * 2;
        self.0[at..at + 2].copy_from_slice(&0u16.to_le_bytes());
    }
    fn dce(&mut self, refclk_10khz: u16) {
        let size = 40usize;
        self.0[DCE..DCE + 2].copy_from_slice(&(size as u16).to_le_bytes());
        self.0[DCE + 2] = 4;
        self.0[DCE + 3] = 1;
        let at = DCE + DCE_REFCLK_OFFSET;
        self.0[at..at + 2].copy_from_slice(&refclk_10khz.to_le_bytes());
    }
    fn integrated(&mut self, memory_type: u8, channels: u8) {
        let size = 64usize;
        self.0[INTEGRATED..INTEGRATED + 2].copy_from_slice(&(size as u16).to_le_bytes());
        self.0[INTEGRATED + 2] = 2;
        self.0[INTEGRATED + 3] = 2;
        self.0[INTEGRATED + MEMORY_TYPE_OFFSET] = memory_type;
        self.0[INTEGRATED + CHANNEL_COUNT_OFFSET] = channels;
    }
    /// Attach a record list at `offset` holding one HPD record for `pin`,
    /// followed by the terminator.
    fn hpd_record(&mut self, offset: usize, pin: u8) {
        self.0[offset] = RECORD_HPD_INT;
        self.0[offset + 1] = 4;
        self.0[offset + 2] = pin;
        self.0[offset + 3] = 0;
        self.0[offset + 4] = RECORD_END;
        self.0[offset + 5] = 2;
    }
    /// Each entry is a (connector objid, encoder objid) pair.
    fn paths(&mut self, entries: &[(u16, u16)]) {
        let size = PATHS_OFFSET + entries.len() * PATH_SIZE;
        self.0[DISPLAY_OBJECT..DISPLAY_OBJECT + 2].copy_from_slice(&(size as u16).to_le_bytes());
        self.0[DISPLAY_OBJECT + 2] = 1;
        self.0[DISPLAY_OBJECT + 3] = 4;
        self.0[DISPLAY_OBJECT + 6] = entries.len() as u8;
        for (index, (conn, enc)) in entries.iter().enumerate() {
            let at = DISPLAY_OBJECT + PATHS_OFFSET + index * PATH_SIZE;
            self.0[at..at + 2].copy_from_slice(&conn.to_le_bytes());
            // Record list for this path, one per entry.
            let records = RECORDS + index * 8;
            self.0[at + 2..at + 4].copy_from_slice(&(records as u16).to_le_bytes());
            self.0[at + 4..at + 6].copy_from_slice(&enc.to_le_bytes());
            self.0[at + 12..at + 14].copy_from_slice(&((index as u16) + 1).to_le_bytes());
            self.hpd_record(records, index as u8 + 1);
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.0
    }
}
fn levels() -> Levels {
    Levels {
        dcfclk: [600, 0, 0, 0, 0, 0, 0, 0],
        dispclk: [1200, 0, 0, 0, 0, 0, 0, 0],
        dppclk: [1200, 0, 0, 0, 0, 0, 0, 0],
        socclk: [600, 0, 0, 0, 0, 0, 0, 0],
        fclk: [1200, 0, 0, 0],
        memclk: [1400, 0, 0, 0],
        // 1:2 WCK ratio, so twice the clock again.
        wck_ratio: [1, 0, 0, 0],
        dcfclk_levels: 1,
        display_levels: 1,
        socclk_levels: 1,
        df_pstates: 1,
        min_gfxclk: 200,
        max_gfxclk: 2500,
    }
}

fn inventory_display_paths_decode_their_transmitters() -> TestResult {
    let image = Image::new();
    let paths = match display_paths(image.bytes()) {
        Ok(paths) => paths,
        Err(_) => return TestResult::Fail("synthetic display object table rejected"),
    };
    // 0x3505 is a connector (type 3), kind 5 (DisplayPort), enum 5; its encoder
    // 0x2101 is an encoder (type 2), UNIPHY (id 1), enum 1 — transmitter A.
    if paths.len() != 2 {
        return TestResult::Fail("path count");
    }
    if paths[0]
        != (Path {
            connector: Connector::DisplayPort,
            connector_instance: 5,
            transmitter: 0,
            hpd: 1,
            device_tag: 1,
        })
    {
        return TestResult::Fail("first path");
    }
    // 0x3606 is eDP enum 6; encoder 0x2202 is UNIPHY1 enum 2 — transmitter D.
    if paths[1].connector != Connector::EmbeddedDisplayPort
        || paths[1].connector_instance != 6
        || paths[1].transmitter != 3
        || paths[1].hpd != 2
    {
        return TestResult::Fail("second path");
    }
    // The full pairing: UNIPHY, UNIPHY1 and UNIPHY2 each carry two
    // transmitters, selected by the enum id.
    for (objid, expected) in [
        (0x2101u16, 0u8),
        (0x2201, 1),
        (0x2102, 2),
        (0x2202, 3),
        (0x2103, 4),
        (0x2203, 5),
    ] {
        if transmitter(objid) != Ok(expected) {
            return TestResult::Fail("transmitter mapping");
        }
    }
    // A connector is not an encoder, an unknown encoder has no transmitter,
    // and enum zero is not an instance.
    for objid in [0x3505u16, 0x2109, 0x2001, 0x2104] {
        if transmitter(objid).is_ok() {
            return TestResult::Fail("non-encoder accepted as a transmitter");
        }
    }
    // A connector of a kind we do not name still decodes, with its own id.
    if connector(0x3509) != Ok((Connector::Other(9), 5)) {
        return TestResult::Fail("unnamed connector kind");
    }
    if connector(0x3005).is_ok() {
        return TestResult::Fail("connector with enum zero accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_display_paths_decode_their_transmitters
);

fn inventory_skips_paths_it_cannot_read_but_refuses_empty() -> TestResult {
    // A board may wire something alongside the DisplayPort connectors; an
    // unreadable path is skipped rather than failing the whole table.
    let mut image = Image::new();
    image.paths(&[(0x3505, 0x2101), (0x3505, 0x2109), (0x1005, 0x2101)]);
    let paths = match display_paths(image.bytes()) {
        Ok(paths) => paths,
        Err(_) => return TestResult::Fail("table with one readable path rejected"),
    };
    if paths.len() != 1 || paths[0].transmitter != 0 {
        return TestResult::Fail("unreadable paths not skipped");
    }
    // A table with nothing readable is not a topology we can use.
    let mut none = Image::new();
    none.paths(&[(0x3505, 0x2109)]);
    if display_paths(none.bytes()) != Err(Error::Unsupported) {
        return TestResult::Fail("table with no readable path accepted");
    }
    // A path array that runs past the table's own declared size is malformed.
    let mut lying = Image::new();
    lying.paths(&[(0x3505, 0x2101)]);
    lying.0[DISPLAY_OBJECT + 6] = 8;
    if display_paths(lying.bytes()) != Err(Error::Invalid) {
        return TestResult::Fail("path count past the declared size accepted");
    }
    let mut empty = Image::new();
    empty.0[DISPLAY_OBJECT + 6] = 0;
    if display_paths(empty.bytes()) != Err(Error::Invalid) {
        return TestResult::Fail("zero path count accepted");
    }
    // A revision this does not read, and an absent table.
    let mut old = Image::new();
    old.0[DISPLAY_OBJECT + 3] = 3;
    if display_paths(old.bytes()) != Err(Error::Unsupported) {
        return TestResult::Fail("unknown display object revision accepted");
    }
    let mut gone = Image::new();
    gone.unpoint(TABLE_DISPLAY_OBJECT_INFO);
    if display_paths(gone.bytes()) != Err(Error::Missing) {
        return TestResult::Fail("absent display object table accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_skips_paths_it_cannot_read_but_refuses_empty
);

fn inventory_memory_configuration_is_never_defaulted() -> TestResult {
    let image = Image::new();
    let levels = levels();
    let memory = match memory_config(image.bytes(), &levels) {
        Ok(memory) => memory,
        Err(_) => return TestResult::Fail("DDR5 configuration rejected"),
    };
    // DDR5 channels are eight bytes wide; the rate is twice the memory clock
    // times the 1:2 WCK ratio.
    if memory.kind != MemoryKind::Ddr5
        || memory.channels != 4
        || memory.channel_width_bytes != 8
        || memory.speed_mts != 5600
    {
        return TestResult::Fail("DDR5 configuration");
    }
    let mut lpddr = Image::new();
    lpddr.integrated(MEM_TYPE_LPDDR5, 8);
    let slow = memory_config(lpddr.bytes(), &levels).unwrap();
    if slow.kind != MemoryKind::Lpddr5 || slow.channels != 8 || slow.channel_width_bytes != 4 {
        return TestResult::Fail("LPDDR5 configuration");
    }
    // Linux substitutes four channels when the table says zero. That is a
    // guess, and the channel count multiplies into every watermark.
    let mut zero = Image::new();
    zero.integrated(MEM_TYPE_DDR5, 0);
    if memory_config(zero.bytes(), &levels) != Err(Error::Invalid) {
        return TestResult::Fail("zero channel count defaulted");
    }
    let mut absurd = Image::new();
    absurd.integrated(MEM_TYPE_DDR5, 32);
    if memory_config(absurd.bytes(), &levels) != Err(Error::Invalid) {
        return TestResult::Fail("impossible channel count accepted");
    }
    // A memory type whose channel width we do not know is not guessable.
    let mut unknown = Image::new();
    unknown.integrated(20, 4);
    if memory_config(unknown.bytes(), &levels) != Err(Error::Unsupported) {
        return TestResult::Fail("unknown memory type accepted");
    }
    // Without a DPM table there is no data rate to use.
    if memory_config(image.bytes(), &Levels::default()) != Err(Error::Invalid) {
        return TestResult::Fail("missing DPM table accepted");
    }
    let mut old = Image::new();
    old.0[INTEGRATED + 3] = 5;
    if memory_config(old.bytes(), &levels) != Err(Error::Unsupported) {
        return TestResult::Fail("unknown integrated info revision accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_memory_configuration_is_never_defaulted
);

fn inventory_reference_clock_and_vco_are_range_checked() -> TestResult {
    let image = Image::new();
    // 2700 units of 10 kHz is the 27 MHz reference.
    if dchub_refclk_khz(image.bytes()) != Ok(27_000) {
        return TestResult::Fail("reference clock");
    }
    let mut other = Image::new();
    other.dce(10_000);
    if dchub_refclk_khz(other.bytes()) != Ok(100_000) {
        return TestResult::Fail("non-default reference clock");
    }
    // A table reporting zero falls back to the documented 27 MHz reference.
    let mut zero = Image::new();
    zero.dce(0);
    if dchub_refclk_khz(zero.bytes()) != Ok(27_000) {
        return TestResult::Fail("zero reference clock fallback");
    }
    let mut old = Image::new();
    old.0[DCE + 2] = 3;
    if dchub_refclk_khz(old.bytes()) != Err(Error::Unsupported) {
        return TestResult::Fail("unknown DCE info revision accepted");
    }
    let mut gone = Image::new();
    gone.unpoint(TABLE_DCE_INFO);
    if dchub_refclk_khz(gone.bytes()) != Err(Error::Missing) {
        return TestResult::Fail("absent DCE info accepted");
    }
    // The feedback multiplier is 8.16 fixed point against a 48 MHz reference:
    // 75 whole steps is the 3.6 GHz default, and the fraction must not be lost.
    if vco_from_pll_request(75) != Some(3_600_000) {
        return TestResult::Fail("integer VCO");
    }
    if vco_from_pll_request(75 | 0x8000 << 16) != Some(3_624_000) {
        return TestResult::Fail("fractional VCO");
    }
    // The CLK block is not in the discovery table, so a read that lands
    // somewhere else must be caught by the range rather than believed.
    if vco_from_pll_request(u32::MAX).is_some() {
        return TestResult::Fail("all-ones read accepted as a VCO");
    }
    if vco_from_pll_request(5).is_some() {
        return TestResult::Fail("implausibly low VCO accepted");
    }
    if vco_from_pll_request(0x1ff).is_some() {
        return TestResult::Fail("implausibly high VCO accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_reference_clock_and_vco_are_range_checked
);

fn inventory_hpd_records_fail_closed_to_unassigned() -> TestResult {
    let image = Image::new();
    // A well-formed record list yields its pin.
    if hpd_selector(image.bytes(), RECORDS as u16) != 1 {
        return TestResult::Fail("HPD record not read");
    }
    // No list at all means the board assigns none.
    if hpd_selector(image.bytes(), 0) != 0 {
        return TestResult::Fail("absent record list");
    }
    // A pin outside the six that exist is not a selector.
    let mut high = Image::new();
    high.hpd_record(RECORDS, 7);
    if hpd_selector(high.bytes(), RECORDS as u16) != 0 {
        return TestResult::Fail("out-of-range HPD pin accepted");
    }
    let mut zero = Image::new();
    zero.hpd_record(RECORDS, 0);
    if hpd_selector(zero.bytes(), RECORDS as u16) != 0 {
        return TestResult::Fail("zero HPD pin accepted");
    }
    // A zero-size record would make the walk stand still; it must stop.
    let mut stuck = Image::new();
    stuck.0[RECORDS] = 9;
    stuck.0[RECORDS + 1] = 0;
    if hpd_selector(stuck.bytes(), RECORDS as u16) != 0 {
        return TestResult::Fail("zero-size record accepted");
    }
    // A list with no terminator inside the image must stop at the bound.
    let mut unterminated = Image::new();
    for offset in RECORDS..unterminated.0.len() {
        unterminated.0[offset] = 9;
    }
    for offset in (RECORDS + 1..unterminated.0.len()).step_by(2) {
        unterminated.0[offset] = 2;
    }
    if hpd_selector(unterminated.bytes(), RECORDS as u16) != 0 {
        return TestResult::Fail("unterminated record list accepted");
    }
    // A record list pointing past the image is not a list.
    if hpd_selector(image.bytes(), 0x7ff) != 0 {
        return TestResult::Fail("out-of-bounds record list accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_hpd_records_fail_closed_to_unassigned
);

fn inventory_route_is_validated_against_the_board() -> TestResult {
    let image = Image::new();
    let paths = display_paths(image.bytes()).unwrap();
    let sink = |channel, instance| crate::amdgpu_usbc::Sink {
        channel,
        instance,
        dpcd: [0; 16],
        edid: Vec::new(),
    };
    // A native sink's DMUB link instance is its transmitter; the topology
    // confirms it and supplies the hot-plug line.
    let route = match route_for_sink(&paths, &sink(crate::amdgpu_dmub::Channel::Legacy, 0), 2) {
        Ok(route) => route,
        Err(_) => return TestResult::Fail("native route rejected"),
    };
    if route.backend != 0 || route.aux != 0 || route.hpd != 1 || route.frontend != 2 {
        return TestResult::Fail("native route");
    }
    if route.channel != crate::amdgpu_dmub::Channel::Legacy {
        return TestResult::Fail("route channel");
    }
    // A transmitter the board wired to nothing we can drive is refused rather
    // than driven on the strength of the sink's index alone.
    if route_for_sink(&paths, &sink(crate::amdgpu_dmub::Channel::Legacy, 1), 0)
        != Err(Error::Unsupported)
    {
        return TestResult::Fail("unwired transmitter accepted");
    }
    if route_for_sink(&paths, &sink(crate::amdgpu_dmub::Channel::Legacy, 5), 0)
        != Err(Error::Unsupported)
    {
        return TestResult::Fail("transmitter with no path accepted");
    }
    // A tunnelled sink's transmitter is assigned at stream time, not by the
    // board, so VBIOS cannot answer for it.
    if route_for_sink(&paths, &sink(crate::amdgpu_dmub::Channel::Dpia, 0), 0)
        != Err(Error::Unsupported)
    {
        return TestResult::Fail("tunnelled route derived from VBIOS");
    }
    // A board whose connector is neither DisplayPort nor eDP is not this path.
    let mut hdmi = Image::new();
    hdmi.paths(&[(0x3503, 0x2101)]);
    let hdmi_paths = display_paths(hdmi.bytes()).unwrap();
    if route_for_sink(
        &hdmi_paths,
        &sink(crate::amdgpu_dmub::Channel::Legacy, 0),
        0,
    ) != Err(Error::Unsupported)
    {
        return TestResult::Fail("HDMI connector accepted as a DisplayPort route");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_route_is_validated_against_the_board
);
