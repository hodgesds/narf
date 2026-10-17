use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const DIR: usize = 0x200;
const DISPLAY_OBJECT: usize = 0x400;
const DCE: usize = 0x500;
const INTEGRATED: usize = 0x600;
const RECORDS: usize = 0x700;
const GPIO: usize = 0x800;
const DCN_BASE: u32 = 0x4000;
const ENTRIES: usize = 31;

/// A synthetic VBIOS carrying the routing and APU inventory tables.
struct Image(Vec<u8>);
impl Image {
    fn new() -> Self {
        let mut image = vec![0u8; 0x900];
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
        this.point(TABLE_GPIO_PIN_LUT, GPIO);
        this.gpios();
        this.point(TABLE_DCE_INFO, DCE);
        this.point(TABLE_INTEGRATED_SYSTEM_INFO, INTEGRATED);
        this.dce(2_700);
        this.integrated(MEM_TYPE_DDR5, 4);
        this.paths(&[(0x3513, 0x211e), (0x3614, 0x2220)]);
        this
    }
    fn gpios(&mut self) {
        self.0[GPIO..GPIO + 4].copy_from_slice(&[100, 0, 2, 1]);
        for (i, shift) in [0u8, 8, 16, 24, 26, 28].into_iter().enumerate() {
            let at = GPIO + 4 + i * 8;
            self.0[at..at + 4].copy_from_slice(&(DCN_BASE + 0x28d1 + i as u32 * 4).to_le_bytes());
            self.0[at + 6] = 0x80 + i as u8;
            let at = at + 6 * 8;
            self.0[at..at + 4].copy_from_slice(&(DCN_BASE + 0x28f5).to_le_bytes());
            self.0[at + 4] = shift;
            self.0[at + 6] = 0x40 + i as u8;
        }
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
            let records = RECORDS + index * 16;
            self.0[at + 2..at + 4]
                .copy_from_slice(&((records - DISPLAY_OBJECT) as u16).to_le_bytes());
            self.0[at + 4..at + 6].copy_from_slice(&enc.to_le_bytes());
            self.0[at + 12..at + 14].copy_from_slice(&((index as u16) + 1).to_le_bytes());
            self.hpd_record(records, 0x40 + index as u8);
            self.0[records + 4..records + 8].copy_from_slice(&[
                1,
                4,
                0x80 + transmitter(*enc).unwrap_or(index as u8),
                0,
            ]);
            self.0[records + 8..records + 10].copy_from_slice(&[0xff, 0]);
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.0
    }
}
fn display_paths(vbios: &[u8]) -> Result<Vec<Path>, Error> {
    display_paths_at(vbios, DCN_BASE, 5)
}
fn routes_for_sink(
    paths: &[Path],
    sink: &crate::amdgpu_usbc::Sink,
    frontend: u8,
) -> Result<Vec<crate::amdgpu_dio::Route>, Error> {
    routes_for_profile(Profile::Dcn314, paths, sink, frontend)
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
    // 0x3513 is a connector (type 3), kind 0x13 (DisplayPort), enum 5; its
    // encoder 0x211e is an encoder (type 2), UNIPHY (0x1e), enum 1 — transmitter
    // A. These are ObjectID.h ids, as Linux's bios_parser_common decodes them.
    if paths.len() != 2 {
        return TestResult::Fail("path count");
    }
    if paths[0]
        != (Path {
            connector: Connector::DisplayPort,
            connector_instance: 5,
            transmitter: 0,
            aux: Some(0),
            hpd: 1,
            device_tag: 1,
            max_speed_mhz: 0,
        })
    {
        return TestResult::Fail("first path");
    }
    // 0x3614 is eDP enum 6; encoder 0x2220 is UNIPHY1 enum 2 — transmitter D.
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
        (0x211eu16, 0u8),
        (0x221e, 1),
        (0x2120, 2),
        (0x2220, 3),
        (0x2121, 4),
        (0x2221, 5),
        (0x2125, 6),
    ] {
        if transmitter(objid) != Ok(expected) {
            return TestResult::Fail("transmitter mapping");
        }
    }
    // A connector is not an encoder, an unknown encoder has no transmitter,
    // and enum zero is not an instance.
    // UNIPHY3 has no second transmitter, and displayobject.h's UNIPHY (1) is
    // ObjectID.h's LVDS, never a transmitter.
    for objid in [0x3513u16, 0x2109, 0x201e, 0x2122, 0x2225, 0x2101] {
        if transmitter(objid).is_ok() {
            return TestResult::Fail("non-encoder accepted as a transmitter");
        }
    }
    // A connector of a kind we do not name still decodes, with its own id.
    if connector(0x3509) != Ok((Connector::Other(9), 5)) {
        return TestResult::Fail("unnamed connector kind");
    }
    // displayobject.h's DisplayPort id (5) is ObjectID.h's VGA.
    if connector(0x3505) != Ok((Connector::Other(5), 5)) {
        return TestResult::Fail("displayobject.h id decoded as DisplayPort");
    }
    if connector(0x3013).is_ok() {
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
    image.paths(&[(0x3513, 0x211e), (0x3513, 0x2109), (0x1013, 0x211e)]);
    let paths = match display_paths(image.bytes()) {
        Ok(paths) => paths,
        Err(_) => return TestResult::Fail("table with one readable path rejected"),
    };
    if paths.len() != 1 || paths[0].transmitter != 0 {
        return TestResult::Fail("unreadable paths not skipped");
    }
    // A table with nothing readable is not a topology we can use.
    let mut none = Image::new();
    none.paths(&[(0x3513, 0x2109)]);
    if display_paths(none.bytes()) != Err(Error::Unsupported) {
        return TestResult::Fail("table with no readable path accepted");
    }
    // A path array that runs past the table's own declared size is malformed.
    let mut lying = Image::new();
    lying.paths(&[(0x3513, 0x211e)]);
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
    // DCE_INFO_CAPS_LTTPR_SUPPORT_ENABLE (0x20) in display_caps; the
    // transparent-enable bit (0x40) is a different capability.
    let mut caps = Image::new();
    caps.dce(10_000);
    if lttpr_non_transparent(caps.bytes()) != Ok(false) {
        return TestResult::Fail("LTTPR bit clear");
    }
    caps.0[DCE + 4] = 0x40;
    if lttpr_non_transparent(caps.bytes()) != Ok(false) {
        return TestResult::Fail("transparent-enable bit is not non-transparent");
    }
    caps.0[DCE + 4] = 0x60;
    if lttpr_non_transparent(caps.bytes()) != Ok(true)
        || lttpr_non_transparent(gone.bytes()) != Err(Error::Missing)
    {
        return TestResult::Fail("LTTPR support bit");
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

fn inventory_gpio_ids_are_resolved_and_bad_records_fail_closed() -> TestResult {
    let image = Image::new();
    for (i, uid) in (0x40..=0x45).enumerate() {
        if hpd_selector(image.bytes(), uid, DCN_BASE) != Ok(i as u8 + 1) {
            return TestResult::Fail("HPD GPIO uid not resolved");
        }
    }
    // uid 1 is not HPD1; the LUT, not the uid, identifies the hardware line.
    if hpd_selector(image.bytes(), 1, DCN_BASE) != Err(Error::Missing) {
        return TestResult::Fail("HPD uid mistaken for selector");
    }
    let mut none = Image::new();
    none.0[DISPLAY_OBJECT + 10..DISPLAY_OBJECT + 12].fill(0);
    let paths = display_paths(none.bytes()).unwrap();
    if paths[0].aux.is_some() || paths[0].hpd != 0 {
        return TestResult::Fail("absent routing invented defaults");
    }
    for case in 0..9 {
        let mut bad = Image::new();
        match case {
            0 => bad.0[RECORDS + 1] = 0,
            1 => bad.0[RECORDS + 1] = 3,
            2 => bad.0[RECORDS + 2] = 1,
            3 => bad.0[RECORDS + 4] = 2,          // duplicate HPD
            4 => bad.0[GPIO + 4 + 6 * 8 + 4] = 1, // not an HPD bit
            5 => bad.0[GPIO + 4 + 4] = 8,         // DDC data, not clock
            6 => bad.0[GPIO + 4 + 6] = 0x81,      // missing requested GPIO uid
            7 => bad.0[DISPLAY_OBJECT + 10..DISPLAY_OBJECT + 12]
                .copy_from_slice(&0xffffu16.to_le_bytes()),
            _ => {
                bad.0[DISPLAY_OBJECT + 10..DISPLAY_OBJECT + 12].copy_from_slice(&8u16.to_le_bytes())
            }
        }
        if display_paths(bad.bytes()).is_ok() {
            return TestResult::Fail("malformed board routing accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_gpio_ids_are_resolved_and_bad_records_fail_closed
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
    // This fixture happens to wire AUX0 to transmitter A. The crossed-wiring
    // regression below ensures that identity is not assumed by the driver.
    let routes = match routes_for_sink(&paths, &sink(crate::amdgpu_dmub::Channel::Legacy, 0), 2) {
        Ok(routes) => routes,
        Err(_) => return TestResult::Fail("native route rejected"),
    };
    if routes.len() != 1 {
        return TestResult::Fail("native sink offered more than one route");
    }
    let route = routes[0];
    if route.backend != 0 || route.aux != 0 || route.hpd != 1 || route.frontend != 2 {
        return TestResult::Fail("native route");
    }
    if route.channel != crate::amdgpu_dmub::Channel::Legacy {
        return TestResult::Fail("route channel");
    }
    // A transmitter the board wired to nothing we can drive is refused rather
    // than driven on the strength of the sink's index alone.
    for instance in [1u8, 4] {
        if routes_for_sink(
            &paths,
            &sink(crate::amdgpu_dmub::Channel::Legacy, instance),
            0,
        )
        .err()
            != Some(Error::Unsupported)
        {
            return TestResult::Fail("unwired transmitter accepted");
        }
    }
    // A board whose connector is neither DisplayPort nor eDP is not this path.
    let mut hdmi = Image::new();
    hdmi.paths(&[(0x350c, 0x211e)]);
    let hdmi_paths = display_paths(hdmi.bytes()).unwrap();
    if routes_for_sink(
        &hdmi_paths,
        &sink(crate::amdgpu_dmub::Channel::Legacy, 0),
        0,
    )
    .err()
        != Some(Error::Unsupported)
    {
        return TestResult::Fail("HDMI connector accepted as a DisplayPort route");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_route_is_validated_against_the_board
);

fn inventory_tunnelled_sinks_borrow_an_unwired_transmitter_first() -> TestResult {
    // The fixture wires transmitters 0 and 3; 1, 2 and 4 are spare.
    let image = Image::new();
    let paths = display_paths(image.bytes()).unwrap();
    let sink = crate::amdgpu_usbc::Sink {
        channel: crate::amdgpu_dmub::Channel::Dpia,
        instance: 2,
        dpcd: [0; 16],
        edid: Vec::new(),
    };
    let routes = match routes_for_sink(&paths, &sink, 1) {
        Ok(routes) => routes,
        Err(_) => return TestResult::Fail("tunnelled sink offered no route"),
    };
    // Every transmitter is a candidate, but the spare ones come first so
    // borrowing cannot deprive a later native plug of its fixed transmitter.
    if routes.len() != DIG_COUNT as usize {
        return TestResult::Fail("candidate count");
    }
    let order: Vec<u8> = routes.iter().map(|route| route.backend).collect();
    if order != [1, 2, 4, 0, 3] {
        return TestResult::Fail("candidate order");
    }
    for route in &routes {
        // The tunnel reports presence, so there is no board hot-plug line, and
        // the AUX index is the tunnelling endpoint rather than a transmitter.
        if route.hpd != 0 || route.aux != 2 || route.frontend != 1 {
            return TestResult::Fail("tunnelled route fields");
        }
        if route.channel != crate::amdgpu_dmub::Channel::Dpia {
            return TestResult::Fail("tunnelled route channel");
        }
    }
    // A board that wires nothing leaves every transmitter spare.
    let mut bare = Image::new();
    bare.paths(&[(0x3513, 0x2121)]);
    let bare_paths = display_paths(bare.bytes()).unwrap();
    let bare_order: Vec<u8> = routes_for_sink(&bare_paths, &sink, 0)
        .unwrap()
        .iter()
        .map(|route| route.backend)
        .collect();
    if bare_order != [0, 1, 2, 3, 4] {
        return TestResult::Fail("candidate order with one wired transmitter");
    }
    // There are four tunnelling endpoints; a fifth is not one.
    let beyond = crate::amdgpu_usbc::Sink {
        instance: DPIA_COUNT,
        ..sink
    };
    if routes_for_sink(&paths, &beyond, 0).err() != Some(Error::Invalid) {
        return TestResult::Fail("out-of-range tunnelling endpoint accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_tunnelled_sinks_borrow_an_unwired_transmitter_first
);

fn inventory_native_route_keeps_aux_hpd_and_transmitter_separate() -> TestResult {
    let mut image = Image::new();
    // Transmitter F, AUX3, HPD5; frontend B chosen independently by the caller.
    image.paths(&[(0x3513, 0x2221)]);
    image.0[RECORDS + 2] = 0x44;
    image.0[RECORDS + 6] = 0x83;
    // A decoy list at the old absolute address must never influence routing.
    image.0[0x300..0x30a].copy_from_slice(&[2, 4, 0x40, 0, 1, 4, 0x80, 0, 0xff, 0]);
    let paths = display_paths_at(image.bytes(), DCN_BASE, 6).unwrap();
    let sink = crate::amdgpu_usbc::Sink {
        channel: crate::amdgpu_dmub::Channel::Legacy,
        instance: 3,
        dpcd: [0; 16],
        edid: Vec::new(),
    };
    let routes = routes_for_profile(Profile::Navi22, &paths, &sink, 1).unwrap();
    if routes.len() != 1
        || routes[0].backend != 5
        || routes[0].aux != 3
        || routes[0].hpd != 5
        || routes[0].frontend != 1
    {
        return TestResult::Fail("native wiring still assumes identical indices");
    }
    let wrong = crate::amdgpu_usbc::Sink {
        instance: 5,
        ..sink.clone()
    };
    if routes_for_profile(Profile::Navi22, &paths, &wrong, 0) != Err(Error::Unsupported) {
        return TestResult::Fail("transmitter number accepted as AUX channel");
    }
    let mut ambiguous = paths.clone();
    ambiguous.push(paths[0]);
    if routes_for_profile(Profile::Navi22, &ambiguous, &sink, 0) != Err(Error::Invalid) {
        return TestResult::Fail("ambiguous AUX selected the first connector");
    }
    let tunnel = crate::amdgpu_usbc::Sink {
        channel: crate::amdgpu_dmub::Channel::Dpia,
        ..sink
    };
    if routes_for_profile(Profile::Navi22, &paths, &tunnel, 0) != Err(Error::Unsupported) {
        return TestResult::Fail("Navi22 invented a DPIA route");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_native_route_keeps_aux_hpd_and_transmitter_separate
);

fn inventory_routes_follow_discovery_and_generation_specific_dig() -> TestResult {
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    let mut dcn = gpu.ip_blocks[0];
    dcn.hw_id = crate::amdgpu_discovery::HW_ID_DCN;
    dcn.major = 3;
    dcn.minor = 0;
    dcn.revision = 0;
    dcn.base_addrs[2] = DCN_BASE;
    gpu.ip_blocks.push(dcn);
    let mut image = Image::new();
    image.paths(&[(0x3513, 0x2221)]);
    image.0[RECORDS + 6] = 0x83;
    let paths = super::display_paths(&gpu, image.bytes()).unwrap();
    let sink = crate::amdgpu_usbc::Sink {
        channel: crate::amdgpu_dmub::Channel::Legacy,
        instance: 3,
        dpcd: [0; 16],
        edid: Vec::new(),
    };
    if super::routes_for_sink(&gpu, &paths, &sink, 5).unwrap()[0].backend != 5 {
        return TestResult::Fail("Navi22 sixth DIG lost");
    }
    let mut regs = vec![0u32; (DCN_BASE + 0x28f6) as usize];
    gpu.regs.virt = regs.as_mut_ptr() as u64;
    gpu.regs.len = regs.len() as u64 * 4;
    let cap = Cap::bootstrap();
    // SAFETY: exclusively owned register model, alive throughout each probe.
    unsafe {
        regs[(DCN_BASE + 0x25b1) as usize] = 1;
        if transmitter_busy(&gpu, &cap, 5) != Ok(true) {
            return TestResult::Fail("Navi22 BE enable offset");
        }
        regs[(DCN_BASE + 0x25b1) as usize] = 0;
        regs[(DCN_BASE + 0x25b2) as usize] = 1;
        if transmitter_busy(&gpu, &cap, 5) != Ok(false) {
            return TestResult::Fail("Navi22 read Phoenix BE offset");
        }
        if transmitter_busy(&gpu, &cap, 6) != Err(Error::Invalid) {
            return TestResult::Fail("seventh DIG admitted");
        }
        gpu.ip_blocks.last_mut().unwrap().minor = 1;
        gpu.ip_blocks.last_mut().unwrap().revision = 4;
        regs[(DCN_BASE + 0x24b2) as usize] = 1;
        if transmitter_busy(&gpu, &cap, 4) != Ok(true)
            || transmitter_busy(&gpu, &cap, 5) != Err(Error::Invalid)
        {
            return TestResult::Fail("Phoenix DIG bounds/offset changed");
        }
        cap.revoke();
        if transmitter_busy(&gpu, &cap, 4) != Err(Error::Revoked) {
            return TestResult::Fail("revoked DIG probe");
        }
    }
    // The LUT's register identity must match this GPU's discovered DCN bank.
    gpu.ip_blocks.last_mut().unwrap().minor = 0;
    gpu.ip_blocks.last_mut().unwrap().revision = 0;
    gpu.ip_blocks.last_mut().unwrap().base_addrs[2] += 4;
    if super::display_paths(&gpu, image.bytes()).is_ok() {
        return TestResult::Fail("GPIO registers from another layout accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_routes_follow_discovery_and_generation_specific_dig
);

fn inventory_routing_rejects_ambiguous_pins_bridges_and_truncation() -> TestResult {
    let mut image = Image::new();
    // Duplicate GPIO UID, even when one definition looks usable.
    let pin = image.0[GPIO + 4..GPIO + 12].to_vec();
    image.0[GPIO + 12..GPIO + 20].copy_from_slice(&pin);
    if display_paths(image.bytes()) != Err(Error::Invalid) {
        return TestResult::Fail("duplicate GPIO uid accepted");
    }
    let mut image = Image::new();
    image.paths(&[(0x3513, 0x211e)]);
    image.0[DISPLAY_OBJECT + PATHS_OFFSET + 6] = 1;
    if display_paths(image.bytes()) != Err(Error::Unsupported) {
        return TestResult::Fail("external encoder silently bypassed");
    }
    let image = Image::new();
    for len in GPIO..GPIO + 100 {
        if display_paths(&image.bytes()[..len]).is_ok() {
            return TestResult::Fail("truncated GPIO LUT admitted");
        }
    }
    let mut paths = display_paths(image.bytes()).unwrap();
    paths[1].transmitter = paths[0].transmitter;
    let sink = crate::amdgpu_usbc::Sink {
        channel: crate::amdgpu_dmub::Channel::Legacy,
        instance: 0,
        dpcd: [0; 16],
        edid: Vec::new(),
    };
    if routes_for_sink(&paths, &sink, 0) != Err(Error::Invalid) {
        return TestResult::Fail("shared transmitter lacks mux ownership");
    }
    if routes_for_sink(&paths, &sink, 5) != Err(Error::Invalid) {
        return TestResult::Fail("frontend beyond profile accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_routing_rejects_ambiguous_pins_bridges_and_truncation
);

fn inventory_navi48_v15_routes_and_backend_stride() -> TestResult {
    let mut gpu = crate::amdgpu_navi48_firmware::tests::gpu();
    let dcn = gpu.ip_blocks.last_mut().unwrap();
    dcn.num_bases = 3;
    dcn.base_addrs[2] = DCN_BASE;
    let mut regs = vec![0u32; (DCN_BASE + 0x28f6) as usize];
    gpu.regs.virt = regs.as_mut_ptr() as u64;
    gpu.regs.len = regs.len() as u64 * 4;
    let mut image = Image::new();
    image.paths(&[(0x3113, 0x2220)]);
    image.0[DISPLAY_OBJECT + 3] = 5;
    // v1.5's reserved USB-C word must not become a v1.4 external encoder.
    image.0[DISPLAY_OBJECT + PATHS_OFFSET + 6] = 1;
    image.0[RECORDS + 2] = 0x41;
    image.0[RECORDS + 6] = 0x81;
    image.0[DCE + 3] = 5;
    let paths = super::display_paths(&gpu, image.bytes()).unwrap();
    let sink = crate::amdgpu_usbc::Sink {
        channel: crate::amdgpu_dmub::Channel::Legacy,
        instance: 1,
        dpcd: [0; 16],
        edid: Vec::new(),
    };
    let routes = super::routes_for_sink(&gpu, &paths, &sink, 2).unwrap();
    if routes[0].aux != 1
        || routes[0].backend != 3
        || routes[0].hpd != 2
        || routes[0].frontend != 2
        || dchub_refclk_khz(image.bytes()) != Ok(27_000)
        || Profile::resolve(&gpu).is_ok()
    {
        return TestResult::Fail("DCN4 routing confused identities or enabled DCN3 programming");
    }
    let cap = Cap::bootstrap();
    // SAFETY: owned register model, with the actual DCN4 addresses as oracle.
    unsafe {
        for (instance, reg) in [0x20bd, 0x21e1, 0x2305, 0x2429].into_iter().enumerate() {
            regs[(DCN_BASE + reg) as usize] = 1;
            if transmitter_busy(&gpu, &cap, instance as u8) != Ok(true) {
                return TestResult::Fail("DCN4 transmitter offset/stride");
            }
            regs[(DCN_BASE + reg) as usize] = 0;
            if transmitter_busy(&gpu, &cap, instance as u8) != Ok(false) {
                return TestResult::Fail("DCN4 inactive transmitter misreported");
            }
        }
        if transmitter_busy(&gpu, &cap, 4) != Err(Error::Invalid) {
            return TestResult::Fail("fifth DCN4 transmitter accepted");
        }
        cap.revoke();
        if transmitter_busy(&gpu, &cap, 0) != Err(Error::Revoked) {
            return TestResult::Fail("revoked DCN4 inventory access");
        }
    }
    if super::routes_for_sink(&gpu, &paths, &sink, 4) != Err(Error::Invalid) {
        return TestResult::Fail("fifth DCN4 frontend accepted");
    }
    image.0[RECORDS + 6] = 0x84;
    if super::display_paths(&gpu, image.bytes()) != Err(Error::Unsupported) {
        return TestResult::Fail("fifth DCN4 AUX accepted");
    }
    image.0[RECORDS + 6] = 0x81;
    image.0[RECORDS + 2] = 0x44;
    if super::display_paths(&gpu, image.bytes()) != Err(Error::Unsupported) {
        return TestResult::Fail("fifth DCN4 HPD accepted");
    }
    image.0[RECORDS + 2] = 0x41;
    gpu.ip_blocks.last_mut().unwrap().revision = 2;
    if super::display_paths(&gpu, image.bytes()) != Err(Error::Unsupported) {
        return TestResult::Fail("foreign DCN4 revision accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_navi48_v15_routes_and_backend_stride
);

/// ATOM_CONNECTOR_SPEED_UPTO (record 4): the first full record of a path's
/// list gives its connector_max_speed; a short one is skipped and a path
/// without one reports zero, as bios_parser2's lookup does.
fn inventory_reads_the_connector_speed_record() -> TestResult {
    let mut image = Image::new();
    // The second path's list: HPD, I2C, then speed records before the end.
    let at = RECORDS + 16 + 8;
    image.0[at..at + 6].copy_from_slice(&[4, 6, 0x10, 0x27, 0, 0]); // short: skipped
    image.0[at + 6..at + 14].copy_from_slice(&[4, 8, 0xbc, 0x34, 0, 0, 0, 0]); // 13500
    image.0[at + 14..at + 22].copy_from_slice(&[4, 8, 0x20, 0x4e, 0, 0, 0, 0]); // 20000
    image.0[at + 22..at + 24].copy_from_slice(&[0xff, 0]);
    match display_paths(image.bytes()) {
        Ok(paths) if paths[0].max_speed_mhz == 0 && paths[1].max_speed_mhz == 13_500 => {
            TestResult::Pass
        }
        _ => TestResult::Fail("connector speed record"),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_reads_the_connector_speed_record
);

fn inventory_reads_discrete_vram_channels_from_vram_info_v25() -> TestResult {
    const VRAM: usize = 0x870;
    let mut image = Image::new();
    image.point(TABLE_VRAM_INFO, VRAM);
    let size = 64u16;
    image.0[VRAM..VRAM + 2].copy_from_slice(&size.to_le_bytes());
    image.0[VRAM + 2] = 2;
    image.0[VRAM + 3] = 5;
    image.0[VRAM + VRAM_MODULE_NUM_OFFSET] = 1;
    // Navi22: twelve channels of CHANNEL_16BIT (log2 16 = 4).
    image.0[VRAM + VRAM_MODULE0_OFFSET + VRAM_CHANNEL_NUM] = 12;
    image.0[VRAM + VRAM_MODULE0_OFFSET + VRAM_CHANNEL_WIDTH] = 4;
    if vram_channels(image.bytes()) != Ok((12, 2)) {
        return TestResult::Fail("vram_info v2.5 channels");
    }
    image.0[VRAM + VRAM_MODULE0_OFFSET + VRAM_CHANNEL_WIDTH] = 9;
    if vram_channels(image.bytes()) != Err(Error::Invalid) {
        return TestResult::Fail("absurd channel width");
    }
    image.0[VRAM + 3] = 6;
    if vram_channels(image.bytes()) != Err(Error::Unsupported) {
        return TestResult::Fail("other vram_info revision read");
    }
    image.unpoint(TABLE_VRAM_INFO);
    if vram_channels(image.bytes()) != Err(Error::Missing) {
        return TestResult::Fail("absent vram_info");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_reads_discrete_vram_channels_from_vram_info_v25
);

fn inventory_encoder_caps_read_the_encoder_record_list() -> TestResult {
    let mut image = Image::new();
    // Path 0's encoder (UNIPHY A: transmitter 0) carries an encoder-caps
    // record after an unrelated one; path 1's (transmitter 3) has no list.
    let list = 0x780usize;
    let at = DISPLAY_OBJECT + PATHS_OFFSET + 8;
    image.0[at..at + 2].copy_from_slice(&((list - DISPLAY_OBJECT) as u16).to_le_bytes());
    image.0[list..list + 12].copy_from_slice(&[
        21,
        4,
        0,
        0, // bracket layout, skipped
        RECORD_ENCODER_CAP,
        6,
        0x0c,
        0,
        0,
        0, // HBR2_EN | HDMI6Gbps_EN
        RECORD_END,
        2,
    ]);
    if encoder_caps(image.bytes(), 0) != Ok(Some(0x0c))
        || encoder_caps(image.bytes(), 3) != Ok(None)
        || encoder_caps(image.bytes(), 5) != Ok(None)
    {
        return TestResult::Fail("encoder caps record");
    }
    // A short record is not an encoder-caps record.
    image.0[list + 5] = 5;
    image.0[list + 9..list + 11].copy_from_slice(&[RECORD_END, 2]);
    if encoder_caps(image.bytes(), 0) != Ok(None) {
        return TestResult::Fail("short caps record");
    }
    // Linux reports no record for every v1.5 object table.
    image.0[list + 5] = 6;
    image.0[DISPLAY_OBJECT + 3] = 5;
    if encoder_caps(image.bytes(), 0) != Ok(None) {
        return TestResult::Fail("v1.5 caps");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-inventory",
    inventory_encoder_caps_read_the_encoder_record_list
);
