use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const DCN2: u64 = 0x1000;
const DCN3: u64 = 0x40000;

#[derive(Default)]
struct Fake {
    values: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    gone: bool,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        *self.values.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.writes.push((at, value));
        self.values.insert(at, value);
    }
}
fn engine(pipe: u8) -> Engine<Fake> {
    Engine {
        io: Fake::default(),
        authority: Cap::bootstrap(),
        dcn2: DCN2,
        dcn3: DCN3,
        pipe,
        slices: None,
        shown: None,
        placed: [None; 2],
    }
}
fn hubp(pipe: u8, reg: u64) -> u64 {
    DCN2 + (reg + u64::from(pipe) * HUBP_STRIDE) * 4
}
fn dpp(pipe: u8, reg: u64) -> u64 {
    DCN2 + (reg + u64::from(pipe) * DPP_STRIDE) * 4
}
fn lock(pipe: u8) -> u64 {
    DCN3 + (CUR_VUPDATE_LOCK_SET + u64::from(pipe) * LOCK_STRIDE) * 4
}
const VIEW: (u32, u32) = (1920, 1080);
/// DCHUB refclk 100 MHz, 1080p60 pixel clock.
const CLOCKS: (u32, u32) = (100_000, 148_500);

fn dcn30_cursor_placement_follows_amdgpu_dm_and_hubp2() -> TestResult {
    let p = placement(100, 50, (64, 64), VIEW, CLOCKS);
    if p != (Placement {
        visible: true,
        x: 100,
        y: 50,
        hot_x: 0,
        hot_y: 0,
        dst_x_offset: 100 * 100_000 / 148_500,
    }) {
        return TestResult::Fail("on-screen placement");
    }
    // A negative origin moves into the hotspot; the image stays visible
    // while any of it is on screen.
    let p = placement(-10, -300, (64, 64), VIEW, CLOCKS);
    if p.visible {
        return TestResult::Fail("origin at -300 beyond the 256 cap shown");
    }
    let p = placement(-10, -5, (64, 64), VIEW, CLOCKS);
    if !p.visible || (p.x, p.y, p.hot_x, p.hot_y, p.dst_x_offset) != (0, 0, 10, 5, 0) {
        return TestResult::Fail("negative origin hotspot");
    }
    for (x, y) in [(-64, 0), (0, -64), (1920, 0), (0, 1080)] {
        if placement(x, y, (64, 64), VIEW, CLOCKS).visible {
            return TestResult::Fail("off-screen cursor visible");
        }
    }
    if lines_per_chunk(32) != 4
        || lines_per_chunk(64) != 3
        || lines_per_chunk(128) != 2
        || lines_per_chunk(256) != 1
    {
        return TestResult::Fail("lines per chunk");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_cursor_placement_follows_amdgpu_dm_and_hubp2
);

fn dcn30_cursor_programs_attributes_and_position_under_lock() -> TestResult {
    let mut e = engine(1);
    // Inherited magnify/enable bits from a previous owner, and a set
    // reserved bit that must survive.
    e.io.values
        .insert(hubp(1, CURSOR_CONTROL), 0x10 | 1 | 0x8000_0000);
    e.io.values.insert(dpp(1, CUR0_CONTROL), 0x8 | 0x2 | 0x80);
    let address = 0x0003_0004_0000;
    let Ok(shown) = e.show(address, (64, 48), (200, 100), VIEW, CLOCKS) else {
        return TestResult::Fail("show refused");
    };
    let w = &e.io.writes;
    if w.first() != Some(&(lock(1), 1)) || w.last() != Some(&(lock(1), 0)) {
        return TestResult::Fail("cursor writes not inside the OPP lock");
    }
    let v = |at| *e.io.values.get(&at).unwrap_or(&0);
    if v(hubp(1, CURSOR_SURFACE_ADDRESS_HIGH)) != 3
        || v(hubp(1, CURSOR_SURFACE_ADDRESS)) != 0x0004_0000
        || v(hubp(1, CURSOR_SIZE)) != 64 << 16 | 48
        || v(hubp(1, CURSOR_CONTROL)) != (3 << 24 | 2 << 16 | 2 << 8 | 1 | 0x8000_0000)
        || v(hubp(1, CURSOR_SETTINGS)) != 3 << 8
        || v(hubp(1, CURSOR_POSITION)) != 200 << 16 | 100
        || v(hubp(1, CURSOR_HOT_SPOT)) != 0
        || v(hubp(1, CURSOR_DST_OFFSET)) != 200 * 100_000 / 148_500
        || v(dpp(1, CUR0_CONTROL)) != (2 << 4 | 1 | 0x80)
    {
        return TestResult::Fail("cursor register fields");
    }
    if shown.placement.x != 200 || e.shown != Some(shown) {
        return TestResult::Fail("shown state");
    }
    // Moving off screen disables both halves; hiding releases the lock.
    e.io.writes.clear();
    if e.move_to((-100, 0), VIEW, CLOCKS)
        .map(|s| s.placement.visible)
        != Ok(false)
        || v_of(&e, hubp(1, CURSOR_CONTROL)) & 1 != 0
        || v_of(&e, dpp(1, CUR0_CONTROL)) & 1 != 0
    {
        return TestResult::Fail("off-screen move");
    }
    if e.hide().is_err() || e.shown.is_some() || e.io.writes.last() != Some(&(lock(1), 0)) {
        return TestResult::Fail("hide");
    }
    TestResult::Pass
}
fn v_of(e: &Engine<Fake>, at: u64) -> u32 {
    *e.io.values.get(&at).unwrap_or(&0)
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_cursor_programs_attributes_and_position_under_lock
);

fn dcn30_cursor_refuses_bad_images_and_releases_lock_on_loss() -> TestResult {
    let mut e = engine(0);
    for (address, size) in [
        (0x1000, (257, 16)),
        (0x1000, (16, 0)),
        (0, (16, 16)),
        (0x1080, (16, 16)),
    ] {
        if e.show(address, size, (0, 0), VIEW, CLOCKS) != Err(Error::Invalid) {
            return TestResult::Fail("invalid image accepted");
        }
    }
    if e.move_to((0, 0), VIEW, CLOCKS) != Err(Error::Invalid) {
        return TestResult::Fail("move without an image");
    }
    e.io.gone = true;
    if e.show(0x1000, (16, 16), (0, 0), VIEW, CLOCKS) != Err(Error::DeviceGone) {
        return TestResult::Fail("device loss not reported");
    }
    if e.io.writes.last() != Some(&(lock(0), 0)) || e.shown.is_some() {
        return TestResult::Fail("lock held after failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_cursor_refuses_bad_images_and_releases_lock_on_loss
);

fn dcn30_cursor_odm_places_each_slice_relative_to_its_viewport() -> TestResult {
    let mut e = engine(0);
    e.slices = Some([(0, 0, 960), (5, 960, 960)]);
    // Straddling the seam: both slices show it, at the same stream x.
    let shown = e.show(0x10_0000, (64, 64), (940, 10), VIEW, CLOCKS);
    if shown.is_err() {
        return TestResult::Fail("ODM cursor refused");
    }
    for pipe in [0, 5] {
        if v_of(&e, hubp(pipe, CURSOR_CONTROL)) & 1 != 1
            || v_of(&e, dpp(pipe, CUR0_CONTROL)) & 1 != 1
            || v_of(&e, hubp(pipe, CURSOR_POSITION)) != 940 << 16 | 10
            || v_of(&e, hubp(pipe, CURSOR_SURFACE_ADDRESS)) != 0x10_0000
        {
            return TestResult::Fail("straddling cursor not on both slices");
        }
    }
    // hubp2_cursor_set_position: DST_X_OFFSET from the slice's own start.
    if v_of(&e, hubp(0, CURSOR_DST_OFFSET)) != 940 * 100_000 / 148_500
        || v_of(&e, hubp(5, CURSOR_DST_OFFSET)) != 0
    {
        return TestResult::Fail("per-slice destination offset");
    }
    // Wholly in the right half: the left slice disables it.
    if e.move_to((1500, 10), VIEW, CLOCKS).is_err() {
        return TestResult::Fail("ODM move refused");
    }
    if v_of(&e, hubp(0, CURSOR_CONTROL)) & 1 != 0
        || v_of(&e, hubp(5, CURSOR_CONTROL)) & 1 != 1
        || v_of(&e, hubp(5, CURSOR_DST_OFFSET)) != (1500 - 960) * 100_000 / 148_500
    {
        return TestResult::Fail("right-half cursor placement");
    }
    // Only the master OPP's cursor lock is taken, and it is released.
    if e.io.writes.iter().any(|&(at, _)| at == lock(5)) || v_of(&e, lock(0)) != 0 {
        return TestResult::Fail("cursor lock");
    }
    if e.hide().is_err()
        || [0, 5]
            .iter()
            .any(|&p| v_of(&e, hubp(p, CURSOR_CONTROL)) & 1 != 0)
    {
        return TestResult::Fail("ODM hide left a slice's cursor on");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_cursor_odm_places_each_slice_relative_to_its_viewport
);
