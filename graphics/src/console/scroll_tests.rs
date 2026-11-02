use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

const WIDTH: u32 = 16;
const HEIGHT: u32 = 56;
const STRIDE: u32 = 20;
const SENTINEL: u32 = 0x1234_5678;

fn console(pixels: &mut [u32], fg: Pixel32) -> FbConsole {
    assert_eq!(pixels.len(), (STRIDE * HEIGHT) as usize);
    // SAFETY: each test retains its backing pixels until the console drops.
    let fb = unsafe { Framebuffer::new(pixels.as_mut_ptr(), WIDTH, HEIGHT, STRIDE) };
    FbConsole::new(fb, fg, Pixel32::BLACK)
}

fn scroll_count(console: &mut FbConsole) -> usize {
    let mut count = 0;
    console.cur_col = 0;
    console.scroll_up_one_row_with(|fb, x, y, byte, fg, bg| {
        count += 1;
        FbConsole::paint_cell(fb, x, y, byte, fg, bg);
    });
    count
}

fn smoke_console_scroll_spares_unchanged_cells() -> TestResult {
    let mut pixels = vec![SENTINEL; (STRIDE * HEIGHT) as usize];
    let mut expected = pixels.clone();
    let mut actual = console(&mut pixels, Pixel32::WHITE);
    actual.write_bytes(b"AA\nAA\nAA");
    let mut reference = console(&mut expected, Pixel32::WHITE);
    reference.write_bytes(b"AA\nAA\n");
    // Only the occupied bottom row changes; old full-screen scrolling
    // repainted all six cells. Compare pixels, including stride padding
    // and the reserved beacon band, against a non-scrolling reference.
    if scroll_count(&mut actual) != 2 || pixels != expected || actual.cursor() != (0, 2) {
        return TestResult::Fail("scroll repainted unchanged cells or changed visible text");
    }
    TestResult::Pass
}
kernel_test_in!(
    "graphics/console",
    smoke_console_scroll_spares_unchanged_cells
);

fn smoke_console_scroll_moves_different_rows() -> TestResult {
    let mut pixels = vec![SENTINEL; (STRIDE * HEIGHT) as usize];
    let mut expected = pixels.clone();
    let mut actual = console(&mut pixels, Pixel32::WHITE);
    actual.write_bytes(b"AB\nCD\nEF");
    let mut reference = console(&mut expected, Pixel32::WHITE);
    reference.write_bytes(b"CD\nEF\n");
    actual.write_byte(b'\n');
    if pixels != expected || actual.cursor() != (0, 2) {
        return TestResult::Fail("changed rows did not move correctly");
    }
    TestResult::Pass
}
kernel_test_in!(
    "graphics/console",
    smoke_console_scroll_moves_different_rows
);

fn smoke_console_scroll_repaints_palette_and_external_drawing() -> TestResult {
    for external in [false, true] {
        let mut pixels = vec![SENTINEL; (STRIDE * HEIGHT) as usize];
        let mut expected = pixels.clone();
        let mut actual = console(&mut pixels, Pixel32::WHITE);
        actual.write_bytes(b"AA\nAA\nAA");
        let fg = if external {
            actual
                .fb_mut()
                .fill_rect(0, TOP_PX_OFFSET, WIDTH, 24, Pixel32::RED);
            Pixel32::WHITE
        } else {
            actual.fg = Pixel32::RED;
            Pixel32::RED
        };
        let mut reference = console(&mut expected, fg);
        reference.write_bytes(b"AA\nAA\n");
        if scroll_count(&mut actual) != 6 || pixels != expected {
            return TestResult::Fail("scroll reused cells after palette or external pixel changes");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "graphics/console",
    smoke_console_scroll_repaints_palette_and_external_drawing
);

fn smoke_console_scroll_repaints_temporary_palette() -> TestResult {
    let mut pixels = vec![SENTINEL; (STRIDE * HEIGHT) as usize];
    let mut expected = pixels.clone();
    let mut actual = console(&mut pixels, Pixel32::WHITE);
    actual.write_bytes(b"AA\nAA\nAA");
    actual.home();
    actual.fg = Pixel32::RED;
    actual.write_bytes(b"AA");
    actual.fg = Pixel32::WHITE;
    let mut reference = console(&mut expected, Pixel32::WHITE);
    reference.write_bytes(b"AA\nAA\n");
    if scroll_count(&mut actual) != 6 || pixels != expected {
        return TestResult::Fail("temporary palette left stale colours after scroll");
    }
    TestResult::Pass
}
kernel_test_in!(
    "graphics/console",
    smoke_console_scroll_repaints_temporary_palette
);
