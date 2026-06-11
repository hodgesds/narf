//! End-of-boot splash composer.
//!
//! Paints a one-screen "kernel up" panel through the global
//! `FbConsole`: a coloured title bar at the top, a body listing
//! the kernel build + a few invariants the user might want to see
//! at a glance, and the mouse cursor on top.
//!
//! Independent of the actual data sources — callers pass a
//! `BootInfo` snapshot they've already collected. This crate
//! doesn't depend on `narf-drivers` / `narf-acpi` / etc.

use core::fmt::Write;

use crate::{console::GLOBAL_FB_CONSOLE, Cursor, Pixel32};

#[derive(Copy, Clone, Debug)]
pub struct BootInfo<'a> {
    pub arch: &'a str,
    pub version: &'a str,
    pub cpu_count: u32,
    pub numa_nodes: u32,
    pub bound_drivers: u32,
    pub backend: &'a str, // "pks", "mte", "pcid", ...
}

const TITLE_BAR_HEIGHT: u32 = 24;
const TITLE_BAR_BG: Pixel32 = Pixel32::rgb(0x20, 0x40, 0x80);
const TITLE_BAR_FG: Pixel32 = Pixel32::WHITE;
const BODY_BG: Pixel32 = Pixel32::NARF_BG;
const BODY_FG: Pixel32 = Pixel32::NARF_FG;
const ACCENT: Pixel32 = Pixel32::rgb(0x40, 0xC0, 0xFF);

/// Render the boot panel into the global framebuffer console.
/// Returns true if a console was installed and the panel painted.
pub fn render(info: &BootInfo<'_>) -> bool {
    let mut g = GLOBAL_FB_CONSOLE.lock();
    let con = match g.as_mut() {
        Some(c) => c,
        None => return false,
    };

    // Reset background + clear.
    con.reset_with_bg(BODY_BG);

    // Paint the title bar (covers the first ~3 rows of glyph cells).
    {
        let fb = con.fb_mut();
        let w = fb.width;
        fb.fill_rect(0, 0, w, TITLE_BAR_HEIGHT, TITLE_BAR_BG);
        // Accent rule between title bar and body.
        fb.fill_rect(0, TITLE_BAR_HEIGHT, w, 2, ACCENT);
    }

    // Title text — drop the cursor inside the title bar's first row.
    con.fg = TITLE_BAR_FG;
    con.bg = TITLE_BAR_BG;
    con.home();
    // Centred-ish: write 1 char of left padding + content.
    let _ = writeln!(con, " NARF {} \u{2014} {}", info.version, info.arch);

    // Body. Move cursor below the title bar (3 glyph rows + the 2-px rule).
    con.fg = BODY_FG;
    con.bg = BODY_BG;
    con.home();
    // Skip the title-bar rows visually by writing blank lines.
    let title_rows = (TITLE_BAR_HEIGHT + 2) / 8;
    for _ in 0..title_rows {
        let _ = writeln!(con);
    }

    let _ = writeln!(con);
    let _ = writeln!(con, " kernel:    NARF v{}", info.version);
    let _ = writeln!(con, " arch:      {}", info.arch);
    let _ = writeln!(con, " enforcer:  {}", info.backend);
    let _ = writeln!(con, " cpus:      {}", info.cpu_count);
    let _ = writeln!(con, " numa:      {} node(s)", info.numa_nodes);
    let _ = writeln!(con, " drivers:   {} bound", info.bound_drivers);
    let _ = writeln!(con);
    let _ = writeln!(con, " framebuffer console + 8x8 glyphs + arrow cursor");
    let _ = writeln!(con, " press a key, move the mouse — events route");
    let _ = writeln!(con, " through narf-input's global ring.");

    // Cursor — draw on top of everything, near screen centre.
    {
        let fb = con.fb_mut();
        let mut cursor = Cursor::new(
            (fb.width / 2) as i32,
            (fb.height / 2) as i32,
            Pixel32::WHITE,
        );
        cursor.draw_at(fb);
    }
    true
}
