//! 8x8 monochrome ASCII font.
//!
//! Stage 1 stub: every printable code maps to a solid 8×8 block;
//! non-printable codes (0x00..=0x1F, 0x7F) map to an empty cell.
//! Real glyph data lands with the framebuffer-console commit when
//! readable text on the framebuffer becomes load-bearing.
//!
//! Format: byte `n` of the returned `[u8; 8]` is row `n`; bit 7 is
//! the leftmost pixel of that row.

const EMPTY: [u8; 8]   = [0x00; 8];
const BLOCK: [u8; 8]   = [0xFF; 8];

/// Look up a glyph by ASCII code. Out-of-range codes return EMPTY;
/// printable codes return BLOCK for now.
pub fn lookup(c: u8) -> [u8; 8] {
    match c {
        0x00..=0x1F | 0x7F => EMPTY,
        _                  => BLOCK,
    }
}
