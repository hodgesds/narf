//! Fuzz target: the VESA E-EDID 1.4 block parser (plus extensions).
//!
//! Surface: `narf_edid::Block::parse` over the first 128 bytes,
//! then — when the base block parses — the extension blocks that
//! follow it: tag `0x02` → `cta861::CtaExtension::parse`, tag
//! `0x70` → `displayid::Section::parse` (tag byte consumed by the
//! caller, per that function's docs). EDID arrives from the
//! display over DDC/I²C; a malicious or broken monitor hands the
//! kernel a self-describing 128-byte block with a checksum, a
//! descriptor table, and an extension count — the classic shape
//! for descriptor-table and length bugs. Every parse is over a
//! fixed 128-byte slice, so work per input is bounded by the
//! input size itself.
//!
//! Invariant: never panic, never read out of bounds, for any byte
//! string. `EdidError` / `DisplayIdError` is the correct outcome
//! for a malformed block. On a successful base parse the decoded
//! accessors are also exercised (`monitor_name`,
//! `preferred_mode`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use narf_edid::cta861::CtaExtension;
use narf_edid::displayid::Section;
use narf_edid::{cta861, Block, EDID_BLOCK_SIZE};

/// Cap the input: one base block plus at most four extension
/// blocks (the parser only ever walks `extension_count` of
/// them); anything longer buys libFuzzer slower iterations.
const MAX_EDID: usize = 5 * EDID_BLOCK_SIZE;

fuzz_target!(|data: &[u8]| {
    if data.len() < EDID_BLOCK_SIZE || data.len() > MAX_EDID {
        return;
    }
    let Ok(block) = Block::parse(&data[..EDID_BLOCK_SIZE]) else {
        return;
    };
    let _ = block.monitor_name();
    let _ = block.preferred_mode();

    let available = (data.len() - EDID_BLOCK_SIZE) / EDID_BLOCK_SIZE;
    let n_ext = (block.extension_count as usize).min(available);
    for i in 0..n_ext {
        let off = EDID_BLOCK_SIZE + i * EDID_BLOCK_SIZE;
        let ext = &data[off..off + EDID_BLOCK_SIZE];
        match ext[0] {
            cta861::CTA_TAG => {
                let _ = CtaExtension::parse(ext);
            }
            0x70 => {
                // DisplayID: the 0x70 tag is consumed by the
                // caller; the section starts at the next byte.
                let _ = Section::parse(&ext[1..]);
            }
            _ => {}
        }
    }
});
