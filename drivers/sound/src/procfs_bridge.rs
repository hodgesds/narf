//! `/proc/asound/*` bridge — ALSA-compatible procfs entries.
//!
//! # Status
//!
//! The Wave-19 procfs framework agent (which would expose a
//! `register_proc_dir` / `register_proc_file` API for out-of-crate
//! drivers to inject entries into `/proc`) has **not yet landed** as of
//! the date this file was written.
//!
//! The current `narf-filesystem` procfs implementation (`filesystem/src/procfs.rs`)
//! is a **monolithic ProcRoot** that matches entry names in a hardcoded
//! `match` arm.  There is no public registration hook for new subtrees.
//!
//! ## What is implemented here
//!
//! This file provides:
//!
//! 1. `render_cards_list()` — the text body for `/proc/asound/cards`.
//!    Format: `" N [id           ]: driver - longname\n"`.
//!    Linux ref: `sound/core/init.c::snd_card_info_read`.
//!
//! 2. `render_version()` — the text body for `/proc/asound/version`.
//!    Always returns `"Advanced Linux Sound Architecture Driver Version k1.0.27.\n"`.
//!    Linux ref: `sound/core/info.c::snd_info_version_read`.
//!
//! 3. `render_codec_dump(card, codec_index)` — text body for
//!    `/proc/asound/card<N>/codec#<C>`.  Returns chip name + AFG widget
//!    count.  Linux ref: `sound/hda/hda_codec.c::hda_codec_info_read`.
//!
//! 4. `render_pcm_info(card, device, is_capture)` — text body for
//!    `/proc/asound/card<N>/pcm<M><P|C>/info`.  Returns basic PCM caps.
//!    Linux ref: `sound/core/pcm_info.c::snd_pcm_stream_proc_info_read`.
//!
//! ## TODO — when Wave-19 procfs framework lands
//!
//! Wire the above generators into procfs by calling the new
//! `register_proc_dir`/`register_proc_file` API:
//!
//! ```rust,ignore
//! // In register_procfs_asound():
//! let asound = procfs::register_proc_dir("asound");
//! procfs::register_proc_file(&asound, "cards",   render_cards_list);
//! procfs::register_proc_file(&asound, "version", render_version);
//! for card in list_cards() {
//!     let card_dir = procfs::register_proc_dir(
//!         &asound, &format!("card{}", card.index));
//!     for codec in 0..1u32 {
//!         procfs::register_proc_file(
//!             &card_dir,
//!             &format!("codec#{}", codec),
//!             move || render_codec_dump(card.index, codec),
//!         );
//!     }
//!     // PCM info files per stream direction.
//!     for m in 0..card.playback_count {
//!         procfs::register_proc_file(
//!             &card_dir,
//!             &format!("pcm{}P/info", m),
//!             move || render_pcm_info(card.index, m, false),
//!         );
//!     }
//!     for m in 0..card.capture_count {
//!         procfs::register_proc_file(
//!             &card_dir,
//!             &format!("pcm{}C/info", m),
//!             move || render_pcm_info(card.index, m, true),
//!         );
//!     }
//! }
//! ```
//!
//! Until that API exists, `/proc/asound` is not reachable via the VFS
//! path resolver; these generators are only exercised via the unit
//! tests below.

use alloc::format;
use alloc::string::String;

use crate::list_cards;

// ── /proc/asound/cards ────────────────────────────────────────────────

/// Generate the text body for `/proc/asound/cards`.
///
/// One line per card:
/// ```text
///  0 [HDA Intel PCH ]: HDA-Intel - HDA Intel PCH
///  1 [HDA AMD       ]: hda-amd - HDA AMD
/// ```
///
/// Linux ref: `sound/core/init.c::snd_card_info_read` (line ~780 in 6.9).
pub fn render_cards_list() -> String {
    let mut out = String::new();
    for card in list_cards() {
        // Pad the id field to 15 characters, left-aligned (Linux format).
        let padded_id = format!("{:<15}", card.id);
        out.push_str(&format!(
            " {} [{}]: {} - {}\n",
            card.index, padded_id, card.driver, card.name
        ));
    }
    out
}

// ── /proc/asound/version ─────────────────────────────────────────────

/// Generate the text body for `/proc/asound/version`.
///
/// Linux ref: `sound/core/info.c::snd_info_version_read` — returns the
/// ALSA driver version string.  We report the canonical ALSA 1.0.27
/// string so tools that parse it by prefix don't reject the output.
pub fn render_version() -> String {
    "Advanced Linux Sound Architecture Driver Version k1.0.27.\n".into()
}

// ── /proc/asound/card<N>/codec#<C> ───────────────────────────────────

/// Generate the text body for `/proc/asound/card<N>/codec#<C>`.
///
/// Reports the codec chip name and AFG function-group count.
/// The real driver would walk the widget graph; we report what the
/// card registry knows (card name = codec chip string, one AFG).
///
/// Linux ref: `sound/hda/hda_codec.c::hda_codec_info_read`.
pub fn render_codec_dump(card_index: u32, codec_index: u32) -> String {
    let cards = list_cards();
    match cards.iter().find(|c| c.index == card_index) {
        None => format!("card {} not found\n", card_index),
        Some(card) => {
            let mut out = String::new();
            out.push_str(&format!("Codec: {}\n", card.name));
            out.push_str(&format!("Address: {}\n", codec_index));
            out.push_str(&format!("AFG Function Id: 0x1 (unsol {}: yes)\n", 1));
            // Number of sub-nodes in the root node (AFG is the root for HDA).
            // Report one output path + one input path as a proxy for the
            // real widget count — sufficient for tooling that just wants to
            // know the codec is alive.
            let widget_count = card.playback_count + card.capture_count;
            out.push_str(&format!("Default PCM:\n"));
            out.push_str(&format!(
                "  rates [0x0060]: 44100 48000\n"
            ));
            out.push_str(&format!(
                "  bits [0x0006]: 16 24\n"
            ));
            out.push_str(&format!(
                "  formats [0x00000001]: PCM\n"
            ));
            out.push_str(&format!("Node count: {}\n", widget_count));
            out
        }
    }
}

// ── /proc/asound/card<N>/pcm<M><P|C>/info ────────────────────────────

/// Generate the text body for `/proc/asound/card<N>/pcm<M><P|C>/info`.
///
/// Reports the PCM stream's capabilities: card name, device, sub-class,
/// supported rates and formats.
///
/// Linux ref: `sound/core/pcm_info.c::snd_pcm_stream_proc_info_read`.
pub fn render_pcm_info(card_index: u32, device: u32, is_capture: bool) -> String {
    let cards = list_cards();
    match cards.iter().find(|c| c.index == card_index) {
        None => format!("card {} not found\n", card_index),
        Some(card) => {
            let direction = if is_capture { "Capture" } else { "Playback" };
            let mut out = String::new();
            out.push_str(&format!("card: {}\n", card_index));
            out.push_str(&format!("device: {}\n", device));
            out.push_str(&format!("subdevice: 0\n"));
            out.push_str(&format!("stream: {}\n", direction));
            out.push_str(&format!("id: {}\n", card.id));
            out.push_str(&format!("name: {}\n", card.name));
            out.push_str(&format!("subname: \n"));
            out.push_str(&format!("class: 0\n"));
            out.push_str(&format!("subclass: 0\n"));
            out.push_str(&format!("subdevices_count: 1\n"));
            out.push_str(&format!("subdevices_avail: 1\n"));
            out
        }
    }
}

// ── Registration stub ─────────────────────────────────────────────────

/// Register `/proc/asound/*` entries.
///
/// TODO: wire this once the Wave-19 procfs framework agent lands and
/// exposes `register_proc_dir` / `register_proc_file`.  Until then
/// this is a no-op.
pub fn register_procfs_asound() {
    // TODO(Wave-19): call procfs::register_proc_dir("asound") and
    // register_proc_file for "cards", "version", "card<N>/codec#<C>",
    // "card<N>/pcm<M>P/info", "card<N>/pcm<M>C/info".
    //
    // Blocked on: Wave-19 procfs framework agent adding the registration
    // API to `narf-filesystem`'s procfs module.
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod procfs_bridge_tests {
    use super::*;
    use crate::register_card;

    fn setup() {
        crate::__reset_for_test();
        crate::mixer::__reset_for_test();
    }

    // Smoke: /proc/asound/cards format matches ALSA expected shape.
    #[test]
    fn cards_format_single_card() {
        setup();
        register_card("HDA-Intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
        let out = render_cards_list();
        // Expected: " 0 [HDA Intel PCH  ]: HDA-Intel - HDA Intel PCH"
        assert!(
            out.contains(" 0 ["),
            "cards missing ' 0 [': {:?}",
            out
        );
        assert!(
            out.contains("HDA-Intel"),
            "cards missing driver name: {:?}",
            out
        );
        assert!(
            out.contains("HDA Intel PCH"),
            "cards missing card name: {:?}",
            out
        );
    }

    // Smoke: /proc/asound/version returns ALSA-style header.
    #[test]
    fn version_returns_alsa_header() {
        let v = render_version();
        assert!(
            v.starts_with("Advanced Linux Sound Architecture"),
            "version string wrong: {:?}",
            v
        );
        assert!(
            v.contains("1.0.27"),
            "version missing 1.0.27: {:?}",
            v
        );
    }

    // Smoke: codec dump contains chip name.
    #[test]
    fn codec_dump_contains_chip_name() {
        setup();
        register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
        let out = render_codec_dump(0, 0);
        assert!(out.contains("Codec:"), "codec dump missing 'Codec:': {:?}", out);
        assert!(out.contains("HDA Intel PCH"), "codec dump missing chip name: {:?}", out);
    }

    // Smoke: pcm info for playback.
    #[test]
    fn pcm_info_playback() {
        setup();
        register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
        let out = render_pcm_info(0, 0, false);
        assert!(out.contains("Playback"), "pcm info missing 'Playback': {:?}", out);
        assert!(out.contains("card: 0"), "pcm info missing 'card: 0': {:?}", out);
    }

    // Smoke: multi-card cards list contains both entries.
    #[test]
    fn cards_format_two_cards() {
        setup();
        register_card("HDA-Intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
        register_card("hda-amd",   "HDA AMD",       "HDA AMD",       1, 1, 1);
        let out = render_cards_list();
        assert!(out.contains(" 0 ["), "missing card 0: {:?}", out);
        assert!(out.contains(" 1 ["), "missing card 1: {:?}", out);
        assert!(out.contains("HDA-Intel"), "missing Intel driver: {:?}", out);
        assert!(out.contains("hda-amd"), "missing AMD driver: {:?}", out);
    }
}
