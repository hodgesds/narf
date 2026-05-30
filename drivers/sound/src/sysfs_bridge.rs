//! `/sys/class/sound/*` kobject attributes — card + device nodes.
//!
//! Populates the following sysfs subtree for each registered sound card:
//!
//! ```text
//! /sys/class/sound/
//!   card<N>/
//!     id          — codec short name (e.g. "HDA Intel PCH")
//!     number      — decimal card index
//!     longname    — long human-readable name
//!   controlC<N>/
//!     dev         — "116:<minor>" (ALSA sound-class major 116)
//!   pcmC<N>D<M>p/
//!     dev         — "116:<minor>"
//!     pcm_class   — "generic"
//!   pcmC<N>D<M>c/
//!     dev         — "116:<minor>"
//!     pcm_class   — "generic"
//! ```
//!
//! Linux references:
//! - `sound/core/init.c::snd_card_register` — registers kobjects
//! - `sound/core/sound.c::snd_register_device` — fills dev attribute
//! - `include/sound/core.h::SNDRV_MAJOR` = 116 (sound class major)
//! - `Documentation/ABI/testing/sysfs-class-sound`

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use narf_filesystem::sysfs::{class_register, class_device_register, kobject_add_attr, Kobject};

use crate::CardInfo;

// ── ALSA major number ─────────────────────────────────────────────────

/// ALSA sound class major number.
///
/// Linux assigns major 116 to the ALSA sound device class.
/// `include/sound/core.h:#define SNDRV_MAJOR 116`.
pub const SNDRV_MAJOR: u32 = 116;

/// Compute the ALSA minor number for a given card + device + type.
///
/// Linux's minor-number scheme for the sound class:
/// ```text
///   minor = (card << 5) | type_offset
/// ```
/// Type offsets (from `include/sound/minors.h`):
///   - control: 0
///   - pcm playback:  card * 32 + 16 + device * 2
///   - pcm capture:   card * 32 + 16 + device * 2 + 1
///
/// Linux ref: `sound/core/sound.c::snd_alloc_minor_range`.
pub fn control_minor(card: u32) -> u32 {
    card * 32
}

pub fn pcm_playback_minor(card: u32, device: u32) -> u32 {
    card * 32 + 16 + device * 2
}

pub fn pcm_capture_minor(card: u32, device: u32) -> u32 {
    card * 32 + 16 + device * 2 + 1
}

// ── Populate one card ─────────────────────────────────────────────────

/// Register all sysfs nodes for a single sound card.
///
/// Called once per card from the sound-driver initcall (or lazily on
/// first access — the kobject graph is idempotent).
///
/// Linux ref: `sound/core/init.c::snd_card_register` +
///            `sound/core/sound.c::snd_register_device`.
pub fn register_card_sysfs(info: &CardInfo) {
    let sound_class = class_register("sound");
    let n = info.index;

    // /sys/class/sound/card<N>/
    let card_kobj = class_device_register(sound_class.clone(), &format!("card{}", n));
    {
        let id_str = info.id;
        let longname = info.name;
        kobject_add_attr(&card_kobj, "id", move || format!("{}\n", id_str));
        let num = n;
        kobject_add_attr(&card_kobj, "number", move || format!("{}\n", num));
        kobject_add_attr(&card_kobj, "longname", move || format!("{}\n", longname));
    }

    // /sys/class/sound/controlC<N>/
    let ctrl_kobj = class_device_register(sound_class.clone(), &format!("controlC{}", n));
    {
        let minor = control_minor(n);
        kobject_add_attr(&ctrl_kobj, "dev", move || {
            format!("{}:{}\n", SNDRV_MAJOR, minor)
        });
    }

    // /sys/class/sound/pcmC<N>D<M>p/ and pcmC<N>D<M>c/ per device.
    for m in 0..info.playback_count {
        let pb_kobj = class_device_register(
            sound_class.clone(),
            &format!("pcmC{}D{}p", n, m),
        );
        let minor = pcm_playback_minor(n, m);
        kobject_add_attr(&pb_kobj, "dev", move || {
            format!("{}:{}\n", SNDRV_MAJOR, minor)
        });
        kobject_add_attr(&pb_kobj, "pcm_class", || "generic\n".into());
    }

    for m in 0..info.capture_count {
        let cap_kobj = class_device_register(
            sound_class.clone(),
            &format!("pcmC{}D{}c", n, m),
        );
        let minor = pcm_capture_minor(n, m);
        kobject_add_attr(&cap_kobj, "dev", move || {
            format!("{}:{}\n", SNDRV_MAJOR, minor)
        });
        kobject_add_attr(&cap_kobj, "pcm_class", || "generic\n".into());
    }
}

/// Register sysfs nodes for every currently-registered card.
///
/// Called from the sound-driver initcall.  New cards registered after
/// boot must call `register_card_sysfs` directly.
pub fn register_all_cards_sysfs() {
    for card in crate::list_cards() {
        register_card_sysfs(&card);
    }
}

// ── Attribute renderers — used by tests ──────────────────────────────

/// Render the text content of `/sys/class/sound/card<N>/id`.
///
/// Returns `"<id>\n"` — the card's short id string.
/// Exposed so tests can assert on the rendered value without going
/// through the full sysfs kobject tree.
pub fn render_card_id_attr(info: &CardInfo) -> String {
    format!("{}\n", info.id)
}

/// Render the text content of `/sys/class/sound/pcmC<N>D<M>p/dev` (or
/// `pcmC<N>D<M>c/dev` when `is_capture` is true).
///
/// Returns `"116:<minor>\n"`.
pub fn render_pcm_dev_attr(card: u32, device: u32, is_capture: bool) -> String {
    let minor = if is_capture {
        pcm_capture_minor(card, device)
    } else {
        pcm_playback_minor(card, device)
    };
    format!("{}:{}\n", SNDRV_MAJOR, minor)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod sysfs_bridge_tests {
    use super::*;
    use narf_filesystem::sysfs;

    fn setup() {
        crate::__reset_for_test();
        crate::mixer::__reset_for_test();
        sysfs::__reset_for_test();
        crate::register_card(
            "hda-intel",
            "HDA Intel PCH",
            "HDA Intel PCH",
            0,
            1,
            1,
        );
        register_all_cards_sysfs();
    }

    // Smoke: /sys/class/sound/card0/id returns the codec name.
    #[test]
    fn card0_id_attr() {
        setup();
        let root = sysfs::class_register("sound");
        let card0 = root.get_child("card0").expect("card0 kobject missing");
        let id_val = card0.attr_show("id").expect("id attr missing");
        assert!(
            id_val.contains("HDA Intel PCH"),
            "id attr value wrong: {:?}",
            id_val
        );
    }

    // Smoke: /sys/class/sound/pcmC0D0p/dev returns "116:N" format.
    #[test]
    fn pcm_playback_dev_attr_format() {
        setup();
        let root = sysfs::class_register("sound");
        let pcm_kobj = root.get_child("pcmC0D0p").expect("pcmC0D0p kobject missing");
        let dev_val = pcm_kobj.attr_show("dev").expect("dev attr missing");
        assert!(
            dev_val.starts_with("116:"),
            "dev attr should start with '116:': {:?}",
            dev_val
        );
    }

    // Smoke: /sys/class/sound/pcmC0D0p/pcm_class = "generic".
    #[test]
    fn pcm_class_attr_is_generic() {
        setup();
        let root = sysfs::class_register("sound");
        let pcm_kobj = root.get_child("pcmC0D0p").expect("pcmC0D0p kobject missing");
        let cls_val = pcm_kobj.attr_show("pcm_class").expect("pcm_class attr missing");
        assert!(cls_val.contains("generic"), "pcm_class should be 'generic': {:?}", cls_val);
    }

    // Smoke: minor number arithmetic matches ALSA spec.
    #[test]
    fn minor_number_arithmetic() {
        assert_eq!(control_minor(0), 0);
        assert_eq!(control_minor(1), 32);
        assert_eq!(pcm_playback_minor(0, 0), 16);
        assert_eq!(pcm_capture_minor(0, 0), 17);
        assert_eq!(pcm_playback_minor(1, 0), 48);
        assert_eq!(pcm_capture_minor(1, 0), 49);
    }

    // Smoke: multi-card — 2 cards → card0 + card1 entries.
    #[test]
    fn multi_card_sysfs_nodes() {
        crate::__reset_for_test();
        crate::mixer::__reset_for_test();
        sysfs::__reset_for_test();
        crate::register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
        crate::register_card("hda-amd",   "HDA AMD",       "HDA AMD",       1, 1, 1);
        register_all_cards_sysfs();
        let root = sysfs::class_register("sound");
        assert!(root.get_child("card0").is_some(), "card0 missing");
        assert!(root.get_child("card1").is_some(), "card1 missing");
        assert!(root.get_child("controlC0").is_some(), "controlC0 missing");
        assert!(root.get_child("controlC1").is_some(), "controlC1 missing");
    }
}
