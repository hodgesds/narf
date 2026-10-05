//! Sound devices have canonical nodes below `/sys/devices`; class and
//! device-number entries are discovery links to those same nodes.

use crate::CardInfo;
use alloc::{format, string::String, sync::Arc, vec::Vec};
use narf_filesystem::sysfs::{
    class_register, get_or_create_child, get_root, kobject_add_attr, kobject_add_uevent_attr,
    kobject_emit_uevent, Kobject,
};
use narf_filesystem::uevent::UeventAction;

pub const SNDRV_MAJOR: u32 = 116;

/// Linux static ALSA layout: 32 minors/card, eight PCMs per direction.
pub fn control_minor(card: u32) -> u32 {
    card * 32
}
pub fn pcm_playback_minor(card: u32, device: u32) -> u32 {
    card * 32 + 16 + device
}
pub fn pcm_capture_minor(card: u32, device: u32) -> u32 {
    card * 32 + 24 + device
}

fn virtual_sound() -> Arc<Kobject> {
    let devices = get_or_create_child(&get_root(), "devices");
    let virtual_dir = get_or_create_child(&devices, "virtual");
    get_or_create_child(&virtual_dir, "sound")
}

fn lookup(path: &str) -> Option<Arc<Kobject>> {
    let mut node = get_root();
    for part in path.trim_start_matches("/sys/").split('/') {
        node = node.get_child(part)?;
    }
    Some(node)
}

fn relative_target(from: &Kobject, to: &Kobject) -> String {
    let from_path = from.path();
    let levels = from_path.trim_start_matches("/sys/").split('/').count();
    format!(
        "{}{}",
        "../".repeat(levels),
        to.path().trim_start_matches("/sys/")
    )
}

fn link(class: &Arc<Kobject>, node: &Arc<Kobject>, minor: Option<u32>) {
    class.remove_child(node.name());
    class.add_symlink(node.name(), relative_target(class, node));
    node.add_symlink("subsystem", relative_target(node, class));
    if let Some(minor) = minor {
        let dev = get_or_create_child(&get_root(), "dev");
        let chars = get_or_create_child(&dev, "char");
        get_or_create_child(&dev, "block");
        chars.add_symlink(
            format!("{SNDRV_MAJOR}:{minor}"),
            relative_target(&chars, node),
        );
        kobject_add_attr(node, "dev", move || format!("{SNDRV_MAJOR}:{minor}\n"));
        kobject_add_uevent_attr(
            node,
            format!(
                "MAJOR={SNDRV_MAJOR}\nMINOR={minor}\nDEVNAME=snd/{}\n",
                node.name()
            ),
        );
    }
}

fn endpoints(info: &CardInfo) -> Vec<(String, u32)> {
    let mut nodes = alloc::vec![(format!("controlC{}", info.index), control_minor(info.index))];
    for device in 0..info.playback_count {
        nodes.push((
            format!("pcmC{}D{device}p", info.index),
            pcm_playback_minor(info.index, device),
        ));
    }
    for device in 0..info.capture_count {
        nodes.push((
            format!("pcmC{}D{device}c", info.index),
            pcm_capture_minor(info.index, device),
        ));
    }
    nodes
}

/// Republish a registry card, preserving its physical parent when available.
pub fn register_card_sysfs(info: &CardInfo) {
    let parent = crate::CARD_REGISTRY
        .lock()
        .iter()
        .find(|card| card.info.index == info.index)
        .and_then(|card| card.parent);
    register_card_sysfs_at(info, parent);
}

pub(crate) fn register_card_sysfs_at(info: &CardInfo, parent: Option<narf_bus::BusAddr>) {
    let physical = match parent {
        Some(narf_bus::BusAddr::Pcie(addr)) => {
            narf_filesystem::sysfs::populate_pci_devices();
            lookup(&format!(
                "devices/pci{:04x}:{:02x}/{addr:?}",
                addr.segment, addr.bus
            ))
        }
        _ => None,
    };
    let container = physical
        .as_ref()
        .map(|parent| get_or_create_child(parent, "sound"))
        .unwrap_or_else(virtual_sound);
    let class = class_register("sound");
    let name = format!("card{}", info.index);
    let added = container.get_child(&name).is_none();
    let card = get_or_create_child(&container, &name);
    let id = info.id;
    let index = info.index;
    let longname = info.name;
    kobject_add_attr(&card, "id", move || format!("{id}\n"));
    kobject_add_attr(&card, "number", move || format!("{index}\n"));
    kobject_add_attr(&card, "longname", move || format!("{longname}\n"));
    kobject_add_uevent_attr(&card, String::new());
    link(&class, &card, None);
    if let Some(parent) = physical {
        card.add_symlink("device", relative_target(&card, &parent));
    }
    let mut added_nodes = Vec::new();
    for (name, minor) in endpoints(info) {
        let new = card.get_child(&name).is_none();
        let node = get_or_create_child(&card, &name);
        link(&class, &node, Some(minor));
        node.add_symlink("device", "..");
        if name.starts_with("pcm") {
            kobject_add_attr(&node, "pcm_class", || "generic\n".into());
        }
        if new {
            added_nodes.push(node);
        }
    }
    // Publish events only after the complete card graph is reachable.
    if added {
        kobject_emit_uevent(&card, UeventAction::Add);
    }
    for node in added_nodes {
        kobject_emit_uevent(&node, UeventAction::Add);
    }
    // 78-sound-card.rules marks the card SOUND_INITIALIZED on CHANGE, after
    // its PCM/control children have appeared. ADD alone leaves it unusable to
    // udev sound consumers even when every individual path resolves.
    if added {
        kobject_emit_uevent(&card, UeventAction::Change);
    }
}

pub(crate) fn unregister_card_sysfs(info: &CardInfo) {
    let class = class_register("sound");
    let name = format!("card{}", info.index);
    let target = class.get_symlink(&name);
    let card = target
        .as_deref()
        .and_then(|path| lookup(path.trim_start_matches("../../")));
    for (name, minor) in endpoints(info) {
        if let Some(node) = card.as_ref().and_then(|card| card.get_child(&name)) {
            kobject_emit_uevent(&node, UeventAction::Remove);
        }
        if let Some(card) = &card {
            card.remove_child(&name);
        }
        class.remove_symlink(&name);
        class.remove_child(&name);
        if let Some(chars) = lookup("dev/char") {
            chars.remove_symlink(&format!("{SNDRV_MAJOR}:{minor}"));
        }
    }
    if let Some(card) = card {
        kobject_emit_uevent(&card, UeventAction::Remove);
    }
    class.remove_symlink(&name);
    class.remove_child(&name);
    if let Some(target) = target {
        if let Some((parent, leaf)) = target.trim_start_matches("../../").rsplit_once('/') {
            if let Some(parent) = lookup(parent) {
                parent.remove_child(leaf);
            }
        }
    }
}

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
        crate::register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
        register_all_cards_sysfs();
    }

    // Smoke: /sys/class/sound/card0/id returns the codec name.
    #[test]
    fn card0_id_attr() {
        setup();
        let card0 = lookup("devices/virtual/sound/card0").expect("card0 kobject missing");
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
        let pcm_kobj =
            lookup("devices/virtual/sound/card0/pcmC0D0p").expect("pcmC0D0p kobject missing");
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
        let pcm_kobj =
            lookup("devices/virtual/sound/card0/pcmC0D0p").expect("pcmC0D0p kobject missing");
        let cls_val = pcm_kobj
            .attr_show("pcm_class")
            .expect("pcm_class attr missing");
        assert!(
            cls_val.contains("generic"),
            "pcm_class should be 'generic': {:?}",
            cls_val
        );
    }

    // Smoke: minor number arithmetic matches ALSA spec.
    #[test]
    fn minor_number_arithmetic() {
        assert_eq!(control_minor(0), 0);
        assert_eq!(control_minor(1), 32);
        assert_eq!(pcm_playback_minor(0, 0), 16);
        assert_eq!(pcm_capture_minor(0, 0), 24);
        assert_eq!(pcm_playback_minor(1, 0), 48);
        assert_eq!(pcm_capture_minor(1, 0), 56);
    }

    // Smoke: multi-card — 2 cards → card0 + card1 entries.
    #[test]
    fn multi_card_sysfs_nodes() {
        crate::__reset_for_test();
        crate::mixer::__reset_for_test();
        sysfs::__reset_for_test();
        crate::register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
        crate::register_card("hda-amd", "HDA AMD", "HDA AMD", 1, 1, 1);
        register_all_cards_sysfs();
        let root = sysfs::class_register("sound");
        assert!(root.get_symlink("card0").is_some(), "card0 missing");
        assert!(root.get_symlink("card1").is_some(), "card1 missing");
        assert!(root.get_symlink("controlC0").is_some(), "controlC0 missing");
        assert!(root.get_symlink("controlC1").is_some(), "controlC1 missing");
    }
}
