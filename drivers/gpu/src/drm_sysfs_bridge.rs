//! DRM sysfs bridge — `/sys/devices/platform/narf-drm/{card<N>,renderD<N+128>}`
//! with `/sys/class/drm/*` and `/sys/dev/char/*` symlinks pointing into it.
//!
//! For each card registered in `drm_registry` this module creates the standard
//! kobject subtree that userspace (libdrm, Mesa, Xorg, Wayland, systemd's
//! libudev) expects for a DRM device.
//!
//! ## Why the device is rooted under `/sys/devices/...`
//!
//! On Linux a DRM minor lives at `/sys/devices/.../drm/card<N>` and
//! `/sys/class/drm/card<N>` is a *symlink* into that tree. systemd's
//! `sd-device` (Fedora's libudev) only assigns a `devnum` — and therefore a
//! resolvable `/dev/dri/card<N>` — to a device whose canonical syspath is a
//! real `/sys/devices/...` node reached through the class symlink. A card
//! parked directly under `/sys/class/drm/` as a real directory reads back its
//! `uevent` fine via `cat`, but `udevadm info --name=/dev/dri/card0` returns
//! "No such device": `devnum` stays 0, `udev_device_get_devnode()` is NULL, and
//! kwin's DRM backend ends up with an empty device node and never modesets.
//! Mirroring Linux's topology (real node under `/sys/devices`, class entry as a
//! symlink) is what makes systemd resolve the GPU. This matches the input-class
//! layout in `sysfs::populate_input_class`.
//!
//! ## Kobject layout per card (index N)
//!
//! ```text
//! /sys/devices/platform/narf-drm/
//!   card<N>/
//!     name        → "card<N>\n"
//!     dev         → "226:<N>\n"                        (major 226 = DRM)
//!     uevent      → MAJOR/MINOR/DEVNAME/DEVTYPE/DRIVER (writable)
//!     subsystem   → symlink → /sys/class/drm
//!     device/     → vendor / device / subsystem_vendor / subsystem_device
//!     power_dpm_state, power_dpm_force_performance_level, [vbios_version], …
//!   renderD<N+128>/
//!     name, dev, uevent (writable), subsystem → /sys/class/drm
//! /sys/class/drm/card<N>       → ../../devices/platform/narf-drm/card<N>
//! /sys/class/drm/renderD<N+128>→ ../../devices/platform/narf-drm/renderD<N+128>
//! /sys/dev/char/226:<N>        → ../../devices/platform/narf-drm/card<N>
//! /sys/dev/char/226:<N+128>    → ../../devices/platform/narf-drm/renderD<N+128>
//! ```
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_sysfs.c::dev_show` — per-attr show functions.
//! - `drivers/gpu/drm/drm_drv.c::drm_dev_register` — registration sequence.
//! - `Documentation/ABI/testing/sysfs-class-drm`.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use narf_filesystem::sysfs::{
    class_register, get_or_create_child, get_root, kobject_add_attr, kobject_add_uevent_attr,
    Kobject,
};

/// DRM major device number.
///
/// Linux: `DRM_MAJOR = 226` (include/uapi/linux/major.h).
const DRM_MAJOR: u32 = 226;

/// Populate the DRM sysfs subtree for every card in the DRM registry.
///
/// Called once from a `Stage::Late` initcall after all `Stage::Subsys`
/// driver probes have completed.
///
/// Linux ref: `drm_sysfs_connector_add` / `drm_dev_register`
/// (drivers/gpu/drm/drm_sysfs.c, drm_drv.c).
pub fn populate_drm_class() {
    let class_drm = class_register("drm");

    for card in crate::drm_registry::cards() {
        let idx = {
            // Determine the index by looking it up in the registry.
            // The registry stores cards in insertion order so the
            // position == index invariant holds.
            let cards = crate::drm_registry::cards();
            cards
                .iter()
                .position(|c| Arc::ptr_eq(c, &card))
                .unwrap_or(0) as u32
        };
        populate_card_node(class_drm.clone(), card, idx);
    }
}

/// The `/sys/.../card<N>/uevent` body. MAJOR + DEVNAME are load-bearing for
/// libudev (it derives the device node `/dev/${DEVNAME}` and devnum from
/// MAJOR:MINOR); weston's `find_primary_gpu` skips any card with no devnode.
/// Linux ref: drm_sysfs.c + device_add's dev_uevent.
pub(crate) fn card_uevent(idx: u32, driver: &str) -> String {
    format!(
        "MAJOR={}\nMINOR={}\nDEVNAME=dri/card{}\nDEVTYPE=drm_minor\nDRIVER={}\n",
        DRM_MAJOR, idx, idx, driver
    )
}

/// The `/sys/.../renderD<M>/uevent` body (M = N+128). A render minor is
/// `drm_render_minor`; Mesa's render-worker lookup wants its devnode resolvable
/// too, so it needs MAJOR/MINOR/DEVNAME just like the card node.
fn render_uevent(render_idx: u32, driver: &str) -> String {
    format!(
        "MAJOR={}\nMINOR={}\nDEVNAME=dri/renderD{}\nDEVTYPE=drm_render_minor\nDRIVER={}\n",
        DRM_MAJOR, render_idx, render_idx, driver
    )
}

/// `/sys/dev/char/<major>:<minor>` → `target` (a path relative to
/// `/sys/dev/char`). udev resolves a device by devnum through here; unlike
/// `sysfs::register_char_dev_link` (which points at the flat class dir) this
/// points into `/sys/devices/...` so systemd's `sd_device_new_from_device_id`
/// lands on the canonical node. Also keeps `/sys/dev/block` present since udev
/// scandir()s both and fails the whole enumerate if either is missing.
fn char_dev_link(minor: u32, target: &str) {
    let root = get_root();
    let dev_dir = get_or_create_child(&root, "dev");
    let dev_char = get_or_create_child(&dev_dir, "char");
    let _dev_block = get_or_create_child(&dev_dir, "block");
    dev_char.add_symlink(format!("{}:{}", DRM_MAJOR, minor), String::from(target));
}

/// Build the kobject subtree for one DRM card.
fn populate_card_node(
    class_drm: Arc<Kobject>,
    card: Arc<dyn crate::drm_registry::DrmCard>,
    idx: u32,
) {
    let root = get_root();
    // `/sys/devices/platform/narf-drm/` — the real device parent. Mirrors the
    // input class's `/sys/devices/platform/narf-input/` container.
    let devices = get_or_create_child(&root, "devices");
    let platform = get_or_create_child(&devices, "platform");
    let narf_drm = get_or_create_child(&platform, "narf-drm");

    let driver = String::from(card.driver());

    // ── card<N> device node under /sys/devices ──────────────────────────
    let card_name = format!("card{}", idx);
    let kobj = Kobject::new_child(narf_drm.clone(), card_name.clone());

    {
        let name = format!("card{}\n", idx);
        kobject_add_attr(&kobj, "name", move || name.clone());
    }
    {
        let dev_str = format!("{}:{}\n", DRM_MAJOR, idx);
        kobject_add_attr(&kobj, "dev", move || dev_str.clone());
    }
    // Writable uevent so a real udevd's `udevadm trigger` re-broadcasts the ADD.
    kobject_add_uevent_attr(&kobj, card_uevent(idx, &driver));

    // `subsystem` → /sys/class/drm. From /sys/devices/platform/narf-drm/card<N>
    // the class dir is four levels up. elogind only marks a seat graphical when
    // it can attach a device whose subsystem is "drm".
    kobj.add_symlink("subsystem", "../../../../class/drm");

    // ── device/ sub-kobject (PCI IDs Mesa reads for driver selection) ────
    let dev_kobj = Kobject::new_child(kobj.clone(), "device");
    {
        let v = card.vendor_id();
        kobject_add_attr(&dev_kobj, "vendor", move || format!("0x{:04x}\n", v));
    }
    {
        let d = card.device_id();
        kobject_add_attr(&dev_kobj, "device", move || format!("0x{:04x}\n", d));
    }
    {
        let sv = card.subsystem_vendor();
        kobject_add_attr(&dev_kobj, "subsystem_vendor", move || {
            format!("0x{:04x}\n", sv)
        });
    }
    {
        let sd = card.subsystem_device();
        kobject_add_attr(&dev_kobj, "subsystem_device", move || {
            format!("0x{:04x}\n", sd)
        });
    }

    // ── Optional AMDGPU-specific attrs ───────────────────────────────────
    if let Some(ver) = card.vbios_version() {
        let ver_owned = String::from(ver);
        kobject_add_attr(&kobj, "vbios_version", move || format!("{}\n", ver_owned));
    }
    if let Some(pct) = card.gpu_busy_percent() {
        kobject_add_attr(&kobj, "gpu_busy_percent", move || format!("{}\n", pct));
    }
    {
        let ps = String::from(card.power_state());
        kobject_add_attr(&kobj, "power_dpm_state", move || format!("{}\n", ps));
    }
    kobject_add_attr(&kobj, "power_dpm_force_performance_level", || {
        "auto\n".into()
    });

    // ── /sys/class/drm/card<N> + /sys/dev/char/226:<N> symlinks → the node ──
    class_drm.add_symlink(
        card_name.clone(),
        format!("../../devices/platform/narf-drm/{}", card_name),
    );
    char_dev_link(
        idx,
        &format!("../../devices/platform/narf-drm/{}", card_name),
    );

    // ── renderD<N+128> sibling device node ───────────────────────────────
    let render_idx = idx + 128;
    let render_name = format!("renderD{}", render_idx);
    let render_kobj = Kobject::new_child(narf_drm.clone(), render_name.clone());
    {
        let rn = format!("renderD{}\n", render_idx);
        kobject_add_attr(&render_kobj, "name", move || rn.clone());
    }
    {
        let rd = format!("{}:{}\n", DRM_MAJOR, render_idx);
        kobject_add_attr(&render_kobj, "dev", move || rd.clone());
    }
    kobject_add_uevent_attr(&render_kobj, render_uevent(render_idx, &driver));
    render_kobj.add_symlink("subsystem", "../../../../class/drm");

    class_drm.add_symlink(
        render_name.clone(),
        format!("../../devices/platform/narf-drm/{}", render_name),
    );
    char_dev_link(
        render_idx,
        &format!("../../devices/platform/narf-drm/{}", render_name),
    );
}
