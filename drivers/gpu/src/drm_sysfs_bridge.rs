//! DRM sysfs bridge — `/sys/class/drm/card<N>/` + `/sys/class/drm/renderD<N+128>/`.
//!
//! For each card registered in `drm_registry` this module creates the
//! standard kobject subtree that userspace (libdrm, Mesa, Xorg, Wayland)
//! expects under `/sys/class/drm/`.
//!
//! ## Kobject layout per card (index N)
//!
//! ```text
//! /sys/class/drm/
//!   card<N>/
//!     name                   → "card<N>\n"
//!     dev                    → "226:<N>\n"          (major 226 = DRM)
//!     uevent                 → MAJOR/MINOR/DEVNAME + DEVTYPE + DRIVER
//!     device/
//!       vendor               → "0x1002\n" / "0x1234\n"
//!       device               → "0x1636\n" / "0x1111\n"
//!       subsystem_vendor     → "0x0000\n"
//!       subsystem_device     → "0x0000\n"
//!     vbios_version          → "<string>\n"   (if available)
//!     gpu_busy_percent       → "0\n"          (if available)
//!     power_dpm_state        → "D0\n"
//!   renderD<N+128>/
//!     name                   → "renderD<N+128>\n"
//!     dev                    → "226:<N+128>\n"
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

use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};

/// DRM major device number.
///
/// Linux: `DRM_MAJOR = 226` (include/uapi/linux/major.h).
const DRM_MAJOR: u32 = 226;

/// Populate `/sys/class/drm/` for every card in the DRM registry.
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

/// The `/sys/class/drm/card<N>/uevent` body. MAJOR + DEVNAME are
/// load-bearing for libudev (it derives the device node `/dev/${DEVNAME}`
/// and devnum from MAJOR:MINOR); weston's `find_primary_gpu` skips any
/// card with no devnode. Linux ref: drm_sysfs.c + device_add's dev_uevent.
pub(crate) fn card_uevent(idx: u32, driver: &str) -> String {
    format!(
        "MAJOR={}\nMINOR={}\nDEVNAME=dri/card{}\nDEVTYPE=drm_minor\nDRIVER={}\n",
        DRM_MAJOR, idx, idx, driver
    )
}

/// Build the kobject subtree for one DRM card.
fn populate_card_node(
    class_drm: Arc<narf_filesystem::sysfs::Kobject>,
    card: Arc<dyn crate::drm_registry::DrmCard>,
    idx: u32,
) {
    // ── card<N> kobject ─────────────────────────────────────────────

    let card_name = format!("card{}", idx);
    let kobj = class_device_register(class_drm.clone(), &card_name);

    // `name` attr — e.g. "card0\n".
    // Linux ref: drm_sysfs.c::dev_show → dev_name(dev).
    {
        let name = format!("card{}\n", idx);
        kobject_add_attr(&kobj, "name", move || name.clone());
    }

    // `dev` attr — "major:minor\n".
    // Linux ref: drm_sysfs.c::dev_show → MAJOR(dev->devt):MINOR(dev->devt).
    {
        let dev_str = format!("{}:{}\n", DRM_MAJOR, idx);
        kobject_add_attr(&kobj, "dev", move || dev_str.clone());
    }

    // `uevent` — MAJOR/MINOR/DEVNAME plus DEVTYPE + DRIVER. The
    // MAJOR + DEVNAME pair is load-bearing: libudev computes a device's
    // node path as `/dev/${DEVNAME}` and its devnum from MAJOR:MINOR, so
    // without them `udev_device_get_devnode()` returns NULL. weston's
    // `find_primary_gpu` skips any DRM device with no devnode, failing
    // with "no drm device found" even though /dev/dri/card<N> exists.
    // Linux ref: drm_sysfs.c::drm_class_dev_uevent (adds DEVNAME via
    // device_add → dev_uevent → add_uevent_var "DEVNAME").
    {
        let driver = String::from(card.driver());
        let idx_copy = idx;
        kobject_add_attr(&kobj, "uevent", move || card_uevent(idx_copy, &driver));
    }

    // `subsystem` symlink → the drm class dir. eudev/libudev derive a
    // device's subsystem from the basename of this link's target; elogind
    // only marks a seat graphical (`seat_can_graphical`) when it can attach a
    // device whose subsystem is "drm". Without it the card enumerates with no
    // subsystem and never makes seat0 graphical. Linux ref: device_add →
    // sysfs_create_link("subsystem").
    kobj.add_symlink("subsystem", "../../../class/drm");

    // `/sys/dev/char/226:<N>` → this card. eudev resolves a device by devnum
    // through here; elogind's `master-of-seat` tag enumeration then does
    // sd_device_new_from_device_id("c226:<N>") which needs this link. Without
    // it the DRM card is invisible to udev-based seat attachment, so
    // seat0.CanGraphical stays false and the compositor's TakeDevice fails.
    narf_filesystem::sysfs::register_char_dev_link(DRM_MAJOR, idx, "drm", &card_name);

    // ── device/ sub-kobject ──────────────────────────────────────────
    //
    // Linux exposes PCI IDs under card<N>/device/ as symlink to the
    // PCI sysfs node. We synthesise flat attrs directly.

    let dev_kobj = narf_filesystem::sysfs::Kobject::new_child(kobj.clone(), "device");

    // `device/vendor` — "0x1002\n" for AMD, "0x1234\n" for bochs, etc.
    // Linux ref: /sys/bus/pci/devices/<slot>/vendor.
    {
        let v = card.vendor_id();
        kobject_add_attr(&dev_kobj, "vendor", move || format!("0x{:04x}\n", v));
    }

    // `device/device`.
    {
        let d = card.device_id();
        kobject_add_attr(&dev_kobj, "device", move || format!("0x{:04x}\n", d));
    }

    // `device/subsystem_vendor`.
    {
        let sv = card.subsystem_vendor();
        kobject_add_attr(&dev_kobj, "subsystem_vendor", move || {
            format!("0x{:04x}\n", sv)
        });
    }

    // `device/subsystem_device`.
    {
        let sd = card.subsystem_device();
        kobject_add_attr(&dev_kobj, "subsystem_device", move || {
            format!("0x{:04x}\n", sd)
        });
    }

    // ── Optional AMDGPU-specific attrs ───────────────────────────────

    // `vbios_version` — only emit when the driver provides it.
    // Linux ref: amdgpu_sysfs.c::amdgpu_sysfs_vbios_version.
    if let Some(ver) = card.vbios_version() {
        let ver_owned = String::from(ver);
        kobject_add_attr(&kobj, "vbios_version", move || format!("{}\n", ver_owned));
    }

    // `gpu_busy_percent` — 0..100.
    // Linux ref: amdgpu_pm.c::amdgpu_sysfs_get_gpu_busy_percent.
    if let Some(pct) = card.gpu_busy_percent() {
        kobject_add_attr(&kobj, "gpu_busy_percent", move || format!("{}\n", pct));
    }

    // `power_dpm_state` — stub "D0".
    // Linux ref: amdgpu_pm.c::amdgpu_get_pm_profile.
    {
        let ps = String::from(card.power_state());
        kobject_add_attr(&kobj, "power_dpm_state", move || format!("{}\n", ps));
    }

    // `power_dpm_force_performance_level` — stub "auto".
    // Linux ref: amdgpu_pm.c::amdgpu_get_dpm_forced_performance_level.
    kobject_add_attr(&kobj, "power_dpm_force_performance_level", || {
        "auto\n".into()
    });

    // ── renderD<N+128> sibling kobject ───────────────────────────────
    //
    // Linux ref: drm_drv.c::drm_dev_register → DRM_MINOR_RENDER = N+128.

    let render_idx = idx + 128;
    let render_name = format!("renderD{}", render_idx);
    let render_kobj = class_device_register(class_drm, &render_name);

    {
        let rn = format!("renderD{}\n", render_idx);
        kobject_add_attr(&render_kobj, "name", move || rn.clone());
    }
    {
        let rd = format!("{}:{}\n", DRM_MAJOR, render_idx);
        kobject_add_attr(&render_kobj, "dev", move || rd.clone());
    }
    render_kobj.add_symlink("subsystem", "../../../class/drm");
    // Render nodes aren't seat masters, but a `/sys/dev/char` link keeps them
    // enumerable by devnum (Mesa's render-worker device lookup).
    narf_filesystem::sysfs::register_char_dev_link(DRM_MAJOR, render_idx, "drm", &render_name);
}
