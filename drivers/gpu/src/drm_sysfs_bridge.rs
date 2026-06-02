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
//!     uevent                 → static DEVTYPE + DRIVER
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

use narf_filesystem::sysfs::{class_register, class_device_register, kobject_add_attr};

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
            cards.iter().position(|c| Arc::ptr_eq(c, &card)).unwrap_or(0) as u32
        };
        populate_card_node(class_drm.clone(), card, idx);
    }
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

    // `uevent` — static DEVTYPE + DRIVER fields.
    // Linux ref: drm_sysfs.c::drm_connector_uevent + drm_device_add_groups.
    {
        let driver = String::from(card.driver());
        let idx_copy = idx;
        kobject_add_attr(&kobj, "uevent", move || {
            format!(
                "DEVTYPE=drm_minor\nDRIVER={}\nMINOR={}\n",
                driver, idx_copy
            )
        });
    }

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
        kobject_add_attr(&kobj, "vbios_version", move || {
            format!("{}\n", ver_owned)
        });
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
}
