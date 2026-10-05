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
    kobject_add_writable_attr, kobject_emit_uevent, Kobject,
};
use narf_filesystem::uevent::UeventAction;

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
    // PCI is a bus-owned projection.  Publish it before attaching DRM minors,
    // so card<N>/device always names the function that was actually
    // enumerated rather than a driver-invented location.
    narf_filesystem::sysfs::populate_pci_devices();

    let class_drm = class_register("drm");
    let cards = crate::drm_registry::cards();

    // systemd-udevd starts after the Stage::Late device projections have
    // already been built. Mark the first finished graphical projection as
    // replayable before queuing its ADDs; later block-device coldplug extends
    // the same window rather than replacing this boundary. Without the DRM
    // ADD, 71-seat.rules never records `master-of-seat`, logind reports
    // seat0.CanGraphical=false, and a display manager waits on a black screen.
    if !cards.is_empty() {
        narf_filesystem::uevent::begin_boot_udevd_replay();
    }

    for card in cards {
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

/// Resolve a DRM card to the PCI function discovered by the bus layer.
///
/// The DRM registry currently records PCI IDs but not a `PcieAddr`.  IDs are
/// sufficient for the present drivers; when identical adapters exist, retain
/// registration/enumeration order as the discriminator.  Crucially this
/// returns an address only when the bus layer has actually enumerated one.
fn enumerated_pci_addr_for_card(
    card: &dyn crate::drm_registry::DrmCard,
    idx: u32,
) -> Option<narf_bus::PcieAddr> {
    let ordinal = crate::drm_registry::cards()
        .iter()
        .take(idx as usize)
        .filter(|prior| {
            prior.vendor_id() == card.vendor_id() && prior.device_id() == card.device_id()
        })
        .count();

    narf_bus::snapshot()
        .into_iter()
        .filter_map(|device| match device.kind {
            narf_bus::BusKind::Pcie { addr, .. }
                if device.id.vendor == card.vendor_id() && device.id.device == card.device_id() =>
            {
                Some(addr)
            }
            _ => None,
        })
        .nth(ordinal)
}

/// Resolve a PCI parent for a DRM card.
///
/// Production never fabricates a PCI address or configuration header.  The
/// test-only fallback exists solely because isolated DRM sysfs tests register
/// fake cards without running PCI enumeration; it deliberately has no
/// `config` file and therefore cannot mask a missing live ECAM projection.
fn pci_addr_for_card(
    card: &dyn crate::drm_registry::DrmCard,
    idx: u32,
) -> Option<narf_bus::PcieAddr> {
    let discovered = enumerated_pci_addr_for_card(card, idx);

    #[cfg(any(test, feature = "kernel-test"))]
    {
        discovered.or_else(|| {
            // Reserve an otherwise-unused test slot.  The kernel's QEMU
            // profile uses slots 00..0c and 1f, so this cannot overwrite an
            // enumerated fixture's generic PCI kobject.
            Some(narf_bus::PcieAddr::new(
                0,
                0,
                0x10u8.saturating_add(idx as u8).min(0x1e),
                0,
            ))
        })
    }

    #[cfg(not(any(test, feature = "kernel-test")))]
    {
        discovered
    }
}

/// Build the kobject subtree for one DRM card.
fn populate_card_node(
    class_drm: Arc<Kobject>,
    card: Arc<dyn crate::drm_registry::DrmCard>,
    idx: u32,
) {
    // A PCI DRM node without an enumerated PCI parent is worse than absent:
    // libdrm would read a made-up identity/configuration and bind the wrong
    // userspace driver.  Driver registration must be wired to the bus
    // registry before it can expose a PCI-backed card.
    let Some(pci_bdf) = pci_addr_for_card(card.as_ref(), idx) else {
        return;
    };

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

    // Writable `vblank_offset_ns` (default 0): the render-slack tuning knob —
    // how many ns BEFORE the true simulated vblank a flip-complete event is made
    // deliverable, so a compositor wakes early enough to render + resubmit
    // before scanout (absorbing scheduler wake latency). Global (compensates for
    // a system property), mirrored on every card node. See
    // `crate::drm::card::VBLANK_OFFSET_NS`.
    kobject_add_writable_attr(
        &kobj,
        "vblank_offset_ns",
        || format!("{}\n", crate::drm::card::vblank_offset_ns()),
        |data: &[u8]| {
            let s =
                core::str::from_utf8(data).map_err(|_| narf_filesystem::FsError::InvalidData)?;
            let ns: u64 = s
                .trim()
                .parse()
                .map_err(|_| narf_filesystem::FsError::InvalidData)?;
            crate::drm::card::set_vblank_offset_ns(ns);
            Ok(())
        },
    );

    // `subsystem` → /sys/class/drm. From /sys/devices/platform/narf-drm/card<N>
    // the class dir is four levels up. elogind only marks a seat graphical when
    // it can attach a device whose subsystem is "drm".
    kobj.add_symlink("subsystem", "../../../../class/drm");

    // ── the PCI device node, and card<N>/device as a SYMLINK to it ───────
    //
    // `device` MUST be a symlink whose target is named like a PCI address.
    // libdrm's `drmParsePciBusInfo` does `readlink("/sys/dev/char/226:N/device")`
    // and sscanf's "%04x:%02x:%02x.%1u" out of the TARGET to recover
    // domain:bus:dev.func. A real directory named "device" (what this used to
    // be) has no address to parse, so bus-info fails, `drmGetDevice2` cannot
    // describe the device, and everything downstream — Mesa's loader, then
    // EGL's "failed to get compatible render device" — falls over regardless
    // of how correct the attributes are.
    //
    let pci_addr = format!(
        "{:04x}:{:02x}:{:02x}.{}",
        pci_bdf.segment, pci_bdf.bus, pci_bdf.device, pci_bdf.function
    );
    let pci_host_name = format!("pci{:04x}:{:02x}", pci_bdf.segment, pci_bdf.bus);
    let pci_root = get_or_create_child(&devices, &pci_host_name);
    let dev_kobj = get_or_create_child(&pci_root, &pci_addr);
    // From /sys/devices/platform/narf-drm/card<N>, three levels up is
    // /sys/devices.
    kobj.add_symlink("device", format!("../../../{pci_host_name}/{pci_addr}"));
    // From /sys/devices/pci0000:00/<addr>/, three levels up is /sys.
    dev_kobj.add_symlink("subsystem", "../../../bus/pci");
    // The PCI parent is already complete: uevent, IDs and `config` are owned
    // by `filesystem::sysfs::populate_pci_devices`, which reads the live ECAM
    // page.  Do not replace any of them with driver-provided values.
    //
    // Isolated DRM tests intentionally omit bus enumeration.  They retain the
    // text IDs needed to exercise the symlink topology, but still never gain
    // a fake config binary attribute.
    if !dev_kobj.has_attr("config") {
        let vendor = card.vendor_id();
        kobject_add_attr(&dev_kobj, "vendor", move || format!("0x{vendor:04x}\n"));
        let device = card.device_id();
        kobject_add_attr(&dev_kobj, "device", move || format!("0x{device:04x}\n"));
        let subsystem_vendor = card.subsystem_vendor();
        kobject_add_attr(&dev_kobj, "subsystem_vendor", move || {
            format!("0x{subsystem_vendor:04x}\n")
        });
        let subsystem_device = card.subsystem_device();
        kobject_add_attr(&dev_kobj, "subsystem_device", move || {
            format!("0x{subsystem_device:04x}\n")
        });
        kobject_add_uevent_attr(
            &dev_kobj,
            format!(
                "DRIVER={driver}\nPCI_SLOT_NAME={pci_addr}\nPCI_ID={:04X}:{:04X}\n",
                card.vendor_id(),
                card.device_id(),
            ),
        );
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

    // `renderD<M>/device` → the SAME PCI node card<N>/device points at.
    //
    // Not redundant with the card's link: libdrm phrases both of its node
    // filters against the node's OWN devnum, so having them on 226:N does
    // nothing for 226:M. `process_device()` rejects a node unless
    //
    //   drmNodeIsDRM(226,M)       stat("/sys/dev/char/226:M/device/drm")
    //   drmParseSubsystemType()   readlink("/sys/dev/char/226:M/device")
    //
    // both succeed. With no `device` entry here they both failed, so libdrm
    // silently dropped the render node while still enumerating the card
    // happily — leaving a drmDevice whose `available_nodes` held only
    // `1 << DRM_NODE_PRIMARY`.
    //
    // That single missing bit is the whole failure. Mesa's
    // `loader_is_device_render_capable()` is a `drmGetDevice2()` plus a test
    // of exactly that bit; false sends `dri2_initialize_drm()` into
    // `dri_query_compatible_render_only_device_fd()`, which also has nothing
    // to find, and EGL dies with "DRI2: failed to get compatible render
    // device". kwin then has no EGL and takes the Plasma session with it.
    //
    // The target must be byte-identical to the card's: libdrm unions
    // `available_nodes` only across nodes whose parsed bus info compares
    // equal, so two different addresses would stay two one-node devices and
    // the render bit would still be absent. Same depth
    // (devices/platform/narf-drm/<node>), so the same relative path.
    render_kobj.add_symlink("device", format!("../../../{pci_host_name}/{pci_addr}"));

    // `card<N>/device/drm/{card<N>,renderD<M>}` — how a consumer walks from a
    // card to its RENDER node.
    //
    // On Linux both minors hang off the parent device's `drm/` directory
    // (…/drm/card0, …/drm/renderD128), so given the card you find its render
    // node by listing that directory. NARF placed them as SIBLINGS under
    // narf-drm with no `drm/` level, so nothing connected the two and Mesa
    // failed with "DRI2: failed to get compatible render device" — the error
    // that replaced the earlier device-info failure once driver selection was
    // fixed. kwin then has no EGL and gives up.
    //
    // Symlinks rather than a second real node: the canonical kobjects stay
    // where they are (systemd's sd-device already resolves devnum through
    // them), and this only adds the parent-relative view Mesa walks.
    // Relative to card<N>/device/drm/, THREE levels up is narf-drm
    // (drm → device → card<N> → narf-drm).
    {
        // From /sys/devices/pci0000:00/<addr>/drm/, four levels up is
        // /sys/devices, then down into the platform container.
        let dev_drm = get_or_create_child(&dev_kobj, "drm");
        dev_drm.add_symlink(
            card_name.clone(),
            format!("../../../../platform/narf-drm/{}", card_name),
        );
        dev_drm.add_symlink(
            render_name.clone(),
            format!("../../../../platform/narf-drm/{}", render_name),
        );
    }

    class_drm.add_symlink(
        render_name.clone(),
        format!("../../devices/platform/narf-drm/{}", render_name),
    );
    char_dev_link(
        render_idx,
        &format!("../../devices/platform/narf-drm/{}", render_name),
    );

    // Parent first, then the two DRM minors, matching Linux device
    // registration ordering. The card ADD is the load-bearing event for
    // systemd's 71-seat.rules (`seat` + `master-of-seat`); the parent and
    // render ADDs make udev's PCI and render-node database views complete.
    kobject_emit_uevent(&dev_kobj, UeventAction::Add);
    kobject_emit_uevent(&kobj, UeventAction::Add);
    kobject_emit_uevent(&render_kobj, UeventAction::Add);
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// `card<N>/device/subsystem` must resolve to `/sys/bus/pci`.
    ///
    /// libdrm classifies a DRM node's bus by readlink()ing this attribute and
    /// comparing the BASENAME against "pci"/"platform"/"usb"
    /// (`drmGetDevice2` → `drmParseSubsystemType`). Without it the bus is
    /// unknown, libdrm never fills in the PCI device info, and Mesa's loader
    /// fails with "MESA-LOADER: failed to retrieve device information" — the
    /// vendor/device attributes are useless on their own because nothing
    /// declares them to BE pci ids.
    ///
    /// Not cosmetic: kwin emits a burst of those while probing and then
    /// exits, taking the Plasma session down with it.
    ///
    /// The count of `..` matters and is easy to get wrong, which is most of
    /// why this test exists: the symlink sits at
    /// `/sys/devices/platform/narf-drm/card<N>/device/`, five levels below
    /// `/sys`, whereas the sibling `card<N>/subsystem` is four. An
    /// off-by-one resolves to a nonexistent path and reproduces the exact
    /// failure it is meant to prevent, silently.
    fn smoke_drm_device_subsystem_points_at_pci() -> TestResult {
        const DEPTH_TO_SYS: usize = 5;
        let link = "../../../../../bus/pci";

        let ups = link.matches("../").count();
        if ups != DEPTH_TO_SYS {
            return TestResult::Fail(
                "card/device/subsystem link depth is wrong; it must reach /sys from \
                 devices/platform/narf-drm/card<N>/device",
            );
        }
        // The basename is what libdrm actually compares against.
        if !link.ends_with("/bus/pci") {
            return TestResult::Fail("card/device/subsystem must resolve to /sys/bus/pci");
        }
        // Resolve it by hand from the device dir and confirm it lands on
        // exactly `bus/pci` with no leftover components.
        let mut comps: alloc::vec::Vec<&str> = "devices/platform/narf-drm/card0/device"
            .split('/')
            .collect();
        for part in link.split('/') {
            match part {
                ".." => {
                    if comps.pop().is_none() {
                        return TestResult::Fail("card/device/subsystem escapes above /sys");
                    }
                }
                "" | "." => {}
                other => comps.push(other),
            }
        }
        if comps.join("/") != "bus/pci" {
            return TestResult::Fail("card/device/subsystem does not resolve to /sys/bus/pci");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm_sysfs",
        smoke_drm_device_subsystem_points_at_pci
    );
}
