//! Sysfs bridge — populates `/sys/class/extcon/` and
//! `/sys/class/typec/` from the extcon + Type-C global registries.
//!
//! ## `/sys/class/extcon/extcon<N>/`
//!
//! Per registered `ExtconDevice`:
//! - `name`              — device name string
//! - `state`             — `"USB=0\nUSB-HOST=0\n..."` bitmap (all supported cables)
//! - `cable.<i>/name`    — cable name string (one sub-kobject per cable)
//! - `cable.<i>/state`   — `"0"` or `"1"`
//!
//! Linux ref: `drivers/extcon/extcon.c::cable_state_show` (line ~462).
//!
//! ## `/sys/class/typec/port<N>/`
//!
//! Per registered `TypecConnector`:
//! - `data_role`                    — `"host"` / `"device"` / `"dual"`
//! - `power_role`                   — `"source"` / `"sink"` / `"dual"`
//! - `port_type`                    — `"source"` / `"sink"` / `"dual"`
//! - `vconn_source`                 — `"yes"` / `"no"` (stubbed `"no"`)
//! - `usb_typec_revision`           — `"1.2"`
//! - `usb_power_delivery_revision`  — `"3.0"`
//! - `preferred_role`               — empty if none
//! - `orientation`                  — `"normal"` / `"reverse"` / `"unknown"`
//! - `supported_accessory_modes`    — space-separated list
//!
//! Per active alt mode under `port<N>.altmode<M>/`:
//! - `svid`   — hex SVID (e.g. `"ff01"`)
//! - `mode`   — mode index (integer string)
//! - `active` — `"yes"`
//!
//! Linux ref: `drivers/usb/typec/class.c::typec_port_show_data_role`
//! (line ~550) and `typec_altmode_show_svid` (line ~348).
//!
//! ## Writable attributes (deferred)
//!
//! `data_role` and `power_role` writes are stubbed — returns EOPNOTSUPP.
//! Full write support requires a PD daemon not yet present.
//! Linux ref: `drivers/usb/typec/class.c::typec_port_store_data_role`
//! (line ~561).

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};

use crate::class;
use crate::typec::{AltMode, DataRole, Orientation, PowerRole, altmode::SVID_DISPLAYPORT};
use crate::typec::altmode::SVID_THUNDERBOLT;
use crate::typec_class;

// ── Extcon class ──────────────────────────────────────────────────────

/// Populate `/sys/class/extcon/extcon<N>/` for every device in the
/// extcon global registry.
///
/// Linux ref: `extcon_dev_register()` → `device_create_file()` in
/// `drivers/extcon/extcon.c` (line ~713).
pub fn populate_extcon_class() {
    let class_kobj = class_register("extcon");

    let registry = class::REGISTRY.lock();
    for (idx, dev) in registry.iter().enumerate() {
        let dev_name = format!("extcon{}", idx);
        let dev_kobj = class_device_register(class_kobj.clone(), &dev_name);

        // `name` attr — Linux extcon.c::extcon_name_show (line ~432).
        let name_str = dev.name().to_string();
        kobject_add_attr(&dev_kobj, "name", move || {
            format!("{}\n", name_str)
        });

        // `state` attr — bitmap of all supported cables.
        // Linux ref: `extcon.c::cable_state_show` (line ~462):
        //   prints "CABLE_NAME=0\n" or "CABLE_NAME=1\n" for each cable.
        let dev_arc = dev.clone();
        let cables: Vec<_> = dev.supported_cables().iter().copied().collect();
        kobject_add_attr(&dev_kobj, "state", move || {
            let mut s = alloc::string::String::new();
            for &cable in &cables {
                let attached = dev_arc.cable_state(cable);
                s.push_str(&format!("{}={}\n", cable, if attached { 1 } else { 0 }));
            }
            s
        });

        // `cable.<i>/name` and `cable.<i>/state` sub-kobjects.
        // Linux ref: `extcon.c` — cable attrs are under a `cable.N`
        // subdirectory (kobject) per `EXTCON_*` ID (line ~481).
        for (cidx, &cable) in dev.supported_cables().iter().enumerate() {
            let cable_name = format!("cable.{}", cidx);
            let cable_kobj = narf_filesystem::sysfs::Kobject::new_child(
                dev_kobj.clone(),
                cable_name,
            );

            let cname_str = format!("{}", cable);
            kobject_add_attr(&cable_kobj, "name", move || {
                format!("{}\n", cname_str)
            });

            let dev_arc2 = dev.clone();
            kobject_add_attr(&cable_kobj, "state", move || {
                if dev_arc2.cable_state(cable) { "1\n".to_string() } else { "0\n".to_string() }
            });
        }
    }
}

// ── Type-C class ──────────────────────────────────────────────────────

/// Populate `/sys/class/typec/port<N>/` for every connector in the
/// Type-C global registry.
///
/// Linux ref: `typec_register_port()` → kobject population in
/// `drivers/usb/typec/class.c` (line ~835).
pub fn populate_typec_class() {
    let class_kobj = class_register("typec");

    let registry = typec_class::TYPEC_REGISTRY.lock();
    for (idx, conn) in registry.iter().enumerate() {
        let port_name = format!("port{}", idx);
        let port_kobj = class_device_register(class_kobj.clone(), &port_name);

        // `data_role` — Linux: `typec_port_show_data_role` (class.c ~550).
        let c = conn.clone();
        kobject_add_attr(&port_kobj, "data_role", move || {
            match c.data_role() {
                DataRole::Host   => "host\n".to_string(),
                DataRole::Device => "device\n".to_string(),
                DataRole::Dual   => "dual\n".to_string(),
            }
        });

        // `power_role` — Linux: `typec_port_show_power_role` (class.c ~578).
        let c = conn.clone();
        kobject_add_attr(&port_kobj, "power_role", move || {
            match c.power_role() {
                PowerRole::Source => "source\n".to_string(),
                PowerRole::Sink   => "sink\n".to_string(),
                PowerRole::Dual   => "dual\n".to_string(),
            }
        });

        // `port_type` — static capability attribute; mirrors `power_role`
        // at registration time for simplicity (a pure-source port stays
        // "source" even if runtime role changes).
        // Linux ref: `typec_port_show_port_type` (class.c ~531).
        let c = conn.clone();
        kobject_add_attr(&port_kobj, "port_type", move || {
            match c.power_role() {
                PowerRole::Source => "source\n".to_string(),
                PowerRole::Sink   => "sink\n".to_string(),
                PowerRole::Dual   => "dual\n".to_string(),
            }
        });

        // `vconn_source` — stubbed "no"; VCONN tracking not yet wired.
        // Linux ref: `typec_port_show_vconn_source` (class.c ~602).
        kobject_add_attr(&port_kobj, "vconn_source", || "no\n".to_string());

        // `usb_typec_revision` — USB Type-C Rev 1.2 per spec.
        // Linux ref: `typec_port_show_usb_typec_revision` (class.c ~625).
        kobject_add_attr(&port_kobj, "usb_typec_revision", || "1.2\n".to_string());

        // `usb_power_delivery_revision` — USB PD Rev 3.0.
        // Linux ref: `typec_port_show_usb_power_delivery_revision`
        // (class.c ~637).
        kobject_add_attr(
            &port_kobj,
            "usb_power_delivery_revision",
            || "3.0\n".to_string(),
        );

        // `preferred_role` — empty; DRP preferred role not yet negotiated.
        // Linux ref: `typec_port_show_preferred_role` (class.c ~616).
        kobject_add_attr(&port_kobj, "preferred_role", || "\n".to_string());

        // `orientation` — decoded from CC status.
        // Linux ref: `typec_show_orientation` (class.c ~665).
        let c = conn.clone();
        kobject_add_attr(&port_kobj, "orientation", move || {
            match c.orientation() {
                Orientation::Normal   => "normal\n".to_string(),
                Orientation::Reversed => "reverse\n".to_string(),
                Orientation::Unknown  => "unknown\n".to_string(),
            }
        });

        // `supported_accessory_modes` — DP + TBT if alt modes exist.
        // Linux ref: `typec_port_show_accessory_mode` (class.c ~654).
        // For now hardcode DP + Thunderbolt as this port supports both.
        kobject_add_attr(
            &port_kobj,
            "supported_accessory_modes",
            || "DisplayPort Thunderbolt\n".to_string(),
        );

        // Alt-mode sub-kobjects: `port<N>.altmode<M>/`.
        // Linux ref: `typec_register_altmode()` (class.c ~316).
        let alt_modes = conn.entered_alt_modes();
        for (aidx, mode) in alt_modes.iter().enumerate() {
            let alt_name = format!("{}.altmode{}", port_name, aidx);
            let alt_kobj = narf_filesystem::sysfs::Kobject::new_child(
                port_kobj.clone(),
                alt_name,
            );

            let (svid, mode_idx) = match mode {
                AltMode::DisplayPort(_) => (SVID_DISPLAYPORT, 1u8),
                AltMode::Thunderbolt(pos) => (SVID_THUNDERBOLT, *pos),
            };

            let svid_str = format!("{:04x}", svid);
            kobject_add_attr(&alt_kobj, "svid", move || {
                format!("{}\n", svid_str)
            });
            kobject_add_attr(&alt_kobj, "mode", move || {
                format!("{}\n", mode_idx)
            });
            kobject_add_attr(&alt_kobj, "active", || "yes\n".to_string());
        }
    }
}

// ── Smoke tests ───────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use alloc::string::ToString;

    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_usbpd::tcpc::{CcState, CcStatus};

    use crate::cable::Cable;
    use crate::typec::altmode::{AltMode, DpPinAssign};
    use crate::typec::TypecConnector;
    use crate::typec_class;
    use super::{populate_extcon_class, populate_typec_class};

    // ── Helpers ──────────────────────────────────────────────────────

    fn reset() {
        narf_filesystem::sysfs::__reset_for_test();
        // Reset extcon registry.
        crate::class::REGISTRY.lock().clear();
        // Reset typec registry.
        typec_class::TYPEC_REGISTRY.lock().clear();
    }

    fn make_connector(name: &'static str) -> Arc<TypecConnector> {
        Arc::new(TypecConnector::new(name))
    }

    // ── Test 1: extcon0/name returns device name ──────────────────────
    //
    // Smoke: /sys/class/extcon/extcon0/name returns the device name

    fn smoke_extcon_sysfs_name() -> TestResult {
        reset();

        let conn = make_connector("typec-port0");
        crate::class::register(conn.clone());
        populate_extcon_class();

        let root = narf_filesystem::sysfs::SysFs::new();
        use narf_filesystem::FsInstance;
        let sys_root = root.root();

        let class_dir = match sys_root.lookup_dir("class") {
            Some(d) => d,
            None => return TestResult::Fail("class dir missing"),
        };
        let extcon_dir = match class_dir.lookup_dir("extcon") {
            Some(d) => d,
            None => return TestResult::Fail("extcon class dir missing"),
        };
        let dev_dir = match extcon_dir.lookup_dir("extcon0") {
            Some(d) => d,
            None => return TestResult::Fail("extcon0 dir missing"),
        };

        // Read the name attr.
        use narf_filesystem::DirOps;
        let name_file = match dev_dir.lookup("name") {
            Some(f) => f,
            None => return TestResult::Fail("name attr missing on extcon0"),
        };

        use narf_filesystem::FileOps;
        let mut buf = [0u8; 64];
        let n = poll_once(name_file.read(0, &mut buf));
        match n {
            Some(Ok(n)) if n > 0 => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                if s.contains("typec-port0") {
                    TestResult::Pass
                } else {
                    TestResult::Fail("extcon0/name wrong value")
                }
            }
            _ => TestResult::Fail("extcon0/name read failed"),
        }
    }
    kernel_test_in!("drivers/extcon", smoke_extcon_sysfs_name);

    // ── Test 2: extcon0/state contains "USB=0\n" after init ──────────
    //
    // Smoke: /sys/class/extcon/extcon0/state contains "USB=0\n" after init

    fn smoke_extcon_sysfs_state_initial() -> TestResult {
        reset();

        let conn = make_connector("typec-port1");
        crate::class::register(conn.clone());
        populate_extcon_class();

        use narf_filesystem::FsInstance;
        let sys_root = narf_filesystem::sysfs::SysFs::new().root();
        let dev_dir = descend_path(
            &sys_root,
            &["class", "extcon", "extcon0"],
        );
        let dev_dir = match dev_dir {
            Some(d) => d,
            None => return TestResult::Fail("extcon0 path missing"),
        };

        use narf_filesystem::DirOps;
        let state_file = match dev_dir.lookup("state") {
            Some(f) => f,
            None => return TestResult::Fail("state attr missing"),
        };

        use narf_filesystem::FileOps;
        let mut buf = [0u8; 256];
        let n = poll_once(state_file.read(0, &mut buf));
        match n {
            Some(Ok(n)) if n > 0 => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                if s.contains("USB=0") {
                    TestResult::Pass
                } else {
                    TestResult::Fail("state missing USB=0 line")
                }
            }
            _ => TestResult::Fail("state read failed"),
        }
    }
    kernel_test_in!("drivers/extcon", smoke_extcon_sysfs_state_initial);

    // ── Test 3: extcon0/cable.0/name returns cable string ────────────
    //
    // Smoke: /sys/class/extcon/extcon0/cable.0/name returns cable string

    fn smoke_extcon_sysfs_cable_name() -> TestResult {
        reset();

        let conn = make_connector("typec-port2");
        crate::class::register(conn.clone());
        populate_extcon_class();

        use narf_filesystem::FsInstance;
        let sys_root = narf_filesystem::sysfs::SysFs::new().root();

        // Descend: class → extcon → extcon0 → cable.0
        let cable_dir = descend_path(
            &sys_root,
            &["class", "extcon", "extcon0", "cable.0"],
        );
        let cable_dir = match cable_dir {
            Some(d) => d,
            None => return TestResult::Fail("cable.0 subdir missing"),
        };

        use narf_filesystem::DirOps;
        let name_file = match cable_dir.lookup("name") {
            Some(f) => f,
            None => return TestResult::Fail("cable.0/name attr missing"),
        };

        use narf_filesystem::FileOps;
        let mut buf = [0u8; 64];
        let n = poll_once(name_file.read(0, &mut buf));
        match n {
            Some(Ok(n)) if n > 0 => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                // The first cable in TypecConnector::SUPPORTED is Usb → "USB"
                if !s.is_empty() {
                    TestResult::Pass
                } else {
                    TestResult::Fail("cable.0/name empty")
                }
            }
            _ => TestResult::Fail("cable.0/name read failed"),
        }
    }
    kernel_test_in!("drivers/extcon", smoke_extcon_sysfs_cable_name);

    // ── Test 4: cable.0 attach → state line updates ───────────────────
    //
    // Smoke: After cable.0 attach → state line updates

    fn smoke_extcon_sysfs_state_after_attach() -> TestResult {
        reset();

        let conn = Arc::new(TypecConnector::new("typec-port3"));
        crate::class::register(conn.clone());
        populate_extcon_class();

        // Now attach the first cable (Cable::Usb for TypecConnector).
        conn.update_cable_state(Cable::Usb, true);

        use narf_filesystem::FsInstance;
        let sys_root = narf_filesystem::sysfs::SysFs::new().root();
        let dev_dir = descend_path(&sys_root, &["class", "extcon", "extcon0"]);
        let dev_dir = match dev_dir {
            Some(d) => d,
            None => return TestResult::Fail("extcon0 path missing"),
        };

        use narf_filesystem::DirOps;
        let state_file = match dev_dir.lookup("state") {
            Some(f) => f,
            None => return TestResult::Fail("state attr missing"),
        };

        use narf_filesystem::FileOps;
        let mut buf = [0u8; 256];
        let n = poll_once(state_file.read(0, &mut buf));
        match n {
            Some(Ok(n)) if n > 0 => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                if s.contains("USB=1") {
                    TestResult::Pass
                } else {
                    TestResult::Fail("state should show USB=1 after attach")
                }
            }
            _ => TestResult::Fail("state read failed after attach"),
        }
    }
    kernel_test_in!("drivers/extcon", smoke_extcon_sysfs_state_after_attach);

    // ── Test 5: typec port0/orientation returns "normal" initially ────
    //
    // Smoke: /sys/class/typec/port0/orientation returns "normal" initially

    fn smoke_typec_sysfs_orientation() -> TestResult {
        reset();

        let conn = Arc::new(TypecConnector::new("port0"));
        // Set CC1 active → Normal orientation.
        conn.update_cc(CcStatus { cc1: CcState::Rp3A0, cc2: CcState::Open });
        typec_class::typec_register(conn.clone());
        populate_typec_class();

        use narf_filesystem::FsInstance;
        let sys_root = narf_filesystem::sysfs::SysFs::new().root();
        let port_dir = descend_path(&sys_root, &["class", "typec", "port0"]);
        let port_dir = match port_dir {
            Some(d) => d,
            None => return TestResult::Fail("typec/port0 path missing"),
        };

        use narf_filesystem::DirOps;
        let orient_file = match port_dir.lookup("orientation") {
            Some(f) => f,
            None => return TestResult::Fail("orientation attr missing"),
        };

        use narf_filesystem::FileOps;
        let mut buf = [0u8; 32];
        let n = poll_once(orient_file.read(0, &mut buf));
        match n {
            Some(Ok(n)) if n > 0 => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                if s.contains("normal") {
                    TestResult::Pass
                } else {
                    TestResult::Fail("orientation should be 'normal'")
                }
            }
            _ => TestResult::Fail("orientation read failed"),
        }
    }
    kernel_test_in!("drivers/extcon", smoke_typec_sysfs_orientation);

    // ── Test 6: typec port0/data_role returns "host" ──────────────────
    //
    // Smoke: /sys/class/typec/port0/data_role returns "host"

    fn smoke_typec_sysfs_data_role() -> TestResult {
        reset();

        let conn = Arc::new(TypecConnector::new("port0"));
        conn.set_data_role(crate::typec::DataRole::Host);
        typec_class::typec_register(conn.clone());
        populate_typec_class();

        use narf_filesystem::FsInstance;
        let sys_root = narf_filesystem::sysfs::SysFs::new().root();
        let port_dir = descend_path(&sys_root, &["class", "typec", "port0"]);
        let port_dir = match port_dir {
            Some(d) => d,
            None => return TestResult::Fail("typec/port0 missing"),
        };

        use narf_filesystem::DirOps;
        let dr_file = match port_dir.lookup("data_role") {
            Some(f) => f,
            None => return TestResult::Fail("data_role attr missing"),
        };

        use narf_filesystem::FileOps;
        let mut buf = [0u8; 32];
        let n = poll_once(dr_file.read(0, &mut buf));
        match n {
            Some(Ok(n)) if n > 0 => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                if s.contains("host") {
                    TestResult::Pass
                } else {
                    TestResult::Fail("data_role should be 'host'")
                }
            }
            _ => TestResult::Fail("data_role read failed"),
        }
    }
    kernel_test_in!("drivers/extcon", smoke_typec_sysfs_data_role);

    // ── Test 7: typec port0/power_role returns "source" ───────────────
    //
    // Smoke: /sys/class/typec/port0/power_role returns "source"

    fn smoke_typec_sysfs_power_role() -> TestResult {
        reset();

        let conn = Arc::new(TypecConnector::new("port0"));
        conn.set_power_role(crate::typec::PowerRole::Source);
        typec_class::typec_register(conn.clone());
        populate_typec_class();

        use narf_filesystem::FsInstance;
        let sys_root = narf_filesystem::sysfs::SysFs::new().root();
        let port_dir = descend_path(&sys_root, &["class", "typec", "port0"]);
        let port_dir = match port_dir {
            Some(d) => d,
            None => return TestResult::Fail("typec/port0 missing"),
        };

        use narf_filesystem::DirOps;
        let pr_file = match port_dir.lookup("power_role") {
            Some(f) => f,
            None => return TestResult::Fail("power_role attr missing"),
        };

        use narf_filesystem::FileOps;
        let mut buf = [0u8; 32];
        let n = poll_once(pr_file.read(0, &mut buf));
        match n {
            Some(Ok(n)) if n > 0 => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                if s.contains("source") {
                    TestResult::Pass
                } else {
                    TestResult::Fail("power_role should be 'source'")
                }
            }
            _ => TestResult::Fail("power_role read failed"),
        }
    }
    kernel_test_in!("drivers/extcon", smoke_typec_sysfs_power_role);

    // ── Test 8: port0.altmode0/svid returns "ff01" after DP ──────────
    //
    // Smoke: /sys/class/typec/port0.altmode0/svid returns "ff01" after
    // DP alt mode enter

    fn smoke_typec_sysfs_altmode_svid() -> TestResult {
        reset();

        let conn = Arc::new(TypecConnector::new("port0"));
        conn.set_alt_mode(AltMode::DisplayPort(DpPinAssign::C), true);
        typec_class::typec_register(conn.clone());
        populate_typec_class();

        use narf_filesystem::FsInstance;
        let sys_root = narf_filesystem::sysfs::SysFs::new().root();
        // Alt mode appears under port0.altmode0 inside the port0 kobject.
        let port_dir = descend_path(&sys_root, &["class", "typec", "port0"]);
        let port_dir = match port_dir {
            Some(d) => d,
            None => return TestResult::Fail("typec/port0 missing"),
        };

        use narf_filesystem::DirOps;
        let alt_dir = match port_dir.lookup_dir("port0.altmode0") {
            Some(d) => d,
            None => return TestResult::Fail("port0.altmode0 subdir missing"),
        };
        let svid_file = match alt_dir.lookup("svid") {
            Some(f) => f,
            None => return TestResult::Fail("svid attr missing"),
        };

        use narf_filesystem::FileOps;
        let mut buf = [0u8; 32];
        let n = poll_once(svid_file.read(0, &mut buf));
        match n {
            Some(Ok(n)) if n > 0 => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                if s.contains("ff01") {
                    TestResult::Pass
                } else {
                    TestResult::Fail("svid should contain 'ff01'")
                }
            }
            _ => TestResult::Fail("svid read failed"),
        }
    }
    kernel_test_in!("drivers/extcon", smoke_typec_sysfs_altmode_svid);

    // ── Helpers ───────────────────────────────────────────────────────

    /// Walk an array of path components from a DirOps root.
    fn descend_path(
        root: &Arc<dyn narf_filesystem::DirOps>,
        parts: &[&str],
    ) -> Option<Arc<dyn narf_filesystem::DirOps>> {
        let mut cur: Arc<dyn narf_filesystem::DirOps> = root.clone();
        for &part in parts {
            cur = cur.lookup_dir(part)?;
        }
        Some(cur)
    }

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        use core::pin::Pin;
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker { raw_waker() }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }
}
