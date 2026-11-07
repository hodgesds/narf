//! `/sys/class/bluetooth/hci<N>/` — sysfs bridge for HCI controllers.
//!
//! Mirrors the Linux `bt_class` / `bt_host` / `bt_link` hierarchy from
//! `net/bluetooth/hci_sysfs.c`.  Each registered `ControllerInfo` becomes
//! one kobject directory under `/sys/class/bluetooth/hciN/` with the
//! standard read-only attribute files.  Active connections land as child
//! kobjects named `hciN:M` (handle M).
//!
//! Linux references:
//!   `net/bluetooth/hci_sysfs.c:9`   — `bt_class` name = "bluetooth"
//!   `net/bluetooth/hci_sysfs.c:24`  — `hci_conn_init_sysfs`: child under hdev
//!   `net/bluetooth/hci_sysfs.c:46`  — connection name = "%s:%d"
//!   `net/bluetooth/hci_sysfs.c:117` — `hci_init_sysfs`: attaches bt_host type
//!   `net/bluetooth/hci_sysfs.c:128` — `bt_sysfs_init`: `class_register(&bt_class)`

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::sysfs::{
    class_device_register, class_register, kobject_add_attr, kobject_add_writable_attr, Kobject,
};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::controller::ControllerInfo;

/// Snapshot of one active connection for sysfs population.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    /// HCI connection handle (0..=0x0EFF per Vol 4 Part E §5.4.2).
    pub handle: u16,
    /// Peer BD_ADDR as 6 bytes.
    pub bd_addr: [u8; 6],
    /// True = LE link; false = BR/EDR.
    pub is_le: bool,
    /// Link state string, e.g. "connected".
    pub state: &'static str,
}

/// Controller kobjects by HCI ordinal, so the pump can mirror its
/// connection table into sysfs without the controller registry having
/// to carry a `Kobject` (which has no `Debug` impl, so it cannot be
/// a field of the `#[derive(Debug)]` `Controller`).
///
/// Populated by [`register_hci_controller`] on every registration
/// (overwriting any stale slot, e.g. after a sysfs test reset);
/// a missing slot means "no controller published at this ordinal"
/// and the index-keyed helpers below become no-ops.
static HCI_KOBJS: IrqSafeSpinLock<Vec<Option<Arc<Kobject>>>> = IrqSafeSpinLock::new(Vec::new());

/// Controller kobject for `index`, if one has been published.
pub fn hci_kobject(index: usize) -> Option<Arc<Kobject>> {
    HCI_KOBJS.lock().get(index).cloned().flatten()
}

fn store_hci_kobject(index: usize, kobj: &Arc<Kobject>) {
    let mut slots = HCI_KOBJS.lock();
    while slots.len() <= index {
        slots.push(None);
    }
    slots[index] = Some(kobj.clone());
}

/// Remove `/sys/class/bluetooth/hci<index>/` for a detached
/// controller: drop the class child (with its per-connection
/// children) and clear the slot, so later index-keyed helpers
/// become no-ops for the ordinal until a fresh registration
/// reuses it. Returns `true` when a node was removed.
///
/// Linux ref: `hci_unregister_dev` → `device_del` / `device_unregister`
/// (`net/bluetooth/hci_sysfs.c`, `drivers/base/core.c`).
pub fn unregister_hci_controller(index: usize) -> bool {
    let removed = {
        let bt_class = class_register("bluetooth");
        bt_class.remove_child(&format!("hci{}", index))
    };
    // Clear the slot even when the class child was already gone
    // (e.g. a sysfs test reset dropped the tree): a stale slot
    // would let later index-keyed helpers resurrect children under
    // a detached controller's kobject.
    if let Some(slot) = HCI_KOBJS.lock().get_mut(index) {
        *slot = None;
    }
    removed
}

/// Register `/sys/class/bluetooth/hci<index>/` for one controller.
///
/// - `index`  — ordinal assigned by the transport registry (0, 1, …).
/// - `info`   — capabilities collected during bring-up.
/// - `conns`  — slice of active connections (may be empty).
///
/// Returns the kobject so callers can add per-controller children later
/// (e.g. when a new connection is established).
///
/// Linux ref: `hci_init_sysfs` + `bt_sysfs_init`
///            (`net/bluetooth/hci_sysfs.c:117,128`).
pub fn register_hci_controller(
    index: usize,
    info: ControllerInfo,
    conns: &[ConnInfo],
) -> Arc<Kobject> {
    // /sys/class/bluetooth/  — Linux: class_register(&bt_class)
    let bt_class = class_register("bluetooth");

    // /sys/class/bluetooth/hci<N>/
    let dev_name = format!("hci{}", index);
    let hci_kobj = class_device_register(bt_class, &dev_name);

    // ── controller-level attributes ──────────────────────────────────

    // `type` — "Primary" for standard BR/EDR+LE controllers,
    // "AMP" for 802.11 PAL controllers (hdev->dev_type).
    // Linux: `hci_dev.dev_type`; default for USB = HCI_PRIMARY.
    kobject_add_attr(&hci_kobj, "type", || "Primary\n".into());

    // `name` — ASCII name string.
    // Linux: `hci_dev.name` ("hciN").
    let name_str = dev_name.clone();
    kobject_add_attr(&hci_kobj, "name", move || format!("{}\n", name_str));

    // `address` — BD_ADDR formatted "XX:XX:XX:XX:XX:XX" (MSB first).
    // Linux: `hci_dev.bdaddr`; mgmt.c prints it via `%pMR`.
    let addr = info.bd_addr;
    kobject_add_attr(&hci_kobj, "address", move || {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\n",
            addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
        )
    });

    // `manufacturer` — decimal manufacturer ID from HCI_Read_Local_Version.
    // Linux: `hdev->manufacturer` (`mgmt.c:670`).
    let mfr = info.manufacturer;
    kobject_add_attr(&hci_kobj, "manufacturer", move || format!("{}\n", mfr));

    // `lmp_ver` — LMP version byte as decimal ASCII.
    // Linux: `hdev->lmp_ver` (`mgmt.c:1173`).
    let lv = info.lmp_version;
    kobject_add_attr(&hci_kobj, "lmp_ver", move || format!("{}\n", lv));

    // `lmp_subver` — LMP subversion (decimal).
    let ls = info.lmp_subversion;
    kobject_add_attr(&hci_kobj, "lmp_subver", move || format!("{}\n", ls));

    // `hci_ver` — HCI version byte.
    // Linux: `hdev->hci_ver` (`mgmt.c:1173`).
    let hv = info.hci_version;
    kobject_add_attr(&hci_kobj, "hci_ver", move || format!("{}\n", hv));

    // `hci_revision` — HCI revision (decimal).
    let hr = info.hci_revision;
    kobject_add_attr(&hci_kobj, "hci_revision", move || format!("{}\n", hr));

    // `idle_timeout` — ms; the controller's live idle policy
    // (see `crate::pm`). Default is the USB hub autosuspend
    // window (30 s); 0 means "never autosuspend" (Linux semantics).
    // Linux: `hdev->idle_timeout`.
    //
    // Writable (#1577): the store parses the written value as
    // milliseconds (0 = never autosuspend) and calls
    // `pm::set_idle_timeout_ms`; negative, non-numeric, empty, or
    // out-of-`u32`-range input is rejected with `EINVAL`
    // (`FsError::InvalidData`) and leaves the policy unchanged.
    // Linux: `hci_dev.idle_timeout` is writable via the same
    // `sysfs` attribute (`net/bluetooth/hci_sysfs.c`).
    let index_for_idle = index;
    let index_for_idle_store = index;
    kobject_add_writable_attr(
        &hci_kobj,
        "idle_timeout",
        move || format!("{}\n", crate::pm::idle_timeout_ms(index_for_idle)),
        move |buf| {
            let s = core::str::from_utf8(buf)
                .map_err(|_| FsError::InvalidData)?
                .trim();
            // `u32::from_str` rejects a leading `-` (negative), any
            // non-digit, and values above `u32::MAX`, so a single
            // parse is the whole validation: 0 = never autosuspend,
            // anything else = idle window in ms.
            let ms: u32 = s.parse().map_err(|_| FsError::InvalidData)?;
            crate::pm::set_idle_timeout_ms(index_for_idle_store, ms);
            Ok(())
        },
    );

    // `sniff_max_interval` — ms, default 800 (0x0320 slots × 0.625 ms).
    // Linux: `hdev->sniff_max_interval` (default 800).
    kobject_add_attr(&hci_kobj, "sniff_max_interval", || "800\n".into());

    // `sniff_min_interval` — ms, default 80 (0x0050 slots × 0.625 ms).
    // Linux: `hdev->sniff_min_interval` (default 80).
    kobject_add_attr(&hci_kobj, "sniff_min_interval", || "80\n".into());

    // `acl_mtu` — ACL data MTU from HCI_Read_Buffer_Size.
    let acl_mtu = info.acl_data_mtu;
    kobject_add_attr(&hci_kobj, "acl_mtu", move || format!("{}\n", acl_mtu));

    // `acl_pkts` — total ACL buffer count from HCI_Read_Buffer_Size.
    let acl_pkts = info.acl_total_num;
    kobject_add_attr(&hci_kobj, "acl_pkts", move || format!("{}\n", acl_pkts));

    // `sco_mtu` — SCO data MTU from HCI_Read_Buffer_Size.
    let sco_mtu = info.sco_data_mtu;
    kobject_add_attr(&hci_kobj, "sco_mtu", move || format!("{}\n", sco_mtu));

    // `sco_pkts` — total SCO buffer count from HCI_Read_Buffer_Size.
    let sco_pkts = info.sco_total_num;
    kobject_add_attr(&hci_kobj, "sco_pkts", move || format!("{}\n", sco_pkts));

    // ── per-connection children ──────────────────────────────────────

    // Publish the controller node for the pump's connection mirroring
    // (and any later per-controller children) before populating the
    // initial connections below.
    store_hci_kobject(index, &hci_kobj);

    for conn in conns {
        add_connection(&hci_kobj, index, conn);
    }

    hci_kobj
}

/// Add a per-connection child kobject `hci<N>:<handle>` under an
/// existing controller kobject.
///
/// Idempotent per handle: any stale child of the same name is removed
/// first, so a duplicate complete event cannot stack two same-named
/// children (`Kobject::new_child` itself never dedups).
///
/// Linux ref: `hci_conn_add_sysfs` — `dev_set_name(&conn->dev, "%s:%d", …)`
///            (`net/bluetooth/hci_sysfs.c:46`).
pub fn add_connection(hci_kobj: &Arc<Kobject>, controller_index: usize, conn: &ConnInfo) {
    use narf_filesystem::sysfs::Kobject;

    let child_name = format!("hci{}:{}", controller_index, conn.handle);
    // Idempotency: drop a stale same-named child before creating.
    hci_kobj.remove_child(&child_name);
    let child = Kobject::new_child(hci_kobj.clone(), child_name);

    let addr = conn.bd_addr;
    kobject_add_attr(&child, "address", move || {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\n",
            addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
        )
    });

    // `type` — "BR/EDR" or "LE".
    // Linux: `hci_conn.type` via `bt_link` device_type.
    let is_le = conn.is_le;
    kobject_add_attr(&child, "type", move || {
        if is_le {
            "LE\n".into()
        } else {
            "BR/EDR\n".into()
        }
    });

    // `state` — e.g. "connected", "disconnecting".
    let state = conn.state;
    kobject_add_attr(&child, "state", move || format!("{}\n", state));
}

/// Remove the per-connection child kobject `hci<N>:<handle>` from a
/// controller kobject. Returns true if a child was removed.
///
/// Linux ref: `hci_conn_del_sysfs` (`net/bluetooth/hci_sysfs.c`).
pub fn remove_connection(hci_kobj: &Arc<Kobject>, controller_index: usize, handle: u16) -> bool {
    hci_kobj.remove_child(&format!("hci{}:{}", controller_index, handle))
}

/// Mirror one connection into sysfs for the controller published at
/// `index`. No-op when no controller kobject is published at that
/// ordinal (e.g. a pump driven without registration).
pub fn add_connection_for(index: usize, conn: &ConnInfo) {
    if let Some(hci_kobj) = hci_kobject(index) {
        add_connection(&hci_kobj, index, conn);
    }
}

/// Drop one connection's sysfs child for the controller published at
/// `index`. Returns false when nothing was published or removed.
pub fn remove_connection_for(index: usize, handle: u16) -> bool {
    match hci_kobject(index) {
        Some(hci_kobj) => remove_connection(&hci_kobj, index, handle),
        None => false,
    }
}

/// Format a BD_ADDR byte array as "XX:XX:XX:XX:XX:XX" (big-endian display,
/// wire bytes are little-endian so index 5 is the most-significant octet).
pub fn format_bdaddr(addr: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
    )
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_filesystem::sysfs::__reset_for_test;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn make_info() -> ControllerInfo {
        ControllerInfo {
            bd_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            hci_version: 13,
            hci_revision: 0x0010,
            lmp_version: 13,
            manufacturer: 0x003F,
            lmp_subversion: 0x0001,
            acl_data_mtu: 0x0200,
            sco_data_mtu: 64,
            acl_total_num: 8,
            sco_total_num: 4,
            dev_class: [0; 3],
            local_name: [0; 248],
            short_name: [0; 10],
        }
    }

    // ── smoke: address format ────────────────────────────────────────

    fn smoke_sysfs_hci_address_format() -> TestResult {
        __reset_for_test();
        let info = make_info();
        let kobj = register_hci_controller(0, info, &[]);
        let val = match kobj.attr_show("address") {
            Some(v) => v,
            None => return TestResult::Fail("address attr missing"),
        };
        // BD_ADDR [0x11,0x22,0x33,0x44,0x55,0x66]: wire LE → display MSB first
        // → 66:55:44:33:22:11
        if !val.contains("66:55:44:33:22:11") {
            return TestResult::Fail("address format mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sysfs", smoke_sysfs_hci_address_format);

    // ── smoke: type attr ─────────────────────────────────────────────

    fn smoke_sysfs_hci_type_primary() -> TestResult {
        __reset_for_test();
        let kobj = register_hci_controller(0, make_info(), &[]);
        let val = match kobj.attr_show("type") {
            Some(v) => v,
            None => return TestResult::Fail("type attr missing"),
        };
        if !val.contains("Primary") {
            return TestResult::Fail("type should be Primary");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sysfs", smoke_sysfs_hci_type_primary);

    // ── smoke: hci_ver attr ──────────────────────────────────────────

    fn smoke_sysfs_hci_ver_attr() -> TestResult {
        __reset_for_test();
        let info = make_info(); // hci_version = 13
        let kobj = register_hci_controller(0, info, &[]);
        let val = match kobj.attr_show("hci_ver") {
            Some(v) => v,
            None => return TestResult::Fail("hci_ver attr missing"),
        };
        if !val.trim_end().ends_with("13") {
            return TestResult::Fail("hci_ver should be 13");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sysfs", smoke_sysfs_hci_ver_attr);

    // ── smoke: idle_timeout is the live pm policy, not "0" ───────

    fn smoke_sysfs_hci_idle_timeout_live() -> TestResult {
        __reset_for_test();
        crate::pm::__reset_for_test();
        let kobj = register_hci_controller(0, make_info(), &[]);
        let val = match kobj.attr_show("idle_timeout") {
            Some(v) => v,
            None => return TestResult::Fail("idle_timeout attr missing"),
        };
        // Default is the hub autosuspend window (30 s), not 0.
        if val.trim() != alloc::format!("{}", crate::pm::DEFAULT_IDLE_TIMEOUT_MS).as_str() {
            return TestResult::Fail("idle_timeout default is not the hub window");
        }
        // The attribute follows the pm state live.
        crate::pm::set_idle_timeout_ms(0, 0);
        let val = match kobj.attr_show("idle_timeout") {
            Some(v) => v,
            None => return TestResult::Fail("idle_timeout attr missing after set"),
        };
        if val.trim() != "0" {
            return TestResult::Fail("idle_timeout did not follow the pm state");
        }
        crate::pm::__reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sysfs", smoke_sysfs_hci_idle_timeout_live);

    // ── smoke: idle_timeout store round-trips + rejects bad input ──
    //
    // #1577: the sysfs store is the only userspace writer of the
    // pm idle policy. Values come from the sysfs/PM semantics
    // themselves (0 = never autosuspend, else ms; anything
    // negative / non-numeric / out of `u32` range is `EINVAL`),
    // never from impl constants.

    fn smoke_sysfs_hci_idle_timeout_store_roundtrip() -> TestResult {
        __reset_for_test();
        crate::pm::__reset_for_test();
        let kobj = register_hci_controller(0, make_info(), &[]);
        if !kobj.attr_is_writable("idle_timeout") {
            return TestResult::Fail("idle_timeout attr is not writable");
        }
        // Store 5000 ms, then read it back through the same attr.
        match kobj.attr_store("idle_timeout", b"5000\n") {
            Some(Ok(())) => {}
            Some(Err(_)) => return TestResult::Fail("store of 5000 rejected"),
            None => return TestResult::Fail("idle_timeout has no store path"),
        }
        let val = match kobj.attr_show("idle_timeout") {
            Some(v) => v,
            None => return TestResult::Fail("idle_timeout attr missing after store"),
        };
        if val.trim() != "5000" {
            return TestResult::Fail("idle_timeout did not read back the stored value");
        }
        if crate::pm::idle_timeout_ms(0) != 5_000 {
            return TestResult::Fail("idle_timeout store did not reach the pm policy");
        }
        // Store 0 (never autosuspend) round-trips too.
        if kobj
            .attr_store("idle_timeout", b"0")
            .is_some_and(|r| r.is_err())
        {
            return TestResult::Fail("store of 0 rejected");
        }
        if kobj.attr_show("idle_timeout").as_deref().map(str::trim) != Some("0") {
            return TestResult::Fail("idle_timeout did not read back 0");
        }
        crate::pm::__reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/sysfs",
        smoke_sysfs_hci_idle_timeout_store_roundtrip
    );

    fn smoke_sysfs_hci_idle_timeout_store_rejects_invalid() -> TestResult {
        __reset_for_test();
        crate::pm::__reset_for_test();
        let kobj = register_hci_controller(0, make_info(), &[]);
        // Pin a known-good value first: a rejected store must leave
        // the policy untouched.
        if kobj
            .attr_store("idle_timeout", b"7000")
            .is_some_and(|r| r.is_err())
        {
            return TestResult::Fail("setup store of 7000 rejected");
        }
        for bad in ["-1", "abc", "", "12ms", "4294967296"] {
            match kobj.attr_store("idle_timeout", bad.as_bytes()) {
                Some(Err(_)) => {}
                Some(Ok(())) => {
                    return TestResult::Fail("invalid idle_timeout store accepted");
                }
                None => return TestResult::Fail("idle_timeout has no store path"),
            }
            if crate::pm::idle_timeout_ms(0) != 7_000 {
                return TestResult::Fail("rejected store changed the pm policy");
            }
        }
        crate::pm::__reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/sysfs",
        smoke_sysfs_hci_idle_timeout_store_rejects_invalid
    );

    // ── smoke: connection child ──────────────────────────────────────

    fn smoke_sysfs_hci_connection_child() -> TestResult {
        __reset_for_test();
        let conn = ConnInfo {
            handle: 0,
            bd_addr: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            is_le: false,
            state: "connected",
        };
        let kobj = register_hci_controller(0, make_info(), &[conn]);
        // Child should appear under the controller kobject.
        let child = match kobj.get_child("hci0:0") {
            Some(c) => c,
            None => return TestResult::Fail("hci0:0 child not found"),
        };
        let addr = match child.attr_show("address") {
            Some(v) => v,
            None => return TestResult::Fail("conn address attr missing"),
        };
        if !addr.contains("FF:EE:DD:CC:BB:AA") {
            return TestResult::Fail("conn address format mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sysfs", smoke_sysfs_hci_connection_child);

    // ── smoke: connection child removal ──────────────────────────────

    fn smoke_sysfs_hci_connection_remove() -> TestResult {
        __reset_for_test();
        let conn = ConnInfo {
            handle: 3,
            bd_addr: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            is_le: true,
            state: "connected",
        };
        let kobj = register_hci_controller(0, make_info(), &[]);
        add_connection(&kobj, 0, &conn);
        if kobj.get_child("hci0:3").is_none() {
            return TestResult::Fail("child missing after add");
        }
        // Re-adding the same handle must not stack a second child.
        add_connection(&kobj, 0, &conn);
        if kobj
            .child_names()
            .iter()
            .filter(|n| n.as_str() == "hci0:3")
            .count()
            != 1
        {
            return TestResult::Fail("duplicate add stacked a second child");
        }
        if !remove_connection(&kobj, 0, 3) {
            return TestResult::Fail("remove should report true");
        }
        if kobj.get_child("hci0:3").is_some() {
            return TestResult::Fail("child survived remove");
        }
        if remove_connection(&kobj, 0, 3) {
            return TestResult::Fail("second remove should report false");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sysfs", smoke_sysfs_hci_connection_remove);
}
