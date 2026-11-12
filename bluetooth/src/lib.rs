//! narf-bluetooth — Bluetooth HCI core (clean-room).
//!
//! Spec sources (public only):
//! - Bluetooth Core Specification 5.3, Vol 4 Part E (HCI Functional
//!   Specification) — Bluetooth SIG.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//! - Bluetooth Core Specification 5.3, Vol 4 Part B (USB Transport
//!   Layer) — Bluetooth SIG.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//! - USB Class Definitions for Wireless Controllers v1.0, USB-IF
//!   (class 0xE0, subclass 0x01, protocol 0x01).
//!
//! GPL Linux Bluetooth source (`net/bluetooth/`) consulted per NARF
//! 2026-05-20 relicense to GPL-2.0-or-later.
//!
//! ## Surface
//!
//! - [`hci`] — packet codec for Command, ACL, Synchronous Data, Event.
//! - [`opcode`] — Mandatory + commonly-used HCI opcode constants.
//! - [`event`] — Event-code enum + event packet builders/parsers.
//! - [`transport`] — `HciTransport` trait. USB / UART concrete
//!   bindings register against the global registry.
//! - [`h5_transport`] — `H5Transport: HciTransport` over a byte
//!   port: H5 link establishment (SYNC / CONFIG) + reliable packets
//!   (sequence numbers, sliding window, retransmission).
//! - [`controller`] — bring-up state machine (Reset → Read Local
//!   Version → Read BD_ADDR → Set Event Mask). Drives a transport
//!   through the mandatory init dance described in Vol 4 Part E §3.
//! - [`classic`] — classic BR/EDR command builders (Inquiry,
//!   Create_Connection, SSP IO-capability exchange, SCO setup).
//! - [`cmd_queue`] — HCI command queue with credit-flow tracking.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod att;
pub mod avdtp;
pub mod avrcp;
pub mod bond_store;
/// Intel PCIe-attached Bluetooth controllers (Lunar Lake onward).
/// Needs the PCIe bus, so x86_64 only for now.
#[cfg(target_arch = "x86_64")]
pub mod btintel_pcie;
pub mod btusb_quirks;
pub mod classic;
pub mod cmd_queue;
pub mod controller;
pub mod ertm;
pub mod event;
pub mod gap;
pub mod gatt;
pub mod gatt_client;
pub mod gatt_server;
pub mod h4;
pub mod h4_transport;
pub mod h5;
pub mod h5_transport;
pub mod hci;
pub mod hci_sock;
pub mod hfp;
pub mod hid_profile;
pub mod hogp;
pub mod hogp_client;
pub mod l2cap;
pub mod l2cap_server;
pub mod mesh;
pub mod mgmt;
pub mod opcode;
/// Per-controller power-management state: park causes (mgmt
/// power-off, system suspend, USB autosuspend) + idle timeout.
/// Issue #820.
pub mod pm;
pub mod profiles;
pub mod pump;
pub mod rfcomm;
pub mod rfcomm_session;
pub mod sdp;
pub mod sdp_server;
pub mod services;
pub mod smp;
pub mod transport;
pub mod usb_transport;

pub mod devfs_bridge;
pub mod sysfs_bridge;

mod tests;

#[cfg(feature = "kernel-test")]
mod e2e_tests;

#[cfg(feature = "kernel-test")]
mod fake_usb_hci;

use narf_capabilities::{Cap, CapKind, CapType, Grant};

/// Cap-type marker for the Bluetooth control surface.
#[derive(Copy, Clone, Debug)]
pub struct Bluetooth;

impl CapType for Bluetooth {
    const KIND: CapKind = CapKind::Bluetooth;
}

/// Mint a Bluetooth authority cap. TCB-only entry.
pub fn bootstrap_bluetooth_authority() -> Cap<Bluetooth, Grant> {
    Cap::<Bluetooth, Grant>::bootstrap()
}

/// Register the controller-firmware download.
///
/// Kept out of [`register_initcalls`] on purpose: it must run after
/// the firmware registry has been populated, and `Stage::Late`
/// initcalls run in registration order. `bare_main` calls this after
/// `narf_firmware::register_initcalls()`, which is what puts it after
/// the initramfs and rootfs firmware scans.
#[cfg(target_arch = "x86_64")]
pub fn register_firmware_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Late, "btintel-pcie-firmware", || {
        btintel_pcie::load_firmware();
        InitResult::Ok
    });
}

/// Stage::Late initcall registration. Stage 0 just registers a
/// per-stage placeholder so the boot summary records that the
/// Bluetooth subsystem is wired in; the actual USB transport bind
/// runs out of the USB host supervisor's per-port attach pass
/// (`narf_drivers_usb::btusb::try_bind_btusb_already_addressed`).
///
/// The HCI event-pump task is enabled here: [`pump::enable_spawning`]
/// adopts every controller that is already ready, and controllers
/// that become ready later (USB attach, PCIe firmware load) start
/// their pump from `pump::notify_controller_ready`.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "btintel-pcie", || {
        btintel_pcie::register_pci_driver();
        InitResult::Ok
    });
    // Stage: opt-in H5 boot bind (`bt-h5=<uart-name>`, issue #1580
    // items 1–2). Runs before `bluetooth-bringup` (registered later
    // by bare_main) so the bound transport is in the registry when
    // the bring-up pass runs; the pump adopts it from
    // `pump::notify_controller_ready` at bring-up time. No cmdline
    // key, or an empty value, means no bind — a UART is never stolen
    // from the `/dev/ttyS<N>` data ttys without opt-in. Link
    // establishment may take the full 5 s budget, hence the
    // explicit 6 s budget (the default 500 ms would only log an
    // over-budget warning, not kill the call).
    narf_init::register_with_budget(
        Stage::Late,
        "bluetooth-h5-boot",
        || {
            use core::fmt::Write as _;
            let Some(name) = h5_transport::boot_bind_name(narf_boot::args()) else {
                return InitResult::NotPresent;
            };
            match h5_transport::H5Transport::bind_named(name) {
                Some(t) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  bluetooth: H5 on {} (bt-h5={})",
                        t.port_name(),
                        name
                    );
                    InitResult::Ok
                }
                None => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  bluetooth: bt-h5={} did not bind (unknown UART, unmapped port, or no link)",
                        name
                    );
                    InitResult::NotPresent
                }
            }
        },
        6000,
    );
    narf_init::register(Stage::Late, "bluetooth-stage0", || {
        // Stage 0: no work beyond registering the subsystem. A real
        // controller probed by the USB supervisor will print its own
        // `bluetooth: ... adapter` line at attach time.
        let _ = transport::transport_count();
        InitResult::Ok
    });
    // Stage: enable the HCI event/ACL pump (see `pump`). Runs after
    // the Stage::Late bring-up initcall in registration order across
    // the boot sequence; controllers discovered later are adopted by
    // `pump::notify_controller_ready` at registration time.
    narf_init::register(Stage::Late, "bluetooth-pump", || {
        pump::enable_spawning();
        InitResult::Ok
    });
    // Stage: install /dev/rfcomm<N> lookup + enumerate hooks into devfs.
    // Linux ref: net/bluetooth/rfcomm/tty.c:rfcomm_dev_add().
    narf_init::register(Stage::Late, "bluetooth-devfs", || {
        fn rfcomm_lookup_hook(
            name: &str,
        ) -> Option<alloc::sync::Arc<dyn narf_filesystem::FileOps>> {
            crate::devfs_bridge::lookup_rfcomm_file(name)
        }
        fn rfcomm_enum_hook() -> alloc::vec::Vec<(alloc::string::String, narf_filesystem::FileType)>
        {
            crate::devfs_bridge::enumerate_rfcomm_devices(0, usize::MAX)
        }
        narf_filesystem::devfs::install_rfcomm_hooks(rfcomm_lookup_hook, rfcomm_enum_hook);
        InitResult::Ok
    });
    // Stage: register /sys/class/bluetooth/ class stub.
    // Linux ref: net/bluetooth/hci_sysfs.c:bt_sysfs_init().
    narf_init::register(Stage::Late, "bluetooth-sysfs", || {
        let _ = narf_filesystem::sysfs::class_register("bluetooth");
        InitResult::Ok
    });
    // Stage: install the mgmt (HCI_CHANNEL_CONTROL) handler so AF_BLUETOOTH
    // sockets reach the native controller registry. Linux ref:
    // net/bluetooth/mgmt.c.
    narf_init::register(Stage::Late, "bluetooth-mgmt", || {
        narf_filesystem::bluetooth::install_mgmt_handler(crate::mgmt::handle);
        narf_filesystem::bluetooth::install_hci_handlers(
            crate::hci_sock::send,
            crate::hci_sock::drain_event,
        );
        narf_filesystem::bluetooth::install_hci_ioctl_handlers(
            crate::hci_sock::dev_count,
            crate::hci_sock::dev_info,
            crate::hci_sock::dev_power,
        );
        narf_filesystem::bluetooth::install_hci_monitor_replay(crate::hci_sock::monitor_replay);
        // Stage: install the L2CAP/RFCOMM channel-socket handlers
        // (issue #814) so AF_BLUETOOTH listen/accept/send/recv reach
        // the pump's server-side channels.
        narf_filesystem::bluetooth::install_bt_l2cap_handlers(
            crate::pump::register_psm,
            crate::pump::unregister_psm,
            crate::pump::take_pending_channel,
            crate::pump::pending_channel,
            crate::pump::send_channel,
            crate::pump::drain_channel_rx,
            crate::pump::channel_rx_pending,
            crate::pump::disconnect_channel,
        );
        narf_filesystem::bluetooth::install_bt_rfcomm_handlers(
            crate::pump::take_pending_rfcomm,
            crate::pump::pending_rfcomm,
            crate::pump::send_rfcomm,
            crate::pump::drain_rfcomm_rx,
            crate::pump::rfcomm_rx_pending,
            crate::pump::close_rfcomm_dlc,
        );
        // Stage: install the outbound-connect handlers (issue
        // #1532) so AF_BLUETOOTH connect() reaches the pump's
        // L2CAP/RFCOMM channel-open client.
        narf_filesystem::bluetooth::install_bt_connect_handlers(
            crate::pump::connect,
            crate::pump::connect_ready,
            crate::pump::cancel_connect,
        );
        // Stage: install the SCO socket handlers (issue #814) so
        // AF_BLUETOOTH SCO connect/send/recv reach the pump's SCO
        // links over the #817 isoch transport.
        narf_filesystem::bluetooth::install_bt_sco_handlers(
            crate::pump::sco_connect,
            crate::pump::sco_connect_status,
            crate::pump::send_sco,
            crate::pump::drain_sco_rx,
            crate::pump::sco_rx_pending,
            crate::pump::disconnect_sco,
            crate::pump::cancel_sco_connect,
            crate::pump::take_pending_sco,
            crate::pump::pending_sco,
        );
        InitResult::Ok
    });
}
