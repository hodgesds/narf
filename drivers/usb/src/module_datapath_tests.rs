//! In-kernel smokes for the module USB datapath (`module_datapath.rs`).
//!
//! None of these load module text: contexts are minted with
//! `__open_for_test` under owner ids no loaded module can have, and every
//! request carries no completion callback, so the module call gate is never
//! entered. The end-to-end proof with real module text driving a real
//! device is `cargo xtask ftdi-module-serial-smoke`.

use alloc::sync::Arc;

use narf_bus::module_usb::{self, Completion};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::class_registry::module_usb_token;
use crate::xhci::EndpointKind;

/// Owner ids far outside the module id space.
const OWNER: u64 = 0xD47A_0000_0000_0001;
const OTHER: u64 = 0xD47A_0000_0000_0002;

const ENODEV: i32 = -19;
const EINVAL: i32 = -22;
const EAGAIN: i32 = -11;
const EBUSY: i32 = -16;
const ENOBUFS: i32 = -105;

const NONE: Completion = Completion {
    callback: None,
    cookie: 0,
};

/// Configuration descriptor: one vendor interface with bulk IN 0x81
/// (64 B), bulk OUT 0x02 (64 B), interrupt IN 0x83 (8 B, bInterval 10),
/// and an isochronous IN 0x84.
const CONFIG: [u8; 46] = [
    9, 0x02, 46, 0, 1, 1, 0, 0x80, 50, // configuration
    9, 0x04, 0, 0, 4, 0xFF, 0xFF, 0xFF, 0, // interface 0
    7, 0x05, 0x81, 0x02, 64, 0, 0, // bulk IN
    7, 0x05, 0x02, 0x02, 64, 0, 0, // bulk OUT
    7, 0x05, 0x83, 0x03, 8, 0, 10, // interrupt IN
    7, 0x05, 0x84, 0x01, 0, 2, 1, // isochronous IN
];

fn smoke_module_datapath_endpoint_from_config() -> TestResult {
    use super::endpoint_from_config;
    let Ok(bulk_in) = endpoint_from_config(&CONFIG, 0x81) else {
        return TestResult::Fail("bulk IN endpoint not found");
    };
    let Ok(bulk_out) = endpoint_from_config(&CONFIG, 0x02) else {
        return TestResult::Fail("bulk OUT endpoint not found");
    };
    let Ok(intr) = endpoint_from_config(&CONFIG, 0x83) else {
        return TestResult::Fail("interrupt IN endpoint not found");
    };
    if bulk_in.kind != EndpointKind::BulkIn
        || bulk_out.kind != EndpointKind::BulkOut
        || intr.kind != EndpointKind::InterruptIn
    {
        return TestResult::Fail("endpoint kinds not taken from bmAttributes + direction");
    }
    if bulk_in.max_packet != 64
        || intr.max_packet != 8
        || intr.interval != 10
        || bulk_in.interval != 0
    {
        return TestResult::Fail("packet size / interval not taken from the descriptor");
    }
    // Isochronous is not offered to modules; an address the descriptor
    // does not name is not configurable.
    if endpoint_from_config(&CONFIG, 0x84) != Err(-95)
        || endpoint_from_config(&CONFIG, 0x85) != Err(EINVAL)
    {
        return TestResult::Fail("isochronous or unknown endpoint was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/module-datapath",
    smoke_module_datapath_endpoint_from_config
);

fn smoke_module_datapath_rejects_unknown_context() -> TestResult {
    crate::class_registry::install_module_host();
    let token = module_usb_token(0xEE, 0xEE);
    let mut buf = [0u8; 8];
    // Argument validation in the bus layer runs before any context lookup.
    if module_usb::transfer(OWNER, token, 0x00, &[], 8, NONE) != Err(EINVAL)
        || module_usb::transfer(OWNER, token, 0x81, &[], 0, NONE) != Err(EINVAL)
        || module_usb::transfer(OWNER, token, 0x81, &[], module_usb::MAX_TRANSFER + 1, NONE)
            != Err(EINVAL)
        || module_usb::configure(OWNER, token, &[], NONE) != Err(EINVAL)
    {
        return TestResult::Fail("malformed datapath request reached the USB stack");
    }
    // A token with no context minted for this owner is -ENODEV everywhere.
    let (status, _) = module_usb::config_descriptor(OWNER, token, &mut buf);
    if status != ENODEV
        || module_usb::control(OWNER, token, [0x80, 6, 0, 1, 0, 0, 18, 0], &[], NONE) != Err(ENODEV)
        || module_usb::transfer(OWNER, token, 0x81, &[], 8, NONE) != Err(ENODEV)
        || module_usb::configure(OWNER, token, &[0x81], NONE) != Err(ENODEV)
        || module_usb::poll(OWNER, token, 1, &mut buf).0 != ENODEV
        || module_usb::cancel(OWNER, token, 1) != ENODEV
        || module_usb::serial_register(OWNER, token, 1, NONE) != Err(ENODEV)
    {
        return TestResult::Fail("datapath call succeeded without a probe context");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/module-datapath",
    smoke_module_datapath_rejects_unknown_context
);

/// First addressed device on any controller (the kernel-test VM's QEMU
/// keyboard), for smokes that need a real `USBDevice`.
fn first_device() -> Option<crate::device::USBDevice> {
    crate::device::enumerate().into_iter().next()
}

fn smoke_module_datapath_context_isolation_and_serial_node() -> TestResult {
    crate::class_registry::install_module_host();
    let Some(device) = first_device() else {
        return TestResult::Skip("no addressed USB device in this VM");
    };
    // A token no real slot uses, so the live device's own binding is untouched.
    let token = module_usb_token(0xEF, 0xEF);
    if !super::__open_for_test(OWNER, token, Arc::new(device), &CONFIG) {
        return TestResult::Fail("could not mint a test context");
    }
    let result = (|| {
        // Descriptor copy: short buffer reports the size, full buffer copies.
        let mut small = [0u8; 8];
        if module_usb::config_descriptor(OWNER, token, &mut small) != (ENOBUFS, CONFIG.len()) {
            return TestResult::Fail("short descriptor buffer did not report the length");
        }
        let mut full = [0u8; 64];
        if module_usb::config_descriptor(OWNER, token, &mut full) != (0, CONFIG.len())
            || full[..CONFIG.len()] != CONFIG
        {
            return TestResult::Fail("configuration descriptor copy mismatch");
        }
        // Another owner cannot use this owner's token.
        if module_usb::config_descriptor(OTHER, token, &mut full).0 != ENODEV
            || module_usb::serial_register(OTHER, token, 1, NONE) != Err(ENODEV)
        {
            return TestResult::Fail("a second owner reached another owner's context");
        }
        // Transfers need a configured endpoint; SET_ADDRESS is refused.
        if module_usb::transfer(OWNER, token, 0x81, &[], 64, NONE) != Err(EINVAL) {
            return TestResult::Fail("transfer on an unconfigured endpoint accepted");
        }
        if module_usb::control(OWNER, token, [0x00, 0x05, 9, 0, 0, 0, 0, 0], &[], NONE)
            != Err(EINVAL)
        {
            return TestResult::Fail("SET_ADDRESS from a module was accepted");
        }
        // The module-backed serial node: TX is what writers queued; RX
        // reaches readers; one node per context; bad family rejected.
        if module_usb::serial_register(OWNER, token, 9, NONE) != Err(EINVAL) {
            return TestResult::Fail("unknown serial family accepted");
        }
        let Ok(port) = module_usb::serial_register(OWNER, token, 1, NONE) else {
            return TestResult::Fail("serial node registration failed");
        };
        if module_usb::serial_register(OWNER, token, 1, NONE) != Err(EBUSY) {
            return TestResult::Fail("second serial node for one context accepted");
        }
        let Some(node) = crate::serial::devfs_bridge::get_port(port as usize) else {
            return TestResult::Fail("serial node not published");
        };
        if node.lock().driver_name() != "ftdi_sio" {
            return TestResult::Fail("serial node family not recorded");
        }
        node.lock().tx.push(b"tx-bytes");
        let mut out = [0u8; 16];
        if module_usb::serial_tx(OWNER, token, port, &mut out) != Ok(8) || &out[..8] != b"tx-bytes"
        {
            return TestResult::Fail("queued TX bytes did not reach the module");
        }
        if module_usb::serial_rx(OWNER, token, port, b"rx") != Ok(2) {
            return TestResult::Fail("RX bytes not accepted");
        }
        let mut read = [0u8; 4];
        if node.lock().rx.pop(&mut read) != 2 || &read[..2] != b"rx" {
            return TestResult::Fail("RX bytes did not reach the node's readers");
        }
        if module_usb::serial_tx(OWNER, token, port + 1, &mut out) != Err(EINVAL) {
            return TestResult::Fail("a module reached a serial node it does not own");
        }
        // Retiring the context withdraws the node and every later call.
        super::__retire_for_test(token);
        if crate::serial::devfs_bridge::get_port(port as usize).is_some() {
            return TestResult::Fail("retired context left its serial node published");
        }
        if module_usb::serial_tx(OWNER, token, port, &mut out) != Err(ENODEV) {
            return TestResult::Fail("serial call succeeded after retirement");
        }
        TestResult::Pass
    })();
    super::__retire_for_test(token);
    result
}
kernel_test_in!(
    "drivers/usb/module-datapath",
    smoke_module_datapath_context_isolation_and_serial_node
);

/// A control-IN request through the datapath: GET_DESCRIPTOR(DEVICE) runs
/// in a kernel task, reaches a terminal status, is pollable exactly once,
/// and a retired context drops a pending request instead of delivering it.
///
/// The kernel-test phase does not attach the VM's QEMU keyboard, so the
/// slots `enumerate` returns may be ones earlier smokes synthesised. When a
/// slot does answer a direct GET_DESCRIPTOR, that answer is the oracle and
/// the datapath must return it byte for byte; otherwise only the lifecycle
/// is checked. Real transfers against a real device are proven by
/// `cargo xtask ftdi-module-serial-smoke`.
fn smoke_module_datapath_control_request_lifecycle() -> TestResult {
    crate::class_registry::install_module_host();
    let devices = crate::device::enumerate();
    let live = devices.iter().take(16).find_map(|d| {
        narf_scheduler::block_on(d.get_device_descriptor())
            .ok()
            .filter(|desc| desc[0] == 18 && desc[1] == 0x01)
            .map(|desc| (d.clone(), desc))
    });
    let (device, expected) = match live {
        Some((d, desc)) => (d, Some(desc)),
        None => match devices.into_iter().next() {
            Some(d) => (d, None),
            None => return TestResult::Skip("no USB slot in this VM"),
        },
    };
    let token = module_usb_token(device.controller().id(), device.slot_id());
    // Keep the device's real binding: this context lives beside it under a
    // test owner, and EP0 control transfers are serialised per slot.
    if !super::__open_for_test(OWNER, token, Arc::new(device), &CONFIG) {
        return TestResult::Fail("could not mint a test context");
    }
    let result = (|| {
        let Ok(urb) = module_usb::control(OWNER, token, [0x80, 0x06, 0, 1, 0, 0, 18, 0], &[], NONE)
        else {
            return TestResult::Fail("GET_DESCRIPTOR submit failed");
        };
        if module_usb::cancel(OWNER, token, urb) != EBUSY {
            return TestResult::Fail("a control request reported itself cancellable");
        }
        let mut desc = [0u8; 18];
        let mut outcome = (EAGAIN, 0);
        let done = narf_scheduler::responsive_spin_until(
            || {
                let _ = narf_scheduler::poll_one_round();
                outcome = module_usb::poll(OWNER, token, urb, &mut desc);
                outcome.0 != EAGAIN
            },
            narf_time::Deadline::after_ms(2_000),
        );
        if !done {
            return TestResult::Fail("control request never completed");
        }
        // Terminal either way; byte-exact when a live device is the oracle.
        if expected.is_some_and(|expected| outcome != (0, 18) || desc != expected) {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  module-datapath smoke: GET_DESCRIPTOR status={} len={} desc[0..2]={:02x} {:02x}",
                outcome.0,
                outcome.1,
                desc[0],
                desc[1]
            );
            return TestResult::Fail("device descriptor not returned through the datapath");
        }
        // Consumed: the id is gone, not replayable.
        if module_usb::poll(OWNER, token, urb, &mut desc).0 != EINVAL
            || super::__urb_count_for_test(OWNER, token) != 0
        {
            return TestResult::Fail("a consumed request was still pollable");
        }
        // A pending request on a retired context is dropped, never delivered.
        let Ok(late) =
            module_usb::control(OWNER, token, [0x80, 0x06, 0, 1, 0, 0, 18, 0], &[], NONE)
        else {
            return TestResult::Fail("second GET_DESCRIPTOR submit failed");
        };
        super::__retire_for_test(token);
        for _ in 0..64 {
            let _ = narf_scheduler::poll_one_round();
        }
        if module_usb::poll(OWNER, token, late, &mut desc).0 != ENODEV
            || super::__context_count_for_test(OWNER) != 0
        {
            return TestResult::Fail("retired context still answered or survived");
        }
        TestResult::Pass
    })();
    super::__retire_for_test(token);
    result
}
kernel_test_in!(
    "drivers/usb/module-datapath",
    smoke_module_datapath_control_request_lifecycle
);
