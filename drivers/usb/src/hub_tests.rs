//! Hub firmware model: configuration starts on alternate setting zero.
//! A multiple-TT capability does not switch the device's active TT mode.

use super::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

// Device + Configuration descriptors captured from the physical VIA hub.
const VIA_DESCRIPTORS: &[u8] = include_bytes!("hid/fixtures/via-2817.bin");

struct HubFirmware {
    alternate: AtomicU16,
    wanted_alternate: u16,
    interface: u16,
    powered: AtomicU16,
    reject_select: bool,
    requests: IrqSafeSpinLock<Vec<HubRequest>>,
}

impl HubFirmware {
    fn new(reject_select: bool) -> Self {
        Self {
            alternate: AtomicU16::new(0),
            wanted_alternate: 1,
            interface: 0,
            powered: AtomicU16::new(0),
            reject_select,
            requests: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}

impl HubTransport for HubFirmware {
    async fn read<'a>(
        &'a self,
        slot: u8,
        request: HubRequest,
        data: &'a mut [u8],
    ) -> Result<usize, xhci::XhciError> {
        if slot != 7
            || request
                != (HubRequest {
                    kind: 0xa0,
                    code: 6,
                    value: 0x2900,
                    index: 0,
                })
        {
            return Err(xhci::XhciError::CmdFailed(6));
        }
        self.requests.lock().push(request);
        let descriptor = [9, 0x29, 4, 0x60, 0, 50, 0, 0, 0xff];
        data[..descriptor.len()].copy_from_slice(&descriptor);
        Ok(descriptor.len())
    }

    async fn write(&self, slot: u8, request: HubRequest) -> Result<usize, xhci::XhciError> {
        if slot != 7 {
            return Err(xhci::XhciError::CmdFailed(6));
        }
        self.requests.lock().push(request);
        match request {
            HubRequest {
                kind: 1,
                code: 11,
                value,
                index,
            } if !self.reject_select
                && value == self.wanted_alternate
                && index == self.interface =>
            {
                self.alternate.store(value, Ordering::Release);
                Ok(0)
            }
            HubRequest {
                kind: 0x23,
                code: 3,
                value: 8,
                index: port @ 1..=4,
            } if self.alternate.load(Ordering::Acquire) == self.wanted_alternate => {
                self.powered.fetch_or(1 << port, Ordering::AcqRel);
                Ok(0)
            }
            _ => Err(xhci::XhciError::CmdFailed(6)),
        }
    }
}

fn smoke_hub_negotiates_multiple_tt() -> TestResult {
    let firmware = HubFirmware::new(false);
    let hub = match narf_scheduler::block_on(UsbHub::attach_transport(
        &firmware,
        7,
        0,
        HUB_PROTOCOL_MULTI_TT,
        PortSpeed::High,
        &VIA_DESCRIPTORS[18..],
    )) {
        Ok(hub) => hub,
        Err(_) => return TestResult::Fail("multiple-TT hub attach failed"),
    };
    if !hub.is_multi_tt()
        || firmware.alternate.load(Ordering::Acquire) != 1
        || firmware.powered.load(Ordering::Acquire) != 0x1e
    {
        return TestResult::Fail("xHCI multiple-TT mode disagrees with the hub's active alternate");
    }
    if hub.interface_alt != 1 || hub.interface_protocol != 2 {
        return TestResult::Fail("hub did not retain the negotiated alternate/protocol");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hub", smoke_hub_negotiates_multiple_tt);

fn smoke_hub_rejects_failed_multiple_tt_switch() -> TestResult {
    let firmware = HubFirmware::new(true);
    if narf_scheduler::block_on(UsbHub::attach_transport(
        &firmware,
        7,
        0,
        HUB_PROTOCOL_MULTI_TT,
        PortSpeed::High,
        &VIA_DESCRIPTORS[18..],
    ))
    .is_ok()
    {
        return TestResult::Fail("hub attached despite a rejected multiple-TT alternate");
    }
    if firmware.alternate.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("failed SET_INTERFACE changed the firmware's active alternate");
    }
    if firmware.requests.lock().len() != 1 {
        return TestResult::Fail("failed mode switch continued with hub class requests");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_hub_rejects_failed_multiple_tt_switch
);

fn smoke_hub_single_tt_does_not_switch_alternate() -> TestResult {
    let mut firmware = HubFirmware::new(true);
    firmware.wanted_alternate = 0;
    let hub = match narf_scheduler::block_on(UsbHub::attach_transport(
        &firmware,
        7,
        0,
        HUB_PROTOCOL_SINGLE_TT,
        PortSpeed::High,
        &VIA_DESCRIPTORS[18..],
    )) {
        Ok(hub) => hub,
        Err(_) => return TestResult::Fail("single-TT hub attach failed"),
    };
    if hub.is_multi_tt()
        || hub.interface_alt != 0
        || firmware.powered.load(Ordering::Acquire) != 0x1e
        || firmware.requests.lock().iter().any(|r| r.code == 11)
    {
        return TestResult::Fail("single-TT hub incorrectly selected a multiple-TT alternate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_hub_single_tt_does_not_switch_alternate
);

fn smoke_hub_rejects_missing_multiple_tt_alternate() -> TestResult {
    let firmware = HubFirmware::new(false);
    // Configuration header + alternate-zero interface/endpoint only. Device
    // protocol 2 cannot justify publishing multiple-TT mode without alt 1.
    let config = &VIA_DESCRIPTORS[18..18 + 25];
    if !matches!(
        narf_scheduler::block_on(UsbHub::attach_transport(
            &firmware,
            7,
            0,
            HUB_PROTOCOL_MULTI_TT,
            PortSpeed::High,
            config,
        )),
        Err(HubError::BadDescriptor)
    ) || !firmware.requests.lock().is_empty()
    {
        return TestResult::Fail("missing multiple-TT alternate was accepted or touched hardware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_hub_rejects_missing_multiple_tt_alternate
);

fn smoke_hub_selects_advertised_interface_and_alternate() -> TestResult {
    let mut config = VIA_DESCRIPTORS[18..].to_vec();
    config[9 + 2] = 2;
    config[25 + 2] = 2;
    config[25 + 3] = 3;
    let mut firmware = HubFirmware::new(false);
    firmware.interface = 2;
    firmware.wanted_alternate = 3;
    let hub = match narf_scheduler::block_on(UsbHub::attach_transport(
        &firmware,
        7,
        2,
        HUB_PROTOCOL_MULTI_TT,
        PortSpeed::High,
        &config,
    )) {
        Ok(hub) => hub,
        Err(_) => return TestResult::Fail("advertised hub interface/alternate was not selected"),
    };
    if !hub.is_multi_tt()
        || hub.interface_alt != 3
        || firmware.alternate.load(Ordering::Acquire) != 3
        || firmware.powered.load(Ordering::Acquire) != 0x1e
    {
        return TestResult::Fail("hub mode selection hard-coded an interface or alternate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_hub_selects_advertised_interface_and_alternate
);
