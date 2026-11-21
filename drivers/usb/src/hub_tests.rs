//! Hub firmware model: configuration starts on alternate setting zero.
//! A multiple-TT capability does not switch the device's active TT mode.

use super::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
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
    /// GET_STATUS reads of `LATE_PORT`; it connects on the second.
    late_reads: AtomicU16,
    /// C_PORT_CONNECTION of `LATE_PORT` is set.
    late_change: AtomicBool,
    /// The status-change endpoint as configured and submitted.
    status_ep: IrqSafeSpinLock<Option<(EndpointConfig, u8, u32)>>,
    /// Ports whose C_PORT_SUSPEND is set (bit N = port N).
    suspend_change: AtomicU16,
}

/// The downstream port whose device connects only after the first walk.
const LATE_PORT: u16 = 2;

impl HubFirmware {
    fn new(reject_select: bool) -> Self {
        Self {
            alternate: AtomicU16::new(0),
            wanted_alternate: 1,
            interface: 0,
            powered: AtomicU16::new(0),
            reject_select,
            requests: IrqSafeSpinLock::new(Vec::new()),
            late_reads: AtomicU16::new(0),
            late_change: AtomicBool::new(false),
            status_ep: IrqSafeSpinLock::new(None),
            suspend_change: AtomicU16::new(0),
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
        if slot == 7 && request.kind == 0xa3 && request.code == 0 && data.len() == 4 {
            // GET_STATUS(port): LATE_PORT's device connects between the
            // first and second read, latching C_PORT_CONNECTION.
            let mut status = 0u32;
            if request.index == LATE_PORT {
                if self.late_reads.fetch_add(1, Ordering::AcqRel) == 1 {
                    self.late_change.store(true, Ordering::Release);
                }
                if self.late_reads.load(Ordering::Acquire) >= 2 {
                    status |= u32::from(PSTAT_CONNECTION);
                }
                if self.late_change.load(Ordering::Acquire) {
                    status |= 1 << 16;
                }
            }
            if self.suspend_change.load(Ordering::Acquire) & (1 << request.index) != 0 {
                status |= 1 << 18;
            }
            data.copy_from_slice(&status.to_le_bytes());
            return Ok(4);
        }
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
            HubRequest {
                kind: 0x23,
                code: 1,
                value: C_PORT_CONNECTION,
                index: LATE_PORT,
            } => {
                self.late_change.store(false, Ordering::Release);
                Ok(0)
            }
            HubRequest {
                kind: 0x23,
                code: 1,
                value: C_PORT_SUSPEND,
                index: port @ 1..=4,
            } => {
                self.suspend_change
                    .fetch_and(!(1 << port), Ordering::AcqRel);
                Ok(0)
            }
            HubRequest {
                kind: 0x23,
                code: 1,
                ..
            } => Ok(0),
            _ => Err(xhci::XhciError::CmdFailed(6)),
        }
    }

    async fn configure_status(
        &self,
        slot: u8,
        endpoint: EndpointConfig,
    ) -> Result<(), xhci::XhciError> {
        if slot != 7 {
            return Err(xhci::XhciError::CmdFailed(0xfd));
        }
        *self.status_ep.lock() = Some((endpoint, 0, 0));
        Ok(())
    }

    fn arm_status(&self, slot: u8, dci: u8, len: u32) -> Result<(), xhci::XhciError> {
        let mut g = self.status_ep.lock();
        match g.as_mut() {
            Some(entry) if slot == 7 => {
                entry.1 = dci;
                entry.2 = len;
                Ok(())
            }
            // Submitting before the endpoint exists fails on hardware.
            _ => Err(xhci::XhciError::NotReady),
        }
    }
}

// Note: HubFirmware mock transports emit no hardware IRQs, and attach_transport
// awaits sleep_ms(settle_ms). Under kernel-test BSP leaves its timer masked and
// timer_pump uninitialized while APs install arm_hrtimer_event globally, so
// mock attaches bridge via block_on_spin (which drives hrtimer_run_softirq).
fn smoke_hub_negotiates_multiple_tt() -> TestResult {
    let firmware = HubFirmware::new(false);
    let hub = match narf_scheduler::block_on_spin(UsbHub::attach_transport(
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

/// `hub_configure`: a hub that refuses its multiple-TT alternate keeps
/// working single-TT ("Using single TT") instead of failing to attach.
fn smoke_hub_falls_back_to_single_tt_when_switch_fails() -> TestResult {
    let firmware = HubFirmware::new(true);
    let hub = match narf_scheduler::block_on_spin(UsbHub::attach_transport(
        &firmware,
        7,
        0,
        HUB_PROTOCOL_MULTI_TT,
        PortSpeed::High,
        &VIA_DESCRIPTORS[18..],
    )) {
        Ok(hub) => hub,
        Err(_) => return TestResult::Fail("hub rejected after a refused multiple-TT alternate"),
    };
    if hub.is_multi_tt() || hub.interface_alt != 0 {
        return TestResult::Fail("refused multiple-TT switch still programmed multiple TT");
    }
    if firmware.alternate.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("failed SET_INTERFACE changed the firmware's active alternate");
    }
    if firmware.requests.lock().len() < 2 {
        return TestResult::Fail("fallback did not continue with hub class requests");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_hub_falls_back_to_single_tt_when_switch_fails
);

fn smoke_hub_single_tt_does_not_switch_alternate() -> TestResult {
    let mut firmware = HubFirmware::new(true);
    firmware.wanted_alternate = 0;
    let hub = match narf_scheduler::block_on_spin(UsbHub::attach_transport(
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
        narf_scheduler::block_on_spin(UsbHub::attach_transport(
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
    let hub = match narf_scheduler::block_on_spin(UsbHub::attach_transport(
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

fn single_tt_hub(firmware: &mut HubFirmware) -> Option<UsbHub> {
    firmware.wanted_alternate = 0;
    narf_scheduler::block_on_spin(UsbHub::attach_transport(
        firmware,
        7,
        0,
        HUB_PROTOCOL_SINGLE_TT,
        PortSpeed::High,
        &VIA_DESCRIPTORS[18..],
    ))
    .ok()
}

/// Linux `hub_activate` submits the hub's status-change interrupt URB,
/// so a port change arrives as a Transfer Event (`hub_irq` →
/// `kick_hub_wq`) rather than waiting for a timer-driven walk. The VIA
/// hub's first interface endpoint is that endpoint (0x81, interrupt,
/// 1-byte bitmap, bInterval 12): it is added to the slot, then armed.
fn smoke_hub_activate_submits_status_change_endpoint() -> TestResult {
    let mut firmware = HubFirmware::new(true);
    let Some(mut hub) = single_tt_hub(&mut firmware) else {
        return TestResult::Fail("single-TT hub attach failed");
    };
    let Some(status) = hub.status else {
        return TestResult::Fail("hub's status-change endpoint not found");
    };
    if status.endpoint.ep_addr != 0x81
        || status.endpoint.kind != EndpointKind::InterruptIn
        || status.endpoint.interval != 12
        || status.dci != 3
        || status.len != 1
    {
        return TestResult::Fail("status-change endpoint decoded wrong");
    }
    if narf_scheduler::block_on_spin(hub.activate_transport(&firmware)).is_err() {
        return TestResult::Fail("hub activation failed");
    }
    match *firmware.status_ep.lock() {
        Some((endpoint, 3, 1)) if endpoint == status.endpoint => {}
        _ => return TestResult::Fail("status-change endpoint was not configured and submitted"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_hub_activate_submits_status_change_endpoint
);

/// A device that connects only after the hub's first walk is found by
/// the next walk, and its C_PORT_CONNECTION is acknowledged (Linux
/// `port_event` / `hub_port_connect_change`): a change bit left set
/// keeps the hub reporting the port on its status-change endpoint every
/// interval. No controller event is involved — only GET_STATUS.
fn smoke_hub_late_connect_is_found_and_acknowledged() -> TestResult {
    let mut firmware = HubFirmware::new(true);
    let Some(hub) = single_tt_hub(&mut firmware) else {
        return TestResult::Fail("single-TT hub attach failed");
    };
    let first =
        narf_scheduler::block_on_spin(hub.connected_downstream_ports_transport(&firmware, 0));
    if !first.is_empty() {
        return TestResult::Fail("a port reported connected before its device arrived");
    }
    let second =
        narf_scheduler::block_on_spin(hub.connected_downstream_ports_transport(&firmware, 0));
    if second != [LATE_PORT as u8] {
        return TestResult::Fail("the late-connecting port was not found by the next walk");
    }
    if firmware.late_change.load(Ordering::Acquire) {
        return TestResult::Fail("C_PORT_CONNECTION was never acknowledged");
    }
    let third =
        narf_scheduler::block_on_spin(hub.connected_downstream_ports_transport(&firmware, 0));
    if third != [LATE_PORT as u8] {
        return TestResult::Fail("a connected port dropped out after its change was acknowledged");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_hub_late_connect_is_found_and_acknowledged
);

/// A host resume ends with the hub setting C_PORT_SUSPEND (USB 2.0
/// §11.24.2.7.2.3): on a port the host considers awake that change is
/// only the resume completing, and the walk acknowledges it (Linux
/// `port_event` clears C_SUSPEND); left set, the hub would report the port
/// on its status-change endpoint every interval and the supervisor would
/// walk it forever. A suspended port's C_PORT_SUSPEND is a remote wakeup
/// and stays for the wake watches (`suspend_change_set`).
fn smoke_hub_walk_acks_resume_completion_on_awake_port() -> TestResult {
    let mut firmware = HubFirmware::new(true);
    let Some(hub) = single_tt_hub(&mut firmware) else {
        return TestResult::Fail("single-TT hub attach failed");
    };
    firmware
        .suspend_change
        .store((1 << 3) | (1 << 4), Ordering::Release);
    let suspended = 1u64 << 4;
    let _ = narf_scheduler::block_on_spin(
        hub.connected_downstream_ports_transport(&firmware, suspended),
    );
    let left = firmware.suspend_change.load(Ordering::Acquire);
    if left & (1 << 3) != 0 {
        return TestResult::Fail("an awake port's C_PORT_SUSPEND was left set");
    }
    if left & (1 << 4) == 0 {
        return TestResult::Fail("a suspended port's remote-wakeup change was cleared");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_hub_walk_acks_resume_completion_on_awake_port
);
