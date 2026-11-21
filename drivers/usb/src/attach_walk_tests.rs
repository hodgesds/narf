//! A hub's ports are walked only when the hub has something to report,
//! as Linux's `hub_event` runs for a hub whose `event_bits` were set by
//! `hub_irq` (its status-change URB completed) — not on a timer. A hub
//! without a status-change endpoint has no such report and is still
//! walked whenever the supervisor runs.
use super::*;
use crate::hub::{HubDescriptor, HubStatusEndpoint};
use crate::xhci::{EndpointConfig, EndpointKind, PortSpeed};
use narf_kernel_test::{kernel_test_in, TestResult};

fn binding(slot_id: u8, status: bool, walk_pending: bool) -> HubBinding {
    let endpoint = EndpointConfig {
        ep_addr: 0x81,
        max_packet: 1,
        kind: EndpointKind::InterruptIn,
        interval: 12,
    };
    HubBinding {
        hub: UsbHub {
            slot_id,
            iface_num: 0,
            descriptor: HubDescriptor {
                num_ports: 4,
                characteristics: 0,
                poweron_time_2ms: 50,
                controller_current: 0,
            },
            speed: PortSpeed::High,
            device_protocol: 1,
            interface_alt: 0,
            interface_protocol: 1,
            status: status.then_some(HubStatusEndpoint {
                endpoint,
                dci: 3,
                len: 1,
            }),
        },
        route_string: 0,
        tier: 0,
        root_hub_port: 1,
        bound_downstream: 0b110,
        suspended_downstream: 0,
        last_activity_tick: [0u64; 64],
        walk_pending,
    }
}

/// Of three hubs — a quiet one with a status-change endpoint, one whose
/// endpoint just reported a change, and one without an endpoint — only
/// the last two are walked. Today every hub is walked on every cycle
/// (four GET_STATUS control transfers per four-port hub every 96 ms).
fn smoke_usb_hub_walked_only_when_it_reports() -> TestResult {
    let hubs = [
        binding(10, true, false),
        binding(11, true, true),
        binding(12, false, false),
    ];
    if hubs_to_walk(&hubs) != [11, 12] {
        return TestResult::Fail("a quiet hub with a status-change endpoint was walked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/supervisor",
    smoke_usb_hub_walked_only_when_it_reports
);
