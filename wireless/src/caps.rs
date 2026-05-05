use narf_capabilities::{CapType, CapKind};

#[derive(Debug)]
pub struct WirelessIface;

impl CapType for WirelessIface {
    const KIND: CapKind = CapKind::NetIface; // Wireless is a specialized NetIface
}
