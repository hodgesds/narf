//! Deterministic peers for wireless driver conversation tests (#706, A2).
//!
//! The kit speaks ordinary 802.11 management/EAPOL and Ethernet/DHCP. Native
//! firmware descriptors, DMA completion, radio policy, carrier publication and
//! the station's controlled port remain the driver's responsibility. These
//! peers never stand in for a production station or establish RF acceptance.
#![no_std]

extern crate alloc;

mod ap;
mod ap_rsn;
pub mod firmware;
mod network;

pub use ap::{ApError, ApPhase, FakeAp};
pub use ap_rsn::{ApPmf, ApSaePwe};
pub use network::{dhcp_message_type, udp_ipv4, DhcpObservations, DhcpServer, NetworkPlan};

mod tests;

mod ap_rsn_tests;
