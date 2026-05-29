//! IPv6 connection layer: NDP, SLAAC, DHCPv6 client, routing, ICMPv6
//! socket, MLD skeleton.
//!
//! This module groups the protocol-level state machines for IPv6. The
//! wire-format codecs live in `crate::pkt_ipv6` and `crate::pkt_dhcpv6`;
//! the top-level RX/TX dispatch sits in `crate::ipv6_stack`.
//!
//! Stage-1 scope (RFC references on each submodule):
//! - `addrs`  — per-iface address registry + lifetimes (RFC 4862 §5.5).
//! - `route`  — longest-prefix-match table over IPv6 prefixes.
//! - `ndp`    — Neighbor Discovery state machine (RFC 4861).
//! - `slaac`  — Stateless Address Autoconfig + RFC 8981 privacy.
//! - `dhcpv6` — DHCPv6 client state machine (RFC 8415).
//! - `icmp6_sock` — Echo (Ping6) + raw type-filtered receive.
//! - `mld`    — MLDv2 report builder (skeleton).

pub mod addrs;
pub mod dhcpv6;
pub mod icmp6_sock;
pub mod mld;
pub mod ndp;
pub mod route;
pub mod slaac;
