# drivers/net/igc — Intel I225/I226 2.5 GbE NIC

Driver for the Intel I225/I226 2.5 GbE family (including I220-V), the
most fully featured NIC crate in the tree. `igc.rs` holds probe, the
device-ID table, MSI-X enablement, RSS configuration, and the `HwNic`
implementation; the supporting modules split the rest — `hardware.rs`
(register access), `queue.rs` (descriptor queues), `packet.rs`,
`protocol.rs`, `ptp.rs` (packet timestamps), `merge.rs` (MAC Merge /
frame preemption), `traffic.rs` (flow rules and traffic scheduling),
`control.rs`, and `counters.rs` — with co-located smokes in
`tests.rs`.

Dual-build: the built-in build compiles the real driver; the module
build registers through the device C ABI and shares reset, PHY, and
queue programming with the built-in path.

- Spec: [drivers/net specification](../specification/spec.md)
- Research: [drivers/net research](../research/README.md)
