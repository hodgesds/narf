# drivers/net/cxgb4 — Chelsio T4/T5/T6 NIC

Explicitly not implemented (issue #799, peripherals program #746).

The Chelsio Terminator 10/40GbE datapath is out of this program's
desktop scope (T4–T6 are server parts), so no datapath is implemented
and none is planned in this lane. `cxgb4.rs` registers one vendor-wide
PCI match for Chelsio (`0x1425`) whose probe declines every device
with `ProbeError::NotForThisDriver`, so the device stays unbound and
available to other claimants instead of looking like a present driver
that does nothing. The loadable-module probe already refused with
`-ENOSYS`; see `module_probe.rs`.

- Spec: [drivers/net specification](../specification/spec.md)
