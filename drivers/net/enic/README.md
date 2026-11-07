# drivers/net/enic — Cisco VIC Ethernet NIC

Explicit refusal marker, not a driver (issue #798). The real datapath
is NOT implemented and is deferred out of desktop scope: there is no
TX/RX path and no `HwNic` implementation. `enic.rs` probe declines
every VIC with `ProbeError::NotForThisDriver` before touching the
hardware (no BAR0 map, no firmware reset), so the device is never
presented as bound and stays available to the next claimant in the
bus arbitration walk (bus spec §9.3). This replaces the earlier
probe-shaped stub (BAR0 map + firmware reset + "would normally
register to net registry here"), so coverage inventories stop
counting enic as a driver.

Dual-build: the built-in build compiles the refusal in `enic.rs`; the
`.ko` build registers through the `narf_register_pci_driver` KSYMTAB
export and its probe thunk returns `-ENOSYS` for the same reason.

- Spec: [drivers/net specification](../specification/spec.md)
