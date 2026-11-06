# drivers/net/bnxt — Broadcom NetXtreme-C/E NIC

Explicit refusal marker, not a driver (issue #798). The real datapath
is NOT implemented and is deferred out of desktop scope: there is no
TX/RX path and no `HwNic` implementation. `bnxt.rs` probe declines
every BCM57414 with `ProbeError::NotForThisDriver` before touching
the hardware (no BAR0 map, no MAC reset), so the device is never
presented as bound and stays available to the next claimant in the
bus arbitration walk (bus spec §9.3). This replaces the earlier
probe-shaped stub (BAR0 map + reset-bit pulse + "would normally
register to net registry here"), so coverage inventories stop
counting bnxt as a driver.

Dual-build: the built-in build compiles the refusal in `bnxt.rs`; the
`.ko` build registers through the `narf_register_pci_driver` KSYMTAB
export and its probe thunk returns `-ENOSYS` for the same reason.

- Spec: [drivers/net specification](../specification/spec.md)
