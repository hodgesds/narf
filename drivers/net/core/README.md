# drivers/net/core — Shared NIC driver surface

The driver-agnostic half of `drivers/net`: the `HwNic` trait and the
types it is defined over (`NicModel`, `NicCaps`, `NicDescriptor`,
`NicError`), in `lib.rs`. Per-driver crates depend on this crate for
the trait surface rather than on the `narf-drivers-net` facade, which
depends on them — so there is no dependency cycle; the facade
re-exports everything here.

Two helpers live alongside the trait: `publish.rs` publishes a probed
NIC into `narf_net::iface` under a dynamic `eth%d` name (the registry
the in-kernel TCP/IP stack, DHCP, and route selection read), and
`rtl_phy.rs` holds the Realtek PHY/EEPROM auxiliary codec shared by
the RTL8125/RTL8168 receive-descriptor and PHY access code.

- Spec: [drivers/net specification](../specification/spec.md)
