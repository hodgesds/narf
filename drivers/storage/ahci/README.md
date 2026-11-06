# drivers/storage/ahci — AHCI SATA host controller

`narf-drivers-storage-ahci` drives SATA disks behind an AHCI host bus
adapter (Intel ICH9 and compatible), from the public AHCI 1.3.1
specification. It maps the ABAR register block, performs HBA global
init, enumerates the implemented ports, classifies each port from its
signature, and runs the IDENTIFY decode (`identify_ata_features`) that
routes per-port device information. Completed commands arrive through
the HBA/port interrupt model (`GHC.IE` master gate, per-port `PORT_IE`,
W1C status clearing), and the async I/O paths build their IRQ wait
future before writing `PORT_CI` so they cannot race the completion.

The implementation lives in `src/ahci.rs` (`Ahci`, `AhciRegs` over the
ABAR window, `HbaConfig`, `PortInfo`, `DiskInfo`, `AhciError`), with
`AhciBlockSync` implementing `BlockDeviceSync` so a probed disk is
usable through the block layer. Like the other storage drivers it is
dual-build — built-in or loadable `.ko` — with `src/module_probe.rs`
holding the module-build registration path and the `block` target
domain declared in `src/lib.rs`.

- Spec: [`../specification/spec.md`](../specification/spec.md) (AHCI 1.3.1 sources)
