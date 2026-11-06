# drivers/storage/megaraid — LSI MegaRAID SAS controller

`narf-drivers-storage-megaraid` is the LSI MegaRAID SAS controller
driver for hardware-RAID logical volumes (Dell PERC, HP SmartArray,
generic LSI). It is dual-build — built-in or loadable `.ko` — with the
`block` target domain declared in `src/lib.rs`.

Registration only, at this point: the built-in
`register_pci_driver()` in `src/megaraid.rs` only announces the driver,
and the source notes the PCI vendor match and multi-queue setup as a
placeholder. The module build (`src/module_probe.rs`) registers the
primary id (vendor `0x1000`, device `0x005b`) as a registration-only
probe that returns `-ENOSYS`. No command submission or block-device
path exists in this crate yet.

- Spec: [`../specification/spec.md`](../specification/spec.md)
