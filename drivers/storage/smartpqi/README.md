# drivers/storage/smartpqi — Microsemi smartpqi controller

`narf-drivers-storage-smartpqi` is the HPE Smart Array PQI storage
driver for the PCIe Queued Interface (PQI) used by modern HP Smart
Array RAID controllers. It is dual-build — built-in or loadable `.ko`
— with the `block` target domain declared in `src/lib.rs`.

Registration only, at this point: the built-in
`register_pci_driver()` in `src/smartpqi.rs` only announces the driver,
and the source notes the PCI vendor match and PQI queue setup as a
placeholder. The module build (`src/module_probe.rs`) registers the
primary id (vendor `0x9005`, device `0x028f`) as a registration-only
probe that returns `-ENOSYS`. No command submission or block-device
path exists in this crate yet.

- Spec: [`../specification/spec.md`](../specification/spec.md)
