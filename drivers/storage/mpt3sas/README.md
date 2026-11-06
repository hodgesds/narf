# drivers/storage/mpt3sas — LSI/Broadcom MPT3 SAS controller

`narf-drivers-storage-mpt3sas` drives LSI/Avago/Broadcom SAS/SATA HBAs
and RAID controllers (Fusion-MPT SAS 3.0). It is dual-build — built-in
or loadable `.ko` — with the `block` target domain declared in
`src/lib.rs`.

What is in `src/mpt3sas.rs` so far is probe and reset: `probe()` maps
BAR1, constructs the `Mpt3Sas` HBA, and `reset()` issues the doorbell
reset and then the host-diagnostic write sequence. PCI registration
matches vendor `0x1000` (LSI Logic), device `0x0097` (SAS3008). No
command submission or block-device registration exists in this crate
yet — `probe()` builds the HBA and returns without registering it with
the storage subsystem.

- Spec: [`../specification/spec.md`](../specification/spec.md)
