# drivers/storage/mpt3sas — LSI/Broadcom MPT3 SAS controller

`narf-drivers-storage-mpt3sas` drives LSI/Avago/Broadcom SAS/SATA HBAs
and RAID controllers (Fusion-MPT SAS 3.0). It is dual-build — built-in
or loadable `.ko` — with the `block` target domain declared in
`src/lib.rs`.

What is in `src/mpt3sas.rs` so far is an interim labelled absence
(issue #935): `probe()` declines every device with
`ProbeError::NotForThisDriver` without mapping a BAR or touching the
hardware, so the bus dispatcher offers the device to the next
claimant instead of counting it bound. The previous probe mapped
BAR1, issued the doorbell reset and the host-diagnostic write
sequence, then dropped the HBA while reporting it bound — that
reset-and-drop path is deleted. PCI registration still matches
vendor `0x1000` (LSI Logic), device `0x0097` (SAS3008) so the
decline is observable in the match table. No command submission or
block-device registration exists in this crate yet. The full #935
endpoint (a real implementation, or clearly-labelled absence, for
MPT3SAS, MegaRAID and SmartPQI) is a separate lane.

- Spec: [`../specification/spec.md`](../specification/spec.md)
