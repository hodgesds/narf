# drivers/storage — Non-NVMe Storage Transport Drivers

The storage transport layer for everything that is not NVMe (which lives in
its own `drivers/nvme` crate). This crate brings up the host controllers and
device fabrics that sit between a physical disk and the kernel's block layer:
SATA/AHCI host bus adapters, SAS/RAID controllers, SD/MMC and eMMC card
hosts, UFS, and the PCIe plumbing (Intel VMD) that hides some of those
controllers behind a bridge. Its job is discovery, controller bring-up, and
command issuance — turning a bus-enumerated PCI function into a usable block
device that `block/` and the filesystem drivers can read and write.

Each supported fabric is a self-contained module. AHCI (`ahci`) maps the ABAR
register block, resets the HBA, enumerates implemented ports, and reads each
port signature so IDENTIFY can later be routed per port. The SD/MMC side is
split into a controller driver and protocol decoders: `sdhci` performs the
full SD Host Controller bring-up (software reset, 3.3 V power-on, 400 kHz
init clock, the CMD0/CMD8/ACMD41/CMD2/CMD3/CMD7 identification handshake, and
single-block PIO transfers), `sd_proto` is a pure, MMIO-free parser for the
R1/R6/R7 responses and the CID/CSD registers (both v1.0 and v2.0 capacity
formulas), and `emmc` is a clean-room JEDEC EXT_CSD decoder that reads card
revision, speed-grade flags, bus width, partition configuration, boot/RPMB
sizes, user capacity, and lifetime/health estimates. `rtsx` drives Realtek
card-reader bridges and provides the block-device bridge that publishes an
enumerated card as a block device. The enterprise storage controllers —
`megaraid`, `smartpqi`, and `mpt3sas` — bring up LSI/Broadcom MegaRAID,
Microsemi smartpqi, and Fusion-MPT SAS/SATA HBAs respectively. `ufs` covers
Universal Flash Storage host-controller interface bring-up, and `vmd` handles
Intel Volume Management Device, which re-roots a subtree of NVMe/storage
functions behind a PCIe bridge and must inject its children into the bus
registry early enough for the same PCI walk to probe them.

All drivers are clean-room implementations traced to public specifications
(Serial ATA AHCI 1.3.1, the SD Host Controller and Physical Layer Simplified
Specifications, JEDEC JESD84/JESD223/JESD220, and the respective controller
programming references) rather than GPL Linux source. The crate registers
each controller as a PCI driver through `drivers/runtime` initcalls: most bind
at `Stage::Subsys`, while Intel VMD binds at `Stage::Device` so its injected
children remain visible to later bus walks. The code is `#![no_std]`, forbids
implicit unsafe in unsafe functions, and drives its MMIO through the
capability-gated `io/` and `memory/` facilities. Because the fabrics attach
over PCI and MMIO, the set of usable drivers is platform- and firmware-
dependent; decoders such as `sd_proto` and `emmc` are hardware-independent and
exercised by deterministic tests.

- Spec: [`specification/spec.md`](./specification/spec.md)
