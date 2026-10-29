# narf-drivers-storage — non-NVMe storage drivers

## Sources (public only)

All driver code is derived strictly from the references below.
**No GPL Linux source consulted.**

### AHCI

- **Serial ATA AHCI Specification, Revision 1.3.1** — Intel.
  Public document. §3 Generic Host Control register block, §4
  Port register block, §5 command list / FIS structure.

### SDHCI

- **SD Host Controller Simplified Specification, Version 3.00** —
  SD Association. Public document (sdcard.org). §2 standard register
  map, §2.2.5 Transfer Mode, §2.2.6 Command, §2.2.9 Present State,
  §2.2.14 Clock Control, §2.2.16 Software Reset, §2.2.18 Normal
  Interrupt Status, §3.6 reset sequence, §3.7 SD bus power on.

### eMMC EXT_CSD

- **JEDEC Standard JESD84-B51 — "Embedded Multi-Media Card (e•MMC)
  Electrical Standard (5.1)"** — JEDEC. Public.
  §6.6.4 (SWITCH command argument layout — Access:2 / Index:8 /
  Value:8 / CmdSet:8). §6.6.5 (HS200 / HS400 timing flags).
  §7.4 (EXT_CSD register, 512 bytes; field offsets in Table 39:
  REV=192, CARD_TYPE=196, BUS_WIDTH=183, HS_TIMING=185,
  PARTITION_CONFIG=179, BOOT_SIZE_MULT=226, RPMB_SIZE_MULT=168,
  SEC_COUNT=212, PRE_EOL_INFO=267, DEVICE_LIFE_TIME_EST_TYP_A=268,
  DEVICE_LIFE_TIME_EST_TYP_B=269).

### SD protocol (CSD / CID / responses)

- **SD Physical Layer Simplified Specification, Version 8.00** —
  SD Association. Public document (sdcard.org).
  §4.9 R1/R3/R6/R7 response formats. §4.10 R1 status bit definitions.
  §5.1 OCR layout. §5.2 CID layout (manufacturer ID, OEM, product
  name, revision, serial, MDT). §5.3.2 CSD v1.0 capacity formula
  (C_SIZE × 2^(C_SIZE_MULT+2) × 2^READ_BL_LEN). §5.3.3 CSD v2.0
  capacity formula ((C_SIZE+1) × 512 KiB).

### UFS / UFSHCI 3.0

- **JEDEC JESD223D — Universal Flash Storage Host Controller
  Interface (UFSHCI)**, Version 3.0, January 2018.
  <https://www.jedec.org/standards-documents/docs/jesd223d>
- **JEDEC JESD220D — Universal Flash Storage (UFS)**, Version 3.1,
  March 2020.
  <https://www.jedec.org/standards-documents/docs/jesd220d>

## Scope

### Landed
- **AHCI** (`ahci`): binds `8086:2922` / `8086:3a22` by ID and every
  `01:06:01` controller by class (Linux's generic `ahci_pci_tbl` entry; e.g.
  AMD 600-series `1022:43f6`, which Linux drives as `board_ahci` with no
  quirks). HBA bring-up `hba_global_init(&impl AhciRegs) -> Result<HbaConfig,
  AhciError>` mirrors Linux `ahci_save_initial_config` + `ahci_reset_controller`
  (AE with 5 retries, CAP / CAP2 / PI / port-capability save, GHC.HR with a 1 s
  bound, restore) plus the AHCI §10.6.3 BIOS/OS handoff (`BiosHandoff`);
  `effective_port_map(cap, vs, pi)` is Linux's PI cross-check / fabrication.
  Each implemented port is deinitialised, given a FIS receive area, spun up,
  COMRESET (`sata_link_debounce`, `SATA_DEB_TIMING_NORMAL`) and waited on for
  BSY (10 s) before its signature is classified. `Ahci::{cap2, handoff,
  block_port, capacity}`; `identify_n_sectors`. Every probed controller
  installs in the controller registry (deduplicated by bus address) and
  every ATA-disk port is IDENTIFYed and published as its own `sata<n>`
  block device with a `DiskIdentity` (transport `ata`, PCI bus path,
  model / serial / firmware) and a partition scan (`sata<n>p<m>`) (#931).
  `AhciBlockSync` is per-disk (controller + port); its transfers chunk
  at the per-controller 128 KiB DMA transfer buffer, so the block
  surface takes any request size the registry contract allows (#930).
  IDENTIFY features (`AtaFeatures` via `identify_ata_features`) drive
  real FLUSH CACHE / FLUSH CACHE EXT, WRITE DMA FUA EXT (write + flush
  emulation where unsupported), and DATA SET MANAGEMENT TRIM, with the
  block adapter advertising Discard only for TRIM-capable disks (#841).
  The driver registers `ahci` with the `power` device_pm fan-out:
  suspend flushes + idles every published disk (failure aborts the
  suspend), resume re-runs the HBA init sequence and revalidates each
  disk's capacity + model before serving I/O again (#932). Only the
  first installed HBA owns an IRQ (the ISR is a single-controller
  design); later HBAs poll. An HBA without CAP.S64A gets its DMA
  buffers below 4 GiB via the masked allocator. New
  `AhciError::AhciEnableFailed`.
- **SDHCI** (`sdhci`): full controller bring-up — software reset,
  power on at 3.3 V, supply 400 kHz init clock, run the SD
  identification sequence (CMD0 / CMD8 / ACMD41 / CMD2 / CMD3 / CMD7
  / CMD16), single-block PIO `read_block` / `write_block` on top of
  CMD17 / CMD24, error reporting via NIS_ERROR + EIS. Identified
  cards are published as `sdhci0` with a partition scan
  (`sdhci0p<m>`) (#834). Register access runs through an
  `SdhciTransport` seam (BAR0 MMIO in production), so the
  identify → publish conversation is fixture-modelled end to end.
- **RTSX** (`rtsx`): Realtek PCIe SD card reader — probe, card
  identify (real CID/CSD decoded via `sd_proto`), single-block
  CMD17 / CMD24 block I/O over the ping-pong buffer. Cards are
  published as `mmcblk0` with real CID sysfs identity and a
  partition scan (`mmcblk0p<m>`); card removal withdraws the
  partitions together with the parent (#834).
- **eMMC EXT_CSD** (`emmc`): clean-room JEDEC JESD84-B51 EXT_CSD
  register decoder. Parses revision, CARD_TYPE flags (HS_26 /
  HS_52 / HS200 / HS400 with 1V8 + 1V2 variants), bus width,
  HS_TIMING, PARTITION_CONFIG (active boot partition + currently
  accessed partition), BOOT/RPMB partition sizes (mult × 128 KiB),
  user-area capacity from SEC_COUNT, PRE_EOL_INFO + per-area life-
  time estimation. Builder for the SWITCH (CMD6) argument used to
  rewrite individual EXT_CSD bytes (Access=Write Byte).
- **SD protocol decoders** (`sd_proto`): pure parsers for R1, R6, R7
  responses; CID register (manufacturer + OEM + product name + serial
  + MDT); CSD register (both v1.0 and v2.0 capacity formulas + read /
  write block lengths). Driver-agnostic; covered by deterministic
  smoke tests independent of MMIO.

### Out of scope (deferred)
- ADMA2 scatter-gather descriptor table — bring-up uses PIO only.
- Multi-block CMD18 / CMD25 transfers with Auto-CMD12.
- High-Speed / DDR / SDR50 / SDR104 timing modes (need eMMC TUNING /
  card-status interrogation).
- eMMC EXT_CSD (JEDEC JESD84-B51) — landed when an eMMC fabric is
  exercised end-to-end.
