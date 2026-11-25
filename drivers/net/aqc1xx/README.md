# narf-drivers-net-aqc1xx — Aquantia/Marvell AQC1xx (Atlantic) NIC family

Stage-2 driver for the AQC113 generation (`hw_atl2` in Linux's
`drivers/net/ethernet/aquantia/atlantic/`) and the older
AQC100/107/108/109/111/112 (`hw_atl` B1) and legacy D-series
(`hw_atl` A0/B0) generations: probe + firmware-boot handshake +
TX/RX rings + publication + carrier, fixture-validated against a
simulated device conversation. Only the silicon itself remains
untested.

## Scope

Registered PCI IDs (vendor `0x1D6A`, per Linux's `aq_pci_tbl` /
`hw_atl_boards`):

- `hw_atl2` (AQC113 generation): AQC113DEV `0x00C0`, AQC113
  `0x04C0`, AQC116C `0x11C0`, AQC115C `0x12C0`, AQC113C `0x14C0`,
  AQC113CA `0x34C0`, AQC114CS `0x93C0`, AQC113CS `0x94C0`.
- `hw_atl` B1: AQC100 `0x00B1`, AQC107 `0x07B1`, AQC108 `0x08B1`,
  AQC109 `0x09B1`, AQC111 `0x11B1`, AQC112 `0x12B1`, plus the S
  variants `0x80B1`, `0x87B1`, `0x88B1`, `0x89B1`, `0x91B1`,
  `0x92B1`.
- `hw_atl` A0/B0 (legacy D-series): `0x0001`, D100 `0xD100`,
  D107 `0xD107`, D108 `0xD108`, D109 `0xD109`. The backend (A0/B0/B1)
  is selected at runtime from the MIF ID register, not the PCI
  revision, and the firmware generation (FW1x/FW2x) from the MPI
  firmware version word.

## Reference

Linux `drivers/net/ethernet/aquantia/atlantic/` (GPL-2.0; NARF is
GPL-2.0-or-later, so adaptation is permitted), reference tree
`~/workspace/scratch/ethernet/linux-atlantic` @ `4dce97c6`:

- `atlantic/aq_common.h` — PCI IDs, `AQ_NIC_RATE_*` bits.
- `atlantic/aq_pci_func.c` — `aq_pci_tbl`, `hw_atl_boards`,
  first-MEM-BAR scan.
- `atlantic/hw_atl2/hw_atl2_utils.c` — `hw_atl2_utils_soft_reset`
  (MIF boot handshake).
- `atlantic/hw_atl2/hw_atl2_utils_fw.c` — shared-buffer mailbox
  (`fw_interface_in` / `fw_interface_out`), link status, MAC,
  `aq_a2_fw_set_link_speed`.
- `atlantic/hw_atl2/hw_atl2_utils.h` — `link_status_s`,
  `filter_caps_s`, `fw_interface_in` / `fw_interface_out` layout.
- `atlantic/hw_atl2/hw_atl2.c` — `hw_atl2_hw_init` (TX/RX path,
  MAC filter, MPI_INIT, IRQ global control), `hw_atl2_caps_aqc113`.
- `atlantic/hw_atl/hw_atl_b0.c` — ring init/start, TX xmit, RX
  receive/fill (reused by `hw_atl2`).
- `atlantic/hw_atl/hw_atl_utils.h` — `hw_atl_txd_s` /
  `hw_atl_rxd_s` / `hw_atl_rxd_wb_s` descriptor structs.
- `atlantic/hw_atl/hw_atl_llh_internal.h` and
  `atlantic/hw_atl2/hw_atl2_llh_internal.h` — register addresses
  and bitfields.
- `atlantic/aq_cfg.h` — defaults (TXDS 4096, RXDS 2048, MTU 1514,
  TX frame max 16 KiB, RX frame max 2 KiB).

## Deliberate asymmetries

- Single queue pair (queue 0) + one MSI-X vector; Linux defaults
  to 8 vectors / 4 TX + 4 RX rings. RSS stays off.
- RX VLAN stripping stays OFF (no VLAN-tag field in
  `Frame::rx_meta`); TX VLAN insertion is not programmed.
- No TX/RX checksum offload or TSO/LSO yet (descriptor context
  words exist in the spec; the datapath uses plain frames).
- `downshift` is 0 (disabled) in the firmware `link_options`;
  Linux programs a downshift counter from its netdev config.
- The driver maps BAR0; Linux scans BARs 0..3 for the first MEM
  BAR. BAR0 is the MMIO BAR on AQC113 hardware.
- TX completion is the descriptor-DD writeback poll (Atlantic has
  no OWN bit); the polled `transmit` waits for DD with a deadline.
- RX buffers are 2048 bytes (Linux's `AQ_CFG_RX_FRAME_MAX`); a
  frame larger than one buffer spans descriptors and is dropped
  (multi-descriptor RX chaining is a remainder).
