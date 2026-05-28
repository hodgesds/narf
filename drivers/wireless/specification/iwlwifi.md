# iwlwifi — Specification

> Status: **v0.4** (Stage 4 baseline: Interface traits + background
> pumps + hardware ring initialization + scan scaffold).
>
> GPL-2.0-or-later driver for Intel Wi-Fi 6 / 6E PCIe host
> controllers (AX200 / AX201 / AX210 / AX211 / AX411 + Killer 1690).
> Adapted directly from Linux `drivers/net/wireless/intel/iwlwifi/`
> source.

## 1. Purpose & scope

**Owns:** Bring-up and operational control of Intel AX2xx-class
radios. Implements `narf_net::Interface` and
`narf_wireless::WirelessNetIface`.

**Does NOT own (any stage):** mac80211-equivalent stack,
802.11 frame parsing/building (lives in `narf_net`), regulatory
domain handling.

## 2. Hardware Interface

### 2.1 CSR (Control / Status Registers)
Directly mapped at the base of BAR0. Used for device reset,
interrupt masking, and gating firmware loading.

### 2.2 PRPH (Peripheral Window)
Indirect access via `HBUS_TARG_PRPH_WADDR` / `_RDAT` / `_WDAT`.
Reaches the internal peripheral register file.

### 2.3 DMA Rings
- **RX**: Single descriptor ring (RXB) mapped in coherent host
  RAM. Drain is managed by the `iwl_rx_pump` task.
- **TX**: Multiple scheduler rings. Queue 0 used for management
  commands and background `iwl_tx_pump`.

### 2.4 Host Commands (HCMD)
Communication with the firmware uses a Group-Command-Version
addressing scheme. Commands (e.g., `SCAN_REQ_UMAC`) are enqueued
as TFDs with a specific command header.

### 2.5 ALIVE Handshake
The driver polls for the `ALIVE` notification (Status `0xCAFE`)
after releasing the device CPU. Reached successfully on all
supported families.

## 3. Stage Progression

- **Stage 1**: PCI match table.
- **Stage 2**: CSR/PRPH mapping + APM init + ucode header parsing.
- **Stage 3**: Firmware loading (Gen2/Gen3) + ALIVE handshake.
- **Stage 4**: Interface traits, IPC ring integration, background
  RX/TX pumps, and scan/association skeletons.
- **Stage 5 (Planned)**: Full 802.11 data path + scan parsing.

## 4. References

- Linux `drivers/net/wireless/intel/iwlwifi/`
- Intel product briefs for AX200, AX210, etc.
- IEEE Std 802.11-2020.
