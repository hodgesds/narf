# iwlwifi — Specification

> Status: **v0.3** (Stage 3 complete: CSR map + APM init + ucode
> header decode + firmware-load + ALIVE handshake).
>
> GPL-2.0-or-later driver for Intel Wi-Fi 6 / 6E PCIe host
> controllers (AX200 / AX201 / AX210 / AX211 / AX411 + Killer 1690).
> Adapted directly from Linux `drivers/net/wireless/intel/iwlwifi/`
> source.

## 1. Purpose & scope

**Owns:** Bring-up of Intel AX2xx-class Wi-Fi 6 / 6E radios
attached over PCIe. Advanced through Stage 3 (ALIVE state).

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

### 2.3 Firmware Loading
- **Gen2 (AX200/AX201)**: Uses the FH (Flow Handler) DMA
  engine to push ucode sections to device SRAM.
- **Gen3 (AX210/AX211/AX411)**: Uses Context Info V2 + IML
  (Intermediate Microcode Loader) for ROM-assisted boot.

### 2.4 ALIVE Handshake
The driver polls for the `ALIVE` notification (Status `0xCAFE`)
after releasing the device CPU. Reached successfully on all
supported families.

## 3. Stage Progression

- **Stage 1**: PCI match table.
- **Stage 2**: CSR/PRPH mapping + APM init + ucode header parsing.
- **Stage 3**: Firmware loading (Gen2/Gen3) + ALIVE handshake.
- **Stage 4 (Planned)**: Scan, associate, and key installation.
- **Stage 5 (Planned)**: TX/RX fast path integration.

## 4. References

- Linux `drivers/net/wireless/intel/iwlwifi/`
- Intel product briefs for AX200, AX210, etc.
- IEEE Std 802.11-2020.
