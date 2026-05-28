# rtw88 — Specification

> Status: **v0.1** (Stage 2 complete: RTL8822C IDDMA load).
>
> Realtek Wi-Fi 5 (802.11ac) driver for PCIe silicon
> (RTL8821CE / RTL8822CE). Adapted from Linux
> `drivers/net/wireless/realtek/rtw88/`.

## 1. Purpose & scope

**Owns:** Power-on and firmware loading for Realtek 11ac
parts. Advanced through Stage 2 (Firmware Loaded).

**Does NOT own:** Data path, H2C command set, or regulatory
compliance.

## 2. Hardware Interface

### 2.1 BARs
- **BAR0**: Register interface (MMIO).
- **BAR2**: TX buffer / Data window (used for firmware staging).

### 2.2 IDDMA (Internal Direct DMA)
Modern rtw88 chips (e.g., RTL8822C) use IDDMA to move firmware
from the TX buffer to internal MCU memory:
1. Host copies firmware blob to BAR2 (TX buffer).
2. Host programs `REG_DDMA_CH0SA` (Source: TX buffer).
3. Host programs `REG_DDMA_CH0DA` (Dest: IMEM/DMEM).
4. Host triggers transfer and polls for completion.

### 2.3 MCU Handshake
After loading, the driver sets `BIT_FW_DW_RDY` and polls
`REG_MCUFW_CTRL` for the ready mask.

## 3. Stage Progression

- **Stage 1**: PCI match table + EFUSE MAC read.
- **Stage 2**: Power-on sequence + IDDMA firmware loading.
- **Stage 3 (Planned)**: H2C command queue + INIT command.
- **Stage 4 (Planned)**: RX/TX fast path.

## 4. References

- Linux `drivers/net/wireless/realtek/rtw88/`
- Realtek RTL8822C public datasheet.
