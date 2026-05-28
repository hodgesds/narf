# ath11k — Specification

> Status: **v0.1** (Stage 2 complete: MHI init + AMSS load).
>
> Qualcomm ath11k Wi-Fi 6 / 6E driver for PCIe host-attached
> silicon (QCA6390 / WCN6855 / QCN9074). Adapted from Linux
> `drivers/net/wireless/ath/ath11k/`.

## 1. Purpose & scope

**Owns:** Bring-up of Qualcomm 11ax silicon using the MHI
(Modem Host Interface) protocol. Advanced through Stage 2
(Mission Mode reached).

**Does NOT own:** WMI command set, data path, or management
plane.

## 2. Hardware Interface

### 2.1 BAR0 Layout
BAR0 contains the MHI register block at an offset (identified
via the `BHIOFF` register at `0x28`).

### 2.2 MHI (Modem Host Interface)
The chip is driven by a state machine:
- **READY**: Chip PBL is waiting for firmware.
- **M0**: Mission Mode (active).

### 2.3 BHI (Boot Host Interface)
Used for primary firmware staging:
1. Host stages `amss.bin` in DMA-coherent memory.
2. Host programs BHI `IMGADDR` / `IMGSIZE`.
3. Host rings `IMGTXDB` doorbell.
4. Chip bootloader validates and jumps to firmware.

## 3. Stage Progression

- **Stage 1**: PCI match table + BAR0 mapping.
- **Stage 2**: MHI initialization + BHI firmware loading (M0 reached).
- **Stage 3 (Planned)**: Channel / Event ring initialization.
- **Stage 4 (Planned)**: WMI handshake.

## 4. References

- Linux `drivers/net/wireless/ath/ath11k/`
- Qualcomm MHI Specification.
