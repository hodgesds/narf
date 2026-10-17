# ath11k — Specification

> Status: **v0.2** — PCI identify only. No firmware boot, no
> control plane, no data path; no network interface is registered.
>
> Qualcomm ath11k Wi-Fi 6 / 6E driver for PCIe host-attached
> silicon (QCA6390 / WCN6855 / QCN9074). Adapted from Linux
> `drivers/net/wireless/ath/ath11k/` (BSD-3-Clause-Clear) and
> `drivers/bus/mhi/host/`, `net/qrtr/`, `drivers/soc/qcom/qmi_*`.

## 1. Purpose & scope

**Owns:** station-mode bring-up of PCIe ath11k parts, first target
the WCN6855 HW2.1 in Lenovo's QCNFA765 module (`17cb:1103`,
subsystem `17aa:9309`).

**Does NOT own:** AHB/SoC-integrated parts (IPQ*, WCN6750), AP /
mesh / monitor modes, ath12k parts (WCN7850 `17cb:1107`, QCN9274
`17cb:1109`).

## 2. Hardware interface

### 2.1 Register access (`pci.rs`)

Offsets below `ATH11K_PCI_WINDOW_START` (`0x80000`) are direct BAR0
accesses. Higher offsets go through the sliding window: write
`ENABLE_BIT | FIELD_GET(GENMASK(24,19), off)` to BAR0+`0x310c`, read
it back, then access BAR0 + `0x80000` + `(off & GENMASK(18,0))`.
Select + access are serialised under one lock with the current
window cached (Linux `ath11k_pci_select_window`). WCN6855 / QCA6390
use the dynamic window; QCN9074 uses a static map (not implemented).

### 2.2 hw_rev (`hw.rs`)

`TCSR_SOC_HW_VERSION` (`0x224`) major/minor, plus
`TCSR_SOC_HW_SUB_VER` (`0x1910010`) for WCN6855 minor `0x10`/`0x11`,
resolve to `HwRev` exactly as Linux `ath11k_pci_probe`: WCN6855
HW2.0 / HW2.1, QCA2066 HW2.1, QCA6698AQ HW2.1. Unsupported steppings
fail probe. `HwRev::fw_dir()` = Linux `hw_params.fw.dir`.

## 3. Public interface

- `register()` — registers the three Linux PCI ids.
- `pci::probe` — identify + log `hw_rev` and firmware dir.
- `pci::{read32, write32}` — Linux-equivalent register access.
- `pci::{is_probed, with_controller}` — bound-device inspection.

Phase 3 groundwork — pure codecs, no MMIO, not yet wired to MHI:

- `qmi` — QMI wire codec equivalent to `soc/qcom/qmi_encdec.c`:
  `QmiHeader` (7-byte packed header), `encode_message` /
  `split_message`, `TlvWriter` + `StructWriter` (encode, enforces
  `*_MAX_LEN` and ei array/string bounds), `decode_tlvs` +
  `StructReader` + `tlv_*` helpers (decode: unknown TLV `>= 0x10`
  skipped, `< 0x10` refused; struct members past the end of a
  struct TLV read as zero, like Linux), `QmiResponse`
  (`qmi_response_type_v01`), `QmiError`. Stricter than Linux only
  where Linux over-reads or desynchronises (truncated TLV, basic
  TLV length ≠ element size) and on a missing mandatory TLV.
- `qmi_wlfw` — the WLFW (service `0x45`) messages ath11k uses,
  byte-identical to the `qmi.c` ei tables: `HostCapReq`,
  `IndRegisterReq`/`Resp`, `RequestMemInd`, `RespondMemReq`,
  `CapReq`/`CapResp` (+ `TargetInfo`), `BdfDownloadReq`
  (+ `bdf_segments`, `bdf_eeprom_request`, `bdf_type_for`),
  `M3InfoReq`, `WlanIniReq`, `WlanCfgReq` (+ the QCA6390/WCN6855
  target CE and service maps), `WlanModeReq`, `DeviceInfoReq`/`Resp`,
  the resp-only responses, and `decode_indication` for
  REQUEST_MEM / FW_MEM_READY / FW_READY / COLD_BOOT_CAL_DONE /
  FW_INIT_DONE. Traits `WlfwRequest` (`encode(txn_id)`) and
  `WlfwMessage` (`decode`, checks header type + msg_id).
  `wlfw_hw_params(HwRev)` = the `ath11k_hw_params` fields QMI reads;
  `*::ath11k(..)` constructors set exactly the fields the matching
  `ath11k_qmi_*_send` sets.
- `qrtr` — QRTR v1 framing for MHI channels 20/21: `encode_packet`
  (`qrtr_node_enqueue`, 4-byte zero padding), `decode_packet`
  (`qrtr_endpoint_post` validation, v1 + v2 headers), `CtrlPkt`
  (`qrtr_ctrl_pkt`), and `QrtrLink`, a frame-in/frame-out model of
  the host name service for one endpoint: answers the remote HELLO,
  learns NEW_SERVER / DEL_SERVER / BYE / DEL_CLIENT, matches
  registered lookups (`qmi_instance(version, instance)`), frames
  DATA with Linux's `confirm_rx` / RESUME_TX flow control.

Tests: `qmi_tests.rs` (arch-neutral). WLFW golden vectors were
produced by running Linux's own `qmi_encdec.c` on the ath11k ei
tables.

## 4. Invariants

- The PCI table is exactly Linux's `ath11k_pci_id_table`.
- The driver never reports a wireless capability it does not have:
  no interface is registered until scan + connect + data work.

## 5. Bring-up roadmap (WCN6855 HW2.1 first)

Each phase lands as its own commit with offline tests; the real
card (QEMU emulates none) is exercised once, after phase 8.

| # | Phase | Linux source |
|---|---|---|
| 0 | PCI identify, correct register access (**done**) | `pci.c`, `pcic.c` |
| 1 | MSI vectors, power-up (`soc_global_reset`, LTSSM, L1SS / ASPM handling) | `pci.c`, `pcic.c` |
| 2 | MHI host: context arrays, event rings, BHI SBL (512 KiB) + BHIe full image, EE/state machine to mission mode, IPCR ch 20/21 | `mhi.c`, `bus/mhi/host/*` |
| 3 | QRTR over MHI + QMI encode/decode; WLFW handshake: host cap, ind register, respond mem, target cap, BDF (`board-2.bin` by bus/qmi-chip-id/board-id), M3 (`m3.bin`), regdb, wlan cfg, mode ON | `qmi.c`, `net/qrtr`, `soc/qcom/qmi_*` |
| 4 | Copy Engines + HTC + WMI: service ready, init, ready; MAC from firmware | `ce.c`, `htc.c`, `wmi.c` |
| 5 | HAL SRNG + DP rings (TCL, REO, WBM, RXDMA refill) | `hal*.c`, `dp.c` |
| 6 | Control: pdev/vdev, regulatory, scan → `BssInfo` list | `mac.c`, `wmi.c`, `reg.c` |
| 7 | Connect: peer, auth/assoc via mgmt TX, EAPOL via `narf-wireless` supplicant, key install | `mac.c`, `wmi.c` |
| 8 | Data path: TX (TCL → WBM completion), RX (REO dst → `Frame`); register `wlan%d` | `dp_tx.c`, `dp_rx.c` |
| 9 | Power: PS, suspend/resume, firmware crash recovery | `core.c`, `mac.c` |

## 6. Dependencies

`narf-bus` (BAR, MSI), `narf-io` (coherent DMA), `narf-firmware`
(`amss.bin`, `m3.bin`, `board-2.bin`, `regdb.bin` — distro packages
ship them `.zst`-compressed), `narf-wireless` (iface trait, EAPOL /
SAE, registry), `narf-net` (frame rings).

## 7. Stage assignment

Stage 5 "Silicon" — real-HW Wi-Fi on the bring-up laptops.

## 8. Open questions

- Test loop (decided): phases land with offline tests only; one
  full hardware bring-up at the end by booting NARF bare-metal on
  the QCNFA765 laptop (`docs/BOOTING_ON_CACHYOS.md`). No serial
  there, so every bring-up stage reports to a pinned framebuffer
  status line as well as the console.
- Firmware: `cargo xtask import-firmware --vendor ath11k`
  decompresses the distro `.zst` blobs at image build time. Open:
  whether probe runs before the rootfs firmware scan, i.e. whether
  the ath11k blobs must go in the initramfs (`--initramfs-firmware`).
