# ath11k — Specification

> Status: **v0.3** — PCI identify, power-up and the MHI host:
> firmware boots to mission mode and the IPCR channels start
> (offline-tested only). No control plane (QMI), no data path; no
> network interface is registered.
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

### 2.3 MHI host (`mhi.rs`, `mhi_host.rs`)

`mhi.rs` holds the wire definitions (`drivers/bus/mhi/common.h`,
`host/internal.h`, `include/linux/mhi.h`): register map, 44-byte
`#[repr(C, packed(4))]` channel / event / command contexts, 16-byte
ring elements, `mhi_ee_type` / `mhi_state` as raw newtypes, the PM
state bits + `dev_state_transitions[]`, and ath11k's QCA6390 /
WCN6855 controller config. `mhi_host.rs` ports the host controller
against an `MhiBus` trait (direct BAR0 like `ath11k_mhi_op_read_reg`,
MSI bits, sleep, time, randomness): context arrays + rings in DMA32
memory, `mhi_init_mmio`, `mhi_async_power_up` / `mhi_sync_power_up`,
FBC download (BHI of the first `sbl_size` bytes, then a BHIe vector
table for the image, skipping the SBL if a second ELF header
follows it), READY → M0 → SBL → AMSS, event-ring processing, the
command ring and `mhi_prepare_for_transfer` with QRTR's buffer policy
(63 pre-posted 8 KiB DL buffers, recycled on completion). Timeouts are
`MHI_TIMEOUT_DEFAULT_MS` = 20 s (`ath11k_mhi_start` overrides the
config's 2 s). One async task (`pci::mhi_task`) owns the controller;
every wait services the MHI interrupt work and also polls the event
rings each 25 ms slice, counting events that arrived without an MSI.
Not ported: RDDM, SYS_ERR recovery, power-down, M3 suspend/resume,
BW scaling, RSC/offload/client-managed rings, EDL.

## 3. Public interface

- `register()` — registers the three Linux PCI ids.
- `pci::probe` — identify, power up, spawn the MHI bring-up task.
- `pci::{read32, write32}` — Linux-equivalent register access.
- `pci::{is_probed, with_controller}` — bound-device inspection.
- `pci::{take_mhi, mhi_ready}` — the running MHI controller (IPCR
  started) for the QRTR layer.
- `mhi_host::MhiController::{queue_ul, take_dl, poll, wait_and_poll}`
  — IPCR UL send (`mhi_queue_skb(…, MHI_EOT)`) / DL receive.
- `narf_io::alloc_coherent_masked` (32-bit coherent mask) backs every
  MHI buffer.

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
| 1 | MSI vectors, power-up (`soc_global_reset`, LTSSM, L1SS / ASPM handling) (**done**) | `pci.c`, `pcic.c` |
| 2 | MHI host: context arrays, event rings, BHI SBL (512 KiB) + BHIe full image, EE/state machine to mission mode, IPCR ch 20/21 (**done**, offline) | `mhi.c`, `bus/mhi/host/*` |
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
- MHI diag steps: `mhi_host::step` (10–35) latch through
  `diag::latch_wifi_error`; the stage moves to `transport` at the
  first M0 and `fw-boot` at mission mode.
- Open: Linux prefers `firmware-2.bin` (an `amss.bin` IE) over
  `amss.bin` when present (`ath11k_fw_pre_init`); only `amss.bin` is
  loaded today.
- Firmware: `cargo xtask import-firmware --vendor ath11k`
  decompresses the distro `.zst` blobs at image build time. Open:
  whether probe runs before the rootfs firmware scan, i.e. whether
  the ath11k blobs must go in the initramfs (`--initramfs-firmware`).
