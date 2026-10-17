# ath11k — Specification

> Status: **v0.5** — PCI identify, power-up, the MHI host (firmware
> to mission mode, IPCR started), the WLFW QMI handshake over QRTR to
> FW_READY, and the core bring-up (QMI firmware start, CE, HTC, WMI
> service ready → INIT → READY with the device MAC) — offline-tested
> only. No data path; no network interface is registered.
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
- `pci::mhi_ready` — MHI reached mission mode with IPCR running.
- After FW_READY the MHI task hands the [`wlfw::Wlfw`] session (owns
  the MHI controller, target memory, M3 image) to
  `core::pci_start` (§3.6); `pci::aspm_restore` is its
  `ath11k_pci_start` ASPM step.
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
  struct TLV read as zero, like Linux; a missing mandatory TLV
  leaves its default, like Linux), `QmiResponse`
  (`qmi_response_type_v01`), `QmiError`. Stricter than Linux only
  where Linux over-reads or desynchronises (truncated TLV, basic
  TLV length ≠ element size).
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

### 3.0 QRTR endpoint, QMI client, WLFW handshake

- `qmi_client` — `QrtrPipe` (one QRTR packet per MHI transfer:
  `send` / `poll` / `recv` / `wait` / `now_ms` / `log`; implemented by
  `MhiController` over IPCR UL/DL) and `QmiClient<P>`: a `QrtrLink`
  (local node 1) plus the ath11k QMI handle — client port
  `QRTR_MIN_EPH_SOCKET` (0x4000), `add_lookup` (local NEW_LOOKUP
  only), `pump` (DL frames → link; link replies HELLO / RESUME_TX →
  UL; DATA to the client port → the waiting transaction or the
  inbound queue), `request::<Req, Resp>(req, timeout)` =
  `qmi_txn_init` (ids from 0, cyclic to 65534) + send (waits on QRTR
  flow control) + `qmi_txn_wait` (match by `txn_id` only, decode with
  the transaction's decoder), `wait_inbound`, `take_inbound`
  (`ServerArrive` / `ServerExit` / indication bytes).
- `wlfw` — `Wlfw<P, F: FirmwareLoader, A: DmaAllocator>`, the
  `ath11k_qmi_driver_event_work` machine: `run_to_fw_ready()` (lookup
  0x45 v1 ins `qmi_service_ins_id`; SERVER_ARRIVE → ind_register +
  host_cap; REQUEST_MEM callback → `alloc_target_mem_chunk` (reuse,
  ≤ 5-segment delayed path) → `respond_fw_mem_request`; FW_MEM_READY →
  target_cap → regdb (`supports_regdb`, result ignored) → board data
  (+ caldata for a BIN board) → `m3_info`; FW_READY / FW_INIT_DONE →
  `FwReadyInfo`), and `firmware_start(mode, shadow_reg_v2)` =
  wlan_ini (`fw_wmi_diag_event`) → wlan_cfg (QCA6390 CE + service
  maps, shadow v2 clamped to 36) → wlan_mode. `WlfwConfig::pci(..)`
  carries `ab->id`, `dev_name` (caldata name) and the timeouts.
  Kernel impls: `NarfFirmware` (`narf_firmware::open`, no retry —
  `amss.bin` already proved the store is up), `Dma32`
  (`alloc_coherent_masked`, 32-bit mask). `step::*` (40–63) name every
  failure; request failures carry `detail = kind << 16 | value`.
- `board` — `board_name` (`__ath11k_core_create_board_name`, `%d`
  ids, 199-byte cap, 40-byte variant), `bdf_search` / `regdb_search`
  (Linux's fallback order), `fetch_board_data_api_n` (`board-2.bin`
  magic + IE walk, Linux's never-reset name match and `-EINVAL` /
  `-ENODATA` cases), `smbios_bdf_ext` (type 0xF8 decoder:
  `ath11k_core_check_cc_code_bdfext`), `check_smbios_in(&RawTable)` /
  `check_smbios()` (`ath11k_core_check_smbios`: `dmi_walk` over the
  table `firmware/smbios` retained at boot; empty = `-ENODATA`),
  `build_board2` (test fixtures). `pci::wlfw_bring_up` passes
  `check_smbios().bdf_ext` into `WlfwConfig::pci`, so the full board
  name carries `,variant=<v>` exactly as `__ath11k_core_create_board_name`.

Tests: `qmi_handshake_tests.rs` — a scripted fake WLFW firmware
behind a fake pipe runs HELLO → FW_READY → `firmware_start`, every
request compared byte for byte (encoders + inlined Linux goldens);
board parser / names / SMBIOS; target memory with fake and real
DMA32 allocators; negatives for every step.

### 3.1 HTC (`htc.rs`, Linux `htc.{c,h}`)

Pure state machine, no MMIO: frames in, `HtcTx { pipe, eid,
credits, frame }` out.

- `HtcHdr` (8-byte `ath11k_htc_hdr`), control-message encoders /
  parsers (READY, CONNECT_SERVICE[_RESP], SETUP_COMPLETE_EX, credit
  trailer records), `svc_id::*`, `conn_flags::*`, `msg_id::*`.
- `Htc::{init, send, revert_credits, rx, wait_target,
  connect_service_request, connect_service_complete, start}` — one
  method per Linux step; per-endpoint TX credits charged as
  `DIV_ROUND_UP(len, target_credit_size)` and replenished from
  `ATH11K_HTC_RECORD_CREDITS` trailers.
- `HtcHandshake` — `ath11k_core_start`'s HTC order: READY → connect
  HTT_DATA_MSG → connect WMI_CONTROL (×`wmi_ep_count`) →
  SETUP_COMPLETE_EX. `HtcConfig::wcn6855()` = credit flow on,
  shadow regs (1 total credit), one WMI endpoint.
- `TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390` (14 entries, hw.c) +
  `map_service_to_pipe`; shared with the QMI WLAN-config request
  (`ServiceToPipe::to_le_bytes`).

### 3.2 WMI (`wmi.rs`, `wmi_ids.rs`, Linux `wmi.{c,h}`)

- `wmi_ids.rs`: every `wmi_cmd_group` / `wmi_tlv_cmd_id` /
  `wmi_tlv_event_id` / `wmi_tlv_tag` / `wmi_tlv_service` /
  pdev / vdev parameter value, generated from the Linux enums
  (compiler-evaluated); re-exported by `wmi`.
- Encoders return `WmiCmd { cmd_id, buf }` byte-identical to the
  Linux builder's `skb->data`; `WmiCmd::frame()` adds `wmi_cmd_hdr`.
  INIT (`TargetResourceConfig::qca6390`, host mem chunks, hw mode),
  SET_HW_MODE, PDEV_SET_PARAM / SET_REGDOMAIN / GET_TEMPERATURE,
  SET_CURRENT_COUNTRY, SET_INIT_COUNTRY, 11D_SCAN_START/STOP,
  VDEV_CREATE/DELETE/START/RESTART/UP/STOP/DOWN/SET_PARAM/INSTALL_KEY,
  PEER_CREATE/DELETE/SET_PARAM/ASSOC, START_SCAN (+
  `ScanReqParams::start_scan_init`), STOP_SCAN, SCAN_CHAN_LIST
  (split by `max_msg_len`), MGMT_TX_SEND, STA_POWERSAVE_MODE/PARAM.
- Decoders: `tlv_iter` / `TlvTable` (`ath11k_wmi_tlv_iter` +
  `wmi_tlv_policies[]`), `decode_event` → `WmiEvent`; SERVICE_READY,
  SERVICE_AVAILABLE (`ServiceMap`), SERVICE_READY_EXT/EXT2, READY
  (device MAC), REG_CHAN_LIST_CC[_EXT], VDEV_START_RESP,
  VDEV_STOPPED, VDEV/PEER_DELETE_RESP, PEER_ASSOC_CONF,
  INSTALL_KEY_COMPLETE, PEER_STA_KICKOUT, SCAN, MGMT_RX (+
  `rx_status()`), MGMT_TX_COMPLETION, ROAM, PDEV_TEMPERATURE. Where
  Linux reads past a TLV unchecked, NARF rejects ("NARF-stricter" in
  the source).

### 3.3 HAL SRNG (`hal.rs`, Linux `hal.{c,h}`)

Register I/O through `power::ChipIo` (`ath11k_hif_read32/write32`:
SRNG R0/R2 blocks are windowed, shadow registers direct). Units are
Linux's: entry size / ring size / HP / TP in 32-bit words.

- `hw::HalRegs` (`qca6390_regs`, `wcn6855_regs`), `HwParams::{regs,
  host_ce_config, supports_shadow_regs, credit_flow, ring_mask}`,
  `hw::RING_MASK_QCA6390`, `hw::HW_HAL_PARAMS_QCA6390`.
- `HalRingType` (21 types), `ring_id::*`, `SRNG_CONFIG_TEMPLATE`
  (`hw_srng_config_template`), `create_config(&HalRegs)`,
  `get_ring_id`, `RingRegOffsets` (the `*_OFFSET(ab)` macros).
- `Hal::new(&HwParams)` = `ath11k_hal_srng_init` (rdp / wrp in DMA32)
  plus the probe-time shadow assignment; `Hal::srng_setup(io, type,
  ring_num, mac_id, SrngParams)` = `ath11k_hal_srng_setup` with
  `src_hw_init` / `dst_hw_init` / `ce_dst_setup` (takes ownership of the
  ring memory, returns the ring id).
- Access: `access_begin`, `access_end`, `src_get_next_entry`,
  `src_reap_next`, `src_get_next_reaped`, `src_peek`, `src_next_peek`,
  `dst_get_next_entry`, `dst_peek`, `src_num_free`, `dst_num_free`,
  `desc_rd` / `desc_wr` (entries are word offsets into the ring),
  `get_hp_addr` / `get_tp_addr` (LMAC), `shadow_update_hp_tp`.
- CE descriptors: `HalCeSrngSrcDesc` / `DestDesc` / `DstStatusDesc`
  (16 / 8 / 16 B), `ce_src_desc_words`, `ce_dst_desc_words`,
  `Hal::ce_{src,dst}_set_desc`, `Hal::ce_dst_status_get_length`
  (reads and clears the length, as Linux).
- **Shadow register v2 list for QMI `WLAN_CFG`:**
  `hal::shadow_reg_v2(&HwParams) -> Option<ShadowConfig>`;
  `ShadowConfig::as_slice()` is `wlfw_wlan_cfg_req.shadow_reg_v2[]`
  (`None` ⇒ `shadow_reg_v2_valid = 0`). Same order as Linux
  `ath11k_ce_get_shadow_config`: non-CE non-LMAC rings by type then
  ring number, then per CE src / dst / dst-status; each entry is the
  ring's HP register (SRC) or TP register (= HP + 4, DST). Shadow
  register *n* is BAR0 `hal_shadow_base_addr + 4n` (`shadow_reg`).
  WCN6855 (all HW2.x family parts) yields 30 entries:
  `a3b034 a3b03c a3b044 a3b04c a3b064 a3b028 a3b020 a3b07c a46000
  a46008 a46010 a46018 a46034 a370b0 a37018 a370c4 a370cc a370d4
  a370dc a370e4 1b80400 1b83400 1b8340c 1b85400 1b8540c 1b86400
  1b88400 1b8b400 1b8b40c 1b8e400` (pinned in `hal_tests.rs` as
  `WCN6855_SHADOW_REG_V2`). `Hal`/`Ce` use exactly this list, so the
  firmware and the host agree on which shadow register mirrors which
  ring.
- `TransportError { step, detail, errno }` + `report()` (latch +
  console line). Steps: HAL 80–88, CE 90–101 (`hal::step`,
  `ce::step`).

### 3.4 Copy Engines (`ce.rs`, Linux `ce.{c,h}`, `pcic.c` CE part)

- `CeAttr`, `HOST_CE_CONFIG_QCA6390` (9 CEs), `HOST_CE_CONFIG_QCN9074`.
- `Ce::alloc(&HwParams, CeMsi, clock)` (HAL init + `ath11k_ce_alloc_pipes`
  + shadow config), `Ce::shadow_reg_v2()`, `Ce::init_pipes(io)`,
  `Ce::start(io)` (CE IRQs on + `ath11k_ce_rx_post_buf`), `Ce::stop()`.
- `Ce::send(io, pipe, &[u8], transfer_id)` = `ath11k_ce_send` (copies
  into the slot's DMA32 bounce buffer); `Ce::take_rx(pipe)` /
  `take_rx_any()` / `rx_pending(pipe)`; `Ce::take_tx_done(pipe)` (only
  without credit flow).
- Completion: `Ce::per_engine_service(io, ce)`; `Ce::service(io,
  pending_mask)` = the pending CEs, a poll of every other
  interrupt-enabled CE (`CeStats::polled_without_irq`), CE4's shadow HP
  refresh timer and the RX replenish retry; `Ce::wait_and_service` and
  `Ce::recv(io, irq, pipe, slice_ms, timeout_ms)` (async RX stream)
  over a `CeIrq` (`MsiCeIrq` on hardware).
- MSI: `ce_msi_idx`, `ce_ring_msi` (ring MSI address/data),
  `ce_irq_vector` (`(idx % n) + base_vector` of the "CE" user),
  `ce_vector_cookie`, `install_ce_irq_handlers` (adds a handler on the
  CE vectors, no `pci.rs` change), `set_ce_irqs_enabled`
  (`ATH11K_FLAG_CE_IRQ_ENABLED`). On PCI there is no CE interrupt
  enable register (`CE_HOST_IE_*` is AHB-only).

### 3.5 DP descriptor layouts (`dp.rs`)

Layouts only (runtime is phase 5): `BufferAddr`, `HalTlvHdr`,
`RxMpduDesc`, `RxMsduDesc`, `HalReoDestRing` (64 B),
`HalReoEntranceRing` (32), `HalTclDataCmd` (28; ring entry = TLV +
28), `HalTclStatusRing` (32), `HalWbmReleaseRing` (32),
`HalWbmLinkDesc` / `HalWbmBufferRing` (8), `HalRxDescWcn6855` (392,
`hal_desc_sz`) with the `ath11k_hw_wcn6855_rx_desc_*` accessors, the
`dp.h` ring sizes. Sizes and offsets are `const` assertions against
`sizeof` / `offsetof` of the Linux structs.

Tests: `hal_tests.rs`, `ce_tests.rs` (x86_64 kernel tests). The CE
tests drive a fake chip that only knows what the host programmed
(ring bases, sizes, pointer addresses, shadow mirroring) and moves data
through the real DMA32 ring memory.

### 3.6 Core bring-up (`core.rs`, Linux `core.c`)

`Ath11kCore<H: Hif, Q: QmiFw>` = `struct ath11k_base` for the bring-up:
the transport, the QMI session, `Htc`, the HTT / WMI endpoints
(`HtcConnected`), `preferred_hw_mode`, `target_caps` (SERVICE_READY),
`svc_map` (SERVICE_READY + SERVICE_AVAILABLE), `svc_ext`
(`ServiceReadyExt`: hw modes, MAC/PHY caps, per-pdev band / HT / VHT /
HE caps for the mac layer, HAL reg caps), `dma_ring_caps`, `ready` +
`mac_addr` (WMI READY), `reg_info` (latest REG_CHAN_LIST_CC[_EXT]),
`seen` bits, `state` (`Idle` / `Ready` / `Failed(err)`), `stats`.

- `Hif` — `shadow_reg_v2`, `init_pipes`, `start` (`ath11k_hif_start`),
  `stop`, `send(pipe, frame, transfer_id = eid)`, `take_rx`,
  `recv_kind(pipe)` (the CE's `recv_cb`: HTC, or HTT T2H for CE5),
  `poll_all`, async `wait(ms)`, `now_ms`. `CeHif<Io, Irq>` is the real
  one over `Ce` (`on_start` = `pci::aspm_restore`); `Bar0` is BAR0 as an
  owned `ChipIo`.
- `QmiFw` — `firmware_start(mode, shadow)` / `firmware_stop()` (wlan_mode
  OFF); implemented by `wlfw::Wlfw`.
- `CoreHooks<H, Q>` — the DP phase's insertion points in Linux's order,
  all default no-ops (`NoDp`): `dp_alloc` (after `init_pipes`),
  `pdev_reo_setup` (after service ready, before INIT), async
  `htt_ver_req` (last step of `ath11k_core_start`), async `pdev_create`,
  `irq_enable`.
- `CoreConfig::for_hw(&HwParams)` (QCA6390 + WCN6855 family; QCN9074
  `None`): `single_pdev_only`, `num_rxdma_per_pdev = 2`, `max_radios =
  3`, `num_vdevs = 3`, credit flow, shadow regs, Linux timeouts (HTC
  1 s, connect 1 s, service / unified ready 5 s, WMI send 3 s).
- `Ath11kCore::new` (`ath11k_wmi_attach` + `ath11k_htc_init`),
  `qmi_firmware_ready(&mut hooks)` (the whole sequence below), and the
  pieces: `htc_wait_target`, `htt_connect`, `wmi_connect`, `htc_start`,
  `wait_for_service_ready`, `init_cmd`, `wait_for_unified_ready`.
- Runtime API for the next phases: `wmi_cmd_send(&WmiCmd)`
  (`ath11k_wmi_cmd_send`: waits ≤ 3 s for credits), `wait_event(id,
  timeout)`, `wmi_cmd_wait(cmd, id, timeout)`, `next_event(timeout)`,
  `take_event`, `queued_event_ids`, `pump(ms)`, `drain_rx`;
  `htt_send(payload)`, `take_htt`, `wait_htt(timeout)`. Queued events
  are `WmiRx { id, frame }` (`frame` keeps `wmi_cmd_hdr`, so
  `wmi::decode_event(&frame)` applies); queues hold 512, oldest dropped.
- WMI RX is `ath11k_wmi_tlv_op_rx`: SERVICE_READY / AVAILABLE / EXT /
  EXT2 / READY / REG_CHAN_LIST update the core (REG is queued too);
  everything else is queued. HTC frames for an endpoint nobody owns, and
  malformed frames, are counted and dropped like Linux.
- `pci_start(Wlfw)` (from `pci::mhi_task`): `Ce::alloc` +
  `install_ce_irq_handlers` with the probe's MSI state (Linux does both
  at probe), then `qmi_firmware_ready(&mut NoDp)`; the core is parked
  ready or failed. `take_core()` (only when ready), `park_core`,
  `core_ready`, `core_failure`. A session the core cannot start on is
  parked too: the firmware owns its target memory.
- Steps (`core::step`, 120–139): UNSUPPORTED 120, NO_DEVICE 121,
  HTC_INIT 122, HTC_READY_TIMEOUT 123, HTC_BAD_READY 124, HTT_CONNECT
  125, HTT_CONNECT_TIMEOUT 126, WMI_CONNECT 127, WMI_CONNECT_TIMEOUT
  128, HTC_START 129, SERVICE_READY_TIMEOUT 130 (detail = `seen` bits),
  SERVICE_READY_DECODE 131 (event id << 16 | errno), WMI_INIT 132,
  WMI_SEND_CREDITS 133 / WMI_SEND 134 (detail = command id), READY_TIMEOUT
  135, READY_DECODE 136, NO_WMI_EP 137, EVENT_TIMEOUT 138 (API only,
  never latched), HTT_SEND 139. HTC failure details are
  `kind << 16 | value` (`htc_err_detail`). QMI start failures latch the
  `wlfw::step` (58–60); CE failures their `ce::step`. The stage moves to
  `commands` when WMI READY arrives.

Linux order implemented (`core.c`): `ath11k_core_qmi_firmware_ready` →
`ath11k_core_start_firmware` (`ath11k_ce_get_shadow_config`,
`ath11k_qmi_firmware_start`: wlan_ini → wlan_cfg → wlan_mode NORMAL) →
`ath11k_ce_init_pipes` → `ath11k_dp_alloc` (hook) → `ath11k_core_start`
[`ath11k_wmi_attach` (preferred SINGLE) → `ath11k_htc_init` (one WMI
endpoint) → `ath11k_hif_start` (`ath11k_pci_start`: ASPM restore if
multi-MSI; `ath11k_pcic_start`: CE IRQs on, RX posted) →
`ath11k_htc_wait_target` (1 s; poll every CE; 1 s) →
`ath11k_dp_htt_connect` → `ath11k_wmi_connect` → `ath11k_htc_start` →
`ath11k_wmi_wait_for_service_ready` → (`ath11k_mac_allocate` skipped) →
`ath11k_dp_pdev_reo_setup` (hook) → `ath11k_wmi_cmd_init` →
`ath11k_wmi_wait_for_unified_ready` → `ath11k_wmi_set_hw_mode(DBS)` →
`ath11k_dp_tx_htt_h2t_ver_req_msg` (hook)] → `ath11k_core_pdev_create`
(hook) → `ath11k_hif_irq_enable` (hook). Errors after firmware start
unwind as Linux: `ath11k_hif_stop` (if started), then
`ath11k_qmi_firmware_stop`.

Tests: `core_tests.rs` — a scripted WCN6855 target at the HTC/WMI
level behind a recording fake HIF (exact order of QMI start, CE init,
hooks, HIF start, every TX frame; HTC connect / setup-complete / WMI
INIT / SET_HW_MODE byte goldens from Linux; MAC, caps, regulatory,
endpoints, credits) and behind the real `CeHif` over `ce_tests`'
`FakeChip` (frames through the real CE rings). Negatives: HTC READY
timeout (with the poll fallback), bad READY, HTT / WMI connect refused
and silent, service ready timeout (nothing, and EXT2 advertised but
missing), EXT decode failure, READY timeout, READY without its TLV,
credit starvation, QMI start failure, CE init failure, CE refusing WMI
INIT, unexpected events / endpoints / malformed frames, API without
endpoints.
### 3.7 DP ring runtime (`dp_ring.rs`, Linux `dp.c`, `dp_tx.c`, `dp_rx.c`, `hal_tx.c`, `hal_rx.c`)

Pure layer over [`hal::Hal`] (the device's one HAL, `Ce::hal`) and
`ChipIo`; nothing is wired into `pci.rs` yet. WCN6855 family only
(`DpHwParams::for_rev`: single pdev, `num_rxdma_per_pdev = 2`,
`rx_mac_buf_ring`, no rxdma1 / monitor, one TCL ring with rbm SW0,
`rx_buf_rbm` SW1, `hal_desc_sz` 392). `DpRingSizes::LINUX` is what
bring-up uses; tests shrink rings.

Call order (Linux call sites):

1. `Dp::alloc(&mut hal, io, &DpHwParams, DpRingSizes::LINUX,
   Some(CeMsi))` — `ath11k_dp_alloc` from
   `ath11k_core_qmi_firmware_ready`, after `ath11k_ce_init_pipes`: WBM
   idle ring (32768 requested, clamped to 32767) + link-descriptor
   banks (2 × 2 MiB + 384 B, 32766 posted), SW2WBM, TCL cmd / status,
   TCL data + WBM2SW0 completion (TLV headers pre-written), REO
   reinject, WBM2SW3 RX release, REO exception, REO cmd (cmd numbers
   from 1), REO status, `ath11k_hw_wcn6855_reo_setup` (aging, fragment
   ring REO2SW1, hash → REO2SW1..4 map in `DEST_RING_CTRL_IX_2/3`),
   48 DSCP→TID tables. DP MSI: `calculate_msi_group` /
   `srng_msi` (`ath11k_dp_srng_calculate_msi_group`, data =
   `group % 18 + 14 + ep_base`).
2. HTT connect (`ath11k_dp_htt_connect`, HTC `HTT_DATA_MSG`) → set
   `dp.htt.eid`.
3. `dp.pdev_reo_setup(..)` — `ath11k_dp_pdev_reo_setup` in
   `ath11k_core_start` after `ath11k_mac_allocate` (REO2SW1..4).
4. Send `htt::ver_req_msg()` (after WMI ready / DBS hw mode, as
   `ath11k_core_start`); feed every HTT-endpoint payload to
   `dp.htt_t2h_msg_handler(..)`; wait ≤ `HTT_TARGET_VERSION_TIMEOUT_MS`
   for `dp.htt.version_ok() == Ok(true)` (else
   `HttTarget::timeout_error()`).
5. `dp.pdev_alloc(.., 0)` — `ath11k_core_pdev_create` →
   `ath11k_dp_pdev_alloc`: RXDMA refill (128), rx_mac_buf (129 / 144),
   RXDMA err dst (133 / 148), monitor status (131 / 146); 4095 + 2 ×
   1023 RX buffers posted (cookie `pdev << 18 | buf_id`, rbm SW1);
   returns the seven HTT SRING_SETUP messages to send in order.
6. `ath11k_mac_op_start`: `htt::ppdu_stats_cfg_msgs(0, 2,
   HTT_PPDU_STATS_TAG_DEFAULT)`, `dp.mon_status_default_msgs(.., true)`
   (`ath11k_mac_config_mon_status_default`).
7. Per station vdev: `VifTx::attach(vdev_id, pdev_id, false)`
   (`ath11k_dp_vdev_tx_attach`), then `ast_hash` / `ast_idx` from the
   BSS peer; key install sets `dp.set_peer_sec_type`.
8. Data: `dp.tx(.., &VifTx, &TxMeta, frame, now_ms)` (Ethernet with
   vdev `TX_ENCAP_TYPE` ETHERNET, or native wifi), and per MSI group
   `dp.service_srng(.., grp, budget)` (`ath11k_dp_service_srng`) →
   `DpServiceOutput { rx: Vec<RxMsdu> (Ethernet II), tx_done,
   reo_status }`; `dp.service_shadow_timers(.., now_ms)` every ≤ 10 ms;
   `reap_mon_status` on the monitor timer (Linux `mon_reap_timer`).

Pieces: `Idr` (lowest-free `idr_alloc`), `hal_tx_cmd_desc`
(`ath11k_hal_tx_cmd_desc_setup`), `link_desc_words`,
`buf_addr_words` / `buf_addr_get`, `hal_tx_set_dscp_tid_map`,
`wcn6855_reo_setup`, `link_desc_return`, `process_rx`,
`process_rx_err`, `rx_process_wbm_err`, `process_rxdma_err`,
`process_reo_status`, `reap_mon_status`, `tx_completion_handler`,
decap helpers (`ieee80211_hdrlen`, `nwifi_to_eth`, `ieee8023_to_eth`).
Setup failures return `TransportError` with `dp_ring::step` 110–124,
142–143 and are latched + printed by `Dp::alloc` / `pdev_alloc`;
per-packet anomalies are counted in `DpStats` (Linux `soc_stats` +
warnings), never latched.

### 3.8 HTT (`htt.rs`, Linux `dp_tx.c` / `dp_rx.c` / `dp.h` HTT parts)

H2T encoders returning the exact `__packed` struct bytes:
`ver_req_msg`, `srng_setup_msg` (52 B), `rx_filter_setup_msg` (28 B),
`ppdu_stats_cfg_msgs`; `get_ring_id_type`; `MON_STATUS_FILTER_DEFAULT`.
T2H: `decode_t2h` → `HttT2h::{VersionConf, PeerMap (v1 / v2),
PeerUnmap, Skipped, Unhandled}` (NARF-stricter: truncated messages are
rejected); `HttTarget` holds the endpoint and version. Steps 135–141
(`htt::step`).

Tests: `dp_tests.rs` (golden REO setup / DSCP sequences, ring
registers, idle list, RX posting, all seven SRING_SETUP and both
RX_RING_SELECTION_CFG messages at Linux sizes; RX reap + decap,
continuation, wrap-around, error rings, link-descriptor return, REO
status, monitor-status reap; TX descriptor golden, native-wifi encap,
completion decode, FIFO-full, wrap, shadow timer; negatives) and
`htt_tests.rs`. The device model learns UMAC rings only from the
programmed registers + the QMI shadow list and LMAC rings only from
the HTT messages, and moves descriptors / buffers by physical address.
### 3.9 Station mac layer (`mac.rs`, `mac_reg.rs`, `mac_peer.rs`, `mac_frame.rs`)

What Linux `ath11k/mac.c` + `reg.c` do for a WCN6855 station, driven
in the order mac80211 / cfg80211 / wpa_supplicant drive them (NARF has
none of those). Independent of the transport: the core implements two
traits.

**`WmiPort`** (WMI side of the core): `send(WmiCmd) -> Result<(), errno>`
(`ath11k_wmi_cmd_send`), `next_event(timeout_ms) -> Option<frame>` (every
WMI event the core does not consume itself, `wmi_cmd_hdr` + TLVs; 0 =
poll), `mgmt_tx(vdev_id, frame) -> Result<desc_id, errno>`
(`ath11k_mac_mgmt_tx_wmi`: DMA-map + `WMI_MGMT_TX_SEND_CMDID`),
`mgmt_tx_done(desc_id)` (`wmi_process_mgmt_tx_comp`, called when the
mac layer sees the MGMT_TX_COMPLETION), `now_ms()`, `max_msg_len()`
(WMI endpoint, for the channel-list split), `random_bytes()`.

**`DataPort`** (DP side): `ppdu_stats_req()`, `mon_status_default(on)`,
`vdev_tx_attach(vdev, addr)`, `wait_peer_mapped(vdev, addr, mapped,
timeout)` (HTT PEER_MAP / UNMAP), `peer_setup` / `peer_cleanup`,
`rx_pn_replay_config(vdev, addr, cipher, pairwise, install)`,
`send_eth(frame)` / `recv_eapol(timeout)` (EAPOL as 802.3,
`ETH_P_PAE`), `set_authorized(addr, on)` (port control for data).

**`Mac<P, D>`**: `new(wmi, dp, DeviceCaps, MacConfig, initial_reg)`
(`ath11k_mac_register`: wiphy bands from `hal_reg_cap`, the default
regdomain from the start-up REG_CHAN_LIST_CC, world regd otherwise),
`start()` (`ath11k_mac_op_start`), `add_interface()`
(`ieee80211_do_open` → `ath11k_mac_op_add_interface`, ERP reset,
`ieee80211_set_wmm_default` → `conf_tx` ×4), `scan(&ScanRequest) ->
Vec<BssInfo>` / `hw_scan(ssids, freqs)` (`ath11k_mac_op_hw_scan`,
`ath11k_start_scan`, scan event state machine, timeout work, cfg80211
BSS table), `associate(&AssociateRequest)` / `connect`, `disassociate()`,
`poll() -> Option<LinkLoss>` (dispatch events: kickout, beacon miss →
3 s connection loss, deauth / disassoc RX, 11d new country, regulatory
updates), `handle_event(frame)`, `connected_bssid()`.
`DeviceCaps::from_events(service_ready, ext, ready, svc_map)`,
`MacConfig::wcn6855()`.

- `mac_reg`: `build_regd` (+ ETSI weather-radar split), `regd_intersect`,
  `RegState::handle_chan_list` (default / new / unchanged, reg info
  store for the STA 6 GHz client rules), `Wiphy` (Linux channel tables,
  `hal_reg_cap` limits, `handle_channel_custom` + `reg_process_ht_flags`
  for a self-managed wiphy, `scan_chan_list()` =
  `ath11k_reg_update_chan_list`).
- `mac_peer`: own HT/VHT caps (`ath11k_create_{ht,vht}_cap`), what the
  Association Request advertises (`ieee80211_add_{ht,vht}_ie`), AP
  station caps (`ieee80211_{ht,vht}_cap_ie_to_sta_*`, bandwidth, NSS),
  `determine_chan` (HT/VHT operation → 20/40/80 MHz, downgraded until
  usable), `vdev_phymode` (`ath11k_phymodes`), `peer_assoc_prepare`
  (`ath11k_peer_assoc_h_*`), `txbf_conf`.
- `mac_frame`: element walk, beacon / probe response / auth / assoc
  response / deauth parsers, Open-System auth, (re)association request
  (`ieee80211_send_assoc` element order), deauth, EAPOL ↔ 802.3.
- WPA2-PSK: `narf_wireless::eapol::Supplicant` + HMAC-SHA1 MICs, M3 key
  data AES-unwrapped (`iwlwifi::rekey::aes_key_unwrap`), the M3 RSN
  element must equal the beacon's, GTK from the KDE; PTK then GTK via
  `WMI_VDEV_INSTALL_KEY` (CCMP, pairwise / group flags) and
  `WMI_PEER_AUTHORIZE`.
- Diagnostics: `mac::step` 150–199, one console line per failure;
  stage `scan` on a scan / link loss, `connected` after authorization.
- `wmi.rs` additions: `scan_prob_req_oui_cmd`,
  `dfs_phyerr_offload_enable_cmd`, `pdev_lro_cfg_cmd`,
  `vdev_set_wmm_params_cmd`, `obss_spr_cmd`, `decode_11d_new_cc`.

Tests: `mac_tests.rs` — a scripted fake firmware + AP behind fake
ports: exact command lists for start / add_interface / scan / join /
teardown (built with the Linux-pinned `wmi.rs` encoders from
hand-derived values), literal auth / association request bytes, scan
dedupe / adjacent channel / malformed / filtered frames, regulatory
build / intersect / weather radar / 6 GHz client rules, peer assoc
parameters (HT40, VHT80, 11b, MCS workaround), a full WPA2-PSK join
against a real authenticator (PTK derived independently, MICs and the
wrapped GTK checked both ways), and negatives (scan start timeout /
failure / completion timeout, VDEV_START status / timeout, PEER_MAP
timeout, auth denied / timeout + BSS unlink, assoc reject / timeout,
peer-assoc-conf timeout, 4-way MIC failure / timeout / RSN mismatch,
key install status / timeout, kickout, beacon loss, deauth RX, 11d new
country).

### 3.10 Peer REO queues + REO commands (`dp_peer.rs`, Linux `dp.c`, `dp_rx.c`, `dp_tx.c`, `hal_rx.c`)

State lives in `Dp::peer_rx` (`DpPeerRx`): per HTT-mapped peer
(`ath11k_peer_find` = `Dp::peers` by vdev + MAC) 17 `RxTid`s (TID 0..15
+ non-QoS 16), `reo_cmd_list`, `cache_flush_list` (+ count), the
blocking-slot state, `stranded`, `stats`. WMI commands are returned,
never sent (the core owns the WMI endpoint, the CE owns the HAL), so the
mac layer interleaves in Linux's order:

1. `ath11k_mac_station_add` (sta_state NOTEXIST → NONE), right after
   `ath11k_peer_create` (peer HTT-mapped) and the mesh 4-addr param:
   `let (mut op, cmd) = dp.peer_setup_begin(vdev_id, addr, mac_id)` →
   send `cmd` (`WMI_PEER_SET_DEFAULT_ROUTING` = `DP_RX_HASH_ENABLE |
   (mac_id + 1) << 1`; failure: return it) → `while let Some(cmd) =
   dp.peer_setup_next(hal, io, &mut op, now)? { send cmd, on failure
   return dp.peer_setup_wmi_failed(hal, io, &op, errno, now) }`. Each
   step is one `ath11k_peer_rx_tid_setup(tid, ba 1, ssn 0, PN none)`:
   a fresh queue (`hal_reo_qdesc_size(256, tid)` / `(ba, 16)` bytes,
   128-aligned DMA32, `hal_reo_qdesc_setup`) or, when it exists, REO
   UPDATE_RX_QUEUE (window + SSN); then its
   `WMI_PEER_REORDER_QUEUE_SETUP_CMDID`. Failures unwind as
   `ath11k_dp_peer_setup`'s `peer_clean` (fresh TID freed, TIDs t..0
   deleted). The last step is the frag setup (`dp_setup_done`).
2. `ath11k_mac_station_remove` (NONE → NOTEXIST), before
   `ath11k_peer_delete`: `dp.peer_cleanup(hal, io, vdev_id, addr, now)`
   (`ath11k_dp_peer_cleanup`): REO UPDATE_RX_QUEUE with VLD cleared per
   active TID, handler `TidDel`. No WMI (Linux never sends
   `WMI_PEER_REORDER_QUEUE_REMOVE_CMDID`; `wmi::rx_reord_queue_remove_cmd`
   exists for completeness). `peer_cleanup_all` =
   `ath11k_mac_peer_cleanup_all`.
3. Every REO status: `dp.reo_status_handler(hal, io,
   &out.reo_status, now)` after `service_srng` (or
   `process_reo_status_and_dispatch`). Matched by command number:
   `TidDel` = `ath11k_dp_rx_tid_del_func` (DRAIN → free; other non-success
   → kept; success → `cache_flush_list`, entries older than 1000 ms or
   beyond 64 are flushed: FLUSH_CACHE per 128-byte block from the end
   without status, then the first with status → `CmdFree` =
   `ath11k_dp_reo_cmd_free` frees).
4. `ath11k_mac_op_ampdu_action`: RX_START → `dp.ampdu_start(.., tid,
   buf_size, ssn, pn_type, now)` → send its `cmd` (failure:
   `dp.rx_tid_wmi_failed`); RX_STOP → `dp.ampdu_stop(..)` → send the
   returned command if any.
5. `ath11k_dp_free` → `dp.reo_cmd_list_cleanup()`.

Encoders: `hal_reo_qdesc_size`, `hal_reo_qdesc_setup` (words),
`hal_reo_cmd_desc` (TLV + 9-word body of GET_QUEUE_STATS / FLUSH_CACHE /
UPDATE_RX_QUEUE; the ring's pre-written command number kept),
`wmi::peer_rx_reorder_queue_setup_cmd` (40 B),
`wmi::rx_reord_queue_remove_cmd` (20 B). `Dp::send_reo_cmd` =
`ath11k_dp_tx_send_reo_cmd` + `ath11k_hal_reo_cmd_send` (crash flush →
`-ESHUTDOWN`, ring full → `-ENOBUFS`, shadow timer armed). HTT PEER_UNMAP
drops the peer's RX state (queues kept in `stranded`, Linux leaks them).
Steps 230–239 (`dp_peer::step`), returned, not latched.

Tests: `dp_peer_tests.rs` — qdesc size table and descriptor goldens
(TID 0 ba 1 / ba 64, WPA, ba 256, non-QoS), every REO command
descriptor, WMI reorder setup / remove bytes, a full peer setup against
the device view of the queues, the update path (double setup, ADDBA),
teardown with deferred free (1000 ms ageing, strict `time_after`, 64
threshold, block flush order, free on status, list cleanup), status
dispatch negatives (unknown number, FAILED / BLOCKED, DRAIN, no handler,
failed flush), REO ring full / rejected types / crash flush, setup
unwinding (unknown peer, routing / TID WMI failure, update-path failure,
ring full mid-setup), ADDBA stop, HTT unmap + re-map.

## 4. Invariants

- Failure-step codes (`wifi: <stage> FAILED step=N` on the panel) are
  one namespace; each layer owns a disjoint range, pinned by
  `smoke_ath11k_step_codes_unique_and_in_range`:

  | Range | Layer (`<module>::step`) |
  |---|---|
  | 1–9 | `pci` (identify, power-up, MSI) |
  | 10–39 | `mhi_host` |
  | 40–79 | `wlfw` (QRTR / QMI handshake) |
  | 80–89 | `hal` |
  | 90–119 | `ce` |
  | 120–149 | `core` (HTC / WMI bring-up) |
  | 150–199 | `mac` (scan / connect) |
  | 200–219 | `dp_ring` |
  | 220–229 | `htt` |
  | 230–249 | `dp_peer` (REO queues / commands) |

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
| 3 | QRTR over MHI + QMI encode/decode; WLFW handshake: host cap, ind register, respond mem, target cap, BDF (`board-2.bin` by bus/qmi-chip-id/board-id), M3 (`m3.bin`), regdb, wlan cfg, mode ON (**done** to FW_READY, offline; `firmware_start` waits for the CE shadow list) | `qmi.c`, `net/qrtr`, `soc/qcom/qmi_*` |
| 4 | Copy Engines + HTC + WMI: service ready, init, ready; MAC from firmware (**done, offline**: HAL SRNG core, CE pipes, shadow v2 list, HTC/WMI codecs, `core.rs` bring-up to WMI READY + SET_HW_MODE DBS; DP hooks no-op) | `core.c`, `hal.c`, `ce.c`, `htc.c`, `wmi.c` |
| 5 | DP rings (TCL, REO, WBM, RXDMA refill) on the HAL (descriptor layouts, ring runtime, HTT ring setup / filters / version / peer map, per-peer REO TID queues + REO command ring **done, offline**; wiring into bring-up open) | `hal*.c`, `dp.c`, `dp_tx.c` (HTT), `dp_rx.c` (rx_tid) |
| 6 | Control: pdev/vdev, regulatory, scan → `BssInfo` list (**done, offline**: `mac.rs` behind `WmiPort`/`DataPort`; core wiring open) | `mac.c`, `wmi.c`, `reg.c` |
| 7 | Connect: peer, auth/assoc via mgmt TX, EAPOL via `narf-wireless` supplicant, key install (**done, offline** for Open + WPA2-PSK/CCMP; SAE open) | `mac.c`, `wmi.c` |
| 8 | Data path: TX (TCL → WBM completion), RX (REO dst → `Frame`); register `wlan%d` (TX / completion / RX reap + decap to Ethernet **done, offline** in `dp_ring.rs`; interface registration open) | `dp_tx.c`, `dp_rx.c` |
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
  first M0 and `fw-boot` at mission mode. QMI steps are `wlfw::step`
  (40–63), stage `control` from the start of the handshake.
- HELLO ordering (decided, from Linux): the host never sends first.
  `qrtr_ns_init` broadcasts its one HELLO from `qrtr_proto_init`
  (`qrtr.ko` init), before `qcom_mhi_qrtr_probe` registers the
  endpoint, and `qrtr_endpoint_register` sends nothing; the device's
  HELLO is answered by `ctrl_cmd_hello` → `say_hello(sq)` (+ no local
  servers to announce), then the device announces WLFW (NEW_SERVER
  0x45, instance `1 | 1 << 8`).
- Shadow registers: `wlan_cfg`'s v2 list comes from
  `ath11k_hal_srng_shadow_config` + `ath11k_ce_shadow_config`, which
  need the HAL SRNG tables (`hw_srng_config_template` + the WCN6855
  register map) the HAL/CE phase ports. The handshake therefore parks
  at FW_READY and `firmware_start` takes the list as a parameter —
  sending a guessed list would misprogram the firmware.
- Board variant: `board::check_smbios` walks the boot DMI table
  (`narf_firmware_smbios::boot_table`, found by the `dmi-scan`
  `Stage::Core` initcall before `pci-probe-all`) with Linux's rules:
  type 0xF8, `hdr->length == 9` exactly, cc flag ISO/WW sets
  `new_alpha2` per structure (decoded, not yet applied), `bdf_enabled`,
  first string starts `BDF_`, the first `min(strlen, 32)` bytes are
  printable ASCII, `strscpy` into 32 bytes (an over-long suffix is kept
  truncated to 31, as Linux leaves it), first structure that sets a
  non-empty `bdf_ext` wins. No 0xF8 / none valid = no variant (QEMU).
  DT variant (`ath11k_core_check_dt`) is not ported (x86 only).
- NARF-only bounds: Linux waits forever for the WLFW server and for
  REQUEST_MEM / FW_MEM_READY / FW_READY and for QRTR RESUME_TX, and
  silently stalls when the memory-request callback cannot allocate;
  here each wait is bounded (30 s, the 10 s transaction budget for
  flow control) and fails with its own step.
- Not ported (unreached on WCN6855 PCIe): fixed memory regions,
  DEVICE_INFO, `fixed_bdf_addr`, recovery (SERVER_EXIT / a second
  FW_INIT_DONE end the handshake), FTM, `firmware-N.bin` M3.
- Open: Linux prefers `firmware-2.bin` (an `amss.bin` IE) over
  `amss.bin` when present (`ath11k_fw_pre_init`); only `amss.bin` is
  loaded today.
- HAL / CE deviations from Linux (deliberate): ring memory and CE
  buffers are DMA32 coherent (Linux streams RX/TX skbs under a 36-bit
  mask); each CE ring slot has a fixed bounce region instead of an skb;
  `Ce::send` rejects sends over `src_sz_max` and pipes without a source
  ring; `srng_setup` rejects short ring memory, oversize rings, double
  setup and a missing shadow slot; CE interrupts are not masked in the
  handler (MSI is edge; Linux's `disable_irq_nosync` → tasklet →
  `enable_irq` becomes pending bits + task wake); the RX replenish
  retry is 50 ms (Linux: 50 jiffies). Register reads ≥ `0xFE0` after
  `DEVICE_INIT_DONE` would need `mhi_device_get_sync` on Linux
  (`ath11k_pci_bus_wake_up`); HAL/CE only touch such registers during
  ring setup, before that flag, and the shadow registers are below it.
- CE ↔ HTC wiring (decided, `core.rs`): RX by the pipe's `recv_cb`
  (HTC handler for CE1/CE2, HTT T2H straight from CE5); TX on the
  endpoint's `ul_pipe` with `transfer_id = eid`, credits reverted when
  the CE refuses. `Ce::alloc` + `install_ce_irq_handlers` run after
  FW_READY, not at probe as in Linux: both are host-only (the CE IRQ
  flag stays off until `ath11k_hif_start`), so the firmware sees the
  same sequence.
- Core deviations from Linux (deliberate, documented in `core.rs`): a
  WMI connect failure fails at once (Linux only warns and then times out
  on service ready); a SERVICE_READY / EXT / EXT2 / READY decode failure
  fails at once (Linux warns and either waits out the 5 s or — EXT
  failing with EXT2 still arriving — goes on without the ext caps);
  `wmi_cmd_wait` / event queues are NARF API, Linux uses per-event
  completions.
- Open (core): the MHI controller is not serviced after FW_READY
  (late QMI indications wait in the IPCR DL ring); `ATH11K_FLAG_*`
  crypto / raw mode are not modelled (HW crypto, native-wifi decap as in
  the INIT resource config); `ath11k_mac_allocate`, `ath11k_dp_*` and
  `ath11k_core_pdev_create` are hooks only; firmware crash recovery
  (`ath11k_core_reconfigure_on_crash`) is not ported.
- DP deviations from Linux (deliberate): RX buffers, TX bounce buffers
  and ring memory are DMA32 coherent `DmaMem`s (Linux streams skbs);
  rings are allocated with no 7-byte slack (the page-aligned allocator
  makes Linux's `PTR_ALIGN` a no-op, and slack would double every
  power-of-two ring); RX is delivered as Ethernet II, not rebuilt
  802.11 (native-wifi → DA / SA / SNAP type; Ethernet-II passthrough;
  802.3 + SNAP → Ethernet II; raw decap dropped); MPDUs with FCS,
  TKIP-MIC or decrypt errors are dropped in the DP (mac80211 drops or
  reports them; NARF has no TKIP countermeasures); multicast PN is not
  checked by the host (Linux leaves it to mac80211); REO-exception
  fragments are dropped (no defragmentation) and their link descriptor
  returned; monitor-status buffers are recycled unparsed (no RSSI /
  rate stats); `Dp` keeps the peer table HTT maps
  (`ath11k_peer_map_event`) itself. NARF-stricter: truncated HTT T2H
  messages, link descriptors outside every bank, an L3 pad that runs
  past the RX buffer, TX frames shorter than their header.
- DP Linux quirks kept on purpose (byte-for-byte): `TID 16` (non-QoS)
  is truncated to 0 by `FIELD_PREP` in TCL `info2`; `encrypt_type` is
  0 (WEP_40) for non-raw frames; `ath11k_hal_rx_msdu_link_desc_set`
  ORs into the recycled SW2WBM entry's `info0`;
  `ath11k_dp_process_rxdma_err` returns processed + 1; a continuation
  buffer reaped when the ring ends mid-MPDU with no complete MSDU is
  stranded (removed from the IDR, not reposted) as in Linux.
- DP not ported: WBM idle scatter list (dead for WBM_IDLE_LINK: > 2 MiB
  of 8-byte entries needs > 8 banks, which `ath11k_dp_link_desc_setup`
  rejects first), fragment reassembly (`ath11k_peer_rx_frag_setup` is its
  peer lookup + `dp_setup_done` only), monitor / full-monitor rings, PPDU / peer TX-RX
  statistics, ring teardown (`ath11k_dp_free`; a failed `Dp::alloc`
  leaves its rings in the HAL, so a retry needs a new `Hal`).
- Open (integration): HTT endpoint plumbing (HTC `HTT_DATA_MSG` →
  `htt_t2h_msg_handler`; HTT messages → `Htc::send` → `Ce::send`), DP
  MSI vectors (ext groups → vectors `(grp % 18) + 14`) driving
  `service_srng`, the shadow-timer tick, vdev encap/decap WMI params
  (`TX_ENCAP_TYPE` / `RX_DECAP_TYPE`), and where `wlan%d` sits on
  `RxMsdu::frame`.
- Peer REO deviations from Linux (deliberate, device-invisible): a queue
  descriptor Linux frees after a REO command could not be queued (ring
  full / crash flush) while the hardware may still hold it is kept in
  `DpPeerRx::stranded`; unsupported / unknown REO command types and
  FLUSH_CACHE BLOCK_LATER without a slot are refused before a ring entry
  is taken (Linux takes it and publishes a stale entry; no ath11k caller
  reaches either); the FLUSH_CACHE / UNBLOCK_CACHE status side of
  `avail_blk_resource` is not tracked (no caller sets BLOCK_LATER);
  TID > 16 is refused (Linux indexes out of bounds); queue memory is
  coherent DMA32 (Linux `dma_alloc_noncoherent` + sync). Linux quirk
  kept: `ath11k_dp_rx_ampdu_stop` REO-updates `peer->rx_tid` (TID 0's
  queue) to window 1 whichever TID stops, then sends the WMI for the
  stopped TID.
- Open (peer REO integration): the mac layer must call the steps of
  §3.9 at the Linux call sites and feed `DpServiceOutput::reo_status` to
  `reo_status_handler` with a millisecond clock.
- Firmware: `cargo xtask import-firmware --vendor ath11k`
  decompresses the distro `.zst` blobs at image build time. Open:
  whether probe runs before the rootfs firmware scan, i.e. whether
  the ath11k blobs must go in the initramfs (`--initramfs-firmware`).
- Mac layer scope (decided): HT + 5 GHz VHT only, no HE in the
  Association Request (the chip is HE-capable; mac80211's HE paths,
  6 GHz association and >80 MHz are therefore unreachable), so phymodes
  are 11NG/11NA/11AC. Scan covers 2.4/5/6 GHz; `BssInfo` lists 2.4/5
  GHz only (`narf_wireless` uses bare channel numbers).
- Mac layer, open vs Linux (each is a deliberate simplification or an
  unverified detail, see `mac.rs` comments): probe-request elements
  approximate `ieee80211_build_preq_ies`; the SME adds only the RSN
  element (wpa_supplicant also adds Extended Capabilities); no Country /
  Power Constraint handling (`ap_power_level`), no TPC / 6 GHz power
  envelope, no HE txbf / BSS colour / TWT; association comeback
  (status 30) is a reject; WPA3-SAE, PMF/BIP, group rekey, roaming,
  GTK rekey offload and CSA are not implemented; kickout is treated as
  link loss (Linux reports low-ack to userspace); deauth reason after a
  failed 4-way is 3 (17 for an RSN mismatch); the 11d "fin" path and the
  6 GHz LPI re-handling follow Linux but are untested on hardware.
