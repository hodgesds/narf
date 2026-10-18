# ath11k — Specification

> Status: **v0.9** — the whole station path is wired and
> offline-tested end to end; nothing has run on the card yet. Probe →
> power-up → MHI (firmware to mission mode) → WLFW QMI to FW_READY →
> core bring-up (QMI firmware start, CE, HTC, WMI to READY) with the
> real data path in Linux's order (DP rings, REO, HTT version, pdev
> rings via HTT SRING_SETUP, DP ext interrupts) → mac layer (start,
> station vif) → `wlan%d` registered with `narf_net` (frame rings, send
> hook, RX drain), the capability registry and `narf_wireless`. Scan,
> Open / WPA2-PSK (CCMP) connect with EAPOL over the DP rings, data TX
> (Ethernet → native-wifi 802.11) and RX (native-wifi → Ethernet II),
> disconnect, link loss and firmware crash recovery run against a composed fake device
> (`integration_tests.rs`). Unverified until the QCNFA765 boots: §8
> "Unverified until hardware".
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
After mission mode the runtime keeps servicing the controller
(`MhiController::service`, through `QrtrPipe::service` from
`QmiFw::service`): on an MHI MSI (`MhiBus::irqs_pending`) at the next
runtime pass, else every 100 ms — the intvec handler (SYS_ERR, RDDM),
the control ring (M0, M1 → M2 + MHI_CB_IDLE, M3, EE events, command
completions) and IPCR. `status_cb` is ath11k's
`ath11k_mhi_op_status_cb`: EE_RDDM (intvec with the EE already RDDM
while `mhi_is_active`, or the RDDM EE event) queues `reset_work` unless
the previous reason was EE_RDDM; SYS_ERROR queues it too, once per run
of consecutive SYS_ERRORs (§8);
`take_reset_request` hands it to the core once (`FwNotice::Reset`).
`mhi_pm_st_worker` items queued after mission mode are logged and
dropped. `power_down()` = `mhi_power_down(graceful)` (SHUTDOWN_PROCESS,
EE DISABLE, `mhi_pm_disable_transition`: MHI RESET + INTVEC re-program +
READY wait — failures only logged, as Linux —, IPCR channels dropped
without the RESET command, event / command rings reset, DISABLE) +
`mhi_unprepare_after_power_down` (BHIe table, contexts, per-boot state
freed); `power_cycle()` = `ath11k_hif_power_down` + `ath11k_hif_power_up`:
`MhiBus::hif_power(Down)` (ASPM restore, force wake, MSI off),
`power_down`, `hif_power(Reset)` (`ath11k_pci_sw_reset(false)`),
`hif_power(Up)` (window 0, `sw_reset(true)`, ASPM off, MSI on), then
`prepare_for_power_up` + `sync_power_up` (the kept image downloaded
again) + IPCR (`QrtrPipe::power_cycle`). Not ported: the RDDM ramdump
image, MHI-core SYS_ERR recovery (`mhi_pm_sys_error_transition`), M3
suspend/resume, BW scaling, RSC/offload/client-managed rings, EDL.

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
  After FW_READY (REGISTERED): `late_event()` pumps the link, runs the
  QMI handlers (COLD_BOOT_CAL_DONE / FW_READY set `cal_done`, REQUEST_MEM
  allocates) and classifies what `ath11k_qmi_driver_event_work` would
  do — `LateEvent::ServerExit` (SERVER_EXIT, or handshake events with no
  SERVER_EXIT before them: the firmware restarted), `LateEvent::Restart`
  (FW_INIT_DONE, or FW_READY without `cbcal_restart_fw`: `restart_work`;
  FW_READY is dropped on `cbcal_restart_fw` parts), events left queued;
  `run_to_fw_restart()` = the event work during a recovery (SERVER_EXIT
  waits for the server, SERVER_ARRIVE → ind_register + host_cap with
  `cal_done`, chunks of the same size / type and the M3 copy reused) until
  FW_INIT_DONE / FW_READY; `endpoint_reset()` = the MHI endpoint went
  away (power cycle): queued events and undelivered traffic dropped,
  `QmiClient::endpoint_reset` (transaction abandoned, `QrtrLink::
  endpoint_reset`: BYE → DEL_SERVER for the node's servers, node / flows
  freed, lookups kept; the handle's port and transaction ids kept).
  `QmiFw::service` for `Wlfw` maps these to `FwNotice` after the MHI reset
  request.
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
- `fw` — `firmware-N.bin` (Linux `fw.{c,h}`): `parse_api_n`
  (`ath11k_fw_request_firmware_api_n`: `"QCOM-ATH11K-FW\0"` padded to 4,
  then `{__le32 id, __le32 len, data}` IEs padded to 4; TIMESTAMP only
  when 4 bytes, FEATURES over `ATH11K_FW_FEATURE_COUNT` (0) bits,
  AMSS_IMAGE, M3_IMAGE, unknown ids skipped; `FwError` = Linux's four
  `-EINVAL` cases), `FwApi::pre_init` (`ath11k_fw_pre_init`: API 2 when
  `firmware-2.bin` loads and parses, else API 1, never fatal), `amss()` /
  `m3()` (non-empty IE or `None`). `pci::load_firmware` runs `pre_init`
  then picks the MHI image as `ath11k_mhi_register` (AMSS IE, else
  `amss.bin`), both inside the 60 s store retry; `Wlfw::fw_api` holds the
  container for `ath11k_qmi_m3_load` (M3 IE, else `m3.bin`).

Tests: `fw_tests.rs` — containers written out byte by byte from `fw.h`
(every IE kind, padding, duplicates, every refusal, the `len > 8` loop
bound, an unpadded last IE, empty IEs) and the API choice;
`qmi_handshake_tests.rs` — a scripted fake WLFW firmware
behind a fake pipe runs HELLO → FW_READY → `firmware_start`, every
request compared byte for byte (encoders + inlined Linux goldens);
board parser / names / SMBIOS; target memory with fake and real
DMA32 allocators; the M3 IE path (`m3_info` names the IE copy, no
`m3.bin` request; an empty IE falls back); negatives for every step.

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
- Teardown: `srng_ids()`; `srng_free(id) -> Option<DmaMem>` (the owner
  gives a ring up — `ath11k_dp_srng_cleanup` frees it, a CE keeps it;
  registers untouched; only once the hardware no longer uses the ring);
  `srng_clear()` = `ath11k_hal_srng_clear` (every listed ring forgotten;
  `rdp` / `wrp` and the shadow list kept, as Linux).
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
  `Ce::start(io)` (CE IRQs on + `ath11k_ce_rx_post_buf`), `Ce::stop()`,
  `Ce::cleanup_pipes()` = `ath11k_ce_cleanup_pipes` (posted RX buffers
  dropped, interrupt-less sources reaped) + NARF's hand-back of each
  ring's memory from the HAL and of the in-flight sends, so
  `init_pipes` sets the same memory up again.
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
through the real DMA32 ring memory; `smoke_ath11k_ce_cleanup_and_reinit`
runs cleanup → device reset → `init_pipes` over the same memory with
data in both directions after it.

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
  `install_ce_irq_handlers` + `runtime::install_dp_irq_handlers` with
  the probe's MSI state (Linux `ath11k_pcic_config_irq` at probe), then
  `qmi_firmware_ready(&mut runtime::DpHooks)` (§3.11, `DpRingSizes::LINUX`);
  on success the core + DP go to `runtime::start_pci` (mac layer →
  `wlan%d`). A failed core is parked (`park_core`, `core_failure`) with
  its DP (`STRANDED_DP`); a session the core cannot start on is parked
  too: the firmware owns its target memory. `take_core()` returns only a
  parked ready core (none in the normal flow).
- `wmi_cmd_try_send(&WmiCmd) -> Result<(), errno>` (one
  `ath11k_wmi_cmd_send_nowait` attempt) + `wmi_send_retryable(errno)`
  for callers that wait outside the core (the runtime ports).
- `QmiFw::service() -> Option<FwNotice>` (default none; `Wlfw`: MHI
  service + QRTR pump + late indications) and `irq_pending()` — the
  runtime calls it on the transport's interrupt or every 100 ms.
  `FwNotice`: `Reset(MhiNotify)` (`reset_work`), `ServerExit`
  (`ATH11K_QMI_EVENT_SERVER_EXIT`), `Restart` (FW_INIT_DONE with
  REGISTERED → `restart_work`). `QmiFw::recover(power_cycle)` (default
  unsupported; `Wlfw`: `QrtrPipe::power_cycle` + `endpoint_reset` when
  asked, then `run_to_fw_restart`). `Ath11kCore::into_parts()` gives the
  HIF, QMI session and config back for a restart (`ath11k_wmi_detach`;
  HTC / WMI state dropped, rebuilt by `Ath11kCore::new`).
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
`ChipIo`; driven by `runtime.rs` (§3.11). WCN6855 family only
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
9. Teardown (`ath11k_core_reconfigure_on_crash`, after the device
   reset): `dp.pdev_free(hal)` (`ath11k_dp_pdev_free`: the seven pdev
   rings + their RX buffers), `dp.pdev_reo_cleanup(hal)`
   (`ath11k_dp_pdev_reo_cleanup`), `dp.free(hal)` (`ath11k_dp_free`:
   link descriptor banks + WBM idle ring, shadow timers stopped, common
   rings, REO command lists with their queue descriptors and the
   stranded ones, pending TX buffers; a pdev / REO ring still set up is
   released first). The HAL then holds none of the DP's rings and takes
   a new `Dp::alloc`. A failed `Dp::alloc` (`fail_cmn_srng_cleanup` /
   `fail_link_desc_cleanup`), `pdev_reo_setup` (`err_reo_cleanup`) or
   `pdev_alloc` (`ath11k_dp_pdev_free`) releases exactly the rings it set
   up, so a retry works on the same `Hal`.

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
completion decode, FIFO-full, wrap, shadow timer; `srng_free` /
`srng_clear`, pdev / REO / DP free and a second DP on the same HAL,
failed alloc / REO setup / pdev alloc releasing exactly their rings;
negatives) and `htt_tests.rs`. The device model learns UMAC rings only from the
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
`ETH_P_PAE`, with whether the MPDU was decrypted), `flush_tx()`
(`ieee80211_flush_queues(.., false)`), `set_authorized(addr, on)` (port control for data),
`set_sta_wme(addr, wme)` (`sta->sta.wme` from the association
response: the TX path builds QoS Data only for a WMM AP).

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
- RX Block Ack (`mgmt_rx` ACTION → `pending.back_rx` →
  `run_deferred` → `process_back`, as `ieee80211_rx_h_action` → the
  interface work): BACK frames from our AP to us with the action's fixed
  fields present. ADDBA Request → `__ieee80211_start_rx_ba_session` with
  ath11k's `SUPPORTS_REORDERING_BUFFER` (no mac80211 reorder buffer and so
  no session timer: the timeout is only echoed) and no HE: TID ≥ 8 or a
  non-HT AP → 37 (`REQUEST_DECLINED`); policy ≠ 1 or window > 64 → 38
  (`INVALID_QOS_PARAM`); window 0 → 64; the same dialog token on a valid
  session → 37 (the timeout compare needs a `tid_rx`); a new token stops
  the old session first; else `DataPort::ampdu_rx_start` =
  `ath11k_dp_rx_ampdu_start` (`ath11k_peer_rx_tid_setup`: REO UPDATE with
  window + SSN, `WMI_PEER_REORDER_QUEUE_SETUP`, `pn_type` WPA once the PTK
  is in) → 0. The ADDBA Response (`ieee80211_send_addba_resp`: A-MSDU
  bit set, policy 1, no ADDBA Extension) goes out on WMI without a TX
  status wait. DELBA from the originator → `__ieee80211_stop_rx_ba_session`
  → `ampdu_rx_stop` = `ath11k_dp_rx_ampdu_stop` (window 1; Linux's TID 0
  REO-update quirk kept), no answer; a DELBA for a TX session finds none
  (TX aggregation is the firmware's: `-EOPNOTSUPP`), ADDBA Responses are
  ignored. Teardown stops every session (`AGG_STOP_DESTROY_STA`, no
  DELBA) before the keys go. BAR is handled by the REO in hardware (ath11k
  never sees BARs; mac80211's BAR path is unreached). A recipient DELBA
  (`ieee80211_send_delba`, `frame::build_delba`) is sent only for a
  locally stopped session (`initiator == RECIPIENT && tx`): the PTK rekey's
  `ieee80211_sta_tear_down_BA_sessions(AGG_STOP_LOCAL_REQUEST)` (reason 36;
  suspend teardown is not ported).
- PTK rekey (`Mac::ptk_rekey`): a pairwise message 1/4 after the 4-way
  (`Supplicant::rx_eapol`: new TPTK, M2 with Secure, the renewed SNonce;
  an unencrypted M1 with PMF and a TK set is dropped) and its 3/4 (MIC
  with the new TPTK, which then becomes the PTK) → M4 under the old key,
  then mac80211's PTK0 replacement for ath11k (`ieee80211_key_replace` →
  `ieee80211_pairwise_rekey`: no Extended Key ID, HW crypto,
  `AMPDU_AGGREGATION`, no `CAN_REPLACE_PTK0`): every RX BA session stopped
  with a DELBA, `ieee80211_flush_queues(false)`, `DISABLE_KEY` of the old
  PTK (cipher NONE + PN config off), `SET_KEY` of the new (fragment flush,
  install, PN config = REO PN reset), management PNs restarted
  (`_ieee80211_set_tx_key`); a retransmitted 3/4 only gets its 4/4. A new
  GTK / IGTK in the 3/4 is installed; an unchanged one is not. A failure
  deauthenticates (reason 1; 17 for an RSNE / RSNXE mismatch), step 277
  `PTK_REKEY` (detail 1 M2 TX, 2 M4 TX, 3 DISABLE, 4 SET, 5 GTK, 6 IGTK).
- Group rekey (`Mac::poll` → `rx_eapol`): EAPOL received while
  authorized goes to the association's supplicant (kept after the 4-way
  with its PTK, replay counter and GTK in use):
  `Supplicant::process_group_m1` (shared `narf_wireless::eapol`, from
  wpa_supplicant `wpa_sm_rx_eapol` / `wpa_supplicant_process_1_of_2` /
  `wpa_supplicant_send_2_of_2`; MIC by Key Descriptor Version, Key Data
  via `narf_crypto::aes_kw`) → the new GTK through `install_key(bssid,
  key_id, gtk, group)` (`ath11k_mac_op_set_key` → `ath11k_install_key`
  `WMI_KEY_GROUP` + PN config), `gtk_idx` updated, message 2/2 over the
  data path. Frames not from the AP, replays, bad MICs are dropped
  (wpa_supplicant `goto out` / `last_eapol_matches_bssid`); an in-use GTK
  is not reinstalled (KRACK check) but answered; a failed handshake (no
  GTK, bad GTK length, before the 4-way, install / TX failure) latches
  `step::EAPOL_GTK` detail `0x101..0x106` / `0x200` / `0x300` and
  deauthenticates with reason 1 (`wpa_sm_deauthenticate`,
  `LinkLoss::Supplicant`).
- RSN selection + 4-way (`mac/sec.rs`, wpa_supplicant
  `wpa_supplicant_set_suites` / `wpa_gen_wpa_ie_rsn` / `wpa_sm_rx_eapol`):
  `SecurityConfig::Wpa2 { psk }` picks PSK-SHA256 (AKM 6) over PSK (2),
  `Wpa3 { password }` picks SAE (8); CCMP-128 group + pairwise only. PMF
  policy = NetworkManager's: optional for PSK (our RSNE always has MFPC),
  required for SAE (MFPC | MFPR); MFP is used when the AP has MFPC and
  BIP-CMAC-128 (default or explicit), refused when the AP or SAE require
  it and it is impossible (`step::CONNECT_UNSUPPORTED` detail 4). Our RSNE:
  `rsn_supp_capab` (16 PTKSA replay counters when the BSS has a WMM
  element, MFPC / MFPR) + PMKID count 0 + BIP-CMAC-128 when MFP. The
  4-way runs on `narf_wireless::eapol::Supplicant::rx_eapol` (AKM-aware
  PTK / MIC / descriptor version, RSNE / RSNXE checks with reason 17), then
  PTK, GTK (WMI) and IGTK (software). `sta->mfp` → `WMI_PEER_PMF` in
  PEER_ASSOC (`ath11k_peer_assoc_h_crypto`; the vdev-start PMF flag stays
  clear, as ath11k leaves `arg.pmf_enabled` unset for a STA).
- WPA3-SAE (`mac/sae.rs`, wpa_supplicant `sme_send_authentication` /
  `sme_sae_auth` over mac80211 `ieee80211_auth` / `ieee80211_rx_mgmt_auth`):
  `SecurityConfig::Wpa3 { password }` to an AP with AKM 8 (WPA3-only or
  transition) authenticates with algorithm 3 on the shared
  `narf_wireless::sae::SaeSession` (IEEE 802.11-2020 Annex J.10 pinned):
  H2E (Commit status 126) when the AP's RSNXE has `SAE_H2E`, else hunting
  and pecking (status 0) — wpa_supplicant `sae_pwe=2`; group 19 only;
  each frame gets `IEEE80211_AUTH_MAX_TRIES` tries (TX status ≤ 500 ms,
  then `IEEE80211_AUTH_TIMEOUT_SAE` 2 s); an anti-clogging request (76)
  resends the same scalar / element with the token (inline, or an
  Anti-Clogging Token Container for H2E; NARF bounds it to 3 rounds);
  77 / other statuses end the attempt; a reflected Commit is ignored;
  Confirm (transaction 2) then the PMK feeds the AKM-8 4-way (descriptor
  version 0, AES-CMAC MICs, KDF-SHA256 PTK). The Association Request
  carries our RSNE (AKM 8, MFPC | MFPR, BIP-CMAC-128) and RSNXE (`SAE_H2E`,
  after HE as `ieee80211_send_assoc` sorts it); no PMKID
  (`sae_pmkid_in_assoc=0`). Steps 271 `SAE_PWE`, 272 `SAE_REJECTED`
  (detail = status), 273 `SAE_COMMIT`, 274 `SAE_CONFIRM`, 275
  `SAE_TIMEOUT`. A firmware recovery reconnects with the kept
  `AssociateRequest`, so the SAE password / PMF / HE state are rebuilt
  from it. Not done: SAE-PK, password identifiers, groups 20 / 21, FT-SAE
  (needs FT authentication: MDE / FTE, R0KH / R1KH). nl80211: ath11k does
  not advertise `NL80211_EXT_FEATURE_SAE_OFFLOAD` (upstream mac80211
  drivers never do; wpa_supplicant runs SAE through
  `NL80211_CMD_AUTHENTICATE` there, which NARF's ath11k has no path for
  yet), so SAE is reached from the in-kernel `associate` (autoconnect).
- HE (`mac/he.rs`): own HE capabilities per band = `ath11k_mac_copy_he_cap`
  for a STA (SERVICE_READY_EXT `he_cap_info` / `he_cap_phy_info` / PPET:
  MAC1 masked to TF MAC padding, sounding dimensions = tx chains - 1,
  TWT requester not responder, TX 1024-QAM < 242-tone RU) +
  `ath11k_mac_set_hemcsmap` (MCS 0-11 per enabled chain; the rx map shifts
  by `tx_chain_mask_shift`, as Linux) + `ath11k_gen_ppe_thresh`; `has_he`
  on every supported band, as Linux (so `HwCaps.he_supported`). HE mode
  (`ConnMode::He`) when the AP has HE Capabilities + Operation (and VHT on
  5 GHz) and `ieee80211_verify_{peer,sta}_he_mcs_support` pass; the
  Association Request carries `ieee80211_put_he_cap` (adjusted to the
  connection width: DCM max RU, 40 / 160 bits, sounding / STBC above 80
  MHz) after VHT (`before_he[]` split). At association success
  `ieee80211_he_cap_ie_to_sta_he_cap` (MCS intersection, 160 / 80+80
  disabled) from the response, HE bandwidth / NSS; `ath11k_bss_assoc`
  sends `WMI_VDEV_PARAM_SET_HEMU_MODE` (`ath11k_mac_vif_recalc_sta_he_txbf`)
  before PEER_ASSOC, whose HE fields follow `ath11k_peer_assoc_h_he`
  (`WMI_PEER_HE`, TWT flags, MAC / PHY words, `he_oper.params & 0xffffff`,
  PPET, the 80 MHz MCS set) and `ath11k_mac_get_phymode_he` /
  `MODE_11AX_HE*_2G`; OBSS spatial reuse from the AP's SR element
  (`ieee80211_he_spr_ie_to_bss_conf`); then `BSS_CHANGED_HE_BSS_COLOR`'s
  STA arm (BSS color change enable, collision detection 10 s / 200 ms
  scan). Step 276 `HE_PARAM` (console; Linux warns). Not done: 6 GHz
  association (HE 6 GHz capability, regulatory connectivity element,
  power rules), 160 / 80+80 MHz, TWT (`BSS_CHANGED_TWT` →
  `WMI_TWT_ENABLE`), HE operation's VHT info as a 5 GHz width source;
  `ath11k_mac_config_obss_pd` is AP-only (mac80211 never signals
  `BSS_CHANGED_HE_OBSS_PD` for a station).
- PMF / 802.11w (`MfpState`): ath11k returns 1 from `ath11k_mac_op_set_key`
  for AES-CMAC, so BIP is mac80211 software on WCN6855 too: the IGTK (M3 /
  Group 1/2, IPN as `rx_pn`) never reaches the firmware. Receive (from the
  AP while `sta->mfp`, `ieee80211_rx_h_decrypt` + `ieee80211_drop_unencrypted_mgmt`):
  group-addressed robust frames need a BIP-CMAC-128 MMIE (key 4 / 5, IPN >
  rx_pn, 64-bit MIC) and lose it; unicast protected ones come decrypted by
  the firmware with CCMP header + MIC (`ath11k_mgmt_rx_event`) and are
  replay-checked on the PTK's management PN, then stripped; unprotected
  unicast robust frames are dropped, except deauth / disassoc before a GTK
  exists ("Permit unprotected deauth/disassoc frames during 4-way-HS").
  Transmit: unicast robust frames (deauth, BACK, SA Query) get the host
  CCMP header (`GENERATE_IV_MGMT`, PN = ++tx_pn, key 0), the Protected bit
  and the 8-byte MIC tail `ath11k_mac_mgmt_tx_wmi` reserves. SA Query: AP
  Requests answered (`ieee80211_process_sa_query_req`); an unprotected
  deauth / disassoc with reason 6 / 7 while authorized starts
  wpa_supplicant's SA Query (`sme_event_unprot_disconnect`, ≤ 1 per 10 s,
  a Request every 201 TU, > 1000 TU unanswered → deauth reason 2,
  `step::SA_QUERY_TIMEOUT` detail = Requests). A group-addressed
  deauth / disassoc from the AP is accepted like a unicast one
  (`ieee80211_accept_frame`).
- Diagnostics: `mac::step` 150–199 and 270–299, one console line per failure;
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
6. `ath11k_mac_op_set_key` after `ath11k_install_key`:
   `dp.pn_replay_config(hal, io, vdev_id, addr, rsn_cipher, pairwise,
   install, now)` = `ath11k_dp_peer_rx_pn_replay_config` (pairwise
   only: REO UPDATE_RX_QUEUE with PN / PN_SIZE / PN_VALID / PN_CHECK /
   SVLD on every active TID, PN check + 48-bit PN on `SET_KEY`; one
   `cmd` carried across TIDs as Linux), then `set_peer_sec_type`.

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

### 3.11 Integration: DP hooks, runtime, netdev (`runtime.rs`, `tx_hdr.rs`, `iface.rs`)

**DP hooks** (`runtime::DpHooks`, the `CoreHooks` of
`qmi_firmware_ready` over `CeHif`): `dp_alloc` = `Dp::alloc(ce.hal, io,
DpHwParams::for_rev, sizes, msi)` after `init_pipes`; `pdev_reo_setup`
after service ready; `htt_ver_req` = `ath11k_dp_tx_htt_h2t_ver_req_msg`
(`dp.htt.eid` from the HTT connect, VERSION_REQ via `htt_send`, every
HTT T2H to `dp.htt_t2h_msg_handler`, wait ≤ 3 s, `version_ok` → major
3); `pdev_create` = `dp.pdev_alloc(.., 0)` + the seven SRING_SETUP
messages in order (first send failure ends it); `irq_enable` = DP ext
interrupts on (`ATH11K_FLAG_EXT_IRQ_ENABLED`) + stage `data-path`.

**DP MSI** (`ath11k_pcic_ext_irq_config`, verified in Linux
`pcic.c`): a group gets one IRQ iff any `ring_mask->*[grp]` is set
(`num_irq = 1`, `irqs[0] = ATH11K_PCI_IRQ_DP_OFFSET + grp`); its vector
is `(grp % num_vectors) + base_vector` of the "DP" user, the IRQ
`ath11k_pcic_get_msi_irq(vector)` = `pci_irq_vector(pdev, vector)`. The
ring side (`ath11k_dp_srng_msi_setup`) programs MSI data
`(group % msi_data_count) + msi_data_start` with `msi_data_start =
base_vector + ep_base_data` — the same vector. WCN6855 (32 vectors, DP =
18 from 14; `ath11k_hw_ring_mask_qca6390`): groups 0–2 → vectors 14–16,
group 3 none, groups 4–10 → 18–24; single-MSI fallback: every group on
vector 0 (shared with MHI / CE). `dp_irq_vector`, `dp_vector_cookie`,
`install_dp_irq_handlers` (inert until `set_dp_irqs_enabled`). The MSI
handler only marks groups pending and wakes the device owner; NAPI is the
next service pass. `ce::MsiCeIrq` waits wake on CE **or** DP pending and
keep up to four waiters (the runtime loop and a mac operation wait
concurrently).

**Runtime** (`Rt` = core + `Dp` + `LinkState` + management TX IDR;
`Shared` = `Mutex<Rt>` + a clone of the interrupt source + clock / RNG /
`max_msg_len`). Every locked step is synchronous; waits happen on the
interrupt source with the lock released (`Shared::wait_until`), and each
step starts with `Rt::service()`:

1. CE: `ce.service(pending)` (IRQ CEs + poll of the others + timers),
   `core.drain_rx()` (HTC / WMI events queued, HTT queued);
2. HTT T2H → `dp.htt_t2h_msg_handler` (version, PEER_MAP / UNMAP);
3. every DP group with rings: `dp.service_srng(grp, 64)` (re-polled
   while it uses the whole budget, ≤ 8 rounds), work on a group whose MSI
   did not fire is counted (`dp_polled_without_irq`, the poll
   fallback); RX MSDUs are classified (unicast not to us dropped,
   multicast echo of our SA dropped, EAPOL → `eapol_rx` only to our
   address or the PAE group address 01-80-C2-00-00-03 as
   `ieee80211_frame_allowed` (`rx_dropped_eapol_da` otherwise), data →
   `data_rx` only while authorized), `reo_status` → `dp.reo_status_handler`, TX
   completions to the TX status (buffers freed in the DP);
4. `dp.service_shadow_timers`, the 10 ms monitor-status reap timer
   (armed by `mon_status_default(true)`), `qmi.service()` on the MHI
   interrupt or every 100 ms; a reported crash is kept in
   `Rt::fw_notice` (first one wins).

`Port` (`Arc<Shared>`) implements `mac::WmiPort` (`send` =
`ath11k_wmi_cmd_send` with credit / CE-full retry for 3 s;
`next_event`; `mgmt_tx` = IDR id (≤ 512 pending) + DMA32 copy +
`wmi::mgmt_send_cmd(vdev, id, frame, paddr, 0, false)`, freed on
`mgmt_tx_done`; `now_ms`; `max_msg_len`; `random_bytes` =
`narf_crypto::fill_random_bytes`) and `mac::DataPort`
(`ppdu_stats_req` = `htt::ppdu_stats_cfg_msgs`; `mon_status_default` =
`dp.mon_status_default_msgs` sent, last result returned as Linux, reap
timer armed; `vdev_tx_attach` = `VifTx::attach`; `wait_peer_mapped`
(mapped: BSS peer recorded, AST from the peer as `ath11k_peer_create`;
unmapped: station data state cleared); `peer_setup` per §3.10 step 1;
`peer_cleanup` per step 2; `rx_pn_replay_config` per step 6 + PTK flag;
`send_eth` / `recv_eapol`; `set_authorized`; `set_sta_wme`). Linux's
synchronous calls (`vdev_tx_attach`, `peer_cleanup`, `set_authorized`,
`set_sta_wme`, `mgmt_tx_done`) are queued (`SyncOp`) and applied in order
at the next locked step.

**TX conversion** (`tx_hdr.rs`, the vdev TX encap / RX decap are
NATIVE_WIFI): `select_queue` = `ieee80211_select_queue` (no WMM →
priority 0 / AC BE; EAPOL → 7; else `classify8021d` =
`cfg80211_classify8021d`: IPv4 TOS / IPv6 TC DSCP → RFC 8325 UP, MPLS
TC, 802.21 → 7, other 0); `build_sta_data` = `ieee80211_build_hdr` for a
station (FC data | ToDS, + QoS Data with QoS control `[tid (| NoAck for
group), 0]` for a WMM AP, + Protected once the PTK is installed; addr1
BSSID, addr2 the Ethernet SA, addr3 the DA; seq from `tid_seq[tid]`
(QoS) or the vif counter (`ieee80211_xmit_fast_finish`); RFC 1042 SNAP,
bridge-tunnel for IPX / AARP, no encapsulation for 802.3 length frames;
`-EPERM` for unicast before authorization unless our own EAPOL).
Management frames get their sequence number on the way to WMI
(`Rt::mgmt_tx_prepare` → `tx_hdr::tx_h_sequence` =
`ieee80211_tx_h_sequence`): management, non-QoS data and group QoS data
share `SeqState::global` (`sdata->sequence_number`, kept for the vif's
lifetime), unicast QoS data uses `tid[]` (`sta->tid_seq`, cleared with the
AP's peer); control frames and QoS Null keep theirs. Then
`Dp::tx(NativeWifi, priority = tid, queue = AC, ring 0, csum_partial)`
strips the QoS control (`ath11k_dp_tx_encap_nwifi`). RX: the
vdev RX decap is NATIVE_WIFI and `dp_ring` decaps native-wifi to
Ethernet II (§3.7). Golden (WMM AP, PTK installed, IPv4 DSCP 0 from
own MAC to `GW`): `08 41 00 00 | BSSID | OWN | GW | 00 00 | aa aa 03 00 00
00 08 00 | <IP datagram>`; TCL `info0 = 0x0001_8004` (ENCAP NATIVE_WIFI,
ADDRY_EN, CMD_NUM 1), `info1 = len`, `info2 = 0x0020_0000 | tid << 22`,
desc id pool = AC.

**Checksum offload** (`tx_offload.rs`): the netdev advertises
`OFFLOADS` = TX + RX checksum, no TSO / VLAN insertion (Linux
`ath11k_mac_register`: `netdev_features = NETIF_F_HW_CSUM`), through
`Interface::offloads` and `narf_net::iface::set_offloads`. The send hook
carries the stack's `TxMeta` in the TX-ring frame and refuses TSO / VLAN
requests; the TX pump turns `TxMeta::csum_l4` into `CHECKSUM_PARTIAL`
(`csum_partial_prepare`: unfragmented IPv4 or extension-header-free IPv6
TCP / UDP of the requested kind, no in-band VLAN, seed = folded
pseudo-header sum as `tcp_v4_send_check` leaves it; anything else is
dropped and counted in `tx_offload_refused`, never sent half-checksummed)
and `Dp::tx` sets `HAL_TCL_DATA_CMD_INFO1_{IP4,UDP4,UDP6,TCP4,TCP6}_CKSUM_EN`
(`ath11k_dp_tx`). RX: `RxMsdu::csum_ok` (`ath11k_dp_rx_h_csum_offload`:
neither attention fail bit) rides with the frame to the RX ring's
`RxMeta` (`rx_meta`: `csum_l3` for IPv4 only, `csum_l4` for whole TCP /
UDP only, the net §3.2 contract). Golden: a `with_csum(Tcp)` IPv4 frame
→ TCL `info1 = 0x001f_0000 | len`, seed in the frame; plain → `info1 =
len`.

**TX queues** (`txq.rs`, mac80211's TXQs; Linux's mac80211 netdev has a
single queue, `alloc_netdev_mqs(.., 1, 1)`, and queues per TXQ): the TX
pump takes up to 64 frames off the stack's TX ring per runtime step;
`Rt::tx_enqueue` drops a frame with no station (`ENOTCONN`, as
`ieee80211_build_hdr`) and queues the rest on their AC
(`ieee80211_select_queue` with the current `sta->sta.wme`; `fq` limits
8192 packets / 16 MiB, overlimit drops the fattest queue's head);
`Rt::tx_push` (`ieee80211_handle_wake_tx_queue`) hands frames to
`Dp::tx` VO → VI → BE → BK, skipping ACs whose hardware queue
(`vif->hw_queue[ac] = ac % 3`: VO / BK 0, VI 1, BE 2) has a stop reason
(`enum queue_stop_reason` bits; `stop_queues` / `wake_queues` =
`ieee80211_{stop,wake}_queues_by_reason`, a wake drains in AC order as
`_ieee80211_wake_txqs`). A frame `Dp::tx` refuses (`-ENOSPC` IDR full,
`-ENOMEM` TCL ring full) is dropped as `ath11k_mac_op_tx` →
`ieee80211_free_txskb` does — ath11k never stops a queue on a full ring.
`Shared::flush_queues(drop)` = `ieee80211_flush_queues` (stop FLUSH,
purge when `drop`, else `ath11k_mac_flush_tx_complete`: ≤ 5 s for no
pending data then management, wake); a disassociate flushes with drop
before the deauth and link loss purges (`ieee80211_set_disassoc`). TCL
ring selection is `ath11k_dp_tx`'s (`ring_selector` =
`smp_processor_id()` → `current_cpu`, `tcl_ring_retry`); WCN6855's
`tcl2wbm_rbm_map` (`ath11k_hw_hal_params_qca6390` → the ipq5018 map) has
one TCL data ring (TCL 0 / WBM 0 / SW0), so every frame uses ring 0 and a
full IDR fails at once (`ring_map == BIT(1) - 1`). The descriptor pool id
is the AC.

**TX status** (`txq::tx_status`, `Rt::tx_status_one`): every WBM
completion `Dp::tx_completion_handler` returns gets the status
`ath11k_dp_tx_htt_tx_complete_buf` (firmware release, the EAPOL /
null-data path: ACK = HTT_TX_COMP OK; DROP / TTL = no ACK) or
`ath11k_dp_tx_complete_msdu` (TQM: ACK = FRAME_ACKED) builds — ack signal
= `ack_rssi` + `ATH11K_DEFAULT_NOISE_FLOOR` unless
`WMI_TLV_SERVICE_HW_DB2DBM_CONVERSION_SUPPORT`; no vif or no peer station
for `peer_id` = freed (dropped); REINJECT / INSPECT releases carry no
status (`ath11k_dp_tx_free_txbuf`). mac80211's side (`__ieee80211_tx_status`):
`tx_status_{acked,noack,dropped}` counters and the station's
`last_ack_signal` / `last_ack_ms`; a frame sent with
`IEEE80211_TX_CTL_REQ_TX_STATUS` (`Rt::tx_enqueue_status`, ack id from
`idr_alloc(.., 1, 0x2000)` as `ieee80211_store_ack_skb`) has its status
queued for its sender (`ieee80211_report_ack_skb`; refused, overlimit,
purged or interface-down frames report dropped).
`Shared::send_eth_tx_status(eth, timeout)` is the consumer entry point
(control-port TX with a cookie / the mlme probe's TX status).

**Netdev** (`iface::Ath11kNetdev`): `narf_net::Interface` (name from
`reserve_name("wlan%d")`, MAC from WMI READY, MTU 1500, `link_up` =
associated + authorized, RX / TX frame rings) and
`narf_wireless::WirelessNetIface` (`get_wireless_info` from the wiphy
channels (2.4 / 5 GHz, enabled only) + own HT / VHT / HE caps;
`scan`, `associate`, `disassociate` lock the mac layer (async mutex
across the operation); `set_config` accepts only the current channel;
`supports_handshake_offload`, `reports_disconnect_events`).
`register_pci`: `narf_net::iface::register(name, mac, send)` +
`set_driver_info("ath11k_pci")` + carrier off + `install_rx_drain`, the
capability registry (`step::NET_REGISTER` printed if refused, not
fatal), `narf_wireless::registry::register`, then two spawned tasks:
the runtime loop (`service_once`: service + deliver RX to the RX ring and
`on_rx_frame_from` outside every lock, `Mac::poll` when no control
operation holds the mac layer → carrier off on link loss; sleep ≤ 10 ms
on the device interrupts) and the TX pump (TX ring → TXQs → TCL). The
stack's send hook only queues on the TX ring (sync, no runtime lock).
Carrier changes go to `narf_net::iface::set_link_metadata`; `IFF_UP` is
the stack's. When the carrier drops, the reason cfg80211 would report
(`__cfg80211_disconnected`) goes to `nl80211::notify_disconnect(name,
reason, from_ap)` (`Sinks::disconnected`, from `Mac::take_disconnect`): a
Deauthentication / Disassociation from the AP → its reason code +
`NL80211_ATTR_DISCONNECTED_BY_AP`; beacon / connection loss (and kickout,
see §8) → 4 (`WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY`,
`__ieee80211_disconnect`), locally generated; `disassociate` and the
stop path → 3 (`DEAUTH_LEAVING`), locally generated. The reason
attribute is omitted for 0, as `nl80211_send_disconnected`.

**Open / stop** (`ieee80211_do_open` / `ieee80211_do_stop`):
`register_pci` installs `narf_net::iface::set_open_stop(name, hook)`;
the hook (sync, lock-free) records the requested `IFF_UP`
(`request_admin`), and whichever task next holds the mac layer — the
runtime loop, or a scan / associate / disassociate — applies it
(`sync_admin`). Open: `ath11k_mac_op_start` when not started, then
`ath11k_mac_op_add_interface` (a failed add_interface stops again,
`err_stop`); a failure (latched by the mac step) brings the interface
back down through `set_link_state(name, false)`. Stop: if associated,
`ieee80211_flush_queues(drop)` + the deauth with reason 3
(`cfg80211_leave`), carrier off, TXQs purged,
`ath11k_mac_op_remove_interface` (11d scan stop, VDEV_DELETE + wait ≤ 5 s
for VDEV_DELETE_RESP; a failure is only logged, step 257), the vif's
management TX IDR and DP vif state dropped, `ath11k_mac_op_stop`
(monitor-status filter off, state OFF, scan timeout / 11d PREPARING
cleared, `num_pending_mgmt_tx = 0`). Scan / associate on a down
interface return `HardwareError` (nl80211's `-ENETDOWN`). The command-line
autoconnect sets `IFF_UP` before its first attempt, as `ip link set up`
precedes wpa_supplicant.

`start_pci(core, dp)`: `Rt::new` → `device_caps` (SERVICE_READY /
EXT / READY; `step::MAC_CAPS`) → `Mac::new(Port, Port, caps,
MacConfig::wcn6855(), core.reg_info)` (`ath11k_mac_register`) →
`register_pci` (down; the hardware starts on `IFF_UP`). Failures latch their layer's step; the
runtime is parked (`STRANDED_RT`), nothing panics, the init path never
waits on it (all of it runs in the probe-spawned MHI task).

**Command-line autoconnect** (`autoconnect.rs`, NARF-only bring-up
aid): a scan / connect without any userspace. Userspace control works
too — nl80211 mutations follow Linux's genetlink permissions (a
CAP_NET_ADMIN sender, e.g. root `iw` or wpa_supplicant / NetworkManager
under systemd, or a delegated interface grant; `wireless/` spec §3.4) —
but the command line needs no Wi-Fi userspace on the first hardware
boot.
`register_pci` parses `ath11k.scan=1` (one passive scan of every enabled
channel, results printed), `ath11k.ssid=<ssid>` (active scan directed at
the SSID, strongest matching 2.4 / 5 GHz BSS, connect; retried every
10 s while disconnected — link loss reconnects — giving up after 6
failures in a row), `ath11k.psk=<64 hex>` (PMK) or
`ath11k.passphrase=<8..63>` (SAE with it as the password when the AP offers AKM 8 — WPA3-only or transition, `autoconnect::associate_request` reads the scan RSNE —, else PSK with PMK = PBKDF2-SHA1(passphrase, SSID, 4096));
no key = Open; `%XX` escapes (the command line splits on whitespace).
A malformed set is reported and ignored. The key is visible in
`/proc/cmdline` — bring-up only.

Steps (`runtime::step`, 250–269): DP_UNSUPPORTED 250 (detail = hw_rev),
DP_MISSING 251 (hook 1 / 2 / 3), HTT_VER_SEND 252 (detail = core step),
SRING_SETUP_SEND 253 (detail = index << 16 | core step), DP_IRQ_CONFIG
254 (no "DP" MSI user), MAC_CAPS 255 (detail bits 1 EXT, 2 READY, 4 no
pdev), NET_REGISTER 256 (console only; detail 1 no authority, 2
revoked, 3 duplicate), IF_DOWN_VDEV_DELETE 257 (console only, Linux
warns; detail = errno), RECOVERY_LIMIT 258 (reset declined; detail =
failures in a row), RECOVERY_FW 259 (power cycle / QMI handshake; detail
= inner step << 16 | detail), RECOVERY_CORE 260 (restart bring-up; the
core's own step latches first), RECOVERY_MAC 261 (open path after the
restart; detail 1, 3 caps).

**Firmware crash recovery** (Linux `ath11k_core_reset`,
`ath11k_core_restart`, `ath11k_core_reconfigure_on_crash`,
`ath11k_core_pre_reconfigure_recovery`,
`ath11k_core_post_reconfigure_recovery`):

1. Detection, in `Rt::service` from `QmiFw::service`: MHI EE_RDDM /
   SYS_ERROR (`FwNotice::Reset`), SERVER_EXIT, FW_INIT_DONE / FW_READY
   while registered (`Restart`). `Rt::fw_notify`: a reset passes
   `ath11k_core_reset`'s gate first (`fail_cont_count` ≥ 5, or ≥ 3 inside
   `reset_fail_timeout` (20 s) → declined, RECOVERY_LIMIT); then
   `pre_reconfigure_recovery`: CRASH_FLUSH (Rt, CE, DP), queues stopped
   (`txq::reason::DRIVER`), TX-status frames dropped, management TX IDR
   freed, station data state cleared, `fw_crash_counter`++, panel stage
   `recovery` (`diag::note_wifi_crash`). From here `wait_until` returns at
   once, `wmi_send` and `tx_eth` fail with `-ESHUTDOWN`: every control
   operation in flight ends.
2. The runtime loop takes the notice (`Shared::take_fw_notice`) and runs
   `Ath11kNetdev::recover`: carrier off, the mac-layer mutex taken,
   `Shared::recover_device(notice)`: the `Rt` leaves the slot (`lock`
   callers wait; nothing is held across the awaits), DP + CE interrupts
   off, `QmiFw::recover(power_cycle = Reset)` (§2.3 power cycle, QMI to
   FW_INIT_DONE), then the reconfigure — after the device reset, so no
   freed memory is still in use: `dp.pdev_free`, `ce.cleanup_pipes`,
   `into_parts` (WMI / HTC detach), `dp.pdev_reo_cleanup`, `dp.free`,
   `hal.srng_clear`, CRASH_FLUSH cleared, `Ath11kCore::new` +
   `qmi_firmware_ready(DpHooks)` over the same transport (new CE / HTC /
   WMI / DP; the TX queues and pending statuses carried over), the new
   `Rt` back in the slot.
3. `post_reconfigure_recovery` / `ieee80211_restart_hw`: a new mac layer
   from the new capabilities (`Mac::config()` kept); if the interface was
   open, the open path again (`ath11k_mac_op_start` + `add_interface`);
   `reconfig_complete` (`fail_cont_count` = 0, queues woken,
   `diag::note_wifi_recovered`); then a directed scan + `associate` with
   the last association's parameters (mac80211 would restore the
   association instead, §8); if that fails the command-line autoconnect
   keeps retrying.
4. A failure latches its step, parks what the firmware was given and
   marks the device dead: control operations fail with `HardwareError`,
   `lock` callers park forever, the runtime loop ends.

Tests: `integration_tests.rs` — one composed fake device: `core_tests`'
`Fw` behind `ce_tests`' `FakeChip` (HTC / WMI through the real CE
rings), `mac_tests`' `World` (WMI answers + an AP with a real WPA2
authenticator; MGMT_TX_SEND decoded from the command, PEER_CREATE /
DELETE → HTT PEER_MAP / UNMAP) and a DP ring model (UMAC rings from the
programmed registers, LMAC rings from SRING_SETUP, buffers moved by
physical address, REO commands answered on the status ring). Covered:
DP MSI vector map (Linux table, single-MSI fallback, ring MSI data =
vector), bring-up to `wlan%d` (HTT message order, rings, caps, stage,
stack registration), scan, WPA2 connect (M2 / M4 over TCL with MICs
checked by the authenticator, M1 / M3 over REO2SW1, PTK + GTK, 17 PN
REO updates, peer ciphers), data TX from the stack's send hook through
the TX ring to TCL (802.11 + TCL descriptor goldens, BE and EF), RX to
the RX ring and the stack as Ethernet II, multicast-echo drop, the poll
fallback with every DP interrupt lost, unauthorized RX drop, disconnect
(carrier off, deauth, HTT unmap clears the data state, TX refused),
kickout link loss through the runtime loop, PEER_MAP timeout, DP
unsupported / DP alloc / HTT version timeout / SRING_SETUP send
failures (latched step, firmware stopped, unwound), missing caps, the
`tx_hdr` goldens (non-QoS, QoS, DSCP table, IPv6, EAPOL, port control, the shared management / non-QoS sequence counter over the device,
bridge tunnel, 802.3 length frames), and the autoconnect parameters
(parse / rejects, the IEEE 802.11 Annex J.4.2 PBKDF2 vector, BSS
choice, a directed-scan connect on the fake device). Recovery: transport
servicing on IRQ / poll; crash → recover → reconnected on the composed
fake (RDDM while connected with WPA2: power cycle of the device model,
the bring-up HTT sequence again, the same ring ids, carrier off → on,
4-way again, data on the new TCL ring, panel counters); CRASH_FLUSH
semantics + a SERVER_EXIT recovery without power cycle (queues stopped
then woken); firmware / restart failures (latched, dead, control
operations refused) and the reset gate.

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
  | 250–269 | `runtime` (DP hooks / IRQs, mac registration, netdev) |
  | 270–299 | `mac` security / HE additions (`mac/sec.rs`, `mac/sae.rs`, `mac/he.rs`) |

- The PCI table is exactly Linux's `ath11k_pci_id_table`.
- The driver never reports a wireless capability it does not have:
  `wlan%d` is registered only after the core, the data path and the mac
  layer (`ath11k_mac_register`) are up, and opens (pdev start + station
  vif) only on `IFF_UP`; 6 GHz association and SAE offload are not
  advertised (bands 2.4 / 5 GHz; `supports_sae_offload` false, as for every
  mac80211 driver); HE is (and is used on 2.4 / 5 GHz).
- No lock is held across an `.await`: `Shared::rt` is taken for
  synchronous steps only (a recovery moves the runtime out of the slot
  instead of holding it); the mac-layer mutex is held across a control
  operation (a recovery is one) and never taken by the runtime loop
  unless free.
- Memory the firmware may DMA into is freed only after the device was
  reset or restarted its firmware (recovery), or never (failed bring-up /
  failed recovery: parked).
- Bring-up never blocks or panics the init path: probe spawns the MHI
  task, which runs everything after; failures latch a step and park the
  objects the firmware may still use.

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
| 5 | DP rings (TCL, REO, WBM, RXDMA refill) on the HAL: descriptor layouts, ring runtime, HTT ring setup / filters / version / peer map, per-peer REO TID queues + REO command ring, wired into bring-up (`DpHooks`, DP ext IRQs, NAPI service, shadow / monitor timers) (**done, offline**) | `hal*.c`, `dp.c`, `dp_tx.c` (HTT), `dp_rx.c` (rx_tid), `pcic.c` (ext IRQ) |
| 6 | Control: pdev/vdev, regulatory, scan → `BssInfo` list, over the runtime ports (**done, offline**) | `mac.c`, `wmi.c`, `reg.c` |
| 7 | Connect: peer, auth/assoc via mgmt TX, EAPOL via `narf-wireless` supplicant over the DP rings, key install + PN config (**done, offline** for Open + WPA2-PSK/CCMP; SAE open) | `mac.c`, `wmi.c`, `dp_rx.c` |
| 8 | Data path: TX (Ethernet → native-wifi 802.11 → TCL → WBM completion), RX (REO dst → Ethernet II → stack / RX ring); `wlan%d` registered with `narf_net` + `narf_wireless` (**done, offline**; first hardware run pending) | `mac80211/tx.c`, `dp_tx.c`, `dp_rx.c` |
| 9 | Power: PS, suspend/resume; firmware crash recovery (**done, offline**: MHI RDDM / SYS_ERR + QMI late events → reset / restart, power cycle, reconfigure, mac restart, reconnect) | `core.c`, `mac.c`, `mhi.c`, `qmi.c` |

## 6. Dependencies

`narf-bus` (BAR, MSI), `narf-io` (coherent DMA), `narf-firmware`
(`firmware-2.bin` or `amss.bin` + `m3.bin`, `board-2.bin`, `regdb.bin`
— distro packages ship them `.zst`-compressed), `narf-wireless` (iface
trait, EAPOL /
SAE, registry), `narf-net` (frame rings).

## 7. Stage assignment

Stage 5 "Silicon" — real-HW Wi-Fi on the bring-up laptops.

## 8. Open questions

- Test loop (decided): phases land with offline tests only; one
  full hardware bring-up at the end by booting NARF bare-metal on
  the QCNFA765 laptop (`docs/BOOTING_ON_CACHYOS.md`). No serial
  there, so every bring-up stage reports to a pinned framebuffer
  status line as well as the console. A firmware crash shows as stage
  `recovery` and `fw-crash=N recovered=M` on that line
  (`diag::note_wifi_crash` / `note_wifi_recovered`,
  `fb::status::wifi_line`).
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
  DEVICE_INFO, `fixed_bdf_addr`, FTM. During the first bring-up a
  SERVER_EXIT still ends the handshake (Linux waits for the server).
- Late QMI events (decided): after REGISTERED, FW_READY takes the restart
  path like FW_INIT_DONE (Linux re-runs `ath11k_core_qmi_firmware_ready`
  directly, over live rings); handshake events that arrive with no
  SERVER_EXIT first are treated as a firmware restart; the recovery
  handshake is bounded like bring-up (30 s per wait).
- `firmware-2.bin` (decided, `fw.rs`): preferred over `amss.bin` /
  `m3.bin` exactly as `ath11k_fw_pre_init`; NARF-only, it is re-tried
  with `amss.bin` while the firmware store fills (Linux requests it once
  at probe). The container bytes are copied out of the store and kept
  for the device's lifetime (`ab->fw.fw`).
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
- MHI crash policy (deliberate): NARF allocates no RDDM image (4 MiB of
  DMA32 with no dump consumer) and does not port the MHI core's own
  SYS_ERR recovery, so a SYS_ERR after mission mode — which Linux, with
  ath11k's RDDM image, leaves to the RDDM entry that follows — queues
  `ath11k_core_reset` like EE_RDDM. During bring-up a SYS_ERR still fails
  the bring-up (Linux's `reset_work` ignores an unregistered device).
- Core after bring-up: `ATH11K_FLAG_*` crypto / raw mode are not modelled (HW
  crypto, native-wifi encap / decap as in the INIT resource config).
- Recovery deviations from Linux (deliberate): no coredump
  (`ath11k_coredump_collect`, no RDDM image); `reset_count` /
  `reset_complete` (a second reset work racing the first) and the
  `recovery_start` wait are not modelled — one runtime task runs one
  recovery at a time and later notices are dropped while one is pending;
  WMI / HTC timeouts do not trigger recovery (Linux's do not either:
  CRASH_FLUSH only shortens them); the mac layer is rebuilt and, for a
  connection the kernel itself made (the command-line autoconnect,
  `Ath11kNetdev::associate_kernel`, `ConnectOrigin::Kernel`), NARF
  associates again over the air with the last parameters. A connection
  userspace asked for (nl80211 CONNECT, ASSOCIATE, any external-supplicant
  association: `ConnectOrigin::Nl80211`) is not restored: cfg80211 hears
  the loss (DEAUTHENTICATE + DISCONNECT, reason 1) and wpa_supplicant
  reconnects, as when mac80211's `ieee80211_reconfig` cannot restore it.
  Linux's reconfig restores the station, keys and BSS
  state in the restarted firmware without new frames — so the old mac
  layer (its supplicant / rekey state, RX BA sessions, scan table) is
  dropped whole rather than torn down session by session: no DELBA is
  sent (Linux's `ieee80211_reconfig` tears the BA sessions down with
  AGG_STOP_LOCAL_REQUEST and a DELBA; NARF's reassociation resets the
  AP's BA state instead), the per-TID REO / fragment state and frag
  timers go with `Dp::free`, and cfg80211 sees a disconnect (reason 1,
  as `ieee80211_sta_connection_lost`) then a new connection; a failed
  recovery leaves the device dead until the next boot (Linux waits for
  another crash event); the `fail_cont_count` gate counts failed
  recoveries (Linux counts resets that did not complete within 20 s).
- DP deviations from Linux (deliberate): RX buffers, TX bounce buffers
  and ring memory are DMA32 coherent `DmaMem`s (Linux streams skbs);
  rings are allocated with no 7-byte slack (the page-aligned allocator
  makes Linux's `PTR_ALIGN` a no-op, and slack would double every
  power-of-two ring); RX is delivered as Ethernet II, not rebuilt
  802.11 (native-wifi → DA / SA / SNAP type; Ethernet-II passthrough;
  802.3 + SNAP → Ethernet II; raw → `ath11k_dp_rx_h_undecap_raw` then
  802.11 → 802.3 for unicast, a decrypted group raw MPDU (Linux keeps its
  IV for mac80211) dropped); MPDUs with FCS,
  TKIP-MIC or decrypt errors are dropped in the DP (mac80211 drops or
  reports them; NARF has no TKIP countermeasures); multicast PN is not
  checked by the host (Linux leaves it to mac80211); the defrag
  reinjection allocates its buffer id from 1 (Linux `idr_alloc(.., 0,
  ..)` returns id 0, which `ath11k_dp_process_rx` skips as invalid: the
  first reassembled MPDU would be lost); TKIP fragment sets are dropped
  after reassembly (no Michael MIC, `ath11k_dp_rx_h_verify_tkip_mic`);
  the pairwise-key fragment flush (`ath11k_peer_frags_flush`) is a
  queued sync op applied at the install command's runtime lock;
  monitor-status buffers are recycled unparsed (no RSSI /
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
  stranded (removed from the IDR, not reposted) as in Linux;
  `ath11k_dp_process_rx_err`'s `drop` is not reset per entry, so after a
  dropped exception entry the later fragments of that pass are freed
  without returning their link descriptors; the defrag keeps
  `is_decrypted` across fragments.
- DP not ported: WBM idle scatter list (dead for WBM_IDLE_LINK: > 2 MiB
  of 8-byte entries needs > 8 banks, which `ath11k_dp_link_desc_setup`
  rejects first), monitor / full-monitor rings, PPDU / peer TX-RX
  statistics. (Ring teardown is ported, §3.7 step 9; NARF-stricter: a
  failed `ath11k_link_desc_setup` also releases the WBM idle ring, which
  Linux's `ath11k_dp_alloc` leaks on that path.)
- Integration (decided, §3.11): HTT T2H from the HTC HTT endpoint (and
  CE5) → `htt_t2h_msg_handler` in every service pass; HTT H2T via
  `Ath11kCore::htt_send`; the DP ext groups on vectors `(grp % 18) + 14`
  (verified against `ath11k_pcic_ext_irq_config`) with a poll of every
  group each pass; DP shadow timers + the 10 ms monitor reap in the
  service pass; vdev TX encap / RX decap NATIVE_WIFI (`mac.rs`), so TX
  frames are built as mac80211 does (`tx_hdr.rs`) and RX `RxMsdu::frame`
  (Ethernet II) goes straight to `wlan%d`.
- Checksum offload deviations (deliberate): NETIF_F_HW_CSUM lets Linux
  hand ath11k any `CHECKSUM_PARTIAL` skb; NARF's frame-ring contract
  makes the driver validate, so only the layouts the TCL engine's five
  CKSUM_EN bits cover are accepted (others are refused, not sent). The
  kernel stack's own receive path (`on_rx_frame_from`) takes no driver
  verdict and verifies in software (Linux `CHECKSUM_NONE` behaviour); the
  RX checksum verdict reaches frame-ring consumers only. Whether the TCL
  engine uses the seed or recomputes the pseudo-header on native-wifi
  frames is hardware-only (Linux passes the same seed).
- TX status, left open: NARF has no consumer that waits for an ACK yet.
  The in-kernel 4-way handshake sends M2 / M4 without asking (Linux
  installs the PTK without waiting too); mac80211's connection monitor
  (`ieee80211_mgd_probe_ap` nullfunc probing after `ieee80211_beacon_loss`,
  completed by `ieee80211_sta_tx_notify`) is not ported — beacon loss is
  ath11k's own 3 s `connection_loss_work` (mac.rs); nl80211 has no
  `CONTROL_PORT_FRAME` / `cfg80211_control_port_tx_status`, and no station
  dump to show the status statistics. Each would call
  `send_eth_tx_status`. Rate / retry statistics (`ath11k_dp_tx_update_txcompl`,
  `ieee80211_rate_status`) are not reported; low-ACK kickout stays the
  firmware's (`REPORTS_LOW_ACK`).
- Integration deviations from Linux (deliberate): `ndo_open` is
  asynchronous (`set_link_state` sets `IFF_UP` and returns; a failed open
  takes the interface down again, where Linux's `dev_open` fails without
  setting it), because the hook runs in the caller's syscall and the WMI
  bring-up waits on the device; the TX
  queues are one FIFO per AC, not one TXQ per TID with mac80211's airtime
  round robin and fq_codel (one station; the AC order and stop reasons are
  Linux's), no A-MSDU / fast-xmit header cache; a PTK rekey runs inside
  one runtime step, so mac80211's `WLAN_STA_BLOCK_BA` window (ADDBA refused
  between teardown and the new key) has nothing to block; EAPOL frames carry 802.1X version 1
  (wpa_supplicant's `DEFAULT_EAPOL_VERSION`); PMF policy is optional for
  PSK (NetworkManager / iwd; standalone wpa_supplicant defaults to
  `pmf=0`); only BIP-CMAC-128 (no BIP-GMAC / CMAC-256), no beacon
  protection (BIGTK), no OCV; a group-addressed robust frame naming an
  IGTK index we do not hold is dropped.
- Control path: userspace drives the station over nl80211 with Linux's
  permission model (`wireless/` spec §3.4), as mac80211 offers ath11k on
  Linux: SME and supplicant in userspace (`supports_userspace_mlme`,
  `supports_external_supplicant`; no handshake offload is advertised, so
  wpa_supplicant uses `WPA_DRIVER_FLAGS_SME`). AUTHENTICATE (Open, or SAE
  with AUTH_DATA = transaction | status | body, `mac/ext.rs`
  `Mac::sme_authenticate` = `ieee80211_mgd_auth`) / ASSOCIATE
  (`Mac::sme_associate` = `ieee80211_mgd_assoc`: userspace's elements as
  given, `ieee80211_send_assoc` ordering, the port closed while
  NL80211_ATTR_CONTROL_PORT is set) / DEAUTHENTICATE / DISASSOCIATE each
  report the peer's or our frame as cfg80211 does; CONNECT without a PMK
  (`SecurityConfig::External`) runs the same through the driver's SME.
  EAPOL (`Mac::take_control_port_rx`) goes to the connection owner as
  CONTROL_PORT_FRAME, or up the netdev with DA = our address
  (PF_PACKET / l2_packet); TX goes through CONTROL_PORT_FRAME or the
  netdev, protected only once a PTK is in. Keys come from NEW_KEY
  (`Mac::ext_add_key` → the same `install_key` / PTK replacement path
  the in-kernel supplicant and PTK rekey use, AES-CMAC kept in software
  BIP, KRACK re-installs ignored), DEL_KEY, and the port opens on
  SET_STATION AUTHORIZED (`Mac::ext_set_authorized`); the in-kernel
  supplicant and its group / PTK rekey never run for such an
  association. These calls arrive in the netlink syscall, which cannot
  wait for the firmware: `Ath11kNetdev` validates them synchronously
  (mac80211's -ENOENT / -EINVAL), then the runtime loop applies them in
  order (`ExtOp`), so a key's WMI install failure is only latched, not
  returned (Linux returns it from NEW_KEY). The in-kernel 4-way handshake
  remains for the autoconnect. Power save follows `ieee80211_set_power_mgmt`
  (`Mac::set_power_save`: `wdev->ps` on by default, WMI PS mode
  disabled / inactivity time + enabled once authorized with a beacon);
  GET_REG reports the self-managed wiphy's `Regd`; STA_INFO carries the
  AP's last management-frame signal (no rate statistics: ath11k's PPDU
  stats are not parsed). Unverified until hardware / real binaries:
  wpa_supplicant, NetworkManager and eapol_test against a real AP, SAE
  anti-clogging / group 20-21 over the userspace SME, EAP-TLS / PEAP
  timing, and the firmware's handling of the userspace-built
  Authentication frames.
- Unverified until hardware (recovery): that the WCN6855 firmware enters
  RDDM (or reports SYS_ERR) on a crash and comes back after the
  `sw_reset` power cycle with a fresh QRTR HELLO; that it sends
  FW_INIT_DONE (not only FW_READY) after the restart; that the target
  re-initialises its LMAC ring pointer words (Linux's srng setup does not
  clear them; the fake firmware does); MSI / ASPM behaviour across the
  cycle; the reconnect timing.
- Unverified until hardware (the first bare-metal run answers these):
  the real firmware's HTC credit size vs `max_msg_len` (one WMI credit
  with shadow registers — a command larger than one credit would stall
  as in Linux); the TCL / WBM / REO ring programming and the shadow
  register list on silicon (only the fake device consumes them); DP MSI
  delivery on the 32-vector block (vectors 14–24) and whether the AMD
  IOMMU / MSI setup leaves the block contiguous; the RX descriptor
  offsets of `HalRxDescWcn6855` on real frames (L3 pad, MSDU length,
  decap type); that the firmware accepts native-wifi frames with seq 0 /
  duration 0 and the Protected bit and encrypts them (expected: the TQM
  rewrites the sequence number; Linux sends the same); PEER_MAP v1 with
  no AST (WCN6855 `htt_peer_map_v2 = false`); monitor-status rings
  filling and being reaped; REO status delivery for the PN updates;
  the HE PEER_ASSOC / HEMU / BSS color commands against the real firmware
  and HE rates on air; the HE-capable firmware associating with an HT/VHT-only Association
  Request; 5 GHz DFS / passive channels in the scan list; the board-2.bin
  variant and regdb for the P14s Gen 5 (17aa:9309); link-loss detection
  timing (beacon miss → 3 s); DMA32 memory pressure with the Linux ring
  sizes (6141 × 2 KiB RX / monitor buffers ≈ 12 MiB + 4 MiB of link descriptors).
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
- RX defragmentation (`dp_frag.rs`, done): single-MSDU fragments from
  the REO exception ring → `ath11k_dp_process_rx_err_buf` →
  `ath11k_dp_rx_frag_h_mpdu` (per peer / TID, sorted by fragment number,
  a new sequence flushes, fragment 0's ring entry kept, the others' link
  descriptors returned, 2 s `frag_timer` from the service pass), on a
  complete set `defrag_validate_incr_pn` (CCMP / GCMP consecutive PNs),
  `ath11k_dp_rx_h_defrag` + `_undecap_frag` and
  `ath11k_dp_rx_h_defrag_reo_reinject` (fragment 0's MSDU link rewritten,
  the MPDU on SW2REO with its REO queue); the REO returns it raw on a
  destination ring (`rxcb->is_frag`). `ath11k_peer_frags_flush` runs
  before a pairwise key install; `ath11k_peer_rx_tid_cleanup` drops held
  fragments. No step codes (Linux only warns).
- Peer REO integration (done): the runtime ports call §3.10's steps at
  the Linux call sites (`station_add` → `peer_setup`, `station_remove`
  → `peer_cleanup`, `set_key` → `pn_replay_config`, `ampdu_action`
  RX_START / RX_STOP → `ampdu_start` / `ampdu_stop`) and every service
  pass feeds `DpServiceOutput::reo_status` to `reo_status_handler`.
- Firmware (decided): `cargo xtask import-firmware --vendor ath11k`
  decompresses the distro `.zst` blobs at image build time and now
  imports file symlinks under their own name (linux-firmware ships every
  `ath11k/WCN6855/hw2.1/*` as a link to `../hw2.0/*`; the importer used
  to skip links, leaving `hw2.1/amss.bin` absent). Probe
  (`pci-probe-all`, `Stage::Device`) runs before the rootfs firmware
  scan (`firmware-scan-rootfs`, `Stage::Late` after `root-mount-auto`);
  the MHI task retries `firmware-2.bin` / `amss.bin` for 60 s, so a
  partitioned root works without `--initramfs-firmware` when the root
  mounts within that window; the later blobs (`m3.bin`, `board-2.bin`,
  `regdb.bin`) load once the MHI image proved the store is up. An ISO /
  initramfs-only image
  needs `--initramfs-firmware "ath11k/WCN6855/hw2.1/*"`.
- Mac layer scope (decided): HT, 5 GHz VHT and HE on 2.4 / 5 GHz up to
  80 MHz (phymodes 11NG / 11NA / 11AC / 11AX HE20-80); 6 GHz association
  and > 80 MHz stay unreachable. Scan covers 2.4/5/6 GHz; `BssInfo` lists 2.4/5
  GHz only (`narf_wireless` uses bare channel numbers).
- Mac layer, open vs Linux (each is a deliberate simplification or an
  unverified detail, see `mac.rs` comments): probe-request elements
  approximate `ieee80211_build_preq_ies`; the offloading SME builds its own
  RSN element (and RSNXE for SAE) and forwards userspace's other
  elements (Extended Capabilities, vendor elements) in their order, with
  `WLAN_EXT_CAPA3_MULTI_BSSID_SUPPORT` set for an HE association
  (`SUPPORTS_ONLY_HE_MULTI_BSSID`); no Country /
  Power Constraint handling (`ap_power_level`), no TPC / 6 GHz power
  envelope, no TWT; association comeback
  (status 30) is a reject; roaming,
  GTK rekey offload and CSA are not implemented; kickout is treated as
  link loss (Linux reports low-ack to userspace); deauth reason after a
  4-way timeout is 3, after a failed message 3/4 1 (17 for an RSNE / RSNXE
  mismatch); the 11d "fin" path and the
  6 GHz LPI re-handling follow Linux but are untested on hardware.
