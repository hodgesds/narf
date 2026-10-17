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
| 3 | QRTR over MHI + QMI encode/decode; WLFW handshake: host cap, ind register, respond mem, target cap, BDF (`board-2.bin` by bus/qmi-chip-id/board-id), M3 (`m3.bin`), regdb, wlan cfg, mode ON (**done** to FW_READY, offline; `firmware_start` waits for the CE shadow list) | `qmi.c`, `net/qrtr`, `soc/qcom/qmi_*` |
| 4 | Copy Engines + HTC + WMI: service ready, init, ready; MAC from firmware (**done, offline**: HAL SRNG core, CE pipes, shadow v2 list, HTC/WMI codecs, `core.rs` bring-up to WMI READY + SET_HW_MODE DBS; DP hooks no-op) | `core.c`, `hal.c`, `ce.c`, `htc.c`, `wmi.c` |
| 5 | DP rings (TCL, REO, WBM, RXDMA refill) on the HAL (descriptor layouts **done**) | `hal*.c`, `dp.c` |
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
- Firmware: `cargo xtask import-firmware --vendor ath11k`
  decompresses the distro `.zst` blobs at image build time. Open:
  whether probe runs before the rootfs firmware scan, i.e. whether
  the ath11k blobs must go in the initramfs (`--initramfs-firmware`).
