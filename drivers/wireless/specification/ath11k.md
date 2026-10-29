# ath11k — Specification

> Status: **v0.9** — the WCN6855-layout station path is wired and
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
> silicon. QCA6390 and WCN6855-layout parts have native receive/runtime
> profiles; QCN9074 has its register map, static BAR windows and
> multi-pdev core/DP configuration, but probe refuses it
> (`pci::UNVERIFIED_RUNTIME`) until a composed start-up has run.
> Adapted from Linux
> `drivers/net/wireless/ath/ath11k/` (BSD-3-Clause-Clear) and
> `drivers/bus/mhi/host/`, `net/qrtr/`, `drivers/soc/qcom/qmi_*`.

## 1. Purpose & scope

**Owns:** station-mode bring-up plus up to four concurrent station, AP/GO or
P2P-role vdevs of PCIe ath11k parts, first target the WCN6855 HW2.1 in Lenovo's QCNFA765
module (`17cb:1103`, subsystem `17aa:9309`). AP/GO includes hostapd-facing
management-frame transport, client-peer programming and an Ethernet data
path; P2P includes the Device/Client/GO WMI roles and remain-on-channel.

**Does NOT own:** AHB/SoC-integrated parts (IPQ*, WCN6750), mesh or monitor
mode (Linux disables monitor for WCN6855), an in-kernel AP authentication /
association state machine (hostapd owns it through registered management
frames), or ath12k parts (WCN7850
`17cb:1107`, QCN9274 `17cb:1109`).

## 2. Hardware interface

### 2.1 Register access (`pci.rs`)

Offsets below `ATH11K_PCI_WINDOW_START` (`0x80000`) are direct BAR0
accesses. Higher offsets go through the sliding window: write
`ENABLE_BIT | FIELD_GET(GENMASK(24,19), off)` to BAR0+`0x310c`, read
it back, then access BAR0 + `0x80000` + `(off & GENMASK(18,0))`.
Select + access are serialised under one lock with the current
window cached (Linux `ath11k_pci_select_window`). WCN6855 / QCA6390
use the dynamic window. QCN9074 (`static_window_map`) uses static
windows (`qcn9074::static_window_start` / `static_bar_offset`, Linux
`ath11k_pci_get_window_start`): the UMAC/DP range at BAR0 + 3 x
`0x80000`, the CE range (`HAL_SEQ_WCSS_UMAC_CE0_SRC_REG` = `0x1b80000`) at
2 x `0x80000`, everything else through the dynamic window; `NativeIo`
routes by the map, and MHI start writes `static_window_select_value()`
(`ath11k_pci_select_static_window`).

### 2.2 hw_rev (`hw.rs`)

`TCSR_SOC_HW_VERSION` (`0x224`) major/minor, plus
`TCSR_SOC_HW_SUB_VER` (`0x1910010`) for WCN6855 minor `0x10`/`0x11`,
resolve to `HwRev` exactly as Linux `ath11k_pci_probe`: WCN6855
HW2.0 / HW2.1, QCA2066 HW2.1, QCA6698AQ HW2.1. Unsupported steppings
fail probe. `HwRev::fw_dir()` = Linux `hw_params.fw.dir`.

The AHB / hybrid-bus SoC parts take their `HwRev` from the DT match
(`ath11k_ahb_probe`: `of_device_get_match_data`): `HwRev::{Ipq8074,
Ipq6018Hw10, Ipq5018Hw10, Wcn6750Hw10}` = `AhbChip::hw_rev()`,
`HwRev::ahb_chip()` the reverse. `HwRev::params()` for them is
`AhbHwParams::hw_params(rev)` (no MSI users on IPQ = `MSI_CONFIG_NONE`;
`HwParams::ce_offset` = `ATH11K_CE_OFFSET`, `AHB_CE_WINDOW_OFFSET` on
IPQ5018, which `Hal::new` passes to `hal::create_config_ce`).

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
follows it), and ath11k's `RDDM_DUMP_SIZE` BHIe RX table (4.125 MiB in
512 KiB DMA32 segments), READY → M0 → SBL → AMSS, event-ring processing, the
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
the previous reason was EE_RDDM. An RDDM-capable controller does not
reset on the earlier SYS_ERROR indication: it waits for the RDDM event,
including a second interrupt that races the PM-state transition. Before
the reset, `MhiController::collect_rddm` waits for `BHIE_RXVECSTATUS`,
copies the device-written segments into `RddmSnapshot`, then moves it to
the physical radio's `FirmwareCrashDump` retrieval slot before recovery;
`take_reset_request` hands the one EE_RDDM request to the core
(`FwNotice::Reset`).
`mhi_pm_st_worker` items queued after mission mode are logged and
dropped. `power_down()` = `mhi_power_down(graceful)` (SHUTDOWN_PROCESS,
EE DISABLE, `mhi_pm_disable_transition`: MHI RESET + INTVEC re-program +
READY wait — failures only logged, as Linux —, IPCR channels dropped
without the RESET command, event / command rings reset, DISABLE) +
`mhi_unprepare_after_power_down` (FBC BHIe table, contexts, per-boot state
freed; the RDDM receive table is retained and any completed CPU snapshot has
already moved to the radio dump slot);
`power_cycle()` = `ath11k_hif_power_down` + `ath11k_hif_power_up`:
`MhiBus::hif_power(Down)` (ASPM restore, force wake, MSI off),
`power_down`, `hif_power(Reset)` (`ath11k_pci_sw_reset(false)`),
`hif_power(Up)` (window 0, `sw_reset(true)`, ASPM off, MSI on), then
`prepare_for_power_up` + `sync_power_up` (the kept image downloaded
again) + IPCR (`QrtrPipe::power_cycle`). `system_suspend`/`system_resume_force`
implement the WCN6855 M3 WoW transport transition; ordinary system suspend
uses `power_down_for_system_suspend` then the existing QMI/DP reconstruction
after resume. The generic no-RDDM MHI-core SYS_ERR recovery
(`mhi_pm_sys_error_transition`) is not used for WCN6855, whose allocated
RDDM image takes the ath11k reset path.

MHI scope proven inapplicable to every admitted profile (QCA6390 HW2.0,
WCN6855 HW2.0/2.1, QCA2066 HW2.1, QCA6698AQ HW2.1), from Linux
`ath11k/mhi.c` and `drivers/bus/mhi/host`:
- *Client-managed, offload and hardware event rings*: `ath11k_mhi_register`
  selects `ath11k_mhi_config_qca6390` for all five revisions; its two event
  rings set `.client_managed = false`, `.offload_channel = false`,
  `.hardware_event = false`, and its only channels (20/21 "IPCR") set
  `.offload_channel = false`. No ath11k configuration (QCN9074 included)
  declares such a ring, so `mhi_init_dev_ctxt`'s client/offload branches are
  never taken. NARF's `mhi::config_for` selects `ATH11K_MHI_CONFIG_QCA6390`
  for the same five revisions and mirrors those values (`mhi_tests.rs`
  "no client-managed / offload / hardware MHI rings") and `mhi_host` keeps the corresponding
  `offload_ev` / `hw_ring` skips only as the faithful MHI-core shape.
- *RSC (coalesced) rings*: RSC is an MHI channel `xfer_type` of
  `DMA_TYPE_RSC` that only a channel config can request (pci_generic's
  modem IP_HW channels); ath11k's IPCR channels are plain `MHI_BUF_RAW`
  transfer rings, so no RSC TRE is ever posted or completed.
- *Bandwidth scaling*: upstream `struct mhi_controller` has no host
  bandwidth-scaling callback; a device `MHI_PKT_TYPE_BW_REQ_EVENT` only
  records `mhi_link_info` and calls `status_cb(MHI_CB_BW_REQ)`, which
  `ath11k_mhi_op_status_cb` ignores (`default: break`). NARF decodes the
  event, delivers `MhiNotify::BwReq` and ignores it the same way
  (`mhi_tests.rs` "MHI_CB_BW_REQ for each").
- *EDL*: ath11k sets no `edl_image` and no `edl_trigger`
  (`mhi_controller` fields left NULL); a device found in `MHI_EE_EDL` is
  handled as `MHI_CB_FATAL_ERROR` + `mhi_pm_sys_err_handler`, and
  `mhi_fw_load_handler` with a NULL EDL image fails the load. NARF
  rejects the same EE (`MhiEe::EDL` in `in_pbl`, no EDL image) instead
  of emulating a flash-programmer download ath11k never performs.

## 3. Public interface

`MhiBus::random_nonzero(max) -> Result<u32, MhiError>` supplies secure
BHI/BHIe sequence IDs. The native provider uses the guarded common entropy
API and reports MHI step 40 (`ENTROPY`, detail = mask, errno = `EIO`) on
failure. A successful zero word is mapped to nonzero sequence 1; an entropy
failure has no fallback. RDDM, BHI and BHIe setup obtain the sequence before
publishing the corresponding DMA address or sequence doorbell.

The implemented runtime supports native QCA6390 HW2.0 and the WCN6855 layout
(HW2.0/HW2.1 plus QCA2066 HW2.1 and QCA6698AQ HW2.1). PCI matching and
MHI/QMI support for another revision do not imply a registered WLAN:

| Hardware | Reachable software | Remaining software gate |
|---|---|---|
| WCN6855 / QCA2066 / QCA6698AQ | MHI/QMI, CE/HTC/WMI, DP and STA/AP/P2P interfaces | Target-card and AP interoperability validation remains; optional Linux features outside this profile are not implied |
| QCA6390 HW2.0 | Native IPQ8074 RX/error/fragment DP and production core/CE profile; resource and host vdev capacity four | Native DMA fixtures pass both architectures; composed production-profile CE startup, WPA2 station/data and four-slot tests pass on x86_64; those integration fixtures are x86-only; physical interoperability remains |
| QCN9074 HW1.0 | Recognized PCI ID; `qcn9074_regs`, static BAR windows, multi-pdev `CoreConfig` / `DpHwParams` admission; tables pass `runtime_profile_complete`, but probe refuses it (`pci::UNVERIFIED_RUNTIME`) until a composed start-up smoke exists (fixture-tested only) | Multi-pdev runtime residuals: the RX service pass (refill replenish, RXDMA error and monitor-status reaping) covers pdev 0 only, the mac layer registers one radio on pdev 0 (`MacConfig::wcn6855`) and WMI commands go to `wmi[0]` although every per-pdev endpoint is connected, and monitor mode (incl. QCN9074 `full_monitor_mode`) is not supported; composed PCI bring-up never run (no hardware, no composed fixture) |

Probe first verifies inherited bus mastering and memory decode are off,
with INTx masked, using command-register readback. Rejected family/singleton
functions stay parked. Repeated dispatch of the already owned canonical PCI
address returns before config/MMIO access, preserving its active DMA.
Accepted profiles retain decode off during capability-invoked BAR sizing
and mapping; memory decode is enabled and read back only after sizing writes
have been restored. Probe validates the complete
HAL/core/DP/MHI software profile before enabling memory decode. It repeats
the check after refining the silicon revision and before MSI allocation or
reset; BME is enabled only after those checks and PCI power-up succeed.
`pci::ProbeError::UnsupportedRuntime` reports these recognized-but-incomplete
families; `PciConfiguration` distinguishes a failed command access.
Unsupported configurations never reach firmware activation or descriptor
allocation. These are software gaps, independent
of access to physical hardware; the WCN6855 acceptance plan does not close
them.

- `register()` — registers the three Linux PCI ids.
- `pci::probe` — identify, power up, spawn the MHI bring-up task.
  `pci::load_firmware` retries within `FW_WAIT_MS` until trusted loader
  authority, the MHI AMSS image (`firmware-2.bin` or `amss.bin`), companion
  `m3.bin` (when not embedded in `firmware-2.bin`) and signed `board-2.bin` or
  `board.bin` are present before MHI power-up begins.
- `pci::NativeIo` retains the exact original BusDevice/PCI cap/BAR binding through
  `MhiStart`, `Bar0Mhi` and `core::Bar0`. MHI direct accesses and CE/DP ChipIo
  accesses execute inside current `Cap::invoke`; complete width/alignment bounds
  precede access, and dynamic-window select/data remain one invoked transaction.
  Revoked reads return all ones, writes/selector restore do not reach hardware.
  Probe/reset, MSI and ASPM configuration also retain current invocation. There
  is no fresh/fake bus grant at the MHI→core→runtime handoff.
- `pci::{read32, write32}` are unsafe Linux-equivalent raw register primitives;
  production MHI/CE/DP adapters call them only under the retained current cap.
- `pci::{is_probed, with_controller}` — bound-device inspection.
- `pci::mhi_ready` — MHI reached mission mode with IPCR running.
- After FW_READY the MHI task hands the [`wlfw::Wlfw`] session (owns
  the MHI controller, target memory, M3 image) to
  `core::pci_start` (§3.6); `pci::aspm_restore` is its
  `ath11k_pci_start` ASPM step.
- `mhi_host::MhiController::{queue_ul, take_dl, poll, wait_and_poll}`
  — IPCR UL send (`mhi_queue_skb(…, MHI_EOT)`) / DL receive.
- `mhi_host::MhiController::{collect_rddm, rddm_snapshot,
  take_rddm_snapshot}` — wait for a completed BHIe RX ramdump, inspect it
  without copying, then move it to ath11k's device-dump owner before reset.
- `runtime::Shared::take_firmware_crash_dump() -> Option<FirmwareCrashDump>`
  — transfer the latest physical-radio dump to diagnostics;
  `FirmwareCrashDump::into_linux_v2()` emits Linux-compatible
  `ATH11K-FW-DUMP` v2 paging/RDDM/remote/pageable/M3 TLVs.
- `mhi_host::MhiController::{system_suspend, system_resume_force,
  power_down_for_system_suspend}` — Linux MHI M3 WoW transport handoff and
  the separate normal-suspend power-off half.
- `iface::Ath11kNetdev` registers `power::system_pm::AsyncSystemPm` at PCI
  probe. `SET_WOWLAN` selects firmware WoW (`WMI_WOW_*`, ARP/NS, GTK and
  keepalive state, HTC suspend ACK); no WoW configuration selects cfg80211's
  disconnect/stop plus cold MHI/QMI/CE/DP/WMI reconstruction path. Both
  routes coordinate every live vdev on the physical radio: configured WoW
  vdevs are armed before the one MHI M3 transition, while cold suspend stops
  every open vdev and resume recreates each one that was administratively
  open. Only WoW preserves association state.
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
- `qrtr_glink` — the AHB transport (`net/qrtr/smd.c`):
  `GlinkQrtr<P: GlinkPipe, B: GlinkBus>` implements `QrtrPipe` over a
  `narf_drivers_qcom_soc::glink::Glink` edge. `new` claims the
  remote-initiated `IPCRTR` channel with the default 5 × 1 KiB intents;
  one rpmsg message = one QRTR packet; `send` before the channel is open
  (or after the remote closed it) is `-ENOTCONN`, an oversize frame
  `-EMSGSIZE`; `wait(ms)` = `GlinkBus::wait_irq` (the edge SPI) then
  `Glink::process_rx`; `take_closed` reports a remote CLOSE once.
  `GicGlinkBus { line: irq::GicSpi, clock }` is the production
  `GlinkBus` (the `glink-edge` SPI).
- `wlfw` — `Wlfw<P, F: FirmwareLoader, A: DmaAllocator>`, whose
  `A::Mem: CoherentMem` supplies DMA address, length, write and immutable
  CPU bytes (the latter for pre-reset device-coredump collection), the
  `ath11k_qmi_driver_event_work` machine: `run_to_fw_ready()` (lookup
  0x45 v1 ins `qmi_service_ins_id`; SERVER_ARRIVE → ind_register +
  host_cap; REQUEST_MEM callback → `alloc_target_mem_chunk` (reuse,
  ≤ 5-segment delayed path) → `respond_fw_mem_request`; FW_MEM_READY →
  target_cap → regdb (`supports_regdb`, result ignored) → board data
  (+ caldata for a BIN board) → `m3_info`; FW_READY / FW_INIT_DONE →
  `FwReadyInfo`), and `firmware_start(mode, shadow_reg_v2)` =
  wlan_ini (`fw_wmi_diag_event`) → wlan_cfg (QCA6390 CE + service
  maps, shadow v2 clamped to 36) → wlan_mode. `WlfwConfig::pci(..)`
  carries `ab->id`, `dev_name` (caldata name) and the timeouts;
  `WlfwConfig::ahb(chip, dev_name, host_ddr)` the AHB values
  (`AhbChip::wlfw_hw_params()`, `bus=ahb` board names, `cal-ahb-<dev>.bin`,
  DT `memory-region[0]` as the HOST_DDR region). AHB paths:
  `fixed_mem_region` → `assign_fixed_target_mem` (HOST_DDR = region,
  BDF = `hw.bdf_addr`, CALDB after HOST_DDR / `ATH11K_QMI_CALDB_ADDRESS` /
  0); `fixed_bdf_addr` → `DmaAllocator::iomem_write(bdf_addr, board_size,
  off, file)` (caldata at `cal_offset`; a file past `board_size` is
  refused with `BDF_IOREMAP`, where Linux would overrun its mapping) and
  one `bdf_fixed_addr_request` (no data TLV, `end = 1`, `total_size` =
  length); `hybrid_bus_type` → `request_device_info` after target_cap
  (BAR must be non-zero and `ATH11K_QMI_DEVICE_BAR_SIZE`; `device_bar()`
  hands it to the HIF). `Dma32::iomem_write` maps the window with
  `narf_drivers_qcom_soc::io::MmioRegs`.
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
- `pci::request_fw` and `wlfw::NarfFirmware` use current registry/blob invocation
  to make bounded owned payload copies before parsing or download. `FwBlob` owns
  its copied bytes and original source cap; `AsRef` returns that owned storage
  only while the source epoch remains current, never a registry slice around an
  invocation. Board/calibration/regulatory roles (`board.bin`, `board-2.bin`,
  `regdb.bin`, `caldata.bin`, `cal-*.bin`) always require a verified signer even
  in unsigned-executable developer builds. Executable/container/M3 policy remains
  the existing firmware registry/build policy; board identity/search order is
  unchanged. Actual real-registry tests cover those strict roles, epoch denial
  and owned bytes; native tests share one real cap across actual MHI/CE/DP MMIO
  adapters and refuse revoked accesses before invalid ECAM/BAR sizing.
  BDF selection captures one current owned slice, checks offset addition and
  range before download, and rejects a revoked/empty snapshot with BDF_FETCH.
  Caldata and M3 similarly reject empty current snapshots before target DMA/QMI.
  A real-cap fixture revokes between board offset parsing and transfer snapshot,
  proving bounded failure without a slice panic, target allocation or traffic.
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
  SET_HW_MODE, PDEV_SET_PARAM / SET_REGDOMAIN / GET_TEMPERATURE /
  BSS_CHAN_INFO_REQUEST,
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
  `rx_status()`), MGMT_TX_COMPLETION, ROAM, PDEV_TEMPERATURE,
  PDEV_BSS_CHAN_INFO. Where
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
- `CeIrq` also has default-no-op bus hooks `hif_start(io)` /
  `hif_stop(io, crash_flush)`, which `CeHif::start` / `stop` run around
  `Ce::start` / `Ce::stop` (the AHB `CE_HOST_IE_*` gating,
  [`ahb_hif`]).

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

`qcn9074.rs`: `HalRxDescQcn9074` (`struct hal_rx_desc_qcn9074`, 384 bytes;
QCN9074, IPQ5018, WCN6750) with the `ath11k_hw_qcn9074_rx_desc_*` getters;
`rx_descriptor::RxDescriptor::Qcn9074` decodes it for `HwRev::Qcn9074Hw10`
(`mpdu_info1` = `mpdu_start.info11`, same bits as the WCN6855 word).

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
- `CoreConfig::for_hw(&HwParams)` (QCA6390, WCN6855 family, the AHB
  parts and QCN9074 — one radio, 8 vdevs, 128 peers, multi-pdev shape;
  `num_peers` feeds the multi-pdev resource config). WCN6855 family: `single_pdev_only`, `num_rxdma_per_pdev = 2`, `max_radios =
  3`, `num_vdevs = 4`, credit flow, shadow regs, Linux timeouts (HTC
  1 s, connect 1 s, service / unified ready 5 s, WMI send 3 s).
  Firmware requests and retained host slot arrays both use four, matching
  local Linux's QCA6390/WCN6855 resource profile.
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
  REGISTERED → `restart_work`). `QmiFw::collect_crash_dump()` is a default
  no-op; `Wlfw` invokes `QrtrPipe::collect_crash_dump` for the RDDM image
  before a reset, then moves the completed image, BHIe FBC paging data and
  Linux-dump-eligible QMI target memory into
  `Shared::take_firmware_crash_dump()` as a `FirmwareCrashDump`. Its
  `into_linux_v2()` produces the `ATH11K-FW-DUMP` v2 header and paging,
  RDDM, remote-memory, pageable and M3 TLVs (the device-coredump retrieval
  surface). `QmiFw::recover(power_cycle)` (default unsupported;
  `Wlfw`: `QrtrPipe::power_cycle` + `endpoint_reset` when asked, then
  `run_to_fw_restart`). `Ath11kCore::into_parts()` gives the
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
`ChipIo`; driven by `runtime.rs` (§3.11). `DpHwParams::for_rev` supports
QCA6390 and the WCN6855 family: single pdev, `num_rxdma_per_pdev = 2`,
`rx_mac_buf_ring`, no rxdma1 / monitor, one TCL ring with rbm SW0,
`rx_buf_rbm` SW1. `hal_desc_sz` is 384 for QCA6390 (`ipq8074.rs`) and
392 for WCN6855 (`dp.rs`). `rx_descriptor::RxDescriptor` selects the
native packed layout by `HwRev`; normal RX, attention/error processing,
continuation coalescing and fragment reinjection all use that view.
`dp_ring::attn_mpdu_err` and `dp_frag::{mpdu_start_enctype,
attn_is_decrypted, attn_is_mcbc}` accept this view. Descriptor length
rewrite uses byte 96 on QCA6390 and byte 104 on WCN6855.
The four native receive/error/coalescing/fragment DMA fixtures pass on both
architectures; composed core/startup/station tests pass on x86_64 and exercise
the selected production profile. Those integration fixtures are x86-only.
`DpRingSizes::LINUX` is what
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
(WMI endpoint, for the channel-list split),
`random_bytes(out) -> Result<(), errno>`. The RNG provider must fill the
whole output with secure, unpredictable bytes or return an error; failed
partial output must never be consumed. Native ports use
`narf_crypto::try_fill_random_bytes`, mapping unavailable entropy to `EIO`.
MAC step 319 (`ENTROPY`) identifies failure before protocol mutation or
transmission: detail 0 = LRO seed, 1 = initial 4-way nonce, 2 = rekey nonce,
3 = SA Query transaction ID, 4 = SAE commit. Initial authentication
failure follows normal disconnect cleanup; an established link loses its
controlled port on rekey or SA Query entropy failure. Both supplicant
paths use `rx_eapol_with_nonce`: fresh SNonce material is requested only
for an accepted M1 that renews it. Retransmissions, M3, group rekeys and
discarded traffic never request nonce entropy. Temporary nonce buffers
are zeroized, including partially filled failed samples. SAE uses
`SaeSession::try_build_commit_with_entropy` through this fallible provider,
with partial samples private to the shared session; committed retries keep
the same scalar and element without resampling.

**`DataPort`** (DP side): `ppdu_stats_req()`, `mon_status_default(on)`,
`vdev_tx_attach(vdev, addr)`, `wait_peer_mapped(vdev, addr, mapped,
timeout)` (HTT PEER_MAP / UNMAP), `peer_setup` / `peer_cleanup`,
`rx_pn_replay_config(vdev, addr, cipher, key_len, pairwise, install)`,
`tkip_rx_mic_config(vdev, addr, Option<[u8; 8]>)` (the host-held receive
Michael direction for a hardware-decrypted, fragmented pairwise TKIP MPDU),
`send_eth(frame)` / `recv_eapol(timeout)` (EAPOL as 802.3,
`ETH_P_PAE`, with whether the MPDU was decrypted),
`probe_ap(timeout)` (a requested-status directed Null / QoS Null
connection probe), `flush_tx()` (`ieee80211_flush_queues(.., false)`),
  `set_authorized(addr, on)` (port control for data),
`set_sta_wme(addr, wme)` (`sta->sta.wme` from the association
response: the TX path builds QoS Data only for a WMM AP), and
`dfs_nop_active(chandef)` / `record_dfs_nop(chandef, deadline)` for the
physical-radio DFS non-occupancy table.

**`Mac<P, D>`**: `new(wmi, dp, DeviceCaps, MacConfig, initial_reg)`
(`ath11k_mac_register`: wiphy bands from `hal_reg_cap`, the default
regdomain from the start-up REG_CHAN_LIST_CC, world regd otherwise),
`start()` (`ath11k_mac_op_start`), `add_interface()`
(`ieee80211_do_open` → `ath11k_mac_op_add_interface`, ERP reset,
`ieee80211_set_wmm_default` → `conf_tx` ×4), `scan(&ScanRequest) ->
Vec<BssInfo>` / `hw_scan(ssids, freqs, random_mac, colocated_6ghz)`
(`ath11k_mac_op_hw_scan`,
`ath11k_start_scan`, scan event state machine, timeout work, cfg80211
BSS table), `associate(&AssociateRequest)` / `connect`, `disassociate()`,
`poll() -> Option<LinkLoss>` (dispatch events: kickout, beacon miss →
3 s deadline → up to two 500 ms requested-status Null / QoS Null probes;
an ACK cancels the deadline, two no-ACK results cause connection loss;
deauth / disassoc RX, 11d new country, regulatory updates),
`handle_event(frame)`, `connected_bssid()`.
`set_cqm_rssi(Option<CqmRssiConfig>)` retains mac80211's software CQM policy:
no ath11k WMI command is required because this profile does not filter
associated AP beacons. It exposes CQM_RSSI_LIST and uses their four-sample
1/16-dBm EWMA for either singleton hysteresis crossings or cfg80211's moving
adjacent low/high RSSI range, producing deferred cfg80211 notifications.
`supports_bss_survey` gates the WMI BSS-channel-info service.  A requested
survey while a vdev has an operating chanctx and no scan is active serializes
`WMI_PDEV_BSS_CHAN_INFO_REQUEST_CMDID` (READ) for this pdev; its 64-bit
firmware counters are divided by the target's 320,000 ticks/ms exactly as
`ath11k_mac_update_bss_chan_survey`, retaining total, busy, BSS-RX and TX
times plus the noise floor.  The ordered runtime worker owns that request;
the public dump path exposes the most recent complete sample rather than
blocking a generic-netlink syscall for Linux's three-second WMI wait.
`configure_antenna` / `set_antenna` preserve Linux ath11k's
`cfg_{tx,rx}_chainmask`: an accepted `SET_WIPHY` pair rebuilds local
HT/VHT/HE stream maps, programs `WMI_PDEV_PARAM_{TX,RX}_CHAIN_MASK` once on
the live physical pdev, and is replayed before every later vdev creation or
recovery start. `configure_rts_threshold` / `set_rts_threshold` retain
`WMI_VDEV_PARAM_RTS_THRESHOLD`, apply it to a live vdev, and make every
sibling vdev worker converge to the new value. The native fragmentation
threshold operation remains intentionally unsupported, matching Linux
ath11k: target firmware cannot transmit More-Fragments frames.
`NL80211_CMD_SET_TX_BITRATE_MASK` is retained per WCN6855 vdev, not per
physical radio. The generic nl80211 layer preserves each active-band legacy,
HT, VHT and HE MCS mask plus GI/LTF choices. ath11k rejects FORCE_LGI and
the same non-contiguous multi-MCS VHT/HE masks Linux rejects
(`mac_peer::validate_tx_bitrate_band` with `vht_mcs_range_present` /
`he_mcs_range_present`, the ports of `ath11k_mac_{vht,he}_mcs_range_present`:
VHT 0-7/0-8/0-9, HE 0-7/0-9/0-11 only; an earlier NARF HE predicate that
also accepted 0-8/0-10 — which `he_limit` would have widened to 0-9/0-11 —
is fixed). Non-contiguous RATEMASK programming is inapplicable rather than
missing: upstream `ath11k_mac_op_set_bitrate_mask` returns `-EINVAL`
("setting %d mcs values in bitrate mask not supported", "TODO: Handle
multiple VHT MCS values setting using RATEMASK CMD"), and neither ath11k nor
ath12k defines a `WMI_TAG_VDEV_CONFIG_RATEMASK` payload or ever sends
`WMI_VDEV_RATEMASK_CMDID`; there is no firmware layout to port
(`mac_tests.rs::smoke_ath11k_mac_bitrate_mask_ranges`). It limits every WMI peer-association
rate set by the requested mask, programs VDEV NSS/LDPC/SGI and HE fixed or
autorate GI/LTF parameters, then sends a peer-association update with
`is_assoc = false` for every already-associated station or AP client. A
single compatible VHT, HE or HT MCS becomes `WMI_PEER_PARAM_FIXED_RATE`; an
unrestricted/multi-rate policy clears that override. The policy is retained
by `Ath11kNetdev` across `Mac::new` during reset and is installed before
future STA/AP peer association, matching `ath11k_vif::bitrate_mask`.
Debugfs-class firmware diagnostics (`mac/diag.rs`). Linux ath11k exposes
these only through debugfs, never nl80211, so NARF provides them as driver
APIs: `Mac::twt_add_dialog` / `twt_del_dialog` / `twt_pause_dialog` /
`twt_resume_dialog` port `ath11k_write_twt_*_dialog` (refuse with
`-EOPNOTSUPP` while `ar->twt_enabled` is off; for a station vif the add
re-arms the pdev engine with `sta_cong_timer_ms = 0` — disable + enable —
and the delete or a failed add restores the defaults; `vdev_id` is always
the vif's) over the byte-exact `wmi::twt_{add,del,pause,resume}_dialog_cmd`
(`struct wmi_twt_*_dialog_params_cmd`; flag bits 8–11 above the u8 TWT setup
command). `WMI_TWT_ADD_DIALOG_EVENTID` is decoded
(`decode_twt_add_dialog_event`, routed to its vdev), a nonzero status is
logged with `ath11k_wmi_twt_add_dialog_event_status`'s strings and kept for
`Mac::take_twt_add_dialog_events` (bounded 16). Linux parses no DEL / PAUSE /
RESUME completion event (they fall to "Unknown eventid"); NARF likewise
leaves them `WmiEvent::Unhandled`. Radar-detector diagnostics: the runtime
records every `WMI_PDEV_DFS_RADAR_DETECTION_EVENTID` once, before any vdev
sees it, in a radio-wide `RadarDiagnostics` (latest detector report — mode,
frequency, width, detector/segment id, timestamp, chirp, frequency offset,
sidx —, acted-on / ignored / invalid-pdev counts) read with
`Shared::radar_diagnostics`; `Shared::set_dfs_block_radar_events` is
`dfs_block_radar_events` (reports recorded, `DataPort::radar_events_blocked`
keeps `ieee80211_radar_detected` from running), and `Mac::simulate_radar`
is `ath11k_wmi_simulate_radar` (`WMI_UNIT_TEST_CMDID`, DFS module 0x2b,
token 0xAA, args `{0, pdev_id, 0}`; `-EINVAL` without a started AP vdev,
offered only on a 5 GHz radio). Tests:
`mac_tests.rs::smoke_ath11k_mac_twt_dialog_control`,
`smoke_ath11k_mac_radar_diagnostics`. Userspace reachability needs a
driver-diagnostics surface in the shared `narf_wireless` crate.
`Ath11kNetdev::tx_power_dbm` returns the latest complete physical-pdev firmware
power sample, falling back to the active vdev's retained `bss_conf.txpower`
equivalent when no sample is current. `GET_INTERFACE` publishes that dBm value
as signed mBm in `NL80211_ATTR_WIPHY_TX_POWER_LEVEL`. Its synchronous read
coalesces a refresh for the ordered runtime worker; it never waits for WMI in
the netlink syscall. `Mac::tx_power_query_pdev` requires a started vdev with a
channel, idle scan and no DFS CAC; the physical runtime additionally checks
sibling CAC before sending. With no channel and no fallback, the attribute is
absent.

`Shared::refresh_tx_power(pdev_id)` owns one physical untagged statistics
transaction across all vdevs, after the ordered caller validates its actual MAC
channel context; the interface-combination reservation cache is not used as
firmware channel proof during reconstruction. It posts `WMI_REQUEST_STATS_CMDID` with
`WMI_REQUEST_PDEV_STAT`, vdev0, zero peer and the exact pdev, using the real
CE/HTC/WMI credit/command path. It accepts only a checked `WMI_UPDATE_STATS`
header44 with precisely one pdev, no other announced records, and one ordered
228-byte ARRAY_BYTE record (base7/TX35/RX15 dwords). Duplicate/missing/truncated
TLVs, malformed inventories, unsolicited responses and a foreign pdev cannot
publish a sample or retire the request. `chan_tx_pwr` is base dword6, divided
by two as Linux's integral-dBm readback; it is firmware's reported minimum
after target/CTL/regulatory/PSD constraints, never a new host TX grant.

Samples remain current for one second. Channel reservations/rollback/release,
new BIOS SAR state and firmware-crash/reconstruction invalidate the cache.
An invalidation retains an outstanding request but prevents its old response
from entering the next channel's cache. Firmware supplies no request nonce:
cancelled or expired transactions are not reused until their genuine terminal
receipt or a completed physical transport reset. A cancelled pre-publication
lock waiter therefore conservatively needs reset. A known native send failure
permits retry only when no command was published. A monotonic transaction token
is checked under the runtime lock before every native send; an old lock/credit
waiter cannot post into, publish or roll back a successor after physical reset.
This cache owns no DMA and
does not reclaim transport allocations. Two portable native wire/state smokes
and four real CE/HTC/WMI integration smokes cover literal geometry, malformed
events, WCN6855/QCA6390 readback, fallback, coalescing, cancelled lock ownership,
native send failure, late receipts, cache invalidation and an actual native
firmware reset with an unscheduled old waiter and fresh successor. Composed integration
fixtures remain x86-only; portable wire/state tests run on both architectures.
Before a management frame enters WMI, ath11k mirrors
`ath11k_mac_mgmt_action_frame_fill_elem_data`: for Radio Measurement Link
Measurement Request it fills the current and regulatory/hardware-maximum
power bytes; for Link Measurement Report it fills the TPC Report's transmit
power byte and leaves the unavailable link margin intact. The fill precedes
PMF protection and malformed or unrelated actions still transmit unchanged.
Linux ath11k's `NL80211_EXT_FEATURE_STA_TX_PWR` is also exposed. Its
`NL80211_ATTR_STA_TX_POWER_SETTING` path programs the mapped AP or AP-client
peer with `WMI_PEER_USE_FIXED_PWR`: automatic sends zero, while limited power
accepts only 1 through 70 dBm. The nl80211 fixed enum is deliberately parsed
but rejected with `-EINVAL`, matching `ath11k_mac_op_sta_set_txpwr`'s missing
power-value behavior. AP client policies are retained in the AP peer record
and replayed after peer association; a managed-station policy is retained by
`Ath11kNetdev` across `Mac::new` and replayed after its BSS peer returns.
`NL80211_ATTR_4ADDR` is supported for station vdevs. `Ath11kNetdev` retains
the cfg80211 managed-station state across `Mac::new` and reports it in every
interface reply. When a BSS peer is live, its ordered worker mirrors
`ath11k_mac_op_sta_set_4addr` by sending `WMI_PEER_USE_4ADDR = 1` on enable
(Linux leaves the target peer setting uncleared on disable). The runtime then
uses ToDS|FromDS native-wifi headers with address two = the station, address
three = the original Ethernet destination and address four = the original
Ethernet source. Enabling also queues mac80211's 30-byte unencrypted,
minimum-rate four-address Null notification. Four-address multicast frames
select the mapped BSS peer's TCL metadata and `TO_FW`, matching
`ath11k_dp_tx`'s WDS-offload path.
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
  `determine_chan` (HT/VHT operation → 20/40/80/160 MHz and non-contiguous
  80+80 MHz,
  downgraded until usable), `vdev_phymode` (`ath11k_phymodes`), `peer_assoc_prepare`
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
  the normal no-WoW system-suspend route reaches the same disassociate/stop
  teardown before the cold HIF/MHI cycle).
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
  from it. SAE-PK validates the AP Confirm proof (Modifier AES-SIV recovery,
  password fingerprint and ECDSA KeyAuth) before accepting the PMK. Not done:
  password identifiers, groups 20 / 21 and FT-SAE (needs FT authentication:
  MDE / FTE, R0KH / R1KH). ath11k does not advertise
  `NL80211_EXT_FEATURE_SAE_OFFLOAD` (upstream mac80211 drivers never do), but
  its userspace-SME path implements SAE over `NL80211_CMD_AUTHENTICATE` as
  wpa_supplicant expects; the in-kernel `associate` path remains available for
  autoconnect.
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
  connection width: DCM max RU, 40 / 160 / 80+80 bits, sounding / STBC above 80
  MHz) after VHT (`before_he[]` split). At association success
  `ieee80211_he_cap_ie_to_sta_he_cap` (MCS intersection with the negotiated
  contiguous-160 or 80+80 capability) from the response, HE bandwidth / NSS; `ath11k_bss_assoc`
  sends `WMI_VDEV_PARAM_SET_HEMU_MODE` (`ath11k_mac_vif_recalc_sta_he_txbf`)
  before PEER_ASSOC, whose HE fields follow `ath11k_peer_assoc_h_he`
  (`WMI_PEER_HE`, TWT flags, MAC / PHY words, `he_oper.params & 0xffffff`,
  PPET, 80 MHz plus contiguous-160 or indexed 80+80 MHz MCS sets when
  negotiated, and the NSS-ratio-constrained wide-channel peer override) and `ath11k_mac_get_phymode_he` /
  `MODE_11AX_HE*_2G`; OBSS spatial reuse from the AP's SR element
  (`ieee80211_he_spr_ie_to_bss_conf`); then `BSS_CHANGED_HE_BSS_COLOR`'s
  STA arm (BSS color change enable, collision detection 10 s / 200 ms
  scan). An HE association response's extension-38 MU-EDCA Parameter Set is
  parsed as its four BE/BK/VI/VO records. For each mac80211 AC callback the
  local legacy WMM update is followed immediately by the matching incremental
  `WMI_WMM_PARAM_TYPE_11AX_MU_EDCA` update, retaining the ECW exponent nibbles
  and MU-EDCA timer exactly as ath11k does, then by the AC's U-APSD write.
  Subsequent associated beacons compare WMM and MU-EDCA parameter-set counts
  as one generation and replay that identical ordered AC programming only on
  change; the counts are retained before malformed WMM records are rejected,
  matching mac80211's no-retry behavior for a broken AP. A missing or invalid
  association-response WMM parameter set leaves QoS enabled with defaults and
  disables later WMM beacon tracking, avoiding mac80211's known invalid/valid
  layout oscillation.
  `NL80211_CMD_SET_CQM` supports mac80211's singleton and CQM_RSSI_LIST RSSI
  monitors for a station/P2P-client vdev. The target does not need a separate
  CQM command: WCN6855 leaves beacon filtering to the host, so four
  associated-AP beacon samples feed Linux's 1/16-dBm EWMA, which is also
  returned as `NL80211_STA_INFO_SIGNAL_AVG`, and drive either
singleton hysteresis or the moving low/high range before
`NL80211_CMD_NOTIFY_CQM` is multicast.
  When firmware exposes `WMI_TLV_SERVICE_TX_DATA_MGMT_ACK_RSSI`, ath11k also
  advertises ACK_SIGNAL_SUPPORT and exposes WBM's latest successful ACK RSSI
  as `NL80211_STA_INFO_ACK_SIGNAL` in `GET_STATION`.
  It always advertises SET_SCAN_DWELL: a `TRIGGER_SCAN` measurement duration
  is copied to all WMI active/passive dwell fields and its burst duration;
  the timeout uses Linux ath11k's capped channel-rest plus per-channel event
  overhead computation.
  The wiphy's 512-byte scan-IE limit is enforced before a caller's Probe
  Request IEs are appended after mac80211-style capability IEs in the WMI
  start-scan extra-IE array.
  An infrastructure MBSSID transmitter mirrors each stable AP BSS-color
  update onto its live non-transmitting profile vdevs through their separate
  WMI workers, as mac80211's transmitting-BSS propagation does.
  Six GHz requires HE + WMM and a valid HE 6 GHz Operation; the
  station derives a 20/40/80/160 MHz or non-contiguous 80+80 MHz ChanDef,
  sends HE 6 GHz Band
  Capabilities, and applies the operation's LPI / standard-power / very-low-
  power AP type to the default-client regulatory rules. Firmware's client
  type selects the default or subordinate TPE category. It parses Power
  Constraint and all valid local / regulatory-client Transmit Power
  Envelopes, selects the Linux-precedence envelope, and sends the
  resulting post-vdev-start `WMI_VDEV_SET_TPC_POWER_CMDID` power levels.
  TWT requires the AP HE responder bit *and* Extended Capabilities responder
  bit; a requester-capable firmware then receives ath11k's default
  `WMI_TWT_ENABLE_CMDID` policy after association and
  `WMI_TWT_DISABLE_CMDID` during teardown. The two 80+80 centre frequencies
  flow through `ChanDef`, vdev-start WMI, separate VHT/HE phymodes, HE MCS
  set index 2, and the distinct 80+80 NSS override field. Trusted beacon and
  Spectrum-Management CSA/ECSA elements are parsed with the cfg80211 operating
  class / Wide-Bandwidth CSA rules, restricted to the current band and local
  HT/VHT/HE/regulatory capability, then scheduled at the advertised TBTT.
  Mode-1 CSA closes the data port, sends a CSA-cause `WMI_VDEV_RESTART`, re-ups
  the station vdev, and reopens only after a beacon confirms the new channel;
  an unsupported or failed switch becomes a local connection loss. Step 276
  `HE_PARAM` (console; Linux warns). `ath11k_mac_config_obss_pd` is AP-only
  (mac80211 never signals `BSS_CHANGED_HE_OBSS_PD` for a station): START_AP's
  mandatory SR control plus optional 1..=20 offsets and two eight-byte SRG
  bitmaps drive pdev threshold, per-AC and SR-prohibit settings after the AP
  vdev comes up. Firmware with `WMI_TLV_SERVICE_SRG_SRP_SPATIAL_REUSE_SUPPORT`
  additionally receives the six `wmi_pdev_obss_pd_bitmap_cmd` SRG/non-SRG
  updates. Without that service, Linux's SNR-form non-SRG threshold is used.
- GTK low-power rekey, network detection and WoW system suspend:
  `NL80211_CMD_SET_REKEY_OFFLOAD`
  retains the userspace
  KEK, KCK, optional AKM and big-endian replay counter in `Mac` without
  logging secret bytes (`ath11k_mac_op_set_rekey_data`). The later WoW/power
  boundary invokes `set_gtk_rekey_offload`: enable emits the exact 52-byte
  `WMI_GTK_OFFLOAD_CMDID` layout; resume requests firmware status before
  disabling the engine. `WMI_GTK_OFFLOAD_STATUS_EVENTID` reconstructs the
  firmware's low/high counter words, updates saved state and multicasts
  `NL80211_CMD_SET_REKEY_OFFLOAD` with the refreshed big-endian counter, as
  `ieee80211_gtk_rekey_notify` does. Awake GTK rekeys remain normal EAPOL
  Group Key Handshakes. `SET_WOWLAN` retains validated disconnect, magic,
  GTK-rekey, masked-pattern and `NET_DETECT` policy. When
  `WMI_TLV_SERVICE_NLO` is present, `NET_DETECT` accepts Linux's nested
  scheduled-scan match/plan/SSID/channel/delay/random-MAC attributes (up to
  16 match sets, 60 channels and two plans), advertises the corresponding
  wiphy limits plus `NL80211_FEATURE_ND_RANDOM_MAC_ADDR`, and translates the
  retained configuration into the WMI network-list-offload TLVs at WoW
  entry. The stop form is sent before wake-event cleanup on failure and
  resume. Linux also accepts up to 512 probe-request IE bytes for this
  command although its NLO WMI layout cannot emit them; NARF retains and
  returns those bytes through `GET_WOWLAN` while preserving Linux's zero IE
  bitmap on the wire. The async system-PM hook flushes TX, clears stale WMI
  state, programs triggers, ARP/NS offload, optional GTK offload, filter and
  keepalive, enables WoW and waits for the HTC EP0
  suspend completion before stopping shadow timers, disabling CE/DP service
  and moving MHI to M3. Resume forces M0, enables CE/DP, waits for
  `WMI_WOW_WAKEUP_HOST_EVENTID`, and removes temporary state. Without a WoW
  policy the station is disconnected/stopped, MHI powers down, and resume
  reconstructs firmware/CE/DP/WMI and the prior administrative vdev without
  silently reconnecting.
- BIOS SAR policy: when `WMI_TLV_SERVICE_BIOS_SAR_SUPPORT` is present, the
  physical WCN6855 wiphy publishes Linux ath11k's eleven fixed frequency
  ranges and `NL80211_CMD_SET_SAR_SPECS`. A valid replacement builds the
  exact 22-byte BIOS table (one limit per range duplicated for RF chain one),
  sends the zeroed geo-table command followed by the SAR-table command, and
  retains the desired table at radio scope. The first MAC opener replays it
  after a cold resume or firmware recovery before recreating vdev traffic.
- Physical `SET_WIPHY`: GET_WIPHY exposes current and available TX/RX chain
  masks plus the retained RTS threshold. A full TX/RX chain-mask pair is
  normalized by nl80211 (all ones means all available chains); the runtime
  shares it between the four supported-family vdevs so the first active worker sends
  the pdev WMI update while every MAC rebuilds its host capability maps. RTS
  updates are sent to each live vdev and retained for the initial
  `VDEV_CREATE` sequence and recovery. Fragment-threshold input below 256 is
  invalid, otherwise it reports Linux ath11k's `-EOPNOTSUPP`.
- Multiple BSSID / EMA AP: when
  `WMI_TLV_SERVICE_MBSS_PARAM_IN_VDEV_START_SUPPORT` is present, WCN6855
  advertises four MBSSID interfaces and an EMA profile periodicity of eight
  through nested `NL80211_ATTR_MBSSID_CONFIG`. `START_AP` translates the
  transmitting or non-transmitting role into `WMI_HOST_VDEV_FLAGS_*` in
  `WMI_VDEV_START_REQUEST_CMDID`; a non-transmitting VDEV_UP additionally
  carries the transmitter BSSID, profile index and `1 << bssid_indicator`.
  The transmitter's raw MBSSID elements become one ordinary template or a
  WMI EMA template family (template count/index and first/last bits in
  `ema_params`); matching RNR elements and common extra RNRs follow Linux
  mac80211's per-profile layout. A child START_AP waits until its transmitter
  has published that family, and an already-up non-transmitting profile is
  never sent a replacement template because firmware crashes on that command.
  `DEL_INTERFACE` of the transmitter cascades to registered non-transmitting
  profiles on the same physical radio.
- Six-GHz discovery: WCN6855 exposes `NL80211_EXT_FEATURE_FILS_DISCOVERY` and
  `NL80211_EXT_FEATURE_UNSOL_BCAST_PROBE_RESP`. The FILS nested form requires
  min/max interval and a 42..=2304-byte action-frame template (each interval
  at most 10,000 TU); unsolicited Probe Response requires its 0..=20-TU
  interval and a template up to 2304 bytes. An empty nested form deletes that
  family. `WMI_FILS_DISCOVERY_TMPL_CMDID` sends FILS templates,
  `WMI_PRB_TMPL_CMDID` sends unsolicited Probe Response templates with a zero
  `WMI_BCN_PRB_INFO`, and `WMI_ENABLE_FILS_CMDID` selects the interval/mode.
  As Linux ath11k does, a nonzero FILS maximum takes precedence over a nonzero
  unsolicited interval; neither sends the zero-interval disable. A CSA's
  unsolicited update is committed only after its target-channel vdev restart;
  an unsuccessful discovery WMI update is reported but does not undo that
  completed CSA.
- FTM responder: when `WMI_TLV_SERVICE_RTT` is set, WCN6855 advertises
  `NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER`. `START_AP`, `SET_BEACON`, and
  the post-CSA beacon accept the enabled nested responder form and retain its
  optional LCI/Civic Measurement Report bodies. As Linux ath11k does,
  `WMI_VDEV_PARAM_ENABLE_DISABLE_RTT_RESPONDER_ROLE` is the only firmware
  operation: it is sent after the relevant AP vdev start/restart, and a WMI
  failure is reported without undoing the otherwise completed AP transition.
- HE OBSS Packet Detection: `START_AP` accepts
  `NL80211_ATTR_HE_OBSS_PD`'s mandatory spatial-reuse control, optional
  1..=20 offsets and exact 8-byte SRG color/partial-BSSID bitmaps. After AP
  vdev-up, Linux ath11k's pdev threshold, per-AC and SR-prohibit sequence is
  sent. The SRG service bit additionally triggers all six pdev bitmap command
  forms; lacking it selects Linux's legacy non-SRG SNR threshold. Failure is
  best effort and leaves the beaconing vdev intact.
- HE BSS color: with `WMI_TLV_SERVICE_BSS_COLOR_OFFLOAD`, WCN6855 advertises
  `NL80211_EXT_FEATURE_BSS_COLOR`. The 1..=63 nested color plus disabled and
  partial flags are retained from START_AP, SET_BEACON, or the post-CSA beacon.
  After AP vdev start/restart ath11k sends both the 5-second AP
  `WMI_OBSS_COLOR_COLLISION_DET_CONFIG_CMDID` and
  `WMI_VDEV_PARAM_BSS_COLOR` (enabled color shifted to bit 24, or
  `0x8000_0000` disabled). The partial bit has no ath11k WMI field. Each
  command is best effort: an error is reported but never rolls the AP vdev
  back down. Firmware `WMI_OBSS_COLOR_COLLISION_DETECTION_EVENTID` detection
  events retain the first 64-bit color bitmap for mac80211's 500-ms
  coalescing window, then notify hostapd through MLME
  `NL80211_CMD_OBSS_COLOR_COLLISION`; disable and free-slot events are not
  surfaced.
  `NL80211_CMD_COLOR_CHANGE_REQUEST` is infrastructure-AP-only: its nested
  temporary countdown beacon (and optional Probe Response) is re-uploaded at
  each TBTT, color is disabled during that interval, then the retained normal
  template and selected color are restored. The runtime emits MLME
  COLOR_CHANGE_STARTED/COMPLETED, or restores the original state and emits
  COLOR_CHANGE_ABORTED when a queued WMI operation fails. The request rejects
  a non-transmitting MBSSID BSS or active CSA; an arriving CSA aborts the
  color change first.
- PMF / 802.11w (`MfpState`): ath11k returns 1 from `ath11k_mac_op_set_key`
  for every BIP suite, so BIP stays in host software on WCN6855: the IGTK
  (M3 / Group 1/2, IPN as `rx_pn`) never reaches firmware. Receive (from the
  AP while `sta->mfp`, `ieee80211_rx_h_decrypt` + `ieee80211_drop_unencrypted_mgmt`):
  group-addressed robust frames need the matching BIP-CMAC-128 64-bit or
  BIP-CMAC-256 / BIP-GMAC 128-bit MMIE (key 4 / 5, IPN > `rx_pn`) and lose it;
  unicast protected ones come decrypted by firmware with a CCMP-family header
  plus the suite's 8- or 16-byte MIC (`ath11k_mgmt_rx_event`), are replay
  checked on the PTK's management PN, then stripped; unprotected
  unicast robust frames are dropped, except deauth / disassoc before a GTK
  exists ("Permit unprotected deauth/disassoc frames during 4-way-HS").
  Transmit: unicast robust frames (deauth, BACK, SA Query) get the host
  CCMP-family header (`GENERATE_IV_MGMT`, PN = ++tx_pn, key 0), the Protected
  bit, and the selected suite's 8- or 16-byte MIC tail that
  `ath11k_mac_mgmt_tx_wmi` reserves. SA Query: AP
  Requests answered (`ieee80211_process_sa_query_req`); an unprotected
  deauth / disassoc with reason 6 / 7 while authorized starts
  wpa_supplicant's SA Query (`sme_event_unprot_disconnect`, ≤ 1 per 10 s,
  a Request every 201 TU, > 1000 TU unanswered → deauth reason 2,
  `step::SA_QUERY_TIMEOUT` detail = Requests). A group-addressed
  deauth / disassoc from the AP is accepted like a unicast one
  (`ieee80211_accept_frame`). AP/GO uses the same primitives: an MFP
  `NEW_STATION` sets `WMI_PEER_PMF`; its unicast robust TX uses that client's
  installed PTK and management PN, received protected frames are replay
  checked and stripped before hostapd sees them, and a default IGTK 4/5
  appends the selected BIP MMIE with monotonically increasing IPN to group
  robust-management TX. The IGTK never reaches firmware.
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
   `cmd` carried across TIDs as Linux), then `set_peer_sec_type`. A
   pairwise TKIP install retains just the eight-byte RX Michael direction in
   `PeerRx`; any pairwise key disable clears it.

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

`Port` (`Arc<Shared>, vdev_id`) implements `mac::WmiPort` (`send` =
`ath11k_wmi_cmd_send` with credit / CE-full retry for 3 s;
`next_event`; `mgmt_tx` = IDR id (≤ 512 pending) + DMA32 copy +
`wmi::mgmt_send_cmd(vdev, id, frame, paddr, 0, false)`, freed on
`mgmt_tx_done`; `now_ms`; `max_msg_len`; `random_bytes` = the fallible
`Shared::new` RNG callback (`fn(&mut [u8]) -> Result<(), errno>`), with
`narf_crypto::try_fill_random_bytes` for native devices) and `mac::DataPort`
(`ppdu_stats_req` = `htt::ppdu_stats_cfg_msgs`; `mon_status_default` =
`dp.mon_status_default_msgs` sent, last result returned as Linux, reap
timer armed; `vdev_tx_attach` = `VifTx::attach`; `wait_peer_mapped`
(mapped: BSS peer recorded, AST from the peer as `ath11k_peer_create`;
unmapped: station data state cleared); `peer_setup` per §3.10 step 1;
`peer_cleanup` per step 2; `rx_pn_replay_config` per step 6 + PTK flag;
`send_eth` / `recv_eapol`; `probe_ap` = `Shared::probe_ap` (builds a
requested-status Null / QoS Null and waits at most 500 ms); `set_authorized`;
`set_sta_wme`; `dfs_nop_active` / `record_dfs_nop` maintain one physical-radio
DFS non-occupancy table across the otherwise per-vdev wiphy snapshots). Every
port receives only its vdev's WMI events, data RX,
management-TX completion state and TX queues; PDEV-wide regulatory, radar and
firmware-recovery events are deliberately broadcast by `Shared` to all live
vdev workers. Linux's
synchronous calls (`vdev_tx_attach`, `peer_cleanup`, `set_authorized`,
`set_sta_wme`, `mgmt_tx_done`) are queued (`SyncOp`) and applied in order
at the next locked step.

For an AP/GO vdev, `Port` retains separate `ApTxState`: the self peer exists
before group keys, each WMI-associated client records authorization, PTK and
WMM state, group traffic is held until a protected AP has a GTK, and Ethernet
TX builds a FromDS native-Wi-Fi header for the selected client or group
receiver. RX accepts only HTT-mapped AP clients, admits EAPOL before the
client's port opens, and otherwise requires that client's authorization. The
client's `NEW_STATION` / `SET_STATION` capability record supplies its legacy,
HT, VHT, HE and 6-GHz capability bodies to `WMI_PEER_ASSOC_CMDID`, intersected
with the local radio. Per-client PMF enters `WMI_PEER_ASSOC_CMDID`; CCMP PTK
management PNs are host-tracked per client, while IGTKs 4/5 are software
BIP-CMAC keys selected by `SET_KEY` default-management state and used for
outbound group robust-management MMIEs. Nested AP U-APSD requests become the
peer APSD/rate flags and the target's AP-PS UAPSD, maximum-service-period and
disabled-SIFS settings; target firmware then owns client buffering and TIM
maintenance.

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
`build_sta_nullfunc` is `ieee80211_nullfunc_get(.., qos_ok = true)`: addr1
and addr3 are BSSID, addr2 is the own address, sequence control is zero;
a WMM AP gets protected QoS Null with QoS control `[7, 0]` on AC VO and a
non-WMM AP gets regular Null on AC BE. `Dp::tx` removes its QoS control and
clears the subtype as `ath11k_dp_tx_encap_nwifi` does before firmware sees it.
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
`ieee80211_build_hdr`) and queues the rest on the selected TID
(`ieee80211_select_queue` with the current `sta->sta.wme`). Each vdev has
16 TID TXQs (`fq_tin`); their shared 4096-bucket flow table is selected by a
stable L2/L3/L4 hash (the frame-ring ABI intentionally has no private
`skb_get_hash`). New and old flow lists use Linux's 300-byte deficit round
robin. The global `fq` limits are 8192 packets / 16 MiB; overlimit removes up
to 32 packets from the fattest flow's head. ECN-enabled CoDel uses mac80211's
20-ms target and 100-ms interval: ECT IPv4/IPv6 frames are CE-marked, then
non-ECT frames are reported as terminal TX drops. `Rt::tx_push`
(`ieee80211_handle_wake_tx_queue`) schedules active TIDs round robin within
their AC and hands frames to `Dp::tx` VO → VI → BE → BK, skipping ACs whose hardware queue
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
`Shared::send_eth_tx_status(eth, timeout)` is the control-port consumer
entry point; `Shared::probe_ap(timeout)` builds the connection monitor's
Null / QoS Null directly, correlates it through the same ACK ID map and
removes the ID on timeout.

For the associated peer, the first MSDU of a TQM PPDU also retains its valid
`hal_tx_rate_stats.info0`. `runtime::tx_rate_info` mirrors
`ath11k_dp_tx_update_txcompl`: BW / packet type / SGI / MCS and OFDMA
tone-count fields decode as legacy, HT, VHT, or HE; short CCK preamble is
removed from the 11b hardware code; the link's negotiated `sta.rx_nss` is the
fallback NSS; and HE 1.6/3.2 µs GI plus 26/52/106/242/484/996/2×996-tone RU
are reported through `RateInfo`. Its bitrate uses the same integer formulas
as `cfg80211_calculate_bitrate_*`. `Ath11kNetdev::station_info` exposes this
as `NL80211_STA_INFO_TX_BITRATE`; an OFDMA rate sends
`NL80211_RATE_INFO_HE_RU_ALLOC`, never a misleading channel-width attribute.
Firmware HTT completions lack a rate record. Fast RX MSDU descriptors do not:
their `info3` packet type / MCS / SGI / receive-BW / MIMO-SS bitmap is carried
in `RxMsdu` and `runtime::rx_rate_info` mirrors `ath11k_dp_rx_h_rate` for
legacy / HT / VHT / HE (the bitmap's popcount is NSS). It becomes
`NL80211_STA_INFO_RX_BITRATE` only after local-address checks identify the BSS
peer. The descriptor does not provide HE RU allocation, so HE RX rates use the
full receive width, as Linux does.

**Netdev** (`iface::Ath11kNetdev`): `narf_net::Interface` (name from
`reserve_name("wlan%d")`, MAC from WMI READY, MTU 1500, `link_up` =
associated + authorized for a station or beaconing for an AP/GO, RX / TX frame
rings) and
`narf_wireless::WirelessNetIface` (`get_wireless_info` from the wiphy
channels (2.4 / 5 / 6 GHz, enabled only) + own HT / VHT / HE caps;
`scan`, `associate`, `disassociate` lock the mac layer (async mutex
across the operation); `set_config` accepts only the current channel;
`supports_scan_random_mac` exposes `WMI_TLV_SERVICE_SPOOF_MAC_SUPPORT`,
`supports_handshake_offload`, `reports_disconnect_events`). A random scan
sets the exact WMI spoof-MAC flag/address/mask pair; with per-channel scan
configuration, `NL80211_SCAN_FLAG_COLOCATED_6GHZ` marks only non-PSC 6 GHz
channels `SCAN_ONLY_IF_RNR_FOUND`, matching `ath11k_mac_op_hw_scan`.
When firmware exposes `WMI_TLV_SERVICE_BSS_CHANNEL_INFO_64`, it also exposes
dump-only `GET_SURVEY`: every enabled 2.4/5/6-GHz channel has a record,
current chanctxs carry `IN_USE`, and completed pdev BSS-channel-info samples
overlay noise / total / busy / BSS-RX / TX time.  A dump queues one coalesced
refresh for the runtime worker and returns its cached snapshot, because a
generic-netlink handler must not re-enter WMI completion processing.
It advertises
station, AP, P2P Device, P2P Client, and P2P GO iftypes. A down-only
`SET_INTERFACE` selects the matching STA/AP WMI vdev subtype; AP/GO nl80211
requests are serialized onto the runtime queue so their WMI completion waits
never re-enter a generic-netlink syscall. One physical `wiphy_id` groups the
root `wlan%d` netdev and up to two `NL80211_CMD_NEW_INTERFACE` children;
NARF admits firmware slots 0, 1 and 2, claimed atomically, and each child has
its own MAC address, `Mac` instance, WMI event queue, RX/TX rings, link/AP
state and unique `WDEV` id. PDEV-wide `ath11k_mac_op_start`/`stop` runs only
at the shared open-vdev refcount's zero-to-one/one-to-zero transitions.
The physical wiphy also reports and enforces NARF's four-vdev interface
combination through `NL80211_ATTR_INTERFACE_COMBINATIONS`: at most two STA,
at most four AP/P2P client/GO vdevs, one P2P Device, a total cap of four,
up to two operating channels for the target's dual-station profile, matching
infrastructure/AP beacon intervals (minimum GCD 100) and radar detection
across every ath11k-supported channel width.
The pdev has one hardware-scan engine and fixed firmware scan id, so the
shared runtime atomically grants it to exactly one vdev for a normal scan or
P2P remain-on-channel operation; a normal scan owns a cancellation-safe lease:
dropping its generic-netlink future queues WMI scan-stop on the vdev worker,
which releases the claim only after firmware is no longer using the fixed scan
id. Terminal scan, ROC expiry/cancel, teardown, and firmware reconstruction
also release their long-lived grants. Radar records its 30-minute NOP in the physical-radio table
as well as the receiving MAC's wiphy state, so siblings and newly-created
vdevs cannot select an overlapping DFS chandef even if the reporting vdev is
deleted before expiry.
`DEL_INTERFACE` may remove an up child: it is removed from nl80211 and the
net registry synchronously, then its worker completes `ndo_stop`, vdev-local
DP/mgmt cleanup and `WMI_VDEV_DELETE` before the slot is made available.
Before a reused slot binds its new MAC it clears the old vdev's pending WMI
events and DP-local link/TX/ACK state, so a late teardown or scan completion
cannot be consumed by the new interface.
The physical root cannot be deleted through this command.
`station_info` snapshots completion-backed packet / retry / failure counters,
ACK signal, HTT PPDU TX rate/duration, and monitor-status PPDU combined/chain
RSSI plus RX duration without blocking the runtime; it uses the MAC lock only
to read the negotiated AP NSS. The RX rate comes from the accepted AP MSDU's
own PHY descriptor (never from an association-width guess).
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
  `NL80211_ATTR_DISCONNECTED_BY_AP`; beacon / connection loss, rejected CSA
  (and kickout,
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
   `Ath11kNetdev::recover`: a replay-safe associated station (external SME,
   Open, or completed in-kernel RSN) or beaconing AP/GO retains carrier while
   its mac80211 state is captured; other station links go carrier off. The
   mac-layer mutex is taken,
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
   The shared channel-reservation table is logical netdev ownership, not a
   mirror of firmware memory: it stays reserved throughout physical reset,
   replay and cancellation. Losing the firmware's channel contexts cannot
   let a third distinct channel take a live STA/AP vdev's slot. A terminal
   link loss, failed vdev replay or completed interface stop clears only that
   vdev's reservation; transport failure/cancellation does not imply RF
   quiescence or reclaim any DMA. Retaining reservations also covers the
   cold transport reconstruction used by system resume.
3. `post_reconfigure_recovery` / `ieee80211_restart_hw`: a new mac layer
   from the new capabilities (`Mac::config()` kept); if the interface was
   open, the open path again (`ath11k_mac_op_start` + `add_interface`). An
   replay-safe station then recreates its channel/vdev/peer, EDCA/MU-EDCA,
   BSS and MFP state, replays PTK then GTKs, and only then re-authorizes;
   no authentication or association frame is sent. A beaconing AP/GO
   similarly restarts its beacon/MBSSID role, group keys, retained BIP keys,
   client peers, PTKs and authorization; a non-transmitting MBSSID profile
   consumes its transmitter's retained template set. Its old BA sessions are
   discarded, as in mac80211 restart. A shared PCI radio waits until every
   live vdev has finished this pass before `reconfig_complete`
   (`fail_cont_count` = 0, queues woken, `diag::note_wifi_recovered`) then
   follows. Only a pre-key in-kernel handshake lacks retained key state and
   performs the existing directed scan + `associate` retry.
   Three native CE/HTC/WMI regressions keep a real WPA2 station and a sibling
   legacy5GHz AP across reset, check both actual replayed channel contexts and
   the two-channel admission limit, fail the sibling's native VDEV_START, and
   cancel its replay after an actual native command publication. The RAM
   target assigns distinct peer IDs to different vdevs. Late credits cannot
   release the cancelled vdev's claim or reopen its stopped native queues.
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

### 3.12 AHB / platform glue (`ahb.rs`, Linux `ahb.c`)

Built on the Qualcomm SoC layer `narf-drivers-qcom-soc`
(`drivers/soc/qcom/specification/spec.md`): devicetree platform devices,
SCM/PAS, MDT loader, SMEM, SMP2P, GCC resets, Q6 WCSS and PAS remoteprocs.

```rust
pub enum AhbChip { Ipq8074, Ipq6018Hw10, Ipq5018Hw10, Wcn6750Hw10 }
pub const AHB_OF_MATCH: [(&str, AhbChip); 4];          // ath11k_ahb_of_match
impl AhbChip { fn from_compatible(&[String]) -> Option<Self>; const fn params(self) -> AhbHwParams;
               const fn wlfw_hw_params(self) -> WlfwHwParams; const fn hw_rev(self) -> HwRev; }
impl AhbHwParams { const fn ce_offset(&self) -> u32; const fn hw_params(&self, HwRev) -> HwParams; }
impl HwRev { const fn ahb_chip(self) -> Option<AhbChip>; }   // + Ipq8074/Ipq6018Hw10/Ipq5018Hw10/Wcn6750Hw10
pub struct HwParams { .., ce_offset: u32 }                  // ATH11K_CE_OFFSET
pub const MSI_CONFIG_NONE, HW_HAL_PARAMS_IPQ8074, HW_HAL_PARAMS_WCN6750;
pub fn hal::create_config_ce(&HalRegs, ce_off) -> [SrngConfig; N];
pub struct AhbHwParams { chip, name, fw_dir, max_radios, bdf_addr, regs, ring_mask,
    qmi_service_ins_id, host_ce_config, target_ce_config, svc_to_ce_map, ce_ie_addr,
    ce_remap, single_pdev_only, rxdma1_enable, htt_peer_map_v2, supports_shadow_regs,
    credit_flow, hal_desc, hybrid_bus_type, static_window_map, fixed_fw_mem,
    fixed_bdf_addr, smp2p_wow_exit, mac_map, msi }
pub const IRQ_NAMES: [&str; 52];                           // ahb.c irq_name[]
pub fn ce_irqs(&AhbHwParams) -> Vec<(ce_id, irq_idx)>;      // ath11k_ahb_config_irq
pub fn ext_irq_groups(&AhbHwParams) -> [Vec<u8>; 11];      // ath11k_ahb_config_ext_irq
pub fn ce_irq_enable_bits(&AhbHwParams, ce_id, ce_offset) -> Vec<(reg, bit)>;
pub fn wcn6750_window_offset(&HalRegs, offset) -> u32;    // static windows
pub fn smp2p_power_save_value(seq_no, PowerSaveMsg) -> u32;
pub const AHB_CE_WINDOW_OFFSET: u32;                       // ATH11K_CE_OFFSET for a CE remap
pub struct AhbIo<R: RegIo> { mem, ce: Option<R>, window: Option<&HalRegs> } // impl ChipIo
pub fn ce_irq_set(&impl ChipIo, &AhbHwParams, ce_id, ce_offset, enable);    // ath11k_ahb_ce_irq_{en,dis}able
pub fn ce_irqs_set(&impl ChipIo, &AhbHwParams, ce_offset, enable);
pub fn find_ahb_devices(blob) -> Vec<(PlatformDevice, AhbChip)>;
pub fn probe_resources(blob, &PlatformDevice) -> Result<AhbResources, AhbError>;
pub struct AhbRemote { platform: Q6Platform }             // ath11k_core_get_rproc
impl AhbRemote { fn resolve(blob, &AhbResources) -> Result<Self, AhbError>; fn loader_matches(&self, AhbChip) -> bool; }
```

`hw.rs` adds `IPQ8074_REGS`, `IPQ5018_REGS`, `WCN6750_REGS` (verbatim
`hw.c`; IPQ5018 CE offsets relative to the remapped CE window) and
`RING_MASK_IPQ8074` / `RING_MASK_WCN6750`. `power_up`/`power_down` are
`Q6Wcss::{load,start,stop}` (IPQ) or `PasRproc::{start,stop}` (WCN6750)
driven with the resources `AhbRemote` resolves.

AHB HIF (`ahb_hif.rs`, Linux `ahb.c` IRQ / start / stop paths):

```rust
pub enum AhbLineKind { Ce(u32 /* CE mask */), Dp(u32 /* ext-group mask */) }
pub struct AhbLine { intid: u32, kind: AhbLineKind }
pub fn ahb_lines(&AhbResources) -> Vec<AhbLine>;    // ath11k_ahb_config_irq / _config_ext_irq; hybrid: pcic over DT MSI
pub type LineCtl = fn(intid, on);                   // enable_irq / disable_irq_nosync
#[derive(Clone)] pub struct AhbIrq;                 // impl CeIrq + DpIrq
impl AhbIrq { new(lines, AhbHwParams, LineCtl), bind_gic(lines, AhbHwParams) -> Result<Self, IrqBindError>,
              release(), line_fired(i) /* hard-IRQ body */, lines(), masked(), fires() }
pub fn ahb_ce_hif<R: RegIo>(&AhbResources, AhbIo<R>, AhbIrq, clock) -> Result<CeHif<AhbIo<R>, AhbIrq>, TransportError>;
```

A line's hard-IRQ body masks it at the distributor (DP: every line of the
group, `ath11k_ahb_ext_grp_disable`) and records the CE / group bits in
the state the PCI MSI handlers feed (`ce::raise_ce`, `runtime::raise_dp`),
so `Rt::service` services AHB and PCI alike; `take_pending` /
`take_dp_pending` unmask the taken lines before the service pass (Linux
unmasks after it; an edge during the pass stays pending in the
distributor). `hif_start` / `hif_stop` set / clear the `CE_HOST_IE_*`
bits (`ath11k_ahb_ce_irqs_{enable,disable}`; kept under crash flush).
Lines bind through `narf_drivers_qcom_soc::irq::GicSpi`, so the GIC
backend underneath can change (the IPQ SoCs are GICv2).

DT bring-up (`ahb_probe.rs`):

```rust
pub struct AhbPlatform { res: AhbResources, remote: AhbRemote, q6_irqs: Q6Irqs, glink: GlinkEdgeDt, lines: Vec<AhbLine> }
impl AhbPlatform { fn probe(blob, &PlatformDevice) -> Result<Self, AhbError>; fn smp2p_edges(&self) -> Vec<String>; }
pub enum BringUpStep { HalCeAlloc, QmiInit, RprocIrqs, RprocBoot, GlinkStart, ConfigIrq, QmiReady }
pub trait AhbBringUp { hal_ce_alloc, qmi_init_service, async rproc_irqs, async rproc_boot, async glink_start,
                       config_irq, async qmi_ready, async rproc_shutdown }
pub async fn bring_up<B: AhbBringUp>(&AhbPlatform, &mut B) -> Result<(), (BringUpStep, AhbError)>;
pub enum AhbError { .., LoaderMismatch, Failed(errno) }
```

`bring_up` runs Linux's order (`ath11k_ahb_probe`: HAL/CE alloc →
`ath11k_core_init`: QMI service, `hif_power_up` = `rproc_boot` with the
remoteproc's Q6 lines / SMP2P edges bound first and the glink subdev
started after → `ath11k_ahb_config_irq` → QMI server arrival / firmware
ready) and shuts the remoteproc down on a failure after it booted.

DT driver: `ahb_probe::register_dt_driver()` registers `ath11k_ahb`
(`AHB_DT_COMPATIBLE` = `ath11k_ahb_of_match`) with the bus DT match table
(`narf_bus::register_dt_driver`, bus spec §3.2) at `Stage::Subsys`; a
`Stage::Device` initcall walks the boot DTB (`narf_bus::probe_all_dt`).
`ahb_dt_probe(blob, path)` = `probe_node` (→ `AhbPlatform::probe`) +
`ahb_live::spawn_bring_up`.

Production bring-up (`ahb_live.rs`):

```rust
pub trait AhbEnv: Send + Sync + 'static {
    type Regs: RegIo; type Delay: Delay; type Smc: SmcConduit; type ScmAlloc: ScmAlloc;
    type Fw: FirmwareLoader; type Dma: DmaAllocator; type Bus: GlinkBus;
    fn map(&mut self, phys, len) -> Result<&'static Regs, AhbError>;          // devm_ioremap
    fn carveout(&mut self, phys, len) -> Result<&'static mut [u8], AhbError>; // memory-region
    fn delay, firmware, scm, dma, clock;
    fn bind_lines(&mut self, Vec<AhbLine>, AhbHwParams) -> Result<AhbIrq, AhbError>;
    fn bind_q6_gic(&mut self, &Q6Irqs, &'static Q6v5) -> Result<(), AhbError>;
    fn glink_bus(&mut self, blob, &GlinkEdgeDt) -> Result<Bus, AhbError>;
    fn remote_tick(&self) {}                                                  // fixtures play the remote
}
pub struct LiveAhb<E: AhbEnv> { pub env: E, pub outcome: Option<LiveOutcome<E>>, pub failure, .. } // impl AhbBringUp
impl LiveAhb { new(env, blob), hif(), rproc_state(), qrtr_open(), glink_negotiated(), set_wlan_smp2p(v) }
pub enum LiveOutcome<E> { Ready(Box<AhbCore<E>>, Box<Dp>), Stranded(Box<AhbCore<E>>, Option<Box<Dp>>) }
pub type AhbWlfw<E> = Wlfw<GlinkQrtr<GlinkSmem<&Regs, DtKick<&Regs>>, Bus>, Fw, Dma>;
pub struct NarfAhbEnv;      // MmioRegs, NarfDelay, ArchSmc, CoherentAlloc, NarfFirmware, Dma32, AhbGlinkBus
pub enum AhbGlinkBus { Gic(GicSpi), Ipcc { line: GicSpi, regs } }   // impl GlinkBus
pub async fn bring_up_task(blob, AhbPlatform);  pub fn spawn_bring_up(blob, AhbPlatform);
pub fn ahb_runtimes() -> Vec<Arc<NarfAhbShared>>;
pub fn runtime::start_ahb(core, dp) -> (Arc<Shared<..>>, Result<[u8; 6], TransportError>);
```

`hal_ce_alloc` maps `reg[0]` (+ the IPQ5018 CE remap) into `AhbIo` and
builds the HIF (`ahb_ce_hif`); WCN6750 allocates the CE pipes only.
`rproc_irqs` maps SMEM and the TCSR mutex, creates one `Smp2p` per edge
(`qcom_smp2p_probe`) with the Q6 inbound bits, the `stop` and
`wlan-smp2p-out` outbound entries, the remoteproc object and its `wdog`
GIC line. `rproc_boot` loads the MDT from the firmware registry into the
carve-out and runs `Q6Wcss::start` (GCC resets from the DT) or
`PasRproc::start`; every wait iteration runs one `qcom_smp2p_intr` pass
per edge (so GIC- and IPCC-parented edges behave alike).
`glink_start` registers `GlinkSmem` and claims `IPCRTR` (`GlinkQrtr`)
over the `glink-edge` interrupt: a GIC SPI, or on WCN6750 the IPCC
(client, signal) behind the IPCC block's SPI, unmasked with
`ipcc_set_enabled` and drained with `ipcc_pending`. `config_irq` binds
the CE / DP lines. `qmi_ready` runs WLFW to FW_READY; WCN6750 then maps
the DEVICE_INFO BAR as `AhbIo { window: Some(WCN6750_REGS) }` (static
windows) and builds the HIF; then `CoreConfig::for_hw` +
`qmi_firmware_ready` with `DpHooks` (`DpHwParams::for_rev`). The WLFW
task hands a ready core to `runtime::start_ahb` (`Rt` + `Shared`, MAC
from `device_caps`); a failed core is kept. Not done: the AHB netdev
(`iface` registration is PCI-typed), post-boot SMP2P crash monitoring
(`fatal` / `wdog` → recovery), and RPMh / AOSS QMP votes (§8).

Per-chip `hw_ops` (`hw_ops.rs`, Linux `hw.c` `*_ops`; the `rx_desc_*`
members are `RxDescriptor`):

```rust
pub struct HwOps { name, mac_from_pdev: MacMap, wmi_init_config: WmiInitConfig, mac_id_ipq8074: bool,
                   tx_mesh: TxMesh, reo_setup: ReoSetup, ring_selector: RingSelector }
pub const IPQ8074_OPS, IPQ6018_OPS, QCA6390_OPS, QCN9074_OPS, WCN6855_OPS, WCN6750_OPS, IPQ5018_OPS: HwOps;
impl HwRev { const fn hw_ops(self) -> Option<&'static HwOps>; }
impl HwOps { hw_mac_from_pdev_id, mac_id_to_pdev_id, mac_id_to_srng_id, ring_selector(cpu, flow_hash),
             reo_setup(io, &HalRegs) }   // ipq8074 / wcn6855 / ipq5018 flavours
```

`Dp::alloc` runs `hw_ops.reo_setup` (QCA6390 now takes Linux's
`ath11k_hw_ipq8074_reo_setup`, not the WCN6855 one). Multi-pdev parts
(`single_pdev_only = false`) send `init_cmd` with
`TargetResourceConfig::ipq8074(hw_num_vdevs, hw_num_peers, num_radios,
num_rf_chains, reg_cc_ext)` (`ath11k_init_wmi_config_ipq8074`),
`hw_mode_id = preferred_hw_mode` and `wmi::band_to_mac(ext, num_radios)`
(`ath11k_fill_band_to_mac_param`) via `InitCmdParam::multi_pdev`;
`Ath11kCore::num_radios()` is SERVICE_READY_EXT's radio count capped at
`max_radios`, and `wmi_pdev_eps` keeps every connected WMI endpoint
(WMI_CONTROL / _MAC1 / _MAC2: CE3, CE7, CE9 on IPQ8074). `DpHooks::
pdev_create` runs `Dp::pdev_alloc` + its SRING_SETUP batch once per radio.
The TX ring selector input is `runtime::tx_ring_selector(rev, flow_hash)`:
the current CPU, or `txq::flow_hash(eth)` (`skb_get_hash`) on WCN6750.

`HwRev`-keyed admission: `CoreConfig::for_hw` covers all four AHB parts
(`num_rxdma_per_pdev = 1`; IPQ `single_pdev_only = false`, `num_vdevs =
16 + 1`; WCN6750 single-pdev, three vdevs), `wlfw_hw_params(HwRev)`
returns `AhbChip::wlfw_hw_params`, `RxDescriptor` decodes
`hal_rx_desc_ipq8074` for IPQ8074/IPQ6018 and `hal_rx_desc_qcn9074` for
IPQ5018/WCN6750, and `DpHwParams::for_rev` admits WCN6750 (the
single-pdev shape: one RXDMA, `ath11k_hw_hal_params_wcn6750`, 2048-entry
TCL rings, no TCL retry) and IPQ8074 / IPQ6018 / IPQ5018 / QCN9074 (multi-
pdev, one RXDMA per pdev, `rxdma1_enable`, HTT peer-map v2, TCL retry,
`ath11k_hw_hal_params_ipq8074` / `_ipq5018`, QCN9074 `full_monitor_mode`).
`Dp::pdev_alloc(.., mac_id)` allocates pdevs in order (`Dp::pdev` +
`Dp::extra_pdevs`, iterated by `Dp::pdevs()`): with rxdma1 each pdev also
gets `rxdma_mon_buf_ring` (buffered like the refill ring),
`rxdma_mon_dst_ring` and `rxdma_mon_desc_ring` with their HTT SRING_SETUP
messages (after RXDMA_DST, before MONITOR_STATUS, as
`ath11k_dp_rx_pdev_alloc`) and the monitor link descriptors posted to the
desc ring (`ath11k_dp_rx_pdev_mon_attach`); `pdev_free` releases every
pdev. `DpRingSizes` gains `rxdma_mon_{buf,dst,desc}` (4096 / 2048 / 4096).

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
  vif) only on `IFF_UP`; the reported bands include 2.4 / 5 / 6 GHz when
  firmware exposes their capability tables, while a selected BSS is always
  identified by its exact MHz frequency. HE is used on every supported band;
  station TWT requester support is advertised only when firmware exposes
  `WMI_TLV_SERVICE_STA_TWT`. `supports_sae_offload` remains false, as for
  every mac80211 driver.
- No lock is held across an `.await`: `Shared::rt` is taken for
  synchronous steps only (a recovery moves the runtime out of the slot
  instead of holding it); the mac-layer mutex is held across a control
  operation (a recovery is one) and never taken by the runtime loop
  unless free.
- Memory the firmware may DMA into is freed only after the device was
  reset or restarted its firmware (recovery), or never (failed bring-up /
  failed recovery: parked).
- HAL descriptor/doorbell and MHI publication barriers order the PCI device
  as an outer-shareable observer on aarch64 (`dmb osh`, compiler-fenced
  before and after); x86_64 uses a full memory fence. CPU-only atomic
  ordering is not substituted for device-visible DMA ordering.
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
| 7 | Connect: peer, auth/assoc via mgmt TX, EAPOL via `narf-wireless` supplicant over the DP rings, key install + PN config (**implemented, offline** for Open, WPA2-PSK/CCMP and SAE; real firmware/userspace acceptance remains) | `mac.c`, `wmi.c`, `dp_rx.c` |
| 8 | Data path: TX (Ethernet → native-wifi 802.11 → TCL → WBM completion), RX (REO dst → Ethernet II → stack / RX ring); `wlan%d` registered with `narf_net` + `narf_wireless` (**done, offline**; first hardware run pending) | `mac80211/tx.c`, `dp_tx.c`, `dp_rx.c` |
| 9 | Power: PS, WoW M3 suspend/resume or no-WoW cold HIF/MHI cycle, and firmware crash recovery (**implemented, validation deferred**: MHI RDDM / SYS_ERR + QMI late events → reset / restart, power cycle, reconfigure; WoW ACK/wakeup and normal cfg80211 disconnect/reconfigure policy) | `core.c`, `mac.c`, `mhi.c`, `qmi.c`, `wow.c` |

## 6. Dependencies

`narf-bus` (BAR, MSI), `narf-drivers-qcom-soc` (AHB: DT platform devices,
SCM/PAS, MDT, SMEM/SMP2P, GCC, Q6 WCSS/PAS remoteprocs), `narf-io` (coherent DMA), `narf-firmware`
(`firmware-2.bin` or `amss.bin` + `m3.bin`, `board-2.bin`, `regdb.bin`
— distro packages ship them `.zst`-compressed), `narf-wireless` (iface
trait, EAPOL /
SAE, registry), `narf-net` (frame rings).

## 7. Stage assignment

Stage 5 "Silicon" — real-HW Wi-Fi on the bring-up laptops.

## 8. Open questions

### Per-profile software inventory

This inventory is based on local Linux `ath11k/{core,hw,pci,mac,wmi,dp_rx}.c`,
`hal_{rx,desc}.h` and the actual NARF profile dispatch. A capability absent from
SERVICE_READY/EXT, the current band's regulatory/MAC/PHY capability or a Linux
hardware parameter is inapplicable to that running profile; absence is never
permission to emulate or advertise it. These rows are software scope, separate
from physical RF, board, firmware and userspace interoperability acceptance.

| Profile | Implemented reachable software | Remaining or inapplicable scope |
|---|---|---|
| WCN6855 HW2.0/HW2.1 | Native dynamic-window PCI/MHI/QMI/CE/HTC/WMI/DP; advertised-band legacy/HT/VHT/HE station/AP/P2P, security/keys/PMF, four-vdev/two-channel ownership, scan/ROC, recovery and PS/WoW/cold suspend; firmware power readback and retained recovery channel reservations | Native composed hardware fixtures remain x86-only: they compile on aarch64, but un-gating them (2026-10-27) killed the aarch64 test kernel inside the composed DHCP/integration fixture before the suite summary, consistent with kernel-stack overflow from by-value fixture state, so they stay gated until that footprint is reworked. DT board-variant and `memory-region` fixed-memory discovery are implemented (`board::dt_facts`, `wlfw::assign_fixed_target_mem`). Per-dialog TWT control and radar-detector diagnostics are implemented as the Linux debugfs-equivalent `Mac`/`Shared` APIs (`mac/diag.rs`; no nl80211 surface exists in Linux either). Non-contiguous RATEMASK programming and spectral diagnostics are inapplicable: Linux refuses the former with `-EINVAL` and initialises spectral only when `hw_params.spectral.fft_sz != 0`, which is false for every admitted profile (`hw::HwRev::spectral`, `hw::spectral_supported`; `group_pn_tests.rs::smoke_ath11k_spectral_inapplicable_on_admitted_pci`). |
| QCA6390 HW2.0 | Independent IPQ8074 RX descriptor/DP profile and core dispatch, shared supported MAC/runtime capabilities, native normal/error/coalescing/fragment ownership and composed station/recovery path | The same explicit optional/control and architecture gaps above apply only when target services advertise them. Six-GHz/HE160/80+80/extended security are admitted only from actual band, peer and firmware capabilities, not inferred from WCN6855. |
| QCN9074 | `qcn9074_regs`, static CE/UMAC BAR windows (`NativeIo` routing + `ath11k_pci_select_static_window` after MHI start), `CoreConfig` (1 radio, 8 vdevs, 128 peers) and multi-pdev `DpHwParams` (rxdma1, peer-map v2, full monitor flag); passes `validate_runtime_profile`; per-pdev rings + SRING_SETUP, `ath11k_init_wmi_config_ipq8074` init_cmd with band-to-mac (`multi_pdev_tests.rs`) | The RX service pass (refill replenish, RXDMA error and monitor-status reaping) covers pdev 0 only, the mac layer registers one radio on pdev 0 (`MacConfig::wcn6855`) and WMI commands go to `wmi[0]` although every per-pdev endpoint is connected, and monitor mode (incl. QCN9074 `full_monitor_mode`) is not supported. Nothing beyond fixtures; no composed QCN9074 startup fixture. |
| Other Linux ath11k SoC/AHB profiles (IPQ8074, IPQ6018, IPQ5018, WCN6750) | Qualcomm SoC platform layer (`drivers/soc/qcom`, `narf-drivers-qcom-soc`): DT platform devices and remoteproc resource resolution, SCM over SMCCC (PAS init/mem-setup/auth-and-reset/shutdown), MDT/MBN split loader, SMEM v11/v12, TCSR mutex, SMP2P, APCS/IPCC kicks, GCC reset/branch tables, Q6 WCSS host-reset start/stop (IPQ) and PAS WPSS start/stop (WCN6750). ath11k AHB glue (§3.12, `ahb.rs`): `ath11k_ahb_of_match`, the four AHB `hw_params` entries (CE/target-CE/service maps, QMI instance ids, ring masks, `ipq8074_regs`/`ipq5018_regs`/`wcn6750_regs`, CE remap/IE addresses, BDF address, firmware dir), the 52 named IRQs with CE and DP-group mapping, WCN6750 static windows and hybrid MSI resources, MSA/CE `memory-region`s, `qcom,rproc` resolution and boot through the matching loader; fixture-tested only (`ahb_tests.rs`, `drivers/soc/qcom/src/tests.rs`) | Admitted into the `HwRev`-keyed tables (§2.2, §3.12) and implemented in software, fixture/QEMU-tested only (nothing run on silicon): GLINK-SMEM + QRTR over GLINK, DT interrupt delivery, WLFW AHB paths, the AHB HIF, the bus DT driver match (`ath11k_ahb`), the production bring-up `ahb_live::LiveAhb` (MMIO mapping, live `Q6Wcss` / `PasRproc` boot with SMEM/SMP2P, GlinkSmem + GlinkQrtr, WLFW task handing a ready core to `runtime::start_ahb`), multi-pdev DP (rxdma1 rings, per-pdev SRING_SETUP, peer-map v2) and WMI (`init_cmd` with `ath11k_init_wmi_config_ipq8074`, per-pdev WMI endpoints). Residual, all chips: no AHB netdev (`iface` registration is PCI-typed), no post-boot SMP2P crash monitoring / recovery, and the path after WLFW FW_READY (DEVICE_INFO BAR mapping, core start) has no fixture (no fake WLFW server over GLINK). IPQ8074/IPQ6018/IPQ5018 multi-pdev: the RX service pass (refill replenish, RXDMA error and monitor-status reaping) covers pdev 0 only, the mac layer registers one radio on pdev 0 (`MacConfig::wcn6855`) and WMI commands go to `wmi[0]` although every per-pdev endpoint is connected, and monitor mode (incl. QCN9074 `full_monitor_mode`) is not supported. IPQ8074: mainline has no WCSS DT node and no `GCC_WCSSAON_RESET`. IPQ5018: no upstream `ipq5018` WCSS remoteproc binding. WCN6750: RPMh `xo` / `cx` / `mx` proxy votes need an RPMh RSC + cmd-db driver (not in `drivers/soc/qcom`); AOSS QMP `load_state` could be built from the existing `io::RegIo` + `ipc::Ipcc` pieces but is not implemented. |

802.11be/MLO/EHT is not an ath11k Wi-Fi6/6E contract; it belongs to newer
hardware/driver families. Firmware-owned HT/HE BA, OFDMA/TWT behavior is distinct
from a NARF user control API. The per-dialog controls are Linux's debugfs
commands sent to that firmware engine (`mac/diag.rs`), not a host TWT
negotiation state machine. Native fragmentation-threshold TX is
inapplicable to the Linux ath11k firmware contract, which cannot transmit
More-Fragments frames; it remains explicitly unsupported. SAR/board values and
RF acceptance must come from real platform inputs, never this inventory.

### Existing acceptance questions

- Per-family software completion: QCA6390 now has Linux
  `rx_desc.h::hal_rx_desc_ipq8074`, native HAL accessors and DP parameters,
  four-vdev firmware/host capacity and production core dispatch. Its
  normal/error/coalescing/CCMP fragment fixtures pass both architectures;
  the composed production startup/station fixture passes on x86_64 and is
  not included in the ARM integration configuration. QCN9074 now passes
  the runtime-profile check (register map, static windows, core/DP
  admission); its composed bring-up is unverified beyond fixtures. It needs the
  static CE/UMAC BAR windows, HAL register/operation tables, non-shadow
  ring setup and its independent core/peer-map/RX/runtime profile. Tests
  of the common transport or WCN6855 cannot validate those missing paths.

- Test loop (decided): phases land with offline tests only; one
  full hardware bring-up at the end by booting NARF bare-metal on
  the QCNFA765 laptop (`docs/BOOTING_ON_CACHYOS.md`). No serial
  there, so every bring-up stage reports to a pinned framebuffer
  status line as well as the console. A firmware crash shows as stage
  `recovery` and `fw-crash=N recovered=M` on that line
  (`diag::note_wifi_crash` / `note_wifi_recovered`,
  `fb::status::wifi_line`).
- MHI diag steps: `mhi_host::step` (10–39) latch through
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
  DT variant (`ath11k_core_check_dt`, `board::dt_facts`): the probe finds
  the function's Devicetree node like Linux `pci_set_of_node` — the boot
  DTB from `narf_bus::boot_dtb()`, the root-bus-first devfn chain from
  `narf_bus::pci::devfn_path` and `narf_firmware_fdt::for_pci_function`
  (host bridge by `linux,pci-domain`, one `reg`-devfn child per hop, unique
  match only). `qcom,calibration-variant`, else the legacy
  `qcom,ath11k-calibration-variant`, is read with `of_property_read_string`
  semantics (NUL required) and `strscpy`-truncated to 31 bytes; it replaces
  the SMBIOS value as Linux's later call in `ath11k_qmi_request_target_cap`
  does (`board::bdf_ext`). Without a DTB (x86/ACPI, QEMU `-kernel` without
  `-dtb`) or a node the SMBIOS value stands
  (`qmi_handshake_tests.rs::smoke_wlfw_dt_board_variant`).
- NARF-only bounds: Linux waits forever for the WLFW server and for
  REQUEST_MEM / FW_MEM_READY / FW_READY and for QRTR RESUME_TX, and
  silently stalls when the memory-request callback cannot allocate;
  here each wait is bounded (30 s, the 10 s transaction budget for
  flow control) and fails with its own step.
- QMI platform contracts proven unreached on the admitted PCI profiles
  (Linux `core.c::ath11k_hw_params`, `qmi.c`, `pci.c`):
  `ath11k_qmi_request_device_info` returns 0 unless
  `hw_params.hybrid_bus_type` (WCN6750 only); `fixed_bdf_addr` and
  `fixed_mem_region` are true only for the IPQ8074/IPQ6018/IPQ5018 AHB
  SoCs (`qmi_wlfw::QmiHwParams` mirrors both false for QCA6390/WCN6855).
  The one PCI route to fixed memory is `ATH11K_FLAG_FIXED_MEM_RGN`, set by
  `ath11k_pci_probe` only when the device's DT node has `memory-region`:
  `WlfwConfig::with_fixed_mem_region` then makes the REQUEST_MEM handler run
  `wlfw::assign_fixed_target_mem` (`ath11k_qmi_assign_target_mem_chunk`:
  HOST_DDR at the first `memory-region` `/reserved-memory` resource, which
  must hold it; BDF at the PCI `bdf_addr` 0; CALDB after HOST_DDR with
  cold-boot calibration, `ATH11K_QMI_CALDB_ADDRESS` without a region, else
  0; other types dropped) instead of DMA allocation, and RESPOND_MEM is never
  "delayed". An unresolvable region fails with `TARGET_MEM_ALLOC` where Linux
  stalls (`smoke_wlfw_fixed_mem_region`). The region is boot-reserved
  (`no-map`) memory the firmware owns; NARF never maps it.
  FTM (`ATH11K_FIRMWARE_MODE_FTM`) is selected only by the `ftm_mode=1`
  module parameter; it then skips mac80211 registration and exposes
  `NL80211_CMD_TESTMODE` passthrough of opaque, vendor-defined WMI FTM
  segments (`testmode.c`) for factory calibration tools. It is not part of
  the station/AP contract, and NARF deliberately boots only
  `ATH11K_FIRMWARE_MODE_NORMAL` (as `ath11k_pci_probe` does by default);
  a factory-test port would need an nl80211 TESTMODE surface in the shared
  wireless crate first. During the first bring-up a
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
- MHI crash policy: NARF allocates ath11k's 4.125 MiB RDDM BHIe RX table
  and builds a CPU-owned `RddmSnapshot` after a completed firmware dump.
  As in Linux's RDDM-capable path, a mission-mode SYS_ERR waits for the
following RDDM entry, which owns the single `ath11k_core_reset` request;
the generic no-RDDM MHI-core recovery remains out of scope for WCN6855.
After collection, the snapshot moves from the MHI controller to the physical
radio's `Shared::take_firmware_crash_dump()` retrieval slot, so reset cannot
invalidate a diagnostic consumer's owned payload.
A SYS_ERR during bring-up still fails the bring-up (Linux's `reset_work`
  ignores an unregistered device).
- Core after bring-up: `ATH11K_FLAG_*` crypto / raw mode are not modelled (HW
  crypto, native-wifi encap / decap as in the INIT resource config).
- Recovery deviations from Linux (deliberate): `reset_count` /
  `reset_complete` (a second reset work racing the first) and the
  `recovery_start` wait are not modelled — one runtime task runs one
  recovery at a time and later notices are dropped while one is pending;
  WMI / HTC timeouts do not trigger recovery (Linux's do not either:
  CRASH_FLUSH only shortens them). A replay-safe associated station
  (nl80211/userspace SME, Open, or completed in-kernel RSN) now follows
  `ieee80211_reconfig`: NARF rebuilds its vdev/peer/BSS and retained
  PTK/GTK/IGTK, GTK-rekey, EDCA, MFP and power-save state without air
  frames; it clears RX BA tokens because the new REO has no matching
  session. A beaconing AP/GO also restores its templates, MBSSID role,
  group/BIP keys, clients, client PTKs and authorization; CSA/color
  countdowns restart from their stable template after the firmware clock
  reset. A failed station replay reports the normal reason-1 disconnect.
  Only a pre-key in-kernel command-line handshake
  (`Ath11kNetdev::associate_kernel`, `ConnectOrigin::Kernel`) remains a
  directed scan plus over-the-air association because it has no complete
  supplicant key state to replay. Per-TID REO / fragment state and fragment
  timers go with `Dp::free`; a failed recovery leaves the device dead until
  the next boot (Linux waits for another crash event); the `fail_cont_count`
  gate counts failed recoveries (Linux counts resets that did not complete
  within 20 s).
- DP deviations from Linux (deliberate): RX buffers, TX bounce buffers
  and ring memory are DMA32 coherent `DmaMem`s (Linux streams skbs);
  rings are allocated with no 7-byte slack (the page-aligned allocator
  makes Linux's `PTR_ALIGN` a no-op, and slack would double every
  power-of-two ring); RX is delivered as Ethernet II, not rebuilt
  802.11 (native-wifi → DA / SA / SNAP type; Ethernet-II passthrough;
  802.3 + SNAP → Ethernet II; raw → `ath11k_dp_rx_h_undecap_raw` then
  802.11 → 802.3 for unicast, a decrypted group raw MPDU (Linux keeps its
  IV for mac80211) dropped); MPDUs with FCS,
  TKIP-MIC or decrypt errors are dropped in the DP; each locally detected
  TKIP-MIC error retains its peer/key identity and is multicast as
  NL80211_CMD_MICHAEL_MIC_FAILURE, as mac80211 reports it to userspace
  (KEY_SEQ is absent when WCN6855 stripped the IV). Multicast PN is checked by
  the host as mac80211 does it (`dp_group_pn`): Linux REO PN offload is
  unicast-only (`ath11k_dp_peer_rx_pn_replay_config` returns early for a
  group key) and `ath11k_dp_rx_h_mpdu` sets no `RX_FLAG_PN_VALIDATED` for a
  decrypted group-addressed first MSDU, so `ieee80211_rx_h_decrypt` owns
  it. `DpRing::h_mpdu` reads the IV from `hdr_status` (the bytes Linux's
  `ath11k_dp_rx_h_undecap_{nwifi,eth}` copy into the rebuilt header),
  selects the GTK by Key ID and drops a PN/TSC not above the key's per-TID
  counter (`rx_group_replay`; CCMP/GCMP `memcmp <= 0`, TKIP's zero-RSC
  first-frame exception; IEEE 802.11-2020 12.5.3.4.4). Group-key install /
  disable (`rx_pn_replay_config`, pairwise = false) allocates / frees the
  counters, and `DataPort::group_rx_seq` seeds them from the GTK KDE RSC or
  `NL80211_ATTR_KEY_SEQ` (`ieee80211_key_alloc(seq)`); tests
  `group_pn_tests.rs` and `dp_tests.rs::smoke_ath11k_dp_rx_decrypted_mcbc_peer`.
  Deviation: the
  counters live in the DP, so a firmware recovery restarts them at the
  reinstalled key's zero RSC instead of mac80211's retained values; the defrag
  reinjection allocates its buffer id from 1 (Linux `idr_alloc(.., 0,
  ..)` returns id 0, which `ath11k_dp_process_rx` skips as invalid: the
  first reassembled MPDU would be lost); a pairwise TKIP fragment set is
  verified with its retained RX Michael direction before reinjection, and an
  invalid or unkeyed set is dropped; the pairwise-key fragment flush
  (`ath11k_peer_frags_flush`) is a
  queued sync op applied at the install command's runtime lock;
  monitor-status buffers are recycled unparsed (no RSSI or full-PPDU
  statistics; the fast RX descriptor's per-MSDU PHY rate is retained for
  STA_INFO); `Dp` keeps the peer table HTT maps
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
- DP omission: WBM idle scatter list (dead for WBM_IDLE_LINK: > 2 MiB of
  8-byte entries needs > 8 banks, which `ath11k_dp_link_desc_setup` rejects
  first). HTT TX PPDU and default monitor-status RX PPDU statistics now route
  through `GET_STATION`, including rate/RU/DCM, combined/chain RSSI, raw-RSSI
  EWMA and PPDU durations. Monitor and full-monitor rings are **not** a
  WCN6855 omission: the Linux WCN6855 `hw_params` explicitly has
  `supports_monitor = false` and `full_monitor_mode = false`, so mac80211
  removes monitor iftype after registration. Ring teardown is ported (§3.7
  step 9); NARF-stricter: a failed `ath11k_link_desc_setup` also releases the
  WBM idle ring, which Linux's `ath11k_dp_alloc` leaks on that path.
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
- TX status: `Shared::send_eth_tx_status` can wait for a requested Ethernet
  frame's ACK, and the connection monitor ports mac80211's
  `ieee80211_mgd_probe_ap`: after ath11k's 3 s beacon-loss work expires it
  transmits up to two directed Null / QoS Null frames, completed through the
  same requested-status map; an ACK preserves the association and two no-ACK
  completions disconnect. CONTROL_PORT_OVER_NL80211_TX_STATUS is advertised:
  requested control-port frames keep their extended-ACK cookie beside the
  private requested-status id and WBM completion multicasts
  CONTROL_PORT_FRAME_TX_STATUS. The in-kernel 4-way handshake sends M2 / M4
  without asking (Linux installs the PTK without waiting too).
  `GET_STATION` reports completion-backed TX / RX packet, failed and retry
  counters, last ACK signal, monitor-status PPDU combined/chain RSSI and RX
  duration, HTT PPDU TX bitrate/duration (legacy / HT / VHT / HE including HE
  OFDMA RU/DCM), plus the accepted BSS MSDU's RX-descriptor-derived RX bitrate
  (legacy / HT / VHT / HE; HE RU is not encoded by that descriptor). Both
  mappings are implemented from Linux's descriptor definitions but await
  WCN6855 on-card qualification. Low-ACK
  kickout stays the firmware's (`REPORTS_LOW_ACK`).
- Integration deviations from Linux (deliberate): `ndo_open` is
  asynchronous (`set_link_state` sets `IFF_UP` and returns; a failed open
  takes the interface down again, where Linux's `dev_open` fails without
  setting it), because the hook runs in the caller's syscall and the WMI
  bring-up waits on the device; TX queues match mac80211's per-TID shape:
  a shared 4096-flow table, `fq_tin` new/old deficit round robin, global
  8192-packet / 16-MiB limits and ECN-enabled fq_codel (20-ms target,
  100-ms interval). The netdev ABI carries no private `skb_get_hash`, so
  the driver derives a stable L2/L3/L4 hash. NARF's one per-vdev TXQ owner
  replaces mac80211's separate `txq_info` allocations; AP-client flows
  therefore share the AP vdev's per-TID fq instance. This does not remove a
  WCN6855 nl80211 feature: ath11k does not advertise AQL or airtime-fairness.
  There is no TX A-MSDU aggregation (ath11k advertises
  `SUPPORTS_AMSDU_IN_AMPDU`, which NARF implements on receive; it does not
  advertise mac80211's distinct `TX_AMSDU` capability). `tx_hdr` constructs
  the same final native-Wi-Fi header and sequence state that Linux's
  fast-xmit finish path does directly, rather than retaining mac80211's
  skb-header cache; a PTK
  rekey runs inside
  one runtime step, so mac80211's `WLAN_STA_BLOCK_BA` window (ADDBA refused
  between teardown and the new key) has nothing to block; EAPOL frames carry 802.1X version 1
  (wpa_supplicant's `DEFAULT_EAPOL_VERSION`); PMF policy is optional for
  PSK (NetworkManager / iwd; standalone wpa_supplicant defaults to
  `pmf=0`); the complete ath11k BIP set (CMAC-128/256 and GMAC-128/256) is
  host-implemented; beacon protection (BIGTK) and OCV are not advertised by
  Linux ath11k/WCN6855 either; a group-addressed robust frame naming an
  IGTK index we do not hold is dropped.
- Control path: userspace drives the station over nl80211 with Linux's
  permission model (`wireless/` spec §3.4), as mac80211 offers ath11k on
  Linux: SME and supplicant in userspace (`supports_userspace_mlme`,
  `supports_external_supplicant`; no handshake offload is advertised, so
  wpa_supplicant uses `WPA_DRIVER_FLAGS_SME`). AUTHENTICATE (Open, or SAE
  with AUTH_DATA = transaction | status | body, `mac/ext.rs`
  `Mac::sme_authenticate` = `ieee80211_mgd_auth`) / ASSOCIATE
  (`Mac::sme_associate` = `ieee80211_mgd_assoc`: userspace's elements as
  given, `ieee80211_send_assoc` ordering; `NL80211_ATTR_PREV_BSSID` must name
  the association displaced by this SME authentication, emits a Reassociation
  Request and requires a Reassociation Response; its rejection retries a
  normal Association Request once as cfg80211 does; the port closed while
  NL80211_ATTR_CONTROL_PORT is set) / DEAUTHENTICATE / DISASSOCIATE each
  report the peer's or our frame as cfg80211 does; CONNECT without a PMK
  (`SecurityConfig::External`) runs the same through the driver's SME.
  EAPOL (`Mac::take_control_port_rx`) goes to the connection owner as
  CONTROL_PORT_FRAME, or up the netdev with DA = our address
  (PF_PACKET / l2_packet); requested CONTROL_PORT_FRAME TX carries its
  extended-ACK cookie through the ath11k WBM completion and multicasts
  CONTROL_PORT_FRAME_TX_STATUS (full Ethernet frame and ACK flag only on
  acknowledgement) on the MLME group. CONTROL_PORT_NO_ENCRYPT reaches native
  Wi-Fi header construction and suppresses the Protected bit even after PTK
  installation: the direct control-port attribute applies to that frame, and
  the CONNECT/ASSOCIATE policy applies to netdev frames whose EtherType equals
  the configured control protocol. TX goes through CONTROL_PORT_FRAME or the
  netdev, protected only once a PTK is in unless that policy bypasses it.
  A local TKIP Michael MIC failure also reaches the MLME group as
  MICHAEL_MIC_FAILURE with its source, pairwise/group type and, when the
  stripped report can be attributed to the active key, its installed key
  index, allowing wpa_supplicant to initiate its normal countermeasures.
  Keys come from NEW_KEY
  (`Mac::ext_add_key` → the same `install_key` / PTK replacement path
  the in-kernel supplicant and PTK rekey use, all BIP suites kept in host
  software while WMI installs data ciphers TKIP, CCMP-128/256, and
  GCMP-128/256, KRACK re-installs ignored), DEL_KEY, and the port opens on
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
  AP's last management-frame signal, WBM TX rate and accepted fast-RX
  descriptor rate (full PPDU statistics are not parsed). Unverified until
  hardware / real binaries:
  wpa_supplicant, NetworkManager and eapol_test against a real AP, SAE-PK
  public-key authentication and anti-clogging / group 20-21 over the
  userspace SME, EAP-TLS / PEAP timing, and the firmware's handling of the
  userspace-built Authentication frames. The in-kernel SAE path verifies
  SAE-PK's AP Confirm proof (Modifier AES-SIV recovery, password fingerprint
  and ECDSA KeyAuth) before it accepts the PMK; the external-SME path leaves
  that exchange to userspace.
- Unverified until hardware (recovery): that the WCN6855 firmware enters
  RDDM (or reports SYS_ERR) on a crash and comes back after the
  `sw_reset` power cycle with a fresh QRTR HELLO; that it sends
  FW_INIT_DONE (not only FW_READY) after the restart; that the target
  re-initialises its LMAC ring pointer words (Linux's srng setup does not
  clear them; the fake firmware does); MSI / ASPM behaviour across the
  cycle; external-SME/AP in-place reconfiguration and reconnect timing.
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
  `ath11k_dp_rx_h_defrag` + `_undecap_frag` +
  `ath11k_dp_rx_h_verify_tkip_mic` for TKIP and
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
- Mac layer scope (decided): HT, 5 GHz VHT and HE on 2.4 / 5 / 6 GHz through
  contiguous 160 MHz and non-contiguous 80+80 MHz (phymodes 11NG / 11NA /
  11AC / 11AX HE20-160 plus VHT80_80 / HE80_80). Six-GHz
  association uses HE 6 GHz Band Capabilities and Operation, WMM, AP power
  type-aware default-client regulatory rules, Transmit Power Envelope / Power
  Constraint parsing and WMI TPC programming after vdev start. Firmware's
  client type selects the matching TPE category. Scan preserves
  each BSS's centre frequency in MHz so a 6 GHz channel is no longer lost to
  a bare-channel-number collision. An 80+80 definition records both centre
  frequencies and is accepted only when the regulatory channel set and both
  peers' distinct wide-channel capability bits permit it.
- Mac layer, open vs Linux (each is a deliberate simplification or an
  unverified detail, see `mac.rs` comments): probe-request elements
  approximate `ieee80211_build_preq_ies`; the offloading SME builds its own
  RSN element (and RSNXE for SAE) and forwards userspace's other
  elements (Extended Capabilities, vendor elements) in their order, with
  `WLAN_EXT_CAPA3_MULTI_BSSID_SUPPORT` and, when firmware supports it,
  `WLAN_EXT_CAPA10_TWT_REQUESTER_SUPPORT` set for an HE association.
  Six-GHz Power Constraint and Transmit Power Envelope handling follows
  Linux's PSD/EIRP and local/regulatory-client precedence, including the
  firmware TX ceiling; it does not invent Country IEs. TWT enables the
  firmware requester service only for an AP that advertises both required
  responder capabilities; individual TWT-dialog management is firmware / AP
  driven rather than a separate NARF control API. A CONNECT to a different
  cached BSSID uses
  `WirelessNetIface::roam`: it releases the old peer/channel locally,
  reauthenticates, sends a Reassociation Request carrying the previous BSSID,
  retries once as a plain Association Request when the AP rejects reassociation,
  and then completes a fresh 4-way handshake. The in-kernel CONNECT path
  handles an Association Comeback (status 30 plus Timeout Interval type 3)
  by waiting the announced TU interval and retrying within the normal three
  association attempts. The userspace-SME path returns that raw response and
  emits `NL80211_CMD_ASSOC_COMEBACK` with the BSSID and unconverted Timeout
  Interval value in TUs, allowing the supplicant to schedule its next
  `ASSOCIATE`. GTK rekey data, WMI control, replay-counter notification and
  the power-owned system WoW/cold-suspend policy are implemented; CSA/ECSA is
  implemented for trusted beacons and robust
  Spectrum-Management actions, while public unprotected extended CSA only
  takes effect after its matching beacon.
  Kickout is treated as
  link loss (Linux reports low-ack to userspace); deauth reason after a
  4-way timeout is 3, after a failed message 3/4 1 (17 for an RSNE / RSNXE
  mismatch); the 11d "fin" path and the
  6 GHz LPI re-handling follow Linux but are untested on hardware.
