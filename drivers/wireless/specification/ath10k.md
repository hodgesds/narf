# ath10k — Specification

> Status: **Retained RAW station; bounded 5-GHz HT40/source/protection extension
> validated in native software suites; physical acceptance pending.**
> The live PCI task obtains BMI identity, selects trusted firmware/BDF,
> runs OTP calibration and downloads the image. It retains runtime CE DMA
> before BMI_DONE, negotiates HTC endpoints, handles firmware host-memory
> requests and completes WMI INIT/READY. Retained HTT RX/TX and a receive-only
> scan vdev follow, with policy-authorized directed/wildcard active discovery.
> Raw-capable non-PFC images can publish a retained legacy/HT20
> station interface with Open/WPA2, bounded native packet progress and terminal
> disconnect. This checkpoint adds conditional non-DFS SISO HT40 with LGI40,
> retained executable/BDF authority and native RTS/CTS intent. Those preceding cases
> pass both-architecture native suites; matched IDs confer no board qualification.
> The separately gated SGI40 extension passes nine native cases on both
> architectures; physical qualification remains open.
> A later chain/NSS/TX-STBC extension is source complete with four new
> unexecuted cases; release compilation and native validation are pending.
> A subsequent 2.4-GHz HT40/20–40 coexistence extension is source complete
> with seven new cases written; its release compilation and native execution
> are pending. Physical RF/power acceptance is still separate.

> A subsequent 80+80 extension is source complete for the qualified QCA9984/
> QCA9888 10.4 station owner. Six new cases are written and unexecuted;
> release compilation, native suites and physical acceptance are pending.
> Contiguous VHT160 (ch36–64 / ch100–128) later followed in §3 on top of the
> station-client DFS witness and the shared AUTO_BW regulatory run; its new
> cases are written and unexecuted.
>
> A later host-bus PM continuation is source complete for MSI-backed
> QCA6174/6164 and QCA9377 runtime owners. Seven new cases are written and
> unexecuted; release compilation, native suites and physical acceptance are
> pending. A released host wake vote is not a firmware-sleep acknowledgement.

> The later bounded RAW/10.4 PFC station continuation is source complete.
> Six new cases are written but unexecuted; coordinated release compilation,
> native execution and physical firmware/board acceptance remain pending.

> A later native Beacon-hint continuation is source complete for the existing
> non-DFS 5 GHz World-factory inventory. Six new cases are written and
> unexecuted; coordinated release/native validation and physical acceptance
> remain pending. Signed host restrictions remain independent authority.

## 1. Purpose & scope

PCIe Qualcomm/Atheros QCA988X, QCA9887, QCA6174/6164, QCA9377, QCA99X0,
QCA9888 and QCA9984. AR9462 belongs to ath9k and is rejected before MMIO.
Linux `drivers/net/wireless/ath/ath10k/` is the reference implementation.

## 2. Assumptions

Probe owns the PCI function exclusively. BAR0 is mapped with device
attributes and must cover the selected RTC, core, PCI-local and CE
windows. Boot uses coherent DMA32 storage and keeps the target awake.
Boot messages are serialized and polled asynchronously. After BMI_DONE the
runtime owner arms one MSI vector when the function has one (see
"Interrupt service" in §3); otherwise it keeps 1 ms polling with CE
interrupts masked. Synchronous network drains and the service worker drive
the same bounded state without waiting on another executor task.
Host-bus/system power transitions remain separate profiles.

## 3. Public interface

**Software acceptance at `6813a24c6`.** The admitted
`multiple_spatial_streams`, `tx_stbc`, `ht40_2ghz`, `ht2040_coexistence`,
bounded `vht80p80` and managed Public Action `offchannel_scan` continuations
pass the checkpoint release/native gates on x86_64 and aarch64. Contiguous160,
host-bus PM, wake offload and native AP/P2P roles keep their separate
remaining rows. This supersedes implementation-time statements below that
release/native execution or software acceptance is pending, only for the named
feature scopes. Physical measurements, signed board/deployment programs and
actual-device RF/power/interoperability acceptance remain separate.

- `register()` / `register_pci_driver()` publish exact PCI matches.
- `pci::probe` disables inherited bus mastering, wakes and identifies the
  chip, retains its metadata and schedules the boot task. Bound-driver
  presence does not mean firmware or an interface is ready.
- Native `pci::bring_up` requires the PCI capability. Actual BAR sizing,
  wake and identity accesses execute inside its invocation. Sizing occurs
  with verified memory decoding and bus mastering off; decoding is restored
  and read back only after all sizing writes have been restored.
- `pci::with_controller` exposes `Ath10kDevice` metadata.
  `target_info: Option<bmi::TargetInfo>` becomes present only after the
  real CE0 request and CE1 response complete. `boot_error` retains a
  bootstrap failure. `firmware_prepared` records the directory, API and
  WMI/HTT dialect only after real ROM-side image preparation;
  `firmware_error` records profile/file/BDF/OTP failures. `htc_ready` records
  actual endpoint negotiation and credit size; `runtime_error` records a
  transport/HTC failure after ROM preparation. `wmi_ready` records a
  correlated successful READY MAC/version/status; `wmi_error` retains
  service/ABI/memory/INIT failures. `htt_ready` records a supported target
  version after retained native RX/fragment setup and aggregation configuration;
  `htt_error` retains setup failure. `scan_ready` records submitted native
  station-vdev0 and passive channel setup, without claiming a firmware
  vdev-create acknowledgement; `scan_error` retains setup/scan failure.
  These metadata alone register no netdev; the RAW station admission below follows
  successful scan-vdev setup.
- `pci::scan_passive(frequencies_mhz)` serializes a receive-only scan over
  the retained physical HTC/WMI/HTT owner. It accepts only configured IEEE
  2.4/5 GHz centre frequencies within SERVICE_READY hardware ranges. Channel
  configuration uses PASSIVE and zero power; this does not infer a country
  policy or grant station transmission. The API returns
  `wmi_runtime::ScanReport` with bounded raw-IE `ScanBss` entries, SNR,
  received/ignored counts and an explicit truncation flag. It correlates
  firmware requestor/scan/vdev identities and never reuses a 12-bit scan ID
  within an owner lifetime. A failed/malformed terminal, timeout or dropped
  post-publication future closes that owner until full reset, retaining DMA.
- `pci::scan_active(frequencies_mhz, ssids)` uses the same retained physical
  owner for 1–16 explicit SSID entries, each 0–32 arbitrary bytes; an empty
  entry requests wildcard probes. The registered interface advertises
  `max_scan_ssids() == 16` and normalizes an active request without entries to
  one wildcard. The active profile is legacy20 on configured channels
  1–11 and the non-DFS 5-GHz centres listed below, within SERVICE_READY ranges
  and factory/host ceilings. An authenticated current host domain must cover every complete
  channel interval. Any overlapping DFS, NO_IR, unproven indoor-only rule,
  narrow bandwidth or negative
  power ceiling denies probes. Implicit lists select only eligible channels;
  explicit denied channels and invalid SSID/geometry/options fail before I/O.
  Random-MAC, dwell and colocated-6-GHz requests remain unsupported.
  Raw PCI diagnostic scans retain exclusive unassociated ownership. The
  registered interface refuses a partially prepared peer and concurrent scan;
  an authorized associated peer uses the retained dwell contract below.
  All six MAIN/10.1/10.2/10.2.4/10.4/TLV layouts encode real SSID arrays,
  CCK/OFDM probe rates and DFS bypass. TLV's inverted probe-request-filter bit
  is handled explicitly. Before START, ordered commands retain factory RD/CTL,
  apply each band's minimum selected-channel ceiling to its native 2-GHz or
  5-GHz PDEV limit before any mixed-band probe, and
  program each active channel's max/reg/max-TX power in half-dBm. Factory
  calibration remains enforced by firmware. Matching terminal completion is
  followed by restoration of the complete receive-only channel list before a
  new scan cache is published; normal passive discovery can continue afterward.
  Host country, channel geometry and power are checked on every command-future
  poll (including credit waits), receive iteration and final restoration. A
  host close/disconnect signal aborts the scan on its next poll, before returning
  results or releasing the radio lock to teardown. A
  lower ceiling or observed policy loss/restriction closes the owner; looser
  same-country policy cannot increase the already selected power. On errors,
  STOP_ONE for the reserved scan ID and receive-only restoration are attempted
  when the control channel permits. Cancellation at any publication, timeout,
  malformed/failed terminal or policy failure retains DMA and requires full
  owned reset. Command submission is not firmware-idle or RF-quiescence proof.
  This follows the shared cached-domain contract; it does not independently
  observe revocation of a cached regulatory firmware capability.
- `pci::scan_active_with_ies(frequencies_mhz, ssids, extra_ies)` and active
  `Device::scan(ScanRequest)` carry up to 256 bytes of caller-supplied probe
  information elements on all six dialects. The facade reports
  `max_scan_ie_len() == 256` to nl80211 for both discovery and its pre-dispatch
  bound. Complete element boundaries,
  vendor OUI and extension-ID presence are checked before transport access;
  firmware-generated SSID/Supported Rates/Extended Rates elements cannot be
  duplicated. Malformed native-interface input returns InvalidArgs; oversized
  or firmware-owned elements and passive requests with extra IEs return
  NotSupported. Rejected input reserves no scan ID, changes no firmware state
  and leaves the owner retryable. Prepared plans own the immutable byte copy
  before scan publication. Legacy WMI appends IE tag4 with raw length and zero
  padding to a four-byte boundary; TLV sets the fixed raw `ie_len` and padded ARRAY_BYTE
  length separately. Empty-IE requests preserve the existing packets.
  These opaque probe elements grant no PHY, association, security or regulatory
  authority. Current channel/power checks, terminal correlation/restoration,
  failure/cancellation and retained-DMA rules are identical to `scan_active`.
- Native chain selection (`wmi_runtime::chains`) intersects actual
  SERVICE_READY `num_rf_chains` with both masks in the actual submitted WMI
  INIT resource configuration. The original firmware count is retained,
  never relabeled as the selected count. MAIN/10.x/TLV resources bound this
  profile to three chains; 10.4 QCA99X0/9984 resources permit four, and other
  10.4 resources permit two. A PCI ID alone enables none of them. This follows
  Linux7.2 wmi.c:5582–5590 and core.c:2737–2779; signed firmware/BDF and real
  OTP calibration remain prerequisites. Before publishing a scan/PHY owner,
  Radio submits native PDEV TX_CHAIN_MASK1 and RX_CHAIN_MASK2, creates vdev0,
  then submits VDEV NSS (MAIN/TLV/10.4 parameter34; 10.x32), as Linux
  mac.c:5036–5070/5763–5778 does. All use the actual per-dialect command/TLV
  shape and retained HTC/CE terminal submission. There is no invented
  firmware parameter ACK or RF receipt. Current source/capability is checked
  through publication; failure or cancellation keeps the owner closed and
  DMA retained. No live chain reconfiguration or packet-key migration is
  attempted. Only after the complete sequence may per-band/request PHY
  capabilities use the immutable selected mask.
- The retained RAW station additionally negotiates a native HT20 profile when
  SERVICE_READY reports HT and a valid RF-chain count, and the actual AP offer
  contains valid HT Capability/Operation and usable WMM. It retains only the
  selected chains' MCS0..31, intersected with the actual AP RX offer/response,
  requires every basic MCS to fit that profile and binds HT Operation to the
  observed primary channel. SGI20 transmit requires the actual firmware capability
  and both beacon/response support; receive follows the local advertised promise.
  A driver-owned HT IE advertises the selected width and stream masks,
  SMPS disabled, no GF and only the firmware-backed LDPC/STBC
  coding described below; caller SME IEs cannot supply it.
  VDEV_START programs native 11NG/11NA HT20 plus ALLOW_HT, retaining the same
  20 MHz factory/host power receipt. The actual association response intersects
  MCS/SGI before native PEER_ASSOC carries HT/QoS, peer HT capabilities,
  maximum MPDU/density, RC flags, exact HT-rate arrays and HT20 phymode on all
  six dialects. TLV arrays have independent raw counts and padded lengths.
  Missing/incompatible HT response cannot open the peer or controlled port.
  Without firmware HT or usable AP WMM, the existing legacy path remains.
  Native RX admits HT/HT-TXBF preambles only for this confirmed profile and
  checks the selected width, supported MCS, non-greenfield and guard interval
  before CCMP replay commitment. RX bounds use the local capability actually
  advertised; peer receive MCS/SGI separately constrain firmware transmit RC.
  Capability reporting exposes exact per-band HT bodies from actual startup
  firmware facts. Native HTT RX_ADDBA/RX_DELBA records establish separate
  sparse-peer/TID agreements with windows up to 64 for all sixteen TIDs.
  Duplicate identical notifications retain sequence/age; changed active
  windows require retirement. The receiver validates FIRST PPDU metadata and
  carries it only through matching peer/TID MIDDLE/LAST MPDUs. Original RAW
  MPDUs enter bounded 12-bit sequence reorder before CCMP/PN; native compressed
  single-TID BAR and a 100 ms hole timeout advance ownership. Firmware FLUSH
  is not an ordering proof. DELBA, peer loss, host close and key-reply epochs
  retire buffered originals. Protected data observed while the port is closed
  is discarded before later receipts can authorize it. Native RAW transmit
  aggregation is explicitly capped at one MPDU/one MSDU; firmware offload is
  not inferred to be disabled by absence of host ADDBA. TX A-MPDU/A-MSDU,
  widths beyond the selected HT40/VHT80 profile and more streams remain separate work.
  Complete first/last native RAW receive MPDUs can carry a default-size A-MSDU
  up to 3839 bytes. The shared opt-in receiver authenticates the original
  QoS header and complete ciphertext before validating every subframe and
  committing one per-key/TID PN. Open aggregates use the same complete parser
  after native peer/HT/header checks and cannot contain protected input.
  Invalid tails, addresses, RFC1042 ambiguity or embedded control protocols
  publish no prefix and consume no PN. A bounded batch holds up to 256 decoded
  Ethernet frames. The current port and refreshed regulatory permission gate
  final IPC publication after allocation and each stack callback after driver
  locks are dropped; buffered data cannot escape a later same-drain rekey.
  IPC and stack callbacks are separate publication boundaries: a later callback
  revocation suppresses that callback and subsequent publications, while an
  IPC copy already authorized before that revocation remains a prior transaction.
  Native tests compose actual CE/WMI/HTT and referenced DMA with Open/WPA2,
  DHCP/IP on both bands/all dialects, response narrowing, absent/malformed
  capabilities, invalid RX geometry before PN, cancellation and policy loss.
- The bounded 5-GHz HT40 extension uses actual SERVICE_READY HT enablement and
  RF-chain facts with the shared typed `JoinPlan::prepare_with_phy` offer and
  response. Linux `mac.c::ath10k_get_ht_cap` makes 20/40 support available with
  `WMI_HT_CAP_ENABLED`; the independent HT40-SGI capability is not inferred from
  SGI20. This profile advertises only the selected chains' MCS set, LGI40,
  optional qualified SGI20 and
  separately gated SGI40 as described below,
  without GF; stream/STBC admission follows the same native chain receipt
  (LDPC/STBC follow the
  coding bullet below). Only the pairs
  5180/5200, 5220/5240, 5745/5765 and 5785/5805 MHz, in either primary order,
  are selected. The actual board/OTP calibration path, immutable EEPROM
  pair/CTL, fixed-country factory/host match, firmware band limits and current
  host rules must admit the entire occupied40 MHz interval. Every overlapping
  bandwidth, power or restrictive rule applies, including a narrow secondary
  overlap. The minimum host ceiling and geometry remain one retained receipt.
  These bounds add restrictions to vendor calibration; they are not fabricated
  measured emissions or a replacement board qualification.
  A denied secondary/width or an AP's20-only offer rebuilds a real HT20 local
  capability before native publication; a narrowed negotiated width cannot leave
  an unqualified40-MHz local advertisement. A response changing an already-programmed width, center, occupied
  pair or HT40 protection mode fails; no unproved VDEV restart or header rewrite
  relabels that owner. Apart from the separately owned one-way 2.4-GHz
  coexistence restart below, AP HT capability/operation changes after association close
  it. Native RX accepts 20-MHz PPDUs within a selected40 profile, admits40 only
  there, and rejects an unadvertised GI, GF and unsupported MCS before replay/PN commitment.
  `SCAN_CHAN_LIST` programs the two qualified constituents with ALLOW_HT and
  HT40_PLUS only on its lower channel row. `VDEV_START` separately carries the
  actual primary, mean center1, center2=0, 11NA-HT40 mode6 and ALLOW_HT; it does
  not misuse the inventory's HT40_PLUS bit. PEER_ASSOC carries BW40/RC-CW40 and
  the response-bound rates on all six dialects. PPDU HT-SIG width and GI retain
  their native meanings through RX BA/reorder and software CCMP.
- SGI40 is independently enabled only by actual SERVICE_READY
  `WMI_HT_CAP_HT40_SGI` (0x0800), alongside HT enablement and the checked chain
  count. `WMI_HT_CAP_HT20_SGI` (0x0002), HT40 width, the PCI tuple and a peer's
  capabilities cannot substitute for it. The per-band local HT body carries
  IEEE SGI40 bit0x0040 only in a source-admitted HT40 profile, including the
  separately controlled 2.4-GHz path below; an HT20 body never inherits it.
  Both GI directions follow the real firmware fact.
  The original scan and actual association response additionally bound TX GI;
  a response cannot restore a GI absent from the scan offer. Local RX uses the
  exact promise sent in our association request and is not narrowed by an AP's
  independent RX-GI field. A genuine20 fallback rebuilds the local capability,
  clears width40 and SGI40 in the actual request/native peer record, and does
  not invent SGI20 for SGI40-only firmware.
  Linux `mac.c::ath10k_get_ht_cap`, `ath10k_peer_assoc_h_ht`,
  `wmi.h::WMI_HT_CAP_HT40_SGI` and
  `net/mac80211/ht.c::ieee80211_ht_cap_ie_to_sta_ht_cap` define the source
  contract: PEER_ASSOC's width/GI capabilities are limited by local and peer
  facts before firmware rate control. The retained original AP bodies remain
  unchanged for response/beacon binding. All six dialects program the negotiated
  native `peer_ht_caps`, RC-CW40=0x02 and RC-SGI=0x04. The single RC-SGI flag
  permits any admitted GI, including qualified SGI20 fallback inside a40-MHz
  profile; individual native capability bits prevent that flag from enabling
  SGI40 or SGI20 without their distinct bounds. Other PHY/coding/stream limits
  are unchanged.
  Actual HT/HT-TXBF PPDU metadata selects independent advertised RX-SGI20 and
  RX-SGI40 bounds using the HT-SIG width and GI bits, before BA sequence or
  CCMP replay admission. The existing FIRST/MIDDLE/LAST owner carries a proven
  SGI40 PPDU through reorder; LAST or a rejected next FIRST cannot lend its
  PHY fact to an orphan. Invalid GI/width/MCS consumes no packet PN. Source,
  whole occupied40 power, generation, key, terminal receipt and final separate
  IPC/stack boundaries remain those of the existing retained owner.
  No synthetic firmware ACK, per-GI measurement, calibration or authority input
  is introduced. The actual retained vendor BDF/OTP calibration, firmware's
  explicit SGI40 capability, immutable factory limits and full occupied-channel
  host ceiling remain mandatory. Linux uses that same calibration/power owner
  when exposing SGI40; ath10k has no Intel-style legacy-only measured-emitter
  record to relabel. These source-backed gates grant no physical RF or board
  interoperability claim.
- 2.4-GHz HT40 and HT20/40 coexistence (`wmi_runtime::coexistence`) use
  the actual initialized HT/chain/GI facts and the selected AP's HT Operation.
  Both primary and extension must be admitted channels 1–11,20MHz apart,
  within SERVICE_READY hardware ranges. The host receipt covers the entire
  40MHz span and takes every overlapping rule's restrictive width, flags and
  power; the firmware retains its factory CTL and actual vendor BDF/OTP
  calibration. START uses MODE_11NG_HT40=7, mean RF center and two real
  11G/ALLOW_HT inventory rows. This does not infer power from a PCI ID.
  Before a 40MHz join, a native passive scan must cover every affected
  receive channel, including admitted receive-only 12/13. A missing inventory
  row, absent AP OBSS parameters or unsupported operating-class country
  triplets selects a genuine local 20 request before native START/PEER_ASSOC.
  A complete report tracks non-HT and 40MHz-intolerant BSSs; a truncated scan
  cannot prove a clear band. The actual refreshed AP facts are bound again
  before deciding whether this prepared native owner is 20 or 40MHz.
  After association, the retained worker schedules passive OBSS scans at the
  AP's BSS Width Trigger Scan Interval, clamped to 10 seconds as hostap does.
  It consumes that exact scan's terminal and restores the real home inventory
  before reporting. Public Action category 4/action 0 carries the 20/40 BSS
  Coexistence IE 72 and distinct channel report IE 73 with operating class 0;
  a 40MHz-intolerant observation sets the20MHz Width Request bit. This public
  action is non-robust even with PMF; it never uses a forged protected frame.
  Own AP width requests, its later 20MHz operation, and affected non-HT or
  intolerant observations make the width trigger sticky for this owner.
  A current source and exact AP/channel binding precede every observation.
  A selected 40 owner may narrow exactly once. DATA stops before native waits;
  outstanding original HTT IDs drain to their real terminal receipts, with no
  key reply in flight. The driver submits PEER_PHYMODE=11NG_HT20 and
  PEER_CHAN_WIDTH=20, actual 20 power/inventory and VDEV_RESTART with center
  equal to primary. Only a matching native RESTART response (type 1, vdev 0,
  requestor 0, success) can publish the new 20 receipt; old START/type 0 and
  foreign-vdev events cannot satisfy it. The old global PDEV power ceiling
  remains through this response; only confirmed20 hardware may receive a
  higher20-only ceiling than the old full40-span minimum. A consumed RX prefix and cleared
  reorder/PPDU/copy admission separate the widths; pairwise keys and PN
  ownership stay with the original authenticated peer. A receive generation
  check suppresses a later stack callback copied before the trigger. RX rejects
  old 40 PPDU metadata before replay commitment, so a valid 20 retry with the
  same PN still works. Cancellation, missing/failed response, policy/source
  loss or peer unmap keeps the owner failed and native DMA retained for the
  existing teardown/reset path. Parameter submission is not a firmware or air
  ACK. This owner never widens or retries an ambiguous restart; a later wider
  association needs a new physical owner. A response changing the initial
  prepared geometry still fails before key/data publication.
  The affected scan contract follows hostap SME: strict overlap of each 20MHz
  channel with `[min(primary,secondary)-10,max(primary,secondary)+10]`, equal
  to inclusive RF-center ±25MHz on the 5MHz raster; center ±30MHz is excluded.
  Primary pins: Linux 7.2 `mac.c::ath10k_get_ht_cap`,
  `ath10k_sta_rc_update_wk`, WMI native peer/start/restart structures; hostap
  Android 15_r17 `wpa_supplicant/sme.c` blob
  `57c9b3814f84b9402a0b6a787fe8b5a37c6645ee`, functions
  `sme_proc_obss_scan`, `wpa_obss_scan_freqs_list`, `sme_sched_obss_scan`;
  `hw_features_common.c::check_40mhz_2g4` at commit
  `f43a200a87e4d4bd578de6eb56b4b527f9e01880` confirms the center ±25MHz edge.
  Seven new native/source cases are written, including all six dialects,
  Open/WPA2 DHCP/IP, both extension directions, timed scans/reports, initial
  real20 fallback, exact native narrowing, same-PN admission and held restart
  cancellation. They remain unexecuted; release compilation is pending.
- HT LDPC and one-stream RX STBC (`wmi_runtime::ht::{ldpc,rx_stbc,Profile}`)
  follow Linux `mac.c::ath10k_get_ht_cap`: IEEE LDPC_CODING (0x0001) is
  advertised only for SERVICE_READY `WMI_HT_CAP_LDPC` (0x0040) or the pair
  `WMI_HT_CAP_RX_LDPC|WMI_HT_CAP_TX_LDPC` (0x1000|0x2000); a lone directional
  bit is not. A nonzero `WMI_HT_CAP_RX_STBC` field (0x0030) advertises one RX
  STBC stream (IEEE 0x0100), only with at least two selected physical RX chains.
  TX STBC additionally requires `WMI_HT_CAP_TX_STBC`0x0008 and two selected TX
  chains. These reach the
  per-band capability body, the driver-owned request IE and the HT20/HT40
  `LocalPhy` through `LocalHt::{with_ldpc,with_rx_stbc,with_tx_stbc}`.
  PEER_ASSOC `peer_ht_caps` applies `mac80211/ht.c::ieee80211_ht_cap_ie_to_sta_ht_cap`
  masking: peer LDPC survives only with local LDPC, the peer's RX STBC field
  (0x0300) is bounded by local TX STBC and half the selected physical TX chains;
  the peer's TX STBC
  (0x0080) survives only with our RX STBC promise. `ath10k_peer_assoc_h_ht`
  then sets `WMI_PEER_LDPC` (0x10000), `WMI_PEER_STBC` (0x8000) and
  `WMI_RC_TX_STBC_FLAG` (0x20), RX-STBC field0xc0 and DS/TS stream flags;
  these values are identical in all six dialect
  peer-flag maps. The firmware owns LDPC encoding toward a capable peer and
  STBC/LDPC decoding. Native RX additionally rejects, before BA sequence or
  CCMP replay commitment, an HT-SIG2 FEC-coding bit (bit6) without our LDPC
  promise, a one-stream STBC field (bits4..5 = 1) without our RX STBC promise
  and any larger/reserved STBC value or NSTS exceeding selected physical chains.
  Native smokes `drivers/wireless/ath10k/coding` cover the service-bit
  advertisement, masked peer record/flags on all six dialects with DHCP-backed
  CCMP traffic and pre-replay PPDU coding checks. No RF coding gain is claimed.
- `wmi_runtime::StationProtection { rts_threshold: Option<u16>,
  cts_protection: bool }` and `pci::set_station_protection` submit native VDEV
  protection intent. None encodes the disabled threshold `u32::MAX`; finite
  values are 0..2347, with 0 forcing RTS. The CTS field is Linux's `use_cts_prot`
  boolean, not the HT Operation protection enum. Every selected HT40 station
  first submits forced RTS before creating its data/security owner. A nonzero
  bound HT40 protection mode cannot relax that RTS floor. The serialized program
  uses ENABLE_RTSCTS=0x21 (enabled, across software retries), PROTECTION_MODE
  boolean and RTS_THRESHOLD, with actual MAIN/10.1/10.2/10.2.4/10.4/TLV command
  IDs/parameter maps and TLV tag95. This follows Linux
  `ath10k_recalc_rtscts_prot`, `ath10k_mac_set_cts_prot` and `ath10k_set_rts_threshold`.
  Reconfiguration refuses an active key reply, reserves the radio before its
  first wait, consumes the real outstanding ordinary HTT terminal receipt and
  requires CE4 source-ready before issuing controls. It retains original RX and
  peer/control events for the packet owner rather than discarding following
  traffic. Current complete occupied-channel permission, immutable sources and
  generation quarantine are checked during native waits and final publication.
  `submitted_station_protection()` reports completed host submission intent;
  CE completion/current receive-prefix progress is not a firmware parameter ACK,
  MAC/FIFO retirement proof or observed RTS/CTS exchange. Failure/cancellation
  closes admission and preserves uncertain DMA; reinstall or late credits do not
  reopen it. The retained radio mutex serializes this direct control with packet
  progress. Autonomous protection changes after AP operation changes, dynamic
  CTS policy and protection interoperability still need further acceptance.
- The single-vdev RAW station can negotiate WMM from an actual AP Parameter IE.
  It appends its own Information IE with U-APSD disabled; caller-supplied WMM
  cannot duplicate or replace that negotiation. The bound successful association
  response supplies the final contention values. Missing, duplicate or malformed
  response parameters fail before peer/data admission, as does BE ACM. With
  no TSPEC owner, that would leave ordinary traffic only BK. VO/VI/BK ACM is
  accepted, and transmit downgrades past ACM ACs (below).
  Native per-dialect PDEV WMM records program BE/BK/VI/VO contention, converting
  IEEE TXOP32-us units to native microseconds; PEER_ASSOC carries the real QoS
  flag only after those transport receipts. This one-radio profile has no
  per-vdev concurrency and makes no firmware ACK claim for these commands.
  Non-BE transmit classification (`wmi_runtime/tx_qos.rs`): on a WMM
  association each host Ethernet frame gets the user priority from Linux
  `net/mac80211/wme.c::ieee80211_select_queue`. That is priority 7 for
  EAPOL; otherwise `net/wireless/util.c::cfg80211_classify8021d` (IPv4 TOS,
  IPv6 traffic class, MPLS TC, RFC 8325 exceptions; the ath11k
  `tx_hdr::classify8021d` port is reused). `ieee80211_downgrade_queue` /
  `wme_downgrade_ac` then step VO to VI (UP 5), VI to BE (UP 3) and BE to
  BK (UP 2) while the AP's WMM Parameter ACM bit covers the AC, using BK
  even when BK also requires admission (no TSPEC is admitted). The TID goes
  into the QoS Control field (open path, or the shared CCMP formatter's
  `transmit_ethernet_qos`, which keeps per-TID sequence and PN) and into
  the HTT descriptor TID (`htt_tx.c::ath10k_htt_tx`
  `HTT_DATA_TX_DESC_FLAGS1_EXT_TID`). The open path also keeps per-TID
  sequence counters. Firmware schedules the four AC queues from the PDEV
  WMM records. EAPOL/key replies remain legacy non-QoS (descriptor TID
  16). RX binds QoS TID to the native descriptor before replay/PN
  commitment. TX aggregation, TSPEC and U-APSD remain separate features.
  APs without WMM retain the legacy packet/command profile.
- N-deep native TX pipeline (`wmi_runtime/tx_pipeline.rs`): station data
  keeps up to 32 native HTT IDs in flight, in a heap-owned table keyed by
  MSDU ID (Linux v7.2 `htt_tx.c::ath10k_htt_tx_alloc_msdu_id`, the
  `htt->pending_tx` IDR). Each ID's payload/fragment DMA stays owned by
  `htt_runtime::tx::Pool` until an HTT TX completion indication names it;
  the CE source receipt only frees the bounce slot, so the next frame may
  be published under its own ID while earlier IDs are outstanding. One
  indication may name several IDs in any order
  (`htt_rx.c::ath10k_htt_rx_tx_compl_ind`); the whole batch is validated
  before any ID is freed, and a duplicate or unknown ID fails the HTT owner
  without partial release. Each ID then retires independently
  (`txrx.c::ath10k_txrx_tx_unref`). Status maps as in Linux: OK is ACK,
  NO_ACK is no-ACK, DISCARD/POSTPONE/unknown are discard. A data receipt
  never fails the link; its outcome is counted per TID
  (`Radio::tx_counters`, index 16 non-QoS). Key-reply fencing is explicit
  and two-sided. A supplicant EAPOL reply (M2/M4, group 2/2) is published
  only once every earlier data ID has reached its terminal indication.
  While the reply is in flight no data ID is admitted and RX admission
  stays paused. A non-OK reply receipt still fails the owner. A full table
  or an in-flight reply returns `Htt(Busy)` before anything is published.
  Station protection programming drains every data ID first; it refuses a
  reply in flight. Teardown and failure close the owner but keep every
  in-flight ID and its DMA until whole-device reset. A completion is never
  invented. The per-ID deadline (3 s) fails the owner, as before.
- Firmware-owned TX Block Ack and aggregate retransmission. Linux v7.2
  sets `TX_AMPDU_SETUP_IN_HW` and `mac.c::ath10k_ampdu_action` returns
  -EOPNOTSUPP for every mac80211 TX action (TX_START, TX_OPERATIONAL,
  TX_STOP_*). Firmware originates ADDBA, keeps the BA window, builds the
  A-MPDU and retransmits unacknowledged subframes. The host's
  `WMI_ADDBA_SEND_CMDID` path exists only for the debugfs manual
  `aggr_mode` (`debugfs_sta.c`), so this tree never sends ADDBA or
  DELBA itself. The host obligations are all met:
  1. an HT peer with the QoS flag and A-MPDU length/density in PEER_ASSOC
     (`ath10k_peer_assoc_h_ht` `peer_max_mpdu`/`peer_mpdu_density`);
  2. the 802.11 TID in each QoS descriptor (`tx_qos.rs`);
  3. several MPDUs of one TID owned at once (the N-deep pipeline above).
  The AP's ADDBA Response and DELBA action frames belong to firmware's
  session. The station owner ignores them: no WMI command, no state change.
  Firmware performs the retries while each MPDU's ID and DMA stay owned. A
  completion indication is terminal after its retry budget. One indication
  may name a whole BA window. ACK, NO_ACK (retries exhausted) and
  DISCARD/POSTPONE are counted per TID (`Radio::tx_counters`). None of these
  outcomes fails the link. A status above POSTPONE is malformed and is
  rejected before any ID is freed. The LL completion carries no
  per-attempt retry count. Linux reports one only through 10.4
  `HTT_10_4_T2H_MSG_TYPE_PEER_STATS` (`htt_rx.c::ath10k_htt_fetch_peer_stats`
  `retry_pkts`), which firmware emits only after `WMI_EXT_RESOURCE_CFG`
  enables `WMI_10_4_PEER_STATS` (`core.c::ath10k_core_start`). This tree
  sends no EXT_RESOURCE_CFG, so per-attempt counts are not claimed.
  Smokes under `drivers/wireless/ath10k/ht` cover eight TID-0 MPDUs in flight
  on all six dialects, an ignored ADDBA/DELBA exchange, mixed
  ACK/NO_ACK/DISCARD outcomes, malformed status, and teardown keeping the
  aggregate's DMA.
- 80 MHz occupied-bandwidth receipt (`regulatory.rs`):
  `Permission::occupied_width(.., width80)` admits the non-DFS VHT80
  segments ch36-48 (center 5210) and ch149-161 (center 5775). This is the
  cfg80211 chandef `center_freq1` that Linux puts in VDEV_START
  `band_center_freq1` for `MODE_11AC_VHT80`
  (`mac.c::ath10k_vdev_start_restart`, `wmi.c` `chan->band_center_freq1`).
  The 40 MHz `secondary` must name the HT pair inside the same segment.
  Every overlapping host rule must allow 80 MHz, and one rule must cover
  the whole segment. DFS, NO_IR, indoor and unknown flags stay restrictive.
  The factory/country binding and power ceiling are the same as for HT40.
  `Permission::check` re-derives the width-tagged receipt, so a narrowed,
  cleared, lower-power or different-country policy closes it. A 40 MHz
  receipt over the same pair is a different receipt. The VHT station
  profile below is the only selector of `width80`.
- VHT station profile (`wmi_runtime/ht.rs`, `station.rs`, `mlme.rs`;
  smokes under `drivers/wireless/ath10k/vht`). A nonzero SERVICE_READY
  `vht_cap_info` builds the local element through the shared
  `LocalPhy::vht80`/`LocalVht` exactly as Linux v7.2
  `mac.c::ath10k_create_vht_cap` does: MCS0-9 only for selected native streams
  in both maps, SGI80 (0x20), RX LDPC (0x10), RX STBC (0x300) and the A-MPDU
  exponent; TX STBC needs its source bit and multiple selected TX chains; beamforming roles
  need a sounding owner and are not advertised, and wider operation needs the separate 160 MHz owners below (80+80 and contiguous160).
  `Device::phy_capabilities(5000)` and `hw_caps.vht_supported` report it.
  Because the element promises 80 MHz support, VHT is offered only on a
  qualified 5-GHz primary whose whole 80 MHz segment
  `Permission::occupied_width(.., width80)` grants; the occupied receipt is
  then the AP-selected 20/40/80 geometry (a contiguous160 or 80+80 BSS is used
  through its primary80). A refused segment, an HT-only AP, a zero
  `vht_cap_info` or an unusable VHT offer falls back to the HT40/HT20
  selection above, which sends no VHT element. PEER_ASSOC follows
  `ath10k_peer_assoc_h_vht`: `WMI_PEER_VHT` (0x0200_0000) and, at 80 MHz,
  `WMI_PEER_80MHZ` (0x0400_0000) in all six dialect maps; `peer_vht_caps` is
  the AP's VHT information masked as mac80211
  `vht.c::ieee80211_vht_cap_ie_to_sta_vht_cap` does (RX LDPC, TXOP PS, +HTC,
  exponent, link adaptation and antenna bits kept; SGI80 symmetric; peer TX
  STBC only with our RX STBC); `peer_max_mpdu` is `max(HT, 2^(13+exp)-1)`;
  the `wmi_vht_rate_set` (TLV tag 102, or the common-command tail at +332) is
  the AP's RX map narrowed by our TX map and its TX map narrowed by our RX
  map, with the AP's highest-rate fields. The native peer NSS follows this
  actual directional VHT map; HT uses its complete0..31 rate array and
  response-bound NSS. Original HT RX PPDUs are bounded by selected/local and
  explicit peer TX MCS facts; VHT RX intersects AP TX and local RX per NSS.
  Unsupported NSS/MCS/STBC/width/GI is rejected before reorder or CCMP PN,
  including a same-PN valid retry. `peer_phymode` is
  `ath10k_peer_assoc_h_phymode` `MODE_11AC_VHT20/40/80` (8/9/10). VDEV_START
  follows `chan_to_phymode`, which maps the chandef width only: 20/40 stay
  `MODE_11NA_HT20/HT40` and 80 MHz is `MODE_11AC_VHT80` with
  `band_center_freq1` 5210/5775; a VHT profile adds `WMI_CHAN_FLAG_ALLOW_VHT`
  (bit12) beside ALLOW_HT, and the station inventory lists all four segment
  rows (HT40_PLUS on the lower channel of each pair) as
  `ath10k_update_channel_list` does. The association response must keep VHT
  and the 80 MHz geometry, and a later beacon changing the bound VHT
  Capabilities/Operation closes the link like an HT change. RX admits
  `HTT_RX_VHT` (0x0c) PPDUs only when VHT is bound, decoding VHT-SIG-A1/A2 as
  `htt_rx.c::ath10k_htt_rx_h_rates`: an SU group id (0/63), only the selected spatial
  streams (with the separately bounded STBC direction), LDPC only with our RX LDPC,
  MCS within our map, and a bandwidth/SGI the profile promised. TXBF (0x0d)
  and MU PPDUs are refused before CCMP/PN.
- 80+80 (`wmi_runtime/vht_wide.rs`, the shared strict VHT plan, native
  station/channel/peer records) is a separate conditional station profile.
  The retained BMI-qualified QCA9984/QCA9888 owner must complete actual
  READY/INIT with10.4, advertise SERVICE_11AC=8 and VHT Supported Channel
  Width Set2, and have initialized/submitted physical chain limits. Linux
  `core.c` limits QCA9984 to two wide streams (1560 LGI highest-rate hint)
  and QCA9888 to one (780); other hardware/dialects remain at primary80.
  Hardware capability queries keep the ordinary MCS maps with that actual
  per-chip highest-rate hint. The opt-in association request conservatively
  limits its VHT maps to the wide stream count at every width; ordinary80
  fallback keeps its existing selected-chain maps. This is not an assertion
  of a per-width local MCS API that does not exist.
  Both real non-DFS80 blocks must be admitted independently: center5210
  (primaries36–48) and center5775 (149–161), in either primary order.
  `Permission::discontiguous` retains center2 and checks every constituent
  against actual SERVICE_READY ranges, immutable fixed-country factory
  identity, authenticated host rules and the existing firmware/BDF/OTP
  calibration owner. The programmed ceiling is the minimum of both complete
  80MHz spans. The spectral gap is not occupied or granted; a restrictive
  gap rule cannot invent a contiguous160 or DFS/CAC owner. The compound
  permission, including center2 and both spans, is checked on every wait
  and copied RX/stack boundary.
  Native START uses MODE_11AC_VHT80_80=14, center1 for the primary segment
  and real center2; the inventory contains all eight original20MHz rows
  with their own HT40_PLUS pair direction. `PeerPrepared` exposes both
  centers and total occupied bandwidth160 to distinguish this geometry.
  10.4 PEER_ASSOC carries BW160=0x20000000 and the actual
  `peer_bw_rxnss_override` word: bit31 plus separately encoded160/80+80 NSS.
  The AP's actual RX map and RX highest-rate hint additionally bound wide
  TX NSS as Linux `get_160mhz_nss_from_maxrate` does; unknown RX hints
  conservatively select one. Known AP TX hints bound received wide NSS
  independently; an unknown TX hint leaves the advertised receive-map
  bound intact. Native SU CBW3 PPDUs need the real two-segment owner and
  those directional NSS bounds before replay/PN. Narrower PPDUs keep their
  own GI/map bounds. Wide SGI uses actual SERVICE_READY bit0x40, separately
  from SGI80 bit0x20, and the original request/response directions.
- Contiguous VHT160 (`vht_wide.rs::Profile::offer_wide`,
  `regulatory.rs::Permission::contiguous160_with_hint`, `wire.rs::
  start_center2`; smokes under `drivers/wireless/ath10k/vht160`) shares the
  80+80 owner's gates (10.4, SERVICE 8, QCA9984/QCA9888 wide NSS 2/1) and
  follows the chip's own Supported Channel Width Set as Linux
  `ath10k_create_vht_cap` copies it: 160-only (`vht_cap_info & 0xc == 4`)
  advertises and offers contiguous160 alone; 160+80+80 (8) opts into both,
  and an AP operating contiguous160 then yields a contiguous profile. The
  spans are VHT160 channel 50 (ch36–64, centre 5250) and 114 (ch100–128,
  centre 5570) — `Permission::center160`; ch149–177 stays out because
  ch165–177 are outside the factory/board inventory. The receipt keeps the
  80+80 shape: `center` is the primary80 half and `center2` the adjacent half
  (80 MHz away; 802.11 forbids adjacent 80+80 segments, so distance alone
  separates the shapes and 80+80 now refuses an adjacent segment). Each half
  is an ordinary 80 MHz receipt, so every radar 20 MHz constituent needs the
  station client's heard Beacon (§ DFS client below); additionally every rule
  overlapping the whole 160 MHz block must allow 160
  (`narf_wireless::reg::RegulatoryDomain::allows_bandwidth`: a direct 160 MHz
  rule, or an `AUTO_BW` run across the 5250 MHz boundary as wireless-regdb
  `US` declares it; `NO_160MHZ` closes it), mirroring cfg80211
  `reg_get_max_bandwidth` and `cfg80211_chandef_usable`. Per-rule bandwidth
  for every width now follows that effective value. The peer VHT width set is
  mac80211's own-width intersection (`ieee80211_vht_cap_ie_to_sta_vht_cap`);
  a 160-only station facing an AP that advertises only 160+80+80 is refused
  (mac80211 would hold that peer at 80 MHz) and falls back to primary80.
  Native START uses MODE_11AC_VHT160=15 (`chan_to_phymode`); PEER_ASSOC uses
  VHT160, or VHT80_80=14 when the bound width set is 160+80+80
  (`ath10k_mac_get_phymode_vht`), with `WMI_PEER_160MHZ` (0x2000_0000, equal
  in the main/10.x/10.2/10.4/TLV maps). The 10.4 `peer_bw_rxnss_override`
  carries the 80+80 NSS field only for a VHT80_80 peer. VDEV_START follows
  `wmi.c::ath10k_wmi_put_wmi_channel`: `band_center_freq1` the primary80 half,
  `band_center_freq2` the whole 160 MHz centre (80+80: the other segment), and
  `WMI_CHAN_FLAG_DFS_CFREQ2` (bit15) when `center2 - 10` is a radar channel;
  no station START carries `WMI_CHAN_FLAG_DFS`. The channel list lists all
  eight rows, radar rows `PASSIVE | DFS`. `PeerPrepared` reports the cfg80211
  chandef (160 MHz centre, no second segment, bandwidth 160). Tests (written,
  unexecuted): `smoke_ath10k_vht160_contiguous_auto_bw_and_radar_constituents`,
  `smoke_ath10k_vht160_direct_rule_upper_radar_span`,
  `smoke_ath10k_vht160_profile_primary80_and_second_center`,
  `smoke_ath10k_vht160_phymodes_and_nss_override`,
  `smoke_ath10k_vht160_station_start_channel_centers_and_dfs_cfreq2`, plus
  `smoke_regulatory_auto_bw_chain_admits_and_refuses_160` and
  `smoke_regulatory_policy_second_flag_byte` in `narf-wireless`. No
  end-to-end native association conversation on a contiguous160 BSS is
  written yet; the 80+80 conversation suite still covers the shared wide
  owner.
  Deprecated width3 and revised width1 VHT Operation encodings share the
  same strict geometry plan. An association response cannot replace a
  center or occupied segment after native START; it fails before
  PEER_ASSOC/M2/DATA. Denied second span, absent chip/dialect/service/width
  facts select an actual primary80 request, native start and peer profile.
  There is no live retune or late width alias. Native source admission and
  existing terminal/cancellation/key ownership remain mandatory.
  Six new cases cover the two actual chip/NSS profiles, both segment orders
  and operation encodings, Open/WPA2 kernel DHCP/IP, unequal span power,
  real primary80 fallback, original encrypted same-PN PHY rejection,
  directional highest-rate hints, second-span final-copy revocation and
  response center2 replacement. They have not run; release compilation and
  physical RF/interoperability acceptance are pending.
- WPA2-PMF and WPA3-SAE (`wmi_runtime/station_pmf.rs`, `data.rs`,
  `management.rs`; smokes under `drivers/wireless/ath10k/pmf` and
  `drivers/wireless/ath10k/wpa3`). Linux v7.2 sets `MFP_CAPABLE`
  (`mac.c::ath10k_mac_register`) and leaves SAE to wpa_supplicant
  `sme_sae_auth` over mac80211 `ieee80211_auth`; here the shared
  `JoinPlan`/`SaeSession` run on the host. A WPA2 join advertises MFPC
  (`JoinOptions::with_pmf(Pmf::Optional)`, wpa_supplicant `ieee80211w=1`, with
  PSK-SHA256 admitted) only toward an AP whose scanned RSNE sets MFPC, so the
  request to any other AP is byte-for-byte unchanged. `SecurityConfig::Wpa3`
  selects SAE (`sae_pwe=2`): a Commit from the kernel CSPRNG, up to three
  anti-clogging retries and Confirm cross the initial management transport
  (algorithm3 frames of any status go to the plan; nothing else advances), and
  the SAE association request carries the PMKID. The association's station
  RSNE/RSNXE (`JoinPlan::rsn_body`, SAE `station_rsnxe`) and the SAE PMK are
  retained, boxed, and build `Security::new` or `Security::new_sae`; the IGTK
  arrives in message 3. `management::validate` admits only SAE Commit
  (status 0/126) and Confirm (status 0) besides Open-System auth and
  association, and Protected Deauthentication/Disassociation (42 bytes) and
  SA Query Response (44 bytes) already CCMP-protected by the host. Under PMF,
  WMI management RX from the bound AP goes through `Security::receive_management`
  (mac80211 `ieee80211_drop_unencrypted_mgmt`): unprotected unicast robust
  frames, broadcast frames without a valid BIP-CMAC-128 MMIE, replays and bad
  MICs are dropped; an admitted Deauthentication/Disassociation closes the
  link, and an admitted SA Query Request queues a protected Response with the
  same transaction id (`ieee80211_process_sa_query_req`), published by the
  Device service worker after the synchronous drain (the WMI management path
  cannot be awaited there). A local disconnect under PMF first sends one
  Deauthentication (reason 3, `ieee80211_set_disassoc`) protected with the
  still-installed PTK; non-PMF teardown still sends none. In the software
  key profile (`ATH10K_CRYPT_MODE_SW`) the host expects robust unicast frames
  still encrypted on WMI management RX and PEER_ASSOC carries no
  `WMI_PEER_PMF`. The registered PCI radio selects the hardware key profile
  of §3.4, which sets `WMI_PEER_PMF` where Linux does and then admits
  firmware-decrypted robust management (`wmi.c::ath10k_wmi_rx_is_decrypted`)
  through a PN-only check; that firmware behaviour needs physical
  confirmation.
- The registered Device binds native preparation, authentication/association,
  WMM/peer/up commands and initial RSNA data to a chosen factory/frequency/power
  receipt. It samples current policy before and after each nested wait and
  before each new command or EAPOL publication. Observed clear, changed country/power,
  DFS, NO_IR, unqualified indoor-only or unknown restrictions terminate admission
  on either band; NO_P2P alone does not restrict STA. Cancellation or a late
  successful receipt cannot reopen the host, commit a failed M4 or release
  uncertain DMA. Passive receive keeps its distinct non-transmit permission.
- The older public `wmi` MAIN-dialect codec now uses Linux's group IDs
  starting at index 1, with distinct scan/debug events and correct
  `VDEV_SET_PARAM` (0x5008), RTS, fragmentation, beacon and DTIM parameter
  IDs. The nonexistent `vdev_param::MAC_ADDR` constant is removed. These
  helpers remain MAIN-only; the retained runtime selects each firmware
  dialect separately.
- `regulatory::Factory::from_eeprom` resolves the bounded SERVICE_READY
  factory EEPROM identity through Linux's pair/country/CTL tables, including
  exact sanitization and roaming-bit handling. Its country is descriptive,
  never host transmit authority. `Factory` and `FactoryError` are reexports
  of the common immutable Qualcomm resolver, also used by ath9k; unknown or
  oversized identifiers return `FactoryError::Unsupported`. Internal station
  permission construction maps that error to its existing unsupported error.
- `pci::prepare_station(bssid, frequency_mhz)` prepares one native station
  context selected from the last successful passive or active scan cache. It requires
  the installed authenticated host regulatory policy; initial geometry is
  legacy/HT20 on channels 1–11 or 5-GHz centres 5180/5200/5220/5240 and
  5745/5765/5785/5805/5825 MHz within firmware hardware limits. 5 GHz requires
  an actual fixed-country factory identity matching the authenticated host
  country, or the original native World-layer Beacon receipt in §3.2;
  host policy alone never promotes a World factory identity. Host
  occupied-channel power is additionally bounded by 20 dBm on 2 GHz and
  30 dBm on 5 GHz, while immutable factory pair/CTL and firmware calibration
  remain active. These bounds are ceilings, not measured board transmit power.
  Every overlapping host power/bandwidth/DFS restriction applies; 5-GHz
  indoor-only restrictions without authority, negative power, DFS and 6 GHz
  stay closed. Native station/channel/peer
  records use 11A for 5 GHz and reject CCK there; 2 GHz retains 11G/11B.
  It programs immutable factory pair/CTL and additional half-dBm power limits,
  waits for a successful correlated VDEV_START_RESPONSE, creates the BSS
  peer and waits for native HTT peer-map confirmation. `PeerPrepared` reports
  the bound BSSID/primary frequency, center_frequency, optional second_center_frequency,
  and bandwidth_mhz (20/40/80, or160 total for80+80),
  sparse firmware peer ID and host power ceiling;
  `Ath10kDevice::station_prepared`/`station_error` retain this diagnostic
  result. These APIs transmit no MLME/data frame and do not imply association,
  key installation, carrier or a registered NIC. A prepared context cannot
  be scanned/replaced until owned teardown/reset is implemented. Any ambiguous
  command, cancellation, malformed map or failed response closes its owner
  while retaining DMA. Station prepare, management exchange and association
  bootstrap a staged signed `wireless-regulatory.bin` through
  `reg::db::ensure_domain()` when the caller has not installed a domain.
  Missing/invalid policy fails before station publication; another driver
  is not required to initialize regulatory state.
- `pci::exchange_initial_management(frame)` exchanges initial unprotected
  Open-System Authentication and then Association Request on that prepared
  peer. Requests must use its BSSID and local station address; association
  must name the cached SSID. Frames must have no DS/protection/fragment flags
  and must carry complete bounded IEs. The installed
  host policy must still match the programmed channel/power permission.
  Matching RX is bound to the same native channel, TA/BSSID and local recipient;
  failed status, malformed transport, timeout or dropped future closes the
  retained radio. Each phase advances at most once. The returned raw peer
  response is a transport prerequisite; use `pci::associate_station` to run
  the checked negotiation and native peer/vdev commands. This exchange API
  alone grants no key, data admission or interface carrier.
  Internal `ManagementReceipt` distinguishes inline submission (no terminal
  air ACK fabricated), HTT packet IDs and referenced-WMI descriptor IDs;
  `ManagementCompletion` keeps the actual firmware status with its ID.
- `pci::associate_station(ssid, SecurityMode, sme_ies)` uses the shared
  `association::JoinPlan` on the exact prepared scan-cache BSS. It checks ESS,
  SSID, legacy rates/basic-rate support and Open/WPA2-PSK CCMP policy before
  publishing authentication; optional SME IEs follow the shared validator.
  Bound native management responses must pass the shared phase, capability,
  status, AID and IE checks. The negotiated legacy rates, capability and AID
  enter dialect-specific native WMI PEER_ASSOC and VDEV_UP. The returned
  `StationAssociated` describes AP negotiation plus command submission;
  it is separate from key installation, RSNA completion, firmware security
  authorization and controlled-port/NIC admission. Submission receipts are
  not fabricated firmware acknowledgments. A failure or dropped waiter keeps
  the radio closed and retains its nested DMA owner. Every receive iteration
  yields, and credit-only or consumed terminal/MAP events are progress rather
  than receive quiescence. Already queued UNMAPs are processed before exposing
  the result; the last UNMAP clears association, and a later MAP cannot revive
  it. The shared plan intersects response Supported/Extended Rates with the
  original offer, preserving every beacon-mandatory basic rate. The resulting
  negotiated set, including optional-rate downgrades, enters native PEER_ASSOC.
  Association remains one-shot; confirmed terminal teardown does not permit
  another join without a future full reset/generation-fencing owner.
- `pci::disconnect_station()` retires the current prepared/associated peer and
  stops station vdev0 through the retained `Radio`. It closes peer visibility
  before its first await, drains stale prerequest events, submits native
  VDEV_DOWN and PEER_DELETE, then waits for every owned sparse HTT ID to UNMAP.
  Matching in-flight MAPs extend that ownership set; duplicate UNMAPs cannot
  retire another ID and rebinding an owned ID to another identity fails.
  Advertised TLV `SYNC_DELETE_CMDS` additionally requires the exact vdev0/BSSID
  PEER_DELETE_RESP, independent of UNMAP order. Native VDEV_STOP follows only
  after peer retirement and receive quiescence; matching VDEV_STOPPED plus a
  second receive-quiescence check confirms terminal stop. Foreign events and
  stale pre-STOP receipts cannot substitute for these events. A late peer MAP
  invalidates the stop transaction. Every receive iteration yields and has a
  deadline plus event bound. Failure, cancellation and even successful teardown
  leave this owner closed. `StationDisconnected { bssid, frequency,
  synchronous_delete }` reports firmware peer/vdev retirement only; all CE/HTT/
  WMI/firmware DMA stays retained until a future whole-device reset/drain proof.
  Teardown sends no over-air deauthentication and makes no PM, DMA reclamation
  or rejoin claim. The registered Device closes host carrier and security
  before awaiting this firmware transaction. All six native WMI dialects are covered;
  only TLV advertises the extra synchronous delete service.
- `pci::recover()` retires a retained boot/runtime/radio generation and schedules
  the existing fresh-ROM boot path: chip-specific reset, new coherent CE rings,
  BMI identity, current authenticated firmware/BDF and OTP calibration, then
  HTC/WMI/HTT/scan setup and normal policy/network-capability interface admission.
  It returns `RecoveryScheduled { attempt }` after scheduling, not readiness;
  current controller stage/error metadata and eventual registration report the
  result. Missing policy or deployment assets retain their normal staged waits.
  No peer, keys, PN or cached BSS cross generations. The rebound interface
  replays the retained network block (automatic credential replay below).
  `RecoveryError::Busy` means no retained session is available (including boot
  in progress); Exhausted enforces three attempts per kernel boot. Transport
  failures propagate without reopening the old generation.
  Radio quarantine precedes its mutex wait and survives cancellation: all native
  PCI radio APIs reject that session. Host carrier/registrations close first;
  after acquiring Radio, packet security is failed and host retirement is
  repeated under that lock to catch an older in-progress `wait_publish`.
  Queued old interface control rechecks closure after acquiring the radio.
  Each generation has a non-reused TX cookie; net-stack snapshots from a removed
  interface cannot send into its replacement. Retired names are reserved before
  unregister, preventing another driver's wlan-name allocation in that gap.
  Every CE interrupt source is masked and every CE is halted before verified
  PCI bus-master disable. A failed halt still attempts master disable but cannot
  start a successor. The retired physical owner is terminal before hardware
  access, and its late Drop performs no MMIO, BME or ASPM operation against a
  successor. DMA reclamation (`boot.rs::PciBoot::flushed`,
  `boot/recovery.rs`): after every CE is halted and PCI bus mastering reads
  back clear, the retiring owner checks PCIe Device Control Relaxed Ordering
  is disabled and completes a non-posted BAR read, which then orders behind
  every earlier device-posted write. Only then is it `reclaimable`, and its
  late Drop frees the boot/firmware/WMI/management/HTT allocations (still with
  no hardware access). With BME off no CE or firmware-directed write can start;
  every successor performs the Linux `ath10k_pci_safe_chip_reset` warm CE/CPU
  or cold SoC reset and reprograms the CE rings before it re-enables bus
  mastering. Any halt, BME, ordering or flush failure keeps every mapping
  pinned. A non-retired terminal Drop uses the same proof after firmware
  DONE. No RF-quiescence proof is claimed. The attempt limit bounds pinned
  generations. It is also the restart step of automatic recovery (below). It is
  not stable-netdev reconnection. Physical reset,
  ROM/firmware restart and repeated RF association still need hardware acceptance.
- Automatic recovery (`restart.rs`, `pci::firmware_crashed`). Linux
  `pci.c::ath10k_pci_napi_poll` checks `ath10k_pci_has_fw_crashed`
  (`FW_INDICATOR & FW_IND_EVENT_PENDING`) before any CE service. It clears
  the bit and queues `ath10k_pci_fw_dump_work`, which counts
  `fw_crash_counter` and calls `core.c::ath10k_core_start_recovery`. That
  function deduplicates with `ATH10K_FLAG_RESTARTING` and queues
  `ath10k_core_restart`. Here every runtime service (`hif_poll`,
  `hif_poll_now`, interrupt-driven or polled) checks the indicator first. On
  a crash it clears only EVENT_PENDING, poisons the generation (all later
  sends/polls fail) and returns `BmiError::FirmwareCrashed`. A
  non-retired owner then calls `pci::firmware_crashed`. A `restart::Gate`
  counts the crash (`pci::firmware_crash_count`). Only the request that
  sets RESTARTING spawns a supervisor; later crashes while restarting are
  counted, never spawned again. The supervisor calls `pci::recover()`.
  `Busy` (the crashed stage has not yet stored its owner) backs off 50 ms,
  up to 100 times, then gives up as `Outcome::Abandoned`. `Exhausted` is
  `Outcome::Wedged`, the `ATH10K_STATE_WEDGED` analogue for the three
  attempts per boot. A failed retirement is `Outcome::Failed` and keeps
  the old DMA pinned. Success is `Outcome::Scheduled { attempt }`. The
  outcome is published through `pci::last_automatic_recovery`, and
  RESTARTING is cleared so a successor's crash can recover again. The
  fresh generation rebinds the same station interface (smokes under
  `drivers/wireless/ath10k/recovery`): as mac80211 `ieee80211_restart_hw`
  keeps the `net_device`, `interface::retire` (recovery and suspend) retires
  it with `narf_net::iface::retire_for_rebind`, which reserves the name
  atomically with removal and keeps its entry, and remembers the name; the
  next `publish_with_mac` claims it with `rebind_name`, so the `wlan%d`
  name, ifindex, addresses, counters and the operator's IFF_UP survive while
  carrier stays down until a new association. The old generation's send
  hook is dropped. A registered or never-retired name is never handed out;
  publication then allocates a fresh `wlan%d`. Rejoin goes through the
  interface's normal scan/associate path. **Automatic credential replay.**
  Every completed association retains its network block in
  `narf_wireless::reconnect` under the netdev name, bound to the owner
  `ath10k` + the radio's permanent MAC (BSSID, SSID, channel,
  SME elements, PSK or SAE password in zeroizing storage; never an external
  supplicant's); an operator `disassociate` forgets it. A `publish_with_mac`
  that rebound the retired name and finds a block spawns
  `Device::replay_retained`: it takes the block once, skips (keeping it) an
  operator-down netdev, scans passively for that SSID/BSSID on its channel
  and runs the ordinary associate path, i.e. auth/assoc and a fresh RSNA
  with the retained credential; a completed replay retains the block again.
  This mirrors Linux when mac80211 cannot reconfigure the restarted device
  (`ieee80211_sta_restart` → `ieee80211_sta_connection_lost` under
  `IEEE80211_SDATA_DISCONNECT_HW_RESTART`) and wpa_supplicant reconnects
  from its network block; mac80211's in-place `ieee80211_reconfig` (re-adding
  the station and keys without an over-the-air exchange) is not modelled,
  so PN/replay state and keys restart with the new RSNA. One attempt per
  generation; no retry/backoff policy. Composed case (written, unexecuted):
  `smoke_ath10k_recovery_replays_retained_credentials_on_rebound_generation`
  (main and TLV: down netdev skipped, replay with a fresh FakeAp 4-way,
  bidirectional data, operator disconnect forgets); shared
  `smoke_wireless_reconnect_profile_retains_credentials_once`. WMI
  command timeouts do not yet trigger recovery: Linux `wmi.c` does that in
  `ath10k_wmi_cmd_send` on `-EAGAIN`, and here those timeouts stay
  fail-stop errors for the caller.
- System suspend (`pm.rs`, `pci::{suspend, resume}`, registered as the
  `ath10k` `narf_power::system_pm::AsyncSystemPm` hook). This follows the
  Linux v6.10 non-WoWLAN path. mac80211 `ieee80211_suspend` calls
  `drv_stop`, which reaches `mac.c::ath10k_stop` (`ath10k_halt`,
  `ath10k_hif_power_down`). `pci.c::ath10k_pci_pm_suspend` then puts the
  target to sleep. `ath10k_pci_pm_resume` -> `ath10k_pci_resume`
  re-disables the RETRY_TIMEOUT byte (config 0x41, lost in D3). mac80211
  `ieee80211_reconfig` -> `ath10k_start` -> `ath10k_hif_power_up` then
  performs a full chip reset and firmware boot. Here `prepare_suspend`
  plans under the session lock (`pm::plan`). With no bound function it
  returns success. Boot or automatic recovery in progress (no retained
  session, or RESTARTING) returns `Busy`, which aborts the system suspend
  with the generation intact. `Pinned` is returned once three earlier
  suspends left unreclaimable DMA, keeping the generation usable. Otherwise
  it retires the live generation exactly as recovery does: host interface
  and radio quarantine first, interrupt teardown, every CE masked and
  halted, bus mastering verified off, ordered flush proof. It then parks
  the function identity. A failed retirement leaves that generation
  terminal (`DriverError`), as a failed `ath10k_stop` would. Resume clears
  config 0x41 if set, then schedules the ordinary fresh-ROM `boot_task`
  (reset, BMI, current authenticated firmware/BDF, HTC/WMI/HTT, interface
  registration). Resume without a parked generation does nothing. As in
  Linux without WoWLAN, the association is not preserved, and rejoin goes
  through the new interface. Suspend does not use the recovery attempt
  budget. With a retained WoWLAN configuration and an associated station,
  §3.6 runs first and keeps the generation; PCI runtime D3 and platform
  wake routing are not provided. The separate D0 host-vote/ASPM owner follows.
- Host-bus PM (`boot/power.rs`). Pinned Linux7.2
  `pci.c::ath10k_pci_{wake,sleep,ps_timer}` and `ath10k_pci_hif_start` supply
  the QCA6174/6164 and QCA9377 `pci_ps` contract. Boot retains its explicit
  wake vote. After actual BMI_DONE, retained CE startup and successful MSI
  delivery setup, each ordinary MMIO operation acquires a nonwrapping awake
  reference under the original current PCI and executable/board capabilities.
  A fresh wake writes the actual PCI-local WAKE bit, reads it back, and waits
  up to30ms for actual RTC_ON3 before the requested register access. Raw
  WAKE/RTC polls invoke those same authorities directly, so wake never
  recursively requires already-awake MMIO. The operation releases its exact
  reference even when the payload fails; failure closes ordinary admission.
  Saved PCIe ASPM is restored and its owned bits read back only after runtime
  CE/IRQ startup with that owner installed, rather than only on Drop.

  A genuine empty native service pass can arm60ms grace only while current
  Radio/software/BA/control state and all source CE, referenced management and
  HTT TX owners are idle. Permanently posted destination RX buffers remain
  mapped; they are not pending host work or released by sleep. During the
  grace the MSI-backed idle pump observes its retained signal counter and
  timer without BAR reads. At60ms it clears and reads back only its host WAKE
  vote. Firmware may remain awake or actually sleep: neither the request nor
  that readback is called a target-sleep receipt. An IRQ, host native operation
  or changed pending ownership defeats the old idle observation; payload MMIO
  still requires a fresh WAKE/RTC proof. A70ms bound from the original empty
  pass forces a full wake/service backstop, preserving the existing10ms
  missed-edge interval after vote release. The hard IRQ only raises the same
  retained signal and performs no sleeping BAR access. Without MSI, or on
  Linux profiles whose `pci_ps` is false, the ordinary polling path remains.

  Initialized unassociated owners use a narrowly opted-in passive maintenance
  path under the Device publication/Radio locks. It drains actual HTC credit
  progress, requires no peer/DATA/scan/ROC/control/copy continuation, and retains
  any other native event unchanged in the existing bounded queue while
  disabling idle. Ordinary transport models default out. Associated DATA also
  requires empty receive/reorder/security/native-original state; current policy,
  source and controlled-port checks remain mandatory. A PM-deferred physical
  poll propagates as explicit progress through HTC/HTT, never as an actual empty
  receive prefix: it cannot complete M4, expire/release reordered frames or
  publish copied RX. Synchronous protocol/control waits bypass the defer path.

  Retirement first closes the original HIF/RF generation and detaches only its
  expired executable scope. Its still-current original PCI authority may wake
  solely for terminal IRQ/CE/reset cleanup, with the vote pinned across reset;
  it cannot restore that old mission owner. Actual CE halt, BMEoff and ordered
  flush remain prerequisites for reclaiming DMA and releasing the terminal
  vote. A failed wake still attempts original-PCI MSI/vector teardown (or CPU
  quarantine if that grant is lost), PCI BMEoff and retains uncertain mappings;
  retired Drop never supplies a delayed hardware-cleanup attempt.
  Seven source cases cover real cap revocation/RTC/vote/refcount edges, retained
  native CE and management tickets, explicit defer versus genuine empty
  receive, and unassociated current-source/input ownership. They are written
  but unexecuted. No target power, wake latency or board measurement is claimed.
- Interrupt service (`irq.rs`, `boot/interrupts.rs`). Linux v6.10
  `pci.c::ath10k_pci_init_irq` tries MSI first; `ath10k_pci_hif_start`
  calls `ath10k_pci_irq_enable`. Here `PciBoot::done_complete` (BMI_DONE
  accepted) first runs `Program::disable` (`ath10k_pci_irq_disable`: every
  CE's copy-complete/watermark HOST_IE and MISC_IE error bits, then
  `ath10k_pci_disable_and_clear_intx_irq` and `ath10k_pci_irq_msi_fw_mask`).
  It then discovers the MSI capability, allocates and programs one vector,
  installs the handler and sets MSI Enable. Only after that does it run
  `Program::enable`. This is `ath10k_ce_per_engine_handler_adjust`:
  copy-complete for engines with a Linux host callback (CE0/CE3 send,
  CE1/CE2/CE5/CE8 receive when present). CE4 (`CE_ATTR_DIS_INTR`) and CE7
  (diagnostics) stay off, and watermark is always off. It also writes
  `PCIE_INTR_ENABLE = FIRMWARE_MASK | CE_MASK_ALL` and sets the
  CORE_CTRL `PCIE_REG_31` firmware MSI gate (QCA988X/QCA9887/QCA6174/QCA9377
  only; Linux leaves QCA99X0-class as TODO). Register constants come from
  `hw.c::{qca988x,qca6174,qca99x0}_regs` and `qcax_{wm,misc}_reg`.
  The vector handler only raises an edge-latched `irq::Signal`; it never
  touches the BAR. The owner's next service runs the hard-handler and
  `ath10k_pci_napi_poll` sequence. First comes `ath10k_pci_has_fw_crashed`
  (see automatic recovery). Next come the line/firmware mask and
  `ath10k_ce_per_engine_service_any`'s HOST_IS clear for every summarized
  engine, both before the rings are polled. Last, the epilogue re-enables
  only when `ath10k_ce_interrupt_summary` reads empty. Otherwise it keeps
  the line masked and re-raises the signal, which is the `napi_schedule`
  path. The data worker waits on that signal, a host TX/power-save kick or
  a 10 ms missed-edge backstop. It re-runs at once while a drain made
  progress. Protocol waits in `hif_poll` use the same wait, clamped to
  their budget. Without MSI (no capability, no vector, a non-PCI function,
  or an aarch64 host whose MSI programming fails) chip interrupts stay
  masked and service keeps the previous 1 ms period. The INTx program is
  limited to the `ath10k_pci_irq_pending` cause check. Blocker for a
  line-interrupt mode: NARF has no ath10k INTx route, meaning a
  level-triggered GSI handler allowed to write `PCIE_INTR_CLR` from the
  hard IRQ. Teardown (`stop_interrupts`) runs on retirement before the
  park and on non-retired Drop. It disables every source, clears MSI
  Enable and frees the vector. A failed cfg-space disable keeps the vector
  quarantined (masked, no waker, never reallocated). All-ones reads from
  surprise removal are never decoded as a cause, crash or summary. No
  interrupt-rate or throughput claim is made without hardware.
- `pci::start_station_data(pmk)` starts the retained packet owner after native
  association, with `None` for Open or the caller's WPA2 PMK. It requires
  firmware `RAW_MODE_SUPPORT` (bit10), RAW RX selected during WMI INIT, and a
  non-PFC HTT profile or the bounded native PFC owner below. All six WMI resource layouts use their actual decap
  field; HTT disables transmit A-MSDU for Linux's raw-mode workaround. Other images
  retain native-WiFi RX and cannot enter this software-CCMP owner. Shared
  `station_security::Security` owns the supplicant, fallible nonce acquisition,
  software CCMP, per-key/TID replay, PN and retired-key history. M2/M4/group
  replies use native raw HTT with NO_ENCRYPT and retain their DMA payload and
  fragment owners after CE completion. Only the matching successful terminal
  HTT ID commits the pending security change. With the §3.4 hardware key
  profile each committed PTK/GTK is then programmed and confirmed by the
  firmware's own HTT security indication; no hardware key receipt is
  fabricated. An early association-era M1 is preserved only after full native
  descriptor/peer/TID/header and unprotected-unicast EAPOL admission; all
  preauthorization IP is discarded. `StationLink { bssid, frequency, protected }`
  requires the live peer and current completed data authorization. Temporary GTK/PTK
  reply waits close the data port without flapping established physical carrier.
- The bounded PFC continuation admits RAW-capable 10.4/HTT-dialect4 images on
  QCA99X0, QCA9984 and QCA9888 only with the retained coherent qstate adapter.
  Unknown transports default to unsupported. Every host queue is bound to a
  delivered native `PEER_MAP`, vdev0/AP MAC and the current station's exact
  peer bitmap. Queue IDs cover0–527 and TIDs0–7; non-QoS RAW retains native
  ext-TID16 while using host queue0, following mac80211's non-WME priority0.
  A foreign vdev, peer replacement, UNMAP or unsupported TID cannot alias a
  queued original. The admitted station Pipeline remains bounded to32 IDs.
  Its existing three-second native-operation deadline and bounded RX queues
  continue while firmware provides no fetch; no unbounded key/RX stall is
  introduced.
- Actual 10.4 `TX_MODE_SWITCH_IND` selects PUSH/PUSH_PULL and global/per-TID
  push limits. Complete native `TX_FETCH_IND` record lengths and bounds are
  validated before any request-prefix ownership changes. Repeated peer/TID
  records carry separate sequential budgets; repeated MODE records use the
  last limit, with every later record validated before earlier limits change.
  The MSDU limit is exact. Following Linux, a whole bounded frame is selected
  only while the accumulated byte count is below the byte threshold. That final frame
  may cross the threshold, and its complete actual length is reported with
  checked accounting. Requiring it to fit a rounded-down qstate hint would
  starve valid queues; a zero-byte request still sends nothing.
  The retained CE4 command extent is256
  bytes including HTC, so one complete `FETCH_RESP` admits at most29 records
  (252 bytes including HTC);30 records close the owner before TX. Responses
  are neither truncated nor split into an invented continuation protocol.
  Token and sequence are opaque echoes, following Linux's `htt_rx.c` and
  `htt_tx.c`: every delivered native event, including identical/lower/wrapped
  echoes, owns a distinct nonwrapping private host operation and phase.
  Polling the same owned phase cannot publish its native ID twice. No
  cross-event cache or wire-scalar ordering/deduplication grants authority.
  Constant response-ID0 and `FETCH_CONFIRM` are convenience metadata, never
  packet, PN, controlled-port or DMA-completion credit.
- PFC qstate is the actual advertised4772-byte layout:528×8 count bytes,
  eight17-word native maps and a nonwrapping sequence. Byte-count encoding
  follows Linux's128-byte coefficient, six-bit factor and two-bit exponent.
  Counts and aligned32-bit map stores precede an outer-shareable DMA barrier
  and one aligned32-bit sequence store. The physical allocation may be8192
  bytes; only the exact advertised span is updated. Original executable,
  board and PCI invocations enclose that coherent copy. Prepared host entries
  and actually CE-published IDs remain distinct; an HTT terminal batch naming
  any unpublished queued ID fails before releasing any payload. Only actual
  native HTT TX terminal status ends an advertised payload/fragment owner.
- A PFC entry is released only by the live DATA/handshake path after fresh
  policy, native peer, source, timeout and key/port checks. Generic management
  or scan credit progress cannot revive queued DATA. Retained DATA/EAPOL input
  waits while prior host DATA entries still await native publication, keeping
  their old security key/port current; native loss, UNMAP and management still
  progress immediately. The existing Pipeline then drains every old DATA air
  terminal before admitting the sole M2/M4/group reply. A key reply retains
  its exact Reply owner while its port is closed, and key/port promotion still
  requires its successful native air terminal. Cancellation, malformed fetch,
  missed-fetch timeout and current-source loss retain uncertain native pool
  mappings for the existing terminal-reset/CE-halt/BME-off/flush proof.
- `pci::transmit_ethernet(bytes)` submits one admitted Ethernet frame through
  this owner and returns its actual retained HTT ID; PFC may keep that original
  in its host queue until a real push allowance or fetch arrives. ToDS/RFC1042 and
  optional software CCMP preserve packet identity; externally supplied EAPOL
  stays closed. `pci::poll_ethernet()` drives the same HTC/HTT owner and returns
  Ethernet only after receive quiescence with a still-owned peer. Native v1
  descriptors and indications must agree on sparse peer, TID, DS, sequence,
  length, RAW decap and an unfragmented legacy/qualified HT20/HT40 MPDU. CRC errors,
  foreign identities, hardware-decrypted RX, PADDR offload/fragments and
  unowned A-MPDU/reorder profiles are excluded. Complete original RAW A-MSDUs
  use the bounded opt-in shared receiver described above. RAW FCS is stripped before CCMP verification;
  only authenticated, replay-checked data reaches RFC1042 decapsulation.
  Last-peer UNMAP, bound deauthentication, failed terminal TX, timeout,
  malformed state and cancellation close the retained radio. Disconnect
  closes security before awaiting firmware retirement. Their async diagnostic
  surface and the nonblocking network drain share the same packet parsing,
  peer events, terminal receipts and security state.
- `interface::Device` implements the registered legacy/HT20/qualified HT40 profile after
  calibrated boot, WMI/HTT/scan setup, RAW station-profile admission, signed
  regulatory bootstrap and current network-registry capability admission.
  `boot_task` publishes the retained `SESSION` and `scan_ready` immediately after
  `initialize_radio`, then runs `interface::wait_publish` so admitted RAW radios
  wait for missing `wireless-regulatory.bin`, loader authority or network
  registry authority without blocking passive-scan diagnostics; non-RAW images,
  unsupported PFC adapters and invalid/unsigned regulatory policy fail immediately without waiting.
  `RadioSession` retains an `Arc<Mutex<Radio<PciBoot>>>` with the selected image
  and board profile; native PCI APIs and the Device share this single owner.
  The Device exposes passive/active scan and Open/WPA2-PSK/WPA2-PMF/WPA3-SAE
  CCMP on configured channels1–11 and the admitted fixed-country non-DFS
  5-GHz centres above, legacy/HT20, the bounded HT40 pairs or VHT above. Unsupported scan options, PHY modes, external EAPOL and
  checksum/TSO/VLAN requests are rejected, including direct frame-ring clients.
  Native control and each bounded packet-progress pass sample the current
  trusted regulatory database rather than an attachment-time clone. Passive
  scan requires complete receive-channel coverage; association resamples
  between preparation, management and security stages and before carrier.
  Packet progress refuses a removed channel or changed programmed power
  ceiling before consuming host TX or publishing native DMA. Such a change
  closes carrier and discards queued traffic; restoring policy cannot reopen
  the terminal owner. Disconnect can still send DOWN/DELETE/STOP independently
  of policy. A cfg-only policy-source seam exercises isolated live changes
  without installing fixture policy in the global database.
  Carrier starts closed and opens only after actual authorization. Disconnect,
  cancelled control operations, peer loss, malformed state and native progress
  failure close carrier permanently; another join requires a future reset owner.
- **Associated scans:** the Device now has a retained scan receipt owner for
  passive or directed/wildcard active scans on an authorized station vdev.
  Firmware's normal WMI scan scheduler handles home/off-channel PS and dwell,
  following Linux `mac.c::ath10k_hw_scan`. Twelve native conversation cases
  pass on x86_64 and aarch64; physical RF/board acceptance remains separate.
  Preflight binds the current associated BSSID and occupied permission before
  reserving a nonwrapping scan ID. Active setup sends the native domain,
  minimum granted per-band power and a complete channel inventory before
  START_SCAN. Probe rows receive only their actual20MHz initiation permission;
  the home20/40/80MHz rows retain their occupied power and negotiated HT/VHT
  flags. Passive setup never promotes a probe row. Small discovery inventories
  retain any real home HT partner/VHT segment rows required by the existing
  association. A successful matched terminal restores home domain, power and
  inventory; an off-channel report cannot erase the bound home beacon cache.
  During dwell the public future releases Radio's async mutex. The ordinary
  native peer/HTT/key/BA drain observes scan events and continues host TX, RX,
  DHCP and stack callbacks under the existing ownership and controlled-port
  fences. Callbacks still run after Radio/ring/publication locks are released.
  Authenticated rekey can temporarily close DATA while preserving carrier and
  the scan's peer binding. Operator PS changes remain queued until restoration.
  Current probe and occupied-home permissions are checked on every control
  poll and packet-progress pass. Policy loss never restores obsolete power.
  A dropped public future closes host publication and wakes the retained
  worker. Its exact STOP_SCAN terminal precedes native DOWN/DELETE/UNMAP and
  VDEV_STOPPED; command submission, wrong scan/request/vdev events and timeout
  cannot stand in for those receipts. A terminal already observed before a
  cancelled restore is retained as the stop proof. Concurrent disassociate
  closes host traffic and returns Busy while this worker owns retirement;
  retry succeeds after the native teardown receipt. Physical-generation
  retirement prevents an old cleanup continuation from addressing a successor.
  DMA stays retained and the failed owner requires full reset; this is no
  receive-generation or recovery proof. Managed remain-on-channel/Public Action
  control uses the separate bounded owner below; native P2P roles remain separate.
  Scan setup/restore/STOP use cooperative retained WMI publication: HTC credits
  and sequence remain in Session, while native CE3 occupancy, bounce bytes and
  completion deadline remain in HIF. A public drop at a credit/CE wait cannot
  poison away the worker's STOP path or make a busy source buffer reusable.
  The worker first waits for that exact source receipt; its later matching
  firmware scan terminal is a separate requirement. Ordinary BMI/control
  operations retain their existing fail-stop cancellation behavior.
  Actual PCI unassociated scans also retain their WMI source/credit waits;
  pure protocol fixtures without native CE keep the legacy transport surface.
  Scan completion follows the time deadline rather than a CPU poll count.
  Copied RX carries the immutable scan program/caps through the last policy
  read before its stack callback, including an off-channel restriction that
  leaves the associated home channel permitted. Retired host closure and
  repeated retirement cannot update or remove a rebound registration.
  Failed scan/peer cleanup queues a supervisor bound to the exact Radio and
  physical generation; raw diagnostic scan errors/cancellation do the same.
  It makes the generation terminal before detaching expired executable/board
  scopes. Reset/MMIO and bus-master-disable attempts still require current
  PCI authority. Native CE park, family-safe reset and a post-reset BME-off
  attempt run even when the DMA halt acknowledgement is ambiguous. Reclamation
  requires the original halt plus ordered-flush proof; otherwise DMA stays
  pinned. A stale request cannot retire a successor. Physical grant loss may
  deny the attempt; no timeout or reset submission asserts physical RF quiet.
- **Bounded ROC, implicit FRAME wait and Public Action responses (source
  implementation; execution pending):** actual managed vdev0 can acquire one
  receive-only or separately TX-qualified channel for1..500ms through typed Radio control. It never creates
  a P2P interface or borrows an AP/GO owner. A live original socket/grant,
  registered IFINDEX and immutable physical generation remain required. The
  current native BSS/key owner must be idle before an associated ROC; existing
  DATA/reply IDs and active security work cannot cross acquisition. Native RF
  transition advances the copied-RX epoch and discards prior PPDU/receive staging.
  Host DATA, ordinary queued management and operator PS programming pause until
  the exact ROC terminal/home restore, preserving the original PTK/PN/carrier.
  STARTED or CE/credit progress is insufficient: the matching nonwrapping scan
  ID/request/vdev must report FOREIGN_CHANNEL at the requested frequency before
  READY or an action descriptor. Passive scan flags and empty probe content are
  retained. Linux's WMI dwell/max-scan fields are set to the requested finite
  budget itself, rather than relying on a blocked host waiter to enforce Linux's
  longer scan backstop; MAIN/10.4/TLV also carry that burst duration. Early native
  completion ends the interval instead of fabricating remaining RF time.
  Host expiry/cancel sends the exact STOP once. COMPLETE/DEQUEUED and, for a live
  BSS, an actual matching BSS_CHANNEL home receipt precede restoring the original
  full occupied domain/power/inventory. A host timer or STOP submission is no
  terminal or RF-quiet proof. Current home/foreign rules and actual device/source
  authority are rechecked across every suspended control; revoked work cannot
  restore obsolete power or publish late READY/EXPIRED. Failure or dropped
  mutation waiters leave stop/DMA/peer ownership with the retained worker and
  existing reset supervisor; ambiguous completion retains resources.
  Explicit-ROC FRAME accepts unprotected nonfragmented Public Action only, with
  the actual local SA and requested ROC frequency/initiating-power receipt.
  Receive-only/NO_IR ROC cannot be upgraded into TX. It records the exact native
  DMA token before the first suspended publication and reports ACK only from
  its actual terminal; multicast never invents ACK. Legacy HTT MGMT_TX, HTT
  TX_FRM and TLV by-reference WMI retain their separate completion identities.
  Inline WMI, which proves only transport submission, refuses this TX facility.
  Actual TLV HTT>=3 with minor>=4 uses its peerid/frequency union; older firmware
  creates a separate WMI DEFAULT destination peer and waits for its MAP. An
  existing BSS peer is preserved. Ordered receive drains fence old records;
  actual TX terminal precedes temporary DELETE/UNMAP and advertised synchronous
  delete acknowledgement. A lost descriptor is never completed by scan expiry.
  An existing public ROC accepts FRAME duration0; it does not silently extend
  that separate interval to satisfy a new wait. FRAME may also acquire an
  independent private ROC when no explicit interval exists. Pure validation
  precedes native mutation. Its native dwell/max-scan
  budget is500ms; omitted wait selects10ms and an explicit wait must be10..500ms.
  The response tail starts at actual TX terminal and is clipped to the original
  finite native grant: neither ACK nor a timer extends RF authority. The separate
  DA peer remains owned through that tail. Only actual scan/home, TX and peer
  retirement plus the complete current home restore release the private result.
  No public READY/EXPIRED cookie is fabricated for this internal lease. Source
  loss, a dropped waiter or host closure closes capture first and retains exact
  native STOP/packet/peer cleanup; uncertain ownership remains pinned.
  Actual netdev REGISTER_FRAME installs at most16 source-bound Action prefixes,
  rejecting overlaps across sockets with EALREADY. Metadata alone emits no RF.
  The completed old HIF prefix is drained and the nonwrapping copy epoch closes
  before filter replacement. Only a live matching FOREIGN_CHANNEL grants raw
  capture: native WMI status/channel, unicast RA=own, nonfragmented unprotected
  Public Action, current prefix and actual physical/source owner must all match.
  The original raw bytes/frequency are retained; SNR is not relabelled as a dBm
  measurement. Serialization and dynamic source checks run after Radio unlock,
  followed by fresh policy/device checks and a final fixed original-source,
  receiver/origin and epoch fence immediately before delivery. Filter/source
  retirement, native expiry/home movement or callback-time policy change denies
  a retained copy without retargeting it. Multicast raw reception is refused:
  Linux's relevant profiles require an additional monitor-vdev/filter path, which
  is not advertised here. Robust SME/PMF injection and P2P device/client/GO roles
  remain separate capabilities. A 2.4GHz NO_CCK request still refuses without an
  actual restorable per-request native rate receipt;5GHz uses its native rate.
  The bounded managed-vdev `offchannel_scan` contract is source implemented.
  Ten new native cases cover six dialects, real delegated source/registration,
  actual FOREIGN/home receipts, Open/WPA2 DHCP/IP after DATA suspension, old/new
  HTT and WMI-reference terminal/peer ownership, multicast TX, timed/cancelled
  STOP holds, source/cap/daemon/policy loss, pure/inline/NO_IR refusals, implicit
  wait, actual WMI responses and callback-time filter/policy/source/expiry loss.
  Four shared cases cover exact IFINDEX/deferred status/registration and fixed
  Radio-kind prepared-event fences. All14 are written but unexecuted; no RF,
  timing or board qualification is claimed.
- RAW station images without firmware `NO_PS` expose an awake station
  power-save default and `WirelessNetIface::set_power_save`. The synchronous
  setter records desired intent; the retained async worker submits native
  station-PS controls only after association. Enabling programs RX wake,
  TX wake, PSPOLL, disabled U-APSD and 100 ms inactivity before PS mode;
  disabling submits mode off. MAIN, 10.1, 10.2, 10.2.4, 10.4 and TLV use
  their own native command identities and TLV layouts. The initial awake
  default or an explicit prejoin preference is submitted before carrier.
  Completion records command
  submission, without claiming a firmware sleep acknowledgement or RF/power
  measurement. A newer requested preference survives an older in-flight
  submission. Current channel/power and host closure are checked on every
  native command-future poll, including a coalesced no-op request. Failure
  or cancellation closes station admission and retains uncertain DMA;
  reinstalling policy or late receipts cannot reopen it. This profile
  enables neither U-APSD nor wake offload. Host-bus PM is the independent
  native MMIO/ASPM owner above and does not infer station RF-sleep authority.
- Physical packet HIF supplies bounded source-ready, begin-send and poll-now
  operations. Each source pipe retains its bounce occupancy/deadline before
  publication. An occupied source is rejected before any buffer copy; its CE
  terminal completion releases bounce capacity only. Independent RX/credit
  progress continues while CE4 is pending; actual HTT IDs still fence payload
  retirement and M4 commits. Async WMI/BMI transactions keep their original
  fail-stop cancellation semantics. Both packet service paths use the same
  HTC/HTT decoders and native peer correlation.
- The Device's synchronous drain uses try-locks, bounded poll/submit and Narf
  frame rings, and releases its Radio/ring state before stack callbacks. It
  never uses block_on and can complete the actual kernel DHCP conversation
  without a scheduled worker. The interrupt-driven service worker (or the
  1 ms poll without MSI) also supplies idle RX/security progress. A five-second no-peer deadline is refreshed by
  bound BSS beacons or admitted native peer traffic; stale/replayed/forged
  CCMP cannot refresh it. Expiry closes the port and carrier while retaining
  uncertain CE/HTT DMA. The owner deliberately does not reset/reclaim firmware,
  preserve connectivity across suspend, or admit a second association.
- `profile::Profile::select(device, version)` binds the PCI device ID and
  exact BMI target version to Linux's PCI firmware directory, board sizes,
  OTP parameters and clock operation. The Ubiquiti ID and QCA6164 have
  separate exact entries; SDIO tuples are excluded. QCA9887
  (`168c:0050`, BMI `4100016d`, `QCA9887/hw1.0`, 7168-byte board, 2116-byte
  calibration) is routed by `hw::HwRev::Qca9887`: Linux `pci.c::ath10k_pci_probe`
  gives `ATH10K_HW_QCA9887` the QCA988X register map, warm soft reset and
  target-address translation, and `core.c::ath10k_core_create` the
  `qca988x_regs`/`qcax_ce_regs`/`qca988x_values` family, so every QCA988X boot,
  CE, HTC/WMI/HTT and station path applies unchanged.
- QCA9887 alternate calibration (`eeprom::fetch`, `bmi::Transport::calibration_eeprom`)
  follows `core.c::ath10k_download_cal_data` → `ath10k_download_cal_eeprom` and
  `pci.c::{ath10k_pci_enable_eeprom,ath10k_pci_read_eeprom,ath10k_pci_validate_cal}`.
  After the board-ID OTP run and signed board lookup, the physical QCA9887
  transport (only, while still in BMI and under the current PCI capability)
  enables the SI clock (RTC SoC +0x28), muxes GPIO5/17 as I2C SDA/clock with
  pull-up, sets SI_CONFIG `0x000d00b8` and reads 2116 bytes one at a time
  (`0xa10000a0` select with address bytes, SI_CS `0x114`, DONE_INT poll bounded
  to 1 s with 20 us sleeps, write-one clear, DONE_ERR check, RX_DATA0 low byte).
  Only a complete image whose 16-bit LE XOR is 0xffff is downloaded to
  `hi_board_data` with `hi_board_data_initialized`, and the OTP calibration
  execution is then skipped (Linux's `done` path). A nonzero `hi_board_ext_data`
  (Linux `ath10k_push_board_ext_data` rejects the 2116-byte length), SI
  timeout/DONE_ERR or a bad checksum fall back to the board file plus OTP.
  An absent device or revoked authority fails the boot. Smokes
  `drivers/wireless/ath10k/eeprom` and
  `smoke_ath10k_qca9887_eeprom_calibration_replaces_board_data_and_skips_otp`
  cover the register sequence, fallbacks and non-QCA9887 isolation.
  DT/NVMEM sources precede the EEPROM (see below). The EEPROM bytes are factory
  calibration only; regulatory and transmit-power authority are unchanged.
- Exact PCI-function calibration files use Linux's
  `ath10k/pre-cal-pci-<domain:bus:device.function>.bin` then
  `ath10k/cal-pci-<domain:bus:device.function>.bin` lookup order. The address
  comes from the owned enumerated PCI function, not a caller's board hint.
  Both inputs require verified signatures even in executable-developer builds,
  exact per-silicon calibration length and complete advertised extension data.
  Pre-cal bytes reach host-interest memory before FLASH board-ID OTP (`0x8000`);
  the selected signed BDF then precedes FLASH_SECTION_ALL calibration (`0x10000`).
  A final cal file replaces the board payload and skips EEPROM/OTP calibration,
  while preserving the existing signed-board and extended-board lookup path.
  Missing optional files preserve EEPROM/board-plus-OTP fallback. A malformed
  or refused present file fails before firmware activation. The same immutable
  source owner retains the actual file capability through mission startup.
  Native file-selection/BMI and signed-registry execution gates are pending.
- Alternate DT/NVMEM calibration sources (`firmware::platform::Platform`,
  `firmware::calibration::select`) follow `core.c::ath10k_core_pre_cal_download`
  and `ath10k_download_cal_data`: pre-calibration NVMEM cell, pre-cal file,
  `qcom,pre-calibration-data` (legacy `qcom,ath10k-pre-calibration-data` only
  when absent); then the `calibration` cell, cal file, `qcom,calibration-data`
  (legacy `qcom,ath10k-calibration-data`); then QCA9887 EEPROM, then OTP.
  `Calibration::origin` records Linux's `cal_mode` source. The node is the PCI
  function's own (`drivers/pci/of.c::pci_set_of_node` via
  `narf_firmware_fdt::for_pci_function` on the boot DTB, `devfn_path` hops
  from the host bridge of the function's domain); without a DTB or node every
  source is absent. `ath10k_core_check_dt` reads `qcom,calibration-variant`
  (legacy `qcom,ath10k-calibration-variant`), truncated like `strscpy` to 31
  bytes, replacing the SMBIOS variant for board names. NVMEM cells resolve
  through `narf_firmware_fdt::rmem_cell` (`of_nvmem_cell_get`); the one
  in-tree provider is `drivers/nvmem/rmem.c` (`nvmem-rmem` reserved memory,
  fixed-layout cells), copied through a retained write-back mapping. Every
  source must be exactly `cal_data_len` bytes. DT/NVMEM bytes carry the boot
  Devicetree's platform-firmware authority, not a registry signature.
  Deliberate deviation: Linux falls through to the next source on any error
  except `-EPROBE_DEFER`; here a present source that is malformed, out of its
  region, bit-field, unreadable or behind an unregistered provider (MTD, I2C
  EEPROM, QFPROM, other layouts: Linux `-EPROBE_DEFER`) fails boot before
  PLL/BMI work, so broken factory data never selects another source. Smokes
  `smoke_ath10k_dt_nvmem_sources_follow_pci_function_node`,
  `smoke_ath10k_nvmem_cell_failures_are_terminal_sources`,
  `smoke_ath10k_calibration_source_precedence_matches_linux` and
  `smoke_ath10k_platform_nvmem_pre_cal_and_dt_cal_drive_native_bmi` (synthetic
  DTBs and BMI target) are written but unexecuted; no physical board or
  platform DTB is claimed.
- `firmware::Image::{parse, load}` own the API 2–6 container and expose
  bounded image/OTP/code-swap slices, feature bits and WMI/HTT operation
  versions. `Files` supplies owned immutable bytes and `Files::wait_missing`
  waits only at pure asset-lookup checkpoints; production uses
  capability-authorized verified firmware-registry blobs. The highest
  present API is parsed; a malformed present blob fails explicitly.
  `RegistryFiles::wait_authority`, `Image::wait_load` and `prepare`'s base and
  extended board lookups wait across staged registry population while preserving
  any already completed PLL and OTP BMI transactions on the live target.
- Production `RegistryFiles::load` invokes both registry lookup and bounded
  blob copying under the actual current capabilities; only owned vectors reach
  firmware/board parsers and BMI work. `board.bin` and `board-2.bin` always require
  a verified signer, including unsigned-executable developer builds. Executables
  retain the registry/build policy. Actual signed-registry tests exercise both
  board roles, developer executable behavior and registry epoch revocation before
  source access; no test profile installs calibration for deployment.
- `firmware_source::Source` retains the exact immutable executable/OTP-container
  and board records actually selected by that loader: owned original bytes,
  their blob capabilities, signer facts and registry digest, plus the exact
  registry and physical PCI capabilities. The historical registry `sha256` field
  stores BLAKE3; the source owner preserves that fact rather than renaming or
  recalculating a different identity. The bounded eight-record log seals only
  after image and board preparation, before mission startup; sealed assets/PCI
  authority cannot be replaced. BMI preparation invokes the current records as
  they become available. Mission startup requires the sealed owner. The real
  PciBoot path has no missing-source fallback, including kernel-test builds;
  only private protocol models can omit external firmware inputs.
  Repeated identical signed-container staging lookups retain the original name,
  bytes, signer and capability rather than exhausting that eight-record log;
  a fresh registry open cannot replace a revoked original epoch.
  Native MMIO read/write closures, every HIF send/receive/progress future poll,
  RSNA processing and terminal key-reply commitment, netdev registration,
  carrier, receive IPC and final stack publication use these retained current
  capabilities. Source invocation snapshots a fixed array of immutable record
  references and drops the loader lock before invoking the operation; no owner,
  ring, loader or publication lock is held through a stack callback that may
  reenter ARP/ND transmit. Revocation fails the old owner; reopening the same
  canonical registry names cannot relabel it. It retains ambiguous DMA rather
  than inventing cancellation/stop proof. Direct PCI station prepare, management,
  association, data and protection operations also resample the actual current
  occupied-power policy and session quarantine around native waits. These are
  current host authority checks, not physical RF shutdown or firmware-internal
  code/key erasure claims.
- `hw::HwRev::registers()` returns the correct per-family windows;
  `Registers::ce_base(pipe)` rejects an out-of-range CE index. The RTC
  chip-ID helper now returns the complete BAR-relative address.
- `ce::RingConfig` includes `hw_rev`. Sizes are **entry counts**, not byte
  counts; source DMAX and byte-swap controls preserve unrelated bits.
  `host_int_disabled` controls `HOST_IE`, never destination byte swap.
  `halt_pipe(mmio, hw_rev, pipe)` requests CMD bit 0 and waits for bit 3
  in the same command register using a bounded responsive wait.
- `ce::Ath10kMmio::authorized()` checks current publication authority.
  The native implementation retains its PCI capability and performs each
  bounded register access inside `Cap::invoke`; revoked reads return all
  ones and revoked writes never reach the BAR. Ring, BMI, diagnostic,
  HIF and host-memory entry points reject revoked authority before new
  descriptor or bounce publication. Revocation does not retire pending DMA.

The internal `boot::PciBoot` owns PCI authority, four coherent CE rings
(CE0 source, CE1 destination, CE7 source/destination), and request,
response and diagnostic bounce allocations. It performs Linux's reset
sequencing, CE7 host-interest/early-allocation/service-map setup, and the
target CPU interrupt before BMI. QCA988X uses the preferred warm-reset
route; it does not automatically cold-reset boards Linux documents can
hang on that path. An inherited nonempty CE fails rather than being
repointed to new host memory.
BAR admission covers every CE window that the selected chip can use,
including CE8 on twelve-CE parts. A revoked capability cannot authorize
the halt/BME readback proof needed to free published storage; Drop retains
those allocations.

Internal `bmi::Bmi` provides target information, chunked memory read/write,
SoC register read/write, execute, zero-padded compressed download and the
one-way BMI_DONE handoff. The live boot task waits for firmware registry
publication, derives board names from the actual PCI/subsystem/OTP identity
and bounded SMBIOS variant, selects board-2 data or explicit legacy board
data, writes host-interest configuration, downloads BDF/extended BDF,
runs OTP and downloads firmware. QCA6174 HW3.2/QCA9377 HW1.1 execute Linux's
ordered PLL setup with bounded asynchronous settle waits. Code-swap TLVs
are checked, copied into retained DMA32 storage and advertised through the
208-byte segment record before image upload. An async mutex retains the
BMI or runtime transport, selected profile and image, including failed
handoffs. The physical `Transport::prepare_done` refuses activation until
all runtime allocations and RX postings are retained; `done_complete`
opens HIF only after terminal CE0 completion. No station admission follows
merely from successful HTC negotiation.

Runtime storage retains Linux host CE2 RX128×2048, CE3 TX32×2048,
CE4 TX8192×256, CE5 RX512×512, plus CE8 RX128×2048 on 12-CE parts.
QCA6174/QCA9377 disable host CE5 and carry HTT receive through CE1.
The original CE0/CE1 allocations are preserved through ROM handoff;
CE1 and runtime RX pipes have one posted bounded buffer per pipe before
DONE, with serialized polling and terminal-completion refill. This is
control-path capacity, not a full runtime packet pool or IRQ service.

`control::Session` owns HTC endpoint and credit state. The production
path receives READY, connects HTT 0x300 with credit flow disabled and WMI 0x100
with the advertised credit allocation, then sends Linux's 12-byte
SETUP_COMPLETE_EX body without RX bundling. Endpoint IDs are checked for
duplicates and family pipe binding. Early WMI events are retained through
the connect response race. WMI sends progress credit trailers while waiting
for enough credits, preserve endpoint TX sequence, and use CE3. Malformed
frames, failed transfers, timeout or dropped in-flight waits close the
session until a future owned reset; no ambiguous control operation retries.

`wmi_boot::Runtime` owns the resulting HTC session through service-ready,
host-memory retention, native INIT and READY. It selects MAIN, 10.1, 10.2,
10.2.4, TLV or 10.4 from the parsed image's WMI operation version. Native
service-ready layouts expose regulatory/RF/PHY capabilities; TLV validates
the service-ready ABI namespace and bounded nested memory-request arrays.
The four-low-bits-per-word service bitmap and dialect-specific extensions
follow Linux's service mapping. Resource requests use the corresponding
120/108/136/176/168-byte layouts; 10.4 peer caching and firmware PFC affect
peer/active-peer/TID/MSDU counts. Optional bundled-management/TX-ACK-RSSI
host capabilities remain unadvertised in this initial station profile.

The physical `HostMemory::retain_wmi_memory` adapter aligns each requested
unit to four bytes, derives units from the same requested vdev/peer/active
peer counts, checks multiplication, zeroes coherent DMA32 storage, and
retains it in the transport before returning addresses for INIT. It handles
at most 16 unique requests; a zero-unit request needs no chunk. Memory is
one-shot, and cancelled or failed initialization cannot repeat allocation
or INIT. Early HTT messages remain retained for the next HTT stage.

The production PCI owner then enters `htt_runtime::Runtime`: HTC carries
the four-byte version request, accepts target major 2 or 3, retains the
2048-entry DMA32 RX-address ring with 1023 posted 2048-byte buffers, and
sends the native 40-byte RX-ring command. All matched PCI profiles use the
300-byte `htt_rx_desc_v1`, including wave2 parts. Continuous-fragment profiles
retain 64-byte descriptors for the same pending-TX ceiling used by WMI;
PFC images also retain the 4772-byte queue-state layout before its address
is advertised. The fragment-bank command precedes RX-ring/aggregation setup.

HTT event progress is idle-safe, distinct from a timed-out protocol request.
TX payload/fragment owners survive CE completion and retire only after a
validated terminal HTT indication; a batch validates every ID and completion
kind before releasing any allocation. Target major 2 uses the separate
56-byte management command and management completion. Native legacy RX
validates MSDU_DONE, copies complete A-MSDUs/chains, then reposts the retained
buffers. TLV full-reorder PADDR events select exact live DMA owners, validate
the entire pointer batch before repost, and preserve the separate seven-byte
offload metadata. Raw RX metadata does not authorize a peer or controlled port.
Current-authority checks precede DMA reads and producer republication.
Cancelled setup/TX/progress and malformed completion state fail closed.

The native `wmi_runtime::Radio` retains HTT while creating station vdev0 and
programming receive-only channels. MAIN, 10.1, 10.2, 10.2.4, TLV and 10.4 use
separate Linux command/event mappings; MAIN/10.4 scans include the burst
word, 10.x omits it, and TLV uses its 100-byte common command plus native
arrays and the inverted FILTER_PROBE_REQ flag. Management RX selects the
24-byte legacy, 40-byte extended, 28-byte 10.4 or tagged TLV header, checks
all advertised extents and optional timestamp tails, and validates beacon
identity/IE/channel data before caching. Passive scan continues HTT terminal
completion processing and retains unrelated events for the later station
worker. It never opens a controlled port, enables carrier or installs keys.

The station-context composition uses dialect-specific native PDEV regulatory,
power, vdev-start and peer-create layouts, including TLV pdev IDs. Firmware
peer IDs are bounded by the 2048-entry descriptor namespace rather than the
resource peer count; multiple IDs for one BSSID remain owned until individual
UNMAPs. The retained station progress path rejects an owned ID rebound to a
different MAC/vdev. No MAP itself authenticates a peer or controlled port.
Native Rust tests evaluate all 65,536 EEPROM values against fixed source-cited
reference data and check WMI wire-layout vectors for all six supported dialects. Composed tests traverse actual scan/cache, host
policy, START status and HTT MAP/UNMAP; they cover cancellation after START
publication, failed status, malformed/out-of-range map and retained DMA.

Management TX follows Linux's actual dispatch. Firmware feature
`HAS_WMI_MGMT_TX` or raw TLV service 76 chooses WMI; `MGMT_TX_BY_REF` then
chooses the TLV referenced command. Legacy MAIN/10.x/10.4 use the native
inline command. Without WMI management, target-major 2 uses the separate
56-byte HTT management message and major 3 uses the normal HTT descriptor.
Incompatible feature/dialect combinations remain unsupported before any
payload allocation. The native mission owner retains each referenced-WMI
payload before the command exposes its DMA address; a CE receipt never frees
it. A complete matching WMI terminal event retires it. Single and bundled
completion parsers handle repeated array tags, preserve the distinct status
array, and validate the whole ID batch before freeing any payload. Descriptor
IDs increase across slot reuse, so a late duplicate cannot free a new packet.
Current authority is rechecked before preparation, publication and retirement;
revocation/cancellation preserve the existing stop-protected DMA lifetime.
Fixed source-cited Rust management vectors include padding and the 64-byte
reference prefix. No compiler wrapper or source harvesting runs in validation.
Composed runtime fixtures traverse
scan/policy/START/MAP, all management dispatch choices, command credit receipts,
terminal completion and native auth/association responses. They cover wrong
recipients, changed policy, partial/duplicate terminal batches, invalid IDs,
and cancellation after actual command publication and during response wait.
Initial response, START-response and peer-map waits yield on every event
iteration, including discarded management frames or wrong-vdev STARTs; a
continuous event flood cannot monopolize one executor poll. Dropping those
waits leaves the radio closed and DMA retained until the existing stop proof
permits release.

The checked association path uses the shared secret-free JoinPlan for
Open/WPA2-PSK legacy management and translates only validated rates, AID and
capabilities into each native PEER_ASSOC/VDEV_UP layout. Forty-five retained
source-cited literal management/association fixtures include
single-rate 11B/11G, an eleven-rate response downgrade and TLV padding. The
historical provenance records native source SHA-256; it is not an active
source-equivalence proof. Native Rust expectations are independently reviewed.
Retained composition fixtures exercise actual CE3 source descriptor publication and
completion, CE2/CE1/CE5 destination completion/copy/repost, HTC framing and
credits, WMI commands and terminal referenced-management retirement. They
cover cancellation after native PEER_ASSOC/VDEV_UP descriptor publication,
send errors, invalid AP capability, queued peer loss, stale remap, and a
post-UP credit-only flood. AP association does not open a controlled port.

Twenty-one fixed Rust fixtures retain VDEV_DOWN, PEER_DELETE and VDEV_STOP
wire layouts, STOPPED/delete-response events, enum IDs, TLV tags and the
synchronous-delete service bit. Native CE/HTC/WMI/
HTT composition checks all six dialects, ACK/UNMAP ordering and sparse/in-flight
IDs, wrong/malformed/missing receipts, stale prerequest events, duplicate UNMAP,
owned-ID rebinding and late MAP, native command errors/cancellation and bounded
progress floods. Original ring/firmware allocations remain retained in every
case, including success. These fixtures establish the terminal teardown
contract without radio or whole-device reset acceptance.

Physical carrier/peer publication does not change operator `IFF_UP` and never
invokes administrative open/stop hooks while retained driver state is locked.
Explicit registration, operator up/down and autoconnect remain administrative
events. Disconnect/failure clears carrier and peer identity while preserving an
operator-UP interface; a later physical carrier sample cannot undo operator DOWN.

### 3.1 Explicit indoor installation policy

Admitted station profiles can use an indoor-only host rule only when the
current trusted deployment policy also carries `DEPLOYMENT_INDOOR`. Every
overlapping indoor-only rule needs that fact; factory identity, full occupied
span, original power ceiling, DFS/NO_IR and other restrictions remain active.
The same permission checks cover native probes, association, terminal peer
admission and packet/copy/control progress. Removing the fact while retaining
the indoor-only restriction closes old admission; restoring it cannot revive
a terminal old radio. See [the exact policy and native contract](ath10k-indoor-regulatory.md).
Source and native cases are written; coordinated release/native acceptance
remains pending. This adds no country inference or generic nl80211 indoor hint.

### 3.2 Native Beacon hints for the factory World layer

The existing configured non-DFS 5 GHz centers can leave the immutable factory
World `NO_IR` layer only after this physical radio receives an actual ESS
Beacon during its original requested scan's matching STARTED and
FOREIGN_CHANNEL dwell. The decoded WMI requestor, scan, vdev and channel must
match; the frame must have Beacon subtype, broadcast receiver, nonzero
interval and coherent BSSID/DS/HT channel fields. Probe responses, public BSS
records, unrelated dwell events, Country IEs and host policy alone grant
nothing. Radar/DFS frequencies are never promoted. This follows Linux7.2
`ath/regd.c::ath_reg_apply_beaconing_flags` and cfg80211
`reg.c::handle_reg_beacon`, with the stricter native Beacon-only source rule.

Eligible factory identities are the resolver's World pairs 0x60..0x6c,
including Linux's conservative 0x64 fallback for 0x6b and the existing roaming
bit/sanitization rules. Fixed-country behavior is unchanged. The profile
does not add channels 12–14, DFS, 6 GHz or new SERVICE_READY inventory. Hints
are frequency facts, not BSSID credentials or inferred country authority.
Every 20 MHz constituent needs its own native observation before 40/80/80+80
admission; a primary Beacon cannot lend an unobserved occupied span.

`Permission` is cloneable rather than Copy and retains a private immutable
receipt for exactly its occupied frequencies, original radio life and
original installed authenticated-policy Arc. Checks use that retained
receipt through native waits, active probes, station/key/DATA progress,
off-channel control and final copied-frame delivery. New Beacons can admit
new plans without widening an old receipt. Policy removal or replacement,
including equal rule bytes or remove/restore, permanently invalidates old
receipts; a replacement radio needs fresh observations. Test-only providers
use an explicit stable `reg::db::Database` snapshot, matching the production
installed-policy generation instead of manufacturing Arcs per query.

The receipt lifts only the factory World restriction. Every current signed
host NO_IR/DFS/unknown flag, paired indoor installation fact, overlapping
bandwidth/power limit and existing factory/hardware limit still applies.
The firmware receives its real factory pair/CTL plus host power ceiling;
neither a country nor a firmware/RF receipt is invented. Two ownership/parser
cases and four native CE/HTT/Open/WPA2/DHCP/IP, false-observation, host/span
and policy-wait/copied-DATA cases are written; coordinated release/native
validation and actual-device qualification remain pending.

### 3.3 Native legacy AP and userspace authenticator

The family AP owner uses a distinct native vdev role, not a station alias.
Admission requires the actual TLV dialect, negotiated HTT3 major3 or later,
RAW/nohwcrypt, nonblocking retained CE transport, non-PFC/non-continuous
storage, beacon-offload service0, synchronous-delete service92 and completed
INIT/READY resources for at least one vdev and nine peers. The admitted
profile is one legacy20 AP with at most eight clients, Open or WPA2 CCMP
(AKM1/2/6), on the existing current factory/host-permitted inventory. The
original signed policy Arc, including the paired indoor limits and any
original native World Beacon receipt, remains bound to the AP. Equal-valued
policy replacement cannot revive its old native or copied work.

`SET_INTERFACE` selects STA2 or AP3 only while administratively down and
without a station, scan, ROC, AP or admitted control owner. The nonwrapping
mode generation binds both shared Radio and AP controls; existing station
and ROC paths refuse AP mode. PFC AP, continuous RX, GO/CLIENT, HT/VHT/HE/EHT
APs, SAE/PMF/IGTK/BIGTK, DFS/CAC, CSA, ERP protection, extra virtual vdevs and
optional discovery roles remain unadvertised or explicitly refused. A real
AP may still bridge ordinary external Ethernet source addresses; it does
not turn those addresses into native peer or key identities.

START drains the original completed native prefix, deletes the inactive STA
vdev with its actual response, creates AP vdev0, obtains its DEFAULT self
peer MAP, programs current factory/power, legacy width/NSS/basic management
and multicast rates, disables intra-BSS firmware forwarding, and programs
actual WMM when present. On a 2.4 GHz OFDM BSS, non-ERP clients are refused
before native peer/port/PN/DMA mutation because their mandatory ERP/CTS
protection is outside this profile; pure11b and genuine ERP/5GHz peers keep
their source-backed admission. A short-slot/preamble beacon likewise refuses
clients lacking those advertised facts rather than silently missing a
required protection transition. It requires the matching START response, copied
firmware-owned BCN_TMPL/PRB_TMPL, AP UP with AID0, an ordered ECHO barrier and
actual beacon-offload TX status before carrier. Beacon/DTIM/SSID, rate,
security, optional-probe and complete-IE validation precedes RF transitions.
The firmware owns TIM/DTIM bitmap/count updates and AP power-save buffering;
there is no invented per-beacon DMA completion. ECHO proves command
processing, never beacon air ACK or DATA/key installation. Live template
replacement closes the old native/copy epoch before publication.

NEW/SET/DEL_STATION retains exact peer MAC/AID, original control source,
actual sparse HTT peer IDs and separate associated/authorized state.
PEER_ASSOC and ordered ECHO are not fabricated firmware peer-association
confirmation layouts. Source-backed AP U-APSD is advertised only with actual
service6: WMM admission and per-client queue/max-SP validation precede native
AP_PS_PEER UAPSD delivery/trigger bits, MAX_SP and ten-second AGEOUT. WMM
VO/VI/BK/BE bits map to actual native AC3/2/1/0. The current ordinary egress
maps Ethernet traffic to best effort; no host priority or no-ACK feature is
invented. Packet handoff first consumes a genuine bounded native Idle prefix;
queued loss beyond one drain budget defers without spending PN/native IDs.
MAP, START, STOPPED and delete response windows open only after the actual
synchronous CE handoff, not while waiting for command credit. Station dumps
report actual mapped/associated presence and leave unmeasured statistics
absent.

Keys use the admitted real software CCMP owner because RAW/nohwcrypt disables
firmware key offload. Pre-START group NEW_KEY/default ACKs are zeroizing
software metadata under their original source/role, without installed key,
PN, port or RF authority. START promotes them only after real AP/self-peer
receipts and native DATA quiescence; a stale source is erased, not
recaptured. Pairwise/group keys install or replace only after every original
published packet has its real air terminal. Per-key receive PN commits only
after physical ToDS peer/descriptor, MIC, complete LLC/control-port and port
validation. Transmit uses physical FromDS addresses and actual retained
nonwrapping 48-bit PN owners. Exact current-key retries preserve counters;
a bounded history rejects retired/cross-peer/cross-role reuse of the same TK
within this retained Radio. History exhaustion fails closed. Recovery does
not replay credentials or claim continuity of old key counters.

The typed native AP API implements start/stop/beacon, peer controls, key
add/delete/default, installed transmit-sequence-only GET_KEY, control-port
TX/RX, management registration/FRAME and native Ethernet rings. GET_KEY
returns only the installed CCMP cipher and real allocated six-byte TX PN,
including consumed unsent PNs; it exports no key bytes or RX replay counter.
The userspace SME owns Open authentication/association and real EAPOL/RSN
handshakes. Configured EAPOL can reach that exact source before DATA opens;
ordinary preauthentication still requires current DATA authorization.

Every request captures shared callback-free emission guards and watches one
stable physical pump waker outside Radio. Native awaits use only those
original guards, signed snapshot, role and physical source capabilities.
After all arbitrary event/source callbacks, publication re-invokes the
original physical sources and checks native/copy, peer, key, DATA and source
proofs before fixed typed event delivery or either Ethernet endpoint.
Known-peer management copies retain that peer's post-event denial/native
fence: genuine loss management can deliver immediately, while delete/re-add
or later authorization cannot rebind an old copy. Management remains
independent of DATA authorization.

Actual HTT and by-reference WMI management terminals alone release packet
IDs and supply ACK status; CE credits and ECHO do neither. Multicast success
does not invent an ACK. Cancellation/source loss closes host copies first
and retains the same vdev, peers, keys and uncertain DMA for the physical
worker. Teardown requires DOWN, all original packet terminals, peer
UNMAP/synchronous-delete responses, STOPPED and vdev delete, then recreates
the inactive STA inventory with its actual original VDEV NSS and explicit
DCF queue programming. A subsequent non-WMM station selects fresh defaults
for its real band/rates; old AP EDCA cannot silently leak into it. The
production-used cleanup step keeps the physical worker alive after proven
AP cleanup, and closes ordinary terminal station/scan paths as before.
Only proven cleanup permits a fresh control
generation on the same current physical device; missing receipts retain DMA
for existing PCI reset/quarantine. No abandoned endpoint or old copied
packet becomes a replacement BSS.

Primary command/event/rate/descriptor sources are the local Linux7.3-rc4
`ath10k/{mac.c,wmi.c,wmi.h,wmi-tlv.c,wmi-tlv.h,htt_tx.c,htt_rx.c,htt.h,hw.h,
rx_desc.h}`. The earlier pinned7.2 files remain separately recorded where
identical. Ten independent native cases are written for actual CE/HTT/AP
start/peer/teardown, TIM/DTIM/templates, staging and PN continuity, terminal
hold/cancel, known-peer copy replacement, long queued-loss prefixes,
prepublication MAP and malformed-message denial, source/policy retirement,
real AES-CCMP port/MIC/replay and copied-data fences, U-APSD native words and
userspace M1–M4 with real MIC/AES wrap before native keys/port/DATA.
Compilation, native execution and actual firmware/board/RF interoperability
acceptance are pending; these cases are not physical evidence.

### 3.4 Station hardware key offload (RAW + `cryptmode=0`)

`Radio::with_hardware_keys(true)` (selected by the PCI radio, as Linux's
default `cryptmode=0` beside `rawmode=1`) keeps `station_security::Security`
as the sole RSNA/PN/replay owner, built `with_hardware_keys`, and layers
firmware key offload over the unchanged software path
(`wmi_runtime/hw_keys.rs`, `wmi_runtime/data.rs`). The earlier plan to move
ath10k onto a bare `eapol::Supplicant` (ath11k `mac/sec.rs`) was not taken:
the retained owner already carries the M4/group-reply commit fence, key-reuse
history, A-MSDU/SPP and SAE/PMF state the RAW path depends on, so the shared
crate gained only an opt-in offload surface (`wireless/` spec §3).

- **Install.** Each PTK/GTK whose material changes at a reply's terminal
  delivery (PTK before GTK; an identical re-delivery installs nothing, as
  wpa_supplicant "do not reinstall") is queued and programmed one at a time
  from the async data step with `WMI_VDEV_INSTALL_KEY` (mac.c
  `ath10k_send_key`/`ath10k_install_key`): vdev 0, BSSID as peer for both,
  `key_idx`, `WMI_KEY_PAIRWISE` (0) or `WMI_KEY_GROUP` (1),
  `WMI_CIPHER_AES_CCM` (4), zero RSC/TSC (the host keeps PN/replay), 16-octet
  key. Main/10.x/10.4 use the packed `wmi_vdev_install_key_cmd` (IDs
  0x5009/0x901b/0x901a/0x901d, wmi.c `ath10k_wmi_op_gen_vdev_install_key`);
  TLV wraps the same struct in tag 96 plus an ARRAY_BYTE key TLV (0x5009,
  wmi-tlv.c `ath10k_wmi_tlv_op_gen_vdev_install_key`). Completion is the HTT
  `SEC_IND` (0xb, htt_rx.c `install_key_done`) naming an owned peer, AES-CCMP
  and the matching unicast/group kind. Only then does `Security::key_installed`
  admit that slot; no indication within Linux's 3 s leaves the slot
  software-only (mac80211 keeps a key in software when `drv_set_key` fails),
  and a late/foreign indication confirms nothing. A newer commit returns a
  slot to pending, so a frame the firmware decrypted under a stale key is
  dropped rather than checked against the fresh key's replay window. Firmware
  key state is dropped with the peer at teardown.
- **TX.** While the current PTK is confirmed, Ethernet DATA uses the
  header-only form (mac80211 `IEEE80211_KEY_FLAG_GENERATE_IV`: Protected
  header, CCMP header with a PN from the shared counter, plaintext) plus the
  8-octet MIC tail htt_tx.c reserves for RAW protected frames, sent without
  `NO_ENCRYPT`. Otherwise, and for every EAPOL reply, the software CCMP form
  with `NO_ENCRYPT` is used (`ATH10K_SKB_F_NO_HWCRYPT`); PN order is one
  counter either way.
- **RX.** With hardware keys an original MPDU the firmware reports as
  AES-CCM (enctype 6) with status OK and no FCS/decrypt/peer-index error is
  `is_decrypted` (htt_rx.c `ath10k_htt_rx_h_mpdu`); `raw_frame` removes the
  FCS and MIC and keeps Protected plus the CCMP header
  (`ath10k_htt_rx_h_undecap_raw`, `fill_crypt_header`), and the shared owner
  applies only the PN check against the same per-key/TID window software
  CCMP uses (`receive_decrypted_with_nonce`, `receive_amsdu_decrypted_with`).
  Frames the firmware could not decrypt keep the existing software path.
- **Management.** PEER_ASSOC sets `peer_flags->pmf` for a PMF association on
  `ATH10K_FW_FEATURE_MFP_SUPPORT` firmware (0x10000000 main/10.2/10.4,
  0x08000000 TLV; 10.1 has no map entry and keeps all management crypto in
  software). On such a peer, once the PTK is confirmed, protected unicast
  deauth/disassoc/action from WMI management RX are firmware-decrypted
  (Protected, CCMP header and MIC kept, `ath10k_wmi_rx_is_decrypted`): the MIC
  is trimmed and only the management PN counter is checked
  (`receive_management_decrypted`); SA Query responses and the PMF
  deauthentication use the header-only management form plus MIC space
  (`GENERATE_IV_MGMT`, wmi.c `ath10k_wmi_op_gen_mgmt_tx`). IGTK/BIP is never
  programmed: Linux `ath10k_set_key` returns 1 (software) for every BIP
  suite, so group robust management stays software BIP-CMAC-128.
- Not offloaded: TKIP/WEP/GCMP (not admitted by the station profile), MLD
  owners, AP-side keys (§3.3 keeps its software owner) and fragments.

Native cases (written, unexecuted): `smoke_ath10k_hw_keys_install_struct_dialects`,
`smoke_ath10k_hw_keys_install_tlv`, `smoke_ath10k_hw_keys_peer_pmf_flag_map`,
`smoke_ath10k_hw_keys_security_indication` (ath10k) and
`smoke_station_ccmp_offload_header_only_shares_tx_pn`,
`smoke_station_ccmp_offload_decrypted_receive_keeps_replay`,
`smoke_station_ccmp_offload_management_uses_management_counter` (shared
crate). The composed RAW data tests construct the software profile; the
production default is covered by the composed conversation
`smoke_ath10k_hw_keys_composed_install_data_rekey_and_pmf`
(`wmi_boot/hw_keys_conversation_tests.rs`, main, 10.2 and TLV over the
actual CE/HTT/WMI/netdev path with MFP firmware and a WPA2-PMF FakeAp). Its
model firmware (`data_tests.rs` `HwKeyCache`) holds only what
`WMI_VDEV_INSTALL_KEY` programmed, validates the packed/TLV command from
wmi.h, answers with `SEC_IND`, encrypts header-only RAW TX and PMF
management at the host PN, and decrypts RAW RX and PMF unicast management
with its keys; the FakeAp still opens every uplink with its own PTK and
replay counter. Covered: PTK then GTK install (IGTK not programmed), TX
through the firmware, a firmware-decrypted downlink admitted then its replay
dropped, a firmware-decrypted SA Query answered header-only, a group rekey
of slot 2 whose second install is held (a frame the firmware decrypts under
the stale GTK is dropped, an undecrypted frame under the new GTK takes the
software path, the released `SEC_IND` re-admits decrypted traffic), and a
replayed then fresh firmware-decrypted protected deauthentication.
Coordinated release compilation, native execution and physical
firmware/board acceptance are pending; no physical key-cache behaviour is
claimed.

### 3.5 DFS

**Station client on radar channels (step 1).** The passive hardware
inventory already lists ch52–64 and ch100–144 as `WMI_CHAN_FLAG_PASSIVE` rows
and `receive_permission` admits host DFS rules for receive-only scans. The
station inventory (`Permission::station_frequency` = non-DFS profile plus
`Permission::dfs_frequency`) now exposes those channels to the interface
scan/associate/band surface; AP (`ap_wire`), off-channel and active-probe
paths keep `profile_frequency` and an ordinary `Owner::receipt`, which never
carries radar, so none of them can transmit first on a radar channel. An
explicit active scan naming a radar channel is refused; the implicit active
scan drops it (Linux mac80211 would probe passively there — discovery here
is the passive scan).

`beacon_hints::Owner` records cfg80211 `beacon_found` for a host-DFS 20 MHz
channel from the same native Beacon-in-matching-dwell source as §3.2, for
every factory SKU (World or fixed country). A new scan whose channel list
covers a radar channel retracts that channel's witness until it is heard
again ("heard in the current scan"). The witness set, its scan generations,
retraction and the RADAR classification are the shared driver-neutral
`narf_wireless::reg::witness::{BeaconWitness, is_radar}` (wireless spec §3.5
"Station passive-channel witness"), bound to the hint window's policy
snapshot; ath10k still records only its `Permission::dfs_frequency`
inventory and keeps its own mask-based `Receipt`. Only `Owner::client_receipt`, consumed
solely by `station_profile`, carries the radar mask; it also satisfies the
World NO_IR layer on those channels because cfg80211 `reg.c::handle_reg_beacon`
clears NO_IR without a RADAR test. `Permission::from_factory_width_with_hint`
admits an overlapping host rule flagged `DFS` (optionally with `NO_IR`) only
when every occupied constituent under a DFS rule has that witness
(`Receipt::permits_radar`), and retains the narrowed receipt so a policy
generation change or radio retirement closes the permission (`check`).
`NO_IR` without `DFS`, unknown flags, indoor and power/bandwidth limits stay
as before. HT40 pairs (ch52/56 … ch140/144) and VHT80 segments (centres 5290,
5530, 5610, 5690) follow; 80+80 remains bounded to the non-DFS centres 5210 /
5775, and contiguous VHT160 (centres 5250 / 5570) admits its radar half under
the same per-constituent witness (§3 contiguous VHT160). `Permission::radar` names the radar constituents; their station
channel-list rows (`station_ht40_channels`, the associated-scan home row) are
`PASSIVE | DFS` exactly as Linux `mac.c::ath10k_update_channel_list`
(`ch->passive |= ch->chan_radar`). A station VDEV_START carries no DFS flag
(Linux sets `chan_radar` only for `WMI_VDEV_TYPE_AP` in
`ath10k_vdev_start_restart`). A STA performs no radar detection in Linux;
neither does this one. Test (written, unexecuted):
`smoke_ath10k_dfs_client_needs_radar_beacon_in_current_scan`.

**AP radar detection, CAC/NOP and radar-triggered CSA are gated out of
upstream ath10k (steps 2–6 inapplicable).** Every ath10k path that would let
this device *initiate* radiation on a radar channel is compiled only under
`CONFIG_ATH10K_DFS_CERTIFIED` (`ath10k/Kconfig`: "DFS support for certified
platforms", `depends on ATH10K && CFG80211_CERTIFICATION_ONUS`, `default n`;
`CFG80211_CERTIFICATION_ONUS` itself `depends on EXPERT`, `default n`):

- `mac.c` iface combinations set `radar_detect_widths` only inside
  `#ifdef CONFIG_ATH10K_DFS_CERTIFIED`. Without it mac80211
  `chan.c::ieee80211_link_use_channel` (radar_detect_width =
  BIT(width) when `cfg80211_chandef_dfs_required`) fails
  `ieee80211_check_combinations`, nl80211 START_RADAR_DETECTION (CAC) has no
  admissible combination, and `chan.c::_cfg80211_reg_can_beacon` refuses
  START_AP until `cfg80211_chandef_dfs_available` — which only a finished
  CAC can make true. An uncertified Linux ath10k AP therefore never beacons
  on a radar channel, exactly as this AP (`ap_wire` keeps
  `profile_frequency`, AP receipts never carry radar) already refuses.
- `mac.c::ath10k_mac_register` creates `ar->dfs_detector` only when
  `IS_ENABLED(CONFIG_ATH10K_DFS_CERTIFIED)`, and
  `ath/dfs_pattern_detector.c::dfs_pattern_detector_init` additionally
  returns NULL without `CONFIG_CFG80211_CERTIFICATION_ONUS`; the FCC/ETSI/JP
  `radar_types` tables and `dfs_pri_detector.c` are unreachable otherwise.
- `wmi.c::ath10k_wmi_event_dfs` returns early on `!IS_ENABLED(
  CONFIG_ATH10K_DFS_CERTIFIED)` and again on `!ar->dfs_detector`, so
  `PHY_ERROR_RADAR` pulses are never decoded into `pulse_event`s and
  `ieee80211_radar_detected` is never called; mac80211
  `util.c::ieee80211_dfs_radar_detected_work` (CSA or stop) is unreachable.
- `mac.c::ath10k_regd_update` passes a DFS region to PDEV_SET_REGDOMAIN only
  under the same gate (else `WMI_UNINIT_DFS_DOMAIN`), and no ath10k code
  sends `pdev_dfs_enable_cmdid`/`pdev_dfs_disable_cmdid` at all — those
  command IDs exist only in the per-dialect tables.

`CFG80211_CERTIFICATION_ONUS` exists for an integrator who certifies the
final system; NARF can never claim physical DFS certification, so it builds
the upstream default configuration and implements no radar detector, CAC
timer owner or radar CSA for ath10k. The station client (above) is the
whole of upstream's default ath10k DFS behaviour. A shared cfg80211-style
DFS channel-state machine (USABLE/UNAVAILABLE/AVAILABLE, CAC, NOP) belongs to
`narf_wireless::reg` when a driver whose upstream enables radar detection by
default needs it; it is not an ath10k obligation.

### 3.6 Station WoWLAN (implementation; validation pending)

**Admission (`wow.c::ath10k_wow_init`).** Only `wmi-tlv.c` implements the
`gen_wow_*` WMI ops, so MAIN/10.x/10.4 images never advertise WoWLAN.
`wmi_runtime/wow.rs::Radio::wowlan_support` requires the TLV dialect,
firmware feature `ATH10K_FW_FEATURE_WOWLAN_SUPPORT` (bit 6), TLV service
`WMI_TLV_SERVICE_WOW` (13, Linux's 4-bits-per-word service map) and the
retained station data owner. Of the installed images only QCA6174 hw3.0
firmware-4/-6, QCA9377 firmware-6 and WCN3990 carry bit 6, and none of them
carries `RAW_MODE_SUPPORT` (bit 10); those PCI images (QCA6174/QCA9377) now
run the station in native-WiFi decap (§3.7), which is the data owner that
makes WoWLAN reachable there, with native-WiFi patterns. WCN3990 is SNOC, not
a NARF PCI profile. The interface advertises disconnect and magic packet
(`ath10k_wowlan_support`); GTK rekey/failure, EAP/4-way triggers and
net-detect are not advertised and `set_wowlan` re-validates every
configuration (`-EOPNOTSUPP` without support, `-EINVAL` otherwise).
Patterns: under native-WiFi decap Linux reduces length/offset by
`WOW_MAX_REDUCE` (134/114, 22 slots = INIT `num_wow_filters`) and converts
802.3 offsets (`ath10k_wow_convert_8023_to_80211`); `wow::Program`
implements both. Under the RAW decap of every NARF station,
`ath10k_vif_wow_set_wakeups` never copies the cfg80211 pattern into its
zero-initialised `new_pattern` and programs zero-length patterns, so NARF
advertises zero patterns there instead of that no-op. `WMI_SERVICE_NLO`
net-detect is implemented (`ath10k_wmi_tlv_op_gen_config_pno_start`):
the TLV NLO start command (tag 144, 112-byte fixed command plus
76-byte network records, command 0x18001) is armed on the WoW path and
stopped on resume, and is advertised only when the firmware reports the
NLO service (16 match sets, random MAC). Disconnected net-detect is
implemented: an unassociated station whose retained configuration carries
net-detect arms WoW on its home station vdev (created at start-up, as
`ath10k_add_interface` creates `arvif->vdev_id` before any
association), because Linux `ath10k_vif_wow_set_wakeups` programs every
STA `arvif` whether or not it is associated. It requires no peer, no
station data owner and no scan or remain-on-channel in flight (mac80211
cancels both before `drv_suspend`). An unassociated station without
net-detect still suspends ordinarily, since its other wake triggers
cannot fire without a link.

**Wire (`wmi-tlv.c`).** GRP_WOW 0x13: ADD_WAKE_PATTERN 0x13001 (tag179
command, ARRAY_STRUCT of the 148+148-byte bitmap tag180, empty IPv4/IPv6
sync, magic and info-timeout arrays and a declared one-word ratelimit),
DEL_WAKE_PATTERN 0x13002 (tag136, `WOW_BITMAP_PATTERN`),
ENABLE_DISABLE_WAKE_EVENT 0x13003 (tag137, `1 << event`), WOW_ENABLE 0x13004
(tag119, enable 1, PCI `link_can_suspend` pause 0) and
HOSTWAKEUP_FROM_SLEEP 0x13005 (tag120). WOW_WAKEUP_HOST event 0x13001
requires `WOW_EVENT_INFO` (tag49: vdev, flag, reason, data_len); the optional
ARRAY_BYTE buffer is retained raw, bounded by `data_len`. Linux ath10k only
logs the reason and never parses that buffer; neither does NARF.

**Suspend (`ath10k_wow_op_suspend`).** `pci::suspend`, for the published
station of the current Radio generation with a retained configuration, an
open data port and station mode, spawns the interface holder
(`interface_wow.rs`), which takes the Radio mutex and keeps it until resume:
no worker, control, scan or recovery can reach BAR/CE/WMI while firmware is
in WoW. Under it `Radio::wow_suspend` encodes everything first, then sends
`ath10k_wow_vif_cleanup` (24 event disables, 22 pattern deletes), the
patterns and the STA event set (disconnect: DEAUTH, DISASSOC, BMISS, CSA_IE;
magic: MAGIC_PKT_RECVD; patterns: PATTERN_MATCH), waits up to 5 s for TX
completion (`ath10k_mac_wait_tx_complete`; frames received during that flush
are not delivered to the quiescing stack), clears and sends WOW_ENABLE and
waits 3 s for HTC endpoint-0 `SEND_SUSPEND_COMPLETE` (`control.rs` now
accepts exactly that endpoint-0 message after startup; any other remains
fail-stop). Then `Hif::wow_suspend_hif` runs `ath10k_pci_suspend`'s
`ath10k_pci_sleep_sync` (grace window dropped, host WAKE vote cleared with
readback) while CE/DMA, MSI and firmware stay live. Any failure leaves the
owner failed and `pci::suspend` falls back to the ordinary retirement above,
as Linux's "return 1" makes mac80211 stop the device. An unassociated
station takes the ordinary path unless it carries net-detect (see
Admission); an NLOD wake resumes the same generation, still
unassociated, and the PNO stop follows WOW_WAKEUP_HOST.

**Resume (`ath10k_wow_op_resume`).** `pci::resume_async` (the async
system-PM resume) signals the holder: `Hif::wow_resume_hif` performs
`ath10k_pci_resume` (force wake with a fresh WAKE/RTC proof, then clear the
D3-reset RETRY_TIMEOUT byte 0x41), `Radio::wow_resume` sends HOSTWAKEUP and
waits 3 s for WOW_WAKEUP_HOST. The report is published as
`pci::last_wowlan_wakeup()` (the shared contract has no
`ieee80211_report_wowlan_wakeup`). A magic/pattern/other wake keeps the
association: firmware keeps the §3.4 hardware keys installed as in Linux,
and the retained station owner keeps host PTK/GTK PN and replay counters
(nothing is reset; frames firmware consumed while asleep only advance the
AP's counters). A disconnect-class reason (AP_ASSOC_LOST, DEAUTH, DISASSOC,
CSA) or a firmware-observed GTK/EAP/4-way handshake, and any transport or
timeout failure, retires the generation and boots a fresh one outside the
recovery budget (Linux RESTARTING + `ieee80211_reconfig`); the rebound
netdev then replays the retained credentials. PCI PME/wake-enable of the
function belongs to the system-PM owner and is not claimed here.

**Tests (written, unexecuted).** `wmi_runtime/wow_tests.rs` (fixed command
layouts, ADD_WAKE_PATTERN layout, program/event mask and 802.3 conversion,
wake-event decode) and `wmi_boot/wow_conversation_tests.rs` (composed WPA2
station with hardware keys: magic suspend→wake→resume with exact Linux
command order and a post-resume CCMP uplink accepted by the FakeAp's
PN/replay check, deauth wake requesting restart, no advertisement without
the firmware feature) under `drivers/wireless/ath10k/wow`;
`wmi_boot/nwifi_conversation_tests.rs` adds the native-WiFi conversation
(`smoke_ath10k_nwifi_wow_pattern_suspend_resume_keeps_link`: one
converted ADD_WAKE_PATTERN, PATTERN_MATCH wake, post-resume native-WiFi
uplink accepted by the AP) and the disconnected net-detect conversation
(`smoke_ath10k_wow_disconnected_net_detect_suspend_resume`: cleanup, NLO
start, NLO_DETECTED only, ENABLE, HOSTWAKEUP, NLO stop on the home vdev,
then a normal join). No physical WoW
entry, wake latency, PME routing or power measurement is claimed.

### 3.7 Native-WiFi decap station (implementation; validation pending)

Linux's default ath10k frame mode is `ATH10K_HW_TXRX_NATIVE_WIFI`
(`rawmode=0`, core.c `ath10k_core_init_firmware_features`: INIT
`rx_decap_mode` 1, `max_num_amsdu` 3); RAW is only taken with
`RAW_MODE_SUPPORT`. NARF keeps RAW wherever bit 10 exists and otherwise, on
TLV firmware (`wmi_boot::Runtime::native_wifi`), runs the station in native
WiFi: `htt_runtime::data_profile` admits it (no PFC), `Radio::data_supported`
additionally requires the hardware-key profile (core.c: software crypto
needs RAW, so this decap has no software data crypto), and the AP owner
(`ap_protocol`, `ap_native`) still requires RAW. The INIT word already left
decap at 1 without bit 10; the HTT aggregation config sends 64/3. The chip
identity (QCA6174 hw2.1/hw3.0, QCA9377 hw1.0 profiles in `profile.rs`) is
unchanged; no board fact is added.

- **TX** (`wmi_runtime/nwifi.rs::transmit`, mac.c `ath10k_tx_h_nwifi`):
  data and EAPOL replies leave as HTT PKT_TYPE native WiFi (flags0 0x21):
  the three-address ToDS header without QoS Control and with the QoS
  subtype cleared; the TID (taken before stripping, htt_tx.c
  `ath10k_htt_tx_get_tid`) rides in the descriptor. Data needs the
  confirmed PTK (`Security::transmit_ethernet_device`: Protected header +
  plaintext, no CCMP header, no host PN consumed; the firmware owns the TX
  PN) and is sent without `NO_ENCRYPT`; until the PTK is confirmed data is
  `Busy`. EAPOL replies use `Security::pending_frame_device`: plaintext
  with `NO_ENCRYPT` before a PTK, or Protected plaintext encrypted by the
  firmware under the confirmed current PTK (`ath10k_tx_h_use_hwcrypto`);
  terminal delivery is reported with `reply_delivered_device`. A reply
  under a PTK the firmware has not confirmed is not sent.
  `WMI_VDEV_PARAM_TX_ENCAP_TYPE` (mac.c `ath10k_mac_op_update_vif_offload`)
  is not sent in either decap; the per-MSDU PKT_TYPE selects native WiFi.
- **RX** (`nwifi::undecap`, htt_rx.c `ath10k_htt_rx_h_mpdu` with
  `fill_crypt_header` and `ath10k_htt_rx_h_undecap_nwifi`): MSDUs whose
  `rx_msdu_start.info1` DECAP_FORMAT is 1 are grouped FIRST..LAST
  (`rx_msdu_end.info0` bits 14/15). The original header (QoS kept) and, for
  a protected frame, the ExtIV CCMP header at the 4-byte decap alignment come
  from the first MSDU's `rx_hdr_status`; each MSDU contributes
  `[nwifi header][LLC...]`. A single MSDU regains DA/SA from its nwifi
  header; an A-MSDU (QoS A-MSDU present) is rebuilt as one aggregate with
  padded subframe headers. MIC/FCS space is appended and the descriptor is
  rewritten to one RAW first+last MSDU (attention ORed across MSDUs), so the
  unchanged RAW admission (`raw_frame`: peer/TID/sequence binding, BA/PHY,
  `is_decrypted`) and the shared owner's PN/replay check
  (`receive_decrypted_with_nonce`, `receive_amsdu_decrypted_with`) run over
  it. The host therefore checks PN on both the legacy indication and the
  in-order path, where Linux trusts the firmware (`fill_crypt_header`
  false). RAW-decapped MSDUs (control/BAR, frames the firmware could not
  decrypt) pass unchanged and abandon a partial group.
- **Management** keeps the existing path (`management::path`: TLV
  by-reference WMI management TX with feature bit 18, else HTT), as Linux.
- **WoW** (§3.6): the native-WiFi owner satisfies `wowlan_support`, so
  QCA6174 hw3.0 firmware-4/-6 and QCA9377 firmware-6 advertise
  disconnect/magic plus 22 native-WiFi patterns (`WOW_MAX_REDUCE`).
- **Descriptor offset fix.** DECAP_FORMAT is `rx_msdu_start_common.info1`
  (byte 32, after `flow_id_crc`); the RAW station and AP admissions read
  byte 28 before and now read 32, as does the data fixture.

Tests (written, unexecuted): `wmi_runtime/nwifi_tests.rs`
(`smoke_ath10k_nwifi_transmit_strips_qos_control`,
`smoke_ath10k_nwifi_undecap_single_decrypted_msdu`,
`smoke_ath10k_nwifi_undecap_amsdu_aggregate`) and the composed
`wmi_boot/nwifi_conversation_tests.rs`
(`smoke_ath10k_nwifi_composed_wpa2_data_and_group_rekey`: QCA6174 TLV
without bit 10, WPA2 join with native-WiFi EAPOL, PTK/GTK install, a
firmware-encrypted native uplink opened by the FakeAp, a decrypted native
downlink admitted and its replay dropped, a group rekey whose reply the
firmware encrypts, and a group frame under the new GTK;
`smoke_ath10k_nwifi_wowlan_advertised_with_patterns`). The model firmware
(`data_tests.rs` `native_frame`/`native_rx_msdu`) rebuilds QoS from the
descriptor TID and encrypts at its own PN, and delivers decryptable data as
native-WiFi MSDUs. Release compilation passed clippy on both arches; native
execution and physical QCA6174/QCA9377 acceptance are pending, and no
physical native-WiFi behaviour is claimed.

### 3.8 P2P roles (groundwork; not advertised)

**Status: partial. No P2P interface type, combination or control opt-in is
advertised; the ledger row stays open.** `wmi_runtime/p2p.rs` holds the
per-vdev identity and native P2P codecs that the P2P device/client/GO owners
will bind; none of them grants RF, peer, key or data authority.

- **Vdev roles.** `Role` maps nl80211 STATION2/AP3/P2P_CLIENT8/P2P_GO9/
  P2P_DEVICE10 to `WMI_VDEV_TYPE_*` and subtype exactly as
  `mac.c::ath10k_add_interface` (P2P_DEVICE and P2P client are TYPE_STA,
  GO is TYPE_AP); every dialect's `get_vdev_subtype` numbers NONE0,
  P2P_DEV1, P2P_CLI2, P2P_GO3. `Vdev::create` is the single
  `WMI_VDEV_CREATE` builder for all dialects (`wmi.c::ath10k_wmi_op_gen_vdev_create`,
  TLV tag 86); the existing station (`Wire::create`) and TLV AP
  (`ap_wire::create`) vdev0 builders now delegate to it byte-identically
  (the AP builder additionally refuses a zero/multicast own address).
- **Vdev ids.** `VdevMap` mirrors `ar->free_vdev_map` (INIT `num_vdevs`,
  lowest free bit as `__ffs64`); exhaustion is `Exhausted` (Linux
  `-EBUSY`), double or out-of-range release is an error. `Radio::start`
  builds the map from the real INIT `num_vdevs` and allocates the managed
  role's vdev first (`Radio::primary`, id 0 as Linux's first interface).
  Scan/dwell/associated-scan/beacon-hint events, HTT TX parameters, the
  station `Peer` (which records its vdev) and its RX indications, the AP
  RX/TX paths and the ROC `Work` all route by that id instead of a literal
  0; the AP replaces the station role on the same id and restores it at
  stop (`ap_wire::create/delete(vdev)`; the TLV delete is byte-identical to
  the former literal command). `Vdev::delete` is `WMI_VDEV_DELETE_CMDID`
  (CREATE+1 in every dialect, TLV tag 87). The ROC scan writes the owning
  vdev at `wmi_start_scan_common.vdev_id` (`mac.c::ath10k_remain_on_channel`
  uses `arvif->vdev_id`).
- **Station builders take a vdev.** Every station WMI builder writes the
  owning `arvif->vdev_id` at its Linux offset: VDEV_START
  (`ath10k_vdev_start`; after the channel in the legacy struct), BSS
  PEER_CREATE/PEER_DELETE, PEER_ASSOC (`ath10k_peer_assoc_prepare`,
  after the peer address), VDEV_UP/DOWN/STOP (`ath10k_bss_assoc`,
  `ath10k_bss_disassoc`, `ath10k_vdev_stop`), VDEV_INSTALL_KEY
  (`ath10k_install_key`), the RTS/CTS VDEV_SET_PARAMs, STA_POWERSAVE
  mode/params, the HT40 coexistence restart and PEER_SET_PARAMs, and the
  WoW wake event/pattern commands. VDEV_START response, VDEV_STOPPED and
  TLV PEER_DELETE_RESP only match the owning vdev. The station owner
  passes the vdev recorded in its `Peer` (the managed vdev for the home
  station); the AP owner passes the managed vdev it replaced. vdev0
  encodings are byte-identical to the former implicit builders.
- **AP builders take a vdev.** `ap_wire::Plan` records the AP-type vdev
  (`Plan::new(vdev, ..)`; today the managed vdev the AP replaced). The
  beacon/probe templates, the AP VDEV_SET_PARAMs, PEER_ASSOC (byte 16),
  PEER_SET_PARAM, AP_PS_PEER_PARAM and VDEV_UP address it, as do the AP's
  VDEV_START/DOWN/STOP, its own/client peer create/delete, HTT and WMI
  management TX and RX_IN_ORD admission (`ap_vdev`). The session's beacon
  TX status and VDEV_STOPPED must carry that vdev; a PEER_DELETE_RESP for
  another vdev is ignored rather than fatal.
- **GO beacon P2P IE.** `go_beacon_ie` follows
  `mac.c::ath10k_mac_setup_bcn_p2p_ie` + `ath10k_mac_remove_vendor_ie`:
  for a GO vdev the first WFA P2P vendor IE after the beacon fixed fields
  becomes `WMI_TLV_P2P_GO_SET_BEACON_IE` (0xd003; tag 90 {vdev, ie_len},
  tag 17 padded bytes) and is removed from the template, because firmware
  inserts it with its own NoA. Ordinary AP beacons are unchanged.
  `ap_wire::Plan` records its vdev role (`Plan::new_role`: `Ap`, or
  `P2pGo` for the AP-type vdev with subtype P2P_GO); only a GO plan admits
  the WFA P2P IE in its beacon and Probe Response (an ordinary AP still
  refuses it). Every beacon publication (`ap_start`, the beacon update)
  sends `ap_wire::templates` in `ath10k_mac_setup_bcn_tmpl` order: the GO's
  0xd003 first, then BCN_TMPL with the P2P IE removed (TIM offset moved
  only when the IE preceded it), then PRB_TMPL unchanged (Linux adds no
  NoA to the firmware probe template). The AP session decodes 0xd002 into
  its `NoaOwner` only for a GO plan's own vdev, and its host-transmitted
  Probe Responses (`ap_tx_management`) carry that NoA
  (`ath10k_tx_h_add_p2p_noa_ie`).
- **GO vdev.** `Radio::go_start` (`ap_native.rs`; the AP START of a device
  marked GO, `Device::go`) follows `mac.c::ath10k_add_interface` for
  `NL80211_IFTYPE_P2P_GO`: TLV P2P firmware, the same AP admission as
  `ap_start`, no P2P client slot, an own unicast address other than the
  INIT and P2P Device addresses, then the lowest free id of the vdev map,
  `WMI_VDEV_CREATE` (`WMI_VDEV_TYPE_AP`, subtype P2P_GO, the GO address),
  the vdev NSS parameter and the AP self peer on that id; the plan is
  `Plan::new_role(.., P2pGo, ..)`. `Radio::primary` is neither deleted nor
  replaced (`ap_is_go`, `ap_owned_vdev`, `go_identity`; `vdev_address`
  answers the GO vdev with its address). `ap_cleanup` on a GO runs the
  AP teardown (DOWN, client peer deletes, the AP self-peer delete of
  `ath10k_remove_interface`, STOP/VDEV_STOPPED) then `WMI_VDEV_DELETE` of
  the GO vdev with its genuine 0x5006, returns the id to the map and does
  not recreate a station vdev; a start refused before any publication
  returns the id at once. The AP session's PEER_MAP must carry its own
  vdev (byte 1, `ath10k_peer_map_event`); another vdev's MAP is not its
  peer and is ignored (before, any non-zero vdev was malformed).
- **GO beside station slots (routing).** Unlike the managed netdev's AP,
  a GO may start while the home station (and a P2P client slot) has a
  peer and data owner; it must not reuse the client's address. One
  channel (`ath10k_tlv_if_limit`): every slot with a peer must be on the
  GO's frequency, and a slot's BSS prepare must be on the running GO's
  frequency (`slots_on_channel`, `go_channel_admits` in
  `sibling_channel_admits`), unless adaptive QCS was enabled
  (`ath10k_tlv_qcs_if_limit`, AP/P2P_GO <= 1 on two channels). Events are
  handed over by owner both ways. `Session::claims` (legacy RX by the
  GO's peer ids, in-order RX by its vdev, PEER_MAP for its vdev,
  UNMAP/ADDBA/DELBA by its peer ids, WMI management whose A1 or A3 is the
  GO address, START_RESP/STOPPED/beacon status/PEER_DELETE_RESP/NoA naming
  its vdev, its outstanding echo and vdev delete): `route_sibling` (every
  station queue and discard loop) and `station_event` (station waits and
  the data step) give a GO-claimed event to `ap_event` at once; a GO that
  cannot consume it is failed for its own netdev's cleanup while the
  station continues. `ap_event` on a GO first parks what a station slot
  claims in that slot's inbox (`park_station_owned`). TX completions
  follow the id (`txrx.c::ath10k_txrx_tx_unref`): the GO takes only its
  own HTT ids (`take_tx_receipt_for`), `take_station_receipt` and the data
  step's foreign arm hand a GO id to the session (`go_receipt`), and WMI
  management completion batches are split by descriptor id (the GO's on
  its session, the rest to the station's bounded `management_done`). A GO
  teardown proves only its own TX quiet (the HTT pool may hold the
  slots' MSDUs); the ordinary AP keeps the whole-pool proof.
- **P2P GO netdev** (`interface_p2p_go.rs`, iftype 9, gated by
  `P2P_ADVERTISED`). `NEW_INTERFACE` (`new_virtual_interface` with
  iftype 9; outside the async control mask) on the home netdev: TLV P2P
  firmware with AP support, home netdev in station mode, no AP session
  and no GO netdev yet (one AP session; `-EBUSY`), address = the requested
  one, else the client's derivation (`brcmf_p2p_generate_bss_mac`); it
  must differ from the netdev, P2P Device and present client addresses
  (`-EINVAL`, userspace names one). A second `Device` is registered at
  once with `go = true` and AP mode for its whole life: own rings, TX
  generation (`send` also resolves the GO), wiphy of the home netdev,
  `current_iftype` 9 (`ap_iftype`; `SET_INTERFACE` accepts only 9,
  `ap_set_iftype`), its own service worker and AP waker. No vdev exists
  until `START_AP`, whose AP controls run `Radio::go_start` on the GO
  vdev (`ieee80211_start_ap` -> `ath10k_add_interface`). The GO netdev
  has no station paths (mode 3), ROC, offchannel FRAME, WoW, power save
  or P2P_DEVICE child. Ownership: the radio has one AP session and
  `owns_ap` (`ap_is_go() == Device::go`) binds it to one netdev:
  `ap_control` on the other netdev is `-EBUSY`, and `ap_drain`,
  `ap_sequence` and `ap_station_macs` see only the owner's session. The
  home worker's AP cleanup skips a GO session (the GO worker's
  `go_cleanup_step` tears it down when closed or abandoned, then opens a
  fresh control generation); the home worker kicks the GO worker on every
  vector turn. The home netdev may still `SET_INTERFACE` station while a
  GO runs but cannot become an AP (`ap_set_mode`); a P2P client netdev
  and a P2P_DEVICE scan are no longer refused merely because a GO
  session exists (the managed AP still refuses both). Group-key staging
  before `START_AP` (`ap_stage_*` with `go`) is admitted beside an
  associated station slot for a GO only. `DEL_INTERFACE`
  (`delete_virtual_interface`) closes and unpublishes the netdev at once;
  the worker stops a running GO (`ap_cleanup`: DOWN, client peer deletes,
  self peer delete, STOP, `WMI_VDEV_DELETE`, as `ieee80211_if_remove` ->
  `ieee80211_stop_ap` -> `ath10k_remove_interface`) and only then frees
  the GO slot; a failed teardown ends in radio recovery, which retires
  the GO netdev with the generation (not recreated).
- **NoA / opportunistic PS.** Linux ath10k never programs CTWindow/OppPS or
  a NoA schedule from the host; firmware owns both and reports them.
  `Noa::tlv_event` decodes `WMI_TLV_P2P_NOA_EVENTID` (0xd002, tags 223
  vdev and 69 `wmi_p2p_noa_info`, both required as
  `ath10k_wmi_tlv_event_p2p_noa`), rejecting more than
  `WMI_P2P_MAX_NOA_DESCRIPTORS` (Linux does not bound it).
  `Noa::information_element` is `p2p.c::ath10k_p2p_noa_ie_fill` (OppPS
  moves from wire bit0 to IEEE bit7; no IE without a descriptor or OppPS).
  `NoaOwner` keeps the IE for its own GO vdev only and appends it to Probe
  Responses only (`mac.c::ath10k_tx_h_add_p2p_noa_ie`). Consequently
  `supports_p2p_go_power_save` stays false: nl80211 CTWindow/OPPPS
  settings have no Linux ath10k host path. MAIN-dialect SWBA NoA
  (`wmi.c::ath10k_wmi_update_noa`) is out of scope because no MAIN AP/GO
  owner exists.
- **Admission.** `p2p_combinations` reproduces `ath10k_tlv_if_comb`
  (STA≤2; AP/P2P_CLIENT/P2P_GO≤2; P2P_DEVICE≤1; 4 interfaces, 1 channel)
  or, with TLV service 39 ADAPTIVE_OCS, `ath10k_tlv_qcs_if_comb`: that
  same one-channel entry followed by the two-channel
  `ath10k_tlv_qcs_if_limit` entry (STA≤2; P2P_CLIENT≤2; AP/P2P_GO≤1;
  P2P_DEVICE≤1), minus the IBSS combination, and nothing for non-TLV
  dialects or `ATH10K_FW_FEATURE_NO_P2P` (bit 3). It is not yet returned
  from `interface_combinations`. As `mac.c::ath10k_start`, `Radio::start`
  sends `ath10k_wmi_adaptive_qcs(ar, true)` with that service before the
  managed vdev is created (`p2p::adaptive_qcs`:
  `WMI_TLV_RESMGR_ADAPTIVE_OCS_CMDID` 0x23001, TLV tag 207 `{enable}`;
  TLV only, failure fails start) and records it, so the two-channel entry
  matches what the firmware was told; with it the station slots'
  one-channel rule is lifted (`sibling_channel_admits`).
- **Per-vdev station slots.** The station owner (BSS `peer`, `data`,
  `power_save`, `protection`, `coexistence`, `peer_pmf_offload`) is a
  `StationSlot` (Linux per-`arvif` state). `Radio.station` is the home slot
  on the managed vdev with the INIT address (unchanged behaviour); an
  optional `p2p_client` slot records its own vdev and address. A
  `ClientScope` exchanges the slots so the existing station prepare,
  association, key, data and management paths run on the client's vdev
  (`station_vdev`, `station_own`) and restores them on drop (including
  cancellation). PEER_MAP must carry the peer's own vdev (byte 1,
  `ath10k_peer_map_event`). The data step demultiplexes what it polls
  (`htt_rx.c` delivery by `peer->vdev_id`): a legacy RX batch by peer id,
  an in-order indication by vdev and peer id, a WMI management frame whose
  A2/A3 is the sibling's BSSID, peer-scoped HTT notes, and PEER_MAP/UNMAP
  the slot did not record are parked in the sibling's bounded inbox (256;
  overflow fails that slot's data owner); TX completions follow the MSDU
  id to the slot that queued it (`txrx.c::ath10k_txrx_tx_unref`), also on
  the protection, coexistence and data-start receipt drains. Radio-level
  observers (scan, ROC, beacon hints) see each event once, when polled.
  The same ownership rule (`StationSlot::claims`: legacy RX by peer id,
  in-order RX by vdev and peer, ADDBA/DELBA by the note's peer id
  (`ath10k_htt_rx_addba`/`delba`), WMI management by A2/A3 BSSID) governs
  every HTT poll outside the data step: `Radio::queue` (station prepare
  START/PEER_MAP and association waits, MLME, protection/flush,
  disconnect, WoW, host power, scan, P2P vdev delete) and the loops that
  discard (associated-scan stop, ROC progress, ROC action delete) hand a
  sibling-owned event to the sibling's inbox (`route_sibling`) instead of
  queueing it for, or discarding it as, the polling owner. The VDEV_START
  wait runs `station_event`, so a sibling PEER_MAP polled there is parked.
  `station_progress`, the data start's early-EAPOL retention and
  `poll_ethernet_now` drain the slot's inbox first; a parked note or
  management frame is never handed back to the slot that polled it.
- **P2P client vdev (radio owner).** `wmi_runtime/p2p_client.rs`
  `start_p2p_client` follows `ath10k_add_interface` for
  `NL80211_IFTYPE_P2P_CLIENT`: TLV P2P firmware, no client yet, no
  scan/ROC/AP, a unicast address other than the INIT address, lowest free
  id, `WMI_VDEV_CREATE` (STA, subtype P2P_CLI) and the vdev NSS parameter
  (the same two commands as the managed station vdev), then a client slot.
  `stop_p2p_client` needs the slot's peer and data retired, sends
  `WMI_VDEV_DELETE` and with SYNC_DELETE waits for 0x5006
  (`wait_vdev_delete`, shared with the P2P_DEVICE vdev). 0x5006 carries no
  vdev id (`ath10k_wmi_tlv_event_vdev_delete_resp`); Linux serialises
  deletes under `conf_mutex` and the radio lock is held across delete and
  wait here, so at most one delete is outstanding. One-channel rule:
  while the sibling slot has a peer, a slot's BSS prepare is refused
  (`Unsupported`, before any coexistence scan) unless it is on the same
  primary frequency, unless adaptive QCS was enabled at start
  (`ath10k_tlv_qcs_if_limit` admits two channels). `vdev_address` answers
  the client vdev with its address.

- **P2P_DEVICE vdev (radio owner only).** `wmi_runtime/p2p_device.rs`
  `start_p2p_device` follows `mac.c::ath10k_add_interface` for
  `NL80211_IFTYPE_P2P_DEVICE`: TLV firmware without NO_P2P only
  (`p2p_supported`), no AP/scan/ROC in flight, lowest free id, then
  `WMI_VDEV_CREATE` (STA type, subtype P2P_DEV, wdev address) and the
  vdev NSS parameter on that id (`Chains::vdev_nss_for`). `stop_p2p_device`
  sends `WMI_VDEV_DELETE` and, with TLV service 92 SYNC_DELETE_CMDS, waits
  5 s for `WMI_TLV_VDEV_DELETE_RESP` (0x5006) as
  `ath10k_vdev_delete_sync` before returning the id. `begin_roc_on(vdev)`
  runs a discovery ROC on the P2P_DEVICE vdev (`ath10k_remain_on_channel`
  uses `arvif->vdev_id`).
- **Per-vdev offchannel builders.** The DEFAULT offchannel peer
  create/delete (`wmi_peer_create_cmd`/`wmi_peer_delete_cmd` vdev_id), the
  TLV by-reference MGMT_TX (`wmi-tlv.c::ath10k_wmi_tlv_op_gen_mgmt_tx_send`
  vdev_id at byte 8) and the inline MGMT_TX (`wmi.c::ath10k_wmi_op_gen_mgmt_tx`
  `hdr.vdev_id`) take the sending vdev; vdev0 encodings are byte-identical.
  A ROC action and a private FRAME ROC run on the requesting vdev: its
  temporary peer, HTT/WMI descriptor and PEER_MAP match (HTT byte 1) use
  that id, and A2 (and Probe Response A3) must be that vdev's own address
  (`Radio::vdev_address`: INIT address for the managed vdev, wdev address
  for the P2P_DEVICE vdev). Directed ROC capture filters on the same address.
- **P2P_DEVICE WDEV** (`interface_p2p.rs`, iftype 10, gated by
  `P2P_ADVERTISED`). `NEW_INTERFACE` (async control mask `1 << 10`,
  `supports_virtual_interfaces` only with `p2p_supported`) publishes a
  control-only child under the netdev's registry Write cap (address: the
  requested one, else the netdev address with the local bit); at most one
  exists. `START_P2P_DEVICE` creates the P2P_DEV vdev
  (`ieee80211_start_p2p_device` -> `ath10k_add_interface`),
  `STOP_P2P_DEVICE`/`DEL_INTERFACE` cancel a ROC on it and delete the vdev
  (`ath10k_remove_interface`, SYNC_DELETE wait) before the retirement
  receipt. ROC, CANCEL_ROC and FRAME on the wdev reuse the netdev's ROC
  owner through `Side` with a `native_control_emission_for` emission bound
  to the wdev's child registration; the netdev worker services the ROC and
  delivers captures/expiry to the wdev (a withdrawn wdev's ROC is forced
  down without closing the netdev). Registrations are per wdev (Action
  everywhere, Probe Request only on the wdev, as
  `ieee80211_default_mgmt_stypes[P2P_DEVICE]`); the radio's bound set
  follows the ROC owner, so registering on one wdev while the other holds
  a ROC is `-EBUSY`. On the P2P_DEVICE vdev a ROC also captures broadcast
  or directed Probe Requests and FRAME may send a directed Probe Response
  whose BSSID is the device address (wpa_supplicant Listen). Netdev
  close/retire withdraws the wdev metadata.
- **P2P_DEVICE scan (P2P search).** The wdev opts into the shared
  WDEV-addressed `TRIGGER_SCAN` (`async_p2p_device_scan_control`,
  `p2p_device_scan_async`; `max_scan_ssids`/`max_scan_ie_len` as the
  netdev). `mac.c::ath10k_hw_scan` on the P2P_DEVICE vif binds the scan to
  `arvif->vdev_id`: `Native::p2p_device_scan` validates the request as the
  netdev's scan and `Radio::p2p_device_scan` runs the TLV start-scan on
  the P2P_DEVICE vdev (`Wire::p2p_device_scan`: `vdev_id` at byte 16;
  active flags without WMI_SCAN_ADD_CCK_RATES 0x4, since a P2P probe never
  offers 11b rates (mac80211 `no_cck`); the caller's P2P/WSC IEs and
  `DIRECT-` SSID are the probe content). Scan events must carry that vdev.
  On this vdev a P2P Device's Listen Probe Response (neither ESS nor IBSS)
  is admitted when it carries the WFA P2P IE; the P2P Wildcard SSID
  matches every `DIRECT-` SSID. Results and IEs belong to the wdev
  (`scan_information_elements`). The radio BSS table is shared as
  cfg80211's per-wiphy table (`scan.c::cfg80211_bss_update`):
  `Radio::publish_scan_cache` merges a P2P_DEVICE scan's entries beside the
  netdev's (bound 64), so a GO found by P2P search is the cached BSS a P2P
  client's station prepare binds; a netdev scan replaces the table it
  observed. Either scan keeps every station slot's associated BSS (home
  and P2P client) that it did not observe. An
  unstarted wdev is `-EIO`; a ROC in flight, a prepared-but-unassociated
  station peer or an AP is `-EBUSY` before publication. A P2P scan
  concurrent with an associated station is supported: Linux runs the
  requesting vif's scan on its own vdev with no associated-state check
  (`mac.c::ath10k_hw_scan`), and firmware owns dwell and the home
  return; the plan's station binding is carried for setup/restore only,
  and every restore packet is sent on completion. Home-station data
  stalls for the scan duration (the host loop holds the radio; bounded
  by the 25 s deadline), and a failed P2P scan while associated still
  fails the radio, as a failed managed associated scan does. A P2P scan
  beside a GO is still refused at the radio layer (remainder).

- **P2P client netdev** (`interface_p2p_client.rs`, iftype 8, gated by
  `P2P_ADVERTISED`). `NEW_INTERFACE` reaches the legacy
  `new_virtual_interface` (iftype 8 is outside the async control mask) on
  the home netdev: TLV P2P firmware, home netdev in station mode, no AP and
  no client yet (one client slot; `-EBUSY`), address = the requested one,
  else the netdev address with the local bit and byte 4 XOR 0x80
  (`brcmfmac/p2p.c::brcmf_p2p_generate_bss_mac`; never the netdev or
  P2P Device address). A second `Device` is registered at once (own
  rings, TX generation, nl80211 wiphy of the home netdev, `current_iftype`
  8) and its service worker creates the vdev (`start_p2p_client` =
  `ath10k_add_interface`); until then its station paths are `Busy`.
  Every station path of the client netdev holds the radio through a client
  `StationGuard` (the mutex guard with the slots exchanged for its whole
  lifetime), so scan, CONNECT (coexistence, prepare, association, keys,
  data start), disconnect, power save, management flush and data drains
  run on the client slot and vdev. Its scan runs on the client vdev
  (`Wire::scan_on_vdev`: `vdev_id` byte 16, ordinary station flags) and
  merges into the shared BSS table; the pending scan's vdev is recorded
  (`scan_vdev`) for its events, retained STOP and beacon hints, and each
  netdev's worker leaves the sibling's failed scan alone
  (`scan_on_sibling`). A client scan (including its 2.4 GHz HT40
  coexistence scan) while the home station has a peer, or while the client
  is associated (the associated dwell owner is the managed vdev's), is
  refused. The client netdev has no AP, ROC, offchannel FRAME, WoW,
  P2P_DEVICE child or radio host-vote maintenance; the home netdev cannot
  become an AP while a client vdev exists. The home worker's vector turn
  kicks the client worker (events it parked in the client slot). TX
  dispatch (`send`) and the netdev RX drain cover both netdevs.
  `DEL_INTERFACE` (`delete_virtual_interface`) closes and unpublishes the
  netdev at once; the worker then disassociates a joined client (best
  effort deauthentication) and deletes the vdev (`stop_p2p_client`), and
  only then frees the client slot. As `mac.c::ath10k_remove_interface`
  this tears down only the client's vif and the home station keeps
  running: `disconnect_station` inside the client scope runs the same
  DOWN/PEER_DELETE/all-UNMAP/(SYNC_DELETE ACK)/STOP/VDEV_STOPPED proof on
  the client vdev and, once it completed, drops the slot's data owner and
  clears the radio's failed latch (the home station's retirement still
  keeps it). The client data owner's in-flight MSDU ids are disowned at
  the HTT layer (`htt::Runtime::orphan_tx`): their TX slots keep the DMA
  until the firmware's completion, which then only frees it and is never
  delivered (`txrx.c::ath10k_txrx_tx_unref`), so no id is reused early;
  an already-queued receipt is consumed at once. A genuine firmware
  failure (missing/malformed/foreign receipt, timeout, late MAP), a
  cancelled retirement, or an ambiguous VDEV_CREATE/DELETE still ends in
  radio recovery, which retires the client netdev with the generation
  (it is not recreated; userspace re-forms the group). When the deferred
  VDEV_CREATE fails after NEW_INTERFACE returned, the netdev is withdrawn
  with an nl80211 `DEL_INTERFACE` event on the `config` group
  (`narf_wireless::nl80211::notify_interface_removed`, as
  `_cfg80211_unregister_wdev` -> `nl80211_notify_iface`) before it is
  unpublished. WPS provisioning
  over the client netdev is not supported (no host EAP-WSC path), so a
  group is joined with WPA2-PSK credentials (persistent group or
  pre-provisioned PSK). A host EAP-WSC path would be an in-kernel WSC
  enrollee programme, not a small lane: EAP identity exchange plus the
  M1–M8 state machine, the WSC TLV codec, KDK derivation, AES key-wrap
  unwrap (RFC 3394) and a credential handoff to the existing PSK join
  path, for PBC and PIN modes. Today EAP type-0 frames are dropped at
  the port filter (EAPOL-Key only) and the shared supplicant handles
  Key frames only, so admitting them without an enrollee would deliver
  nothing.

- **Advertisement.** `P2P_ADVERTISED = true`; each radio further needs
  the facts `mac.c::ath10k_mac_register` uses (`CombinationFacts`, read
  after start: WMI dialect, `ATH10K_FW_FEATURE_NO_P2P`, adaptive QCS).
  For TLV firmware without NO_P2P every netdev of the wiphy (home, P2P
  client, GO) reports `WirelessModes::P2P`, `p2p_interface_types`
  `[8, 9, 10]` (P2P_CLIENT and P2P_GO netdevs, P2P_DEVICE wdev) and
  `interface_combinations` = `p2p_combinations(dialect, adaptive_qcs,
  no_p2p)` (`ath10k_tlv_if_comb`, or `ath10k_tlv_qcs_if_comb` once
  `ath10k_wmi_adaptive_qcs(ar, true)` was sent); the home netdev offers
  NEW_INTERFACE for iftypes 8/9 and the async P2P_DEVICE control. Other
  dialects and NO_P2P firmware advertise none and refuse every P2P
  NEW_INTERFACE. Unsupported, explicitly: WPS provisioning on the client
  netdev, a second P2P client or GO (one slot each, one AP session),
  host-programmed CTWindow/OppPS (`supports_p2p_go_power_save` false,
  as Linux ath10k) and the MAIN-dialect P2P path.
Tests (written, unexecuted): `wmi_runtime/p2p_tests.rs`
`smoke_ath10k_p2p_vdev_create_roles`,
`smoke_ath10k_p2p_vdev_map_lowest_free`,
`smoke_ath10k_p2p_go_beacon_ie_moves_to_firmware`,
`smoke_ath10k_p2p_noa_event_builds_absence_ie`,
`smoke_ath10k_p2p_noa_owner_probe_response_only`,
`smoke_ath10k_p2p_tlv_combinations`,
`smoke_ath10k_p2p_combination_facts_gate_advertisement`,
`smoke_ath10k_p2p_vdev_delete_and_roc_vdev`,
`smoke_ath10k_p2p_device_vdev_nss_on_own_id`,
`smoke_ath10k_p2p_offchannel_builders_carry_vdev`,
`smoke_ath10k_p2p_station_builders_carry_vdev`,
`smoke_ath10k_p2p_ap_builders_carry_vdev`,
`wmi_boot/ap_native_tests.rs` `smoke_ath10k_p2p_go_own_vdev_start_and_teardown`,
`smoke_ath10k_p2p_go_ignores_other_vdev_peer_map`,
`smoke_ath10k_p2p_go_session_owned_by_go_netdev`,
`smoke_ath10k_p2p_device_scan_on_own_vdev_without_cck`,
`smoke_ath10k_p2p_device_scan_admits_listen_probe_response`,
`smoke_ath10k_p2p_client_scan_on_client_vdev`,
`smoke_ath10k_p2p_station_slot_parks_bounded`,
`smoke_ath10k_p2p_slot_claims_by_peer_vdev_and_bssid`;
`wmi_boot/radio_tests.rs`
`smoke_ath10k_p2p_device_scan_merges_shared_bss_table`;
`wmi_boot/teardown_tests.rs`
`smoke_ath10k_p2p_client_disconnect_keeps_radio_running`;
`wmi_boot/htt_tests.rs`
`smoke_ath10k_htt_orphaned_tx_completion_frees_dma_silently`.

## 4. Invariants

- PCI parking is read back before BAR sizing: BME and memory decode off,
  INTx masked; sizing runs in the current capability invocation, then
  memory decode is enabled and verified before MMIO. Additional matched singleton radios
  are parked with BME/memory decode off and rejected. BME is enabled only
  after initialization of retained rings.
- Repeated dispatch of the already owned PCI address fails before any
  parking or MMIO operation and cannot stop its active DMA.
- A ring slot cannot be reused until its terminal completion. Source
  completion validates the read index; RX completion reads the aligned
  16-bit count atomically and checks it against the posted capacity.
- A transaction poisons the session before its first bounce-buffer write or
  descriptor publication and clears poison only after validated completion.
  Cancellation, timeout or malformed completion retains poison. Pending DMA is
  not treated as cancelled and its backing memory is not recycled.
- Before mission handoff, Drop frees allocations only after all chip CEs
  acknowledge halt and PCI bus-master disable is read back. Once DONE was
  attempted, including ambiguous cancellation/timeout, DMA allocations remain
  retained even if those checks succeed: firmware/autonomous writes need a
  future complete reset/drain proof before recycling. A stop failure also retains.
- CPU pointers come from coherent CPU mappings; DMA addresses only enter
  device descriptors/registers. Descriptor publication and consumption
  include device-visible ordering: outer-shareable DMB on aarch64, bracketed
  by compiler fences, and a full fence on x86_64.
- BMI_DONE prevents further bootloader commands even if that handoff times
  out. Rounded writes and LZ tail chunks are zero-padded.
- Identity or bootloader success never enables carrier, transmit or a
  purported association.
- Selected occupied20/40 geometry, programmed host ceiling, immutable
  executable/board records and exact PCI/session generation remain current
  through native waits and final packet publication. Source or policy replacement
  cannot relabel a live owner. A protection request is submitted intent, not an
  inferred firmware/RF acknowledgement; dropping it after publication keeps the
  radio closed and uncertain DMA retained.

## 5. Architecture notes

The same DMA32 and little-endian CE descriptor format is used on both NARF
architectures. The PCIe QCA99X0/9888/9984 profiles use 8-byte descriptors;
the separate 16-byte WCN3990 format is not their DMA format.

## 6. Dependencies

`bus/` supplies PCI authority and device mappings, `io/` coherent DMA32,
`lib/` the retained async mutex, and scheduler/time supply bounded waits.
The firmware registry supplies verified blobs under derived read authority.
Board selection uses exact identities and checked record bounds; malformed
containers or failed OTP execution do not proceed to image activation.

## 7. Stage assignment

Boot transport groundwork in Stage 5. Software regressions cover corrected
CE programming, ring completion/wrap/reuse, DMA bounds, BMI chunking,
short responses and the DONE transition. Composed ROM fixtures execute the
production BMI orchestration and verify selected BDF bytes, OTP parameters,
PLL register order, code-swap payload/segment records and failed-calibration
gates. Runtime regressions execute actual generic CE DMA receive/refill,
8192-entry CE4 and per-family CE5/CE8 selection, cancellation after actual
CE3 publication, DONE prerequisite/terminal hooks, and a literal-wire HTC
model including credit starvation/refill, early service-ready, both HTT
receive pipes and terminal duplicate/cancellation handling. These tests
include actual HTC→WMI composition for all six dialects, INIT packets from
fixed source-cited Rust wire vectors, resource-dependent memory sizes,
zero-unit skip, malformed ABI/count/extent handling and dropped INIT ownership.
HTC→WMI→HTT fixtures exercise actual retained RX/fragment/PFC storage, native
configuration and TX literals checked against fixed Rust reference data
structures, major-2 management, terminal TX ownership, idle progress,
A-MSDU/chained RX, out-of-order PADDR ownership and malformed/duplicate batch
retention. The composed models are architecture-neutral; they do not emulate
a Qualcomm radio or establish reset/ROM interoperability. Composed scan
fixtures cover all six dialects through actual HTC/WMI/HTT, native vdev and
channel/scan commands checked against fixed Rust reference data
functions, production hardware-channel selection, two scans with distinct
IDs, stale/wrong-requestor responses, malformed beacons, management header
variants, concurrent terminal HTT completion and dropped/failed ownership.

**Beacon WMM updates** (closes `dynamic_wmm`). After association, a beacon
from the associated BSS whose WMM Parameter element carries a different
Parameter Set Count than the programmed set queues that set
(`wmm::beacon`, mac80211 `ieee80211_sta_wmm_params`). An absent or
unparsable element changes nothing; a new set with BE ACM is refused and
closes the station, as the association response would. The Device worker's
await point (`flush_station_management`, beside the protected-management
flush) re-sends the per-dialect `WMI_PDEV_SET_WMM_PARAMS` command
(`ath10k_conf_tx` for every AC), then updates the peer's parameters and ACM
downgrade. Smoke: `smoke_ath10k_wmm_beacon_parameter_set_change_reprograms_contention`
(all six dialects).

**Beacon ERP protection** (closes `automatic_protection`). On 2.4 GHz, each
beacon from the associated BSS yields mac80211's `use_cts_prot` (ERP element
present with Use_Protection, `ieee80211_handle_bss_capability`). A value that
differs from the programmed one is queued as `BSS_CHANGED_ERP_CTS_PROT`; the
Device worker's await point then runs `set_station_protection` (Linux
`ath10k_recalc_rtscts_prot` + `ath10k_mac_set_cts_prot`: RTS/CTS enable,
`use_cts_prot`, RTS threshold), keeping the configured threshold (HT40 keeps
its forced RTS). It waits for an open, reply-free data path instead of
failing the owner. Linux `ath10k_bss_info_changed` handles no HT Operation
protection change; a changed HT Operation still closes the station
(`matches_beacon`). Smoke:
`smoke_ath10k_beacon_erp_protection_reprograms_cts_all_six_dialects`.

**TSPEC is inapplicable** (row removed 2026-10-28): ath10k never sets
`NL80211_FEATURE_SUPPORTS_WMM_ADMISSION`, so `nl80211_add_tx_ts` refuses
ADD_TX_TS and mac80211 never originates ADDTS; ACM ACs keep the
`ieee80211_downgrade_queue` behaviour in `tx_qos.rs`. (Of the upstream
wireless drivers only iwlwifi mvm/mld set that feature.)

**Station U-APSD is not reachable upstream** (row folded into `ap`
2026-10-28): mac80211 starts every station with
`IEEE80211_DEFAULT_UAPSD_QUEUES` 0, no driver sets `hw.uapsd_queues`, and
only the mac80211 debugfs `uapsd_queues` file changes it, so
`IEEE80211_STA_UAPSD_ENABLED` is never set and `ath10k_conf_tx_uapsd` only
ever programs U-APSD off. Every nl80211 U-APSD control
(`NL80211_STA_WME_UAPSD_QUEUES`, `WIPHY_FLAG_AP_UAPSD`) is AP-side, which
belongs to the `ap` row.

## 8. Remaining software and hardware acceptance

The retained validation profile is calibrated BMI boot with a signed board
file, firmware advertising RAW_MODE_SUPPORT, non-PFC HTT, legacy/HT20 station on
host-permitted channels1–11 or the matching fixed-country non-DFS 5-GHz profile,
passive/active scan, Open or WPA2-PSK/CCMP, DHCP and
bidirectional IP. Peer/vdev retirement is terminal; firmware and DMA allocations
remain owned until full-device reset. Interrupts remain masked and the bounded
polling path is the initial packet service. No country, real calibration data,
firmware asset or credential is invented by the driver or its models.

Native composition tests consume actual generic CE descriptors, HTT DMA payloads
and RX descriptors through the retained Radio and Device. One independent AP
supplies scan/management/EAPOL/CCMP and a shared DHCP server, while the real
kernel DHCP client and IP dispatch run through the registered callbacks. Cases
cover all six WMI dialects with Open/WPA2, exact lease/IP bytes, occupied CE4
bounce preservation while RX proceeds, separate CE/HTT retirement, held-M4
cancellation, connection-loss expiry and failed terminal disconnect. These are
software evidence; they do not attest a physical board or firmware image.
Native station-PS cases exercise all six dialects with Open/WPA2 DHCP/IP,
literal command layouts, each publication's cancellation/policy/failure fence,
concurrent closure and preference replacement. `NO_PS` images reject requests
before I/O. These checks establish submitted control intent; physical DTIM,
buffering, wake latency and energy behavior remain hardware acceptance work.

The preceding checkpoint added 22 native smokes: nine under
`drivers/wireless/ath10k/ht40`, eight under
`drivers/wireless/ath10k/source` and five under
`drivers/wireless/ath10k/protection`. HT40 cases compose all six dialects with
Open/WPA2, the actual kernel DHCP/IP path, PS and terminal retirement; they also
exercise every eligible pair, truthful HT20 fallback, literal inventory/start/
peer geometry, response narrowing failures, PPDU/GI/MCS before replay,
cancellation, live secondary restrictions and final allocation/callback fences.
Source cases use an isolated real signed registry with inert fixture bytes,
actual capability revocation/reinstall, native BMI/MMIO and held M4/CE/HTT
storage. They prove no deployable board permissions. Protection cases check
all dialects and bound HT modes, real old-packet terminal drain, preserved
following RX, each command's cancellation/current-source/current-policy fence
and threshold 0/2347/disabled bounds. All22 new cases pass the coordinated
both-architecture software suites; no physical or performance result is claimed.

The SGI40 extension passes nine more native smokes on both architectures under
`drivers/wireless/ath10k/sgi40`. Actual
per-dialect SERVICE_READY packets feed the production capability parser before
Device capability capture, including SGI40-only and HT-disabled cases. Literal
per-band/request HT bodies, peer capability/RC fields, native RX HT-SIG and
independent CCMP packets check directional scan/response narrowing and truthful
local20 fallback. Composed Open/WPA2 tests run the real kernel DHCP/IP path,
initial PS and terminal retirement across both primary orders and all six WMI
dialects. Other cases exercise malformed GI/MCS before same-PN retry, native BA
FIRST proof/reordering/LAST retirement, seven native cancellation points,
held WMM/M4 source and occupied-power revocation, and final allocation/callback
boundaries with prior-authorized IPC distinguished from later revocation.
Reinstalling source or restoring policy cannot reopen the failed owner.

The per-profile ledger below distinguishes actual reachability from a codec or
ID. `R` denotes the shared retained legacy/HT20 Open/WPA2/RAW/non-PFC station
backend; `H` denotes the conditional 5-GHz HT40/SISO extension whose LGI40 path
is validated in native software suites. Its separately gated SGI40 addition
also passes both-architecture native cases. Both depend on actual image capability/service
facts, matching board/OTP data, current PCI/source/host authority and successful
native receipts; neither asserts that every vendor image for that tuple is
usable. The six WMI dialects are selected from the image's real API facts,
not inferred from this PCI table. `profile::PROFILES`, `hw::HwRev::from_pci_id`,
`pci::boot_task`, `firmware::prepare`, `wmi_runtime::ht::Profile::offer` and
`regulatory::Permission::occupied` are the production selection chain. Linux
`ath10k/core.c`'s hardware table, `hw.h`, `mac.c::ath10k_get_ht_cap` and
`wmi.c::ath10k_wmi_event_service_ready` are the corresponding primary facts.

| Chip / PCI tuple | Exact BMI target / firmware directory | Native reachability and remaining profile-specific qualification |
|---|---|---|
| QCA988X,168c:003c |4100016c / QCA988X/hw2.0 | R; H conditional. Real vendor calibration, factory country, RAW/non-PFC and firmware capability acceptance remain external. |
| QCA988X UBNT,0777:11ac |4100016c / QCA988X/hw2.0 | R; H conditional. Distinct PCI identity is retained; rebadge is not generic board permission. |
| QCA6164,168c:0041 |05010000 / QCA6174/hw2.1 | R; H conditional. Exact subsystem BDF and reported chain/band facts required; shared directory does not imply identical silicon capability. |
| QCA6174,168c:003e |05010000 / QCA6174/hw2.1 | R; H conditional; native CE1 HTT route and actual board/image required. |
| QCA6174,168c:003e |05020000 / QCA6174/hw3.0 | R; H conditional; actual revision/OTP/image selection retained. |
| QCA6174,168c:003e |05030000 / QCA6174/hw3.0 | R; H conditional; existing chip-specific PLL sequence precedes native mission startup. |
| QCA99X0,168c:0040 |01000000 / QCA99X0/hw2.0 | R; H conditional; 12-pipe hardware/firmware host-memory profile remains exact, chain/NSS extension is source complete, software execution and physical acceptance pending. |
| QCA9984,168c:0046 |01000000 / QCA9984/hw1.0 | R; H conditional; 2048-byte extended board data and selected OTP remain required. The bounded10.4 80+80, contiguous160 and chain/NSS extensions await software execution and board qualification. |
| QCA9888,168c:0056 |01000000 / QCA9888/hw2.0 | R; H conditional; distinct board/OTP identity is required despite shared CE family. |
| QCA9377,168c:0042 |05020000 / QCA9377/hw1.0 | R; H conditional; actual RAW/non-PFC image and CE1 routing required. |
| QCA9377,168c:0042 |05020001 / QCA9377/hw1.0 | R; H conditional; existing revision-specific PLL path and exact board data retained. |
| QCA9887,168c:0050 |4100016d / QCA9887/hw1.0 | R; H conditional. QCA988X-family register/reset route plus SI EEPROM calibration with board-file/OTP fallback; single-chain board facts and actual RAW/non-PFC image required. |
| AR9462,168c:0034 | none | Explicit pre-MMIO rejection; ath9k ownership, not a missing ath10k station implementation. |

The chain/NSS/TX-STBC extension is source complete under the contract in §3.
Four new source cases under `drivers/wireless/ath10k/chains` cover all six
dialects, actual SERVICE_READY/INIT limits, native CE-held partial publication,
two-stream HT plus TX-STBC through real RSNA/DHCP/IP, and rejected MCS/NSTS
before a valid same-PN packet. Existing coding/SGI/VHT cases retain their
assertions with the newly selected local masks; the VHT PPDU case now admits
actual two-stream traffic and rejects three streams. None of these changed
cases has been executed yet; coordinated release compile/native gates remain
pending. No physical board or over-air STBC result is claimed.

The bounded 2.4-GHz HT40/HT20–40 coexistence continuation is source complete
as described in §3; seven new cases and its release/native validation are
pending. This makes no additional per-chip physical RF or power claim.

Across the reached rows, concrete remaining software packages are
DFS qualification (VHT20/40/80, the bounded 80+80 owner and contiguous VHT160
are implemented; contiguous VHT160 awaits release/native validation); physical acceptance of the §3.4 hardware key offload;
P2P roles; wake offload is implemented in §3.6 (TLV + WOWLAN + RAW images;
net-detect implemented on the associated WoW path, disconnected
net-detect open) and awaits release/native validation;
DT/NVMEM calibration sources are implemented (nvmem-rmem provider only) and await native validation.
Automatic credential replay after recovery is implemented (§ recovery, rebind)
and awaits coordinated release/native acceptance.
The signed indoor installation continuation is implemented in §3.1 and awaits
coordinated release/native acceptance.
The native World-layer Beacon continuation is implemented in §3.2 and awaits
coordinated release/native acceptance; host and physical qualification remain
separate.
The bounded TLV legacy AP and source-qualified AP-side U-APSD owner is
implemented in §3.3, with ten new native cases written and unexecuted.
Coordinated release compilation, native suites and physical firmware/RF/board
acceptance remain pending. Other dialects/PFC/optional AP PHY and security
roles are refused rather than inferred from an AP-capable PCI identity.

Firmware-owned TX BA, the N-deep HTT pipeline and aggregate retry accounting
are implemented above, beside the bounded RX BA/reorder and RAW A-MSDU receiver. Unsupported role, width, stream,
or security capability remains closed; this ledger makes no per-chip RF or
board-power claim from a model or PCI ID.

Wider VHT geometry is enumerated from Linux `mac.c::ath10k_mac_get_phymode_vht`
and `ath10k_create_vht_cap`; each width depends on the base VHT row (VHT20/40
with actual SERVICE_READY `vht_cap_info`/`vht_supp_mcs`):
`vht80` is MODE_11AC_VHT80 (with `WMI_PEER_80MHZ`) on every reached 5-GHz VHT
image; `vht160` (MODE_11AC_VHT160, `WMI_PEER_160MHZ`) and `vht80p80`
(MODE_11AC_VHT80_80) require `vht_cap_info` SUPP_CHAN_WIDTH 160 or
160/80+80 and the `peer_bw_rxnss_override` NSS map bounded by the per-chip
`vht160_mcs_{rx,tx}_highest` in `core.c::ath10k_hw_params_list`, nonzero only
for QCA9984 (1560) and QCA9888 (780). Other reached tuples cannot claim 160 or
80+80 from a PCI ID. The new80+80 owner implements the second independent
occupied-power receipt and actual center2 as described in§3. Contiguous160
is implemented for ch36–64 and ch100–128 (§3 contiguous VHT160): the radar
half is admitted only by the station client's per-constituent Beacon witness
and the 5250 MHz rule boundary only by an AUTO_BW run or a direct 160 MHz
rule. The upper 149–177 span stays out: it extends beyond the current
admitted inventory and has no established per-board/factory/host authority
here. Release compilation of the new cases and native/physical validation
remain pending.

Physical acceptance still must validate exact PCI/BMI identity, trusted firmware
and board calibration, ROM/OTP/PLL/code-swap, native CE/HTC/WMI/HTT progress,
scan, Open/WPA2 and actual DHCP/IP with a real AP, idle/beacon liveness, link loss,
revocation and terminal teardown without DMA reuse. No such run is recorded.
An image lacking RAW support or a PFC image outside the explicit native
queue/peer/TID/request geometry above remains a diagnostic scan owner and must
not be counted as a usable station under this profile. The bounded RAW/PFC
continuation is source complete with six new cases written; release compilation,
native execution and actual-device interoperability are still pending.

The table and packages above remain open beyond the bounded R/H profiles. The
family is not feature-complete or physically qualified after this checkpoint.
