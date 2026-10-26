# ath10k — Specification

> Status: **Retained legacy/HT20 RAW station implemented; physical acceptance pending.**
> The live PCI task obtains BMI identity, selects trusted firmware/BDF,
> runs OTP calibration and downloads the image. It retains runtime CE DMA
> before BMI_DONE, negotiates HTC endpoints, handles firmware host-memory
> requests and completes WMI INIT/READY. Retained HTT RX/TX and a receive-only
> scan vdev follow, with policy-authorized directed/wildcard active discovery.
> Raw-capable non-PFC images can publish a retained legacy/HT20
> station interface with Open/WPA2, bounded native packet progress and terminal
> disconnect. Hardware-validation readiness is scoped to this exact profile.

## 1. Purpose & scope

PCIe Qualcomm/Atheros QCA988X, QCA6174/6164, QCA9377, QCA99X0, QCA9888
and QCA9984. AR9462 belongs to ath9k and is rejected before MMIO.
Linux `drivers/net/wireless/ath/ath10k/` is the reference implementation.

## 2. Assumptions

Probe owns the PCI function exclusively. BAR0 is mapped with device
attributes and must cover the selected RTC, core, PCI-local and CE
windows. Boot uses coherent DMA32 storage and keeps the target awake.
Boot messages are serialized and polled asynchronously. The initial native
packet service polls with CE interrupts masked; synchronous network drains
and the periodic worker drive the same bounded state without waiting on
another executor task. IRQ throughput and host-bus/system power transitions
remain separate profiles.

## 3. Public interface

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
  These metadata alone register no netdev; raw/non-PFC admission below follows
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
  The interface returns Busy for scans with a prepared/associated peer, without
  closing that live station or publishing scan commands.
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
- The retained RAW station additionally negotiates a native HT20/one-stream profile when
  SERVICE_READY reports HT and a valid RF-chain count, and the actual AP offer
  contains valid HT Capability/Operation and usable WMM. It retains MCS0..7,
  requires every basic MCS to fit that profile and binds HT Operation to the
  observed primary channel. SGI20 requires the actual firmware capability and
  both beacon/response support. A driver-owned HT IE advertises 20 MHz, one
  stream, SMPS disabled and no GF/STBC/LDPC; caller SME IEs cannot supply it.
  VDEV_START programs native 11NG/11NA HT20 plus ALLOW_HT, retaining the same
  20 MHz factory/host power receipt. The actual association response intersects
  MCS/SGI before native PEER_ASSOC carries HT/QoS, peer HT capabilities,
  maximum MPDU/density, RC flags, exact HT-rate arrays and HT20 phymode on all
  six dialects. TLV arrays have independent raw counts and padded lengths.
  Missing/incompatible HT response cannot open the peer or controlled port.
  Without firmware HT or usable AP WMM, the existing legacy path remains.
  Native RX admits HT/HT-TXBF preambles only for this confirmed profile and
  checks 20 MHz, supported MCS, non-greenfield and negotiated guard interval
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
  wider channels, more streams and VHT remain separate work.
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
  Native tests compose actual CE/WMI/HTT and referenced DMA with Open/WPA2,
  DHCP/IP on both bands/all dialects, response narrowing, absent/malformed
  capabilities, invalid RX geometry before PN, cancellation and policy loss.
- The single-vdev RAW station can negotiate WMM from an actual AP Parameter IE.
  It appends its own Information IE with U-APSD disabled; caller-supplied WMM
  cannot duplicate or replace that negotiation. The bound successful association
  response supplies the final contention values. Missing, duplicate, malformed
  or BE-admission-controlled response parameters fail before peer/data admission.
  Native per-dialect PDEV WMM records program BE/BK/VI/VO contention, converting
  IEEE TXOP32-us units to native microseconds; PEER_ASSOC carries the real QoS
  flag only after those transport receipts. This one-radio profile has no
  per-vdev concurrency and makes no firmware ACK claim for these commands.
  Ordinary Ethernet uses QoS BE/TID0 through actual RAW HTT metadata and the
  shared host CCMP formatter; EAPOL/key replies remain legacy non-QoS. RX binds
  QoS TID to the native descriptor before replay/PN commitment. BA/TX
  aggregation, TSPEC, U-APSD and non-BE transmit classification remain separate
  features. APs without WMM retain the legacy packet/command profile.
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
  country; a world factory identity is never promoted by host policy. Host
  occupied-channel power is additionally bounded by 20 dBm on 2 GHz and
  30 dBm on 5 GHz, while immutable factory pair/CTL and firmware calibration
  remain active. These bounds are ceilings, not measured board transmit power.
  Every overlapping host power/bandwidth/DFS restriction applies; 5-GHz
  indoor-only restrictions without authority, negative power, DFS, 6 GHz and
  beacon-hint-dependent channels stay closed. Native station/channel/peer
  records use 11A for 5 GHz and reject CCK there; 2 GHz retains 11G/11B.
  It programs immutable factory pair/CTL and additional half-dBm power limits,
  waits for a successful correlated VDEV_START_RESPONSE, creates the BSS
  peer and waits for native HTT peer-map confirmation. `PeerPrepared` reports
  the bound BSSID/frequency, sparse firmware peer ID and host power ceiling;
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
  No credentials, peer, keys, cached BSS or association are replayed. A successful
  new generation can be scanned/joined through its newly registered interface.
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
  successor. All old boot/firmware/WMI/management/HTT allocations remain pinned,
  even after successful reset scheduling: no posted-DMA drain, reclamation or
  RF-quiescence proof is claimed. The attempt limit bounds these retained DMA
  generations. This is manual replacement/rejoin support, not automatic recovery,
  stable-netdev reconnection, system suspend or reclaimed DMA. Physical reset,
  ROM/firmware restart and repeated RF association still need hardware acceptance.
- `pci::start_station_data(pmk)` starts the retained packet owner after native
  association, with `None` for Open or the caller's WPA2 PMK. It requires
  firmware `RAW_MODE_SUPPORT` (bit10), RAW RX selected during WMI INIT, and a
  non-PFC HTT profile. All six WMI resource layouts use their actual decap
  field; HTT disables transmit A-MSDU for Linux's raw-mode workaround. Other images
  retain native-WiFi RX and cannot enter this software-CCMP owner. Shared
  `station_security::Security` owns the supplicant, fallible nonce acquisition,
  software CCMP, per-key/TID replay, PN and retired-key history. M2/M4/group
  replies use native raw HTT with NO_ENCRYPT and retain their DMA payload and
  fragment owners after CE completion. Only the matching successful terminal
  HTT ID commits the pending security change. No hardware key receipt is
  fabricated. An early association-era M1 is preserved only after full native
  descriptor/peer/TID/header and unprotected-unicast EAPOL admission; all
  preauthorization IP is discarded. `StationLink { bssid, frequency, protected }`
  requires the live peer and current completed data authorization. Temporary GTK/PTK
  reply waits close the data port without flapping established physical carrier.
- `pci::transmit_ethernet(bytes)` submits one admitted Ethernet frame through
  this owner and returns its actual HTT publication ID. ToDS/RFC1042 and
  optional software CCMP preserve packet identity; externally supplied EAPOL
  stays closed. `pci::poll_ethernet()` drives the same HTC/HTT owner and returns
  Ethernet only after receive quiescence with a still-owned peer. Native v1
  descriptors and indications must agree on sparse peer, TID, DS, sequence,
  length, RAW decap and an unfragmented legacy/qualified HT20 MPDU. CRC errors,
  foreign identities, hardware-decrypted RX, PADDR offload/fragments and
  unowned A-MPDU/reorder profiles are excluded. Complete original RAW A-MSDUs
  use the bounded opt-in shared receiver described above. RAW FCS is stripped before CCMP verification;
  only authenticated, replay-checked data reaches RFC1042 decapsulation.
  Last-peer UNMAP, bound deauthentication, failed terminal TX, timeout,
  malformed state and cancellation close the retained radio. Disconnect
  closes security before awaiting firmware retirement. Their async diagnostic
  surface and the nonblocking network drain share the same packet parsing,
  peer events, terminal receipts and security state.
- `interface::Device` implements the registered legacy/HT20 station profile after
  calibrated boot, WMI/HTT/scan setup, RAW/non-PFC firmware admission, signed
  regulatory bootstrap and current network-registry capability admission.
  `boot_task` publishes the retained `SESSION` and `scan_ready` immediately after
  `initialize_radio`, then runs `interface::wait_publish` so RAW/non-PFC radios
  wait for missing `wireless-regulatory.bin`, loader authority or network
  registry authority without blocking passive-scan diagnostics; non-RAW/PFC
  images and invalid/unsigned regulatory policy fail immediately without waiting.
  `RadioSession` retains an `Arc<Mutex<Radio<PciBoot>>>` with the selected image
  and board profile; native PCI APIs and the Device share this single owner.
  The Device exposes passive/active scan and Open/WPA2-PSK/CCMP on configured
  channels1–11 and the admitted fixed-country non-DFS 5-GHz centres above,
  legacy/HT20 only. Unsupported scan options, PHY modes, external EAPOL and
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
- RAW/non-PFC images without firmware `NO_PS` expose an awake station
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
  enables neither U-APSD nor host-bus/system suspend or wake offload.
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
  without a scheduled worker. A masked-interrupt periodic poll also supplies
  idle RX/security progress. A five-second no-peer deadline is refreshed by
  bound BSS beacons or admitted native peer traffic; stale/replayed/forged
  CCMP cannot refresh it. Expiry closes the port and carrier while retaining
  uncertain CE/HTT DMA. The owner deliberately does not reset/reclaim firmware,
  preserve connectivity across suspend, or admit a second association.
- `profile::Profile::select(device, version)` binds the PCI device ID and
  exact BMI target version to Linux's PCI firmware directory, board sizes,
  OTP parameters and clock operation. The Ubiquiti ID and QCA6164 have
  separate exact entries; SDIO tuples are excluded. A QCA9887 tuple does
  not add a PCI match or runtime support for that part.
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
Full local Linux C management generators produce command goldens, including
padding and the 64-byte reference prefix. Composed runtime fixtures traverse
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
capabilities into each native PEER_ASSOC/VDEV_UP layout. Full unmodified Linux
C serializers generate 45 literal management/association fixtures, including
single-rate 11B/11G, an eleven-rate response downgrade and TLV padding. The
accompanying generator records native
source SHA-256 provenance and runs independently of Rust encoders. Retained
composition fixtures exercise actual CE3 source descriptor publication and
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

Physical acceptance still must validate exact PCI/BMI identity, trusted firmware
and board calibration, ROM/OTP/PLL/code-swap, native CE/HTC/WMI/HTT progress,
scan, Open/WPA2 and actual DHCP/IP with a real AP, idle/beacon liveness, link loss,
revocation and terminal teardown without DMA reuse. No such run is recorded.
An image lacking RAW support, or requiring PFC, remains a diagnostic scan owner
and must not be counted as a usable station under this profile.

Broader bands/widths, HT40/multiple streams/VHT/BA aggregation, PFC fetch/queue ownership, alternate
calibration sources, interrupt throughput, associated/off-channel scanning,
automatic/stable-interface recovery and host-bus/system power management remain
explicit later profiles. They
are not prerequisites for validating the bounded station profile above.
