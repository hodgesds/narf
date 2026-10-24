# ath10k — Specification

> Status: **ROM/HTC/WMI/HTT and passive scan implemented; WLAN software incomplete.**
> The live PCI task obtains BMI identity, selects trusted firmware/BDF,
> runs OTP calibration and downloads the image. It retains runtime CE DMA
> before BMI_DONE, negotiates HTC endpoints, handles firmware host-memory
> requests and completes WMI INIT/READY. Retained HTT RX/TX and a passive
> scan vdev follow. Retained legacy station association and an async
> raw/software-CCMP packet owner follow. The synchronous packet service and
> interface registration remain; this is not yet a NIC usable by DHCP.

## 1. Purpose & scope

PCIe Qualcomm/Atheros QCA988X, QCA6174/6164, QCA9377, QCA99X0, QCA9888
and QCA9984. AR9462 belongs to ath9k and is rejected before MMIO.
Linux `drivers/net/wireless/ath/ath10k/` is the reference implementation.

## 2. Assumptions

Probe owns the PCI function exclusively. BAR0 is mapped with device
attributes and must cover the selected RTC, core, PCI-local and CE
windows. Boot uses coherent DMA32 storage and keeps the target awake.
Boot messages are serialized and polled asynchronously; runtime IRQ and
packet service are not yet attached.

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
  No netdev is registered.
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
  context selected from the last successful passive-scan cache. It requires
  the installed authenticated host regulatory policy; initial geometry is
  legacy 20 MHz on channels 1–11 within firmware hardware limits. The strict
  initial factory-world 20 dBm ceiling and every overlapping host power,
  bandwidth and DFS restriction constrain it. Negative power, DFS, 5/6 GHz
  and beacon-hint-dependent channels stay closed in this profile.
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
  the checked negotiation and native peer/vdev commands. Keys, data admission
  and a NIC remain software work.
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
  Teardown sends no over-air deauthentication and makes no key, carrier, PM,
  DMA reclamation or rejoin claim. All six native WMI dialects are covered;
  only TLV advertises the extra synchronous delete service.
- `pci::start_station_data(pmk)` starts the retained packet owner after native
  association, with `None` for Open or the caller's WPA2 PMK. It requires
  firmware `RAW_MODE_SUPPORT` (bit10), RAW RX selected during WMI INIT, and a
  non-PFC HTT profile. All six WMI resource layouts use their actual decap
  field; HTT disables A-MSDU for Linux's raw-mode workaround. Other images
  retain native-WiFi RX and cannot enter this software-CCMP owner. Shared
  `station_security::Security` owns the supplicant, fallible nonce acquisition,
  software CCMP, per-key/TID replay, PN and retired-key history. M2/M4/group
  replies use native raw HTT with NO_ENCRYPT and retain their DMA payload and
  fragment owners after CE completion. Only the matching successful terminal
  HTT ID commits the pending security change. No hardware key receipt is
  fabricated. `StationLink { bssid, frequency, protected }` requires the live
  peer and controlled port; it publishes no netdev.
- `pci::transmit_ethernet(bytes)` submits one admitted Ethernet frame through
  this owner and returns its actual HTT publication ID. ToDS/RFC1042 and
  optional software CCMP preserve packet identity; externally supplied EAPOL
  stays closed. `pci::poll_ethernet()` drives the same HTC/HTT owner and returns
  Ethernet only after receive quiescence with a still-owned peer. Native v1
  descriptors and indications must agree on sparse peer, TID, DS, sequence,
  length, RAW decap and an unfragmented legacy standalone MPDU. CRC errors,
  foreign identities, hardware-decrypted RX, PADDR offload/fragments and
  aggregation are excluded. RAW FCS is stripped before CCMP verification;
  only authenticated, replay-checked data reaches RFC1042 decapsulation.
  Last-peer UNMAP, bound deauthentication, failed terminal TX, timeout,
  malformed state and cancellation close the retained radio. Disconnect
  closes security before awaiting firmware retirement. These APIs remain
  async: split-submit/nonblocking physical CE progress is still required
  before the synchronous network drain can run DHCP without another task.
- `profile::Profile::select(device, version)` binds the PCI device ID and
  exact BMI target version to Linux's PCI firmware directory, board sizes,
  OTP parameters and clock operation. The Ubiquiti ID and QCA6164 have
  separate exact entries; SDIO tuples are excluded. A QCA9887 tuple does
  not add a PCI match or runtime support for that part.
- `firmware::Image::{parse, load}` own the API 2–6 container and expose
  bounded image/OTP/code-swap slices, feature bits and WMI/HTT operation
  versions. `Files` supplies owned immutable bytes; production uses
  capability-authorized verified firmware-registry blobs. The highest
  present API is parsed; a malformed present blob fails explicitly.
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
Independent tests compile Linux's unmodified regulatory initialization over
all 65,536 EEPROM values and native WMI generators/packed channel structs for
all six supported dialects. Composed tests traverse actual scan/cache, host
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

Twenty-one further fixtures compile unmodified Linux VDEV_DOWN, PEER_DELETE
and VDEV_STOP generators together with packed STOPPED/delete-response events,
enum IDs, TLV tags and the synchronous-delete service bit. Native CE/HTC/WMI/
HTT composition checks all six dialects, ACK/UNMAP ordering and sparse/in-flight
IDs, wrong/malformed/missing receipts, stale prerequest events, duplicate UNMAP,
owned-ID rebinding and late MAP, native command errors/cancellation and bounded
progress floods. Original ring/firmware allocations remain retained in every
case, including success. These fixtures establish the terminal teardown
contract without radio or whole-device reset acceptance.

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
an independently compiled C layout oracle, resource-dependent memory sizes,
zero-unit skip, malformed ABI/count/extent handling and dropped INIT ownership.
HTC→WMI→HTT fixtures exercise actual retained RX/fragment/PFC storage, native
configuration and TX literals checked against independently compiled Linux
structures, major-2 management, terminal TX ownership, idle progress,
A-MSDU/chained RX, out-of-order PADDR ownership and malformed/duplicate batch
retention. The composed models are architecture-neutral; they do not emulate
a Qualcomm radio or establish reset/ROM interoperability. Composed scan
fixtures cover all six dialects through actual HTC/WMI/HTT, native vdev and
channel/scan commands checked against independently compiled Linux C
functions, production hardware-channel selection, two scans with distinct
IDs, stale/wrong-requestor responses, malformed beacons, management header
variants, concurrent terminal HTT completion and dropped/failed ownership.

## 8. Remaining software and hardware acceptance

The following are software work, not gates that a physical boot can close:

1. Alternate pre-cal/cal sources (file/DT/EEPROM), non-BMI images and diagnostic fast download are
   not implemented; the supported ROM path requires a valid OTP image and
   calibrated BDF. Missing board files currently fail the boot session.
2. Complete per-firmware-family feature/dialect operation tables and
   optional board/clock/UART quirks, with real firmware validation of the
   current OTP/BDF/PLL/code-swap path.
3. A retained station worker composing the native packet/event owner with
   complete WMI operation handling, higher-capacity CE service, HIF IRQ/MSI,
   recovery and full DMA/firmware PM/teardown. Terminal peer/vdev disconnect is
   implemented, but it does not reset or reclaim the retained hardware owner.
   HTT setup alone does not publish an interface.
4. Station/runtime WMI maps beyond scan, context preparation and initial
   legacy association;
   complete HTT peer/BA/security routing,
   PFC fetch/mode/host-queue handling, native packet conversion, RX security
   and replay/reorder policy. Existing standalone WMI/HTT codecs are not the
   production station implementation.
5. Extend the initial authenticated channels 1–11 factory/host context policy
   to all claimed bands and widths, beacon hints/DFS and complete station
   control, active/
   directed scan and richer scan options, complete management/EAPOL/key exchange,
   packet conversion, and `WirelessNetIface`/netdev registration.

After those are integrated, physical acceptance must exercise ROM/BMI,
board calibration, IRQ/DMA, scan, association, IP traffic, link loss and
reset/PM on each claimed family. Current bootstrap still needs silicon
validation; success in the offline suite does not remove the software
requirements above.
