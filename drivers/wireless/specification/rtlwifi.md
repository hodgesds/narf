# rtlwifi — Specification

> Status: retained RTL8188EE firmware, factory-qualified MAC/BB/RF/IQ/LC,
> signed channel/power, native polled station/packet/stop and Open/WPA2 device
> integration are implemented. Composed DHCP/IP and lifecycle regressions are
> retained. A separate RTL8188EE HT20/LGI continuation and15 new native tests
> pass native software suites and build gates. Board qualification and
> physical validation remain separate for every emitting profile.

## 1. Purpose & scope

Owns the retained RTL8188EE station and diagnostic detection of RTL8192CE/DE/EE,
RTL8723AE/BE and RTL8821AE. RTL8822BE belongs to rtw88 and is no longer matched here.

## 2. Assumptions

The caller owns the PCI function exclusively. Linux's per-chip `bar_id=2`
selects the register aperture. Diagnostic probe does not initialize packet
DMA, unmask device IRQs or report association success.

## 3. Public interface

**Software acceptance at `6813a24c6`.** The separately qualified RTL8188EE
`ht40`, `rts_cts_protection`, `rf_gain_tracking` and
`dynamic_antenna_selection` continuations pass the checkpoint release/native
gates on x86_64 and aarch64. Other chip runtimes, VHT, Bluetooth coexistence
and WoWLAN retain their separate remaining rows. This supersedes
implementation-time statements below that release/native execution or software
acceptance is pending, only for the named feature scopes. Physical
measurements, signed board/deployment programs and actual-device
RF/power/interoperability acceptance remain separate.

`pci::bring_up(device, cap)` first parks inherited PCI DMA through the shared
Realtek command policy: clear `BUS_MASTER`, enable `MEM_SPACE | INTX_DISABLE`,
and read back the command register. Any access failure, retained BME or missing
requested decoding fails before BAR mapping. Bus mastering remains disabled
through probe and the native worker's `MacConfigured` boundary; identity and
allocation alone do not authorize DMA. A repeat probe of the retained bus address
returns without configuration access; a distinct additional singleton match
parks only its own PCI function. Only the retained qualified packet owner below
has a one-shot transition that can enable BME.

`RtlwifiDevice::registers` is the mandatory BAR2 `map_bar_control` mapping;
it must cover through EFUSE access gate `0xcf`. Probe enables MEM decoding,
runs the profile power flow and reads factory identity with IRQs masked.
The mapping and actual power/IRQ/EFUSE operations execute inside the current
PCI `Cap::invoke` operation. The same invocation helper protects every native
firmware access; holding a retained token alone grants no register access.
MAC/LLT code is not dispatched as if a packet DMA owner already existed.

`efuse::read_mac(registers, pci_device_id, pci_function)` reads sparse physical
programming records and returns a nonzero unicast identity. The helper sets
read clocks, uses the appropriate access/power gate, triggers reads by clearing
bit 31, waits for it to set, allows data to settle and closes access on failure.
Programming LDOE25 is not enabled for a read.

| Profile | Unprotected physical bytes | Logical bytes | MAC offset |
|---|---:|---:|---:|
| 8188EE / 8192EE / 8723BE / 8821AE | 238 | 512 | `0xd0` |
| 8192CE and alternate ID | 497 | 128 | `0x16` |
| 8192DE function 0 / 1 | 497 | 256 | `0x55` / `0x5b` |
| 8723AE | 497 | 256 | `0x67` |

Unknown geometry/functions fail before I/O. Sparse-map bounds/overrides
share the checked Realtek record decoder. Only the retained qualified RTL8188EE
station below implements scan/association/data; other matched silicon remains
diagnostic and returns `NotSupported` for those operations.

`power::run_with(io, cut, fab, interface, table)` is the production-shared
byte-register parser: selected rows preserve unrelated fields, PCI rows use
MAC base, register failures stop at the exact transaction, and unknown commands,
invalid delay units or missing END fail. `power_on_with` selects the flow.
RTL8188EE uses the complete Linux PCI NIC-enable flow, including
CardDisabled→CardEmu, BB reset, Schmitt trigger and LDO-normal. It first performs
the Linux XCK-output/HWPDN/reserved-register-unlock prefix. Other parts still
require their complete reset/power qualification.

RTL8188EE probe retains `firmware_transport::Owner<firmware_native::PciIo>`
before spawning `initialize_registered()`. `RtlwifiDevice::firmware_status()`
returns the shared attempt state; other profiles return None. Registry selection
uses exactly `rtlwifi/rtl8188efw.bin`, authenticated through firmware authority.
Registry lookup and bounded image copying run inside actual current registry/blob
`Cap::invoke`; only owned bytes reach the image parser or an awaited uploader.
The complete 32-byte header, exact nonempty declared RAM-code length, 88E1
signature and at most eight 4096-byte pages are checked before native DMA
allocation or register I/O. The measured board-envelope loader uses the same
current lookup/copy boundary and still requires a verified signer; executable
signature policy remains the firmware registry/build contract.
The EE filename remains mandatory because the signature alone cannot distinguish
USB EU firmware. Supplied-byte `initialize` is for authenticated owners/tests.
Registered-source resolution, owned copy and complete header parsing precede the
atomic attempt claim. Missing/revoked/invalid inputs leave the same Detected owner
retryable without MMIO; genuinely begun owners return AlreadyStarted before
resolving any new source. Real signed-registry fixtures cover denial followed by
valid restaging and the unchanged one-shot hardware boundary.
`pci::provision().await` exposes that bounded retry for the existing native
controller while its firmware is Detected or Ready (resuming from `RadioConfigured`
or `ChannelConfigured` checkpoints when policy or calibration arrives). Probe's worker drives
background provisioning via `drive_scheduled` across 120 attempts with 500 ms intervals.
It clones the original firmware/Prepared/factory Arcs under
CONTROLLER, releases the IRQ-safe lock before awaiting, and calls the existing
native initializer; it never reconstructs ownership or resets/replays a begun
attempt. Cancellation while waiting for the regular async admission mutex
changes no owner state. Absent/non-EE controllers fail admission.
The private native admission fixture checks exact Arc identity, cancelled wait
and real one-shot Failed-owner denial with revoked, unreachable hardware.

The one-shot owner closes CR HCI/TX/RX DMA and MAC packet gates and verifies
readback, enables the CPU clock, performs 8051 reset when replacing a running
image, writes selected 4KiB pages at MMIO0x1000 in bounded byte chunks, pads the
final dword and awaits fresh checksum plus firmware WINTINI readiness. It checks
reserved page-selector/CPU bits and stops on absent device, stale authority,
active BME or a short BAR. Every real MMIO operation occurs inside Cap::invoke
and validates MEM decoding with BME disabled. No raw authority/handle escapes.

States are Detected, Validated, Preparing, Downloading, Ready and terminal
Failed(error). The bounded attempt is self-driven/async, holds no IRQ-disabling
guard across await, and never invokes block_on in a spawned task. Cancellation,
timeout or write/checksum/start failure prevents retry and performs no cleanup
I/O. Ready means a running firmware CPU, with packet DMA/IRQ/station admission
still closed. The one-shot native continuation below admits only its exact EE
mailbox and the separately admitted station profiles below; firmware readiness
does not advertise HT/VHT support.
Firmware CPU readiness alone leaves the interface down.

`prepare::Prepared<I, M>` is the RTL8188EE-only inactive descriptor/LLT owner.
It validates DMA32 full extents, alignment and overlap before MMIO, constructs
seven distinct linked 64-byte TX rings (DW10 next pointers, all OWN clear),
one 32-byte RX ring and separately retained9100-byte RX buffers (DW6 address,
OWN/EOR). Exact Linux `_rtl88ee_llt_table_init` uses boundary0xab/max-page0xaf;
all seven queue bases and RX base use the 8188EE register map: BCN308, HIGH310,
MGMT318, VO320, VI328, BE330, BK338 and RX340. The retained owner uses explicit
EE-only constants, independent of the inactive generic8192EE scaffolds.
Fixed Rust EE-specific register vectors record the documented publication
order; the native device model checks those addresses and register widths. The former8192EE base publication is a rejected packet-admission
regression. No 8192EE TXBD
count registers or aliased queue bases are used. BME stays off, PCIe DMA byte
0x301 stays0xff, CR packet gates and both interrupt masks remain closed.

The private `prepare_native` adapter claims one non-cloneable `PacketIo` from
the exact successful firmware owner. Failed allocation, cancellation and Drop
never reopen that claim. Every actual allocation/register access uses current
PCI authority and verifies parked bus mastering; unsupported per-domain IOMMU
mode is rejected. The controller and diagnostic interface share an async
mutex that retains the complete native owner before its first base write.
`RtlwifiDevice::native_preparation_status()` reports the retained Allocated,
Prepared, RadioConfigured, ChannelConfigured, MacConfigured or terminal Failed
state; the packet core additionally has Running/Stopping/Stopped phases.
None covers unallocated state (including allocation
failure) or initialization holding the async guard. Cancellation installs Failed before awaiting LLT. Published mappings
are retained on every error/Drop until the card-disable quiescence proof
(`Prepared::quiesce`, below) succeeds; no
firmware/reset helper may reconstruct a second packet owner.

`initialize_registered` now composes authenticated firmware boot with that
retained inactive preparation in the real probe worker, then continues through
`Prepared::configure_radio(profile)` under the same retained async owner.
`efuse::Factory` retains the complete decoded logical map alongside its validated
MAC. The radio profile checks EEPROM8129/VID10ec/DID8179 and applies Linux's
HP197d RF52 override only for default-customer103c:197d factory identity.
Other silicon is not dispatched through this continuation.

The radio continuation loads all90 MAC,191 BB,128 AGC and95 RF table rows,
including exact50ms RF settling intervals, and retains all88 PG triples for
the later channel-power owner. It uses 8-bit-address/20-bit LSSI and the actual
HSSI edge/readback protocol, with 10/120us waits and PI/SI register selection.
The previous unused family scaffolds do not supply any of these operations.
The factory antenna type and HP identity select Linux's static MAIN/AUX path
before IQK; dynamic antenna selection is outside this fixed measured profile.
Single-path IQK backs up and restores MAC/ADDA/BB state, performs bounded TX
and RX retries over up to three samples, compares Linux's tolerance and fallback
candidates, applies the signed TX/RX matrix and retains recovery registers.
Missing/unstable TX or RX measurements fail rather than reporting calibrated
hardware through Linux's TX-only/default fallback. LCK follows Linux's paused
or continuous-TX sequence and its100ms calibration interval; elapsed time alone
does not establish physical oscillator convergence.

The one-shot transition installs terminal Failed before its first await and
commits `RadioConfigured` plus `radio_report()` only after all operations and
final parked-gate checks succeed. Every native register still executes under
current PCI authority with BME off. PCIe DMA0x301 staysff, CR packet gates and
both interrupt masks stay closed; error, cancellation and Drop retain all
published mappings. Repeated configuration does no I/O. Native Rust tests compare the register/RF owner with fixed source-cited
write/delay reference traces, signed matrix, HP variant, factory negatives,
transaction failures and cancellation at RF/IQK/LCK waits.

`RadioConfigured` remains below full MAC operational configuration, active
packet ownership and station admission. It cannot scan, transmit ordinary
packets, associate or raise carrier. Physical table/calibration acceptance
remains unvalidated.

`Prepared::configure_channel(permission)` continues the retained owner through
the initial legacy1T20 profile on channels1–11. PathA factory gains come from
all six CCK bases, five BW40 bases and signed OFDM nibbles; per-rate PG groups
follow the EEPROM regulatory mode. Erased gains or signed arithmetic outside
the hardware range fail before I/O instead of selecting defaults or wrapping.
There are 192 fixed Rust numeric EFUSE/PG reference cases.
The driver does not use Linux's scan turbo, HT rates or thermal gain boosts.

Raw gain indices and Linux's index-to-dBm reporting estimate do not establish
an EIRP bound. `channel_power::Calibration::load_registered` reads exactly
`rtlwifi/rtl8188ee-cal-v1-<factory-mac-as-12-hex-digits>.bin` through current
firmware capability invocation and requires an authenticated signer. The
artifact qualifies the complete board operating envelope for fixed legacy20,
1T1R, continuously awake software-crypto operation without gain tracking.
It binds VID10ec/DID8179, the MAC and SHA256(MAC || full512-byte decoded EFUSE
map), including channel-plan, power, antenna and thermal identity. EU/other-bus
artifacts cannot supply this permission.

The NEPC v1 blob has a96-byte little-endian header: magic[4], version:u16,
header-size:u16, total-size:u32, VID:u16, DID:u16, factory-digest[32], MAC[6],
reserved[2], nonnegative antenna upper bound:i16 in quarter-dBi, qualified
EIRP upper bound:i16 in quarter-dBm, row-count:u16, profile:u16=1 and reserved[32].
Each260-byte row contains channel:u8, reserved[3], and64 signed quarter-dBm
conducted upper bounds for each CCK and OFDM gain index. Unknown bounds are
INT16_MAX; channels must be strictly increasing and within1–11. These are
measured conservative upper envelopes across the qualified operating range,
not curves inferred from factory indices or another chip.

Each final rate gain is bounded by the exact factory/PG result, the matching
measured envelope plus antenna gain, the artifact EIRP ceiling and every
overlapping signed host rule, with an independent20dBm ceiling from Linux's
`RTL819x_2GHZ_CH01_11` shared by every retained channel-plan/world mapping.
Neither a board signer nor a more permissive host rule raises that bound.
Partial-span, unsupported flags, absent curves
or an uncovered channel deny TX permission. The opaque permission binds the
same retained radio report's full factory identity. A mismatched grant does
no device access; accepted programming installs terminal Failed before await.
Actual CCK/OFDM gains, MAC/BB20MHz and RF18 channel are read back before
`ChannelConfigured` is committed. MCS slots are zero and no HT packet profile
is admitted. TX remains paused, BME/PCIe DMA/CR packet gates and IRQ masks
stay closed. Missing staged calibration/policy leaves the native worker's
radio owner retained and without channel/transmit admission. Initial worker
qualification selects channel1; later station control must obtain its own
matching channel permission. Cancellation/failure never commits a permission
or reuses the uncertain owner.

`Prepared::configure_mac(factory)` checks the same opaque factory identity and
continues `ChannelConfigured` to `MacConfigured` without opening packet gates.
It supplies the remaining operational clock/watchdog/queue/MAC prefix, exact
legacy receive/transmit configuration, legacy response rates and factory MAC.
Host sequence numbers, software crypto and no early-mode prefix are explicit;
CAM encryption/decryption and both interrupt masks stay disabled. Readbacks
qualify all stable configuration fields. Linux's `efuse_read_1byte(0x1fa)`
PA-bias call is guarded by this chip's256-byte physical geometry and returns
ff without I/O, so no out-of-range/protected-tail read or bias write is invented.
The real probe worker reaches this boundary after signed board/channel policy.

`prepare::packet` extends that same retained owner, rings and unique `PacketIo`.
Its crate-private `start_packets` validates actual retained descriptor links,
DMA32 addresses, base registers, RX postings and operational MAC readbacks before
the one-shot current-capability BME transition and CR/PCIe DMA opening. Device
IRQs stay masked. The retained station service below drives this bounded
polling transport; transport readiness alone leaves carrier down.

Management and legacy data use distinct retained rings. Negotiated WMM adds
QoS data TID0..7 on the BK/BE/VI/VO rings selected by `ieee802_1d_to_ac`.
Linux queue IDs BK0/BE1/VI2/VO3/MGNT6 supply doorbell bits1/2/4/8/64;
allocation-vector indices5/4/3/2/1 never substitute those IDs. One pending native payload is retained before OWN
publication, along with its exact queue, slot, serial, length and address.
The host copies through the actual retained DMA mapping and preserves DW10's
linked-next pointer. Terminal OWN clear is checked against stable descriptor
identity, and the delivery carries bytes read from that retained payload.
This is terminal host/DMA delivery, not an AP acknowledgement. Fixed Rust packet/reference vectors describe descriptor fields and polling
contracts; the native device model reacts to actual published descriptors/body, including ring
wrap. It does not complete from a saved encoder/source byte vector.

RX reads OWN-cleared32-byte descriptors, checks retained DW6 address/high-word,
EOR, complete length/driver-info/shift extents and current fixed channel.
The baseline legacy profile rejects CRC/ICV, fragments, aggregates, HT/40MHz
and non-normal report types; the separately admitted HT profile below extends
only its checked HT20/LGI and whole-original A-MSDU cases.
Protected MPDUs require the native SWDEC bit; open frames may legitimately
have it clear. It retains original MPDU bytes for shared station security,
removes the four appended FCS bytes and reposts the same owned buffer only
after processing/copy and device barriers. Malformed ownership/address/extent
data is terminal. Invalid ordinary packet profiles are consumed without
admitting bytes to management or security.

`wait_delivery` installs terminal Failed before its first actual wait; timeout,
cancellation, stale PCI authority or descriptor rebinding cannot reopen TX or
release pending DMA. `stop_packets` closes host admission first, attempts all
independent IRQ/TX-pause/CR/PCIe-DMA/BME gates and verifies the accessible
readbacks. Success commits terminal `Stopped`, with no reuse/restart. Every
published ring/RX buffer and pending payload remains retained on stop, failure,
cancellation and Drop: parked BME is not claimed as a prefetch-quiescence or
reclamation proof; only a later successful `Prepared::quiesce` (TX buffer
empty and RXDMA idle) releases them. The next station facade must invoke this terminal stop on
all association/disconnect/error paths; transport readiness alone raises no
carrier or controlled port.

`interface::Device` is the single shared native RTL8188EE view used by the
controller, wireless registry and real Ethernet stack. It retains the same async
`Prepared` storage installed before the probe worker publishes any ring address;
it preserves that owner for a live generation; verified recovery replaces the
retained slot with a fresh owner. Current net authority
is required before production publication admits station DMA. Only
the selected qualified channel in1–11, legacy20/1T or the separately qualified
HT20/LGI profile below under its exact channel qualification,
mandatory basic1Mbps, software crypto and one peer at a time are admitted.
MSI drives the native owner when available, with polling fallback;
a bounded synchronous drain serves the real stack even while a synchronous
DHCP caller prevents other executor tasks from running. Both native-owner and
endpoint-state mutexes are released before stack dispatch/reentrant ARP/ND TX.
Missing signed board calibration or staged host policy can be retried from the
retained parked radio/MAC boundary; a dirty/cancelled generation requires
fresh-owner recovery before retry.
The existing public scan/associate facade invokes `Device::ready` before arming
station cancellation. From RadioConfigured/ChannelConfigured it reloads the
signed envelope/current domain, continues channel/MAC setup and stages station
calibration on that same retained Prepared owner. It performs no firmware reset,
owner reconstruction itself; explicit fresh-generation recovery is separate.

Public scan validates channel/frequency, filters and bounded dwell;
beacons/probe responses come only from actual consumed native RX descriptors.
Shared `association::observe` checks raw admission, addresses, ESS/interval,
singleton IEs, rates and DS/current-channel agreement; EE additionally requires
the actual qualified channel/basic1Mbps. Signal is unknown instead of invented RSSI. Active
software scans now send actual broadcast Probe Requests on the qualified
channel, one per requested SSID (up to mac80211's ordinary four; empty means
wildcard), through the owned MGNT ring at basic1Mbps. Their rates and optional
HT capability come from the retained current profile. No AP operation IEs or
unqualified rate/power facts are advertised. Each probe requires actual native
TX descriptor retirement before the bounded receive dwell begins; broadcast
frames imply no peer ACK. Probe responses enter the same raw RX/BSS path.
Cancellation and source loss close this generation and retain uncertain DMA.
Four native composed scan cases cover Open/WPA2 conversations, literal probe
and descriptor bytes, held completion/cancellation and prevalidation without
radio mutation. All four active-probe cases pass on both architectures at
`73b90b62d`. A single-channel request can select a qualified channel1–11
through the fresh-owner transition below. Multi-channel dwell aggregation is
implemented pending its own native acceptance below; broader qualified
HT/fallback profiles remain separate work (randomized scan addresses are
source-inapplicable, section 8). Without the distinct HT record,
HT/VHT/HE/EHT remain unselected; VHT/HE/EHT are never admitted by this EE path.

`prepare::station` retains the immutable observed BSS, shared `JoinPlan`, PMK,
shared `station_security::Security`, exact pending TX ID/bytes, monotonic
deadlines and key history beside the native DMA/mailbox owner. Actual Open
authentication and association responses must complete MLME; software flags
never substitute for peer frames. Negotiated rates and peer capabilities set
real RRSR/INIRTS, preamble, slot/SIFS and initial non-QoS DCF BE registers. CAM is reset
and software crypto remains selected. Current signed domain/board permission
and physical radio switch are checked before progress/submission; a changed
permission is terminal for the already configured channel.

Before MLME, the service toggles RPWM awake and consumes H2C20 active mode
`[0,0x10,5,0,0x0c]`. After association it installs peer/AID/media filters, consumes
H2C3 keepalive and follows Linux's reserved-page/JOIN continuation: enable
software beacon access, clear stale BCN_VALID, publish the owned768-byte body
on the actual BCN ring, consume H2C0 page locations, await fresh BCN_VALID,
restore beacon/TXQ/CR gates, then consume H2C1 media connected. HMETFR uses
four rotating boxes and actual byte lanes, extension before inline; only
demonstrated command IDs/body lengths are accepted. Command cancellation, stale
authority, radio-off, timeout or readback failure installs terminal failure
before awaiting. The reserved body stays retained for the firmware claim;
beacon OWN clearing is not invented as its receipt. Native Rust tests check fixed mailbox/reserved-body/command-descriptor vectors
and actual model MMIO/DMA, rather than comparing caller source buffers.

WPA2-PSK/CCMP supplies original AP RSNE/RSNXE and fallible fresh entropy to
shared RSNA/software CCMP. M4 must reach the exact terminal host receipt with
both native ID and bytes matching the retained security reply before keys,
controlled port and carrier open. AP authorization or different same-length
DMA bytes are insufficient. Established carrier survives a temporary rekey
reply gate; new data waits for the native reply. No extra AP/on-air ACK is
required beyond the demonstrated vendor terminal host receipt. Narf-Ring
clients cannot inject EAPOL, spoof factory source or request
checksum/TSO/VLAN offloads, which no rtlwifi chip provides (see section 8).

RX security uses original native MPDUs and actual descriptor software-decrypt
metadata; exact authenticated Ethernet reaches both the real RX Narf-Ring and
stack. A consumed invalid/report descriptor is distinguished from true OWN-idle,
so queued peer loss/failure is processed before carrier or received data escapes.
An environment-owned admission flag and publication lock serialize close with
all bounded packet-start, ordinary MLME/data and reserved-beacon DMA publication.
Async CAM/mailbox continuation checks closure after waits; no publication guard
survives an await. Disconnect closes host publication before waiting for the retained owner,
fences an already-entered stale carrier publisher, consumes H2C1 disconnected,
clears peer registers and terminally closes packet gates. Cancellation,
deadline, policy/capability/radio failure or peer loss closes keys and carrier,
discards host TX and retains native DMA. No reset/reclaim or second-association
recovery is promised.

Composed Device fixtures boot the production paged firmware owner, consume its
unique `PacketIo`, run retained radio/channel/MAC and native MLME/security, then
use actual kernel DHCP and exact bidirectional Ethernet/IP. A reactive shared
AP/DHCP server reads only published DMA descriptors/bodies. Dedicated smokes
cover Open/WPA2, held/modified M4, direct IPC metadata, current policy,
report/deauth bursts, rekey and disconnect/pending-DMA/old-publisher failures.
Inert MMIO/DMA/AP and private signed-envelope fixtures establish software
composition, not authenticated firmware execution on silicon or RF/power
measurement. Physical operation still requires exact signed EE firmware,
canonical signed regulatory policy and a measured matching NEPC board envelope.

Physical carrier/peer publication does not change operator `IFF_UP` and never
invokes administrative open/stop hooks while retained driver state is locked.
Explicit registration, operator up/down and autoconnect remain administrative
events. Disconnect/failure clears carrier and peer identity while preserving an
operator-UP interface; a later physical carrier sample cannot undo operator DOWN.

### Negotiated RTL8188EE WMM (all ACs/TIDs)

The retained EE station automatically offers its own WMM Information IE when
the scanned AP has one valid shared `narf_wireless::wmm` Parameter element.
The common management plan must first bind the actual association response;
that response must then contain valid WMM parameters. Missing, duplicate,
malformed or BE admission-controlled parameters fail the attempt before QoS
admission. An AP cannot upgrade a legacy request through an unsolicited IE.
This WMM continuation enables no HT, BA, U-APSD or TSPEC. Host priority
classification and all-AC routing are described below; the distinct HT
continuation reuses the same AC owner.

Source `rtl_get_hal_edca_param` programs BE/BK/VI/VO at0x508/50c/504/500 with
TXOP in32us units, ECW exponents and SIFS10 plus AIFSN times the actual negotiated
9/20us slot. All rows are checked before writes, including the8-bit AIFS bound;
every write is read back. BE uses AIFSN>=3, ECWmin>=5, ECWmax>=10 and TXOP0;
BK/VI/VO use the AP rows unchanged. REG_ACMHWCTRL AC bits stay clear: source
`HW_VAR_ACM_CTRL` reads only `mac->ac[0]` (BE) ACM, which this profile refuses. The signed NEPC gain/response envelope
still constrains the same1T legacy PHY/rates; WMM changes no gain, channel,
antenna, response-rate or RF calibration authority. Calibration now retains
the exact authenticated source cap, rechecks it when deriving permission and
encloses the actual EDCA operation in that current invocation.
The native live environment consumes only the currently installed policy;
signed-policy bootstrap belongs to explicit preparation. Clearing that
installation closes TX and the station. Explicit reinstall cannot revive
an attempt that already observed the absence.

Only successful response binding and native EDCA readbacks admit the packet
owner's QoS bit. TXD4.QOS and a26-byte MPDU header carry the classified TID;
software CCMP authenticates that header (and nonce priority) before publication.
EAPOL keeps its existing driver-owned non-QoS TX path; RX admits checked
ordinary QoS headers and shared per-key/TID replay. Live AP parameter changes
follow the dynamic-EDCA rules below. Four native Rust smokes cover literal EDCA/TXD fields, real
Open/WPA2 DMA and exact bidirectional data, malformed/downgraded responses,
ignored register writes, actual signed/device epoch loss, isolated installed-policy
clear/reinstall, retained mappings and cancelled M4. Physical WMM/RF acceptance
remains unrecorded; broader HT profiles remain separate work. Operating reset,
system suspend and inactive power save are implemented and software-validated below.

#### Traffic classification and all-AC/TID routing (implemented)

`station.rs::send_station_ethernet` classifies each Ethernet frame with the
upstream `cfg80211_classify8021d(skb, NULL)` rules (IPv4/IPv6 DSCP via RFC 8325
section 4 exceptions, MPLS TC, 802.21 = 7; reused from
`ath11k::tx_hdr::classify8021d`) and then applies mac80211
`ieee80211_downgrade_queue`: while the AP's ACM bit covers the TID's AC the
priority walks VO->VI->BE->BK, BK being terminal (`wmm.rs::priority`). NARF
holds no TSPEC, so no ACM AC is ever admitted. The TID is placed in the QoS
control before software CCMP, so it is also the CCMP nonce priority. Open
frames use a per-TID SN space (`qos_sequence`); CCMP frames use shared
`Security`'s per-TID counters.

`packet.rs::queue` accepts QoS DATA TID0..7 with normal ACK and no
EOSP/A-MSDU/TXOP bits, maps `ieee802_1d_to_ac` onto the EE linked rings
(`access_category_queue`: BK REG_BKQ_DESA, BE REG_BEQ_DESA, VI REG_VIQ_DESA, VO
REG_VOQ_DESA) and rings REG_PCIE_CTRL BIT(hw_queue) for BK0/BE1/VI2/VO3 as
`rtl88ee_tx_polling` does. TXD1 QSEL is `skb->priority` (the TID), matching
`_rtl88ee_map_hwqueue_to_fwqueue`; non-QoS DATA uses BE/QSEL0.
`firmware_native.rs::packet_kick` admits exactly those doorbells plus BEACON4
and MGNT6. The single-outstanding-frame receipt rule spans all rings.
Smoke `smoke_rtl8188ee_wmm_classifies_dscp_to_all_tids_and_access_category_rings`
(Open and WPA2) checks every AC ring, QSEL, doorbell, per-TID SN, CCMP priority
at the fixture AP and ACM downgrade VO->VI and VO+VI->BE.

#### Dynamic EDCA (implemented)

mac80211 `ieee80211_sta_wmm_params` re-applies EDCA only when a beacon from
the bound AP carries a different WMM Parameter Set Count; `drv_conf_tx` then
reaches rtl88ee `set_qos`. `station.rs::update_station_edca` follows that: an
unchanged count is ignored, a new count re-admits all four rows before the
first write, programs/reads back 0x508/50c/504/500 inside the same retained
calibration (or HT grant) invocation and installs the new parameters for
later classification. Missing WMM or an inadmissible set (e.g. BE ACM) is
terminal before any EDCA write. Smoke
`smoke_rtl8188ee_wmm_beacon_parameter_set_count_updates_live_edca` covers the
ignored same-count beacon, a live update, data after it and terminal refusal.

### Response-bound legacy data rates

Within the legacy profile, ordinary DATA selects the fastest physically ordered rate in the actual
association response/request intersection:54,48,36,24,18,12,11,9,6,5.5,2,1Mbps.
IEEE bit order is not throughput order: CCK11Mbps outranks OFDM9/6Mbps. The
retained EE submit path programs actual TXD5 rate0..11 with USE_RATE and
DISDATAFB; management, association and EAPOL retain CCK1. Basic1Mbps remains
required for those transmissions. Signed NEPC class envelopes already cover
all four CCK and all eight OFDM rates; each selected rate keeps its checked
factory/PG gain and current power/source admission. The submit path is the
highest rate (`rtl_get_tcb_desc` hw_rate); once the firmware owns an RA mask
(below) and a separately signed NEFB grant is current, ordinary DATA may
fall back to lower rates of that same mask. No
additional response rate is inferred. The operational MAC also programs Linux's station
`rtl_op_add_interface` `HW_VAR_RETRY_LIMIT`: `REG_RL` (0x42a) = short 0x30
[15:8] | long 0x30 [7:0] with readback (`packet_mac::configure`), so the
firmware RA/NEFB fallback chain runs on Linux's retry limits rather than the
reset values (closes `adaptive_retry_control`).
The exact retained signed calibration invocation encloses allocation,
descriptor/body publication and doorbell, with fresh host policy inside it.

One composed native smoke exercises every literal descriptor rate in Open
and WPA2, AP response narrowing, the all12-rate offer, actual QoS/CCMP bytes,
current signed/PCI loss and retained mappings. The existing actual held-M4
cancellation test now negotiates this richer offer before terminal closure.

### Separately qualified RTL8188EE HT20/LGI station

`RtlwifiDevice::ht20_request()` returns the optional program's filename and
binding after resolving the current exact legacy NEPC record and the actual
ready executable identity. It supplies no
measured gain or radio permission. The original v2 continuation applies only to
`10ec:8179`, channel1/2412MHz, one TX/RX stream, mandatory MCS0–7, LGI+SGI20,
response-bound WMM (classified TID0..7 on its AC ring) and Open or WPA2-PSK/software CCMP. It adds no
HT40, LDPC/STBC, RTS/CTS protection, extra AC,
antenna tracking, PM or restart. Other matched chips cannot enter it.

The optional signed file is
`rtlwifi/rtl8188ee-ht20-v2-<factory-MAC-as-12-hex-digits>.bin`.
`ht::Grant` retains both the actual new firmware capability and the same
`Arc<Calibration>` as the native station. Its binding includes the full
factory identity, SHA256 of the exact preceding NEPC bytes and the digest of
the actual uploaded `rtl8188efw.bin` image, plus the
reviewed HT gain/register/timing/descriptor/control/receive program. Neither
another NEPC record for the same MAC nor the old legacy record authorizes it.
The same firmware owner retains the exact registry source capability after
upload; every actual HT operation and publication invokes that source as well
as both calibration authorities again. Supplied-image/current-cap-free inputs
remain private inert fixture coverage and cannot grant production HT. The new signed
qualification must cover the full static antenna/IQK/LCK, supply and raw
thermal0–63 operating envelope without gain tracking, all preceding legacy
emissions, automatic MAC responses, declined ADDBA controls and the eight
MCS conducted upper envelopes. No measured curve, thermal sample, calibration
completion or silicon acceptance is supplied by the implementation.

The NEHT record is1184 bytes, little endian except byte arrays:

| Offset | Field |
|---|---|
|0 | magic `NEHT` |
|4 | version:u16=2, header-size:u16=160 |
|8 | total-size:u32=1184 |
|12 | VID:u16=10ec, DID:u16=8179 |
|16 | exact program/request binding[32] |
|48 | full factory identity[32] |
|80 | exact preceding NEPC digest[32] |
|112 | factory MAC[6] |
|118 | channel1, width20, NSS1, GI-mode1 (LGI+SGI20), reserved[2]=0 |
|124 | antenna upper bound:i16 in quarter-dBi, at least the preceding bound |
|126 | EIRP ceiling:i16 in quarter-dBm, no higher than20dBm |
|128 | reserved[32]=0 |
|160 | eight MCS rows, each64 signed quarter-dBm conducted upper bounds |

INT16_MAX marks an unknown bound. Every selected index requires an actual
known bound; erased factory inputs and negative/out-of-range signed gain
arithmetic are refused. Each final MCS gain is the highest index no larger
than its exact factory/PG maximum whose conducted bound plus antenna fits
the signed program, preceding NEPC, factory20dBm and all current host limits.
Every v2 MCS bound covers both LGI and SGI20, including retry, automatic
response and mode-transient peaks. The same combined ceiling also checks
every already-programmed CCK/OFDM gain;
a narrower HT record cannot ignore earlier emissions or silently retune them.

The genuine parked lifecycle is explicit. After legacy channel/MAC preparation
and calibration staging, `Device::ready` resolves the optional HT source while
the same owner is still `MacConfigured`/`Dormant`, before awake/start opens
packet gates. Only an absent optional record retains legacy operation.
Malformed, unsigned, mismatched, unknown-curve or revoked inputs are rejected
before HT writes and leave the parked owner retryable. Programming installs
terminal failure before its first register write and commits only after exact
readbacks. A running legacy owner cannot reload this profile or call the parked
channel configurator; the retained fresh-generation reset path below replaces
that running owner before reconfiguration and requires fresh association.

Linux `rtl8188ee/hw.c::read_power_value_fromprom` selects the signed high nibble
of EFUSE0x1b for HT20; `phy.c::handle_path_a` adds it to the BW40 base.
`rf.c::_rtl88e_get_txpower_writeval_by_regulatory` and the retained PG triples
bound the exact pathA/ch1 per-rate result. `ht.rs` programs/readbacks
MCS0–3 at0xe10 and MCS4–7 at0xe14, with unused2SS registers0xe18/0xe1c still0.
The existing RF18, BB800/900 and BW60320MHz owner is preserved. Native HT
response SIFS registers use14µs, as in `rtl88ee_update_channel_access_setting`;
the distinct `rtl_get_hal_edca_param(N_24G)` AIFS formula is16+9*AIFSN.
All EDCA rows are validated before writing; TXOP exceeds no native11-bit bound,
and the same conservative BE clamp/no-TXOP policy is retained.

Scan and join use shared typed `LocalHt::siso20(true,true).with_rx_amsdu_7935(true)`,
`observe_with_phy` and `JoinPlan::prepare_with_phy`. The driver owns the HT
Capability and WMM Information IEs. The complete actual response must remain
bound to the original offer, current primary and selected20MHz geometry;
unsupported protection modes and malformed/missing/duplicate selected elements
cannot open the native profile. An unsolicited response cannot upgrade an
unqualified legacy request. Only the ready optional profile supplies public
HT capability metadata; its hardware promise includes RX/TX MCS0–7 and the
7935-byte A-MSDU receive capability (`HT_CAP_MAX_AMSDU`, bit11).

Actual DATA TX chooses a negotiated MCS using native TXD5 rates0x0c–0x13,
with negotiated GI, BW0, subcarrier0, USE_RATE/DISFB and the classified-TID QoS header
formed before software CCMP. AGG remains0. Management, EAPOL and declined BA
controls retain the exact legacy1Mbps path and terminal OWN/body receipt;
no AP ACK or new C2H receipt is fabricated. Linux `rtl88ee_tx_fill_desc`
uses TXD5 bit6 for SGI only when the rate is greater than MCS0; the native
sender preserves that MCS0 LGI case. Actual peer SGI20 reception in both
offer and response gates MCS1–7 SGI, and the native RA_MASK command records
the same negotiated fact. SGI DATA retains DISFB: the separate NEFB v1
qualification does not authorize mixed-GI fallback retries. The NEHT v2
recipe requires every per-MCS conducted bound to cover both LGI and SGI,
including automatic responses, BA and transients. Awake, CAM and reserved
page/JOIN futures recheck the current exact signed sources and policy on
every poll, including a resumed native mailbox wait.

Native RX checks the actual EE RXD HT/rate/GF/short/BW and QoS/header facts
before security. Unsupported MCS,40MHz, non-normal reports, fragments,
PAGGR/FAGGR and mismatched native shapes are consumed without PN admission.
PHYST, when present, must contain the actual28-byte `rx_fwinfo_88e` within
the promised driver-info extent. RXD3 SPLCP and the PHY `sgi_en` fact are
retained and checked against the local SGI20 receive promise before security.
This is not rtw88 page1. EE has no independent channel byte here: channel comes
from the retained programmed permission, as in Linux `rtl88ee_rx_query_desc`.
Absent PHYST retains only the checked RXD facts and invents no signal/channel
observation. Protected originals still require native SWDEC and retain their
complete CCMP header/ciphertext/MIC. The9100-byte native buffers admit one
whole original7935-byte aggregate plus its actual header/status/FCS extents.

Standalone A-MSDUs use shared authenticated whole-original receive, or bounded
Open decoding, before any Ethernet publication. Every suffix and inner
address/control/VLAN check succeeds before complete delivery and protected PN
commit. No prefix or deaggregated firmware fragment is admitted.

The SGI20 continuation has two new native regressions under
`drivers/wireless/rtlwifi/sgi20`: all eight TX MCS source cases for both
Open/WPA2 and SGI-capable/LGI-only APs, public capability versus actual
TXD/RA-mask fields, independent local RX capacity, native RXD/PHY SGI,
large A-MSDU reception and replay. Both native regressions pass on x86_64
and aarch64, including current NEFB refusal for the SGI firmware profile
and the source-specific MCS0 LGI descriptor.
Reference: Linux [rtl8188ee/trx.c](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/realtek/rtlwifi/rtl8188ee/trx.c)
and [trx.h](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/realtek/rtlwifi/rtl8188ee/trx.h).

#### Recipient Block Ack and RX reordering (implemented)

`rtl_op_ampdu_action` RX_START/RX_STOP reach `rtl_rx_agg_start`/`stop`, which
only record per-TID host state (and consult BT coexistence, absent on 88EE);
mac80211 owns the session and reorder buffer while the MAC acknowledges
A-MPDUs autonomously. `station.rs` follows `agg-rx.c`
`__ieee80211_start_rx_ba_session` for a peer-bound ADDBA Request on the HT
profile: TID>=8 answers status37, delayed policy or window>64 answers38,
window0 selects64 (`rtl_rx_ampdu_apply` keeps `IEEE80211_MAX_AMPDU_BUF_HT`
without BT limits), a repeated dialog token succeeds only with an unchanged
timeout, a new token replaces the session. The response sets immediate policy
and the A-MSDU bit, because rtlwifi sets `SUPPORTS_AMSDU_IN_AMPDU`; `packet.rs`
publishes ADDBA Request/Response and DELBA actions on the management ring with the
same terminal-receipt ownership as before.

Native RXD DW1 PAGGR/FAGGR are now reported (`Mpdu::aggregated`) on the HT
profile and accepted only for QoS DATA; the station refuses any A-MPDU member
on a TID without a session before CCMP/PN. Unicast QoS DATA from the peer on a
session TID passes through the shared `narf_wireless::reorder` buffer
(`ieee80211_rx_reorder_ampdu`) at capture, keeping its capture-time admission
and epoch, so CCMP/PN and A-MSDU deaggregation see sequence order. RCR_ACF is
part of the 88EE `receive_config` and mac80211 never clears it in station mode,
so 20-byte BlockAckReq frames are admitted natively and handled as
`ieee80211_rx_h_ctrl`: release up to the BAR SSN and refresh the session timer;
a BAR on a TID without a session sends one recipient DELBA
`WLAN_REASON_QSTA_REQUIRE_SETUP` per TID. Holes release after the 100ms
`HT_RX_REORDER_BUF_TIMEOUT`; session inactivity sends recipient DELBA
`WLAN_REASON_QSTA_TIMEOUT`; an originator DELBA purges the session; failure and
disconnect purge all sessions. Smokes
`smoke_rtl8188ee_ht20_rx_ba_reorders_ampdu_and_bar_before_pn` (Open/WPA2:
literal response, out-of-order release, BAR release across a missing SN,
timeout release, sessionless A-MPDU refusal and single DELBA, originator
DELBA), `smoke_rtl8188ee_ht20_rx_ba_policy_and_inactivity_delba` and the
updated `smoke_rtl8188ee_ht20_real_addba_response_terminal_receipt_and_cancelled_dma`
cover the paths.

#### Originator Block Ack and TX A-MPDU (implemented)

rtlwifi starts originator sessions from its own rate-control `tx_status`
(`rc.c::rtl_tx_status`): a delivered QoS DATA frame (not EAPOL) to an HT
station passes `_rtl_tx_aggr_check` (not scanning, `cnt_after_linked >= 3`
watchdog periods of `RTL_WATCH_DOG_TIME` 2 s after association, TID at
RTL_AGG_STOP) and calls `ieee80211_start_tx_ba_session(sta, tid, 5000)`.
`station.rs::tx_status` records the delivery after the terminal OWN receipt.
mac80211 refuses a start beyond HT_AGG_BURST_RETRIES (3) within
HT_AGG_RETRIES_PERIOD (15 s) or beyond HT_AGG_MAX_RETRIES (15); because
rtlwifi had already moved the TID to RTL_AGG_PROGRESS, that TID is never
retried on the current link (`tx_ba_stuck`), exactly as upstream.
`rtl_tx_agg_start` returns `IEEE80211_AMPDU_TX_START_IMMEDIATE` and
`rtl_tx_agg_oper`/`rtl_tx_agg_stop` only record `agg_state`, so no register
or H2C access accompanies any transition. The ADDBA Request
(`agg-tx.c::ieee80211_send_addba_request`) carries the A-MSDU bit
(SUPPORTS_AMSDU_IN_AMPDU), immediate policy, window 64
(IEEE80211_MAX_AMPDU_BUF_HT), timeout 5000 TU and SSN = the TID's next
sequence (Open counter or shared `Security::next_qos_sequence`).
`ieee80211_process_addba_resp` matches only the outstanding dialog token:
status 0 with a nonzero window makes the TID operational with the response
timeout, anything else stops it without DELBA (AGG_STOP_DECLINED). No
response within ADDBA_RESP_INTERVAL (1 s) or an operational session idle past
its timeout stops it as a local request with an initiator DELBA
`WLAN_REASON_QSTA_NOT_USE`; a recipient DELBA stops it silently
(AGG_STOP_PEER_REQUEST). Failure and disconnect drop every session and the
retry bookkeeping.

`rtl8188ee/trx.c::rtl88ee_tx_fill_desc` writes the station's
`ht_cap.ampdu_density` into TXD DW2[22:20] and, for an
`IEEE80211_TX_CTL_AMPDU` frame, DW2 AGG_EN (bit 12) and DW6 MAX_AGG_NUM 0x14
(bits 15:11). `packet.rs::submit_aggregate` applies these to QoS DATA on the
HT profile only (density is meaningless without AGG_EN, so management, EAPOL
and non-QoS frames keep a zero field). `rts_enable` follows mac80211 rate
flags, not aggregation, so A-MPDUs carry no RTS (row `rts_cts_protection`).
Frames on a TID whose ADDBA is outstanding go out unaggregated instead of
waiting on the stopped mac80211 TXQ; the peer receives them as ordinary
MPDUs. The HT program binding (`ht.rs::request`) records the new emission
profile, so an older signed NEHT record no longer matches. Smoke
`smoke_rtl8188ee_ht20_originator_ba_and_tx_ampdu` (Open and WPA2) covers the
link-settle gate, literal request, stale-token rejection, AGG_EN/density/
MAX_AGG_NUM descriptor bits, peer DELBA, restart token, response-timeout
DELBA, silent declines, the burst-retry park and teardown.

RX originals capture controlled-port admission and a receive generation while
the actual descriptor is copied. A terminal EAPOL TX receipt must additionally
reach genuine RX-idle before shared key/port completion, so queued pre-M4 DATA
cannot gain retrospective authority. Complete private plaintext own/AP-bound
EAPOL alone may cross the M2 receipt generation into the actual supplicant;
it never receives ordinary DATA admission. Reply publication, terminal receipt,
key replacement, cancellation and close retire old queued output. The actual
RX IPC consumer is retired immediately and refreshed for the successor epoch.

Final carrier, IPC enqueue/receive and stack publication retain exact source,
host policy and native PCI MEM/BME/INTX invocation. Each unlocked stack callback
resamples the actual owner/controlled port and an owned generation token;
callbacks hold no native-owner, endpoint, admission or ring locks. Reentrant
rekey cannot publish the remainder of an old aggregate, even after full reopen.
Ordinary TX-credit waits leave the receive epoch open. Software TX queuing
through temporary rekey backpressure remains supported; actual descriptors
still require the current native key/source/policy owner.

Fifteen new native Rust smokes under `drivers/wireless/rtlwifi/ht20` pass on both
architectures. They cover literal factory/PG/measurement cases, exact source identity
and negative assets, pre-write retry versus dirty-owner refusal, Open/WPA2 real
kernel DHCP/IP, all negotiated MCS descriptors, whole3839 A-MSDU and atomic PN,
native PHY/QoS/aggregation refusal before PN, actual ADDBA control receipts,
held/cancelled M4, per-poll mailbox source loss, current signed/PCI/installed
policy denial, ignored gain/SIFS writes, and held/reopened reentrant key epochs
versus ordinary TX credit. They use inert native register/DMA/firmware/AP inputs;
build/test gates pass; exact-board RF/firmware/external interoperability acceptance
remains outstanding. This initial EE feature does not complete rtlwifi.

### RTL8188EE interrupt delivery (implemented)

Linux `rtl_pci_intr_mode_decide` prefers MSI (`rtl_pci_intr_mode_msi`:
`pci_enable_msi` + `request_irq(_rtl_pci_interrupt)`). `interface::publish`
arms one MSI vector on the retained function (`firmware_native::PciIo::
arm_msi`: `narf_bus::msi::enable_msi`/`program_msi`, a
`narf_interrupts::vector` and a handler that only raises an
`irq::Signal`; delivery stays disabled until the owner is running). The
publisher worker then sleeps on the signal with a 20 ms housekeeping tick
instead of polling every 1 ms; stack TX (`enqueue`) is the second wake
source. Without a vector (no MSI capability, allocation failure, refused
enable) every mask stays clear and the worker keeps the 1 ms polled
service, so the polling-fallback goldens (`HIMR`/`HIMRE` = 0 after
`start_packets`) are unchanged.

On the first service pass after `start_packets` with a bound vector, the
owner runs `rtl88ee_enable_interrupt` exactly: `HIMR` = `irq_mask[0]`
(0x200084ff: PSTIMEOUT, HSISR_IND_ON_INT, C2HCMD, HIGHDOK, MGNTDOK,
BK/BE/VI/VO DOK, RDU, ROK — `rtl8188ee/sw.c::rtl88e_init_sw_vars`),
`HIMRE` = `irq_mask[1]` (IMR_RXFOVW), `REG_C2HEVT_CLEAR` = 0, then
`HSIMR` = `sys_irq_mask` (PDN|RON), with readback; MSI delivery is enabled
afterwards. Each woken pass runs one `_rtl_pci_interrupt` bottom half:
disable (`HIMR`/`HIMRE` = 0), `rtl88ee_interrupt_recognized` (read `HISR`
and `HISRE`, AND with the masks, write the same bits back: W1C),
`_rtl_pci_hs_interrupt` (`HSISR` |= sys mask) when IMR_HSISR_IND_ON_INT is
set, then re-enable. The existing ring walk follows, exactly where Linux
calls `_rtl_pci_rx_interrupt`/`_rtl_pci_tx_isr`. An all-ones `HISR`
(function gone) and any readback mismatch are terminal. Close masks the
chip (`rtl88ee_disable_interrupt`; `stop_packets` also clears the masks)
before the vector is disabled, its handler removed, synchronized and freed
(`rtl_pci_deinit`); a cfg-space disable failure quarantines the vector.

Tests: `smoke_rtl8188ee_native_irq_masks_and_w1c_recognition_match_linux`
(write order/values, W1C of masked bits only, HSISR ack, ring service
after recognition, withdraw/stop masking, all-ones and readback failures)
and `smoke_rtl8188ee_native_device_irq_worker_binds_and_releases_vector`
(composed Device: bind after join, woken W1C pass, TX wake, release after
masking at disassociate, refused delivery falls back to masked polling).

### RTL8188EE leisure power save (implemented)

Linux `rtl88ee_mod_params.fwctrl_lps` defaults off; `rtlwifi::
set_leisure_power_save` is the `fwlps=` module-parameter equivalent and
the default stays off. With it on, the publisher worker runs the
`rtl_watchdog_wq_callback` decision every `RTL_WATCHDOG_TIME` (2 s):
`cnt_after_linked` counts linked periods (cap 20); `num_rx + num_tx > 8 ||
num_rx > 2` calls `rtl_lps_leave`, otherwise `rtl_lps_enter`, whose
`rtl_lps_enter_core` gates are fwctrl_lps, `cnt_after_linked >= 5`, an
associated station and no `being_setkey` (RSNA port open, no handshake
frame outstanding). The data path also requests a leave when a pass
crosses the busy threshold (`_rtl_pci_rx_interrupt`/`_rtl_pci_tx_isr`)
and holds EAPOL/ARP/DHCP TX until the firmware is awake
(`rtl_is_special_data`). The `busytraffic` 4-period average (>100
frames/period) is subsumed: it can only be true when the per-period
threshold already chose leave.

`enter_leisure` is `_rtl88ee_fwlps_enter` with `low_power_enable = false`
(`rtl88e_init_sw_vars`): H2C SETPWRMODE 0x20 `[1, 0x10, 5, 0, 0]` (mode
`FW_PS_DTIM_MODE` != 0, RLBM 0, smart_ps 1, `reg_max_lps_awakeintvl` 5,
no U-APSD, `FW_PWR_STATE_RF_OFF`; `rtl88e_set_fw_pwrmode_cmd`), then
`HW_VAR_SET_RPWM(FW_PS_STATE_RF_OFF_88E)` toggling `REG_PCIE_HRPWM` bit 7.
`leave_leisure` is `_rtl88ee_fwlps_leave`: RPWM ALL_ON then SETPWRMODE
`FW_PS_ACTIVE_MODE` `[0, 0x10, 5, 0, 0x0c]` (the existing `awake`). On
this path RF_OFF_88E and ALL_ON_88E are both `FW_PS_CLOCK_ON`: registers
and DMA stay live, no CPWM acknowledgement is awaited (only the
low_power_enable clock-on path polls IMR_CPWM), and ordinary TX is still
serviced. The firmware's Null/PS-Poll frames use the reserved pages
already published by the join. `disconnect_station_peer` leaves LPS before
the JOINBSSRPT report; `stop_packets` clears the state. A firmware that
never consumes SETPWRMODE, or radio-off, is terminal like every other
mailbox failure.

Tests: `smoke_rtl8188ee_native_leisure_power_save_matches_linux_fwlps`
(exact H2C/RPWM vectors, double enter/leave refusal, ring service while
dozing, disconnect wake ordering, stuck mailbox and radio-off failure) and
`smoke_rtl8188ee_native_device_leisure_policy_follows_linux_watchdog`
(five-period gate, fwlps off, held DHCP wake, busy-RX leave, re-entry and
disconnect wake on the composed Device).

### RTL8188EE card-disable DMA quiescence (implemented)

Parked BME alone is not a prefetch fence, so a stopped owner still retains
every published ring and buffer. `Prepared::quiesce` adds the Linux
card-disable idle proof (`rtl88ee_card_disable` →
`_rtl88ee_poweroff_adapter`, `RTL8188EE_TRANS_ACT_TO_LPS`): on a Stopped
owner, with REG_TXPAUSE (0x522) and REG_PCIE_CTRL_REG+1 (0x301) read back
as 0xff and bus mastering already cleared by `stop_packets`, it polls the
TX packet-buffer status bytes 0x5f8..0x5fb for zero ("should be zero if no
packet is transmitting", pwrseq polling bound 5000 x 10 us) and
REG_RXDMA_CONTROL (0x286) BIT(1) RXDMA_IDLE (100 x 10 us). Linux proceeds
after an RXDMA timeout; here any timeout, readback mismatch or all-ones
read leaves every mapping retained. Success is the retirement proof: the
owner becomes reclaimable and its Drop releases the rings, RX buffers,
pending TX payload and reserved-page body instead of leaking them.
`disconnect_station_peer` runs the proof after a successful stop; a failed
proof never turns a completed disconnect into an error. A quiesced owner
never restarts.

Test: `smoke_rtl8188ee_native_card_disable_quiescence_reclaims_dma`
(non-stopped refusal, busy TX buffer, busy RXDMA, reopened DMA gate,
successful proof releases every region, unproven stop retains all).

### RTL8188EE driver rate adaptation and DATA fallback (implemented)

Linux v7.2 RTL8188EE runs `dm_type = DM_TYPE_BYDRIVER`, so
`rtl88e_dm_init_rate_adaptive_mask` sets `useramask` and the driver owns
the firmware RA mask. `rate_adaptive.rs` ports it:

* RX PWDB (`rtl8188ee/trx.c::_rtl88ee_query_rxphystatus`): when RXD PHYST
  carries the 28-byte EE PHY status, CCK frames (`RX_HAL_IS_CCK_RATE`,
  rate 1–11 Mbps) map `cck_agc_rpt` LNA/VGA through the 8-row table with
  BB `RFPGA0_XA_HSSIPARAMETER2` (0x824) BIT(9) `cck_highpwr`, +6 dB, the
  CCK/OFDM gain offset (+6, the 4/14/26/34/42 bands) and the low-power
  expansion; OFDM/HT frames use `((pwdb_all >> 1) & 0x7f) - 110`. Both go
  through `stats.c::rtl_query_rxpwrpercentage`. `Mpdu::pwdb` carries it.
* Smoothing (`stats.c::rtl_process_phyinfo` → `rtl_process_pwdb`): only
  frames whose ToDS/FromDS-selected BSSID equals the bound AP and that are
  not control frames (`_rtl88ee_translate_rx_signal_stuff`
  `packet_matchbssid`; CRC/ICV/HW errors never reach the station) update
  the zero-initialised `dm.undec_sm_pwdb` with `RX_SMOOTH_FACTOR` 20 and
  the +1 on a rising sample.
* Mask (`rtl8188ee/hw.c::rtl88ee_update_hal_rate_mask`, RF_1T1R, HT20 so
  `curtxbw_40mhz = mac->bw_40 = 0`, station MACID 0): `supp_rates[0]`
  (the association legacy intersection) `| rx_mask[0] << 12` (the HT TX
  MCS set) masked per `wireless_mode` (`core.c::rtl_op_sta_add`: N_24G →
  `RATR_INX_WIRELESS_NGB` 0 with 0x000f0000/0x000ff000/0x000ff005; G →
  `GB` 4 with 0xf00/0xff0/0xff5; B (`supp_rates <= 0xf`) → `B` 6 with
  0xd/0xf) and level. The 5-byte `H2C_88E_RA_MASK` (0x84, the entry after
  `H2C_88E_AOAC_RSVDPAGE` 0x83 in `fw.h`) is `(bitmap & 0x0fffffff) |
  ratr_index << 28` then `macid | SGI << 5 | 0x80`; SGI follows the bound
  peer receive capability under NEHT v2. The existing mailbox writer's
  two-extension-byte form is admitted for (0x84, 5) only. After the box is
  consumed, `_rtl88ee_set_bcn_ctrl_reg(BIT(3), 0)` sets REG_BCN_CTRL
  (0x550) BIT(3) with readback.
* Install: `core.c::rtl_op_bss_info_changed(BSS_CHANGED_ASSOC)` calls
  `update_rate_tbl(sta, 0, true)`; `connect_station` installs the level-0
  mask right after the JOIN completes, inside the same signed-calibration
  (or HT grant) invocation and admission as the join mailbox.
* Refresh (`rtl8188ee/dm.c::rtl88e_dm_refresh_rate_adaptive_mask`, from
  `rtl88e_dm_watchdog` every `RTL_WATCHDOG_TIME` 2 s, skipped while
  `fw_current_inpsmode`): the publisher worker's `Device::rate_adaptive`
  step picks DM_RATR_STA_HIGH/MIDDLE/LOW from `undec_sm_pwdb` with the
  `pre_ratr_state` thresholds (HIGH/INIT 50/20, MIDDLE 55/20, LOW 50/25) and
  re-sends the mask only when the level changes, then commits
  `pre_ratr_state`. A linked station outside LPS with a mask is required.
* TXD (`rtl8188ee/trx.c::rtl88ee_tx_fill_desc` with `useramask`, and
  `base.c::_rtl_txrate_selectmode`): ordinary DATA (`Kind::Data`) after the
  mask, under a current NEFB grant (below), carries DW1 RATE_ID = `ratr_index` (MACID 0) and DW4 DISDATAFB
  clear; USE_RATE stays set because 88EE forces `use_driver_rate`, so the
  highest negotiated rate is the initial rate and the firmware falls back
  within the mask (`set_tx_desc_disable_fb(disable_ratefallback = 0)`).
  Management, EAPOL and every frame before the mask keep RATE_ID 0 and
  DISDATAFB (`rtl_get_tcb_desc` rix 0 / `disable_ratefallback = 1`); only
  their RATE_ID differs from Linux's `RATR_INX_WIRELESS_MC`, which the
  hardware ignores with fallback disabled. Every fallback rate is one of
  the CCK/OFDM/MCS0–7 rates whose conducted peaks the signed NEPC/NEHT
  envelopes already bound.
* Teardown and failure: `stop_packets` (disconnect, abort) withdraws the
  mask, so a later owner starts with fallback disabled; a mailbox that is
  never consumed or radio-off is terminal for the owner and never enables
  fallback; a failed refresh aborts the station.

#### Separately qualified DATA fallback (`NEFB` v1, `fallback.rs`)

The NEPC legacy record and the NEHT HT20 program (whose binding text says
`USE_RATE DISFB`) qualify a fixed-rate emission profile: every frame at one
rate, DW4 DISDATAFB set. Letting the firmware step down changes the emitted
rate sequence over time, so — like rtw88 `N2xF` — it is its own signed
continuation, `rtlwifi/rtl8188ee-fallback-v1-<mac>.bin` (128 bytes):
`NEFB`, version 1, header length 128, total length, `10ec:8179`, a 32-byte
binding over the program title, factory identity, retained NEPC digest,
firmware name and image digest and the Linux source text
(`base.c::rtl_get_tcb_desc` station DATA `disable_ratefallback = 0`,
`ratr_index = sta_entry->ratr_index`; `rtl88ee_tx_fill_desc` forced
`use_driver_rate`, DISABLE_FB DW4.10, RATE_ID DW1.16–19), then the factory
identity, NEPC digest and MAC again, payload byte0 = 1 and every other byte
zero. Unsigned, mis-bound or non-zero-reserved records are refused; a
present but inadmissible record fails the association rather than silently
changing the profile.

* Consulted at association (`Environment::fallback`, `NativeEnvironment`
  loads the registered asset) and held for that association only;
  `reset_passive` (safe rejoin) forgets it.
* Every DATA submit and every watchdog pass re-proves it through
  `Cap::invoke` on the record, the NEPC calibration and the firmware
  identity. A revoked grant is dropped: the next DATA frame carries
  USE_RATE + DISDATAFB + RATE_ID 0 at the same highest rate, and the link,
  keys, BA sessions and installed RA mask stay (no reassociation).
* The RA mask H2C itself is sent with or without the grant: Linux sends it
  from `core.c::rtl_op_sta_add`/`rtl_op_bss_info_changed(BSS_CHANGED_ASSOC)`
  (`update_rate_tbl`) and `rtl88e_dm_refresh_rate_adaptive_mask` without
  regard to any frame's `disable_ratefallback`, and with DISDATAFB set the
  firmware never applies it to a DATA frame.

Tests: `smoke_rtl8188ee_data_fallback_requires_separate_signed_grant`
(open and WPA2 legacy: granted DATA clears DISDATAFB with RATE_ID 4,
revocation mid-link returns to DISFB/RATE_ID 0 with the link and mask kept,
the watchdog never resurrects it, disassociation forgets it, an
inadmissible record refuses the association),
`smoke_rtl8188ee_ht20_data_fallback_is_a_separate_revocable_grant` (HT20
MCS7: same with real RX after revocation) and the ungranted fixed-rate
descriptors in `smoke_rtl8188ee_negotiated_legacy_data_rate_uses_native_descriptor_and_ccmp`
and `smoke_rtl8188ee_ht20_wpa2_native_kernel_dhcp_and_ip`.

Tests: `smoke_rtl8188ee_rx_pwdb_and_smoothing_match_linux` and
`smoke_rtl8188ee_rate_mask_levels_match_linux` (hand-computed Linux CCK/
OFDM PWDB values, smoothing, BSSID selection, every mode/level mask,
hysteresis and the 2 s period), `smoke_rtl8188ee_native_rate_mask_enables_data_fallback`
(owner gates, exact H2C and BCN_CTRL, DATA/management/special TXD before
and after the mask, OFDM/CCK RX PWDB through the real RX ring, terminal
stop withdraws the mask, stuck mailbox and radio-off) and
`smoke_rtl8188ee_native_device_rate_mask_follows_rx_pwdb` (composed
Device: level-0 mask at association, fallback DATA descriptor, strong and
weak beacon PWDB moving HIGH → MIDDLE → LOW, no re-send at an unchanged
level, no refresh after disassociate).

### RTL8188EE device removal (implemented)

`pci.rs` registers `narf_bus::register_pci_remove` for every matched id.
The hook follows Linux v7.2 `pci.c::rtl_pci_remove`: only the bound
function detaches from the controller slot, its address is quarantined
(`probe` refuses it before any config/BAR access), and an async task runs
`interface::Device::remove`:

1. `ieee80211_unregister_hw`: the publisher worker is told to exit, the
   admission closes (carrier down, `nl80211` disconnect), and the
   registrations `publish` made are withdrawn (`ACTIVE`/`CLAIMED`,
   `narf_wireless::registry`, `narf_net::registry`, `narf_net::iface`).
2. `rtl_op_stop` → `rtl_pci_stop`: `rtl88ee_disable_interrupt` masks
   HIMR/HIMRE before `rtl_pci_deinit` disables MSI and frees the vector
   (`withdraw_interrupts`); a linked station first leaves LPS and sends the
   JOINBSSRPT disconnect (`disconnect_station`).
3. `rtl88ee_card_disable`: `Prepared::retire` stops a not-yet-stopped
   owner (`stop_packets`, BME cleared) and runs the card-disable
   quiescence proof (`Prepared::quiesce`). Only a proven-idle (or never
   published) owner is dropped, which releases every ring, RX buffer,
   pending payload and reserved-page body, and the quarantine is lifted.
   An unproven owner keeps every mapping pinned and its address stays
   quarantined. Removal is idempotent and a removed Device never reopens.

Non-8188EE diagnostic profiles never publish DMA; their removal only
withdraws the static interface and wireless registration.

Tests: `smoke_rtl8188ee_native_device_remove_releases_after_quiescence`
(linked removal: disconnect report, mask before vector release, BME
parked, owner/DMA/netdev/carrier gone, idempotent, no reopen; busy RXDMA
keeps the owner and every mapping; never-associated removal) and
`smoke_rtl8188ee_pci_remove_detaches_and_quarantines_exact_owner` (wrong
address ignored, quarantined re-probe refused without I/O, reclaimed
removal lifts the quarantine).

### RTL8188EE safe rejoin after disassociation (implemented)

Linux v7.2 never stops the PCI engines on disassociation: mac80211
`ieee80211_set_disassoc` reaches `core.c::rtl_op_bss_info_changed`
(`BSS_CHANGED_ASSOC`, `!assoc`), which leaves LPS, sends
`HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_DISCONNECT)`, sets the NO_LINK network
type and clears the BSSID, then `rtl_op_sta_remove` drops the station; a
later scan/association reuses the same rings, firmware and interrupts.
`Prepared::disconnect_station` follows that when the owner is running and
its last frame has a host receipt (`rejoinable`):

- `leave_station_peer` leaves LPS, sends JOINBSSRPT `[0]`, runs
  `station_control::disconnected` (MSR NO_LINK, BSSID 0x618..0x61d zero,
  AID, RCR without BSSID filtering, BCN_CTRL TSF-update disable) with
  readback, withdraws the firmware RA mask and the QoS/HT TXD profile and
  keeps DMA, rings and interrupts live. The reserved-page body moves to a
  retired list: its upload was proven by BCN_VALID but the command-beacon
  OWN bit may stay set, so it is released only with the quiescence proof
  (or pinned with the owner). The next association reuses BEACON_QUEUE
  descriptor 0 like Linux `rtl_cmd_send_packet`, which is only admitted
  after such a proven upload.
- The station state forgets the association (plan, keys/PN/replay, BA,
  WMM/HT negotiation, AID, RA smoothing), advances the receive epoch and
  returns to `Passive`; the HT grant, scan cache and signed calibration are
  kept. `interface::Device::disassociate` then reopens admission under the
  owner and publication locks, so scan and associate work again; stale
  publishers are fenced by the advanced epoch.
- A frame still owned by the device, a non-running owner or any mailbox/
  register failure keeps the terminal path (`disconnect_station_peer`:
  stop, quiescence proof, `Stopped`) or aborts the owner.

Tests: `smoke_rtl8188ee_native_leave_peer_keeps_dma_for_rejoin` (exact
JOINBSSRPT, NO_LINK/BSSID registers, RA mask withdrawn, ring service
continues, device-owned frame refused, stuck mailbox terminal),
`smoke_rtl8188ee_real_station_open_wpa2_native_exact_ip` (Passive, BME on,
no peer), `smoke_rtl8188ee_native_device_{open,wpa2}_kernel_dhcp_exact_ip`
(composed Device: disconnect report, rescan, second association with a
fresh AP session, a new reserved-page upload on the reused descriptor,
exact uplink, second disconnect) and the HT20 and paused-publisher
regressions (stale publisher still fenced, Passive after close).

### RTL8188EE operating-owner replacement (implemented and software-validated)

The persistent `interface::Device` now retains generation-tagged reset work.
Its worker detects a closed owner and makes up to three automatic recovery
attempts with a one-second retry interval. A later valid passive scan can
request another attempt when missing inputs or device access are restored.
Invalid scan options do not initiate reset. Initial staged provisioning,
scanning, association, disconnect, removal and replacement share the same
async control mutex.

Replacement closes the logical frontend, advances a checked non-wrapping
generation, withdraws interrupts, aborts the station, and requires the actual
old `Prepared::retire` DMA-idle receipt. Old synchronous TX publications and
unlocked stack callbacks hold counted leases; replacement drains those leases
before clearing queued packets and reopening. Copies, cancellations and late
errors retain their original generation. Neither an old copy nor its late
error can acquire publication or close a replacement generation. No spinlock
is held through a stack callback or asynchronous hardware wait.

After retirement, current PCI vendor/device/subsystem/BAR identity, parked
BME and successful interrupt withdrawal permit a fresh control port. The
cooperative card-disable/enable sequence follows Linux rtl8188ee `hw.c`,
`fw.c` and `pwrseq.h`; it stops the firmware CPU and executes the actual
ACT/LPS/CardEmu/CardDisabled transitions. Power polling requires observed
hardware ACKs. The factory map is reread and compared before a fresh
authenticated firmware owner, fresh LLT/rings, IQ/LC radio calibration and
current signed channel policy are installed. The old firmware `begin` and
packet claim remain one-shot. No keys, PNs, scan cache or old DMA are restored;
the interface returns to Passive and requires a fresh association/RSNA.

The public reset waiter pumps work owned by the device; dropping it preserves
the exact in-flight power transition for the worker. Removal continues to
drive already-retained work before withdrawing the owner. Missing DMA/IRQ
retirement proof retains old resources and forbids replacement. A failed new
preparation is stopped and parked before retry. The logical interface name,
MAC and operator-controlled IFF_UP survive a successful replacement.

Native regressions compose the production generation supervisor with real
firmware, LLT, radio, station and DHCP code, using inert MMIO/DMA/peer models.
All four recovery cases pass on x86_64 and aarch64 at native checkpoint
`73b90b62d`; the operating-reset inventory row is closed. These fixtures prove
the software protocol and lifecycle; physical board acceptance remains separate.

### RTL8188EE system suspend and IPS (implemented and software-validated)

The native frontend registers both `AsyncSystemPm` and synchronous device-PM
hooks. Async preparation closes the station, retires real DMA and interrupts,
drains logical publications and runs the actual card-disable flow. A separate
completion bit becomes true only after the hardware transition completes;
duplicate or failed preparation cannot turn an absent receipt into success.
The synchronous hook saves the parked PCI type-0 header. Resume checks the
current function identity, clears BME/MEM before restoring BARs, restores only
parked MEM/INTx-disabled configuration, then checks exact BAR identity again.
MSI vectors and firmware state are recreated by the async fresh-owner path;
no old MSI enable, key, PN or receive ring is restored.

The retained work slot survives a dropped suspend waiter. If the actual
system-PM preparation future is abandoned, its cancellation guard requests
resume after that same in-flight transition finishes. A short request mutex
and exclusive preparation flag keep a competing preparation from reviving
an abandoned request. Failed preparation attempts rollback through the same
fresh-owner path. Source loss or missing hardware receipts remain closed;
no cleanup grants DMA reclamation or host carrier without the required proof.

`set_inactive_power_save(bool)` mirrors the default-on rtl8188ee `ips`
parameter (`inactiveps` field); disabling it wakes an IPS-disabled owner.
The existing two-second watchdog requests IPS only for an idle
Passive station, serialized against scan/join/provisioning. A request retains
its activity stamp so a queued old idle decision cannot power down a recent
scan. IPS retires the native owner and physically disables the card; a later
valid scan wakes through fresh firmware/LLT/radio/MAC and policy validation.
An associated station uses the separately controlled firmware LPS path.
System suspend can adopt an already verified IPS-disabled state; system
resume returns to a fresh Passive owner with the same name/MAC/IFF_UP.

Four native composed power cases cover retained suspend, fresh WPA2/DHCP,
IPS scan wake and system handoff, absent DMA receipts, and cancellation-driven
resume. All four pass on x86_64 and aarch64 at native checkpoint `73b90b62d`,
alongside the four existing power cases. The system-PM and IPS inventory rows
are closed. Final release Clippy and ordinary boot gates pass at the
behavior-preserving lint successor `127744339`; physical board acceptance
remains separate.

### Qualified legacy20 channel changes (implemented and software-validated)

The async `set_config` and a single-channel scan request can select channels
1–11 under an actual current signed NEPC row and host policy. Permission
preflight occurs before closure or register writes. A connected/joining peer
requires disassociation first. The retained channel operation then closes and
retires the old DMA/IRQ owner, drains logical publications and runs the real
card cycle before fresh firmware, LLT/rings, radio calibration and RF18/BW/gain
programming. No credentials, keys, packets or cached BSS migrate. A fresh
physical beacon/probe response is required before a new association.

Station admission, publication and RX channel observations use the physical
owner's current channel permission rather than a channel1 constant. Every
publication re-derives that exact permission against current host policy and
the signed per-channel gain curve. Failed preflight does not mutate hardware;
missing old-DMA retirement retains mappings and forbids replacement. Dropping
the public waiter preserves the transition. IPS and system resume rebuild the
last requested channel only under fresh current permission.

Channel1 NEHT/NEFB records do not authorize HT or adaptive fallback on another
channel; absent their separate per-channel continuations, those channels use
the qualified fixed legacy20 path. Discovery
reports only channels permitted by the current NEPC and host policy. Other
bands/widths remain separate.
Four native composed cases exercise actual1→6→11→1 RF18 and distinct gain
receipts with Open/WPA2 DHCP, preflight/idle rejection, abandoned waiters and
IPS wake. All four pass on both architectures at native checkpoint
`196e0a946`; final release gates pass at its one-line lint successor
`32504f88d`. The later multi-channel scan and per-channel HT/fallback
continuations are accepted below.

### Multi-channel software scanning (implemented and software-validated)

A scan now validates the complete requested channel/frequency set before its
first hardware action. Duplicate selectors are deduplicated, conflicting
channel/frequency sets are rejected, and an empty set selects all currently
qualified channels in1–11. Each dwell uses the actual retained physical
channel owner and its current permission. Active scans publish real native
Probe Requests; passive scans only consume physical beacons/probe responses.
An associated station must disconnect before this cold-retune scan profile.
Successful multi-channel scans return to the original operating channel.

The logical device retains at most32 owned BSS/IE observations for10seconds,
so returning home does not discard metadata from earlier scan channels.
The display cache carries no packet, regulatory or key authority. Selecting
a BSS on another channel creates a fresh physical owner and requires a new
matching physical beacon/probe response before authentication or RSNA. A
cached scan result cannot authorize joining a peer that has moved away.
Cancelled dwells close their generation; cancelled retunes retain the exact
driver-owned transition, and incomplete scans publish no partial cache.

Five native composed cases exercise Open/WPA2 scan-selected fresh joins and
actual DHCP, default passive scanning with physical off-channel filtering,
whole-plan prevalidation, stale display metadata and cancelled retained work.
All five pass on both architectures with the completed release gates
recorded below. The dwell/probe/channel progression follows
Linux [mac80211 scan.c](https://github.com/torvalds/linux/blob/master/net/mac80211/scan.c).

### Per-channel HT20 and DATA fallback (implemented and software-validated)

`RtlwifiDevice::ht20_request_on_channel(channel)` and
`rate_fallback_request(channel)` return provisioning filenames and bindings
for channels1–11 after resolving the current factory, NEPC and executable
identity. They grant no transmit permission. The existing `ht20_request()`
continues selecting the channel1 v2 program.

Noninitial channels use signed NEHT v3 files named
`rtlwifi/rtl8188ee-ht20-v3-ch<channel>-<MAC>.bin`. The160-byte header retains
the v2 curve geometry, but version3 and byte118 bind the exact channel2–11;
the program hash also binds that channel. HT gain selection follows Linux's
EFUSE BW40 base group at0x16+group, the signed high nibble at0x1b, and the
per-regulatory channel group's pathA MCS PG offsets. It intersects that
factory ceiling with the exact channel's signed HT curves and current NEPC
permission. Channel1 v2 records retain their existing bytes, name and hash.
No channel1 record or another channel's program authorizes these gains.

Noninitial-channel fallback uses signed NEFB v2 files named
`rtlwifi/rtl8188ee-fallback-v2-ch<channel>-<MAC>.bin`. Byte118 remains the
enable bit; byte119 binds channel2–11, and bytes120–127 remain zero. Version,
program hash, factory, NEPC and actual firmware identity must agree. Channel1
retains the existing NEFB v1 contract. Installation additionally matches the
physical station permission's channel. SGI transmissions retain DISFB, as
neither fallback version qualifies mixed-GI retries. Missing optional files
preserve legacy or fixed-rate operation; malformed/revoked files cannot
authorize the richer profile.

Five native cases cover literal factory-group bounds, version/channel/source
substitution and revocation, and composed channel6/channel11 HT Open/WPA2
MLME, actual kernel DHCP, real TXAGC readbacks and native fallback descriptors.
All five pass on both architectures with the completed release gates below.
Wider widths and thermal gain tracking remain separate rows.

### Multiple retained radios (implemented and software-validated)

Each PCI function now has its own retained controller, interface name, native
frontend and MSI signal. Probe reserves the exact BDF before hardware access;
repeat bound probes leave that owner intact, concurrent probes of that same
function cannot create another owner, and another function can initialize
independently. Removal quarantines only the retiring BDF until its actual
DMA/IRQ/publication retirement completes. Missing proof leaves that function
blocked without withdrawing another radio.

Stack sends use the existing context-send hook with a checked, nonwrapping
cookie for the logical device. The callback resolves and clones that exact
endpoint before releasing the route lock; it cannot reinterpret a removed
cookie as another interface. Receive draining snapshots all retained endpoints
and invokes each outside the table lock. MSI handler cookies identify the
actual allocated vector, whose signal is removed after handler synchronization
and before vector reuse. Quarantined vectors and signals remain retained.

`pci::with_controller_at(BusAddr, callback)` and async `provision_at(BusAddr)`
select an exact bound function. Existing `with_controller` and `provision`
remain compatibility helpers for the first bound controller. Probe's staged
worker captures its own native owner rather than provisioning another device
after a BDF is reused. PM, reset, scan and packet publication remain serialized
by that device's control mutex and generation.

Six native cases cover independent and stale stack/IRQ routes, checked cookie
exhaustion, exact PCI reservations/quarantine, and two composed Open/WPA2
firmware/radio owners using actual context-routed kernel DHCP and native data
through removal of one radio. All six pass on both architectures.

Acceptance checkpoint `fc0101c6e` passes all34 focused cases on both
architectures. The fixture-only successor `ed1946ffd` additionally fixes an
inherited HE fixture stack overflow and passes all39 focused cases, full
wireless/foundation suites (**4214/0/13** x86_64; **3855/0/7** aarch64),
both release Clippy contexts, formatting, ordinary production release boots
and both btrfs postflight images per architecture. The active-scanning,
additional-operating-channels and multi-radio inventory rows are closed for
the retained factory-qualified1–11 profiles. Physical board RF qualification
remains separate; the later Intel command-group correction has its own gates.

### PCIe ASPM (software-validated)

The retained RTL8188EE owner follows Linux's default-on `aspm` policy for
L0s/L1 and CLKREQ. `set_pcie_aspm(bool)` sets the policy for the next cold
preparation. Admission intersects the endpoint's actual Link Capabilities
with the live upstream bridge's already-enabled Link Control. CLKREQ also
requires the endpoint's advertised Clock Power Management support. Linux's
known Intel/ATI/AMD/SiS bridge vendor set is retained; absent/unknown parents
authorize no endpoint ASPM entry. The shared bridge and common-clock bits
remain platform-owned.

Probe and actual card-disable/enable transitions first verify endpoint
ASPM/CLKREQ disabled. After verified card disable, idle link policy can be
restored only using that same owner's completed internal preparation;
failure of this optional optimization grants no packet or DMA ownership.
Before packet admission, the cooperative MDIO/DBI
program follows `_rtl88ee_enable_aspm_back_door`: the actual354/358 word
writes and70c/718 DBI read-modify-writes require observed command retirement
and exact data readbacks. Polls yield through the native timer wait, with
the source's bounded20 ten-microsecond waits. No pending/ignored write is a
completion receipt. The parent policy is reread after the cooperative waits
before committing endpoint Link Control, whose unrelated bits are preserved
and whose actual readback is checked.

Every native configuration/MMIO action executes within the current exact
function's capability invocation. A cancelled bus preparation leaves the
parked owner failed; packet admission requires a fresh recovery. Each fresh
physical owner redoes internal preparation, including after suspend/IPS.
Six native cases cover literal hardware transactions, actual policy limits,
timeouts/readback/source loss, cancellation, the native revoked-cap path,
and Open/WPA2 kernel DHCP with fresh-owner parent-policy withdrawal. All six
native Rust cases pass on both architectures in fixture checkpoint `ab09f5d73`.
The full integration passes 4259/0/13 on x86_64 and 3900/0/7 on aarch64.
Release CI, formatting, ordinary boots and both btrfs postflights pass on
production checkpoint `6e89e3ab3`; the successor changes only native fixtures,
whose scoped release CI also passes. Physical acceptance and other chip
runtimes remain separate.

### Separately qualified RTL8188EE HT20/40 (implemented, acceptance pending)

The [NEHT v4 full-program contract](rtl8188ee-ht40.md) extends the retained
EE owner with a distinct primary/secondary/center20/40 program. It preserves
the accepted v2 channel1 and v3 channel2–11 HT20/SGI20/7935RX formats;
`RtlwifiDevice::ht40_request(primary, secondary)` returns exact provisioning
metadata without radio I/O. New signed CCK/OFDM and MCS0–7 peak rows must
qualify the complete20MHz fallback and40MHz LGI emission programs, static
antenna/IQK/LCK/supply/thermal envelope and autonomous responses. No board
measurements or deployment artifacts are invented or supplied.

EE follows Linux `core.c::rtl_op_config` → `current_channel=primary±2` →
`rtl8188ee` switch-channel TX-power/RF commands:40MHz factory/PG lookup uses
CENTER, while the preceding NEPC20/fallback uses PRIMARY. V4 bounds MCS
gains by both source maxima, including the signed HT20 difference only in
the20MHz case. Existing CCK/OFDM raw arrays must also fit CENTER factory
maxima and the new measured full-program rows. Full occupied40MHz current
host policy and executable/NEPC/v4 capabilities are checked around every
native wait, DMA publication and copied IPC/stack callback.

A peer is offered40 only for an exact qualified secondary. The same PCI
owner waits for actual full32-bit scheduler terminal, pauses queues, closes
MAC TX/RX, programs/reads back BB/RF/gains and then reopens gates. All native
DMA allocations/OWN receipts remain retained; a MAC pause grants no DMA
reclamation. Primary does not change and RXD's original width remains
independent of metadata, so old40 frames cannot be relabeled as20. Copied
epochs retire before the transition. A narrowed20 response completes real
20MHz programming before keys/port or DATA open. Native MCS DATA uses BW40
and SC3; basic management/control uses the actual20MHz primary subcarrier.
LGI40 composes with existing SGI20 fallback,7935RX, software CCMP, BA and
source host RA. SGI40/MCS32/2SS/RTS/CTS and old NEFB under v4 stay closed.

Eight new `drivers/wireless/rtlwifi/ht40` native regressions exercise signed
identity and center factory maxima, plus/minus Open/WPA2 DHCP and exact IP,
initial/response20 fallback, original same-PN width/GI rejection, full-span
policy/v4 loss with held DATA OWN, cancelled native RF waits and actual
readback/scheduler terminal failures. Formatting/whitespace checks pass;
coordinated release compilation/native execution remain pending. All prior
NEHT/scan/power/recovery cases remain required; physical acceptance remains
external.

### Separately qualified RTL8188EE RTS/CTS (implemented, acceptance pending)

The [NERT v1 contract](rtl8188ee-protection.md) separately qualifies RTS/CTS
emissions over the exact current NEPC/firmware and measured NEHT payload.
New full-program CCK/OFDM/MCS peak rows must cover the existing unchanged
raw gains and automatic control retries; NERT cannot increase preceding
channel/width/factory/EIRP rights. `RtlwifiDevice::rts_cts_request()` returns
exact Passive-program provisioning metadata. No real measurements or
signed board artifacts are supplied.

Native ERP Use_Protection requests CTS-to-self for OFDM/MCS. The per-device
`WirelessNetIface::set_rts_threshold(bytes)` implements nl80211 SET_WIPHY
and selects RTS/CTS when DATA MPDU+FCS exceeds the threshold; `u32::MAX`
preserves the source disabled default. GET_WIPHY reports the retained
physical setting across station reset and owner recovery. RTS takes
precedence, including threshold-selected EAPOL DATA. Source DW4 CTS11 or
RTS12 uses initial OFDM24 rate8, with HW-RTS/RTS-short/BW/SC/STBC clear and
existing RTS fallback limit15; ordinary DATA width/SC/GI/QoS/BA/CCMP and
terminal OWN remain unchanged. Old NEFB stays excluded from protected DATA.
Previously unsupported numeric HT protection modes remain refused.

Exact current NERT sources enclose asynchronous M4/RA/peer polls, actual
OWN/doorbell and copied IPC/stack publication. Live bound beacons update
ERP, and ordinary DATA waits for actual receive-idle so a queued later ERP
fact cannot be overtaken. Required missing, unknown or revoked qualification
fails closed; it never silently removes protection. Threshold updates use
the publication gate and mode is reread inside that gate. Failed/held DMA
receipts remain retained.

Six new native `drivers/wireless/rtlwifi/protection` regressions cover signed
identity/known peaks, legacy/HT Open/WPA2 DHCP and exact IP, source RTS/CTS
descriptors, thresholds/precedence, HT40 composition, pre-auth qualification
refusal, live ERP and held M4 revocation. They await coordinated release
compilation and final native execution. Physical measurements and RF
control-frame/peer acceptance remain external.

### Separately qualified RTL8188EE thermal tracking (implemented, acceptance pending)

The [NETH v1 contract](rtl8188ee-tracking.md) adds the actual source EE
thermal TXAGC path over the exact retained firmware/NEPC, measured NEHT
and optional measured NERT payloads. `RtlwifiDevice::thermal_tracking_request()`
returns the selected private provisioning recipe without radio I/O. It
requires real factory thermal EFUSE0xba1–63; no erased default substitutes
for board data. No real measurements or signed deployment assets are supplied.

The actual RF42 trigger/read alternates on the2s watchdog, averages four
nonzero readings, and follows the pinned source CCK swing-index delta for
CCK/OFDM/MCS TXAGC. Per-rate signed arithmetic avoids packed-word wrap.
Tracking reduces gains and restores them within the original qualified
indices; every preceding factory/curve/antenna/current-policy bound still
applies. A64-thermal x10-rate-family x64-gain signed full-program envelope
covers calibration tones, all transition states, responses, sampling gaps
and the full static antenna/supply/thermal operating range. All64 peaks must
be known at an admitted index; no interpolation or sample creates authority.
Old NEFB remains excluded from this combined program.

Average drift>=8 repeats actual retained IQK/LCK. Native host receipts,
full scheduler idle, all-queue pause and MAC TX/RX closure precede updates;
RF18/RF0, saved BB/MAC/IQK, actual gains and reopened gates are read back.
Per-poll/current-publication source checks remain in force. Peer/channel/
key/PN/BA/DMA ownership and original OWN receipts are retained. Source loss,
bad samples, unknown bounds, failed readbacks and cancelled RF waits fail
closed. A subsequent peer selection restores the original current qualified
program before selecting its new width and measurements.

Six new native `drivers/wireless/rtlwifi/tracking` cases are written for signed
full-dimensional identity/holes, Open/WPA2 legacy/HT DHCP/IP and exact gain
reduction/restoration, plus/minus HT40 and response20 fallback with RTS,
real IQK/LCK, failure closure and held M4/cancelled RF ownership. Compilation
and native execution remain pending. Board measurement/signing and physical
thermal/RF acceptance remain external. Linux EE supports dynamic antenna
diversity, which stays a separate measured-antenna continuation.

### Separately qualified RTL8188EE automatic antenna selection (implemented, acceptance pending)

The [NEAN v1 contract](rtl8188ee-antenna.md) adds actual automatic diversity
for factory types1/2 and SMART type4. It binds exact current firmware/NEPC
and measured NEHT/NERT/NETH payloads, with separately signed two-selector
x64-thermal x10-rate-family x64-gain full-program envelopes and antenna
bounds. Every possible path and temperature must admit actual gains under
all preceding/current limits; no static board curve authorizes another
antenna. No board measurements or signed physical deployment assets are
supplied. `RtlwifiDevice::antenna_diversity_request()` is pure provisioning
metadata; the source EE driver has no manual nl80211 antenna setter.

Complete real PHY records supply the mux and PWDB. AP-bound statistics drive
source type1/2 averages/ties; SMART uses actual own-MAC-directed samples,
source two-combination mapping and a real2s training deadline. Actual RX/
response/default controls and TXD2[24,25]/DW7[29] select qualified paths.
Initialization forces/readbacks factory-type MAIN/AUX mux codes, resolving
the pinned Linux prior-logical-selector/type alias. Every transition uses
real host receipts, scheduler idle, MAC/queue pause and antenna/gain/RF/gate
readbacks. Current NEAN sources enclose polling, native TX and copied final
publication, including combined thermal updates. A subsequent peer restores
the exact static antenna program and repeats IQK/LCK before retiring NEAN.
Key/PN/BA/DMA ownership and original OWN receipts are preserved.

Six new native `drivers/wireless/rtlwifi/antenna` cases cover factory/full-
dimensional identity, type1/2/HP actual PHY and DHCP, SMART timing/target/
selection, HT40+RTS+thermal composition, failed readbacks/idle/cancellation/
static restore, copied-source loss and held M4. Compilation and native
execution remain pending. Physical antenna mapping, full-program per-path
measurements, trusted signing and silicon/RF acceptance remain external.

### RTL8821AE retained runtime (implemented, pending validation)

`rtl8821ae/` holds the exact Linux-derived pieces the RTL8821AE retained owner
is built from. Probe retains the matched `0x8821` function as a native device
(`pci.rs`, alongside RTL8188EE) and admits it under its signed NAPC envelope;
an unprovisioned board stays unadmitted. The composed station, VHT, recovery
and WoWLAN paths are described below.

- `pwrseq` — PCI rows of every `rtl8821A_*_flow` (enable, disable, suspend,
  resume, radio-off, LPS enter/leave), generated from `pwrseq.h` with masks
  unchanged; USB/SDIO-only rows are omitted. `power::power_on_with` now runs
  the exact `_rtl8821ae_init_mac` prefix (`REG_RSV_CTRL=0`, clear
  `APS_FSMCO[15]`) and parses `RTL8821A_NIC_ENABLE_FLOW` with
  `PWR_CUT_A_MSK` exactly as Linux, replacing the former approximate table.
- `tables` / `headerfile` — RTL8821AE MAC, PHY_REG, AGC, RADIOA and
  PHY_REG_PG arrays (`table.c`, source sha256 recorded) and the conditional
  `__rtl8821ae_phy_config_with_headerfile` walker with `_rtl8821ae_check_positive`.
  `Condition::from_hardware` takes the cut from `REG_SYS_CFG[15:12]`, rejects
  `TRP_VAUX_EN` test chips, requires the `0x8129` EFUSE autoload ID and derives
  `board_type` from EFUSE `0xbc/0xbd/0xbf` plus `REG_MULTI_FUNC_CTRL[18]`.
  An unprovisioned map produces no condition, so no row is selected.
- `power_limit` — typed `RTL8821AE_TXPWR_LMT` rows; 63 (`MAX_POWER_INDEX`)
  and absent rows return `None` and must not be substituted.
- `fw` — `rtl8821aefw_29.bin` (alt `rtl8821aefw.bin`) and
  `rtl8821aefw_wowlan.bin`; `IS_FW_HEADER_EXIST_8821`, exact RAM-code length,
  at most eight 4 KiB pages; `rtl8821ae_download_fw` enable/page/pad/disable,
  `FWDL_CHKSUM_RPT`, `MCUFWDL_RDY`, 8821A self-reset and `WINTINI_RDY`
  polling with Linux counts, plus `_rtl8821ae_wait_for_h2c_cmd_finish`.
- `llt` — `_rtl8821ae_llt_table_init` (boundary `0xf7`, max page 255,
  RQPN `0x80e60808`) with exact register widths.
- `trx` — 64-byte TX ring entry (40-byte descriptor, buffer dword 10, next
  dword 12) filled as `rtl8821ae_tx_fill_desc`, including SPE_RPT/SW_DEFINE
  TX-report requests; 32-byte RX status decode including `rpt_sel` (C2H),
  VHT NSS and WoWLAN pattern/magic/unicast wake reasons.
- `c2h` — `rtl_c2h_content_parsing` ids, V1 TX reports
  (`rtl_tx_report_handler`), RA reports with `rtl8821ae_hw_rate_to_mrate`, and
  the `rtl_get_tx_report_sn` SW_DEFINE sequence.

- Retained owners, 8821AE profile — `firmware_transport::Owner` admits
  `0x8821`: `parse` dispatches to `rtl8821ae::fw::parse`,
  `initialize_registered` loads `rtl8821aefw_29.bin` and retries
  `rtl8821aefw.bin` only on `NotFound` (`core.c::rtl_fw_do_work`
  `alt_fw_name`), and the run clears CR DMA/MAC gates, applies the
  `rtl8821ae_hw_init` `REG_SYS_CFG &= 0x7f` and runs `rtl8821ae_download_fw`
  (a still-running RAM image is stopped as Linux's `mac_func_enable` case,
  since probe does not run `_rtl8821ae_poweroff_adapter`). `prepare::Chip`
  selects the linked-ring profile: shared `REG_*_DESA` map, 64-byte TX slots
  with `next_desc_address` at dword 12 (`rtl8821ae/trx.h`), and the exact
  `_rtl8821ae_llt_table_init` over an exact-width `Io::write16`.
  `prepare_native::prepare_rtl8821ae` composes firmware, the one-shot packet
  claim, DMA32 rings and LLT; EE radio qualification refuses the 8821AE
  profile. Native provisioning reaches it (see the station owner below).

- `mac` / `phy` — parked `rtl8821ae_hw_init` hardware steps, reached by
  `Prepared::configure_rtl8821ae` (Prepared → RadioConfigured; the EE
  channel/MAC phases stay unreachable for this profile): the
  `_rtl8821ae_init_mac` remainder (APS_FSMCO[4], HWSEQ, `0x7c[6]` by
  SYS_CFG+3[0], GPIO_MUXCFG, HISR/HISRE W1C, FWIMR, TRXDMA `0xf5b1`, RCR
  `0xf4007b0e`, RXFLTMAP2, PCIE_CTRL+3, INT_MIG, MCUTST_1, secondary CCA),
  the MAC table (byte writes; it rewrites RCR bytes as in Linux), BB enable
  (FEN_PCIEA then BB resets, RF_CTRL, OPT_CTRL+2), PHY_REG with per-row
  delays, AGC dword rows, `cck_high_power`, crystal cap into
  `REG_MAC_PHY_CTRL[23:12]` (EFUSE `0xb9`, `0xff` ⇒ `0x20`), `reg_837`, RADIOA
  through `RA_LSSIWRITE_8821A` (`_rtl8821ae_phy_rf_serial_write`; serial
  read with 20 us HSSI settle), `_rtl8821ae_hw_configure`, software crypto
  (`SECR = 0`), MAC address, NAV upper 235 and the conditional RXDMA BIT2
  release. `_rtl8821ae_read_rfe_type` follows the EFUSE `0xca` tree (the
  4→2 override is 8812AE-only). The table condition comes from live SYS_CFG/
  MULTI_FUNC_CTRL plus the factory map; unprovisioned or test chips fail.
  Deferred to the packet owner as for EE: `REG_CR = 0x2ff`, PCIe DMA
  release and IRQ masks (`IRQ_MASK`/`SYS_IRQ_MASK` recorded). Omitted: LED
  refresh, ASPM back door (ASPM stays disabled) and hardware CAM crypto.

- `txpower` / `envelope` / `channel` — 2.4 GHz path-A power and channel,
  reached by `Prepared::configure_rtl8821ae_channel` (RadioConfigured →
  ChannelConfigured, same retained owner, permission bound to the factory
  identity committed by `configure_rtl8821ae`). `txpower` is the exact Linux
  arithmetic: `_rtl8821ae_read_power_value_fromprom`/`_from_hwpg` path A
  (CCK/BW40 groups, 4-bit signed BW20/OFDM diffs, `EEPROM_RF_BOARD_OPTION`
  regulatory; an autoload-failed or out-of-range map yields no factory power
  instead of Linux's `0x2D` defaults), `PHY_REG_PG` store/BCD base/relative
  conversion (Linux's absolute difference kept), `TXPWR_LMT` minimum-of-rows,
  limit-to-index conversion (including the 2.4 GHz VHT base carry-over) and
  the `TXPWR_LMT_WW` minimum, `_rtl8821ae_phy_get_txpower_by_rate` and
  `_rtl8821ae_get_txpower_index` (remnant indices 0, no thermal tracking; a
  negative sum is refused rather than wrapped to `MAX_POWER_INDEX`).
  `envelope` admits a channel only from a signed per-board `NAPC` v1 file
  (`rtlwifi/rtl8821ae-cal-v1-<mac>.bin`: factory identity, MAC, antenna gain,
  qualified EIRP, per-channel measured CCK/OFDM/1SS output curves for
  channels 1-11, 20 MHz): each station rate (CCK, OFDM, MCS0-7, VHT1SS0-9)
  gets the highest measured index not above the Linux index whose output
  plus antenna gain fits min(host regulatory rule, qualification, `regd.c`
  ch1-11 EIRP) — the shared `channel_power::domain_ceiling` policy. Unsigned,
  foreign, unprovisioned or unmeasured ⇒ not admitted.
  `NAPC` v2 (`rtl8821ae-cal-v2-<mac>.bin`, loaded first; v1 only on
  `NotFound`; v1 parsing unchanged) keeps the v1 header with version 2,
  header bandwidth 0 and up to `V2_ROWS` (98) rows of the same size, each
  keyed by (band 0/1, bandwidth 20/40/80, secondary offset 0/1 above/2
  below, primary channel) in strictly increasing order: 2.4 GHz ch1-11 at
  20 MHz or 40 MHz (above 1-7, below 5-11); 5 GHz the 8821AE plan
  (`CHANNELS_5G`, 36-165) at 20 MHz, 40 MHz with the fixed pairing, 80 MHz
  inside a block (165 has neither); 5 GHz rows must leave the CCK curve
  unmeasured. `envelope::Operating` gives the center frequency;
  `permission_for(domain, op)` applies `span_ceiling` (every overlapping
  host rule covers the whole span, allows the width and has no flag, so
  DFS/NO_IR/indoor rules refuse; capped by `regd.c` 2402-2472 MHz 20 dBm,
  5140-5360 / 5460-5860 MHz 30 dBm). A rate whose curve has no fitting
  measured index is left unadmitted (TXAGC 0, outside `admitted_rates`)
  instead of failing the whole permission; every legacy rate of the band
  must be admitted. The Linux index is composed for every v2 operating
  point (`txpower::ByRate::index_at`): it runs at the *wide* channel
  `core.c::rtl_op_config` stores in `current_channel` (40 MHz primary ± 2,
  80 MHz block center; `Operating::wide_channel`) and the operating
  `current_chan_bw`. 2.4 GHz 40 MHz: CCK/BW40 group bases of the wide
  channel, OFDM diff, no HT/VHT diff (`txpwr_ht40diff[TX_1S]` is 0). 5 GHz
  (path-A block `0x22`-`0x2f` 14 group bases, `0x30` BW20/OFDM diffs,
  `0x36` BW80 diff; `_rtl8821ae_get_chnl_group` 5 GHz groups; per-channel
  index from `core.c::channel5g`): base of the wide channel's group, OFDM
  diff, 20 MHz BW20 diff, 40 MHz no diff (`txpwr_5g_bw40diff[TX_1S]` 0),
  80 MHz HT/VHT `(group + next group) / 2 + bw80_diff` per `channel5g_80m`
  while OFDM keeps the 40 MHz base; no CCK. An unprogrammed 5 GHz block
  (`0x30 == 0xff`), group (> 63, Linux's `0xFE`) or BW80 diff (`0x36 ==
  0xff`) yields no factory power for the points that need it. 5 GHz
  power-by-rate (`PHY_REG_PG` band 1, bases OFDM/HT/HT2/VHT/VHT2 into
  `txpwr_by_rate_base_5g`, relative conversion) and limits
  (`_rtl8812ae_phy_get_txpower_limit`: OFDM always the 20 MHz rows, 5 GHz
  HT at 80 MHz reads the 40 MHz rows, `_rtl8812ae_phy_cross_reference_ht_and_vht_txpower_limit`
  HT↔VHT fill-in at 5 GHz 20/40 MHz, 5 GHz section bases) are the Linux
  arithmetic (`ByRate::limit_at` / `by_rate_at`). The 5 GHz permission
  carries `phy_get_tx_swing_8812A(BAND_ON_5G)` (EFUSE `0xC7`, same decode).
  `channel::configure(io, permission, reg_837)` programs 2.4 GHz 20 and
  40 MHz permissions: `sw_chnl_callback` and TXAGC at the wide channel,
  then `set_bw_mode_callback(HT_CHANNEL_WIDTH_20_40)` — `_rtl8821ae_phy_set_reg_bw`
  (`REG_TRXPTCL_CTL` BIT(7) set, BIT(8) clear), `_rtl8821ae_phy_get_secondary_chnl`
  (secondary above ⇒ `VHT_DATA_SC_20_LOWER_OF_80MHZ` 2, below ⇒ upper 1)
  into `0x483`, `RRFMOD` `0x00300201` and `[5:2]`, `RCCAONSEC[31:28]`,
  1T1R `RL1PEAKTH` 8 (6 when `reg_837` BIT(2)), `RCCK_SYSTEM` BIT(4) for
  an upper primary, RF `0x18[11:10] = 1` on paths A and B. 5 GHz
  permissions (20/40/80 MHz) are programmed too: `switch_wirelessband(5G)`
  8821AE branch (`RA_RFE_PINMUX` LNA 5 / PAPE 4, `REG_CCK_CHECK` 0x80, the
  bounded 50 x 50 us `REG_TXPKT_EMPTY[5:4]` wait Linux continues past,
  `RA_TXSCALE[11:8] = 1`, `RTXPATH[7:4] = 0`, `RCCK_RX[27:24] = 0xf`, the
  5 GHz swing); the 8821AE branch has no RFE-type programming (the RFE
  pin tables are 8812AE-only), so no RFE type needs refusing here.
  `sw_chnl_callback` ranges: `RFC_AREA` 0x494 (36-48) / 0x453 (50-64) /
  0x452 (100-116) / 0x412 (118+), RF 0x18 band 0x101 / 0x301 / 0x501, RF
  `RF_APK` 0x114e9 (36-64) / 0x110e9; TXAGC skips CCK at 5 GHz;
  `set_bw_mode_callback(80)`: `REG_TRXPTCL_CTL` BIT(8) set / BIT(7) clear,
  `0x483 = sc40 << 4 | sc20` from the primary's position in the 80 MHz
  block (`channel::data_sc80`), `RRFMOD` `0x00300202` and `[5:2]`,
  `RADC_BUF_CLK[30] = 1`, `RCCAONSEC`, 1T1R `RL1PEAKTH` 7 (5 when
  `reg_837` BIT(2)), RF `0x18[11:10] = 0`. IQK runs at the permission's
  band (`0xc8c` 5 GHz values); at 80 MHz it runs the VDF branch (`iqk`
  below). `rtl8821ae_phy_lc_calibrate` is empty in
  Linux. Test `smoke_rtl8821ae_5ghz_band_channel_and_bw80` (written,
  unexecuted). The 5 GHz station (below) requests these permissions. The station owner requests a 40 MHz permission
  for an HT40 AP (HT20/40 station, below). No board values are supplied by the
  format. Tests
  `smoke_rtl8821ae_napc_v2_rows_bands_widths_and_partial_admission`,
  `smoke_rtl8821ae_txpower_index_bw40_and_5ghz`,
  `smoke_rtl8821ae_napc_v2_permission_bw40_and_5ghz` (written,
  unexecuted). `channel` programs
  `rtl8821ae_phy_switch_wirelessband(2.4G)` with `phy_get_tx_swing_8812A`
  (EFUSE `0xC6`, path-B decode wins as in Linux; RA/RB_TXSCALE), then
  `sw_chnl_callback` (RFC_AREA `0x96a`, RF `0x18`), the admitted per-rate
  TXAGC byte RMWs and `RA_TXPWRTRAING` (levels saturate at 2 instead of
  Linux's `u32` wrap), then `set_bw_mode_callback(20 MHz)` incl. the Linux
  path-B RF bandwidth write. LCK: `rtl8821ae_phy_lc_calibrate` is empty in
  Linux and `hw_init` comments it out, so there is no 8821AE LCK effect.

- `iqk` — path-A IQ calibration, `Prepared::calibrate_rtl8821ae_iqk`
  (ChannelConfigured, MacConfigured or Running, admitted permission held):
  `phy.c::_rtl8821ae_phy_iq_calibrate` — MAC/BB, AFE and RF-A backups,
  `_rtl8821ae_iqk_configure_mac` (`0x522 = 0x3f` TX pause, `0x550[11,3]`,
  RX antenna off, CCA off), ten `_rtl8821ae_iqk_tx` rounds (LOK with
  RF `0x58` load, TX IQK, RX-mode TXK, RX IQK with up to ten retries on
  `0xd00[11]`), the first pairwise-agreeing average (TX ±3, RX ±4,
  sign-extended 11-bit samples, C truncating division) filled through
  `_rtl8821ae_iqk_{tx,rx}_fill_iqc` (identity `0x200,0` when no pair
  agrees; RX left untouched when no RX round passed), then RF/AFE/MACBB
  restore — also attempted when a round fails with an I/O error, which
  fails the owner. `iqk::LinkedInterval::tick` is
  `dm.c::rtl8821ae_dm_iq_calibrate`: IQK fires once, on the second DM
  watchdog period with `link_state >= LINKED`; losing the link re-arms it.
  Divergences from Linux, deliberate: (1) backup sets are the full intended
  lists — all 11 MAC/BB registers including `0x82c` and the 12 listed AFE
  registers; the helper-scope `MACBB_REG_NUM 10`/`AFE_REG_NUM 14` defines
  are never applied to these lists and no register-0 access is made
  (restoring more state than a short count would is safe); (2) Linux's
  never-used path-B RF backup read is omitted on this 1T1R chip; (3) Linux
  gates TX one-shots with `~iqk_ready`/`~tx_fail` on 0/1 values, which is
  always true, so every TX shot is accepted on its first attempt — kept as
  the hardware-validated behaviour (status reads still issued); the RX
  `rx_fail == 0` check is real; (4) Linux indexes RX samples by round but
  averages `0..rx_average`, reading uninitialised slots after a failed RX
  round — here only successful RX samples, in round order, are compared.
  All `current_chan_bw` branches exist (40 MHz: RF `0x18[11:10] = 1`
  after LOK, see HT40 below; 80 MHz: `= 0`). At 80 MHz (`vdf_enable`) each
  round runs Linux's VDF paths: TX IQK as three tones on page C1 (`0xc80/
  0xc84` `0x18008c38`/`0x38008c38` with `0xce8[31] = 0`; BIT(28) cleared;
  `0x18008c20`/`0x38008c20` with `0xce8[31] = 1` and `tx_dt` in
  `0xce8[29:16]`), the third tone being `tx_x0[cal]`; then TX VDF off and
  three tones of RX-mode TXK (`0xcb8[3:0] = 0xd`, `0xc88 = 0x821603e0`,
  `0xc8c = 0x68163e96`; tone 1 `0x08008c38`/`0x28008c38`, tone 2 `rx_dt` in
  `0xce8[13:0]`) + RX IQK (`0xcb8[3:0] = 0xe`, `0xc80[29] = 1`,
  `0xc84[29] = 0`, RX VDF `0xce8[30] = 1` on tone 2), the third RX tone
  being `rx_x0[cal]` and its pass/fail `rx0iqkok`; TX VDF back on.
  `iqk::vdf_dt` is `tx_dt`/`rx_dt`: `(16 * 2(y1 - y0)) * 10000 / {15708,
  13823}`, then `(dt >> 1) + (dt & 1)` (C int semantics). The `vdf_x/y`
  scratch is shared between the TX and RX loops as in Linux, so a failed
  RX tone leaves the TX sample in its slot for `rx_dt`. Tests
  `smoke_rtl8821ae_iqk_80mhz_vdf_branch`,
  `smoke_rtl8821ae_iqk_fill_and_full_restore`,
  `smoke_rtl8821ae_iqk_rx_fail_retries_and_untouched`,
  `smoke_rtl8821ae_iqk_linked_interval_and_agreement` (written, unexecuted).

- `h2c` / `mac::ReceiveConfig` — firmware command, LPS and interrupt
  pieces for the station owner (not yet composed). `h2c::Mailbox::fill` is
  `fw.c::_rtl8821ae_fill_h2c_command`: `REG_CR == 0xEA` (MAC off) ⇒ the
  `REG_SYS_CFG1+3 = 0xff` side effect and `RadioOff`; HMETFR polled one
  plus 99 × 10 us; byte-wise writes, 4–7-byte commands writing the
  zero-padded 4-byte extension box first; `last_hmeboxnum` rotation. A
  timeout or MAC-off box is an error that poisons the mailbox (Linux drops
  the command silently). Builders: `media_status` (`MSRRPT`, INFRA MACID
  0), `pwrmode` (`SETPWRMODE`, ACTIVE = switch default rlbm 2/interval 4/
  `FW_PWR_STATE_ACTIVE`; MAX from `reg_fwctrl_lps = 2`; smart_ps 1,
  byte5 `0x40`), `rsvdpage_location`, `rate_mask`
  (`rtl8821ae_update_hal_rate_mask` for a 2.4 GHz B/G/N 1T1R station on a
  20 MHz channel: `rtl_op_sta_add` mode selection, RSSI-level masks,
  `rtl_mrate_idx_to_arfr_id`, short-GI, `!update_bw << 3`), `set_bcn_ctrl`,
  `set_rpwm` (`HW_VAR_SET_RPWM` toggle), `fwlps_enter`/`fwlps_leave`
  (`low_power_enable` false). These are the `bt_ctrl_lps == false` forms:
  Linux 8821AE reports `get_btc_status() == true`, but coex only takes LPS
  control on boards with the BT function (`REG_MULTI_FUNC_CTRL[18]`);
  BT-strapped boards are admitted with the pass-1 coexistence owner
  (`rtl8821ae/coex.rs`: bound `btc_coexist` facts, the TDMA decision
  matrix, and the LPS gate — BT-state notify and the per-traffic-class
  8821A algorithm tables are outstanding).
  Interrupts: `enable_interrupt` with `int_clear` (HISR/HISRE/HSISR
  write-back, then HIMR/HIMRE/HSIMR; no `REG_C2HEVT_CLEAR` write on this
  chip), `disable_interrupt`, `service_interrupt` (disable → recognize W1C
  under `irq_mask` → enable, as `_rtl_pci_interrupt`; the 88EE/8723BE-only
  HSISR handler is not run). `mac::ReceiveConfig::set_check_bssid` is
  `rtl8821ae_set_check_bssid` with the software `receive_config` and cached
  `reg_bcn_ctrl_val`: the first call settles the hardware RCR, whose
  `0x608`/`0x609` bytes the MAC table rewrote after `_rtl8821ae_init_mac`.
  Tests `smoke_rtl8821ae_h2c_box_bytes_extension_first_and_rotation`,
  `smoke_rtl8821ae_h2c_busy_box_and_powered_off_mac_fail_closed`,
  `smoke_rtl8821ae_h2c_pwrmode_rate_mask_and_lps_order`,
  `smoke_rtl8821ae_interrupt_profile_masks_and_w1c`,
  `smoke_rtl8821ae_rcr_settles_after_mac_table_rewrite` (written,
  unexecuted).

- Native station owner, 8821AE branch (`packet_ae.rs`,
  `rtl8821ae/station.rs`, `rtl8821ae/rsvd_page.rs`, `station_power.rs`).
  The retained `Prepared` packet/station owner dispatches on its chip
  profile; every 88EE path is unchanged. Probe now retains `0x8821` like
  `0x8179` (firmware owner, factory map, native `Device`, ASPM disabled,
  BAR2 at least `MMIO_SIZE`), and `prepare_native::prepare_rtl8821ae`
  (reached from `initialize_registered_on_channel`, i.e. native
  provisioning) continues Prepared → RadioConfigured → ChannelConfigured
  (permission from the signed `NAPC` envelope under current host policy) →
  MacConfigured (`Prepared::configure_rtl8821ae_mac`) and stages the
  envelope for the station. The MSI vector binding is the shared native
  one (`interface::publish` → `arm_msi`), with the 8821AE interrupt profile.
  - Admission binds the coexistence owner on boards with the Bluetooth
    function strapped on (`REG_MULTI_FUNC_CTRL` BIT(18)): coex takes
    LPS/antenna control (`rtl8821ae/coex.rs`, pass 1 — admission, the
    LPS gate, and the TDMA decision matrix).
  - `start_packets`: proves `SECR = 0`, `TXPAUSE = 0` and clear IMRs, opens
    bus mastering, then the `rtl8821ae_hw_init` DMA release (`REG_CR` word
    `0x2ff`, `REG_PCIE_CTRL_REG + 1 = 0`) and `rtl8821ae_set_network_type
    (STATION)` without a link (`_rtl8821ae_set_media_status`: BCN_CTRL dword
    0, stop TX beacon, beacon sub-function, MSR INFRA, BCNTCFG+1 `0x66`;
    then `set_check_bssid(false)`, which settles the MAC-table-rewritten
    RCR). The RCR/BCN_CTRL software cache starts at `receive_config` /
    `0x1d` (`_rtl8821ae_hw_configure`).
  - TX: `rtl8821ae_tx_fill_desc` first+last segment, no early mode, through
    `trx::TxDesc::fill`: descriptor dwords 0..=9 plus the buffer in dword 10,
    dword 12's next pointer untouched; Linux queue selection and doorbells
    as 88EE; BW 20, HWSEQ for non-QoS frames, MACID 0. Ordinary unicast
    DATA once the RA mask is installed follows `rtl_get_tcb_desc` for a
    non-zero rix: `USE_RATE` and `DISABLE_FB` clear, `hw_rate` the mode's
    highest rate (11M for B, 54M otherwise) and RATE_ID the AP's
    `ratr_index` (addr1 is the AP, whatever the DA), so the firmware RA
    picks and falls back inside the mask. This needs no separate
    continuation (unlike 88EE's fixed-rate NEPC/NEFB) because the mask is
    bounded by the `NAPC` permission: `envelope::Permission` carries the
    set of full-order rates holding a measured admitted index
    (`admits`/`admitted_rates`), `h2c::mask_rates` maps the installed
    `H2C_8821AE_RA_MASK` bitmap to full-order rates by `arfr_id` (legacy
    bits 0..=11, HT MCS or VHT1SS bits 12.. by `RATEID_IDX_*`), and
    `ae_install_rate_mask` refuses (`Power(Policy)`) an empty mask or any
    rate outside the admitted set — never silently narrowing it, so the
    Linux mask/`ratr_index` pair stays exact. `ae_submit` likewise refuses a
    descriptor whose `hw_rate` (forced or RA initial) or, with protection
    selected, `DESC_RATE24M` RTS rate is not admitted. Every other frame keeps the forced `hw_rate`
    with fallback disabled and RATE_ID the installed `ratr_index` for
    unicast, `RATR_INX_WIRELESS_MC` otherwise (`_rtl_txrate_selectmode`,
    8821AE has no `RTL_SPEC_NEW_RATEID`). EAPOL (unprotected; software
    crypto has no `hw_key` IV to skip) and Null frames carry `SPE_RPT` +
    `SW_DEFINE` (`rtl_is_tx_report_skb`/`rtl_set_tx_report`, `(++sn &
    0x3f) << 2`). ERP Use_Protection and the RTS threshold select
    protection as 88EE (`protection::select`, AP must offer 24M), filled as
    `_rtl_query_protection_mode`: RTS/CTS sets `RTS_EN`, CTS-to-self
    `CTS2SELF`, both `RTS_RATE = DESC_RATE24M`, long preamble. No NERT
    continuation is needed: the RTS rate must be in the `NAPC` admitted
    set (checked per frame, above). HT is described below. The host receipt checks OWN clear with dwords
    0/1/7, the buffer in dword 10, dword 11/13 zero and the linked next
    pointer.
  - RX: `rtl8821ae_rx_query_desc` fields; anything outside the legacy
    20 MHz profile (or, on an HT link, the HT20 profile below) (CRC/ICV, A-MPDU, HT/VHT rate, BW ≠ 20) is consumed and
    dropped; payload at drvinfo + shift (the PCI buffer holds no
    descriptor); FCS stripped; protected frames require SWDEC (software
    CCMP). With PHYST the `trx.c::query_rxphystatus` PWDB is decoded from
    the PHY status at `rx_bufshift` (`trx::rx_pwdb`): OFDM `((pwdb_all >> 1)
    & 0x7f) - 110`; CCK the 8821 `cfosho[0]` LNA/VGA table with `pout = -6`
    (LNA 3/6/7 leave `rx_pwr_all` 0 as Linux; no `cck_high_power` step on
    8821), both through `rtl_query_rxpwrpercentage`. PHYST with drvinfo
    shorter than the 6 read bytes is a descriptor error. The station feeds
    BSSID-matching frames to `rtl_process_pwdb` (zeroed `undec_sm_pwdb`).
  - C2H (`rpt_sel`, `rtl_c2hcmd_enqueue` → `rtl_c2h_content_parsing`):
    V1 TX reports (`rtl_tx_report_handler`) record `last_recv_sn` and
    complete the matching outstanding `SW_DEFINE` with `st == 0` as the
    ACK and the retry count (`take_rtl8821ae_tx_report`,
    `rtl8821ae_tx_reports_settled` = `rtl_check_tx_report_acked` without
    the 3 s timeout, which the caller's deadline owns); RA reports
    (`rtl8821ae_c2h_ra_report_handler`) record `rtldm->tx_rate`. BT
    info/MP reports are ignored (BT boards are not admitted).
  - Join (`rtl_op_bss_info_changed`): authentication-time BSSID, RRSR
    (`supp_rates & 0x15f`), `rtl8821ae_update_channel_access_setting`
    (slot, SIFS `0x0a` for mode G else `0x0e`, R2T `0x0a`), the fixed
    `rtl8821ae_set_qos` BK/VI/VO rows and the ACK preamble; at association
    CAM reset, `HW_VAR_KEEP_ALIVE` (10), `set_network_type` with the link
    (CBSSID on), then `HW_VAR_H2C_FW_JOINBSSRPT(CONNECT)`: `HW_VAR_AID`,
    `_rtl8821ae_download_rsvd_page(false)` (CR+1 BIT0, BCN_CTRL BIT3/BIT4,
    TXQ BIT6, up to five uploads of `rtl8821ae_set_fw_rsvdpagepkt(false,
    false)` — the verbatim `reserved_page_packet_8821` pages 0..4 with the
    Linux A1/A2/A3/AID substitutions (the template now keeps the Linux
    `0XB2`/`0XB3` bytes of pages 3/4, whose loss had shifted the BT-QoS-Null
    frame control and TX descriptor; `smoke_rtl8821ae_rsvd_page_template_page_layout`),
    1240 bytes, `rtl8821ae_tx_fill_cmddesc`
    on BEACON descriptor 0 and BIT(4) polling — each followed by the
    `H2C_8821AE_RSVDPAGE` location command, 20 × 10 us BCN_VALID polls) and
    the MSRRPT connect report. A BCN_VALID timeout (Linux logs and goes on)
    is terminal. The RA mask (`rtl8821ae_update_hal_rate_mask`, level
    `DM_RATR_STA_INIT`, `update_bw`) follows; its `ratr_index` is kept for
    data descriptors. LPS uses `_rtl8821ae_fwlps_{enter,leave}`.
    Disassociation: leave LPS, `set_network_type` without link, MSRRPT
    disconnect and zero BSSID (AID left as Linux does); rings stay live.
  - DM watchdog (`refresh_station_rate_mask` slot, every
    `RTL_WATCHDOG_TIME`, firmware awake), in `rtl8821ae_dm_watchdog`
    order: `rtl8821ae_dm_refresh_rate_adaptive_mask` (linked station; high
    threshold 50, low `low2high_rssi_thresh_for_ra40m`, which dm init never
    sets, so 0; `go_up_gap` 5 raises high from MIDDLE and both from LOW) —
    a level change re-sends `rtl8821ae_update_hal_rate_mask(level,
    update_bw)` inside the envelope's authority; then a pending RA
    report's `rtl8821ae_dm_update_init_rate` →
    `rtl8821ae_dm_txpwr_track_set_pwr(MIX_MODE, path A)` without thermal
    tracking: `RA_TXSCALE[31:21] = txscaling_tbl[default_ofdm_index]`
    (the swing's table index, 24 when absent) when within the rate's
    `pwr_tracking_limit` (Linux's `MGN_1M..MGN_11M` numeric range, which
    also covers 6M/9M, is kept); above the limit (only VHT1SS MCS8/9 can
    be) Linux would re-run TXAGC with a remnant, which is refused. Linux
    runs the report from `c2hcmd_wq`; here it is deferred to this step so
    the BB write happens inside the current authority. Then
    `iqk::LinkedInterval` and `calibrate_rtl8821ae_iqk`.
  - Station power base: the station re-derives the channel grant from the
    `NAPC` envelope (`station_power::Base`/`Grant`) at every publication and
    wait, as it does from `NEPC` for 88EE.
  - ERP: an AP announcing Use_Protection is admitted on 8821AE (and
    8192EE, below; 88EE still needs the NERT grant); the beacon-tracked ERP flag drives the
    per-frame protection mode.
  - Fresh-generation recovery rebuild (`rebuild_native.rs`,
    `power_runtime::{disable,enable}_rtl8821ae`). After the shared
    old-DMA retirement proof, `power_down` runs Linux
    `_rtl8821ae_poweroff_adapter` in source order:
    `RTL8821A_NIC_LPS_ENTER_FLOW`; `rtl8821ae_firmware_selfreset`
    (RSV_CTRL+1 BIT0 / SYS_FUNC_EN+1 BIT2 low, 50 us, both high) only when
    MCUFWDL BIT7 is set and the owner's firmware stage is Ready;
    SYS_FUNC_EN+1 BIT2 low; MCUFWDL = 0; `RTL8821A_NIC_DISABLE_FLOW`;
    RSV_CTRL+1 BIT0 low/high; RSV_CTRL = 0x0e. Linux's preceding
    `_rtl8821ae_set_media_status(UNSPECIFIED)` is not issued (88EE
    precedent): the card-disable/enable cycle resets MSR and the fresh
    owner's MAC init programs it before any link. ASPM is not touched
    afterwards (8821AE keeps it disabled). `rebuild` then runs the
    `_rtl8821ae_init_mac` enable prefix (RSV_CTRL = 0, APS_FSMCO+1 BIT7
    low, `RTL8821A_NIC_ENABLE_FLOW` with `PWR_CUT_A_MSK`, as at probe),
    re-verifies the EFUSE factory identity, builds a fresh
    `Owner(RTL_DEV_8821AE)` and runs `initialize_registered_on_channel`
    (`prepare_rtl8821ae`: firmware, LLT, MAC/BB/RF, IQK, `NAPC` channel
    permission). The same `power_down` now serves system suspend / IPS for
    this profile (it previously ran the 88EE table). Channel retune
    (`allow_channel`) is admitted by the `NAPC` 20 MHz permission and
    rebuilds through this flow on 2.4 GHz channels 1-11. After a
    disconnect the width is not narrowed eagerly: the running-owner width
    retune is only legal in Joining/Configuring, and the next join (or any
    rebuild) re-programs 20 MHz first. Test
    `smoke_rtl8821ae_recovery_poweroff_and_enable_order` (written,
    unexecuted).
  - Not composed for 8821AE: ASPM (kept disabled), WMM EDCA from the
    AP (Linux 8821AE ignores it too), VHT, BT coexistence.
  - HT20 station (`rtl8821ae/ht.rs`). HT is offered only when the AP
    has WMM and the current `NAPC` permission admits every rate of the
    Linux association RA mask (`ht::admitted`: MCS0-7 measured), so the
    `RATEID_IDX_BGN_40M_1SS` mask stays a subset of the admitted set.
    Capability: `base.c::_rtl_init_hw_ht_capab` for 1T1R — SGI20, MAX_AMSDU
    (7935-byte RX; `disable_amsdu_8k` unset), A-MPDU factor 3 (64K),
    density 7 (16 us), RX/TX MCS0-7 `TX_DEFINED`, SMPS disabled, no
    STBC/LDPC; the 20/40 bit with SGI40/DSSSCCK40 only with a 40 MHz
    permission (HT20 form otherwise, since the station could not follow a
    40 MHz BSS). Not advertised, deliberately: MCS32 (`rx_mask[4]`) and
    `rx_highest` (left 0). At association (`BSS_CHANGED_HT`):
    `HW_VAR_SHORTGI_DENSITY` / `HW_VAR_AMPDU_FACTOR` (8821AE `(0x2000 <<
    min(peer, 3)) - 1`, `0xffff` at 64K, BIT(31), `0x458`) /
    `HW_VAR_AMPDU_MIN_SPACE` (density `max(7, peer)` into the
    `min_space_cfg` cache, `0x45c`), inside the station publication;
    `mac->mode = WIRELESS_MODE_N_24G` gives SIFS `0x0e`. RA mask: the
    mac80211 intersection (`tx_mcs`, both-side SGI) into
    `rtl8821ae_update_hal_rate_mask` (N24 rows, `current_chan_bw`, SGI bit),
    descriptor RATE_ID `RATR_INX_WIRELESS_NGB` (0) and RA initial rate
    `DESC_RATEMCS7` (`_rtl_get_highest_n_rate`). TX: data SGI only for
    `hw_rate > DESC_RATEMCS0`, AGG_EN + MAX_AGG_NUM `0x1f` for an
    operational originator BA TID, the peer's `ampdu_density`; the shared
    station BA/ADDBA/reorder owner is unchanged. RX: MCS0-7 and A-MPDU
    members accepted on the HT link (BW 20 only), MPDUs up to the 7935-byte
    A-MSDU; Linux's `is_short_gi = !SPLCP` only feeds rate statistics, so
    no frame is gated on it. An AP with HT protection mode ≠ 0 is refused
    (as on 88EE). Test `smoke_rtl8821ae_ht_capability_timing_and_n_mask`
    (written, unexecuted).
  - HT40. At join the AP's HT40 offer (against the 20/40 capability) gives
    a geometry on the provisioned primary; the 20/40 capability is sent
    only when `permission_for(domain, 2.4 GHz 40 MHz above/below)` succeeds
    under current host policy and admits MCS0-7. Before authentication
    (mac80211's BSS chandef) and again at Configuring (the negotiated
    width, which may narrow to 20 MHz) the owner re-derives the target
    permission (`legacy20` for 20 MHz) and, if it differs from the held
    one, runs `channel::configure` (band switch, `sw_chnl_callback` and
    TXAGC at the wide channel, `set_bw_mode_callback`) inside that
    permission's authority (`station_power::wait_rtl8821ae` now re-derives
    at the grant's operating point, as does `Base::regrant` for every
    station policy check), with no frame outstanding and the receive epoch
    retired; failure fails the owner. The link keeps the width after a
    disconnect until the next join retunes. TX at 40 MHz:
    `_rtl_query_bandwidth_mode` (unicast above 54M ⇒ packet BW40) through
    `rtl8821ae_bw_mapping`/`rtl8821ae_sc_mapping` (BW40 ⇒ DATA_BW 1, SC 0;
    20 MHz packets name the primary, secondary above ⇒ 2, below ⇒ 1), SGI
    from the both-side SGI40 (`_rtl_query_shortgi`), RA mask
    `current_chan_bw` 1 with the BW40 N rows (`0x000ff015`). RX accepts BW
    20/40. IQK at 40 MHz restores RF `0x18[11:10] = 1` after each LOK load
    (`iqk::calibrate_at`). Test
    `smoke_rtl8821ae_ht40_regrant_and_iqk_bandwidth_restore` (written,
    unexecuted).
  - 5 GHz station (8821AE only; 88EE stays on 2.4 GHz 1-11 because its
    `allow_channel`/`channel_power` refuse every other channel). The
    channel identity stays the primary channel number (5 GHz numbers never
    collide with 1-14): `envelope::Operating::twenty` takes the band from
    it (36+ ⇒ 5 GHz, as `rtl_op_config` takes it from the chandef), and
    `Calibration::permission` (allow_channel, `prepare_rtl8821ae`,
    `admit_rtl8821ae`) is the 20 MHz `NAPC` v2 permission on that band.
    `station_channel` / `station_frequency_mhz` / `station_channel_at`
    (2.4 GHz 1-11 at 2407 + 5 ch, the `CHANNELS_5G` plan at 5000 + 5 ch)
    replace the `1..=11` / 2407 shapes in scan (`available_channels` lists
    1-11 then the 5 GHz plan, each only if `allow_channel` admits it;
    requested channels/frequencies; observation frequency; join
    channel/frequency), `retune_once`, `set_config` and the
    `initialize_registered_on_channel` 8821AE dispatch (moved before the
    88EE 1-11 gate). DFS / NO_IR / indoor rules refuse the permission
    (`span_ceiling`), so such channels are neither listed, scanned nor
    joined — a deliberate narrowing of cfg80211, which would passively
    scan NO_IR channels; no receive-only grant exists. Interface band
    advertisement lists a 5000 MHz band with the admitted 5 GHz channels
    (HT capability as at 2.4 GHz). Probe requests on 5 GHz are
    `ieee80211_put_preq_ies_band` for the 5 GHz band: Supported Rates
    6-54 Mb/s (`rtl_ratetable_5g`, eight rates, no Extended Supported
    Rates) and no DS Parameter Set. Candidates (`Candidate::receive`)
    and joins on 5 GHz require no CCK rate and 6 Mb/s supported and basic
    (the 2.4 GHz analogue of the 1 Mb/s rule). Management, probe, EAPOL
    and Null frames use `_rtl_get_tx_hw_rate` of `rate_control_send_low`,
    the band's lowest rate: `DESC_RATE6M` on 5 GHz (`DESC_RATE1M` on
    2.4 GHz), which the permission must admit (every 5 GHz legacy rate is).
    The reserved-page download descriptor keeps `rtl8821ae_tx_fill_cmddesc`'s
    `DESC_RATE1M` on both bands, as Linux (it is a beacon-queue download,
    not an on-air frame). `configure_rates(five_ghz)`: RRSR
    `basic & 0x15f` (`supp_rates[1] << 4` layout), slot 9 (mac80211
    `ieee80211_handle_bss_capability` forces short slot on 5 GHz), SIFS
    `0x0e` (`WIRELESS_MODE_A`/`N_5G`, never G). RA mask
    (`rtl8821ae_update_hal_rate_mask`): `WIRELESS_MODE_A` ⇒
    `RATR_INX_WIRELESS_G` / `RATEID_IDX_G` (7), `bitmap & 0xff0`;
    `WIRELESS_MODE_N_5G` ⇒ `RATR_INX_WIRELESS_NG` / `RATEID_IDX_GN_N1SS`
    (5) with the N_24G 1T1R rows; data RA initial rate 54M (A) / MCS7
    (N_5G); RATE_ID the raw `ratr_index` (5 / 1), multicast
    `RATR_INX_WIRELESS_MC`. HT40 on 5 GHz: `ht::Geometry::new_5g` takes
    only the fixed 8821AE pairing (36/40 .. 140/144, 149/153, 157/161);
    `rtl8821ae_wide` and `retune_rtl8821ae` build the 5 GHz operating
    point (band of the held permission), and `channel::configure` runs the
    5 GHz band switch / `sw_chnl` / `set_bw_mode` above. Test
    `smoke_rtl8821ae_5ghz_station_plan_probe_ra_mask_and_rates`
    (`rtl8821ae/tests.rs`, written, unexecuted).
  - VHT80 station (8821AE, 5 GHz only; `rtl8821ae/vht.rs`). Capability is
    `base.c::_rtl_init_hw_vht_capab` for `HARDWARE_TYPE_RTL8821AE`: RX/TX
    map 1SS MCS0-9 (`0xfffe`), `SHORT_GI_80`, `TXSTBC`, `RXSTBC_1`, A-MPDU
    exponent 7; no LDPC (`vht_ldpc_cap` 0). TX STBC is advertised as Linux
    but, as in `rtl8821ae_tx_fill_desc`, no descriptor requests STBC; RX
    STBC is baseband-decoded. Deliberate omissions (promises not
    implemented): SU beamformer/beamformee (no sounding code, in Linux or
    here), `HTC_VHT`, antenna-pattern bits, `MAX_MPDU_LENGTH_11454` (the
    9100-byte RX buffer cannot hold one; 3895 is advertised) and the
    `rx/tx_highest` rates. The join offers `vht::local()` (HT20/40 +
    VHT80) only when `rtl8821ae_vht80` finds an AP VHT80 selection whose
    80 MHz block matches the `NAPC` v2 W80 permission's wide channel and
    that permission, under current host policy, admits VHT 1SS MCS0-9 and
    HT MCS0-7 (`vht::admitted`); otherwise the HT20/40 profile. Width
    targets reduce an 80 MHz selection to its primary HT40 pair
    (`rtl8821ae_offered_width`) and `retune_rtl8821ae(.., eighty)` requests
    the W80 permission (`rtl_op_config` `CHAN_WIDTH_80`: `channel::configure`
    80 MHz, IQK VDF). A VHT association answer narrowed below 80 MHz is
    refused (`Error::Profile`), never run as an unadmitted mode. RA:
    `rtl8821ae_update_hal_rate_mask` `WIRELESS_MODE_AC_5G` —
    `supp_rates_5g << 4 | _rtl8821ae_rate_to_bitmap_2ssvht(rx_mcs_map) << 12`
    (mac80211-intersected map), 1T1R rows `0x003f8000`/`0x003ff000`/
    `0x003ff010`, BIT21 dropped at 20 MHz (`_set_ra_vht_ratr_bitmap`),
    `RATR_INX_WIRELESS_AC_5N` → `RATEID_IDX_VHT_1SS` (10), SGI from any
    intersected SGI20/40/80, `rate_mask[2] = current_chan_bw (2) |
    !update_bw << 3 | vht_eni 1 << 4`; the mask stays a subset of the
    admitted set (`ae_install_rate_mask`). Data descriptors: RATE_ID
    `RATR_INX_WIRELESS_AC_5N` (8), `hw_rate` `_rtl_get_vht_highest_n_rate`
    (1T1R: MCS7/8/9 from the intersected `tx_mcs_map`), admission via the
    descriptor-to-TXAGC order (`vht::order`: VHT1SS 0x2c..0x35 → 28..37);
    at `current_chan_bw` 80 `_rtl_query_bandwidth_mode` +
    `rtl8821ae_bw_mapping` (unicast > MCS15 ⇒ 2, > 54M ⇒ 1, else 0) and
    `rtl8821ae_sc_mapping` (80: 0; 40: `cur_80_prime_sc` 40-of-80; 20:
    primary 20-of-80 — the `channel::data_sc80` nibbles); SGI from SGI80
    (`_rtl_query_shortgi` with `bw_80`). RX accepts VHT 1SS MCS0-9
    (`rtl8821ae_get_rx_vht_nss` 1) and BW 80 on the 80 MHz channel. C2H RA
    reports keep `rtl8821ae_dm_update_init_rate` for any reported rate.
    Host API (`get_wireless_info` / `phy_capabilities`, nl80211
    `GET_WIPHY`): `base.c::_rtl_init_mac80211` runs
    `_rtl_init_hw_ht_capab` on both sbands and `_rtl_init_hw_vht_capab`
    on the 5 GHz sband only. `vht::host_capabilities` derives per-band
    bits from the staged `NAPC` envelope under current host policy
    (`Calibration::operating_points` + `permission_for`): HT on an
    `ht::admitted` 20 MHz point, the 20/40 HT form on an `ht::admitted`
    40 MHz point, VHT (with the 20/40 HT form) on a `vht::admitted`
    5 GHz W80 point. The interface stores them when the station service
    starts / a join is published and clears them on close; `hw_caps`
    `vht_supported` needs the VHT bit and a listed 5 GHz band, and
    `vht::host_phy` returns the association-path bodies
    (`ht::capability(forty)`, `vht::capability()` on 5000 only). Without
    an admitted W80 point no VHT is advertised (never a capability the
    join could not use). Tests
    `smoke_rtl8821ae_host_vht_capability_per_band`,
    `smoke_rtl8821ae_vht80_capability_ra_mask_and_tx_mapping`,
    `smoke_rtl8821ae_iqk_80mhz_vdf_branch` (written, unexecuted).
  - WoWLAN pieces (8821AE, `rtl8821ae/wow.rs`; used by the suspend/resume
    path below). Capability as Linux
    `base.c::_rtl_init_mac80211` with `sw.c` `wo_wlan_mode = MAGIC |
    PATTERN`: magic packet, 16 patterns of 13..=128 bytes, no offset; no
    disconnect / GTK-rekey trigger (Linux never sets `gtk_offload_enable`
    or `arp_offload_enable` for this chip, so GTK rekey offload is out of
    scope; the firmware still wakes on disconnect). H2C payloads
    `rtl8821ae_set_fw_wowlan_mode` (0x80), `_remote_wake_ctrl_cmd` (0x81),
    `_keep_alive_cmd` (0x03, 10 s), `_disconnect_decision_ctrl_cmd`
    (0x04, 30 s / 3), `_global_info_cmd` (0x82) and the
    `H2C_8821AE_AOAC_RSVDPAGE` (0x83) locations; whole-packet reserved
    pages (`rtl8821ae_set_fw_rsvdpagepkt(.., true)`: pages 5..7 verbatim in
    `rsvd_page::WOWLAN_TEMPLATE`, ARP-response A1/A2/A3, 2008 bytes);
    `core.c::_rtl_add_wowlan_patterns` (type, 6-bit mask shift, CRC over
    the masked bytes after DA/SA, `crc16_ccitt` + complement) and
    `hw.c::rtl8821ae_add_wowlan_pattern` WKFM CAM writes through the RX
    packet-buffer window (a write the buffer never completes is an error
    here; Linux only warns), then `REG_WKFMCAM_NUM`; wake reason
    `_rtl8821ae_get_wakeup_reason` (`REG_MCUTST_WOWLAN`). 8812AE (PCI
    0x8812, `rtl8812aefw_wowlan.bin`) is not a supported chip here: its
    probe is not bound, so its WoWLAN is out of scope. Test
    `smoke_rtl8821ae_wowlan_payloads_patterns_and_wake_reason` (written,
    unexecuted).
  - WoWLAN system suspend/resume (8821AE, whole path; the host capability
    is advertised). Interface: `wowlan_support` returns `wow::support()`
    only for a published native RTL8821AE (`Lifecycle::wowlan_capable`),
    `set_wowlan` re-validates (`wow::validate`, EINVAL) and retains the
    configuration in `Lifecycle::wowlan` across generations,
    `wowlan_config` returns it; other chips keep `EOPNOTSUPP`.
    Suspend (`system_sleep.rs`): `prepare_suspend_target(target)` first
    admits the endpoint PME → `_PRW` GPE route from D3hot
    (`PciIo::wake_route`, `narf_power::pci_wake`); without one (or with the
    target-less `prepare_suspend`) the normal card-disable runs. With a
    route, `Operation::WowSuspend` → `sleep_once(.., wow)`: under the
    prepared mutex, before admission closes, the associated `Open`
    station runs `Prepared::wow_suspend` → `packet_ae::ae_wow_card_disable`
    in Linux order: `_rtl_add_wowlan_patterns` (WKFM CAM),
    `rtl_lps_leave`, `disable_interrupt`, `REG_MCUTST_WOWLAN = 0`,
    `rtl8821ae_set_fw_related_for_wowlan(true)` (`rtl8821aefw_wowlan.bin`
    from the trusted registry, `firmware_transport::
    registered_wowlan_image`; H2C box and FW PS state reset),
    `_rtl8821ae_dynamic_rqpn(0xE0, 0x3, 0x80c20d0d)` (`wow::dynamic_rqpn`,
    `wow::init_llt`), `set_fw_global_info_cmd` (`NO_ENCRYPTION` both: this
    software-CCMP profile is Linux's `sw_crypto` case, so the firmware
    only matches magic packets / patterns in unprotected frames),
    `_rtl8821ae_download_rsvd_page(true)` (the whole-packet body, AOAC
    location H2C after each upload, `send_beacon` repeat, `REG_CR + 1`
    BIT(0) kept), `HW_VAR_AID`, MSRRPT connect, `set_fw_wowlan_mode(1)`,
    keep-alive, disconnect decision, RX DMA drain, `REG_APS_FSMCO + 1 =
    0`, `SYS_CLKR |= BIT(3)`, `RSV_CTRL = 0x20, 0x60`,
    `set_fw_remote_wake_ctrl_cmd(1)` (last H2C), PCIe TX DMA stop.
    Divergences: Linux continues after the RXDMA-idle and TX-DMA-idle
    poll timeouts; here they (with cleared bus mastering) are the host DMA
    retirement proof, so a timeout fails the branch and the owner takes
    the existing cold card-disable. `reset_trx_ring` is not needed (the
    rings are retired; resume is a fresh generation). PME status is
    cleared by the PME arm's PMCSR write. Then `wow_parked` (power state
    3, H2C box retained), config save, PME/GPE arm, D3hot + 10 ms settle.
    The host link is reported down when admission closes at suspend.
    Resume: `resume_from_suspend` D0 + settle + config restore + route
    disarm (a failed disarm quarantines the route and fails resume), then
    `Operation::Resume`; the rebuild's `power_down` in state 3 first runs
    `_rtl8821ae_wowlan_initialize_adapter`'s `_get_wakeup_reason`
    (recorded in `Lifecycle::wakeup`), `set_fw_wowlan_mode(0)` and
    `set_fw_remote_wake_ctrl_cmd(0)` over the parked control window, then
    the existing cold card-disable/enable rebuild (instead of Linux's warm
    `_rtl8821ae_simple_initialize_adapter`); the station stays
    disconnected as Linux `rtl_op_resume`'s `ieee80211_resume_disconnect`.
    A WoWLAN branch failure falls back to the cold path; a route that
    cannot be armed keeps D0 (no wake source) with the same resume.
    No board receipt exists for any of this. Test
    `smoke_rtl8821ae_wowlan_card_disable_register_order` (written,
    unexecuted).
  - Fixed a shared native allocation: RX slots are now allocated with the
    9100-byte `prepare::RX_BUFFER` the ring builder requires (it was 4096).
  Tests `smoke_rtl8821ae_native_owner_start_descriptors_receipt_and_rx`,
  `smoke_rtl8821ae_native_join_rsvd_page_h2c_and_leave`,
  `smoke_rtl8821ae_bt_function_board_refused_at_admission`,
  `smoke_rtl8821ae_c2h_tx_ra_reports_pwdb_and_firmware_rate_adaptation`
  (`packet_ae_tests.rs`) and
  `smoke_rtl8821ae_pwdb_ra_hysteresis_and_init_rate_match_linux`
  (`rate_adaptive.rs`), `smoke_rtl8821ae_ra_mask_rates_within_napc_admission`
  (`rtl8821ae/tests.rs`) (written, unexecuted).

Tests in `rtl8821ae/tests.rs` and `packet_ae_tests.rs` are written and
unexecuted. Physical-board qualification (signed `NAPC` envelope
measurements, silicon association) remains external.

### RTL8192EE retained runtime (implemented, pending validation)

`rtl8192ee/` holds the Linux-derived pieces the third native rtlwifi chip
(`0x818b`, 2T2R 2.4 GHz) is built from, following the RTL8821AE pattern.
Probe retains an admissible `0x818b` function as a native device and
admits it under its signed `N92E` envelope (probe admission below); an
unprovisioned board stays unadmitted.

- `pwrseq` — PCI rows of every `rtl8192E_*_flow` (card enable/disable,
  suspend/resume, radio-off, LPS enter/leave), generated from `pwrseq.h`
  with masks unchanged; USB/SDIO-only rows are omitted.
  `power::RTL8192EE_PWR_ON` is now the exact `RTL8192E_NIC_ENABLE_FLOW`
  (CardDis→CardEmu→Act; it was the CardEmu→Act subset), and
  `power::power_on_with` runs the `_rtl92ee_init_mac` prefix before it:
  `REG_RSV_CTRL = 0`, `REG_SYS_CFG1[24]` ⇒ `0x7c = 0xc3` else `0x16 |=
  BIT4|BIT6`, `0x7c = 0x83`, then `REG_AFE_CTRL2 &= 0xfb`, `REG_AFE_CTRL4 &=
  0xfffffc7f`, `REG_AFE_CTRL2 &= 0xbf`, `REG_AFE_CTRL4 &= 0xffdfffff` (the
  dword masks are issued as RMWs of the affected bytes over the byte power
  interface).
- `fw` — `rtlwifi/rtl8192eefw.bin` (no alternate or WoWLAN image):
  `IS_FW_HEADER_EXIST` (`0x92e0`), exact RAM-code length (Linux-firmware
  image: `0x7dfe` = 32254 payload bytes), at most eight 4 KiB pages; a
  headerless image is refused. `rtl92ee_download_fw` with Linux counts:
  enable (`MCUFWDL = 0x05`, `+2 &= 0xf7`), pages with `udelay(2)` after each
  full page and the `rtl_fill_dummy` pad, disable, `FWDL_CHKSUM_RPT` within
  the first 2999 undelayed reads (the post-increment bound of
  `_rtl92ee_fw_free_to_go`), `MCUFWDL_RDY`/`~WINTINI_RDY`,
  `rtl92ee_firmware_selfreset`, `WINTINI_RDY` over 3001 reads × 50 us.
  `firmware_transport::Owner` admits `0x818b` (parse dispatch, registry
  name, `run_8192ee`): CR DMA/MAC gates cleared, then the `rtl92ee_hw_init`
  `0x577 = 0x03` and 40 MHz crystal (`AFE_CTRL4 = 0x2a`, `+1 = 0`,
  `AFE_CTRL2 = 0x83`) writes and the download with the `mac_func_enable`
  stop of a still-running RAM image. Not issued: `REG_PCIE_CTRL_REG =
  0x8000` (releases the TX DMA queue stops; belongs to the ring owner) and
  the BT-coexist antenna writes (`0x64`/`0x65`; BT boards are never
  admitted). The `_rtl92ee_init_mac` remainder (CR, HWSEQ, auto LLT, BD ring
  bases and counts) is the ring owner's.
- `adapter` — `rtl92ee_read_eeprom_info`/`_rtl92ee_read_adapter_info`
  (`rtl_get_hwinfo`) and `rtl92ee_read_bt_coexist_info_from_hwpg`: a
  `TRP_VAUX_EN` test chip is refused; EEPROM boot, autoload failure or a map
  without `0x8129` is unprovisioned (no facts; Linux would run defaults with
  `btcoexist = 1`). MAC, VID/DID/SVID/SMID, channel plan, version, customer
  id (`0xff` ⇒ 0), board type `0xc1[7:5]` (`0xff` ⇒ 0) plus `ODM_BOARD_BT`
  when `[7:5] == 1` (the BT-coexist board), crystal cap `0xb9` (`0xff` ⇒
  `0x20`) and the Lenovo OEM rule.
- `trx` — new TRX flow (`use_new_trx_flow`): per TX queue a ring of
  64-byte buffer descriptors (four 16-byte segments, `RTL8192EE_SEG_NUM = 1`)
  beside a ring of 64-byte TX descriptors; `rtl92ee_pre_fill_tx_bd_desc`
  (segment 0 = 40-byte descriptor with PSB `ceil((len + 40) / 256)`,
  segment 1 = frame, the rest zero, DMA32 high words 0) and
  `rtl92ee_tx_fill_desc` first+last segment fields (no descriptor OWN on
  this chip; A-MPDU `max_agg_num 0x14`; SPE_RPT/SW_DEFINE TX reports) and
  `rtl92ee_tx_fill_cmddesc`. Queue ownership is the `REG_*_TXBD_IDX` write
  pointer (`get_desc_addr_fr_q_idx`; beacon/TXCMD/HCCA alias BE), beacon
  uses the BD OWN bit; `calc_fifo_space`, `rtl92ee_get_available_desc` and
  `rtl92ee_is_tx_desc_closed`. RX: 16-byte buffer descriptors prepared with
  data length `8192 + 24` (`HW_DESC_RX_PREPARE`), the completion predicate
  of `rtl92ee_rx_check_dma_ok`, `REG_RXQ_TXBD_IDX` 11-bit pointers, and the
  24-byte RX status at the start of each buffer (`rtl92ee_rx_query_desc`
  fields incl. `rpt_sel` C2H and wake reasons; payload at `24 + drvinfo +
  shift`). Ring sizes: 512 per TX queue (beacon 2), 512 RX.
- `mac` — `_rtl92ee_init_mac` after the power sequence: HWSEQ `0x7f`,
  SYS_CLKR BIT3, GPIO_MUXCFG+1 BIT4 clear, `_rtl92ee_llt_table_init`
  (RQPN `0x80e60808`, boundary `0xf7` into TRXFF/DWBCN0/1/BCNQ/BCNQ1/MGQ/
  `0x45d`, `TRXFF_BNDY+2 = 0x3cff`, PBP `0x31`, DRVINFO 4, auto-LLT BIT0 with
  Linux's pre-write-value wait), HISR/HISRE W1C, TRXDMA `0xf5b1`,
  FWHW_TXQ+1 `0x1f`, RCR `0xf000710e`, RXFLTMAP2, TCR `0x8200`, the BD ring
  bases (BEACON/MGQ/VO/VI/BE/BK/HQ0/RX, DMA32), TSFTIMER_HCI, PCIE_CTRL+3
  `|= 0xf7`, INT_MIG/MCUTST_1 0, `TXBD_NUM = 0x1200` (14 writes in Linux
  order, VOQ twice) and `RXBD_NUM = 0xa200`. Deliberate: the `REG_CR` `0xff`
  / `0x2ff` writes open the DMA engines and are left to the packet owner
  (`mac::release_cr`); LLT always runs (fresh owner).
- BD-ring owner profile — `prepare::Chip::Rtl8192ee` (`from_device(0x818b)`;
  `allocate_for` refuses it: no linked next pointer) built by
  `Prepared::allocate_rtl8192ee` (`rtl8192ee/packet_owner.rs`, mounted as
  `prepare::packet::ee92`; native shape `prepare_native::allocate_rtl8192ee`).
  Linux `_rtl_pci_init_trx_var`/`_rtl_pci_init_tx_ring`/`_rtl_pci_init_rx_ring`
  counts: per TX queue a 64-byte BD ring and a 64-byte descriptor ring of
  `TX_DESC_NUM_92E` 512 entries (beacon 2), 256-byte aligned, zeroed; 512
  RX BDs `HW_DESC_RX_PREPARE`d over 9100-byte buffers; DMA32, overlap
  checked before any BAR access. `prepare()` runs
  `_rtl8192ee_check_pcie_dma_hang` (`REG_BACKDOOR_DBI_DATA + 3` BIT(2)
  then 100 ms; a TX/RX hang bit runs the
  `_rtl8192ee_reset_pcie_interface_dma` recovery — RX DMA pause, host
  DMA stop, CR-gate and IRQ-mask close, re-probe, pause release — and
  only a still-hung engine after recovery refuses the board), keeps
  host DMA stopped (`0x301 = 0xff`), CR DMA/MAC gates and HIMR/HIMRE
  closed, marks the owner retained and runs `mac::init_mac` with the BD
  bases, then reads back the eight bases and every `*_TXBD_NUM`/`RXBD_NUM`.
  Packet owner (reachable only from `MacConfigured`, which this profile
  cannot reach yet): `start_packets` validates the published rings, idle
  BDs and zero `TXBD_IDX`/`RXQ_TXBD_IDX`, opens bus mastering, then issues
  the deferred `REG_CR = 0x2ff` and `rtl92ee_hw_init`'s `REG_PCIE_CTRL_REG
  = 0x8000`. TX (`rtl_pci_tx`): the device write point must equal
  `cur_tx_wp` with `calc_fifo_space` room; descriptor (forced legacy
  rate, fallback disabled, `RATR_INX_WIRELESS_MC` — no
  `RTL_SPEC_NEW_RATEID`; RA-adapted DATA is described under HT below),
  BD naming it and the frame, then the
  `REG_*_TXBD_IDX` doorbell (`rtl92ee_set_desc(HW_DESC_OWN)`). Completion
  is `rtl92ee_is_tx_desc_closed` over the `[27:16]` read point with the BD
  and stable descriptor words intact. RX (`_rtl_pci_rx_interrupt`): the
  `rtl92ee_rx_desc_buff_remained_cnt` count (`start_rx` per owner), the
  `rtl92ee_rx_check_dma_ok` reads, the 24-byte status, legacy non-A-MPDU
  frames delivered, C2H/HT/error frames consumed and dropped, the BD
  re-prepared and the advanced `next_rx_rp` written to `0x3b4` (HT
  frames on an HT link: see HT below).
  Deliberate: an RX BD never showing completion is not consumed; the BD is
  re-prepared before the `0x3b4` acknowledgement; host/device pointer
  disagreement fails the owner. Interrupts use the 8192EE profile
  (`h2c` below; `enable_interrupts`/`recognize_interrupts` dispatch to it)
  and C2H RX packets are parsed (below) instead of dropped. Card-disable
  retirement proof (`quiesce` → `ee92_quiesce`, from the
  `rtl92ee_card_disable` sources; the 88EE `0x286` BIT(1) RX-idle poll is
  not applied, the 8192EE sources have no such bit): stopped owner with
  `0x522 = 0xff` and `0x301 = 0xff`, the `RTL8192E_TRANS_ACT_TO_LPS` TX
  packet-buffer polls (0x5f8..=0x5fb zero, 5000 × 10 us), every TX queue's
  device read point at the host write point (nothing left to fetch), then
  RX DMA paused by `REG_RXDMA_CONTROL` BIT(2) (`_rtl8192ee_reset_pcie_
  interface_dma` step 2) with read-back; any timeout or disagreement keeps
  every mapping pinned. The RX side of the proof rests on that pause and
  the cleared bus mastering. `power_runtime::disable_rtl8192ee` is
  `_rtl92ee_poweroff_adapter` in source order (LPS-enter flow, `REG_RF_CTRL
  = 0`, self-reset when MCUFWDL BIT(7) and the firmware is ready, MCU reset,
  MCUFWDL 0, disable flow, RSV_CTRL+1 BIT(0) pulse, RSV_CTRL `0x0e`; the
  `_rtl92ee_set_media_status(UNSPECIFIED)` write is not issued, as 88EE/
  8821AE); it has no caller until the 8192EE rebuild owner exists.
- `tables` / `headerfile` — all six `rtl8192ee/table.c` arrays (MAC,
  PHY_REG, PHY_REG_PG, AGC, RADIOA, RADIOB; lengths from `table.h`, source
  sha256 `d3bc9536…7937e` recorded), generated verbatim. The 8192EE walker is
  `_check_condition` — not the 8821AE `check_positive` form: board type
  `[7:0]` (`0xff` any), interface `[15:8]` against `INTF_PCI` 0 (`0x07`
  any), platform `[23:16]` against `0x08` (`0x0f` any), `0xCDCDCDCD`
  always true — with the exact `phy_config_bb_with_hdr_file` /
  `rtl92ee_phy_config_rf_with_headerfile` index arithmetic (a discarded
  branch's terminator row is re-examined as a condition). Every shipped
  branch condition is `0xFF010718` (platform `0x01`), which never matches,
  so the else rows apply on every board. `bb_action`/`rf_action` are
  `_rtl92ee_config_bb_reg`/`_rtl92ee_config_rf_reg` row decodes (delay
  markers; the RF `0xb6`/`0xb2` read-back retries belong to the RF writer).
- `phy` — `rtl92ee_phy_set/query_bb_reg` and `_rtl92ee_phy_rf_serial_
  write/read` over `phy_init_bb_rf_register_def` (paths A/B: LSSI
  `0x840/0x844`, HSSI read edge via `0x824` then the path's HSSI2, 20 us,
  PI/SI read-back by HSSI1 BIT(8)); shifted values are not re-masked, as
  Linux. `mac_config` writes every MAC row (Linux does not walk conditions
  on that array). `bb_config` = `rtl92ee_phy_bb_config` (SYS_FUNC_EN word
  `| BIT13|BIT1|BIT0`, RF_CTRL 7, SYS_FUNC_EN `0xe3`, `AFE_XTAL_CTRL+1 =
  0x80`, `0x4c |= BIT23`, PHY_REG walk with delays + 1 us, the PHY_REG_PG
  store into `[rf][txnum][section]` (`_rtl92ee_get_rate_section_index`),
  `_rtl92ee_phy_store_txpower_by_rate_base` BCD bases and
  `phy_convert_txpwr_dbm_to_rel_val`, AGC walk, `cck_high_power`, crystal
  cap `0x2c[23:12]`). `rf_config` = `_rtl92ee_phy_rf6052_config_parafile`
  for `RF_2T2R` (RFENV save/restore, 3-wire lengths) with
  `_rtl92ee_config_rf_reg`'s retries: `0xb6` until `[19:8]` matches,
  `0xb2` until equal with an RF `0x18 = 0x0fc07` per retry, each at most
  six. `configure` continues with the `rtl92ee_hw_init` RF tail
  (`rfreg_chnlval` reads, `backup_rf_0x1a`, 20 MHz `RF_CHNLBW` to both
  paths, CCK/OFDM block on, RF A `0xB1 = 0x54418`).
- `txpower` — `_rtl8192ee_read_power_value_fromprom` /
  `_rtl92ee_read_txpower_info_from_hwpg` 2.4 GHz fields (42-byte path
  stride from `0x10`, channel 14 CCK group 5, signed nibbles, thermal
  `0xBA`, regulatory `0xC1[2:0]`); a map with `0x11 == 0xff` is Linux's
  autoload-fail branch (`txpwr_fromeprom` false, TXAGC never written) and is
  refused. `index` = `_rtl92ee_get_txpower_index` (u8 wrapping, clamp
  `0x3f`, by-rate diff unless regulatory 2, the Linux rate-section/shift
  quirks kept); `set_level` = `rtl92ee_phy_set_txpower_level` (A then B;
  CCK, OFDM, MCS0-7, MCS8-15 byte RMWs of the `_rtl92ee_set_txpower_index`
  registers). No power-limit table exists for this chip in Linux.
- `channel` — `rtl_op_config` wide channel (HT40+ = primary + 2 / LOWER,
  HT40- = primary - 2 / UPPER; 40 MHz pairs outside wide 3..=11 refused),
  `_rtl92ee_phy_sw_chnl_step_by_step` (TX power at the new width, then
  `rfreg_chnlval[p] & 0xfffff00 | ch` through the unmasked `0x3ff` RF RMW
  on both paths, 10 ms), `rtl92ee_phy_set_bw_mode_callback` (BWOPMODE,
  RRSR+2 sub-channel, RFMOD, `0xce4[31:30]`, CCK sideband, LSTF, `0x818
  [27:26]`) and `rtl92ee_phy_rf6052_set_bandwidth` (`rfreg_chnlval[0]` to
  both paths, as Linux).
- `iqk` — `rtl92ee_phy_iq_calibrate(false)`: up to three
  `_rtl92ee_phy_iq_calibrate(t, is2t)` runs (t = 0 backs up 16 ADDA, the
  `0x522/0x550/0x551` bytes + `0x040` dword and 9 BB registers; ADDA on
  `0x0fc01616`, IQK BB setup, `0x520[23:16] = 0xff`; two retries each of
  path A TX/RX, path-A standby, path B TX/RX; reloads only for t != 0,
  incl. Linux's double `0xc50 = 0x50`), `_rtl92ee_phy_simularity_compare`
  (signed odd entries, MAX_TOLERANCE 5, zero-RX candidate rule), the
  matrix fills with Linux's u32 wrapping and unmasked values (Linux's
  path-B fill reads/writes `ROFDM0_XATXIQIMBALANCE`; kept) and the save of
  the nine result registers (`recover` = `b_recovery`).
  `_rtl92ee_phy_lc_calibrate(false)` is implemented but, as in Linux
  (no caller on 8192EE), not run.
- `init` — the `rtl92ee_hw_init` tail after the firmware download, run by
  `Prepared::configure_rtl8192ee` (Prepared → RadioConfigured; adapter
  facts re-derived from live `REG_SYS_CFG1`/`REG_9346CR`, the efuse MAC
  must match, BT-coexist boards and power maps without TX power refused
  before any write): `phy::configure`, `_rtl92ee_hw_configure` (RRSR, ARFR
  0/1, slot, CF-End, retry, BAR, DARFRC/RARFRC, beacon, PIFS/aggr break,
  NAV/protection, EDCA, ACKTO, SIFS, `0x4c7`, RX packet limit, max aggr,
  MAR), `rtl_cam_reset_all_entry`, `HW_VAR_ETHER_ADDR`, the IQK, the PA
  bias from physical EFUSE `0x1FA` (`efuse_one_byte_read`, 100-poll
  timeout ⇒ `0xff`), `REG_NAV_UPPER = 235`, the LDPC RX-hang SWR fix and
  `0x4fc = 0`. Not issued: HW security config (software crypto, Linux's
  `sw_crypto` return), the ASPM back door / `enable_aspm` (ASPM stays
  disabled), `rtl92ee_bt_hw_init`; `rtl92ee_dm_init` is software state for
  the DM owner. `Prepared::configure_rtl8192ee_channel(Permission)`
  (RadioConfigured/ChannelConfigured → ChannelConfigured; MacConfigured/
  Running keep their phase, the station retune) refuses a permission
  minted for another factory identity, then runs `channel::
  configure_admitted`: `_rtl92ee_phy_sw_chnl_step_by_step` at the wide
  channel with the envelope's per-path indices (`txpower::set_indices`,
  the `set_level` registers/order, unadmitted rates 0) and the retained
  `rfreg_chnlval`, then `set_bw_mode`; it records the channel for the
  packet owner. `configure_rtl8192ee_mac` (ChannelConfigured →
  MacConfigured) requires the radio and permission of the same identity
  and sets the station address.
- `envelope` — signed per-board `N92E` v1 power envelope
  (`rtlwifi/rtl8192ee-cal-v1-<mac>.bin`, device `0x818b`; layout in the
  module header): factory identity, MAC, antenna gain (the combined
  two-chain gain) and qualified EIRP, then up to 25 rows strictly ordered
  by (bandwidth, offset, channel) — 2.4 GHz 20 MHz ch1-11, 40 MHz above
  1-7 and below 5-11 (span inside 2402-2472 MHz) — each with eight
  64-entry measured conducted-output curves: path A and path B for CCK,
  OFDM, MCS0-7 and MCS8-15, indexed by that path's TXAGC value (`i16::MAX`
  unmeasured). The format only carries measurements; no board value is
  supplied. `permission_for(domain, op)` takes the ceiling as 8821AE (20
  MHz `domain_ceiling`; 40 MHz: every overlapping host rule covers the
  whole span, allows 40 MHz and has no flag, capped by `regd.c` 20 dBm)
  and the qualification, and per rate and path lowers the Linux index
  (`_rtl92ee_get_txpower_index` at the wide channel and width, as
  `rtl92ee_phy_set_txpower_level` runs at `current_channel`) to the
  highest measured index whose output + 13 qdBm (two equal incoherent
  chains, `10 log10 2` rounded up; both chains are assumed to transmit
  every rate) + antenna gain fits. A rate is admitted only when both paths
  fit; every CCK/OFDM rate must be admitted, MCS rates may be left out
  (`admitted_rates`, full order, the set `ee92_install_rate_mask` and
  `ee92_dm_watchdog` bound the RA mask by). Unsigned, foreign, unordered,
  out-of-plan or unmeasured ⇒ not admitted. Test
  `smoke_rtl8192ee_n92e_envelope_permission_and_admission`
  (`rtl8192ee/phy_tests.rs`, written, unexecuted).
- `h2c` — `fw.c::_rtl92ee_fill_h2c_command` (`REG_CR == 0xEA` ⇒
  `REG_SYS_CFG1 (0xf0) + 3 = 0xff` side effect and `RadioOff`; HMETFR one
  plus 99 × 10 us checks, each re-check followed by Linux's `0x130` read;
  byte-wise writes, 4–7-byte commands writing the zero-padded extension box
  first; `last_hmeboxnum` rotation; a timeout or MAC-off box poisons the
  mailbox). Linux's power-save gate is kept: while `dot11_psmode !=
  EACTIVE` or IPS RF-off the command is dropped without any access
  (`Sent::Dropped`); since `rtl_lps_set_psmode` sets `dot11_psmode` first,
  `fwlps_enter` (`_rtl92ee_fwlps_enter`, `low_power_enable` false) drops its
  `SETPWRMODE(DTIM)` and writes only the RPWM RF-off, while `fwlps_leave`
  writes RPWM all-on then sends `SETPWRMODE(ACTIVE)`. RPWM is
  `REG_PCIE_HRPWM` **0x3dc** on this chip (`HW_VAR_SET_RPWM` toggle).
  `pwrmode`: ACTIVE = switch default (rlbm 2, interval 4,
  `FW_PWR_STATE_ACTIVE`), DTIM = `reg_fwctrl_lps = 3` (rlbm 2,
  `reg_max_lps_awakeintvl` 5, RF off); smart_ps 1, byte5 `0x40`.
  `media_status` (MSRRPT, MACID 0), `RSVDPAGE_LOCATION` (`[PROBERSP 4,
  PSPOLL 2, NULL 3, QOS_NULL 6, BT_QOS_NULL 7]`), `rate_mask` =
  `rtl92ee_update_hal_rate_mask` for a 2.4 GHz B/G/N station with
  `rf_type` 2T2R (N rows `0x0f8f0000` / `0x0ffff000` / `0x0ffff015` (40) /
  `0x0ffff005` (20), so MCS8-15 come from `rx_mask[1] << 20`;
  `_rtl92ee_mrate_idx_to_arfr_id` NGB 0 at 40 MHz / NB 2 at 20, GB 6, B 8;
  SGI only for the width's SGI; `rate_mask[2] = bw40 | !update_bw << 3`),
  `mask_rates` (full-order rates: legacy bits 0..=11, MCS0-15 bits
  12..=27), `set_bcn_ctrl`. Interrupts: `rtl92ee_enable_interrupt` writes
  only HIMR `0x200004ff` / HIMRE `0x100` (`sw.c`; no status clear, HSIMR or
  C2H-event write); `service_interrupt` = disable → `rtl92ee_interrupt_
  recognized` W1C under the masks → enable (HSISR / `IMR_C2HCMD` handlers
  are other chips').
- `c2h` — `rtl_c2h_content_parsing` with the core V1 TX report (no
  `RTL_SPEC_EXT_C2H`) and `rtl92ee_c2h_ra_report_handler` (`cmd_buf[0] &
  0x3f` rate, `cmd_buf[3]` BIT(0) collision; a body under four bytes is
  refused, Linux reads it unconditionally) → `rtl92ee_dm_dynamic_arfb_
  select` (`REG_DARFRC` low/high pair tables). The packet owner records TX
  reports and keeps the RA report pending for the DM step
  (`ee92_apply_ra_report`, Linux's `c2hcmd_wq`).
- `dm` — `_rtl92ee_dm_ra_state_check` (thresholds 50 / 20 from
  `rtl92ee_dm_init_rate_adaptive_mask`, `go_up_gap` 5 raising high from
  MIDDLE and both from LOW; the state is the rate mask's `rssi_level`) and
  the `_rtl92ee_query_rxphystatus` `rx_pwdb_all` (OFDM `((byte4 >> 1) &
  0x7f) - 110`; CCK 8192EE LNA/VGA table `+ 16` and the `!cck_highpwr`
  boost). Of `rtl92ee_dm_watchdog` only the RA mask refresh is composed;
  false alarm/DIG/adaptivity/CCK PD/EDCA turbo/ATC/primary CCA are not run
  (as on 88EE). The 8192EE watchdog has no TX-power tracking step
  (`rtl92ee_dm_init_txpower_tracking` only seeds indices).
  Owner composition (`packet_owner.rs`): `ee92_install_rate_mask` is
  `rtl92ee_update_hal_rate_mask` (`H2C_92E_RA_MASK`, then BCN_CTRL
  BIT(3)), refused — never narrowed — unless the mask's rates are a
  non-empty subset of the caller's admitted rates, and skipped in LPS; it
  records the peer, `bw_40` and `ratr_index`. `ee92_dm_watchdog(undec_sm_
  pwdb, admitted)` runs only out of LPS: `_rtl92ee_dm_ra_state_check`
  against `ratr_state` (INIT at start), on a change `update_rate_tbl(sta,
  ratr_state, true)` through the same admission check, then the pending
  RA report's dynamic ARFB (`ee92_apply_ra_report`); `use_ldpc`/
  `lower_rts_rate` are not consumed (no LDPC TX, no protection). TX
  reports: `ee92_submit` sets SPE_RPT + SW_DEFINE (`rtl_set_tx_report`,
  `rtl_get_tx_report_sn`) for EAPOL and (QoS) Null frames
  (`rtl_is_tx_report_skb`, shared with 8821AE). Power-down:
  `rebuild_native` `power_down` dispatches `0x818b` to
  `power_runtime::disable_rtl8192ee` and keeps ASPM disabled; the
  rebuild's re-enable is `enable_rtl8192ee` (probe admission below).
  The station loop's smoothed PWDB feed and the per-board admitted set are composed by the station branch (below). Tests
  `smoke_rtl8192ee_tx_report_rate_mask_watchdog_and_quiesce`,
  `smoke_rtl8192ee_poweroff_adapter_order` (written, unexecuted);
  `smoke_rtl8192ee_txbd_doorbell_completion_and_rx_ack` now expects the
  `ee92_quiesce` proof (its earlier `Err(State)` assertion predated it).
- Station branch (`station_power::{Base,Grant}::Rtl8192ee`, `station.rs`,
  `ht_width.rs`, `rtl8192ee/station.rs`, `packet_owner.rs`): the signed
  `N92E` calibration is staged as the station power base
  (`stage_rtl8192ee_calibration`, `regrant` = `permission_for` at the same
  operating point, `with_current` = the envelope's firmware-asset
  authority; no 88EE HT/protection/tracking/antenna/fallback grant is
  admitted, `power_wait` → `station_power::wait_rtl8192ee`) and
  `station_grant` returns the programmed `rtl8192ee_power`. Every
  `packet.rs` station path dispatches to an 8192EE arm instead of the 88EE
  one: `awake_station` (`rtl92ee_hw_init` leaves the firmware awake;
  `REG_CR != 0xEA`, nothing sent), `prepare_station_peer` (`HW_VAR_BSSID`,
  `HW_VAR_BASIC_RATE` = `((supp_rates & 0x15f) | 1 | 0xd) & ~BIT(1)` as two
  RRSR bytes — Linux passes `sta->supp_rates[0]`, not the basic set —,
  `rtl92ee_update_channel_access_setting` (slot 9/20, SIFS `0x0a0a` /
  `0x0e0e` with HT, `REG_RESP_SIFS_OFDM` `0x0e0e`), the fixed
  `rtl92ee_set_qos` BK/VI/VO rows (also for every WMM update) and
  `HW_VAR_ACK_PREAMBLE` (`REG_RRSR + 2 = cur_40_prime_sc << 5 | short <<
  7`)), `complete_station_peer_admitted` (`rtl_cam_reset_all_entry`,
  `HW_VAR_KEEP_ALIVE` 10, `rtl92ee_set_network_type` linked — MSR INFRA,
  RCR CBSSID_DATA|BCN on the cached `receive_config`, BCN_CTRL BIT(4)
  cleared — then `ee92_join_report`), `enter/leave_leisure`
  (`_rtl92ee_fwlps_enter/leave`), `leave_station_peer` /
  `disconnect_station_peer` (leave LPS, NOLINK network type, MSRRPT
  disconnect, zero BSSID; the RA link is withdrawn, `ratr_state` kept as
  Linux). `start_packets` issues `rtl_op_add_interface`'s NOLINK network
  type with read-back of the CBSSID-clear RCR. The 88EE
  `install_rate_mask` refuses 8192EE; the association mask is
  `install_rtl8192ee_rate_mask` (`update_rate_tbl(sta, 0, true)`: peer
  `supp_rates[0]`, intersected TX MCS, SGI, `bw_40`; the permission's
  `admitted_rates()` bound) inside the envelope authority, and the station
  watchdog (`refresh_station_rate_mask`) runs `ee92_dm_watchdog` with the
  station loop's smoothed `undec_sm_pwdb`, which the RX path now feeds:
  `ee92_receive_step` decodes `rx_pwdb_all` from the PHY status
  (`status.physt`, driver info >= 8 bytes; CCK at rates <= 11M with the
  retained `cck_high_power`). `retune_rtl8192ee` (join and Configuring)
  re-derives the `N92E` permission for the offered width on the
  provisioned primary and runs `configure_rtl8192ee_channel` inside it
  (no frame outstanding, receive epoch retired). HT and probe admission
  are composed (below). Test
  `smoke_rtl8192ee_station_peer_join_lps_and_leave`
  (`packet_owner_tests.rs`, written, unexecuted).
- `rsvd_page` — `fw.c::reserved_page_packet` verbatim (1024 bytes, eight
  128-byte pages: beacon 0..=1, PS-Poll 2, Null 3, probe response 4..=5,
  QoS-Null 6, BT-QoS-Null 7; sha256 `7182a1ec…7ff043` recorded; Linux's
  pages 6/7 are all zero and still get A1/A2/A3) and the
  `rtl92ee_set_fw_rsvdpagepkt(false)` substitutions (beacon A2/A3, PS-Poll
  AID `| 0xc000`/BSSID/TA, Null/probe/QoS-Null/BT-QoS-Null A1/A2/A3).
  `ee92_join_report` is `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)`:
  `HW_VAR_AID` (`REG_BCN_PSR_RPT` word `& 0xC000 | aid`), then
  `_rtl92ee_download_rsvd_page` (`ee92_download_rsvd_page`): `REG_CR + 1`
  BIT(0), BCN_CTRL `(0, BIT3)`/`(BIT4, 0)` on the cached
  `reg_bcn_ctrl_val` (`0x1d`), `0x422` BIT(6) cleared; up to five uploads,
  each clearing BCN_VALID (`REG_DWBCN0_CTRL + 2` BIT(0)), writing
  BEACON_QUEUE descriptor 0 (`rtl92ee_tx_fill_cmddesc`) and beacon BD 0,
  sending `H2C_92E_RSVDPAGE`, waiting `REG_MGQ_TXBD_NUM + 3` BIT(4) clear
  (20 × 10 us) and setting it, then BCN_VALID (20 × 50 us, acknowledged
  with BIT(0)); BCN_CTRL `(BIT3, 0)`/`(0, BIT4)`, `0x422` restored when it
  had BIT(6), `REG_CR + 1` BIT(0) cleared; then MSRRPT connect. Deliberate:
  Linux's `rtl_cmd_send_packet` writes only `ring->desc[0]` on the new
  TRX flow (`rtl92ee_tx_polling` is empty) and never the beacon BD the
  engine fetches from `REG_BCNQ_DESA`; here BD 0 is filled as Linux's own
  beacon path does (`_rtl_pci_prepare_bcn_tasklet`:
  `rtl92ee_pre_fill_tx_bd_desc` + `HW_DESC_OWN` on `BEACON_QUEUE`). A
  stale BD OWN without an earlier proven upload is refused, the 1024-byte
  body stays owned by the claim (`packet.reserved`) until quiescence, and
  a BCN_VALID that never sets is a terminal `CommandTimeout` (Linux logs
  and continues). Test `smoke_rtl8192ee_rsvd_page_download_through_beacon_bd`
  (`packet_owner_tests.rs`, written, unexecuted).
  Tests (`rtl8192ee/h2c_tests.rs`, written, unexecuted):
  `smoke_rtl8192ee_rsvd_page_template_and_substitution`,
  `smoke_rtl8192ee_h2c_box_order_rotation_and_ps_gate`,
  `smoke_rtl8192ee_h2c_busy_off_and_lps_order`,
  `smoke_rtl8192ee_rate_mask_2t2r_levels_and_rates`,
  `smoke_rtl8192ee_interrupt_profile_masks_and_w1c`,
  `smoke_rtl8192ee_c2h_reports_and_dynamic_arfb`,
  `smoke_rtl8192ee_dm_ra_state_and_pwdb`.
  Test `smoke_rtl8192ee_tables_and_check_condition_walk` (written,
  unexecuted).
- HT20/40 station (`rtl8192ee/ht.rs`, `ht_width.rs`, `station.rs`,
  `packet_owner.rs`). The join plan offers `ht::local(forty, two_stream)`
  only when the AP has WMM and the current `N92E` permission admits
  MCS0-7 on both paths (`rtl8192ee_ht`). Capability:
  `_rtl_init_hw_ht_capab` for `RF_2T2R` (SGI20, MAX_AMSDU 7935-byte RX,
  A-MPDU factor 3, density 7, RX MCS0-15 `TX_DEFINED`, no STBC/LDPC, no
  MCS32/`rx_highest`); the 20/40 bit with SGI40/DSSSCCK40 only when
  `rtl8192ee_wide` finds a `permission_for(domain, 40 MHz above/below)`
  for the AP's offered geometry on the provisioned primary that admits
  MCS0-7; the local TX MCS8-15 selection only when the 20 MHz permission
  on the primary and (if offered) the 40 MHz one both admit every
  two-stream rate (`rtl8192ee_two_stream`; Configuring may narrow to 20
  MHz). `retune_rtl8192ee` runs before authentication and at
  Configuring for the negotiated width. At Configuring
  (`BSS_CHANGED_HT`) only `HW_VAR_AMPDU_FACTOR` (`ht::timing`,
  `REG_AGGLEN_LMT` nibbles lowered to `1 << (min(peer, 3) + 2)`) is
  written — `rtl92ee_set_hw_reg` has no SHORTGI_DENSITY/AMPDU_MIN_SPACE
  case — inside the station publication, `packet.ht` is set, and the 88EE
  `ht_timing` branch is skipped; an AP with HT protection mode ≠ 0 is
  refused (as 88EE/8821AE). `Candidate::receive` observes beacons with
  the 8192EE HT20 PHY. Host capability (`ht::host_capabilities` /
  `host_phy` → `interface.rs` `rtl8192ee_caps`): 2.4 GHz HT on an
  `admitted` 20 MHz point, the 20/40 form on an `admitted` 40 MHz point,
  TX MCS8-15 only when every HT-admitting point admits it. RA mask: the
  association `install_rtl8192ee_station_rate_mask` (mac80211
  intersection, `bw_40` = programmed width). TX (`ee92_submit`,
  `rtl_get_tcb_desc` + `rtl92ee_tx_fill_desc`): ordinary unicast DATA
  with an installed mask (`queue_station`'s fallback arm, as 8821AE: no
  protection, mask present) clears USE_RATE/DISFB, starts at
  `_rtl_get_highest_n_rate` (MCS15 for a peer naming `rx_mask[1]`, else
  MCS7; 11M B / 54M G) and names RATE_ID from `mac->mode`
  (`_rtl_txrate_selectmode` with `dm.useramask`, no NEW_RATEID: NGB 0 /
  GB 4 / B 6), MACID 0. Special data (`rtl_is_special_data`: EAPOL,
  ARP, IPv4 UDP BOOTP 67/68, `packet_owner::special_data`) sets
  `ra.is_special_data`, so `rtl92ee_tx_fill_desc` keeps USE_RATE and
  forces `DESC_RATE11M` (DISFB, `RATR_INX_WIRELESS_MC` from rix 0); Linux
  classifies before software encryption, this driver receives the
  station's protected frames, so a protected frame is never special. A
  (QoS) Null DATA frame (`rtl_get_tcb_desc` nullfunc: DISFB +
  `RATR_INX_WIRELESS_MC`) has USE_RATE cleared by `tx_fill_desc`, so the
  firmware RA of MACID 0 picks the rate — only once the RA mask (bounded
  by `admitted_rates`) is installed; before it the Null keeps the driver
  rate. Every other frame keeps the forced rate with USE_RATE + DISFB and
  `RATR_INX_WIRELESS_MC` (Linux clears USE_RATE for all non-management
  frames; ordinary DATA leaves the driver rate only with an installed
  mask). The forced/initial rate must be in the permission's
  `admitted_rates`.
- ERP / RTS-threshold protection (`station.rs::native_protection`,
  `ee92_submit`). An AP announcing ERP Use_Protection, or a configured RTS
  threshold, is admitted under the `N92E` permission (no 88EE `NERT`
  grant): join, beacon tracking and SET_WIPHY accept it when the AP offers
  24M. `protection::select` (mac80211 `use_cts_prot` /
  `IEEE80211_TX_RC_USE_RTS_CTS` per MPDU+FCS length) feeds
  `_rtl_query_protection_mode` into `rtl92ee_tx_fill_desc`: RTS/CTS sets
  RTS_EN, CTS-to-self CTS2SELF (RTS_EN cleared, as `rts && !cts`), both
  `RTS_RATE = DESC_RATE24M`, RTS_SC 0, HW_RTS 0, RTS_SHORT 0
  (`rts_use_shortpreamble` false). Protection is independent of the RA
  (Linux fills both), so protected ordinary DATA keeps USE_RATE/DISFB
  clear. `ee92_submit` refuses (`Power(Policy)`) a protected frame whose
  `DESC_RATE24M` is not in `admitted_rates`. Short preamble / slot follow
  `ieee80211_handle_bss_capability` (`rtl8192ee::station::erp_timing`:
  with an ERP element the preamble is short unless Barker bit 2, else the
  capability 0x20; slot from capability 0x400), programmed at association
  through `configure_rates` (the BSS ERP octet; the authentication-time
  `prepare_station_peer` uses the capability alone, as mac80211 has no
  ERP state yet) and, when a tracked beacon changes either flag,
  `BSS_CHANGED_ERP_PREAMBLE` (`HW_VAR_ACK_PREAMBLE`) /
  `BSS_CHANGED_ERP_SLOT` (`HW_VAR_SLOT_TIME`, `REG_SLOT` 9/20; its
  `HW_VAR_AC_PARAM` loop writes nothing) inside the station publication
  (`track_rtl8192ee_erp`, `erp_changed`). Test
  `smoke_rtl8192ee_erp_protection_special_and_null_tx`
  (`packet_owner_tests.rs`, written, unexecuted). `bw_40`: a unicast packet above
  54M on an HT link is 40 MHz (`data_bw` 1, SC 3), every other packet
  names `cur_40_prime_sc`. AGG_EN + `max_agg_num 0x14` for an
  operational BA TID with the peer's density (QoS DATA only). Linux
  writes no data SGI bit on 8192EE (SGI comes from the RA mask's SGI
  flag), so `short_gi` is only validated against the HT link. RX
  (`ee92_receive_step`): on an HT link MCS0-15 and A-MPDU members (BA
  owner gates them) up to the 7935-byte A-MSDU MPDU; `Mpdu.ht` from the
  MCS rate, `aggregated` from PAGGR; `rtl92ee_rx_query_desc` never sets
  `is_ht`/`rx_is40mhzpacket`/`is_short_gi`, so width40/short_gi stay
  false and nothing is gated on them. Test
  `smoke_rtl8192ee_ht_ra_adaptive_aggregate_tx` (`packet_owner_tests.rs`,
  written, unexecuted); the existing doorbell/rate-mask tests now hold a
  channel-1 `N92E` permission (`permission20`).
- Probe admission (`pci.rs`, `prepare_native.rs`, `interface.rs`,
  `rebuild_native.rs`, `power_runtime.rs`). `bring_up` retains `0x818b`
  (BAR2 at least `rtl8192ee::MMIO_SIZE`) only when the facts
  `configure_rtl8192ee` re-derives already hold at probe: not a test
  chip, provisioned map (`adapter::Adapter::from_hardware` over live
  `REG_SYS_CFG1`/`REG_9346CR`), not a BT-coexist board
  (`rtl92ee_read_bt_coexist_info_from_hwpg` board type 1), EFUSE MAC
  equal, TX power present (`0x11 != 0xff`); otherwise it stays
  diagnostic. `prepare_native::prepare_rtl8192ee` (dispatched from
  `initialize_registered_on_channel`, channels 1-11): registry firmware,
  `allocate_rtl8192ee`, `prepare` (DMA-hang check, `init_mac`),
  `configure_rtl8192ee`, then `admit_rtl8192ee` (`N92E` 20 MHz
  permission on the channel, `configure_rtl8192ee_channel`,
  `configure_rtl8192ee_mac`, `stage_rtl8192ee_calibration`), shared with
  the interface readiness path (`ready`, which no longer falls back to
  the 88EE `NEPC` for this chip). `prepare_bus_power` keeps ASPM disabled
  (8192EE `enable_aspm` not composed); `allow_channel` is the `N92E` 20
  MHz permission. Rebuild: after `power_down`
  (`disable_rtl8192ee`), `power_runtime::enable_rtl8192ee` runs the
  `_rtl92ee_init_mac` prefix and `RTL8192E_NIC_ENABLE_FLOW` (the probe's
  `power_on_with` entry, asynchronously), re-verifies the factory
  identity and re-provisions a fresh `Owner(0x818b)`. As 8821AE, a
  failed first provisioning is not retried (`provisioning` retries only
  88EE). Not composed: BT coexistence, ASPM, WoWLAN, LDPC/STBC
  (ERP/RTS protection is composed, above).

Tests (`rtl8192ee/tests.rs`, written, unexecuted):
`smoke_rtl8192ee_tx_buffer_descriptor_segments_and_psb`,
`smoke_rtl8192ee_tx_descriptor_fields`,
`smoke_rtl8192ee_rx_buffer_descriptor_and_status`,
`smoke_rtl8192ee_ring_pointer_arithmetic`,
`smoke_rtl8192ee_init_mac_llt_ring_bases_and_bd_counts`,
`smoke_rtl8192ee_init_mac_prefix_and_enable_flow`,
`smoke_rtl8192ee_all_flows_pci_mac_and_terminated`,
`smoke_rtl8192ee_firmware_header_geometry`,
`smoke_rtl8192ee_firmware_paged_download_and_selfreset`,
`smoke_rtl8192ee_retained_firmware_owner_profile`,
`smoke_rtl8192ee_adapter_info_factory_rules`,
`smoke_rtl8192ee_bd_rings_allocation_publish_and_retention`,
`smoke_rtl8192ee_txbd_doorbell_completion_and_rx_ack`
(`rtl8192ee/packet_owner_tests.rs`).

### RTL8192CE / RTL8188CE retained runtime (admitted station, both RF types)

`rtl8192ce/` holds the Linux `rtl8192ce` + `rtl8192c` (common) pieces the
native RTL8192CE (2T2R) / RTL8188CE (1T1R) owner is built from
(`rtl92ce_pci_ids`: `0x8178`, `0x8177`, `0x8176`, `0x8191`, all four in
`regs::ALL_DEV_IDS`; `rtl8192ce::is_8192ce`). Probe retains an admissible
function and admits it under its signed `N92C` envelope (probe admission,
at the end of this section).

- `version` — `_rtl92ce_read_chip_version` over `REG_SYS_CFG` and (92C
  serial only) `REG_HPON_FSM`. Qualified: `CHIP_88C` ⇒ `RF_1T1R`
  (RTL8188CE) and `CHIP_92C` ⇒ `RF_2T2R` (RTL8192CE), TSMC and UMC A/B
  cuts. Refused: `TRP_VAUX_EN` test chips, `CHIP_UNKNOWN` cuts, and the
  `CHIP_BONDING_92C_1T2R` bonding (Linux's `switch (version & 3)` assigns no
  RF type to it). Firmware per `rtl92c_init_sw_vars`: UMC A-cut 88C ⇒
  `rtl8192cfwU.bin`, UMC B-cut ⇒ `rtl8192cfwU_B.bin`, else `rtl8192cfw.bin`.
- `adapter` — `rtl92ce_read_eeprom_info` / `_rtl92ce_read_adapter_info`
  over the 128-byte `HWSET_MAX_SIZE` map: EEPROM boot, autoload failure or
  a map without `0x8129` is unprovisioned (no facts). MAC `0x16`,
  VID/DID/SVID/SMID, channel plan `0x75` (Linux then installs
  `COUNTRY_CODE_WORLD_WIDE_13`), version, customer id, the
  `rtl8192ce_read_bt_coexist_info_from_hwpg` fields (`RF_OPTION1[7:5]` is
  `bt_coexistence`) and the HP/Toshiba/QMI OEM rule. The map is kept
  verbatim for the TX-power decode.
- `power` — this family has no pwrseq table: the `_rtl92ce_init_mac`
  prefix (`RSV_CTRL = 0`, `SPS0_CTRL = 0x2b`, `AFE_XTAL_CTRL = 0x0f`,
  `APS_FSMCO+1` BIT0 request and 1000 x 100 us poll, exact-width
  `APS_FSMCO = 0x1012`, `SYS_ISO_CTRL+1 = 0x82`). BT-coexist branches are
  not issued (such boards are never admitted). An APFM poll expiry is a
  gate failure (Linux continues). Probe issues no power-on step for these
  IDs (`power::power_on_table_for` is `None`; `RTL8192CE_PWR_ON` stays for
  8192DE only): Linux reads the chip version and EFUSE at probe and powers
  the MAC in `rtl92ce_hw_init`, here the firmware owner's run.
- `fw` — `IS_FW_HEADER_EXIST` (`0x92c0` / `0x88c0`), exact RAM-code length
  (linux-firmware: `0x3f20` / `0x39c2` / `0x3fac`), whole file at most
  `max_fw_size = 0x4000`. `rtl92c_download_fw` for normal chips:
  `SYS_FUNC_EN+1 |= 0x04`, `MCUFWDL |= 1`, `+2 &= 0xf7`, pages with
  `rtl_fill_dummy` and no inter-page delay, close (`&= 0xfe`, `+1 = 0`),
  `FWDL_CHKSUM_RPT` within the first 99 undelayed reads, `MCUFWDL_RDY` /
  `~WINTINI_RDY`, `WINTINI_RDY` over 101 reads x 5 ms. A failed
  `_rtl92c_fw_free_to_go` is an error here (Linux logs and returns 0). A
  still-running RAM image is stopped as in `_rtl92ce_poweroff_adapter`
  (`rtl92c_firmware_selfreset`: `HMETFR+3 = 0x20`, up to 100 x 50 us for
  `SYS_FUNC_EN+1` BIT2, then `MCUFWDL = 0`).
  `firmware_transport::Owner` admits the family (parse dispatch,
  `run_8192ce`): the registered image must be the one selected for the
  measured version; the run qualifies the version before any write, runs
  the power prefix, clears CR DMA/MAC gates instead of `REG_CR = 0x2ff`
  (ring owner), stops a running image and downloads.

- `tables` — `table.c` arrays generated verbatim (MAC_2T 162, PHY_REG
  1T/2T 374, PHY_REG_PG 192, AGC 1T/2T 320, RADIOA 1T/2T 282, RADIOB_2T 78,
  RADIOB_1T 1 word, never walked for a 1T1R part). Selection is
  `IS_92C_SERIAL` (2T tables) vs 88C (1T); there are no conditional rows.
- `trx` — legacy linked rings (`trx.{c,h}`): 64-byte TX entries whose
  first 40 bytes (`clear_pci_tx_desc_content` / `TX_DESC_NEXT_DESC_OFFSET`)
  are filled per frame and whose dword 10 is the next link; the
  single-segment `rtl92ce_tx_fill_desc` fields (6-bit rate, A-MPDU
  `agg_break` + `max_agg_num 0x14`, RTS/HW-RTS/CTS2SELF at `DESC_RATE24M`,
  40 MHz `data_bw`/sub-carrier incl. `cur_40_prime_sc`, fallback limits,
  `hwseq_en`/`pkt_id 8` for non-QoS under `fwctrl_lps`, BMC) and
  `rtl92ce_tx_fill_cmddesc`; 32-byte RX descriptors with the buffer at
  dword 6 and the `rtl92ce_rx_query_desc` status fields (payload at
  `drvinfo + shift`; the descriptor is not in the buffer).
- `llt` — `_rtl92ce_llt_table_init` with `LLT_CONFIG == 5`: `RQPN_NPQ`
  word 0, `RQPN = 0x80b01c29`, `TRXFF_BNDY = 0x27ff00f6`, boundary 246 in
  `TDECTRL+1`/BCNQ/MGQ/`0x45d`, PBP `0x11`, DRVINFO 4, 256 links (TX chain
  ending `0xff`, ring 246..255 closing at 246) with the 21-read LLT poll.
- `mac` — `_rtl92ce_init_mac` after the LLT: HISR (`0x124`) / HISRE W1C,
  `TRXFF_BNDY+2 = 0x27ff`, `TRXDMA_CTRL = (old & 0xf) | 0xf771`,
  `FWHW_TXQ+1 = 0x1f`, RCR `0xf0006b0e`, TCR `0x3200`, `0x4d0 = 0`,
  `PCIE_CTRL_REG+3 = 0x77` (92C) / `0x22` (88C), INT_MIG 0, the
  `APSD_CTRL` BIT6/BIT7 wait, `MCUTST_1 = 0`; the post-MAC-table RCR trim
  (`~(ACRC32|AICV)`), `_rtl92ce_hw_configure` (non-BT) and software crypto +
  station address. `REG_CR = 0x2ff` and the ring bases stay with the owner.
- `prepare::Chip::Rtl8192ce` — the retained linked-ring owner profile
  (88EE geometry, next link at byte 40) runs `_rtl92ce_llt_table_init` and
  masks the 92C IMRs (`0x120` / `0x128`, not the 88EE `0xb0` / `0xb8`). The
  88EE `REG_PCIE_CTRL_REG+1 = 0xff` DMA-stop write is not issued: on the
  92C Linux uses `REG_PCIE_CTRL_REG` only as the TX polling doorbell, so CR
  gates and parked BME hold its DMA closed. Probe's
  interrupt masking is chip-aware (`irq::disable_interrupts_for`, below).

- `phy` — `rtl92c_phy_set/query_bb_reg` and `_rtl92c_phy_rf_serial_
  write/read` (`offset &= 0x3f`; read: `0x824` edge low, the path's HSSI2
  with address and edge, `0x824` edge high, `mdelay(1)` after each, PI/SI
  read-back by the path's HSSI1 BIT(8)); `rtl92ce_phy_set_rf_reg` reads
  first for every mask but `RFREG_OFFSET_MASK` (incl. `MASKDWORD`).
  `configure` = `rtl92ce_hw_init` from `rtl92c_phy_mac_config` (MAC_2T
  bytes, then `0x14 = 0x71` on 92C / `0x4ca = 0x0a` on 88C), the RCR trim,
  `rtl92c_phy_bb_config` (SYS_FUNC_EN word `| BIT13|BIT1|BIT0`,
  `AFE_PLL_CTRL = 0x83`/`+1 = 0xdb`, RF_CTRL 7, SYS_FUNC_EN `0xe3`,
  `AFE_XTAL_CTRL+1 = 0x80`, LEDCFG0 BIT23, PHY_REG 1T/2T walk with
  `rtl_addr_delay` + 1 us, PHY_REG_PG `_rtl92c_store_pwrindex_diffrate_
  offset` (4 groups), AGC 1T/2T walk, `cck_high_power`; the `RF_1T2R`
  `_rtl92c_phy_bb_config_1t` never runs), `_rtl92ce_phy_rf6052_config_
  parafile` over `num_total_rfpath` (1 for 88C, 2 for 92C; RFENV
  save/restore, `rtl_rfreg_delay` rows), the UMC fixups (88C A-cut RF A
  `RF_RX_G1 = 0x30255`, `RF_RX_G2 = 0x50a00`; B-cut RF A `0x0c/0x0a/RF_IPA/
  RF_SYN_G2/RF_RCK1/RF_RCK2`), `rfreg_chnlval` from both paths (also on
  88C, as Linux), CCK/OFDM on and `0x884` BIT10. Bandwidth:
  `rtl92ce_phy_set_bw_mode_callback` (BWOPMODE, RRSR+2 `(v & 0x90) | sc <<
  5`, RFMOD 0x800/0x900, `0x884` BIT10 1 at 20 / 0 at 40, CCK sideband
  `sc >> 1`, `0xd00[11:10]`, `0x818[27:26]`) and
  `rtl92ce_phy_rf6052_set_bandwidth` (path A only, bit 10 at 20 MHz).
  Channel: `sw_chnl_rf` = the `CMDID_RF_WRITEREG` step (`RF_CHNLBW[9:0]`
  per RF path) plus `_rtl92c_phy_sw_rf_seting` (UMC B-cut RF A `RF_RX_G1`
  `0x00255` on channel 6 at 20 MHz, else rewritten with itself) and 10 ms.
  `lc_calibrate` = `_rtl92ce_phy_lc_calibrate(is2t)` (TXPAUSE or `0xd03`
  continuous-TX save, `MASK12BITS` writes with Linux's unmasked values,
  `0x18 | 0x08000`, 100 ms). `rfpath_switch_main` = `_rtl92c_phy_set_
  rfpath_switch(1)` with `is_hal_stop` true (hw_init precedes
  `set_hal_start`): LEDCFG0 BIT23, `0x878` BIT13, then 92C `0x864[6:5] = 1`
  / 88C `0x860[9:8] = 2`.
- `txpower` — `_rtl92ce_read_txpower_info_from_hwpg(autoload_fail =
  false)`: CCK/HT40-1S areas (`0x5a`/`0x60`, stride 3, both bytes must be
  non-`0xff` else `0x22`), HT40-2S diff nibbles (`0x66`), `ht40_2s =
  max(1s - diff, 0)`, `rtl92c_get_chnl_group` (index `< 3` / `< 9` / else),
  per-path power-limit nibbles (`0x6f`/`0x72`, `0xff` ⇒ 0), HT20 diff
  (`0x69`, BIT3 ⇒ `| 0xF0`, default 2), legacy diff (`0x6c`, default 3),
  regulatory `0x79[2:0]`, TSSI, thermal `[4:0]` (default `0x12`).
  `set_level` = `rtl92c_phy_set_txpower_level`: CCK from `txpwrlevel_cck`,
  OFDM from `ht40_1s` (1T1R) or `ht40_2s` (2T2R);
  `rtl92ce_phy_rf6052_set_cck_txpower` (scan: `0x3f3f3f3f` unless
  regulatory != 0; byte clamp `0x3f`; `0xe08[15:8]`, `0x86c[31:8]`,
  `0x86c[7:0]`, `0x838[31:8]`) and `rtl92ce_phy_rf6052_set_ofdm_txpower`
  (`rtl92c_phy_get_power_base` with u8-wrapping HT20 diff at 20 MHz;
  `_rtl92c_get_txpower_writeval_by_regulatory` incl. the regulatory-1
  channel groups and regulatory-3 customer limit; `_rtl92c_write_ofdm_
  power_reg` with `0x7f` byte masks, clamp and the `0xc90`/`0xc98` three
  `-6` bytes after MCS15_MCS12 (2T2R) or MCS07_MCS04 (otherwise)). Both
  paths' TXAGC registers are written on 88C too, as Linux. Linux reads the
  rate differences from `rtlphy->mcs_offset`, which nothing on this family
  writes (the PG walk fills `mcs_txpwrlevel_origoffset`), so `MCS_OFFSET`
  is zero and the write value is the power base; the BT1/BT2 high-power
  subtractions never apply (no BT boards).
- `iqk` — `rtl92c_phy_iq_calibrate(false)` for both RF types (`is2t =
  IS_92C_SERIAL`): three `_rtl92c_phy_iq_calibrate(t)` runs (t = 0 backs up
  16 ADDA dwords, `0x522/0x550/0x551` bytes + `0x040` dword, `0xc04/0xc08/
  0x874`, and latches `rfpi_enable`); ADDA on (`0x0b1b25a0`/`0x0bdb25a0`
  1T, `0x04db25a4`/`0x0b1b25a4` 2T), PI mode while SI, two tries of path A
  (`0xe3c` `0x28160502` 1T / `0x28160202` 2T with the path-B tone
  registers) and on 2T path-A standby + two tries of path B, Linux's
  brace-less `result[t][1]`/`[5]` assignments kept; restores (PI, ADDA,
  MAC reloads only for t != 0). `_rtl92c_phy_simularity_compare` (bound
  8/4, MAX_TOLERANCE 5, zero-RX candidate rule copying only the TX pair),
  candidate choice, path A / (2T) path B matrix fills (u32 `x`, `long y`),
  save of the ten `iqk_bb_reg` (`recover` reloads them). No APK
  (`_rtl92c_phy_ap_calibrate` is empty in Linux).
- `channel` — `rtl_op_config` wide channel (HT40+ = primary + 2 / LOWER,
  HT40- = primary - 2 / UPPER; pairs outside wide 3..=11 refused), TX power
  at the new width, `sw_chnl_rf`, then `set_bw_mode` (`act_scanning`
  false on the station path).
- `init` — the `rtl92ce_hw_init` tail after the download, run by
  `Prepared::configure_rtl8192ce` (`rtl8192ce/radio_owner.rs`, Prepared →
  RadioConfigured; version re-qualified from live `REG_SYS_CFG` /
  `REG_HPON_FSM`, adapter facts from `REG_9346CR`; BT boards, a MAC other
  than the factory identity and undecodable maps refused before any write):
  `phy::configure`, `mac::hw_configure`, `rtl_cam_reset_all_entry`,
  `mac::station_identity`, the RF path switch, IQK, LCK (`rtl92c_dm_check_
  txpower_tracking` is a no-op on a fresh owner: `dm.txpower_tracking` is
  set only by the later `rtl92c_dm_init`), then `efuse_read_1byte(0x1FA)`
  (up to 1000 polls, data read even on timeout, as Linux): BIT0 clear ⇒ RF
  A `0x15[3:0] = 5`, BIT1 clear on 92C ⇒ RF B, BIT4 clear ⇒ `0x16 = (v &
  0x0f) | 0x80`, 10 us, `| 0x90`. `Prepared::configure_rtl8192ce_channel`
  (RadioConfigured/ChannelConfigured → ChannelConfigured) runs `channel::
  configure` with the retained version, factory power and `rfreg_chnlval`.
  Not issued: ASPM back door / `enable_aspm`, `rtl8192ce_bt_hw_init`;
  `rtl92c_dm_init` is DM-owner software state.
- `h2c` — `rtl92c_fill_h2c_cmd` / `_rtl92c_fill_h2c_command` (zeroed
  8-byte copy; `_rtl92c_check_fw_read_last_h2c` = `REG_HMETFR` bit clear
  and `REG_MCUTST_1 + box` zero, 99 re-checks 10 us apart each followed by
  the `0x1BF` read; 1–3-byte commands id BIT(7) clear, 4–5-byte set with
  the first two bytes into `REG_HMEBOX_EXT_n` (`0x88 + 2n`) first;
  `last_hmeboxnum` rotation; no power-save gate on this family). Deliberate:
  an undrained box or bad length poisons the mailbox (Linux logs and
  drops). Payloads: `SETPWRMODE` (id 1: mode, smart PS 1, awake interval
  5), `JOINBSSRPT` (id 2), `RA_MASK` (id 6) = `rtl92ce_update_hal_rate_mask`
  for a 2.4 GHz station (`macid` 0; B/G/N masks per RSSI level, N rows by
  RF type — 1T1R `0x000f0000/0x000ff000/0x000ff015|005`, 2T2R `0x0f0f0000/
  0x0f0ff000/0x0f0ff015|005` — SGI for the width's SGI, `ratr_index << 28`,
  byte 4 `0x80 | sgi << 5`); `HW_VAR_SET_RPWM` (`0x3dc` BIT7 toggle).
  Interrupts: `rtl92ce_enable_interrupt` (HIMR `0x120` = `0x1b5f`, HIMRE
  `0x128` = `0x300`), `rtl92ce_disable_interrupt` (both 0) and
  `rtl92ce_interrupt_recognized` (HISR `0x124` under mask, W1C). Probe's
  `pci::bring_up` now masks through `irq::disable_interrupts_for(did)`
  (`irq::imr_pair`: `0x120/0x128` for the CE IDs, `0xb0/0xb8` otherwise).
- `envelope` — signed per-board `N92C` power envelope
  (`rtlwifi/rtl8192ce-cal-v1-<mac>.bin`; `rtl8192ce/envelope.rs`). Same
  96-byte header shape as `N92E` with its own magic, the probed
  `rtl92ce_pci_ids` device and an RF-type byte (1 = `RF_1T1R`, 2 =
  `RF_2T2R`, must equal the measured chip version) in place of the zero
  pad; rows in the `N92E` 2.4 GHz 20/40 MHz plan carry per family (CCK,
  OFDM, MCS0-7, and MCS8-15 on 2T2R only) path A (and path B on 2T2R
  only) 64-entry measured curves — 3 per row for 1T1R, 8 for 2T2R. The
  upper bound is `txpower::linux_indices` (the exact bytes
  `rtl92c_phy_set_txpower_level` would write at the wide channel/width,
  incl. Linux's `0xff00ffff` mask zeroing path A CCK 11M). Admission per
  transmitting path: highest measured index not above the Linux byte whose
  output + antenna gain (+ the 13 qdBm two-chain bound on 2T2R only) fits
  the whole-span ceiling (`rtl8192ee::envelope::span_ceiling`, capped by
  the qualified EIRP); every CCK/OFDM rate must be admitted; the admitted
  set is CCK/OFDM/MCS0-7 (1T1R) or up to MCS0-15 (2T2R). 1T1R path B
  TXAGC bytes are written 0. Format only: no board values are supplied.
  `channel::configure_admitted` / `txpower::set_indices` program the
  admitted indices in Linux's register order (the `0xc90`/`0xc98` tail
  follows the written MCS15 / MCS7 byte), then `sw_chnl_rf` and
  `set_bw_mode`. `Prepared::configure_rtl8192ce_channel(Permission)`
  (RadioConfigured/ChannelConfigured → ChannelConfigured;
  MacConfigured/Running retune keeps the phase) checks identity and RF
  type; `configure_rtl8192ce_mac` (ChannelConfigured → MacConfigured)
  requires the same identity on owner and permission. `init::Radio`
  retains `receive_config` (the `rtl92c_phy_mac_config` RCR trim) for
  `HW_VAR_RCR`. Test (written, unexecuted):
  `smoke_rtl8192ce_n92c_envelope_permission_and_admission`.
- `packet owner` — `rtl8192ce/packet_owner.rs`, mounted as
  `prepare::packet::ce92` and dispatched from `packet.rs` for
  `Chip::Rtl8192ce` (start, submit, receive, IRQ enable/disable/recognize,
  leisure enter/leave, quiesce; `stop_packets` masks `0x120`/`0x128` and
  issues no `0x301` stop on this chip). Start: bus mastering, then the
  deferred `_rtl92ce_init_mac` `REG_CR = 0x2ff` (word) and `TXPAUSE = 0`,
  with both 92C IMRs read back zero; requires the channel recorded by
  `configure_rtl8192ce_channel`. TX: one outstanding frame (rate rules
  below), [`trx::fill`] descriptor (macid 0 under `dm.useramask`), OWN
  written last, `REG_PCIE_CTRL_REG` `BIT(hw_queue)`
  doorbell; the shared host receipt (`delivery`) applies unchanged. RX:
  in-ring 32-byte descriptor (`trx::RxStatus`, payload at `drvinfo +
  shift`, `rx_arm` re-post with OWN last; HT/A-MPDU and PWDB below). IRQ: `rtl92ce_enable_interrupt`
  / `_disable_` / `_interrupt_recognized` (HISRE untouched, `intb` 0).
  Leisure: `HW_VAR_FW_LPS_ACTION` — enter: `fw_current_inpsmode`, on 88C
  `rtl92c_dm_rf_saving(hw, true)` (the `HW_VAR_H2C_FW_PWRMODE` rule for
  `!IS_92C_SERIAL`), `SETPWRMODE(FW_PS_DTIM_MODE)` (`reg_fwctrl_lps = 3`),
  RPWM `0x02`; leave: RPWM `0x0c`, `SETPWRMODE(FW_PS_ACTIVE_MODE)`. Join
  (`ce92_join_report`): `_rtl92ce_set_media_status(STATION, linked)`, then
  `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)` exactly as `rtl92ce_set_
  hw_reg` (`HW_VAR_AID`, `REG_CR + 1` BIT0, BCN_CTRL `(0,BIT3)`/`(BIT4,0)`,
  `0x422` BIT6 clear, `rtl92c_set_fw_rsvdpagepkt` — the 768-byte
  `reserved_page_packet` (byte-identical to 88EE's, so
  `station_control::reserved_pages` is reused) through beacon descriptor 0
  with `rtl92ce_tx_fill_cmddesc` and the `BIT(4)` doorbell, then
  `H2C_RSVDPAGE {4, 2, 3}` — restores, `H2C_JOINBSSRPT(1)`). The 92C has no
  BCN_VALID receipt (Linux sends the location right after the doorbell);
  the body is owned by the claim until quiescence. The join's media
  status is `rtl92ce_set_network_type` (media status, then
  `rtl92ce_set_check_bssid(true)` over the retained `receive_config`).
  Leave (`ce92_disconnected`, Linux `BSS_CHANGED_ASSOC` `!assoc` order):
  LPS leave (RPWM `0x0c`, `FW_PS_ACTIVE_MODE`), RA link withdrawn,
  `rtl92ce_set_network_type` unlinked (MSR NOLINK, CBSSID off),
  `JOINBSSRPT(RT_MEDIA_DISCONNECT)` (AID / reserved page are connect-only),
  zero BSSID.
  RA (`ce92_install_rate_mask`): `rtl92ce_update_hal_rate_mask` refused
  unless its rate bits are a non-empty subset of the caller's admitted
  set. DM (`ce92_dm_watchdog`, only out of LPS): `rtl92c_dm_false_alarm_
  counter_statistics` and `rtl92c_dm_dynamic_bb_powersaving` (88C
  `rtl92c_dm_rf_saving(false)` on `undec_sm_pwdb`, 30/25 hysteresis; 92C
  nothing). Linux's `rtl92c_dm_watchdog` has
  `rtl92c_dm_refresh_rate_adaptive_mask` commented out, so the RA mask is
  never refreshed by the watchdog. Not composed: PWDB monitor, DIG,
  dynamic TX power, TX-power tracking, EDCA turbo (registers keep their
  `rtl92ce_hw_init` values). Card disable (`ce92_quiesce`): the 92C
  sources define no TX-buffer-empty / RXDMA-idle status (no 88EE
  `0x5f8`/`0x286` poll). Proof composed here, after `stop_packets`
  (TXPAUSE `0xff`, CR DMA enables clear, BME off): every non-beacon TX
  descriptor OWN clear (`rtl92ce_is_tx_desc_closed`), then
  `rtl92ce_card_disable` (`_rtl92ce_set_media_status(UNSPECIFIED)`,
  `_rtl92ce_poweroff_adapter` non-BT without `enable_aspm`, incl.
  `REG_SYS_FUNC_EN + 1 = 0x51` dropping `FEN_DCORE`), then a non-posted
  read of `REG_SYS_FUNC_EN + 1` returning `0x51` (PCIe ordering keeps any
  earlier device write ahead of it). Any disagreement retains every
  mapping. Chip pieces: `rtl8192ce/ps.rs`. Tests (`rtl8192ce/ps_tests.rs`,
  written, unexecuted): `smoke_rtl8192ce_media_status_and_aid`,
  `smoke_rtl8192ce_rf_saving_hysteresis`,
  `smoke_rtl8192ce_false_alarm_statistics`,
  `smoke_rtl8192ce_poweroff_adapter`. Owner-level model tests of the
  `ce92` paths are not written yet.
  Station branch (`rtl8192ce/station.rs`, `packet_owner.rs`): exact
  `rtl92ce_set_hw_reg` `HW_VAR_BSSID`, `HW_VAR_BASIC_RATE` (`(rates &
  0x15f) | 1` into RRSR and the highest-bit index into
  `REG_INIRTS_RATE_SEL`; no 92EE `| 0xd`), `HW_VAR_SLOT_TIME` (its
  `HW_VAR_AC_PARAM` loop writes nothing under `EACMWAY2_SW`),
  `HW_VAR_SIFS` (`0x0a0a`, `0x1010` with HT), `HW_VAR_ACK_PREAMBLE`,
  `rtl92ce_set_qos` (fixed BK/VI/VO rows, BE never written). The
  `station_power` `Base::Rtl8192ce` / `Grant::Rtl8192ce` pair (regrant at
  the same operating point, `with_current`, `wait_rtl8192ce`),
  `station_grant`, `stage_rtl8192ce_calibration` and CE arms for every
  `packet.rs` station path: awake (`REG_CR != 0xEA`; `rtl92ce_hw_init`
  leaves the firmware awake), prepare peer (BSSID + rates at the
  permission's `cur_40_prime_sc`), complete peer (`rtl_cam_reset_all_entry`,
  `HW_VAR_KEEP_ALIVE` via `H2C_92C_KEEP_ALIVE_CTRL` 48, then
  `ce92_join_report`), LPS enter/leave, leave and terminal disconnect
  (`ce92_disconnected`), association RA mask
  (`install_rtl8192ce_station_rate_mask`: `mac->mode` B for
  `supp_rates[0] <= 0xf` else G, `bw_40` from the programmed width,
  bounded by the `N92C` admitted rates, inside the envelope's authority;
  N_24G for an HT profile, below) and the DM watchdog
  (`rtl8192ce_watchdog`, never re-sends a mask, as Linux). The 88EE
  `install_rate_mask` path refuses CE. Test (written, unexecuted):
  `smoke_rtl8192ce_station_registers`.
- RX (`ce92_receive_step`, `rtl92ce_rx_query_desc`): on an HT link
  (`packet.ht`, set at Configuring) MCS0-7 on `RF_1T1R` / MCS0-15 on
  `RF_2T2R` (the advertised RX set) and A-MPDU members (the BA owner gates
  them) up to the 7935-byte A-MSDU MPDU; `Mpdu.ht` from RXHT, `width40`
  from the BW bit (`rx_is40mhzpacket`), `aggregated` from PAGGR; no SGI
  flag (Linux reports none). PWDB: `_rtl92ce_query_rxphystatus`
  `rx_pwdb_all` from the driver-info PHY status at `rx_bufshift`
  (`trx::rx_pwdb`: OFDM `pwdb_all` byte 4; CCK `cck_agc_rpt` byte 5 with
  the `cck_high_power` report/gain split, `+6` cap and the four offset
  bands), fed to `rtl_process_phyinfo` smoothing for BSSID-matched frames.
  Test `smoke_rtl8192ce_rx_phy_status_pwdb` (`rtl8192ce/tests.rs`,
  written, unexecuted).
- TX (`ce92_submit`, `rtl_get_tcb_desc` + `rtl92ce_tx_fill_desc`):
  ordinary unicast DATA under the installed RA mask (`queue_station`'s
  8192EE/8192CE arm, protection independent) clears USE_RATE, starting at
  `_rtl_get_highest_n_rate` (MCS15 on `RF_2T2R` with `rx_mask[1]`, else
  MCS7; 11M B / 54M G); every DATA frame of the link names RATE_ID from
  `wireless_mode` (`_rtl_txrate_selectmode` with `dm.useramask`, no
  NEW_RATEID: NGB 0 / GB 4 / B 6), MACID 0; other frames
  `RATR_INX_WIRELESS_MC`. DISFB is never set (`set_tx_desc_disable_fb(0)`).
  Special data (`rtl_is_special_data`, shared `packet_owner::special_data`:
  EAPOL, ARP, DHCP; plaintext only) takes `_rtl_rc_get_rate` rix 0, i.e.
  `use_driver_rate` at `DESC_RATE1M`; a (QoS) Null DATA frame keeps
  `use_driver_rate` at the driver rate (`rtl92ce_tx_fill_desc` writes
  USE_RATE as given, unlike 92EE). `bw_40`: unicast above 54M on an HT link
  is 40 MHz (`data_bw` 1, SC 3), every other frame `cur_40_prime_sc`.
  AGG_EN (`agg_break`) + `max_agg_num 0x14` for an operational BA TID with
  the peer's density (QoS DATA only); data SGI from `_rtl_query_shortgi`
  (SGI40 at 40 MHz, SGI20 at 20). Protection: ERP Use_Protection / RTS
  threshold admitted under `N92C` (`native_protection`), RTS_EN or
  CTS2SELF at `DESC_RATE24M`, long preamble, HW_RTS per `trx::fill`. Every
  rate the descriptor can put on air (`hw_rate`, and `DESC_RATE24M` when
  protected) must be in `admitted_rates` (`Power(Policy)` otherwise).
  Short preamble / slot follow `ieee80211_handle_bss_capability` (BSS ERP
  octet at association, `configure_rates`; tracked beacon changes through
  `rtl8192ce::station::erp_changed`, `ce92.erp_timing`).
- HT station (`rtl8192ce/ht.rs`): `_rtl_init_hw_ht_capab` per RF type
  (RX MCS0-7 / MCS0-15, `SUP_WIDTH_20_40 | SGI_40 | SGI_20 | DSSSCCK40 |
  MAX_AMSDU`, factor 3, density 7; MCS32 / `rx_highest` omitted); the
  20/40 form only under an admitted 40 MHz `N92C` permission for the AP's
  geometry (`ht_width.rs::rtl8192ce_wide`), TX MCS8-15 only on `RF_2T2R`
  when the 20 MHz and (offered) 40 MHz permissions admit every two-stream
  rate (`rtl8192ce_two_stream`). Join plan: `rtl8192ce::ht::local` under
  `rtl8192ce_ht()` (MCS0-7 admitted); width via `retune_rtl8192ce`
  (`configure_rtl8192ce_channel` at the target operating point inside the
  permission's authority, as `retune_rtl8192ee`). `BSS_CHANGED_HT`: all
  three `rtl92ce_set_hw_reg` cases (`HW_VAR_SHORTGI_DENSITY`,
  `HW_VAR_AMPDU_FACTOR` `regtoset_normal` into `REG_AGGLEN_LMT`,
  `HW_VAR_AMPDU_MIN_SPACE` into `0x45c`, `min_space_cfg` cache kept across
  associations). Beacon observation with the HT20 PHY; host capability
  (`ht::host_capabilities` / `host_phy` → `interface.rs`
  `rtl8192ce_caps`). Association RA mask: N_24G peer with mac80211's
  intersected TX MCS set and SGI flags, bounded by `admitted_rates`. Test
  `smoke_rtl8192ce_ht_capability_timing_and_erp` (`rtl8192ce/ps_tests.rs`,
  written, unexecuted).
- Probe admission (`pci.rs`, `prepare_native.rs`, `interface.rs`,
  `rebuild_native.rs`, `power_runtime.rs`). `bring_up` retains a
  `rtl92ce_pci_ids` function (BAR2 at least `rtl8192ce::MMIO_SIZE`) only
  when the facts `configure_rtl8192ce` re-derives already hold:
  `_rtl92ce_read_chip_version` qualifies (no test chip, 1T2R bonding or
  unknown cut, so the RF type is `RF_1T1R` or `RF_2T2R`), provisioned map,
  not a BT-coexist board, EFUSE MAC equal, TX-power areas decode; otherwise
  it stays diagnostic. `prepare_native::prepare_rtl8192ce` (channels 1-11):
  registry firmware, generic linked-ring `allocate`, `prepare`,
  `configure_rtl8192ce(factory, firmware.device_id())`, then
  `admit_rtl8192ce` (`N92C` envelope for the probed device and measured RF
  type, 20 MHz permission on the channel, `configure_rtl8192ce_channel`,
  `configure_rtl8192ce_mac`, `stage_rtl8192ce_calibration`), shared with
  the interface readiness path. `prepare_bus_power` keeps ASPM disabled
  (92CE `enable_aspm` not composed); `allow_channel` is the `N92C` 20 MHz
  permission (RF type from the live version). Rebuild: `power_down`
  accepts the owner's `ce92_quiesce` card disable by its `SYS_FUNC_EN + 1
  == 0x51` receipt (else runs `_rtl92ce_poweroff_adapter` for the live
  qualified version, `power_runtime::disable_rtl8192ce`); there is no
  separate enable (the fresh owner's firmware run issues the
  `_rtl92ce_init_mac` prefix once, as `rtl92ce_hw_init`), then
  `verify_factory` and a fresh `Owner`. Not composed: BT coexistence, ASPM,
  WoWLAN, LDPC/STBC, DIG / dynamic TX power / TX-power tracking / EDCA
  turbo (above). No board envelope values are supplied (format only), so
  no physical board is admitted without its signed `N92C` asset.
  Tests (`rtl8192ce/phy_tests.rs`, written, unexecuted):
  `smoke_rtl8192ce_rf_serial_read_write_both_paths`,
  `smoke_rtl8192ce_h2c_rate_mask_and_irq_profile`,
  `smoke_rtl8192ce_bb_rf_config_per_rf_type`,
  `smoke_rtl8192ce_txpower_efuse_and_txagc`,
  `smoke_rtl8192ce_channel_bw40_and_umc_b_rx_g1`,
  `smoke_rtl8192ce_iqk_both_rf_types`,
  `smoke_rtl8192ce_lck_and_pa_bias_rule`.

Tests (written, unexecuted): `smoke_rtl8192ce_chip_version_rf_type_and_firmware_name`,
`smoke_rtl8192ce_firmware_header_geometry`,
`smoke_rtl8192ce_firmware_paged_download`,
`smoke_rtl8192ce_retained_firmware_owner_profile`,
`smoke_rtl8192ce_adapter_info_factory_rules`,
`smoke_rtl8192ce_tx_descriptor_fields`,
`smoke_rtl8192ce_rx_descriptor_status_and_arm`,
`smoke_rtl8192ce_llt_and_init_mac_remainder`,
`smoke_rtl8192ce_linked_ring_profile`,
`smoke_rtl8192ce_tables_verbatim_geometry`.

### RTL8723BE retained runtime (admitted legacy 2.4 GHz station)

`rtl8723be/` holds the Linux `rtl8723be` + `rtl8723com` pieces the native
RTL8723BE (`0xb723`, 1T1R 2.4 GHz + BT combo) owner is built from. Probe
retains a provisioned function (see "Station composition and probe
admission" at the end of this section); BT-coexist boards are admitted,
the coexistence owner runs every composed call site.

- `version` — `_rtl8723be_read_chip_version`: `REG_SYS_CFG1` must carry
  `CHIP_8723B` (Linux only logs and continues with `VERSION_UNKNOWN`, which
  selects nothing meaningful; refused here), then `NORMAL_CHIP`, the
  `REG_SYS_CFG[15:12]` cut and `CHIP_VENDOR_SMIC` when `EXT_VENDOR_ID == 1`.
  Firmware: `rtl8723befw_36.bin`, then `rtl8723befw.bin` only when the
  primary is absent (`rtl_fw_do_work` `alt_fw_name`).
- `adapter` — `rtl8723be_read_eeprom_info` / `_rtl8723be_read_adapter_info`
  over the 512-byte map: EEPROM boot, autoload failure or a map without
  `0x8129` is unprovisioned (Linux skips the whole adapter read). MAC `0xd0`,
  VID/DID/SVID/SMID, channel plan `0xb8`, version, customer id, crystal
  `0xb9` (`0xff` ⇒ `0x20`), thermal `0xba` (`0xff` ⇒ `0x18`, ignore), the
  `0xc1[2:0]` regulatory (`0xff` ⇒ 0), the OEM rule (its `0x8176`/`0x8178`
  DID branches are carried as written) and
  `rtl8723be_read_bt_coexist_info_from_hwpg`: `btcoexist =
  REG_MULTI_FUNC_CTRL[18]`, `ant_num = 0xc3[0]` (`ANT_X2 = 0`, `ANT_X1 = 1`),
  `single_ant_path = 0xc3[6]`; `board_type = ODM_BOARD_BT` for BT boards.
  `rtlhal->package_type` comes from the physical EFUSE byte `0x1fb`
  (`efuse::read_physical_byte`: `efuse_power_switch` + `efuse_one_byte_read`,
  100-read poll; a timeout is value 0 ⇒ `PACKAGE_DEFAULT`).
- `pwrseq` — PCI rows of every `rtl8723B_*_flow`, generated from
  `pwrseq.h` (sha256 in the file header). Probe's power table for `0xb723`
  is now the exact `rtl8723B_card_enable_flow` after the
  `_rtl8723be_init_mac` prefix (`RSV_CTRL = 0`, `APS_FSMCO+1 &= ~BIT7`),
  parsed with `PWR_CUT_ALL_MSK` as Linux does (so the test-chip-masked
  `0x68[3]` row is issued). The former shared rows are kept, unchanged, as
  `RTL8723AE_PWR_ON` for the diagnostic RTL8723AE.
- `fw` — `is_fw_header` (`signature & 0xfff0 == 0x5300`), exact RAM-code
  length (linux-firmware `0x7bf2` / `0x77fa`), whole file at most
  `max_fw_size = 0x8000` (eight pages). `rtl8723_download_fw(hw, true,
  6000)`: a running RAM image is reset (`rtl8723be_firmware_selfreset`:
  `RSV_CTRL+1` BIT0 and `SYS_FUNC_EN+1` BIT2 low for 50 us) and
  `MCUFWDL = 0`; enable, pages with `rtl_fill_dummy`, close;
  `FWDL_CHKSUM_RPT` within the first 5999 undelayed reads, `MCUFWDL_RDY` /
  `~WINTINI_RDY`, the 8723BE self-reset, then `WINTINI_RDY` over 6001 reads
  x 5 ms. A failed `rtl8723_fw_free_to_go` is an error here (Linux returns
  0). `firmware_transport::Owner` admits `0xb723` (`run_8723be`, 31 s
  bound covering Linux's): identify the chip before any write, clear CR
  DMA/MAC gates instead of `REG_CR = 0x2ff` (ring owner), `REG_SYS_CFG &=
  0x7f`, download. Tests `smoke_rtl8723be_chip_version_and_firmware_names`,
  `smoke_rtl8723be_adapter_facts_bt_antenna_and_defaults`,
  `smoke_rtl8723be_firmware_header_geometry`,
  `smoke_rtl8723be_firmware_paged_download`,
  `smoke_rtl8723be_retained_firmware_owner_profile`,
  `smoke_rtlwifi_8723be_enable_prefix_and_card_enable_flow` (written,
  unexecuted).
- `trx` — `rtl8723be/trx.h` is the RTL8821AE layout bit for bit (no
  `tx_ant`; RX `rxht` at dword 3 BIT6): 40-byte TX descriptor in a 64-byte
  entry, buffer at dword 10, `next_desc_address` at dword 12 (byte 48),
  32-byte RX status with the buffer at dword 6. `rtl8723be_tx_fill_desc`
  single-buffer path (`max_agg_num 0x14`, TCB RTS rate/SC/short, short GI
  only above `DESC92C_RATEMCS0`, 40 MHz SC 3 or `cur_40_prime_sc`,
  `HWSEQ_EN` for non-QoS, BMC, tx report), `rtl8723be_tx_fill_cmddesc`
  (OWN left to the publishing owner) and the `rtl8723be_rx_query_desc`
  status fields.
- `llt` — `_rtl8723be_llt_table_init`: boundary 245 in `TRXFF_BNDY`,
  `TDECTRL+1`, BCNQ, MGQ, `0x45d`; PBP `0x31`, DRVINFO 4, 256 links, then
  `RQPN = 0x80e40808` and `RQPN_NPQ = 0`.
- `mac` — `_rtl8723be_init_mac` remainder in three segments around the
  owner's `REG_CR = 0xff` / `0x2ff` and LLT (pre-CR `MULTI_FUNC_CTRL[3]`,
  `APS_FSMCO[4]`; clocks `HWSEQ_CTRL |= 0x7f`, 2 ms, `0x7c[6]` when
  `SYS_CFG[24]`, `SYS_CLKR[3]`, `GPIO_MUXCFG[12]` clear; post-LLT HISR/HISRE
  W1C, `FWIMR[30]`, `TRXDMA_CTRL (old & 0xf) | 0xf5b1`, RCR `0xf0007a0e`,
  `RXFLTMAP2`, TCR `0x03008200`, `PCIE_CTRL+3 |= 0x77`, INT_MIG/MCUTST_1,
  `0x577 = 3`, the eight `rtl_set_bbreg` DPDT/fixed-board RMWs, RXDMA
  release), the RCR `ACRC32|AICV` trim, `_rtl8723be_hw_configure` and the
  station address (software crypto). `btc_power_on_setting` belongs to the
  coexistence owner. Tests `smoke_rtl8723be_tx_rx_descriptor_layout`,
  `smoke_rtl8723be_llt_table`, `smoke_rtl8723be_init_mac_and_hw_configure`
  (written, unexecuted).
- ring profile — `prepare::Chip::Rtl8723be` (`0xb723` only; the 8723AE has
  none): the 88EE linked-ring geometry with the next link at byte 48, the
  88EE IMR map (`REG_HIMR` 0xb0 / `REG_HIMRE` 0xb8) and the 0x301 DMA stop.
  `Prepared::prepare` issues, behind that stop and parked BME, the
  `_rtl8723be_init_mac` pre-CR segment, `REG_CR = 0xff` with its 2 ms, the
  clock segment (its own 2 ms), then closes the CR DMA/MAC gates again
  (`REG_CR = 0x2ff` is deferred to packet start), masks both IMRs, runs
  `rtl8723be::llt::init` and publishes the `REG_*_DESA` bases. The
  post-LLT segment belongs to the later radio step. Packet start,
  interrupt enable, awake, the station power grant and the interface's
  admission are the 8723BE branches below (never an 88EE path).
  Test `smoke_rtl8723be_retained_rings_init_mac_prefix_and_llt` (written,
  unexecuted).
- `tables` / `phy` / `init` — `table.c` PHY_REG / PHY_REG_PG / RADIOA /
  MAC / AGCTAB generated verbatim (sha256 in the file header);
  `rtl8723be_phy_config_with_headerfile` + `_rtl8723be_check_positive`
  over the cut, `rtlhal->package_type`, PCIe and `ODM_BOARD_BT` (`driver2`
  is 0: RTL8723BE never sets the per-path amplifier types; RADIOA's only
  conditions are the TFBGA90/80/79 package blocks). `rtl8723_phy_*_bb_reg`
  and `rtl8723_phy_rf_serial_{read,write}` (one `udelay(120)`, PI/SI
  read-back), `rtl8723be_phy_mac_config` (+ `0x4ca = 0x0b`),
  `rtl8723be_phy_bb_config` (`0x948 = 0x280` for `ANT_MAIN`, else 0;
  `_rtl8723be_config_bb_reg` delay rows; crystal cap into
  `REG_MAC_PHY_CTRL[23:12]`), `rtl8723be_phy_rf6052_config` (path A; HP
  OEM `RF 0x52 = 0x7E4BD`) and the `rfreg_chnlval` reads.
  `Prepared::configure_rtl8723be(factory, efuse_0x1fb)` (Prepared →
  RadioConfigured) re-qualifies the version and adapter from live
  registers and the factory map (MAC must equal the factory identity), then
  runs the `_rtl8723be_init_mac` post-LLT segment and the `rtl8723be_hw_init`
  tail through `_rtl8723be_hw_configure`, `rtl_cam_reset_all_entry` and
  the station address. Tests `smoke_rtl8723be_tables_verbatim_geometry`,
  `smoke_rtl8723be_check_positive_package_selection`,
  `smoke_rtl8723be_mac_bb_rf_config` (written, unexecuted).
- `channel` — `_rtl8723be_phy_set_rfpath_switch` (`0x92C` = 1 main / 2
  aux), `_rtl8723be_phy_lc_calibrate(hw, false)` (TX-pause or
  continuous-TX RF 0x00 save by `0xd03[6:4]`, the discarded `RF 0x18`
  read, `RF 0xb0` / `RF 0x18` writes around 50 ms),
  `rtl8723be_phy_set_bw_mode_callback` + `rtl8723be_phy_rf6052_set_bandwidth`
  over the retained `rfreg_chnlval[0]`, and the `CMDID_RF_WRITEREG`
  channel step (`RF_CHNLBW[9:0]`, path A, 10 ms; channels 1..=14).
  `channel::Grant` is the permitted operating point (switched channel,
  width, `cur_40_prime_sc`, path-A TXAGC indices), minted only by
  `Grant::bounded`, which caps every index at the Linux
  `_rtl8723be_get_txpower_index` value; `channel::configure` writes the
  indices, the RF channel step and `set_bw_mode` (the `rtl_op_config`
  order; indices at the operating width). `Prepared::configure_rtl8723be_channel(grant)`
  (RadioConfigured/ChannelConfigured → ChannelConfigured) requires the
  grant's factory identity. The signed per-board envelope
  (`envelope.rs`, #1461) mints the `Permission` the packet owner
  transmits under, and the channel `Grant` is minted from that
  permission's operating point (`Grant::bounded` caps every index at the
  Linux factory value). Test
  `smoke_rtl8723be_rfpath_lck_bandwidth_and_channel` (written,
  unexecuted).
- `iqk` — `rtl8723be_phy_iq_calibrate(hw, false)`: `0x948` save/restore,
  up to three `_rtl8723be_phy_iq_calibrate(t, is2t)` runs (t == 0 ADDA / MAC
  / BB backups, `rtl8723_phy_path_adda_on` `0x01c00014`,
  `rtl8723_phy_mac_setting_calibration`, BB settings, two retries of S1
  path A TX / RX and S0 path B TX / RX through RF path A with `0x948 = 0`
  / `0x280`; reloads, `0xc50`/`0xc58` toggles and tone resets from t == 1),
  `_rtl8723be_phy_simularity_compare` (12 → 0, 13 → 0, 23 → 1, else 3 when
  `result[3]` is non-zero, else 0xff), the path A / B matrix fills (u32
  wrapping; path B's RX-extension write is commented out in Linux and not
  issued), the `iqk_matrix` row and the nine-register `iqk_bb_backup`
  (`iqk::recover`). TX-path results: once the first check passes Linux
  returns 0x01 whatever the second check says; the RX paths stop early
  then. Skipped on `ANT_X1` boards (`get_btc_status()` is always true).
- `txpower` — path A of `_rtl8723be_read_power_value_fromprom` (a map with
  `0x11 == 0xff` is refused: Linux's autoload-fail branch leaves
  `bw40_diff[0][0]` uninitialised), the PHY_REG_PG by-rate store with BCD
  bases and `_phy_convert_txpower_dbm_to_relative_value`,
  `_rtl8723be_get_txpower_index` (u8 wrapping, regulatory 2 drops the
  by-rate diff, `0x3f` clamp) and the `_rtl8723be_phy_set_txpower_index`
  byte lanes for CCK / OFDM / MCS0-7. `configure_rtl8723be` refuses a map
  without the power area before the first table write.
- `ERFON` — `init::configure` now ends with `rtl8723be_phy_set_rfpath_switch(1)`,
  IQK (`ANT_X2` only), `rtl8723be_phy_lc_calibrate`, `REG_NAV_UPPER = 235`
  and the `REG_RXDMA_CONTROL` BIT2 release. `rtl8723be_bt_hw_init` (before
  this block) belongs to the coexistence owner; `rtl8723be_dm_check_txpower_tracking`
  is a no-op on the first `hw_init`; `REG_PCIE_CTRL_REG + 1 = 0` is the
  packet owner's. Tests `smoke_rtl8723be_txpower_efuse_by_rate_and_level`,
  `smoke_rtl8723be_iqk_compare_and_full_run`,
  `smoke_rtl8723be_erfon_block_and_channel_grant` (written, unexecuted).

- `h2c` / `c2h` / `dm` / card disable — `_rtl8723be_fill_h2c_command`
  (the 92EE box / extension-box structure, 100 HMETFR checks with the
  `0x130` read; **no** power-save gate and no `REG_CR == 0xEA` check, so
  the LPS-enter `SETPWRMODE` is written; a full wait is an error that
  poisons the mailbox where Linux drops silently), `rtl8723be_set_fw_pwrmode_cmd`
  (`reg_fwctrl_lps = 2` ⇒ `FW_PS_MAX_MODE`, `smart_ps` 0 on leave / 2 on
  enter, the BT-controlled form `h2c::BtLps` with `SMART_PS = 0`, MIN /
  ACTIVE by `btc_is_bt_lps_on`, byte 5 / power state from coexistence and
  the awake-interval-2 rule), `HW_VAR_SET_RPWM` at `0x361`,
  `_rtl8723be_fwlps_{enter,leave}` (`low_power_enable` false),
  `rtl8723be_update_hal_rate_mask` (RF_1T1R, every N station on
  `RATR_INX_WIRELESS_NGB` ⇒ ARFR 1 at either width, GB 6, B 8),
  `rtl8723be_{enable,disable}_interrupt` (HSIMR = `sys_irq_mask` on every
  enable), `rtl8723be_interrupt_recognized` with `_rtl_pci_hs_interrupt`
  (`IMR_HSISR_IND_ON_INT`); `rtl_c2h_content_parsing` with no
  `c2h_ra_report_handler` (RA report unread) and BT info / MP bodies handed
  to the coexistence owner; `_rtl8723be_query_rxphystatus` PWDB (four-entry
  CCK LNA table, no `cck_highpwr` step) and
  `rtl8723be_dm_refresh_rate_adaptive_mask` (low threshold
  `low2high_rssi_thresh_for_ra40m` = 0, the 8821AE rule). Only the RA mask
  refresh of `rtl8723be_dm_watchdog` is composed (DIG, false alarm, EDCCA,
  CCK PD, EDCA turbo, ATC and TX-power tracking are not).
  `power_runtime::disable_rtl8723be` = `_rtl8723be_poweroff_adapter`
  (LPS-enter flow, self-reset on MCUFWDL BIT7 + ready, MCU reset,
  MCUFWDL 0, card-disable flow, RSV_CTRL+1 pulse, RSV_CTRL 0x0e); the
  rebuild owner's power-down runs it after the station owner's
  retirement proof (below). Tests `smoke_rtl8723be_h2c_boxes_pwrmode_and_rpwm`,
  `smoke_rtl8723be_ra_mask_dm_and_rx_pwdb`,
  `smoke_rtl8723be_c2h_irq_and_card_disable` (written, unexecuted).
- BT coexistence, pass 1 (wired via the pass-3 owner below; not admitted). `btcoex/btc.rs` is the
  `halbtcoutsrc.c` / `rtl_btc.c` glue: `BtCoexist` (`struct btc_coexist`
  state; `bind` = `exhalbtc_initlize_variables` +
  `exhalbtc_bind_bt_coex_withadapter` from `HwPg::rtl8723be(&Adapter)`:
  `ant_num` 2/1, `single_ant_path`, `BTC_CHIP_RTL8723B`, TFBGA unless
  package 0/1, PCI, `btdm_ant_pos` main); the `btc_*` function pointers as
  the `Hal` trait (byte/word/dword, RF, `fill_h2c_cmd`, the C2H `BT_MP`
  wait, `rtl_lps_{leave,enter}`, `rtl_rx_ampdu_apply`); `Ctx` carries
  `halbtc_bitmask_write_1byte`, `write_local_reg_1byte`, BB set/get,
  `halbtc_send_bt_mp_operation` (H2C 0x67), `halbtc_set_bt_reg` (value
  then address, 200 ms each), `halbtc_get_bt_patch_version`, the
  `halbtc_get` queries over `WifiInfo` (HS / ext-switch / MP / IOT peer
  constant as on rtlwifi), the `halbtc_set` actions (`halbtc_*_lps`,
  `disable_low_power`, `halbtc_aggregation_check` with its 8 s gate),
  `rtl_btc_btmpinfo_notify`, `record_pwr_mode`, `lps_ctrl` (the `BtLps`
  inputs), `get_ampdu_cfg`, `is_disable_edca_turbo` and the `exhalbtc_*` /
  `rtl_btc_*` entry points (power-on, pre-load, `rtl_btc_init_hw_config` =
  `init_hw_config(!bt_exist)` + `init_coex_dm`, IPS with the `ERFON` scan
  start/finish, LPS, scan, connect, media, special packet, BT info, halt
  (unbind), PnP, periodical) over the `Algorithm` trait. Differences:
  access errors propagate; the MP completion is the next accepted `BT_MP`
  body (at most 8 per operation); debugfs display is not carried.
  `rtl8723be/btc.rs::BtcHal` implements `Hal` over `Io` + `Mailbox` +
  `fwlps_{leave,enter}` (`LpsGate` holds the `ps.c` conditions; word reads
  come from the aligned dword); `BtMpSource` delivers C2H MP bodies (only
  `NoBtMp` so far). `btcoex/b8723b1ant.rs` is `halbtc8723b1ant.c` (0x47):
  coex dm/sta with the function statics as fields, limited TX/RX, BT-info
  query, BT / Wi-Fi counter monitors, link info, auto report, low-penalty
  RA, the 16 coex tables, ignore-WLAN-act, the full `ps_tdma` table
  (`ps_tdma_bytes`, `wifi_duration_adjust`, `ap_tdma`), LPS/RPWM,
  `set_ant_path`, `tdma_dur_adj_for_acl`, power-save state, every action,
  `run_coexist_mechanism`, init coex dm / hw config and every `ex_`
  handler (power-on, init hwconfig incl. `wifi_only`, init coex dm, IPS,
  LPS, scan, connect, media status, special packet, BT info, RF status,
  halt, PnP, periodical). `btcoex/b8723b2ant.rs` is `halbtc8723b2ant.c`
  (0x3f): coex dm/sta with the `is_wifi_status_changed` and
  `tdma_duration_adjust` statics as fields, the 2/3-level BT and Wi-Fi
  RSSI states, limited RX, BT / Wi-Fi counter monitors (`slave_role`),
  `action_algorithm`, FW DAC swing / dec BT power / SW DAC swing (0x883),
  low-penalty RA (0xf4..0xf6), the 16 coex tables, ignore-WLAN-act,
  LPS/RPWM, the full `ps_tdma` table with the 1.5-antenna `+100` switch,
  `wifi_duration_adjust` and the slave-role byte-4 bit, `set_ant_path`
  (internal / external switch, 0x6e GNT_BT), power-save state, all-off,
  init coex dm, BT inquiry, link / idle processing, `is_common_action`,
  `tdma_duration_adjust` (the per-`max_interval` / `tx_pause` chains as
  `ADJUST_ARMS`, applied in Linux order on the updated `cur_ps_tdma`,
  plus the mismatch restore), every profile action, multi-port,
  `run_coexist_mechanism`, `wifioff_hwcfg` and every `ex_` handler
  (power-on, pre-load firmware, init hwconfig, init coex dm, IPS, LPS,
  scan, connect, media status, special packet, BT info, halt, PnP,
  periodical). `b8723b2ant::Rtl8723b` is the `exhalbtc_*` RTL8723B
  dispatch: both algorithms keep state and each notify goes to the 2-ant
  one when `btdm_ant_num == 2`, the 1-ant one when 1. Difference: the BT
  info row copy is bounded to 10 bytes. Tests
  `smoke_rtlwifi_btc_bind_bitmask_and_wifi_queries`,
  `smoke_rtlwifi_btc_mp_operation_and_bt_reg`,
  `smoke_rtlwifi_btc_lps_actions_and_aggregation`,
  `smoke_rtlwifi_btc8723b1ant_ps_tdma_tables`,
  `smoke_rtlwifi_btc8723b1ant_power_on_and_init_hw_config`,
  `smoke_rtlwifi_btc8723b1ant_bt_info_a2dp_connected`,
  `smoke_rtlwifi_btc8723b1ant_periodical_bt_disable_and_ips`,
  `smoke_rtlwifi_btc8723b2ant_tables_and_algorithm`,
  `smoke_rtlwifi_btc8723b2ant_power_on_and_init_hw_config`,
  `smoke_rtlwifi_btc8723b2ant_a2dp_tdma_adjust_and_ips` (written,
  unexecuted).
- BT coexistence, pass 3 step 1: owner wiring (not admitted).
  `rtl8723be/coex.rs::Owner` is `rtlpriv->btcoexist` for this chip:
  `BtCoexist`, the `Rtl8723b` dispatch, the chip's single H2C `Mailbox`
  and the `ps.c` `LpsGate` (`fwctrl_lps = true`). Each Linux `rtl_btc_ops`
  call site is one method: `bind` (`pci.c::rtl_pci_start` →
  `btc_init_variables`, via `Prepared::bind_rtl8723be_coex` in
  `Allocated`; `prepare` refuses an unbound 8723BE and
  `configure_rtl8723be` refuses a live adapter re-read whose board info
  differs), `power_on_setting` (`hw.c:827`, inside `prepare` after the
  enable flow and before `REG_MULTI_FUNC_CTRL |= BIT(3)`),
  `init_hw_config` (`hw.c:1409/2708` `rtl8723be_bt_hw_init`, inside
  `init::configure` after the station address and before the `ERFON`
  block), `ips` (`ps.c:239/284`), `lps_leave` / `lps_enter`
  (`rtl_lps_set_psmode`, `ps.c:368/375`: `_rtl8723be_fwlps_{leave,enter}`
  with `h2c::BtLps` taken from `btc_is_bt_ctrl_lps` / `is_bt_lps_on` /
  `get_lps_val` / `get_rpwm_val`, `btc_record_pwr_mode` of the body sent,
  and `btc_lps_notify` after the leave / before the enter), `scan`
  (`core.c:1425/1478`), `media_status` (`core.c:1181`), `connect`,
  `special_packet` + `eapol` (`base.c:1455` / `base.c:1539` `in_4way`),
  `watchdog` (`base.c:2205`: `btc_periodical` at most once per 2 s, then
  the 30 s `in_4way` timeout), `c2h` (`rtl_c2h_content_parsing`,
  `base.c:2313` BT info → `btc_btinfo_notify`, `base.c:2319` BT MP →
  `btc_btmpinfo_notify`; TX reports returned to the caller) and `halt`
  (`pci.c:1774`, `Prepared::halt_rtl8723be_coex`, unbinds). The real
  `BtMpSource` is `btc::RxBtMp` over the owner's `C2hSource` (the RX
  C2H stream): `bt_mp_comp` polls every millisecond up to the wait and
  returns the first `BT_MP` body; other C2H packets go back through
  `defer_c2h` (Linux's C2H work item runs after `rtl_c2h_fast_cmd`).
  Before packet start (power-on, `bt_hw_init`) `NoBtMp` / `NoC2h` stand
  in: no RX ring runs, so no MP body can arrive. Differences: the
  re-entrant `btc_lps_notify` that an algorithm-requested LPS change
  makes in Linux is recorded by `BtcHal` (`LpsNotified`) and replayed
  after the outer notify (both 8723B handlers only set
  `coex_sta->under_lps`, read only by debugfs); the watchdog cadence is
  enforced from the caller's clock. The station / packet owner that
  calls those methods now exists (`packet::Owner`, #1461): it implements
  `C2hSource` over its RX ring (`C2hQueue`), dispatches RX C2H into the
  coexistence owner, and calls `ips` / `lps_*` / `scan` / `connect` /
  `media_status` / `special_packet` / `eapol` / `watchdog` / `c2h`.
  The retained station owner reaches it through `Prepared` (see "Station
  composition and probe admission" below). Tests
  `smoke_rtl8723be_coex_owner_lps_c2h_watchdog_halt`, the coexistence
  order checks added to `smoke_rtl8723be_erfon_block_and_channel_grant`
  and `smoke_rtl8723be_retained_rings_init_mac_prefix_and_llt` (written,
  unexecuted).

- Station composition and probe admission (implemented, pending
  validation). Template: the RTL8192CE admission; ring geometry and host
  receipt are the RTL8821AE ones (`trx.h` identical).
  - Power base: `station_power::{Base,Grant}::Rtl8723be` over the `NAPC`
    envelope (`Calibration::with_current`, `regrant` at the same operating
    point, `wait_rtl8723be`); `station_grant` is the programmed
    `rtl8723be_power`; `stage_rtl8723be_calibration`.
  - Radio: `configure_rtl8723be_channel(calibration, domain, op)` programs
    the `channel::Grant` `Calibration::grant_for` mints (measured index
    capped at the Linux `rtl8723be_phy_set_txpower_level` index for the
    configured EFUSE power / PHY_REG_PG store / regulatory option) and
    records the permission; `configure_rtl8723be_mac` sets the station
    address phase. `bind_rtl8723be_coex_measured` binds the coexistence
    owner from the live `rtl8723be_read_bt_coexist_info_from_hwpg` facts.
  - Packet branch `rtl8723be/packet_owner.rs` (`prepare::packet::be8723`):
    start (`REG_CR` word `0x2ff`, `REG_PCIE_CTRL_REG + 1 = 0`,
    `set_network_type(STATION)` unlinked); `rtl8723be_tx_fill_desc` TX
    (forced rate + DISFB, or firmware RA at `_rtl_get_highest_n_rate` for
    ordinary unicast DATA under the installed mask; RATE_ID NGB 0 / GB 4 /
    B 6 / MC 7; `rtl_set_tx_report` for EAPOL / Null; RTS/CTS and
    CTS-to-self at `DESC_RATE24M`; every on-air rate admitted by the
    permission); RX with `rtl8723be_rx_query_desc` and `rpt_sel` C2H queued
    for `be8723_service_c2h` (`rtl_c2h_content_parsing` through
    `coex::Owner::c2h`, TX reports recorded); IRQ enable / recognition;
    `rtl8723be/station.rs` (`_rtl8723be_set_media_status`,
    `set_check_bssid`, `set_network_type`, `HW_VAR_{BSSID,BASIC_RATE,
    SLOT_TIME,SIFS,ACK_PREAMBLE,AID}`, `update_channel_access_setting`,
    `set_qos`); association (`rtl_cam_reset_all_entry`, `KEEP_ALIVE`,
    linked network type, `HW_VAR_AID`, `_rtl8723be_download_rsvd_page`
    over `rtl8723be/rsvd_page.rs` — the verbatim `fw.c`
    `reserved_page_packet`, BCN_VALID polled, up to five uploads — and
    the `H2C_8723B_RSVDPAGE` location, MSRRPT connect, then
    `btc_mediastatus_notify`); `rtl8723be_update_hal_rate_mask` bounded by
    the admitted rates; the watchdog (queued C2H, `rtl8723be_dm_refresh_
    rate_adaptive_mask`, `btc_periodical`); LPS through
    `coex::Owner::lps_{enter,leave}`; disassociation (MSRRPT disconnect,
    `btc_mediastatus_notify(0)`, zero BSSID); stop (`btc_halt_notify`, then
    the `RTL8723_NIC_LPS_ENTER_FLOW` TX-buffer-empty / RXDMA-idle proof).
    Every H2C goes through the coexistence owner's mailbox (the chip's
    single `last_hmeboxnum`). ERP preamble/slot tracking, fixed EDCA rows
    and per-frame `DESC_RATE24M` protection are composed in the shared
    station.
  - Admission: `prepare_native::prepare_rtl8723be` (physical EFUSE `0x1fb`
    package byte before the firmware run, registry firmware, packet claim,
    measured coexistence bind, `prepare`, `configure_rtl8723be`, then
    `admit_rtl8723be`: the `NAPC` 20 MHz grant on channels 1-11, MAC,
    staged envelope); `interface.rs` readiness admits through
    `admit_rtl8723be`; `allow_channel` re-derives the `NAPC` permission;
    retune/removal rebuild through `power_runtime::disable_rtl8723be` +
    `enable_rtl8723be` (`_rtl8723be_init_mac` prefix + enable flow); ASPM
    stays off. `pci.rs::bring_up` retains `0xb723` when the BAR covers the
    8723BE MMIO, `_rtl8723be_read_chip_version` qualifies, the map is
    provisioned with the factory MAC and the path-A TX power decodes.
  - Not composed (follow-ups): HT/40 MHz on this profile (the station
    stays legacy 20 MHz; `rtl8723be_update_hal_rate_mask` N rows are never
    installed), the `btc_scan_notify` / `connect` / `special_packet` / IPS
    call sites from the shared station, `rtl8723be_dm_watchdog` steps other
    than the RA refresh, short-preamble TX (as the other native profiles),
    TX-report matching for the station, ASPM. Tests
    `smoke_rtl8723be_station_registers_and_rsvd_page`,
    `smoke_rtl8723be_native_owner_start_descriptors_receipt_and_rx`,
    `smoke_rtl8723be_native_join_rsvd_page_ra_mask_and_leave` (written,
    unexecuted).

### RTL8723AE retained runtime (in progress, not admitted)

`rtl8723ae/` + `rtl8723ae.rs` port Linux `rtl8723ae` and the `rtl8723com`
pieces it uses (PCI `0x8723`, 1T1R 2.4 GHz HT with Bluetooth; the
RTL8192C generation: 92CE-style descriptors, its own `pwrseq` flows and
its own coexistence in `hal_btc.c` / `hal_bt_coexist.c`). Probe keeps the
chip diagnostic (the firmware owner is built — `firmware_transport::Owner`
admits `0x8723` via `run_8723ae` — but probe does not run it yet).

- `version` — `_rtl8723e_read_chip_version`: `NORMAL_CHIP | CHIP_8723`,
  `CHIP_VENDOR_UMC` from `REG_SYS_CFG[19]` with the `CHIP_VER_RTL_MASK` cut
  (UMC only), ROM version `REG_GPIO_OUTSTS[31:28] >> 20` and
  `polarity_ctl` from `REG_MULTI_FUNC_CTRL[1]`. `TRP_VAUX_EN` test chips and
  parts without `BT_FUNC` (no Linux RF type) are refused. Firmware per
  `rtl8723e_init_sw_vars`: `rtl8723fw.bin`, or `rtl8723fw_B.bin` for
  `IS_81XXC_VENDOR_UMC_B_CUT`; no `alt_fw_name`. `fw::FW_8723AE` (the
  diagnostic resolver) now names Linux's default `rtl8723fw.bin`.
- `adapter` — `rtl8723e_read_eeprom_info` / `_rtl8723e_read_adapter_info`
  over the 256-byte map with the 8723AE `params[]` (`0x8129`, VID `0x49`,
  DID `0x4b`, SVID `0x4d`, SMID `0x4f`, MAC `0x67`, plan `0x28`, version
  `0x30`, customer `0x31`); an EEPROM boot, autoload failure or bad ID is
  unprovisioned (Linux's `rtl_get_hwinfo` return skips TX power and BT).
  `rtl8723e_read_bt_coexist_info_from_hwpg` + `rtl8723e_bt_var_init`:
  `bt_coexistence = REG_MULTI_FUNC_CTRL[18]`, type `BT_RTL8723A`, ant num /
  isolation / radio-shared from `RF_OPTION4` (`0x2e`) bits 0/4/5; the
  8723AE OEM switch (its Lenovo/Toshiba/ASUS lists differ from 8723BE).
  Probe now issues the `REG_EFUSE_TEST[9:8] = EFUSE_WIFI_SEL_0` selection
  `rtl8723e_read_eeprom_info` makes before the map read. Divergence kept:
  the 8723AE `rtl_hal_cfg` has no `maps[EFUSE_ACCESS]`, so Linux's
  `efuse_power_switch` writes `0x69`/`0` to offset 0 (`REG_SYS_ISO_CTRL`);
  the shared reader keeps using `REG_EFUSE_ACCESS` (`0xcf`) instead.
- `pwrseq` — PCI rows of every `rtl8723A_*_flow`, generated from
  `pwrseq.h` (sha256 in the file header). Probe's power table for `0x8723`
  is now the exact `rtl8723A_card_enable_flow` after `REG_RSV_CTRL = 0`
  (replacing the former diagnostic rows), parsed with `PWR_CUT_ALL_MSK`.
- `power` — the rest of `_rtl8712e_init_mac`'s power segment, run by the
  firmware owner before the download as in Linux: `REG_PCIE_CTRL_REG+2[4]`,
  `0x369[7]` and the ePHY `0x1e[4]` MDIO loop (`0x358`/`0x356`/`0x354`
  word writes, 100 us settles, readback `0xc290`, failure after 100
  rounds exactly as Linux).
- `fw` — `is_fw_header` (`signature & 0xfff0 == 0x2300`), exact RAM-code
  length (linux-firmware `0x2d6e` / `0x59b4`), whole file at most
  `max_fw_size = 0x6000`. `rtl8723_download_fw(hw, false, 1000)`: a
  running image is stopped by `rtl8723ae_firmware_selfreset`
  (`REG_HMETFR+3 = 0x20`, `SYS_FUNC_EN+1[2]` wait of 99 x 50 us, forced
  clear) then `MCUFWDL = 0`; enable, pages with `rtl_fill_dummy`, close;
  `FWDL_CHKSUM_RPT` within 999 undelayed reads, `MCUFWDL_RDY` /
  `~WINTINI_RDY` with no 8051 reset, `WINTINI_RDY` over 1001 reads x 5 ms.
  A failed `rtl8723_fw_free_to_go` is an error here (Linux returns 0).
  `firmware_transport::Owner` admits `0x8723` (`run_8723ae`, 6 s bound):
  identify before any write, `power::post_flow`, clear the CR DMA/MAC gates
  (ring owner), download; only the image the measured version selects is
  accepted. Tests `smoke_rtl8723ae_chip_version_and_firmware_names`,
  `smoke_rtl8723ae_adapter_facts_bt_and_oem`,
  `smoke_rtl8723ae_firmware_header_geometry`,
  `smoke_rtl8723ae_firmware_paged_download`,
  `smoke_rtl8723ae_init_mac_post_flow_ephy`,
  `smoke_rtlwifi_8723ae_enable_prefix_and_card_enable_flow` (written,
  unexecuted).
- `c2h` — the firmware-event mailbox (`rtl_8723e_c2h_command_handle`,
  `hal_btc.c:1690`): header byte at `REG_C2HEVT_MSG_NORMAL` (`0x01A0`,
  id low nibble / len high nibble, sequence at `0x01A1`, body from
  `0x01A2`) with the `0x01AF` close-byte protocol (already
  `C2H_EVT_HOST_CLOSE` `0x00` → nothing read or written; anything other
  than `C2H_EVT_FW_CLOSE` `0xFF` → `0x00` written, body unread;
  firmware-closed → body read, dispatched, closed with `0x00`).
  `C2H_V0_BT_RSSI` (4) / `C2H_V0_BT_OP_MODE` (5) / unknown ids are
  consumed without effect; `C2H_V0_BT_INFO` (12) parses via
  `rtl8723e_dm_bt_parse_bt_info` (original byte 0, retry byte 1 when the
  body is at least 2 bytes, inquiry page bit 2, connection bit 0) and
  returns the four fields as `BtInfo` for the coexistence owner
  (`coex::Owner::ingest` + `periodical`, fed by the packet owner's
  `service_c2h`). `packet::Owner::service_c2h` schedules `c2h::drain`
  when `irq::IsrStatus::c2h_pending` is set, mirroring the `pci.c`
  fwevt gate, which is 8723AE-only (fixture-tested; no live IRQ caller
  yet — probe keeps the chip diagnostic). Tests
  `smoke_rtl8723ae_c2h_mailbox_close_protocol`,
  `smoke_rtl8723ae_c2h_mailbox_bt_info` (written, unexecuted).
- `coex` — the 8723AE Bluetooth-coexistence owner, pass 1 (#1458): board
  binding, `BtInfo` ingestion per `rtl8723e_dm_bt_parse_bt_info`, the
  periodical decision (shared `btcoex` matrix) and the DM primitives
  (`hal_bt_coexist.c`); the 1-ant / 2-ant mechanism trees live in `dm.rs`
  (#1470: `run_mechanism`, 2-ant dispatch, `set_bt_dm`, `_8723a` all-off).
  The RF halves are programmed through the shared `rtl8723com` LSSI
  writer (`rtl8723be::phy::rf_serial_write` = `rtl8723_phy_rf_serial_write`;
  every coex RF write is full-mask, so `rtl8723e_phy_set_rf_reg` reduces
  to it): `agc_table` writes its five dwords through the single `0xc78`
  port (as Linux; an earlier port wrote `0xc78..0xc88`) and then
  `RF_RX_AGC_HP` x4 / `RF_RX_G1` on `RF90_PATH_A`; `mech_init` (now
  async) reads the `RF_RCK1` / `RF_RCK2[7:4]` origins with
  `rtl8723be::phy::get_rf` (`rtl8723e_dm_init_bt_coexist`); the LPF
  corner (`rtl8723e_dm_bt_set_sw_rf_rx_lpf_corner`) writes RF `0x1e =
  0xf0ff7` on shrink and restores the captured origin on resume.
  Deliberate deviation: resume before the first init (Linux would write
  the zero-initialised origin) is skipped. Tests
  `smoke_rtl8723ae_coex_dm_registers`, `smoke_rtl8723ae_dm_mech_init_and_query`,
  `smoke_rtl8723ae_dm_all_off_sequences` (written, unexecuted). The
  1-ant path is a Linux stub, ported as a no-op. The coex owner is still
  unreachable from probe (chip not admitted).
- `envelope` — signed per-board NAPC power envelopes, 2.4 GHz only
  (#1458): `Calibration::permission_for` mints the `Permission` the
  packet owner transmits under (v1/v2 rows, CCK/OFDM/HT 1SS curves,
  no BB swing, no factory per-rate TXAGC cap).
- `packet` — the AE packet owner (#1458): 92CE-style TX descriptor
  fill, RX descriptor query, firmware + envelope admission gates
  (`Owner::admit`, `admit_tx`) and the mailbox service entry
  (`service_c2h`). The chip is still not admitted (probe diagnostic).

### RTL8192DE retained runtime (in progress, not admitted)

- `rtl8192de` — dual-MAC per-function ownership model (step 1; not
  admitted): `mode_from_prom` (PCI `EEPROM_MAC_FUNCTION` `0x08` bit 3,
  USB `EEPROM_ENDPOINT_SETTING` `0x10` bit 0 inverted),
  `phy_ctrl_word` (`REG_MAC_PHY_CTRL_NORMAL` `0x00f8`; PCI base `0xf0`,
  USB read-modify clearing bits 0–2; dual-dual `0x03`, single `0x04`,
  dual-single `0x01`), `mode_info` (single/dual-single 2T2R on both
  bands from 2.4 GHz; dual-dual 1T1R with MAC0 on 5 GHz, MAC1 on
  2.4 GHz), `ampdu_factor_base` (`0xb9726641` / `0x66626641` /
  `0xb972a841`), sw consequences (non-single disables 8K A-MSDU and
  caps RX at 4096; default channel 36 on 5 GHz, 1 otherwise),
  `max_aggr_num` (`0x0B` single, `0x07` dual), and table selection
  (MAC0 always the combined AGC table; MAC1 the 2G table on 2.4 GHz,
  the 5G table on 5 GHz; per-path internal-PA radio tables; the DMDP
  radio-B-on-path-A swap). The 10 `table.c` arrays (3462 words) are
  transcribed verbatim via generator + independent checker. Firmware
  image name `rtlwifi/rtl8192defw.bin`. Per-function EFUSE identity
  (function 0 / 1 → MAC offsets `0x55` / `0x5b`) already lives in
  `efuse.rs`. Steps 2–4 delivered the firmware header parse + paged
  download + transport admission (`run_8192de`), the signed NAPC
  envelope (2.4 GHz, v1/v2), the packet owner and descriptors, the
  power-on sequence + MAC init, the station chains, bands/HT/QoS/
  lifecycle, the TX-power levels and the DE factory table
  (`txpower::linux_indices`, `phy::PgStore`). Step 5 completes the
  envelope: NAPC v3 rows carry four curves (CCK, OFDM, HT MCS0-7,
  HT MCS8-15) on both bands (`rtl8192de-cal-v3-<mac>.bin`, loaded
  before v2/v1; v1/v2 parsing unchanged), with the 5 GHz row plan
  taken from `channel::CHANNEL_ALL[59]` — 45 × 20 MHz primaries plus
  the +/-2 pairing at 40 MHz (42 above, 42 below; 154 v3 rows total
  with the 2.4 GHz plan) — strictly ordered by (band, bandwidth,
  offset, channel), and 5 GHz rows leaving the CCK curve unmeasured
  (mirroring rtl8821ae). `permission_for` requires every legacy rate
  of the band (CCK + OFDM + MCS0-7 on 2.4 GHz, OFDM + MCS0-7 on
  5 GHz); MCS8-15 are admitted when measured, never required, and
  `ht::two_stream` admits local two-stream TX only on `RF_2T2R`
  (dual-dual 1T1R functions never transmit two streams). The 5 GHz
  ceiling is the spanning-rule ceiling capped by the `regd.c`
  5140-5360 / 5460-5860 MHz 30 dBm blocks (DFS/NO_IR/indoor rules
  refuse); `domain_ceiling` stays 2.4 GHz-only. The remainder
  (issue #1865) is delivered: `Prepared::Chip::Rtl8192de`
  (`from_device(0x8193)`, next-desc byte 40, mode-dependent LLT,
  IMR `0x120`/`0x128`, the `0x301` DMA stop), the radio owner
  (`bind_rtl8192de_mode` before `prepare`, `configure_rtl8192de`
  re-qualifying mode / test chip / autoload / cut from live registers
  and EFUSE, `configure_rtl8192de_channel` over the `N92D` permission,
  `configure_rtl8192de_mac`), the station-power `Base`/`Grant` and
  `stage_rtl8192de_calibration`, native `prepare_rtl8192de` /
  `admit_rtl8192de` (2.4 GHz channels 1-11; the PCI function index
  comes from the retained `PciIo`), the `rtl92de_hw_init`
  orchestrator (`init::configure`: power-on, MAC, BB/RF tail, TX-power
  level, dual-MAC RF-ready poll), AMPDU density / RDG / HTC-LPS hwseq
  / sectype / TX-report (`SPE_RPT` + `SW_DEFINE` sequence) /
  rate-id / MAC-id in the packet owner and descriptors, the H2C
  rate-mask send (`update_hal_rate_mask`, admitted-gated) and the
  RPWM LPS enter/leave (`0x02` / `0x0c`), and card disable /
  power-off (`check_poweroff`, `poweroff_adapter`, `card_disable`).
  NARF order is download → prepare (LLT + rings) → configure
  (power-on + MAC + PHY tail); BME stays off throughout, so the
  deferred power-on is safe. RDG is dead in upstream Linux v6.1
  (`mac->rdg_en` is never assigned), so the RDG descriptor bit is
  carried but never set by the link. Step 6 (follow-up to #1865,
  #1888) adds the DM state (`rtl92d_dm_init`), the `rtl92de_hw_init`
  early-mode / ASPM back-door / hardware-security helpers, LC
  calibration (`lck.rs`), the IQK reload wired into the channel switch
  (`calib::reload_iqk_setting` from `channel::switch_channel`), the
  reserved-page packet (`rsvd_page.rs`) and the 5 GHz native gate
  (`native_channel`: a dual-dual MAC0 function admits the 5 GHz plan,
  MAC1 admits 2.4 GHz 1–11). The orchestrator `init::configure` runs
  them in `hw.c` order: `mac::early_mode` (`earlymode_enable` false, as
  `rtl92de_init_sw_vars`), `cam_reset` then `enable_hw_security_config`
  (the NARF station encrypts in software, the `swenc=1` equivalent, so
  nothing is written), original values + TX-power level, the station
  address, `enable_aspm_back_door` (ASPM stays off on the probed link:
  the `const_support_pciaspm` 0 back-door byte `0x03`), `Dm::new` (kept
  in `Radio::dm`), `lck::lc_calibrate` (`init_ready` false, no scan;
  a poll timeout proceeds as in Linux), then the dual-dual RF-ready
  poll. `prepare_native::prepare_rtl8192de` gates the channel with
  `native_channel` over the PROM mode and PCI function, and
  `initialize_registered_on_channel` dispatches 92DE before the 2.4 GHz
  1–11 gate. Test `smoke_rtl8192de_hw_init` (extended; written,
  unexecuted). TX-report arrival matching is inapplicable on 92D, not
  open: Linux gives 92D no C2H arrival route (`rtl92de_rx_query_desc`
  never sets `packet_report_type`; the `IMR_C2HCMD` dispatch in
  `pci.c` is gated to RTL8723AE), so a requested report only resolves
  through the 3 s timeout, as here.
  Still open: probe admission (`pci.rs` retained set, the
  `interface.rs` readiness dispatch). The shared station composition
  has no 92DE packet branch yet: the station power `wait` dispatch
  (`station.rs::power_wait`) now routes `Base::Rtl8192de` to
  `wait_rtl8192de`, but `packet.rs` has no 92DE arm (start, descriptor
  fill, RX, the 0x120/0x128 IMRs, LPS, join), and the 92DE join path
  (`rtl8192de::station` BSSID/media-status helpers,
  `station::join_bss_report`, whose `rsvd_page::Upload` writes a
  CPU-side descriptor and rings the doorbell itself, so it needs a
  DMA-ring form first) is not composed into the shared station.
  Admitting the chip now would publish a station that cannot transmit.

## 4. Invariants

Read requests never set the programming trigger. Preserve unrelated EFUSE
address/control and SYS-clock bits. Exclude protected physical tails, reject
truncated/outside records, and never register an invalid factory identity.

## 5. Architecture notes

BAR mapping and byte-order conversion are architecture independent. Shared
register-model smokes cover every matched geometry and both dual-MAC functions.

## 6. Dependencies

Bus/PCI ownership, MMIO and firmware registry follow their subsystem contracts.
The scheduler's responsive wait supplies bounded EFUSE completion/settling.

## 7. Stage assignment

Factory identity, RTL8188EE CPU firmware, inactive LLT/linked-ring preparation
and retained factory-qualified table/IQK/LCK continuation are software covered.
Native legacy station/Device and composed DHCP/IP/lifecycle regressions are
implemented and software-validated. Physical board qualification remains.

## 8. Open questions / remaining software

| Prerequisite | State |
|---|---|
| Correct BAR2/read-only EFUSE lifecycle and per-chip identity | Implemented; shared-path regressions |
| Complete source-matched per-chip power/reset qualification | RTL8188EE PCI enable prefix/flow implemented; other families remain incomplete |
| Authenticated image/header selection and runtime firmware loading | RTL8188EE retained probe owner implemented; other profiles missing |
| DMA allocation/publication/quiesce, IRQ ownership, H2C/C2H | RTL8188EE retained DMA32 rings/LLT, one-shot polled service, terminal host delivery, demonstrated awake/keepalive/reserved-page/JOIN mailbox and terminal close/retention implemented. MSI interrupt delivery with W1C recognition (polling fallback), card-disable DMA quiescence and fresh-generation reset/recovery are implemented and software-validated |
| RF/BB tables, calibration, channel/power and rate control | RTL8188EE tables/retained1T IQK/LCK, static factory antenna, signed board/factory/regulatory legacy20 power, operational MAC and negotiated legacy peer/rate/filter integration implemented. Measured board envelope and silicon qualification remain; optional NETH thermal tracking is implemented pending native acceptance; the original NEPC profile still excludes tracking |
| Scan, management RX/TX, authentication/association and WPA2 | Retained EE channel1 passive scan, Open MLME, shared WPA2/CCMP and exact M4 receipt implemented; Device/composition regressions pass native suites. Other matched chips remain missing |
| Ethernet packet path and terminal TX completion ownership | EE same-owner native Device/Narf-Ring/stack and Open/WPA2 real-kernel DHCP/exact bidirectional IP fixtures pass software gates; actual board testing remains |
| Multi-radio, removal, suspend/reset/recovery | RTL8188EE PCI removal (quiescence-gated DMA release), retained reset, system suspend and IPS implemented and software-validated; independent retained radios implemented and software-validated |

Per-chip remaining inventory uses Linux per-chip `sw.c` and radio/PCI ops:

| Chip | Source hardware scope | Remaining native software |
|---|---|---|
| RTL8188EE |2.4GHz1T1R HT, source `bandset=BAND_ON_2_4G` |Software-validated: separately signed HT20/LGI MCS0–7, standalone3839 A-MSDU, recipient BA/RX reorder, originator BA/TX A-MPDU and capture/publication epochs above. NEHT v2 additionally implements SGI20 and7935-byte reception; four native composed regressions pass on both architectures. Reset/recovery, system suspend and IPS are software-validated. HT20/40 NEHT v4 is implemented pending native acceptance above. RTS/CTS NERT continuation is implemented pending native acceptance above. Thermal TXAGC NETH continuation is implemented pending native acceptance above. Automatic antenna NEAN continuation is implemented pending native acceptance above. The retained EE source feature rows are implemented; other chip runtimes remain separate (PCIe ASPM, MSI delivery, fwlps leisure power save and DMA quiescence are implemented). Exact NEPC/NEHT board measurements and physical acceptance remain external gates. |
| RTL8192CE family aliases / RTL8192EE |2.4GHz HT; CE aliases need exact RF-type qualification, including the8176/8188CE variant; EE is2T2R |Retained chip firmware/MAC/PHY/RF/calibration/power/packet/station chain, then full HT/QoS/lifecycle. The8179/8188EE HT path does not admit these IDs. |
| RTL8192DE |Dual-band dual-MAC HT |Exact per-function reset/power/firmware/DMA/radio ownership and station chains, then bands/HT/QoS/lifecycle |
| RTL8723AE/BE |2.4GHz1T1R HT with BT |Chip-specific retained chain, antenna/BT coexistence and HT/QoS/lifecycle |
| RTL8821AE |Dual-band VHT, source `RTL_SPEC_SUPPORT_VHT` |Exact retained firmware/MAC/PHY/RF/power/station chain, VHT/QoS and lifecycle |

The source2.4GHz bandset rules out5GHz work on EE/CE/8192EE/8723;
initial-profile restrictions do not rule out their HT/QoS hardware features.

C2H event inventory (resolves the former `additional_c2h_events` unknown;
Linux v6.12 `rtlwifi/wifi.h` `rtl_c2h_evt_v1/v2`, `base.c`
`rtl_c2h_content_parsing`, `pci.c` RX/IRQ dispatch and per-chip `trx.c`/`sw.c`):

| Route | Events/consumer | Chips |
|---|---|---|
| RX-ring `C2H_PACKET` (`get_rx_status_desc_rpt_sel` DW BIT(28)) -> `rtl_c2hcmd_enqueue` | C2H_DBG/C2H_TXBF (log only), C2H_TX_REPORT (`rtl_tx_report_handler`, solicited by `rtl_set_tx_report` SPE_RPT), C2H_RA_RPT (`c2h_ra_report_handler`), C2H_BT_INFO/C2H_BT_MP (`btc_ops`) | 8192EE (RA_RPT), 8723BE (TX_REPORT, BT), 8821AE (TX_REPORT, RA_RPT, BT) |
| `IMR_C2HCMD` -> `fwevt_wq` -> `c2h_command_handle` (`REG_C2HEVT_MSG_NORMAL`) | firmware event mailbox | 8723AE only (`pci.c` gates on `HARDWARE_TYPE_RTL8723AE`) |
| RTL8188EE | none: its RPT_SEL is the 2-bit DW3[15:14] field (`rtl8188ee/trx.h`), which cannot encode `C2H_PACKET`=4; its IMR_C2HCMD is never dispatched; TX_REPORT2 `macid_valid_entry` is written but never consumed anywhere in rtlwifi | retained EE profile |

The retained EE packet core consumes non-NORMAL report descriptors without
admission, which is the complete upstream EE behaviour. The other routes are
part of the per-chip retained runtimes (`rtl8192ee`, `rtl8723ae`,
`rtl8723be`, `rtl8821ae`), adaptive rate rows and `bt_coexistence`.

Per-chip HT/QoS variant inventory (resolves the former
`other_chip_phy_variants` unknown; `base.c::_rtl_init_hw_ht_capab`): every
rtlwifi chip advertises the same HT set - SUP_WIDTH_20_40, SGI_20, SGI_40,
DSSSCCK40, MAX_AMSDU (7935 bytes), A-MPDU factor 64K and density 16 (8us) -
and only `get_rf_type` varies the RX MCS mask (1T1R: MCS0-7; 1T2R/2T2R:
MCS0-15, part of the RTL8192CE/8192DE/8192EE chip rows). SGI40 and
DSSS/CCK-in-40 belong to `ht40`; aggregation and BA to the named BA rows.
`MAX_AMSDU` is cleared only for RTL8192DE dual-MAC (`disable_amsdu_8k`,
4096-byte RX buffers); every other chip uses `pci.c` `rxbuffersize = 9100`
and advertises7935-byte A-MSDU reception. The retained EE profile now follows
that geometry with9100-byte RX slots, including on initial legacy setup, and
only the separately signed NEHT v2 enables HT MAX_AMSDU. Its recipe binds
the entire RX geometry, atomic body validation and preceding radio/firmware
identity; a v1 record cannot authorize the enlarged receive promise. Public
PHY capabilities and the actual association request use the same bit11.
Open reception uses the negotiated local limit; CCMP reception passes that
limit into shared `receive_amsdu_with`, preserving full-body validation before
PN commit. The AP's receive capacity remains a separate directional fact.
Native descriptor length, PHY prefix/shift, FCS and buffer extents bound the
original frame before copying or parsing. Smokes
`smoke_rtl8188ee_rx7935_native_prefix_fcs_and_whole_security` and
`smoke_rtl8188ee_rx7935_oversize_bad_suffix_and_revoked_source` cover exact7935,
7936 rejection, Open/WPA2, malformed suffix atomicity, replay, retained DMA
and queued RX after qualification revocation. Both native regressions pass
on x86_64 and aarch64.
References: upstream [pci.c](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/realtek/rtlwifi/pci.c)
and [base.c](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/realtek/rtlwifi/base.c).
QoS/EDCA
programming is per-chip `set_hw_reg(HW_VAR_AC_PARAM)` with the shared
`rtl_get_hal_edca_param`, carried by each chip row.

Source-proven inapplicability (rows removed from the remaining inventory):

- **Checksum, TSO and VLAN offload.** `rtlwifi/base.c::_rtl_init_mac80211`
  never assigns `hw->netdev_features` and the file has no `NETIF_F_*`,
  `ip_summed`, checksum, TSO or VLAN reference; the per-chip `trx.c` TX/RX
  descriptor fill/query paths (checked: `rtl8821ae`, `rtl8192ee`) carry no
  checksum, LSO or VLAN-tag field. No rtlwifi chip offers these offloads, so
  the Narf-Ring refusal of offload requests is the complete behaviour.
- **LDPC.** `_rtl_init_hw_ht_capab` sets only SUP_WIDTH_20_40, SGI_40,
  SGI_20, DSSSCCK40 and MAX_AMSDU (never `IEEE80211_HT_CAP_LDPC_CODING`), and
  `_rtl_init_hw_vht_capab` for RTL8821AE/8812AE never sets
  `IEEE80211_VHT_CAP_RXLDPC`. LDPC is inapplicable to every rtlwifi chip.
- **HT STBC.** No HT STBC bit is advertised for any chip, so STBC is
  inapplicable to the EE slice and all HT-only chips. STBC exists only in the
  RTL8821AE VHT capability (`IEEE80211_VHT_CAP_TXSTBC | RXSTBC_1`) and is part
  of the remaining `vht` work.

- **Randomized scan MAC addresses.** `nl80211.c::nl80211_check_scan_flags`
  rejects `NL80211_SCAN_FLAG_RANDOM_ADDR` with `-EOPNOTSUPP` unless the wiphy
  sets `NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR`; mac80211 core never sets it
  (`main.c` adds only LOW_PRIORITY/AP scan and RANDOM_SN for software scan) and
  rtlwifi never does, so a random-address scan cannot be requested upstream.
- **TSPEC admission.** `nl80211.c` exposes `NL80211_CMD_ADD_TX_TS` (and
  `nl80211_add_tx_ts` returns `-EOPNOTSUPP` otherwise) only when the driver sets
  `NL80211_FEATURE_SUPPORTS_WMM_ADMISSION`; mac80211 `ieee80211_add_tx_ts`
  never originates ADDTS itself. rtlwifi (`base.c::_rtl_init_mac80211`, `core.c`) never sets that wiphy feature, so no TSPEC
  can be admitted; the implemented ACM downgrade (`ieee80211_downgrade_queue`)
  is the complete upstream behaviour for ACM ACs.
- **U-APSD.** mac80211 `mlme.c::ieee80211_mgd_assoc` sets
  `assoc_data->uapsd` only when the vif has `IEEE80211_VIF_SUPPORTS_UAPSD`,
  otherwise the WMM Information element carries QoS Info 0 and U-APSD is never
  enabled. rtlwifi never sets that flag (`core.c::rtl_op_add_interface` sets only `IEEE80211_VIF_BEACON_FILTER`), so U-APSD is inapplicable; the
  driver-owned Information IE requesting no U-APSD is the complete behaviour.

Power management beyond named suspend, enumerated from per-chip `sw.c`
module parameters (`rtl88ee_mod_params`, `rtl8821ae_mod_params`) and
`base.c` hw flags: inactive power save (`inactiveps = true` on both),
leisure power save (`fwctrl_lps`/`swctrl_lps`: off by default on 88EE,
firmware LPS `reg_fwctrl_lps = 2` MAX mode on by default on 8821AE, enabling
`SUPPORTS_PS`/`SUPPORTS_DYNAMIC_PS`), PCIe ASPM (`aspm_support = 1`,
`const_pci_aspm = 3`) and WoWLAN on RTL8821AE/8812AE (`wo_wlan_mode =
WAKE_ON_MAGIC_PACKET | WAKE_ON_PATTERN_MATCH` with
`rtlwifi/rtl8821aefw_wowlan.bin`). RTL8188EE has no WoWLAN. Each is now a
named feature; IPS and PCIe ASPM are implemented and software-validated
above. Other chip-specific power paths retain their remaining rows.

References: Linux `rtlwifi/efuse.c`, per-chip `sw.c`/`reg.h`,
`rtl8192d/hw_common.c` dual-MAC selection, and per-chip firmware/HW code.

### Current remaining feature blockers (2026-10-30)

These named rows retain the source/profile limits described above. Chip-specific
runtimes remain separate from the retained RTL8188EE owner.

| Row | Concrete blocker |
|---|---|
| `bt_coexistence` | Bluetooth coexistence on RTL8723AE/BE: the per-chip coexistence owners are delivered (8723AE pass-1 owner + 1-/2-ant mechanism trees, #1458/#1470; 8723BE owner with 1-/2-antenna dispatch and every `rtl_btc_ops` call site, #1351); blocked on probe admission for both chips (diagnostic-only) and the 8723AE coex RF halves (pending an `rf.rs` RF-write API) |
| `dynamic_antenna_selection` | Native factory type1/2 hardware diversity and SMART type4, actual PHY mux/descriptor/training/restore and separate signed NEAN per-selector/thermal full-program qualification are implemented above, pending release compilation/native acceptance. Original static records remain unchanged; board measurements and physical mapping/RF acceptance remain external |
| `five_ghz_operation` | 5GHz band operation on RTL8192DE/RTL8821AE; blocked on the rtl8192de/rtl8821ae chip runtimes (RTL8188EE is 2.4GHz-only) |
| `ht40` | Source-correct native HT20/40/secondary selection and signed NEHT v4 full-program qualification are implemented above, pending coordinated native acceptance. Existing NEHT v2/v3 remain20MHz. Measured per-device board data and physical acceptance remain external |
| `rf_gain_tracking` | Native thermal TXAGC, actual IQK/LCK/restore and separate signed NETH full-dimensional qualification are implemented above, pending coordinated release compilation/native acceptance. Original NEPC/NEHT/NERT formats remain unchanged; measured board envelopes and physical thermal acceptance remain external |
| `rts_cts_protection` | Native ERP CTS-to-self and per-device RTS threshold, exact source TXD fields and separate signed NERT full-program qualification are implemented above, pending compilation/native acceptance; physical board measurements remain external |
| `vht` | VHT operation including TX/RX STBC on RTL8821AE; blocked on the rtl8821ae runtime |
| `wowlan` | WoWLAN magic-packet/pattern wake on RTL8821AE/8812AE; blocked on the rtl8821ae runtime and system_suspend |
