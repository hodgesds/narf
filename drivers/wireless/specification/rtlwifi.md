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
| `bt_coexistence` | Bluetooth coexistence on RTL8723AE/BE; blocked on the rtl8723ae/rtl8723be chip runtimes |
| `dynamic_antenna_selection` | Native factory type1/2 hardware diversity and SMART type4, actual PHY mux/descriptor/training/restore and separate signed NEAN per-selector/thermal full-program qualification are implemented above, pending release compilation/native acceptance. Original static records remain unchanged; board measurements and physical mapping/RF acceptance remain external |
| `five_ghz_operation` | 5GHz band operation on RTL8192DE/RTL8821AE; blocked on the rtl8192de/rtl8821ae chip runtimes (RTL8188EE is 2.4GHz-only) |
| `ht40` | Source-correct native HT20/40/secondary selection and signed NEHT v4 full-program qualification are implemented above, pending coordinated native acceptance. Existing NEHT v2/v3 remain20MHz. Measured per-device board data and physical acceptance remain external |
| `rf_gain_tracking` | Native thermal TXAGC, actual IQK/LCK/restore and separate signed NETH full-dimensional qualification are implemented above, pending coordinated release compilation/native acceptance. Original NEPC/NEHT/NERT formats remain unchanged; measured board envelopes and physical thermal acceptance remain external |
| `rts_cts_protection` | Native ERP CTS-to-self and per-device RTS threshold, exact source TXD fields and separate signed NERT full-program qualification are implemented above, pending compilation/native acceptance; physical board measurements remain external |
| `vht` | VHT operation including TX/RX STBC on RTL8821AE; blocked on the rtl8821ae runtime |
| `wowlan` | WoWLAN magic-packet/pattern wake on RTL8821AE/8812AE; blocked on the rtl8821ae runtime and system_suspend |
