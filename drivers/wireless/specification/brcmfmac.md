# Broadcom FullMAC PCIe — software bring-up

> Status: v0.9. Signed exact board provisioning, BCM43602 CR4 firmware, retained
> PCIe control/flow/data rings and a constrained FullMAC station path are implemented. Recovery remains
> software work; physical validation is pending.

## 1. Purpose & scope

Owns Broadcom PCIe FullMAC (`brcmfmac`) device ownership, chip discovery,
firmware bootstrap, shared-memory/msgbuf transport, and station integration.
SDIO CYW43439 uses the separate [CYW43439 contract](cyw43439.md).

## 2. Assumptions

PCI matching identifies a candidate, not a validated chip or usable radio.
AI/AMBA ChipCommon is at 0x18000000. The PCIe BAR0 window selects a
4-KiB backplane page through PCI configuration offset 0x80. CPU, RAM,
firmware, and board-data decisions must use discovered chip/revision
information rather than equating the PCI device ID with the chip ID.

## 3. Public interface

`pcie::probe(BusDevice, Cap<BusDeviceCap, Write>)` retains exclusive PCI
authority in a parked controller. `unsafe pcie::bring_up(device, cap)`
requires exclusive BAR/config ownership and returns that same owned state.
Both paths clear inherited `BUS_MASTER|MEM_SPACE`, set `INTX_DISABLE`,
verify all three bits before BAR sizing, then enable and verify memory decode
with bus mastering off. Repeated owned-BDF probes return before PCI access;
extra devices are parked with decode and bus mastering disabled.
The control BAR mapping ignores a firmware-provided prefetchable attribute.
They publish a bound-driver inventory entry before the separate station lifecycle.

`chip::Backplane` supplies serialized fallible `read32`/`write32` operations.
The production PCIe implementation keeps the BAR and capability private;
each access validates alignment/range, selects the page, and verifies
readback with at most one retry. The complete select/access pair runs inside a `CapOp` invocation; the
configuration helpers also check current validity at each select. Checked BAR2
TCM reads/writes and PCI decode/DMA transitions run inside the same invocation
contract, so possession of a retained BAR never authorizes a later access. `Chip::discover` reads the actual
chip ID/revision, walks bounded AI EROM descriptors, and returns discovered
`Core { id, revision, base, wrapper }` records. It performs no writes.
Non-AI interconnects and malformed/out-of-range maps are rejected.
`Chip::discover_ai` shares the bounded EROM walker with SDIO consumers;
those callers validate their own CM3/RAM/D11/SDIO profile. `disable_core`
and `reset_core` implement AI clock/reset/readback ordering with 300-us
assert and 3-ms release deadlines. CYW43439 uses these live helpers; PCIe
BCM43602 CR4 passive/active integration uses these same helpers; CA7 and
other chip-specific lifecycle paths remain gated.

`Chip::park_pcie` masks the PCIe interrupt and mailbox sources before
acknowledging the sampled mailbox status. PCIe core revisions below 64
use offsets 0x24/0x48/0x4c; revisions 64 and above use 0xc14/0xc30/0xc34.
Those offsets are relative to the discovered core, independently of the
firmware shared-memory version. This is interrupt parking, not a reset.

`native_runtime::register_board_profile(BoardProfile)` preserves the trusted
kernel-platform contract: exact PCI vendor/device/subsystem, discovered
chip/revision mask and registry firmware/NVRAM names registered before probe.
The executable follows the firmware registry's existing signature policy;
NVRAM always requires a verified signer. No built-in deployment board is guessed.

For retained BCM43602 PCI DIDs 43ba/43bb/43bc, probe maps BAR0/BAR2 with decode
and BME parked, discovers identity and retains that same native owner before
spawning deferred provisioning. Without an explicit registration,
`provision::select(Family::Pcie43602, HostIdentity, None)` resolves the signed
canonical `brcm/wifi-board-selection-v1.bin`. Selection binds the actual PCI
segment/BDF, full vendor/device/subsystem/class identity, discovered chip/revision
and a named board to exact asset keys, lengths and SHA256 payload hashes.
`Selection::load` invokes registry/blob capabilities before copying selected
bytes. No generic chip NVRAM fallback supplies board authority.

`native_runtime::provision_state()` reports Parked/Starting/Ready/Failed.
`provision().await` requires `trusted_net_authority` and retries newly staged assets/policy only while Parked.
Probe drives background provisioning via `drive_scheduled` across 120 attempts with 500 ms intervals. Missing,
unsigned, malformed, mismatched or revoked provisioning preserves the exact parked
owner without a CR4/ring attempt. All selected assets, single-board NVRAM and an
existing or signed regulatory domain validate before Starting. First hardware
attempt, cancellation or failure after that point is terminal; no second native
owner is reconstructed. The trusted explicit-registration path uses the same
retained continuation. Interface names are reserved before async station attach.

### Signed board-selection format

`provision` consumes **NBSP v1**, little endian, wrapped in the firmware loader's
existing verified NRFW envelope. Header (16 bytes) contains magic `NBSP`, version:u16=1,
header_size:u16=16, total_size:u32, count:u16 (1..16), record_size:u16=616. Exact
extent, canonical ASCII names/keys, zero reserved/padding bytes and unique selectors
are mandatory; overlapping duplicate selectors are rejected regardless of masks.
Each record has the following fixed layout:

| Offset | Field |
| --- | --- |
| 0,1 | family:u8 (1=PCIe43602,2=SDIO43439), function:u8 (0 or1) |
| 2,4 | chip:u16, nonzero revision_mask:u16; actual revision must be below 16 |
| 6,7,8 | host_kind:u8 (1=PCI,2=explicit SDIO MMIO), reserved:u8=0, address:u64 |
| 16..24 | host vendor/device/subsystem-vendor/subsystem-device:u16, class:u32 |
| 28,30 | card vendor/device:u16 (zero for PCIe) |
| 32,96 | board label[64] (NUL/zero padded), reserved[16]=0 |
| 112,280,448 | three asset slots[168]; final PCIe slot is entirely zero |

PCI address packs segment<<24, bus<<16, device<<8, function in 40 bits. An
explicit MMIO address must be nonzero/aligned; it grants no wiring authority.
SDIO PCI host classes are 080500/080501 and card F1 must be 02d0:a9af or 04b4:bd3d.
An asset contains role:u8 (1=executable,2=NVRAM,3=CLM), flags:u8 (bit0 requires
signer), reserved:u16=0, payload_length:u32, actual SHA256[32], key[128]. Roles 2/3
always require a signer; role 1 may additionally require one but never relaxes the
registry/build executable policy. Raw lengths are bounded to 16 MiB, NVRAM to 64000.
Before copying selected executables or beginning a hardware attempt, CR4 requires
at least four bytes and CM3 preserves its existing nonempty/at-most-4-MiB rule.
The explicit trusted BCM registration uses the same static CR4 preflight. Actual
RAM capacity and image/RAM compatibility still require discovered loader state;
these bounds supply no guessed RAM size. The registry's current single coherent
backing separately limits installed payloads to 4 MiB.
Keys have no empty, dot or parent components; asset keys within one row differ.
The manifest's SHA256 is independent of the registry's historically named
`BlobView.sha256` field, which contains BLAKE3.

`cargo xtask wifi-fixtures board-manifest --input input.json --output output.bin`
encodes explicit
board facts and hashes actual payload files. Input records supply family, board,
revision mask, full host identity, SDIO card tuple when applicable and ordered
asset key/path/signed entries. `wrapped:true` explicitly strips an existing NRFW
envelope before hashing; paths otherwise denote raw payloads. Sign/package the
output with `cargo xtask pack-firmware --payload ... --name
brcm/wifi-board-selection-v1.bin --signature ... --public-key ... --out ...` and
stage that manifest plus exactly named assets through the existing firmware loader.
The tool supplies no board default or signer authority; `--synthetic-fixture` emits only
synthetic private test identities.

Selected source caps and exact copied bytes remain pinned across boot/runtime.
Native PCI/SDIO accesses invoke those original source caps and current bus authority;
actual source-cap epoch revocation closes the qualified transport. Firmware registry
hot replacement preserves existing cap bindings, so it cannot retarget a running
owner or its bytes; a newly resolved selection rejects mismatched replacement
assets. Replacement alone does not revoke a previously pinned signed selection.
No per-register name lookup mints additional firmware capabilities.

`boot::Cr4<B: boot::Bus>::claim/boot` consumes exclusive backplane/TCM access.
It admits BCM43602 only, halts CR4, disables discovered D11 cores, derives RAM
from CR4 bank registers, applies bank5/7 PDA quirks, checks firmware/NVRAM
nonoverlap, and uploads the reset vector at TCM0 before release. `pack_nvram`
requires a selected single-board file with boardrev, adds the final list NUL,
alignment, and complement token excluding the token bytes. Multi-device
NVRAM is rejected until an actual selector exists. Shared readiness has a
5-second deadline and requires a changed tail sentinel plus aligned RAM-bound
metadata. Firmware RAM hints may shrink, never enlarge discovered RAM.

`runtime::Runtime<B: runtime::Bus>::attach(Booted<B>)` owns five common rings,
eight IOCTL-response buffers, eight event buffers, request input, scratch and
ring-update memory. Shared versions5/6 use checked disjoint TCM metadata and
16-bit indices at 4-byte strides. Nonzero rx_dataoffset descriptor-prefix
geometries and v7 remain gated before any DMA allocation/publication. Optional host DMA-index
fields are cleared to select the supported TCM fallback. All DMA allocations
and host addresses are retained before publication and before enabling BME.

`begin_ioctl`/`take_response` serialize bounded control requests with monotonic
nonwrapping transaction/buffer IDs, zero-filled physical query prefixes,
posted-buffer identity plus command/transaction/interface correlation, and
copy-before-repost. `command(...).await` drives bounded polling with a 2-second
deadline; cancellation poisons the owner and preserves active input bytes.
`poll` consumes at most10 completions per each of three rings (30 total)
per call, so control pressure cannot starve TX/RX; `pop_event` returns owned
event payloads. Stale IDs, malformed extents/indices,
uncorrelated flow/data completion, or bounded event overflow fail-stop the owner
and attempt to disable BME. The station worker serializes live transport operations through an async mutex,
with no IRQ lock across awaits. Transport progress alone grants no station
authorization. The native station owner exclusively consumes the transport after
provisioning; the old `connect_wpa2_psk` helper remains an orchestration model.

`enable_data` retains up to32 receive buffers of2048 bytes before publishing
RX32 posts. The native bootstrap calls it before starting the packet worker.
`open_flow(source,destination,priority)` allocates a512×48 flow ring, retains
it before the create request, initializes its TCM indices, and returns a
`FlowToken`. The token is Creating until a matching firmware create completion;
only Open flows admit `send`. Source/destination and priority are immutable.

`send` admits bounded Ethernet-II frames, copies the14-byte Ethernet header
into the TX descriptor and publishes only the remaining body as DMA. At most64
combined outstanding packets/receipts are retained. A matching request ID plus
flow ID and metadata-free classic16-byte TX completion retire exactly one body
mapping after a CPU DMA-read release edge; `pop_tx_receipt` returns its result.
`close_flow` refuses outstanding TX, then waits for the correlated delete ACK.
Create/delete have2-second deadlines driven by the shared poller. At most8 (or
the lower firmware maximum) flow mappings are retained concurrently. A successful
delete ACK after all exact TX completions fences firmware ownership and permits
reusing that retained mapping and hardware ID; failed/timed-out deletes cannot.
`FlowToken` includes a nonwrapping host generation so old software handles cannot
act on a recycled ID. Mappings remain allocated until whole-device quiescence;
recycling does not free DMA based only on PCI command readback.

RX classic32-byte completions validate posted ID, interface, status, Ethernet
format, full16-bit offset/length and buffer bounds. Payload is copied before
posting the same allocation under a fresh nonwrapping ID. `pop_received` returns
owned Ethernet frames; bounded RX queue pressure drops ordinary data and keeps
buffer progress. Unknown/stale completion identity fails the owner. Native
`open_flow`, `flow_state`, `send`, `close_flow`, `pop_received`, and
`pop_tx_receipt` forward to this retained runtime through its async mutex.
These legacy native forwarding APIs return Failed/None while the station owner
exclusively consumes the runtime. Missing provisioning/policy now preserves a
Parked pre-boot owner; it creates no permanent control-only runtime.
Station authorization and network publication are not implied by a flow token.

`station_transport::Adapter` implements the common `cyw43439::fullmac::Fullmac`
command/event/data contract over real msgbuf rings. Query results are limited to
the caller extent despite a longer iovar-name envelope; SET uses its actual input
extent. It decodes posted vendor event frames, tracks bounded TX deadlines, and
admits Ethernet only after the station's correlated link/key lifecycle authorizes
a peer. Link-down drains exact TX receipts and acknowledged flow deletions before
new-peer traffic. A bounded flow cache evicts idle destinations only through the
same delete-ACK fence.

For an exact signed or trusted-platform BCM43602 board profile, native bootstrap loads an existing
authenticated regulatory domain or signed wireless-regulatory.bin, then calls the
common station attach path and publishes a named wireless/net interface only after
firmware initialization. This chip's Linux firmware embeds CLM; no SDIO glom or
external CLM commands are sent. The current shared profile restricts scanning and
joining to authenticated 2.4-GHz channels, Open or firmware-supported WPA2-PSK/CCMP,
a fixed BSSID and roam_off=1. Missing firmware supplicant support rejects WPA2;
there is no host-PSK fallback. Firmware MAC/channels, canonical RSN IE, key/link
events, controlled-port Ethernet-II checks and synchronous bounded network drains
come from the same station implementation as CYW43439. No physical acceptance or
5-GHz/WPA3/AP support is implied.

The `runtime::Memory` contract separates CPU and DMA addresses and requires
cache maintenance plus peripheral barriers at ownership transitions; the
native `DmaBuffer` adapter uses `dmb osh` on aarch64.
`Memory::sync_from_device` performs pre-read cache visibility. A separate
`Memory::release` edge retires CPU DMA reads before TCM consumer-index
publication; the pre-read invalidation/barrier is not a substitute. Drop after any address
publication disables BME best effort and retains every mapping permanently:
config readback alone does not prove all previously posted PCI writes drained.
Recovery/IOMMU quiescence and reclamation are explicit remaining software work.

Physical carrier/peer publication does not change operator `IFF_UP` and never
invokes administrative open/stop hooks while retained driver state is locked.
Explicit registration, operator up/down and autoconnect remain administrative
events. Disconnect/failure clears carrier and peer identity while preserving an
operator-UP interface; a later physical carrier sample cannot undo operator DOWN.

### Dual-band 20 MHz station profile

The common station also admits firmware-owned required PMF with WPA2-PSK/CCMP
when native `mfp` capability probing succeeds. The driver validates AP/SME
MFPC/MFPR and BIP-CMAC-128, emits a canonical required-PMF RSNE, configures/readbacks
`mfp=2` after WSEC, and still requires correlated SET_SSID/FWSUP_COMPLETED.
Before opening the port it queries actual firmware MFP mode, current BSSID and
bounded `assoc_info`/`assoc_req_ies`; the transmitted RSNE must match the required
profile, followed by another actual event/data idle fence. Every native GET/SET
retains current policy checks across polls and receipts. Missing capability,
unsupported management cipher, malformed/downgraded receipt, wrong peer, absent
policy or cancellation cannot open the port or revive a failed owner. Legacy
Open/WPA2 remains reachable when MFP is unsupported. This does not enable SAE.
The common Device advertises AES-CMAC/BIP only from actual MFP plus supplicant
capability, so userspace can select required-PMF APs without inventing support.
It separately exposes default-closed `supports_wpa2_mfp_offload()` from those
native probes. Shared nl80211 PMK CONNECT requires it plus `USE_MFP=1` and a
strict MFPC|MFPR PSK/CCMP RSNE with explicit/default BIP-CMAC-128. Unsupported
caller security promises such as OCV are rejected before native join writes.
The separate bounded Optional-PMF contract below opts in explicitly.

IGTK installation, BIP replay/integrity and protected robust-management/SA Query
processing remain inside the firmware offload. The host manufactures no IGTK,
key receipt or protected-event flag. Its protected-peer metadata requires the
verified firmware configuration, actual association request and completed key
event; link/deauth events remain the firmware's management-authentication
decisions. Physical PMF acceptance remains external. See `cyw43439.md` §3 for
the complete shared contract. Five native msgbuf smokes under
`drivers/wireless/brcmfmac/pmf` cover both shared5/6 and both firmware key-event
orders through DHCP/exact IP, native mode/cipher ordering, capability/receipt/
peer denials, teardown and cancelled verification with all posted DMA retained.
Raw CONNECT attributes additionally exercise the real shared parser/execution
path through shared5/6 native MFP/association verification and port publication;
missing native MFP capability is rejected without a device command.

### Bounded optional-PMF CONNECT

The actual BCM43602 MFP/supplicant probes additionally gate
`supports_optional_mfp()` and its separate nl80211
`NL80211_EXT_FEATURE_MFP_OPTIONAL`. Shared PSK/CCMP `CONNECT USE_MFP=2` retains
an MFPC-only/MFPR-clear caller RSNE; native CAPABLE1 is set/read back after
WSEC. Explicit required policy remains native2; Open remains0. The driver
derives policy from the original RSNE, never a caller authorization flag.
The full common negotiation/matrix contract is in [CYW §3](cyw43439.md).

Native1 configuration does not establish negotiated PMF. After peer-bound
association and FWSUP_COMPLETED, the current original msgbuf owner checks
native BSSID/mode and complete bounded actual association request/response
RSN snapshots under its current source and full occupied-power grant. An
exact-consumption local check rejects partial/trailing RSN fields before any
BIP default normalization; valid legacy18/default20/22/explicit26 extents remain.
An MFPC AP requires matching actual response MFPC/MFPR and PSK/CCMP/BIP-CMAC128
facts; missing, malformed or changed proof closes that submitted lifecycle.
An AP without MFPC can complete unprotected, including an absent response
RSNE, without falsely setting protected metadata. Another real native ring
idle precedes port publication. Current policy, cancellation, host close and
receive epochs retain the same strong owner/publication fences. No uncertain
command/packet DMA is released by an apparent policy or cryptographic flag.

Eight `drivers/wireless/brcmfmac/optional_pmf` smokes pass on both architectures for shared5/6:
the complete policy/AP/capability matrix, actual RSN/default-BIP/absence and
downgrade/duplicate/malformed evidence, mode/peer/length/OCV failures, foreign
and genuine native key events, held mode/request/response cancellation,
current policy loss at the actual response wait, raw Optional CONNECT and
real Open/WPA2 protected/unprotected DHCP/IP, including occupied VHT80.
Existing required-PMF coverage remains. These additions pass coordinated
software gates and do not establish firmware-internal BIP or physical PMF.

Broad optional-PMF interoperability remains open: MFPC APs omitting response
RSNE require a source-proven native negotiated-MFP indication. The local
Linux ABI supplies no such `sta_info` flag. Configured1 or IOCTL success
cannot replace that proof. This residual is not closed by the bounded profile.

### Firmware-qualified HT20/HT40 and short GI admission

The common Station now uses actual native `nmode`/`rxchain` and the two
native per-band `bw_cap` plus exact `chanspecs` inventory before constraining
the firmware to20MHz for `WLC_UP`. Source HT capability bodies remain distinct
on the real2.4/5GHz bands; HT40/SGI40 require native width and inventory support,
and no chain/bandwidth/6GHz/VHT profile is guessed from an alias. AP HT/WMM/basic-MCS admission and
current BSSID/chanspec/actual association request+response IE verification
precede the port, followed by another real completion-ring idle drain. Firmware
owns BA/reorder and Ethernet deaggregation. Required PMF composes with the PHY
verification; cancellation keeps the native control/DMA owner terminal.
See `cyw43439.md` §3 for the exact shared profile and remaining feature inventory.
For HT40 the complete occupied span supplies a retained power/policy grant,
and both constituent channels must return valid native `per_chan_info` without
unsupported restrictions. Power precedes the selected band's `bw_cap=3`
set/readback and exact40MHz join chanspec. Current BSSID/chanspec and actual
request/response HT width/secondary/MCS/WMM receipts precede port publication.
Pre-join20MHz fallback preserves constrained HT20 when native/AP/policy facts
do not qualify40; post-submission width or peer mismatches terminate the owner.
Control futures and queued data recheck the full occupied grant, including
secondary-only restriction/power changes and source clear. No host flag alone
authorizes wider firmware operation or short GI negotiation.

Three `drivers/wireless/brcmfmac/ht20` smokes exercise source capability literals,
both shared5/6 versions, both bands, actual three-chain HT RX masks, and
Open/WPA2/required-PMF DHCP/exact bidirectional IP. They reject invalid chains,
wider/current-peer/HT/MCS/WMM receipts and preserve posted DMA through cancelled
verification. This does not establish physical firmware/PHY interoperability.
Five `drivers/wireless/brcmfmac/ht40` native smokes add shared5/6, both bands,
exact cap/chanspec/association ordering, Open/WPA2/required-PMF DHCP/exact IP,
capability/inventory/policy fallback and secondary-power reduction, native
restriction/width/request/response denials, current secondary revocation across
data and held native waits, and cancellation with posted DMA retained.

### Firmware-qualified BCM43602 VHT80

Only the retained, discovered BCM43602 PCIe adapter opts into
`Fullmac::VHT80`; the common CYW43439 SDIO implementation keeps this false.
No chip alias, board name, firmware filename or AP IE grants VHT. Exact signed
board selection, original executable/NVRAM capabilities, embedded CLM and
current PCI/backplane authority remain prerequisites. Linux
`brcmf_setup_wiphybands`/`brcmf_update_vht_cap` supply the capability contract:
native nonzero `nmode`/`vhtmode`, valid `rxchain`, the original5GHz `bw_cap`
20/40/80 bits and an actual bounded D11AC80 `chanspecs` entry. This profile
additionally requires native `txstreams` in1..3; absent VHT/stream capability
preserves qualified HT, while malformed replies fail closed. RX and TX
MCS0..9 capability maps use their independently reported stream counts.
Only SGI80 is offered. Initial WLC_UP/scan operation remains20MHz.

VHT beamforming capability (implemented): under nonzero `vhtmode`, after
`txstreams`, the probe queries native `txbf_bfe_cap` and `txbf_bfr_cap` as
Linux `brcmf_setup_wiphybands` does (an unsupported query is zero) and adds
`brcmf_update_vht_cap`'s bits: SU/MU beamformee from `BRCMF_TXBF_{SU,MU}_BFE_CAP`
(bits0/1), SU/MU beamformer from `..._BFR_CAP`, and, when either is nonzero
with more than one TX stream, beamformee STS2, sounding dimensions
`txstreams-1` and VHT MRQ/MFB link adaptation. Bits outside SU/MU are
ignored. Code: `drivers/wireless/src/cyw43439/station_phy.rs::beamforming_capability`.
Firmware owns sounding, steering and its own association request; the host
reports the capability on5GHz and the existing actual `assoc_req_ies` check
now requires those same bits, so a request lacking them is a changed request
and terminates that owner. Smoke `drivers/wireless/brcmfmac/vht80`
`..._native_beamforming_capability_and_request` (shared5/6) checks five
literal capability words including unsupported/unknown-bit replies and the
mismatched-request refusal. CYW43439 never reaches this VHT probe.

Remaining VHT options are not host features of this FullMAC family:

- LDPC, STBC and extended NSS/BW: Linux brcmfmac (`brcmf_update_ht_cap`,
  `brcmf_update_vht_cap`) neither advertises nor programs them, and the
  firmware ABI exposes no host control; firmware builds its own association
  capability. A host-reported bit would be fabricated. Open question: the
  exact actual-request comparison (first six VHT capability bytes) would
  refuse firmware that sets its own RX LDPC/STBC bits; physical BCM43602
  firmware requests must be checked before deployment.
- 80+80: Linux brcmfmac never advertises `SUPP_CHAN_WIDTH_160_80PLUS80`; it
  only decodes `BRCMU_CHAN_BW_80P80` chanspecs in reports.
- 160 MHz: Linux advertises it only from a firmware `bw_cap` 160 bit. The
  retained BCM43602 is an 802.11ac Wave-1 3x3 80 MHz part, so this profile
  ignores that bit; 160 MHz belongs to enabling a 160-capable chip under the
  remaining additional-chip-profile work.

The actual selected BSS's complete original HT/VHT/WMM/rate IEs pass shared
`Offer::from_elements`; complete known basic/legacy rates, membership
selectors, mandatory HT/VHT MCS and exact primary/center geometry must fit
the local native capability. This parser supplies no radio/key/port rights.
The native80MHz plan needs all four20MHz constituents in the current native
channel list and its exact primary-sideband chanspec in firmware inventory.
Only pre-join capability/inventory/policy narrowing can select80→40→20.
This preserves the AP's original VHT IEs and truthful physical VHT capability;
the configured/read-back `bw_cap=7/3/1` and exact join/current chanspec bound
actual operation. There is no fabricated HT-only request or rewritten AP
response. At20MHz the real request may retain source HT40 capability or
advertise its bounded HT20 subset;40/80 requires the qualified HT40 shape.
Unqualified source capabilities cannot be added by an unsolicited request.

All four80MHz constituents must return valid, unrestricted native
`per_chan_info`. The retained grant covers center frequency±40MHz, every
overlapping restriction/maximum bandwidth and the minimum power ceiling,
including quarters outside the primary's20/40MHz. `qtxpower` precedes native
bandwidth programming. Current exact BSSID/chanspec, bounded `assoc_info`,
the real firmware `assoc_req_ies` and AP `assoc_resp_ies` must preserve the
source capability maps, SGI/width bounds, valid WMM/basic rates and complete
AP operation. Shared response negotiation must cover every actually occupied
constituent and retain the offered VHT presence. Another actual native idle
observation precedes key/controlled-port publication. Post-submit mismatch,
failed width readback, restrictions or cancelled receipts terminate that
owner, with all uncertain native DMA retained. `CHANNEL_ADOPTED` after PHY
verification/connection closes the old grant; autonomous retuning needs a
separate qualified lifecycle.

`Station::vht_capabilities` and the facade expose native capability on5GHz
only. `vht_connection` requires the current verified peer/grant;
`channel_width_mhz` reports actual20/40/80 operation. These facts grant no TX
authority. Firmware owns CCMP, BA/reorder, deaggregation and rate control.
An MCS0..9 map is a capability bound, not permission to transmit each MCS in
every width/NSS combination: Linux `minstrel_get_valid_vht_rates` excludes
20MHz MCS9 at NSS1/2 and80MHz MCS6 at NSS3. This FullMAC path programs no raw
host rate or invented per-rate native receipt.

The common final-publication owner carries a nonwrapping association epoch
with each captured native Ethernet batch. It rechecks current full occupied
policy and invokes native source/bus/event progress after frame allocation,
before IPC publication and before each unlocked stack callback. Host close
immediately changes the epoch, closes carrier/queue admission and drains old
RX IPC; a same-peer rejoin cannot authorize an old batch. State→publication→ring
is the lock order, with no state/publication/ring guard across a stack callback
or publication guard across an await. Close can serialize against an actual
native TX post without pretending to reclaim firmware-owned descriptors.
Late key/link/control/PS receipts cannot reopen a closed or replaced lifetime.

Eight new `drivers/wireless/brcmfmac/vht80` smokes pass for both shared5/6:
all eight literal sidebands, independent RX3/TX1..3 capability maps, exact native
cap/chanspec/four-quarter queries, signed selected-board Open/WPA2/required-PMF
real DHCP/bidirectional IP,80→40→20 fallback and remote-quarter power,
malformed current/request/response/inventory and caller PHY/WMM injection,
live remote-quarter revocation during queued data/held replies, cancellation,
autonomous channel adoption, final IPC/callback policy loss and actual
reentrant stack close/same-peer receive epochs. A bounded exhaustive80MHz
codec smoke and two common CYW native publication/no-VHT smokes accompany
them. These additions pass the coordinated both-architecture software gates;
no hardware EEPROM/calibration/RF/AP/DMA acceptance or throughput result is
claimed.

The exact BCM43602 `Fullmac::BAND_5GHZ` profile admits firmware-reported valid
channels from Linux's 2.4/5 GHz tables, intersected with the retained host-policy
snapshot. It first sets and reads back `bw_cap=20 MHz` on both firmware bands
before `WLC_UP`; a join chanspec alone is not a bandwidth proof. An absent,
failed or wider readback prevents interface/station publication. CYW43439's
SDIO profile leaves this capability false and never gains 5 GHz from an
unexpected valid-channel reply.

Scan uses20MHz D11AC encodings; join uses its fully qualified20/40/80MHz encoding.
Wider AP BSS records decode their primary from center/sideband and require any
reported ctl_ch to agree; 6 GHz/4.9 GHz numeric aliases, malformed widths and
band mismatches fail. The facade splits genuine allowed channels into separate
wiphy bands; HT/VHT metadata and wider operating widths are not inferred.
Native Rust tests check the 43-channel inventory, exhaustive 16-bit geometry
invariants, band/control consistency and literal wide-channel examples. Native shared5/6 models compose Open/WPA2, firmware station power save,
DHCP and exact bidirectional IP on channels36/149, and validate bandwidth caps,
wire values, NO_IR/passive discovery and restrictive-overlap rejection.

NO_IR/DFS receive channels can remain visible for passive discovery; every
active channel and association must independently obtain TX permission before
power/scan/join dispatch. A permissive overlapping rule cannot erase a stricter
limit. Fixed-domain initialization retains its policy snapshot; native attachment
observes live shared DB replacement/clear as described below. Physical 5 GHz
RF/width/power/AP acceptance is required in addition to these software results.

The common FullMAC station now uses a live immutable host-policy source during
native attachment. Shared DB replacement/clear is observed around setup, control
receipts, scan/join idle fences and host data progress; fixed-domain explicit
initialization remains snapshot-only. Source loss, country change, channel
removal/NO_IR/DFS or a lower ceiling than acknowledged firmware power closes the
host port and poisons the retained owner. Reinstalling policy or receiving late
link/key events cannot reopen it. Same-country changes covering that original
power grant preserve the peer without increasing power. Native msgbuf tests
exercise queued-TX closure and replacement during actual join/PS receipts, with
no uncertain DMA freed. This does not automatically follow revocation of a cached
policy firmware capability or establish firmware RF quiescence; reset/reload and
DMA reclamation remain separate gates. See `cyw43439.md` §3 and `wireless/` §3.5.

## 4. Invariants

- No bus mastering without owned DMA mappings, ring lifetimes, and a
  retained terminal ownership. Probe leaves it disabled until explicit
  board firmware/control-ring attachment; all post-publication failures keep
  mappings retained even when BME-disable readback fails.
- Window selection and the subsequent MMIO access have one mutable owner.
  Raw BAR handles are not exposed to concurrent clients.
- Discovery consumes at most 1024 EROM words and retains at most 64 cores.
  Extended address/size descriptors are consumed; a nonzero high address
  word is never truncated into a 32-bit address. Selected register and
  wrapper pages must lie in 0x18000000..0x20000000.
- A map must contain ChipCommon at its expected base and exactly one PCIe2
  core. Duplicate register bases and partial component descriptors fail.
- A gone-device all-ones status is never acknowledged as a live mailbox.
- No await or hardware wait may hold the static controller's IRQ lock.
  Subsequent async firmware/runtime work must move ownership out or use
  an async mutex and scheduler deadlines.

## 5. Architecture notes

The register protocol is architecture independent. `MmioRegion` provides
volatile access and architecture barriers; PCI configuration uses the
capability-checked bus helpers. AI discovery model tests run on both
x86_64 and aarch64; passing them does not establish physical operation.

## 6. Dependencies

Implemented: PCI enumeration/exclusive authority, Device BAR0/BAR2,
BCM43602 bank-derived CR4 boot, signed host/board/asset selection and retained
pre-boot provisioning,
shared 5/6 TCM indices, retained common/control/flow/RX/TX DMA, bounded correlated
IOCTL/events/data ownership, generation-safe retained flow recycling, shared
station/control-port lifecycle and native probe-to-interface dispatch.

The retained initial profile is shared 5/6, zero descriptor prefix, polling,
2.4/5 GHz Open or firmware-supplicant WPA2-PSK/CCMP, with one-shot terminal failure
and permanent retention of published DMA. Its remaining deployment requirements
are real target identity/calibration/firmware assets, a verified selection manifest
(or trusted platform registration), authenticated regulatory policy and physical
station acceptance. No deployment board is manufactured by these tests.

The common FullMAC interface also exposes ordinary station power save, with
an awake default and serialized/coalesced PM_FAST/PM_OFF plus the default
2000 ms `pm2_sleep_ret` policy. Both native msgbuf replies are required before
recording applied state; rejection/partial transition closes carrier/queued TX
and leaves uncertain DMA retained. Shared5/6 models check exact command bytes,
duplicate policy, authorized-peer preservation and firmware refusal at either
step; Open/WPA2 DHCP/IP conversations run while PS is enabled. This implements
firmware station PS only; host-bus PM, suspend/WoW and reset replay remain open.

The common FullMAC scan also installs caller Probe Request vendor IEs with
the native `vndr_ie` iovar before escan (Linux `brcmf_vif_set_mgmt_ie`,
`BRCMF_VNDR_IE_PRBREQ_FLAG`), and refuses triggered random-MAC scans because
brcmfmac randomizes only PNO `pfn_macaddr`; see [CYW §3](cyw43439.md)
"Caller Probe Request IEs" and "Random scan source address". The shared5/6
msgbuf smoke `drivers/wireless/brcmfmac/scan_ies` checks literal add/del
records before each changed escan.

Additional software outside that retained profile remains: nonzero descriptor
prefixes/shared 7, other CPU/RAM/chip/OTP selectors (including 160 MHz-capable
chips), HE/EHT profiles, native802.11
RX/metadata, larger flow budgets, host-supplicant fallback, WPA3/AP, replayed
recovery/system PM, confirmed stop/IOMMU quiescence and DMA reclamation, and IRQ delivery.
These do not expand the initial polling/retained-failure acceptance claim.

## 7. Stage assignment

Stage 5 software bring-up. No hardware readiness claim follows from the
PCI match inventory, protocol encoders, or synthetic discovery tests.

## 8. Verification and open questions

Regression fixtures exercise production `Cr4`, `Runtime`, PCI command
transition, `Chip::discover` and `park_pcie` paths using literal Linux-format descriptors. They cover
different discovered PCIe core bases, the revision-64 interrupt-layout
boundary, extended address/size words, aliased/missing cores, invalid
EROM pointers, malformed pairs, absent termination, and gone mailboxes.
Literal CR4 transcripts cover RAM banks/reset-vector/NVRAM/shared readiness;
actual DMA ring fixtures cover request bytes/query zero fill, response and
event correlation/reposting, literal TX/RX wire offsets, full create/TX/delete
state and DMA retirement, wide RX offset/reposting, stale/wrong-flow completions,
control-pressure fairness, invalid indices, cancellation,
and allocation cleanup before versus mapping retention after publication.

The retained shared 5/6, zero-prefix BCM43602 profile also has a complete
station/IP conversation fixture. An explicitly synthetic board profile goes
through production CR4 claim/boot, message-ring attachment and RX posting;
the independent firmware model consumes the actual control/flow descriptors
and DMA bodies and posts native IOCTL/event/TX/RX completions. The production
FullMAC `Station`, `Device`, controlled port, network drain and kernel DHCP
client run unchanged. Shared `DhcpServer` supplies a correlated lease, followed
by exact bidirectional Ethernet/IPv4 payload checks. Open and WPA2-PSK/CCMP
firmware offload run on both shared versions; SET_SSID and FWSUP_COMPLETED are
checked in either order. The fixture does not simulate firmware-internal EAPOL
or cryptography. TX payload allocations remain live until their matching
TX-status completion, and disconnect waits for actual link-down while old
flows retire only on native delete responses. Missing keys/cancelled waits,
link loss with queued TX and same-poll RX, and refused disconnect plus stale
authorization events keep the port closed and published DMA retained. These
are composition checks: no fixture firmware/NVRAM is registered for deployment
and no actual board calibration or hardware interoperability is inferred.

Fixed independently reviewed NBSP wire literals also feed actual Ed25519
NRFW installation, registry lookup/invocation, SHA256 matching and pinned source
caps. Regressions reject wrong host BDF/subsystem/F1 identity, chip revision,
unsigned manifest/NVRAM/CLM, wrong hashes/lengths, missing selected keys, malformed
or duplicate selectors, statically invalid executable sizes, and actual cap
epoch revocation before native PCI or
SDIO dispatch. Hot replacement preserves old exact bytes while new mismatched
loads fail. Retained native PCI and real initialized SDHCI/Card models prove
pre-boot denial/retry keeps the same owner and a first native-command failure is
terminal. A real signed exact one-byte CR4 image and a signed CM3 selection
declaring 4 MiB+1 both preserve the same parked owner; valid restaging then
continues that owner. Independent size boundaries cover CR4 0/1/3/4 bytes and
CM3 0/1/4 MiB/4 MiB+1 without assuming larger registry allocations.
A second composition begins with signed registry selection and runs
CR4/shared 5/6 through the existing Open/WPA2 kernel DHCP/exact-IP fixture. These
fixtures never install a deployment canonical manifest or real board profile.

Primary references: `/usr/src/linux/drivers/net/wireless/broadcom/brcm80211/`
`brcmfmac/chip.c`, `pcie.c`, `firmware.c`, `msgbuf.c`, `commonring.c`, and
`include/brcm_hw_ids.h` in the same source tree. Actual board firmware and
silicon acceptance remain external qualification requirements for the exact retained profile.
