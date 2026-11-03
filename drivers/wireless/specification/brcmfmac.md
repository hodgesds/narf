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
ring-update memory. Shared versions5/6/7 use checked disjoint TCM metadata and
16-bit indices at 4-byte strides. Shared 7 keeps the v6 ring-info layout and
selects Linux `brcmf_ring_itemsize` (24-byte TX status, 40-byte RX complete)
instead of `brcmf_ring_itemsize_pre_v7` for the D2H rings; the completion
fields consumed here are unchanged (smokes `drivers/wireless/brcmfmac/station`
Open/WPA2 DHCP/IP and `drivers/wireless/brcmfmac/wmm` run on shared 5/6/7
with the firmware model writing v7-stride completions). Shared7 also admits
`rx_dataoffset`1..4: Linux7.3-rc4 `msgbuf.c::brcmf_msgbuf_process_rx`
locates messages inside each original item, never by enlarging its stride.
Admission proves the used control/TX/RX spans20/16/28 fit the unchanged
24/24/40-byte slots; the control IOCTL's final used field is `cmd`, followed
by a reserved word. Shared5/6 nonzero prefixes and shared7 prefixes above4
are refused at both CR4 readiness and runtime attach before DMA allocation.
Zero-prefix shared5/6/7 validation and published ring geometry are unchanged.
Each complete original descriptor is copied and released before decoding
past its prefix, retiring DMA or advancing the original wrapped index.
Event buffers use the shared payload offset; RX data uses its explicit
nonzero offset, otherwise the shared offset. These offsets are alternatives,
never a sum, and each whole payload must fit its original posted buffer.
Posted identity, transaction/command/interface checks, copy-before-repost,
current native source, controlled-port/key gates and actual matching TX
terminal ownership remain mandatory. Unknown or malformed completions close
the owner and retain uncertain DMA.

Six new cases under `drivers/wireless/brcmfmac/prefix` are written, pending
execution: preallocation admission, poisoned descriptor prefixes with actual
control-ring wrap, explicit/shared RX offsets and stale/bad extents, matching
TX terminal retention, and full Open/WPA2 scan/key/DHCP/IP conversations over
all four nonzero prefixes. The firmware fixture writes the original physical
strides and real correlated receipts; it alternates explicit and fallback RX
offsets. This is a bounded software implementation, with no physical target
or broader firmware-geometry qualification claim. Optional host DMA-index
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
A present response RSNE from an MFPC AP must match its MFPC/MFPR and
PSK/CCMP/BIP-CMAC128 facts; malformed or changed proof closes that submitted
lifecycle. An omitted (non-FT) response RSNE is admitted as protected, per
IEEE 802.11-2020 12.6.3 negotiation and Linux `brcmf_configure_wpaie`.
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

MFPC APs omitting the response RSNE now complete as protected associations
(Linux v7.2 `cfg80211.c::brcmf_configure_wpaie` trusts firmware's `mfp`; see
[CYW §3](cyw43439.md) for the IEEE 802.11-2020 9.3.3.6/12.6.3 argument). The
shared `optional_pmf` smokes cover that admission on both families.

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

### PCIe mailbox interrupt service

The retained msgbuf owner services the PCIe2 mailbox the way Linux v7.2
`pcie.c` does, with MSI delivery and a polled fallback:

- Register layout: `brcmf_reginfo_default` (`INTMASK` 0x24, `MAILBOXINT`
  0x48, `MAILBOXMASK` 0x4c, `MB_INT_D2H_DB` 0x00ff0000, `MB_INT_FN0` 0x300)
  or `brcmf_reginfo_64` (0xc14/0xc30/0xc34, `D2H_DB` 0xffff, no FN0) when
  the discovered PCIe2 core revision is >= 64 (`brcmf_pcie_probe`).
  `runtime::mailbox::Reginfo::for_core` derives the backplane addresses
  from the discovered core base.
- Bring-up: `Runtime::attach` masks the mailbox (`brcmf_pcie_intr_disable`)
  before publishing ring addresses, then after BME it binds one MSI vector
  (`brcmf_pcie_request_irq`: `pci_enable_msi` + threaded IRQ; NARF
  `irq.rs` programs the MSI capability, installs the handler before MSI
  Enable and refuses a second binding), enables `D2H_DB | FN0`
  (`brcmf_pcie_preinit` -> `brcmf_pcie_intr_enable`) and only then rings
  host-ready.
- Service: the vector handler only raises a `Signal`; the BAR window stays
  with the async owner. Every owner service first runs the
  `brcmf_pcie_quick_check_isr` + `brcmf_pcie_isr_thread` sequence:
  read `MAILBOXINT`, mask, write the status back (W1C), consume D2H mailbox
  data on FN0 (`brcmf_pcie_handle_mb_data`: `DS_ENTER_REQ` -> `H2D_HOST_DS_ACK`,
  `D3_ACK` recorded, `FWHALT` fails this firmware generation), service the
  D2H completion rings (`brcmf_proto_msgbuf_rx_trigger`) and re-enable the
  mask while the link is up. An all-ones `MAILBOXINT` is device loss and
  fails the owner. H2D mailbox words follow `brcmf_pcie_send_mb_data`
  (TCM `htod_mb_data_addr`, config `SBMBX` 0x98, written twice on PCIe2
  core revisions <= 13); a word still pending defers a DS ACK to the next
  service instead of overwriting it.
- Worker: the station service loop waits on the signal with a 10 ms
  missed-edge backstop when a vector is bound, and keeps the 1 ms poll when
  MSI is unavailable (INTx stays disabled; NARF has no shared level GSI
  route that could clear `MAILBOXINT` from hard IRQ).
- Teardown (`brcmf_pcie_release_irq`): mask, disable MSI and free the vector
  (a failed disable quarantines it), then clear latched status.

Smokes `drivers/wireless/brcmfmac`
`smoke_brcmf_pcie_msi_mailbox_service_and_release`,
`smoke_brcmf_pcie_polled_mailbox_fallback_and_gone_device` and
`smoke_brcmf_pcie_signal_wait_and_reginfo` cover the mask ordering, vector
wake, W1C acknowledge, DS ACK (immediate and deferred), FWHALT, all-ones
loss, polled fallback and vector release.

### Confirmed stop and DMA reclamation

`Runtime::quiesce` is the only path that makes published msgbuf memory
(common rings, flow rings, control/event/RX buffers, IOCTL input, scratch and
ring-update buffers, pending TX payloads) reclaimable:

1. `enter_d3` (Linux v7.2 `brcmf_pcie_pm_enter_D3`): refuse while an IOCTL
   is pending, set the bus down (`BRCMF_BUS_DOWN`: every H2D post — IOCTL,
   flow create/delete, TX — now returns `Busy`, and RX/control buffers are
   no longer reposted), send `BRCMF_H2D_HOST_D3_INFORM`
   (`brcmf_pcie_send_mb_data`, 100 x 10 ms pending-word wait) and wait
   `BRCMF_PCIE_MBDATA_TIMEOUT` (2 s) for `BRCMF_D2H_DEV_D3_ACK` through the
   mailbox service. On timeout the bus returns to UP with the mailbox
   re-enabled, exactly as Linux, and nothing is reclaimed; `FWHALT` fails
   the owner.
2. Consume every D2H completion published before the ack, without
   reposting, and require each completion ring's firmware write index to
   equal the host read index.
3. `brcmf_pcie_release_irq` (mask, free vector, clear status), then clear
   BME with a verified readback (`park_dma` + `dma_enabled`).
4. Flush: non-posted BAR2/BAR0 reads issued after the BME clear must
   still observe the same D2H write indices and a present function
   (`MAILBOXINT` not all-ones). PCIe ordering forbids a read completion
   passing the function's earlier posted writes, so a write issued before
   the clear has landed by then, and any later index change voids the proof.

Only a complete proof sets `reclaimable`; `Drop` then releases every
mapping. Any failure (timeout, FWHALT, access fault, a changed index) fails
the owner and keeps the published memory leaked by design. Linux frees the
rings after `brcmf_pcie_release_irq` (`brcmf_pcie_reset`,
`brcmf_pcie_remove`) without device-side evidence; this proof is the
stricter NARF reclaim gate. It assumes the function does not set Relaxed
Ordering on its DMA writes (Linux brcmfmac never enables RO for it; NARF
`narf_bus::pci_express` exposes only an OR-in `set_device_control`, so it
cannot clear `DEVCTL.RO` either).

Production caller (PCI removal). `register_pci_driver` registers a
`narf_bus::register_pci_remove` hook for every BCM43602 id (Linux v7.2
`pcie.c::brcmf_pcie_remove`: `BRCMFMAC_PCIE_STATE_DOWN`,
`brcmf_bus_cancel_reset_work`, `brcmf_detach`, `brcmf_pcie_release_irq`,
then `brcmf_pcie_release_{scratch,ring}buffers`). The hook quarantines the
BDF and runs `native_runtime::remove`: it marks the bootstrap removed (no
later provisioning attempt), waits out an in-flight attempt (the parked
slot is held from boot through station publication), then
`Generation::remove` withdraws the shell — `Device::withdraw` clears the
active endpoint, unregisters the wireless and network-registry entries,
retires the netdev with `narf_net::iface::retire_for_rebind` (a later probe
of the function reclaims the name via `rebind_name`) and stops the worker —
and `Device::teardown` runs `Fullmac::stop_transport` (the confirmed stop
above) and `release_transport` under the station mutex. Only a complete
proof frees the mappings and releases the BDF claim; otherwise the
generation is dropped with its mappings pinned and the address stays
quarantined (`probe` refuses it). A never-booted owner has nothing to
release. Linux disconnect (`brcmf_cfg80211_disconnect`) does not stop the
bus, so disconnect keeps the transport running here too.

Smokes: `smoke_brcmf_confirmed_stop_reclaims_published_dma` (drain, IRQ
release, BME, H2D gating, every mapping freed),
`smoke_brcmf_remove_withdraws_then_reclaims_after_stop_proof` (joined
station: withdrawn, netdev retired for rebind, admission closed, every
mapping freed, a second removal is absent),
`smoke_brcmf_remove_without_stop_proof_keeps_mappings_pinned`,
`smoke_brcmf_unacknowledged_d3_reverts_and_retains_dma` (2 s timeout, UP
again, nothing freed) and `smoke_brcmf_late_dma_or_halt_fails_stop_proof`
(post-clear index change and FWHALT keep memory retained).

### Dead-firmware stop (FWHALT, lost power)

A generation whose firmware halted (`BRCMF_D2H_DEV_FWHALT`, Linux v7.2
`pcie.c::brcmf_pcie_handle_mb_data` -> `core.c::brcmf_fw_crashed`), lost
power across suspend (`brcmf_pcie_pm_leave_D3` reads `INTMASK` == 0) or
never answered D3_INFORM cannot complete the confirmed stop above.
`Runtime::stop_dead` (`runtime/reset.rs`) is its proof:

1. Bus down and terminal; `brcmf_pcie_release_irq`; BME cleared with a
   verified readback.
2. Two non-posted flush reads after the clear (D2H write indices, then
   `MAILBOXINT`, then the indices again): the function must be present
   (not all-ones) and the indices unchanged.
3. `Runtime::reset_device`, exactly Linux `brcmf_pcie_reset_device`: clear
   `BRCMF_PCIE_LINK_STATUS_CTRL_ASPM_ENAB` in config `0xBC`, write 4 to the
   ChipCommon `watchdog` (0x80), sleep 100 ms, restore the link-control
   word and, on PCIe2 core revision <= 13, rewrite the eleven
   `BRCMF_PCIE_CFGREG_*` words through `CONFIGADDR`/`CONFIGDATA`. BME must
   still read clear after that shadow restore (re-parked once if not).
4. The ARM CR4 is halted (`brcmf_chip_set_passive`: CR4 reset with
   `ARMCR4_BCMA_IOCTL_CPUHALT`, D11 cores disabled) and its wrapper
   `ioctrl` must read back `CPUHALT` with `resetctrl` out of reset.

Only then is the owner reclaimable. `Adapter::stop_transport` takes this
path when the generation is already terminal or `quiesce` failed with
`Failed` (FWHALT during the wait) or `Timeout` (no ack); a confirmed-stop
proof that observed device activity after the BME clear (`Protocol`)
never falls back and stays pinned. A vanished function (all-ones reads)
or a revoked firmware proof (every BAR0 access is gated on it) keeps the
mappings pinned. Smokes: `smoke_brcmf_dead_firmware_stop_resets_and_reclaims`,
`smoke_brcmf_dead_stop_without_device_keeps_dma_pinned`,
`smoke_brcmf_remove_after_fwhalt_takes_dead_stop_and_reclaims`.

### Transport reset, generation swap and rejoin

Linux v7.2 `core.c::brcmf_fw_crashed` (FWHALT) schedules
`brcmf_core_bus_reset` -> `pcie.c::brcmf_pcie_reset`: `brcmf_detach`,
`brcmf_pcie_release_irq`, scratch/ring release, `brcmf_pcie_reset_device`,
`brcmf_fw_get_firmwares` -> `brcmf_pcie_setup` (fresh download) and
`brcmf_attach`, which registers a new netdev. `brcmf_bus_cancel_reset_work`
(from `brcmf_pcie_remove`) sets `bus_if->removing` so no reset runs after
removal starts. NARF performs the same sequence as a generation swap:

- `Adapter.inner` is `Option<Runtime>`; `Fullmac::reset_transport`
  requires a proven stop (confirmed or dead), runs
  `Runtime::reset_device`, frees the old generation
  (`Runtime::into_bus`) and boots a fresh one through the retained
  `station_transport::Reboot` authority, then posts RX buffers.
- `boot::Cr4::claim`/`claim_selected`/`boot` return `Refused { error, bus }`
  instead of consuming the bus, so a refused download keeps the reset
  function in the adapter (`parked`) for a retry.
- The production authority (`native_runtime::Reprovision`) retains the
  firmware-registry capability, manifest, explicit board (if any) and
  discovered chip/revision; every reboot re-runs `select_using` +
  `load_using` (or `trusted_assets_using`), so revoked or replaced assets
  refuse the reboot. Every BAR0 access stays gated on the new proof.
- `Generation::recover` (shared `cyw43439/generation.rs`), serialized with
  `remove` on the generation mutex: withdraw the old shell (netdev retired),
  `stop_transport`, `reset_transport`, `take_generation`, re-check removal
  (a removal that arrived meanwhile wins: the fresh generation is stopped
  behind its own proof and released, never published), republish under
  `narf_net::iface::rebind_name` through the publisher (production:
  `attach_runtime`, i.e. `Station::initialize_live` replay plus the normal
  registration), then rejoin: the last completed operator association is
  retained per shell (`Open`/`Wpa2`/`Wpa3`; host-supplicant associations
  are not, their keys live in userspace; a disconnect clears it), the exact
  BSS is rescanned on its channel and associated again. An unproven stop,
  a refused reset or publication leaves the function terminal with no shell
  (`pinned` recorded for removal when mappings were leaked).
- `Generation::supervise`, spawned after the first publication, checks
  every 100 ms for `Fullmac::transport_failed` (FWHALT, lost power, any
  fatal protocol/access error; broader than Linux, which resets only on
  FWHALT or a debugfs request) and recovers, up to `MAX_RESETS` (64).

Smokes: `smoke_brcmf_fwhalt_reset_reboots_replays_and_rejoins_same_netdev`,
`smoke_brcmf_remove_racing_reset_never_republishes`,
`smoke_brcmf_reset_failures_stay_terminal_or_pinned`.

### Cold resume

Linux v7.2 `pcie.c::brcmf_pcie_pm_leave_D3` resumes hot when `INTMASK`
reads nonzero (D0_INFORM, below); otherwise the dongle lost power or
firmware across suspend and Linux calls `brcmf_pcie_remove` followed by
`brcmf_pcie_probe` on the same function. The `brcmfmac` system-PM resume
hook now calls `native_runtime::resume` -> `Generation::resume`: the hot
path is unchanged, and a `Failed` (cold) resume runs `Generation::recover`
under the generation mutex, i.e. the dead-firmware stop (no D3 ack can
come from lost firmware), `brcmf_pcie_reset_device`, a fresh signed
download, `Station::initialize_live` replay and republication under the
same netdev name. Suspend disconnected the station (Linux
`brcmf_cfg80211_suspend` without WoWL), so nothing is rejoined. A
concurrent supervisor recovery is not repeated: `recover` returns early
when the current generation is no longer terminal. Smoke:
`smoke_brcmf_cold_resume_swaps_generation_and_keeps_netdev` (cold resume
swaps the generation; the next suspend/resume of the rebooted firmware is
hot; removal frees both generations).

### Flow-ring budget

The host flow budget follows the firmware ring info: `max_flowrings`
(shared >= 6) or `max_submissionrings - 2` (shared 5), validated <= 512
by `Runtime::attach` exactly as Linux v7.2 `pcie.c::brcmf_pcie_init_ringbuffers`,
then capped at `BRCMF_FLOWRING_HASHSIZE - 1` (511) as
`msgbuf.c::brcmf_proto_msgbuf_attach` does. Flow ring ids are
`index + BRCMF_H2D_MSGRING_FLOWRING_IDSTART` (2) with TCM index slots
`h2d_{w,r}_idx_ptr + id * 4`, and each 512 x 48-byte ring is allocated on
create and recycled only after a delete completion. The former fixed host
cap of eight flows is gone. Smoke:
`smoke_brcmf_flow_budget_follows_firmware_max_flowrings` (12 firmware
rings open ids 2..13 and refuse a 13th without failing the owner; a
2-ring firmware still bounds at 2).

### System suspend (D3_INFORM) and hot resume (D0_INFORM)

`brcmfmac::register` installs an `AsyncSystemPm` hook ("brcmfmac") — the
async phase that runs while interrupts still service futures, before the
interrupt-gated device fan-out — mirroring Linux v7.2 `brcmf_pciedrvr_pm`
(`.suspend = brcmf_pcie_pm_enter_D3`, `.resume = brcmf_pcie_pm_leave_D3`):

- Prepare: `cyw43439::interface::suspend_pcie` runs Linux
  `brcmf_cfg80211_suspend` without WoWL — a connected station is brought
  down (`brcmf_link_down`: DISASSOC and carrier off) and queued TX dropped —
  then `Fullmac::suspend_transport`. The msgbuf adapter retires every flow
  (delete completions) and outstanding TX within 2 s and calls
  `Runtime::enter_d3` (D3_INFORM / D3_ACK, bus down). A D3 timeout or a
  flow/TX that does not retire returns an error with the transport still UP,
  so the coordinator unwinds the earlier hooks; nothing is lost.
- Resume: `resume_pcie` -> `Runtime::leave_d3`: `INTMASK` nonzero (the
  dongle kept power and firmware) sends `H2D_HOST_D0_INFORM`, re-enables the
  mailbox and rings host-ready over the retained rings; the station may
  then associate again (Linux likewise leaves cfg80211 disconnected). A
  transport that was never suspended refuses resume without failing.

Smokes: `smoke_brcmf_system_suspend_resume_d3_d0_handshake` (D3/D0 words,
mask state, rings retained, second cycle with a lost dongle fails the
owner without freeing DMA, vector released on teardown) and
`smoke_brcmf_system_suspend_timeout_unwinds_usable`.

Cold resume (Linux `cleanup:` -> `brcmf_pcie_remove` + `brcmf_pcie_probe`
when `INTMASK` reads 0) is not replayed: the owner becomes terminal and the
carrier stays down. See the `system_resume`/`transport_reset` rows.

IOMMU-backed quiescence remains open: the proof above holds with the
IOMMU in identity/disabled mode (the only modes the native allocator
accepts; `PerDomain` is refused in `native_runtime.rs::allocate`).
`narf-io` would need a per-device detach that confirms completion — e.g.
`narf_io::iommu::IommuDomain::detach_and_flush(&self, bdf: Bdf) ->
Result<FlushReceipt, IoError>` that clears the DTE/context entry, issues
the device IOTLB invalidation and waits for its completion (AMD-Vi
`COMPLETION_WAIT`, VT-d invalidation-wait descriptor, SMMUv3 `CMD_SYNC`)
before returning — plus a `PerDomain` `alloc_coherent` that maps into that
device's domain. Today `IommuDomain::detach`/`unmap` only adjust counters
and `PerDomain` map/unmap return `NotMapped`.

### Primary-bsscfg firmware-SME AP

The exact retained BCM43602 PCIe adapter opts into `Fullmac::PRIMARY_AP`.
`interface::Device<Adapter>` exposes mode3 only after native initialization
and an actual original PCI/firmware source are available. Mode changes require
an administratively down, disconnected, operation-free physical owner. A
nonwrapping mode generation and exclusive native-control reservation bind
each asynchronous public AP request. No virtual bsscfg, P2P or station-BSSID
alias is created. CYW43439 SDIO now has its own native Card/CM3/SDPCM/BCDC composition
(`cyw43439.md` §3); this PCIe composition itself grants no SDIO authority.

`ap::Session` implements primary interface0/bsscfg0 legacy20 on admitted
2.4/5GHz channels. It retains the original signed-domain Arc, native channel
inventory, occupied-span transmit permission, and original source/role guards.
An equal-byte policy replacement invalidates the old owner. START validates
the entire request before mutation, disables native HT/VHT/WMM and unsupported
ARP/ND offloads, performs the real DOWN/INFRA/AP/chanspec/UP/security/SSID
transactions, and checks actual native AP/rate/BSS109/beacon-period/DTIM
readbacks. These observations establish native BSS configuration, not an
independent over-air beacon receipt. Standard beacon/TIM/DTIM generation is
firmware-owned. SET_BEACON supports validated native vendor-IE replacement;
standard rate/security/geometry changes are refused before publication.
Optional offload GET/SET `BCME_UNSUPPORTED` is handled explicitly: no invented
saved zero or restoration value. A supported write-only disable remains
disabled on restoration; an observed enabled but undisablable engine refuses
AP admission. Missing native evidence never becomes an affirmative receipt.

Every AP Program IOCTL retains its original fixed native/source/policy/role
capture through input DMA, control-ring descriptor, native write pointer and
doorbell publication. Ring setup and the actual native consumer-index read
precede that final scope. A source retired during setup cannot publish an
old command; a possibly issued index/doorbell failure closes the owner and
pins its original DMA until actual whole-device stop. Ordinary station
commands and denial-only AP Stop cleanup retain their existing paths. An
additional native case covers real admin retirement at the setup boundary
and a possibly visible native index failure; execution remains pending.

Program SET also preserves and checks the actual completed native input
prefix: bounded adapter progress retains every event/data record, and the
physical owner checks D2H producer positions after control-ring setup before
final publication. Session and pending SET filters share one native event
transition classifier. Pending BSS/peer denial or replacement cannot be
crossed by an old SET. GET-only firmware queries remain under the same
original final capture and can complete with benign BSS-UP or queued SME
records retained; no query creates a key/port or suppresses later loss.
The existing native publication case additionally injects a real peer-loss
completion during setup, denies stale AUTHORIZE, completes an actual GET
with that event pending, then requires the genuine DEL_STATION observation.

Firmware is the AP SME. Actual ASSOC_IND/REASSOC_IND payload IEs and matching
native `sta_info` authentication/association/rate/MAC observations establish
one of at most8 peers. The frontend advertises `DEVICE_AP_SME` value0 and uses
prepared NEW/DEL_STATION events; it does not synthesize raw AUTH/ASSOC frames
or advertise userspace MLME. Open BSS ports require actual native AUTHORIZE;
WPA2 CCMP AKM1/2 uses userspace EAPOL plus actual `wsec_key` and AUTHORIZE
receipts. HT/VHT, WMM/UAPSD, PMF/IGTK, WPA1, P2P, extra interfaces, CSA and
DFS/CAC are unsupported by this bounded AP profile and remain unadvertised.

Pre-START group keys/default choices are zeroizing software staging under
their original sources. START promotes them only through matching native ADD
receipts. PRIMARY ADD supplies native CCMP GTK transmit selection; Linux's
SET_DEFAULT_KEY does not select a different CCMP slot. A software default
choice can enable group DATA only for that actual most recent native GTK.
Pairwise index0 and group indices1..3 are admitted; native PN/IPN is neither
reconstructed nor exported. A physical-owner lifetime fingerprint history
records material before the first native attempt. An exact current retry
retains its original receipt/source without reinstalling; retired material
cannot be reinstalled after delete/readd or BSS replacement. Pairwise DEL_KEY
uses actual SCB removal, native absence and matching flow/TX retirement,
because Linux supplies no peer-selective OFF encoding. Group OFF uses the
documented PRIMARY slot record. Genuine DEL_STATION follows real native loss;
software port denial alone emits no invented removal event.

Per-destination msgbuf flows preserve original peer/key/port authority across
bounded completed-input drains, native flow creation and TX publication.
Existing native IDs retire only on matching request/flow TX_STATUS. Neither
flow creation nor IOCTL completion supplies packet credit. TX_STATUS here is
a DMA terminal, not a source-backed independent ACK bit: control-port TX status
and GET_KEY sequence capability stay false. Forced-clear control TX after a
PTK install is refused without a native per-frame no-encrypt contract.
EAPOL can arrive in the same native drain as its outgoing M1/M3 terminal;
ordinary DATA serialization does not discard that SME response. Ordinary
0x88c7 preauthentication retains the full original DATA authorization/key
actors on TX and RX. The unsupported no-preauth endpoint option is refused.

The common Session additionally holds at most4 EAPOL records per pending
peer (32 total) under the original native/BSS/peer/copy/source proof and a
counted lease until actual SCB verification; excess peer-controlled frames
are dropped rather than failing the session. Its distinct preverification
purpose cannot transmit or grant DATA/key/port authority. NEW_STATION is
queued first; release moves the same original proof without recapture.
Loss/reassociation/source retirement and STOP discard stale holds. The
existing native RSN case now includes actual same-drain association and
EAPOL-Start, while retaining every later MIC/AES/key/port assertion.

Host receive claims only consumed native descriptor/event plus retained
BSS/peer/key/port/copy generations. Firmware owns CCMP/replay/SCB internals;
Ethernet does not disclose hardware key index, PN or SCB generation. The absent
NO_ENCRYPT event flag supplies no reconstructed encryption assertion. A
completed-prefix drain is not firmware MAC/FIFO RX-key quiescence. Known-peer
copies retain counted leases and original epochs across arbitrary prepared
event callbacks; final native/source/policy/role checks run afterward without
recapturing an endpoint. Native DATA transitions retire queued host originals
and in-flight enqueue epochs. Ring and stack publication are independently
checked. Same-MAC successors require actual native SCB absence, original
flow/TX retirement and a fresh completed-prefix boundary.

STOP/cancellation closes copies/ports first, performs native BSS withdrawal,
requires SCB absence plus actual flow/TX terminals, restores known native
configuration and clears supported key/template slots. A poisoned command
path escalates to the existing original-owner whole-device stop. Unproved
stop/DMA ownership remains pinned or quarantined; no timer, dropped waiter,
card-power assumption or software flag frees it. System suspend stops the AP
before the existing actual D3 handshake; resume does not replay its BSS/keys.
Only a fresh START can create a new owner. Source-safe teardown/recovery keeps
the existing confirmed-stop reclamation rules.

Nine native AP cases are written, unexecuted pending coordinated validation.
They compose actual CR4/common-ring IOCTL/event/flow/TX/RX records through the
public `Device` frontend: Open lifecycle and successor, staged keys/ports and
SCB removal, real MIC/AES-wrapped userspace RSN with same-drain M2/M4, atomic
admission/optional offloads, more than64 pending events before loss/TX, copied
SME peer replacement, independent preauth actors, cancelled native key input,
and policy replacement/system PM. Firmware-internal DATA CCMP/replay and
physical RF/board interoperability are not claimed by the fixture. Sources
are local Linux7.3-rc4 `brcmfmac/{cfg80211,core,msgbuf}.c`, `fwil.h` and
`fwil_types.h`; the handoff saves file hashes and exact source excerpts.

### Native flagged-radiotap monitor

The BCM43602 msgbuf adapter implements an exclusive receive-only mode6 on
its original registered interface. Discovery requires the actual native
`cap` reply's exact `rtap` token, which Linux 7.3-rc4 maps to both
`MONITOR_FLAG` and `MONITOR_FMT_RADIOTAP`. `monitor`, known firmware IDs and
hardware-header formats alone remain unsupported. CYW43439 SDIO monitor
is not enabled by this common frontend.

While administratively DOWN, mode6 changes the netdev representation to
IEEE802.11 radiotap and accepts only flags0 plus an actual inventory and
signed-policy-qualified 20MHz receive channel. It keeps the original policy
Arc, radio/firmware/PCI source, registration/MAC/namespace and nonreviving
mode generation. An actual administrative UP event supplies the original
sealed receiver observation; that observation and the AF_PACKET token
supply no hardware capability. The native path requires GET_MONITOR107=0,
no AP or associated peers, actual `chanspec` SET/readback, SET_MONITOR108=3,
GET_MONITOR107=3, exact channel readback and current format evidence.
Reserving native raw DMA drain before those receipts never activates RX
publication. Linux uses a separate host-only `mon_if`; this bounded NARF
profile uses the existing interface exclusively, with no concurrent station,
AP, additional firmware bsscfg, packet injection or Ethernet ingress.

Only a real msgbuf frame-type2 completion under that retained native owner
can produce a capture. Original posted IDs, completion status, interface,
DMA extents and explicit-versus-shared offset alternatives remain checked;
bytes are copied before the matching native buffer is reposted. Native
radiotap and MPDU bytes pass verbatim to AF_PACKET. The bounded radiotap
header must contain an observed CHANNEL matching the original native RF
owner; configured channel never supplies missing packet metadata. No
signal/rate/FCS/decryption values, over-air ACK or key/replay proof are
invented. A bounded drain must reach the actual completed control prefix
before publishing a batch, while continuous raw RX need not become globally
idle. Copied frames recheck original policy, source, interface, mode and
capture epochs through final publication.

DOWN, policy/source retirement, MAC or role replacement, native channel/loss
events, suspend and removal deny old copies and tokens first. Native stop
requires SET_MONITOR108=0, GET_MONITOR107=0, restoration/readback of the
original chanspec and retirement of the completed prefix before leaving the
reservation. These are filter/control receipts, not a firmware MAC/FIFO
quiescence proof. Cancelled or uncertain commands use the existing physical
whole-device stop and pin/quarantine mappings without fabricated completion.
System resume requires a fresh original UP; it never replays the old token.

Seven written native cases in `drivers/wireless/brcmfmac/monitor` compose
actual CR4/msgbuf5/6/7, version7 prefixes1/4, public mode/channel/admin
controls, literal native radiotap, original AF_PACKET delivery, policy/MAC
retirement, invalid records, activation/cancel, control-prefix progress and
system PM. Execution and software acceptance are pending; no physical RF or
firmware qualification follows from these source fixtures.

### Virtual-interface wire foundation

`brcmfmac::vif_wire` is the shared (PCIe msgbuf and SDIO BCDC) encoding and
host-registry layer that additional interfaces and P2P will compose. It
grants no interface, role, data or transmit authority, and no adapter
advertises an additional interface, P2P or a new monitor role from it.
It mirrors Linux 7.3-rc4: `features` maps only the exact native `cap`
tokens of `feature.c` `brcmf_fwcap_map` (`mbss`, `mchan`, `p2p`, `rtap`)
with `brcmf_feat_attach`'s MBSS exclusion for 4330/43362, using the same
strict bounded C-string rules as monitor/AP discovery. `bsscfg_iovar`
is `fwil.c::brcmf_create_bsscfg` (bsscfg0 is a plain iovar; others are
`bsscfg:` + name NUL + le32 index + data). `vif_mac`,
`interface_create_v{1,2,3}` and `mbss_ssid` reproduce
`brcmf_set_vif_sta_macaddr`, the naturally aligned
`wl_interface_create_v1/v2` (20 bytes) and `v3` fixed part (28 bytes, with
`len`/`fixed_len`/`bssid`/`if_index` left zero as Linux does), and the
legacy `bsscfg:ssid` `ssid<N>` fallback of `brcmf_cfg80211_request_ap_if`.
`IfEvent`/`classify` decode `struct brcmf_if_event` (event 54) and apply
`fweh.c::brcmf_fweh_handle_if_event`: NOIF is ignored unless it is the P2P
device (P2P_CLIENT role, or STA role while P2P-device setup is ongoing),
and out-of-range ifidx/bsscfgidx is dropped. Unlike Linux, a payload
shorter than five bytes or an unknown action/role is malformed rather than
read. `Registry` is `iflist[bsscfgidx]` + `if2bss[ifidx]` with
`brcmf_add_if`/`brcmf_del_if`/`brcmf_get_ifp` semantics: an ADD over a
live nonzero ifidx reports the detached old entry for authority retirement
(nonwrapping generation; it never revives), an ifidx0 ADD over an occupied
bsscfg and DEL of bsscfg0 are ignored, a P2P device bsscfg gets no ifidx
data mapping, and `first_free_bsscfgidx` skips the P2P-reserved bsscfg1.

#### Per-ifidx transport demultiplexing

`Fullmac` now carries secondary firmware interfaces (ifidx
1..`BRCMF_MAX_IFS`) beside, never through, the interface-0 methods:
`VIF_DEMUX`, `vif_listen`, `vif_open`/`vif_close`, `pop_vif_event`,
`pop_vif_data`, `send_vif_data` and `command_vif`. Both native transports
implement it over `brcmfmac::vif_demux` (`Demux`, `route`).

- SDIO BCDC (`cyw43439::runtime`): RX data uses `BCDC_GET_IF_IDX` (BDC
  `flags2` low nibble), TX sets it (`BCDC_SET_IF_IDX`), and IOCTLs carry
  `BCDC_DCMD_IF_SHIFT`. As in `bcdc.c` `brcmf_proto_bcdc_cmplt` /
  `brcmf_proto_bcdc_query_dcmd`, a reply is correlated by its
  `BCDC_DCMD_ID` request id (plus command/direction); its ifidx bits are
  not consulted, so a zeroed or different echo still completes the
  request (`smoke_cyw_f2_secondary_ifidx_demux`).
- PCIe msgbuf (`brcmfmac::runtime` + `station_transport::Adapter`): flow
  rings are keyed by (ifidx, fifo, da) with `create->msg.ifidx`
  (`msgbuf.c::brcmf_msgbuf_flowring_create_worker`), TX posts carry the
  flow's ifidx and IOCTL requests carry `msg.ifidx`. As in Linux, control
  completions are correlated by flow ring id (flow create/delete,
  `brcmf_msgbuf_process_flow_ring_{create,delete}_response`), request id +
  flow ring id (TX status, `brcmf_msgbuf_process_txstatus`) or transaction
  id (IOCTL, `brcmf_msgbuf_process_ioctl_complete`); their completion
  `msg.ifidx` is not consulted, so a zeroed or different echo is not a
  protocol error. RX completions and events accept ifidx < 16. A secondary close deletes only
  that ifidx's flows and reports `Ok(true)` after every delete completion.
- Events: `BRCMF_E_IF` and any event whose header names a nonzero ifidx or
  bsscfg route to the secondary queue (`fweh.c::brcmf_fweh_event_worker`
  handles IF before per-bsscfg dispatch); indices >= 16 are dropped (SDIO)
  or fail-stop (PCIe, unchanged). Secondary events are retained only while
  an owner listens; otherwise they are dropped as Linux drops events for a
  bsscfg without `brcmf_if`.
- Data for an ifidx that its owner has not opened is dropped
  (`brcmf_proto_bcdc_hdrpull` `-EBADE`, msgbuf `brcmf_get_ifp` NULL);
  previously any nonzero ifidx was a fatal protocol error. Interface-0
  queues, flows, AP and monitor ownership are unchanged, and PCIe suspend
  is refused while a secondary interface is open or owns flows.
- Exclusivity is per ifidx, as Linux keys msgbuf flow rings by
  (ifidx, fifo, da) (`flowring.c`) and BCDC data by `flags2` ifidx: the
  primary AP owner needs only interface 0 free of station flows/TX
  (`ap_enter`), its leave/quiet/peer-retire wait only for interface 0
  flows and TX (`Tx.ifidx`), and `vif_open`/`send_vif_data` (PCIe) and
  `send_data_on` (SDIO) stay available during a primary AP. Monitor
  reservation remains device-wide.

One written/unexecuted case: `drivers/wireless/cyw43439/runtime`
`smoke_cyw_f2_secondary_ifidx_demux`. No PCIe msgbuf secondary-ifidx
fixture exists yet.

#### Interface create/remove command owner

`brcmfmac::vif_owner::Owner` (one per transport generation) is the
host `fweh`/`cfg80211` interface owner above the demux. `create(role, mac)`
mirrors `brcmf_apsta_add_vif`: refuse while a vif event is armed, check
`brcmf_vif_add_validate` against the `brcmf_setup_ifmodes` combinations
(`admits`; RSDB not parsed: non-P2P combo0 = 1 STA + 1 AP, P2P combo0 =
STA <= 1 + mchan, P2P combination = STA 1 + AP 1, MBSS = up to 4 AP only),
enable secondary listening, issue `brcmf_cfg80211_request_{sta,ap}_if`
(`interface_create` v1, v2, bsscfg version query, v3; AP-only
`bsscfg:ssid` fallback at `first_free_bsscfgidx`; a STA's caller MAC is
used verbatim, otherwise the alternating `vif_mac` per attempt), then wait
up to `BRCMF_VIF_EVENT_TIMEOUT` (1500 ms) for the native IF ADD and return
its registry `Entry` (event ifidx/bsscfgidx/address). `remove(entry)`
mirrors `brcmf_cfg80211_del_apsta_iface`: `bsscfg:interface_remove` on the
vif's own ifidx, wait for the matching IF DEL, then poll
`Fullmac::vif_close` until the transport retired every native resource of
that ifidx. `service` is the secondary event worker: IF events update the
`Registry`; an unsolicited DEL or a stale-ADD replacement is queued on
`pop_retired` (fweh default `brcmf_remove_interface`); other events are
retained per live (bsscfg, generation) entry for `pop_event`. No netdev or
role is registered by this owner. Three written/unexecuted cases in
`drivers/wireless/brcmfmac/vif` (`vif_owner_tests.rs`) run over the
scripted `fullmac_fixture`, which now implements the secondary seam.

#### Secondary netdev registration/removal owner

`cyw43439/interface_vif.rs` (shared by SDIO CYW43439 and PCIe BCM43602)
is the `core.c` `brcmf_add_if`/`brcmf_net_attach`/`brcmf_remove_interface`
host owner. At attach the primary issues `cap` and, when the transport has
the secondary demux and the firmware answers, keeps one `vif_owner::Owner`
(features from the actual tokens; chip 43439 or 43602 for the MBSS
exclusion) in its state. `Device::new_virtual_interface` (STA/AP iftypes)
admits one create at a time against `Owner::can_add`, then publishes a
`VifDevice` (`narf_net::Interface` + `WirelessNetIface`, same wiphy as the
primary) through `narf_net::registry().register`,
`iface::register_with_context` and the wireless registry, carrier down.
nl80211 NEW_INTERFACE cannot wait on the bus, so, unlike Linux (which
registers the netdev after the 1500 ms IF ADD wait), the primary receive
worker then runs `Owner::create` under the state mutex; the IF ADD address
replaces the provisional MAC (`ifp->mac_addr`), `vif_open` admits the
ifidx, and a refused/timed-out create unpublishes the shell.
`delete_virtual_interface` hides the netdev at once and the worker runs
`Owner::remove`; an unanswered remove still closes the ifidx data via
`vif_close` while the owner keeps counting the firmware bsscfg. An
unsolicited IF DEL (`pop_retired`) unpublishes the shell and polls
`vif_close`. Removal is `iface::unregister`, never `retire_for_rebind`:
a reset does not recreate secondary interfaces; `Device::withdraw`
(`brcmf_detach`) unpublishes every shell of its family first. Live shells
are pumped by the primary worker (`pop_vif_data` into the shell RX ring
and `on_rx_frame_from`, shell TX ring into `send_vif_data` with
`cfg80211_classify8021d` priority, one credit-blocked frame retained),
gated on the shell carrier. Only a secondary station raises that carrier
(below); an AP shell refuses every role operation, and
`supports_virtual_interfaces` stays false (`VIF_ROLES`); nothing is
advertised.

#### Per-bsscfg Fullmac adapter

`brcmfmac::vif_bsscfg::Bsscfg` is the `struct brcmf_if` view of one live
secondary registry `Entry` over the primary transport; it implements
`Fullmac` so the unchanged role state machines can drive that bsscfg.
It borrows the primary runtime, the generation's `vif_owner::Owner` and
a persistent `Link` (entry, bsscfg-local failure, `set_link` peer).
`command` always goes to `command_vif(entry.ifidx)`; a GET/SET_VAR whose
name is one Linux issues through `brcmf_fil_bsscfg_{int,data}_{get,set}`
(`BSSCFG_IOVARS`: actframe, actframe_abort, auth, bip,
interface_remove, join, mfp, p2p_scan, p2p_state, ssid, vndr_ie,
wme_bss_disable, wpa_auth, wsec, wsec_key) is rewritten with
`vif_wire::bsscfg_iovar` (`fwil.c::brcmf_create_bsscfg`); every other
iovar and direct dcmd is sent unchanged to the ifidx (`brcmf_fil_iovar_*`,
`brcmf_fil_cmd_*`). `poll` is the shared transport poll followed by
`Owner::service`; `pop_event` is `Owner::pop_event(entry)` (only that
(bsscfg, generation)); `pop_data`/`send_data` are
`pop_vif_data`/`send_vif_data(entry.ifidx)`. Interface-0 queues are never
read through it. `fail` and a lost entry (IF DEL, stale-ADD replacement)
fail-stop only that bsscfg; queue overflow in `service` fail-stops the
transport as the primary worker does. AP Program, monitor, PM, reset and
stop methods keep their refusing defaults. `Parked<R>` is the inert
runtime a persistent secondary role is held over between operations.
One written/unexecuted case in `drivers/wireless/brcmfmac/vif`:
`smoke_brcmf_vif_bsscfg_adapter_addresses_its_own_interface`.

#### Secondary station role

A STA shell owns a persistent `interface_vif::Secondary`: a `Station`
built by `Station::secondary` from the primary's device-wide state
(channels, regulatory domain/policy, `sup_wpa`/MFP/SAE/`wlc_ver`
capabilities, `roam_off`, PHY) with every per-interface record empty
(no BSSID, cache, PMKSA list, keys or verified PHY), parked over
`vif_bsscfg::Parked`. After the IF ADD and `vif_open` the worker rebinds
it to a `Bsscfg` and issues the per-interface dcmds the primary issues at
initialization on that ifidx (`BRCMF_C_SET_PM` 0, `BRCMF_C_SET_INFRA` 1,
`BRCMF_C_SET_AUTH` 0); a refusal unpublishes and removes the interface.
Join security over the adapter (`Fullmac::BSSCFG`) sets `wsec` as Linux
`brcmf_set_wsec_mode` does, with `brcmf_fil_bsscfg_int_set` (wire
`bsscfg:wsec` + bsscfgidx on the vif ifidx); the primary keeps its
established `BRCMF_C_SET_WSEC` (bsscfg0, plain-iovar equivalent) path.
`scan`/`associate`/`disassociate` on the shell reach the primary through
the type-erased `interface_vif::Roles` (registered per wiphy at
publication) and run the unchanged station state machine rebound to the
adapter under the primary state mutex, with the primary in station mode;
a join requires the secondary to be idle. Each worker pass polls the
secondary (its own bsscfg events only) and makes its correlated
`set_link` peer the shell carrier (drop queued frames and
`notify_disconnect` on loss). A fail-stopped secondary (adapter `fail`,
cancelled operation) retires its interface via `interface_remove`; the
role ends with its shell. Secondary interfaces are created and driven
while the primary is a station or an AP (`ap_mode` 2 or 3; the AP worker
pass also runs `vif_worker`); a primary mode change is validated against
the live secondaries as `brcmf_vif_change_validate` does
(`Owner::can_change_primary`, then `set_primary_role`), so non-P2P
firmware admits primary AP + secondary STA (combo0) and refuses a
primary AP beside a secondary AP without MBSS. STA+STA needs `p2p`
firmware (`p2p`+`mchan` combo0, or the P2P combination). Like Linux
(`num_different_channels` = 1 without mchan), channel agreement between
the primary AP and a secondary STA is left to the firmware; no host
multi-channel scheduling exists.
One written/unexecuted case in `drivers/wireless/brcmfmac/vif`
(`smoke_brcmf_vif_secondary_station_joins_on_its_own_bsscfg`, both the
SDIO and PCIe seam families): create, per-interface dcmds, an Open join
whose dcmds go to ifidx 2 with `bsscfg:wpa_auth` at bsscfg 3, link
events from bsscfg 3 only, no primary link/event disturbance, and a
secondary DEAUTH closing only the secondary port. The BCM43602
CR4/msgbuf model (`station_model.rs`: IF ADD/DEL for ifidx 1 bsscfg 1,
per-IOCTL `msg.ifidx`, per-flow creating ifidx) backs
`smoke_brcmf_msgbuf_secondary_ifidx_ioctl_events_flows_and_removal`
(`vif_msgbuf_tests.rs`, written/unexecuted): IF registration on ifidx 0
with `BRCMF_E_IF` in the written mask, a secondary IOCTL with
`msg.ifidx` 1 completed with a zero completion ifidx, a bsscfg-1 event
reaching only its entry, a secondary flow ring sourced from the VIF
address, and removal while that flow is live (IF DEL on ifidx 1, flow
deleted after its TX status). Mock-seam cases (both families, written/
unexecuted): `smoke_brcmf_vif_event_mask_is_the_union_of_live_owners`
(primary STA + secondary AP need, roam-policy rewrite, removal) and
`smoke_brcmf_vif_primary_ap_keeps_secondary_station_events`.
The msgbuf station model answers ifidx 1 as its own interface
(`Firmware::command_on`): `bsscfg:` + le32 1 iovars are unwrapped, a
secondary `SET_SSID`/`DISASSOC` raises link events on bsscfg 1 only, and
with `Handle::enable_vif_ap` the interface is created as an AP (IF ADD
role 1) backed by its own `ap_model::Profile` (BSSID = the IF ADD
address, SME events re-addressed to ifidx/bsscfg 1, TX of ifidx-1 flows).
`smoke_brcmf_msgbuf_secondary_station_joins_on_ifidx_one` (written/
unexecuted) joins a secondary STA over msgbuf: every join dcmd carries
`msg.ifidx` 1, `wpa_auth` goes out as `bsscfg:wpa_auth`, the link opens
only the secondary port and a bsscfg-1 DEAUTH closes only it.
`smoke_brcmf_msgbuf_primary_station_beside_secondary_ap` (written/
unexecuted) is the combo0 concurrency case on the real PCIe transport:
primary STA joined on ifidx 0, `cap` = `ap sta mchan` parsed by
`vif::discover`, a `VifDevice` AP shell created by the worker, START
through `ApControlAuthority` with the Program entirely on ifidx 1 (no
`BRCMF_C_DOWN`/`apsta`, no `nmode`/`vhtmode`/`qtxpower`, `bsscfg:wsec`,
`event_msgs` still containing the STA events), a peer association
reaching the shell's NEW_STATION, and STOP leaving the primary joined.

#### Secondary AP role

Both transports hold one firmware-SME AP owner per firmware interface
(`Fullmac::SECONDARY_AP` and the `*_on` AP methods). SDIO BCDC
(`cyw43439/runtime_ap.rs`) addresses the AP's dcmds with
`BCDC_DCMD_IF_SHIFT` and its data with BDC `flags2`; its completed
prefix is that ifidx's unconsumed demux records. PCIe msgbuf
(`station_transport.rs`) keeps a per-ifidx owner whose leave/quiet/peer
retirement touch only that ifidx's (ifidx, fifo, da) flows and TX, and
whose IOCTLs carry `msg.ifidx` (`runtime/ap_ioctl.rs`
`command_ap_on`). A Program SET is refused only for retained raw event
records of the target ifidx that the original capture says block it
(`brcmf_fweh_event_worker` dispatches by ifidx) or that do not parse;
unconsumed completion-ring entries are not yet attributed and still gate
every ifidx. Interface-0 ownership is unchanged. While a secondary
AP owns an ifidx, `send_vif_data`/`send_data_on` refuse it and
`vif_close` waits for its leave. `vif_bsscfg::Bsscfg` delegates the AP
methods to its entry's ifidx, applying the bsscfg iovar rewrite to AP
Program dcmds and checking its own retained bsscfg records.

`ap_native::Scope::Secondary` mirrors `cfg80211.c`
`brcmf_cfg80211_start_ap`/`brcmf_cfg80211_stop_ap` for a non-`mbss`
AP vif: `BRCMF_C_DOWN` + `apsta 0` only when the firmware has neither
RSDB nor MCHAN (RSDB, the `rsdb_mode` iovar, is not parsed and is
treated as absent), `mbss 1` before `SET_AP` and `mbss 0` on stop with
`BRCMF_FEAT_MBSS`, and no `nmode`, `vhtmode` or `qtxpower` writes;
`wsec`/`wpa_auth`/`auth`/`mfp`/`wsec_key`/`vndr_ie`/`wme_bss_disable` go
out as bsscfg iovars. Linux never writes `event_msgs` in `start_ap`
(fweh enables every handled event device-wide); the secondary scope
declares the AP SME events as its bsscfg's need in the composed mask
(below) and leaves the firmware mask unchanged on stop.
`Session::prepare_secondary` builds such an AP; the primary Program is
unchanged and refuses to run through a bsscfg view (`Scope::admits`).

An AP shell (`interface_vif_ap.rs`) owns its own `interface_ap::Host`
(mode generation, control reservation, staged keys, event source) and,
after the IF ADD, the same parked secondary `Station` as a STA shell (no
dcmds: Linux issues none for an AP vif before `start_ap`). Its
`WirelessNetIface` AP methods reach the primary through
`Roles::vif_ap_control`, which applies the primary frontend's
request/emission/fixed-capture checks with the shell as receiver and
runs the unchanged `Session` operations (start with staged keys, stop,
beacon, station authorize/delete, key ops, control port TX) on the
station rebound to the `Bsscfg`. The carrier is up between a committed
START and STOP/failure. Each worker pass services the session, sends one
retained shell frame under its original data capture, and delivers
received data/events after the state lock, each behind the bsscfg's
completed-prefix final check. Removal stops a running AP first; a failed
stop fail-stops the bsscfg and the ifidx's AP owner retires its own
flows/TX (`ap_leave_on`) before `vif_close`. Only one AP may run: a
secondary START is refused beside the primary or another secondary AP
(Linux `vif->mbss` path not implemented), and a primary START is refused
while a secondary AP runs. Known gap: channel agreement with a primary
STA is left to the firmware (no mchan scheduling).

#### Composed event mask

The firmware has one device-wide `event_msgs` mask. Linux registers
handlers per event in `fweh` and `fweh.c` `brcmf_fweh_activate_events`
writes their union plus `BRCMF_E_IF`; no role writes a private mask.
`brcmfmac::event_mask::Composition` (held in each transport's
`vif_demux::Demux`, so a PCIe generation reset starts empty like the
rebooted firmware) records one need per owner — `Need::Primary`
(interface-0 role), `Need::Interfaces` (the secondary registry:
`BRCMF_E_IF` while it listens) and `Need::Secondary(ifidx)` — and every
`event_msgs` writer sends the union through `Fullmac::events_compose`
and records it with `events_written`. A `vif_bsscfg::Bsscfg` view maps
`Need::Primary` to its own `Need::Secondary(ifidx)`. Writers: station
initialization and `set_firmware_roaming` (`station::write_events`, the
STA events ± `BRCMF_E_ROAM`), the AP start (`AP_EVENTS`) and primary AP
restore (`ap_native`), `vif_owner::create` (`BRCMF_E_IF`, written only
when it adds the bit) and `Station::configure_secondary` (the secondary
STA's events, written only when they add bits — e.g. beside a primary
AP, whose own need holds only AP events). `vif_owner::remove` withdraws
the removed ifidx's need (and the registry's after the last interface)
without a write; the next writer drops those bits. A primary AP stop
restores the firmware mask it saved at start as the primary need, so
bits that were live then stay set until the next station write.

Still missing before `virtual_interfaces`/`p2p_mode` can be claimed on
either family: secondary-ifidx fixtures and advertisement, and for
P2P the `p2p.c` discovery bsscfg (`p2p_disc`, `p2p_ifadd`/`p2p_ifdel`,
`bsscfg:p2p_da_override`), action-frame TX/RX and GO negotiation owners.
Three literal wire/registry cases in `drivers/wireless/brcmfmac/vif` are
written for this foundation.

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

The retained initial profile is shared 5/6, zero descriptor prefix, MSI or polled mailbox service,
2.4/5 GHz Open or firmware-supplicant WPA2-PSK/CCMP, with one-shot terminal failure
and retention of published DMA unless a confirmed stop proves it reclaimable. Its remaining deployment requirements
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

Negotiated `wme_ac_sta` WMM state and all-priority data are common FullMAC
work ([CYW §3](cyw43439.md) "Negotiated WMM state and all-priority data").
On msgbuf the station keeps one flow per `brcmf_flowring_prio2fifo` FIFO,
created with the first frame's priority as TID, and
`Runtime::send_with_priority` posts each frame's own priority in the TX
descriptor flags (`BRCMF_MSGBUF_PKT_FLAGS_PRIO_SHIFT`); a priority from a
different FIFO is a protocol error. Smoke: `drivers/wireless/brcmfmac/wmm`.

Additional software outside that retained profile remains: descriptor
prefixes exceeding the admitted shared7 slack, other CPU/RAM/chip/OTP selectors
(including 160 MHz-capable
chips), HE/EHT profiles, monitor formats outside the bounded native
radiotap owner above, AP, replayed
recovery/system PM, IOMMU-backed quiescence.
These do not expand the initial retained-failure acceptance claim.
WPA3-SAE offload (WCC `WSEC_PMK` passphrase ABI), the PMKSA cache, firmware
roaming/FT, per-AC telemetry and host-supplicant fallback are common FullMAC
work shared with CYW; see [CYW §3](cyw43439.md).

Native802.11 receive is not a separate station feature: Linux
`msgbuf.c::brcmf_msgbuf_process_rx_complete` hands a completion flagged
`BRCMF_MSGBUF_PKT_FLAGS_FRAME_802_11` only to `brcmf_netif_mon_rx`
(`core.c`), which strips or converts its metadata according to
`BRCMF_FEAT_MONITOR_FMT_RADIOTAP`/`_HW_RX_HDR` after `BRCMF_C_SET_MONITOR`.
Station firmware delivers802.3 frames. Native802.11 RX and RX metadata are
therefore provided only by the bounded native monitor owner above;
ordinary station RX remains Ethernet.

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
