# Broadcom FullMAC PCIe — software bring-up

> Status: v0.7. Signed exact board provisioning, BCM43602 CR4 firmware, retained
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
`provision().await` retries newly staged assets/policy only while Parked. Missing,
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

`src/brcmfmac/provision/make_manifest.py input.json output.bin` encodes explicit
board facts and hashes actual payload files. Input records supply family, board,
revision mask, full host identity, SDIO card tuple when applicable and ordered
asset key/path/signed entries. `wrapped:true` explicitly strips an existing NRFW
envelope before hashing; paths otherwise denote raw payloads. Sign/package the
output with `cargo xtask pack-firmware --payload ... --name
brcm/wifi-board-selection-v1.bin --signature ... --public-key ... --out ...` and
stage that manifest plus exactly named assets through the existing firmware loader.
The tool supplies no board default or signer authority; `--fixtures` emits only
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
2.4 GHz Open or firmware-supplicant WPA2-PSK/CCMP, with one-shot terminal failure
and permanent retention of published DMA. Its remaining deployment requirements
are real target identity/calibration/firmware assets, a verified selection manifest
(or trusted platform registration), authenticated regulatory policy and physical
station acceptance. No deployment board is manufactured by these tests.

Additional software outside that retained profile remains: nonzero descriptor
prefixes/shared 7, other CPU/RAM/chip/OTP selectors, broader bands/widths, native802.11
RX/metadata, larger flow budgets, host-supplicant fallback, WPA3/AP, replayed
recovery/PM, confirmed stop/IOMMU quiescence and DMA reclamation, and IRQ delivery.
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

Independent Python `struct`/`hashlib` NBSP literals also feed actual Ed25519
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
