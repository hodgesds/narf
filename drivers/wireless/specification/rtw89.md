# rtw89 — Specification

> Status: AX factory identity, checked firmware preparation, native cold-power
> primitives and bounded native TX ownership are implemented. The composed
> firmware/station owner remains incomplete.

## 1. Purpose & scope

Owns RTL8852A/B/C, RTL8851B and planned RTL8922A PCIe support. Current live
identity code implements AX DDV EFUSE; BE has a different read/block layout.

## 2. Assumptions

The caller owns BAR2, mapped with Device attributes and covering the register
window. The diagnostic probe still uses its existing power prologue; the new
cold-power owner must be composed with firmware/secure-fuse and CH12 setup
before replacing that path. No factory-MAC result establishes station readiness.

## 3. Public interface

`pci::bring_up(device, cap)` first parks inherited PCI DMA through the shared
Realtek command policy: clear `BUS_MASTER`, enable `MEM_SPACE | INTX_DISABLE`,
and read back the command register. Any access failure, retained BME or missing
requested decoding fails before BAR mapping. Bus mastering remains disabled
on success and every later error; identity and ring allocation do not authorize
DMA. A repeat probe of the retained bus address returns without configuration access; a distinct additional singleton match parks only its own PCI function. Re-enabling
BME requires a future complete firmware/ring/reset owner.
The complete diagnostic mapping/power/identity operation runs within actual
capability invocation. It retains unpublished storage, with no ring base/index
publication, enabled MSI-X delivery, RX pump or network-interface registration.
The private native TX/report hooks also invoke the retained device capability;
revocation returns `Authority` before register access or packet allocation.

The internal `prepared::load(Files, ChipId, physical_cut)` selects owned
verified firmware snapshots. AX filenames use the Linux `rtw89/rtw8852*_fw`
and `rtw8851b_fw` basenames, preferring supported format suffixes before the
unversioned fallback. Only a missing file permits filename fallback; invalid
images or missing/revoked authority abort. 8852B/8851B prefer the NORMAL_CE
image, then NORMAL. MFW selection bounds every entry before choosing the
nearest non-manufacturing cut at or below the physical revision. BE is rejected
before file access. The native registry adapter copies bytes inside the actual
firmware capability invocation.

`fwdl::parse_auto` accepts AX header versions0/1 only: base sizes32/48 and
section size16 in both versions. Inner section types remain four bits; BBMCU
is an outer image type. AX download chunks are2020 bytes independent of header
version. Header/table/dynamic-extension/payload extents and indexed/formatted
MSSC signature pools, including v1 DSP checksums, are checked before committing
caller section output. A malformed image leaves that output untouched.
`PreparedFirmware` keeps selected-image, payload and signature-pool offsets
bound to one immutable owner and physical chip profile. The private
`DownloadPlan` combines that owner with successfully read physical secure
fuses. Unknown programmed fuses fail explicitly; erased selection is accepted
only after both actual DDV bytes are read. Indexed and formatted signatures
use the Linux AX selection/stride rules, checked bitmap dimensions/rank and
pool extents. Secure hardware requires a matching signature and a host
blacklist at least as new as the image's version; B/C have the upstream
version0 empty policy, while A/51 require an authenticated board policy.
No missing policy or signature falls back to an unsecured transfer.

The plan couples v1 ignored-security descriptor compaction/count with the
same payload selection, strips host dynamic bytes and sets part_size2020.
B's secure v0 length960 override changes both descriptor and payload; ambiguous
checksum-bearing overrides and v0 ignored-descriptor cases fail explicitly.
Signatures replace bytes only in owned output, preserving the verified image.
Header H2C requests no runtime ACK; section chunks are raw firmware bytes
without an invented H2C/last flag. This prepares transfers but does not
establish CH12/WCPU ownership or start a download.

The private `command_native::Native` CH12 backend owns checked coherent packet
and ring allocations. Constructor/configuration require independently fenced
DMA and verified PCI BME-off; activation separately requires completed
PCIe/BDRAM/DLE/HFC setup, CH12-only TX DMA and verified BME-on. The backend
does not enable BME itself, and rejects the incomplete per-domain IOMMU path.
All register operations invoke current device authority and check complete
width/alignment extents. Real revocation rejects the constructor before
unmapped configuration access and prevents later packet publication.

Firmware commands have a24-byte TXWD body on A/B/51 and a16-byte RX-like
descriptor on C. TXBD length includes descriptor plus command bytes; there
is no WP/address-info extension. Hardware RP is bits27:16 and host WP bits11:0;
host doorbells write only the low16-bit half. `CommandQueue` retains mappings
before descriptor/doorbell publication, validates whole read-pointer movement
before retirement, and preserves the last eight consumed commands for the
Linux multi-tag delay. Failed publication and Drop retain queued/quarantined
DMA and the published ring. Only an independent hardware stop/idle/prefetch
fence permits explicit reclamation; capability revocation or BME-off alone
does not establish that proof. The backend remains inactive in the diagnostic
probe until the complete PCIe/WCPU startup owner is implemented.

`power::Power<Io>::power_on` ports the complete PCI RTL8852A byte table and
RTL8852B/C/8851B power-on callbacks, including XTAL commands, cut/RFE/SPS
quirks, power/ONMAC deadlines, platform edges, isolation and function enables.
`power_off` ports the A off table and B/C/51 callbacks, preserving corrected
physical-cut and calibration identity. It requires independently stopped/fenced
DMA, verified PCI BME-off and serialized producers; it does not grant a DMA
reclamation proof. Callback completion plus explicit MAC-OFF readback permits
the same profile to power on again. `normalize_inherited` applies that off/on
sequence to an inherited ON MAC; unknown transitional states fail explicitly.
Failure/cancellation leaves Starting or Stopping and rejects replay before
further I/O. The native backend checks live capability, extent
and width alignment for every register operation, and provides asynchronous
DDV reads for ECV/secure/factory bytes. Cancelled or incompletely restored DDV
power-cut state stays retained and refuses reuse. These primitives do not yet
activate CH12, publish a station or establish complete MAC/RF readiness.

`fifo::Fifo::prepare` implements the AX firmware-download DLE/HFC pre-init:
per-chip MAC/DMAC and internal AXI enables, WDE64/PLE128 geometry, DLFW quotas
with the SCC WCPU minimum, bounded WDE/PLE readiness, and CH12-only host flow
control. 8852C uses its V1 HFC register page. Independent Linux C traces cover
all four AX profiles with inherited zero and nonzero register seeds. The
operation requires a powered, serialized, DMA-fenced device with PCI BME off;
it publishes no system-memory rings. Failure or cancellation retains
Configuring and refuses replay. PCIe quirks/BDRAM, CH12 DMA and WCPU composition
remain necessary before this private primitive can be activated.

`efuse::read_mac(registers, ChipId, cut)` runs the AX DDV read lifecycle and
decodes the two-byte sparse records. All four AX profiles use a 1216-byte
physical map with four-byte security prefixes/tails. Logical size is 1536 on
8852A and 2048 on the other AX profiles; PCI MAC is at logical `0x400`.
Offsets were independently checked with C `offsetof` using Linux's structs.

8852A selects/verifies Wi-Fi bank zero. Other AX profiles configure DDV power
cut and undo it after success or timeout; 8852B cut A additionally enables and
clears burst mode. Invalid maps/identities fail explicitly. RTL8922A is
rejected before applying the incompatible AX EFUSE/power sequence.

`tx_transport::prepare_header(chip, info, sequence, frame_dma, frame)` prepares
AX PCI body/WP/address-info records for an initial unprotected, non-QoS,
three-address native profile. It rejects unsupported BE, wrong QSEL/channel,
fragmentation, optional headers, and address extents outside the 40-bit baseline
or 36-bit 8852C address format. Baseline uses a 24-byte body and eight-byte
address info; 8852C uses a 32-byte body and six-byte segments of at most 2044
bytes. TXBD length covers only the descriptor header, never the native payload.
The body-only legacy `datapath::stage_tx` codec is not a PCI submission.

`TxQueue<T>` owns at most the configured ring depth (2..512), reserves a slot,
retains before publication, and transfers ownership only after both TXBD
consumption and an identity-matched AX RPQ release. Stale/contradictory records
and invalid read-pointer movement are explicit errors. Unpublished reservations
can be aborted. Drop cannot prove device quiescence and conservatively retains
outstanding published resources; reset/removal reclamation remains required.

The retained device backend `submit_native` and `complete_native_report` are
private unsafe integration points with an explicit initialized/live-ring and
no-reset contract. They allocate masked DMA, retain header plus payload, perform
cache maintenance and order publication before the doorbell. They have no
station/firmware producer or RPQ pump caller yet. The registered Ethernet
`pci::send_frame` rejects before allocation or MMIO until those owners and
Ethernet-to-native encapsulation exist.

## 4. Invariants

Physical reads write the address and wait for the hardware ready flag before
consuming data. Bounds exclude security control bytes. Missing logical words
remain erased and later records override earlier words. Failures cannot leak
EFUSE power-cut/write-mask/burst settings. TXBD consumption alone cannot free
a packet still referenced by firmware. A report alone cannot recycle a BD still
referenced by DMA. Ring wrap cannot overwrite either retained allocation.

## 5. Architecture notes

EFUSE/register-model tests run on both architecture builds. PCIe DMA/address
width, device ordering and completion lifetime require independent qualification.

## 6. Dependencies

`narf-bus` provides Device BAR mappings, scheduler/time provide responsive
bounded waits, and the firmware registry will supply authenticated images.

## 7. Stage assignment

AX identity is software covered. Existing packet descriptor/ring code is
bring-up scaffolding and does not establish a working station runtime.

## 8. Open questions / remaining software

| Prerequisite | State |
|---|---|
| AX DDV factory identity and cleanup | Implemented; shared-path regressions |
| Complete per-chip power/PCIe initialization | Native power-on/off, inherited-state normalization and DLFW DLE/HFC primitives implemented with Linux-C traces; probe composition and full PCIe/BDRAM setup remain |
| Firmware container/profile selection, CH12 DMA, WCPU handshakes | Checked AX selection, native fuse reads, coupled secure plans and native CH12 ownership implemented; full PCIe activation and WCPU lifecycle remain |
| Ring quiesce/publication, BDRAM setup, IRQ ownership and recovery | Incomplete |
| AX initial native TX layout and bounded completion ownership | Shared production backend implemented and model-tested; not yet activated by station/firmware owner |
| RPQ release handling, RX assembly/validation and frame delivery | Incomplete |
| RF/BB calibration, regulatory channel/power and coexistence | Missing |
| Scan, real management MLME, WPA2 keys/controlled port, Ethernet data | Missing |
| BE EFUSE/block format and BE transport | Missing |
| Reset/removal/suspend and multi-device lifetime | Missing |

References: Linux `rtw89/efuse.c`, `rtw8852a.h`, `rtw8852b_common.h`,
`rtw8852c.h`, `rtw8851b.h`, `core.c::rtw89_core_get_ch_dma`,
`pci.c::{rtw89_pci_txwd_submit,rtw89_pci_release_txwd_skb,rtw89_pci_fill_txaddr_info,rtw89_pci_fill_txaddr_info_v1}`,
and per-chip PCI configuration.
