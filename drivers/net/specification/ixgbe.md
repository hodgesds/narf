# ixgbe — Specification

> Status: **v0.2 — multi-queue, RSS, VLAN, WoL, PM, ethtool** (Stages 1-6 as v0.1, plus §9
> multi-queue addressing; RSS/VLAN/WoL/PM/ethtool land in later
> commits of the same stream).
>
> Clean-room driver for the Intel 82599 / X540 / X550 10 GbE
> controller family. Reference material: the public
> *Intel 82599 10 GbE Controller Datasheet* (rev. 3.3) plus the
> matching X540 / X550 datasheets. No GPL Linux `ixgbe` source
> consulted.

## 1. Scope

Owns the full bring-up of an 82599-class NIC: PCIe BAR0 mapping,
documented `CTRL.RST` reset, EEPROM-backed MAC read, TX/RX
descriptor rings per configured queue (advanced TX layout, legacy
RX layout for simplicity), MSI-X vectors per queue (or one shared
misc vector for 1/1), and a `HwNic` adapter exposing the same
surface the e1000/mlx5 drivers do.

Does NOT own: FCoE, RSS.

## 2. PCI match

| device     | vid    | did    |
|------------|--------|--------|
| 82599EB    | 0x8086 | 0x10FB |
| X540-AT2   | 0x8086 | 0x1528 |
| X550       | 0x8086 | 0x1563 |
| X550EM_x   | 0x8086 | 0x15AB |

## 3. Register surface (BAR0)

All registers are 4-byte little-endian (host order). Offsets per
82599 §8.2.

| offset    | name      | notes                                |
|-----------|-----------|--------------------------------------|
| 0x00000   | CTRL      | Device Control (RST = bit 26)        |
| 0x00008   | STATUS    | LAN_ID + LINK_UP                     |
| 0x00018   | CTRL_EXT  | Extended Control (DRV_LOAD = bit 28) |
| 0x00800   | EICR      | Extended Interrupt Cause             |
| 0x00808   | EICS      | Extended Interrupt Cause Set         |
| 0x00810   | EIAC      | Extended Interrupt Auto-Clear        |
| 0x00880   | EIMS      | Extended Interrupt Mask Set/Read     |
| 0x00888   | EIMC      | Extended Interrupt Mask Clear        |
| 0x00890   | EIAM      | Extended Interrupt Auto-Mask         |
| 0x00898   | GPIE      | General-Purpose Interrupt Enable     |
| 0x00900+  | IVAR[n]   | Interrupt-vector allocation (n=0..63, 2 queues each) |
| 0x00A00   | IVAR_MISC | Misc (OTHER) interrupt-vector allocation |
| 0x00AA0   | EIMS_EX0  | Extended interrupt mask set, queues 0..31 (per-queue vectors) |
| 0x00AA4   | EIMS_EX1  | Extended interrupt mask set, queues 32..63 (per-queue vectors) |
| 0x00AD0   | EIAM_EX0  | Extended interrupt auto-mask, queues 32..63 |
| 0x01000+0x40*n | RDBAL[n] | RX desc base low (n=0..63; n=64..127 at 0x0D000+0x40*(n-64)) |
| 0x01004+0x40*n | RDBAH[n] | RX desc base high                    |
| 0x01008+0x40*n | RDLEN[n] | RX desc length                       |
| 0x01010+0x40*n | RDH[n]   | RX desc head                         |
| 0x01014+0x40*n | SRRCTL[n] | RX split control (0x02100+4*n alias for n=0..15) |
| 0x01018+0x40*n | RDT[n]   | RX desc tail                         |
| 0x01028+0x40*n | RXDCTL[n] | RX queue Enable (bit 25) + VME (bit 30) |
| 0x03000   | RXCTRL    | RX master enable (bit 0 = RXEN)      |
| 0x05080   | FCTRL     | Filter Control (BAM/MPE/UPE)         |
| 0x05088   | VLNCTRL   | VLAN Control (VET/VFE, see §11)      |
| 0x05800   | WUC       | Wake Up Control (PME_En bit 1, see §12) |
| 0x05808   | WUFC      | Wake Up Filter Control (see §12)     |
| 0x05810   | WUS       | Wake Up Status, RW1C (see §12)       |
| 0x0A000+4*n | VFTA[n] | VLAN Filter Table Array (n=0..127, see §11) |
| 0x0A200+8*n | RAL[n]  | Receive Address Low                  |
| 0x0A204+8*n | RAH[n]  | Receive Address High (AV = bit 31)   |
| 0x06000+0x40*n | TDBAL[n] | TX desc base low (n=0..127)      |
| 0x06004+0x40*n | TDBAH[n] | TX desc base high                    |
| 0x06008+0x40*n | TDLEN[n] | TX desc length                       |
| 0x06010+0x40*n | TDH[n]   | TX desc head                         |
| 0x06018+0x40*n | TDT[n]   | TX desc tail                         |
| 0x06028+0x40*n | TXDCTL[n] | TX queue enable (bit 25) + thresholds |
| 0x08120   | MTQC      | Multiple TX Queues Command (0 = non-DCB/non-VT, queues 0..63) |
| 0x05C00+4*n | RETA[n] | RSS redirection table (n=0..31, see §10; native alias 0x0EB00+4*n) |
| 0x05C80+4*n | RSSRK[n] | RSS random key (n=0..9, see §10; native alias 0x0EB80+4*n)    |
| 0x05818   | MRQC      | Multiple RX Queues Command (see §10; native alias 0x0EC80) |
| 0x04200   | LINKS     | LINK_UP = bit 30                     |
| 0x04074   | GPRC      | Good Packets Received Count (RC, see §13) |
| 0x04080   | GPTC      | Good Packets Transmitted Count (RC, see §13) |
| 0x01030+0x40*n | QPRC[n] | Queue packets received count, RC (n=0..15, see §13i) |
| 0x06030+0x40*n | QPTC[n] | Queue packets transmitted count, RC (n=0..15, see §13i) |
| 0x10010   | EERD      | EEPROM Read (legacy 82599 path)      |

Per-queue stride is 0x40 bytes. RX queues 0..63 use the 0x01000
bank; RX queues 64..127 use the 0x0D000 bank. TX queues use one
0x06000 bank for 0..127.

> Correction note (2026-10-31, datasheet §8.2): the v0.1 table
> listed IVAR at 0x01000, IVAR_MISC at 0x011E0, GPIE at 0x00A50,
> EIAM at 0x00A90, RDBAL at 0x02100+, and RAL at 0x05400. All six
> were wrong — 0x01000 is RDBAL[0], 0x00A90 is EICS[1], and
> 0x02100 is the SRRCTL alias range. The table above is the
> datasheet-grounded version, and `enable_msix_vector` was fixed
> to match (it had been routing MSI-X vectors into RDBAL[0]).

## 4. EEPROM read (82599 §10.2.4.2)

```
EERD = (addr << 2) | START(1<<0)
poll EERD.DONE (bit 1) up to ~10 ms
data = EERD >> 16
```

MAC bytes 0..2 live at EEPROM word 0; bytes 2..4 at word 1; bytes
4..6 at word 2 (byte-swapped per word — low byte = even index).

## 5. TX descriptor format (advanced TX, §7.2.3.2.4)

```
struct AdvTxDesc {
    addr:        u64,    // buffer phys
    cmd_type_len:u32,    // [29:24]=DTYP, [27]=DEXT, [25]=RS, [24]=EOP, [23:0]=DTALEN
    olinfo:      u32,    // [13:0]=PAYLEN, [3:0]=CC, [16]=IXSM, [13:0]
}
```

Stage 3 cut: legacy descriptor isn't supported on 82599 — we use
the advanced (DEXT=1) layout with `DTYP = 0x3` (Advanced Data
Descriptor).

## 6. RX descriptor format (legacy, §7.1.5)

Same 16-byte legacy layout as e1000:

```
struct RxDesc {
    addr:    u64,
    length:  u16,
    csum:    u16,
    status:  u8,
    errors:  u8,
    special: u16,
}
```

## 7. MSI-X (Stage 5)

82599 supports up to 64 MSI-X vectors. We allocate one shared
"misc" vector (link/RX/TX collapsed) for Stage 5. IVAR[0] maps
queue 0's RX/TX onto that vector; OTHER_CAUSES_IVAR routes
link-state changes to it as well. The bus-side `enable_msix`
helper does the table programming.

Per-queue vectors (`enable_msix_queue_vectors`) route RX queue
`q` and TX queue `q` to vector `q` (the Linux q_vector shape)
via `route_all_queue_vectors`, with the OTHER cause sharing
vector 0; queue causes are unmasked via EIMS_EX(0/1) and the
OTHER cause via EIMS bit 31 (EIMS_OTHER); EIAM/EIAM_EX0
auto-mask the same sets. The datapath stays polled — no
production path consumes these interrupts yet — so this is
routing + unmasking, not ISR wire-up. The EX-mask register
addresses were cross-checked against Linux ixgbe_type.h @
cbbddb6 (IXGBE_EIMS_EX / IXGBE_EIAM_EX / IXGBE_EIMS_OTHER);
all other layout in this spec is datasheet-sourced.
`enable_msix_vector` (single shared misc vector) remains as the
1/1 alternative; the two must not both run.

## 9. Multi-queue (v0.2)

`drivers/net/ixgbe/src/ixgbe/queues.rs` owns queue addressing:
`rx_queue_regs(q)` / `tx_queue_regs(q)` (stride 0x40, second RX
bank for 64..127), `QueueConfig` validation (live cap 64 queues,
ring length a power of two in 32..=4096), and IVAR routing
(`route_queue_vector` / `route_queue_vector_dir` /
`route_misc_vector`: one IVAR per two queues, RX/TX fields +
valid bits per §8.2.3.5.16; OTHER cause via IVAR_MISC bits 14:8 +
valid bit 15). `Ixgbe::bring_up_with_config` allocates and
programs TX/RX DMA rings for every configured queue
(`program_tx_queue` / `program_rx_queue`, shared with the
fake-bank fixtures) and spawns a per-queue pump set: one RX pump
per RX queue (all fanning mirror copies into the one
`rx_mirror` producer; only queue 0's pump observes the link),
one TX pump per TX queue fed by a round-robin dispatcher from
the stack-facing channel (no flow steering — RSS steering stays
opt-in via `configure_rss`); a single-TX-queue config keeps the
direct pump with no dispatcher hop, so the 1/1 topology is
unchanged. `Ixgbe::bring_up` is the 1/1 case of the same path.
`Ixgbe::num_tx_queues` / `num_rx_queues` (exposed via both
`HwNic` and `narf_net::Interface`) report the configured counts,
and `queue_affinity(q)` reports vector `q` for configured queues
(boot CPU; pumps are unpinned). Per-queue MSI-X vectors are
`enable_msix_queue_vectors` (see §7). Fixtures replay the queue-0
register conversation on a fake bank, plus multi-queue
conversations (queues 0..3 + 63), IVAR sibling-preservation
checks, and the full vector routing table (including asymmetric
configs) — all through the same production helpers bring-up uses.

## 10. RSS

`drivers/net/ixgbe/src/ixgbe/rss.rs` programs RSS-only mode
(MRQC at 0x05818, MRQE = 0001b = single 16-queue set, all six
hash-field enables: TcpIPv4/IPv4/IPv6/TcpIPv6/UdpIPv4/UdpIPv6),
the 40-byte key into RSSRK[0..9] (0x05C80 + 4*n, little-endian
words), and the 128-entry balanced indirection table into
RETA[0..31] (0x05C00 + 4*n, 4-bit entries). The key and table
come from `narf_net::rss` (standard conformance key + balanced
table), so hardware steering equals `RssConfig::rx_queue` for
the same frame — fixtures assert that agreement plus the
MRQC/RSSRK/RETA register conversation on a fake bank.
`Ixgbe::configure_rss(queues)` (1..=16) programs and records
the state; `HwNic`/`Interface::rss()` expose it and `caps()`
gains `RSS` once programmed. Bring-up leaves RSS off (queue 0
only) until configured; reprogramming requires RX disabled.
FlowDirector/ATR stays a follow-up (§14).

Register-map authority (issue #1397, resolved): the 82599
datasheet (rev. 2.6, 322429-007) dual-maps MRQC/RSSRK/RETA —
§8.2.3.7.12 lists MRQC at 0x0EC80 / 0x05818, §8.2.3.7.14 RSSRK
at 0x0EB80 / 0x05C80, §8.2.3.7.15 RETA at 0x0EB00 / 0x05C00,
each "also mapped ... to maintain compatibility with the
82598". Neither the old RSS path (0x0E block) nor the VMDq
path (0x05 block, PR #1398) programmed a wrong register: both
aliases are the same physical registers. `ixgbe/regs.rs` is the
single authority both paths must import (canonical = 0x05
block, following Linux's shipping map; native aliases kept
as pinned constants, not programmed), and the alias-map
fixture pins the pairing. The remaining VMDq+RSS composition
work is the MRQE mode value (0xB = 64 pools + RSS per
§8.2.3.7.12) + per-pool RETA, on the VMDq path — not an
address question.

## 11. VLAN filtering

`drivers/net/ixgbe/src/ixgbe/vlan.rs` programs the 4096-bit
VLAN filter: VFTA[0..127] at 0x0A000 + 4*n (bit i of register n
passes VID 32*n+i) plus VLNCTRL at 0x05088 (VET 0x8100, VFE
bit 30, optional CFI/CFIEN bits 28/29). `Ixgbe::configure_vlan`
programs and records the filter (caps gain `VLAN_TAGGING`);
`clear_vlan` restores the empty table + VFE off;
`set_vlan_strip(q, enable)` toggles per-queue RXDCTL.VME
(bit 30, strip the tag on that queue's 802.1Q frames).
Untagged frames are unaffected by the table. NOTE: this
driver still uses legacy RX descriptors, so a stripped tag's
VLAN field is not yet surfaced to the stack — the advanced-
descriptor migration that reports it is a follow-up (§14).

## 12. Wake-on-LAN

`drivers/net/ixgbe/src/ixgbe/wol.rs` programs the 82599 wake
filters: WUFC at 0x05808 (LNKC 0, MAG 1, EX 2, MC 3, BC 4, ARP 5,
IPV4 6, IPV6 7, FLX0..5 16..21), WUC at 0x05800 (PME_En bit 1,
PME_Status bit 2), WUS at 0x05810 (RW1C, same bits + MNG 8),
IP4AT at 0x05840 + 8*n (n = 0..3) and IP6AT at 0x05880 + 4*n.
`Ixgbe::configure_wol` arms (clear status, program WUFC, set
PME_En) and records the config; `wol_status` decodes WUS.
Per-part rule: 82599EB by its datasheet rule; X540/X550/X550EM_x
only when the board record permits (Linux EEPROM-cap rule — see
§13g). Nothing arms by default: without a permitting record,
X540+ stays unarmed, and X550's LOM/board gating IS the record.
IPAV is programmed (§13h): the datasheet
prints its address as 0x5838 (leading zero dropped in
extraction); Linux normalizes it to 0x05838, and §13h pins
the valid-bit layout.

## 12b. Power management and detach

`drivers/net/ixgbe/src/ixgbe/pm.rs` implements the PM plans on
a fake bank (fixtures assert the register conversations):
`suspend_plan` masks all interrupts (EIMC = all-ones), clears
RXEN (RXCTRL 0x03000 bit 0), disables queue 0 (RXDCTL/TXDCTL
ENABLE bit 25 cleared), clears wake status, and arms WoL when
given a config; `resume_rebuild_plan` rebuilds the DMA rings
in place (see §13l) and re-enables RXEN and the misc vector
(EIMS = 1); `detach_plan` suspends with no WoL and clears
CTRL_EXT DRV_LOAD (bit 28, set at bring-up).
`Ixgbe::suspend(wol)` / `resume()` / `prepare_detach()` drive
the plans and the `quiesced` flag, which makes `tx`/`tx_frame`
refuse and RX report nothing while set (pumps cannot be
cancelled — they hold Arc clones). `detach_controller()`
additionally drops the CONTROLLER slot, clears the RX mirror
note, and unregisters the iface (eth%d names are reused).
The PCI D-state step itself belongs to the platform PM layer,
not this driver. `resume()` returns `Result`: on error the
device stays quiesced and the caller may re-probe.

## 13. Ethtool surface

Probe records `ETHTOOL_GDRVINFO` data via
`narf_net::iface::set_driver_info` (driver "ixgbe", version
"0.1.0", PCIe bus address per the igb pattern) and the honest
offload set via `set_offloads` (TX checksum, TSO to the `tx()`
bound, VLAN insertion). The
driver-side snapshot is `drivers/net/ixgbe/src/ixgbe/
ethtool.rs`: `EthtoolInfo` (identity, MTU, link, queue counts,
caps word, RSS/VLAN/WoL state) plus `read_stats`, which reads
GPRC (0x04074) / GPTC (0x04080) — both RC, so snapshots are
interval counters, not lifetime totals. `Ixgbe::ethtool_info`
builds the snapshot on demand. Honest advertisement: RX
checksum is NOT claimed (the decoder exists but is not plumbed
into frame metadata); TSO claims the `tx()` bound (4096 bytes;
`tx_frame()` runs to 16384, see §13j); VLAN insertion IS
claimed (`TxMeta::vlan_tag` rides the context descriptor +
VLE). VLAN + checksum offload without TSO is rejected, not
advertised (see §13j).

## 13j. TX VLAN insertion + TSO frame-cap fix (#1269)

`tx()` and `tx_frame()` plan each transmit with `tx_plan`,
which returns an optional context descriptor plus the data
descriptor. When TSO and/or VLAN insertion is requested, the
context goes in slot S and the data descriptor in slot S+1
(the tail advances past both; DD is polled on the data
descriptor only — context descriptors carry no DD
write-back). Frames with neither keep the old 1-slot form.

VLAN insertion: the context descriptor's `vlan_macip_lens`
carries the full 16-bit TCI (VID + PCP + CFI) in bits 31:16,
and the data descriptor sets DCMD.VLE (0x40000000). MACLEN
stays 14 with insertion (the tag is hardware-added, not
driver-supplied). The inserted TPID is the VLNCTRL.VET
default 0x8100; the TX path does not program VLNCTRL.

TSO: `parse_tso_headers` accepts IPv4/TCP only (untagged
frames; a tagged frame is a distinct error — strip the tag
or request `vlan_tag` insertion). The context carries
MACLEN/IPLEN/L4LEN, TUCMD IPV4|L4T_TCP, and MSS; the data
descriptor sets TSE. PAYLEN is the TCP payload size only
(frame length minus headers) — the old `with_tso` full-frame
PAYLEN was wrong for TSO. Single-send PAYLEN stays the full
frame size.

Bounds: non-TSO frames keep the 1518 cap. TSO frames run to
4096 through `tx()` (the per-slot copy-buffer size) and to
16384 through `tx_frame()` (Linux's per-descriptor data
length, `IXGBE_MAX_DATA_PER_TXD`). The advertised
`max_tso_bytes` is 4096 — the bound the registered send
path (`ixgbe_send_frame` → `tx()`) honors. Larger TSO needs
multi-descriptor scatter (see §14).

Advertisement: `caps()` adds `NicCaps::TSO` unconditionally
(the path now honors TSO); `VLAN_TAGGING` keeps its RX-filter
meaning. Probe `set_offloads` is `tx_checksum: true`,
`max_tso_bytes: 4096`, `vlan_insert: true`.

Rejected, not silently mis-sent: TSO with mss 0; VLAN +
checksum offload without TSO (the csum path programs no
context, so a VLAN context with IPLEN 0 would misplace the
hardware checksum computation); TSO on a tagged or non-IPv4
frame; IPv6 TSO (v4-only context constructor).

Grounding: Linux ixgbe @ cbbddb6 — VLE
`ixgbe_type.h:2962`, tag bits `ixgbe.h:166,169` +
`ixgbe_main.c` csum/TSO paths, per-descriptor cap
`ixgbe.h:250-251` + split loop `ixgbe_main.c:9010`, PAYLEN
`ixgbe_main.c:8916,8980`; datasheet rev. 2.0 §7.2.3.2.2
(context layout, MACLEN table, "MSS is ignored when TSE is
not set") and §7.2.3.2.4 (VLE, DTALEN 15.5 KB, PAYLEN
single-send vs TSO, 256 KB TSO).

Smokes: VLE bit + context packing (VLAN-only and TSO+VLAN),
TSO header parsing incl. options and all rejections, TSO
PAYLEN split, and the full `tx_plan` matrix (plain / TSO /
VLAN-only / VLAN+TSO / VLAN+csum rejection / mss-0
rejection).

## 13b. SR-IOV / VMDq (issue #1261)

`drivers/net/ixgbe/src/ixgbe/vmdq.rs` implements the PF side of
SR-IOV / VMDq, grounded in Linux ixgbe @ cbbddb6 (no local
datasheet copy; see the module header for the full grounding note
and the deliberate deviations). VT mode is 64 pools x 2 queues
(`MTQC` VT_ENA | 64VF, `MRQC` VMDQEN, `VT_CTL` default pool +
replication, VEB switching via `PFDTXGSWC`). Pool 0 is the PF's
(queues 0/1, the 1/1 default bring-up, untouched); VF `i` owns
pool `i+1` (at most 63 VFs — a documented deviation from Linux,
which numbers VF pools from 0 with the PF after them; pool
numbers are invisible to VFs). Pool registers: MPSAR pool bitmaps,
VLVF/VLVFB pool VLANs (VFTA bit set additively on add, never
cleared on remove — VFTA stays owned by §11), VMOLR/VMVIR,
VFRE/VFTE, QDE drop-enable, VMECM spoof counting, per-queue
TX write-back reset, VFLRE/VFLREC reset events, and RAR
programming (pool selected before RAH/RAL, per Linux). VF
primary MACs pin to RAR `i+1` (a NARF simplification vs Linux's
free-RAR scan). The VF mailbox (`PFMAILBOX` control +
`PFMBMEM` memory + `MBVFICR` request/ack bits) carries the PF/VF
message interface: RESET (full reset sequence, 4-word
MAC-or-NACK reply), SET_MAC_ADDR, SET_VLAN, SET_LPE, SET_MACVLAN
(delete-only for index <= 1; add is a success no-op because
Linux's add path is commented out), API_NEGOTIATE, and
GET_QUEUES (2 TX + 2 RX queues). All other message types
(SET_MULTICAST, RETA, RSS key, XCAST, link state, IPSEC,
features) are NACKed. `Ixgbe::configure_vmdq` enables VT mode
opt-in; the dispatcher is fixture-proven but awaits an
interrupt pump, and PCI SR-IOV config-space enablement is a
separate follow-up (see §14).

## 13c. Flow Director (FDIR)

Implemented surface (`drivers/net/ixgbe/src/ixgbe/fdir.rs`,
opt-in via `Ixgbe::configure_fdir` and friends; probe still
brings up 1/1): FDIR init in signature mode (hash keys +
FDIRCTRL: flex shift 6, max 0xA filters per bucket, full
threshold 4) and perfect mode (plus perfect-match enable and
drop queue 127), perfect-filter input masks (FDIRM + TCP/UDP
port masks + IPv4 masks; SCTP mask only on X550-family parts),
perfect-filter add (IPv4 only) and erase (query first, remove
if present), signature-filter add (the ATR primitive: ATR
signature hash + FDIRHASH/FDIRCMD write pair), table reinit
(CLEARHT toggle + FDIRCTRL rewrite + INIT_DONE poll +
statistics clear), and statistics reads (all read to clear).

Grounding: Linux ixgbe @ cbbddb6 (`ixgbe_type.h` FDIR block +
`ixgbe_82599.c` FDIR functions). No local 82599 datasheet copy
exists, so the Linux transcription is the authority, as with
§13b. This lane programs ONLY the 0x0EE00 FDIR block and never
touches MRQC / RETA / RSSRK (verified: no Linux FDIR function
writes them); the #1397 MRQC-map conflict therefore does not
block this lane, and this lane does not pick a side in it. The
"ATR interacts with RSS" note is steering semantics (an
FDIR-steered flow bypasses RSS indirection), not a register
dependency.

Limits (see §14): no TX sampling hook (no in-tree TX packet
parser; sample rate + queue binding are policy for a
follow-up), no IPv6 perfect filters (Linux masks DIPv6), no
persistent filter list (reinit clears filters; callers
re-add), no cloud / MACVLAN filter modes, flex bytes fixed at
the ethertype shift. The signature-add 64-bit FDIRHASH write
is split into two 32-bit writes (hash, then command) because
`RegBank` is 32-bit. Section number is letter-suffixed so it
merges cleanly against §13b regardless of landing order.

## 13d. DCB (Refs #1263)

`drivers/net/ixgbe/src/ixgbe/dcb.rs` programs Data Center
Bridging, opt-in via `Ixgbe::configure_dcb` (call before bringing
up traffic: the MTQC write reinterprets the queue layout).
Surface, all transcribed from Linux ixgbe @ cbbddb6 (see the
module header for the full grounding note): MTQC mode (non-VT
rows only: RT_ENA|8TC_8TQ = 0xD, RT_ENA|4TC_4TQ = 0x9, with the
TX descriptor arbiter disabled around the write and
SECTXMINIFG |= 0x1F00); packet-buffer partitioning, EQUAL
strategy (RX (512 or 384 KiB)/num << 10, TX 160 KiB/num,
TXPBTHRESH = TX/1024 - 10, unused TCs zeroed); RX packet
arbiter (RTRPCS disable, RTRUP2TC UP map, RTRPT4C per-TC
credits with LSP only, RTRPCS enable); TX descriptor arbiter
(128 per-queue credits cleared, RTTDT2C per-TC credits,
RTTDCS = TDPAC|TDRM); TX packet arbiter (RTTPCS disable with
ARBD_DCB, RTTUP2TC UP map, RTTPT2C per-TC credits, RTTPCS
enable); PFC (FCCFG priority FC, MFLCN per-TC bits on X540+
else the single RPFCE bit, per-TC FCRTL/FCRTH watermarks with
the RXPBSIZE-24 KiB guard for disabled TCs, FCTTV pause time,
FCRTV refresh); TC statistics (RQSMR 16 queues per TC, TQSM
32/32/16/16/8/8/8/8). The config struct carries explicit
per-TC credits; the pure `ieee_credits` helper ports Linux's
IEEE 802.1Qaz credit computation for callers starting from
bandwidth percentages. Queue plan: TX 32/32/16/16/8/8/8/8, RX
16 per TC; with the 1/1 probe, queue 0 belongs to TC0.

⚠️ Grounding status (do not soften): Linux-only. Issue #1263
asks for datasheet grounding for the DCB/TC registers + MTQC
DCB rows, and no 82599/X540/X550 datasheet copy exists in this
workspace; the sole in-tree corroboration is MTQC's address
0x08120 (§3 table). Re-grounding against the datasheet is a
follow-up. Composition notes: MTQC VT rows belong to #1398
(SR-IOV, unmerged) — whoever lands second reconciles MTQC
into one setup covering VT×DCB combos; RSS composition is
unvalidated (different queue-layout assumptions — callers
pick one mode); DCBx negotiation, CEE bandwidth-group
credits, IPv6-style extras, and a DCB disable path are NOT
implemented (re-probe restores non-DCB mode).

Lettering note: §13d anticipates #1398's §13b (VMDq) and
#1400's §13c (FlowDirector), so the three sections merge
cleanly regardless of landing order.
## 13f. EEE control/status (Linux model, no MAC registers)

EEE in Linux ixgbe has no MAC register programming: `get_eee`
returns `-EOPNOTSUPP` unless the device is EEE-capable AND its
PHY is firmware-controlled. The driver-side model lives in
`drivers/net/ixgbe/src/ixgbe/eee.rs` (`EeeSpeeds`,
`LpModes`, `EeeState`, `EeeStatus`, `EeeRequest`,
`validate_request`), wired as `Ixgbe::configure_eee` /
`Ixgbe::eee_status` / `Ixgbe::eee_capable` with stored state
in `eee_state`:

- Capability gate, exactly Linux's `ixgbe_set_eee_capable`
  switch: only X550EM_A_1G_T (0x15E4), X550EM_A_1G_T_L
  (0x15E5), and E610_BACKPLANE (0x57AE), E610_SFP (0x57AF),
  E610_10G_T (0x57B0), E610_2_5G_T (0x57B1) are capable. No
  in-tree device id (82599EB, X540, X550, X550EM_X — note
  X550EM_X 0x15AB is a different part from X550EM_A_1G_T)
  is capable, so `configure_eee` returns `UnsupportedDevice`
  on every in-tree part today.
- Enable semantics (Linux `set_eee`): enabled stores
  advertised = supported, disabled stores advertised = empty.
  Validation (Linux `validate_keee`, in check order):
  capability → TX-LPI enable → TX-LPI timer → advertised
  set → already-enabled. Only the enabled flag may move.
- Status derivations (Linux `get_eee_fw`): enabled =
  advertised non-empty, TX-LPI enabled = enabled, active =
  advertised ∩ link-partner non-empty over link modes.
- FW-PHY decode: `FW_PHY_ACT_UD_2` (0x1002) info word →
  partner modes via the `ixgbe_lp_map` (100M_TX/1G_T/10G_T/
  1G_KX/10G_KX4/10G_KR bits 1..6). X550 FW-PHY defaults are
  100M + 1G, supported and advertised.
- ACI computation: `aci_eee_cap` maps advertised speeds to
  the E610 capability word exactly as `setup_eee_e610`
  does (2.5G → BIT(12), 5G → BIT(11), 10G → BIT(2));
  100M/1G map to nothing. E610 defaults: 2.5G_T →
  {2.5G}, other E610 → {2.5G, 5G, 10G}.

⚠️ Datasheet grounding NOT met (see the `eee.rs` header):
no 82599/X540/X550 datasheet copy exists locally; every
value here is Linux-transcribed. Re-grounding stays a
follow-up, and the maintainer may bounce this section on
that ground alone.

Remainders: the FW-PHY activity transport (host-interface
command) and the ACI transport do not exist in-tree, so
live link-partner queries and live re-application after a
set (Linux resets the link; the setup-link activity carries
`FW_PHY_ACT_SETUP_LINK_EEE` BIT(20)) are follow-ups, as is
landing X550EM_A / E610 device support so any part can
actually enable EEE. `EthtoolInfo` is unchanged: the
snapshot cannot populate EEE state from hardware without
those transports, so EEE status is reported through
`eee_status()`, not the snapshot.

## 13g. X540 WoL grounding + X550 LOM opt-in (Linux model)

Grounding: Linux ixgbe @ `cbbddb6` — the X540/X550 datasheets
were NOT consulted, so this section is Linux-transcribed, not
datasheet-grounded (same standing as §13b–§13f, which are
unmerged drafts on sibling branches; whoever lands second must
union the §1/§14 areas, not overwrite them).

X540 verdict: SUPPORTED, via the shared wake block. Linux's
shutdown path programs `IXGBE_WUFC` with the stored filter word
for 82599/X540/X550/X550EM_x alike (`ixgbe_main.c`
`__ixgbe_shutdown`), and `pci_wake_from_d3` is enabled for the
same set — there are no X540-specific wake registers and no
per-part WoL ops. The in-tree `WolConfig::arm` conversation
(WUS clear, WUFC program, WUC.PME_En) is therefore the X540
conversation too, pinned by the §13g smoke.

The gate is a board record, not a device ID. Linux's
`ixgbe_wol_supported` (`ixgbe_main.c:11375`) reads the EEPROM
DEVICE_CAPS word at probe (`hw->eeprom.ops.read(hw, 0x2c, ...)`
at `:11913`) and, for mac.type >= X540 (enum order
`ixgbe_type.h:3216-3220`: 82598EB < 82599EB < X540 < X550 <
X550EM_x), arms WoL only when the masked cap word permits:
`wol_cap = eeprom_cap & 0xC` (`ixgbe_type.h:2179-2181`:
PORT0_1 0x4, PORT0 0x8, MASK 0xC); cap 0x4 permits any function,
cap 0x8 permits function 0 only (`hw->bus.func == 0`), anything
else — including 0xC, both bits set, which the equality
comparisons reject — permits nothing. 82599 and older use a
subdevice table instead; 82598 never wakes.

X550 LOM verdict: the same rule. Linux has no separate LOM
concept in `ixgbe_wol_supported` — the board's EEPROM image IS
the LOM/board opt-in, and a board that does not opt in never
wakes. Intel's adapter guidance (most 10 GbE adapters do not
support WoL; X550 supports it as LAN on Motherboard when the
board enables it) is consistent with this mechanism.

NARF design (`wol.rs` `WolBoardCap`, `wol_allowed`,
`Ixgbe::set_wol_board_cap`): the record carries the raw cap
bits plus the device's PCI function number, and `allows()`
implements the Linux rule literally, including the 0xC
rejection and the mask-then-compare order (so 0x14 masks to
0x4 and permits). The default record permits nothing;
`configure_wol` and `suspend` gate on `wol_allowed`, and the
ethtool snapshot's `wol_supported` reflects the gated verdict.
Setting a record arms nothing by itself. One deliberate
difference from Linux: Linux arms magic-packet-only by default
at probe when `wol_enabled` (`adapter->wol = IXGBE_WUFC_MAG`
at `:11916-11917`); NARF arms only on an explicit
`configure_wol` / suspend-with-config call — no probe-time
default arming.

Remainders: X540/X550 datasheet re-grounding (this section is
Linux-only); an EEPROM word-0x2c reader via the existing EERD
helper so the record can one day come from hardware instead of
board configuration; X550EM_A / E610 DIDs (same Linux rule
applies when they land); the 82599 subdevice table (NARF does
not track subdevice IDs; the 82599EB datasheet rule stands).

## 13h. IPAV — IP Address Valid (resolved by #1267)

#1267 asked for the true IPAV address: #1259 had left it
unprogrammed because the datasheet text extracted as "0x5838",
one hex digit short of the neighbouring 0x058xx registers.
Resolution: the Intel 82599 Datasheet rev. 2.0 §8.2.3.24.4
header itself prints "0x5838" — the PDF text drops the
leading zero, exactly as #1259 observed — and Linux
normalizes the same register to 0x05838 (`ixgbe_type.h:508`;
`e1000_hw.h:990` and igb `e1000_regs.h:304` agree, "IP
Address Valid - RW"). The slot between WUS (0x05810) and
IP4AT (0x05840) in the §8.2.3.24 sequence confirms it.
Datasheet grounding is MET for IPAV specifically (unlike
the sibling §13b–§13g items, which remain Linux-only).

Bit layout (datasheet §8.2.3.24.4, RW): V40 bit 0 =
IPv4 slot 0 valid, V41 bit 1 = slot 1, V42 bit 2 = slot 2,
V43 bit 3 = slot 3, V60 bit 16 = IPv6 address 0 valid;
all other bits reserved. V40 init comes from EEPROM
(IPv4[0] itself is EEPROM-loaded from MIPAF); the other
valid bits init 0b. The register states whether the
IP4AT/IP6AT entries are valid for wake matching.

Programming (`wol.rs`): `program_ipv4` sets the slot's
valid bit alongside the table write, `program_ipv6` sets
V60, `invalidate_ipv4` / `invalidate_ipv6` clear them.
`arm` / `disarm` do not touch IPAV: validity is per-entry
state, and with WUFC = 0 no filter can fire regardless of
the valid bits. Note Linux never writes IPAV on any path
(it appears only in ethtool register dumps), so there is
no Linux write sequence to copy — the datasheet layout
above is the sole authority for the programming, and the
smoke pins address, bits, set-on-program, and
clear-only-the-target-bit behavior. Per-part arming is
still governed by the §12 board-cap rule; IPAV
programming itself is part-agnostic register programming.

## 13i. Per-queue statistics (QPRC/QPTC)

Datasheet-grounded (82599 rev. 2.0 §8.2.3.23.74/.78), corroborated
by Linux ixgbe (`ixgbe_type.h:860-861`, `ixgbe_main.c` "16
register reads" loop, `ixgbe_ethtool.c` register dump):

- QPRC[n] at 0x01030 + 0x40*n, n = 0..15, RC: packets received
  for the queue. FCoE packets count even when posted only to the
  DDP queue (no trace in the legacy queue).
- QPTC[n] at 0x06030 + 0x40*n, n = 0..15, RC: packets transmitted
  for the queue (forwarded to the MAC and/or the internal Tx-to-Rx
  switch). Packets dropped by anti-spoofing filtering or VLAN tag
  validation are NOT counted. The datasheet also maps QPTC at
  0x08680 + 0x4*n; this driver reads the 82598-compatible
  0x06030 + 0x40*n mapping, which is the one Linux reads.
- Both counters are RC (read-clear), like GPRC/GPTC: a snapshot
  consumes the interval since the last read. `read_queue_stats`
  reads min(num_rx_queues, 16) QPRC and min(num_tx_queues, 16)
  QPTC registers into `QueueStats` (arrays of 16 plus
  `rx_valid`/`tx_valid` counts); `EthtoolInfo` carries it as
  `queue_stats`, read by the same `ethtool_info` call as the
  totals, so one snapshot consumes every interval counter.
  `summary()` keeps the totals line unchanged; per-queue detail
  lives in the struct field.
- The 16-queue bound is hardware, not policy: the QPRC block ends
  where QPRDC begins (0x01430 = 0x01030 + 16*0x40), and Linux
  reads exactly 16. A 64-queue bring-up therefore reports only
  the first 16 queues per-queue; queues >= 16 have no per-queue
  packet counter, and their traffic remains visible only in the
  GPRC/GPTC totals.
- Part scope: Linux reads this block for every mac type in the
  family (82599EB, X540, X550, X550EM_x, x550em_a, e610) with no
  per-part gating. The 82599 datasheet grounds the addresses;
  X540/X550 datasheet re-grounding stays open under #1266's
  remainders.

## 13l. Resume ring rebuild (issue #1271 decision: rebuild, not re-probe)

Decision: on resume, the driver REBUILDS the DMA rings in
place from the retained host buffers instead of requiring a
full re-probe after a suspend that lost DMA state.

Rationale, following Linux: Linux `ixgbe_resume`
(`ixgbe_main.c`) does `pci_enable_device_mem` →
`ixgbe_reset` → WUS clear → `ixgbe_init_interrupt_scheme`
→ `ixgbe_open` (when running), and `open` reconfigures the
rings from scratch (`ixgbe_configure_tx_ring` /
`ixgbe_configure_rx_ring`: clear the queue-enable bit,
program base / length / head / tail, then set enable).
NARF maps that shape onto what it retains: the driver owns
the ring buffers for the device's lifetime (`tx_ring` /
`rx_ring` / `tx_pool` / `rx_slots` are struct fields, never
freed on suspend), so `Ixgbe::resume` zeroes the TX ring,
re-arms every RX descriptor from its slot's current buffer
(slots rotate as frames are handed up — current contents,
not bring-up order, are the truth), resets the pump cursors,
and `pm::resume_rebuild_plan` reprograms one ring per
configured queue (never a hardcoded queue 0 — the plan takes
one DMA base per queue, which is what composes with
per-queue rings), restores SRRCTL / FCTRL / RXEN, and
unmasks the misc vector. The rebuild is unconditional and
idempotent: reprogramming rings from retained buffers is
correct whether or not the suspend actually lost device
state, so no lost-vs-preserved detection is needed.

Deliberate differences from Linux, each documented so the
maintainer can overrule:
- NO `CTRL.RST` on resume. A reset would wipe non-DMA
  config this rebuild does not restore (RAR, RSS tables,
  VLAN tables, IVAR routing), leaving a worse-than-before
  datapath. The rebuild overwrites exactly the datapath
  state it owns; registers it does not touch keep their
  pre-suspend values when the device preserves them.
- NO re-probe path. Re-probe would need a platform PM
  re-enumeration hook plus controller replacement under
  live pump `Arc` clones; neither exists in-tree. The
  fail-closed `Err` from `resume()` is the re-probe
  trigger instead: the device stays quiesced, pumps keep
  refusing work, and the caller may re-probe.

Fail-closed rules (all checked before any register or ring
memory is touched): queue config must validate; ring
length must equal the allocated ring lengths; RX slot count
must equal the ring length; per-queue base counts must
match the queue counts; every queue's register block must
resolve. Any violation returns `Err` with the device still
quiesced.

Remainders (not silently dropped):
- Non-DMA state is NOT restored: RAR, RSS tables, VLAN
  tables, and the MSI-X interrupt scheme keep pre-suspend
  values only if the device preserved them. A suspend that
  loses non-DMA state still needs a re-probe — or a future
  full-reconfigure lane that restores those tables from the
  driver's retained config (`mac`, `rss_cfg`,
  `vlan_filter`, `msix`).
- No `CTRL.RST` means a device that wedges across suspend
  (rather than merely losing state) is not reset by this
  path; that recovery belongs to the same future lane.

## 14. Sequenced follow-ups (not silently dropped)

Per the v0.1 exclusion list, still open after this stream:

- SR-IOV / VMDq remainders (see §13b): the mailbox interrupt
  pump; PCI SR-IOV config-space enablement; SET_MULTICAST and
  the other NACKed message types; 32-VF mode; spoof-check
  enforcement; DCB+VT combinations. The #1397 address question
  is settled (datasheet dual-map; `ixgbe/regs.rs` is the shared
  authority): what remains is the MRQE 0xB + per-pool RETA
  composition on the VMDq path.
- FlowDirector remainders (see §13c): TX sampling hook for ATR
  (packet parser + sample-rate policy + queue binding), IPv6
  perfect filters, persistent filter list with restore on
  reinit, cloud / MACVLAN filter modes.
- DCB — see §13d (Refs #1263; Linux-grounded, datasheet
  re-grounding + MTQC VT×DCB reconciliation + DCBx + CEE
  credits + disable path remain).
- FCoE (FCRETA, FCRXCTRL) — out of the Ethernet scope.
- EEE: model + capability gate + FW-PHY decode + ACI cap
  computation landed (§13f); remainders are datasheet
  re-grounding, the FW-PHY activity + ACI transports, live
  link re-application after a set, and X550EM_A / E610
  device support.
- X540 / X550EM_x WoL grounding + X550 LOM opt-in — landed as
  the Linux-cap-rule model (§13g); remainders are datasheet
  re-grounding, the EEPROM word-0x2c reader, and E610/X550EM_A
  DIDs.
- Per-queue statistics counters (QPRC/QPTC) — landed (§13i);
  QPRDC (per-queue drops) and QBRC/QBTC (per-queue bytes) remain
  as follow-ups.
- Resume full-reconfigure (RAR / RSS / VLAN / MSI-X restore)
  for suspends that lose non-DMA state — see §13l.
- IPv6 TSO (the TSO context constructor is v4-only; the parser
  rejects non-IPv4 frames — a v6 constructor + parser leg is a
  separate change).
- Multi-descriptor TSO scatter for frames above 16384 bytes, and
  `tx()` copy-buffer growth for larger `tx()` TSO (the advertised
  bound is the `tx()` one until then).
- VLAN + checksum offload without TSO (the csum path needs
  header parsing + a context descriptor before it can carry a
  VLAN context).
- Csum-path context stickiness: after a TSO/VLAN frame, a later
  csum-only frame reuses the stale context. Harmless per the
  datasheet (non-TSE frames ignore MSS/L4LEN; no VLE means no
  insertion), but documented here until a csum-path context is
  added.
- X540/X550 descriptor-format re-grounding against their own
  datasheets (this lane's descriptor grounding is 82599 rev.
  2.0 + Linux, which programs the same format across parts).

Per project rule, smokes live in `drivers/net/src/ixgbe/tests.rs`
and register via `kernel_test_in!("drivers/net/ixgbe", …)`.
Coverage:

- PCI match table includes all four documented IDs.
- `eeprom_decode` round-trips a synthetic EEPROM word.
- `AdvTxDesc::ctrl_word` packs `EOP|RS|DEXT|DTYP=3|len`.
- `RxDesc` size + alignment.
- (live) `bring_up` against an attached 82599 — `Skip` if absent.
