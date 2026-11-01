# ixgbe — Specification

> Status: **v0.2 in progress** (Stages 1-6 as v0.1, plus §9
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
documented `CTRL.RST` reset, EEPROM-backed MAC read, TX descriptor
ring (advanced layout), RX descriptor ring (legacy layout for
simplicity), one MSI-X vector for link / RX completion, and a
`HwNic` adapter exposing the same surface the e1000/mlx5 drivers
do.

Does NOT own: DCB, FCoE, SR-IOV, RSS, FlowDirector, EEE, VMDq.

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
| 0x0EB00+4*n | RETA[n] | RSS redirection table (n=0..31, see §10) |
| 0x0EB80+4*n | RSSRK[n] | RSS random key (n=0..9, see §10)    |
| 0x0EC80   | MRQC      | Multiple RX Queues Command (see §10) |
| 0x04200   | LINKS     | LINK_UP = bit 30                     |
| 0x04074   | GPRC      | Good Packets Received Count (RC, see §13) |
| 0x04080   | GPTC      | Good Packets Transmitted Count (RC, see §13) |
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

## 9. Multi-queue (v0.2)

`drivers/net/ixgbe/src/ixgbe/queues.rs` owns queue addressing:
`rx_queue_regs(q)` / `tx_queue_regs(q)` (stride 0x40, second RX
bank for 64..127), `QueueConfig` validation (live cap 64 queues,
ring length a power of two in 32..=4096), and IVAR routing
(`route_queue_vector` / `route_misc_vector`: one IVAR per two
queues, RX/TX fields + valid bits per §8.2.3.5.16; OTHER cause via
IVAR_MISC bits 14:8 + valid bit 15). Bring-up still runs the live
datapath on queue 0's rings; `Ixgbe::num_tx_queues` /
`num_rx_queues` (exposed via both `HwNic` and `narf_net::Interface`)
report the configured counts (1/1 today). Extra-queue DMA rings
and per-queue pumps are a sequenced follow-up (§14): the
addressing, validation, and vector routing they need are done
here, and fixtures replay the queue-0 register conversation on a
fake bank plus IVAR sibling-preservation checks.

## 10. RSS

`drivers/net/ixgbe/src/ixgbe/rss.rs` programs RSS-only mode
(MRQC at 0x0EC80, MRQE = 0001b = single 16-queue set, all six
hash-field enables: TcpIPv4/IPv4/IPv6/TcpIPv6/UdpIPv4/UdpIPv6),
the 40-byte key into RSSRK[0..9] (0x0EB80 + 4*n, little-endian
words), and the 128-entry balanced indirection table into
RETA[0..31] (0x0EB00 + 4*n, 4-bit entries). The key and table
come from `narf_net::rss` (standard conformance key + balanced
table), so hardware steering equals `RssConfig::rx_queue` for
the same frame — fixtures assert that agreement plus the
MRQC/RSSRK/RETA register conversation on a fake bank.
`Ixgbe::configure_rss(queues)` (1..=16) programs and records
the state; `HwNic`/`Interface::rss()` expose it and `caps()`
gains `RSS` once programmed. Bring-up leaves RSS off (queue 0
only) until configured; reprogramming requires RX disabled.
FlowDirector/ATR stays a follow-up (§14).

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

## 12. Wake-on-LAN and power management (v0.2 — see §14)

Placeholder for the WoL/PM commits: WUFC / WUC / WUS, suspend /
resume / detach quiesce.

## 13. Ethtool surface (v0.2 — see §14)

Placeholder for the ethtool commit: driver info + stats snapshot.

## 14. Sequenced follow-ups (not silently dropped)

Per the v0.1 exclusion list, still open after this stream:

- SR-IOV / VMDq (MRQC virtualization modes, PFVTCTL, VF
  registers) — needs the virtualization programming model.
- FlowDirector (FDIRCTRL / FDIRHASH / filter tables) — ATR
  complexity; the RSS path covers flow steering for now.
- DCB (MTQC RT_Ena, RTRUP2TC, packet-buffer partitioning).
- FCoE (FCRETA, FCRXCTRL) — out of the Ethernet scope.
- EEE (energy-efficient Ethernet link modes).
- Per-queue DMA rings + pumps for queues 1..63, and per-queue
  MSI-X vectors beyond the shared misc vector.
- X540 / X550EM_x WoL grounding (X540 datasheet not consulted;
  X550 WoL is LOM/board-gated — see §12).
- IPAV (0x05838 candidate) — datasheet text extraction was
  ambiguous, so it is not programmed; see §12.
- Per-queue statistics counters (QPRC/QPTC offsets ungrounded).

Per project rule, smokes live in `drivers/net/src/ixgbe/tests.rs`
and register via `kernel_test_in!("drivers/net/ixgbe", …)`.
Coverage:

- PCI match table includes all four documented IDs.
- `eeprom_decode` round-trips a synthetic EEPROM word.
- `AdvTxDesc::ctrl_word` packs `EOP|RS|DEXT|DTYP=3|len`.
- `RxDesc` size + alignment.
- (live) `bring_up` against an attached 82599 — `Skip` if absent.
