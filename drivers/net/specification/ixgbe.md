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
documented `CTRL.RST` reset, EEPROM-backed MAC read, TX descriptor
ring (advanced layout), RX descriptor ring (legacy layout for
simplicity), one MSI-X vector for link / RX completion, and a
`HwNic` adapter exposing the same surface the e1000/mlx5 drivers
do.

Does NOT own: FCoE, SR-IOV, RSS, VMDq.

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
| 0x05C00+4*n | RETA[n] | RSS redirection table (n=0..31, see §10; native alias 0x0EB00+4*n) |
| 0x05C80+4*n | RSSRK[n] | RSS random key (n=0..9, see §10; native alias 0x0EB80+4*n)    |
| 0x05818   | MRQC      | Multiple RX Queues Command (see §10; native alias 0x0EC80) |
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
IPAV is NOT programmed: the datasheet text
extracted ambiguously ("0x5838"), so it is a remainder (§14),
not a guessed value.

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
offload set via `set_offloads` (TX checksum only). The
driver-side snapshot is `drivers/net/ixgbe/src/ixgbe/
ethtool.rs`: `EthtoolInfo` (identity, MTU, link, queue counts,
caps word, RSS/VLAN/WoL state) plus `read_stats`, which reads
GPRC (0x04074) / GPTC (0x04080) — both RC, so snapshots are
interval counters, not lifetime totals. `Ixgbe::ethtool_info`
builds the snapshot on demand. Honest advertisement: RX
checksum is NOT claimed (the decoder exists but is not plumbed
into frame metadata), TSO claims no bound (the send path caps
frames at 1518 bytes), and VLAN insertion is NOT claimed (RX
filtering only).

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

- SR-IOV / VMDq (MRQC virtualization modes, PFVTCTL, VF
  registers) — needs the virtualization programming model.
  The #1397 address question is settled (datasheet dual-map;
  `ixgbe/regs.rs` is the shared authority): what remains is
  the MRQE 0xB + per-pool RETA composition on the VMDq path.
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
- Per-queue DMA rings + pumps for queues 1..63, and per-queue
  MSI-X vectors beyond the shared misc vector.
- X540 / X550EM_x WoL grounding + X550 LOM opt-in — landed as
  the Linux-cap-rule model (§13g); remainders are datasheet
  re-grounding, the EEPROM word-0x2c reader, and E610/X550EM_A
  DIDs.
- IPAV (0x05838 candidate) — datasheet text extraction was
  ambiguous, so it is not programmed; see §12.
- Per-queue statistics counters (QPRC/QPTC offsets ungrounded).
- Resume full-reconfigure (RAR / RSS / VLAN / MSI-X restore)
  for suspends that lose non-DMA state — see §13l.

Per project rule, smokes live in `drivers/net/src/ixgbe/tests.rs`
and register via `kernel_test_in!("drivers/net/ixgbe", …)`.
Coverage:

- PCI match table includes all four documented IDs.
- `eeprom_decode` round-trips a synthetic EEPROM word.
- `AdvTxDesc::ctrl_word` packs `EOP|RS|DEXT|DTYP=3|len`.
- `RxDesc` size + alignment.
- (live) `bring_up` against an attached 82599 — `Skip` if absent.
