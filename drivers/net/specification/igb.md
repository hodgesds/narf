# igb — Specification

> Status: **v0.1 — bring-up + SR-IOV / VMDq (issue #1253)**.
>
> Clean-room driver for the Intel I210 / I211 / 82576 / I350 1 GbE
> controller family. Reference material: the Linux `igb` driver at
> `torvalds/linux` commit `cbbddb6` (`drivers/net/ethernet/intel/igb/`),
> plus the I210 and 82576 datasheets where the code comments say so.
> Register and behaviour claims below are grounded in that Linux
> tree; anything not corroborated there is listed under §5 as a
> remainder, not silently assumed.

## 1. Purpose & scope

This document covers the igb driver's SR-IOV / VMDq surface
(issue #1253) and the interface it adds to the existing bring-up.
The bring-up itself (BAR0 mapping, CTRL.RST reset, EEPROM-backed MAC
read, queue-0 TX/RX rings, MSI-X vector 0, VLAN filter, WoL) is
documented in code comments in `drivers/net/igb/src/igb.rs` and is
not re-specified here.

In scope for this document:

- VT allocation: 1..=7 VFs, VF pools, PF pool, RAR budgeting.
- VF MAC/VLAN filter management through VLVF + VFTA.
- The PF↔VF mailbox: RESET, SET_MAC_ADDR, SET_MULTICAST, SET_LPE,
  SET_VLAN, SET_PROMISC, plus the admin paths (MAC, port VLAN, trust,
  spoof-check flag).
- The MRQC / RSS interaction with VFs allocated.
- VMDq-aware PF VLAN add/remove.

Out of scope (remainders, §5): PCI SR-IOV config-space enablement
and VF BAR exposure, the mailbox interrupt pump, live PF queue
relocation, VF rate limiting, MTA restore on PF multicast-list
change, and the tighter SET_LPE clamp.

## 2. PCI match

| device            | did    | RAR entries | pool encoding |
|-------------------|--------|-------------|---------------|
| I210 family       | 0x1533, 0x1536, 0x1537, 0x1538, 0x157B, 0x157C | 16 | numeric |
| I211              | 0x1539 | 16 | one-hot |
| 82576 / 82576-NS  | 0x10C9, 0x150A | 24 | one-hot |
| I350              | 0x1521 | 32 | one-hot |

RAR counts follow Linux `igb` (`e1000_82575.c` RAR-count table:
82576/82580 → 24, I350/I354 → 32, default → 16). Pool encoding
follows Linux `igb_rar_set_index`: the I210 family programs the pool
as a numeric field (`RAH_POOL_1 * pool`); every other claimed device
programs it one-hot (`RAH_POOL_1 << pool`).

## 3. Public interface

New code lives in `drivers/net/igb/src/igb/vmdq.rs` (pure register
math + shadow state; no allocation, no unsafe, fixed arrays only)
plus wiring in `drivers/net/igb/src/igb.rs`.

| item | behaviour |
|------|-----------|
| `Igb::vt_allocate(num_vfs)` | Device-side VT allocation (Linux `igb_enable_sriov` device half). Requires MSI-X, 1..=7 VFs, one allocation per device. Seeds VLVF/VMOLR/VFRE/VFTE shadows from live MMIO, programs VT_CTL default pool + per-family switch registers (Linux `igb_vmm_control`, igb_main.c:10077), and programs MRQC into VMDq mode with RXCSUM PCSD (Linux `igb_setup_mrqc`). |
| `Igb::vt_dispatch_mailbox(vf, msg)` | Runs one mailbox message through `VtState::dispatch` and applies its program: register writes directly, MTA sets as read-OR-write, VFTA consequences through the `VlanFilter` shadow. Returns the reply words; the caller writes them to VMBMEM and rings P2VMAILBOX (the pump is a remainder). |
| `Igb::vlan_filter_add` / `vlan_filter_remove` | Unchanged when no VT allocation is active. With VFs allocated, the PF add/remove goes through the VMDq-aware path (§4.4). Lock order everywhere: `vt` before `vlan_filter`, never reversed. |
| `vmdq::VtState` | Allocation state: VF records, VLVF shadow, VF MAC-filter table, VMOLR/DVMOLR shadows, VFRE/VFTE shadows, VLAN-promiscuous flag. |
| `vmdq::Program` | Bounded program (48 writes, 30 MTA sets, 4 VLAN adds, 32 VLAN removes); overflow fails closed with `ProgramOverflow`. Application order is load-bearing: VFTA clears for removes first, then register writes and MTA sets, then VFTA sets for adds (see §4.4). |
| `vmdq::VtState::dispatch` | Mailbox dispatch (Linux `igb_rcv_msg_from_vf`): already-ACK/NACK input gets no reply; RESET is exact-match `msg[0] == 0x01` and bypasses the CTS gate; every other message requires CTS; replies carry CTS + ACK/NACK (RESET replies carry ACK/NACK only, no CTS). Linux throttles repeat NACKs on a 2 s window; this time-free core NACKs unconditionally (documented simplification). |
| Admin: `set_vf_mac_admin`, `set_vf_vlan_admin`, `set_vf_trust`, `set_vf_spoofchk_flag` | PF-side administration (Linux `ndo_set_vf_mac` / `ndo_set_vf_vlan` / trust flag / spoof-check flag). Zero MAC clears the PF-set flag; a valid MAC sets it; a multicast MAC is refused. |

## 4. VT behaviour

### 4.1 Pool model (opposite of ixgbe's)

VF `i` owns pool `i`; the PF owns pool `vfs_allocated_count`
(Linux `igb_main.c`: PF id = `vfs_allocated_count`; PF queue `i`
lives at register index `num_vfs + i`, i.e. `rbase_offset =
vfs_allocated_count`). Do NOT copy ixgbe's numbering (ixgbe: PF = 0,
VF = `i + 1`); the two drivers number pools differently because
their Linux drivers do.

VF count is capped at 7 (Linux `igb_enable_sriov` rejects `num_vfs >
7`; `IGB_MAX_VF_FUNCTIONS` = 8 counts the PF itself).

### 4.2 RAR / MAC filters

- VF `i`'s primary RAR is `rar_entry_count - (i + 1)` (VF MACs are
  allocated from the end of the table toward the first entry).
- VF filter RARs scan from slot `1 + PF_MAC_FILTERS_RESERVED` (= 4):
  RAR 0 is the PF default and RARs 1..3 are reserved for PF filters,
  so VF filters never take them. The filter budget is
  `rar_entry_count - (1 + 3 + num_vfs)` (e.g. 82576 with 7 VFs → 13,
  I350 with 1 VF → 27, I210 with 1 VF → 11).
- A RAR entry programs pool bits whenever it is in use, even for an
  invalid (zero) address — which gets pool bits but no AV bit. A
  cleared entry programs (0, 0).
- SET_MAC_ADDR: info 0 = primary (refused when PF-set and the VF is
  untrusted, or when the address is invalid); CLR removes all of the
  VF's filters; ADD takes the first free filter entry (ENOSPC when
  full); any other info is refused. Validation happens before
  mutation: a refused message changes no state.

### 4.3 VLVF / VFTA (VLAN filtering with VFs)

VLVF has 32 entries at `0x05D00 + 4n`. Slot 0 is reserved for VLAN 0;
other VIDs scan slots 31..1. An entry holds the VID, the enable bit
(`0x80000000`), and one pool bit per pool (`bit 12 + pool`).

The update follows Linux `igb_vfta_set` (`e1000_mac.c:174`,
two-part algorithm: the VFTA bit is computed first but written only
once the VLVF part succeeds):

- Add: set the pool bit, write `bits | vid | ENABLE`.
- Remove: clear the pool bit; if no pool bits remain, clear the
  VFTA bit first, then write entry 0; otherwise keep the VFTA bit
  (delta forced to 0) and write `bits | vid | ENABLE`.
- No slot + bypass → VFTA-only (the PF still receives via the
  default pool); no slot + no bypass → error, VFTA untouched.
- `vid > 4095` or `vind > 7` → error.

`igb_set_vf_vlan` (igb_main.c:7512): when adding a VID the PF
already monitors, the PF pool bit is secured first with no bypass
(and its failure propagates); on remove, the PF entry is cleaned up
(`igb_update_pf_vlvf`) when the PF monitors the VID or VLAN
promiscuous mode is on. The PF-step-failure cleanup is a provable
no-op in every reachable state (a successful PF step means a slot
for the VID already exists; a failed PF step leaves no entry for
the cleanup to touch), so the error propagates without it.

`igb_update_pf_vlvf`: no-op when no entry exists; no-op when pools
other than the PF remain; otherwise writes the PF pool bit under
VLAN promiscuous mode, else 0. Slot 0 is never touched here (Linux
returns early for index 0, which covers both "not found" and the
VLAN-0 entry).

### 4.4 PF VLAN add/remove with VFs, and application order

- PF add uses the PF pool bit with bypass = `vid != 0`.
- PF remove uses bypass = true, then the `update_pf_vlvf` path.
- The VFTA word is written only when the VFTA bit actually changes.

Application order (Linux `igb_vfta_set`): a remove that disables an
entry must clear its VFTA bit BEFORE the entry write, or a packet
for that VID could leak into the PF via the default pool in
between; an add must program the VLVF entry BEFORE its VFTA bit.
`vt_dispatch_mailbox` applies removes' VFTA clears, then register
writes and MTA sets, then adds' VFTA sets; `vlan_filter_remove`
applies the same order inline.

### 4.5 Mailbox messages

Mailbox registers: VMBMEM at `0x00800 + 64n` (16 words per VF),
P2VMAILBOX at `0x00C00 + 4n`, MBVFICR `0x00C80`, MBVFIMR `0x00C84`,
VFLRE `0x00C88`, VFRE `0x00C8C`, VFTE `0x00C90`. Message words use
`E1000_VT_MSGINFO_MASK` (`0xFF << 16`, `e1000_mbx.h`) for the info
field; ACK = `0x80000000`, NACK = `0x40000000`, CTS = `0x20000000`.

| message | behaviour |
|---------|-----------|
| RESET (0x01) | `igb_vf_reset_msg`: VF reset (flags keep only PF_SET_MAC; MAC, trust, spoof-check, and port VLAN survive) + stored-MAC reprogram + VFTE/VFRE bit set + CTS flag + 3-word reply (ACK + MAC when the MAC is nonzero, else NACK). |
| SET_MAC_ADDR (0x02) | See §4.2. |
| SET_MULTICAST (0x03) | Hash count is stored uncapped; the first 30 hashes are kept and programmed to the MTA. More than 30 hashes sets VMOLR.MPME; any hashes set ROMPE + MTA sets. Always ACKs. |
| SET_VLAN (0x04) | Refused when a port VLAN is administratively set. VID 0 + remove is a no-op success. Otherwise the pool bit plus strip state (`strip = vid != 0`). |
| SET_LPE (0x05) | VMOLR = (shadow without the RLPML field) \| size \| LPE. Size clamps to the RLPML field width (`0x3FFF`); see §5 for the tighter clamp remainder. |
| SET_PROMISC (0x06) | Clears UNI/MULTI flags and ROPE/ROMPE/MPME. MULTICAST info sets MPME + the MULTI flag and clears that info bit; otherwise a stored hash count over 30 sets MPME, a nonzero count sets ROMPE + MTA sets. Leftover info bits NACK *after* the VMOLR write (Linux write-then-check order). |

VMOLR is at `0x05AD0 + 4n`; VMVIR at `0x03700 + 4n`. On I350 the
strip bit lives in DVMOLR (`0x0C038 + 64n`), not VMOLR — same bit,
different register.

### 4.6 Switch programming (`igb_vmm_control`, igb_main.c:10077)

- 82576: DTXCTL VLAN_ADDED (`0x03590`, bit `0x8`) + RPLOLR STRVLAN
  (`0x05AF0`, bit `0x40000000`), then loopback on, replication on
  (VT_CTL VM_REPL_EN, bit 30), anti-spoofing on (DTXSWC `0x03500`:
  both spoof masks set, then the PF pool's MAC-spoof bit `BIT(pf)`
  and VLAN-spoof bit `BIT(pf + 8)` toggled back off).
- I350: neither DTXCTL nor RPLOLR; loopback + replication +
  anti-spoofing on TXSWC (`0x05ACC`).
- I210/I211: `vmm_control` returns early — none of the switch
  registers are programmed (no loopback, no replication, no
  anti-spoofing). VT_CTL default-pool programming still applies
  (it comes from `igb_setup_mrqc`, not `vmm_control`).

### 4.7 MRQC / RSS interaction

With VFs allocated, MRQC mode is VMDq (`0x3`) with 1 RSS queue and
VMDq+RSS-MQ (`0x5`) with more than 1 RSS queue (in-tree
`mrqc_word`), and RXCSUM gains PCSD (+ CRCOFL for ≥ 82576, in-tree
`rxcsum_rss_word`). VT_CTL default pool = `vfs_allocated_count`
when VFs exist.

The I350 interaction is already encoded in-tree and is NOT
re-derived here: `max_queues_for_device` pins I350 with any VF to 1
RSS queue and 82576 with VFs to 2. Later RSS reprogramming of MRQC
must pass `vmdq = true` and the actual RSS queue count; with VFs
allocated the queue counts above are the ones to pass.

Existing PF-only paths (VFTA, RETA, WoL) are unaffected with 0 VFs:
`vt_allocate` is opt-in, and `vlan_filter_add` / `vlan_filter_remove`
take the PF-only path until it runs.

### 4.8 EEE control/status (issue #794)

EEE advertisement + ethtool get/set for the copper parts, in
`drivers/net/igb/src/igb/eee.rs` (`EeeRegs` trait + `MmioEeeRegs`
real impl, pure word helpers, scripted `FakeRegs` fixture) with
wiring as `Igb::eee_status` / `Igb::set_eee` and an `eee` field
on `EthtoolInfo` (populated from a live read; `None` while the
part is not EEE-capable or the PHY does not answer). The MMD
decode/encode (`eee_modes` / `eee_mmd_adv`) delegate to the
shared `narf_drivers_net_core::phy` surface (issue #794).

- Capability gate: copper device ids only — I210 copper /
  flashless, I211 copper, 82576, 82576_NS, I350 copper.
  Fiber/SerDes/SGMII parts have no copper PHY to negotiate
  EEE on, and return an error.
- Set (mirrors igc's `setup_link` EEE block, Linux
  `igb_set_eee`): MMD 7/60 = 100M bit 1 + 1G bit 2, MMD
  7/62 = 2.5G bit 0 (Linux `igb_set_eee` / igc
  `igc_setup_link` EEE sequence), IPCNFG 0x0E38 bits 12
  (100M) + 14 (1G) — the e1000-generation layout, NOT
  igc's I225 bits 2–4 — EEER 0x0E30 TX/RX-LPI-EN + the
  0x70000 wait/delay bits, then a BMCR restart
  (0x1200) so the new advertisement goes on the wire.
  Supported set is 100M + 1G only; 2.5G request bits are
  masked out of the IPCNFG word.
- Get: MMD 7/60 + 7/62 (advertised), MMD 7/61 + 7/63
  (partner), EEER bit 16 (TX-LPI on), STATUS bit 1
  (link-up). `active` = link-up and advertised ∩ partner
  non-empty, with the shared bit encoding 8 = 100M,
  16 = 1G, 32 = 2.5G.
- Caveat: the MAC forces 1G full-duplex
  (CTRL_FRCSPD/FRCDPLX), so the programmed advertisement
  is negotiated by the PHY autoneg the BMCR restart
  kicks; `active` stays false until a partner negotiates
  EEE. Set is the exception to the "no set-side ethtool
  ops" rule: unlike ring/RETA changes it needs no
  stop/reconfigure sequence — Linux applies it live the
  same way.

## 5. Remainders (not silently dropped)

- **PCI SR-IOV config-space enablement + VF BAR exposure.** Needs a
  PCI-layer lane; `vt_allocate` is device-side only (it does not
  touch config space and does not publish VF BARs).
- **Mailbox interrupt pump.** Nothing polls MBVFICR or routes its
  MSI-X vector to `vt_dispatch_mailbox` yet; the dispatcher is
  callable and fixture-proven, the pump is not wired.
- **Live PF queue relocation to `rbase_offset`.** The pool math
  (`pf_queue_base = num_vfs`) and its fixtures are done, but
  bring-up is queue-0-only, so no live queue is relocated.
- **VF rate limiting** (Linux `igb_ndo_set_vf_bw`).
- **MTA restore on PF multicast-list change** (Linux
  `igb_restore_vf_multicasts`).
- **SET_LPE tighter clamp.** Linux clamps to
  `MAX_JUMBO_FRAME_SIZE`, a constant that lives outside the
  drivers-only reference trees and was not verified; this lane
  clamps to the RLPML field width (`0x3FFF`) instead. The tighter
  clamp is a remainder, not a guess.
- **PF RAR filter coordination.** This lane's filter allocator
  reserves RARs 1..3 for PF filters; any future PF filter path must
  mark those used rather than re-scanning from slot 1.
- **Later RSS reprogramming** must pass `vmdq = true` + actual RSS
  queues to `mrqc_word` (union duty with the RSS path, §4.7).
- **Spec union duty.** This file sits alongside
  `drivers/net/specification/spec.md`; whoever edits net spec
  structure next should cross-link it.
