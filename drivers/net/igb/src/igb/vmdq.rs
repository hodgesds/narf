//! igb SR-IOV / VMDq — PF-side virtualization: VT mode, VMDq pool
//! registers, the VF mailbox, and the PF/VF message interface.
//!
//! Grounding (STRICT): every register address and bit in this module
//! comes from Linux igb @ cbbddb6 (`drivers/net/ethernet/intel/igb/`:
//! `e1000_regs.h`, `e1000_82575.h`, `e1000_defines.h`, `e1000_mbx.h`,
//! `e1000_mbx.c`, `e1000_mac.c`, `igb_main.c`). No I350 datasheet copy
//! was available locally, so Linux is the authoritative source here,
//! cross-checked against the in-tree values where they overlap (MRQC
//! at 0x5818, VFTA at 0x5600, RAL0/RAH0 at 0x5400/0x5404).
//!
//! Pool model (Linux igb, NOT ixgbe's): VF `i` owns pool `i`, and the
//! PF owns pool `vfs_allocated_count` — the PF's queues sit AFTER the
//! VF pools (`rbase_offset = vfs_allocated_count`, igb_main.c:678).
//! This is the opposite of NARF ixgbe's PF-pool-0 choice; the two
//! drivers number pools differently because their Linux drivers do.
//!
//! What this module does NOT do (sequenced follow-ups, not silently
//! dropped): PCI SR-IOV config-space enablement and VF BAR exposure
//! live in `narf_bus::sriov` — `vt_allocate` is the device-side
//! allocation and the caller enables the bus half first; live PF
//! queue relocation to `rbase_offset` (NARF igb bring-up is
//! queue-0-only, so the pool-queue math here is fixture-proven until
//! a multi-queue bring-up lands); the `MAX_JUMBO_FRAME_SIZE` clamp
//! on SET_LPE (that constant lives outside the drivers-only
//! reference trees, so SET_LPE clamps to the VMOLR RLPML field width
//! instead). VF rate limiting (`igb_ndo_set_vf_bw` /
//! `igb_set_vf_rate_limit` / `igb_check_vf_rate_limit`) and MTA
//! restore on PF multicast-list change
//! (`igb_restore_vf_multicasts`) are implemented here; the PF-side
//! caller is `Igb::vt_restore_vf_multicasts` (in `igb.rs`) —
//! NARF has no `set_rx_mode` / PF MTA writer yet, so no in-tree
//! caller rewrites the PF MTA today and the restore half waits on
//! that lane (see `restore_vf_multicast`).
//!
//! The mailbox interrupt pump (`Igb::vt_mailbox_pump_step`, in
//! `igb.rs`) consumes MBVFICR and drives this dispatcher; it lives
//! there because it owns MMIO.

use super::{
    VlanFilter, IGB_82576, IGB_82576_NS, IGB_I210_COPPER, IGB_I210_COPPER_FLASHLESS,
    IGB_I210_FIBER, IGB_I210_SERDES, IGB_I210_SERDES_FLASHLESS, IGB_I210_SGMII, IGB_I211_COPPER,
    IGB_I350_COPPER,
};

/// Maximum VFs Linux igb allocates (`igb_enable_sriov` rejects
/// `num_vfs > 7`, igb_main.c:3763; `IGB_MAX_VF_FUNCTIONS` = 8 counts
/// the PF itself, igb.h:59).
pub const MAX_VFS: usize = 7;
/// PF MAC filters reserved in the RAR budget (igb.h:107).
pub const PF_MAC_FILTERS_RESERVED: usize = 3;
/// Maximum multicast hashes a VF may register (`igb_set_vf_multicasts`
/// stores at most 30; more forces VMOLR.MPME).
pub const MAX_VF_MC_HASHES: usize = 30;
/// VF mailbox words (e1000_mbx.h: `E1000_VFMAILBOX_SIZE` = 16).
pub const VFMAILBOX_WORDS: usize = 16;
/// VLVF entries (e1000_82575.h: `E1000_VLVF_ARRAY_SIZE` = 32).
pub const VLVF_ENTRIES: usize = 32;
/// Largest VF-MAC-filter pool: the biggest RAR table (I350, 32) minus
/// the PF reservation (1 default + 3 filters) minus 1 VF.
pub const MAX_VF_MAC_FILTERS: usize = 27;

/// VT_CTL — VMDq Control (e1000_regs.h:299).
pub const REG_VT_CTL: u64 = 0x0581C;
/// VT_CTL default-pool field shift (e1000_82575.h:216).
pub const VT_CTL_DEFAULT_POOL_SHIFT: u32 = 7;
/// VT_CTL default-pool field mask (e1000_82575.h:217).
pub const VT_CTL_DEFAULT_POOL_MASK: u32 = 0x7 << VT_CTL_DEFAULT_POOL_SHIFT;
/// VT_CTL IGNORE_MAC (e1000_82575.h:220).
pub const VT_CTL_IGNORE_MAC: u32 = 1 << 28;
/// VT_CTL DISABLE_DEF_POOL (e1000_82575.h:221).
pub const VT_CTL_DISABLE_DEF_POOL: u32 = 1 << 29;
/// VT_CTL VM_REPL_EN — replication enable (e1000_82575.h:222).
pub const VT_CTL_VM_REPL_EN: u32 = 1 << 30;

/// VLVF base — VLAN VM Filter, 32 entries (e1000_regs.h:347).
pub const REG_VLVF_BASE: u64 = 0x05D00;
/// VLVF VLAN-ID field (e1000_82575.h:241).
pub const VLVF_VLANID_MASK: u32 = 0x0000_0FFF;
/// VLVF pool-select field shift (e1000_82575.h:242).
pub const VLVF_POOLSEL_SHIFT: u32 = 12;
/// VLVF pool-select field mask, pools 0..7 (e1000_82575.h:243).
pub const VLVF_POOLSEL_MASK: u32 = 0xFF << VLVF_POOLSEL_SHIFT;
/// VLVF LVLAN bit (e1000_82575.h:244).
pub const VLVF_LVLAN: u32 = 0x0010_0000;
/// VLVF VLAN-ID enable (e1000_82575.h:245).
pub const VLVF_VLANID_ENABLE: u32 = 0x8000_0000;

/// VMOLR base — VM Offload, one per pool (e1000_regs.h:345).
pub const REG_VMOLR_BASE: u64 = 0x05AD0;
/// VMOLR long-packet-max-length field (e1000_82575.h:225).
pub const VMOLR_RLPML_MASK: u32 = 0x0000_3FFF;
/// VMOLR accept-long-packet (e1000_82575.h:226).
pub const VMOLR_LPE: u32 = 0x0001_0000;
/// VMOLR RSS enable (e1000_82575.h:227).
pub const VMOLR_RSSE: u32 = 0x0002_0000;
/// VMOLR accept-untagged-packets (e1000_82575.h:228).
pub const VMOLR_AUPE: u32 = 0x0100_0000;
/// VMOLR accept-overflow-multicast (e1000_82575.h:229).
pub const VMOLR_ROMPE: u32 = 0x0200_0000;
/// VMOLR accept-overflow-unicast (e1000_82575.h:230).
pub const VMOLR_ROPE: u32 = 0x0400_0000;
/// VMOLR accept-broadcast (e1000_82575.h:231).
pub const VMOLR_BAM: u32 = 0x0800_0000;
/// VMOLR multicast-promiscuous (e1000_82575.h:232).
pub const VMOLR_MPME: u32 = 0x1000_0000;
/// VMOLR VLAN-strip enable (e1000_82575.h:233).
pub const VMOLR_STRVLAN: u32 = 0x4000_0000;
/// VMOLR CRC-strip enable (e1000_82575.h:234).
pub const VMOLR_STRCRC: u32 = 0x8000_0000;

/// VMVIR base — VM VLAN Insert, one per pool (e1000_regs.h:348).
pub const REG_VMVIR_BASE: u64 = 0x03700;
/// VMVIR always-use-default-VLAN (e1000_82575.h:247).
pub const VMVIR_VLANA_DEFAULT: u32 = 0x4000_0000;
/// VMVIR never-insert-VLAN-tag (e1000_82575.h:248).
pub const VMVIR_VLANA_NEVER: u32 = 0x8000_0000;

/// VF Receive Enables (e1000_regs.h:332).
pub const REG_VFRE: u64 = 0x00C8C;
/// VF Transmit Enables (e1000_regs.h:333).
pub const REG_VFTE: u64 = 0x00C90;
/// Mailbox VF Cause, read-write-clear (e1000_regs.h:329).
pub const REG_MBVFICR: u64 = 0x00C80;
/// Mailbox VF Interrupt Mask (e1000_regs.h:330).
pub const REG_MBVFIMR: u64 = 0x00C84;
/// VF Register Events, read-write-clear (e1000_regs.h:331).
pub const REG_VFLRE: u64 = 0x00C88;
/// Mailbox VF Interrupt Mask value that unmasks every VF (Linux
/// `igb_irq_enable`: `wr32(E1000_MBVFIMR, 0xFF)` when VFs are
/// allocated).
pub const MBVFIMR_ALL_VFS: u32 = 0xFF;
/// PF<->VF mailbox memory base, 64 bytes per VF (e1000_regs.h:344).
pub const REG_VMBMEM_BASE: u64 = 0x00800;
/// PF->VF mailbox control base, one word per VF (e1000_regs.h:343).
pub const REG_P2VMAILBOX_BASE: u64 = 0x00C00;

/// RAH Address Valid (e1000_defines.h:475).
pub const RAH_AV: u32 = 0x8000_0000;
/// RAH pool-select unit (e1000_defines.h:481).
pub const RAH_POOL_1: u32 = 0x0004_0000;
/// RAH pool-select field mask (e1000_defines.h:480).
pub const RAH_POOL_MASK: u32 = 0x03FC_0000;

/// DTXSWC — DMA Tx Switch Control, 82576 (e1000_regs.h:335).
pub const REG_DTXSWC: u64 = 0x03500;
/// TXSWC — Tx Switch Control, I350/I354 (e1000_regs.h:340).
pub const REG_TXSWC: u64 = 0x05ACC;
/// Per-VF MAC-spoof bits (e1000_82575.h:209).
pub const DTXSWC_MAC_SPOOF_MASK: u32 = 0x0000_00FF;
/// Per-VF VLAN-spoof bits (e1000_82575.h:210).
pub const DTXSWC_VLAN_SPOOF_MASK: u32 = 0x0000_FF00;
/// Global VMDq loopback enable (e1000_82575.h:213).
pub const DTXSWC_VMDQ_LOOPBACK_EN: u32 = 1 << 31;

/// DTXCTL — DMA TX Control, 82576 (e1000_regs.h:186).
pub const REG_DTXCTL: u64 = 0x03590;
/// DTXCTL VLAN-added (e1000_82575.h:257).
pub const DTXCTL_VLAN_ADDED: u32 = 0x0008;
/// RPLOLR — Replication Offload (e1000_regs.h:337).
pub const REG_RPLOLR: u64 = 0x05AF0;
/// RPLOLR VLAN-strip (e1000_82575.h:253).
pub const RPLOLR_STRVLAN: u32 = 0x4000_0000;

/// RTTDQSEL — Tx Desc Plane Queue Select (e1000_regs.h:233).
/// Write-only: selects which VF's queue the RTTBCNRC write that
/// follows applies to (Linux `igb_set_vf_rate_limit`: "vf X uses
/// queue X").
pub const REG_RTTDQSEL: u64 = 0x3604;
/// RTTBCNRM — Tx BCN Rate-scheduler MMW (e1000_regs.h:235).
/// Linux `igb_set_vf_rate_limit` always writes 0x14 here (the
/// MMW_SIZE for 9728-byte jumbo support).
pub const REG_RTTBCNRM: u64 = 0x3690;
/// RTTBCNRM value Linux programs (igb_main.c:18307).
pub const RTTBCNRM_MMW_SIZE: u32 = 0x14;
/// RTTBCNRC — Tx BCN Rate-Scheduler Config (e1000_regs.h:237).
/// Write-only: the rate-factor word for the queue RTTDQSEL
/// selected.
pub const REG_RTTBCNRC: u64 = 0x36B0;
/// RTTBCNRC rate-scheduler enable (e1000_defines.h:1936).
pub const RTTBCNRC_RS_ENA: u32 = 0x8000_0000;
/// RTTBCNRC fractional rate-factor mask (e1000_defines.h:1938).
pub const RTTBCNRC_RF_DEC_MASK: u32 = 0x0000_3FFF;
/// RTTBCNRC integer rate-factor shift (e1000_defines.h:1940).
pub const RTTBCNRC_RF_INT_SHIFT: u32 = 14;
/// RTTBCNRC integer rate-factor mask (e1000_defines.h:1942-1944:
/// `RF_DEC_MASK << RF_INT_SHIFT`).
pub const RTTBCNRC_RF_INT_MASK: u32 = 0x0FFF_C000;

/// MTA base — Multicast Table Array, 128 words (e1000_regs.h:283).
pub const REG_MTA_BASE: u64 = 0x05200;
/// MTA words (e1000_82575.c: `mta_reg_count` = 128).
pub const MTA_WORDS: usize = 128;

/// DVMOLR base — I350 VLAN-strip offload, 64 bytes per pool
/// (e1000_regs.h:346). Only used for the strip bit on I350; every
/// other pool's VMOLR lives at `REG_VMOLR_BASE`.
pub const REG_DVMOLR_BASE: u64 = 0x0C038;

/// Mailbox control bits (e1000_mbx.h).
pub const P2VMAILBOX_STS: u32 = 0x0000_0001;
/// Mailbox ACK bit (e1000_mbx.h).
pub const P2VMAILBOX_ACK: u32 = 0x0000_0002;
/// Mailbox VF-owns-buffer bit (e1000_mbx.h).
pub const P2VMAILBOX_VFU: u32 = 0x0000_0004;
/// Mailbox PF-owns-buffer bit (e1000_mbx.h).
pub const P2VMAILBOX_PFU: u32 = 0x0000_0008;
/// Mailbox reset-VFU bit (e1000_mbx.h).
pub const P2VMAILBOX_RVFU: u32 = 0x0000_0010;

/// Mailbox VF-request bits in MBVFICR (e1000_mbx.h).
pub const MBVFICR_VFREQ_MASK: u32 = 0x0000_00FF;
/// Mailbox VF-ack bits in MBVFICR (e1000_mbx.h).
pub const MBVFICR_VFACK_MASK: u32 = 0x00FF_0000;

/// Message-type ACK flag (e1000_mbx.h).
pub const VT_MSGTYPE_ACK: u32 = 0x8000_0000;
/// Message-type NACK flag (e1000_mbx.h).
pub const VT_MSGTYPE_NACK: u32 = 0x4000_0000;
/// Message-type clear-to-send flag (e1000_mbx.h).
pub const VT_MSGTYPE_CTS: u32 = 0x2000_0000;
/// Message-info field shift (e1000_mbx.h).
pub const VT_MSGINFO_SHIFT: u32 = 16;
/// Message-info field mask (e1000_mbx.h).
pub const VT_MSGINFO_MASK: u32 = 0xFF << VT_MSGINFO_SHIFT;

/// VF requests reset (e1000_mbx.h).
pub const VF_RESET: u32 = 0x01;
/// VF requests MAC address set (e1000_mbx.h).
pub const VF_SET_MAC_ADDR: u32 = 0x02;
/// VF requests multicast set (e1000_mbx.h).
pub const VF_SET_MULTICAST: u32 = 0x03;
/// VF requests VLAN set (e1000_mbx.h).
pub const VF_SET_VLAN: u32 = 0x04;
/// VF requests long-packet-max-length set (e1000_mbx.h).
pub const VF_SET_LPE: u32 = 0x05;
/// VF requests promiscuous set (e1000_mbx.h).
pub const VF_SET_PROMISC: u32 = 0x06;
/// MAC-filter clear info (e1000_mbx.h).
pub const VF_MAC_FILTER_CLR: u32 = 0x01 << VT_MSGINFO_SHIFT;
/// MAC-filter add info (e1000_mbx.h).
pub const VF_MAC_FILTER_ADD: u32 = 0x02 << VT_MSGINFO_SHIFT;
/// Promiscuous-multicast info (e1000_mbx.h).
pub const VF_SET_PROMISC_MULTICAST: u32 = 0x02 << VT_MSGINFO_SHIFT;
/// PF control message (e1000_mbx.h).
pub const PF_CONTROL_MSG: u32 = 0x0100;

/// VLVF register address for entry `i` (0..32).
pub const fn vlvf_addr(i: usize) -> u64 {
    REG_VLVF_BASE + (i as u64) * 4
}

/// VMOLR register address for pool `p` (0..8).
pub const fn vmolr_addr(p: usize) -> u64 {
    REG_VMOLR_BASE + (p as u64) * 4
}

/// VMVIR register address for pool `p` (0..8).
pub const fn vmvir_addr(p: usize) -> u64 {
    REG_VMVIR_BASE + (p as u64) * 4
}

/// Mailbox-memory word address for VF `vf`, word `w` (0..16).
pub const fn vmbmem_addr(vf: usize, w: usize) -> u64 {
    REG_VMBMEM_BASE + (vf as u64) * 64 + (w as u64) * 4
}

/// P2V mailbox-control address for VF `vf`.
pub const fn p2vmailbox_addr(vf: usize) -> u64 {
    REG_P2VMAILBOX_BASE + (vf as u64) * 4
}

/// MTA word address for word `w` (0..128).
pub const fn mta_addr(w: usize) -> u64 {
    REG_MTA_BASE + (w as u64) * 4
}

/// RAL address for RAR entry `i` (e1000_regs.h:287-289: entries 0..15
/// at 0x5400, entries 16..31 at 0x54E0).
pub const fn ral_addr(i: usize) -> u64 {
    if i <= 15 {
        0x05400 + (i as u64) * 8
    } else {
        0x054E0 + ((i - 16) as u64) * 8
    }
}

/// RAH address for RAR entry `i` (same split as [`ral_addr`]).
pub const fn rah_addr(i: usize) -> u64 {
    if i <= 15 {
        0x05404 + (i as u64) * 8
    } else {
        0x054E4 + ((i - 16) as u64) * 8
    }
}

/// RAR entry count for a claimed device id (e1000_82575.c:412-427:
/// 82576/82580 -> 24, I350/I354 -> 32, default -> 16; NARF claims no
/// 82580, and the I210/I211 family takes the default 16). `None` for
/// an id this driver does not claim.
pub const fn rar_entries_for_device(device_id: u16) -> Option<usize> {
    match device_id {
        IGB_82576 | IGB_82576_NS => Some(24),
        IGB_I350_COPPER => Some(32),
        IGB_I210_COPPER
        | IGB_I210_FIBER
        | IGB_I210_SERDES
        | IGB_I210_SGMII
        | IGB_I210_COPPER_FLASHLESS
        | IGB_I210_SERDES_FLASHLESS
        | IGB_I211_COPPER => Some(16),
        _ => None,
    }
}

/// How a RAR entry encodes its pool: 82575/I210 use a numeric pool
/// field (`RAH_POOL_1 * pool`, igb_main.c `igb_rar_set_index`); every
/// other family uses a one-hot bit (`RAH_POOL_1 << pool`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PoolEncoding {
    /// Numeric field (I210 family).
    Numeric,
    /// One-hot bit (82576, I350, I211).
    OneHot,
}

/// Pool encoding for a claimed device id. `None` for unclaimed ids.
pub const fn pool_encoding_for_device(device_id: u16) -> Option<PoolEncoding> {
    match device_id {
        IGB_I210_COPPER
        | IGB_I210_FIBER
        | IGB_I210_SERDES
        | IGB_I210_SGMII
        | IGB_I210_COPPER_FLASHLESS
        | IGB_I210_SERDES_FLASHLESS => Some(PoolEncoding::Numeric),
        IGB_82576 | IGB_82576_NS | IGB_I350_COPPER | IGB_I211_COPPER => Some(PoolEncoding::OneHot),
        _ => None,
    }
}

/// Which switch-control registers a device family programs under
/// `igb_vmm_control` (e1000_82575.c): 82576 uses DTXSWC + DTXCTL +
/// RPLOLR; I350 uses TXSWC only; I210/I211 program none of them
/// (`vmm_control` returns early for those families).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SwitchFamily {
    /// 82576/82576-NS: DTXSWC + DTXCTL + RPLOLR.
    Dtxswc82576,
    /// I350: TXSWC only.
    TxswcI350,
    /// I210/I211: no switch registers.
    None,
}

/// Switch family for a claimed device id. `None` for unclaimed ids is
/// expressed as `Some(SwitchFamily::None)` for claimed I210/I211;
/// unclaimed ids return `None`.
pub const fn switch_family_for_device(device_id: u16) -> Option<SwitchFamily> {
    match device_id {
        IGB_82576 | IGB_82576_NS => Some(SwitchFamily::Dtxswc82576),
        IGB_I350_COPPER => Some(SwitchFamily::TxswcI350),
        IGB_I210_COPPER
        | IGB_I210_FIBER
        | IGB_I210_SERDES
        | IGB_I210_SGMII
        | IGB_I210_COPPER_FLASHLESS
        | IGB_I210_SERDES_FLASHLESS
        | IGB_I211_COPPER => Some(SwitchFamily::None),
        _ => None,
    }
}

/// Pool index for VF `vf` (Linux: VF pools come first).
pub const fn vf_pool(vf: usize) -> usize {
    vf
}

/// Pool index for the PF when `num_vfs` VFs are allocated (Linux:
/// `pf_id = vfs_allocated_count`, igb_main.c:1522).
pub const fn pf_pool(num_vfs: usize) -> usize {
    num_vfs
}

/// PF queue register base when `num_vfs` VFs are allocated (Linux:
/// `rbase_offset = vfs_allocated_count`, igb_main.c:678 — the PF's
/// queue `i` lives at register index `num_vfs + i`). NARF igb
/// bring-up is queue-0-only today, so this is fixture-proven math
/// until a multi-queue bring-up relocates the live PF queues.
pub const fn pf_queue_base(num_vfs: usize) -> usize {
    num_vfs
}

/// RAR entry holding VF `vf`'s primary MAC (Linux `igb_set_vf_mac`:
/// VF MACs start at the end of the RAR table and move toward the
/// first, so a collision with PF entries is impossible).
pub const fn primary_rar(rar_entry_count: usize, vf: usize) -> usize {
    rar_entry_count - (vf + 1)
}

/// VF-MAC-filter entries available when `num_vfs` VFs are allocated
/// (Linux `igb_enable_sriov`: RAR count minus 1 PF default, minus
/// `PF_MAC_FILTERS_RESERVED` PF filters, minus one primary per VF).
/// `None` when the table cannot even hold the primaries.
pub const fn vf_mac_filter_count(rar_entry_count: usize, num_vfs: usize) -> Option<usize> {
    let reserved = 1 + PF_MAC_FILTERS_RESERVED + num_vfs;
    if rar_entry_count < reserved {
        None
    } else {
        Some(rar_entry_count - reserved)
    }
}

/// VT_CTL word with the default pool set to `num_vfs` (Linux
/// `igb_setup_mrqc`: clear DEFAULT_POOL_MASK | DISABLE_DEF_POOL,
/// then set `vfs_allocated_count << DEFAULT_POOL_SHIFT`).
pub const fn vt_ctl_default_pool_word(current: u32, num_vfs: usize) -> u32 {
    (current & !(VT_CTL_DEFAULT_POOL_MASK | VT_CTL_DISABLE_DEF_POOL))
        | ((num_vfs as u32) << VT_CTL_DEFAULT_POOL_SHIFT)
}

/// VT_CTL word with replication enabled or disabled (Linux
/// `igb_vmdq_set_replication_pf`).
pub const fn vt_ctl_replication_word(current: u32, enable: bool) -> u32 {
    if enable {
        current | VT_CTL_VM_REPL_EN
    } else {
        current & !VT_CTL_VM_REPL_EN
    }
}

/// Switch-control word with VMDq loopback enabled or disabled (Linux
/// `igb_vmdq_set_loopback_pf`: the global bit; the per-family
/// register itself is chosen by [`switch_family_for_device`]).
pub const fn switch_loopback_word(current: u32, enable: bool) -> u32 {
    if enable {
        current | DTXSWC_VMDQ_LOOPBACK_EN
    } else {
        current & !DTXSWC_VMDQ_LOOPBACK_EN
    }
}

/// Switch-control word with anti-spoofing enabled for every VF except
/// the PF pool (Linux `igb_vmdq_set_anti_spoofing_pf`: set both spoof
/// masks, then XOR the PF's MAC-spoof bit and VLAN-spoof bit back
/// off — the PF must be able to spoof for emulation-mode NICs).
pub const fn switch_antispoof_word(current: u32, pf_pool_idx: usize) -> u32 {
    let with_masks = current | DTXSWC_MAC_SPOOF_MASK | DTXSWC_VLAN_SPOOF_MASK;
    with_masks ^ ((1 << pf_pool_idx) | (1 << (pf_pool_idx + 8)))
}

/// Switch-control word with anti-spoofing fully disabled (Linux
/// `igb_vmdq_set_anti_spoofing_pf` with `enable = false`).
pub const fn switch_antispoof_off_word(current: u32) -> u32 {
    current & !(DTXSWC_MAC_SPOOF_MASK | DTXSWC_VLAN_SPOOF_MASK)
}

/// Switch-control word with VF `vf`'s spoof bits set or cleared
/// (Linux anti-spoofing bit positions, proved by
/// `igb_vmdq_set_anti_spoofing_pf`'s `BIT(pf) | BIT(pf + 8)`
/// toggle: MAC-spoof bit `vf`, VLAN-spoof bit `vf + 8`).
pub const fn switch_spoofchk_word(current: u32, vf: usize, enable: bool) -> u32 {
    let bits = (1 << vf) | (1 << (vf + 8));
    if enable {
        current | bits
    } else {
        current & !bits
    }
}

/// RAR register pair for `mac` steered to `pool` (Linux
/// `igb_rar_set_index`: low = MAC bytes 0..4 little-endian, high =
/// bytes 4..6 plus AV when valid, plus the pool encoding whenever
/// the entry is in use — even for an invalid address, which Linux
/// programs with pool bits but no AV). A cleared entry (`in_use`
/// false) programs (0, 0): Linux writes the zeroed address with no
/// AV and no pool bits.
pub const fn rar_words(
    mac: [u8; 6],
    pool: usize,
    encoding: PoolEncoding,
    in_use: bool,
    valid: bool,
) -> (u32, u32) {
    if !in_use {
        return (0, 0);
    }
    let lo = (mac[0] as u32)
        | ((mac[1] as u32) << 8)
        | ((mac[2] as u32) << 16)
        | ((mac[3] as u32) << 24);
    let mut hi = (mac[4] as u32) | ((mac[5] as u32) << 8);
    if valid {
        hi |= RAH_AV;
    }
    hi |= match encoding {
        PoolEncoding::Numeric => RAH_POOL_1 * (pool as u32),
        PoolEncoding::OneHot => RAH_POOL_1 << pool,
    };
    (lo, hi)
}

/// Whether `mac` is a valid unicast address for a VF filter (Linux
/// `is_valid_ether_addr`: not multicast, not all-zero).
pub const fn is_valid_ether_addr(mac: [u8; 6]) -> bool {
    mac[0] & 1 == 0
        && !(mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0)
}

/// Whether `mac` is all-zero (Linux `is_zero_ether_addr`).
pub const fn is_zero_ether_addr(mac: [u8; 6]) -> bool {
    mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0
}

/// MTA word/bit for a multicast hash (Linux `igb_mta_set`: the table
/// is 128 words; the word is hash bits 31:5 masked by 127, the bit
/// is hash bits 4:0, OR-ed in).
pub const fn mta_set(hash: u16) -> (usize, u32) {
    let word = ((hash as usize) >> 5) & (MTA_WORDS - 1);
    let bit = 1u32 << (hash & 0x1F);
    (word, bit)
}

/// Whether this device id has the e1000_82576 MAC type, the only
/// one Linux rate limiting supports (`igb_ndo_set_vf_bw` /
/// `igb_check_vf_rate_limit` bail unless `hw->mac.type ==
/// e1000_82576`). The mapping is `igb_get_invariants_82575`
/// (e1000_82575.c:1069-1087); NARF claims only the 82576 and
/// 82576-NS ids of that family.
pub const fn rate_limit_supported(device_id: u16) -> bool {
    device_id == IGB_82576 || device_id == IGB_82576_NS
}

/// RTTBCNRC word for `tx_rate` Mbps on a `link_speed` Mbps link
/// (Linux `igb_set_vf_rate_limit`): 0 when unthrottled, else
/// RS_ENA plus the integer rate factor (`link_speed / tx_rate`,
/// FIELD_PREP'd into RF_INT_MASK) plus the fractional remainder
/// scaled by 2^14 (`(link_speed - rf_int * tx_rate) * 2^14 /
/// tx_rate`, masked to RF_DEC_MASK). The remainder arithmetic
/// runs in u64 so the scaling cannot overflow; the integer field
/// is masked before shifting, which is exactly FIELD_PREP's
/// semantics.
pub const fn vf_rate_limit_bcnrc(tx_rate: u32, link_speed: u32) -> u32 {
    if tx_rate == 0 {
        return 0;
    }
    let rf_int = link_speed / tx_rate;
    let rf_dec = (((link_speed - rf_int * tx_rate) as u64 * (1u64 << RTTBCNRC_RF_INT_SHIFT))
        / tx_rate as u64) as u32;
    RTTBCNRC_RS_ENA
        | ((rf_int & RTTBCNRC_RF_DEC_MASK) << RTTBCNRC_RF_INT_SHIFT)
        | (rf_dec & RTTBCNRC_RF_DEC_MASK)
}

/// Errors from VT configuration and mailbox dispatch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmdqError {
    /// VF index out of range for the allocation.
    BadVf,
    /// VF count out of range (must be 1..=7).
    BadVfCount,
    /// Device id not claimed by this driver.
    UnknownDevice,
    /// RAR table too small for the VF primaries.
    NoRarSpace,
    /// No free VF-MAC-filter entry.
    NoMacFilterSpace,
    /// No free VLVF entry for a VLAN.
    NoVlvfSpace,
    /// VID out of range (> 4095).
    BadVid,
    /// Message malformed (short buffer, unknown type, leftover info).
    BadMessage,
    /// Operation refused (untrusted VF overriding a PF-set MAC,
    /// VF overriding an admin-set VLAN, invalid MAC).
    Refused,
    /// Rate limiting is not supported on this MAC type (Linux
    /// `igb_ndo_set_vf_bw` returns -EOPNOTSUPP unless the MAC type
    /// is e1000_82576).
    Unsupported,
    /// A program overflowed its fixed write budget (fail-closed:
    /// nothing is applied).
    ProgramOverflow,
}

/// Shadow of the 32 VLVF registers. The shadow IS the programmed
/// state: every mutation here is paired with a register write by the
/// caller, mirroring Linux's read-modify-write on the live registers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VlvfTable {
    /// Entry words, index = VLVF slot.
    pub entries: [u32; VLVF_ENTRIES],
}

impl VlvfTable {
    /// Empty table (no VLAN has a pool filter).
    pub const fn new() -> Self {
        Self {
            entries: [0; VLVF_ENTRIES],
        }
    }

    /// Pool bit for pool `p`.
    pub const fn pool_bit(pool: usize) -> u32 {
        1 << (VLVF_POOLSEL_SHIFT + pool as u32)
    }

    /// Entry index holding `vid`, if any (Linux `igb_find_vlvf_entry`:
    /// VLAN 0 always maps to slot 0; other VIDs search slots 31..1).
    pub fn find_entry(&self, vid: u16) -> Option<usize> {
        if vid == 0 {
            return Some(0);
        }
        let mut idx = VLVF_ENTRIES;
        while idx > 1 {
            idx -= 1;
            if self.entries[idx] & VLVF_VLANID_MASK == vid as u32 {
                return Some(idx);
            }
        }
        None
    }

    /// Slot for `vid` (Linux `igb_find_vlvf_slot`): the existing entry,
    /// else the first empty slot scanning 31..1; slot 0 is reserved
    /// for VLAN 0 and never allocated for another VID. With `bypass`,
    /// no empty slot is allocated (`None` when unmatched). `None`
    /// without bypass means the table is full.
    pub fn find_slot(&self, vid: u16, bypass: bool) -> Option<usize> {
        if vid == 0 {
            return Some(0);
        }
        if let Some(idx) = self.find_entry(vid) {
            return Some(idx);
        }
        if bypass {
            return None;
        }
        let mut idx = VLVF_ENTRIES;
        while idx > 1 {
            idx -= 1;
            if self.entries[idx] & VLVF_VLANID_MASK == 0 {
                return Some(idx);
            }
        }
        None
    }

    /// Pool bits currently set in entry `idx`.
    pub fn pools(&self, idx: usize) -> u32 {
        self.entries[idx] & VLVF_POOLSEL_MASK
    }
}

impl Default for VlvfTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-VF PF-side state (Linux `vf_data_storage`, minus the kernel
/// list/timer fields NARF has no use for).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VfState {
    /// Current primary MAC (zero = unset).
    pub mac: [u8; 6],
    /// PF administratively set the MAC (Linux `IGB_VF_FLAG_PF_SET_MAC`).
    pub pf_set_mac: bool,
    /// VF is trusted (Linux `IGB_VF_FLAG_TRUSTED` — a trusted VF may
    /// override a PF-set MAC).
    pub trusted: bool,
    /// Spoof checking enabled (Linux default: true).
    pub spoofchk_enabled: bool,
    /// Clear to send (Linux `IGB_VF_FLAG_CTS` — set by RESET, gates
    /// every other message).
    pub cts: bool,
    /// An ack-NACK has already been sent for this non-CTS epoch
    /// (the pump's `igb_rcv_ack_from_vf` equivalent). Linux
    /// rate-limits that NACK to once per 2 s (`last_nack`); NARF
    /// has no jiffies here, so one NACK per reset epoch bounds the
    /// same spam. Cleared by `vf_reset` and when CTS is earned.
    pub ack_nack_sent: bool,
    /// Admin-assigned port VLAN, 0 = none (Linux `pf_vlan`).
    pub pf_vlan: u16,
    /// Admin-assigned port VLAN QoS (Linux `pf_qos`).
    pub pf_qos: u8,
    /// Stored multicast hashes (first 30 of the VF's list).
    pub mc_hashes: [u16; MAX_VF_MC_HASHES],
    /// Full multicast count as reported by the VF (uncapped: > 30
    /// forces VMOLR.MPME even though only 30 hashes are stored).
    pub mc_count: usize,
    /// VF asked for multicast-promiscuous (Linux
    /// `IGB_VF_FLAG_MULTI_PROMISC`, set by SET_PROMISC with the
    /// multicast bit, cleared by every other SET_PROMISC and by
    /// VF reset). `restore_vf_multicast` re-applies MPME for it
    /// instead of the stored hashes.
    pub multi_promisc: bool,
    /// Admin-set TX rate limit in Mbps, 0 = unthrottled (Linux
    /// `vf_data_storage.tx_rate`, `igb_ndo_set_vf_bw`). Survives
    /// VF reset, like Linux's (only a link-speed change clears it,
    /// via `check_vf_rate_limit`).
    pub tx_rate: u16,
    /// VLAN stripping enabled for this VF (VMOLR.STRVLAN).
    pub vlan_strip: bool,
}

impl VfState {
    /// Fresh VF state (Linux `igb_vf_configure`: zero MAC, spoof
    /// check on, untrusted, not clear-to-send).
    pub const fn new() -> Self {
        Self {
            mac: [0; 6],
            pf_set_mac: false,
            trusted: false,
            spoofchk_enabled: true,
            cts: false,
            ack_nack_sent: false,
            pf_vlan: 0,
            pf_qos: 0,
            mc_hashes: [0; MAX_VF_MC_HASHES],
            mc_count: 0,
            multi_promisc: false,
            tx_rate: 0,
            vlan_strip: false,
        }
    }
}

impl Default for VfState {
    fn default() -> Self {
        Self::new()
    }
}

/// One VF-MAC-filter entry (Linux `vf_mac_filter` list node).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VfMacFilter {
    /// Owning VF, `None` = free entry.
    pub owner: Option<usize>,
    /// Filter MAC.
    pub mac: [u8; 6],
    /// RAR slot programming this filter, `None` when free.
    pub rar: Option<usize>,
}

impl VfMacFilter {
    /// Free entry.
    pub const fn free() -> Self {
        Self {
            owner: None,
            mac: [0; 6],
            rar: None,
        }
    }
}

/// PF-side VT state: the allocation plus every shadow the mailbox
/// dispatcher mutates. VMOLR shadows are per pool (VF pools first,
/// PF pool last at index `num_vfs`); only VF pools are touched by
/// dispatch — the PF pool's VMOLR belongs to the RX-mode path.
#[derive(Clone, Debug)]
pub struct VtState {
    /// Device id this allocation belongs to.
    pub device_id: u16,
    /// Allocated VF count (1..=7).
    pub num_vfs: usize,
    /// RAR entries on this device.
    pub rar_entry_count: usize,
    /// RAR pool encoding for this device.
    pub pool_encoding: PoolEncoding,
    /// Per-VF state.
    pub vfs: [VfState; MAX_VFS],
    /// VLVF shadow.
    pub vlvf: VlvfTable,
    /// VF-MAC-filter pool (free entries have `owner == None`).
    pub mac_filters: [VfMacFilter; MAX_VF_MAC_FILTERS],
    /// Live filter entries (<= `MAX_VF_MAC_FILTERS`).
    pub mac_filter_count: usize,
    /// VMOLR shadow per pool (index = pool).
    pub vmolr: [u32; 8],
    /// DVMOLR shadow per pool (I350 only: the strip bit lives in
    /// DVMOLR there, not VMOLR).
    pub dvmolr: [u32; 8],
    /// VFRE shadow (bit `vf` = VF receive enabled).
    pub vfre: u32,
    /// VFTE shadow (bit `vf` = VF transmit enabled).
    pub vfte: u32,
    /// PF VLAN-promiscuous flag (Linux `IGB_FLAG_VLAN_PROMISC` —
    /// no production setter exists yet, so this stays false until a
    /// promiscuous-VLAN path sets it).
    pub vlan_promisc: bool,
    /// Link speed in Mbps the VF rate limits were programmed
    /// against (Linux `adapter->vf_rate_link_speed`, set by
    /// `igb_ndo_set_vf_bw`, cleared by `igb_check_vf_rate_limit`
    /// on a speed change). 0 = no rate limit was ever set, so the
    /// re-check is a no-op.
    pub vf_rate_link_speed: u32,
}

impl VtState {
    /// Allocate `num_vfs` VFs for `device_id` (Linux `igb_enable_sriov`
    /// validation: MSI-X is the caller's check, count 1..=7, RAR
    /// budget must hold the primaries). VF state starts as Linux
    /// `igb_vf_configure` leaves it; VMOLR shadows start at zero and
    /// are built by reset/dispatch, matching Linux's read-modify-write
    /// from the reset value.
    pub fn new(device_id: u16, num_vfs: usize) -> Result<Self, VmdqError> {
        if num_vfs == 0 || num_vfs > MAX_VFS {
            return Err(VmdqError::BadVfCount);
        }
        let rar_entry_count = rar_entries_for_device(device_id).ok_or(VmdqError::UnknownDevice)?;
        let pool_encoding = pool_encoding_for_device(device_id).ok_or(VmdqError::UnknownDevice)?;
        let mac_filter_count =
            vf_mac_filter_count(rar_entry_count, num_vfs).ok_or(VmdqError::NoRarSpace)?;
        Ok(Self {
            device_id,
            num_vfs,
            rar_entry_count,
            pool_encoding,
            vfs: [VfState::new(); MAX_VFS],
            vlvf: VlvfTable::new(),
            mac_filters: [VfMacFilter::free(); MAX_VF_MAC_FILTERS],
            mac_filter_count,
            vmolr: [0; 8],
            dvmolr: [0; 8],
            vfre: 0,
            vfte: 0,
            vlan_promisc: false,
            vf_rate_link_speed: 0,
        })
    }

    /// Pool index for VF `vf`, or `BadVf`.
    pub fn check_vf(&self, vf: usize) -> Result<usize, VmdqError> {
        if vf >= self.num_vfs {
            return Err(VmdqError::BadVf);
        }
        Ok(vf_pool(vf))
    }
}

/// One register write in a [`Program`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RegWrite {
    /// Register address.
    pub addr: u64,
    /// Value to program.
    pub value: u32,
}

impl RegWrite {
    /// One write.
    pub const fn new(addr: u64, value: u32) -> Self {
        Self { addr, value }
    }
}

/// A bounded set of register writes plus VFTA consequences, returned
/// by every state-changing operation so the caller (which owns MMIO)
/// can apply it. Bounded so a runaway operation fails closed with
/// [`VmdqError::ProgramOverflow`] instead of silently dropping a
/// write. VFTA consequences are VID add/remove operations, not raw
/// writes: the caller applies them through the existing `VlanFilter`
/// shadow (one word write each), keeping a single VFTA authority.
///
/// Application order is load-bearing (Linux `igb_vfta_set`): a
/// remove that disables an entry (last pool out) must clear its
/// VFTA bit BEFORE the entry write, or a packet for that VID could
/// leak into the PF via the default pool in between; an add must
/// program the VLVF entry BEFORE its VFTA bit, for the mirror
/// reason. So callers apply in this order: VFTA clears for
/// `vlan_removes`, then register writes (and MTA sets), then VFTA
/// sets for `vlan_adds`. `Igb::vt_dispatch_mailbox` is the
/// reference application of this order.
#[derive(Clone, Debug)]
pub struct Program {
    /// Register writes.
    pub writes: [RegWrite; 48],
    /// Live writes.
    pub n_writes: usize,
    /// MTA OR-sets (address + bit to OR in, read-modify-write).
    pub mta_sets: [(u64, u32); MAX_VF_MC_HASHES],
    /// Live MTA sets.
    pub n_mta_sets: usize,
    /// VIDs whose VFTA bit must be set.
    pub vlan_adds: [u16; 4],
    /// Live VLAN adds.
    pub n_vlan_adds: usize,
    /// VIDs whose VFTA bit must be cleared.
    pub vlan_removes: [u16; VLVF_ENTRIES],
    /// Live VLAN removes.
    pub n_vlan_removes: usize,
}

impl Program {
    /// Empty program.
    pub const fn new() -> Self {
        Self {
            writes: [RegWrite { addr: 0, value: 0 }; 48],
            n_writes: 0,
            mta_sets: [(0, 0); MAX_VF_MC_HASHES],
            n_mta_sets: 0,
            vlan_adds: [0; 4],
            n_vlan_adds: 0,
            vlan_removes: [0; VLVF_ENTRIES],
            n_vlan_removes: 0,
        }
    }

    /// Push a register write, or overflow.
    pub fn push_write(&mut self, addr: u64, value: u32) -> Result<(), VmdqError> {
        if self.n_writes >= self.writes.len() {
            return Err(VmdqError::ProgramOverflow);
        }
        self.writes[self.n_writes] = RegWrite { addr, value };
        self.n_writes += 1;
        Ok(())
    }

    /// Push an MTA OR-set, or overflow.
    pub fn push_mta(&mut self, addr: u64, bit: u32) -> Result<(), VmdqError> {
        if self.n_mta_sets >= self.mta_sets.len() {
            return Err(VmdqError::ProgramOverflow);
        }
        self.mta_sets[self.n_mta_sets] = (addr, bit);
        self.n_mta_sets += 1;
        Ok(())
    }

    /// Record a VFTA-bit set, or overflow.
    pub fn push_vlan_add(&mut self, vid: u16) -> Result<(), VmdqError> {
        if self.n_vlan_adds >= self.vlan_adds.len() {
            return Err(VmdqError::ProgramOverflow);
        }
        self.vlan_adds[self.n_vlan_adds] = vid;
        self.n_vlan_adds += 1;
        Ok(())
    }

    /// Record a VFTA-bit clear, or overflow.
    pub fn push_vlan_remove(&mut self, vid: u16) -> Result<(), VmdqError> {
        if self.n_vlan_removes >= self.vlan_removes.len() {
            return Err(VmdqError::ProgramOverflow);
        }
        self.vlan_removes[self.n_vlan_removes] = vid;
        self.n_vlan_removes += 1;
        Ok(())
    }
}

impl Default for Program {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of a PF-side VLAN add/remove through the VMDq-aware path
/// (Linux `igb_vfta_set` + `igb_update_pf_vlvf`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PfVlanOutcome {
    /// VLVF write to apply, if the entry changed.
    pub vlvf_write: Option<(usize, u32)>,
    /// Whether the VFTA bit changed (caller writes the shadow word
    /// only when true — other pools may keep the bit set).
    pub vfta_changed: bool,
}

impl VtState {
    /// VMDq-aware VFTA/VLVF update for one VID and pool (Linux
    /// `igb_vfta_set`, two-part algorithm: the VFTA bit is computed
    /// first but only written once the VLVF part succeeds). `bypass`
    /// selects the VLVF-bypass path (VFTA-only when no entry matches
    /// and no slot is free). Returns the VLVF write and whether the
    /// VFTA bit changed; the caller owns the VFTA shadow and writes
    /// the word only when `vfta_changed` is true.
    ///
    /// `vfta_bit_set` is the caller's current VFTA bit for `vid`
    /// (read from its shadow before this call).
    pub fn vfta_set(
        &mut self,
        vid: u16,
        pool: usize,
        vlan_on: bool,
        bypass: bool,
        vfta_bit_set: bool,
    ) -> Result<PfVlanOutcome, VmdqError> {
        if vid > 4095 {
            return Err(VmdqError::BadVid);
        }
        // Part 1: the VFTA delta (XOR mask against the current bit).
        let vfta_delta = vlan_on != vfta_bit_set;
        // Part 2: the VLVF half. With no VFs this function is never
        // called (the PF-only path skips VLVF entirely), so reaching
        // here with zero VFs is a caller bug, not a silent no-op.
        if self.num_vfs == 0 {
            return Err(VmdqError::BadVfCount);
        }
        let Some(idx) = self.vlvf.find_slot(vid, bypass) else {
            if bypass {
                // VFTA-only fallback: the VLAN still filters for the
                // PF via the default pool.
                return Ok(PfVlanOutcome {
                    vlvf_write: None,
                    vfta_changed: vfta_delta,
                });
            }
            return Err(VmdqError::NoVlvfSpace);
        };
        let mut bits = self.vlvf.entries[idx];
        bits |= VlvfTable::pool_bit(pool);
        if !vlan_on {
            bits ^= VlvfTable::pool_bit(pool);
            if bits & VLVF_POOLSEL_MASK == 0 {
                // Last pool left: clear the VFTA bit first (so no
                // stray packet leaks in via the default pool), then
                // disable the entry.
                self.vlvf.entries[idx] = 0;
                return Ok(PfVlanOutcome {
                    vlvf_write: Some((idx, 0)),
                    vfta_changed: vfta_delta,
                });
            }
            // Other pools still use this VID: the VFTA bit stays.
            let value = bits | (vid as u32) | VLVF_VLANID_ENABLE;
            self.vlvf.entries[idx] = value;
            return Ok(PfVlanOutcome {
                vlvf_write: Some((idx, value)),
                vfta_changed: false,
            });
        }
        let value = bits | (vid as u32) | VLVF_VLANID_ENABLE;
        self.vlvf.entries[idx] = value;
        Ok(PfVlanOutcome {
            vlvf_write: Some((idx, value)),
            vfta_changed: vfta_delta,
        })
    }

    /// PF-pool cleanup after a VF VLAN add failure or remove (Linux
    /// `igb_update_pf_vlvf`): when no pool other than the PF still
    /// uses `vid`, disable the entry — or, under VLAN promiscuous
    /// mode, leave just the PF pool bit (no VID, no enable). Returns
    /// the VLVF write, if any. No-op when no entry exists.
    pub fn update_pf_vlvf(&mut self, vid: u16) -> Option<(usize, u32)> {
        let idx = self.vlvf.find_entry(vid)?;
        // VLAN 0 maps to slot 0, which `find_entry` returns for vid 0
        // — but Linux `igb_update_pf_vlvf` returns early for idx 0
        // (no entry, or the VLAN-0 entry, is never touched here).
        if idx == 0 {
            return None;
        }
        let pf_bit = VlvfTable::pool_bit(pf_pool(self.num_vfs));
        let others = (!pf_bit) & VLVF_POOLSEL_MASK & self.vlvf.entries[idx];
        if others != 0 {
            return None;
        }
        let value = if self.vlan_promisc { pf_bit } else { 0 };
        self.vlvf.entries[idx] = value;
        Some((idx, value))
    }

    /// Remove VF `vf`'s pool bit from every VLVF entry (Linux
    /// `igb_clear_vf_vfta`), returning the program: entry writes plus
    /// VFTA-bit clears for VIDs that lost their last pool. The PF
    /// pool bit is never removed by this path, and the VFTA bit is
    /// left set whenever the PF still uses the VID.
    pub fn clear_vf_vlvf(&mut self, vf: usize) -> Result<Program, VmdqError> {
        let pool = self.check_vf(vf)?;
        let pool_bit = VlvfTable::pool_bit(pool);
        let pf_bit = VlvfTable::pool_bit(pf_pool(self.num_vfs));
        // Other VF pools (PF excluded): if any remain, only our bit
        // goes away and the VFTA bit stays.
        let other_vf_mask = VLVF_POOLSEL_MASK & !pf_bit;
        let mut prog = Program::new();
        for idx in 0..VLVF_ENTRIES {
            let mut entry = self.vlvf.entries[idx];
            if entry & pool_bit == 0 {
                continue;
            }
            entry ^= pool_bit;
            if entry & other_vf_mask != 0 {
                self.vlvf.entries[idx] = entry;
                prog.push_write(vlvf_addr(idx), entry)?;
                continue;
            }
            if entry & VLVF_POOLSEL_MASK != 0 {
                // PF still uses this VID: leave the VFTA bit alone.
                // Under promiscuous mode keep just the pool bits;
                // otherwise disable the entry (the PF falls back to
                // VFTA + default pool).
                let value = if self.vlan_promisc {
                    entry & VLVF_POOLSEL_MASK
                } else {
                    0
                };
                self.vlvf.entries[idx] = value;
                prog.push_write(vlvf_addr(idx), value)?;
                continue;
            }
            // Last pool left: clear the VFTA bit, then disable.
            let vid = (entry & VLVF_VLANID_MASK) as u16;
            self.vlvf.entries[idx] = 0;
            prog.push_write(vlvf_addr(idx), 0)?;
            prog.push_vlan_remove(vid)?;
        }
        Ok(prog)
    }

    /// VF VLAN set/clear through the mailbox/admin path (Linux
    /// `igb_set_vf_vlan`): when adding a VID the PF already monitors,
    /// the PF pool bit is secured first (and its failure propagates);
    /// on remove, the PF entry is cleaned up when the PF monitors
    /// the VID or VLAN promiscuous mode is on. `pf_monitors`
    /// answers whether the PF's filter holds a VID.
    pub fn set_vf_vlan(
        &mut self,
        vid: u16,
        add: bool,
        vf: usize,
        pf_monitors: impl Fn(u16) -> bool,
    ) -> Result<Program, VmdqError> {
        let pool = self.check_vf(vf)?;
        if vid > 4095 {
            return Err(VmdqError::BadVid);
        }
        let monitors = pf_monitors(vid);
        let mut prog = Program::new();
        if add && monitors {
            // The PF must keep visibility: its pool bit first, and
            // no bypass (failure propagates).
            let pf_out = self.vfta_set(vid, pf_pool(self.num_vfs), true, false, true)?;
            if let Some((idx, value)) = pf_out.vlvf_write {
                prog.push_write(vlvf_addr(idx), value)?;
            }
        }
        // The VF's own bit. The VFTA bit for this VID is already set
        // whenever the PF monitors it, so pass that as the current
        // bit (the delta logic then leaves it set).
        let vf_out = self.vfta_set(vid, pool, add, false, monitors)?;
        if let Some((idx, value)) = vf_out.vlvf_write {
            prog.push_write(vlvf_addr(idx), value)?;
        }
        if vf_out.vfta_changed {
            if add {
                prog.push_vlan_add(vid)?;
            } else {
                prog.push_vlan_remove(vid)?;
            }
        }
        // Linux: on remove (or on failure) clean the PF entry up
        // when the PF monitors the VID or VLAN promiscuous mode is
        // on. Failure past the PF step cannot happen — a successful
        // PF step means a slot for this VID already exists, so the
        // VF step finds it — and a PF-step failure (no slot, no
        // bypass) leaves no entry for `update_pf_vlvf` to touch in
        // any reachable state, so propagating the error without the
        // cleanup is equivalent to Linux here.
        if !add && (monitors || self.vlan_promisc) {
            if let Some((idx, value)) = self.update_pf_vlvf(vid) {
                prog.push_write(vlvf_addr(idx), value)?;
            }
        }
        // Invariant: the VF step cannot fail after the PF step
        // succeeds. Both steps look up a slot for the same VID, and
        // the PF step already secured one (an existing entry or a
        // fresh slot); the VF step therefore always finds it. The
        // only other VF-step failures (BadVid, BadVfCount) are ruled
        // out before the PF step runs. So an Err return never leaves
        // the shadow ahead of the program.
        Ok(prog)
    }

    /// VMOLR word for pool `pool` with untagged-packet acceptance
    /// set per `aupe` (Linux `igb_set_vmolr`): BAM and RSSE are
    /// always cleared here; RSS enable for the PF pool belongs to
    /// the RX-mode path, not this helper.
    pub fn vmolr_aupe_word(&self, pool: usize, aupe: bool) -> u32 {
        let mut word = self.vmolr[pool];
        if aupe {
            word |= VMOLR_AUPE;
        } else {
            word &= !VMOLR_AUPE;
        }
        word & !(VMOLR_BAM | VMOLR_RSSE)
    }

    /// Set a VF's VLAN-strip bit (Linux `igb_set_vf_vlan_strip`:
    /// VMOLR.STRVLAN, or DVMOLR.STRVLAN on I350 — the bit is the
    /// same, only the register differs). Returns the (address,
    /// value) write: on I350 the strip state lives in the DVMOLR
    /// shadow, everywhere else in the VMOLR shadow.
    pub fn set_vf_vlan_strip(&mut self, vf: usize, enable: bool) -> Result<(u64, u32), VmdqError> {
        let pool = self.check_vf(vf)?;
        self.vfs[vf].vlan_strip = enable;
        if self.device_id == IGB_I350_COPPER {
            if enable {
                self.dvmolr[pool] |= VMOLR_STRVLAN;
            } else {
                self.dvmolr[pool] &= !VMOLR_STRVLAN;
            }
            Ok((self.strip_reg(pool), self.dvmolr[pool]))
        } else {
            if enable {
                self.vmolr[pool] |= VMOLR_STRVLAN;
            } else {
                self.vmolr[pool] &= !VMOLR_STRVLAN;
            }
            Ok((self.strip_reg(pool), self.vmolr[pool]))
        }
    }

    /// Strip register for a pool on this device: DVMOLR on I350,
    /// VMOLR everywhere else (Linux `igb_set_vf_vlan_strip`).
    pub fn strip_reg(&self, pool: usize) -> u64 {
        if self.device_id == IGB_I350_COPPER {
            REG_DVMOLR_BASE + (pool as u64) * 64
        } else {
            vmolr_addr(pool)
        }
    }
}

/// One handler step: the program to apply plus whether the VF gets
/// an ACK (`true`) or a NACK (`false`). A NACK step may still carry
/// a program — Linux's promisc handler programs VMOLR before
/// failing on leftover info bits — so the caller applies the
/// program in both cases and picks the reply bit from `ok`.
#[derive(Clone, Debug)]
pub struct HandlerStep {
    /// Register/VLAN program to apply.
    pub program: Program,
    /// ACK when true, NACK when false.
    pub ok: bool,
}

impl HandlerStep {
    /// ACK with a program.
    pub fn ack(program: Program) -> Self {
        Self { program, ok: true }
    }

    /// NACK with a program (possibly empty).
    pub fn nack(program: Program) -> Self {
        Self { program, ok: false }
    }

    /// NACK with no program.
    pub fn nack_empty() -> Self {
        Self {
            program: Program::new(),
            ok: false,
        }
    }
}

/// Mailbox dispatch outcome: the reply words for the VF plus the
/// program the caller applies to hardware (and the VFTA shadow, via
/// the VLAN ops).
#[derive(Clone, Debug)]
pub struct DispatchOutcome {
    /// Reply to write back to the VF's mailbox memory.
    pub reply: [u32; 3],
    /// Reply words to write (0 = no reply, unlock only).
    pub reply_len: usize,
    /// Program to apply.
    pub program: Program,
}

impl VtState {
    /// Append `other` onto `prog` (shared by reset/admin paths that
    /// compose several sub-programs).
    pub fn append_program(prog: &mut Program, other: Program) -> Result<(), VmdqError> {
        for w in other.writes.iter().take(other.n_writes) {
            prog.push_write(w.addr, w.value)?;
        }
        for (addr, bit) in other.mta_sets.iter().take(other.n_mta_sets) {
            prog.push_mta(*addr, *bit)?;
        }
        for vid in other.vlan_adds.iter().take(other.n_vlan_adds) {
            prog.push_vlan_add(*vid)?;
        }
        for vid in other.vlan_removes.iter().take(other.n_vlan_removes) {
            prog.push_vlan_remove(*vid)?;
        }
        Ok(())
    }

    /// Program the VF's primary MAC into its RAR slot (Linux
    /// `igb_set_vf_mac`): the slot is at the top of the table, the
    /// pool is the VF's pool. Updates the stored MAC.
    pub fn program_vf_mac(&mut self, vf: usize, mac: [u8; 6]) -> Result<Program, VmdqError> {
        let pool = self.check_vf(vf)?;
        let slot = primary_rar(self.rar_entry_count, vf);
        let (lo, hi) = rar_words(
            mac,
            pool,
            self.pool_encoding,
            true,
            is_valid_ether_addr(mac),
        );
        self.vfs[vf].mac = mac;
        let mut prog = Program::new();
        prog.push_write(ral_addr(slot), lo)?;
        prog.push_write(rah_addr(slot), hi)?;
        Ok(prog)
    }

    /// Function-level VF reset (Linux `igb_vf_reset`, minus the
    /// `set_rx_mode` MTA flush, which belongs to the RX-mode path):
    /// flags keep only PF_SET_MAC, VLANs cleared, port VLAN restored,
    /// VMVIR/VMOLR/strip restored, multicast hashes dropped. VFRE /
    /// VFTE / CTS are NOT touched here — the reset MESSAGE handler
    /// owns those (Linux splits `igb_vf_reset` from
    /// `igb_vf_reset_msg` the same way).
    pub fn vf_reset(
        &mut self,
        vf: usize,
        pf_monitors: impl Fn(u16) -> bool,
    ) -> Result<Program, VmdqError> {
        self.check_vf(vf)?;
        let vf_data = &mut self.vfs[vf];
        // Linux `igb_vf_reset` clears flags except PF_SET_MAC; the
        // MAC address, trust, spoof-check, and port VLAN are separate
        // fields and survive (the reset MESSAGE re-programs the
        // stored MAC right after this runs).
        let saved = *vf_data;
        // Flags keep only PF_SET_MAC; CTS is re-earned by RESET.
        // The TX rate limit survives (Linux keeps `tx_rate` across
        // `igb_vf_reset`; only a link-speed change clears it), but
        // the multicast-promiscuous flag does not (it is a flag,
        // and `igb_vf_reset` clears all flags but PF_SET_MAC), so
        // it stays at `VfState::new()`'s false.
        *vf_data = VfState::new();
        vf_data.mac = saved.mac;
        vf_data.pf_set_mac = saved.pf_set_mac;
        vf_data.trusted = saved.trusted;
        vf_data.spoofchk_enabled = saved.spoofchk_enabled;
        vf_data.pf_vlan = saved.pf_vlan;
        vf_data.pf_qos = saved.pf_qos;
        vf_data.tx_rate = saved.tx_rate;
        let pf_vlan = saved.pf_vlan;
        let pf_qos = saved.pf_qos;
        let mut prog = self.clear_vf_vlvf(vf)?;
        let vlan_prog = self.set_vf_vlan(pf_vlan, true, vf, &pf_monitors)?;
        Self::append_program(&mut prog, vlan_prog)?;
        // VMVIR: port VLAN + QoS, or 0 when untagged.
        let combined = (pf_vlan as u32) | ((pf_qos as u32) << 13);
        let vmvir = if combined == 0 {
            0
        } else {
            combined | VMVIR_VLANA_DEFAULT
        };
        prog.push_write(vmvir_addr(vf_pool(vf)), vmvir)?;
        // VMOLR: untagged acceptance iff no port VLAN.
        let pool = vf_pool(vf);
        let aupe_word = self.vmolr_aupe_word(pool, pf_vlan == 0);
        self.vmolr[pool] = aupe_word;
        prog.push_write(vmolr_addr(pool), aupe_word)?;
        // Strip iff a port VLAN is set.
        let (strip_addr, strip_value) = self.set_vf_vlan_strip(vf, pf_vlan != 0)?;
        prog.push_write(strip_addr, strip_value)?;
        Ok(prog)
    }

    /// VF reset EVENT (Linux `igb_vf_reset_event`): a VF that
    /// asserted its VFLRE bit is treated as hotplug removed/added —
    /// its MAC is cleared unless the PF set it — then the
    /// function-level reset runs. Unlike the reset MESSAGE, this
    /// does not re-enable VFRE/VFTE or earn CTS.
    pub fn vf_reset_event(
        &mut self,
        vf: usize,
        pf_monitors: impl Fn(u16) -> bool,
    ) -> Result<Program, VmdqError> {
        self.check_vf(vf)?;
        if !self.vfs[vf].pf_set_mac {
            self.vfs[vf].mac = [0; 6];
        }
        self.vf_reset(vf, pf_monitors)
    }

    /// Revoke clear-to-send (Linux `igb_rcv_msg_from_vf` on a
    /// mailbox-read failure). The VF re-earns CTS with its next
    /// RESET message. Out-of-range VFs are a silent no-op so the
    /// pump's failure path never panics.
    pub fn revoke_cts(&mut self, vf: usize) {
        if self.check_vf(vf).is_ok() {
            self.vfs[vf].cts = false;
        }
    }

    /// Reset MESSAGE handler (Linux `igb_vf_reset_msg`): function
    /// reset, primary-MAC reprogram, VFRE/VFTE enable, CTS set, and
    /// the 3-word reply (ACK + MAC when a MAC is set, else NACK).
    pub fn vf_reset_msg(
        &mut self,
        vf: usize,
        pf_monitors: impl Fn(u16) -> bool,
    ) -> Result<DispatchOutcome, VmdqError> {
        let mut prog = self.vf_reset(vf, pf_monitors)?;
        let mac = self.vfs[vf].mac;
        let mac_prog = self.program_vf_mac(vf, mac)?;
        Self::append_program(&mut prog, mac_prog)?;
        self.vfre |= 1 << vf;
        self.vfte |= 1 << vf;
        prog.push_write(REG_VFTE, self.vfte)?;
        prog.push_write(REG_VFRE, self.vfre)?;
        self.vfs[vf].cts = true;
        // A fresh CTS epoch may NACK one stray ack again.
        self.vfs[vf].ack_nack_sent = false;
        let mut reply = [0u32; 3];
        if !is_zero_ether_addr(mac) {
            reply[0] = VF_RESET | VT_MSGTYPE_ACK;
            reply[1] = (mac[0] as u32)
                | ((mac[1] as u32) << 8)
                | ((mac[2] as u32) << 16)
                | ((mac[3] as u32) << 24);
            reply[2] = (mac[4] as u32) | ((mac[5] as u32) << 8);
        } else {
            reply[0] = VF_RESET | VT_MSGTYPE_NACK;
        }
        Ok(DispatchOutcome {
            reply,
            reply_len: 3,
            program: prog,
        })
    }

    /// Lowest free RAR slot for a VF-MAC filter (Linux
    /// `igb_add_mac_filter_flags`: first empty entry scanning
    /// 0..(rar_count - num_vfs), skipping the VF-primary region at
    /// the top; RAR 0 is the PF default and never free here).
    /// `None` when no slot is free.
    pub fn free_filter_rar(&self) -> Option<usize> {
        let limit = self.rar_entry_count - self.num_vfs;
        for slot in 1..limit {
            let used = self.mac_filters[..self.mac_filter_count]
                .iter()
                .any(|f| f.owner.is_some() && f.rar == Some(slot));
            if !used {
                return Some(slot);
            }
        }
        None
    }

    /// SET_MAC_ADDR handler (Linux `igb_set_vf_mac_addr` +
    /// `igb_set_vf_mac_filter`): info 0 sets the primary MAC
    /// (refused for an untrusted VF overriding a PF-set MAC, or an
    /// invalid address); CLR removes all of the VF's filters; ADD
    /// takes the first free filter entry (ENOSPC -> NACK). All
    /// validation precedes mutation, so a NACK step carries no
    /// program.
    pub fn set_vf_mac_addr(&mut self, vf: usize, msg: &[u32]) -> HandlerStep {
        if self.check_vf(vf).is_err() {
            return HandlerStep::nack_empty();
        }
        let info = msg_word(msg, 0) & VT_MSGINFO_MASK;
        let addr = msg_mac(msg);
        if info == 0 {
            if self.vfs[vf].pf_set_mac && !self.vfs[vf].trusted {
                return HandlerStep::nack_empty();
            }
            if !is_valid_ether_addr(addr) {
                return HandlerStep::nack_empty();
            }
            return match self.program_vf_mac(vf, addr) {
                Ok(program) => HandlerStep::ack(program),
                Err(_) => HandlerStep::nack_empty(),
            };
        }
        if info == VF_MAC_FILTER_CLR {
            let mut prog = Program::new();
            for entry in self.mac_filters[..self.mac_filter_count].iter_mut() {
                if entry.owner == Some(vf) {
                    if let Some(slot) = entry.rar {
                        if prog.push_write(ral_addr(slot), 0).is_err()
                            || prog.push_write(rah_addr(slot), 0).is_err()
                        {
                            return HandlerStep::nack_empty();
                        }
                    }
                    entry.owner = None;
                    entry.mac = [0; 6];
                    entry.rar = None;
                }
            }
            return HandlerStep::ack(prog);
        }
        if info == VF_MAC_FILTER_ADD {
            if !is_valid_ether_addr(addr) {
                return HandlerStep::nack_empty();
            }
            let Some(slot) = self.free_filter_rar() else {
                return HandlerStep::nack_empty();
            };
            let Some(entry) = self.mac_filters[..self.mac_filter_count]
                .iter_mut()
                .find(|f| f.owner.is_none())
            else {
                return HandlerStep::nack_empty();
            };
            entry.owner = Some(vf);
            entry.mac = addr;
            entry.rar = Some(slot);
            let (lo, hi) = rar_words(addr, vf_pool(vf), self.pool_encoding, true, true);
            let mut prog = Program::new();
            if prog.push_write(ral_addr(slot), lo).is_err()
                || prog.push_write(rah_addr(slot), hi).is_err()
            {
                return HandlerStep::nack_empty();
            }
            return HandlerStep::ack(prog);
        }
        HandlerStep::nack_empty()
    }

    /// SET_MULTICAST handler (Linux `igb_set_vf_multicasts`): store
    /// the count (uncapped) and the first 30 hashes; VMOLR gets
    /// MPME when the count exceeds 30, ROMPE + MTA sets otherwise
    /// (nothing when the count is 0). Always ACKs.
    pub fn set_vf_multicasts(&mut self, vf: usize, msg: &[u32]) -> HandlerStep {
        let Ok(pool) = self.check_vf(vf) else {
            return HandlerStep::nack_empty();
        };
        let n = ((msg_word(msg, 0) & VT_MSGINFO_MASK) >> VT_MSGINFO_SHIFT) as usize;
        let mut prog = Program::new();
        self.vfs[vf].mc_count = n;
        let stored = n.min(MAX_VF_MC_HASHES);
        for j in 0..stored {
            let word = msg_word(msg, 1 + j / 2);
            let hash = if j % 2 == 0 {
                (word & 0xFFFF) as u16
            } else {
                (word >> 16) as u16
            };
            self.vfs[vf].mc_hashes[j] = hash;
            let (w, bit) = mta_set(hash);
            if prog.push_mta(mta_addr(w), bit).is_err() {
                return HandlerStep::nack_empty();
            }
        }
        let mut word = self.vmolr[pool] & !(VMOLR_ROMPE | VMOLR_MPME);
        if n > MAX_VF_MC_HASHES {
            word |= VMOLR_MPME;
        } else if n > 0 {
            word |= VMOLR_ROMPE;
        }
        self.vmolr[pool] = word;
        if prog.push_write(vmolr_addr(pool), word).is_err() {
            return HandlerStep::nack_empty();
        }
        HandlerStep::ack(prog)
    }

    /// SET_LPE handler (Linux `igb_set_vf_rlpml`): VMOLR gets the
    /// size plus LPE. The size is clamped to the RLPML field width
    /// here; Linux additionally clamps to MAX_JUMBO_FRAME_SIZE, a
    /// constant outside the drivers-only reference trees, so that
    /// tighter clamp is a remainder, not a guess.
    pub fn set_vf_rlpml(&mut self, vf: usize, size: u32) -> HandlerStep {
        let Ok(pool) = self.check_vf(vf) else {
            return HandlerStep::nack_empty();
        };
        let size = size & VMOLR_RLPML_MASK;
        let mut word = self.vmolr[pool] & !VMOLR_RLPML_MASK;
        word |= size | VMOLR_LPE;
        self.vmolr[pool] = word;
        let mut prog = Program::new();
        if prog.push_write(vmolr_addr(pool), word).is_err() {
            return HandlerStep::nack_empty();
        }
        HandlerStep::ack(prog)
    }

    /// SET_VLAN handler (Linux `igb_set_vf_vlan_msg`): refused when
    /// an admin port VLAN is set; VID 0 removal is a no-op success;
    /// otherwise the VF VLAN path plus the strip bit (strip iff the
    /// VID is nonzero).
    pub fn set_vf_vlan_msg(
        &mut self,
        vf: usize,
        msg: &[u32],
        pf_filter: &VlanFilter,
    ) -> HandlerStep {
        if self.check_vf(vf).is_err() {
            return HandlerStep::nack_empty();
        }
        if self.vfs[vf].pf_vlan != 0 {
            return HandlerStep::nack_empty();
        }
        let add = (msg_word(msg, 0) & VT_MSGINFO_MASK) != 0;
        let vid = (msg_word(msg, 1) & VLVF_VLANID_MASK) as u16;
        if vid == 0 && !add {
            return HandlerStep::ack(Program::new());
        }
        let mut prog = match self.set_vf_vlan(vid, add, vf, |v| pf_filter.contains(v)) {
            Ok(prog) => prog,
            Err(_) => return HandlerStep::nack_empty(),
        };
        let Ok((strip_addr, strip_value)) = self.set_vf_vlan_strip(vf, vid != 0) else {
            return HandlerStep::nack_empty();
        };
        if prog.push_write(strip_addr, strip_value).is_err() {
            return HandlerStep::nack_empty();
        }
        HandlerStep::ack(prog)
    }

    /// SET_PROMISC handler (Linux `igb_set_vf_promisc`): clears both
    /// promisc flags and the ROPE/ROMPE/MPME bits, then sets MPME
    /// for multicast-promiscuous, or restores ROMPE + MTA sets (or
    /// MPME for > 30 hashes) from the stored multicast list.
    /// Leftover info bits NACK — but only AFTER the VMOLR program
    /// is applied, mirroring Linux's write-then-check order.
    pub fn set_vf_promisc(&mut self, vf: usize, msg: &[u32]) -> HandlerStep {
        let Ok(pool) = self.check_vf(vf) else {
            return HandlerStep::nack_empty();
        };
        let mut info = msg_word(msg, 0) & VT_MSGINFO_MASK;
        let mut prog = Program::new();
        // Linux `igb_set_vf_promisc` clears the unicast and
        // multicast promiscuous flags first, then re-sets the
        // multicast one only when the message asks for it; the
        // restore path reads the flag back.
        self.vfs[vf].multi_promisc = false;
        let mut word = self.vmolr[pool] & !(VMOLR_ROPE | VMOLR_ROMPE | VMOLR_MPME);
        if info & VF_SET_PROMISC_MULTICAST != 0 {
            word |= VMOLR_MPME;
            self.vfs[vf].multi_promisc = true;
            info &= !VF_SET_PROMISC_MULTICAST;
        } else if self.vfs[vf].mc_count > MAX_VF_MC_HASHES {
            word |= VMOLR_MPME;
        } else if self.vfs[vf].mc_count > 0 {
            word |= VMOLR_ROMPE;
            for j in 0..self.vfs[vf].mc_count.min(MAX_VF_MC_HASHES) {
                let (w, bit) = mta_set(self.vfs[vf].mc_hashes[j]);
                if prog.push_mta(mta_addr(w), bit).is_err() {
                    return HandlerStep::nack_empty();
                }
            }
        }
        self.vmolr[pool] = word;
        if prog.push_write(vmolr_addr(pool), word).is_err() {
            return HandlerStep::nack_empty();
        }
        if info != 0 {
            return HandlerStep::nack(prog);
        }
        HandlerStep::ack(prog)
    }

    /// Full mailbox dispatch (Linux `igb_rcv_msg_from_vf`): messages
    /// already marked ACK/NACK get no reply (unlock only); RESET is
    /// handled by the reset-message path; every other message
    /// requires CTS (a non-CTS message gets a NACK — Linux throttles
    /// repeat NACKs on a 2 s window, which this time-free core does
    /// not model, so it NACKs unconditionally); the reply carries
    /// CTS plus ACK/NACK. Structural errors (bad VF, empty message)
    /// return Err with no reply at all.
    pub fn dispatch(
        &mut self,
        vf: usize,
        msg: &[u32],
        pf_filter: &VlanFilter,
    ) -> Result<DispatchOutcome, VmdqError> {
        self.check_vf(vf)?;
        if msg.is_empty() {
            return Err(VmdqError::BadMessage);
        }
        let first = msg[0];
        if first & (VT_MSGTYPE_ACK | VT_MSGTYPE_NACK) != 0 {
            // Already processed: unlock only, no reply, no program.
            return Ok(DispatchOutcome {
                reply: [0; 3],
                reply_len: 0,
                program: Program::new(),
            });
        }
        if first == VF_RESET {
            return self.vf_reset_msg(vf, pf_filter_contains(pf_filter));
        }
        if !self.vfs[vf].cts {
            return Ok(DispatchOutcome {
                reply: [first | VT_MSGTYPE_CTS | VT_MSGTYPE_NACK, 0, 0],
                reply_len: 1,
                program: Program::new(),
            });
        }
        let step = match first & 0xFFFF {
            VF_SET_MAC_ADDR => self.set_vf_mac_addr(vf, msg),
            VF_SET_PROMISC => self.set_vf_promisc(vf, msg),
            VF_SET_MULTICAST => self.set_vf_multicasts(vf, msg),
            VF_SET_LPE => self.set_vf_rlpml(vf, msg_word(msg, 1)),
            VF_SET_VLAN => self.set_vf_vlan_msg(vf, msg, pf_filter),
            _ => HandlerStep::nack_empty(),
        };
        let reply_bit = if step.ok {
            VT_MSGTYPE_ACK
        } else {
            VT_MSGTYPE_NACK
        };
        Ok(DispatchOutcome {
            reply: [first | VT_MSGTYPE_CTS | reply_bit, 0, 0],
            reply_len: 1,
            program: step.program,
        })
    }

    /// PF admin: set a VF's MAC (Linux `igb_ndo_set_vf_mac`). A zero
    /// MAC clears the PF-set flag (libvirt restore path); a valid
    /// MAC sets it; anything else is refused. The RAR program is
    /// always emitted (even for zero, which programs pool bits
    /// without AV, exactly as Linux's `igb_rar_set_index` does for
    /// an IN_USE entry with an invalid address).
    pub fn set_vf_mac_admin(&mut self, vf: usize, mac: [u8; 6]) -> Result<Program, VmdqError> {
        self.check_vf(vf)?;
        if is_zero_ether_addr(mac) {
            self.vfs[vf].pf_set_mac = false;
        } else if is_valid_ether_addr(mac) {
            self.vfs[vf].pf_set_mac = true;
        } else {
            return Err(VmdqError::Refused);
        }
        self.program_vf_mac(vf, mac)
    }

    /// PF admin: set a VF's port VLAN (Linux `igb_ndo_set_vf_vlan` /
    /// `igb_enable_port_vlan` / `igb_disable_port_vlan`). `vlan` > 4095
    /// or `qos` > 7 is refused. Enable programs the VLAN, VMVIR,
    /// VMOLR untagged-off, revokes the previous port VLAN, and sets
    /// stripping; disable restores tagless access and clears the
    /// admin VLAN.
    pub fn set_vf_vlan_admin(
        &mut self,
        vf: usize,
        vlan: u16,
        qos: u8,
        pf_monitors: impl Fn(u16) -> bool,
    ) -> Result<Program, VmdqError> {
        self.check_vf(vf)?;
        if vlan > 4095 || qos > 7 {
            return Err(VmdqError::Refused);
        }
        let mut prog = Program::new();
        if vlan != 0 || qos != 0 {
            let vlan_prog = self.set_vf_vlan(vlan, true, vf, &pf_monitors)?;
            Self::append_program(&mut prog, vlan_prog)?;
            let combined = (vlan as u32) | ((qos as u32) << 13);
            let vmvir = combined | VMVIR_VLANA_DEFAULT;
            prog.push_write(vmvir_addr(vf_pool(vf)), vmvir)?;
            let pool = vf_pool(vf);
            let aupe_word = self.vmolr_aupe_word(pool, false);
            self.vmolr[pool] = aupe_word;
            prog.push_write(vmolr_addr(pool), aupe_word)?;
            let old = self.vfs[vf].pf_vlan;
            if vlan != old {
                let revoke = self.set_vf_vlan(old, false, vf, &pf_monitors)?;
                Self::append_program(&mut prog, revoke)?;
            }
            self.vfs[vf].pf_vlan = vlan;
            self.vfs[vf].pf_qos = qos;
            let (strip_addr, strip_value) = self.set_vf_vlan_strip(vf, true)?;
            prog.push_write(strip_addr, strip_value)?;
        } else {
            let vlan_prog = self.set_vf_vlan(0, true, vf, &pf_monitors)?;
            Self::append_program(&mut prog, vlan_prog)?;
            prog.push_write(vmvir_addr(vf_pool(vf)), 0)?;
            let pool = vf_pool(vf);
            let aupe_word = self.vmolr_aupe_word(pool, true);
            self.vmolr[pool] = aupe_word;
            prog.push_write(vmolr_addr(pool), aupe_word)?;
            let old = self.vfs[vf].pf_vlan;
            if old != 0 {
                let revoke = self.set_vf_vlan(old, false, vf, &pf_monitors)?;
                Self::append_program(&mut prog, revoke)?;
            }
            self.vfs[vf].pf_vlan = 0;
            self.vfs[vf].pf_qos = 0;
            let (strip_addr, strip_value) = self.set_vf_vlan_strip(vf, false)?;
            prog.push_write(strip_addr, strip_value)?;
        }
        Ok(prog)
    }

    /// PF admin: trust flag (Linux `igb_ndo_set_vf_trust` — flag
    /// only; its effect is gating SET_MAC_ADDR overrides, which the
    /// dispatcher already implements).
    pub fn set_vf_trust(&mut self, vf: usize, trusted: bool) -> Result<(), VmdqError> {
        self.check_vf(vf)?;
        self.vfs[vf].trusted = trusted;
        Ok(())
    }

    /// Switch-control word with VF `vf`'s spoof bits set or cleared
    /// (Linux anti-spoofing bit positions, proved by
    /// `igb_vmdq_set_anti_spoofing_pf`'s `BIT(pf) | BIT(pf + 8)`
    /// toggle: MAC-spoof bit `vf`, VLAN-spoof bit `vf + 8`). The
    /// caller reads the family register, applies this builder, and
    /// writes it back; the flag itself is set by the caller via
    /// [`Self::set_vf_spoofchk_flag`].
    pub const fn switch_spoofchk_word(current: u32, vf: usize, enable: bool) -> u32 {
        let bits = (1 << vf) | (1 << (vf + 8));
        if enable {
            current | bits
        } else {
            current & !bits
        }
    }

    /// Spoof-check flag (Linux `igb_ndo_set_vf_spoofchk` flag half;
    /// the register half is [`Self::switch_spoofchk_word`]).
    pub fn set_vf_spoofchk_flag(&mut self, vf: usize, enable: bool) -> Result<(), VmdqError> {
        self.check_vf(vf)?;
        self.vfs[vf].spoofchk_enabled = enable;
        Ok(())
    }

    /// Program one VF's TX rate limit (Linux
    /// `igb_set_vf_rate_limit`): select the VF's queue, write the
    /// fixed MMW_SIZE, then the rate-factor word. `tx_rate` 0
    /// programs a zero word, i.e. unthrottled.
    fn rate_limit_program(vf: usize, tx_rate: u32, link_speed: u32) -> Result<Program, VmdqError> {
        let mut prog = Program::new();
        prog.push_write(REG_RTTDQSEL, vf as u32)?;
        prog.push_write(REG_RTTBCNRM, RTTBCNRM_MMW_SIZE)?;
        prog.push_write(REG_RTTBCNRC, vf_rate_limit_bcnrc(tx_rate, link_speed))?;
        Ok(prog)
    }

    /// PF admin: set a VF's TX rate limit (Linux
    /// `igb_ndo_set_vf_bw`, `ndo_set_vf_rate`). `link_speed_mbps`
    /// is the already-mapped actual link speed (Linux
    /// `igb_link_mbps`: 100 -> 100, 1000 -> 1000, anything else,
    /// including 10 Mb/s, -> 0) and `link_up` is STATUS.LU; the
    /// MMIO-owning caller supplies both. Refusals mirror Linux
    /// exactly: non-82576 MAC type is `Unsupported` (-EOPNOTSUPP);
    /// a nonzero minimum rate, an out-of-range VF, a down link, a
    /// negative rate, or a rate above the link speed is `Refused`
    /// (-EINVAL). On success the stored rate and the link speed it
    /// was programmed against are kept for `check_vf_rate_limit`.
    /// Reachable from the PF admin path only — there is no VF
    /// mailbox message for rate limits, so the dispatcher does not
    /// route here.
    pub fn set_vf_bw(
        &mut self,
        vf: usize,
        min_tx_rate: i32,
        max_tx_rate: i32,
        link_speed_mbps: u32,
        link_up: bool,
    ) -> Result<Program, VmdqError> {
        if !rate_limit_supported(self.device_id) {
            return Err(VmdqError::Unsupported);
        }
        if min_tx_rate != 0 {
            return Err(VmdqError::Refused);
        }
        self.check_vf(vf)?;
        if !link_up || max_tx_rate < 0 || max_tx_rate as u32 > link_speed_mbps {
            return Err(VmdqError::Refused);
        }
        self.vf_rate_link_speed = link_speed_mbps;
        self.vfs[vf].tx_rate = max_tx_rate as u16;
        Self::rate_limit_program(vf, max_tx_rate as u32, link_speed_mbps)
    }

    /// Re-apply every VF's stored TX rate limit after a link-speed
    /// change (Linux `igb_check_vf_rate_limit`, the watchdog half
    /// of rate limiting). A no-op when no rate was ever set
    /// (`vf_rate_link_speed` is 0) or the MAC type is not 82576.
    /// When the speed moved, every stored rate is cleared first
    /// and the recorded speed is forgotten, so the next call is a
    /// no-op until a fresh `set_vf_bw` — exactly Linux's
    /// "Link speed has been changed. VF Transmit rate is disabled".
    /// The returned program holds 3 writes per allocated VF and
    /// always fits the 48-write budget (7 VFs * 3 = 21).
    pub fn check_vf_rate_limit(&mut self, link_speed_mbps: u32) -> Result<Program, VmdqError> {
        let mut prog = Program::new();
        if self.vf_rate_link_speed == 0 || !rate_limit_supported(self.device_id) {
            return Ok(prog);
        }
        if link_speed_mbps != self.vf_rate_link_speed {
            for vf in 0..self.num_vfs {
                self.vfs[vf].tx_rate = 0;
            }
            self.vf_rate_link_speed = 0;
        }
        for vf in 0..self.num_vfs {
            let sub = Self::rate_limit_program(vf, self.vfs[vf].tx_rate as u32, link_speed_mbps)?;
            Self::append_program(&mut prog, sub)?;
        }
        Ok(prog)
    }

    /// Restore one VF's multicast state after the PF's multicast
    /// list changed (the per-VF body of Linux
    /// `igb_restore_vf_multicasts`): rebuild the VF's VMOLR
    /// ROMPE/MPME bits from the stored hash count and the
    /// multicast-promiscuous flag, and re-emit the stored hashes
    /// as MTA OR-sets. A VF with no hashes gets a bare VMOLR
    /// write clearing both bits; a VF with > 30 hashes or the
    /// promiscuous flag gets MPME and no MTA sets.
    ///
    /// Why per-VF: the Linux function loops over all VFs, but a
    /// single NARF `Program` holds at most 30 MTA sets, and 7 VFs
    /// with 30 hashes each would need 210 — so the all-VF restore
    /// is `Igb::vt_restore_vf_multicasts`, which applies one
    /// per-VF program at a time. Linux calls the restore from
    /// `igb_set_rx_mode` / `igb_write_mc_addr_list`, i.e. after
    /// the PF MTA is rewritten; NARF has no `set_rx_mode` / PF
    /// MTA writer yet, so the caller that lands the PF
    /// multicast-list path must call the `Igb` method after its
    /// MTA rewrite — this function is the restore half, not the
    /// list-change half.
    pub fn restore_vf_multicast(&mut self, vf: usize) -> Result<Program, VmdqError> {
        let pool = self.check_vf(vf)?;
        let mut prog = Program::new();
        let mut word = self.vmolr[pool] & !(VMOLR_ROMPE | VMOLR_MPME);
        if self.vfs[vf].mc_count > MAX_VF_MC_HASHES || self.vfs[vf].multi_promisc {
            word |= VMOLR_MPME;
        } else if self.vfs[vf].mc_count > 0 {
            word |= VMOLR_ROMPE;
            for j in 0..self.vfs[vf].mc_count.min(MAX_VF_MC_HASHES) {
                let (w, bit) = mta_set(self.vfs[vf].mc_hashes[j]);
                prog.push_mta(mta_addr(w), bit)?;
            }
        }
        self.vmolr[pool] = word;
        prog.push_write(vmolr_addr(pool), word)?;
        Ok(prog)
    }
}

/// Read message word `i`, zero-filling past the end (Linux reads a
/// 16-word zero-initialized mailbox buffer, so a short message is
/// just trailing zeros).
pub const fn msg_word(msg: &[u32], i: usize) -> u32 {
    if i < msg.len() {
        msg[i]
    } else {
        0
    }
}

/// MAC bytes from message words 1..2, little-endian packed (Linux
/// `igb_set_vf_mac_addr`: the address starts at the second 32-bit
/// word of the message).
pub fn msg_mac(msg: &[u32]) -> [u8; 6] {
    let w1 = msg_word(msg, 1);
    let w2 = msg_word(msg, 2);
    [
        (w1 & 0xFF) as u8,
        ((w1 >> 8) & 0xFF) as u8,
        ((w1 >> 16) & 0xFF) as u8,
        ((w1 >> 24) & 0xFF) as u8,
        (w2 & 0xFF) as u8,
        ((w2 >> 8) & 0xFF) as u8,
    ]
}

/// Closure adapter: `VlanFilter::contains` as a `Fn(u16) -> bool` for
/// the reset path (which needs a fresh closure each call because
/// `dispatch` borrows the filter immutably while `vf_reset_msg`
/// needs the same predicate).
pub fn pf_filter_contains(filter: &VlanFilter) -> impl Fn(u16) -> bool + '_ {
    move |vid| filter.contains(vid)
}

#[cfg(any(test, feature = "builtin"))]
mod tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::super::{
        mrqc_word, VlanFilter, IGB_82576, IGB_I210_COPPER, IGB_I350_COPPER, MRQC_ENABLE_VMDQ,
        MRQC_ENABLE_VMDQ_RSS_MQ,
    };
    use super::*;

    fn vt_82576_2() -> VtState {
        VtState::new(IGB_82576, 2).unwrap()
    }

    fn smoke_igb_vmdq_register_layout() -> TestResult {
        if REG_VT_CTL != 0x0581C
            || vlvf_addr(0) != 0x05D00
            || vlvf_addr(31) != 0x05D7C
            || vmolr_addr(0) != 0x05AD0
            || vmolr_addr(7) != 0x05AEC
            || vmvir_addr(0) != 0x03700
            || REG_VFRE != 0x00C8C
            || REG_VFTE != 0x00C90
            || REG_MBVFICR != 0x00C80
            || vmbmem_addr(0, 0) != 0x00800
            || vmbmem_addr(1, 0) != 0x00840
            || vmbmem_addr(0, 15) != 0x0083C
            || p2vmailbox_addr(3) != 0x00C0C
            || REG_DTXSWC != 0x03500
            || REG_TXSWC != 0x05ACC
            || REG_DTXCTL != 0x03590
            || REG_RPLOLR != 0x05AF0
            || REG_RTTDQSEL != 0x3604
            || REG_RTTBCNRM != 0x3690
            || REG_RTTBCNRC != 0x36B0
            || RTTBCNRM_MMW_SIZE != 0x14
            || mta_addr(0) != 0x05200
            || mta_addr(127) != 0x053FC
        {
            return TestResult::Fail("igb vmdq register offset drift");
        }
        if RTTBCNRC_RS_ENA != 0x8000_0000
            || RTTBCNRC_RF_DEC_MASK != 0x0000_3FFF
            || RTTBCNRC_RF_INT_SHIFT != 14
            || RTTBCNRC_RF_INT_MASK != 0x0FFF_C000
        {
            return TestResult::Fail("igb RTTBCNRC field drift");
        }
        if ral_addr(0) != 0x05400
            || rah_addr(0) != 0x05404
            || ral_addr(15) != 0x05478
            || ral_addr(16) != 0x054E0
            || rah_addr(31) != 0x055DC
        {
            return TestResult::Fail("igb RAL/RAH split (16-entry) drift");
        }
        if VT_CTL_DEFAULT_POOL_MASK != 0x380
            || VLVF_POOLSEL_MASK != 0x000F_F000
            || VLVF_VLANID_ENABLE != 0x8000_0000
            || RAH_POOL_1 != 0x0004_0000
        {
            return TestResult::Fail("igb vmdq field mask drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_register_layout);

    fn smoke_igb_vmdq_allocation() -> TestResult {
        if VtState::new(IGB_82576, 0).is_ok() || VtState::new(IGB_82576, 8).is_ok() {
            return TestResult::Fail("igb vt_allocate accepts out-of-range VF count");
        }
        if VtState::new(0xFFFF, 2).is_ok() {
            return TestResult::Fail("igb vt_allocate accepts unclaimed device id");
        }
        let a = VtState::new(IGB_82576, 7).unwrap();
        if a.mac_filter_count != 24 - (1 + 3 + 7) {
            return TestResult::Fail("igb 82576/7VF filter budget drift");
        }
        let b = VtState::new(IGB_I350_COPPER, 1).unwrap();
        if b.mac_filter_count != 32 - (1 + 3 + 1) || b.rar_entry_count != 32 {
            return TestResult::Fail("igb I350 filter budget / RAR count drift");
        }
        let c = VtState::new(IGB_I210_COPPER, 1).unwrap();
        if c.rar_entry_count != 16 || c.pool_encoding != PoolEncoding::Numeric {
            return TestResult::Fail("igb I210 RAR count / pool encoding drift");
        }
        if pf_pool(7) != 7 || pf_queue_base(7) != 7 {
            return TestResult::Fail("igb PF pool / queue base is not vfs_allocated_count");
        }
        if primary_rar(24, 0) != 23 || primary_rar(24, 6) != 17 {
            return TestResult::Fail("igb VF primary RAR slot drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_allocation);

    fn smoke_igb_vmdq_reset_event() -> TestResult {
        let mut vt = vt_82576_2();
        // VF 0 holds a MAC the PF did not set: a reset event
        // clears it (hotplug remove/add) and clears the ack-NACK
        // latch, and the program still restores VMOLR.
        vt.vfs[0].mac = [0x02, 0, 0, 0, 0, 0x01];
        vt.vfs[0].ack_nack_sent = true;
        let prog = match vt.vf_reset_event(0, |_| false) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("reset event failed for a live VF"),
        };
        if vt.vfs[0].mac != [0; 6] {
            return TestResult::Fail("reset event kept a non-PF-set MAC");
        }
        if vt.vfs[0].ack_nack_sent {
            return TestResult::Fail("reset event did not clear the ack-NACK latch");
        }
        if !prog.writes[..prog.n_writes]
            .iter()
            .any(|w| w.addr == vmolr_addr(0))
        {
            return TestResult::Fail("reset event program lost the VMOLR restore");
        }
        // A PF-set MAC survives the event.
        vt.vfs[0].mac = [0x02, 0, 0, 0, 0, 0x02];
        vt.vfs[0].pf_set_mac = true;
        if vt.vf_reset_event(0, |_| false).is_err() {
            return TestResult::Fail("reset event failed for a PF-set MAC");
        }
        if vt.vfs[0].mac != [0x02, 0, 0, 0, 0, 0x02] {
            return TestResult::Fail("reset event cleared a PF-set MAC");
        }
        // Out-of-range VF fails closed; revoke_cts is a no-op there.
        if vt.vf_reset_event(7, |_| false).is_ok() {
            return TestResult::Fail("reset event accepted an out-of-range VF");
        }
        vt.vfs[0].cts = true;
        vt.revoke_cts(0);
        if vt.vfs[0].cts {
            return TestResult::Fail("revoke_cts did not clear CTS");
        }
        vt.revoke_cts(7);
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_reset_event);

    fn smoke_igb_vmdq_rar_words() -> TestResult {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let (lo, hi) = rar_words(mac, 3, PoolEncoding::Numeric, true, true);
        if lo != 0x3322_1100 || hi != 0x800C_5544 {
            return TestResult::Fail("igb numeric RAR pool encoding drift");
        }
        let (_, hi) = rar_words(mac, 3, PoolEncoding::OneHot, true, true);
        if hi != 0x8020_5544 {
            return TestResult::Fail("igb one-hot RAR pool encoding drift");
        }
        let (lo, hi) = rar_words([0; 6], 2, PoolEncoding::OneHot, true, false);
        if lo != 0 || hi != 0x0010_0000 {
            return TestResult::Fail("igb zero-MAC RAR keeps pool bits without AV");
        }
        if rar_words(mac, 0, PoolEncoding::OneHot, false, false) != (0, 0) {
            return TestResult::Fail("igb cleared RAR entry is not (0, 0)");
        }
        if !is_valid_ether_addr(mac)
            || is_valid_ether_addr([0x01, 0, 0, 0, 0, 0])
            || is_valid_ether_addr([0; 6])
        {
            return TestResult::Fail("igb ether-addr validity drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_rar_words);

    fn smoke_igb_vmdq_switch_words() -> TestResult {
        if vt_ctl_default_pool_word(0xFFFF_FFFF, 7)
            != (0xFFFF_FFFF & !0x380 & !(1 << 29)) | (7 << 7)
        {
            return TestResult::Fail("igb VT_CTL default-pool word drift");
        }
        if vt_ctl_replication_word(0, true) != VT_CTL_VM_REPL_EN
            || vt_ctl_replication_word(VT_CTL_VM_REPL_EN, false) != 0
        {
            return TestResult::Fail("igb VT_CTL replication word drift");
        }
        // PF pool 7: masks 0xFFFF with the PF's MAC-spoof bit 7 and
        // VLAN-spoof bit 15 toggled back off.
        if switch_antispoof_word(0, 7) != 0x7F7F {
            return TestResult::Fail("igb anti-spoofing word drift");
        }
        if switch_spoofchk_word(0, 2, true) != (1 << 2) | (1 << 10)
            || switch_spoofchk_word(0xFFFF, 2, false) != 0xFFFF & !((1 << 2) | (1 << 10))
        {
            return TestResult::Fail("igb per-VF spoofchk bit drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_switch_words);

    fn smoke_igb_vmdq_vlvf_add_remove() -> TestResult {
        let mut vt = vt_82576_2();
        // First add: fresh slot 31 (scan 31..1), VFTA bit changes.
        let out = vt.vfta_set(100, 2, true, false, false).unwrap();
        if out.vlvf_write != Some((31, 100 | VLVF_VLANID_ENABLE | (1 << (12 + 2))))
            || !out.vfta_changed
        {
            return TestResult::Fail("igb VLVF first add drift");
        }
        // Second pool on the same VID: same slot, both bits, no VFTA change.
        let out = vt.vfta_set(100, 5, true, false, true).unwrap();
        if out.vlvf_write
            != Some((
                31,
                100 | VLVF_VLANID_ENABLE | (1 << (12 + 2)) | (1 << (12 + 5)),
            ))
            || out.vfta_changed
        {
            return TestResult::Fail("igb VLVF second-pool add drift");
        }
        // Remove one pool: other remains, VFTA bit stays.
        let out = vt.vfta_set(100, 2, false, false, true).unwrap();
        if out.vlvf_write != Some((31, 100 | VLVF_VLANID_ENABLE | (1 << (12 + 5))))
            || out.vfta_changed
        {
            return TestResult::Fail("igb VLVF partial remove drift");
        }
        // Remove the last pool: entry disabled, VFTA bit clears.
        let out = vt.vfta_set(100, 5, false, false, true).unwrap();
        if out.vlvf_write != Some((31, 0)) || !out.vfta_changed {
            return TestResult::Fail("igb VLVF last-pool remove drift");
        }
        // VLAN 0 always maps to slot 0.
        let out = vt.vfta_set(0, 1, true, false, false).unwrap();
        if out.vlvf_write != Some((0, VLVF_VLANID_ENABLE | (1 << (12 + 1)))) {
            return TestResult::Fail("igb VLVF VLAN-0 slot drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_vlvf_add_remove);

    fn smoke_igb_vmdq_vlvf_exhaustion() -> TestResult {
        let mut vt = vt_82576_2();
        for vid in 1..32u16 {
            vt.vfta_set(vid, 0, true, false, false).unwrap();
        }
        // Slots 1..31 full: a 32nd VID fails, but bypass falls back
        // to VFTA-only (PF receives via the default pool).
        if vt.vfta_set(100, 0, true, false, false).is_ok() {
            return TestResult::Fail("igb VLVF exhaustion not detected");
        }
        let out = vt.vfta_set(100, 0, true, true, false).unwrap();
        if out.vlvf_write.is_some() || !out.vfta_changed {
            return TestResult::Fail("igb VLVF bypass fallback drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_vlvf_exhaustion);

    fn smoke_igb_vmdq_set_vf_vlan() -> TestResult {
        let mut vt = vt_82576_2();
        let mut filter = VlanFilter::new();
        filter.add(200);
        // PF monitors 200: the PF pool bit is secured first, then the
        // VF bit; the VFTA bit was already set, so no vlan op.
        let prog = vt
            .set_vf_vlan(200, true, 1, |v| filter.contains(v))
            .unwrap();
        if prog.n_vlan_adds != 0 || prog.n_vlan_removes != 0 {
            return TestResult::Fail("igb set_vf_vlan PF-monitored add emits spurious VLAN op");
        }
        let entry = vt.vlvf.entries[31];
        if entry & VlvfTable::pool_bit(1) == 0 || entry & VlvfTable::pool_bit(2) == 0 {
            return TestResult::Fail("igb set_vf_vlan PF+VF pool bits drift");
        }
        // Remove the VF bit: the VFTA bit stays (the PF still
        // monitors the VID), but with only the PF pool left and
        // VLAN promiscuous off, update_pf_vlvf clears the entry —
        // the PF falls back to VFTA + the default pool.
        let prog = vt
            .set_vf_vlan(200, false, 1, |v| filter.contains(v))
            .unwrap();
        if prog.n_vlan_removes != 0 {
            return TestResult::Fail("igb set_vf_vlan remove clears a shared VFTA bit");
        }
        if vt.vlvf.entries[31] != 0 {
            return TestResult::Fail("igb set_vf_vlan remove leaves a PF-only VLVF entry");
        }
        if prog.n_writes != 1 || prog.writes[0] != RegWrite::new(vlvf_addr(31), 0) {
            return TestResult::Fail("igb set_vf_vlan remove update_pf_vlvf write drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_set_vf_vlan);

    fn smoke_igb_vmdq_clear_vf_vlvf() -> TestResult {
        let mut vt = vt_82576_2();
        // VF 0 and VF 1 share VID 300; VF 0 alone has VID 301.
        vt.set_vf_vlan(300, true, 0, |_| false).unwrap();
        vt.set_vf_vlan(300, true, 1, |_| false).unwrap();
        vt.set_vf_vlan(301, true, 0, |_| false).unwrap();
        // Clear VF 0: VID 300 keeps VF 1 (no VFTA clear), VID 301
        // loses its last pool (VFTA clear + entry disabled).
        let prog = vt.clear_vf_vlvf(0).unwrap();
        if prog.n_vlan_removes != 1 || prog.vlan_removes[0] != 301 {
            return TestResult::Fail("igb clear_vf_vlvf VFTA consequence drift");
        }
        if vt.vlvf.find_entry(300).is_none() || vt.vlvf.find_entry(301).is_some() {
            return TestResult::Fail("igb clear_vf_vlvf entry drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_clear_vf_vlvf);

    fn smoke_igb_vmdq_mrqc_modes() -> TestResult {
        // In-tree mrqc_word: VMDq with 1 RSS queue -> mode 0x3,
        // VMDq+RSS with 2 queues -> mode 0x5.
        if mrqc_word(false, false, true, 1) & 0xF != MRQC_ENABLE_VMDQ
            || mrqc_word(false, false, true, 2) & 0xF != MRQC_ENABLE_VMDQ_RSS_MQ
            || mrqc_word(false, false, false, 1) & 0xF == MRQC_ENABLE_VMDQ
        {
            return TestResult::Fail("igb MRQC VMDq mode drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_mrqc_modes);

    fn smoke_igb_vmdq_mta_set() -> TestResult {
        if mta_set(0x1234) != (17, 1 << 20) || mta_addr(17) != 0x05200 + 17 * 4 {
            return TestResult::Fail("igb MTA hash word/bit drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_mta_set);

    fn smoke_igb_vmdq_dispatch_reset() -> TestResult {
        let mut vt = vt_82576_2();
        let filter = VlanFilter::new();
        // RESET with no MAC: NACK reply, but CTS + enables still set.
        let out = vt.dispatch(0, &[VF_RESET], &filter).unwrap();
        if out.reply_len != 3 || out.reply[0] != VF_RESET | VT_MSGTYPE_NACK {
            return TestResult::Fail("igb RESET-no-MAC reply drift");
        }
        if !vt.vfs[0].cts || vt.vfre != 1 || vt.vfte != 1 {
            return TestResult::Fail("igb RESET does not set CTS/VFRE/VFTE");
        }
        // RESET after an admin MAC: ACK + MAC words.
        vt.set_vf_mac_admin(1, [0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
            .unwrap();
        let out = vt.dispatch(1, &[VF_RESET], &filter).unwrap();
        if out.reply[0] != VF_RESET | VT_MSGTYPE_ACK
            || out.reply[1] != 0x0000_0002
            || out.reply[2] != 0x0000_0100
        {
            return TestResult::Fail("igb RESET-with-MAC reply drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_dispatch_reset);

    fn smoke_igb_vmdq_dispatch_mac_vlan() -> TestResult {
        let mut vt = vt_82576_2();
        let filter = VlanFilter::new();
        // Pre-CTS SET_MAC: NACK, no program.
        let mac_msg = [VF_SET_MAC_ADDR, 0x0000_0202, 0x0000_0100];
        let out = vt.dispatch(0, &mac_msg, &filter).unwrap();
        if out.reply[0] != VF_SET_MAC_ADDR | VT_MSGTYPE_CTS | VT_MSGTYPE_NACK
            || out.program.n_writes != 0
        {
            return TestResult::Fail("igb pre-CTS message not NACKed cleanly");
        }
        // RESET to earn CTS, then SET_MAC primary: RAR writes + ACK.
        vt.dispatch(0, &[VF_RESET], &filter).unwrap();
        let out = vt.dispatch(0, &mac_msg, &filter).unwrap();
        if out.reply[0] != VF_SET_MAC_ADDR | VT_MSGTYPE_CTS | VT_MSGTYPE_ACK
            || out.program.n_writes != 2
        {
            return TestResult::Fail("igb SET_MAC_ADDR primary drift");
        }
        // RAR slot for VF 0 on 82576 (24 entries): 23.
        if out.program.writes[0].addr != ral_addr(23) || out.program.writes[1].addr != rah_addr(23)
        {
            return TestResult::Fail("igb SET_MAC_ADDR RAR slot drift");
        }
        // SET_VLAN add: VLVF write + strip write + ACK.
        let vlan_msg = [VF_SET_VLAN | (1 << 16), 400];
        let out = vt.dispatch(0, &vlan_msg, &filter).unwrap();
        if out.reply[0] != (VF_SET_VLAN | (1 << 16)) | VT_MSGTYPE_CTS | VT_MSGTYPE_ACK {
            return TestResult::Fail("igb SET_VLAN reply drift");
        }
        if vt.vlvf.find_entry(400).is_none() || !vt.vfs[0].vlan_strip {
            return TestResult::Fail("igb SET_VLAN state drift");
        }
        // Already-ACKed input: no reply at all.
        let out = vt
            .dispatch(0, &[VF_SET_VLAN | VT_MSGTYPE_ACK], &filter)
            .unwrap();
        if out.reply_len != 0 {
            return TestResult::Fail("igb already-processed message replied");
        }
        // Unknown type: NACK.
        let out = vt.dispatch(0, &[0x77], &filter).unwrap();
        if out.reply[0] != 0x77 | VT_MSGTYPE_CTS | VT_MSGTYPE_NACK {
            return TestResult::Fail("igb unknown message not NACKed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_dispatch_mac_vlan);

    fn smoke_igb_vmdq_dispatch_multicast_lpe_promisc() -> TestResult {
        let mut vt = vt_82576_2();
        let filter = VlanFilter::new();
        vt.dispatch(0, &[VF_RESET], &filter).unwrap();
        // SET_MULTICAST with 2 hashes: ROMPE + 2 MTA sets.
        let mc_msg = [VF_SET_MULTICAST | (2 << 16), 0x2222_1111, 0x4444_3333];
        let out = vt.dispatch(0, &mc_msg, &filter).unwrap();
        if out.reply[0] != mc_msg[0] | VT_MSGTYPE_CTS | VT_MSGTYPE_ACK
            || out.program.n_mta_sets != 2
            || vt.vmolr[0] & VMOLR_ROMPE == 0
        {
            return TestResult::Fail("igb SET_MULTICAST 2-hash drift");
        }
        // SET_LPE: size 0x5000 clamps to the RLPML field (0x3FFF).
        let out = vt.dispatch(0, &[VF_SET_LPE, 0x5000], &filter).unwrap();
        if vt.vmolr[0] & VMOLR_RLPML_MASK != 0x1000 || vt.vmolr[0] & VMOLR_LPE == 0 {
            return TestResult::Fail("igb SET_LPE clamp drift");
        }
        let _ = out;
        // SET_PROMISC multicast: MPME.
        let out = vt
            .dispatch(0, &[VF_SET_PROMISC | VF_SET_PROMISC_MULTICAST], &filter)
            .unwrap();
        if vt.vmolr[0] & VMOLR_MPME == 0
            || out.reply[0]
                != (VF_SET_PROMISC | VF_SET_PROMISC_MULTICAST) | VT_MSGTYPE_CTS | VT_MSGTYPE_ACK
        {
            return TestResult::Fail("igb SET_PROMISC multicast drift");
        }
        // SET_PROMISC with leftover info bits: NACK, but the VMOLR
        // program is still applied (Linux write-then-check order).
        let out = vt
            .dispatch(0, &[VF_SET_PROMISC | (0x04 << 16)], &filter)
            .unwrap();
        if out.reply[0] != (VF_SET_PROMISC | (0x04 << 16)) | VT_MSGTYPE_CTS | VT_MSGTYPE_NACK
            || out.program.n_writes != 1
        {
            return TestResult::Fail("igb SET_PROMISC leftover-bits drift");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/igb",
        smoke_igb_vmdq_dispatch_multicast_lpe_promisc
    );

    fn smoke_igb_vmdq_admin() -> TestResult {
        let mut vt = vt_82576_2();
        // Zero MAC clears the PF-set flag; valid sets it; multicast
        // (bit 0 of byte 0) is refused.
        vt.set_vf_mac_admin(0, [0x02, 0, 0, 0, 0, 0x01]).unwrap();
        if !vt.vfs[0].pf_set_mac {
            return TestResult::Fail("igb admin MAC does not set PF_SET_MAC");
        }
        vt.set_vf_mac_admin(0, [0; 6]).unwrap();
        if vt.vfs[0].pf_set_mac {
            return TestResult::Fail("igb admin zero MAC does not clear PF_SET_MAC");
        }
        if vt.set_vf_mac_admin(0, [0x01, 0, 0, 0, 0, 0x01]).is_ok() {
            return TestResult::Fail("igb admin multicast MAC not refused");
        }
        // Admin port VLAN: VMVIR carries vid | qos<<13 | DEFAULT,
        // VMOLR untagged-off, strip on.
        let prog = vt.set_vf_vlan_admin(0, 500, 3, |_| false).unwrap();
        let _ = prog;
        if vt.vfs[0].pf_vlan != 500 || vt.vfs[0].pf_qos != 3 || !vt.vfs[0].vlan_strip {
            return TestResult::Fail("igb admin port-VLAN state drift");
        }
        if vt.vmolr[0] & VMOLR_AUPE != 0 {
            return TestResult::Fail("igb admin port-VLAN leaves AUPE set");
        }
        // Admin VLAN blocks VF SET_VLAN (tested via the message path
        // with a fresh CTS-earned VF).
        let filter = VlanFilter::new();
        vt.dispatch(0, &[VF_RESET], &filter).unwrap();
        let out = vt
            .dispatch(0, &[VF_SET_VLAN | (1 << 16), 600], &filter)
            .unwrap();
        if out.reply[0] != (VF_SET_VLAN | (1 << 16)) | VT_MSGTYPE_CTS | VT_MSGTYPE_NACK {
            return TestResult::Fail("igb admin VLAN does not block VF SET_VLAN");
        }
        // Disable restores tagless access.
        vt.set_vf_vlan_admin(0, 0, 0, |_| false).unwrap();
        if vt.vfs[0].pf_vlan != 0 || vt.vfs[0].vlan_strip {
            return TestResult::Fail("igb admin port-VLAN disable drift");
        }
        // Trust flag gates primary-MAC override.
        vt.set_vf_mac_admin(0, [0x02, 0, 0, 0, 0, 0x02]).unwrap();
        let out = vt
            .dispatch(0, &[VF_SET_MAC_ADDR, 0x0000_0303, 0x0000_0100], &filter)
            .unwrap();
        if out.reply[0] != VF_SET_MAC_ADDR | VT_MSGTYPE_CTS | VT_MSGTYPE_NACK {
            return TestResult::Fail("igb untrusted VF overrode PF-set MAC");
        }
        vt.set_vf_trust(0, true).unwrap();
        let out = vt
            .dispatch(0, &[VF_SET_MAC_ADDR, 0x0000_0303, 0x0000_0100], &filter)
            .unwrap();
        if out.reply[0] != VF_SET_MAC_ADDR | VT_MSGTYPE_CTS | VT_MSGTYPE_ACK {
            return TestResult::Fail("igb trusted VF cannot override PF-set MAC");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_admin);

    fn smoke_igb_vmdq_vf_rate_limit() -> TestResult {
        // Pure rate-factor words (Linux `igb_set_vf_rate_limit`):
        // 1000/500 -> rf_int 2, rf_dec 0.
        if vf_rate_limit_bcnrc(500, 1000) != 0x8000_8000 {
            return TestResult::Fail("igb VF rate 500@1000 factor drift");
        }
        // 1000/250 -> rf_int 4.
        if vf_rate_limit_bcnrc(250, 1000) != 0x8001_0000 {
            return TestResult::Fail("igb VF rate 250@1000 factor drift");
        }
        // 1000/333 -> rf_int 3, rf_dec (1 * 16384) / 333 = 49.
        if vf_rate_limit_bcnrc(333, 1000) != 0x8000_C031 {
            return TestResult::Fail("igb VF rate 333@1000 fractional factor drift");
        }
        // Unthrottled programs a zero word.
        if vf_rate_limit_bcnrc(0, 1000) != 0 {
            return TestResult::Fail("igb VF rate 0 does not program unthrottled");
        }
        // Gate: only the 82576 MAC type.
        if !rate_limit_supported(IGB_82576)
            || !rate_limit_supported(IGB_82576_NS)
            || rate_limit_supported(IGB_I350_COPPER)
        {
            return TestResult::Fail("igb VF rate-limit MAC-type gate drift");
        }
        let mut vt = vt_82576_2();
        // Set 500 Mbps on VF 0 at 1 Gbps, link up: queue select,
        // MMW_SIZE, factor word; stored rate + link speed kept.
        let prog = match vt.set_vf_bw(0, 0, 500, 1000, true) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb set_vf_bw refused a valid limit"),
        };
        if prog.n_writes != 3
            || prog.writes[0] != RegWrite::new(REG_RTTDQSEL, 0)
            || prog.writes[1] != RegWrite::new(REG_RTTBCNRM, 0x14)
            || prog.writes[2] != RegWrite::new(REG_RTTBCNRC, 0x8000_8000)
            || vt.vfs[0].tx_rate != 500
            || vt.vf_rate_link_speed != 1000
        {
            return TestResult::Fail("igb set_vf_bw 500@1000 program drift");
        }
        // Clear: rate 0 restores the unthrottled word.
        let prog = match vt.set_vf_bw(0, 0, 0, 1000, true) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb set_vf_bw refused a clear"),
        };
        if prog.writes[2] != RegWrite::new(REG_RTTBCNRC, 0) || vt.vfs[0].tx_rate != 0 {
            return TestResult::Fail("igb set_vf_bw clear does not restore unthrottled");
        }
        // Refusals: out-of-range VF, nonzero min rate, rate above
        // the link, negative rate, link down.
        if vt.set_vf_bw(2, 0, 500, 1000, true).is_ok()
            || vt.set_vf_bw(0, 100, 500, 1000, true).is_ok()
            || vt.set_vf_bw(0, 0, 1001, 1000, true).is_ok()
            || vt.set_vf_bw(0, 0, -1, 1000, true).is_ok()
            || vt.set_vf_bw(0, 0, 500, 1000, false).is_ok()
        {
            return TestResult::Fail("igb set_vf_bw accepted an out-of-range limit");
        }
        // A refused set leaves the stored rate untouched.
        if vt.vfs[0].tx_rate != 0 {
            return TestResult::Fail("igb refused set_vf_bw mutated stored rate");
        }
        // Non-82576 MAC type: -EOPNOTSUPP, even for a valid limit.
        let mut i350 = VtState::new(IGB_I350_COPPER, 2).unwrap();
        if !matches!(
            i350.set_vf_bw(0, 0, 500, 1000, true),
            Err(VmdqError::Unsupported)
        ) {
            return TestResult::Fail("igb set_vf_bw accepted a rate on I350");
        }
        // Re-check: set both VFs, then re-apply at the same speed.
        vt.set_vf_bw(0, 0, 500, 1000, true).unwrap();
        vt.set_vf_bw(1, 0, 250, 1000, true).unwrap();
        let prog = match vt.check_vf_rate_limit(1000) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb check_vf_rate_limit failed at same speed"),
        };
        if prog.n_writes != 6
            || prog.writes[0] != RegWrite::new(REG_RTTDQSEL, 0)
            || prog.writes[2] != RegWrite::new(REG_RTTBCNRC, 0x8000_8000)
            || prog.writes[3] != RegWrite::new(REG_RTTDQSEL, 1)
            || prog.writes[5] != RegWrite::new(REG_RTTBCNRC, 0x8001_0000)
        {
            return TestResult::Fail("igb check_vf_rate_limit same-speed re-apply drift");
        }
        // Speed change to 100: rates cleared, recorded speed
        // forgotten, both VFs re-programmed unthrottled.
        let prog = match vt.check_vf_rate_limit(100) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb check_vf_rate_limit failed on speed change"),
        };
        if vt.vfs[0].tx_rate != 0
            || vt.vfs[1].tx_rate != 0
            || vt.vf_rate_link_speed != 0
            || prog.n_writes != 6
            || prog.writes[2] != RegWrite::new(REG_RTTBCNRC, 0)
            || prog.writes[5] != RegWrite::new(REG_RTTBCNRC, 0)
        {
            return TestResult::Fail("igb check_vf_rate_limit speed-change reset drift");
        }
        // Nothing stored any more: the next check is a no-op.
        let prog = match vt.check_vf_rate_limit(100) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb check_vf_rate_limit failed when idle"),
        };
        if prog.n_writes != 0 {
            return TestResult::Fail("igb check_vf_rate_limit not a no-op when unset");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_vf_rate_limit);

    fn smoke_igb_vmdq_restore_vf_multicasts() -> TestResult {
        let mut vt = vt_82576_2();
        let filter = VlanFilter::new();
        // Register VF multicast hashes through the mailbox path:
        // VF 0 takes 2 hashes (0x1111, 0x2222), VF 1 takes 1 (0x5555).
        vt.dispatch(0, &[VF_RESET], &filter).unwrap();
        vt.dispatch(1, &[VF_RESET], &filter).unwrap();
        let mc0 = [VF_SET_MULTICAST | (2 << 16), 0x2222_1111, 0x4444_3333];
        vt.dispatch(0, &mc0, &filter).unwrap();
        let mc1 = [VF_SET_MULTICAST | (1 << 16), 0x6666_5555];
        vt.dispatch(1, &mc1, &filter).unwrap();
        if vt.vfs[0].mc_count != 2 || vt.vfs[1].mc_count != 1 {
            return TestResult::Fail("igb VF multicast registration drift");
        }
        // Simulate the PF multicast-list change: Linux
        // `igb_set_rx_mode` rewrites the MTA (dropping every VF
        // hash) and the PF-side VMOLR bits. The MTA flush itself
        // belongs to the future `set_rx_mode` path; here the VMOLR
        // shadows are cleared the way that rewrite would clear
        // them, and the restore must put the VF state back.
        vt.vmolr[0] &= !(VMOLR_ROMPE | VMOLR_MPME);
        vt.vmolr[1] &= !(VMOLR_ROMPE | VMOLR_MPME);
        let prog = match vt.restore_vf_multicast(0) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb restore_vf_multicast failed for VF 0"),
        };
        // 0x1111 -> word 8, bit 17; 0x2222 -> word 17, bit 2.
        if prog.n_mta_sets != 2
            || prog.mta_sets[0] != (mta_addr(8), 1 << 17)
            || prog.mta_sets[1] != (mta_addr(17), 1 << 2)
            || prog.n_writes != 1
            || prog.writes[0].addr != vmolr_addr(0)
            || prog.writes[0].value & VMOLR_ROMPE == 0
            || vt.vmolr[0] & VMOLR_ROMPE == 0
        {
            return TestResult::Fail("igb restore_vf_multicast VF 0 program drift");
        }
        // VF 1: its single hash comes back (0x5555 -> word 42, bit 21).
        let prog = match vt.restore_vf_multicast(1) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb restore_vf_multicast failed for VF 1"),
        };
        if prog.n_mta_sets != 1
            || prog.mta_sets[0] != (mta_addr(42), 1 << 21)
            || vt.vmolr[1] & VMOLR_ROMPE == 0
        {
            return TestResult::Fail("igb restore_vf_multicast VF 1 program drift");
        }
        // Out-of-range VF fails closed.
        if vt.restore_vf_multicast(2).is_ok() {
            return TestResult::Fail("igb restore_vf_multicast accepted an out-of-range VF");
        }
        // > 30 hashes: MPME, no MTA sets. Register 31 hashes on
        // VF 0 through the message path (count stays 31, 30 stored).
        let mut msg = [0u32; 16];
        msg[0] = VF_SET_MULTICAST | (31 << 16);
        for i in 1..16 {
            msg[i] = 0x0001_0001;
        }
        vt.dispatch(0, &msg, &filter).unwrap();
        if vt.vfs[0].mc_count != 31 {
            return TestResult::Fail("igb VF multicast >30 count drift");
        }
        vt.vmolr[0] &= !(VMOLR_ROMPE | VMOLR_MPME);
        let prog = match vt.restore_vf_multicast(0) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb restore_vf_multicast failed for >30 hashes"),
        };
        if prog.n_mta_sets != 0 || vt.vmolr[0] & VMOLR_MPME == 0 || vt.vmolr[0] & VMOLR_ROMPE != 0 {
            return TestResult::Fail("igb restore_vf_multicast >30 hashes drift");
        }
        // Multicast-promiscuous VF: restore re-applies MPME
        // instead of the hashes.
        vt.dispatch(1, &[VF_SET_PROMISC | VF_SET_PROMISC_MULTICAST], &filter)
            .unwrap();
        if !vt.vfs[1].multi_promisc {
            return TestResult::Fail("igb SET_PROMISC did not set multi_promisc");
        }
        vt.vmolr[1] &= !(VMOLR_ROMPE | VMOLR_MPME);
        let prog = match vt.restore_vf_multicast(1) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb restore_vf_multicast failed for promisc VF"),
        };
        if prog.n_mta_sets != 0 || vt.vmolr[1] & VMOLR_MPME == 0 || vt.vmolr[1] & VMOLR_ROMPE != 0 {
            return TestResult::Fail("igb restore_vf_multicast promisc VF drift");
        }
        // Plain SET_PROMISC clears the flag: the stored hash comes back.
        vt.dispatch(1, &[VF_SET_PROMISC], &filter).unwrap();
        if vt.vfs[1].multi_promisc {
            return TestResult::Fail("igb plain SET_PROMISC did not clear multi_promisc");
        }
        vt.vmolr[1] &= !(VMOLR_ROMPE | VMOLR_MPME);
        let prog = match vt.restore_vf_multicast(1) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb restore_vf_multicast failed after unpromisc"),
        };
        if prog.n_mta_sets != 1 || vt.vmolr[1] & VMOLR_ROMPE == 0 {
            return TestResult::Fail("igb restore_vf_multicast after unpromisc drift");
        }
        // A VF with no hashes gets a bare VMOLR write clearing
        // both bits and no MTA sets.
        let mut vt2 = vt_82576_2();
        vt2.vmolr[0] |= VMOLR_ROMPE | VMOLR_MPME;
        let prog = match vt2.restore_vf_multicast(0) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb restore_vf_multicast failed for empty VF"),
        };
        if prog.n_mta_sets != 0
            || prog.n_writes != 1
            || vt2.vmolr[0] & (VMOLR_ROMPE | VMOLR_MPME) != 0
        {
            return TestResult::Fail("igb restore_vf_multicast empty VF drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vmdq_restore_vf_multicasts);
}
