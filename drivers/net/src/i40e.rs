//! Intel Ethernet 700-series (`i40e`) — X710 / XL710 / XXV710 /
//! X722 — Admin-Queue bring-up.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 `drivers/net/ethernet/intel/i40e/` (GPL-2.0; NARF
//! is GPL-2.0-or-later so adaptation is permitted):
//!
//! - `i40e_devids.h`     — the PCI device-ID table.
//! - `i40e_register.h`   — every MMIO offset used below.
//! - `i40e_common.c`     — `i40e_pf_reset`.
//! - `i40e_adminq.c`     — `i40e_config_asq_regs` /
//!   `i40e_config_arq_regs`, `i40e_asq_send_command`.
//! - `i40e_adminq_cmd.h` + `include/linux/net/intel/libie/adminq.h` —
//!   descriptor layout, flags, opcodes.
//!
//! ## Hardware this targets
//!
//! Verified against the Minisforum **MS-03**, which carries a
//! dual-port **X710 for 10GbE SFP+** at PCI `59:00.0` and `59:00.1`
//! (`8086:1572`, rev 02).
//!
//! ## Why this chip is shaped differently from `igc` / `ixgbe`
//!
//! On the 700 series nearly nothing is programmed by poking rings
//! directly. The device runs its own firmware, and the driver talks
//! to it over a pair of DMA rings — the **Admin Transmit Queue**
//! (ATQ, driver → firmware) and **Admin Receive Queue** (ARQ,
//! firmware → driver, for unsolicited events). Getting a MAC
//! address, reading link state, or creating a VSI are all AQ
//! commands, not register writes. So the ordering here is:
//!
//! 1. PF reset (`i40e_pf_reset`): wait out any in-flight global
//!    reset, wait for the NVM "core + global done" bits, then pulse
//!    `PFGEN_CTRL.PFSWR` and wait for it to self-clear.
//! 2. Allocate and program the ATQ + ARQ rings.
//! 3. Handshake: `get_version` (0x0001) for the firmware and API
//!    versions, `driver_version` (0x0002) to announce ourselves.
//! 4. `clear_pxe_mode` (0x0110) to take the port away from the
//!    option ROM.
//! 5. `mac_address_read` (0x0107) for the port's LAN MAC, and
//!    `get_link_status` (0x0607) for speed / link.
//!
//! 6. Find the PF's main VSI via `get_switch_config` (0x0200) and
//!    read its context with `get_vsi_parameters` (0x0212).
//! 7. Stand up the LAN HMC, install the TX/RX queue contexts, enable
//!    the queues, and add the MAC filters the VSI needs to receive.
//!
//! ## Link state
//!
//! Link state is **event-driven**, not a snapshot. Firmware posts a
//! `get_link_status` event on the Admin Receive Queue whenever the
//! link changes, and `i40e_arq_pump` drains the ARQ and re-issues the
//! command. It ignores the event payload and trusts the command's
//! answer, which is what Linux's `i40e_handle_link_event` does — the
//! command is the authoritative read, and re-issuing it also re-arms
//! reporting, which firmware disarms after each event.
//!
//! That matters on this board: both SFP+ cages start empty, so a
//! cached bring-up snapshot would report the port down forever even
//! after a module is seated.
//!
//! Steps 6–7 live in the [`hmc`], [`vsi`] and [`ring`] submodules;
//! each documents the traps in its own layer.
//!
//! ## Scope
//!
//! One queue pair, polled. What is deliberately absent:
//!
//! - **MSI-X and interrupt-driven completion.** TX completion comes
//!   from head writeback and RX from the descriptor done bit, both
//!   polled by the frame pumps.
//! - **RSS across multiple queues**, which needs a hash LUT and a
//!   vector per queue.
//! - **Checksum and TSO offload.** Every frame goes out as a single
//!   data descriptor with no context descriptor ahead of it.
//! - **Extra VSIs.** `add_vsi` (0x0210) is for VMDq, flow director
//!   and SR-IOV VFs; the PF's own VSI already exists and is reused.
//! - **Jumbo frames.** `rxmax` is pinned at 1522 to match the
//!   2 KiB per-descriptor buffer.
//! - **Interrupt-driven ARQ.** The pump polls; firmware raises an
//!   interrupt for admin events, which would let it park instead.
//!
//! ## Multi-port
//!
//! The X710 presents one PF per port — two on the MS-03, four on the
//! QSFP parts. Each probes independently and registers under its own
//! name from [`INTERFACE_NAMES`] (`i40e0`, `i40e1`, …), assigned in
//! probe order.
//!
//! [`I40eNicIface`] owns an `Arc<I40eNic>` rather than indexing a
//! global. That is what makes this work: `Interface::rx_ring` returns
//! a reference borrowed from `&self`, so an interface with no storage
//! has to return a `static` — and every port would then share one
//! pair of rings, quietly delivering the second port's frames to the
//! first port's queue.

#![allow(dead_code)]

pub mod hmc;
pub mod ring;
pub mod vsi;

mod tests;

extern crate alloc;

use core::sync::atomic::{compiler_fence, AtomicU64, Ordering};

use alloc::sync::Arc;

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, RX_RING_N, TX_RING_N};

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Linux `i40e_devids.h`. The 700 series spans XL710 (40G), X710
// (10G), XXV710 (25G) and X722; every one of them presents the same
// Admin Queue, so a single probe path covers the family.

/// Intel.
pub const I40E_VENDOR: u16 = 0x8086;

/// X710/XL710 SFP+ — `I40E_DEV_ID_SFP_XL710`. The SKU on the MS-03.
pub const I40E_DEV_SFP_XL710: u16 = 0x1572;
/// `I40E_DEV_ID_QEMU` — the emulated 700-series QEMU exposes.
pub const I40E_DEV_QEMU: u16 = 0x1574;
/// `I40E_DEV_ID_KX_B`.
pub const I40E_DEV_KX_B: u16 = 0x1580;
/// `I40E_DEV_ID_KX_C`.
pub const I40E_DEV_KX_C: u16 = 0x1581;
/// `I40E_DEV_ID_QSFP_A`.
pub const I40E_DEV_QSFP_A: u16 = 0x1583;
/// `I40E_DEV_ID_QSFP_B`.
pub const I40E_DEV_QSFP_B: u16 = 0x1584;
/// `I40E_DEV_ID_QSFP_C`.
pub const I40E_DEV_QSFP_C: u16 = 0x1585;
/// `I40E_DEV_ID_10G_BASE_T`.
pub const I40E_DEV_10G_BASE_T: u16 = 0x1586;
/// `I40E_DEV_ID_20G_KR2`.
pub const I40E_DEV_20G_KR2: u16 = 0x1587;
/// `I40E_DEV_ID_20G_KR2_A`.
pub const I40E_DEV_20G_KR2_A: u16 = 0x1588;
/// `I40E_DEV_ID_10G_BASE_T4`.
pub const I40E_DEV_10G_BASE_T4: u16 = 0x1589;
/// `I40E_DEV_ID_25G_B`.
pub const I40E_DEV_25G_B: u16 = 0x158A;
/// `I40E_DEV_ID_25G_SFP28`.
pub const I40E_DEV_25G_SFP28: u16 = 0x158B;
/// `I40E_DEV_ID_10G_BASE_T_BC`.
pub const I40E_DEV_10G_BASE_T_BC: u16 = 0x15FF;
/// `I40E_DEV_ID_10G_B`.
pub const I40E_DEV_10G_B: u16 = 0x104F;
/// `I40E_DEV_ID_10G_SFP`.
pub const I40E_DEV_10G_SFP: u16 = 0x104E;
/// `I40E_DEV_ID_5G_BASE_T_BC`.
pub const I40E_DEV_5G_BASE_T_BC: u16 = 0x101F;
/// `I40E_DEV_ID_1G_BASE_T_BC`.
pub const I40E_DEV_1G_BASE_T_BC: u16 = 0x0DD2;
/// `I40E_DEV_ID_X710_N3000`.
pub const I40E_DEV_X710_N3000: u16 = 0x0CF8;
/// `I40E_DEV_ID_XXV710_N3000`.
pub const I40E_DEV_XXV710_N3000: u16 = 0x0D58;
/// `I40E_DEV_ID_KX_X722`.
pub const I40E_DEV_KX_X722: u16 = 0x37CE;
/// `I40E_DEV_ID_QSFP_X722`.
pub const I40E_DEV_QSFP_X722: u16 = 0x37CF;
/// `I40E_DEV_ID_SFP_X722`.
pub const I40E_DEV_SFP_X722: u16 = 0x37D0;
/// `I40E_DEV_ID_1G_BASE_T_X722`.
pub const I40E_DEV_1G_BASE_T_X722: u16 = 0x37D1;
/// `I40E_DEV_ID_10G_BASE_T_X722`.
pub const I40E_DEV_10G_BASE_T_X722: u16 = 0x37D2;
/// `I40E_DEV_ID_SFP_I_X722`.
pub const I40E_DEV_SFP_I_X722: u16 = 0x37D3;
/// `I40E_DEV_ID_SFP_X722_A`.
pub const I40E_DEV_SFP_X722_A: u16 = 0x0DDA;

/// Every device ID this driver claims, in one `const` so
/// `register_pci_driver` and the match-table smoke cannot drift.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    I40E_DEV_X710_N3000,
    I40E_DEV_XXV710_N3000,
    I40E_DEV_1G_BASE_T_BC,
    I40E_DEV_SFP_X722_A,
    I40E_DEV_5G_BASE_T_BC,
    I40E_DEV_10G_SFP,
    I40E_DEV_10G_B,
    I40E_DEV_SFP_XL710,
    I40E_DEV_QEMU,
    I40E_DEV_KX_B,
    I40E_DEV_KX_C,
    I40E_DEV_QSFP_A,
    I40E_DEV_QSFP_B,
    I40E_DEV_QSFP_C,
    I40E_DEV_10G_BASE_T,
    I40E_DEV_20G_KR2,
    I40E_DEV_20G_KR2_A,
    I40E_DEV_10G_BASE_T4,
    I40E_DEV_25G_B,
    I40E_DEV_25G_SFP28,
    I40E_DEV_10G_BASE_T_BC,
    I40E_DEV_KX_X722,
    I40E_DEV_QSFP_X722,
    I40E_DEV_SFP_X722,
    I40E_DEV_1G_BASE_T_X722,
    I40E_DEV_10G_BASE_T_X722,
    I40E_DEV_SFP_I_X722,
];

/// Human-readable SKU tag for a device id.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        I40E_DEV_SFP_XL710 => "i40e-x710-sfp",
        I40E_DEV_QEMU => "i40e-qemu",
        I40E_DEV_KX_B | I40E_DEV_KX_C => "i40e-xl710-kx",
        I40E_DEV_QSFP_A | I40E_DEV_QSFP_B | I40E_DEV_QSFP_C => "i40e-xl710-qsfp",
        I40E_DEV_10G_BASE_T | I40E_DEV_10G_BASE_T4 | I40E_DEV_10G_BASE_T_BC => "i40e-x710-baset",
        I40E_DEV_20G_KR2 | I40E_DEV_20G_KR2_A => "i40e-xl710-kr2",
        I40E_DEV_25G_B | I40E_DEV_25G_SFP28 | I40E_DEV_XXV710_N3000 => "i40e-xxv710",
        I40E_DEV_KX_X722
        | I40E_DEV_QSFP_X722
        | I40E_DEV_SFP_X722
        | I40E_DEV_1G_BASE_T_X722
        | I40E_DEV_10G_BASE_T_X722
        | I40E_DEV_SFP_I_X722
        | I40E_DEV_SFP_X722_A => "i40e-x722",
        _ => "i40e",
    }
}

/// `true` iff this driver claims `did`.
pub fn is_supported_device(did: u16) -> bool {
    let mut i = 0;
    while i < SUPPORTED_DEVICE_IDS.len() {
        if SUPPORTED_DEVICE_IDS[i] == did {
            return true;
        }
        i += 1;
    }
    false
}

// ── BAR + register offsets (Linux `i40e_register.h`) ────────────────

/// The 700 series puts its whole CSR space in BAR0.
pub const I40E_BAR_CSR: u8 = 0;

/// `I40E_PFGEN_CTRL` — PF control. Bit 0 (`PFSWR`) requests a PF
/// reset and self-clears when the reset finishes.
pub const REG_PFGEN_CTRL: u64 = 0x0009_2400;
/// `I40E_PFGEN_CTRL_PFSWR_MASK`.
pub const PFGEN_CTRL_PFSWR: u32 = 1 << 0;

/// `I40E_PFGEN_PORTNUM` — which physical port this PF is attached to.
pub const REG_PFGEN_PORTNUM: u64 = 0x001C_0480;
/// `I40E_PFGEN_PORTNUM_PORT_NUM_MASK` — bits [1:0].
pub const PFGEN_PORTNUM_MASK: u32 = 0x3;

/// `I40E_PF_FUNC_RID` — this function's requester id.
pub const REG_PF_FUNC_RID: u64 = 0x0009_C000;
/// `I40E_GLPCI_CAPSUP` — PCIe capability support.
pub const REG_GLPCI_CAPSUP: u64 = 0x000B_E4A8;
/// `I40E_GLPCI_CAPSUP_ARI_EN_MASK` — ARI is enabled, which widens
/// the function-number field of `PF_FUNC_RID` from 3 bits to 8.
pub const GLPCI_CAPSUP_ARI_EN: u32 = 1 << 4;
/// `I40E_PFLAN_QALLOC` — the PF's absolute LAN queue range.
pub const REG_PFLAN_QALLOC: u64 = 0x001C_0400;

/// Queue pairs this driver brings up. One is enough to carry
/// traffic; RSS across several needs a LUT and per-queue interrupt
/// vectors, neither of which is in scope here.
pub const NUM_QUEUE_PAIRS: u32 = 1;

/// Interface names, one per probed PF.
///
/// `HwNic::name` returns `&'static str`, so a per-port name cannot be
/// built at runtime without leaking it. A fixed table costs nothing
/// and bounds the driver to a knowable number of ports: a 4-port X710
/// presents four PFs, so this covers four such cards.
///
/// Names are assigned in probe order. That is the same convention
/// every other NIC driver in tree uses, and it is stable for a fixed
/// board — but it is *not* topology-derived the way Linux's
/// `enp89s0f0` is, so a card added to another slot can renumber the
/// ports after it.
pub const INTERFACE_NAMES: &[&str] = &[
    "i40e0", "i40e1", "i40e2", "i40e3", "i40e4", "i40e5", "i40e6", "i40e7", "i40e8", "i40e9",
    "i40e10", "i40e11", "i40e12", "i40e13", "i40e14", "i40e15",
];

/// Name for the `index`-th probed PF, or `None` once the table is
/// exhausted.
///
/// Returning `None` rather than reusing a name is deliberate: the
/// registry rejects duplicates, so a reused name would leave the port
/// silently unregistered with no indication why. An explicit `None`
/// lets the probe say so.
pub fn interface_name(index: usize) -> Option<&'static str> {
    INTERFACE_NAMES.get(index).copied()
}

/// `I40E_GLGEN_RSTCTL` — global reset control; bits [5:0] hold
/// `GRSTDEL`, the global-reset delay in 100 ms units.
pub const REG_GLGEN_RSTCTL: u64 = 0x000B_8180;
/// `I40E_GLGEN_RSTCTL_GRSTDEL_MASK`.
pub const GLGEN_RSTCTL_GRSTDEL_MASK: u32 = 0x3F;

/// `I40E_GLGEN_RSTAT` — global reset status. `DEVSTATE` (bits [1:0])
/// is non-zero while a global reset is in flight.
pub const REG_GLGEN_RSTAT: u64 = 0x000B_8188;
/// `I40E_GLGEN_RSTAT_DEVSTATE_MASK`.
pub const GLGEN_RSTAT_DEVSTATE_MASK: u32 = 0x3;

/// `I40E_GLNVM_ULD` — NVM upload-done status.
pub const REG_GLNVM_ULD: u64 = 0x000B_6008;
/// `I40E_GLNVM_ULD_CONF_CORE_DONE_MASK` (bit 3).
pub const GLNVM_ULD_CORE_DONE: u32 = 1 << 3;
/// `I40E_GLNVM_ULD_CONF_GLOBAL_DONE_MASK` (bit 4).
pub const GLNVM_ULD_GLOBAL_DONE: u32 = 1 << 4;
/// Both "done" bits — what `i40e_pf_reset` waits for.
pub const GLNVM_ULD_READY: u32 = GLNVM_ULD_CORE_DONE | GLNVM_ULD_GLOBAL_DONE;

// Admin Transmit Queue (driver → firmware).
/// `I40E_PF_ATQBAL` — ring base, low 32 bits.
pub const REG_PF_ATQBAL: u64 = 0x0008_0000;
/// `I40E_PF_ATQBAH` — ring base, high 32 bits.
pub const REG_PF_ATQBAH: u64 = 0x0008_0100;
/// `I40E_PF_ATQLEN` — descriptor count in bits [9:0], enable in 31.
pub const REG_PF_ATQLEN: u64 = 0x0008_0200;
/// `I40E_PF_ATQH` — head, advanced by firmware.
pub const REG_PF_ATQH: u64 = 0x0008_0300;
/// `I40E_PF_ATQT` — tail, the driver's doorbell.
pub const REG_PF_ATQT: u64 = 0x0008_0400;

// Admin Receive Queue (firmware → driver).
/// `I40E_PF_ARQBAL`.
pub const REG_PF_ARQBAL: u64 = 0x0008_0080;
/// `I40E_PF_ARQBAH`.
pub const REG_PF_ARQBAH: u64 = 0x0008_0180;
/// `I40E_PF_ARQLEN`.
pub const REG_PF_ARQLEN: u64 = 0x0008_0280;
/// `I40E_PF_ARQH`.
pub const REG_PF_ARQH: u64 = 0x0008_0380;
/// `I40E_PF_ARQT`.
pub const REG_PF_ARQT: u64 = 0x0008_0480;
/// `I40E_PF_ARQH_ARQH_MASK` — the head index is 10 bits; the upper
/// bits of the register are not part of it.
pub const ARQH_MASK: u32 = 0x3FF;

/// `I40E_PF_ATQLEN_ATQENABLE_MASK` / `..._ARQENABLE_MASK` (bit 31).
pub const AQLEN_ENABLE: u32 = 1 << 31;
/// `ATQOVFL` / `ARQOVFL` (bit 29) — queue overflowed.
pub const AQLEN_OVFL: u32 = 1 << 29;
/// `ATQCRIT` / `ARQCRIT` (bit 30) — critical error.
pub const AQLEN_CRIT: u32 = 1 << 30;

// ── Admin Queue descriptor ──────────────────────────────────────────

/// Admin Queue descriptor — `struct libie_aq_desc`, 32 bytes,
/// little-endian throughout.
///
/// `params` is a 16-byte union in Linux. Keeping it a raw byte array
/// here and decoding through typed helpers avoids replicating a
/// dozen `#[repr(C)]` payload structs for commands we do not issue.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AqDesc {
    /// `LIBIE_AQ_FLAG_*`.
    pub flags: u16,
    /// Command opcode ([`AqOpcode`]).
    pub opcode: u16,
    /// Length of the indirect data buffer, when `BUF` is set.
    pub datalen: u16,
    /// Firmware's return value ([`AqError`]).
    pub retval: u16,
    pub cookie_high: u32,
    pub cookie_low: u32,
    /// Command-specific parameters. For an indirect command the last
    /// eight bytes are `addr_high` then `addr_low`.
    pub params: [u8; 16],
}
const _: () = assert!(core::mem::size_of::<AqDesc>() == 32);

// Descriptor flags — `LIBIE_AQ_FLAG_*`.
/// Descriptor Done — firmware has written this descriptor back.
pub const AQ_FLAG_DD: u16 = 1 << 0;
/// Complete.
pub const AQ_FLAG_CMP: u16 = 1 << 1;
/// Error — check `retval`.
pub const AQ_FLAG_ERR: u16 = 1 << 2;
/// VF error.
pub const AQ_FLAG_VFE: u16 = 1 << 3;
/// Large buffer (> 512 bytes).
pub const AQ_FLAG_LB: u16 = 1 << 9;
/// Read Data — the buffer is driver → firmware.
pub const AQ_FLAG_RD: u16 = 1 << 10;
/// VF command.
pub const AQ_FLAG_VFC: u16 = 1 << 11;
/// An external data buffer is attached.
pub const AQ_FLAG_BUF: u16 = 1 << 12;
/// Signed command.
pub const AQ_FLAG_SI: u16 = 1 << 13;
/// Error interrupt.
pub const AQ_FLAG_EI: u16 = 1 << 14;
/// Flush error.
pub const AQ_FLAG_FE: u16 = 1 << 15;

/// `LIBIE_AQ_LG_BUF` — buffers above this need `AQ_FLAG_LB`.
pub const AQ_LARGE_BUF: u16 = 512;
/// Alias used by the smokes to name the threshold they assert.
pub const AQC_LARGE_BUF_CHECK: u16 = AQ_LARGE_BUF;

/// The Admin Queue opcodes this driver issues.
/// Linux `enum i40e_admin_queue_opc`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AqOpcode {
    /// Firmware + API version (direct).
    GetVersion = 0x0001,
    /// Announce the driver's version (indirect).
    DriverVersion = 0x0002,
    /// Tell firmware the driver is unloading (direct).
    QueueShutdown = 0x0003,
    /// Read the port's MAC addresses (indirect).
    MacAddressRead = 0x0107,
    /// Release the port from the option ROM's PXE mode (direct).
    ClearPxeMode = 0x0110,
    /// Current link speed / state (direct).
    GetLinkStatus = 0x0607,
    /// Read the switch topology (indirect).
    GetSwitchConfig = 0x0200,
    /// Read an existing VSI's context (indirect).
    GetVsiParameters = 0x0212,
    /// Add a MAC/VLAN filter to a VSI (indirect).
    AddMacvlan = 0x0250,
    /// Enable the link and restart auto-negotiation (direct).
    SetLinkRestartAn = 0x0605,
}

/// Firmware return codes — `enum libie_aq_err`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AqError {
    Ok,
    Eperm,
    Enoent,
    /// Bad opcode.
    Esrch,
    Eio,
    Eagain,
    Enomem,
    Eacces,
    Ebusy,
    Eexist,
    Einval,
    Enospc,
    Enosys,
    /// Not allowed in the device's current mode.
    Emode,
    Enosec,
    Ebadsig,
    Esvn,
    Ebadman,
    Ebadbuf,
    /// A code this driver does not name.
    Other(u16),
}

impl AqError {
    /// Decode a `retval` field.
    pub const fn from_retval(v: u16) -> Self {
        match v {
            0 => AqError::Ok,
            1 => AqError::Eperm,
            2 => AqError::Enoent,
            3 => AqError::Esrch,
            5 => AqError::Eio,
            8 => AqError::Eagain,
            9 => AqError::Enomem,
            10 => AqError::Eacces,
            12 => AqError::Ebusy,
            13 => AqError::Eexist,
            14 => AqError::Einval,
            16 => AqError::Enospc,
            17 => AqError::Enosys,
            21 => AqError::Emode,
            24 => AqError::Enosec,
            25 => AqError::Ebadsig,
            26 => AqError::Esvn,
            27 => AqError::Ebadman,
            28 => AqError::Ebadbuf,
            other => AqError::Other(other),
        }
    }

    /// `true` for `LIBIE_AQ_RC_OK`.
    pub const fn is_ok(self) -> bool {
        matches!(self, AqError::Ok)
    }
}

// ── Ring geometry ───────────────────────────────────────────────────

/// ATQ / ARQ descriptor count. Linux defaults to 32 for the PF
/// (`I40E_AQ_LEN`); the field is 10 bits so anything up to 1023 is
/// legal.
pub const AQ_RING_LEN: u16 = 32;
/// Bytes in one AQ descriptor ring.
pub const AQ_RING_BYTES: usize = AQ_RING_LEN as usize * core::mem::size_of::<AqDesc>();
/// Per-descriptor data-buffer size. Linux uses 4096
/// (`I40E_AQ_BUF_SZ`); every command here needs far less, but the
/// ARQ buffers must be able to hold whatever event firmware posts.
pub const AQ_BUF_BYTES: usize = 4096;
/// `I40E_ADMINQ_DESC_ALIGNMENT` — the ring base must be 4 KiB
/// aligned.
pub const AQ_RING_ALIGN: usize = 4096;

/// `I40E_ASQ_CMD_TIMEOUT` is 250 ms in Linux. Same budget here.
pub const AQ_CMD_TIMEOUT_MS: u64 = 250;
/// Upper bound on waiting out a global reset. Linux computes this
/// from `GLGEN_RSTCTL.GRSTDEL` and caps it at ~16 s.
pub const GLOBAL_RESET_MAX_MS: u64 = 16_000;
/// Budget for `GLNVM_ULD` to report core + global done. Linux polls
/// `I40E_PF_RESET_WAIT_COUNT` (200) times at ~10 ms.
pub const NVM_READY_MAX_MS: u64 = 2_000;
/// Budget for `PFGEN_CTRL.PFSWR` to self-clear.
pub const PF_RESET_MAX_MS: u64 = 1_000;

// ── Link status ─────────────────────────────────────────────────────

/// Negotiated link speed, decoded from the `link_speed` byte of a
/// `get_link_status` response. The byte is a one-hot bitmask, not an
/// ordinal — `enum i40e_aq_link_speed`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkSpeed {
    Unknown,
    Speed100Mb,
    Speed1Gb,
    Speed2_5Gb,
    Speed5Gb,
    Speed10Gb,
    Speed20Gb,
    Speed25Gb,
    Speed40Gb,
}

// `I40E_LINK_SPEED_*_SHIFT` from `i40e_adminq_cmd.h`.
const LINK_SPEED_2_5GB_BIT: u8 = 1 << 0;
const LINK_SPEED_100MB_BIT: u8 = 1 << 1;
const LINK_SPEED_1000MB_BIT: u8 = 1 << 2;
const LINK_SPEED_10GB_BIT: u8 = 1 << 3;
const LINK_SPEED_40GB_BIT: u8 = 1 << 4;
const LINK_SPEED_20GB_BIT: u8 = 1 << 5;
const LINK_SPEED_25GB_BIT: u8 = 1 << 6;
const LINK_SPEED_5GB_BIT: u8 = 1 << 7;

impl LinkSpeed {
    /// Decode the one-hot `link_speed` byte. Highest set bit wins if
    /// firmware ever reports more than one.
    pub const fn from_byte(b: u8) -> Self {
        if b & LINK_SPEED_40GB_BIT != 0 {
            LinkSpeed::Speed40Gb
        } else if b & LINK_SPEED_25GB_BIT != 0 {
            LinkSpeed::Speed25Gb
        } else if b & LINK_SPEED_20GB_BIT != 0 {
            LinkSpeed::Speed20Gb
        } else if b & LINK_SPEED_10GB_BIT != 0 {
            LinkSpeed::Speed10Gb
        } else if b & LINK_SPEED_5GB_BIT != 0 {
            LinkSpeed::Speed5Gb
        } else if b & LINK_SPEED_2_5GB_BIT != 0 {
            LinkSpeed::Speed2_5Gb
        } else if b & LINK_SPEED_1000MB_BIT != 0 {
            LinkSpeed::Speed1Gb
        } else if b & LINK_SPEED_100MB_BIT != 0 {
            LinkSpeed::Speed100Mb
        } else {
            LinkSpeed::Unknown
        }
    }

    /// Short label for the boot transcript.
    pub const fn label(self) -> &'static str {
        match self {
            LinkSpeed::Unknown => "unknown",
            LinkSpeed::Speed100Mb => "100M",
            LinkSpeed::Speed1Gb => "1G",
            LinkSpeed::Speed2_5Gb => "2.5G",
            LinkSpeed::Speed5Gb => "5G",
            LinkSpeed::Speed10Gb => "10G",
            LinkSpeed::Speed20Gb => "20G",
            LinkSpeed::Speed25Gb => "25G",
            LinkSpeed::Speed40Gb => "40G",
        }
    }
}

/// `I40E_AQ_LINK_UP` in the `link_info` byte.
pub const LINK_INFO_LINK_UP: u8 = 0x01;
/// `I40E_AQ_LSE_ENABLE` — ask firmware to post link-status events on
/// the ARQ from now on. Reporting is one-shot: firmware disarms it
/// after each event, so every `get_link_status` has to re-arm.
pub const AQ_LSE_ENABLE: u8 = 0x3;
/// `I40E_AQ_LSE_DISABLE`.
pub const AQ_LSE_DISABLE: u8 = 0x2;
/// `I40E_AQ_LSE_IS_ENABLED` — set in a *response*'s `command_flags`
/// when event reporting is currently armed.
pub const AQ_LSE_IS_ENABLED: u16 = 0x1;

/// `I40E_AQ_MEDIA_AVAILABLE` — a transceiver is present. On an SFP+
/// port with no module plugged this is clear even though the PF is
/// healthy, so it is reported separately from link state.
pub const LINK_INFO_MEDIA_AVAILABLE: u8 = 0x40;

/// Decoded `get_link_status` (0x0607) response.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkStatus {
    pub link_up: bool,
    pub media_available: bool,
    /// Firmware will post a link-status event on the ARQ.
    pub lse_enabled: bool,
    pub phy_type: u8,
    pub speed_raw: u8,
    pub max_frame_size: u16,
}

impl LinkStatus {
    /// Decode the 16-byte `params` of a completed `get_link_status`
    /// descriptor. Field order is `struct i40e_aqc_get_link_status`:
    /// `command_flags:u16`, `phy_type:u8`, `link_speed:u8`,
    /// `link_info:u8`, `an_info:u8`, `ext_info:u8`, `loopback:u8`,
    /// `max_frame_size:u16`, `config:u8`, …
    pub const fn parse(params: &[u8; 16]) -> Self {
        let link_info = params[4];
        let command_flags = u16::from_le_bytes([params[0], params[1]]);
        Self {
            link_up: link_info & LINK_INFO_LINK_UP != 0,
            media_available: link_info & LINK_INFO_MEDIA_AVAILABLE != 0,
            lse_enabled: command_flags & AQ_LSE_IS_ENABLED != 0,
            phy_type: params[2],
            speed_raw: params[3],
            max_frame_size: u16::from_le_bytes([params[8], params[9]]),
        }
    }

    /// Negotiated speed.
    pub const fn speed(&self) -> LinkSpeed {
        LinkSpeed::from_byte(self.speed_raw)
    }

    /// Pack into one word so the live state can live in an atomic
    /// that `Interface::link_up` can read from `&self`.
    pub const fn encode(&self) -> u64 {
        (self.link_up as u64)
            | ((self.media_available as u64) << 1)
            | ((self.lse_enabled as u64) << 2)
            | ((self.speed_raw as u64) << 8)
            | ((self.phy_type as u64) << 16)
            | ((self.max_frame_size as u64) << 32)
    }

    /// Inverse of [`Self::encode`].
    pub const fn decode(v: u64) -> Self {
        Self {
            link_up: v & 1 != 0,
            media_available: (v >> 1) & 1 != 0,
            lse_enabled: (v >> 2) & 1 != 0,
            speed_raw: ((v >> 8) & 0xFF) as u8,
            phy_type: ((v >> 16) & 0xFF) as u8,
            max_frame_size: ((v >> 32) & 0xFFFF) as u16,
        }
    }
}

/// Decoded `get_version` (0x0001) response — `struct
/// libie_aqc_get_ver`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FirmwareVersion {
    pub rom_version: u32,
    pub fw_build: u32,
    pub fw_major: u8,
    pub fw_minor: u8,
    pub api_major: u8,
    pub api_minor: u8,
}

impl FirmwareVersion {
    /// Decode the 16-byte `params` of a completed `get_version`
    /// descriptor.
    pub const fn parse(params: &[u8; 16]) -> Self {
        Self {
            rom_version: u32::from_le_bytes([params[0], params[1], params[2], params[3]]),
            fw_build: u32::from_le_bytes([params[4], params[5], params[6], params[7]]),
            fw_major: params[9],
            fw_minor: params[10],
            api_major: params[13],
            api_minor: params[14],
        }
    }
}

/// `I40E_AQC_LAN_ADDR_VALID` in the `mac_address_read` response
/// `command_flags`.
pub const MAC_ADDR_LAN_VALID: u16 = 0x10;
/// `I40E_AQC_PORT_ADDR_VALID`.
pub const MAC_ADDR_PORT_VALID: u16 = 0x40;

/// `struct i40e_aqc_mac_address_read_data` — the 24-byte buffer the
/// firmware DMAs back for `mac_address_read`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MacAddresses {
    pub pf_lan: [u8; 6],
    pub pf_san: [u8; 6],
    pub port: [u8; 6],
    pub pf_wol: [u8; 6],
}

impl MacAddresses {
    /// Decode the response buffer. Returns `None` if it is short.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 24 {
            return None;
        }
        let mut out = Self::default();
        out.pf_lan.copy_from_slice(&buf[0..6]);
        out.pf_san.copy_from_slice(&buf[6..12]);
        out.port.copy_from_slice(&buf[12..18]);
        out.pf_wol.copy_from_slice(&buf[18..24]);
        Some(out)
    }
}

/// `true` iff `mac` is one of the invalid sentinels.
pub const fn mac_is_invalid(mac: [u8; 6]) -> bool {
    let mut all_zero = true;
    let mut all_ff = true;
    let mut i = 0;
    while i < 6 {
        if mac[i] != 0x00 {
            all_zero = false;
        }
        if mac[i] != 0xFF {
            all_ff = false;
        }
        i += 1;
    }
    all_zero || all_ff
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum I40eError {
    BarMapFailed,
    /// BAR0 was mapped but too small to hold the CSR space the AQ
    /// registers live in.
    BarTooSmall,
    NoMemory,
    /// A global reset never reached steady state.
    GlobalResetTimeout,
    /// `GLNVM_ULD` never reported core + global done.
    NvmNotReady,
    /// `PFGEN_CTRL.PFSWR` never self-cleared.
    PfResetTimeout,
    /// An ATQ / ARQ base register read back a value we did not write.
    AdminQueueConfig,
    /// A posted command never got its `DD` bit back.
    AdminQueueTimeout,
    /// Firmware completed the command with a non-OK `retval`.
    AdminQueueError(AqError),
    /// The device reported an all-zero / all-FF MAC.
    BadMacAddress,
    /// The HMC capability registers read back as absent.
    HmcUnavailable,
    /// More queues were requested than this function can back.
    HmcTooManyQueues,
    /// The device reports a context size the packing tables were not
    /// written against, so every field would land at the wrong
    /// offset.
    HmcUnexpectedObjectSize,
    /// A queue index outside the configured range.
    BadQueueIndex,
    /// `get_switch_config` returned something undecodable.
    BadSwitchConfig,
    /// The switch reported no single PF VSI to attach to.
    NoMainVsi,
    /// `get_vsi_parameters` returned a short or undecodable context.
    BadVsiParams,
    /// Firmware refused a MAC filter — typically out of filter
    /// resources.
    MacFilterRejected,
    /// `QTX_ENA.QENA_STAT` never followed the request.
    TxQueueEnableTimeout,
    /// `QRX_ENA.QENA_STAT` never followed the request.
    RxQueueEnableTimeout,
    /// `PFLAN_QALLOC` reported an empty queue range for this PF.
    NoQueuesAllocated,
    /// The main VSI does not start at queue 0, or uses non-contiguous
    /// queue mapping — either way this driver's single-queue
    /// assumption does not hold for it.
    UnexpectedVsiQueueMap,
    /// Frame was empty or larger than one descriptor buffer.
    FrameTooLong,
    /// No free TX descriptor.
    TxRingFull,
    /// The device's head never advanced past the posted descriptor.
    TxTimeout,
}

// ── Live driver state ───────────────────────────────────────────────

/// A probed 700-series PF, brought up far enough to talk to its
/// firmware.
pub struct I40eNic {
    csr: MmioRegion,
    /// ATQ descriptor ring.
    atq: DmaBuffer,
    /// One data buffer per ATQ slot, for indirect commands.
    atq_bufs: alloc::vec::Vec<DmaBuffer>,
    /// ARQ descriptor ring.
    arq: DmaBuffer,
    /// One data buffer per ARQ slot.
    arq_bufs: alloc::vec::Vec<DmaBuffer>,
    /// Next ATQ slot to post into.
    atq_next: IrqSafeSpinLock<u16>,
    /// PCI device id, for diagnostics.
    pub device_id: u16,
    /// Physical port this PF drives (`PFGEN_PORTNUM`).
    pub port_num: u8,
    /// Firmware / API versions from `get_version`.
    pub fw: FirmwareVersion,
    /// The port's LAN MAC from `mac_address_read`.
    pub mac: [u8; 6],
    /// Live link state, as [`LinkStatus::encode`].
    ///
    /// An atomic rather than a plain field because the ARQ pump
    /// writes it while `Interface::link_up` reads it through `&self`,
    /// and because a cached snapshot taken at bring-up reports a
    /// cable plugged in afterwards as still down forever.
    link_state: AtomicU64,
    /// Next ARQ descriptor to inspect.
    arq_ntc: IrqSafeSpinLock<u16>,
    /// PF number within the device (`PF_FUNC_RID`).
    pub pf_id: u8,
    /// First absolute LAN queue assigned to this PF
    /// (`PFLAN_QALLOC.FIRSTQ`).
    pub base_queue: u16,
    /// Switch element id of the PF's main VSI.
    pub vsi_seid: u16,
    /// The main VSI's context as read at bring-up.
    pub vsi: vsi::VsiParams,
    /// LAN HMC backing store for the queue contexts.
    hmc: hmc::LanHmc,
    /// The single configured queue pair. Guarded because `transmit`
    /// and `receive` both advance ring indices.
    queue: IrqSafeSpinLock<ring::QueuePair>,

    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

// SAFETY: every interior-mutable field (`atq_next`, `queue`, the two
// IPC ring slots) is guarded by an `IrqSafeSpinLock`. The DMA buffers
// and the MMIO region describe identity-mapped physical ranges this
// PF owns exclusively, and the remaining fields are plain data
// written once during bring-up.
unsafe impl Send for I40eNic {}
// SAFETY: as above — every mutating path takes a lock, so concurrent
// `&I40eNic` access from several CPUs is serialized.
unsafe impl Sync for I40eNic {}

impl core::fmt::Debug for I40eNic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("I40eNic")
            .field("device_id", &self.device_id)
            .field("port_num", &self.port_num)
            .field("fw", &self.fw)
            .field("mac", &self.mac)
            .field("link", &self.link_status())
            .finish_non_exhaustive()
    }
}

impl I40eNic {
    /// Map BAR0, reset the PF, stand up the Admin Queue, and run the
    /// firmware handshake.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 and config space exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, I40eError> {
        // SAFETY: forwarded — caller owns BAR0.
        let csr = unsafe { map_bar(device, I40E_BAR_CSR) }.map_err(|_| I40eError::BarMapFailed)?;
        // Every register this driver touches lives below 0x1C_0500;
        // a BAR that cannot cover `PFGEN_PORTNUM` is not a 700-series
        // CSR window.
        if csr.len < REG_PFGEN_PORTNUM + 4 {
            return Err(I40eError::BarTooSmall);
        }

        // SAFETY: `csr` is the mapped CSR window and every offset is
        // bounds-checked above.
        unsafe { Self::pf_reset(&csr)? };

        // SAFETY: same.
        let port_num = (unsafe { csr.read32(REG_PFGEN_PORTNUM) } & PFGEN_PORTNUM_MASK) as u8;

        // PF number. With ARI enabled the function number is the full
        // low byte of `PF_FUNC_RID`; without it, only the low three
        // bits. The X710 is multi-function, so getting this wrong
        // points `GLHMC_LAN*BASE(pf)` at another port's FPM.
        // SAFETY: same.
        let (capsup, func_rid) =
            unsafe { (csr.read32(REG_GLPCI_CAPSUP), csr.read32(REG_PF_FUNC_RID)) };
        let pf_id = if capsup & GLPCI_CAPSUP_ARI_EN != 0 {
            (func_rid & 0xFF) as u8
        } else {
            (func_rid & 0x7) as u8
        };

        // The PF's absolute LAN queue range.
        // SAFETY: same.
        let qalloc = unsafe { csr.read32(REG_PFLAN_QALLOC) };
        let (base_queue, last_queue) = ring::decode_qalloc(qalloc);
        if last_queue < base_queue {
            return Err(I40eError::NoQueuesAllocated);
        }

        // Admin Queue rings. `alloc_coherent` hands back page-aligned
        // memory, which satisfies `I40E_ADMINQ_DESC_ALIGNMENT`.
        let atq = alloc_coherent(AQ_RING_BYTES.max(AQ_RING_ALIGN), DomainId::DRIVER_0)
            .map_err(|_| I40eError::NoMemory)?;
        let arq = alloc_coherent(AQ_RING_BYTES.max(AQ_RING_ALIGN), DomainId::DRIVER_0)
            .map_err(|_| I40eError::NoMemory)?;
        let mut atq_bufs = alloc::vec::Vec::with_capacity(AQ_RING_LEN as usize);
        let mut arq_bufs = alloc::vec::Vec::with_capacity(AQ_RING_LEN as usize);
        for _ in 0..AQ_RING_LEN {
            atq_bufs.push(
                alloc_coherent(AQ_BUF_BYTES, DomainId::DRIVER_0)
                    .map_err(|_| I40eError::NoMemory)?,
            );
            arq_bufs.push(
                alloc_coherent(AQ_BUF_BYTES, DomainId::DRIVER_0)
                    .map_err(|_| I40eError::NoMemory)?,
            );
        }

        // Zero both rings before firmware can look at them.
        for i in 0..AQ_RING_LEN as usize {
            // SAFETY: `atq` / `arq` are identity-mapped DMA pages of
            // at least `AQ_RING_BYTES`; `i < AQ_RING_LEN`.
            unsafe {
                write_desc(&atq, i, AqDesc::default());
                write_desc(&arq, i, AqDesc::default());
            }
        }

        // The ARQ descriptors are pre-armed with their buffers so
        // firmware has somewhere to put events.
        for (i, buf) in arq_bufs.iter().enumerate() {
            let phys = buf.dma_addr().raw();
            let mut d = AqDesc {
                flags: AQ_FLAG_BUF | AQ_FLAG_LB,
                datalen: AQ_BUF_BYTES as u16,
                ..AqDesc::default()
            };
            set_desc_buf_addr(&mut d, phys);
            // SAFETY: as above.
            unsafe { write_desc(&arq, i, d) };
        }

        // SAFETY: `csr` is the mapped CSR window; the ring physical
        // addresses come from DMA allocations owned by this PF.
        unsafe {
            Self::config_asq_regs(&csr, atq.dma_addr().raw())?;
            Self::config_arq_regs(&csr, arq.dma_addr().raw())?;
        }

        // The LAN HMC has to exist before any queue context can be
        // written. Linux builds it *after* the Admin Queue only
        // because it sizes the object counts from `get_capabilities`,
        // which is an AQ command; this driver pins the count at
        // `NUM_QUEUE_PAIRS` and reads the rest straight out of the
        // `GLHMC_*` capability registers, so it has no such
        // dependency. Those registers are CORER-reset and the
        // `PFHMC_SD*` block is PFR-reset, both of which the reset
        // above already settled.
        // SAFETY: `csr` is the mapped CSR window.
        let hmc = unsafe { hmc::LanHmc::bring_up(&csr, pf_id, NUM_QUEUE_PAIRS, NUM_QUEUE_PAIRS)? };
        let queue = ring::QueuePair::alloc(0)?;

        let mut nic = Self {
            csr,
            atq,
            atq_bufs,
            arq,
            arq_bufs,
            atq_next: IrqSafeSpinLock::new(0),
            device_id: device.id.device,
            port_num,
            fw: FirmwareVersion::default(),
            mac: [0; 6],
            link_state: AtomicU64::new(0),
            arq_ntc: IrqSafeSpinLock::new(0),
            pf_id,
            base_queue,
            vsi_seid: 0,
            vsi: vsi::VsiParams::default(),
            hmc,
            queue: IrqSafeSpinLock::new(queue),
            rx_ipc_ring: IrqSafeSpinLock::new(None),
            tx_ipc_ring: IrqSafeSpinLock::new(None),
        };

        nic.fw = nic.aq_get_version()?;
        // Announce ourselves. Firmware tolerates this failing on some
        // NVM revisions, so a non-OK retval is logged, not fatal.
        let _ = nic.aq_send_driver_version();
        // Take the port back from the option ROM. `Esrch` ("bad
        // opcode") is the documented answer on parts whose firmware
        // predates the command; treat only that as benign.
        match nic.aq_clear_pxe_mode() {
            Ok(()) | Err(I40eError::AdminQueueError(AqError::Esrch)) => {}
            Err(e) => return Err(e),
        }
        nic.mac = nic.aq_read_mac_address()?;
        if mac_is_invalid(nic.mac) {
            return Err(I40eError::BadMacAddress);
        }

        // Find the PF's main VSI. Firmware built it during device
        // init, so this reads the existing element rather than
        // creating one.
        let switch = nic.aq_get_switch_config()?;
        let main_vsi = switch.main_vsi().ok_or(I40eError::NoMainVsi)?;
        nic.vsi_seid = main_vsi.seid;
        nic.vsi = nic.aq_get_vsi_params(main_vsi.seid)?;

        // Everything below drives PF-relative queue 0. That is the
        // main VSI's first queue on a freshly reset PF, but it is the
        // VSI context that says so — refuse rather than quietly drive
        // someone else's queue if this device disagrees.
        if !nic.vsi.is_contiguous() || nic.vsi.queue_mapping_0 != 0 {
            return Err(I40eError::UnexpectedVsiQueueMap);
        }

        // Install the queue contexts and start the queues.
        // SAFETY: `nic.csr` is this PF's mapped CSR window and the
        // HMC backing page is published.
        unsafe {
            let q = nic.queue.lock();
            q.configure(&nic.csr, &nic.hmc, 0, nic.pf_id, nic.vsi.qs_handle_0)?;
            q.enable(&nic.csr, nic.base_queue)?;
        }

        // Without these the VSI drops everything: a perfect match on
        // our own address, plus broadcast for ARP.
        nic.aq_add_default_mac_filters(nic.vsi_seid, nic.mac)?;

        // Ask the PHY to bring the link up. On an empty SFP+ cage
        // this succeeds and the link still stays down, which is why
        // link state is reported separately from bring-up success.
        let _ = nic.aq_set_link_restart_an(true);
        // Seeds the atomic and arms LSE reporting; from here the ARQ
        // pump keeps both current.
        nic.refresh_link_status()?;

        Ok(nic)
    }

    /// Transmit one frame on queue 0.
    pub fn transmit(&self, frame: &[u8]) -> Result<(), I40eError> {
        let mut q = self.queue.lock();
        // SAFETY: `self.csr` is this PF's mapped CSR window, and the
        // queue pair was configured and enabled during bring-up.
        unsafe { q.transmit(&self.csr, frame) }
    }

    /// Pop one received frame from queue 0, if any.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        let mut q = self.queue.lock();
        // SAFETY: as above.
        unsafe { q.receive(&self.csr) }
    }

    /// `i40e_pf_reset`: wait out any global reset, wait for the NVM
    /// to report ready, then pulse `PFGEN_CTRL.PFSWR`.
    ///
    /// # Safety
    /// `csr` must be this PF's mapped BAR0 and cover every offset
    /// touched here.
    unsafe fn pf_reset(csr: &MmioRegion) -> Result<(), I40eError> {
        // Linux derives the budget from `GRSTDEL` (100 ms units,
        // times 20 for its 100 ms poll). We read the same field so
        // the wait scales with the part, but cap it at the same
        // ~16 s ceiling.
        // SAFETY: caller-asserted mapped CSR window.
        let grstdel = unsafe { csr.read32(REG_GLGEN_RSTCTL) } & GLGEN_RSTCTL_GRSTDEL_MASK;
        let global_budget_ms = ((grstdel as u64) * 100 * 2).clamp(100, GLOBAL_RESET_MAX_MS);

        let global_idle = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { csr.read32(REG_GLGEN_RSTAT) } & GLGEN_RSTAT_DEVSTATE_MASK == 0,
            narf_time::Deadline::after_ms(global_budget_ms),
        );
        if !global_idle {
            return Err(I40eError::GlobalResetTimeout);
        }

        let nvm_ready = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { csr.read32(REG_GLNVM_ULD) } & GLNVM_ULD_READY == GLNVM_ULD_READY,
            narf_time::Deadline::after_ms(NVM_READY_MAX_MS),
        );
        if !nvm_ready {
            return Err(I40eError::NvmNotReady);
        }

        // SAFETY: same.
        let ctrl = unsafe { csr.read32(REG_PFGEN_CTRL) };
        // SAFETY: same; `PFGEN_CTRL` is a writable control register.
        unsafe { csr.write32(REG_PFGEN_CTRL, ctrl | PFGEN_CTRL_PFSWR) };
        compiler_fence(Ordering::SeqCst);

        let cleared = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: same.
                let c = unsafe { csr.read32(REG_PFGEN_CTRL) };
                if c & PFGEN_CTRL_PFSWR == 0 {
                    return true;
                }
                // A global reset starting underneath us supersedes
                // the PF reset — Linux breaks out of the loop the
                // same way.
                // SAFETY: same.
                let rstat = unsafe { csr.read32(REG_GLGEN_RSTAT) };
                rstat & GLGEN_RSTAT_DEVSTATE_MASK != 0
            },
            narf_time::Deadline::after_ms(PF_RESET_MAX_MS),
        );
        if !cleared {
            return Err(I40eError::PfResetTimeout);
        }
        Ok(())
    }

    /// `i40e_config_asq_regs`.
    ///
    /// # Safety
    /// `csr` must be this PF's mapped BAR0; `ring_phys` must be the
    /// 4 KiB-aligned physical base of an `AQ_RING_LEN`-entry ring.
    unsafe fn config_asq_regs(csr: &MmioRegion, ring_phys: u64) -> Result<(), I40eError> {
        // SAFETY: caller-asserted.
        unsafe {
            csr.write32(REG_PF_ATQH, 0);
            csr.write32(REG_PF_ATQT, 0);
            csr.write32(REG_PF_ATQLEN, AQ_RING_LEN as u32 | AQLEN_ENABLE);
            csr.write32(REG_PF_ATQBAL, ring_phys as u32);
            csr.write32(REG_PF_ATQBAH, (ring_phys >> 32) as u32);
        }
        compiler_fence(Ordering::SeqCst);
        // Read one register back: if the low base doesn't stick, the
        // CSR window isn't really ours.
        // SAFETY: same.
        if unsafe { csr.read32(REG_PF_ATQBAL) } != ring_phys as u32 {
            return Err(I40eError::AdminQueueConfig);
        }
        Ok(())
    }

    /// `i40e_config_arq_regs`. Unlike the ATQ, the tail is advanced
    /// to the last slot so firmware sees every pre-armed buffer.
    ///
    /// # Safety
    /// As [`Self::config_asq_regs`].
    unsafe fn config_arq_regs(csr: &MmioRegion, ring_phys: u64) -> Result<(), I40eError> {
        // SAFETY: caller-asserted.
        unsafe {
            csr.write32(REG_PF_ARQH, 0);
            csr.write32(REG_PF_ARQT, 0);
            csr.write32(REG_PF_ARQLEN, AQ_RING_LEN as u32 | AQLEN_ENABLE);
            csr.write32(REG_PF_ARQBAL, ring_phys as u32);
            csr.write32(REG_PF_ARQBAH, (ring_phys >> 32) as u32);
            csr.write32(REG_PF_ARQT, (AQ_RING_LEN - 1) as u32);
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        if unsafe { csr.read32(REG_PF_ARQBAL) } != ring_phys as u32 {
            return Err(I40eError::AdminQueueConfig);
        }
        Ok(())
    }

    /// Post one descriptor on the ATQ and wait for firmware to write
    /// it back. `buf_in` is copied into the slot's data buffer before
    /// the doorbell when the command carries data outbound.
    ///
    /// Returns the written-back descriptor. The caller reads any
    /// response buffer with [`Self::atq_buf_bytes`].
    fn aq_send(
        &self,
        opcode: AqOpcode,
        params: [u8; 16],
        buf_in: Option<&[u8]>,
        buf_len: u16,
    ) -> Result<(usize, AqDesc), I40eError> {
        // The lock is held for the *whole* transaction — slot claim,
        // descriptor write, doorbell, and the wait for DD — not just
        // the slot claim. Two overlapping commands would each publish
        // their own `slot + 1` as the tail, and the later writer can
        // move the tail backwards past a descriptor firmware has not
        // fetched yet. That was latent while every AQ command came
        // from the single-threaded bring-up path; the ARQ pump now
        // issues `get_link_status` at arbitrary times, so it is real.
        //
        // Holding an `IrqSafeSpinLock` across the spin is sound here:
        // `responsive_spin_until` is a pure spin loop that never
        // parks, which is the `block_on_spin` case AGENTS.md allows.
        let mut slot_g = self.atq_next.lock();
        let slot = *slot_g as usize;
        *slot_g = (*slot_g + 1) % AQ_RING_LEN;

        let mut desc = AqDesc {
            flags: AQ_FLAG_SI,
            opcode: opcode as u16,
            datalen: 0,
            retval: 0,
            cookie_high: 0,
            cookie_low: 0,
            params,
        };

        if buf_len > 0 {
            let phys = self.atq_bufs[slot].dma_addr().raw();
            desc.flags |= AQ_FLAG_BUF;
            if buf_len > AQ_LARGE_BUF {
                desc.flags |= AQ_FLAG_LB;
            }
            desc.datalen = buf_len;
            if let Some(src) = buf_in {
                desc.flags |= AQ_FLAG_RD;
                let n = src.len().min(AQ_BUF_BYTES);
                for (i, b) in src.iter().take(n).enumerate() {
                    // SAFETY: `atq_bufs[slot]` is an identity-mapped
                    // `AQ_BUF_BYTES` DMA buffer and `i < n <= AQ_BUF_BYTES`.
                    unsafe {
                        core::ptr::write_volatile(
                            self.atq_bufs[slot].cpu_mut_ptr_at::<u8>(i as u64),
                            *b,
                        )
                    };
                }
            }
            set_desc_buf_addr(&mut desc, phys);
        }

        // SAFETY: `self.atq` is this PF's identity-mapped ring of
        // `AQ_RING_LEN` descriptors and `slot < AQ_RING_LEN`.
        unsafe { write_desc(&self.atq, slot, desc) };
        compiler_fence(Ordering::SeqCst);

        // Doorbell: tail = the slot after the one we just filled.
        let tail = ((slot + 1) % AQ_RING_LEN as usize) as u32;
        // SAFETY: `self.csr` is this PF's mapped CSR window.
        unsafe { self.csr.write32(REG_PF_ATQT, tail) };
        compiler_fence(Ordering::SeqCst);

        let done = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: as above — a volatile read of a descriptor
                // firmware writes back in place.
                let d = unsafe { read_desc(&self.atq, slot) };
                d.flags & AQ_FLAG_DD != 0
            },
            narf_time::Deadline::after_ms(AQ_CMD_TIMEOUT_MS),
        );
        if !done {
            return Err(I40eError::AdminQueueTimeout);
        }

        // SAFETY: as above.
        let wb = unsafe { read_desc(&self.atq, slot) };
        drop(slot_g);
        let rc = AqError::from_retval(wb.retval);
        if !rc.is_ok() {
            return Err(I40eError::AdminQueueError(rc));
        }
        Ok((slot, wb))
    }

    /// Copy `len` bytes out of the ATQ slot's data buffer — where
    /// firmware leaves an indirect command's response.
    fn atq_buf_bytes(&self, slot: usize, len: usize) -> alloc::vec::Vec<u8> {
        let n = len.min(AQ_BUF_BYTES);
        let mut out = alloc::vec::Vec::with_capacity(n);
        for i in 0..n {
            // SAFETY: `atq_bufs[slot]` is an identity-mapped
            // `AQ_BUF_BYTES` DMA buffer and `i < n <= AQ_BUF_BYTES`.
            out.push(unsafe {
                core::ptr::read_volatile(self.atq_bufs[slot].cpu_ptr_at::<u8>(i as u64))
            });
        }
        out
    }

    /// `get_version` (0x0001) — direct, response lands in `params`.
    pub fn aq_get_version(&self) -> Result<FirmwareVersion, I40eError> {
        let (_slot, wb) = self.aq_send(AqOpcode::GetVersion, [0; 16], None, 0)?;
        Ok(FirmwareVersion::parse(&wb.params))
    }

    /// `driver_version` (0x0002) — indirect; the version string goes
    /// in the data buffer, the numeric quad in `params`.
    pub fn aq_send_driver_version(&self) -> Result<(), I40eError> {
        let mut params = [0u8; 16];
        params[0] = DRIVER_VERSION_MAJOR;
        params[1] = DRIVER_VERSION_MINOR;
        params[2] = DRIVER_VERSION_BUILD;
        params[3] = DRIVER_VERSION_SUBBUILD;
        let name = DRIVER_VERSION_STRING.as_bytes();
        self.aq_send(
            AqOpcode::DriverVersion,
            params,
            Some(name),
            name.len() as u16,
        )?;
        Ok(())
    }

    /// `clear_pxe_mode` (0x0110). `rx_cnt = 2` is what Linux sends.
    pub fn aq_clear_pxe_mode(&self) -> Result<(), I40eError> {
        let mut params = [0u8; 16];
        params[0] = 0x2; // struct i40e_aqc_clear_pxe.rx_cnt
        self.aq_send(AqOpcode::ClearPxeMode, params, None, 0)?;
        Ok(())
    }

    /// `mac_address_read` (0x0107) — indirect. Returns the PF LAN
    /// MAC, which is the address the port transmits from.
    pub fn aq_read_mac_address(&self) -> Result<[u8; 6], I40eError> {
        const RESP_LEN: u16 = 24; // struct i40e_aqc_mac_address_read_data
        let (slot, wb) = self.aq_send(AqOpcode::MacAddressRead, [0; 16], None, RESP_LEN)?;
        let flags = u16::from_le_bytes([wb.params[0], wb.params[1]]);
        if flags & MAC_ADDR_LAN_VALID == 0 {
            return Err(I40eError::BadMacAddress);
        }
        let buf = self.atq_buf_bytes(slot, RESP_LEN as usize);
        MacAddresses::parse(&buf)
            .map(|m| m.pf_lan)
            .ok_or(I40eError::BadMacAddress)
    }

    /// `get_link_status` (0x0607) — direct.
    pub fn aq_get_link_status(&self) -> Result<LinkStatus, I40eError> {
        let mut params = [0u8; 16];
        // Ask firmware to post link-status events on the ARQ. This is
        // not sticky — firmware disarms reporting after each event,
        // so the ARQ pump re-issues this command on every one.
        params[0] = AQ_LSE_ENABLE;
        let (_slot, wb) = self.aq_send(AqOpcode::GetLinkStatus, params, None, 0)?;
        Ok(LinkStatus::parse(&wb.params))
    }

    /// `queue_shutdown` (0x0003) — tell firmware the driver is going
    /// away, so it can stop posting ARQ events into rings we are
    /// about to free.
    pub fn aq_queue_shutdown(&self) -> Result<(), I40eError> {
        let mut params = [0u8; 16];
        params[0] = 0x1; // I40E_AQ_DRIVER_UNLOADING
        self.aq_send(AqOpcode::QueueShutdown, params, None, 0)?;
        Ok(())
    }

    /// Last known link state.
    pub fn link_status(&self) -> LinkStatus {
        LinkStatus::decode(self.link_state.load(Ordering::Acquire))
    }

    /// Ask firmware for the current link state, publish it, and re-arm
    /// link-status event reporting.
    ///
    /// Takes `&self` — the state lives in an atomic, so this is the
    /// ARQ pump's normal path as well as a caller-driven refresh.
    pub fn refresh_link_status(&self) -> Result<LinkStatus, I40eError> {
        let s = self.aq_get_link_status()?;
        self.link_state.store(s.encode(), Ordering::Release);
        Ok(s)
    }

    /// `true` when the link is currently up.
    pub fn link_up(&self) -> bool {
        self.link_status().link_up
    }

    /// Pop one Admin Receive Queue event, if firmware has posted one.
    ///
    /// Mirrors `i40e_clean_arq_element`: compare the firmware-advanced
    /// head against our cursor, take the descriptor, re-arm it against
    /// the same buffer, and publish the cleaned index as the new tail.
    pub fn poll_arq_event(&self) -> Option<AqDesc> {
        let mut ntc_g = self.arq_ntc.lock();
        let ntc = *ntc_g;
        // SAFETY: `self.csr` is this PF's mapped CSR window.
        let ntu = (unsafe { self.csr.read32(REG_PF_ARQH) } & ARQH_MASK) as u16;
        if ntu == ntc || ntu >= AQ_RING_LEN {
            return None;
        }

        // SAFETY: `self.arq` is this PF's identity-mapped ARQ ring and
        // `ntc < AQ_RING_LEN`.
        let event = unsafe { read_desc(&self.arq, ntc as usize) };

        // Firmware overwrote `datalen` and the buffer address with the
        // event's, so the descriptor has to be rebuilt against the
        // slot's own buffer before it is handed back.
        let phys = self.arq_bufs[ntc as usize].dma_addr().raw();
        let mut rearmed = AqDesc {
            flags: AQ_FLAG_BUF | AQ_FLAG_LB,
            datalen: AQ_BUF_BYTES as u16,
            ..AqDesc::default()
        };
        set_desc_buf_addr(&mut rearmed, phys);
        // SAFETY: as above.
        unsafe { write_desc(&self.arq, ntc as usize, rearmed) };
        compiler_fence(Ordering::SeqCst);

        // The tail is the last descriptor handed back, so it is the
        // one just cleaned — not the next one.
        // SAFETY: `self.csr` is this PF's mapped CSR window.
        unsafe { self.csr.write32(REG_PF_ARQT, ntc as u32) };
        compiler_fence(Ordering::SeqCst);

        *ntc_g = (ntc + 1) % AQ_RING_LEN;
        Some(event)
    }

    /// Copy `len` bytes out of ARQ slot `slot`'s data buffer.
    pub fn arq_buf_bytes(&self, slot: usize, len: usize) -> alloc::vec::Vec<u8> {
        let n = len.min(AQ_BUF_BYTES);
        let mut out = alloc::vec::Vec::with_capacity(n);
        for i in 0..n {
            // SAFETY: `arq_bufs[slot]` is an identity-mapped
            // `AQ_BUF_BYTES` DMA buffer and `i < n <= AQ_BUF_BYTES`.
            out.push(unsafe {
                core::ptr::read_volatile(self.arq_bufs[slot].cpu_ptr_at::<u8>(i as u64))
            });
        }
        out
    }

    /// The port's LAN MAC.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
}

/// Driver version reported to firmware via `driver_version`. Bumping
/// this is cosmetic — firmware only logs it.
pub const DRIVER_VERSION_MAJOR: u8 = 0;
pub const DRIVER_VERSION_MINOR: u8 = 1;
pub const DRIVER_VERSION_BUILD: u8 = 0;
pub const DRIVER_VERSION_SUBBUILD: u8 = 0;
/// Version string firmware stores alongside the numeric quad.
pub const DRIVER_VERSION_STRING: &str = "narf-i40e";

/// Write descriptor `i` of `ring`.
///
/// # Safety
/// `ring` must be an identity-mapped DMA region of at least
/// `AQ_RING_BYTES`, and `i` must be less than `AQ_RING_LEN`.
unsafe fn write_desc(ring: &DmaBuffer, i: usize, d: AqDesc) {
    let off = (i * core::mem::size_of::<AqDesc>()) as u64;
    // SAFETY: caller-asserted bounds; `AqDesc` is `repr(C)` POD.
    unsafe { core::ptr::write_volatile(ring.cpu_mut_ptr_at::<AqDesc>(off), d) };
}

/// Read descriptor `i` of `ring`.
///
/// # Safety
/// As [`write_desc`].
unsafe fn read_desc(ring: &DmaBuffer, i: usize) -> AqDesc {
    let off = (i * core::mem::size_of::<AqDesc>()) as u64;
    // SAFETY: caller-asserted bounds; `AqDesc` is `repr(C)` POD.
    unsafe { core::ptr::read_volatile(ring.cpu_ptr_at::<AqDesc>(off)) }
}

/// Stamp an indirect command's buffer address into the last eight
/// bytes of `params` (`addr_high` then `addr_low`, both LE).
pub fn set_desc_buf_addr(d: &mut AqDesc, phys: u64) {
    let hi = ((phys >> 32) as u32).to_le_bytes();
    let lo = (phys as u32).to_le_bytes();
    d.params[8..12].copy_from_slice(&hi);
    d.params[12..16].copy_from_slice(&lo);
}

/// Read back the buffer address an indirect descriptor carries.
pub fn desc_buf_addr(d: &AqDesc) -> u64 {
    let hi = u32::from_le_bytes([d.params[8], d.params[9], d.params[10], d.params[11]]);
    let lo = u32::from_le_bytes([d.params[12], d.params[13], d.params[14], d.params[15]]);
    ((hi as u64) << 32) | lo as u64
}

// ── Driver-match registration ───────────────────────────────────────

/// Every probed PF. The X710 on the MS-03 is dual-port, so unlike
/// the single-controller drivers this keeps a list.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<I40eNic>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != I40E_VENDOR || !is_supported_device(device.id.device) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: probe owns the device's cfg space + BARs for the
    // duration of this call.
    let nic = match unsafe { I40eNic::bring_up(&device, &cap) } {
        Ok(n) => n,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  i40e: bring-up failed on {:04x}:{:04x}: {:?}",
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    {
        use core::fmt::Write as _;
        let link = nic.link_status();
        let _ = writeln!(
            narf_console::Writer,
            "  i40e: {} port {} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} fw={}.{} api={}.{} link={} ({}{})",
            name_for(nic.device_id),
            nic.port_num,
            nic.mac[0],
            nic.mac[1],
            nic.mac[2],
            nic.mac[3],
            nic.mac[4],
            nic.mac[5],
            nic.fw.fw_major,
            nic.fw.fw_minor,
            nic.fw.api_major,
            nic.fw.api_minor,
            if link.link_up { "up" } else { "down" },
            link.speed().label(),
            if link.media_available {
                ""
            } else {
                ", no module"
            },
        );
        let _ = writeln!(
            narf_console::Writer,
            "  i40e: pf={} vsi seid={} qs_handle={} base_q={} {} queue pair(s), HMC {} B @ {:#018x}",
            nic.pf_id,
            nic.vsi_seid,
            nic.vsi.qs_handle_0,
            nic.base_queue,
            NUM_QUEUE_PAIRS,
            nic.hmc.l2fpm_size,
            nic.hmc.backing_phys(),
        );
        if !link.lse_enabled {
            // Without event reporting the pump has nothing to drain
            // and link state would only move on a manual refresh.
            let _ = writeln!(
                narf_console::Writer,
                "  i40e: firmware did not arm link-status events; link state will not track \
                 cable changes"
            );
        }
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Hand the net stack its ends of the frame rings.
    let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();
    *nic.rx_ipc_ring.lock() = Some(rx_cons);
    *nic.tx_ipc_ring.lock() = Some(tx_prod);

    let nic = Arc::new(nic);
    let index = {
        let mut g = CONTROLLERS.lock();
        g.push(nic.clone());
        g.len() - 1
    };

    // Every PF is published under its own name. The X710 presents one
    // PF per port and the MS-03 has two, so this is the difference
    // between one usable 10G port and two.
    match interface_name(index) {
        Some(name) => {
            let auth = match narf_net::trusted_net_authority() {
                Some(a) => a.derive().ok(),
                None => None,
            };
            if let Some(auth) = auth {
                let iface = I40eNicIface {
                    name,
                    nic: nic.clone(),
                };
                if let Err(e) = narf_net::registry().register(&auth, iface) {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "  i40e: {} not registered with the net stack: {:?}",
                        name,
                        e,
                    );
                }
            }
        }
        None => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  i40e: more than {} ports probed; this one carries traffic but is not \
                 reachable from the net stack",
                INTERFACE_NAMES.len(),
            );
        }
    }

    spawn_pumps(nic, rx_prod, tx_cons);
    Ok(())
}

fn spawn_pumps(
    device: Arc<I40eNic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        i40e_rx_pump(d1, rx_prod).await;
    });
    let d2 = device.clone();
    narf_scheduler::spawn(async move {
        i40e_tx_pump(d2, tx_cons).await;
    });
    let d3 = device;
    narf_scheduler::spawn(async move {
        i40e_arq_pump(d3).await;
    });
}

/// Drain the Admin Receive Queue and keep link state current.
///
/// Firmware posts a `get_link_status` event whenever the link
/// changes — a cable plugged in, an SFP+ module seated, the peer
/// bouncing. The payload is deliberately ignored, exactly as Linux's
/// `i40e_handle_link_event` does: re-issuing the command is the
/// authoritative read *and* re-arms reporting, which firmware
/// otherwise leaves disarmed until the next request.
async fn i40e_arq_pump(device: Arc<I40eNic>) {
    loop {
        // Drain everything queued before yielding, so a burst of
        // events cannot outrun the pump.
        while let Some(event) = device.poll_arq_event() {
            if event.opcode == AqOpcode::GetLinkStatus as u16 {
                match device.refresh_link_status() {
                    Ok(link) => {
                        use core::fmt::Write as _;
                        let _ = writeln!(
                            narf_console::Writer,
                            "  i40e: link {} ({})",
                            if link.link_up { "up" } else { "down" },
                            link.speed().label(),
                        );
                    }
                    Err(e) => {
                        // Leave the cached state alone rather than
                        // guessing; the next event retries.
                        use core::fmt::Write as _;
                        let _ = writeln!(
                            narf_console::Writer,
                            "  i40e: link event refresh failed: {:?}",
                            e
                        );
                    }
                }
            }
            // Any other event is still drained — leaving it would
            // stall the ring and stop link events arriving too.
        }
        narf_scheduler::yield_now().await;
    }
}

async fn i40e_rx_pump(device: Arc<I40eNic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    loop {
        if let Some(pkt) = device.receive() {
            if let Ok(dma_buf) = alloc_coherent(pkt.len(), DomainId::DRIVER_0) {
                let mut frame = Frame::new(dma_buf, pkt.len() as u32);
                frame.payload_mut().copy_from_slice(&pkt);
                let _ = rx_prod.send(frame).await;
            }
        }
        narf_scheduler::yield_now().await;
    }
}

async fn i40e_tx_pump(device: Arc<I40eNic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload());
    }
}

/// One probed PF, as the net stack sees it.
///
/// This owns its `Arc<I40eNic>` rather than looking the controller up
/// by index. That is what makes multiple ports work at all:
/// `Interface::rx_ring` / `tx_ring` return a reference borrowed from
/// `&self`, so an interface with no storage of its own has to hand
/// back a `static` — and every instance would then share one pair of
/// rings, with the second port's frames landing in the first port's
/// queue. Borrowing straight out of the NIC gives each port its own.
#[derive(Debug)]
pub struct I40eNicIface {
    /// This port's name, from [`INTERFACE_NAMES`].
    name: &'static str,
    nic: Arc<I40eNic>,
}

impl I40eNicIface {
    /// The interface name this port registered under.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The controller behind this interface.
    pub fn nic(&self) -> &I40eNic {
        &self.nic
    }
}

impl narf_net::Interface for I40eNicIface {
    fn name(&self) -> &str {
        self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.nic.link_up()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.nic.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.nic.tx_ipc_ring
    }
}

impl crate::HwNic for I40eNicIface {
    fn name(&self) -> &'static str {
        self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.nic.link_up()
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::IntelIxgbe
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        ring::RING_LEN as usize
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        <Self as narf_net::Interface>::rx_ring(self)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Self as narf_net::Interface>::tx_ring(self)
    }
}

/// Register the i40e PCI driver — one match entry per device ID.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: I40E_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Number of PFs brought up so far.
pub fn instance_count() -> usize {
    CONTROLLERS.lock().len()
}

/// `true` once at least one PF has been probed.
pub fn is_probed() -> bool {
    !CONTROLLERS.lock().is_empty()
}

/// Run `f` against PF `index`, if it exists.
pub fn with_controller<R>(index: usize, f: impl FnOnce(&I40eNic) -> R) -> Option<R> {
    CONTROLLERS.lock().get(index).map(|a| f(a))
}

#[doc(hidden)]
/// Test-only: drop every probed PF so a smoke can assert end-state.
pub fn __reset_for_test() {
    CONTROLLERS.lock().clear();
}
