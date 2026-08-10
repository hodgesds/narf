//! e1000 / e1000e family driver — Intel 8254x and 8257x Gigabit
//! Ethernet controllers.
//!
//! Spec: Intel "PCI/PCI-X Family of Gigabit Ethernet Controllers
//! Software Developer's Manual" (8254x) §13 (Register Descriptions)
//! and §3.2 (Receive Functionality), plus the "Intel 82574L Gigabit
//! Ethernet Controller Datasheet" (8257x). The two families share
//! enough register layout that one driver covers both with a small
//! probe-time discriminator.
//!   <https://www.intel.com/content/www/us/en/sdm.html>
//!   <https://www.intel.com/content/dam/doc/manual/8254x-software-developers-manual.pdf>
//!   <https://www.intel.com/content/dam/doc/datasheet/82574l-gbe-controller-datasheet.pdf>
//!
//! Bring-up sequence: reset the device, read the MAC address from
//! RAL/RAH, allocate TX + RX descriptor rings, set link up, then
//! attach an IRQ delivery path:
//!
//!   1. Try MSI-X (PCIe 8257x parts expose it via the standard cap
//!      list — see 82574L datasheet §1.4.4 and §6).
//!   2. Fall back to legacy INTx routed through the AML `_PRT`
//!      table → IOAPIC redirection-table entry. PCI INTx is level-
//!      triggered, active-low (PCI Local Bus Spec §2.2.6); the ISR
//!      reads ICR (Interrupt Cause Read; auto-clears on read per
//!      §13.4.17) so the device deasserts the line.
//!   3. Fall back to polled completion if neither IRQ path is
//!      reachable. Polled `tx`/`rx_recv` are kept regardless so
//!      bring-up tests work in the no-IRQ environment.
//!
//! IMS (Interrupt Mask Set, §13.4.20) is programmed with the
//! standard "frame arrived / TX completed / receiver overrun" set:
//! RXT0 (RX timer expired) + TXDW (TX desc written back) + RXO
//! (receiver overrun). RXDMT0 (RX desc min threshold) is included
//! so we can refill before the ring underflows.
//!
//! Register subset (all 4-byte aligned, BAR0 + offset):
//!
//! | offset  | name | description                       |
//! |---------|------|-----------------------------------|
//! | 0x0000  | CTRL | Device Control                    |
//! | 0x0008  | STATUS| Device Status                    |
//! | 0x0014  | EERD | EEPROM Read                       |
//! | 0x00C0  | ICR  | Interrupt Cause Read (auto-clear) |
//! | 0x00D0  | IMS  | Interrupt Mask Set/Read           |
//! | 0x00D8  | IMC  | Interrupt Mask Clear              |
//! | 0x0100  | RCTL | Receive Control                   |
//! | 0x0400  | TCTL | Transmit Control                  |
//! | 0x2800  | RDBAL| RX Descriptor Base Low            |
//! | 0x2804  | RDBAH| RX Descriptor Base High           |
//! | 0x2808  | RDLEN| RX Descriptor Ring Length         |
//! | 0x2810  | RDH  | RX Descriptor Head                |
//! | 0x2818  | RDT  | RX Descriptor Tail                |
//! | 0x3800  | TDBAL| TX Descriptor Base Low            |
//! | 0x3804  | TDBAH| TX Descriptor Base High           |
//! | 0x3808  | TDLEN| TX Descriptor Ring Length         |
//! | 0x3810  | TDH  | TX Descriptor Head                |
//! | 0x3818  | TDT  | TX Descriptor Tail                |
//! | 0x5400  | RAL  | Receive Address Low (MAC[0..4])   |
//! | 0x5404  | RAH  | Receive Address High (MAC[4..6] + valid bit) |

use core::sync::atomic::{compiler_fence, AtomicU64, Ordering};

use alloc::sync::Arc;
use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, RX_RING_N, TX_RING_N};

// ── PCI device IDs we recognise ─────────────────────────────────────
//
// The list mirrors Linux's `e1000e_pci_tbl[]` in
// `drivers/net/ethernet/intel/e1000e/netdev.c` for the SKUs that
// matter on modern Intel laptops + their docks: PCH-LPT (Haswell)
// I217/I218, PCH-SPT (Skylake-H/Sunrise Point) I219_LM/V/LM2/V2,
// PCH-CNP/CMP (Cannon/Comet Lake) LM6..LM12, PCH-ICP (Ice Lake)
// LM8/9, PCH-TGP (Tiger Lake) LM13..LM15, PCH-ADP (Alder Lake)
// LM16/17/19, PCH-RPL (Raptor Lake) LM22/23, PCH-MTP/LNP/ARL/PTP/NVL
// (Meteor / Lunar / Arrow / Panther / Nova Lake) LM18/20/21/24/25/27/29.
// All share the e1000e PHY/MAC architecture; per-PCH quirks live in
// Linux's `ich8lan.c` and are tracked in `notes/intel-e1000e-igc-audit.md`.
//
// Plus a few I210/I211 entries (handled by Linux's `igb` driver) so
// the bus probe still recognises them; full bring-up needs the
// advanced-descriptor path that igc.rs uses for I225/I226.

/// Vendor: Intel.
pub const E1000_VENDOR: u16 = 0x8086;

// 8254x / 8257x legacy + QEMU-emulated parts.
/// Classic 82540EM (`-device e1000`).
pub const E1000_DEV_82540EM: u16 = 0x100E;
/// 82545EM Gigabit.
pub const E1000_DEV_82545EM: u16 = 0x100F;
/// QEMU's `-device e1000-82544gc`.
pub const E1000_DEV_82544GC: u16 = 0x100C;
/// 82574L (used by QEMU q35 default + `-device e1000e`).
pub const E1000E_DEV_82574L: u16 = 0x10D3;

// PCH-LPT (Lynx Point — Haswell-era).
/// I217-LM, found on real Lenovo laptops (Haswell).
pub const E1000E_DEV_I217LM: u16 = 0x153A;
/// I217-V.
pub const E1000E_DEV_I217V: u16 = 0x153B;
/// I218-LM (Lynx Point LP — Haswell-ULT).
pub const E1000E_DEV_I218LM: u16 = 0x155A;
/// I218-V.
pub const E1000E_DEV_I218V: u16 = 0x1559;
/// I218-LM2 (Wildcat Point).
pub const E1000E_DEV_I218LM2: u16 = 0x15A0;
/// I218-V2.
pub const E1000E_DEV_I218V2: u16 = 0x15A1;
/// I218-LM3 (Wildcat Point).
pub const E1000E_DEV_I218LM3: u16 = 0x15A2;
/// I218-V3.
pub const E1000E_DEV_I218V3: u16 = 0x15A3;

// PCH-SPT (Sunrise Point — Skylake-H).
/// I219-LM (Sunrise Point — Skylake).
pub const E1000E_DEV_I219LM: u16 = 0x156F;
/// I219-V (Sunrise Point — Skylake).
pub const E1000E_DEV_I219V: u16 = 0x1570;
/// I219-LM2 (SPT-H).
pub const E1000E_DEV_I219LM2: u16 = 0x15B7;
/// I219-V2.
pub const E1000E_DEV_I219V2: u16 = 0x15B8;
/// I219-LM3 (Lewisburg PCH — Skylake-SP / X299).
pub const E1000E_DEV_I219LM3: u16 = 0x15B9;
/// I219-LM4 (Sunrise Point H refresh).
pub const E1000E_DEV_I219LM4: u16 = 0x15D7;
/// I219-V4.
pub const E1000E_DEV_I219V4: u16 = 0x15D8;
/// I219-LM5.
pub const E1000E_DEV_I219LM5: u16 = 0x15E3;
/// I219-V5.
pub const E1000E_DEV_I219V5: u16 = 0x15D6;

// PCH-CNP (Cannon Point — Coffee Lake / Cannon Lake).
/// I219-LM6.
pub const E1000E_DEV_I219LM6: u16 = 0x15BD;
/// I219-V6.
pub const E1000E_DEV_I219V6: u16 = 0x15BE;
/// I219-LM7.
pub const E1000E_DEV_I219LM7: u16 = 0x15BB;
/// I219-V7.
pub const E1000E_DEV_I219V7: u16 = 0x15BC;

// PCH-ICP (Ice Point — Ice Lake).
/// I219-LM8 (Ice Lake).
pub const E1000E_DEV_I219LM8: u16 = 0x15DF;
/// I219-V8.
pub const E1000E_DEV_I219V8: u16 = 0x15E0;
/// I219-LM9 (Ice Lake).
pub const E1000E_DEV_I219LM9: u16 = 0x15E1;
/// I219-V9.
pub const E1000E_DEV_I219V9: u16 = 0x15E2;

// PCH-CMP (Comet Point — Comet Lake).
/// I219-LM10.
pub const E1000E_DEV_I219LM10: u16 = 0x0D4E;
/// I219-V10.
pub const E1000E_DEV_I219V10: u16 = 0x0D4F;
/// I219-LM11.
pub const E1000E_DEV_I219LM11: u16 = 0x0D4C;
/// I219-V11.
pub const E1000E_DEV_I219V11: u16 = 0x0D4D;
/// I219-LM12.
pub const E1000E_DEV_I219LM12: u16 = 0x0D53;
/// I219-V12.
pub const E1000E_DEV_I219V12: u16 = 0x0D55;

// PCH-TGP (Tiger Point — Tiger Lake).
/// I219-LM13.
pub const E1000E_DEV_I219LM13: u16 = 0x15FB;
/// I219-V13.
pub const E1000E_DEV_I219V13: u16 = 0x15FC;
/// I219-LM14.
pub const E1000E_DEV_I219LM14: u16 = 0x15F9;
/// I219-V14.
pub const E1000E_DEV_I219V14: u16 = 0x15FA;
/// I219-LM15.
pub const E1000E_DEV_I219LM15: u16 = 0x15F4;
/// I219-V15.
pub const E1000E_DEV_I219V15: u16 = 0x15F5;

// PCH-ADP (Alder Point — Alder Lake) + PCH-RPL (Raptor Point).
/// I219-LM16 (Alder Lake).
pub const E1000E_DEV_I219LM16: u16 = 0x1A1E;
/// I219-V16.
pub const E1000E_DEV_I219V16: u16 = 0x1A1F;
/// I219-LM17.
pub const E1000E_DEV_I219LM17: u16 = 0x1A1C;
/// I219-V17.
pub const E1000E_DEV_I219V17: u16 = 0x1A1D;
/// I219-LM19 (Alder Point refresh).
pub const E1000E_DEV_I219LM19: u16 = 0x550C;
/// I219-V19.
pub const E1000E_DEV_I219V19: u16 = 0x550D;
/// I219-LM22 (Raptor Lake).
pub const E1000E_DEV_I219LM22: u16 = 0x0DC7;
/// I219-V22.
pub const E1000E_DEV_I219V22: u16 = 0x0DC8;
/// I219-LM23 (Raptor Lake).
pub const E1000E_DEV_I219LM23: u16 = 0x0DC5;
/// I219-V23.
pub const E1000E_DEV_I219V23: u16 = 0x0DC6;

// PCH-MTP (Meteor Point — Meteor Lake / Phoenix-class PCH).
/// I219-LM18 (Meteor Point — covers Phoenix HawkPoint1 LOM).
pub const E1000E_DEV_I219LM18: u16 = 0x550A;
/// I219-V18.
pub const E1000E_DEV_I219V18: u16 = 0x550B;

// PCH-LNP (Lunar Point — Lunar Lake).
/// I219-LM20.
pub const E1000E_DEV_I219LM20: u16 = 0x550E;
/// I219-V20.
pub const E1000E_DEV_I219V20: u16 = 0x550F;
/// I219-LM21.
pub const E1000E_DEV_I219LM21: u16 = 0x5510;
/// I219-V21.
pub const E1000E_DEV_I219V21: u16 = 0x5511;

// PCH-ARL (Arrow Point — Arrow Lake).
/// I219-LM24.
pub const E1000E_DEV_I219LM24: u16 = 0x57A0;
/// I219-V24.
pub const E1000E_DEV_I219V24: u16 = 0x57A1;

// PCH-PTP (Panther Point — Panther Lake).
/// I219-LM25.
pub const E1000E_DEV_I219LM25: u16 = 0x57B3;
/// I219-V25.
pub const E1000E_DEV_I219V25: u16 = 0x57B4;
/// I219-LM27.
pub const E1000E_DEV_I219LM27: u16 = 0x57B7;
/// I219-V27.
pub const E1000E_DEV_I219V27: u16 = 0x57B8;

// PCH-NVL (Nova Lake).
/// I219-LM29.
pub const E1000E_DEV_I219LM29: u16 = 0x57B9;
/// I219-V29.
pub const E1000E_DEV_I219V29: u16 = 0x57BA;

// I210 / I211 — Linux handles these via `igb`, not `e1000e`. We
// recognise the IDs here so the bus probe binds *something*; the
// bring-up sequence is a best-effort that may need follow-up if a
// real I210/I211 lands on this driver (Stage-1 follow-up tracked
// in `notes/intel-e1000e-igc-audit.md`).
/// I210 Copper.
pub const E1000_DEV_I210_COPPER: u16 = 0x1533;
/// I210 Fiber.
pub const E1000_DEV_I210_FIBER: u16 = 0x1536;
/// I210 Serdes.
pub const E1000_DEV_I210_SERDES: u16 = 0x1537;
/// I210 SGMII.
pub const E1000_DEV_I210_SGMII: u16 = 0x1538;
/// I210 Copper flashless.
pub const E1000_DEV_I210_COPPER_FLASHLESS: u16 = 0x157B;
/// I210 Serdes flashless.
pub const E1000_DEV_I210_SERDES_FLASHLESS: u16 = 0x157C;
/// I211 Copper.
pub const E1000_DEV_I211_COPPER: u16 = 0x1539;
/// 82576 (used on some Lenovo ThinkPad docks via I210 PHY).
pub const E1000_DEV_82576: u16 = 0x10C9;
/// 82576 with NS clock.
pub const E1000_DEV_82576_NS: u16 = 0x150A;
/// I350 Copper (embedded server SoC).
pub const E1000_DEV_I350_COPPER: u16 = 0x1521;

// ── Register offsets ────────────────────────────────────────────────

const REG_CTRL: u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const REG_EERD: u64 = 0x0014;
/// Interrupt Cause Read — reading this register returns the set of
/// pending causes and clears them all (8254x SDM §13.4.17). The ISR
/// reads ICR exactly once per IRQ to acknowledge the device and
/// deassert legacy INTx.
const REG_ICR: u64 = 0x00C0;
const REG_IMS: u64 = 0x00D0;
/// Interrupt Mask Clear — writing 1 to a bit disables that cause's
/// IRQ delivery (8254x SDM §13.4.22).
const REG_IMC: u64 = 0x00D8;
const REG_RCTL: u64 = 0x0100;
const REG_TCTL: u64 = 0x0400;
const REG_RDBAL: u64 = 0x2800;
const REG_RDBAH: u64 = 0x2804;
const REG_RDLEN: u64 = 0x2808;
const REG_RDH: u64 = 0x2810;
const REG_RDT: u64 = 0x2818;
const REG_TDBAL: u64 = 0x3800;
const REG_TDBAH: u64 = 0x3804;
const REG_TDLEN: u64 = 0x3808;
const REG_TDH: u64 = 0x3810;
const REG_TDT: u64 = 0x3818;
const REG_RAL0: u64 = 0x5400;
const REG_RAH0: u64 = 0x5404;

// PCH (Lynx Point onward) — Management Engine PHY-ownership
// handshake. The Intel ME shares the integrated PHY with the host
// on I217/I218/I219 (`drivers/net/ethernet/intel/e1000e/ich8lan.c`
// — `e1000_get_swflag_ich8lan` + `e1000_release_swflag_ich8lan`).
//
// FWSM (Firmware Status, 0x05B54) bit 15 = `FW_VALID`: ME firmware
// is alive and may be touching the PHY. EXTCNF_CTRL (Extended
// Configuration Control, 0x00F00) bit 5 = `SW_FLAG`: software
// owns the PHY. The driver writes 1 to claim, reads back to confirm,
// holds for the PHY/MAC op, then writes 0 to release. On non-ME
// silicon FWSM reads as 0 → the dance is a no-op (this is what QEMU
// 82540EM looks like).
/// `E1000_FWSM` — Firmware Status (PCH parts).
const REG_FWSM: u64 = 0x5B54;
/// `E1000_ICH_FWSM_FW_VALID` — ME firmware valid bit.
const ICH_FWSM_FW_VALID: u32 = 1 << 15;
/// `E1000_EXTCNF_CTRL` — Extended Configuration Control.
const REG_EXTCNF_CTRL: u64 = 0x0F00;
/// `E1000_EXTCNF_CTRL_SWFLAG` — software-owns-the-PHY flag.
const EXTCNF_CTRL_SWFLAG: u32 = 1 << 5;

// EEE (Energy Efficient Ethernet) — IEEE 802.3az. On I218/I219 the
// MAC negotiates EEE LPI with its link partner; when the partner
// (a dock or switch ASIC) pushes aggressive EEE during init while
// the host hasn't acknowledged capabilities, the PHY can wedge. The
// Linux workaround in `e1000_set_eee_pchlan` clears IPCNFG.EEE bits
// before CTRL.SLU so the partner doesn't see capabilities advertised
// during the brief window before the driver has finished bring-up.
// IPCNFG = 0x00E38; bit 14 = `EEE_1G_AN`, bit 12 = `EEE_100M_AN`
// per Linux `defines.h`.
/// `E1000_IPCNFG` — In-band Configuration (PCH parts).
pub const REG_IPCNFG: u64 = 0x0E38;
/// `E1000_IPCNFG_EEE_1G_AN` — advertise 1000BT EEE.
pub const IPCNFG_EEE_1G_AN: u32 = 1 << 14;
/// `E1000_IPCNFG_EEE_100M_AN` — advertise 100BT EEE.
pub const IPCNFG_EEE_100M_AN: u32 = 1 << 12;
/// `E1000_EEER` — Energy Efficient Ethernet Register (PCH parts).
pub const REG_EEER: u64 = 0x0E30;
/// `E1000_EEER_TX_LPI_EN` — enable TX LPI (low-power idle).
pub const EEER_TX_LPI_EN: u32 = 1 << 16;
/// `E1000_EEER_RX_LPI_EN` — enable RX LPI.
pub const EEER_RX_LPI_EN: u32 = 1 << 17;
/// `E1000_EEER_LPI_FC` — LPI frame counter.
pub const EEER_LPI_FC: u32 = 1 << 18;

/// Mask of IPCNFG bits cleared by `disable_eee_pchlan` — the 1G/100M
/// EEE-advertise bits. Exposed so smokes can verify the workaround
/// matches Linux's bit layout (`drivers/net/ethernet/intel/e1000e/
/// defines.h`).
pub const IPCNFG_EEE_AN_MASK: u32 = IPCNFG_EEE_1G_AN | IPCNFG_EEE_100M_AN;
/// Mask of EEER bits cleared by `disable_eee_pchlan` — disables TX
/// LPI, RX LPI, and the LPI frame counter so the PHY doesn't enter
/// low-power-idle while the link is still negotiating.
pub const EEER_LPI_MASK: u32 = EEER_TX_LPI_EN | EEER_RX_LPI_EN | EEER_LPI_FC;

// CTRL bits.
const CTRL_RST: u32 = 1 << 26;
const CTRL_SLU: u32 = 1 << 6; // Set Link Up

// TCTL bits.
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3; // Pad Short Packets

// TX descriptor flags.
const TXD_CMD_EOP: u8 = 1 << 0;
const TXD_CMD_IFCS: u8 = 1 << 1; // Insert FCS
const TXD_CMD_RS: u8 = 1 << 3; // Report Status
const TXD_STAT_DD: u8 = 1 << 0; // Done

// TX checksum / TSO bits for the legacy e1000 descriptor.
// Source: Linux e1000_hw.h E1000_TXD_CMD_DEXT / E1000_TXD_CMD_TSE.
/// DEXT — Descriptor Extension flag. Must be set when checksum or TSO
/// offload bits are active.
pub const TXD_CMD_DEXT: u8 = 1 << 5;
/// TSE — TCP Segmentation Enable. Combined with DEXT + DTYP_D.
pub const TXD_CMD_TSE: u8 = 1 << 2;
/// DTYP_D — Data descriptor type indicator.
pub const TXD_DTYP_D: u8 = 1 << 4;
/// IXSM — Insert IP Checksum. Placed in the `css` byte alongside DEXT.
pub const TXD_OPTS_IXSM: u8 = 1 << 0;
/// TXSM — Insert TCP/UDP Checksum.
pub const TXD_OPTS_TXSM: u8 = 1 << 1;

// RX descriptor checksum status bits (e1000_hw.h E1000_RXD_STAT_IPCS /
// E1000_RXD_STAT_TCPCS and E1000_RXD_ERR_IPE / E1000_RXD_ERR_TCPE).
pub const RXD_STAT_IPCS: u8 = 1 << 6;
pub const RXD_STAT_TCPCS: u8 = 1 << 5;
pub const RXD_ERR_IPE: u8 = 1 << 6;
pub const RXD_ERR_TCPE: u8 = 1 << 5;

/// RX checksum verification result decoded from a legacy e1000 RxDesc.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    /// Hardware did not compute a checksum for this frame.
    None,
    /// Hardware computed and verified the checksum — no errors.
    Ok,
    /// Hardware detected a checksum error.
    Fail,
}

// RCTL bits (Receive Control register).
const RCTL_EN: u32 = 1 << 1; // Receiver Enable
const RCTL_UPE: u32 = 1 << 3; // Unicast Promiscuous
const RCTL_MPE: u32 = 1 << 4; // Multicast Promiscuous
const RCTL_BAM: u32 = 1 << 15; // Broadcast Accept
const RCTL_BSIZE_2K: u32 = 0 << 16; // Buffer Size = 2048
const RCTL_SECRC: u32 = 1 << 26; // Strip Ethernet CRC

// RX descriptor status flags.
const RXD_STAT_DD: u8 = 1 << 0; // Done
const RXD_STAT_EOP: u8 = 1 << 1; // End of Packet

// IMS / ICR bit layout (8254x SDM §13.4.17 + §13.4.20). Same set
// applies to ICR (read-to-clear) and IMS (write-1-to-set). The
// 82574L datasheet §10.2 keeps the same bit positions; e1000e
// adds extra bits we don't enable.
/// TXDW — Transmit Descriptor Written Back. Fires when a TX
/// descriptor with RS set has been written back with DD = 1.
pub const IMS_TXDW: u32 = 1 << 0;
/// TXQE — Transmit Queue Empty. Fires once the TX ring drains.
pub const IMS_TXQE: u32 = 1 << 1;
/// LSC — Link Status Change.
pub const IMS_LSC: u32 = 1 << 2;
/// RXSEQ — Receive Sequence Error.
pub const IMS_RXSEQ: u32 = 1 << 3;
/// RXDMT0 — Receive Descriptor Minimum Threshold (head reached the
/// "low watermark" — driver should refill).
pub const IMS_RXDMT0: u32 = 1 << 4;
/// RXO — Receiver FIFO Overrun.
pub const IMS_RXO: u32 = 1 << 6;
/// RXT0 — Receiver Timer Expired (a frame landed in the ring and
/// the receive interrupt timer expired). Standard "RX done"
/// indicator under per-frame interrupts (RDTR = 0).
pub const IMS_RXT0: u32 = 1 << 7;

/// Default IMS bring-up mask: RX completion + TX completion + RX
/// overrun + low-threshold. RXSEQ is included so we can observe
/// link-side framing errors.
const IMS_DEFAULT: u32 =
    IMS_RXT0 | IMS_RXDMT0 | IMS_RXO | IMS_RXSEQ | IMS_TXDW | IMS_TXQE | IMS_LSC;

const TX_RING_LEN: usize = 8;
const RX_RING_LEN: usize = 8;
/// Buffer size for each RX entry — must match RCTL.BSIZE.
const RX_BUF_LEN: usize = 2048;

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct TxDesc {
    pub addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

const _: () = assert!(core::mem::size_of::<TxDesc>() == 16);

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct RxDesc {
    pub addr: u64,
    pub length: u16,
    pub csum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

const _: () = assert!(core::mem::size_of::<RxDesc>() == 16);

// ── Descriptor offload helpers ───────────────────────────────────────

impl TxDesc {
    /// Build a TX descriptor with IP + TCP/UDP checksum offload enabled.
    /// `csum_opts` should be `TXD_OPTS_IXSM | TXD_OPTS_TXSM` for
    /// full TCP/IPv4 offload. Setting DEXT + DTYP_D signals the
    /// hardware that the `css` byte carries offload options.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    pub fn new_with_csum(addr: u64, len: u16, csum_opts: u8) -> Self {
        let mut cmd = TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS;
        let mut css = 0u8;
        if csum_opts != 0 {
            cmd |= TXD_CMD_DEXT | TXD_DTYP_D;
            css = csum_opts;
        }
        TxDesc {
            addr,
            length: len,
            cso: 0,
            cmd,
            status: 0,
            css,
            special: 0,
        }
    }

    /// Build a TX descriptor with TSO enabled. The hardware will segment
    /// the payload into MSS-sized chunks. DEXT | DTYP_D | TSE must all
    /// be set; both IP and TCP csum-insert bits are also required.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    pub fn with_tso(addr: u64, len: u16, _mss: u16) -> Self {
        let cmd = TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS | TXD_CMD_DEXT | TXD_DTYP_D | TXD_CMD_TSE;
        let css = TXD_OPTS_IXSM | TXD_OPTS_TXSM;
        TxDesc {
            addr,
            length: len,
            cso: 0,
            cmd,
            status: 0,
            css,
            special: 0,
        }
    }
}

impl RxDesc {
    /// Decode the RX checksum result from the legacy e1000 descriptor
    /// status and errors bytes.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    pub fn csum_result(&self) -> RxCsumResult {
        let ip_computed = self.status & RXD_STAT_IPCS != 0;
        let tcp_computed = self.status & RXD_STAT_TCPCS != 0;
        if !ip_computed && !tcp_computed {
            return RxCsumResult::None;
        }
        let ip_err = self.errors & RXD_ERR_IPE != 0;
        let tcp_err = self.errors & RXD_ERR_TCPE != 0;
        if ip_err || tcp_err {
            RxCsumResult::Fail
        } else {
            RxCsumResult::Ok
        }
    }
}

/// e1000 driver errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum E1000Error {
    BarMapFailed,
    NoMemory,
    UnsupportedDevice,
    /// Caller passed a frame larger than 1518 bytes.
    FrameTooLong,
    /// TX descriptor never completed.
    TxTimeout,
    /// PHY-ownership handshake (FWSM/SWFLAG) timed out — the
    /// Management Engine never released the PHY. Bring-up gives up
    /// rather than risk a wedged PHY register read.
    PhyOwnershipTimeout,
    /// Catch-all.
    Other(&'static str),
}

/// `true` for PCH (I217 / I218 / I219) silicon, where the Intel ME
/// shares the integrated PHY with the host and the FWSM-gated
/// SWFLAG handshake is required around any PHY/MAC reconfiguration.
/// Mirrors Linux's `mac.type >= e1000_pchlan` discriminator.
///
/// Pre-PCH parts (82540 / 82574L, the QEMU-emulated lineage) and
/// the I210/I211/82576/I350 entries that came in with the Stage-1
/// audit don't have an ME-attached PHY and return `false`.
pub fn is_pch_part(did: u16) -> bool {
    matches!(
        did,
        E1000E_DEV_I217LM
            | E1000E_DEV_I217V
            | E1000E_DEV_I218LM
            | E1000E_DEV_I218V
            | E1000E_DEV_I218LM2
            | E1000E_DEV_I218V2
            | E1000E_DEV_I218LM3
            | E1000E_DEV_I218V3
            | E1000E_DEV_I219LM
            | E1000E_DEV_I219V
            | E1000E_DEV_I219LM2
            | E1000E_DEV_I219V2
            | E1000E_DEV_I219LM3
            | E1000E_DEV_I219LM4
            | E1000E_DEV_I219V4
            | E1000E_DEV_I219LM5
            | E1000E_DEV_I219V5
            | E1000E_DEV_I219LM6
            | E1000E_DEV_I219V6
            | E1000E_DEV_I219LM7
            | E1000E_DEV_I219V7
            | E1000E_DEV_I219LM8
            | E1000E_DEV_I219V8
            | E1000E_DEV_I219LM9
            | E1000E_DEV_I219V9
            | E1000E_DEV_I219LM10
            | E1000E_DEV_I219V10
            | E1000E_DEV_I219LM11
            | E1000E_DEV_I219V11
            | E1000E_DEV_I219LM12
            | E1000E_DEV_I219V12
            | E1000E_DEV_I219LM13
            | E1000E_DEV_I219V13
            | E1000E_DEV_I219LM14
            | E1000E_DEV_I219V14
            | E1000E_DEV_I219LM15
            | E1000E_DEV_I219V15
            | E1000E_DEV_I219LM16
            | E1000E_DEV_I219V16
            | E1000E_DEV_I219LM17
            | E1000E_DEV_I219V17
            | E1000E_DEV_I219LM18
            | E1000E_DEV_I219V18
            | E1000E_DEV_I219LM19
            | E1000E_DEV_I219V19
            | E1000E_DEV_I219LM20
            | E1000E_DEV_I219V20
            | E1000E_DEV_I219LM21
            | E1000E_DEV_I219V21
            | E1000E_DEV_I219LM22
            | E1000E_DEV_I219V22
            | E1000E_DEV_I219LM23
            | E1000E_DEV_I219V23
            | E1000E_DEV_I219LM24
            | E1000E_DEV_I219V24
            | E1000E_DEV_I219LM25
            | E1000E_DEV_I219V25
            | E1000E_DEV_I219LM27
            | E1000E_DEV_I219V27
            | E1000E_DEV_I219LM29
            | E1000E_DEV_I219V29
    )
}

/// `true` if the Management Engine firmware reports valid + active
/// on this MAC. On non-PCH silicon and on PCH parts without ME (or
/// with ME disabled in BIOS) FWSM reads as 0 → returns `false`.
///
/// Linux equivalent: `er32(FWSM) & E1000_ICH_FWSM_FW_VALID`
/// (`drivers/net/ethernet/intel/e1000e/ich8lan.c::e1000_check_mng_mode_ich8lan`).
fn me_is_active(mmio: &MmioRegion) -> bool {
    // SAFETY: identity-mapped MMIO; FWSM is inside the e1000 BAR0
    // register window on every PCH part.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let fwsm = unsafe { mmio.read32(REG_FWSM) };
    (fwsm & ICH_FWSM_FW_VALID) != 0
}

/// Claim PHY ownership via the EXTCNF_CTRL.SWFLAG handshake.
///
/// Linux: `e1000_get_swflag_ich8lan`
/// (`drivers/net/ethernet/intel/e1000e/ich8lan.c`). The driver
/// writes 1 to EXTCNF_CTRL.SWFLAG, then polls for it to read back
/// as 1 — when the ME owns the PHY it will leave the bit at 0 until
/// it's done. Linux loops up to 10× (each iter ~10 ms with a 5 ms
/// hold-time after acquire); we keep the same total budget. The
/// hold-time mirrors `udelay(SW_FLAG_TIMEOUT)` in the kernel.
///
/// On non-ME silicon (FWSM = 0) we skip — there's nothing to
/// handshake with. Returns `Ok` either way; `Err` only on the wedge
/// case where the ME never releases.
fn acquire_phy_swflag(mmio: &MmioRegion) -> Result<bool, E1000Error> {
    if !me_is_active(mmio) {
        // No ME — no handshake. Return "didn't take the flag" so
        // the release path is a no-op too.
        return Ok(false);
    }
    for _ in 0..10 {
        // SAFETY: `mmio` was mapped from BAR0 by the caller and
        // `REG_EXTCNF_CTRL` is a valid 32-bit register offset within it,
        // so the read/write target a real device register of the right
        // width.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            let v = mmio.read32(REG_EXTCNF_CTRL);
            mmio.write32(REG_EXTCNF_CTRL, v | EXTCNF_CTRL_SWFLAG);
        }
        // Linux uses `udelay(SW_FLAG_TIMEOUT)` = 50 µs between
        // poll iterations. responsive_spin_until ticks sleep_pumps
        // so a slow ME doesn't starve other kernel async tasks.
        let got = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(REG_EXTCNF_CTRL) } & EXTCNF_CTRL_SWFLAG != 0,
            narf_time::Deadline::after_ms(10),
        );
        if got {
            return Ok(true);
        }
        // ME still hasn't released; clear our request and retry.
        // Linux re-reads + re-writes; we mirror.
        // SAFETY: same.
        unsafe {
            let v = mmio.read32(REG_EXTCNF_CTRL);
            mmio.write32(REG_EXTCNF_CTRL, v & !EXTCNF_CTRL_SWFLAG);
        }
    }
    Err(E1000Error::PhyOwnershipTimeout)
}

/// Drop PHY ownership by clearing EXTCNF_CTRL.SWFLAG.
///
/// Linux: `e1000_release_swflag_ich8lan`. No handshake on release;
/// just a single write. Called paired with `acquire_phy_swflag` —
/// the `owned` return from acquire gates whether to write at all
/// (skips on non-ME silicon).
fn release_phy_swflag(mmio: &MmioRegion, owned: bool) {
    if !owned {
        return;
    }
    // SAFETY: identity-mapped MMIO.
    unsafe {
        let v = mmio.read32(REG_EXTCNF_CTRL);
        mmio.write32(REG_EXTCNF_CTRL, v & !EXTCNF_CTRL_SWFLAG);
    }
}

/// Disable Energy Efficient Ethernet on PCH parts.
///
/// Linux: `e1000_set_eee_pchlan`
/// (`drivers/net/ethernet/intel/e1000e/ich8lan.c`). Clears the
/// 1G/100M EEE-advertise bits in IPCNFG (0x0E38) and drains LPI
/// state from EEER (0x0E30) so the partner can't push aggressive
/// EEE while the driver is mid-bring-up. Without this, some I218
/// PHYs wedge when a dock partner advertises EEE during the brief
/// window after MAC reset but before CTRL.SLU.
///
/// This is the IPCNFG-side workaround tracked in
/// `notes/intel-e1000e-igc-audit.md` §E. The full LP-ability PHY-
/// page write lives in a follow-up (needs MDIC access, which we
/// don't expose yet).
fn disable_eee_pchlan(mmio: &MmioRegion) {
    // SAFETY: identity-mapped MMIO; IPCNFG + EEER are inside BAR0
    // on every PCH part.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        let ipcnfg = mmio.read32(REG_IPCNFG);
        mmio.write32(REG_IPCNFG, ipcnfg & !IPCNFG_EEE_AN_MASK);
        let eeer = mmio.read32(REG_EEER);
        mmio.write32(REG_EEER, eeer & !EEER_LPI_MASK);
    }
}

/// Live e1000 controller. Holds the MMIO mapping + the TX descriptor
/// ring's DMA buffer. Each frame transmits through a per-call DMA
/// scratch buffer that drops after completion.
pub struct E1000 {
    mmio: MmioRegion,
    /// TX descriptor-ring DMA buffer.
    tx_ring: DmaBuffer,
    /// Persistent TX frame buffers, one per descriptor slot
    /// (audit #4: pre-fix `tx()` did `alloc_coherent(4096)` per
    /// frame and dropped it on return — under AMD-Vi a freed
    /// page could be reused while the NIC still had a delayed
    /// DMA in flight, corrupting whatever owns the recycled
    /// page). Pool sized to TX_RING_LEN; slot index matches the
    /// descriptor index, so `tx()` writes into `tx_pool[slot]`
    /// before pointing the descriptor's `addr` at it.
    tx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side TDT cursor (tail).
    tx_tail: IrqSafeSpinLock<u32>,
    /// RX descriptor-ring DMA buffer.
    rx_ring: DmaBuffer,
    /// RX buffer pool — one DMA page per descriptor (`RX_BUF_LEN`
    /// bytes consumed; remainder unused).
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side RX head cursor (next descriptor to inspect for
    /// completion). The hardware writes to RDT and we lag behind
    /// reading at this index.
    rx_head: IrqSafeSpinLock<u32>,
    /// MAC address read from RAL/RAH at bring-up.
    pub mac: [u8; 6],
    /// True after CTRL_SLU has been set + STATUS reports link up.
    pub link_up: bool,
    /// MSI-X table mapping when MSI-X is enabled. Holds the table
    /// alive for the device lifetime; dropping it would unmap the
    /// MSI-X BAR.
    _msix: Option<MsixTable>,
    /// IDT vector bound to the device's IRQ (MSI-X table entry 0
    /// or the IOAPIC GSI route). `None` means we fell back to
    /// polled-only completion.
    pub irq_vector: Option<u8>,
    /// `true` for I217 / I218 / I219 (PCH-attached PHY where the
    /// Intel ME can co-own the PHY register set). Determines
    /// whether subsequent PHY/MAC reconfiguration needs to ride
    /// the FWSM/SWFLAG handshake.
    pub pch_part: bool,
    /// `true` if `FWSM.FW_VALID` was set at probe — the Management
    /// Engine firmware is alive and may be touching the PHY. False
    /// on QEMU (no ME) and on real silicon where the ME is
    /// disabled in BIOS.
    pub me_active: bool,

    // IPC integration
    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

// SAFETY: `E1000` only auto-fails `Send` because `MmioRegion`/`DmaBuffer`
// wrap raw device/DMA pointers. Those pointers stay valid for the device
// lifetime and are not tied to any thread, so the handle is sound to move
// across threads.
unsafe impl Send for E1000 {}
// SAFETY: every field reachable through `&E1000` from multiple threads is
// either immutable after bring-up (mac/link_up/mmio mapping) or guarded by
// an `IrqSafeSpinLock` (tx/rx cursors and IPC rings); concurrent MMIO/DMA
// register access via the shared pointers is serialized by those locks, so
// shared access is sound.
unsafe impl Sync for E1000 {}

impl core::fmt::Debug for E1000 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("E1000")
            .field("mac", &self.mac)
            .field("link_up", &self.link_up)
            .field("irq_vector", &self.irq_vector)
            .field("pch_part", &self.pch_part)
            .field("me_active", &self.me_active)
            .finish_non_exhaustive()
    }
}

/// MMIO base of the IRQ-attached e1000, shared with the static ISR
/// so it can read ICR (auto-clear, §13.4.17) and deassert legacy
/// INTx. 0 = no controller bound (handler short-circuits).
///
/// Single-controller invariant matches the rest of the driver:
/// `CONTROLLER` is a single `Option<E1000>` slot below.
static ISR_MMIO_BASE: AtomicU64 = AtomicU64::new(0);

/// Sync ISR: read ICR to acknowledge + deassert level-triggered INTx,
/// then return. The dispatch layer (`narf_interrupts::dispatch::on_irq`)
/// bumps the per-vector fire-count and wakes the registered waker; the
/// `rx_async`/`tx_async` consumers then run the actual descriptor
/// drain on a normal task.
fn e1000_isr() {
    let base = ISR_MMIO_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    // SAFETY: `base` is the device's BAR0 phys, identity-mapped at
    // bring-up; ICR (offset 0xC0) is well inside the e1000 register
    // window. The read auto-clears all pending cause bits per 8254x
    // SDM §13.4.17 — this is the documented acknowledge for
    // level-triggered INTx delivery and a no-op for MSI-X (which
    // is edge-triggered but tolerates the read).
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        let _icr = narf_arch::mmio::read32(base + REG_ICR);
    }
}

impl E1000 {
    /// Bring up the controller: reset, read MAC, install RX + TX
    /// rings, set link up, attach IRQ delivery (MSI-X → INTx →
    /// polled fallback) and program IMS for the standard RX/TX
    /// completion mask.
    ///
    /// # Safety
    /// Caller owns the device's BAR exclusively for the duration of
    /// init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<(Self, Producer<Frame, RX_RING_N>, Consumer<Frame, TX_RING_N>), E1000Error> {
        // SAFETY: caller owns the device.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| E1000Error::BarMapFailed)?;

        // PCH-vs-legacy discriminator. On I217/I218/I219 the Intel
        // Management Engine shares the integrated PHY with the host;
        // PHY/MAC reconfiguration must ride the FWSM/SWFLAG handshake
        // (Linux `e1000_get_swflag_ich8lan`). On the QEMU-emulated
        // 82540EM (`pch_part = false`) this is all a no-op.
        let pch_part = is_pch_part(device.id.device);
        let me_active = pch_part && me_is_active(&mmio);

        // 0. PCH PHY-ownership handshake. Claim PHY before reset so
        //    we don't race the ME's PHY-config-on-reset path. Skipped
        //    on legacy parts. We hold the SWFLAG across the whole
        //    bring-up — Linux scopes it tighter (per PHY-register
        //    access), but our bring-up is short and doesn't touch
        //    PHY MDIC, so a single hold is cheaper than per-op.
        let phy_owned = if pch_part {
            acquire_phy_swflag(&mmio)?
        } else {
            false
        };

        // 1. Reset (CTRL.RST = 1; cleared by hardware after reset).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_CTRL, CTRL_RST);
        }
        // Wait for RST to clear. responsive_spin_until ticks
        // sleep_pumps every ~4096 iters so FB cursor / serial drain
        // stay alive. e1000 datasheet §13.3.1: CTRL.RST self-clears
        // within ~10 ms; 100 ms is the wedge threshold.
        narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(REG_CTRL) } & CTRL_RST == 0,
            narf_time::Deadline::after_ms(100),
        );

        // 1b. On PCH parts, disable EEE before CTRL.SLU. Some I218
        //    PHYs wedge when a dock partner advertises EEE during the
        //    post-reset → pre-link-up window. Linux's `e1000_set_eee_
        //    pchlan` does the same (clears IPCNFG.EEE_*_AN before
        //    starting link). No-op on legacy parts.
        if pch_part {
            disable_eee_pchlan(&mmio);
        }

        // 2. Read MAC from RAL/RAH.
        // SAFETY: `mmio` was mapped from BAR0; `REG_RAL0` is a valid 32-bit
        // register offset within it.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let ral = unsafe { mmio.read32(REG_RAL0) };
        // SAFETY: `mmio` was mapped from BAR0; `REG_RAH0` is a valid 32-bit
        // register offset within it.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let rah = unsafe { mmio.read32(REG_RAH0) };
        let mac = [
            (ral & 0xFF) as u8,
            ((ral >> 8) & 0xFF) as u8,
            ((ral >> 16) & 0xFF) as u8,
            ((ral >> 24) & 0xFF) as u8,
            (rah & 0xFF) as u8,
            ((rah >> 8) & 0xFF) as u8,
        ];

        // 3. Mask all interrupt causes during bring-up. IMC is
        //    write-1-to-clear (8254x SDM §13.4.22); writing all-ones
        //    leaves IMS = 0 and prevents stale IRQs while we program
        //    the rings. We re-enable the per-cause mask in IMS at the
        //    end of bring-up once the ISR is installed.
        // SAFETY: identity-mapped.
        unsafe {
            mmio.write32(REG_IMC, !0u32);
            // Clear any pending causes by reading ICR (read-to-clear).
            let _ = mmio.read32(REG_ICR);
        }

        // 4. Allocate TX descriptor ring + persistent per-slot
        //    frame buffers. The buffers outlive any single tx()
        //    call so a delayed DMA write (AMD-Vi turn-around
        //    latency) can't land on a freed page.
        let tx_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| E1000Error::NoMemory)?;
        let ring_phys = tx_ring.phys_addr().raw();
        let mut tx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(TX_RING_LEN);
        for _ in 0..TX_RING_LEN {
            let b = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| E1000Error::NoMemory)?;
            tx_pool.push(b);
        }
        // Zero the ring (alloc_coherent guarantees fresh memory but
        // we're explicit).
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..(TX_RING_LEN * 16) {
                core::ptr::write_volatile((ring_phys + i as u64) as *mut u8, 0);
            }
        }
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_TDBAL, ring_phys as u32);
            mmio.write32(REG_TDBAH, (ring_phys >> 32) as u32);
            mmio.write32(REG_TDLEN, (TX_RING_LEN * 16) as u32);
            mmio.write32(REG_TDH, 0);
            mmio.write32(REG_TDT, 0);
        }
        // 5. Enable TX. PSP = pad short packets to 64 bytes (Ethernet
        //    minimum frame size). Collision threshold + collision
        //    distance are spec-default — bits 12..21 stay zero in our
        //    minimal config.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_TCTL, TCTL_EN | TCTL_PSP);
        }

        // 5b. Allocate RX descriptor ring + buffer pool.
        let rx_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| E1000Error::NoMemory)?;
        let rx_ring_phys = rx_ring.phys_addr().raw();
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RX_RING_LEN);
        for i in 0..RX_RING_LEN {
            let buf = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| E1000Error::NoMemory)?;
            let buf_phys = buf.phys_addr().raw();
            let desc = RxDesc {
                addr: buf_phys,
                length: 0,
                csum: 0,
                status: 0,
                errors: 0,
                special: 0,
            };
            // SAFETY: identity-mapped DMA ring.
            unsafe {
                core::ptr::write_volatile((rx_ring_phys + (i * 16) as u64) as *mut RxDesc, desc);
            }
            rx_pool.push(buf);
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_RDBAL, rx_ring_phys as u32);
            mmio.write32(REG_RDBAH, (rx_ring_phys >> 32) as u32);
            mmio.write32(REG_RDLEN, (RX_RING_LEN * 16) as u32);
            mmio.write32(REG_RDH, 0);
            // RDT points to the last *available* slot (i.e. one past
            // the last filled slot). With all slots filled, RDT =
            // RX_RING_LEN - 1.
            mmio.write32(REG_RDT, (RX_RING_LEN - 1) as u32);
            // RCTL: enable, accept broadcast/unicast/multicast,
            // strip CRC, 2K buffers.
            mmio.write32(
                REG_RCTL,
                RCTL_EN | RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC | RCTL_BSIZE_2K,
            );
        }

        // 6. Set link up.
        // SAFETY: same.
        let cur = unsafe { mmio.read32(REG_CTRL) };
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_CTRL, cur | CTRL_SLU);
        }
        // STATUS bit 1 = LU (link up). QEMU e1000 reports up
        // immediately on user-mode net.
        // SAFETY: same.
        let status = unsafe { mmio.read32(REG_STATUS) };
        let link_up = status & (1 << 1) != 0;

        // 7. Try to attach an IRQ delivery path. Mirror the
        //    `xhci.rs` MSI-X → INTx → polled fallback chain.
        let (msix, irq_vector, used_intx) = match Self::try_enable_msix(cap, device) {
            Ok((tbl, v)) => (Some(tbl), Some(v), false),
            Err(_) => match Self::try_install_intx(cap, device) {
                Some(v) => (None, Some(v), true),
                None => (None, None, false),
            },
        };

        // Publish MMIO base for the static ISR before installing the
        // handler — otherwise an early INTx could race and find a
        // zero base.
        if irq_vector.is_some() {
            ISR_MMIO_BASE.store(mmio.phys.raw(), Ordering::Release);
        }
        if let Some(v) = irq_vector {
            narf_interrupts::install_handler(v, e1000_isr);
        }

        // 8. Adjust the PCI Command register based on which IRQ path
        //    won. INTx delivery requires the legacy interrupt enable
        //    (i.e. INTX_DISABLE *cleared*); MSI-X delivery is happy
        //    with INTX_DISABLE set so the device can't double-fire.
        //
        //    The probe path enables MEM_SPACE + BUS_MASTER but leaves
        //    INTx behaviour to the driver. We only program the bit
        //    we need to flip here.
        if !used_intx && irq_vector.is_some() {
            // MSI-X path: explicitly mask legacy INTx.
            let _ = narf_bus::pci::set_command(cap, device, narf_bus::pci::cmd::INTX_DISABLE);
        }

        // 9. Enable interrupt causes. ICR was cleared above; IMS is
        //    a write-1-to-set register (8254x SDM §13.4.20).
        //    Skip if no IRQ vector is bound — keep the "all masked"
        //    state from step 3 so polled callers don't see spurious
        //    cause bits.
        if irq_vector.is_some() {
            // SAFETY: identity-mapped MMIO.
            unsafe {
                mmio.write32(REG_IMS, IMS_DEFAULT);
            }
        }

        // 10. Release PHY ownership now that bring-up is done. Linux
        //     holds SWFLAG only for the duration of each PHY access;
        //     we held it across the whole init for clean-room
        //     simplicity. A no-op on legacy parts and on PCH parts
        //     where the ME wasn't active.
        if pch_part {
            release_phy_swflag(&mmio, phy_owned);
        }

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let e1000 = Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_tail: IrqSafeSpinLock::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            link_up,
            _msix: msix,
            irq_vector,
            pch_part,
            me_active,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        };

        // Pump tasks are spawned by the caller (probe) once it has
        // wrapped self in Arc — spawning here would prevent bring_up
        // from returning Self because the Arc clones inside spawn_pumps
        // keep the refcount above 1, making Arc::try_unwrap fail.
        Ok((e1000, rx_prod, tx_cons))
    }

    /// Walk the controller's MSI-X capability, allocate an IDT
    /// vector + table slot, program slot 0 to deliver to BSP, and
    /// flip the global MSI-X enable. Returns `(table, vector)` on
    /// success. Failure propagates to `try_install_intx`.
    fn try_enable_msix(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(MsixTable, u8), E1000Error> {
        let mut msix = enable_msix(cap, device).map_err(|_| E1000Error::NoMemory)?;
        let v = narf_interrupts::vector::alloc().map_err(|_| E1000Error::NoMemory)?;
        let _ = msix.alloc_vector().ok_or(E1000Error::NoMemory)?;
        // Deliver to APIC id 0 (BSP). On aarch64 this routes through
        // the GIC ITS doorbell with EventID=v.
        // SAFETY: caller holds the BusDeviceCap; we own the MSI-X
        // table (no other writer); we issue this write before the
        // global enable so the device can't fire stale data.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let _ = unsafe { msix.program_vector(0, 0, v) }.map_err(|_| E1000Error::NoMemory)?;
        // SAFETY: cfg-space write to a known cap-list offset.
        unsafe { msix.enable() }.map_err(|_| E1000Error::NoMemory)?;
        Ok((msix, v))
    }

    /// Legacy INTx fallback: read PCI INTERRUPT_PIN, look up the
    /// (bridge, slot, pin) triple in the AML `_PRT` routing table,
    /// allocate an IDT vector, and program the IOAPIC redirection-
    /// table entry for the resolved GSI.
    ///
    /// PCI INTx is level-triggered, active-low (PCI Local Bus Spec
    /// §2.2.6). Returns the allocated vector, or `None` on any
    /// failure (caller falls through to polled completion).
    #[cfg(target_arch = "x86_64")]
    fn try_install_intx(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Option<u8> {
        let pin = narf_bus::pci::read_intx_pin(cap, device).ok()?;
        if pin == 0 || pin > 4 {
            return None;
        }
        let slot = match device.kind {
            narf_bus::BusKind::Pcie { addr, .. } => addr.device,
            _ => return None,
        };
        // PCI _PRT pin is 0-based (0=INTA..3=INTD); cfg-space pin is
        // 1-based. Map between them.
        let prt_pin = pin - 1;
        // Today every QEMU q35 bridge AML lives at "\\_SB.PCI0";
        // real consumer BIOSes match this convention.
        let route = narf_aml::irq_routing::route_for("\\_SB.PCI0", slot, prt_pin)?;
        if route.entry.source.is_some() {
            // Named-link _PRT entry — needs link-device _CRS
            // evaluation to learn the current GSI.
            return None;
        }
        let gsi = route.entry.source_index;
        let v = narf_interrupts::vector::alloc().ok()?;
        // Program IOAPIC: PCI INTx is level / active-low. The
        // handler is installed after this returns by the bring-up
        // path so the dispatch table sees the e1000 ISR before the
        // first IRQ can be delivered (vector::alloc reserves the
        // slot but doesn't open it for delivery).
        // SAFETY: vector reserved above; route_gsi_to_vector only
        // programs the IOAPIC redirection-table entry.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let ok = unsafe {
            narf_acpi::ioapic::route_gsi_to_vector(
                gsi,
                v,
                0,
                narf_acpi::ioapic::POLARITY_LOW | narf_acpi::ioapic::TRIGGER_LEVEL,
            )
        };
        if !ok {
            return None;
        }
        Some(v)
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn try_install_intx(_cap: &Cap<BusDeviceCap, Write>, _device: &BusDevice) -> Option<u8> {
        None
    }

    /// Transmit a single Ethernet frame. Polled completion via the
    /// TX descriptor's DD (Descriptor Done) status bit. Available
    /// regardless of whether IRQ delivery is wired — the polled
    /// path is what bring-up tests run, and it's also the synchronous
    /// fallback for callers that can't await.
    pub fn tx(&self, frame: &[u8]) -> Result<(), E1000Error> {
        if frame.is_empty() || frame.len() > 1518 {
            return Err(E1000Error::FrameTooLong);
        }
        // Pick the next TX descriptor slot, then reuse that
        // slot's persistent DMA buffer (audit #4 — pre-fix this
        // alloc_coherent'd a fresh page per frame and dropped it
        // on return).
        let mut tail_g = self.tx_tail.lock();
        let slot = (*tail_g) as usize % TX_RING_LEN;
        let phys = self.tx_pool[slot].phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked by
        // the FrameTooLong guard above (1518 < 4096).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, *b);
            }
        }
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        let desc = TxDesc {
            addr: phys,
            length: frame.len() as u16,
            cso: 0,
            cmd: TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS,
            status: 0,
            css: 0,
            special: 0,
        };
        // SAFETY: identity-mapped DMA ring page.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut TxDesc, desc);
        }
        // Bump TDT.
        let next_tail = (*tail_g + 1) % (TX_RING_LEN as u32);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_TDT, next_tail);
        }
        *tail_g = next_tail;
        drop(tail_g);

        // Poll for DD. responsive_spin_until ticks sleep_pumps.
        // 250 ms wall-clock budget covers worst-case Tx-side
        // congestion stall.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile((desc_addr + 12) as *const u8) } & TXD_STAT_DD != 0,
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(E1000Error::TxTimeout);
        }
        Ok(())
    }

    /// Inspect the TX descriptor most recently posted at `slot` and
    /// return whether its DD bit is set. Used by `tx_async` to
    /// detect completion after `wait_for_irq` returns.
    fn tx_slot_done(&self, slot: usize) -> bool {
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        // SAFETY: identity-mapped DMA ring; slot < TX_RING_LEN.
        let status = unsafe { core::ptr::read_volatile((desc_addr + 12) as *const u8) };
        status & TXD_STAT_DD != 0
    }

    /// Enqueue a frame and return the TX descriptor slot index. The
    /// caller is responsible for awaiting completion (via the
    /// `tx_async` wrapper, which holds the scratch buffer alive
    /// until DD is observed).
    fn tx_enqueue(&self, frame: &[u8]) -> Result<usize, E1000Error> {
        if frame.is_empty() || frame.len() > 1518 {
            return Err(E1000Error::FrameTooLong);
        }
        // Persistent per-slot buffer (audit #4); same change as the
        // sync `tx()` path. Returns just the slot id now since the
        // buffer is owned by the controller and doesn't need to
        // be moved through the async future.
        let mut tail_g = self.tx_tail.lock();
        let slot = (*tail_g) as usize % TX_RING_LEN;
        let phys = self.tx_pool[slot].phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked above.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, *b);
            }
        }
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        let desc = TxDesc {
            addr: phys,
            length: frame.len() as u16,
            cso: 0,
            cmd: TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS,
            status: 0,
            css: 0,
            special: 0,
        };
        // SAFETY: identity-mapped DMA ring page.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut TxDesc, desc);
        }
        let next_tail = (*tail_g + 1) % (TX_RING_LEN as u32);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_TDT, next_tail);
        }
        *tail_g = next_tail;
        Ok(slot)
    }

    /// Drain one received frame from the RX ring, copying it into
    /// `out` and returning the number of bytes. Returns 0 if no
    /// frame is currently pending. After consuming, the descriptor
    /// is rearmed and RDT is bumped so the device sees the freshly-
    /// available slot.
    pub fn rx_recv(&self, out: &mut [u8]) -> usize {
        let mut head_g = self.rx_head.lock();
        let head = (*head_g) as usize;
        let ring_phys = self.rx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring; head < RX_RING_LEN.
        let desc = unsafe { core::ptr::read_volatile(desc_addr as *const RxDesc) };
        if desc.status & RXD_STAT_DD == 0 {
            return 0;
        }
        // Copy out the payload.
        let len = (desc.length as usize).min(out.len()).min(RX_BUF_LEN);
        let buf_phys = desc.addr;
        for (i, b) in out.iter_mut().enumerate().take(len) {
            // SAFETY: the RX buffer at `buf_phys` is an identity-mapped DMA
            // page the device filled; `i < len <= RX_BUF_LEN`, so the byte
            // address `buf_phys + i` stays within that page.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *b = unsafe { core::ptr::read_volatile((buf_phys + i as u64) as *const u8) };
        }
        // Rearm the descriptor: clear status, leave addr as-is.
        let new_desc = RxDesc {
            addr: buf_phys,
            length: 0,
            csum: 0,
            status: 0,
            errors: 0,
            special: 0,
        };
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut RxDesc, new_desc);
        }
        // Bump RDT to the just-freed slot. After consuming descriptor
        // `head`, the most recently freed slot is `head` itself —
        // RDT points at the last available slot for the device.
        let new_head = ((head + 1) % RX_RING_LEN) as u32;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_RDT, head as u32);
        }
        *head_g = new_head;
        let _ = RXD_STAT_EOP; // EOP-multi-descriptor frames land in a follow-up.
        len
    }

    /// `true` if at least one RX descriptor has its DD bit set.
    /// Cheaper than `rx_recv` when callers want to poll without
    /// consuming.
    pub fn rx_has_pending(&self) -> bool {
        let head = (*self.rx_head.lock()) as usize;
        let ring_phys = self.rx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let status = unsafe { core::ptr::read_volatile((desc_addr + 12) as *const u8) };
        status & RXD_STAT_DD != 0
    }

    /// Read CTRL register — useful for tests + diagnostics.
    pub fn read_ctrl(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_CTRL) }
    }

    /// Read STATUS register.
    pub fn read_status(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_STATUS) }
    }

    /// Read IMS (Interrupt Mask Set/Read, 8254x SDM §13.4.20). A
    /// non-zero value indicates IRQ-driven completion is armed.
    pub fn read_ims(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_IMS) }
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<E1000>>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // Enable MEM_SPACE + BUS_MASTER. Leave the legacy INTx path
    // open here — `bring_up` flips INTX_DISABLE on once it has
    // negotiated MSI-X. If we set INTX_DISABLE up front, the INTx
    // fallback can't deliver.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over device.
    let (dev_inner, rx_prod, tx_cons) = match unsafe { E1000::bring_up(&device, &cap) } {
        Ok(t) => t,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    let dev = Arc::new(dev_inner);
    *CONTROLLER.lock() = Some(dev.clone());
    spawn_pumps(dev.clone(), rx_prod, tx_cons);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    // Register with the kernel-side TCP stack: hands the stack a
    // `(mac, send_fn)` pair and a name. The RX-drain hook lets
    // kernel-side busy-wait paths (ARP / TCP handshake) pull
    // frames off the NIC ring directly while spinning, since the
    // spawned RX-pump task can't run while a syscall is parked
    // in `responsive_spin_until`.
    narf_net::iface::register("eth0", dev.mac, e1000_send_frame);
    narf_net::iface::install_rx_drain(rx_pump_step);

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, E1000Nic);
    }

    Ok(())
}

fn spawn_pumps(
    device: Arc<E1000>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        e1000_rx_pump(d1, rx_prod).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        e1000_tx_pump(d2, tx_cons).await;
    });
}

async fn e1000_rx_pump(device: Arc<E1000>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    // Adaptive RX poll. The old form `yield_now().await` every loop made
    // this task self-wake on EVERY executor round — a perpetually-runnable
    // task that kept the cooperative executor from ever halting
    // (nr_running never hit 0), pinned the CPU at 100%, and paced every
    // scheduler round at the spin rate. With a second idle NIC attached
    // (e1000 alongside virtio-net, the standard off-box-redis QEMU
    // config), that spin paced the WHOLE system: a freshly-woken peer
    // (the epoll-parked server task on the *other* NIC) waited a full
    // ~230 µs spinning round to be re-polled, turning a sub-100 µs wake
    // into a ~0.5 ms request latency. Fix: after a run of empty polls,
    // PARK on the timer wheel so the executor can halt; stay tight-poll
    // while frames are actually flowing.
    const IDLE_BACKOFF_ROUNDS: u32 = 64;
    let idle_park_cycles = narf_time::ns_to_cycles(1_000_000);
    let mut buf = [0u8; 2048];
    let mut idle_rounds: u32 = 0;
    loop {
        let n = device.rx_recv(&mut buf);
        if n > 0 {
            idle_rounds = 0;
            // Push to network stack.
            let dma_buf = alloc_coherent(n, DomainId::DRIVER_0).expect("Frame alloc failed");
            let mut frame = Frame::new(dma_buf, n as u32);
            frame.payload_mut().copy_from_slice(&buf[..n]);
            let _ = rx_prod.send(frame).await;
            continue;
        }
        idle_rounds = idle_rounds.saturating_add(1);
        if idle_rounds < IDLE_BACKOFF_ROUNDS {
            // Recently active: tight re-poll for low RX latency.
            narf_scheduler::yield_now().await;
        } else {
            // Idle: park ~1 ms on the timer wheel so the executor can
            // halt instead of spinning this empty poll every round.
            narf_time::sleep_cycles(idle_park_cycles).await;
        }
    }
}

async fn e1000_tx_pump(device: Arc<E1000>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.tx(frame.payload());
    }
}

/// SendFn registered with `narf_net::iface` at probe time. Routes
/// the kernel-side TCP stack's outbound frames through E1000::tx.
fn e1000_send_frame(frame: &[u8]) -> Result<(), ()> {
    // Clone the Arc out rather than holding the IRQ-masking CONTROLLER
    // lock across `tx`, which busy-polls the DD bit for up to 250 ms.
    // Holding it here masked interrupts on this CPU for the whole
    // hardware wait and made every concurrent sender (and the RX pump)
    // spin on the same lock, interrupts masked — a thundering herd that
    // starves timers and RCU. See `probed_controller`.
    let ctrl = probed_controller().ok_or(())?;
    ctrl.tx(frame).map_err(|_| ())
}

/// Drain one frame from the RX ring + dispatch it through the
/// network stack's RX handler. Returns true iff a frame was
/// processed. Called from a kernel-side polling task spawned at
/// boot.
pub fn rx_pump_step() -> bool {
    let mut buf = [0u8; 1600];
    // Same shape as `e1000_send_frame`: don't hold CONTROLLER across the
    // ring drain, or a TX stuck in its 250 ms DD poll under the same
    // lock stalls RX (and vice versa) with interrupts masked. `rx_recv`
    // serializes against other RX consumers on the controller's own
    // `rx_head` lock.
    let n = match probed_controller() {
        Some(c) => c.rx_recv(&mut buf),
        None => 0,
    };
    if n == 0 {
        return false;
    }
    // `&mut`: an attached XDP program may rewrite header bytes in place. `buf`
    // is this function's own stack scratch buffer holding a copy of the RX
    // descriptor's payload, so mutating it before the stack parses it out is
    // sound and never touches the live DMA ring.
    narf_net::iface::on_rx_frame_from("eth0", &mut buf[..n]);
    true
}

/// Every Intel device id this driver claims. Kept as a single
/// `const` so the `register_pci_driver` loop and the match-table
/// smoke test see the same list (and additions can't drift between
/// the two).
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    // Legacy / QEMU-emulated.
    E1000_DEV_82540EM,
    E1000_DEV_82545EM,
    E1000_DEV_82544GC,
    E1000E_DEV_82574L,
    // PCH-LPT (Haswell).
    E1000E_DEV_I217LM,
    E1000E_DEV_I217V,
    E1000E_DEV_I218LM,
    E1000E_DEV_I218V,
    E1000E_DEV_I218LM2,
    E1000E_DEV_I218V2,
    E1000E_DEV_I218LM3,
    E1000E_DEV_I218V3,
    // PCH-SPT (Skylake-H).
    E1000E_DEV_I219LM,
    E1000E_DEV_I219V,
    E1000E_DEV_I219LM2,
    E1000E_DEV_I219V2,
    E1000E_DEV_I219LM3,
    E1000E_DEV_I219LM4,
    E1000E_DEV_I219V4,
    E1000E_DEV_I219LM5,
    E1000E_DEV_I219V5,
    // PCH-CNP (Coffee / Cannon Lake).
    E1000E_DEV_I219LM6,
    E1000E_DEV_I219V6,
    E1000E_DEV_I219LM7,
    E1000E_DEV_I219V7,
    // PCH-ICP (Ice Lake).
    E1000E_DEV_I219LM8,
    E1000E_DEV_I219V8,
    E1000E_DEV_I219LM9,
    E1000E_DEV_I219V9,
    // PCH-CMP (Comet Lake).
    E1000E_DEV_I219LM10,
    E1000E_DEV_I219V10,
    E1000E_DEV_I219LM11,
    E1000E_DEV_I219V11,
    E1000E_DEV_I219LM12,
    E1000E_DEV_I219V12,
    // PCH-TGP (Tiger Lake).
    E1000E_DEV_I219LM13,
    E1000E_DEV_I219V13,
    E1000E_DEV_I219LM14,
    E1000E_DEV_I219V14,
    E1000E_DEV_I219LM15,
    E1000E_DEV_I219V15,
    // PCH-ADP (Alder Lake) + PCH-RPL (Raptor Lake).
    E1000E_DEV_I219LM16,
    E1000E_DEV_I219V16,
    E1000E_DEV_I219LM17,
    E1000E_DEV_I219V17,
    E1000E_DEV_I219LM19,
    E1000E_DEV_I219V19,
    E1000E_DEV_I219LM22,
    E1000E_DEV_I219V22,
    E1000E_DEV_I219LM23,
    E1000E_DEV_I219V23,
    // PCH-MTP (Meteor Lake) — covers Phoenix HawkPoint1 PCH LOM.
    E1000E_DEV_I219LM18,
    E1000E_DEV_I219V18,
    // PCH-LNP (Lunar Lake).
    E1000E_DEV_I219LM20,
    E1000E_DEV_I219V20,
    E1000E_DEV_I219LM21,
    E1000E_DEV_I219V21,
    // PCH-ARL (Arrow Lake).
    E1000E_DEV_I219LM24,
    E1000E_DEV_I219V24,
    // PCH-PTP (Panther Lake).
    E1000E_DEV_I219LM25,
    E1000E_DEV_I219V25,
    E1000E_DEV_I219LM27,
    E1000E_DEV_I219V27,
    // PCH-NVL (Nova Lake).
    E1000E_DEV_I219LM29,
    E1000E_DEV_I219V29,
    // I210 / I211 / 82576 / I350 (Linux: `igb`).
    E1000_DEV_I210_COPPER,
    E1000_DEV_I210_FIBER,
    E1000_DEV_I210_SERDES,
    E1000_DEV_I210_SGMII,
    E1000_DEV_I210_COPPER_FLASHLESS,
    E1000_DEV_I210_SERDES_FLASHLESS,
    E1000_DEV_I211_COPPER,
    E1000_DEV_82576,
    E1000_DEV_82576_NS,
    E1000_DEV_I350_COPPER,
];

/// Register the driver against every Intel device id we recognise.
/// One match per id pair so each is independently maintainable.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: E1000_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        E1000_DEV_82540EM => "e1000-82540em",
        E1000_DEV_82545EM => "e1000-82545em",
        E1000_DEV_82544GC => "e1000-82544gc",
        E1000E_DEV_82574L => "e1000e-82574l",
        // PCH-LPT.
        E1000E_DEV_I217LM => "e1000e-i217lm",
        E1000E_DEV_I217V => "e1000e-i217v",
        E1000E_DEV_I218LM => "e1000e-i218lm",
        E1000E_DEV_I218V => "e1000e-i218v",
        E1000E_DEV_I218LM2 => "e1000e-i218lm2",
        E1000E_DEV_I218V2 => "e1000e-i218v2",
        E1000E_DEV_I218LM3 => "e1000e-i218lm3",
        E1000E_DEV_I218V3 => "e1000e-i218v3",
        // PCH-SPT.
        E1000E_DEV_I219LM => "e1000e-i219lm",
        E1000E_DEV_I219V => "e1000e-i219v",
        E1000E_DEV_I219LM2 => "e1000e-i219lm2",
        E1000E_DEV_I219V2 => "e1000e-i219v2",
        E1000E_DEV_I219LM3 => "e1000e-i219lm3",
        E1000E_DEV_I219LM4 => "e1000e-i219lm4",
        E1000E_DEV_I219V4 => "e1000e-i219v4",
        E1000E_DEV_I219LM5 => "e1000e-i219lm5",
        E1000E_DEV_I219V5 => "e1000e-i219v5",
        // PCH-CNP.
        E1000E_DEV_I219LM6 => "e1000e-i219lm6",
        E1000E_DEV_I219V6 => "e1000e-i219v6",
        E1000E_DEV_I219LM7 => "e1000e-i219lm7",
        E1000E_DEV_I219V7 => "e1000e-i219v7",
        // PCH-ICP.
        E1000E_DEV_I219LM8 => "e1000e-i219lm8",
        E1000E_DEV_I219V8 => "e1000e-i219v8",
        E1000E_DEV_I219LM9 => "e1000e-i219lm9",
        E1000E_DEV_I219V9 => "e1000e-i219v9",
        // PCH-CMP.
        E1000E_DEV_I219LM10 => "e1000e-i219lm10",
        E1000E_DEV_I219V10 => "e1000e-i219v10",
        E1000E_DEV_I219LM11 => "e1000e-i219lm11",
        E1000E_DEV_I219V11 => "e1000e-i219v11",
        E1000E_DEV_I219LM12 => "e1000e-i219lm12",
        E1000E_DEV_I219V12 => "e1000e-i219v12",
        // PCH-TGP.
        E1000E_DEV_I219LM13 => "e1000e-i219lm13",
        E1000E_DEV_I219V13 => "e1000e-i219v13",
        E1000E_DEV_I219LM14 => "e1000e-i219lm14",
        E1000E_DEV_I219V14 => "e1000e-i219v14",
        E1000E_DEV_I219LM15 => "e1000e-i219lm15",
        E1000E_DEV_I219V15 => "e1000e-i219v15",
        // PCH-ADP / RPL.
        E1000E_DEV_I219LM16 => "e1000e-i219lm16",
        E1000E_DEV_I219V16 => "e1000e-i219v16",
        E1000E_DEV_I219LM17 => "e1000e-i219lm17",
        E1000E_DEV_I219V17 => "e1000e-i219v17",
        E1000E_DEV_I219LM19 => "e1000e-i219lm19",
        E1000E_DEV_I219V19 => "e1000e-i219v19",
        E1000E_DEV_I219LM22 => "e1000e-i219lm22",
        E1000E_DEV_I219V22 => "e1000e-i219v22",
        E1000E_DEV_I219LM23 => "e1000e-i219lm23",
        E1000E_DEV_I219V23 => "e1000e-i219v23",
        // PCH-MTP / LNP / ARL / PTP / NVL.
        E1000E_DEV_I219LM18 => "e1000e-i219lm18",
        E1000E_DEV_I219V18 => "e1000e-i219v18",
        E1000E_DEV_I219LM20 => "e1000e-i219lm20",
        E1000E_DEV_I219V20 => "e1000e-i219v20",
        E1000E_DEV_I219LM21 => "e1000e-i219lm21",
        E1000E_DEV_I219V21 => "e1000e-i219v21",
        E1000E_DEV_I219LM24 => "e1000e-i219lm24",
        E1000E_DEV_I219V24 => "e1000e-i219v24",
        E1000E_DEV_I219LM25 => "e1000e-i219lm25",
        E1000E_DEV_I219V25 => "e1000e-i219v25",
        E1000E_DEV_I219LM27 => "e1000e-i219lm27",
        E1000E_DEV_I219V27 => "e1000e-i219v27",
        E1000E_DEV_I219LM29 => "e1000e-i219lm29",
        E1000E_DEV_I219V29 => "e1000e-i219v29",
        // I210 / I211 / 82576 / I350.
        E1000_DEV_I210_COPPER => "igb-i210-copper",
        E1000_DEV_I210_FIBER => "igb-i210-fiber",
        E1000_DEV_I210_SERDES => "igb-i210-serdes",
        E1000_DEV_I210_SGMII => "igb-i210-sgmii",
        E1000_DEV_I210_COPPER_FLASHLESS => "igb-i210-copper-flashless",
        E1000_DEV_I210_SERDES_FLASHLESS => "igb-i210-serdes-flashless",
        E1000_DEV_I211_COPPER => "igb-i211-copper",
        E1000_DEV_82576 => "igb-82576",
        E1000_DEV_82576_NS => "igb-82576-ns",
        E1000_DEV_I350_COPPER => "igb-i350-copper",
        _ => "e1000",
    }
}

#[derive(Debug)]
pub struct E1000Nic;

impl narf_net::Interface for E1000Nic {
    fn name(&self) -> &str {
        "eth0"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.link_up).unwrap_or(false)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.rx_ipc_ring.lock().take();
            }
        });
        &RING
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.tx_ipc_ring.lock().take();
            }
        });
        &RING
    }
}

impl crate::HwNic for E1000Nic {
    fn name(&self) -> &'static str {
        "eth0"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.link_up).unwrap_or(false)
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::IntelE1000
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::TX_CSUM | crate::NicCaps::RX_CSUM
    }
    fn ring_capacity(&self) -> usize {
        RX_RING_LEN
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        <Self as narf_net::Interface>::rx_ring(self)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Self as narf_net::Interface>::tx_ring(self)
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Clone the installed controller handle, holding `CONTROLLER` only for
/// the refcount bump.
///
/// `CONTROLLER` is an `IrqSafeSpinLock`, so holding it across a device
/// round-trip masks interrupts on the waiting CPU for the whole wait and
/// forces every other CPU touching the NIC to spin with interrupts
/// masked too — `tx` busy-polls the descriptor DD bit for up to 250 ms,
/// which starves timers and RCU exactly like the virtio-blk CONTROLLER
/// herd. Cloning the `Arc` out instead keeps the device alive without
/// any lock held; mutual exclusion on the rings is provided by the
/// controller's own `tx_tail`/`rx_head` locks, which are held only
/// across the bounded descriptor post/drain, never across the DD poll.
pub fn probed_controller() -> Option<Arc<E1000>> {
    CONTROLLER.lock().clone()
}

/// Run `f` against the probed controller WITHOUT holding `CONTROLLER`
/// for the duration — see [`probed_controller`]. `f` may block or poll
/// the device; interrupts keep their caller-supplied state throughout.
pub fn with_controller<R>(f: impl FnOnce(&E1000) -> R) -> Option<R> {
    probed_controller().map(|a| f(&a))
}

/// IRQ-driven RX. Constructs the `wait_for_irq` future *before*
/// inspecting the ring (so an IRQ that lands between the ring drain
/// and the await still wakes us — the future snapshots fire-count
/// at construction). On wake, drains one frame into `out` and
/// returns the byte count. Returns 0 if no controller is bound or
/// no IRQ vector is wired (caller should fall back to `rx_recv`).
pub async fn rx_async(out: &mut [u8]) -> usize {
    let vector = match with_controller(|c| c.irq_vector).flatten() {
        Some(v) => v,
        None => return 0,
    };
    // Construct the wait future *before* we look at the ring. The
    // future captures the current fire-count as its baseline; if an
    // RX IRQ fires while we're inside `rx_recv`, the future resolves
    // immediately on next poll. 250 ms deadline bounds the dormancy
    // when the device goes silent or the IRQ isn't wired right —
    // we fall back to a polled re-drain instead of stalling
    // forever.
    let waiter = narf_interrupts::wait_for_irq_until(vector, narf_time::Deadline::after_ms(250));
    // Fast path: there might already be a frame ready (e.g. an IRQ
    // landed before we got here). Drain it without awaiting.
    if let Some(n) = with_controller(|c| {
        if c.rx_has_pending() {
            Some(c.rx_recv(out))
        } else {
            None
        }
    })
    .flatten()
    {
        // Cancel the waiter — clear_waker fires in its Drop.
        drop(waiter);
        return n;
    }
    // Slow path: await the next RX IRQ OR timeout, then drain
    // whatever the ring has (Ok or Err: drain either way).
    let _ = waiter.await;
    with_controller(|c| c.rx_recv(out)).unwrap_or(0)
}

/// IRQ-driven TX. Posts `frame` to the TX ring then awaits TXDW.
/// Mirrors the polled `tx` semantics (one frame per call) but parks
/// the caller on the IRQ instead of spinning on DD. Falls back to
/// the polled `tx` path if no IRQ vector is wired.
pub async fn tx_async(frame: &[u8]) -> Result<(), E1000Error> {
    let vector = match with_controller(|c| c.irq_vector).flatten() {
        Some(v) => v,
        None => {
            // No IRQ wired — synchronous path is the only option.
            return with_controller(|c| c.tx(frame)).unwrap_or(Err(E1000Error::UnsupportedDevice));
        }
    };
    // Construct the future first, then enqueue. If the device
    // completes before we await, the post-enqueue fire-count check
    // inside `WaitForIrq::poll` resolves immediately. 500 ms
    // deadline bounds the wait — TX completes in microseconds
    // normally; if it doesn't, the IRQ isn't wired right and we
    // should bail rather than stall.
    let waiter = narf_interrupts::wait_for_irq_until(vector, narf_time::Deadline::after_ms(500));
    let slot = match with_controller(|c| c.tx_enqueue(frame))
        .unwrap_or(Err(E1000Error::UnsupportedDevice))
    {
        Ok(s) => s,
        Err(e) => {
            drop(waiter);
            return Err(e);
        }
    };
    // Await the pre-enqueue waiter, then loop on additional IRQs in
    // case the wake was for a different cause (e.g. RXT0) and our
    // slot's DD bit isn't yet set. Each iteration has its own
    // deadline; if we hit 5 spurious wakes the caller's higher-
    // level timeout (sys_send, etc.) will abort us.
    let _ = waiter.await;
    while !with_controller(|c| c.tx_slot_done(slot)).unwrap_or(false) {
        let _ =
            narf_interrupts::wait_for_irq_until(vector, narf_time::Deadline::after_ms(500)).await;
    }
    Ok(())
}
