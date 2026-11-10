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
//! | 0x0170  | FCTTV| Flow Control Transmit Timer Value |
//! | 0x0400  | TCTL | Transmit Control                  |
//! | 0x1000  | PBA  | Packet Buffer Allocation (RXA = RX KB) |
//! | 0x2160  | FCRTL| Flow Control Receive Threshold Low |
//! | 0x2168  | FCRTH| Flow Control Receive Threshold High |
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

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};

use alloc::sync::Arc;
use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, pool::DmaPool, DmaBuffer};
use narf_ipc::{channel, Consumer, Producer};
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
// The I210/I211/82576/I350 entries that used to be squatted here now
// live in the dedicated `narf-drivers-net-igb` crate, which drives them
// on the advanced-descriptor path (like igc.rs for I225/I226).

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

// I210 / I211 / 82576 / I350 moved to the dedicated advanced-descriptor
// `narf-drivers-net-igb` crate. The legacy 8254x
// bring-up here cannot drive them correctly (no advanced RX/TX descriptors,
// no SRRCTL, no extended MSI-X routing, no per-queue TXDCTL/RXDCTL enable),
// so those IDs are no longer declared or claimed by this driver.

// ── Register offsets ────────────────────────────────────────────────

const REG_CTRL: u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
const STATUS_FD: u32 = 1 << 0;
const STATUS_LU: u32 = 1 << 1;
const STATUS_SPEED_MASK: u32 = 0b11 << 6;
const STATUS_SPEED_100: u32 = 0b01 << 6;
const STATUS_SPEED_1000: u32 = 0b10 << 6;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const REG_EERD: u64 = 0x0014;
/// Interrupt Cause Read — reading this register returns the set of
/// pending causes and clears them all (8254x SDM §13.4.17). The ISR
/// reads ICR exactly once per IRQ to acknowledge the device and
/// deassert legacy INTx.
const REG_ICR: u64 = 0x00C0;
/// Interrupt Throttling Rate. The interval is expressed in 256-ns units on
/// 82540-class hardware; zero disables moderation.
const REG_ITR: u64 = 0x00C4;
/// 82574/e1000e MSI-X interrupt-throttle register for vector 0. This driver
/// binds one shared vector, so only entry zero is programmed.
const REG_EITR0_82574: u64 = 0x00E8;
const REG_IMS: u64 = 0x00D0;
/// Interrupt Mask Clear — writing 1 to a bit disables that cause's
/// IRQ delivery (8254x SDM §13.4.22).
const REG_IMC: u64 = 0x00D8;
const REG_RCTL: u64 = 0x0100;
const REG_TCTL: u64 = 0x0400;
const REG_TIPG: u64 = 0x0410;
/// Flow Control Transmit Timer Value — pause quanta loaded into
/// transmitted pause frames (Linux e1000e regs.h `E1000_FCTTV`).
const REG_FCTTV: u64 = 0x0170;
/// Packet Buffer Allocation — low 16 bits (RXA) are the RX packet
/// buffer size in KB (Linux e1000e regs.h `E1000_PBA`).
const REG_PBA: u64 = 0x1000;
/// Flow Control Receive Threshold Low (Linux e1000e regs.h
/// `E1000_FCRTL`).
const REG_FCRTL: u64 = 0x2160;
/// Flow Control Receive Threshold High (Linux e1000e regs.h
/// `E1000_FCRTH`).
const REG_FCRTH: u64 = 0x2168;
/// Missed Packets Count — RX frames dropped for want of a descriptor
/// (receive-FIFO overrun). Clears on read. 8254x SDM §13.
const REG_MPC: u64 = 0x4010;
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

// VLAN filtering (802.1Q) — 8254x SDM §3.2.9 + §13 register block.
// VET holds the ethertype a packet must match to count as VLAN;
// VFTA is the 4096-bit VID filter (128 words of 32 bits). The
// 0x038 / 0x5600 bases are the shared 8254x register map, the same
// bases NARF's igb driver programs for its family (see
// drivers/net/igb/src/igb.rs); the 82540EP datasheet confirms
// 802.1Q filtering "for up to 4096 VLAN tags".
const REG_VET: u64 = 0x038; // VLAN Ether Type
const VET_8021Q: u32 = 0x8100;
const REG_VFTA_BASE: u64 = 0x5600; // VLAN Filter Table Array
const VFTA_WORDS: usize = 128; // 4096 VIDs / 32 bits per word

// Multicast filtering — 8254x SDM §3.2.1 + §13 register block.
// MTA is the 4096-bit hash vector (128 words); RAL/RAH is the
// 16-entry exact-match array (stride 8, RAH at +4, sharing the
// REG_RAL0 base). The 0x5200 MTA base is the shared 8254x register
// map (the 82580-family datasheet shows MTA at 0x5200 + 4n).
const REG_MTA_BASE: u64 = 0x5200; // Multicast Table Array
const MTA_WORDS: usize = 128; // 4096 hash bits / 32 bits per word
const REG_RAL_STRIDE: u64 = 8; // RAL array entry stride (RAH at +4)
const RAH_AV: u32 = 1 << 31; // Receive Address High: Address Valid
                             // RCTL.MO lives in bits 13:12 (SDM §13.4.22). This driver leaves
                             // MO = 0 (the reset value), selecting window [47:36]; the other
                             // windows are implemented in `multicast_hash12` for completeness
                             // and tested, but never programmed.

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

// MDIC (MDI Control) — PHY register access via MDIO. The 8254x SDM
// §13.4.19 register (offset 0x0020) carries one MDIO transaction:
// data in bits 15:0, register address in bits 20:16, PHY address in
// bits 25:21, opcode in bits 27:26 (01 = write, 10 = read), READY in
// bit 28, ERROR in bit 30. Values match Linux `e1000_hw.h`
// (`E1000_MDIC_*`) and the igb crate's in-tree MDIC constants
// (`drivers/net/igb/src/igb.rs`); the internal copper PHY lives at
// PHY address 1 on every bound part (Linux classic e1000 uses
// phy_addr 1 for all non-CE4100 parts; igb hardcodes the same).
/// `E1000_MDIC` — MDI Control.
const REG_MDIC: u64 = 0x0020;
/// `E1000_MDIC_DATA_MASK` — data field of an MDIC word.
const MDIC_DATA_MASK: u32 = 0x0000_FFFF;
/// `E1000_MDIC_REG_SHIFT` — register-address field shift.
const MDIC_REG_SHIFT: u32 = 16;
/// `E1000_MDIC_PHY_SHIFT` — PHY-address field shift.
const MDIC_PHY_SHIFT: u32 = 21;
/// Internal-PHY address (1) placed in the MDIC PHY field.
const MDIC_PHY_ADDR: u32 = 1 << MDIC_PHY_SHIFT;
/// `E1000_MDIC_OP_WRITE` — MDIC write opcode.
const MDIC_OP_WRITE: u32 = 0x0400_0000;
/// `E1000_MDIC_OP_READ` — MDIC read opcode.
const MDIC_OP_READ: u32 = 0x0800_0000;
/// `E1000_MDIC_READY` — transaction-complete bit.
const MDIC_READY: u32 = 1 << 28;
/// `E1000_MDIC_ERROR` — transaction-error bit (read path only).
const MDIC_ERROR: u32 = 1 << 30;

// IEEE 802.3 Clause 22 PHY registers (standard, not vendor-specific)
// and Clause 28/40 auto-negotiation words. Register numbers and bit
// values match Linux `include/linux/mii.h` (MII_BMCR 0, MII_BMSR 1,
// MII_PHYSID1 2, MII_PHYSID2 3, MII_ADVERTISE 4, MII_LPA 5,
// MII_CTRL1000 9, MII_STAT1000 0x0a); BMCR bits match the igb
// crate's in-tree constants too. No fresh SDM read was done for
// these — see the lane disclosure in the PR body.
/// PHY basic-mode control register.
const PHY_BMCR: u32 = 0;
/// PHY identifier register 1 (OUI bits 3–18).
const PHY_ID1: u32 = 2;
/// PHY auto-negotiation advertisement register.
const PHY_ANAR: u32 = 4;
/// PHY link-partner ability register.
const PHY_LPA: u32 = 5;
/// PHY 1000BASE-T control register.
const PHY_GBCR: u32 = 9;
/// PHY 1000BASE-T status register.
const PHY_STAT1000: u32 = 10;
/// BMCR auto-negotiation enable bit.
const BMCR_ANENABLE: u16 = 1 << 12;
/// BMCR auto-negotiation restart bit.
const BMCR_ANRESTART: u16 = 1 << 9;
/// BMSR link-status bit. Latch-low per IEEE 802.3 §22.2.4.2: once the
/// link drops the bit sticks at 0 until read, so a single read can
/// report a stale down — readers take two consecutive reads and
/// trust the second.
const BMSR_LINK: u16 = 1 << 2;
/// BMSR auto-negotiation complete bit. Same latch-low discipline as
/// LINK: readers take two consecutive reads and trust the second.
const BMSR_ANCOMPLETE: u16 = 1 << 5;
/// ANAR/LPA selector field value for IEEE 802.3 CSMA (bits 4:0).
const ANAR_SELECTOR_CSMA: u16 = 0x0001;
/// ANAR/LPA 10BASE-T half-duplex bit.
const ANAR_10HALF: u16 = 1 << 5;
/// ANAR/LPA 10BASE-T full-duplex bit.
const ANAR_10FULL: u16 = 1 << 6;
/// ANAR/LPA 100BASE-TX half-duplex bit.
const ANAR_100HALF: u16 = 1 << 7;
/// ANAR/LPA 100BASE-TX full-duplex bit.
const ANAR_100FULL: u16 = 1 << 8;
/// ANAR/LPA symmetric pause bit. Advertised by this driver (gap
/// 7 landed): symmetric pause is what the datapath implements
/// (thresholds + RFCE/TFCE).
const ANAR_PAUSE: u16 = 1 << 10;
/// ANAR/LPA asymmetric pause bit. NOT advertised: this driver
/// implements symmetric pause only, and per the IEEE resolution
/// table the ASM bit changes no outcome once PAUSE is set — so
/// advertising it would claim a mode we do not distinguish.
const ANAR_PAUSE_ASYM: u16 = 1 << 11;
/// ANAR 10/100 speed bits — the field `aneg_anar_next` rewrites.
const ANAR_SPEED_MASK: u16 = ANAR_10HALF | ANAR_10FULL | ANAR_100HALF | ANAR_100FULL;
/// ANAR pause bits — the pair the resolution table reads.
const ANAR_PAUSE_MASK: u16 = ANAR_PAUSE | ANAR_PAUSE_ASYM;
/// 1000BASE-T control 1000BASE-T half-duplex advertisement bit.
const GBCR_1000HALF: u16 = 1 << 8;
/// 1000BASE-T control 1000BASE-T full-duplex advertisement bit.
const GBCR_1000FULL: u16 = 1 << 9;
/// 1000BASE-T control speed bits — the field `aneg_gbcr_next` rewrites.
const GBCR_SPEED_MASK: u16 = GBCR_1000HALF | GBCR_1000FULL;
/// 1000BASE-T status link-partner 1000BASE-T half-duplex bit.
const STAT1000_1000HALF: u16 = 1 << 10;
/// 1000BASE-T status link-partner 1000BASE-T full-duplex bit.
const STAT1000_1000FULL: u16 = 1 << 11;

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

/// EEE (IEEE 802.3az) Clause 45 MMD device + registers, and the
/// `narf_net::nic::EeeStatus` advertisement encoding shared with
/// igc (`drivers/net/igc/src/hardware.rs` `modes()`).
///
/// * MMD device 7 is the PCS; registers 60/61 are the EEE
///   advertisement / link-partner advertisement, 62/63 the
///   advertisement-2 pair that carries 2.5GBASE-T (IEEE 802.3
///   Table 45-89/45-90 region; in-tree precedent: igc reads
///   exactly 7/60, 7/61, 7/62, 7/63 for its EEE status).
/// * Clause 45 access rides Clause 22 MDIO through registers 13
///   (MMDAC, MMD access control) and 14 (MMDAAD, address/data);
///   the data phase sets MMDAC bit 14 (`0x4000`, "data, no address
///   post-increment") — the same sequence as igc's `mmd()`.
/// * Advertisement bits in `EeeStatus` are 8 = 100BASE-TX, 16 =
///   1000BASE-T, 32 = 2.5GBASE-T (igc's `modes()` closure).
/// * MMD 7/60 bit 1 = 100BASE-TX EEE, bit 2 = 1000BASE-T EEE;
///   MMD 7/62 bit 0 = 2.5GBASE-T EEE (the same decode as igc).
/// * PCH parts (I217/I218/I219) advertise 100M + 1G only: IPCNFG
///   carries exactly the `EEE_1G_AN` / `EEE_100M_AN` bits above —
///   there is no 2.5G advertisement bit on these parts, so a 2.5G
///   request bit is masked out of the IPCNFG word (never
///   programmed), while the MMD decode still reports it if a
///   partner advertises it.
pub const EEE_MMD_DEV: u16 = 7;
/// MMD EEE advertisement register (Clause 45, device 7).
pub const EEE_MMD_ADV: u16 = 60;
/// MMD link-partner EEE advertisement register (Clause 45, device 7).
pub const EEE_MMD_LP_ADV: u16 = 61;
/// MMD EEE advertisement-2 register (Clause 45, device 7; 2.5G).
pub const EEE_MMD_ADV2: u16 = 62;
/// MMD link-partner EEE advertisement-2 register (Clause 45, device 7).
pub const EEE_MMD_LP_ADV2: u16 = 63;
/// Clause 22 MMD access-control register (MMDAC).
pub const PHY_MMDAC: u32 = 13;
/// Clause 22 MMD access address/data register (MMDAAD).
pub const PHY_MMDAAD: u32 = 14;
/// MMDAC function field for the data phase (bit 14: data access,
/// no address post-increment) — igc's `mmd()` writes
/// `dev | 0x4000` here.
pub const MMDAC_FUN_DATA: u16 = 0x4000;
/// `EeeStatus` advertised/partner bit: 100BASE-TX EEE.
pub const EEE_ADV_100M: u32 = 1 << 3;
/// `EeeStatus` advertised/partner bit: 1000BASE-T EEE.
pub const EEE_ADV_1G: u32 = 1 << 4;
/// `EeeStatus` advertised/partner bit: 2.5GBASE-T EEE.
pub const EEE_ADV_2_5G: u32 = 1 << 5;
/// Speeds a PCH part can advertise EEE on (100M + 1G only).
pub const EEE_PCH_SUPPORTED: u32 = EEE_ADV_100M | EEE_ADV_1G;

// CTRL bits.
const CTRL_RST: u32 = 1 << 26;
const CTRL_SLU: u32 = 1 << 6; // Set Link Up
                              // VLAN Mode Enable (8254x SDM §13.4.1). The single VLAN-mode gate
                              // for both directions: on RX, a VET-matching packet has its 4-byte
                              // tag stripped and the TCI recorded in the descriptor's `special`
                              // field (SDM §3.2); on TX, it enables VLE tag insertion (SDM
                              // §3.3.3.1: "otherwise VLE capability is ignored"). NOTE: SDM §3.2
                              // prose writes "RCTL.VME", but the §13 register tables place VME
                              // only in CTRL bit 30, and §3.3.3.1 confirms CTRL.VME gates VLE —
                              // this driver treats CTRL.VME as the one gate, and the RX path
                              // re-inserts stripped tags, so leaving it set once enabled is safe.
const CTRL_VME: u32 = 1 << 30; // VLAN Mode Enable
/// CTRL Receive Flow Control Enable (Linux e1000e defines.h
/// `E1000_CTRL_RFCE`): honor incoming pause frames.
const CTRL_RFCE: u32 = 1 << 27;
/// CTRL Transmit Flow Control Enable (Linux e1000e defines.h
/// `E1000_CTRL_TFCE`): generate pause frames.
const CTRL_TFCE: u32 = 1 << 28;
/// CTRL flow-control bits — the mask `configure_flow_control`
/// rewrites (read-modify-write preserves SLU, VME, and friends).
const CTRL_FC_MASK: u32 = CTRL_RFCE | CTRL_TFCE;
/// Flow-control threshold masks (Linux e1000e defines.h): both
/// thresholds live in bits 15:3, i.e. 8-byte granularity.
const FCRTL_RTL_MASK: u32 = 0x0000FFF8;
const FCRTH_RTH_MASK: u32 = 0x0000FFF8;
/// FCRTL XON-enable bit (Linux e1000e defines.h
/// `E1000_FCRTL_XONE`): with it set the MAC transmits an XON
/// frame when occupancy drops below the low threshold.
const FCRTL_XONE: u32 = 1 << 31;
/// PBA RX-allocation field mask (Linux e1000e defines.h
/// `E1000_PBA_RXA_MASK`): low 16 bits are the RX buffer size in KB.
const PBA_RXA_MASK: u32 = 0xFFFF;
/// Pause quanta loaded into transmitted pause frames (Linux
/// e1000e `E1000_FC_PAUSE_TIME`, 0x0680 quanta ≈ 858 µs at 1 GbE).
const FC_PAUSE_TIME: u32 = 0x0680;
// NOTE: the flow-control high watermark is capped by the largest
// frame that can arrive (`crate::mtu::rx_frame_size`, derived from
// the programmed MTU at the call site) — the old `FC_MAX_FRAME`
// 1518 literal is gone with the hardcoded MTU (issue #802).

// TCTL bits.
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3; // Pad Short Packets
const TCTL_CT_15: u32 = 15 << 4;
const TCTL_COLD_63: u32 = 63 << 12;
const TCTL_RTLC: u32 = 1 << 24; // Re-transmit on late collision
                                // Linux's 82543+ copper defaults: IPGT=8, IPGR1=8, IPGR2=6.
const TIPG_COPPER_DEFAULT: u32 = 8 | (8 << 10) | (6 << 20);

// TX descriptor flags.
const TXD_CMD_EOP: u8 = 1 << 0;
const TXD_CMD_IFCS: u8 = 1 << 1; // Insert FCS
const TXD_CMD_RS: u8 = 1 << 3; // Report Status
                               // VLAN Packet Enable (8254x SDM §3.3.3.1, Table 3-10): when set on
                               // a legacy data descriptor, hardware inserts the 802.1Q tag (VET
                               // ethertype + the descriptor's `special` TCI) into the transmitted
                               // frame. Requires CTRL.VME set, and is valid only when EOP is set.
const TXD_CMD_VLE: u8 = 1 << 6; // VLAN Packet Enable
const TXD_STAT_DD: u8 = 1 << 0; // Done

// TX checksum / TSO bits for the legacy e1000 descriptor.
// Source: Linux e1000_hw.h E1000_TXD_CMD_DEXT / E1000_TXD_CMD_TSE.
/// DEXT — Descriptor Extension flag. Must be set when checksum or TSO
/// offload bits are active.
pub const TXD_CMD_DEXT: u8 = 1 << 5;
/// TSE — TCP Segmentation Enable. Combined with DEXT + DTYP_D.
pub const TXD_CMD_TSE: u8 = 1 << 2;
/// DTYP_D — data descriptor type indicator. This is bit 20 of the lower
/// dword, therefore bit 4 of [`TxDesc::cso`], not of `cmd`.
pub const TXD_DTYP_D: u8 = 1 << 4;
/// IXSM — Insert IP Checksum. Placed in the `css` byte alongside DEXT.
pub const TXD_OPTS_IXSM: u8 = 1 << 0;
/// TXSM — Insert TCP/UDP Checksum.
pub const TXD_OPTS_TXSM: u8 = 1 << 1;

// Context-descriptor command bits occupy the high byte of cmd_and_length.
const TXD_CTX_CMD_TCP: u32 = 1 << 24;
const TXD_CTX_CMD_IP: u32 = 1 << 25;
const TXD_CTX_CMD_TSE: u32 = 1 << 26;
const TXD_CTX_CMD_DEXT: u32 = 1 << 29;
const TXD_CTX_PAYLEN_MASK: u32 = (1 << 20) - 1;

// RX descriptor status/error bits (Linux e1000_hw.h E1000_RXD_STAT_* /
// E1000_RXD_ERR_*). Status: IPCS = IP checksum calculated, TCPCS = TCP
// checksum calculated, UDPCS = UDP checksum calculated, IXSM = checksum
// ignored by hardware. Errors: IPE / TCPE = IP / TCP-UDP checksum error;
// CE / SE / SEQ / CXE / RXE = frame errors Linux drops unless RXALL
// (e1000e FRAME_ERR_MASK).
pub const RXD_STAT_IPCS: u8 = 1 << 6;
pub const RXD_STAT_TCPCS: u8 = 1 << 5;
pub const RXD_STAT_UDPCS: u8 = 1 << 4;
pub const RXD_STAT_IXSM: u8 = 1 << 2;
pub const RXD_ERR_IPE: u8 = 1 << 6;
pub const RXD_ERR_TCPE: u8 = 1 << 5;
pub const RXD_ERR_CE: u8 = 1 << 0;
pub const RXD_ERR_SE: u8 = 1 << 1;
pub const RXD_ERR_SEQ: u8 = 1 << 2;
pub const RXD_ERR_CXE: u8 = 1 << 4;
pub const RXD_ERR_RXE: u8 = 1 << 7;
pub const RXD_ERR_FRAME_MASK: u8 =
    RXD_ERR_CE | RXD_ERR_SE | RXD_ERR_SEQ | RXD_ERR_CXE | RXD_ERR_RXE;

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
/// Long Packet Enable (8254x SDM §13.4.22; same bit on e1000e):
/// with LPE clear the receiver drops frames longer than the
/// standard maximum; jumbo MTUs need it set. Linux `e1000` /
/// `e1000e` set `E1000_RCTL_LPE` (0x20) whenever the MTU exceeds
/// 1500.
const RCTL_LPE: u32 = 1 << 5;
const RCTL_BAM: u32 = 1 << 15; // Broadcast Accept
const RCTL_BSIZE_2K: u32 = 0 << 16; // Buffer Size = 2048
/// Buffer Size = 16384 (RCTL.BSIZE field 11b; Linux
/// `E1000_RCTL_BSIZE_16384`). The only step that holds a jumbo
/// frame; see `crate::mtu`.
const RCTL_BSIZE_16K: u32 = 0x3 << 16;
/// RCTL.BSIZE field mask (bits 17:16).
const RCTL_BSIZE_MASK: u32 = 0x3 << 16;
// VLAN Filter Enable (8254x SDM §13.4.22). When set, a received
// 802.1Q frame (type matches VET) is accepted only if its VID bit
// is set in the VFTA; otherwise it is dropped (SDM §3.2.9).
const RCTL_VFE: u32 = 1 << 18; // VLAN Filter Enable
const RCTL_SECRC: u32 = 1 << 26; // Strip Ethernet CRC

/// RCTL.BSIZE + LPE bits for `mtu` (issue #802): the 16K buffer
/// step plus Long Packet Enable once the MTU exceeds standard, the
/// 2K step with LPE clear otherwise. Every RCTL program in this
/// file (bring-up, suspend-off, resume, `program_mtu`) derives
/// these two bits from this one function so the words cannot drift.
const fn rctl_bsize_lpe(mtu: u32) -> u32 {
    if mtu > crate::mtu::STD_MTU {
        RCTL_BSIZE_16K | RCTL_LPE
    } else {
        RCTL_BSIZE_2K
    }
}

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
/// Linux's initial conservative e1000 rate is 20,000 interrupts/second. The
/// register stores the interval in 256-ns units: 1e9 / (20_000 * 256) = 195.
const ITR_20K_INTERRUPTS_PER_SEC: u32 = 195;

/// One page of 16-byte legacy TX descriptors. Keep one entry unused so TDT
/// never catches TDH and makes a full ring indistinguishable from an empty
/// one. The prior 8-entry ring plus a per-packet DD wait serialized QEMU's
/// e1000 model to a few Mbit/s; a 256-entry ring gives the device a useful
/// batch while retaining the legacy descriptor format.
const TX_RING_LEN: usize = 256;
const TX_RING_USABLE: usize = TX_RING_LEN - 1;

/// TX watchdog timeout (Linux `dev->watchdog_timeo` is 5 s by
/// default, and igc's supervisor uses the same 5 s): a TX descriptor
/// posted longer ago than this with no DD is a wedged ring, not
/// congestion.
const TX_TIMEOUT_NS: u64 = 5_000_000_000;
/// Watchdog supervisor cadence, matching igc's 10 ms maintenance tick.
const TX_WATCHDOG_POLL_NS: u64 = 10_000_000;
/// The stack may hand the device one complete Ethernet/IPv4/TCP super-frame
/// up to this size. A 64-KiB coherent buffer remains within the allocator's
/// single-segment contract and lets the 8254x TSO engine amortize stack and
/// doorbell work across a full TCP send-buffer chunk.
const MAX_TSO_FRAME: usize = 64 * 1024;
/// 8254x descriptors are deliberately split at 4 KiB, matching the legacy
/// Linux driver's controller-errata-safe maximum data per descriptor.
const MAX_DATA_PER_TXD: usize = 4096;
/// RX descriptor ring depth. The ring page is 4096 bytes = 256 × 16-byte
/// descriptors, so 256 is the most the existing allocation holds and matches
/// the Linux e1000 default. An 8-deep ring overran (RXO) under any burst —
/// a `curl` download or `ping` flood fills 8 slots before the RX pump drains
/// them and the device silently drops the rest — so the ring is sized to
/// absorb a full burst. RDLEN = 256*16 = 4096 (128-byte-aligned, valid).
const RX_RING_LEN: usize = 256;
/// Buffer size for each RX entry, in bytes. Sized once for the
/// family's largest frame (`crate::mtu::RX_BUF_BYTES`, 16384: the
/// classic 16128-byte max frame); RCTL.BSIZE selects how much of
/// it the device may use at the *current* MTU (2K at 1500, 16K
/// when jumbo), so the allocation never moves on an MTU change.
const RX_BUF_LEN: usize = crate::mtu::RX_BUF_BYTES;
/// Maximum descriptors returned to hardware by one RX-pump pass. Batching the
/// RDT doorbell avoids one MMIO write (and one QEMU VM exit) per Ethernet
/// frame, while the finite budget prevents sustained RX from monopolising the
/// cooperative executor.
const RX_DRAIN_BUDGET: usize = 64;

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct TxDesc {
    pub addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

const _: () = assert!(core::mem::size_of::<TxDesc>() == 16);

/// 8254x extended transmit context descriptor. A TSO packet is described by
/// one of these followed by one or more extended data descriptors.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxContextDesc {
    pub ipcss: u8,
    pub ipcso: u8,
    pub ipcse: u16,
    pub tucss: u8,
    pub tucso: u8,
    pub tucse: u16,
    pub cmd_and_length: u32,
    pub status: u8,
    pub hdr_len: u8,
    pub mss: u16,
}

const _: () = assert!(core::mem::size_of::<TxContextDesc>() == 16);

/// Opaque handle for a reserved TX ring slot, returned by `tx_send_vlan`.
/// The slot/generation pair is meaningful only to the driver's own
/// completion polling (`tx_slot_done`); fields stay private so a caller
/// cannot forge a ticket for a slot it never reserved. `epoch` is the
/// ring epoch at reservation time: a watchdog recovery resets the
/// cursor and advances the epoch, so a ticket from before the reset
/// never compares as completed — its frame was dropped with the ring,
/// and its `tx()` call must time out rather than report a success it
/// did not earn.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxTicket {
    slot: usize,
    generation: u64,
    epoch: u64,
}

/// Pure producer/consumer bookkeeping for the legacy TX ring. Hardware owns
/// `[next_to_clean, next_to_use)`; software leaves one descriptor unused.
#[derive(Debug)]
struct TxRingCursor {
    next_to_use: usize,
    next_to_clean: usize,
    in_flight: usize,
    generations: alloc::vec::Vec<u64>,
    /// Ring epoch, advanced by [`TxRingCursor::reset`] on every
    /// watchdog recovery. A ticket from an earlier epoch belongs to
    /// a ring whose descriptors were discarded with the reset.
    epoch: u64,
    /// Cycle counter at which each slot was posted (`0` = no
    /// descriptor outstanding). The watchdog treats an aged entry
    /// as a wedged ring.
    posted_at: alloc::vec::Vec<u64>,
}

impl TxRingCursor {
    fn new() -> Self {
        Self {
            next_to_use: 0,
            next_to_clean: 0,
            in_flight: 0,
            generations: alloc::vec![0; TX_RING_LEN],
            posted_at: alloc::vec![0; TX_RING_LEN],
            epoch: 0,
        }
    }

    /// Reset after the device was reset: no posted descriptor will
    /// ever complete, so every slot is free again and no post time
    /// survives. The epoch advances so tickets issued before the
    /// reset never compare as completed — their frames were dropped
    /// with the ring. Generations are preserved: a stale ticket's
    /// generation still matches only if its slot was never
    /// re-reserved, and the epoch gate in `tx_slot_done` decides
    /// the rest.
    fn reset(&mut self) {
        self.next_to_use = 0;
        self.next_to_clean = 0;
        self.in_flight = 0;
        self.posted_at.iter_mut().for_each(|t| *t = 0);
        self.epoch = self.epoch.wrapping_add(1);
    }

    fn reserve(&mut self) -> Option<TxTicket> {
        self.reserve_at(narf_time::now_cycles())
    }

    /// Reserve with an explicit post time, so the fixture can age a
    /// descriptor without waiting out a real 5 s stall.
    fn reserve_at(&mut self, now: u64) -> Option<TxTicket> {
        if self.in_flight >= TX_RING_USABLE {
            return None;
        }
        let slot = self.next_to_use;
        self.next_to_use = (slot + 1) % TX_RING_LEN;
        self.in_flight += 1;
        self.generations[slot] = self.generations[slot].wrapping_add(1);
        self.posted_at[slot] = now;
        Some(TxTicket {
            slot,
            generation: self.generations[slot],
            epoch: self.epoch,
        })
    }

    fn available(&self) -> usize {
        TX_RING_USABLE - self.in_flight
    }

    fn complete_oldest(&mut self) -> Option<usize> {
        if self.in_flight == 0 {
            return None;
        }
        let slot = self.next_to_clean;
        self.next_to_clean = (slot + 1) % TX_RING_LEN;
        self.in_flight -= 1;
        self.posted_at[slot] = 0;
        Some(slot)
    }

    /// True when any posted descriptor has waited longer than
    /// `timeout` cycles for its DD bit — the ring is wedged (igc
    /// `Queue::stalled` shape, per-slot so a later post cannot mask
    /// an older stuck one).
    fn stalled(&self, now: u64, timeout: u64) -> bool {
        self.posted_at
            .iter()
            .any(|&posted| posted != 0 && now.wrapping_sub(posted) > timeout)
    }

    fn ticket_was_reused(&self, ticket: TxTicket) -> bool {
        ticket.epoch == self.epoch && self.generations[ticket.slot] != ticket.generation
    }
}

#[derive(Debug)]
struct TxQueueState {
    cursor: TxRingCursor,
    /// A zero-copy buffer remains here until hardware writes DD for its slot.
    /// Copy-mode descriptors use the controller's persistent `tx_pool` and
    /// leave their entry `None`.
    owned: alloc::vec::Vec<Option<DmaBuffer>>,
    /// Descriptor whose DD bit completes the packet containing this slot.
    /// Plain packets watch themselves; every context/data slot in a TSO packet
    /// watches its final EOP/RS data descriptor.
    completion_slot: alloc::vec::Vec<usize>,
    /// Last producer tail published to TDT. This distinguishes descriptors
    /// queued behind `TxMeta::more` from descriptors hardware can already
    /// consume, which matters when the next multi-descriptor TSO packet does
    /// not fit in the remaining ring space.
    doorbell_tail: usize,
}

impl TxQueueState {
    fn new() -> Self {
        Self {
            cursor: TxRingCursor::new(),
            owned: (0..TX_RING_LEN).map(|_| None).collect(),
            completion_slot: (0..TX_RING_LEN).collect(),
            doorbell_tail: 0,
        }
    }

    fn needs_flush_for(&self, descriptor_count: usize) -> bool {
        self.cursor.available() < descriptor_count && self.doorbell_tail != self.cursor.next_to_use
    }

    /// True when a posted TX descriptor is older than `timeout`
    /// cycles (see [`TxRingCursor::stalled`]).
    fn stalled(&self, now: u64, timeout: u64) -> bool {
        self.cursor.stalled(now, timeout)
    }

    /// Reset all TX state after the device was reset: no posted
    /// descriptor will ever complete, so every slot is free again
    /// and no post time survives. Returns the zero-copy buffers the
    /// ring owned so the caller can return them to the pool instead
    /// of leaking a slot's worth of pool capacity per recovery.
    /// The cursor epoch advances, so tickets issued before the reset
    /// never compare as completed (see [`TxTicket`]).
    fn reset(&mut self) -> alloc::vec::Vec<Option<DmaBuffer>> {
        self.cursor.reset();
        self.completion_slot = (0..TX_RING_LEN).collect();
        self.doorbell_tail = 0;
        core::mem::replace(&mut self.owned, (0..TX_RING_LEN).map(|_| None).collect())
    }
}

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct RxDesc {
    pub addr: u64,
    pub length: u16,
    pub csum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

const _: () = assert!(core::mem::size_of::<RxDesc>() == 16);

impl RxDesc {
    /// Sample an RX ring slot the device may be completing right now.
    /// `word(i)` reads little-endian qword `i` of the 16-byte slot.
    ///
    /// The device writes the descriptor back while the host polls it, so a
    /// sample must never pair a fresh DD with fields of the slot's previous
    /// contents. Qword 1 carries length, checksum, status (with DD), errors
    /// and the VLAN tag: it is taken first and as ONE load, so a set DD
    /// always comes with the length and error bits written with it. Qword 0
    /// (the buffer address) is loaded only after DD was seen. `None` means
    /// "not completed": nothing else of the slot was read. Linux
    /// `e1000_clean_rx_irq` does the same: it tests `rx_desc->status`, then
    /// `dma_rmb()`, then reads the length.
    ///
    /// A whole-struct `read_volatile` gives no such order: the compiler
    /// lowers it to separate field loads in an order of its choosing, and
    /// `length` sits before `status`, so a DD posted between the two loads
    /// showed the re-armed slot's zero length under it.
    #[inline]
    fn sample(mut word: impl FnMut(usize) -> u64) -> Option<Self> {
        let upper = word(1);
        let status = (upper >> 32) as u8;
        if status & RXD_STAT_DD == 0 {
            return None;
        }
        // Pair the device's DD write with the loads that follow it.
        compiler_fence(Ordering::SeqCst);
        let addr = word(0);
        Some(Self {
            addr,
            length: upper as u16,
            csum: (upper >> 16) as u16,
            status,
            errors: (upper >> 40) as u8,
            special: (upper >> 48) as u16,
        })
    }
}

// ── Descriptor offload helpers ───────────────────────────────────────

impl TxDesc {
    /// Build a TX descriptor with IP + TCP/UDP checksum offload enabled.
    /// `csum_opts` should be `TXD_OPTS_IXSM | TXD_OPTS_TXSM` for
    /// full TCP/IPv4 offload. Setting DEXT + DTYP_D signals the
    /// hardware that the `css` byte carries offload options.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    pub fn new_with_csum(addr: u64, len: u16, csum_opts: u8) -> Self {
        let mut cmd = TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS;
        let mut cso = 0u8;
        let mut css = 0u8;
        if csum_opts != 0 {
            cmd |= TXD_CMD_DEXT;
            cso |= TXD_DTYP_D;
            css = csum_opts;
        }
        TxDesc {
            addr,
            length: len,
            cso,
            cmd,
            status: 0,
            css,
            special: 0,
        }
    }

    /// Build a TX descriptor with TSO enabled. The hardware will segment
    /// the payload into MSS-sized chunks using the preceding context
    /// descriptor. DEXT | DTYP_D | TSE must all be set; both IP and TCP
    /// checksum insertion bits are required. This public helper describes a
    /// one-buffer packet, so it marks the descriptor EOP + RS.
    pub fn with_tso(addr: u64, len: u16, _mss: u16) -> Self {
        Self::tso_data(addr, len, true)
    }

    fn tso_data(addr: u64, len: u16, last: bool) -> Self {
        let mut cmd = TXD_CMD_IFCS | TXD_CMD_DEXT | TXD_CMD_TSE;
        if last {
            cmd |= TXD_CMD_EOP | TXD_CMD_RS;
        }
        let css = TXD_OPTS_IXSM | TXD_OPTS_TXSM;
        TxDesc {
            addr,
            length: len,
            cso: TXD_DTYP_D,
            cmd,
            status: 0,
            css,
            special: 0,
        }
    }

    /// Build a legacy (non-offload) data descriptor. `vlan_tag` is
    /// `Some(tci)` for a VLAN-inserted frame: hardware adds the VET
    /// ethertype + tag (SDM §3.3.3.1) and the caller must have set
    /// CTRL.VME first; `None` is the plain descriptor the TX path
    /// has always built (VLE clear, `special` zero).
    pub fn legacy_data(addr: u64, len: u16, vlan_tag: Option<u16>) -> Self {
        let mut cmd = TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS;
        let mut special = 0u16;
        if let Some(tci) = vlan_tag {
            // VLE is valid only when EOP is set (SDM Table 3-10);
            // legacy_data always marks EOP, so this is safe here.
            cmd |= TXD_CMD_VLE;
            special = tci;
        }
        TxDesc {
            addr,
            length: len,
            cso: 0,
            cmd,
            status: 0,
            css: 0,
            special,
        }
    }
}

// ── VLAN filtering (802.1Q) ────────────────────────────────────────
// 8254x SDM §3.2.9: the VFTA is a 4096-bit vector indexed by VID.
// `VlanFilter` is the driver's shadow of that table: every register
// write the driver performs is computed from this shadow, so the
// fixture tests pin the exact word/value pairs the hardware sees.

/// VFTA word holding `vid`'s bit (VIDs 0..=4095 map onto words
/// 0..=127, 32 VIDs per word).
fn vfta_word(vid: u16) -> usize {
    vid as usize / 32
}

/// Bit within its VFTA word for `vid`.
fn vfta_bit(vid: u16) -> u32 {
    1u32 << (vid % 32)
}

/// Shadow of the hardware VFTA plus the count of programmed VIDs.
/// `add`/`remove` return `true` iff the shadow changed; duplicates
/// and out-of-range VIDs are no-ops (the caller distinguishes them
/// with [`VlanFilter::contains`]).
#[derive(Clone, Debug)]
pub struct VlanFilter {
    words: [u32; VFTA_WORDS],
    count: usize,
}

// NOTE: arrays implement Default only up to 32 elements, so the 128-word
// tables cannot derive it; Default is new() spelled out by hand.
impl Default for VlanFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl VlanFilter {
    pub const fn new() -> Self {
        Self {
            words: [0; VFTA_WORDS],
            count: 0,
        }
    }

    pub fn add(&mut self, vid: u16) -> bool {
        if vid > 4095 || self.contains(vid) {
            return false;
        }
        self.words[vfta_word(vid)] |= vfta_bit(vid);
        self.count += 1;
        true
    }

    pub fn remove(&mut self, vid: u16) -> bool {
        if !self.contains(vid) {
            return false;
        }
        self.words[vfta_word(vid)] &= !vfta_bit(vid);
        self.count -= 1;
        true
    }

    pub fn contains(&self, vid: u16) -> bool {
        vid <= 4095 && self.words[vfta_word(vid)] & vfta_bit(vid) != 0
    }

    pub fn word(&self, word: usize) -> u32 {
        self.words[word]
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Split a descriptor `special` field (the stripped 802.1Q TCI,
/// SDM §3.2 Table 3-4) into (VID, user priority, CFI).
fn vlan_tci_parts(tci: u16) -> (u16, u8, bool) {
    (tci & 0x0FFF, ((tci >> 13) & 0x7) as u8, tci & 0x1000 != 0)
}

/// Restore the wire format of a VLAN frame the hardware stripped:
/// shift the payload (everything after the 12-byte MAC header)
/// right by 4 bytes and write the TPID + TCI in the gap. `buf` is
/// the caller's buffer holding `len` stripped bytes; returns the
/// new length, or `None` when the frame is shorter than an Ethernet
/// header or the buffer has no room for the 4 re-inserted bytes
/// (caller then delivers the stripped frame as-is).
fn vlan_reinsert_tag(buf: &mut [u8], len: usize, tci: u16) -> Option<usize> {
    if len < 14 || buf.len() < len + 4 {
        return None;
    }
    buf.copy_within(12..len, 16);
    buf[12..14].copy_from_slice(&(VET_8021Q as u16).to_be_bytes());
    buf[14..16].copy_from_slice(&tci.to_be_bytes());
    Some(len + 4)
}

// ── Multicast filtering ─────────────────────────────────────────────
// 8254x SDM §3.2.1: exact match = the 16-entry RAL/RAH array; hash
// match = the 4096-bit MTA vector indexed by 12 bits of the
// destination address selected by RCTL.MO. Internal bit 0 is the
// first bit on the wire, so window [47:36] (MO = 0) is
// (mac[5] << 4) | (mac[4] >> 4) — mac[5] is the high byte of the
// slice, mac[4] the low byte.

/// 12-bit MTA index for `mac` under RCTL.MO window `mo` (0..=3):
/// MO 0 → [47:36], MO 1 → [46:35], MO 2 → [45:34], MO 3 → [43:32]
/// (SDM §3.2.1). Values above 3 fall through to the MO 3 window.
fn multicast_hash12(mac: &[u8; 6], mo: u8) -> u16 {
    let (hi, lo) = (mac[5] as u16, mac[4] as u16);
    let hash = match mo {
        0 => (hi << 4) | (lo >> 4),
        1 => (hi << 5) | (lo >> 3),
        2 => (hi << 6) | (lo >> 2),
        _ => (hi << 8) | lo,
    };
    hash & 0xFFF
}

/// MTA word holding `hash`'s bit (hashes 0..=4095 map onto words
/// 0..=127, 32 hashes per word).
fn mta_word(hash: u16) -> usize {
    hash as usize / 32
}

/// Bit within its MTA word for `hash`.
fn mta_bit(hash: u16) -> u32 {
    1u32 << (hash % 32)
}

/// Shadow of the hardware MTA plus the count of set hash bits.
/// Same changed/duplicate contract as [`VlanFilter`]. NOTE: the
/// count tracks set BITS, not addresses — two addresses hashing
/// to the same bit share it, and removing one clears it for both.
/// That is standard hash-filter semantics; an exact-match RAL slot
/// is the answer when a collision must not drop a peer.
#[derive(Clone, Debug)]
pub struct MulticastFilter {
    words: [u32; MTA_WORDS],
    count: usize,
}

// NOTE: arrays implement Default only up to 32 elements, so the 128-word
// tables cannot derive it; Default is new() spelled out by hand.
impl Default for MulticastFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl MulticastFilter {
    pub const fn new() -> Self {
        Self {
            words: [0; MTA_WORDS],
            count: 0,
        }
    }

    pub fn add(&mut self, mac: &[u8; 6]) -> bool {
        let hash = multicast_hash12(mac, 0);
        if self.words[mta_word(hash)] & mta_bit(hash) != 0 {
            return false;
        }
        self.words[mta_word(hash)] |= mta_bit(hash);
        self.count += 1;
        true
    }

    pub fn remove(&mut self, mac: &[u8; 6]) -> bool {
        let hash = multicast_hash12(mac, 0);
        if self.words[mta_word(hash)] & mta_bit(hash) == 0 {
            return false;
        }
        self.words[mta_word(hash)] &= !mta_bit(hash);
        self.count -= 1;
        true
    }

    pub fn contains(&self, mac: &[u8; 6]) -> bool {
        let hash = multicast_hash12(mac, 0);
        self.words[mta_word(hash)] & mta_bit(hash) != 0
    }

    pub fn clear(&mut self) {
        self.words = [0; MTA_WORDS];
        self.count = 0;
    }

    pub fn word(&self, word: usize) -> u32 {
        self.words[word]
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Encode a MAC into an (RAL, RAH) pair for one RAL-array slot.
/// Hardware expects little-endian byte order (RAL = bytes 0..3,
/// RAH = bytes 4..5) with the Address Valid bit set in RAH.
fn rar_encode(mac: &[u8; 6]) -> (u32, u32) {
    let ral =
        mac[0] as u32 | ((mac[1] as u32) << 8) | ((mac[2] as u32) << 16) | ((mac[3] as u32) << 24);
    let rah = mac[4] as u32 | ((mac[5] as u32) << 8) | RAH_AV;
    (ral, rah)
}

/// Runtime-programmable RAL slots are 1..=15. Slot 0 is the station
/// address, programmed once at bring-up from the value firmware
/// left in RAL0/RAH0; runtime callers must not overwrite it.
fn rar_slot_ok(slot: usize) -> bool {
    (1..=15).contains(&slot)
}

impl TxContextDesc {
    /// Build the context for one Ethernet/IPv4/TCP TSO super-frame. `ip_hlen`
    /// and `tcp_hlen` include options; `payload_len` excludes every header.
    pub fn ipv4_tso(ip_hlen: u8, tcp_hlen: u8, payload_len: u32, mss: u16) -> Self {
        let ipcss = 14u8;
        let tucss = ipcss.saturating_add(ip_hlen);
        Self {
            ipcss,
            ipcso: ipcss + 10,
            ipcse: u16::from(tucss).saturating_sub(1),
            tucss,
            tucso: tucss + 16,
            tucse: 0,
            cmd_and_length: TXD_CTX_CMD_DEXT
                | TXD_CTX_CMD_TSE
                | TXD_CTX_CMD_TCP
                | TXD_CTX_CMD_IP
                | (payload_len & TXD_CTX_PAYLEN_MASK),
            status: 0,
            hdr_len: tucss.saturating_add(tcp_hlen),
            mss,
        }
    }
}

/// Validate and convert a complete Ethernet/IPv4/TCP frame to the header form
/// the 8254x TSO engine consumes. The engine fills each segment's IPv4 length
/// and checksum; the TCP checksum starts with the zero-length pseudo-header
/// seed and is completed after segmentation.
fn prepare_ipv4_tso(frame: &mut [u8], mss: u16) -> Result<TxContextDesc, E1000Error> {
    const ETH_LEN: usize = 14;
    const IPV4_MIN: usize = 20;
    const TCP_MIN: usize = 20;
    if mss == 0 || frame.len() > MAX_TSO_FRAME || frame.len() < ETH_LEN + IPV4_MIN + TCP_MIN {
        return Err(E1000Error::FrameTooLong);
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 || frame[14] >> 4 != 4 {
        return Err(E1000Error::Other("TSO requires Ethernet/IPv4"));
    }
    let ip_hlen = usize::from(frame[14] & 0x0f) * 4;
    if !(IPV4_MIN..=60).contains(&ip_hlen)
        || frame.len() < ETH_LEN + ip_hlen + TCP_MIN
        || frame[23] != 6
    {
        return Err(E1000Error::Other("invalid IPv4/TCP TSO header"));
    }
    let frag = u16::from_be_bytes([frame[20], frame[21]]);
    if frag & 0x3fff != 0 {
        return Err(E1000Error::Other("fragmented IPv4 TSO frame"));
    }
    let tcp_off = ETH_LEN + ip_hlen;
    let tcp_hlen = usize::from(frame[tcp_off + 12] >> 4) * 4;
    if !(TCP_MIN..=60).contains(&tcp_hlen) || frame.len() < tcp_off + tcp_hlen {
        return Err(E1000Error::Other("invalid TCP TSO header"));
    }
    let payload_len = frame.len() - tcp_off - tcp_hlen;
    if payload_len == 0 || payload_len > TXD_CTX_PAYLEN_MASK as usize {
        return Err(E1000Error::FrameTooLong);
    }

    let src = [frame[26], frame[27], frame[28], frame[29]];
    let dst = [frame[30], frame[31], frame[32], frame[33]];
    frame[16..18].fill(0); // IPv4 total length: hardware writes each segment.
    frame[24..26].fill(0); // IPv4 checksum: hardware recomputes each segment.
    let seed = narf_net::pkt_tcp::ipv4_tcp_pseudo_seed(src, dst, 0);
    frame[tcp_off + 16..tcp_off + 18].copy_from_slice(&seed.to_be_bytes());

    Ok(TxContextDesc::ipv4_tso(
        ip_hlen as u8,
        tcp_hlen as u8,
        payload_len as u32,
        mss,
    ))
}

impl RxDesc {
    /// Decode the RX checksum result from the legacy e1000 descriptor
    /// status and errors bytes, in Linux `e1000e_rx_checksum` order:
    /// IXSM first (hardware ignored the checksum — no verdict), then
    /// error bits, then computed bits. Errors win over computed bits:
    /// a UDP frame reports its checksum via UDPCS, not TCPCS, so the
    /// old computed-first order returned `None` for a UDPCS-only frame
    /// carrying TCPE and missed a real checksum failure.
    pub fn csum_result(&self) -> RxCsumResult {
        if self.status & RXD_STAT_IXSM != 0 {
            return RxCsumResult::None;
        }
        if self.errors & (RXD_ERR_IPE | RXD_ERR_TCPE) != 0 {
            return RxCsumResult::Fail;
        }
        if self.status & (RXD_STAT_IPCS | RXD_STAT_TCPCS | RXD_STAT_UDPCS) != 0 {
            return RxCsumResult::Ok;
        }
        RxCsumResult::None
    }

    /// `true` if the descriptor carries a frame error Linux drops
    /// (CRC / symbol / sequence / carrier-extension / RX-data error),
    /// independent of the checksum verdict.
    pub fn has_frame_error(&self) -> bool {
        self.errors & RXD_ERR_FRAME_MASK != 0
    }
}

/// Why a received descriptor's frame must be dropped before delivery.
/// Pure decision helper over the descriptor bytes so the matrix is
/// fixture-pinned; both RX paths consult it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxDropReason {
    /// CRC error — reported via `note_rx_crc_error` (its own counter,
    /// also counted toward `rx_errs`).
    CrcError,
    /// Non-CRC frame error (symbol, sequence, carrier-extension, or
    /// RX-data). Linux drops these unless RXALL; NARF has no RXALL
    /// mode, so they are always dropped. Reported via `note_rx_drop`.
    FrameError,
    /// Hardware computed a checksum and it failed. Deliberate
    /// difference from Linux `e1000e`, which delivers the frame and
    /// lets the stack re-verify: NARF's stack would drop it anyway
    /// (`tcp_stack::handle_ipv4` / transport checksum verification),
    /// so dropping in-driver is fail-closed with the same end state —
    /// a bad frame never reaches a socket. The stack's
    /// `rx_csum::*_ERRORS` counters do not increment for these;
    /// the driver reports them via `note_rx_drop` instead.
    CsumFail,
}

/// Drop decision for one completed RX descriptor: CRC first (its own
/// counter), then other frame errors (their checksum bits are
/// meaningless on a corrupt frame), then the checksum verdict.
/// `None` means deliver.
pub fn rx_drop_reason(desc: &RxDesc) -> Option<RxDropReason> {
    if desc.errors & RXD_ERR_CE != 0 {
        return Some(RxDropReason::CrcError);
    }
    if desc.has_frame_error() {
        return Some(RxDropReason::FrameError);
    }
    if desc.csum_result() == RxCsumResult::Fail {
        return Some(RxDropReason::CsumFail);
    }
    None
}

/// Report one RX-verdict drop to the stack counters, under `name` —
/// the interface the frame arrived on.
fn count_rx_drop(name: &str, reason: RxDropReason) {
    match reason {
        RxDropReason::CrcError => {
            narf_net::iface::note_rx_crc_error(name, 1);
        }
        RxDropReason::FrameError | RxDropReason::CsumFail => {
            narf_net::iface::note_rx_drop(name, 1);
        }
    }
}

/// e1000 driver errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum E1000Error {
    BarMapFailed,
    NoMemory,
    UnsupportedDevice,
    /// Caller passed a frame larger than the programmed MTU's wire
    /// size (`crate::mtu::frame_size`).
    FrameTooLong,
    /// TX descriptor never completed.
    TxTimeout,
    /// PHY-ownership handshake (FWSM/SWFLAG) timed out — the
    /// Management Engine never released the PHY. Bring-up gives up
    /// rather than risk a wedged PHY register read.
    PhyOwnershipTimeout,
    /// MDIC transaction never set READY within the poll budget.
    PhyMdioTimeout,
    /// MDIC transaction completed with the ERROR bit set (read path).
    PhyMdioError,
    /// No PHY answered the MDIC identification read (ID1/ID2 read
    /// all-ones, the MDIO pull-up signature, or all-zeros).
    PhyNotPresent,
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

/// Build an MDIC read command word for `reg` (internal PHY address 1).
fn mdic_read_cmd(reg: u32) -> u32 {
    ((reg & 0x1F) << MDIC_REG_SHIFT) | MDIC_PHY_ADDR | MDIC_OP_READ
}

/// Build an MDIC write command word for `reg` carrying `data`.
fn mdic_write_cmd(reg: u32, data: u16) -> u32 {
    (data as u32) | ((reg & 0x1F) << MDIC_REG_SHIFT) | MDIC_PHY_ADDR | MDIC_OP_WRITE
}

/// Extract the 16-bit data field from a completed MDIC word.
fn mdic_data(word: u32) -> u16 {
    (word & MDIC_DATA_MASK) as u16
}

/// Decode an EEE advertisement pair (MMD 7/60 + 7/62) into the
/// `narf_net::nic::EeeStatus` bit encoding: MMD 7/60 bit 1 →
/// 100BASE-TX (8), bit 2 → 1000BASE-T (16); MMD 7/62 bit 0 →
/// 2.5GBASE-T (32). Same decode as igc's `modes()` closure.
fn eee_modes_from_mmd(local: u16, local2: u16) -> u32 {
    (if local & 0x2 != 0 { EEE_ADV_100M } else { 0 })
        | (if local & 0x4 != 0 { EEE_ADV_1G } else { 0 })
        | (if local2 & 0x1 != 0 { EEE_ADV_2_5G } else { 0 })
}

/// Next IPCNFG word for an advertised set: rewrite only the PCH
/// EEE-advertise bits (1G bit 14, 100M bit 12 — `IPCNFG_EEE_AN_MASK`)
/// and preserve every other field. A 2.5G request bit has no IPCNFG
/// bit on PCH parts and is dropped, never programmed.
fn eee_ipcnfg_next(current: u32, advertised: u32) -> u32 {
    (current & !IPCNFG_EEE_AN_MASK)
        | (if advertised & EEE_ADV_100M != 0 {
            IPCNFG_EEE_100M_AN
        } else {
            0
        })
        | (if advertised & EEE_ADV_1G != 0 {
            IPCNFG_EEE_1G_AN
        } else {
            0
        })
}

/// Next EEER word for an enable/disable: rewrite only the LPI mask
/// (TX LPI EN bit 16, RX LPI EN bit 17, LPI frame counter bit 18)
/// and preserve every other field. Mirrors the enable side of
/// `disable_eee_pchlan` (which clears exactly this mask).
fn eee_eeer_next(current: u32, enable: bool) -> u32 {
    (current & !EEER_LPI_MASK) | (if enable { EEER_LPI_MASK } else { 0 })
}

/// EEE status from scripted register state: `advertised` is the
/// programmed set (IPCNFG decode), `partner` the link-partner set
/// (MMD 7/61+63 decode). Active is the negotiated intersection —
/// the same derivation ixgbe's FW-PHY path uses (`advertised ∩
/// link-partner non-empty`) — gated on live link-up; `tx_lpi`
/// is EEER TX-LPI-EN as read.
fn eee_status_from(
    advertised: u32,
    partner: u32,
    link_up: bool,
    tx_lpi: bool,
) -> narf_net::nic::EeeStatus {
    narf_net::nic::EeeStatus {
        advertised,
        partner,
        active: link_up && (advertised & partner) != 0,
        tx_lpi,
    }
}

/// Compose a 32-bit PHY identifier from the PHYSID1/PHYSID2 reads
/// (Linux `e1000_get_phy_id` shape: ID1 in the high half).
fn phy_id_from(id1: u16, id2: u16) -> u32 {
    ((id1 as u32) << 16) | (id2 as u32)
}

/// `true` unless the ID read is the no-device signature: all-ones
/// (MDIO pull-ups, nothing answering) or all-zeros.
fn phy_id_valid(id: u32) -> bool {
    id != 0 && id != 0xFFFF_FFFF
}

/// Decode the BMSR link-status bit (single-read value; callers that
/// need latch-low-correct state use `E1000::phy_link_up`).
fn bmsr_link(bmsr: u16) -> bool {
    bmsr & BMSR_LINK != 0
}

/// Auto-negotiation complete from a BMSR sample (same latch-low
/// double-read discipline as `bmsr_link`).
fn bmsr_ancomplete(bmsr: u16) -> bool {
    bmsr & BMSR_ANCOMPLETE != 0
}

/// Negotiated link mode from auto-negotiation (IEEE 802.3 Annex 28B
/// priority order, highest first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkMode {
    Speed10Half,
    Speed10Full,
    Speed100Half,
    Speed100Full,
    Speed1000Half,
    Speed1000Full,
}

impl LinkMode {
    /// Full-duplex modes. Flow control is full-duplex-only per
    /// IEEE 802.3; a half-duplex negotiation forces it off (see
    /// `resolve_flow_control`).
    pub const fn is_full_duplex(self) -> bool {
        matches!(
            self,
            LinkMode::Speed10Full | LinkMode::Speed100Full | LinkMode::Speed1000Full
        )
    }
}

/// This driver's auto-negotiation advertisement as (ANAR, GBCR):
/// 10/100 half+full in ANAR, 1000 full only in GBCR, symmetric
/// pause set, asymmetric pause clear. 1000 half is denied exactly
/// as Linux does ("We do not allow the Phy to advertise 1000 Mb
/// Half Duplex", `e1000_phy_setup_autoneg`); pause is advertised
/// because flow control landed (audit gap 7): FCRTL/FCRTH +
/// RFCE/TFCE are programmed by `configure_flow_control` after
/// link-up, so the advertisement no longer promises an
/// unimplemented capability.
fn aneg_advertisement() -> (u16, u16) {
    (
        ANAR_SELECTOR_CSMA | ANAR_10HALF | ANAR_10FULL | ANAR_100HALF | ANAR_100FULL | ANAR_PAUSE,
        GBCR_1000FULL,
    )
}

/// Next ANAR value from the current one, Linux
/// `e1000_phy_setup_autoneg` shape: clear the 10/100 speed bits and
/// the asymmetric-pause bit, then set this driver's speeds +
/// symmetric pause. The selector is forced to CSMA rather than
/// preserved from the read: a zero selector is invalid, so forcing
/// is strictly safer than copying a broken read. Remote-fault,
/// acknowledge, and next-page bits are preserved (the PHY owns
/// acknowledge; software must not clear it mid-negotiation).
fn aneg_anar_next(current: u16) -> u16 {
    (current & !(ANAR_SPEED_MASK | ANAR_PAUSE_ASYM))
        | ANAR_SELECTOR_CSMA
        | ANAR_10HALF
        | ANAR_10FULL
        | ANAR_100HALF
        | ANAR_100FULL
        | ANAR_PAUSE
}

/// Next GBCR value from the current one: clear both 1000 speed
/// bits, set 1000 full only (1000 half denied, see
/// `aneg_advertisement`).
fn aneg_gbcr_next(current: u16) -> u16 {
    (current & !GBCR_SPEED_MASK) | GBCR_1000FULL
}

/// Next BMCR value from the current one: set ANENABLE + ANRESTART,
/// preserving every other bit (Linux `e1000_copper_link_autoneg`
/// read-modify-write shape; a blind write would drop power-down,
/// loopback, and forced speed/duplex bits).
fn aneg_bmcr_restart(current: u16) -> u16 {
    current | BMCR_ANENABLE | BMCR_ANRESTART
}

/// Resolve the negotiated mode from our advertisement and the link
/// partner's ability words (ANAR/LPA share speed-bit positions;
/// 1000BASE-T lives in GBCR/STAT1000). Priority per IEEE 802.3
/// Annex 28B: 1000F > 1000H > 100F > 100H > 10F > 10H. 100BASE-T4
/// is not considered: neither side advertises it (Linux e1000e
/// does not either), so it can never be the common mode. `None`
/// means no common mode — the link cannot come up on these
/// advertisements.
const fn resolve_negotiated_mode(
    our_anar: u16,
    our_gbcr: u16,
    lp_anar: u16,
    lp_stat1000: u16,
) -> Option<LinkMode> {
    if our_gbcr & GBCR_1000FULL != 0 && lp_stat1000 & STAT1000_1000FULL != 0 {
        Some(LinkMode::Speed1000Full)
    } else if our_gbcr & GBCR_1000HALF != 0 && lp_stat1000 & STAT1000_1000HALF != 0 {
        Some(LinkMode::Speed1000Half)
    } else if our_anar & ANAR_100FULL != 0 && lp_anar & ANAR_100FULL != 0 {
        Some(LinkMode::Speed100Full)
    } else if our_anar & ANAR_100HALF != 0 && lp_anar & ANAR_100HALF != 0 {
        Some(LinkMode::Speed100Half)
    } else if our_anar & ANAR_10FULL != 0 && lp_anar & ANAR_10FULL != 0 {
        Some(LinkMode::Speed10Full)
    } else if our_anar & ANAR_10HALF != 0 && lp_anar & ANAR_10HALF != 0 {
        Some(LinkMode::Speed10Half)
    } else {
        None
    }
}

/// Link-partner ability as read from LPA + STAT1000.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartnerAbility {
    /// LPA word (register 5): 10/100 speed bits + pause bits, same
    /// positions as ANAR.
    pub anar: u16,
    /// 1000BASE-T status word (register 10): partner 1000 halves.
    pub stat1000: u16,
}

impl PartnerAbility {
    /// Negotiated mode against our advertisement words.
    pub const fn negotiated_mode(&self, our_anar: u16, our_gbcr: u16) -> Option<LinkMode> {
        resolve_negotiated_mode(our_anar, our_gbcr, self.anar, self.stat1000)
    }
}

/// Negotiated flow control from auto-negotiation (IEEE 802.3ab
/// pause resolution, table as quoted in Linux e1000e mac.c
/// `e1000_config_fc_after_link_up`). Naming follows Linux:
/// TxPause means this station SENDS pause frames (it needs
/// thresholds + TFCE); RxPause means it HONORS incoming pause
/// frames (RFCE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowControl {
    /// No pause in either direction.
    Disabled,
    /// Honor incoming pause frames only (RFCE, no thresholds).
    RxPause,
    /// Generate pause frames only (thresholds + TFCE).
    TxPause,
    /// Both directions (thresholds + RFCE + TFCE).
    Full,
}

/// Resolve flow control from our ANAR word and the link partner's
/// LPA word. Half duplex forces Disabled per IEEE 802.3 (pause is
/// a full-duplex-only mechanism). With this driver's advertisement
/// (PAUSE set, ASM_DIR clear) the only non-Disabled outcome is
/// Full when the partner also sets PAUSE; the asymmetric arms are
/// implemented for table completeness and covered by smokes.
pub fn resolve_flow_control(our_anar: u16, lp_anar: u16, full_duplex: bool) -> FlowControl {
    if !full_duplex {
        return FlowControl::Disabled;
    }
    let our_pause = our_anar & ANAR_PAUSE != 0;
    let our_asym = our_anar & ANAR_PAUSE_ASYM != 0;
    let lp_pause = lp_anar & ANAR_PAUSE != 0;
    let lp_asym = lp_anar & ANAR_PAUSE_ASYM != 0;
    if our_pause && lp_pause {
        FlowControl::Full
    } else if !our_pause && our_asym && lp_pause && lp_asym {
        FlowControl::TxPause
    } else if our_pause && our_asym && !lp_pause && lp_asym {
        FlowControl::RxPause
    } else {
        FlowControl::Disabled
    }
}

/// CTRL flow-control bits for a resolved mode (Linux e1000e
/// `e1000e_force_mac_fc` mapping: Disabled → neither, RxPause →
/// RFCE, TxPause → TFCE, Full → both).
pub fn flow_control_ctrl_bits(mode: FlowControl) -> u32 {
    match mode {
        FlowControl::Disabled => 0,
        FlowControl::RxPause => CTRL_RFCE,
        FlowControl::TxPause => CTRL_TFCE,
        FlowControl::Full => CTRL_RFCE | CTRL_TFCE,
    }
}

/// Flow-control watermarks from the PBA RX allocation, in bytes:
/// `(low, high)`. High is 90% of the RX buffer capped by one
/// max-size frame of headroom, low is 80% — the Linux e1000e
/// generic/pch2lan formulas — both masked to 8-byte granularity.
/// `None` is fail-closed: PBA 0 (unprogrammed / QEMU default) or a
/// degenerate result means "do not enable transmit pause" rather
/// than a threshold that would XOFF immediately.
pub fn flow_control_watermarks(pba_rxa_kb: u32, max_frame: u32) -> Option<(u32, u32)> {
    if pba_rxa_kb == 0 {
        return None;
    }
    let bytes = pba_rxa_kb * 1024;
    let high = core::cmp::min(bytes * 9 / 10, bytes.saturating_sub(max_frame)) & FCRTH_RTH_MASK;
    let low = (bytes * 8 / 10) & FCRTL_RTL_MASK;
    if low == 0 || high == 0 || low >= high {
        return None;
    }
    Some((low, high))
}

/// Read a 16-bit register from the internal PHY via MDIC.
///
/// Linux: classic `e1000_read_phy_reg` MDIC branch
/// (`e1000_hw.c`): write the OP_READ command word, poll READY
/// (Linux: 64 × 50 µs ≈ 3.2 ms; we use the igb crate's 10 ms
/// `responsive_spin_until` bound, strictly looser), then fail on
/// the ERROR bit and return the low 16 bits. No SWFLAG scoping
/// here — callers (`E1000::phy_read`) own the per-access handshake.
fn mdic_read(mmio: &MmioRegion, reg: u32) -> Result<u16, E1000Error> {
    // SAFETY: identity-mapped MMIO; MDIC is inside the e1000 BAR0
    // register window on every bound part.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        mmio.write32(REG_MDIC, mdic_read_cmd(reg));
    }
    let ready = narf_scheduler::responsive_spin_until(
        // SAFETY: identity-mapped MMIO.
        || unsafe { mmio.read32(REG_MDIC) } & MDIC_READY != 0,
        narf_time::Deadline::after_ms(10),
    );
    if !ready {
        return Err(E1000Error::PhyMdioTimeout);
    }
    // SAFETY: identity-mapped MMIO.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let word = unsafe { mmio.read32(REG_MDIC) };
    if word & MDIC_ERROR != 0 {
        return Err(E1000Error::PhyMdioError);
    }
    Ok(mdic_data(word))
}

/// Write a 16-bit value to an internal-PHY register via MDIC.
///
/// Linux: classic `e1000_write_phy_reg` MDIC branch: write the
/// OP_WRITE command word carrying the data, poll READY (Linux:
/// 641 × 5 µs ≈ 3.2 ms; we use the same 10 ms bound as the read
/// path). The write path checks READY only — Linux does not test
/// the ERROR bit here either. No SWFLAG scoping here — callers
/// (`E1000::phy_write`) own the per-access handshake.
fn mdic_write(mmio: &MmioRegion, reg: u32, data: u16) -> Result<(), E1000Error> {
    // SAFETY: identity-mapped MMIO; MDIC is inside the e1000 BAR0
    // register window on every bound part.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        mmio.write32(REG_MDIC, mdic_write_cmd(reg, data));
    }
    let ready = narf_scheduler::responsive_spin_until(
        // SAFETY: identity-mapped MMIO.
        || unsafe { mmio.read32(REG_MDIC) } & MDIC_READY != 0,
        narf_time::Deadline::after_ms(10),
    );
    if !ready {
        return Err(E1000Error::PhyMdioTimeout);
    }
    Ok(())
}

/// Read a Clause 45 MMD register through the Clause 22 MDIO
/// window: MMDAC = device, MMDAAD = register, MMDAC =
/// device | `MMDAC_FUN_DATA` (data phase), then read MMDAAD;
/// MMDAC is restored to 0 afterwards. Exactly igc's `mmd()`
/// sequence; a cleanup failure is an error too, matching igc
/// (a failed restore must not be silently swallowed — the next
/// MDIO access would address the wrong device).
/// Callers own SWFLAG scoping (see `E1000::phy_read`).
///
/// Only the read side exists here: the PCH set path programs
/// IPCNFG/EEER only (exactly Linux's `e1000_set_eee_pchlan`),
/// so no MMD write helper is provided — an unused one would be
/// dead code, and inventing a use for it would diverge from Linux.
fn mmd_read(mmio: &MmioRegion, dev: u16, reg: u16) -> Result<u16, E1000Error> {
    mdic_write(mmio, PHY_MMDAC, dev)?;
    mdic_write(mmio, PHY_MMDAAD, reg)?;
    mdic_write(mmio, PHY_MMDAC, dev | MMDAC_FUN_DATA)?;
    let result = mdic_read(mmio, PHY_MMDAAD);
    let cleanup = mdic_write(mmio, PHY_MMDAC, 0);
    cleanup?;
    result
}

/// Program auto-negotiation advertisement and restart negotiation
/// (Linux `e1000_copper_link_autoneg` minus the wait: bring-up
/// must not block on link — the LSC drain reports the transition).
/// ANAR, then GBCR, then BMCR restart, each read-modify-write.
/// Callers own SWFLAG scoping: bring_up holds it across init (so
/// it calls this directly), and `E1000::autoneg_setup` takes it
/// for the sequence. Must NOT be called with no SWFLAG held on a
/// PCH part with an active ME.
fn autoneg_setup_mmio(mmio: &MmioRegion) -> Result<(), E1000Error> {
    let anar = mdic_read(mmio, PHY_ANAR)?;
    mdic_write(mmio, PHY_ANAR, aneg_anar_next(anar))?;
    let gbcr = mdic_read(mmio, PHY_GBCR)?;
    mdic_write(mmio, PHY_GBCR, aneg_gbcr_next(gbcr))?;
    let bmcr = mdic_read(mmio, PHY_BMCR)?;
    mdic_write(mmio, PHY_BMCR, aneg_bmcr_restart(bmcr))?;
    Ok(())
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

/// Live e1000 controller. Holds the MMIO mapping and descriptor/buffer rings.
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
    /// Shared zero-copy TX pool. Stack acquisition and completion reclaim use
    /// this same free-list, so the steady-state path allocates no pages.
    tx_zc_pool: Arc<DmaPool>,
    /// Driver-side TX producer/clean cursors plus buffers owned by hardware.
    /// The IRQ handler never takes this lock; it only acknowledges ICR.
    tx_state: IrqSafeSpinLock<TxQueueState>,
    /// RX descriptor-ring DMA buffer.
    rx_ring: DmaBuffer,
    /// RX buffer pool — one `RX_BUF_LEN` allocation per descriptor.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side RX head cursor (next descriptor to inspect for
    /// completion). The hardware writes to RDT and we lag behind
    /// reading at this index.
    rx_head: IrqSafeSpinLock<u32>,
    /// Shadow of the hardware VLAN filter table (VFTA). VLAN mode
    /// is opt-in: the first VID added programs VET + RCTL.VFE +
    /// CTRL.VME; the last VID removed clears RCTL.VFE (CTRL.VME
    /// stays set — see `vlan_filter_remove`).
    vlan_filter: IrqSafeSpinLock<VlanFilter>,
    /// Shadow of the hardware multicast hash table (MTA).
    /// Filtering is the bring-up default (no UPE|MPE); the stack
    /// adds addresses explicitly or requests promiscuous mode.
    multicast_filter: IrqSafeSpinLock<MulticastFilter>,
    /// PCI device id this controller was probed for. Selects the
    /// jumbo ceiling (`crate::mtu::max_mtu`): classic 8254x parts
    /// take 16110, e1000e parts 9000.
    did: u16,
    /// Programmed interface MTU (issue #802). 1500 at bring-up; the
    /// sole post-bring-up writer is `set_mtu` via the `DeviceControl`
    /// hook. `Interface::mtu` / `HwNic::mtu` read it.
    mtu: IrqSafeSpinLock<u32>,
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
    rx_ipc_prod: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    pub rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    /// Raw-frame mirroring stays off until a registry consumer actually takes
    /// `rx_ipc_ring`; the in-kernel TCP stack otherwise pays no copy/allocation.
    rx_mirror_enabled: AtomicBool,
    pub tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    /// Set by `detach_device`: every datapath entry point fails fast
    /// once this is set (igb pattern, spec §3 / issue #789). The async
    /// pumps are not torn down on detach — they hold `Arc<E1000>` —
    /// but they can no longer touch the device through a gated entry.
    detached: AtomicBool,
    /// Set by `suspend`, cleared by `resume`: the datapath gates
    /// refuse TX and RX while this is set, and the interface
    /// publishes link down.
    suspended: AtomicBool,
    tx_timeouts: AtomicU64,
    /// Controller resets performed by [`E1000::recover`].
    tx_resets: AtomicU64,
    /// Set while [`E1000::recover`] owns the reset sequence: TX
    /// posts fail fast instead of racing the ring reprogram (the
    /// fresh ring's TDT is re-zeroed by recovery, so a post landing
    /// mid-reset would be silently dropped).
    recovering: AtomicBool,
    /// PCI address of the function this instance drives. Probe
    /// refuses a second bind of the same live address (issue #795):
    /// two `E1000`s for one chip would drive one set of rings.
    pub addr: narf_bus::BusAddr,
    /// Interface name `publish_netdev_with_context` assigned this
    /// instance (`eth%d`). Per-instance (i40e/igc pattern): the old
    /// module-level `E1000_IFNAME` static could only name one NIC.
    ifname: crate::publish::IfName,
    /// Link Status Change pending, set by the ISR when ICR reports
    /// LSC. Per-instance: the old module-level `LSC_PENDING` could
    /// only flag one NIC's transition (issue #791).
    lsc_pending: AtomicBool,
}

// SAFETY: `E1000` only auto-fails `Send` because `MmioRegion`/`DmaBuffer`
// wrap raw device/DMA pointers. Those pointers stay valid for the device
// lifetime and are not tied to any thread, so the handle is sound to move
// across threads.
unsafe impl Send for E1000 {}
// SAFETY: every field reachable through `&E1000` from multiple threads is
// either immutable after bring-up (mac/link_up/mmio mapping) or guarded by
// an `IrqSafeSpinLock` (TX state, RX cursor and IPC rings); concurrent MMIO/DMA
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

/// Link Status Change pending lives on the controller now
/// (`E1000::lsc_pending`): the ISR sets the flag of the device whose
/// vector fired, and that device's RX pump (task context) consumes
/// it, re-samples STATUS, and republishes the iface link metadata.
/// A module-level flag could only name one NIC's transition
/// (issue #791 vs #795).
/// Decode a STATUS word into a publication sample. Shared by probe
/// (initial state) and the RX pump's LSC drain (every transition).
fn link_sample_from_status(status: u32) -> crate::publish::LinkSample {
    if status & STATUS_LU == 0 {
        return crate::publish::LinkSample::DOWN;
    }
    let speed_mbps = match status & STATUS_SPEED_MASK {
        STATUS_SPEED_1000 => 1000,
        STATUS_SPEED_100 => 100,
        _ => 10,
    };
    let duplex = if status & STATUS_FD != 0 {
        narf_net::iface::LinkDuplex::Full
    } else {
        narf_net::iface::LinkDuplex::Half
    };
    crate::publish::LinkSample {
        carrier: true,
        speed_mbps: Some(speed_mbps),
        duplex: Some(duplex),
        // STATUS reports no media state; e1000-family parts are
        // fixed copper/fiber, not caged modules (issue #791).
        media_available: None,
        phy_type: None,
        phy_type_name: None,
    }
}

/// Sync ISR, demultiplexed by vector: `install_handler_named`
/// passes the vector back as the cookie, and the handler acks only
/// the controllers bound to that vector — the igc `ISR_HW` pattern,
/// without the table, since the vector already lives on the
/// controller. The old static `ISR_MMIO_BASE` could only ack one
/// NIC: a second e1000 overwrote it, leaving the first device's
/// level-triggered INTx unacknowledged (issue #795). Detached
/// controllers are skipped: detach masks the device, so a stale
/// in-flight interrupt must not revive it. The dispatch layer
/// (`narf_interrupts::dispatch::on_irq`) bumps the per-vector
/// fire-count and wakes the registered waker; the `rx_async` /
/// `tx_async` consumers then run the actual descriptor drain on a
/// normal task.
fn e1000_isr(cookie: u64) -> narf_interrupts::dispatch::IrqStatus {
    let vector = cookie as u8;
    for dev in CONTROLLERS.lock().iter() {
        if dev.detached.load(Ordering::Acquire) || dev.irq_vector != Some(vector) {
            continue;
        }
        // SAFETY: `dev.mmio` is the device's BAR0 mapping, valid for
        // the controller lifetime; ICR (offset 0xC0) is well inside
        // the e1000 register window. The read auto-clears all pending
        // cause bits per 8254x SDM §13.4.17 — the documented
        // acknowledge for level-triggered INTx delivery and a no-op
        // for MSI-X (which is edge-triggered but tolerates the read).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let icr = unsafe { narf_arch::mmio::read32(dev.mmio.virt + REG_ICR) };
        // LSC is in the default IMS mask, so a link transition reaches
        // this read; record it for the pump instead of discarding the
        // cause word (issue #791). The RX pump (task context)
        // consumes the per-device flag, re-samples STATUS, and
        // republishes the iface link metadata.
        if icr & IMS_LSC != 0 {
            dev.lsc_pending.store(true, Ordering::Release);
        }
    }
    narf_interrupts::dispatch::IrqStatus::Handled
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

        // 1c. Program auto-negotiation advertisement and restart
        //    negotiation, before the rings and CTRL.SLU: starting AN
        //    here gives it the whole bring-up window to complete
        //    before the STATUS.LU sample at step 6 (the LSC drain
        //    reports the transition if it completes later).
        //    Best-effort: a PHY that does not answer MDIC keeps its
        //    reset-default advertisement, which still negotiates —
        //    failing bring-up here would brick a NIC whose only
        //    fault is an unreadable PHY register. Post-bring-up,
        //    `autoneg_setup()` re-runs this with errors propagated.
        //    SWFLAG is already held (step 0) on PCH parts, so the
        //    raw mmio sequence is correct here; the `E1000`
        //    method must NOT be used (it would release early).
        let _ = autoneg_setup_mmio(&mmio);

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

        // Re-program the station address into RAL0 with AV set:
        // filtering mode (no UPE below) accepts self-unicast only
        // via this exact-match slot, and firmware is not guaranteed
        // to have left AV set.
        // SAFETY: same as the RAL0/RAH0 reads above.
        unsafe {
            mmio.write32(REG_RAL0, ral);
            mmio.write32(REG_RAH0, rah | RAH_AV);
        }

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
        let tx_ring =
            alloc_coherent(4096, crate::BUILTIN_DOMAIN).map_err(|_| E1000Error::NoMemory)?;
        // Device-side handle; CPU access goes through `tx_ring.cpu_*` below.
        let tx_ring_dma = tx_ring.dma_addr();
        let mut tx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(TX_RING_LEN);
        for _ in 0..TX_RING_LEN {
            // TX_BUF_BYTES covers the family's largest frame, so a
            // jumbo TX copy always fits its slot (issue #802).
            let b = alloc_coherent(crate::mtu::TX_BUF_BYTES, crate::BUILTIN_DOMAIN)
                .map_err(|_| E1000Error::NoMemory)?;
            tx_pool.push(b);
        }
        // Zero the ring (alloc_coherent guarantees fresh memory but
        // we're explicit).
        // SAFETY: coherent DMA via the kernel direct map.
        unsafe {
            for i in 0..(TX_RING_LEN * 16) {
                core::ptr::write_volatile(tx_ring.cpu_mut_ptr_at::<u8>(i as u64), 0);
            }
        }
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_TDBAL, tx_ring_dma.raw() as u32);
            mmio.write32(REG_TDBAH, (tx_ring_dma.raw() >> 32) as u32);
            mmio.write32(REG_TDLEN, (TX_RING_LEN * 16) as u32);
            mmio.write32(REG_TDH, 0);
            mmio.write32(REG_TDT, 0);
        }
        // 5. Enable TX with Intel's 82543+ copper defaults. CT/COLD and TIPG
        //    are software-programmed fields, not useful reset defaults; zeroing
        //    them happened to move packets in QEMU but is not a valid physical
        //    e1000 configuration. These values match Linux e1000's legacy-ring
        //    setup (collision threshold 15, distance 63, IPGT/IPGR1/IPGR2
        //    8/8/6).
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_TIPG, TIPG_COPPER_DEFAULT);
            mmio.write32(
                REG_TCTL,
                TCTL_EN | TCTL_PSP | TCTL_CT_15 | TCTL_COLD_63 | TCTL_RTLC,
            );
        }

        // 5b. Allocate RX descriptor ring + buffer pool.
        let rx_ring =
            alloc_coherent(4096, crate::BUILTIN_DOMAIN).map_err(|_| E1000Error::NoMemory)?;
        let rx_ring_dma = rx_ring.dma_addr();
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RX_RING_LEN);
        for i in 0..RX_RING_LEN {
            // RX_BUF_LEN covers the family's largest frame (issue
            // #802); RCTL.BSIZE selects how much of it the device
            // may use at the current MTU.
            let buf = alloc_coherent(RX_BUF_LEN, crate::BUILTIN_DOMAIN)
                .map_err(|_| E1000Error::NoMemory)?;
            // The descriptor carries the DEVICE address of the buffer.
            let buf_dma = buf.dma_addr();
            let desc = RxDesc {
                addr: buf_dma.raw(),
                length: 0,
                csum: 0,
                status: 0,
                errors: 0,
                special: 0,
            };
            // SAFETY: coherent DMA ring via the kernel direct map.
            unsafe {
                core::ptr::write_volatile(rx_ring.cpu_mut_ptr_at::<RxDesc>((i * 16) as u64), desc);
            }
            rx_pool.push(buf);
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_RDBAL, rx_ring_dma.raw() as u32);
            mmio.write32(REG_RDBAH, (rx_ring_dma.raw() >> 32) as u32);
            mmio.write32(REG_RDLEN, (RX_RING_LEN * 16) as u32);
            mmio.write32(REG_RDH, 0);
            // RDT points to the last *available* slot (i.e. one past
            // the last filled slot). With all slots filled, RDT =
            // RX_RING_LEN - 1.
            mmio.write32(REG_RDT, (RX_RING_LEN - 1) as u32);
            // Filter tables start empty: default-deny for both
            // VLAN (no VIDs) and multicast (no hash bits). The
            // shadows are fresh (see the constructor), so zeroing
            // here keeps hardware and shadow in sync even if this
            // bring-up runs on an already-programmed device.
            for word in 0..VFTA_WORDS {
                mmio.write32(REG_VFTA_BASE + word as u64 * 4, 0);
            }
            for word in 0..MTA_WORDS {
                mmio.write32(REG_MTA_BASE + word as u64 * 4, 0);
            }
            // RCTL: enable, accept broadcast + exact-match unicast
            // (RAL0, re-programmed above) + hash multicast, strip
            // CRC, 2K buffers at the initial MTU 1500. Unicast/multicast
            // promiscuous are OFF by default — the old accept-all
            // behavior is available explicitly via
            // `set_promiscuous(true)`.
            // RCTL.MO bits are 0 in this value (window [47:36]).
            mmio.write32(
                REG_RCTL,
                RCTL_EN | RCTL_BAM | RCTL_SECRC | rctl_bsize_lpe(crate::mtu::STD_MTU),
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
        let link_up = status & STATUS_LU != 0;

        // 6b. Fail-closed flow-control defaults (audit gap 7):
        // thresholds zero, RFCE/TFCE clear. Reset defaults are
        // already zero, but an already-programmed device (re-probe
        // / kexec) could carry stale thresholds — zeroing here
        // keeps hardware in the known-disabled state until the
        // post-link `configure_flow_control` enables it, the same
        // rationale as the VFTA/MTA zeroing above. FCTTV is left
        // alone: with TFCE clear no pause frames are generated,
        // and `configure_flow_control` programs it whenever it
        // sets TFCE.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_FCRTL, 0);
            mmio.write32(REG_FCRTH, 0);
            let ctrl = mmio.read32(REG_CTRL);
            mmio.write32(REG_CTRL, ctrl & !CTRL_FC_MASK);
        }

        // 7. Try to attach an IRQ delivery path. Mirror the
        //    `xhci.rs` MSI-X → INTx → polled fallback chain.
        let (msix, irq_vector, used_intx) = match Self::try_enable_msix(cap, device) {
            Ok((tbl, v)) => (Some(tbl), Some(v), false),
            Err(_) => match Self::try_install_intx(cap, device) {
                Some(v) => (None, Some(v), true),
                None => (None, None, false),
            },
        };

        // Install the ISR with the vector as its cookie, so the
        // handler can demultiplex by vector (see `e1000_isr`). An early
        // interrupt racing bring-up finds no controller bound to the
        // vector yet and is ignored; IMS is programmed below, so no
        // cause can fire before the device is up.
        if let Some(v) = irq_vector {
            narf_interrupts::dispatch::install_handler_named(v, "e1000", u64::from(v), e1000_isr);
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
                // Moderate the shared completion vector before unmasking its
                // causes. Per-frame RX interrupts dominate a virtual 82540 at
                // gigabit packet rates; this matches Linux's initial e1000
                // setting while keeping the worst-case added latency near
                // 50 microseconds. MSI-X parts use their per-vector EITR0;
                // legacy INTx/MSI parts use the shared ITR.
                mmio.write32(
                    if msix.is_some() {
                        REG_EITR0_82574
                    } else {
                        REG_ITR
                    },
                    ITR_20K_INTERRUPTS_PER_SEC,
                );
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
        let tx_zc_pool = Arc::new(DmaPool::new(
            MAX_TSO_FRAME,
            crate::BUILTIN_DOMAIN,
            TX_RING_LEN,
        ));
        // Fill before the queue becomes visible. Zero-copy TX sees an empty
        // pool as backpressure instead of allocating in its send path.
        let _ = tx_zc_pool.prefill(TX_RING_LEN);

        let e1000 = Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_zc_pool,
            tx_state: IrqSafeSpinLock::new(TxQueueState::new()),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            vlan_filter: IrqSafeSpinLock::new(VlanFilter::new()),
            multicast_filter: IrqSafeSpinLock::new(MulticastFilter::new()),
            did: device.id.device,
            mtu: IrqSafeSpinLock::new(crate::mtu::STD_MTU),
            mac,
            link_up,
            _msix: msix,
            irq_vector,
            pch_part,
            me_active,
            rx_ipc_prod: IrqSafeSpinLock::new(None),
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            rx_mirror_enabled: AtomicBool::new(false),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
            detached: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            tx_timeouts: AtomicU64::new(0),
            tx_resets: AtomicU64::new(0),
            recovering: AtomicBool::new(false),
            addr: device.addr,
            ifname: crate::publish::IfName::new(),
            lsc_pending: AtomicBool::new(false),
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
        let ticket = self.tx_enqueue(frame, true, None)?;
        let done = narf_scheduler::responsive_spin_until(
            || self.tx_slot_done(ticket),
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(E1000Error::TxTimeout);
        }
        Ok(())
    }

    fn tx_desc_done(&self, slot: usize) -> bool {
        let status_off = (slot * core::mem::size_of::<TxDesc>()) as u64 + 12;
        // SAFETY: coherent DMA ring; `slot < TX_RING_LEN` at every caller.
        let status = unsafe { core::ptr::read_volatile(self.tx_ring.cpu_ptr_at::<u8>(status_off)) };
        status & TXD_STAT_DD != 0
    }

    /// Reclaim completed descriptors in producer order. The shared pool lock
    /// is nested under `tx_state`; the reverse order never occurs because
    /// `tx_acquire` drops the pool lock before entering the driver's callback.
    fn reclaim_tx_locked(&self, state: &mut TxQueueState) {
        while state.cursor.in_flight != 0 {
            let slot = state.cursor.next_to_clean;
            let completion = state.completion_slot[slot];
            if !self.tx_desc_done(completion) {
                break;
            }
            // Pair the device's DD write with the CPU's later buffer reuse.
            compiler_fence(Ordering::SeqCst);
            let completed = state.owned[slot].take();
            state.completion_slot[slot] = slot;
            let reclaimed = state.cursor.complete_oldest();
            debug_assert_eq!(reclaimed, Some(slot));
            if let Some(buf) = completed {
                self.tx_zc_pool.release(buf);
            }
        }
    }

    /// Publish every descriptor queued since the previous TDT write. Repeated
    /// calls are cheap: no MMIO write occurs when hardware already knows the
    /// current producer tail.
    fn kick_tx_locked(&self, state: &mut TxQueueState) {
        let tail = state.cursor.next_to_use;
        if state.doorbell_tail == tail {
            return;
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO; `tail` is a descriptor-ring index.
        unsafe {
            self.mmio.write32(REG_TDT, tail as u32);
        }
        state.doorbell_tail = tail;
    }

    /// Publish one descriptor after its ring slot and optional owned buffer
    /// have been reserved under `tx_state`.
    fn post_tx_locked(
        &self,
        state: &mut TxQueueState,
        ticket: TxTicket,
        dma_addr: u64,
        len: usize,
        kick: bool,
        vlan_tag: Option<u16>,
    ) {
        let desc = TxDesc::legacy_data(dma_addr, len as u16, vlan_tag);
        let desc_off = (ticket.slot * core::mem::size_of::<TxDesc>()) as u64;
        // SAFETY: the cursor only reserves slots in `[0, TX_RING_LEN)` and the
        // descriptor ring is exactly `TX_RING_LEN * size_of::<TxDesc>()` bytes.
        unsafe {
            core::ptr::write_volatile(self.tx_ring.cpu_mut_ptr_at::<TxDesc>(desc_off), desc);
        }
        state.completion_slot[ticket.slot] = ticket.slot;
        // The descriptor and retained buffer must be globally visible before
        // a later MMIO doorbell lets hardware fetch them.
        compiler_fence(Ordering::SeqCst);
        // Batch a TCP burst into one VM-exit/MMIO doorbell. Force a kick at the
        // one-slot-empty limit so an interrupted producer cannot fill the
        // software ring with descriptors hardware has never seen.
        if kick || state.cursor.in_flight >= TX_RING_USABLE {
            self.kick_tx_locked(state);
        }
    }

    /// Publish one IPv4/TCP TSO packet as a context descriptor followed by
    /// 4-KiB-bounded extended data descriptors. All slots watch the final
    /// EOP/RS descriptor, since context and intermediate descriptors are not
    /// independently written back with DD.
    fn post_tso_locked(
        &self,
        state: &mut TxQueueState,
        dma_addr: u64,
        len: usize,
        context: TxContextDesc,
        owned: DmaBuffer,
        kick: bool,
    ) -> Option<TxTicket> {
        let data_descs = len.div_ceil(MAX_DATA_PER_TXD);
        let descriptor_count = 1 + data_descs;
        if state.cursor.available() < descriptor_count {
            // `TxMeta::more` may have deliberately deferred the doorbell for
            // the preceding packet. A multi-descriptor packet can run out of
            // room before the one-slot-empty threshold, so flush that partial
            // batch before waiting for completions. Otherwise hardware never
            // sees the descriptors whose DD bits the retry loop needs.
            if state.needs_flush_for(descriptor_count) {
                self.kick_tx_locked(state);
            }
            return None;
        }

        let context_ticket = state.cursor.reserve().expect("capacity checked");
        let context_off = (context_ticket.slot * core::mem::size_of::<TxDesc>()) as u64;
        // SAFETY: capacity was checked and every reserved slot is inside the
        // one-page descriptor ring.
        unsafe {
            core::ptr::write_volatile(
                self.tx_ring.cpu_mut_ptr_at::<TxContextDesc>(context_off),
                context,
            );
        }

        let mut offset = 0usize;
        let mut final_ticket = context_ticket;
        while offset < len {
            let chunk = (len - offset).min(MAX_DATA_PER_TXD);
            let last = offset + chunk == len;
            let ticket = state.cursor.reserve().expect("capacity checked");
            let desc = TxDesc::tso_data(dma_addr + offset as u64, chunk as u16, last);
            let desc_off = (ticket.slot * core::mem::size_of::<TxDesc>()) as u64;
            // SAFETY: as above; `chunk <= MAX_DATA_PER_TXD <= u16::MAX`.
            unsafe {
                core::ptr::write_volatile(self.tx_ring.cpu_mut_ptr_at::<TxDesc>(desc_off), desc);
            }
            final_ticket = ticket;
            offset += chunk;
        }

        let mut slot = context_ticket.slot;
        for _ in 0..descriptor_count {
            state.completion_slot[slot] = final_ticket.slot;
            slot = (slot + 1) % TX_RING_LEN;
        }
        debug_assert!(state.owned[final_ticket.slot].is_none());
        state.owned[final_ticket.slot] = Some(owned);

        compiler_fence(Ordering::SeqCst);
        if kick || state.cursor.in_flight >= TX_RING_USABLE {
            self.kick_tx_locked(state);
        }
        Some(final_ticket)
    }

    /// Copy into a persistent per-slot buffer and enqueue. Ring-full waits are
    /// exceptional and bounded; normal traffic publishes immediately.
    fn tx_enqueue(
        &self,
        frame: &[u8],
        kick: bool,
        vlan_tag: Option<u16>,
    ) -> Result<TxTicket, E1000Error> {
        if let Some(e) = self.gate_error() {
            return Err(e);
        }
        if frame.is_empty() || frame.len() > crate::mtu::frame_size(*self.mtu.lock()) as usize {
            return Err(E1000Error::FrameTooLong);
        }
        let mut ticket = None;
        let posted = narf_scheduler::responsive_spin_until(
            || {
                let mut state = self.tx_state.lock();
                self.reclaim_tx_locked(&mut state);
                let Some(reserved) = state.cursor.reserve() else {
                    return false;
                };
                let slot = reserved.slot;
                debug_assert!(state.owned[slot].is_none());
                // SAFETY: frame length is bounded above; the persistent DMA
                // allocation is a page and therefore has ample capacity.
                unsafe {
                    for (i, b) in frame.iter().enumerate() {
                        core::ptr::write_volatile(
                            self.tx_pool[slot].cpu_mut_ptr_at::<u8>(i as u64),
                            *b,
                        );
                    }
                }
                self.post_tx_locked(
                    &mut state,
                    reserved,
                    self.tx_pool[slot].dma_addr().raw(),
                    frame.len(),
                    kick,
                    vlan_tag,
                );
                ticket = Some(reserved);
                true
            },
            narf_time::Deadline::after_ms(250),
        );
        if !posted {
            return Err(E1000Error::TxTimeout);
        }
        ticket.ok_or(E1000Error::Other("TX reservation lost"))
    }

    /// Enqueue a DMA address, optionally transferring ownership of its backing
    /// buffer to the completion path. The zero-copy fast path uses `owned =
    /// Some`; the public synchronous compatibility helper uses `None` and
    /// keeps ownership at its caller until DD.
    fn tx_enqueue_dma(
        &self,
        buf_phys: u64,
        len: usize,
        mut owned: Option<DmaBuffer>,
        kick: bool,
    ) -> Result<TxTicket, E1000Error> {
        if let Some(e) = self.gate_error() {
            if let Some(buf) = owned.take() {
                self.tx_zc_pool.release(buf);
            }
            return Err(e);
        }
        // Single-frame zero-copy submission: the cap is the
        // programmed MTU's wire size (issue #802). TSO super-frames
        // never come through here (`tx_tso_owned` posts directly
        // with its own MAX_TSO_FRAME cap).
        if len == 0 || len > crate::mtu::frame_size(*self.mtu.lock()) as usize {
            if let Some(buf) = owned.take() {
                self.tx_zc_pool.release(buf);
            }
            return Err(E1000Error::FrameTooLong);
        }
        let mut ticket = None;
        let posted = narf_scheduler::responsive_spin_until(
            || {
                let mut state = self.tx_state.lock();
                self.reclaim_tx_locked(&mut state);
                let Some(reserved) = state.cursor.reserve() else {
                    return false;
                };
                debug_assert!(state.owned[reserved.slot].is_none());
                state.owned[reserved.slot] = owned.take();
                self.post_tx_locked(&mut state, reserved, buf_phys, len, kick, None);
                ticket = Some(reserved);
                true
            },
            narf_time::Deadline::after_ms(250),
        );
        if !posted {
            if let Some(buf) = owned.take() {
                self.tx_zc_pool.release(buf);
            }
            return Err(E1000Error::TxTimeout);
        }
        ticket.ok_or(E1000Error::Other("TX reservation lost"))
    }

    /// Enable VLAN mode in hardware: program VET to 802.1Q, then
    /// set RCTL.VFE (filter) and CTRL.VME (strip/insert gate).
    /// Called on the first VID add; VET is programmed before the
    /// enable bits so no frame is filtered against a stale
    /// ethertype.
    fn vlan_mode_enable(&self) {
        // SAFETY: mapped MMIO; VET/RCTL/CTRL are valid 32-bit
        // register offsets within BAR0.
        unsafe {
            self.mmio.write32(REG_VET, VET_8021Q);
            let rctl = self.mmio.read32(REG_RCTL);
            self.mmio.write32(REG_RCTL, rctl | RCTL_VFE);
            let ctrl = self.mmio.read32(REG_CTRL);
            self.mmio.write32(REG_CTRL, ctrl | CTRL_VME);
        }
    }

    /// Opt a VID into the hardware VLAN filter (shadow + the one
    /// VFTA word; enabling VLAN mode on the first VID). Returns
    /// `true` iff the VID is now in the filter (`false` only for
    /// VID > 4095). Duplicate adds are no-ops that still return
    /// `true`.
    pub fn vlan_filter_add(&self, vid: u16) -> bool {
        let mut filter = self.vlan_filter.lock();
        let changed = filter.add(vid);
        if !changed {
            return filter.contains(vid);
        }
        let word = vfta_word(vid);
        let value = filter.word(word);
        let first = filter.count() == 1;
        drop(filter);
        // SAFETY: mapped MMIO; VFTA word `word` is within the
        // 128-word table for any valid VID.
        unsafe {
            self.mmio.write32(REG_VFTA_BASE + word as u64 * 4, value);
        }
        if first {
            self.vlan_mode_enable();
        }
        true
    }

    /// Remove a VID from the hardware VLAN filter. Returns `true`
    /// iff the VID was present (and is now removed). Clearing the
    /// last VID clears RCTL.VFE so VLAN frames pass unfiltered;
    /// CTRL.VME stays set: it only affects VET-matching packets,
    /// and the RX path re-inserts their tags, so leaving it set
    /// cannot corrupt untagged traffic — while clearing it
    /// mid-stream could un-strip a frame already in flight.
    pub fn vlan_filter_remove(&self, vid: u16) -> bool {
        let mut filter = self.vlan_filter.lock();
        if !filter.remove(vid) {
            return false;
        }
        let word = vfta_word(vid);
        let value = filter.word(word);
        let empty = filter.is_empty();
        drop(filter);
        // SAFETY: mapped MMIO; see `vlan_filter_add`.
        unsafe {
            self.mmio.write32(REG_VFTA_BASE + word as u64 * 4, value);
            if empty {
                let rctl = self.mmio.read32(REG_RCTL);
                self.mmio.write32(REG_RCTL, rctl & !RCTL_VFE);
            }
        }
        true
    }

    /// Number of VIDs currently in the hardware VLAN filter.
    pub fn vlan_filter_count(&self) -> usize {
        self.vlan_filter.lock().count()
    }

    /// Transmit one frame with an 802.1Q tag inserted by hardware
    /// (VLE + `special` TCI, SDM §3.3.3.1). Ensures CTRL.VME is set
    /// first — without it VLE is ignored. Same single-descriptor
    /// MTU-derived bound as `tx_enqueue` (the tag travels in the
    /// context descriptor, not the frame buffer); the stack's
    /// untagged path is untouched.
    pub fn tx_send_vlan(&self, frame: &[u8], tci: u16) -> Result<TxTicket, E1000Error> {
        // SAFETY: mapped MMIO; CTRL is a valid 32-bit register.
        unsafe {
            let ctrl = self.mmio.read32(REG_CTRL);
            if ctrl & CTRL_VME == 0 {
                self.mmio.write32(REG_CTRL, ctrl | CTRL_VME);
            }
        }
        self.tx_enqueue(frame, true, Some(tci))
    }

    /// Add a multicast address to the hardware hash filter (MTA
    /// shadow + the one MTA word). Returns `true` iff the address
    /// is now accepted (duplicate adds — same hash bit — are
    /// no-ops returning `true`). Filtering is already the
    /// bring-up default, so no RCTL change is needed here.
    pub fn multicast_add(&self, mac: &[u8; 6]) -> bool {
        let mut filter = self.multicast_filter.lock();
        let changed = filter.add(mac);
        if !changed {
            return filter.contains(mac);
        }
        let hash = multicast_hash12(mac, 0);
        let word = mta_word(hash);
        let value = filter.word(word);
        drop(filter);
        // SAFETY: mapped MMIO; MTA word `word` is within the
        // 128-word table for any 12-bit hash.
        unsafe {
            self.mmio.write32(REG_MTA_BASE + word as u64 * 4, value);
        }
        true
    }

    /// Remove a multicast address from the hash filter. Returns
    /// `true` iff its hash bit was set (and is now cleared). NOTE:
    /// hash collisions share a bit — removing one of two colliding
    /// addresses clears the bit for both (see `MulticastFilter`).
    pub fn multicast_remove(&self, mac: &[u8; 6]) -> bool {
        let mut filter = self.multicast_filter.lock();
        if !filter.remove(mac) {
            return false;
        }
        let hash = multicast_hash12(mac, 0);
        let word = mta_word(hash);
        let value = filter.word(word);
        drop(filter);
        // SAFETY: mapped MMIO; see `multicast_add`.
        unsafe {
            self.mmio.write32(REG_MTA_BASE + word as u64 * 4, value);
        }
        true
    }

    /// Clear the whole hash filter (all 128 MTA words to zero).
    /// Used by detach/reset paths.
    pub fn multicast_clear(&self) {
        let mut filter = self.multicast_filter.lock();
        filter.clear();
        drop(filter);
        // SAFETY: mapped MMIO; MTA spans 128 words from REG_MTA_BASE.
        unsafe {
            for word in 0..MTA_WORDS {
                self.mmio.write32(REG_MTA_BASE + word as u64 * 4, 0);
            }
        }
    }

    /// Program an exact-match RAL slot (1..=15) with `mac`.
    /// Returns `false` for slot 0 (station address, bring-up owned)
    /// or slot > 15. Exact-match slots complement the hash filter:
    /// they accept one address each, with no collision sharing.
    pub fn rar_program(&self, slot: usize, mac: &[u8; 6]) -> bool {
        if !rar_slot_ok(slot) {
            return false;
        }
        let (ral, rah) = rar_encode(mac);
        // SAFETY: mapped MMIO; slot 1..=15 maps to RAL offsets
        // REG_RAL0 + 8*slot (+4 for RAH), within the 16-entry array.
        unsafe {
            self.mmio
                .write32(REG_RAL0 + slot as u64 * REG_RAL_STRIDE, ral);
            self.mmio
                .write32(REG_RAL0 + slot as u64 * REG_RAL_STRIDE + 4, rah);
        }
        true
    }

    /// Clear an exact-match RAL slot (drops its AV bit). Same slot
    /// validation as `rar_program`.
    pub fn rar_clear(&self, slot: usize) -> bool {
        if !rar_slot_ok(slot) {
            return false;
        }
        // SAFETY: mapped MMIO; see `rar_program`.
        unsafe {
            self.mmio
                .write32(REG_RAL0 + slot as u64 * REG_RAL_STRIDE, 0);
            self.mmio
                .write32(REG_RAL0 + slot as u64 * REG_RAL_STRIDE + 4, 0);
        }
        true
    }

    /// Program a new interface MTU (issue #802), via the
    /// `DeviceControl` hook. Validates against the per-device
    /// ceiling before touching hardware (EINVAL 22); same-MTU is a
    /// no-op. Hardware is programmed before the stored MTU moves,
    /// so a reader never sees an MTU the device is not programmed
    /// for. TX/RX buffers are already sized for the family maximum
    /// at probe, so no ring rebuild is needed here.
    pub fn set_mtu(&self, mtu: u32) -> Result<(), i32> {
        const EINVAL: i32 = 22;
        if mtu == *self.mtu.lock() {
            return Ok(());
        }
        let program = crate::mtu::mtu_transition(self.did, mtu).map_err(|_| EINVAL)?;
        self.program_mtu(&program);
        *self.mtu.lock() = program.mtu;
        Ok(())
    }

    /// Program the RCTL receive word for `program` (BSIZE step +
    /// LPE), then re-derive the flow-control watermarks when pause
    /// reception is armed — the thresholds were computed for the
    /// old max frame (Linux's 2009 mtu-threshold fix, same shape).
    /// A plain RCTL read-modify-write like the VLAN/promiscuous
    /// paths; control-plane only, so the shared-RCTL race with
    /// those paths is the pre-existing one.
    fn program_mtu(&self, program: &crate::mtu::MtuProgram) {
        // SAFETY: identity-mapped MMIO; RCTL is a valid 32-bit register.
        unsafe {
            let rctl = self.mmio.read32(REG_RCTL);
            let rctl = (rctl & !(RCTL_BSIZE_MASK | RCTL_LPE)) | rctl_bsize_lpe(program.mtu);
            self.mmio.write32(REG_RCTL, rctl);
        }
        // SAFETY: mapped MMIO; CTRL/PBA/FCRTL/FCRTH are valid
        // 32-bit offsets within BAR0, and FCTTV/CTRL bits are
        // untouched here.
        unsafe {
            let ctrl = self.mmio.read32(REG_CTRL);
            if ctrl & (CTRL_RFCE | CTRL_TFCE) != 0 {
                let pba = self.mmio.read32(REG_PBA) & PBA_RXA_MASK;
                if let Some((low, high)) = flow_control_watermarks(pba, program.rx_frame) {
                    self.mmio.write32(REG_FCRTL, low | FCRTL_XONE);
                    self.mmio.write32(REG_FCRTH, high);
                }
            }
        }
    }

    /// Explicit promiscuous fallback: `true` restores the old
    /// UPE|MPE accept-all behavior; `false` returns to real
    /// filtering (exact-match RAL + MTA hash + broadcast).
    pub fn set_promiscuous(&self, enable: bool) {
        // SAFETY: mapped MMIO; RCTL is a valid 32-bit register.
        unsafe {
            let rctl = self.mmio.read32(REG_RCTL);
            let rctl = if enable {
                rctl | RCTL_UPE | RCTL_MPE
            } else {
                rctl & !(RCTL_UPE | RCTL_MPE)
            };
            self.mmio.write32(REG_RCTL, rctl);
        }
    }

    /// Zero-copy synchronous compatibility path. The caller retains the DMA
    /// buffer and must keep it alive until this method observes DD.
    pub fn tx_dma_frame(&self, buf_phys: u64, len: usize) -> Result<(), E1000Error> {
        let ticket = self.tx_enqueue_dma(buf_phys, len, None, true)?;
        let done = narf_scheduler::responsive_spin_until(
            || self.tx_slot_done(ticket),
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(E1000Error::TxTimeout);
        }
        Ok(())
    }

    /// Fire-and-forget zero-copy submission. Ownership moves into the ring and
    /// the buffer is returned to `tx_zc_pool` only after DD. This is the normal
    /// stack path and deliberately does not wait for each packet.
    fn tx_dma_owned(&self, buf: DmaBuffer, len: usize, kick: bool) -> Result<(), E1000Error> {
        if len > buf.len() {
            self.tx_zc_pool.release(buf);
            return Err(E1000Error::FrameTooLong);
        }
        let phys = buf.dma_addr().raw();
        self.tx_enqueue_dma(phys, len, Some(buf), kick).map(|_| ())
    }

    /// Fire-and-forget TSO submission. The caller has already normalized the
    /// packet headers and built `context`; ownership moves to the final data
    /// descriptor and is recycled only after that descriptor reports DD.
    fn tx_tso_owned(
        &self,
        buf: DmaBuffer,
        len: usize,
        context: TxContextDesc,
        kick: bool,
    ) -> Result<(), E1000Error> {
        if let Some(e) = self.gate_error() {
            self.tx_zc_pool.release(buf);
            return Err(e);
        }
        if len == 0 || len > MAX_TSO_FRAME || len > buf.len() {
            self.tx_zc_pool.release(buf);
            return Err(E1000Error::FrameTooLong);
        }
        let dma_addr = buf.dma_addr().raw();
        let mut owned = Some(buf);
        let posted = narf_scheduler::responsive_spin_until(
            || {
                let mut state = self.tx_state.lock();
                self.reclaim_tx_locked(&mut state);
                if state.cursor.available() < 1 + len.div_ceil(MAX_DATA_PER_TXD) {
                    return false;
                }
                let buf = owned
                    .take()
                    .expect("buffer retained until ring reservation");
                self.post_tso_locked(&mut state, dma_addr, len, context, buf, kick)
                    .is_some()
            },
            narf_time::Deadline::after_ms(250),
        );
        if posted {
            Ok(())
        } else {
            if let Some(buf) = owned.take() {
                self.tx_zc_pool.release(buf);
            }
            Err(E1000Error::TxTimeout)
        }
    }

    /// Completion check for sync/async callers. If the slot has already been
    /// reclaimed and reused, the ticket's descriptor necessarily completed.
    fn tx_slot_done(&self, ticket: TxTicket) -> bool {
        let state = self.tx_state.lock();
        // A ticket from before a watchdog recovery belongs to a ring
        // whose descriptors were discarded: its frame never went
        // out, and no later frame's DD bit on the same slot may
        // stand in for it. It stays "not done" so its `tx()` times
        // out honestly instead of reporting a success it did not earn.
        ticket.epoch == state.cursor.epoch
            && (state.cursor.ticket_was_reused(ticket) || self.tx_desc_done(ticket.slot))
    }

    /// Drain one received frame from the RX ring, copying it into
    /// `out` and returning the number of bytes. Returns 0 if no
    /// frame is currently pending. After consuming, the descriptor
    /// is rearmed and RDT is bumped so the device sees the freshly-
    /// available slot.
    /// Copy one received frame out of the ring, skipping (and counting)
    /// descriptors the RX verdict drops — frame errors and checksum
    /// failures — so a caller that polls for one frame never stalls on
    /// a bad frame at the head. Returns 0 when the ring holds no
    /// deliverable frame. Descriptors consumed by drops are re-armed
    /// and handed back via RDT exactly like delivered ones.
    pub fn rx_recv(&self, out: &mut [u8]) -> usize {
        if !self.datapath_open() {
            return 0;
        }
        let mut head_g = self.rx_head.lock();
        let mut head = (*head_g) as usize;
        let ring_phys = self.rx_ring.dma_addr().raw();
        // Count, not head comparison: a full ring of drops wraps `head`
        // back to its start, which a comparison would misread as "none".
        let mut dropped = 0usize;
        loop {
            let desc_addr = ring_phys + (head * 16) as u64;
            let Some(desc) = self.rx_completed_desc(head) else {
                // Ring empty. If drops were consumed above, hand those
                // descriptors back before returning; otherwise RDT is
                // already at the last freed slot.
                if dropped != 0 {
                    let last_freed = (head + RX_RING_LEN - 1) % RX_RING_LEN;
                    compiler_fence(Ordering::SeqCst);
                    // SAFETY: identity-mapped MMIO.
                    unsafe {
                        self.mmio.write32(REG_RDT, last_freed as u32);
                    }
                    *head_g = head as u32;
                }
                return 0;
            };
            if let Some(reason) = rx_drop_reason(&desc) {
                count_rx_drop(self.ifname(), reason);
                // Rearm the dropped descriptor: clear status, leave
                // addr as-is. RDT advances below once a deliverable
                // frame is found, or on the empty-exit above.
                let new_desc = RxDesc {
                    addr: desc.addr,
                    length: 0,
                    csum: 0,
                    status: 0,
                    errors: 0,
                    special: 0,
                };
                // SAFETY: identity-mapped DMA ring.
                unsafe {
                    core::ptr::write_volatile(
                        narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<RxDesc>(),
                        new_desc,
                    );
                }
                head = (head + 1) % RX_RING_LEN;
                dropped += 1;
                continue;
            }
            // Copy out the payload.
            let len = (desc.length as usize).min(out.len()).min(RX_BUF_LEN);
            let buf_phys = desc.addr;
            for (i, b) in out.iter_mut().enumerate().take(len) {
                // SAFETY: the RX buffer at `buf_phys` is an identity-mapped DMA
                // buffer the device filled; `i < len <= RX_BUF_LEN`, so the byte
                // address `buf_phys + i` stays within that buffer.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                *b = unsafe {
                    core::ptr::read_volatile(
                        narf_memory::PhysAddr::new(buf_phys + i as u64).kernel_ptr::<u8>(),
                    )
                };
            }
            // VLAN: hardware stripped the tag and recorded the TCI in
            // `special` (SDM §3.2). Restore the wire format in the
            // caller's buffer when it has room; otherwise deliver the
            // stripped frame (documented corner — the polled path's
            // caller owns the buffer size).
            let len = if desc.special != 0 {
                vlan_reinsert_tag(out, len, desc.special).unwrap_or(len)
            } else {
                len
            };
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
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<RxDesc>(),
                    new_desc,
                );
            }
            // Bump RDT to the just-freed slot. After consuming descriptor
            // `head`, the most recently freed slot is `head` itself —
            // RDT points at the last available slot for the device.
            // Dropped slots before it are freed by the same write: slots
            // are consumed in ring order, so every slot up to `head`
            // is available.
            let new_head = ((head + 1) % RX_RING_LEN) as u32;
            compiler_fence(Ordering::SeqCst);
            // SAFETY: identity-mapped MMIO.
            unsafe {
                self.mmio.write32(REG_RDT, head as u32);
            }
            *head_g = new_head;
            let _ = RXD_STAT_EOP; // EOP-multi-descriptor frames land in a follow-up.
            return len;
        }
    }

    /// Process up to `budget` received frames **in place** from their RX DMA
    /// pages, then return all consumed descriptors to hardware with one RDT
    /// doorbell. The device has set DD before each callback and a descriptor is
    /// re-armed only after its callback returns, so processing cannot race a
    /// device write. A bounded batch also keeps the cooperative executor fair.
    /// Returns the number of descriptors consumed — delivered frames plus
    /// verdict-dropped frames. The async pump treats nonzero as "ring
    /// activity, keep draining"; dropped frames never reach `f`.
    fn rx_drain_in_place<F: FnMut(&mut [u8])>(&self, budget: usize, mut f: F) -> usize {
        if !self.datapath_open() {
            return 0;
        }
        if budget == 0 {
            return 0;
        }
        let mut head_g = self.rx_head.lock();
        let mut head = (*head_g) as usize;
        let ring_phys = self.rx_ring.dma_addr().raw();
        let mut drained = 0;
        let limit = budget.min(RX_RING_LEN);
        while drained < limit {
            let desc_addr = ring_phys + (head * 16) as u64;
            let Some(desc) = self.rx_completed_desc(head) else {
                break;
            };
            // Verdict gate: dropped frames are re-armed and counted
            // below exactly like delivered ones (so `drained` still
            // counts consumed descriptors and the single RDT doorbell
            // hands them back), but `f` — and therefore the stack and
            // the RX mirror — never sees them.
            if let Some(reason) = rx_drop_reason(&desc) {
                count_rx_drop(self.ifname(), reason);
            } else {
                let len = (desc.length as usize).min(RX_BUF_LEN);
                // Descriptor `head` is backed by `rx_pool[head]` at probe and
                // re-armed in place (the buffer address never changes), so the
                // pairing is stable for the device's lifetime. Hand the stack a
                // mutable slice straight into that identity-mapped buffer.
                // SAFETY: the buffer is device-filled (DD set) and not concurrently
                // written (we re-arm only after `f` returns); it is identity-mapped
                // and `len <= RX_BUF_LEN`, so the slice stays within
                // the buffer. An XDP rewrite in `f` writes the DMA buffer we own.
                // VLAN: when CTRL.VME is set, hardware strips the tag and
                // records the TCI in `special` (SDM §3.2). Re-tag in place
                // before the stack sees the frame; the DMA page holds
                // RX_BUF_LEN bytes, so a stripped frame with room for 4
                // more bytes is restored to wire format. `special == 0`
                // is delivered as-is: either untagged, or a priority-only
                // tag (VID 0, priority 0, CFI 0), which carries no VLAN
                // membership and is indistinguishable from untagged in
                // the legacy descriptor. A frame that exactly fills the
                // buffer cannot be re-tagged in place and is delivered
                // stripped (documented corner).
                let page = self.rx_pool[head].cpu_mut_ptr_at::<u8>(0);
                let deliver_len = if desc.special != 0 {
                    // SAFETY: `page` is the base of the `rx_pool[head]` DMA buffer
                    // (one RX_BUF_LEN allocation per descriptor), which
                    // the driver owns; DD is set, so the device has finished
                    // writing it, and we re-arm only after `f` returns, so no
                    // concurrent device write aliases this slice. RX_BUF_LEN is
                    // the allocation size, so the slice is in-bounds and non-null.
                    let page_slice = unsafe { core::slice::from_raw_parts_mut(page, RX_BUF_LEN) };
                    vlan_reinsert_tag(page_slice, len, desc.special).unwrap_or(len)
                } else {
                    len
                };
                // SAFETY: same `rx_pool[head]` page as above; `deliver_len <=
                // RX_BUF_LEN` because `vlan_reinsert_tag` returns `None`
                // (falling back to `len`) unless `len + 4` fits in the
                // RX_BUF_LEN slice, and `len` itself is clamped to RX_BUF_LEN.
                // The slice ends before the descriptor is re-armed below, so
                // the device cannot write it concurrently while `f` runs.
                let frame = unsafe { core::slice::from_raw_parts_mut(page, deliver_len) };
                f(frame);
            }
            // Re-arm the descriptor: clear status, keep the same buffer
            // address. The final compiler fence orders every descriptor write
            // before the single tail doorbell below.
            let new_desc = RxDesc {
                addr: desc.addr,
                length: 0,
                csum: 0,
                status: 0,
                errors: 0,
                special: 0,
            };
            // SAFETY: identity-mapped DMA ring.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<RxDesc>(),
                    new_desc,
                );
            }
            head = (head + 1) % RX_RING_LEN;
            drained += 1;
        }
        if drained != 0 {
            let last_rearmed = (head + RX_RING_LEN - 1) % RX_RING_LEN;
            compiler_fence(Ordering::SeqCst);
            // SAFETY: identity-mapped MMIO; `last_rearmed` is the final RX
            // descriptor made available in this batch.
            unsafe {
                self.mmio.write32(REG_RDT, last_rearmed as u32);
            }
            *head_g = head as u32;
        }
        drained
    }

    /// Process one received frame **in place** from its RX DMA page — zero
    /// copy — then re-arm the descriptor. This is the single-frame public API;
    /// the asynchronous pump uses `rx_drain_in_place` to amortize its RDT
    /// doorbell across a burst. Returns `true` iff a descriptor was
    /// consumed (a frame delivered to `f`, or a verdict-dropped frame).
    pub fn rx_recv_in_place<F: FnMut(&mut [u8])>(&self, f: F) -> bool {
        self.rx_drain_in_place(1, f) != 0
    }

    /// The completed write-back of RX slot `slot`, or `None` while the
    /// device still owns it. DD-first, see [`RxDesc::sample`].
    fn rx_completed_desc(&self, slot: usize) -> Option<RxDesc> {
        debug_assert!(slot < RX_RING_LEN);
        RxDesc::sample(|word| {
            // SAFETY: coherent RX ring mapped for the controller's lifetime;
            // `slot < RX_RING_LEN` at every caller and `word` is 0 or 1, so
            // the aligned qword lies inside descriptor `slot`.
            u64::from_le(unsafe {
                core::ptr::read_volatile(
                    self.rx_ring
                        .cpu_ptr_at::<u64>((slot * 16 + word * 8) as u64),
                )
            })
        })
    }

    /// `true` if at least one RX descriptor has its DD bit set.
    /// Cheaper than `rx_recv` when callers want to poll without
    /// consuming. Gated like the drains: a suspended or detached
    /// device reports nothing pending so pollers idle instead of
    /// spinning on a ring the gates will not drain.
    pub fn rx_has_pending(&self) -> bool {
        if !self.datapath_open() {
            return false;
        }
        let head = (*self.rx_head.lock()) as usize;
        let ring_phys = self.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 12).kernel_ptr::<u8>())
        };
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

    /// Read + clear the Missed Packets Count — frames the MAC dropped because
    /// no RX descriptor was available (receive-FIFO overrun). e1000 statistics
    /// registers clear on read, so each call returns the count accumulated
    /// since the previous read.
    pub fn read_mpc(&self) -> u32 {
        // SAFETY: MPC (0x4010) is within the mapped BAR0 register window.
        unsafe { self.mmio.read32(REG_MPC) }
    }

    /// Read IMS (Interrupt Mask Set/Read, 8254x SDM §13.4.20). A
    /// non-zero value indicates IRQ-driven completion is armed.
    pub fn read_ims(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_IMS) }
    }

    // ── Power management and detach ─────────────────────────────────────
    //
    // The igb contract (`drivers/net/igb/src/igb.rs`, spec §3, issue
    // #789), adapted to e1000's legacy rings: a detach path must
    // publish link down, call `publish::clear_rx_mirror_attached` for
    // the interface name (e1000 dual-publishes: stack dispatch +
    // RX-mirror ring, and `eth%d` names are lowest-free-allocated
    // and reused), and unregister the interface; suspend of a
    // detached device fails, and every datapath entry point fails
    // fast once `detached` or `suspended` is set, so a parked pump
    // holding an `Arc<E1000>` can no longer touch the device.
    //
    // Linux order followed loosely (classic `e1000_suspend` →
    // `__e1000_shutdown`, `e1000_resume` in `e1000_main.c`): suspend
    // masks interrupts and stops the TX/RX DMA engines; resume
    // restores the bring-up control words and unmasks. Deliberate
    // NARF deltas, all documented here rather than silently
    // differing: (1) no PCI power-state transition — the bus layer
    // owns PCI config, this driver never power-gates the function;
    // (2) no full reset/reinit on resume — the rings persist across
    // suspend (only the EN bits gate DMA), so in-flight descriptor
    // state survives and resume is a control-word restore, not a
    // bring-up replay; (3) no PHY power-down on suspend and no PHY
    // power-up on resume — deliberate: the PHY is never powered
    // down, so its autoneg advertisement persists across suspend
    // and resume re-links without an AN restart;
    // (4) no WoL arming on suspend — WoL (audit gap 6) needs this
    // contract first and lands as its own item, so suspend is
    // always unarmed (no WUC/WUFC programming exists to clear).
    //
    // Flag ordering matters: suspend sets `suspended` BEFORE the
    // MMIO writes so a concurrent datapath entry fails at the gate
    // even before the DMA engines stop; resume restores the MMIO
    // words BEFORE clearing `suspended` so no datapath entry can
    // post to a still-stopped engine.

    /// Whether the datapath may run: false while suspended or
    /// detached. Factored pure so the fixture pins the gate the live
    /// paths use (igb's `datapath_allowed`, same shape).
    pub const fn datapath_allowed(detached: bool, suspended: bool) -> bool {
        !detached && !suspended
    }

    /// RCTL word for suspend/detach: the bring-up receive word with
    /// EN cleared — receive DMA stopped, all filter/config bits kept
    /// so resume restores exactly what bring-up programmed.
    const RCTL_SUSPEND_OFF: u32 = RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC | RCTL_BSIZE_2K;

    /// TCTL word for suspend/detach: the bring-up transmit word with
    /// EN cleared — transmit DMA stopped, PSP/CT/COLD/RTLC kept.
    const TCTL_SUSPEND_OFF: u32 = TCTL_PSP | TCTL_CT_15 | TCTL_COLD_63 | TCTL_RTLC;

    /// The gate error for a TX entry point, or `None` when the
    /// datapath is open. RX entry points use the same predicate and
    /// return their own empty value (0 / false).
    fn gate_error(&self) -> Option<E1000Error> {
        if self.detached.load(Ordering::Acquire) {
            Some(E1000Error::Other("e1000 device detached"))
        } else if self.suspended.load(Ordering::Acquire) {
            Some(E1000Error::Other("e1000 device suspended"))
        } else if self.recovering.load(Ordering::Acquire) {
            Some(E1000Error::Other("e1000 TX recovery in progress"))
        } else {
            None
        }
    }

    /// Whether this controller's datapath entry points may run.
    fn datapath_open(&self) -> bool {
        Self::datapath_allowed(
            self.detached.load(Ordering::Acquire),
            self.suspended.load(Ordering::Acquire),
        )
    }

    /// Suspend the device: mask interrupts, stop the TX/RX DMA
    /// engines, and publish link down. A second suspend is a no-op
    /// success; suspending a detached device fails. While suspended
    /// the datapath gates refuse TX and RX and `Interface::link_up`
    /// reports down. The LSC flag is cleared after masking so a
    /// stale transition cannot republish link up over suspend's
    /// DOWN sample (no new LSC can arrive once masked).
    pub fn suspend(&self) -> Result<(), E1000Error> {
        if self.detached.load(Ordering::Acquire) {
            return Err(E1000Error::Other("e1000 device detached"));
        }
        if self.suspended.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        // The register program lives in `pm::suspend_plan` so
        // fixtures drive the exact conversation against a fake
        // bank (issue #793); the live path runs it via `MmioBank`.
        // Suspend-off keeps the programmed BSIZE/LPE so resume
        // restores the jumbo program, not the 1500 default.
        pm::suspend_plan(
            &mut pm::MmioBank::new(&self.mmio),
            Self::RCTL_SUSPEND_OFF | rctl_bsize_lpe(*self.mtu.lock()),
        );
        self.lsc_pending.store(false, Ordering::Release);
        crate::publish::publish_link(self.ifname(), crate::publish::LinkSample::DOWN);
        Ok(())
    }

    /// Resume a suspended device: restore the bring-up RCTL/TCTL
    /// words, re-arm the interrupt mask (only when a vector is
    /// bound — polled devices keep the all-masked state bring-up
    /// left them in), and republish link from live STATUS.
    /// Resuming a running device is a no-op success; resuming a
    /// detached device fails. The rings were never torn down, so no
    /// descriptor re-priming is needed: RDT/RDH/TDT/TDH still point
    /// where suspend left them and DMA continues from there.
    pub fn resume(&self) -> Result<(), E1000Error> {
        if self.detached.load(Ordering::Acquire) {
            return Err(E1000Error::Other("e1000 device detached"));
        }
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        // The register program lives in `pm::resume_plan` so
        // fixtures drive the exact conversation against a fake
        // bank (issue #793); the words below are exactly the
        // bring-up program (RCTL at bring-up step 7, TCTL at
        // step 6), so resume cannot drift from bring-up — except the
        // BSIZE/LPE bits, which follow the programmed MTU (issue
        // #802) rather than the 1500 default.
        pm::resume_plan(
            &mut pm::MmioBank::new(&self.mmio),
            RCTL_EN
                | RCTL_BAM
                | RCTL_UPE
                | RCTL_MPE
                | RCTL_SECRC
                | rctl_bsize_lpe(*self.mtu.lock()),
            self.irq_vector.is_some(),
        );
        self.suspended.store(false, Ordering::Release);
        let status = self.read_status();
        crate::publish::publish_link(self.ifname(), link_sample_from_status(status));
        Ok(())
    }

    /// Device half of detach: set the datapath gate and drop the
    /// ISR's MMIO base first (so no new datapath work or late
    /// interrupt can race the teardown), then mask interrupts and
    /// stop the TX/RX units. There is no WoL arming to clear: this
    /// driver never programs WUC/WUFC. The registry half lives in
    /// [`e1000_detach`].
    fn detach_device(&self) {
        self.detached.store(true, Ordering::Release);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_IMC, !0u32);
            self.mmio.write32(REG_RCTL, Self::RCTL_SUSPEND_OFF);
            self.mmio.write32(REG_TCTL, Self::TCTL_SUSPEND_OFF);
        }
    }

    /// TX stall recoveries (Linux `tx_timeout_count`).
    pub fn tx_timeouts(&self) -> u64 {
        self.tx_timeouts.load(Ordering::Relaxed)
    }

    /// Controller resets performed by [`E1000::recover`].
    pub fn tx_resets(&self) -> u64 {
        self.tx_resets.load(Ordering::Relaxed)
    }

    /// Test-side accessor: the TX producer cursor — the slot the
    /// next `tx_enqueue` will fill. The multi-instance fixture
    /// snapshots it before `send_on` to prove the frame landed in
    /// the addressed port's TX slot buffer (issue #795).
    pub fn tx_next_to_use(&self) -> usize {
        self.tx_state.lock().cursor.next_to_use
    }

    /// Test-side accessor: true when TX pool slot `slot` currently
    /// holds the first 14 bytes of `frame` — the routing proof for
    /// the multi-instance fixture (issue #795): `tx_enqueue` copies
    /// the frame into `tx_pool[slot]` before posting the
    /// descriptor, so the bytes land exactly on the instance that
    /// was addressed.
    pub fn tx_slot_matches(&self, slot: usize, frame: &[u8]) -> bool {
        if slot >= TX_RING_LEN || frame.len() < 14 {
            return false;
        }
        let _state = self.tx_state.lock();
        for (k, expected) in frame.iter().take(14).enumerate() {
            // SAFETY: slot selects a live TX pool buffer, which holds
            // at least 14 bytes; k stays within those bytes. The TX lock
            // excludes CPU writers, and the device only reads TX data.
            let b =
                unsafe { core::ptr::read_volatile(self.tx_pool[slot].cpu_ptr_at::<u8>(k as u64)) };
            if b != *expected {
                return false;
            }
        }
        true
    }

    /// One watchdog pass (shared by the supervisor task and the
    /// fixture): if the link is up and a TX descriptor has waited
    /// past the timeout, count the timeout and recover. Returns
    /// true when recovery fired.
    fn check_tx_watchdog_at(&self, now: u64) -> bool {
        if self.detached.load(Ordering::Acquire)
            || self.suspended.load(Ordering::Acquire)
            || self.recovering.load(Ordering::Acquire)
        {
            return false;
        }
        if self.read_status() & STATUS_LU == 0 {
            return false;
        }
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        if !self.tx_state.lock().stalled(now, timeout) {
            return false;
        }
        self.tx_timeouts.fetch_add(1, Ordering::Relaxed);
        self.recover().is_ok()
    }

    /// TX-timeout recovery (Linux `e1000_tx_timeout` +
    /// `e1000e_reset` shape): stop the TX/RX units, master-reset
    /// the MAC, reprogram the rings and filters from the bring-up
    /// values and the live shadows, and restart. The TX cursor is
    /// reset — descriptors posted before the reset will never
    /// complete — and their zero-copy buffers are returned to the
    /// pool. A reset that never self-clears leaves the device
    /// stopped and reports `Other`; a concurrent recovery reports
    /// `Other` without touching the device.
    pub fn recover(&self) -> Result<(), E1000Error> {
        if self.detached.load(Ordering::Acquire) || self.suspended.load(Ordering::Acquire) {
            return Err(E1000Error::Other("e1000 device detached or suspended"));
        }
        if self.recovering.swap(true, Ordering::AcqRel) {
            return Err(E1000Error::Other("e1000 TX recovery already in progress"));
        }
        let result = self.recover_inner();
        self.recovering.store(false, Ordering::Release);
        if result.is_ok() {
            self.tx_resets.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn recover_inner(&self) -> Result<(), E1000Error> {
        // Preserve runtime promiscuous acceptance: bring-up programs
        // RCTL without UPE/MPE and `set_promiscuous` adds them later,
        // so a bare bring-up word here would silently drop the mode.
        // SAFETY: identity-mapped MMIO.
        let rctl_keep = unsafe { self.mmio.read32(REG_RCTL) } & (RCTL_UPE | RCTL_MPE);
        // 1. Stop the TX/RX units and mask interrupts (suspend
        // words: EN clear, PSP/CT/COLD kept).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_IMC, !0u32);
            let _ = self.mmio.read32(REG_ICR);
            self.mmio.write32(REG_TCTL, Self::TCTL_SUSPEND_OFF);
            self.mmio.write32(REG_RCTL, Self::RCTL_SUSPEND_OFF);
        }
        // 2. Master reset (CTRL.RST = 1; cleared by hardware after
        // reset). 8254x SDM §13.3.1: RST self-clears within ~10 ms;
        // 100 ms is the wedge threshold (same bound as bring-up).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_CTRL, CTRL_RST);
        }
        let cleared = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read32(REG_CTRL) } & CTRL_RST == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !cleared {
            return Err(E1000Error::Other("e1000 reset did not self-clear"));
        }
        // Zero the TX ring: a descriptor the reset abandoned keeps
        // whatever DD state it had, and a later frame's DD bit on
        // the same slot must not stand in for a dropped one. (The
        // cursor epoch already bars that, but the ring itself should
        // not carry pre-reset state either.)
        // SAFETY: the TX ring is a coherent DMA buffer of exactly
        // `TX_RING_LEN * size_of::<TxDesc>()` bytes.
        unsafe {
            core::ptr::write_bytes(
                self.tx_ring.cpu_mut_ptr_at::<u8>(0),
                0,
                TX_RING_LEN * core::mem::size_of::<TxDesc>(),
            );
        }
        // 3. Reprogram the station address (bring-up step 2) and the
        // TX ring (steps 4–5) from the live ring allocation.
        let (ral, rah) = rar_encode(&self.mac);
        let tx_phys = self.tx_ring.dma_addr().raw();
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_RAL0, ral);
            self.mmio.write32(REG_RAH0, rah);
            self.mmio.write32(REG_TDBAL, tx_phys as u32);
            self.mmio.write32(REG_TDBAH, (tx_phys >> 32) as u32);
            self.mmio.write32(REG_TDLEN, (TX_RING_LEN * 16) as u32);
            self.mmio.write32(REG_TDH, 0);
            self.mmio.write32(REG_TDT, 0);
            self.mmio.write32(REG_TIPG, TIPG_COPPER_DEFAULT);
            self.mmio.write32(
                REG_TCTL,
                TCTL_EN | TCTL_PSP | TCTL_CT_15 | TCTL_COLD_63 | TCTL_RTLC,
            );
        }
        // 4. Re-prime the RX descriptors from the pool (bring-up
        // step 5b) and reprogram the RX ring + filters from the
        // shadows.
        let rx_phys = self.rx_ring.dma_addr().raw();
        for (i, buf) in self.rx_pool.iter().enumerate().take(RX_RING_LEN) {
            let buf_dma = buf.dma_addr();
            let desc = RxDesc {
                addr: buf_dma.raw(),
                length: 0,
                csum: 0,
                status: 0,
                errors: 0,
                special: 0,
            };
            // SAFETY: coherent DMA ring via the kernel direct map.
            unsafe {
                core::ptr::write_volatile(
                    self.rx_ring.cpu_mut_ptr_at::<RxDesc>((i * 16) as u64),
                    desc,
                );
            }
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_RDBAL, rx_phys as u32);
            self.mmio.write32(REG_RDBAH, (rx_phys >> 32) as u32);
            self.mmio.write32(REG_RDLEN, (RX_RING_LEN * 16) as u32);
            self.mmio.write32(REG_RDH, 0);
            self.mmio.write32(REG_RDT, (RX_RING_LEN - 1) as u32);
            for word in 0..VFTA_WORDS {
                self.mmio.write32(
                    REG_VFTA_BASE + word as u64 * 4,
                    self.vlan_filter.lock().word(word),
                );
            }
            for word in 0..MTA_WORDS {
                self.mmio.write32(
                    REG_MTA_BASE + word as u64 * 4,
                    self.multicast_filter.lock().word(word),
                );
            }
            self.mmio.write32(
                REG_RCTL,
                RCTL_EN | RCTL_BAM | RCTL_SECRC | RCTL_BSIZE_2K | rctl_keep,
            );
            // Flow-control defaults (bring-up step 6b): thresholds
            // zero, RFCE/TFCE clear.
            self.mmio.write32(REG_FCRTL, 0);
            self.mmio.write32(REG_FCRTH, 0);
            let ctrl = self.mmio.read32(REG_CTRL);
            self.mmio.write32(REG_CTRL, ctrl & !CTRL_FC_MASK);
        }
        // 5. Set link up and re-enable interrupts (bring-up steps
        // 6 + 9; the ISR base is unchanged by the reset).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            let cur = self.mmio.read32(REG_CTRL);
            self.mmio.write32(REG_CTRL, cur | CTRL_SLU);
            if self.irq_vector.is_some() {
                self.mmio.write32(
                    if self._msix.is_some() {
                        REG_EITR0_82574
                    } else {
                        REG_ITR
                    },
                    ITR_20K_INTERRUPTS_PER_SEC,
                );
                self.mmio.write32(REG_IMS, IMS_DEFAULT);
            }
        }
        // 6. Reset the software cursors now that the rings are
        // fresh: posted descriptors will never complete, so their
        // slots are free and their post times are void. Owned
        // zero-copy buffers go back to the pool.
        let owned = {
            let mut state = self.tx_state.lock();
            state.reset()
        };
        for buf in owned.into_iter().flatten() {
            self.tx_zc_pool.release(buf);
        }
        *self.rx_head.lock() = 0;
        let status = self.read_status();
        crate::publish::publish_link(self.ifname(), link_sample_from_status(status));
        Ok(())
    }
}

impl E1000 {
    /// This instance's published interface name (`eth%d`), or `""`
    /// before probe publishes it. Per-instance state (i40e/igc
    /// pattern); the pumps and the registry adapter read the name
    /// off the device they serve, never a module-level static.
    pub fn ifname(&self) -> &'static str {
        self.ifname.get()
    }
}

// ── Suspend/resume register plans (issue #793) ───────────────────────
//
// The register conversation `E1000::suspend` / `E1000::resume` run,
// factored over a minimal bank so fixtures drive the exact program
// against a fake bank (end-to-end register writes, no silicon) while
// the live path runs it against BAR0 via [`MmioBank`]. Same shape as
// ixgbe's `pm` + `queues::RegBank`. No new constants: every word is
// the driver's existing bring-up / suspend word, so the plan cannot
// drift from the live sequence it factors out of.
//
// Deliberate deltas (unchanged from the methods above): no PCI
// power-state transition — the bus layer owns PCI config, this
// driver never power-gates the function; no full reset/reinit on
// resume — the rings persist across suspend (only the EN bits gate
// DMA); no PHY power-down — the PHY is never powered down, so its
// autoneg advertisement persists and resume re-links without an AN
// restart; no WoL arming — WoL (audit gap 6) lands as its own item.
mod pm {
    use super::{
        MmioRegion, IMS_DEFAULT, REG_ICR, REG_IMC, REG_IMS, REG_RCTL, REG_STATUS, REG_TCTL,
        TCTL_COLD_63, TCTL_CT_15, TCTL_EN, TCTL_PSP, TCTL_RTLC,
    };
    use crate::e1000::E1000;

    /// Minimal 32-bit register-bank abstraction so the register
    /// conversation can be exercised against a fake bank in fixtures
    /// and against real MMIO in the driver via [`MmioBank`].
    pub trait RegBank {
        fn read32(&self, offset: u64) -> u32;
        fn write32(&mut self, offset: u64, value: u32);
    }

    /// [`RegBank`] over a real BAR0 mapping.
    #[derive(Debug)]
    pub struct MmioBank<'a> {
        mmio: &'a MmioRegion,
    }

    impl<'a> MmioBank<'a> {
        pub fn new(mmio: &'a MmioRegion) -> Self {
            Self { mmio }
        }
    }

    impl RegBank for MmioBank<'_> {
        fn read32(&self, offset: u64) -> u32 {
            // SAFETY: the driver owns BAR0 exclusively; the caller
            // guarantees `offset` is a valid device register.
            unsafe { self.mmio.read32(offset) }
        }
        fn write32(&mut self, offset: u64, value: u32) {
            // SAFETY: same as above.
            unsafe { self.mmio.write32(offset, value) }
        }
    }

    /// Suspend register program: mask interrupts (IMC is
    /// write-1-to-clear; the ICR read drains any cause bits already
    /// latched), then stop the TX/RX DMA engines with the EN bits
    /// cleared and all filter/config bits kept, so resume restores
    /// exactly what bring-up programmed. The caller passes the
    /// RCTL word with the programmed BSIZE/LPE (issue #802), so
    /// suspend preserves the jumbo program for resume.
    pub fn suspend_plan(bank: &mut impl RegBank, rctl: u32) {
        bank.write32(REG_IMC, !0u32);
        let _ = bank.read32(REG_ICR);
        bank.write32(REG_TCTL, E1000::TCTL_SUSPEND_OFF);
        bank.write32(REG_RCTL, rctl);
    }

    /// Resume register program: restore the bring-up RCTL/TCTL
    /// words, re-arm the interrupt mask only when a vector is bound
    /// (polled devices keep the all-masked state bring-up left them
    /// in), then sample live STATUS so the caller can republish link
    /// from hardware rather than from a stale snapshot. The caller
    /// passes the RCTL word with the programmed BSIZE/LPE
    /// (issue #802) rather than the 1500 default.
    pub fn resume_plan(bank: &mut impl RegBank, rctl: u32, irq_bound: bool) -> u32 {
        bank.write32(REG_RCTL, rctl);
        bank.write32(
            REG_TCTL,
            TCTL_EN | TCTL_PSP | TCTL_CT_15 | TCTL_COLD_63 | TCTL_RTLC,
        );
        if irq_bound {
            bank.write32(REG_IMS, IMS_DEFAULT);
        }
        bank.read32(REG_STATUS)
    }
}

impl narf_power::device_pm::DevicePmOps for E1000 {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.suspend()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.resume()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
}

// ── Driver-match registration ────────────────────────────────────────

/// Every probed controller, by probe order. The index is the cookie
/// the kernel-side stack's send path resolves through
/// [`e1000_send_frame`] — the i40e `CONTROLLERS` pattern, so a second
/// 8254x on the same machine probes, binds, and carries traffic
/// instead of being dropped by a singleton slot (issue #795). The
/// vec never shrinks: detaches mark the device in place instead of
/// removing its slot, so a live controller's cookie stays valid for
/// the kernel lifetime.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<E1000>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// The probed controller at `index`, if it is live (probed and not
/// detached). The index is the cookie probe assigned (see
/// `CONTROLLERS`); it is stable because the vec never shrinks.
fn live_controller(index: usize) -> Option<Arc<E1000>> {
    CONTROLLERS
        .lock()
        .get(index)
        .filter(|c| !c.detached.load(Ordering::Acquire))
        .cloned()
}

/// `DeviceControl` hook for the runtime MTU switch (issue #802).
/// Mirrors r8169's `RtlMtuControl`: only the MTU is acted on —
/// MAC/promiscuous/multicast changes pass through untouched (the
/// same-MTU no-op keeps `try_set_mac` metadata-only, as before).
#[derive(Debug)]
pub struct E1000MtuControl {
    controller: Arc<E1000>,
}

impl narf_net::iface::DeviceControl for E1000MtuControl {
    fn configure(&self, config: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
        self.controller.set_mtu(config.mtu)
    }
}

/// Detach the bound e1000 device at `index`, if any: device half
/// (mask, stop DMA, drop the ISR base, set the datapath gate), then
/// the registry half the net spec §3 obliges — publish link down,
/// clear the RX-mirror attach note for the interface name (names are
/// lowest-free-allocated and reused), and unregister the interface.
/// Idempotent: an out-of-range index or an already-detached device
/// does nothing. The async pumps are not joined (they hold
/// `Arc<E1000>` clones), but every datapath entry point fails fast
/// once detached, so a parked pump can no longer touch the device.
/// The `CONTROLLERS` slot is kept so other controllers' cookies
/// stay valid.
pub fn e1000_detach(index: usize) {
    let Some(device) = CONTROLLERS.lock().get(index).cloned() else {
        return;
    };
    if device.detached.load(Ordering::Acquire) {
        return;
    }
    device.detach_device();
    let name = device.ifname();
    crate::publish::publish_link(name, crate::publish::LinkSample::DOWN);
    crate::publish::clear_rx_mirror_attached(name);
    let _ = narf_net::iface::unregister(name);
    narf_power::device_pm::unregister_device_pm(name);
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // A second probe of the SAME live function is a no-op success
    // (the old idempotent behaviour): the bus re-walks devices, and
    // rebuilding a second `E1000` for the same silicon would let two
    // instances drive one chip's rings. A second FUNCTION binds as a
    // new instance instead of being dropped (issue #795). A detached
    // entry does not block a re-probe of its address, so a hot
    // re-bind after detach can reclaim the function.
    if CONTROLLERS
        .lock()
        .iter()
        .any(|c| c.addr == device.addr && !c.detached.load(Ordering::Acquire))
    {
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
    *dev_inner.rx_ipc_prod.lock() = Some(rx_prod);
    let dev = Arc::new(dev_inner);
    // Retain before any ring DMA address reaches the device; the
    // index is this instance's send-path cookie (see `CONTROLLERS`).
    let index = {
        let mut g = CONTROLLERS.lock();
        g.push(dev.clone());
        g.len() - 1
    };
    spawn_pumps(dev.clone(), tx_cons);

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
    // in `responsive_spin_until`. The send hook carries this
    // instance's `CONTROLLERS` index as its cookie, so each port's
    // outbound frames resolve to its own NIC.
    let name = crate::publish::publish_netdev_with_context(
        dev.mac,
        index as u64,
        e1000_send_frame,
        link_sample_from_status(dev.read_status()),
    );
    // `e1000_get_drvinfo`: driver "e1000", no version (the core reports the
    // kernel release), bus_info = pci_name().
    let bus_info = match device.addr {
        narf_bus::BusAddr::Pcie(pci) => alloc::format!("{:?}", pci),
        narf_bus::BusAddr::Mmio(_) => alloc::string::String::new(),
    };
    narf_net::iface::set_driver_info(&name, "e1000", None, bus_info);
    // Runtime MTU switch (issue #802): `try_set_mtu` validates
    // against the per-device ceiling and programs RCTL before the
    // registry commits the new MTU.
    let _ = narf_net::iface::set_device_control(
        &name,
        Arc::new(E1000MtuControl {
            controller: dev.clone(),
        }),
    );
    let status = dev.read_status();
    crate::publish::publish_link(&name, link_sample_from_status(status));
    narf_net::iface::set_offloads(
        &name,
        narf_net::OffloadCapabilities {
            // The live path below implements 8254x IPv4/TCP context + data
            // descriptors. The TCP stack currently limits this capability to
            // IPv4 until the IPv6 context/header contract is wired too.
            max_tso_bytes: MAX_TSO_FRAME as u32,
            ..Default::default()
        },
    );
    dev.ifname.set(name.clone());
    // Device-PM registration (#793): system suspend fans out
    // through `E1000::suspend` / `E1000::resume` via the
    // `DevicePmOps` impl above. The registry is idempotent on the
    // interface name; detach withdraws the entry.
    narf_power::device_pm::register_device_pm_ops(dev.ifname(), dev.clone());
    narf_net::iface::install_rx_drain(rx_pump_step);
    // The legacy e1000 has one RX queue and delivers ordinary MTU-sized
    // descriptors, so software GRO is what amortizes the shared stack work at
    // gigabit packet rates. The coalescer excludes loopback and preserves
    // control/options boundaries; the RX pump flushes it whenever the ring is
    // drained to empty.
    let _ = narf_net::iface::set_software_gro(&name, true);
    // Opt into zero-copy TX (P-F): the stack builds egress frames straight into
    // a pooled DMA buffer and hands it to `e1000_send_frame_zc`, which DMAs it
    // without the per-frame slice copy `e1000_send_frame` does. The 64 KiB
    // buffers also hold a complete bounded TSO super-frame; completion returns
    // them to the same TX-ring-deep recycling pool. The context form
    // carries this instance's `CONTROLLERS` index as its cookie (igc
    // pattern), so a second port's zero-copy frames resolve to its
    // own pool instead of the first port's.
    narf_net::iface::enable_zero_copy_tx_context(
        &name,
        index as u64,
        e1000_send_frame_zc,
        alloc::vec![dev.tx_zc_pool.clone()],
        0,
        false,
    );

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, E1000Nic { nic: dev.clone() });
    }

    Ok(())
}

fn spawn_pumps(device: Arc<E1000>, tx_cons: Consumer<Frame, TX_RING_N>) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        e1000_rx_pump(d1).await;
    });

    let d2 = device.clone();
    narf_scheduler::spawn(async move {
        e1000_tx_pump(d2, tx_cons).await;
    });

    let d3 = device;
    narf_scheduler::spawn(async move {
        e1000_watchdog_pump(d3).await;
    });
}

async fn e1000_rx_pump(device: Arc<E1000>) {
    // Build the IRQ waiter BEFORE checking DD. WaitForIrq snapshots the
    // vector's fire count, so an interrupt racing the empty-ring check either
    // makes the waiter immediately ready or invokes its registered waker. The
    // old 1-ms timer poll capped a receiver to roughly one ACK opportunity per
    // millisecond (~17 Mbit/s in the TAP iperf diagnostic).
    //
    // Once awake, drain without yielding until the ring is empty. This is the
    // same shape as an interrupt-driven NAPI poll: the device interrupt starts
    // a burst, then descriptor DD bits drive the hot path without one wake per
    // packet. A short deadline remains as a lost-interrupt safety net; devices
    // without a wired vector retain the 1-ms polling fallback.
    const IRQ_FALLBACK_MS: u64 = 10;
    let poll_fallback_cycles = narf_time::ns_to_cycles(1_000_000);
    loop {
        // Link Status Change drain (issue #791): the ISR flagged a
        // transition; re-sample STATUS in task context and republish.
        // The pump wakes on the same interrupt (LSC is in IMS_DEFAULT)
        // or on the 10 ms fallback, so this adds no polling loop.
        if device.lsc_pending.swap(false, Ordering::AcqRel) {
            let status = device.read_status();
            crate::publish::publish_link(device.ifname(), link_sample_from_status(status));
        }
        let irq_waiter = device.irq_vector.map(|vector| {
            narf_interrupts::wait_for_irq_until(
                vector,
                narf_time::Deadline::after_ms(IRQ_FALLBACK_MS),
            )
        });
        if device.rx_drain_in_place(RX_DRAIN_BUDGET, |frame| dispatch_rx_frame(&device, frame)) != 0
        {
            continue;
        }

        // Empty ring is the NAPI-complete point for software GRO. This is a
        // no-op when this CPU holds no GRO flows.
        narf_net::tcp_stack::gro_flush();
        let missed = device.read_mpc();
        if missed > 0 {
            narf_net::iface::note_rx_overrun(device.ifname(), missed as u64);
        }
        match irq_waiter {
            Some(waiter) => {
                let _ = waiter.await;
            }
            None => narf_time::sleep_cycles(poll_fallback_cycles).await,
        }
    }
}

async fn e1000_tx_pump(device: Arc<E1000>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.tx(frame.payload());
    }
}

/// TX-timeout supervisor (igc maintenance-task shape): every 10 ms
/// run one watchdog pass; a queue stalled 5 s with carrier up is
/// recovered and counted. The pass itself gates on detach/suspend
/// and on an in-flight recovery, so this loop is only a timer.
async fn e1000_watchdog_pump(device: Arc<E1000>) {
    let tick = narf_time::ns_to_cycles(TX_WATCHDOG_POLL_NS);
    loop {
        narf_time::sleep_cycles(tick).await;
        device.check_tx_watchdog_at(narf_time::now_cycles());
    }
}

/// Single RX fan-out used by both the async task and syscall-context drain.
/// Previously the async task consumed frames into the raw frame ring while
/// `rx_pump_step` independently consumed frames into TCP; whichever won the
/// race stole the packet from the other path. In particular, lost TCP ACKs
/// collapsed e1000 throughput into multi-second RTO gaps.
fn dispatch_rx_frame(device: &E1000, frame: &mut [u8]) {
    // Preserve the raw frame-ring contract only after a consumer attaches.
    // The copy happens before stack/XDP dispatch because that path may mutate
    // headers in place. A full or closed observer ring drops its mirror, never
    // the packet destined for the live network stack.
    if device.rx_mirror_enabled.load(Ordering::Acquire) {
        if let Ok(dma_buf) = alloc_coherent(frame.len(), crate::BUILTIN_DOMAIN) {
            let mut mirror = Frame::new(dma_buf, frame.len() as u32);
            mirror.payload_mut().copy_from_slice(frame);
            if let Some(prod) = device.rx_ipc_prod.lock().as_mut() {
                let _ = prod.try_send(mirror);
            }
        }
    }
    narf_net::iface::on_rx_frame_from(device.ifname(), frame);
}

/// `SendCtxFn` registered with `narf_net::iface` at probe time. Routes
/// the kernel-side TCP stack's outbound frames through E1000::tx; the
/// cookie is the controller's index in `CONTROLLERS`.
fn e1000_send_frame(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    // Clone the Arc out rather than holding the IRQ-masking CONTROLLERS
    // lock across `tx`, which busy-polls the DD bit for up to 250 ms.
    // Holding it here masked interrupts on this CPU for the whole
    // hardware wait and made every concurrent sender (and the RX pump)
    // spin on the same lock, interrupts masked — a thundering herd that
    // starves timers and RCU. See `controller`.
    let ctrl = live_controller(cookie as usize).ok_or(())?;
    if let Some(mss) = meta.tso_mss {
        let mut buf = ctrl.tx_zc_pool.try_acquire().ok_or(())?;
        if frame.len() > buf.len() {
            ctrl.tx_zc_pool.release(buf);
            return Err(());
        }
        buf.as_mut_slice()[..frame.len()].copy_from_slice(frame);
        let context = match prepare_ipv4_tso(&mut buf.as_mut_slice()[..frame.len()], mss) {
            Ok(context) => context,
            Err(_) => {
                ctrl.tx_zc_pool.release(buf);
                return Err(());
            }
        };
        return ctrl
            .tx_tso_owned(buf, frame.len(), context, !meta.more)
            .map_err(|_| ());
    }
    ctrl.tx_enqueue(frame, !meta.more, None)
        .map(|_| ())
        .map_err(|_| ())
}

/// Zero-copy `SendFrameCtxFn` (P-F): the stack built this frame directly into a
/// DMA buffer from the controller's shared TX pool. Transfer ownership to the
/// descriptor ring and return after publication; completion reclaim recycles
/// the buffer only after hardware writes DD. The cookie is the
/// controller's index in `CONTROLLERS` (see `enable_zero_copy_tx_context`
/// in probe); resolving it here is what keeps a second port's
/// zero-copy frames out of the first port's pool.
fn e1000_send_frame_zc(
    cookie: u64,
    mut frame: narf_net::Frame,
    meta: narf_net::TxMeta,
) -> Result<(), ()> {
    let ctrl = live_controller(cookie as usize).ok_or(())?;
    let context = match meta.tso_mss {
        Some(mss) => match prepare_ipv4_tso(frame.payload_mut(), mss) {
            Ok(context) => Some(context),
            Err(_) => {
                let (buf, _, _) = frame.into_parts_with_offset();
                ctrl.tx_zc_pool.release(buf);
                return Err(());
            }
        },
        None => None,
    };
    let (buf, offset, len) = frame.into_parts_with_offset();
    if offset != 0 {
        ctrl.tx_zc_pool.release(buf);
        return Err(());
    }
    match context {
        Some(context) => ctrl
            .tx_tso_owned(buf, len as usize, context, !meta.more)
            .map_err(|_| ()),
        None => ctrl
            .tx_dma_owned(buf, len as usize, !meta.more)
            .map_err(|_| ()),
    }
}

/// Drain one frame from each live controller's RX ring + dispatch it
/// through the network stack's RX handler. Returns true iff any ring
/// advanced (a frame was delivered, or a verdict-dropped frame was
/// consumed). Called from a kernel-side polling task spawned at boot.
/// Every live port is drained (not just the first): with one global
/// drain step, a second NIC's replies would otherwise stall until its
/// async pump gets CPU — which never happens while the syscall is
/// parked (issue #795).
pub fn rx_pump_step() -> bool {
    // Zero-copy: dispatch the frame straight out of its RX DMA page rather than
    // copying it into a scratch buffer first (P-F). Same lock discipline as
    // `e1000_send_frame` — `rx_recv_in_place` holds only the controller's
    // `rx_head` lock across the synchronous stack dispatch, never CONTROLLERS,
    // so a TX stuck in its 250 ms DD poll cannot stall RX. An attached XDP
    // program rewriting header bytes writes the DMA page directly, which the
    // driver owns until it re-arms the slot after dispatch returns.
    // Clone the handles out first so no `CONTROLLERS` lock is held
    // across the synchronous stack dispatch.
    let controllers: alloc::vec::Vec<Arc<E1000>> = CONTROLLERS
        .lock()
        .iter()
        .filter(|c| !c.detached.load(Ordering::Acquire))
        .cloned()
        .collect();
    let mut any = false;
    for c in controllers {
        if c.rx_recv_in_place(|frame| dispatch_rx_frame(&c, frame)) {
            any = true;
        }
    }
    any
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
    // I210 / I211 / 82576 / I350 moved to the dedicated advanced-descriptor
    // `narf-drivers-net-igb` crate — it is their sole PCI owner now.
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
        // I210 / I211 / 82576 / I350 now live in `narf-drivers-net-igb`.
        _ => "e1000",
    }
}

/// The `narf_net::Interface` + `HwNic` adapter probe registers for
/// one e1000 instance. Holds the instance's `Arc<E1000>` directly:
/// the old zero-sized `E1000Nic` resolved every call through the
/// module-level `CONTROLLER` singleton, so a second 8254x's
/// interface reported the first port's MAC, link state, and rings
/// (issue #795). The rings are borrowed from the NIC's own
/// `rx_ipc_ring` / `tx_ipc_ring` fields. The name always comes from
/// `E1000::ifname()`, which is `""` before probe publishes it
/// (matching the old `e1000_ifname()` default).
#[derive(Debug)]
pub struct E1000Nic {
    nic: Arc<E1000>,
}

impl narf_net::Interface for E1000Nic {
    fn name(&self) -> &str {
        self.nic.ifname()
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        // Per-port programmed MTU (#802): read off this Nic's own
        // controller, not the `CONTROLLERS` registry — the old
        // singleton `with_controller` lookup is gone on main (#1633)
        // and would report the wrong port's MTU on a second 8254x.
        *self.nic.mtu.lock()
    }
    fn link_up(&self) -> bool {
        // Probe-time value, gated on suspend. Live transitions still
        // arrive via `publish_link` / the LSC drain.
        self.nic.link_up && !self.nic.suspended.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        // Ring consumer attached: enable this instance's RX mirror —
        // the old take-into-static set `rx_mirror_enabled` at this
        // moment — and record the attach under this port's own name,
        // so detach can clear it. The flag is one-way, never cleared.
        self.nic.rx_mirror_enabled.store(true, Ordering::Release);
        crate::publish::note_rx_mirror_attached(self.nic.ifname());
        &self.nic.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.nic.tx_ipc_ring
    }
}

impl crate::HwNic for E1000Nic {
    fn name(&self) -> &'static str {
        self.nic.ifname()
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        // Per-port programmed MTU (#802): read off this Nic's own
        // controller — see the `Interface` impl above.
        *self.nic.mtu.lock()
    }
    fn link_up(&self) -> bool {
        // Same suspend gate as the `Interface` impl above.
        self.nic.link_up && !self.nic.suspended.load(Ordering::Acquire)
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::IntelE1000
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::TX_CSUM
            | crate::NicCaps::RX_CSUM
            | crate::NicCaps::VLAN_TAGGING
            | crate::NicCaps::MULTICAST_HASH
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

/// True iff at least one controller is live (probed and not
/// detached).
pub fn is_probed() -> bool {
    CONTROLLERS
        .lock()
        .iter()
        .any(|c| !c.detached.load(Ordering::Acquire))
}

/// Number of live controllers. The index of a controller in
/// `CONTROLLERS` is its send-path cookie; the vec never shrinks, so
/// a live controller's cookie is stable for the kernel lifetime.
pub fn instance_count() -> usize {
    CONTROLLERS
        .lock()
        .iter()
        .filter(|c| !c.detached.load(Ordering::Acquire))
        .count()
}

/// Clone the controller handle at `index`, holding `CONTROLLERS`
/// only for the refcount bump.
///
/// `CONTROLLERS` is an `IrqSafeSpinLock`, so holding it across a
/// device round-trip masks interrupts on the waiting CPU for the
/// whole wait and forces every other CPU touching the NIC to spin
/// with interrupts masked too — `tx` busy-polls the descriptor DD
/// bit for up to 250 ms, which starves timers and RCU exactly like
/// the virtio-blk CONTROLLER herd. Cloning the `Arc` out instead
/// keeps the device alive without any lock held; mutual exclusion
/// on the rings is provided by the controller's own
/// `tx_state`/`rx_head` locks, which are held only across the
/// bounded descriptor post/drain, never across the DD poll.
/// Returns `None` for an out-of-range index or a detached device.
pub fn controller(index: usize) -> Option<Arc<E1000>> {
    live_controller(index)
}

/// Run `f` against the controller at `index` WITHOUT holding
/// `CONTROLLERS` for the duration — see [`controller`]. `f` may
/// block or poll the device; interrupts keep their caller-supplied
/// state throughout.
pub fn with_controller<R>(index: usize, f: impl FnOnce(&E1000) -> R) -> Option<R> {
    controller(index).map(|a| f(&a))
}

/// IRQ-driven RX on the controller at `index`. Constructs the
/// `wait_for_irq` future *before*
/// inspecting the ring (so an IRQ that lands between the ring drain
/// and the await still wakes us — the future snapshots fire-count
/// at construction). On wake, drains one frame into `out` and
/// returns the byte count. Returns 0 if no controller is bound or
/// no IRQ vector is wired (caller should fall back to `rx_recv`).
pub async fn rx_async(index: usize, out: &mut [u8]) -> usize {
    let vector = match with_controller(index, |c| c.irq_vector).flatten() {
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
    if let Some(n) = with_controller(index, |c| {
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
    with_controller(index, |c| c.rx_recv(out)).unwrap_or(0)
}

/// IRQ-driven TX on the controller at `index`. Posts `frame` to the
/// TX ring then awaits TXDW.
/// Mirrors the polled `tx` semantics (one frame per call) but parks
/// the caller on the IRQ instead of spinning on DD. Falls back to
/// the polled `tx` path if no IRQ vector is wired.
pub async fn tx_async(index: usize, frame: &[u8]) -> Result<(), E1000Error> {
    let vector = match with_controller(index, |c| c.irq_vector).flatten() {
        Some(v) => v,
        None => {
            // No IRQ wired — synchronous path is the only option.
            return with_controller(index, |c| c.tx(frame))
                .unwrap_or(Err(E1000Error::UnsupportedDevice));
        }
    };
    // Construct the future first, then enqueue. If the device
    // completes before we await, the post-enqueue fire-count check
    // inside `WaitForIrq::poll` resolves immediately. 500 ms
    // deadline bounds the wait — TX completes in microseconds
    // normally; if it doesn't, the IRQ isn't wired right and we
    // should bail rather than stall.
    let waiter = narf_interrupts::wait_for_irq_until(vector, narf_time::Deadline::after_ms(500));
    let ticket = match with_controller(index, |c| c.tx_enqueue(frame, true, None))
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
    while !with_controller(index, |c| c.tx_slot_done(ticket)).unwrap_or(false) {
        let _ =
            narf_interrupts::wait_for_irq_until(vector, narf_time::Deadline::after_ms(500)).await;
    }
    Ok(())
}

impl E1000 {
    /// Read a 16-bit register from the internal PHY via MDIC, with
    /// the FWSM/SWFLAG handshake scoped per access (Linux
    /// `e1000_get_swflag_ich8lan` discipline, and the audit gap-5
    /// re-scope requirement): acquire, transact, release — even on
    /// transaction error, so a failed read never leaves the ME
    /// locked out. On non-PCH parts the handshake is skipped
    /// entirely (no ME to coordinate with).
    ///
    /// Must NOT be called during `bring_up`: bring-up holds SWFLAG
    /// across init, and this method's release would drop that hold
    /// early. Post-bring-up only.
    pub fn phy_read(&self, reg: u32) -> Result<u16, E1000Error> {
        let owned = if self.pch_part {
            acquire_phy_swflag(&self.mmio)?
        } else {
            false
        };
        let r = mdic_read(&self.mmio, reg);
        if self.pch_part {
            release_phy_swflag(&self.mmio, owned);
        }
        r
    }

    /// Write a 16-bit value to an internal-PHY register via MDIC,
    /// with the same per-access SWFLAG scoping as [`E1000::phy_read`]
    /// (and the same do-not-call-during-bring-up constraint).
    pub fn phy_write(&self, reg: u32, data: u16) -> Result<(), E1000Error> {
        let owned = if self.pch_part {
            acquire_phy_swflag(&self.mmio)?
        } else {
            false
        };
        let r = mdic_write(&self.mmio, reg, data);
        if self.pch_part {
            release_phy_swflag(&self.mmio, owned);
        }
        r
    }
}

impl crate::phy::Phy for E1000 {
    type Error = E1000Error;

    /// MDIC Clause-22 read. Same do-not-call-during-bring_up
    /// constraint as [`E1000::phy_read`]: bring-up holds SWFLAG
    /// across init, and this method's per-access release would
    /// drop that hold early.
    fn read_reg(&self, reg: u8) -> Result<u16, E1000Error> {
        self.phy_read(u32::from(reg))
    }

    /// MDIC Clause-22 write, same constraint as `read_reg`.
    fn write_reg(&self, reg: u8, val: u16) -> Result<(), E1000Error> {
        self.phy_write(u32::from(reg), val)
    }
}

impl E1000 {
    /// EEE status from live registers (Linux `e1000e_get_eee`
    /// shape for PCH parts): advertised from IPCNFG (the PCH
    /// advertisement store — `e1000_set_eee_pchlan` programs
    /// exactly these bits), link-partner advertisement from the
    /// PHY's Clause 45 MMD 7/61+63, TX-LPI from EEER bit 16,
    /// link-up from live STATUS.LU (not the probe-time `link_up`
    /// field — the LSC drain owns that sample). Active is the
    /// negotiated intersection, derived by [`eee_status_from`].
    /// Post-bring-up only (same SWFLAG constraint as
    /// [`E1000::phy_read`]); the handshake is held once across
    /// the whole read sequence, not per MDIC access.
    pub fn eee_status(&self) -> Result<narf_net::nic::EeeStatus, E1000Error> {
        let owned = if self.pch_part {
            acquire_phy_swflag(&self.mmio)?
        } else {
            false
        };
        let r = self.eee_status_locked();
        if self.pch_part {
            release_phy_swflag(&self.mmio, owned);
        }
        r
    }

    fn eee_status_locked(&self) -> Result<narf_net::nic::EeeStatus, E1000Error> {
        // SAFETY: identity-mapped MMIO; IPCNFG/EEER/STATUS are
        // inside the e1000 BAR0 register window on every PCH part.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let ipcnfg = unsafe { self.mmio.read32(REG_IPCNFG) };
        // SAFETY: EEER (0x0E30) is a 32-bit EEE control/status register
        // inside the mapped BAR0 window on every PCH part.
        let eeer = unsafe { self.mmio.read32(REG_EEER) };
        // SAFETY: STATUS (0x0008) is a 32-bit read-only status register
        // inside the mapped BAR0 window on every PCH part.
        let status = unsafe { self.mmio.read32(REG_STATUS) };
        let partner = mmd_read(&self.mmio, EEE_MMD_DEV, EEE_MMD_LP_ADV)?;
        let partner2 = mmd_read(&self.mmio, EEE_MMD_DEV, EEE_MMD_LP_ADV2)?;
        let advertised = (if ipcnfg & IPCNFG_EEE_100M_AN != 0 {
            EEE_ADV_100M
        } else {
            0
        }) | (if ipcnfg & IPCNFG_EEE_1G_AN != 0 {
            EEE_ADV_1G
        } else {
            0
        });
        Ok(eee_status_from(
            advertised,
            eee_modes_from_mmd(partner, partner2),
            status & STATUS_LU != 0,
            eeer & EEER_TX_LPI_EN != 0,
        ))
    }

    /// Enable or disable EEE advertisement (Linux
    /// `e1000_set_eee_pchlan` + an autoneg restart): enabled
    /// programs IPCNFG 1G+100M advertise bits and the EEER LPI
    /// bits; disabled clears exactly those bits (the inverse of
    /// [`disable_eee_pchlan`], which bring-up runs before
    /// CTRL.SLU). The autoneg restart puts the new advertisement
    /// on the wire — without it the advertisement would only
    /// take effect at the next renegotiation (igc's `setup_link`
    /// restarts AN after writing its EEE advertisement for the
    /// same reason). Already-in-state is a no-op (no link flap).
    /// Post-bring-up only (same SWFLAG constraint as
    /// [`E1000::phy_read`]).
    pub fn set_eee(&self, enable: bool) -> Result<(), E1000Error> {
        let owned = if self.pch_part {
            acquire_phy_swflag(&self.mmio)?
        } else {
            false
        };
        let r = self.set_eee_locked(enable);
        if self.pch_part {
            release_phy_swflag(&self.mmio, owned);
        }
        r
    }

    fn set_eee_locked(&self, enable: bool) -> Result<(), E1000Error> {
        let advertised = if enable { EEE_PCH_SUPPORTED } else { 0 };
        // SAFETY: identity-mapped MMIO; IPCNFG/EEER are inside the
        // e1000 BAR0 register window on every PCH part.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let ipcnfg = unsafe { self.mmio.read32(REG_IPCNFG) };
        // SAFETY: EEER (0x0E30) is a 32-bit EEE control/status register
        // inside the mapped BAR0 window on every PCH part.
        let eeer = unsafe { self.mmio.read32(REG_EEER) };
        let ipcnfg_next = eee_ipcnfg_next(ipcnfg, advertised);
        let eeer_next = eee_eeer_next(eeer, enable);
        if ipcnfg_next == ipcnfg && eeer_next == eeer {
            return Ok(());
        }
        // SAFETY: identity-mapped MMIO (same registers as above).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.mmio.write32(REG_IPCNFG, ipcnfg_next);
            self.mmio.write32(REG_EEER, eeer_next);
        }
        let bmcr = mdic_read(&self.mmio, PHY_BMCR)?;
        mdic_write(&self.mmio, PHY_BMCR, aneg_bmcr_restart(bmcr))?;
        Ok(())
    }

    /// Read the PHY identifier (PHYSID1/PHYSID2 composed per
    /// `phy_id_from`). Fails closed with `PhyNotPresent` when the
    /// read returns the no-device signature rather than inventing
    /// an identity for an absent PHY. Implemented in terms of
    /// the shared [`crate::phy::Phy`] trait (issue #790).
    pub fn phy_id(&self) -> Result<u32, E1000Error> {
        let id = <Self as crate::phy::Phy>::read_phy_id(self)?;
        if !crate::phy::phy_id_valid(id) {
            return Err(E1000Error::PhyNotPresent);
        }
        Ok(id)
    }

    /// Read PHY link status via BMSR. Two consecutive reads: the
    /// first re-arms the latch-low link bit (IEEE 802.3 §22.2.4.2),
    /// the second reports live state. This is the PHY-side signal;
    /// the MAC-side `STATUS.LU` sample that `link_up` reports is a
    /// separate, already-existing path. Implemented in terms of
    /// the shared [`crate::phy::Phy`] trait (issue #790).
    pub fn phy_link_up(&self) -> Result<bool, E1000Error> {
        <Self as crate::phy::Phy>::link_up(self)
    }

    /// Program auto-negotiation advertisement and restart
    /// negotiation (post-bring-up entry to `autoneg_setup_mmio`).
    /// The ANAR+GBCR+BMCR triple is one logical programming
    /// operation, so the SWFLAG is held across the sequence
    /// rather than per register (tighter than bring_up's
    /// whole-init hold, safer than per-register against ME
    /// interleaving mid-sequence).
    ///
    /// Must NOT be called during `bring_up`: bring-up holds SWFLAG
    /// across init, and this method's release would drop that hold
    /// early. Bring-up calls `autoneg_setup_mmio` directly.
    pub fn autoneg_setup(&self) -> Result<(), E1000Error> {
        let owned = if self.pch_part {
            acquire_phy_swflag(&self.mmio)?
        } else {
            false
        };
        let r = autoneg_setup_mmio(&self.mmio);
        if self.pch_part {
            release_phy_swflag(&self.mmio, owned);
        }
        r
    }

    /// Auto-negotiation complete sample: two consecutive BMSR
    /// reads (latch-low), trust the second — same discipline as
    /// `phy_link_up`. Same do-not-call-during-bring_up constraint
    /// as `phy_read`. Implemented in terms of the shared
    /// [`crate::phy::Phy`] trait (issue #790).
    pub fn autoneg_complete(&self) -> Result<bool, E1000Error> {
        <Self as crate::phy::Phy>::autoneg_complete(self)
    }

    /// Link-partner ability: LPA + 1000BASE-T status. Same
    /// do-not-call-during-bring_up constraint as `phy_read`.
    pub fn link_partner_ability(&self) -> Result<PartnerAbility, E1000Error> {
        Ok(PartnerAbility {
            anar: self.phy_read(PHY_LPA)?,
            stat1000: self.phy_read(PHY_STAT1000)?,
        })
    }

    /// Negotiated mode against the live advertisement words: our
    /// ANAR/GBCR as programmed plus the partner's ability. `None`
    /// means no common mode (or the partner has not answered yet —
    /// callers distinguish via `autoneg_complete`).
    pub fn negotiated_mode(&self) -> Result<Option<LinkMode>, E1000Error> {
        let our_anar = self.phy_read(PHY_ANAR)?;
        let our_gbcr = self.phy_read(PHY_GBCR)?;
        let partner = self.link_partner_ability()?;
        Ok(partner.negotiated_mode(our_anar, our_gbcr))
    }

    /// Resolve and program flow control after link-up (audit gap
    /// 7). Reads our ANAR/GBCR + the partner ability, resolves the
    /// mode (half duplex or no common mode → Disabled), then
    /// programs FCRTL/FCRTH/FCTTV + the CTRL RFCE/TFCE bits.
    /// Thresholds are programmed only when we generate pause
    /// frames (TxPause/Full), exactly as Linux's
    /// `e1000e_set_fc_watermarks` gates on tx_pause; other modes
    /// zero the thresholds. A degenerate PBA (0, or too small for
    /// a frame) degrades TxPause/Full to Disabled rather than
    /// programming a threshold that would XOFF immediately.
    /// FCTTV is programmed on every call so repeated configuration
    /// leaves deterministic state. Same do-not-call-during-bring_up
    /// constraint as `negotiated_mode` (it uses `phy_read`);
    /// callers invoke it after `autoneg_complete` reports true.
    /// Bring-up itself leaves flow control fail-closed
    /// (thresholds zero, RFCE/TFCE clear); this is the post-link
    /// step that enables it.
    pub fn configure_flow_control(&self) -> Result<FlowControl, E1000Error> {
        let our_anar = self.phy_read(PHY_ANAR)?;
        let our_gbcr = self.phy_read(PHY_GBCR)?;
        let partner = self.link_partner_ability()?;
        let full = partner
            .negotiated_mode(our_anar, our_gbcr)
            .is_some_and(|m| m.is_full_duplex());
        let mut mode = resolve_flow_control(our_anar, partner.anar, full);
        let mut fcrtl = 0u32;
        let mut fcrth = 0u32;
        let mut fcttv = 0u32;
        if matches!(mode, FlowControl::TxPause | FlowControl::Full) {
            // SAFETY: mapped MMIO; PBA is a valid 32-bit register
            // offset within BAR0.
            let pba = unsafe { self.mmio.read32(REG_PBA) } & PBA_RXA_MASK;
            // The high watermark leaves room for one full-size
            // frame below it; the size follows the programmed MTU
            // (issue #802), not the old 1518 literal — Linux fixed
            // the same drift in 2009 ("flow control thresholds not
            // correct when changing mtu").
            match flow_control_watermarks(pba, crate::mtu::rx_frame_size(*self.mtu.lock())) {
                Some((low, high)) => {
                    fcrtl = low | FCRTL_XONE;
                    fcrth = high;
                    fcttv = FC_PAUSE_TIME;
                }
                // Degenerate PBA: fail closed to Disabled.
                None => mode = FlowControl::Disabled,
            }
        }
        // SAFETY: mapped MMIO; the FC registers are valid 32-bit
        // offsets within BAR0, and the CTRL read-modify-write
        // preserves SLU, VME, and every other bit.
        unsafe {
            self.mmio.write32(REG_FCRTL, fcrtl);
            self.mmio.write32(REG_FCRTH, fcrth);
            self.mmio.write32(REG_FCTTV, fcttv);
            let ctrl = self.mmio.read32(REG_CTRL);
            self.mmio.write32(
                REG_CTRL,
                (ctrl & !CTRL_FC_MASK) | flow_control_ctrl_bits(mode),
            );
        }
        Ok(mode)
    }
}

mod tests {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::pm::RegBank;
    use super::{
        alloc_coherent, channel, mta_bit, mta_word, multicast_hash12, rar_encode, rar_slot_ok,
        vfta_bit, vfta_word, vlan_reinsert_tag, vlan_tci_parts, DmaBuffer, DmaPool, Frame,
        IrqSafeSpinLock, MmioRegion, MulticastFilter, RxDesc, TxDesc, TxQueueState, VlanFilter,
        E1000, RX_RING_LEN, RX_RING_N, TXD_CMD_EOP, TXD_CMD_IFCS, TXD_CMD_RS, TXD_CMD_VLE,
        TXD_STAT_DD, TX_RING_LEN, TX_RING_N, TX_RING_USABLE, TX_TIMEOUT_NS,
    };

    fn smoke_partial_tso_ring_requires_deferred_batch_flush() -> TestResult {
        let mut state = TxQueueState::new();
        for _ in 0..(TX_RING_USABLE - 3) {
            if state.cursor.reserve().is_none() {
                return TestResult::Fail("e1000 TX ring exhausted before expected");
            }
        }
        if state.cursor.available() != 3 {
            return TestResult::Fail("e1000 TX ring availability accounting drifted");
        }
        if !state.needs_flush_for(5) {
            return TestResult::Fail("deferred TX batch was not flushed before TSO wait");
        }

        state.doorbell_tail = state.cursor.next_to_use;
        if state.needs_flush_for(5) {
            return TestResult::Fail("published TX batch requested a redundant flush");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/e1000",
        smoke_partial_tso_ring_requires_deferred_batch_flush
    );

    fn smoke_link_sample_from_status_decodes() -> TestResult {
        // The decode shared by probe and the LSC drain (issue #791):
        // LU | SPEED_1000 | FD publishes carrier at 1000 Full; without
        // LU the sample is DOWN no matter what the other bits say.
        let up = super::link_sample_from_status(
            super::STATUS_LU | super::STATUS_SPEED_1000 | super::STATUS_FD,
        );
        if !up.carrier
            || up.speed_mbps != Some(1000)
            || up.duplex != Some(narf_net::iface::LinkDuplex::Full)
        {
            return TestResult::Fail("e1000 STATUS decode lost carrier/speed/duplex");
        }
        let down = super::link_sample_from_status(super::STATUS_SPEED_1000 | super::STATUS_FD);
        if down.carrier || down.speed_mbps.is_some() {
            return TestResult::Fail("e1000 STATUS decode reported carrier without LU");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_link_sample_from_status_decodes);

    fn smoke_aneg_advertisement_shape() -> TestResult {
        // ANAR = selector + 10/100 half+full + symmetric pause =
        // 0x05E1; GBCR = 1000 full only = 0x0200; asymmetric pause
        // clear (gap 7 landed, symmetric only).
        let (anar, gbcr) = super::aneg_advertisement();
        if anar != 0x05E1 || gbcr != 0x0200 {
            return TestResult::Fail("e1000 autoneg advertisement word mismatch");
        }
        if anar & super::ANAR_PAUSE_MASK != super::ANAR_PAUSE {
            return TestResult::Fail(
                "e1000 autoneg advertisement pause bits are not symmetric-only",
            );
        }
        if anar & 0x001F != super::ANAR_SELECTOR_CSMA {
            return TestResult::Fail("e1000 autoneg advertisement selector is not CSMA");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_aneg_advertisement_shape);

    fn smoke_aneg_next_rewrites_only_its_fields() -> TestResult {
        // From zero: exactly the advertisement words.
        if super::aneg_anar_next(0x0000) != 0x05E1 {
            return TestResult::Fail("e1000 aneg_anar_next(0) is not the advertisement");
        }
        if super::aneg_gbcr_next(0x0000) != 0x0200 {
            return TestResult::Fail("e1000 aneg_gbcr_next(0) is not 1000 full");
        }
        // From all-ones: speeds + symmetric pause rewritten,
        // asymmetric pause cleared, selector forced,
        // reserved/remote-fault/ack/next-page bits preserved.
        if super::aneg_anar_next(0xFFFF) != 0xF7FF {
            return TestResult::Fail("e1000 aneg_anar_next(0xFFFF) preserved the wrong bits");
        }
        if super::aneg_gbcr_next(0xFFFF) != 0xFEFF {
            return TestResult::Fail("e1000 aneg_gbcr_next(0xFFFF) preserved the wrong bits");
        }
        // BMCR restart sets only ANENABLE + ANRESTART.
        if super::aneg_bmcr_restart(0x0000) != 0x1200 {
            return TestResult::Fail("e1000 aneg_bmcr_restart(0) missed ANENABLE/ANRESTART");
        }
        if super::aneg_bmcr_restart(0x0800) != 0x1A00 {
            return TestResult::Fail("e1000 aneg_bmcr_restart dropped the power-down bit");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/e1000",
        smoke_aneg_next_rewrites_only_its_fields
    );

    fn smoke_aneg_resolve_priority_and_no_common() -> TestResult {
        let ours = super::aneg_advertisement();
        // Full agreement at 1000 full.
        if super::resolve_negotiated_mode(ours.0, ours.1, 0x01E1, 0x0800)
            != Some(super::LinkMode::Speed1000Full)
        {
            return TestResult::Fail("e1000 aneg resolve missed 1000 full agreement");
        }
        // Partner 1000 full but we do not offer 1000: fall to 100 full.
        if super::resolve_negotiated_mode(0x01E1, 0x0000, 0x01E1, 0x0800)
            != Some(super::LinkMode::Speed100Full)
        {
            return TestResult::Fail("e1000 aneg resolve did not fall through missing 1000");
        }
        // 1000 half resolves only when both sides offer it (general
        // resolver; this driver never advertises it).
        if super::resolve_negotiated_mode(0x01E1, 0x0100, 0x01E1, 0x0400)
            != Some(super::LinkMode::Speed1000Half)
        {
            return TestResult::Fail("e1000 aneg resolve missed 1000 half agreement");
        }
        // Partner 1000 full, we offer 1000 half only: fall to 100 full.
        if super::resolve_negotiated_mode(0x01E1, 0x0100, 0x01E1, 0x0800)
            != Some(super::LinkMode::Speed100Full)
        {
            return TestResult::Fail("e1000 aneg resolve confused 1000 half/full");
        }
        // Partner 10 half only: lowest common mode.
        if super::resolve_negotiated_mode(ours.0, ours.1, 0x0020, 0x0000)
            != Some(super::LinkMode::Speed10Half)
        {
            return TestResult::Fail("e1000 aneg resolve missed 10 half agreement");
        }
        // No common mode: partner answers nothing we offer.
        if super::resolve_negotiated_mode(ours.0, ours.1, 0x0000, 0x0000).is_some() {
            return TestResult::Fail("e1000 aneg resolve invented a mode with no overlap");
        }
        // BMSR complete bit.
        if !super::bmsr_ancomplete(0x0020) || super::bmsr_ancomplete(0x0000) {
            return TestResult::Fail("e1000 bmsr_ancomplete misread the complete bit");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/e1000",
        smoke_aneg_resolve_priority_and_no_common
    );

    fn smoke_vlan_vfta_mapping() -> TestResult {
        // Boundary VIDs: first/last bit of the first word, first bit
        // of the second word, last VID of the table.
        if vfta_word(0) != 0 || vfta_bit(0) != 1 {
            return TestResult::Fail("e1000 VFTA mapping wrong for VID 0");
        }
        if vfta_word(31) != 0 || vfta_bit(31) != (1 << 31) {
            return TestResult::Fail("e1000 VFTA mapping wrong for VID 31");
        }
        if vfta_word(32) != 1 || vfta_bit(32) != 1 {
            return TestResult::Fail("e1000 VFTA mapping wrong for VID 32");
        }
        if vfta_word(4095) != 127 || vfta_bit(4095) != (1 << 31) {
            return TestResult::Fail("e1000 VFTA mapping wrong for VID 4095");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_vlan_vfta_mapping);

    fn smoke_vlan_filter_shadow() -> TestResult {
        let mut filter = VlanFilter::new();
        if !filter.is_empty() || filter.count() != 0 {
            return TestResult::Fail("e1000 VlanFilter not empty on creation");
        }
        if filter.add(4096) || filter.contains(4096) {
            return TestResult::Fail("e1000 VlanFilter accepted VID > 4095");
        }
        if !filter.add(0) || !filter.add(32) || !filter.add(1) {
            return TestResult::Fail("e1000 VlanFilter rejected a valid VID");
        }
        if filter.add(0) || filter.count() != 3 {
            return TestResult::Fail("e1000 VlanFilter duplicate add changed the shadow");
        }
        // Word 0 holds VIDs 0 and 1; word 1 holds VID 32.
        if filter.word(0) != 0b11 || filter.word(1) != 1 {
            return TestResult::Fail("e1000 VlanFilter shadow words wrong");
        }
        if !filter.remove(0) || filter.contains(0) || filter.word(0) != 0b10 {
            return TestResult::Fail("e1000 VlanFilter remove did not clear VID 0");
        }
        if filter.remove(0) || filter.remove(4096) {
            return TestResult::Fail("e1000 VlanFilter remove of absent VID reported success");
        }
        if !filter.remove(1) || !filter.remove(32) || !filter.is_empty() {
            return TestResult::Fail("e1000 VlanFilter did not empty after removing all VIDs");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_vlan_filter_shadow);

    fn smoke_vlan_tci_parts() -> TestResult {
        // TCI layout (SDM Table 3-4): PRI[15:13], CFI[12], VID[11:0].
        if vlan_tci_parts(0x0000) != (0, 0, false) {
            return TestResult::Fail("e1000 TCI decode wrong for 0x0000");
        }
        if vlan_tci_parts(0xF123) != (0x123, 7, true) {
            return TestResult::Fail("e1000 TCI decode wrong for 0xF123");
        }
        if vlan_tci_parts(0x0064) != (100, 0, false) {
            return TestResult::Fail("e1000 TCI decode wrong for VID 100");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_vlan_tci_parts);

    fn smoke_vlan_reinsert_tag() -> TestResult {
        // Stripped frame: dst(6) + src(6) + ethertype(2) + "ABCD".
        let mut buf = [0u8; 32];
        buf[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        buf[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        buf[12..14].copy_from_slice(&[0x08, 0x00]);
        buf[14..18].copy_from_slice(b"ABCD");
        let new_len = vlan_reinsert_tag(&mut buf, 18, 0x0064);
        if new_len != Some(22) {
            return TestResult::Fail("e1000 VLAN reinsert returned wrong length");
        }
        if buf[12..14] != [0x81, 0x00] || buf[14..16] != [0x00, 0x64] {
            return TestResult::Fail("e1000 VLAN reinsert wrote wrong TPID/TCI");
        }
        if buf[16..18] != [0x08, 0x00] || buf[18..22] != *b"ABCD" {
            return TestResult::Fail("e1000 VLAN reinsert misplaced the payload");
        }
        // No room for the 4 bytes: refuses, buffer untouched.
        let mut tight = [0u8; 20];
        tight[0..18].copy_from_slice(&buf[0..18]);
        if vlan_reinsert_tag(&mut tight, 18, 0x0064).is_some() {
            return TestResult::Fail("e1000 VLAN reinsert grew a too-small buffer");
        }
        // Shorter than an Ethernet header: refuses.
        let mut short = [0u8; 32];
        if vlan_reinsert_tag(&mut short, 10, 0x0064).is_some() {
            return TestResult::Fail("e1000 VLAN reinsert accepted a runt frame");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_vlan_reinsert_tag);

    fn smoke_vlan_tx_descriptor() -> TestResult {
        let plain = TxDesc::legacy_data(0x1000, 64, None);
        if plain.cmd != (TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS) || plain.special != 0 {
            return TestResult::Fail("e1000 plain TX descriptor changed shape");
        }
        let tagged = TxDesc::legacy_data(0x1000, 64, Some(0x0064));
        if tagged.cmd & TXD_CMD_VLE == 0 || tagged.special != 0x0064 {
            return TestResult::Fail("e1000 VLAN TX descriptor missing VLE/TCI");
        }
        if tagged.cmd & TXD_CMD_EOP == 0 {
            return TestResult::Fail("e1000 VLAN TX descriptor missing EOP (VLE requires it)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_vlan_tx_descriptor);

    fn smoke_multicast_hash_windows() -> TestResult {
        // SDM §3.2.1 windows over the example address
        // 01:AA:00:12:34:56 (mac[4] = 0x34, mac[5] = 0x56).
        // Each value is derived from the window definition, not
        // copied: MO 0 = (0x56 << 4) | (0x34 >> 4), etc.
        let mac: [u8; 6] = [0x01, 0xAA, 0x00, 0x12, 0x34, 0x56];
        if multicast_hash12(&mac, 0) != 0x563 {
            return TestResult::Fail("e1000 multicast hash wrong for MO 0 [47:36]");
        }
        if multicast_hash12(&mac, 1) != 0xAC6 {
            return TestResult::Fail("e1000 multicast hash wrong for MO 1 [46:35]");
        }
        if multicast_hash12(&mac, 2) != 0x58D {
            return TestResult::Fail("e1000 multicast hash wrong for MO 2 [45:34]");
        }
        if multicast_hash12(&mac, 3) != 0x634 {
            return TestResult::Fail("e1000 multicast hash wrong for MO 3 [43:32]");
        }
        // The hash is always 12 bits, even for all-ones bytes.
        if multicast_hash12(&[0xFF; 6], 0) != 0xFFF {
            return TestResult::Fail("e1000 multicast hash not masked to 12 bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_multicast_hash_windows);

    fn smoke_multicast_mta_mapping() -> TestResult {
        if mta_word(0x563) != 43 || mta_bit(0x563) != (1 << 3) {
            return TestResult::Fail("e1000 MTA mapping wrong for hash 0x563");
        }
        if mta_word(0xFFF) != 127 || mta_bit(0xFFF) != (1 << 31) {
            return TestResult::Fail("e1000 MTA mapping wrong for hash 0xFFF");
        }
        if mta_word(0) != 0 || mta_bit(0) != 1 {
            return TestResult::Fail("e1000 MTA mapping wrong for hash 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_multicast_mta_mapping);

    fn smoke_multicast_filter_shadow() -> TestResult {
        let mut filter = MulticastFilter::new();
        let a: [u8; 6] = [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB];
        // `b` collides with `a` exactly: same mac[5], and mac[4]
        // differs only in the low nibble, which the MO-0 window
        // (mac[4] >> 4) discards.
        let b: [u8; 6] = [0x01, 0x00, 0x5E, 0x00, 0x0F, 0xFB];
        if multicast_hash12(&a, 0) != multicast_hash12(&b, 0) {
            return TestResult::Fail("e1000 test collision pair does not collide");
        }
        if !filter.add(&a) || filter.count() != 1 || !filter.contains(&a) {
            return TestResult::Fail("e1000 MulticastFilter rejected a new address");
        }
        // Colliding address: bit already set, no count change.
        if filter.add(&b) || filter.count() != 1 {
            return TestResult::Fail("e1000 MulticastFilter double-counted a hash collision");
        }
        // Removing one colliding address clears the shared bit.
        if !filter.remove(&a) || filter.contains(&b) || !filter.is_empty() {
            return TestResult::Fail("e1000 MulticastFilter collision removal wrong");
        }
        if filter.remove(&a) {
            return TestResult::Fail("e1000 MulticastFilter remove of absent address succeeded");
        }
        if !filter.add(&a) || !filter.contains(&a) {
            return TestResult::Fail("e1000 MulticastFilter re-add failed");
        }
        filter.clear();
        if !filter.is_empty() || filter.count() != 0 || filter.word(0) != 0 {
            return TestResult::Fail("e1000 MulticastFilter clear did not empty the shadow");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_multicast_filter_shadow);

    fn smoke_multicast_rar_encoding() -> TestResult {
        // Little-endian byte order + AV in RAH bit 31.
        let (ral, rah) = rar_encode(&[0x01, 0xAA, 0x00, 0x12, 0x34, 0x56]);
        if ral != 0x1200_AA01 || rah != 0x8000_5634 {
            return TestResult::Fail("e1000 RAR encoding wrong (byte order or AV bit)");
        }
        // Slot validation: 0 is bring-up owned, 16 is out of range.
        if rar_slot_ok(0) || !rar_slot_ok(1) || !rar_slot_ok(15) || rar_slot_ok(16) {
            return TestResult::Fail("e1000 RAL slot validation wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_multicast_rar_encoding);

    fn smoke_datapath_allowed_gate_matrix() -> TestResult {
        // The gate every datapath entry point uses: only the
        // neither-detached-nor-suspended cell is open.
        let open = super::E1000::datapath_allowed;
        if !open(false, false) {
            return TestResult::Fail("e1000 datapath gate closed a running device");
        }
        if open(true, false) {
            return TestResult::Fail("e1000 datapath gate opened a detached device");
        }
        if open(false, true) {
            return TestResult::Fail("e1000 datapath gate opened a suspended device");
        }
        if open(true, true) {
            return TestResult::Fail("e1000 datapath gate opened a detached+suspended device");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_datapath_allowed_gate_matrix);

    fn smoke_suspend_words_preserve_bringup_config() -> TestResult {
        // Suspend/detach words are the bring-up words with EN
        // cleared — literals written out, not composed from the
        // module's own constants, so a mistranscribed bit cannot
        // pass its own test. RCTL bring-up = EN|BAM|UPE|MPE|SECRC
        // (BSIZE_2K is 0); TCTL bring-up = EN|PSP|CT_15|COLD_63|RTLC.
        if super::E1000::RCTL_SUSPEND_OFF != 0x0400_8018 {
            return TestResult::Fail("e1000 RCTL suspend word drifted from bring-up minus EN");
        }
        if super::E1000::TCTL_SUSPEND_OFF != 0x0103_F0F8 {
            return TestResult::Fail("e1000 TCTL suspend word drifted from bring-up minus EN");
        }
        if super::E1000::RCTL_SUSPEND_OFF & super::RCTL_EN != 0
            || super::E1000::TCTL_SUSPEND_OFF & super::TCTL_EN != 0
        {
            return TestResult::Fail("e1000 suspend word still has its EN bit set");
        }
        if super::E1000::RCTL_SUSPEND_OFF | super::RCTL_EN
            != super::RCTL_EN
                | super::RCTL_BAM
                | super::RCTL_UPE
                | super::RCTL_MPE
                | super::RCTL_SECRC
                | super::RCTL_BSIZE_2K
        {
            return TestResult::Fail("e1000 RCTL suspend word lost a bring-up config bit");
        }
        if super::E1000::TCTL_SUSPEND_OFF | super::TCTL_EN
            != super::TCTL_EN
                | super::TCTL_PSP
                | super::TCTL_CT_15
                | super::TCTL_COLD_63
                | super::TCTL_RTLC
        {
            return TestResult::Fail("e1000 TCTL suspend word lost a bring-up config bit");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/e1000",
        smoke_suspend_words_preserve_bringup_config
    );
    fn smoke_mdic_command_words() -> TestResult {
        // Read of PHYSID1 (reg 2): OP_READ | phy 1 | reg 2.
        if super::mdic_read_cmd(super::PHY_ID1) != 0x0822_0000 {
            return TestResult::Fail("e1000 MDIC read command word wrong");
        }
        // Write of 0x1140 to reg 0: OP_WRITE | phy 1 | data.
        if super::mdic_write_cmd(0, 0x1140) != 0x0420_1140 {
            return TestResult::Fail("e1000 MDIC write command word wrong");
        }
        // Register field is 5 bits: reg 0x3F masks to 0x1F.
        if super::mdic_read_cmd(0x3F) != (super::MDIC_OP_READ | super::MDIC_PHY_ADDR | (0x1F << 16))
        {
            return TestResult::Fail("e1000 MDIC register field not masked to 5 bits");
        }
        // Data extraction masks off READY/ERROR/opcode bits.
        if super::mdic_data(0x5000_1234) != 0x1234 {
            return TestResult::Fail("e1000 MDIC data field not masked to 16 bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_mdic_command_words);

    fn smoke_phy_id_composition_and_validity() -> TestResult {
        if super::phy_id_from(0x0141, 0x0CC2) != 0x0141_0CC2 {
            return TestResult::Fail("e1000 PHY ID composition wrong");
        }
        if !super::phy_id_valid(0x0141_0CC2) {
            return TestResult::Fail("e1000 PHY ID validity rejected a real ID");
        }
        if super::phy_id_valid(0xFFFF_FFFF) || super::phy_id_valid(0) {
            return TestResult::Fail("e1000 PHY ID validity accepted a no-device signature");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_phy_id_composition_and_validity);

    fn smoke_bmsr_link_decode() -> TestResult {
        if !super::bmsr_link(0x0004) {
            return TestResult::Fail("e1000 BMSR link bit not decoded");
        }
        if super::bmsr_link(0xFFFB) || super::bmsr_link(0x0000) {
            return TestResult::Fail("e1000 BMSR link bit decoded from a link-down value");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_bmsr_link_decode);

    fn smoke_eee_mmd_mode_decode() -> TestResult {
        // MMD 7/60 = 0b110 (100M + 1G), 7/62 = 0b1 (2.5G): the full
        // narf_net encoding 0x38. Each bit decodes independently.
        if super::eee_modes_from_mmd(0x6, 0x1) != 0x38 {
            return TestResult::Fail("e1000 EEE MMD mode decode wrong for 100M+1G+2.5G");
        }
        if super::eee_modes_from_mmd(0x2, 0x0) != super::EEE_ADV_100M
            || super::eee_modes_from_mmd(0x4, 0x0) != super::EEE_ADV_1G
            || super::eee_modes_from_mmd(0x0, 0x1) != super::EEE_ADV_2_5G
            || super::eee_modes_from_mmd(0x0, 0x0) != 0
        {
            return TestResult::Fail("e1000 EEE MMD mode decode wrong for a single speed");
        }
        // Bits outside the EEE fields (e.g. capability bits in the
        // same words) must not leak into the advertisement.
        if super::eee_modes_from_mmd(0xFFF9, 0xFFFE) != 0 {
            return TestResult::Fail("e1000 EEE MMD mode decode leaked non-EEE bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_eee_mmd_mode_decode);

    fn smoke_eee_ipcnfg_eeer_words() -> TestResult {
        // PCH advertisement is IPCNFG bits 12 (100M) + 14 (1G):
        // the supported set programs 0x5000, nothing else.
        if super::eee_ipcnfg_next(0, super::EEE_PCH_SUPPORTED) != 0x5000 {
            return TestResult::Fail("e1000 EEE IPCNFG word wrong for the PCH set");
        }
        if super::eee_ipcnfg_next(0, 0) != 0 {
            return TestResult::Fail("e1000 EEE IPCNFG word not cleared for disable");
        }
        // A 2.5G-only request has no IPCNFG bit on PCH parts: it
        // clears the PCH advertise bits and sets nothing, while
        // unrelated IPCNFG fields are preserved.
        if super::eee_ipcnfg_next(0xFFFF_FFFF, super::EEE_ADV_2_5G) != 0xFFFF_AFFF {
            return TestResult::Fail("e1000 EEE IPCNFG word programmed 2.5G on a PCH part");
        }
        if super::eee_ipcnfg_next(0x0000_0001, super::EEE_ADV_100M) != 0x0000_1001 {
            return TestResult::Fail("e1000 EEE IPCNFG word did not preserve other bits");
        }
        // EEER: enable sets exactly the LPI mask (0x70000), disable
        // clears exactly it, other bits preserved.
        if super::eee_eeer_next(0, true) != 0x70000 || super::eee_eeer_next(0x70000, false) != 0 {
            return TestResult::Fail("e1000 EEE EEER word wrong for enable/disable");
        }
        if super::eee_eeer_next(0x8000_0001, true) != 0x8007_0001
            || super::eee_eeer_next(0x8007_0001, false) != 0x8000_0001
        {
            return TestResult::Fail("e1000 EEE EEER word did not preserve other bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_eee_ipcnfg_eeer_words);

    fn smoke_eee_status_derivation() -> TestResult {
        // Scripted register state: IPCNFG advertises 100M+1G,
        // partner advertises the same, link up, TX LPI on.
        let up = super::eee_status_from(
            super::EEE_PCH_SUPPORTED,
            super::eee_modes_from_mmd(0x6, 0x0),
            true,
            true,
        );
        if !up.active || up.advertised != 0x18 || up.partner != 0x18 || !up.tx_lpi {
            return TestResult::Fail("e1000 EEE status wrong for negotiated link");
        }
        // No link → not active even with matching advertisements.
        let down = super::eee_status_from(super::EEE_PCH_SUPPORTED, 0x18, false, true);
        if down.active {
            return TestResult::Fail("e1000 EEE status active without link");
        }
        // Disjoint advertisements → not active (partner is 100M-only).
        let disjoint = super::eee_status_from(0x10, 0x08, true, false);
        if disjoint.active || disjoint.tx_lpi {
            return TestResult::Fail("e1000 EEE status active for disjoint advertisements");
        }
        // Disabled locally (advertised 0) → not active, tx_lpi as read.
        let off = super::eee_status_from(0, 0x18, true, false);
        if off.active {
            return TestResult::Fail("e1000 EEE status active while disabled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_eee_status_derivation);

    fn smoke_rx_csum_result_matrix() -> TestResult {
        // Pin the descriptor bit values against the Linux literals
        // (e1000_hw.h), not the module's own constants, so a
        // mistranscribed constant cannot pass its own test.
        if super::RXD_STAT_IPCS != 0x40
            || super::RXD_STAT_TCPCS != 0x20
            || super::RXD_STAT_UDPCS != 0x10
            || super::RXD_STAT_IXSM != 0x04
            || super::RXD_ERR_IPE != 0x40
            || super::RXD_ERR_TCPE != 0x20
        {
            return TestResult::Fail("e1000 RX descriptor bit constants drifted from Linux");
        }
        // (status, errors) -> expected verdict. Status bits: DD 0x01,
        // IXSM 0x04, UDPCS 0x10, TCPCS 0x20, IPCS 0x40; error bits:
        // TCPE 0x20, IPE 0x40.
        let cases: [(u8, u8, super::RxCsumResult); 13] = [
            (0x00, 0x00, super::RxCsumResult::None),
            (0x40, 0x00, super::RxCsumResult::Ok),
            (0x20, 0x00, super::RxCsumResult::Ok),
            (0x10, 0x00, super::RxCsumResult::Ok),
            (0x60, 0x00, super::RxCsumResult::Ok),
            (0x40, 0x40, super::RxCsumResult::Fail),
            (0x20, 0x20, super::RxCsumResult::Fail),
            // The UDP hole the old computed-first order missed: UDPCS
            // only, carrying TCPE, must fail, not report None.
            (0x10, 0x20, super::RxCsumResult::Fail),
            // Errors win even with no computed bit set.
            (0x00, 0x20, super::RxCsumResult::Fail),
            (0x00, 0x40, super::RxCsumResult::Fail),
            (0x60, 0x60, super::RxCsumResult::Fail),
            // IXSM wins over everything: hardware ignored the checksum.
            (0x44, 0x00, super::RxCsumResult::None),
            (0x04, 0x20, super::RxCsumResult::None),
        ];
        for (status, errors, want) in cases {
            let desc = super::RxDesc {
                status,
                errors,
                ..Default::default()
            };
            if desc.csum_result() != want {
                return TestResult::Fail("e1000 csum_result matrix mismatch");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_rx_csum_result_matrix);

    fn smoke_rx_drop_reason_matrix() -> TestResult {
        // Error bits: CE 0x01, SE 0x02, SEQ 0x04, CXE 0x10, TCPE 0x20,
        // IPE 0x40, RXE 0x80. Status bits as in the csum matrix.
        let cases: [(u8, u8, Option<super::RxDropReason>); 10] = [
            (0x00, 0x01, Some(super::RxDropReason::CrcError)),
            (0x40, 0x41, Some(super::RxDropReason::CrcError)),
            (0x00, 0x02, Some(super::RxDropReason::FrameError)),
            (0x00, 0x04, Some(super::RxDropReason::FrameError)),
            (0x00, 0x10, Some(super::RxDropReason::FrameError)),
            (0x00, 0x80, Some(super::RxDropReason::FrameError)),
            (0x40, 0x20, Some(super::RxDropReason::CsumFail)),
            (0x10, 0x20, Some(super::RxDropReason::CsumFail)),
            (0x40, 0x00, None),
            (0x00, 0x00, None),
        ];
        for (status, errors, want) in cases {
            let desc = super::RxDesc {
                status,
                errors,
                ..Default::default()
            };
            if super::rx_drop_reason(&desc) != want {
                return TestResult::Fail("e1000 rx_drop_reason matrix mismatch");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_rx_drop_reason_matrix);

    fn smoke_flow_control_resolve_table() -> TestResult {
        // Our advertisement: PAUSE set, ASM_DIR clear.
        let ours = super::ANAR_PAUSE;
        // Partner symmetric → Full.
        if super::resolve_flow_control(ours, super::ANAR_PAUSE, true) != super::FlowControl::Full {
            return TestResult::Fail("e1000 FC resolve missed symmetric Full");
        }
        // Partner asymmetric-only → Disabled (table row 1,0,0,DC).
        if super::resolve_flow_control(ours, super::ANAR_PAUSE_ASYM, true)
            != super::FlowControl::Disabled
        {
            return TestResult::Fail("e1000 FC resolve enabled pause against ASM-only partner");
        }
        // Partner none → Disabled.
        if super::resolve_flow_control(ours, 0x0000, true) != super::FlowControl::Disabled {
            return TestResult::Fail("e1000 FC resolve enabled pause against no-pause partner");
        }
        // Half duplex forces Disabled even with symmetric agreement.
        if super::resolve_flow_control(ours, super::ANAR_PAUSE, false)
            != super::FlowControl::Disabled
        {
            return TestResult::Fail("e1000 FC resolve enabled pause on half duplex");
        }
        // General-table arms (not reachable with our advertisement,
        // implemented for table completeness):
        // local ASM-only + partner both → TxPause.
        let local_asym = super::ANAR_PAUSE_ASYM;
        let partner_both = super::ANAR_PAUSE | super::ANAR_PAUSE_ASYM;
        if super::resolve_flow_control(local_asym, partner_both, true)
            != super::FlowControl::TxPause
        {
            return TestResult::Fail("e1000 FC resolve missed ASM-only TxPause arm");
        }
        // local both + partner ASM-only → RxPause.
        if super::resolve_flow_control(partner_both, super::ANAR_PAUSE_ASYM, true)
            != super::FlowControl::RxPause
        {
            return TestResult::Fail("e1000 FC resolve missed RxPause arm");
        }
        // local ASM-only + partner PAUSE-only → Disabled (table row).
        if super::resolve_flow_control(local_asym, super::ANAR_PAUSE, true)
            != super::FlowControl::Disabled
        {
            return TestResult::Fail("e1000 FC resolve enabled pause on ASM/PAUSE-only mismatch");
        }
        // local none → Disabled regardless of partner.
        if super::resolve_flow_control(0x0000, partner_both, true) != super::FlowControl::Disabled {
            return TestResult::Fail("e1000 FC resolve enabled pause with no local advertisement");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_flow_control_resolve_table);

    fn smoke_flow_control_watermarks() -> TestResult {
        // PBA 32 KB: high = min(90% = 29491, 32768 − 1518 = 31250)
        // masked = 29488; low = 80% = 26214 masked = 26208.
        if super::flow_control_watermarks(32, 1518) != Some((26208, 29488)) {
            return TestResult::Fail("e1000 FC watermarks wrong at PBA 32K");
        }
        // PBA 14 KB: high = min(12902, 12818) masked = 12816;
        // low = 11468 masked = 11464.
        if super::flow_control_watermarks(14, 1518) != Some((11464, 12816)) {
            return TestResult::Fail("e1000 FC watermarks wrong at PBA 14K");
        }
        // PBA 0 (unprogrammed) → fail-closed None.
        if super::flow_control_watermarks(0, 1518).is_some() {
            return TestResult::Fail("e1000 FC watermarks enabled on PBA 0");
        }
        // PBA 1 KB cannot fit a max frame below the high mark → None.
        if super::flow_control_watermarks(1, 1518).is_some() {
            return TestResult::Fail("e1000 FC watermarks enabled on degenerate PBA");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_flow_control_watermarks);

    fn smoke_flow_control_ctrl_bits() -> TestResult {
        if super::flow_control_ctrl_bits(super::FlowControl::Disabled) != 0 {
            return TestResult::Fail("e1000 FC ctrl bits nonzero for Disabled");
        }
        if super::flow_control_ctrl_bits(super::FlowControl::RxPause) != super::CTRL_RFCE {
            return TestResult::Fail("e1000 FC ctrl bits wrong for RxPause");
        }
        if super::flow_control_ctrl_bits(super::FlowControl::TxPause) != super::CTRL_TFCE {
            return TestResult::Fail("e1000 FC ctrl bits wrong for TxPause");
        }
        if super::flow_control_ctrl_bits(super::FlowControl::Full)
            != super::CTRL_RFCE | super::CTRL_TFCE
        {
            return TestResult::Fail("e1000 FC ctrl bits wrong for Full");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_flow_control_ctrl_bits);

    fn smoke_shared_phy_resolve_matches_e1000() -> TestResult {
        // The shared trait's Clause-22 resolution
        // (`crate::phy::resolve_aneg`, issue #790) must agree with
        // this driver's own `resolve_negotiated_mode` on every
        // advertisement combination: same priority
        // (1000FD > 1000HD > 100FD > 100HD > 10FD > 10HD), same
        // intersection rule. The words are literals from the
        // register map in this file (ANAR 10HD 0x0020 / 10FD
        // 0x0040 / 100HD 0x0080 / 100FD 0x0100; GBCR 1000HD
        // 0x0100 / 1000FD 0x0200; STAT1000 1000HD 0x0400 /
        // 1000FD 0x0800), not the constants under test.
        use narf_net::iface::LinkDuplex;
        for (our_anar, our_gbcr, lp_anar, lp_stat1000, want) in [
            (
                0x01e0u16,
                0x0200u16,
                0x01e1u16,
                0x0800u16,
                Some((1000u32, LinkDuplex::Full)),
            ),
            (
                0x01e0,
                0x0300,
                0x01e1,
                0x0400,
                Some((1000, LinkDuplex::Half)),
            ),
            (
                0x01e0,
                0x0200,
                0x0100,
                0x0000,
                Some((100, LinkDuplex::Full)),
            ),
            (
                0x01e0,
                0x0200,
                0x0080,
                0x0000,
                Some((100, LinkDuplex::Half)),
            ),
            (0x01e0, 0x0200, 0x0040, 0x0000, Some((10, LinkDuplex::Full))),
            (0x01e0, 0x0200, 0x0020, 0x0000, Some((10, LinkDuplex::Half))),
            (0x01e0, 0x0200, 0x0000, 0x0000, None),
            // Disjoint advertisements: no common mode.
            (0x0100, 0x0000, 0x0020, 0x0000, None),
            // Priority: partner offers 100FD + 1000FD, we offer
            // 1000HD only (not FULL) → falls through to 100FD.
            (
                0x01e0,
                0x0100,
                0x0100,
                0x0800,
                Some((100, LinkDuplex::Full)),
            ),
        ] {
            let ours = super::resolve_negotiated_mode(our_anar, our_gbcr, lp_anar, lp_stat1000);
            let shared = crate::phy::resolve_aneg(our_anar, our_gbcr, lp_anar, lp_stat1000);
            let ours_mapped = ours.map(|m| {
                let (speed, duplex) = match m {
                    super::LinkMode::Speed10Half => (10u32, LinkDuplex::Half),
                    super::LinkMode::Speed10Full => (10, LinkDuplex::Full),
                    super::LinkMode::Speed100Half => (100, LinkDuplex::Half),
                    super::LinkMode::Speed100Full => (100, LinkDuplex::Full),
                    super::LinkMode::Speed1000Half => (1000, LinkDuplex::Half),
                    super::LinkMode::Speed1000Full => (1000, LinkDuplex::Full),
                };
                (speed, duplex)
            });
            let shared_mapped = match shared {
                (Some(speed), Some(duplex)) => Some((speed, duplex)),
                (None, None) => None,
                _ => Some((u32::MAX, LinkDuplex::Half)),
            };
            if ours_mapped != want || shared_mapped != want {
                return TestResult::Fail(
                    "shared PHY resolve disagrees with e1000 resolve_negotiated_mode",
                );
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_shared_phy_resolve_matches_e1000);
    fn smoke_tx_stall_detection() -> TestResult {
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        let mut state = TxQueueState::new();
        if state.stalled(1_000_000, timeout) {
            return TestResult::Fail("e1000 idle TX ring reported stalled");
        }
        let now = 10_000_000u64;
        if state.cursor.reserve_at(now).is_none() {
            return TestResult::Fail("e1000 TX reserve failed on an empty ring");
        }
        if state.stalled(now + timeout, timeout) {
            return TestResult::Fail("e1000 TX stall fired at exactly the timeout");
        }
        if !state.stalled(now + timeout + 1, timeout) {
            return TestResult::Fail("e1000 TX stall did not fire past the timeout");
        }
        // A second, later post does not mask the older stuck one...
        if state.cursor.reserve_at(now + 100).is_none() {
            return TestResult::Fail("e1000 TX reserve failed with room left");
        }
        if !state.stalled(now + timeout + 1, timeout) {
            return TestResult::Fail("e1000 later TX post masked the stuck descriptor");
        }
        // ...and completing the oldest clears the stall once nothing
        // aged remains.
        let _ = state.cursor.complete_oldest();
        if state.stalled(now + timeout + 1, timeout) {
            return TestResult::Fail("e1000 TX stall survived completing the stuck slot");
        }
        let _ = state.cursor.complete_oldest();
        if state.stalled(now + timeout + 1, timeout) {
            return TestResult::Fail("e1000 empty TX ring reported stalled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_tx_stall_detection);

    fn smoke_tx_stall_reset_clears() -> TestResult {
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        let mut state = TxQueueState::new();
        let now = 10_000_000u64;
        let Some(ticket) = state.cursor.reserve_at(now) else {
            return TestResult::Fail("e1000 TX reserve failed on an empty ring");
        };
        if !state.stalled(now + timeout + 1, timeout) {
            return TestResult::Fail("e1000 TX stall did not fire before reset");
        }
        let owned = state.reset();
        if !owned.iter().all(|slot| slot.is_none()) {
            return TestResult::Fail("e1000 TX reset returned unexpected owned buffers");
        }
        if state.stalled(now + timeout + 1, timeout) {
            return TestResult::Fail("e1000 TX stall survived the reset");
        }
        // The pre-reset ticket is not "reused": the reset advanced
        // the ring epoch, so its frame (dropped with the ring) can
        // never compare as completed.
        if state.cursor.ticket_was_reused(ticket) {
            return TestResult::Fail("e1000 pre-reset TX ticket compared as reused after reset");
        }
        // ...while a fresh reservation in the new epoch behaves.
        if state.cursor.reserve_at(now).is_none() {
            return TestResult::Fail("e1000 TX reserve failed after reset");
        }
        if state.cursor.available() != TX_RING_USABLE - 1 {
            return TestResult::Fail("e1000 TX ring did not come back full after reset");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_tx_stall_reset_clears);

    /// Fake 8254x for the TX-timeout fixture: a 128 KiB MMIO backing
    /// page plus a sleep-pump that emulates the two hardware
    /// behaviours recovery depends on — CTRL.RST self-clear (SDM
    /// §13.3.1) and TX descriptor completion (DD) once the test
    /// arms it. Built from the spec (register offsets, reset
    /// semantics), never from the implementation's constants.
    static FIXTURE_MMIO: AtomicU64 = AtomicU64::new(0);
    static FIXTURE_COMPLETE_TX: AtomicBool = AtomicBool::new(false);
    static FIXTURE_PUMP_REGISTERED: AtomicBool = AtomicBool::new(false);

    fn fixture_pump() {
        let base = FIXTURE_MMIO.load(Ordering::Acquire);
        if base == 0 {
            return;
        }
        // SAFETY: fixture-owned fake MMIO; base is published by the
        // fixture and cleared on drop. The backing page is 128 KiB,
        // so every register offset below is in bounds.
        unsafe {
            let ctrl = core::ptr::read_volatile((base + super::REG_CTRL) as *const u32);
            if ctrl & super::CTRL_RST != 0 {
                core::ptr::write_volatile(
                    (base + super::REG_CTRL) as *mut u32,
                    ctrl & !super::CTRL_RST,
                );
            }
            if FIXTURE_COMPLETE_TX.load(Ordering::Acquire) {
                let tdbal =
                    core::ptr::read_volatile((base + super::REG_TDBAL) as *const u32) as u64;
                let tdbah =
                    core::ptr::read_volatile((base + super::REG_TDBAH) as *const u32) as u64;
                let ring = (tdbah << 32) | tdbal;
                if ring != 0 {
                    for slot in 0..TX_RING_LEN {
                        let desc = narf_memory::PhysAddr::new(
                            ring + (slot * core::mem::size_of::<TxDesc>()) as u64,
                        );
                        // SAFETY: fixture-owned DMA ring; slot bounded.
                        let addr = core::ptr::read_volatile(desc.kernel_ptr::<u64>());
                        if addr != 0 {
                            let status = desc.kernel_mut_ptr::<u8>().add(12);
                            let s = core::ptr::read_volatile(status);
                            core::ptr::write_volatile(status, s | TXD_STAT_DD);
                        }
                    }
                }
            }
        }
    }

    struct TxTimeoutFixture {
        device: E1000,
        _mmio_mem: DmaBuffer,
    }

    impl TxTimeoutFixture {
        fn new() -> Self {
            // 128 KiB fake BAR0 (8254x BAR0 is 128 KiB).
            let mut mem = alloc_coherent(128 * 1024, crate::BUILTIN_DOMAIN).unwrap();
            mem.as_mut_slice().fill(0);
            let csr = MmioRegion {
                phys: mem.phys_addr(),
                virt: mem.as_mut_ptr() as u64,
                len: mem.len() as u64,
                kind: narf_bus::BarKind::Mmio32 {
                    prefetchable: false,
                },
            };
            // SAFETY: fixture-owned MMIO backing.
            unsafe {
                csr.write32(super::REG_STATUS, super::STATUS_LU);
            }
            FIXTURE_MMIO.store(csr.virt, Ordering::Release);
            if !FIXTURE_PUMP_REGISTERED.swap(true, Ordering::AcqRel) {
                narf_scheduler::sleep_pumps::register_nested_only(fixture_pump);
            }
            let tx_ring = alloc_coherent(4096, crate::BUILTIN_DOMAIN).unwrap();
            let mut tx_pool = alloc::vec::Vec::with_capacity(TX_RING_LEN);
            for _ in 0..TX_RING_LEN {
                tx_pool.push(alloc_coherent(4096, crate::BUILTIN_DOMAIN).unwrap());
            }
            let tx_zc_pool = alloc::sync::Arc::new(DmaPool::new(
                super::MAX_TSO_FRAME,
                crate::BUILTIN_DOMAIN,
                TX_RING_LEN,
            ));
            let _ = tx_zc_pool.prefill(TX_RING_LEN);
            let rx_ring = alloc_coherent(4096, crate::BUILTIN_DOMAIN).unwrap();
            let mut rx_pool = alloc::vec::Vec::with_capacity(RX_RING_LEN);
            for _ in 0..RX_RING_LEN {
                rx_pool.push(alloc_coherent(4096, crate::BUILTIN_DOMAIN).unwrap());
            }
            let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
            let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();
            let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            let device = E1000 {
                mmio: csr,
                tx_ring,
                tx_pool,
                tx_zc_pool,
                tx_state: IrqSafeSpinLock::new(TxQueueState::new()),
                rx_ring,
                rx_pool,
                rx_head: IrqSafeSpinLock::new(0),
                vlan_filter: IrqSafeSpinLock::new(VlanFilter::new()),
                multicast_filter: IrqSafeSpinLock::new(MulticastFilter::new()),
                // Fixture device: the fake BAR0 is an 8254x window,
                // so the classic 82540EM id (jumbo ceiling 16110).
                did: super::E1000_DEV_82540EM,
                mtu: IrqSafeSpinLock::new(crate::mtu::STD_MTU),
                mac,
                link_up: true,
                _msix: None,
                irq_vector: None,
                pch_part: false,
                me_active: false,
                rx_ipc_prod: IrqSafeSpinLock::new(None),
                rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
                rx_mirror_enabled: AtomicBool::new(false),
                tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
                detached: AtomicBool::new(false),
                suspended: AtomicBool::new(false),
                tx_timeouts: AtomicU64::new(0),
                tx_resets: AtomicU64::new(0),
                recovering: AtomicBool::new(false),
                // Fixture address: the test never probes a real device,
                // so the zero PCIe address is only a registry key
                // (same pattern as other driver fixtures).
                addr: narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0, 0, 0, 0)),
                ifname: crate::publish::IfName::new(),
                lsc_pending: AtomicBool::new(false),
            };
            // Bring-up register program (steps 4–6), minus the IRQ
            // install: rings, filters, link up.
            let (ral, rah) = rar_encode(&mac);
            let tx_phys = device.tx_ring.dma_addr().raw();
            let rx_phys = device.rx_ring.dma_addr().raw();
            // SAFETY: fixture-owned fake MMIO.
            unsafe {
                device.mmio.write32(super::REG_RAL0, ral);
                device.mmio.write32(super::REG_RAH0, rah);
                device.mmio.write32(super::REG_TDBAL, tx_phys as u32);
                device
                    .mmio
                    .write32(super::REG_TDBAH, (tx_phys >> 32) as u32);
                device
                    .mmio
                    .write32(super::REG_TDLEN, (TX_RING_LEN * 16) as u32);
                device.mmio.write32(super::REG_TDH, 0);
                device.mmio.write32(super::REG_TDT, 0);
                device
                    .mmio
                    .write32(super::REG_TIPG, super::TIPG_COPPER_DEFAULT);
                device.mmio.write32(
                    super::REG_TCTL,
                    super::TCTL_EN
                        | super::TCTL_PSP
                        | super::TCTL_CT_15
                        | super::TCTL_COLD_63
                        | super::TCTL_RTLC,
                );
                device.mmio.write32(super::REG_RDBAL, rx_phys as u32);
                device
                    .mmio
                    .write32(super::REG_RDBAH, (rx_phys >> 32) as u32);
                device
                    .mmio
                    .write32(super::REG_RDLEN, (RX_RING_LEN * 16) as u32);
                device.mmio.write32(super::REG_RDH, 0);
                device
                    .mmio
                    .write32(super::REG_RDT, (RX_RING_LEN - 1) as u32);
                device.mmio.write32(
                    super::REG_RCTL,
                    super::RCTL_EN | super::RCTL_BAM | super::RCTL_SECRC | super::RCTL_BSIZE_2K,
                );
                let ctrl = device.mmio.read32(super::REG_CTRL);
                device.mmio.write32(super::REG_CTRL, ctrl | super::CTRL_SLU);
            }
            // Prime the RX descriptors from the pool (bring-up step 5b).
            for (i, buf) in device.rx_pool.iter().enumerate().take(RX_RING_LEN) {
                let desc = RxDesc {
                    addr: buf.dma_addr().raw(),
                    length: 0,
                    csum: 0,
                    status: 0,
                    errors: 0,
                    special: 0,
                };
                // SAFETY: fixture-owned DMA ring.
                unsafe {
                    core::ptr::write_volatile(
                        device.rx_ring.cpu_mut_ptr_at::<RxDesc>((i * 16) as u64),
                        desc,
                    );
                }
            }
            core::mem::drop(rx_prod);
            core::mem::drop(tx_cons);
            Self {
                device,
                _mmio_mem: mem,
            }
        }
    }

    /// In-memory register bank for the PM fixtures: 16 KiB of BAR0
    /// window, covering every register the suspend/resume plans
    /// touch (highest is TCTL at 0x400; STATUS at 0x8, ICR at 0xC0,
    /// IMS/IMC at 0xD0/0xD8, RCTL at 0x100).
    struct FakeBank {
        regs: alloc::vec::Vec<u32>,
    }

    impl FakeBank {
        fn new() -> Self {
            Self {
                regs: alloc::vec![0u32; 0x1000 / 4],
            }
        }
        fn value(&self, offset: u64) -> u32 {
            self.regs.get((offset / 4) as usize).copied().unwrap_or(0)
        }
    }

    impl super::pm::RegBank for FakeBank {
        fn read32(&self, offset: u64) -> u32 {
            self.value(offset)
        }
        fn write32(&mut self, offset: u64, value: u32) {
            if let Some(slot) = self.regs.get_mut((offset / 4) as usize) {
                *slot = value;
            }
        }
    }

    impl Drop for TxTimeoutFixture {
        fn drop(&mut self) {
            FIXTURE_COMPLETE_TX.store(false, Ordering::Release);
            FIXTURE_MMIO.store(0, Ordering::Release);
        }
    }

    fn smoke_tx_timeout_recovery_fixture() -> TestResult {
        let fixture = TxTimeoutFixture::new();
        let device = &fixture.device;
        let frame = [0xAAu8; 64];
        // 1. Stall: post one frame directly so its ticket survives,
        // then a second post through the synchronous path times out
        // — the wedged ring, as the field sees it.
        let ticket = match device.tx_enqueue(&frame, true, None) {
            Ok(ticket) => ticket,
            Err(_) => {
                return TestResult::Fail("e1000 TX post failed on a fresh ring");
            }
        };
        if device.tx(&frame).is_ok() {
            return TestResult::Fail("e1000 TX completed against a wedged fake device");
        }
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        let posted = device.tx_state.lock().cursor.posted_at[0];
        if posted == 0 {
            return TestResult::Fail("e1000 TX post did not stamp a post time");
        }
        // 2. The watchdog does not fire inside the grace period...
        if device.check_tx_watchdog_at(posted + timeout) {
            return TestResult::Fail("e1000 watchdog fired at exactly the timeout");
        }
        if device.tx_resets() != 0 || device.tx_timeouts() != 0 {
            return TestResult::Fail("e1000 watchdog counted a recovery it did not fire");
        }
        // ...but fires past it, resets the controller, and the ring
        // comes back.
        if !device.check_tx_watchdog_at(posted + timeout + 1) {
            return TestResult::Fail("e1000 watchdog did not fire past the timeout");
        }
        if device.tx_timeouts() != 1 || device.tx_resets() != 1 {
            return TestResult::Fail("e1000 watchdog recovery was not counted");
        }
        // The pre-reset ticket never reports done: its frame was
        // dropped with the ring, and no later frame's DD bit on the
        // same slot may stand in for it (ring-epoch gate).
        if device.tx_slot_done(ticket) {
            return TestResult::Fail("e1000 pre-reset TX ticket reported done after recovery");
        }
        // SAFETY: fixture-owned fake MMIO.
        unsafe {
            if device.mmio.read32(super::REG_TDT) != 0 {
                return TestResult::Fail("e1000 recovery left a stale TX tail");
            }
            if device.mmio.read32(super::REG_TCTL) & super::TCTL_EN == 0 {
                return TestResult::Fail("e1000 recovery left TX disabled");
            }
            if device.mmio.read32(super::REG_RCTL) & super::RCTL_EN == 0 {
                return TestResult::Fail("e1000 recovery left RX disabled");
            }
            if device.mmio.read32(super::REG_RDT) != (RX_RING_LEN - 1) as u32 {
                return TestResult::Fail("e1000 recovery left the RX tail unprimed");
            }
        }
        if device
            .tx_state
            .lock()
            .stalled(posted + timeout + 1, timeout)
        {
            return TestResult::Fail("e1000 TX stall survived the recovery");
        }
        // 3. Traffic resumes: with the fake device completing
        // descriptors again, a fresh post completes.
        FIXTURE_COMPLETE_TX.store(true, Ordering::Release);
        if device.tx(&frame).is_err() {
            return TestResult::Fail("e1000 TX did not resume after recovery");
        }
        // A fresh post inside the grace period does not re-fire the
        // watchdog.
        let posted2 = device.tx_state.lock().cursor.posted_at[0];
        if device.check_tx_watchdog_at(posted2 + timeout) {
            return TestResult::Fail("e1000 watchdog re-fired inside the grace period");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_tx_timeout_recovery_fixture);
    fn smoke_e1000_pm_suspend_stops_dma() -> TestResult {
        // Bring-up state: DMA engines on, interrupts armed.
        let mut bank = FakeBank::new();
        bank.write32(
            super::REG_RCTL,
            super::RCTL_EN | super::RCTL_BAM | super::RCTL_SECRC,
        );
        bank.write32(super::REG_TCTL, super::TCTL_EN | super::TCTL_PSP);
        bank.write32(super::REG_IMS, super::IMS_DEFAULT);
        super::pm::suspend_plan(&mut bank, super::E1000::RCTL_SUSPEND_OFF);
        if bank.value(super::REG_IMC) != !0u32 {
            return TestResult::Fail("e1000 suspend did not mask interrupts");
        }
        if bank.value(super::REG_TCTL) != super::E1000::TCTL_SUSPEND_OFF
            || bank.value(super::REG_TCTL) & super::TCTL_EN != 0
        {
            return TestResult::Fail("e1000 suspend did not stop TX DMA");
        }
        if bank.value(super::REG_RCTL) != super::E1000::RCTL_SUSPEND_OFF
            || bank.value(super::REG_RCTL) & super::RCTL_EN != 0
        {
            return TestResult::Fail("e1000 suspend did not stop RX DMA");
        }
        // Suspend words keep the filter/config bits so resume
        // restores exactly what bring-up programmed.
        if bank.value(super::REG_RCTL) & super::RCTL_BAM == 0
            || bank.value(super::REG_TCTL) & super::TCTL_PSP == 0
        {
            return TestResult::Fail("e1000 suspend words lost bring-up config bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_e1000_pm_suspend_stops_dma);

    fn smoke_e1000_pm_resume_restores_and_relinks() -> TestResult {
        let mut bank = FakeBank::new();
        super::pm::suspend_plan(&mut bank, super::E1000::RCTL_SUSPEND_OFF);
        // Live link: STATUS reports LU at 1000 Full.
        bank.write32(
            super::REG_STATUS,
            super::STATUS_LU | super::STATUS_SPEED_1000 | super::STATUS_FD,
        );
        let rctl = super::RCTL_EN
            | super::RCTL_BAM
            | super::RCTL_UPE
            | super::RCTL_MPE
            | super::RCTL_SECRC
            | super::RCTL_BSIZE_2K;
        let status = super::pm::resume_plan(&mut bank, rctl, true);
        if bank.value(super::REG_RCTL) & super::RCTL_EN == 0
            || bank.value(super::REG_TCTL) & super::TCTL_EN == 0
        {
            return TestResult::Fail("e1000 resume did not re-enable DMA engines");
        }
        if bank.value(super::REG_IMS) != super::IMS_DEFAULT {
            return TestResult::Fail("e1000 resume did not re-arm the interrupt mask");
        }
        if status & super::STATUS_LU == 0 {
            return TestResult::Fail("e1000 resume did not sample live STATUS");
        }
        let sample = super::link_sample_from_status(status);
        if !sample.carrier || sample.speed_mbps != Some(1000) {
            return TestResult::Fail("e1000 resume link sample lost carrier/speed");
        }
        // Polled device: no vector bound, mask stays as bring-up left it.
        let mut polled = FakeBank::new();
        super::pm::suspend_plan(&mut polled, super::E1000::RCTL_SUSPEND_OFF);
        let _ = super::pm::resume_plan(&mut polled, rctl, false);
        if polled.value(super::REG_IMS) != 0 {
            return TestResult::Fail("e1000 resume armed IMS on a polled device");
        }
        // Suspend → resume → suspend is stable: a second cycle
        // programs the same words (idempotent fan-out).
        super::pm::suspend_plan(&mut bank, super::E1000::RCTL_SUSPEND_OFF);
        if bank.value(super::REG_RCTL) != super::E1000::RCTL_SUSPEND_OFF
            || bank.value(super::REG_TCTL) != super::E1000::TCTL_SUSPEND_OFF
        {
            return TestResult::Fail("e1000 second suspend drifted from the first");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/e1000",
        smoke_e1000_pm_resume_restores_and_relinks
    );

    fn smoke_rctl_bsize_lpe_follows_mtu() -> TestResult {
        // Standard MTU: 2K step (0), LPE clear — the bring-up word.
        if super::rctl_bsize_lpe(1500) != super::RCTL_BSIZE_2K {
            return TestResult::Fail("e1000 RCTL program not 2K at MTU 1500");
        }
        // Any jumbo MTU: 16K step + LPE, on every part (the buffer
        // step is a property of RCTL, not of the device id).
        if super::rctl_bsize_lpe(1501) != super::RCTL_BSIZE_16K | super::RCTL_LPE
            || super::rctl_bsize_lpe(9000) != super::RCTL_BSIZE_16K | super::RCTL_LPE
            || super::rctl_bsize_lpe(16110) != super::RCTL_BSIZE_16K | super::RCTL_LPE
        {
            return TestResult::Fail("e1000 RCTL program not 16K+LPE at jumbo MTU");
        }
        // The 16K step covers the classic max frame; the LPE bit is
        // bit 5 (Linux E1000_RCTL_LPE).
        if super::RCTL_LPE != 1 << 5 || super::RCTL_BSIZE_16K != 0x3 << 16 {
            return TestResult::Fail("e1000 RCTL LPE/BSIZE_16K constants drifted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_rctl_bsize_lpe_follows_mtu);

    fn smoke_e1000_rx_desc_sample_never_mixes_occupants() -> TestResult {
        // A re-armed RX slot holds its buffer address with length, status
        // and errors zeroed until the device writes the descriptor back,
        // and the host may be sampling the slot at that moment. Model the
        // device posting the WHOLE write-back after each possible number of
        // host loads. Whatever the interleaving, a sample that reports DD
        // must be the write-back in full: with the re-armed slot's fields
        // under a fresh DD the driver delivers a zero-length frame.
        const ARMED_ADDR: u64 = 0x0000_0001_2345_6000;
        const NEW_ADDR: u64 = 0x0000_0001_2345_7000;
        // SDM §3.2.3 legacy RX descriptor qword 1: length at bytes 8..9,
        // checksum 10..11, status 12 (DD bit 0, EOP bit 1), errors 13,
        // special (VLAN tag) 14..15.
        let old = [ARMED_ADDR, 0u64];
        let new = [
            NEW_ADDR,
            0x05EAu64 | (0xC5C5 << 16) | (0x03 << 32) | (0x20 << 40) | (0x0123 << 48),
        ];

        for post_after in 0..=2usize {
            let slot = core::cell::Cell::new(old);
            let loads = core::cell::Cell::new(0usize);
            let sampled = RxDesc::sample(|word| {
                if loads.get() == post_after {
                    slot.set(new);
                }
                loads.set(loads.get() + 1);
                slot.get()[word]
            });
            let Some(desc) = sampled else {
                // Not completed yet: the driver polls again.
                if post_after == 0 {
                    return TestResult::Fail("a write-back posted before the sample read as armed");
                }
                if loads.get() != 1 {
                    return TestResult::Fail("an incomplete slot was read past its status word");
                }
                continue;
            };
            if loads.get() != 2 {
                return TestResult::Fail("a completed sample is not exactly two qword loads");
            }
            if desc.length != 0x05EA
                || desc.csum != 0xC5C5
                || desc.status != 0x03
                || desc.errors != 0x20
                || desc.special != 0x0123
            {
                return TestResult::Fail("fresh DD sampled with a stale length or error field");
            }
            if desc.addr != NEW_ADDR {
                return TestResult::Fail("fresh DD sampled with the re-armed slot's qword 0");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/e1000",
        smoke_e1000_rx_desc_sample_never_mixes_occupants
    );
}
