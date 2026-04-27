//! e1000 / e1000e family driver — Intel 8254x and 8257x Gigabit
//! Ethernet controllers.
//!
//! Spec: Intel "PCI/PCI-X Family of Gigabit Ethernet Controllers
//! Software Developer's Manual" (8254x) + "Intel 82574L Gigabit
//! Ethernet Controller Datasheet" (8257x). The two families share
//! enough register layout that one driver covers both with a small
//! probe-time discriminator.
//!
//! Stage-4 cut: bring up the device far enough to read the MAC
//! address from the Receive Address Registers (RAL/RAH), program a
//! TX descriptor ring, transmit a single Ethernet frame, and poll
//! the descriptor's Done bit. RX, MSI-X, link-state IRQs land in
//! follow-ups — they reuse the `bus::map_bar` + `narf_io::alloc_coherent`
//! + `narf_interrupts::wait_for_irq` patterns the virtio-pci
//! drivers established.
//!
//! Register subset (all 4-byte aligned, BAR0 + offset):
//!
//! | offset  | name | description                       |
//! |---------|------|-----------------------------------|
//! | 0x0000  | CTRL | Device Control                    |
//! | 0x0008  | STATUS| Device Status                    |
//! | 0x0014  | EERD | EEPROM Read                       |
//! | 0x00D0  | IMS  | Interrupt Mask Set/Read           |
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

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs we recognise ─────────────────────────────────────

/// Vendor: Intel.
pub const E1000_VENDOR: u16 = 0x8086;

/// Classic 82540EM (`-device e1000`).
pub const E1000_DEV_82540EM: u16 = 0x100E;
/// 82545EM Gigabit.
pub const E1000_DEV_82545EM: u16 = 0x100F;
/// QEMU's `-device e1000-82544gc`.
pub const E1000_DEV_82544GC: u16 = 0x100C;
/// 82574L (used by QEMU q35 default + `-device e1000e`).
pub const E1000E_DEV_82574L: u16 = 0x10D3;
/// I217-LM, found on real Lenovo laptops.
pub const E1000E_DEV_I217LM: u16 = 0x153A;

// ── Register offsets ────────────────────────────────────────────────

const REG_CTRL:   u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
const REG_EERD:   u64 = 0x0014;
const REG_IMS:    u64 = 0x00D0;
const REG_RCTL:   u64 = 0x0100;
const REG_TCTL:   u64 = 0x0400;
const REG_TDBAL:  u64 = 0x3800;
const REG_TDBAH:  u64 = 0x3804;
const REG_TDLEN:  u64 = 0x3808;
const REG_TDH:    u64 = 0x3810;
const REG_TDT:    u64 = 0x3818;
const REG_RAL0:   u64 = 0x5400;
const REG_RAH0:   u64 = 0x5404;

// CTRL bits.
const CTRL_RST:     u32 = 1 << 26;
const CTRL_SLU:     u32 = 1 << 6;   // Set Link Up

// TCTL bits.
const TCTL_EN:      u32 = 1 << 1;
const TCTL_PSP:     u32 = 1 << 3;   // Pad Short Packets

// TX descriptor flags.
const TXD_CMD_EOP:  u8 = 1 << 0;
const TXD_CMD_IFCS: u8 = 1 << 1;    // Insert FCS
const TXD_CMD_RS:   u8 = 1 << 3;    // Report Status
const TXD_STAT_DD:  u8 = 1 << 0;    // Done

const TX_RING_LEN:  usize = 8;

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
struct TxDesc {
    addr:    u64,
    length:  u16,
    cso:     u8,
    cmd:     u8,
    status:  u8,
    css:     u8,
    special: u16,
}

const _: () = assert!(core::mem::size_of::<TxDesc>() == 16);

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
}

/// Live e1000 controller. Holds the MMIO mapping + the TX descriptor
/// ring's DMA buffer. Each frame transmits through a per-call DMA
/// scratch buffer that drops after completion.
pub struct E1000 {
    mmio:       MmioRegion,
    /// TX descriptor-ring DMA buffer.
    tx_ring:    DmaBuffer,
    /// Driver-side TDT cursor (tail).
    tx_tail:    IrqSafeSpinLock<u32>,
    /// MAC address read from RAL/RAH at bring-up.
    pub mac:    [u8; 6],
    /// True after CTRL_SLU has been set + STATUS reports link up.
    pub link_up: bool,
}

impl core::fmt::Debug for E1000 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("E1000")
            .field("mac",      &self.mac)
            .field("link_up",  &self.link_up)
            .finish_non_exhaustive()
    }
}

impl E1000 {
    /// Bring up the controller: reset, read MAC, install TX ring,
    /// set link up. Polled. RX path lands once the net stack has a
    /// consumer.
    ///
    /// # Safety
    /// Caller owns the device's BAR exclusively for the duration of
    /// init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, E1000Error> {
        // SAFETY: caller owns the device.
        let mmio = unsafe { map_bar(device, 0) }
            .map_err(|_| E1000Error::BarMapFailed)?;

        // 1. Reset (CTRL.RST = 1; cleared by hardware after reset).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_CTRL, CTRL_RST);
        }
        // Wait for RST to clear.
        for _ in 0..1_000_000u32 {
            // SAFETY: identity-mapped.
            let v = unsafe { mmio.read32(REG_CTRL) };
            if v & CTRL_RST == 0 { break; }
            core::hint::spin_loop();
        }

        // 2. Read MAC from RAL/RAH.
        // SAFETY: identity-mapped.
        let ral = unsafe { mmio.read32(REG_RAL0) };
        let rah = unsafe { mmio.read32(REG_RAH0) };
        let mac = [
            (ral & 0xFF) as u8,
            ((ral >> 8) & 0xFF) as u8,
            ((ral >> 16) & 0xFF) as u8,
            ((ral >> 24) & 0xFF) as u8,
            (rah & 0xFF) as u8,
            ((rah >> 8) & 0xFF) as u8,
        ];

        // 3. Mask all interrupts (we poll TX completion).
        // SAFETY: identity-mapped.
        unsafe { mmio.write32(REG_IMS, 0); }

        // 4. Allocate TX descriptor ring.
        let tx_ring = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| E1000Error::NoMemory)?;
        let ring_phys = tx_ring.phys_addr().raw();
        // Zero the ring (alloc_coherent guarantees fresh memory but
        // we're explicit).
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..(TX_RING_LEN * 16) {
                core::ptr::write_volatile(
                    (ring_phys + i as u64) as *mut u8, 0);
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
        unsafe { mmio.write32(REG_TCTL, TCTL_EN | TCTL_PSP); }

        // 6. Set link up.
        // SAFETY: same.
        let cur = unsafe { mmio.read32(REG_CTRL) };
        // SAFETY: same.
        unsafe { mmio.write32(REG_CTRL, cur | CTRL_SLU); }
        // STATUS bit 1 = LU (link up). QEMU e1000 reports up
        // immediately on user-mode net.
        // SAFETY: same.
        let status = unsafe { mmio.read32(REG_STATUS) };
        let link_up = status & (1 << 1) != 0;

        Ok(Self {
            mmio,
            tx_ring,
            tx_tail: IrqSafeSpinLock::new(0),
            mac,
            link_up,
        })
    }

    /// Transmit a single Ethernet frame. Polled completion via the
    /// TX descriptor's DD (Descriptor Done) status bit.
    pub fn tx(&self, frame: &[u8]) -> Result<(), E1000Error> {
        if frame.len() == 0 || frame.len() > 1518 {
            return Err(E1000Error::FrameTooLong);
        }
        // Stage the frame into a fresh DMA scratch page.
        let scratch = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| E1000Error::NoMemory)?;
        let phys = scratch.phys_addr().raw();
        // SAFETY: identity-mapped DMA.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile(
                    (phys + i as u64) as *mut u8, *b);
            }
        }
        // Pick the next TX descriptor slot.
        let mut tail_g = self.tx_tail.lock();
        let slot = (*tail_g) as usize % TX_RING_LEN;
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        let desc = TxDesc {
            addr:    phys,
            length:  frame.len() as u16,
            cso:     0,
            cmd:     TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS,
            status:  0,
            css:     0,
            special: 0,
        };
        // SAFETY: identity-mapped DMA ring page.
        unsafe { core::ptr::write_volatile(desc_addr as *mut TxDesc, desc); }
        // Bump TDT.
        let next_tail = (*tail_g + 1) % (TX_RING_LEN as u32);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.write32(REG_TDT, next_tail); }
        *tail_g = next_tail;
        drop(tail_g);

        // Poll for DD.
        let mut spins = 0u32;
        loop {
            // SAFETY: identity-mapped DMA.
            let status = unsafe {
                core::ptr::read_volatile((desc_addr + 12) as *const u8)
            };
            if status & TXD_STAT_DD != 0 { break; }
            spins += 1;
            if spins > 10_000_000 { return Err(E1000Error::TxTimeout); }
            core::hint::spin_loop();
        }
        // scratch drops here.
        let _ = scratch;
        Ok(())
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
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<E1000>> =
    IrqSafeSpinLock::new(None);

pub fn probe(
    device: BusDevice,
    cap:    Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() { return Ok(()); }
    narf_bus::pci::set_command(
        &cap, &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    ).map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over device.
    let dev = match unsafe { E1000::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    Ok(())
}

/// Register the driver against every Intel device id we recognise.
/// One match per id pair so each is independently maintainable.
pub fn register_pci_driver() {
    for did in [
        E1000_DEV_82540EM, E1000_DEV_82545EM, E1000_DEV_82544GC,
        E1000E_DEV_82574L, E1000E_DEV_I217LM,
    ] {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: E1000_VENDOR, device: did,
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
        E1000E_DEV_I217LM => "e1000e-i217lm",
        _                 => "e1000",
    }
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&E1000) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
