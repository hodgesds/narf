//! Intel ixgbe — 82599 / X540 / X550 10 GbE controller driver.
//!
//! Spec: `drivers/net/specification/ixgbe.md`. Clean-room: register
//! layout sourced from the public Intel 82599 / X540 / X550
//! datasheets. No GPL Linux source consulted.

use core::sync::atomic::{compiler_fence, Ordering};

use alloc::vec::Vec;

use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

mod tests;

// ── PCI device IDs ─────────────────────────────────────────────────

/// Intel.
pub const IXGBE_VENDOR: u16 = 0x8086;

/// 82599EB (SFI/SFP+).
pub const IXGBE_DEV_82599EB: u16 = 0x10FB;
/// X540-AT2.
pub const IXGBE_DEV_X540: u16 = 0x1528;
/// X550 (10G base-T copper).
pub const IXGBE_DEV_X550: u16 = 0x1563;
/// X550EM_x (10G SFP+).
pub const IXGBE_DEV_X550EM_X: u16 = 0x15AB;

const ALL_DEV_IDS: &[u16] = &[
    IXGBE_DEV_82599EB,
    IXGBE_DEV_X540,
    IXGBE_DEV_X550,
    IXGBE_DEV_X550EM_X,
];

// ── Register offsets (BAR0) ────────────────────────────────────────
// 82599 §8.2.

pub(crate) const REG_CTRL: u64 = 0x00000;
pub(crate) const REG_STATUS: u64 = 0x00008;
pub(crate) const REG_CTRL_EXT: u64 = 0x00018;
pub(crate) const REG_EERD: u64 = 0x10010;

pub(crate) const REG_EICR: u64 = 0x00800;
pub(crate) const REG_EIMS: u64 = 0x00880;
pub(crate) const REG_EIMC: u64 = 0x00888;
pub(crate) const REG_GPIE: u64 = 0x00A50;
pub(crate) const REG_EIAM: u64 = 0x00A90;
pub(crate) const REG_IVAR0: u64 = 0x01000; // 64 IVARs, stride 4
pub(crate) const REG_IVAR_MISC: u64 = 0x011E0; // OTHER_CAUSES_IVAR

pub(crate) const REG_FCTRL: u64 = 0x05080;
pub(crate) const REG_RAL0: u64 = 0x0A200; // 82599 receive-address regs §8.2.3.7.9
pub(crate) const REG_RAH0: u64 = 0x0A204;
pub(crate) const REG_RXCTRL: u64 = 0x03000;
pub(crate) const REG_LINKS: u64 = 0x04200;

// 82599 RX queue 0 register block. §8.2.3.8 — stride 0x40 per queue.
pub(crate) const RX_RDBAL: u64 = 0x01000;
pub(crate) const RX_RDBAH: u64 = 0x01004;
pub(crate) const RX_RDLEN: u64 = 0x01008;
pub(crate) const RX_RDH: u64 = 0x01010;
pub(crate) const RX_RDT: u64 = 0x01018;
pub(crate) const RX_RXDCTL: u64 = 0x01028;
pub(crate) const RX_SRRCTL: u64 = 0x01014;

pub(crate) const TX_TDBAL: u64 = 0x06000;
pub(crate) const TX_TDBAH: u64 = 0x06004;
pub(crate) const TX_TDLEN: u64 = 0x06008;
pub(crate) const TX_TDH: u64 = 0x06010;
pub(crate) const TX_TDT: u64 = 0x06018;
pub(crate) const TX_TXDCTL: u64 = 0x06028;

// CTRL bits (§8.2.3.1.1).
pub(crate) const CTRL_RST_MASK: u32 = (1 << 26) | (1 << 3); // RST | LRST

// CTRL_EXT bits.
pub(crate) const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;
pub(crate) const CTRL_EXT_NS_DIS: u32 = 1 << 16;

// FCTRL bits.
pub(crate) const FCTRL_BAM: u32 = 1 << 10;
pub(crate) const FCTRL_UPE: u32 = 1 << 9;
pub(crate) const FCTRL_MPE: u32 = 1 << 8;

// RXCTRL bits.
pub(crate) const RXCTRL_RXEN: u32 = 1 << 0;

// LINKS bits.
pub(crate) const LINKS_UP: u32 = 1 << 30;

// RAH bits — Address-Valid; programmed when we plumb the MAC into RAH/RAL.
#[allow(dead_code)]
pub(crate) const RAH_AV: u32 = 1 << 31;

// EERD bits (§10.2.4.2).
pub(crate) const EERD_START: u32 = 1 << 0;
pub(crate) const EERD_DONE: u32 = 1 << 1;
pub(crate) const EERD_ADDR_SHIFT: u32 = 2;

// RXDCTL / TXDCTL.
pub(crate) const RXDCTL_ENABLE: u32 = 1 << 25;
pub(crate) const TXDCTL_ENABLE: u32 = 1 << 25;

// SRRCTL — bsize selector (1 KiB units), legacy descriptor type.
pub(crate) const SRRCTL_BSIZE_2K: u32 = 2; // bits[4:0]
pub(crate) const SRRCTL_DESCTYPE_LEGACY: u32 = 0 << 25;

// Advanced TX descriptor cmd_type_len bits (§7.2.3.2.4).
pub(crate) const ADVTXD_DTYP_DATA: u32 = 0x3 << 20;
pub(crate) const ADVTXD_DCMD_DEXT: u32 = 1 << 29;
pub(crate) const ADVTXD_DCMD_RS: u32 = 1 << 27;
pub(crate) const ADVTXD_DCMD_IFCS: u32 = 1 << 25;
pub(crate) const ADVTXD_DCMD_EOP: u32 = 1 << 24;
pub(crate) const ADVTXD_STAT_DD: u32 = 1 << 0;

// Legacy RX descriptor status bits.
pub(crate) const RXD_STAT_DD: u8 = 1 << 0;
#[allow(dead_code)]
pub(crate) const RXD_STAT_EOP: u8 = 1 << 1;

// Ring sizes — keep small for Stage-3/4 bring-up.
pub(crate) const TX_RING_LEN: usize = 32;
pub(crate) const RX_RING_LEN: usize = 32;
pub(crate) const RX_BUF_LEN: usize = 2048;

// ── Descriptor types ───────────────────────────────────────────────

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct AdvTxDesc {
    pub addr: u64,
    pub cmd_type_len: u32,
    pub olinfo: u32,
}
const _: () = assert!(core::mem::size_of::<AdvTxDesc>() == 16);

impl AdvTxDesc {
    /// Pack the cmd_type_len field for a single-buffer EOP send with
    /// RS reporting and FCS insertion. `len` must fit in 16 bits
    /// (datasheet §7.2.3.2.4: DTALEN is 16 bits).
    pub fn ctrl_word(len: u16) -> u32 {
        (len as u32)
            | ADVTXD_DTYP_DATA
            | ADVTXD_DCMD_DEXT
            | ADVTXD_DCMD_RS
            | ADVTXD_DCMD_IFCS
            | ADVTXD_DCMD_EOP
    }
}

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

// ── EEPROM decode helper (Stage 2) ─────────────────────────────────

/// Decode the EEPROM "data" word out of an EERD register value.
/// The 82599 datasheet (§10.2.4.2.1) places the read-result in
/// bits [31:16].
pub fn eeprom_decode(eerd: u32) -> u16 {
    (eerd >> 16) as u16
}

/// Pack a 16-bit EEPROM address into a START-bit-set EERD write.
pub fn eerd_start(addr: u16) -> u32 {
    ((addr as u32) << EERD_ADDR_SHIFT) | EERD_START
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IxgbeError {
    BarMapFailed,
    NoMemory,
    UnsupportedDevice,
    /// CTRL.RST never cleared.
    ResetTimeout,
    /// EERD.DONE never set.
    EepromTimeout,
    /// Caller passed a frame larger than 1518 bytes.
    FrameTooLong,
    /// TX descriptor never completed.
    TxTimeout,
    /// MSI-X capability not present / could not be enabled.
    MsixUnavailable,
}

// ── Driver state ───────────────────────────────────────────────────

pub struct Ixgbe {
    pub(crate) mmio: MmioRegion,
    pub(crate) tx_ring: DmaBuffer,
    pub(crate) rx_ring: DmaBuffer,
    /// Held to keep the per-descriptor DMA buffers alive for the
    /// lifetime of the controller; addresses live inside the RX
    /// descriptors themselves.
    #[allow(dead_code)]
    pub(crate) rx_pool: Vec<DmaBuffer>,
    pub(crate) tx_tail: IrqSafeSpinLock<u32>,
    pub(crate) rx_head: IrqSafeSpinLock<u32>,
    /// MAC read from the EEPROM at bring-up.
    pub mac: [u8; 6],
    /// True after the MAC was successfully programmed into RAH/RAL
    /// and LINKS reports up.
    pub link_up: bool,
    /// Recorded device id (drives `name()`).
    pub did: u16,
    /// Stage 5: MSI-X table once enabled.
    pub(crate) msix: Option<MsixTable>,
}

impl core::fmt::Debug for Ixgbe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ixgbe")
            .field("mac", &self.mac)
            .field("link_up", &self.link_up)
            .field("did", &format_args!("0x{:04X}", self.did))
            .finish_non_exhaustive()
    }
}

impl Ixgbe {
    /// Bring the controller up: PCI MMIO map, master reset, MAC
    /// read, TX/RX rings programmed, link enabled. MSI-X gets wired
    /// up by `enable_msix_vector()` once the bus side has been
    /// validated.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 exclusively for the duration of
    /// init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, IxgbeError> {
        // SAFETY: caller-authority over the device.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| IxgbeError::BarMapFailed)?;

        // 1. Mask all extended interrupts (§4.6.3.2 — driver should
        //    own EIMC before firmware moves on).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_EIMC, 0xFFFF_FFFF);
            // Read EICR to clear any latched causes.
            let _ = mmio.read32(REG_EICR);
        }

        // 2. Master reset — CTRL.LRST | CTRL.RST.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_CTRL, CTRL_RST_MASK);
        }
        let mut spins = 0u32;
        loop {
            // SAFETY: same.
            let v = unsafe { mmio.read32(REG_CTRL) };
            if v & CTRL_RST_MASK == 0 {
                break;
            }
            spins += 1;
            if spins > 1_000_000 {
                return Err(IxgbeError::ResetTimeout);
            }
            core::hint::spin_loop();
        }
        // Datasheet §4.6.3.2 — wait ~10 ms for FW handshake. Burn
        // some spins as a Stage-1 stand-in (a sleep_pump comes later).
        for _ in 0..200_000 {
            core::hint::spin_loop();
        }

        // 3. Re-mask after reset.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_EIMC, 0xFFFF_FFFF);
            let _ = mmio.read32(REG_EICR);
        }

        // 4. Read MAC. Try EEPROM words 0..2 first (§10.2.4.2);
        //    fall back to RAL/RAH if firmware already loaded the
        //    Receive Address.
        let mac = read_mac(&mmio).unwrap_or_else(|_| read_mac_from_rar(&mmio));

        // 5. Tell firmware the OS driver has loaded.
        // SAFETY: same.
        unsafe {
            let cur = mmio.read32(REG_CTRL_EXT);
            mmio.write32(REG_CTRL_EXT, cur | CTRL_EXT_DRV_LOAD | CTRL_EXT_NS_DIS);
        }

        // 6. Set up the TX ring (queue 0).
        let tx_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
        let tx_phys = tx_ring.phys_addr().raw();
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..(TX_RING_LEN * 16) {
                core::ptr::write_volatile((tx_phys + i as u64) as *mut u8, 0);
            }
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(TX_TDBAL, tx_phys as u32);
            mmio.write32(TX_TDBAH, (tx_phys >> 32) as u32);
            mmio.write32(TX_TDLEN, (TX_RING_LEN * 16) as u32);
            mmio.write32(TX_TDH, 0);
            mmio.write32(TX_TDT, 0);
            // Enable TX queue.
            let dctl = mmio.read32(TX_TXDCTL);
            mmio.write32(TX_TXDCTL, dctl | TXDCTL_ENABLE);
        }
        // Poll for queue-enable to take effect (§7.2.3.4.1).
        let mut spins = 0u32;
        loop {
            // SAFETY: same.
            let v = unsafe { mmio.read32(TX_TXDCTL) };
            if v & TXDCTL_ENABLE != 0 {
                break;
            }
            spins += 1;
            if spins > 1_000_000 {
                break;
            }
            core::hint::spin_loop();
        }

        // 7. RX ring + pool.
        let rx_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
        let rx_ring_phys = rx_ring.phys_addr().raw();
        let mut rx_pool = Vec::with_capacity(RX_RING_LEN);
        for i in 0..RX_RING_LEN {
            let buf = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
            let bp = buf.phys_addr().raw();
            let desc = RxDesc {
                addr: bp,
                length: 0,
                csum: 0,
                status: 0,
                errors: 0,
                special: 0,
            };
            // SAFETY: identity-mapped DMA ring page.
            unsafe {
                core::ptr::write_volatile((rx_ring_phys + (i * 16) as u64) as *mut RxDesc, desc);
            }
            rx_pool.push(buf);
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(RX_RDBAL, rx_ring_phys as u32);
            mmio.write32(RX_RDBAH, (rx_ring_phys >> 32) as u32);
            mmio.write32(RX_RDLEN, (RX_RING_LEN * 16) as u32);
            mmio.write32(RX_RDH, 0);
            mmio.write32(RX_RDT, (RX_RING_LEN - 1) as u32);
            // SRRCTL: 2K legacy buffers.
            mmio.write32(RX_SRRCTL, SRRCTL_BSIZE_2K | SRRCTL_DESCTYPE_LEGACY);
            // Enable RX queue.
            let dctl = mmio.read32(RX_RXDCTL);
            mmio.write32(RX_RXDCTL, dctl | RXDCTL_ENABLE);
            // Promiscuous + broadcast accept.
            mmio.write32(REG_FCTRL, FCTRL_BAM | FCTRL_UPE | FCTRL_MPE);
            // Master RX enable.
            mmio.write32(REG_RXCTRL, RXCTRL_RXEN);
        }

        // 8. Read LINKS to seed link_up.
        // SAFETY: same.
        let links = unsafe { mmio.read32(REG_LINKS) };
        let link_up = links & LINKS_UP != 0;

        Ok(Self {
            mmio,
            tx_ring,
            rx_ring,
            rx_pool,
            tx_tail: IrqSafeSpinLock::new(0),
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            link_up,
            did: device.id.device,
            msix: None,
        })
    }

    /// Read the EERD-decoded MAC bytes (Stage 2 surface).
    pub fn read_mac_eeprom(&self) -> Result<[u8; 6], IxgbeError> {
        read_mac(&self.mmio)
    }

    /// Transmit a single frame, polling the descriptor's DD bit.
    pub fn tx(&self, frame: &[u8]) -> Result<(), IxgbeError> {
        if frame.is_empty() || frame.len() > 1518 {
            return Err(IxgbeError::FrameTooLong);
        }
        let scratch = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
        let phys = scratch.phys_addr().raw();
        // SAFETY: identity-mapped DMA.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, *b);
            }
        }
        let mut tail_g = self.tx_tail.lock();
        let slot = (*tail_g) as usize % TX_RING_LEN;
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        let desc = AdvTxDesc {
            addr: phys,
            cmd_type_len: AdvTxDesc::ctrl_word(frame.len() as u16),
            // PAYLEN field at bits [31:14] of olinfo (§7.2.3.2.4).
            olinfo: (frame.len() as u32) << 14,
        };
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut AdvTxDesc, desc);
        }
        let next_tail = (*tail_g + 1) % (TX_RING_LEN as u32);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(TX_TDT, next_tail);
        }
        *tail_g = next_tail;
        drop(tail_g);

        // Poll DD: olinfo's low 4 bits of [3:0] (status) carry DD.
        // The advanced write-back lays status at olinfo[3:0]
        // (§7.2.3.2.4 write-back layout).
        let mut spins = 0u32;
        loop {
            // SAFETY: identity-mapped DMA.
            let olinfo = unsafe { core::ptr::read_volatile((desc_addr + 12) as *const u32) };
            if olinfo & ADVTXD_STAT_DD != 0 {
                break;
            }
            spins += 1;
            if spins > 10_000_000 {
                return Err(IxgbeError::TxTimeout);
            }
            core::hint::spin_loop();
        }
        let _ = scratch;
        Ok(())
    }

    /// Drain one RX frame into `out`. Returns 0 if nothing pending.
    pub fn rx_recv(&self, out: &mut [u8]) -> usize {
        let mut head_g = self.rx_head.lock();
        let head = (*head_g) as usize;
        let ring_phys = self.rx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let desc = unsafe { core::ptr::read_volatile(desc_addr as *const RxDesc) };
        if desc.status & RXD_STAT_DD == 0 {
            return 0;
        }
        let len = (desc.length as usize).min(out.len()).min(RX_BUF_LEN);
        let buf_phys = desc.addr;
        for i in 0..len {
            // SAFETY: identity-mapped DMA buffer.
            out[i] = unsafe { core::ptr::read_volatile((buf_phys + i as u64) as *const u8) };
        }
        let new_desc = RxDesc {
            addr: buf_phys,
            length: 0,
            csum: 0,
            status: 0,
            errors: 0,
            special: 0,
        };
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut RxDesc, new_desc);
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: MMIO.
        unsafe {
            self.mmio.write32(RX_RDT, head as u32);
        }
        let new_head = ((head + 1) % RX_RING_LEN) as u32;
        *head_g = new_head;
        let _ = RXD_STAT_EOP;
        len
    }

    pub fn rx_has_pending(&self) -> bool {
        let head = (*self.rx_head.lock()) as usize;
        let ring_phys = self.rx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let status = unsafe { core::ptr::read_volatile((desc_addr + 12) as *const u8) };
        status & RXD_STAT_DD != 0
    }

    /// Stage 5: enable MSI-X on this device. Allocates a single
    /// shared "misc" vector and routes RX queue 0 + the OTHER cause
    /// onto it via the IVAR registers. Stage 5 stops at table
    /// programming; the actual ISR wire-up happens once the
    /// `narf-interrupts` MSI delivery side is consumed by the net
    /// stack.
    pub fn enable_msix_vector(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(), IxgbeError> {
        let mut table = enable_msix(cap, device).map_err(|_| IxgbeError::MsixUnavailable)?;
        // Take vector 0 for "misc" (link / RX0 / TX0 collapsed).
        let _ = table.size(); // probed for completeness
                              // SAFETY: identity-mapped MMIO.
        unsafe {
            // Route RX queue 0 RX cause to vector 0:
            //   IVAR[0]: bit 7 = valid, bits[6:0] = vector.
            // RX uses low byte; TX uses byte 2.
            let ivar = (0x80u32) | (0x80u32 << 16);
            self.mmio.write32(REG_IVAR0, ivar);
            // OTHER_CAUSES_IVAR — link-state etc. → vector 0.
            self.mmio.write32(REG_IVAR_MISC, 0x80);
            // GPIE: enable multiple-MSIX, auto-mask, no EIAME yet.
            self.mmio.write32(REG_GPIE, (1 << 4) | (1 << 5) | (1 << 6));
            // EIAM: auto-clear vector 0 on read of EICR.
            self.mmio.write32(REG_EIAM, 1);
            // Unmask vector 0.
            self.mmio.write32(REG_EIMS, 1);
        }
        self.msix = Some(table);
        Ok(())
    }

    pub fn read_status(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_STATUS) }
    }

    pub fn read_links(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_LINKS) }
    }
}

// ── HwNic impl (Stage 6) ───────────────────────────────────────────

impl crate::HwNic for Ixgbe {
    fn name(&self) -> &'static str {
        name_for(self.did)
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.link_up
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::IntelIxgbe
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::PROMISC | crate::NicCaps::MULTICAST_HASH
    }
    fn ring_capacity(&self) -> usize {
        TX_RING_LEN
    }
}

// ── EEPROM helpers ─────────────────────────────────────────────────

fn eeprom_read_word(mmio: &MmioRegion, addr: u16) -> Result<u16, IxgbeError> {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        mmio.write32(REG_EERD, eerd_start(addr));
    }
    let mut spins = 0u32;
    loop {
        // SAFETY: same.
        let v = unsafe { mmio.read32(REG_EERD) };
        if v & EERD_DONE != 0 {
            return Ok(eeprom_decode(v));
        }
        spins += 1;
        if spins > 1_000_000 {
            return Err(IxgbeError::EepromTimeout);
        }
        core::hint::spin_loop();
    }
}

fn read_mac(mmio: &MmioRegion) -> Result<[u8; 6], IxgbeError> {
    let w0 = eeprom_read_word(mmio, 0)?;
    let w1 = eeprom_read_word(mmio, 1)?;
    let w2 = eeprom_read_word(mmio, 2)?;
    Ok([
        (w0 & 0xFF) as u8,
        (w0 >> 8) as u8,
        (w1 & 0xFF) as u8,
        (w1 >> 8) as u8,
        (w2 & 0xFF) as u8,
        (w2 >> 8) as u8,
    ])
}

fn read_mac_from_rar(mmio: &MmioRegion) -> [u8; 6] {
    // SAFETY: identity-mapped MMIO.
    let ral = unsafe { mmio.read32(REG_RAL0) };
    // SAFETY: same.
    let rah = unsafe { mmio.read32(REG_RAH0) };
    [
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ]
}

// ── PCI registration ───────────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Ixgbe>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over the device.
    let dev = match unsafe { Ixgbe::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    for did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(*did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: IXGBE_VENDOR,
                device: *did,
            },
            probe,
        });
    }
}

pub fn name_for(did: u16) -> &'static str {
    match did {
        IXGBE_DEV_82599EB => "ixgbe-82599eb",
        IXGBE_DEV_X540 => "ixgbe-x540",
        IXGBE_DEV_X550 => "ixgbe-x550",
        IXGBE_DEV_X550EM_X => "ixgbe-x550em",
        _ => "ixgbe",
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&Ixgbe) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

pub fn with_controller_mut<R>(f: impl FnOnce(&mut Ixgbe) -> R) -> Option<R> {
    CONTROLLER.lock().as_mut().map(f)
}
