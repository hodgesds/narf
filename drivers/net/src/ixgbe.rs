//! Intel ixgbe — 82599 / X540 / X550 10 GbE controller driver.
//!
//! Spec: `drivers/net/specification/ixgbe.md`. Clean-room: register
//! layout sourced from the public Intel 82599 / X540 / X550
//! datasheets. No GPL Linux source consulted.

use core::sync::atomic::{compiler_fence, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, TxMeta, RX_RING_N, TX_RING_N};

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

// TX context / TSO descriptor bits.
// Source: Linux ixgbe_type.h §7.2.3.2.2 / ixgbe_main.c.
pub(crate) const ADVTXD_DTYP_CTXT: u32 = 0x2 << 20;
pub(crate) const ADVTXD_DCMD_TSE: u32 = 1 << 31;
pub(crate) const ADVTXD_POPTS_IXSM: u32 = 0x0100;
pub(crate) const ADVTXD_POPTS_TXSM: u32 = 0x0200;
pub(crate) const ADVTXD_PAYLEN_SHIFT: u32 = 14;
pub(crate) const ADVTXD_TUCMD_IPV4: u32 = 0x400;
pub(crate) const ADVTXD_TUCMD_L4T_TCP: u32 = 0x800;
#[allow(dead_code)]
pub(crate) const ADVTXD_TUCMD_L4T_UDP: u32 = 0x000;
pub(crate) const ADVTXD_L4LEN_SHIFT: u32 = 8;
pub(crate) const ADVTXD_MSS_SHIFT: u32 = 16;
pub(crate) const ADVTXD_MACLEN_SHIFT: u32 = 9;

/// RX checksum verification result decoded from a legacy ixgbe RxDesc.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    /// Hardware did not compute a checksum for this frame.
    None,
    /// Hardware computed and verified the checksum — no errors.
    Ok,
    /// Hardware detected a checksum error.
    Fail,
}

/// Advanced TX context descriptor — precedes the data descriptor for
/// TSO and carries MSS / L4-len / TUCMD fields. Per ixgbe §7.2.3.2.2.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvTxCtxtDesc {
    pub vlan_macip_lens: u32,
    pub seqnum_seed: u32,
    pub type_tucmd_mlhl: u32,
    pub mss_l4len_idx: u32,
}

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

// ── Descriptor offload helpers ───────────────────────────────────────

impl AdvTxDesc {
    /// Build a TX descriptor with IP + TCP/UDP checksum offload.
    /// POPTS bits are set in `olinfo`; PAYLEN is also loaded there.
    pub fn with_csum(addr: u64, len: u16) -> Self {
        AdvTxDesc {
            addr,
            cmd_type_len: Self::ctrl_word(len),
            olinfo: ((len as u32) << ADVTXD_PAYLEN_SHIFT) | ADVTXD_POPTS_IXSM | ADVTXD_POPTS_TXSM,
        }
    }

    /// Build a TX data descriptor for TSO. The DCMD_TSE bit is added to
    /// `cmd_type_len`; the context descriptor carries the MSS and L4len.
    pub fn with_tso(addr: u64, len: u16, _mss: u16) -> Self {
        AdvTxDesc {
            addr,
            cmd_type_len: Self::ctrl_word(len) | ADVTXD_DCMD_TSE,
            olinfo: ((len as u32) << ADVTXD_PAYLEN_SHIFT) | ADVTXD_POPTS_IXSM | ADVTXD_POPTS_TXSM,
        }
    }
}

impl AdvTxCtxtDesc {
    /// Build a TSO context descriptor for an IPv4/TCP frame.
    /// `mac_len` = Ethernet header length (usually 14).
    /// `ip_len`  = IP header length in bytes (usually 20).
    /// `l4_len`  = TCP header length in bytes (usually 20).
    /// `mss`     = maximum segment size in bytes.
    pub fn new_tso_v4(mac_len: u8, ip_len: u8, l4_len: u8, mss: u16) -> Self {
        let vlan_macip_lens = (ip_len as u32) | ((mac_len as u32) << ADVTXD_MACLEN_SHIFT);
        let type_tucmd_mlhl =
            ADVTXD_DCMD_DEXT | ADVTXD_DTYP_CTXT | ADVTXD_TUCMD_IPV4 | ADVTXD_TUCMD_L4T_TCP;
        let mss_l4len_idx =
            ((l4_len as u32) << ADVTXD_L4LEN_SHIFT) | ((mss as u32) << ADVTXD_MSS_SHIFT);
        AdvTxCtxtDesc {
            vlan_macip_lens,
            seqnum_seed: 0,
            type_tucmd_mlhl,
            mss_l4len_idx,
        }
    }
}

impl RxDesc {
    /// Decode the RX checksum result from the legacy ixgbe RxDesc.
    /// The `csum` field is non-zero when hardware computed a checksum;
    /// `errors` being 0 means the check passed.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    pub fn csum_result(&self) -> RxCsumResult {
        if self.csum == 0 {
            RxCsumResult::None
        } else if self.errors == 0 {
            RxCsumResult::Ok
        } else {
            RxCsumResult::Fail
        }
    }
}

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
    /// Catch-all.
    Other(&'static str),
}

// ── Driver state ───────────────────────────────────────────────────

pub struct Ixgbe {
    pub(crate) mmio: MmioRegion,
    pub(crate) tx_ring: DmaBuffer,
    /// Persistent per-slot TX frame buffers (audit #4 — pre-fix
    /// `tx()` did `alloc_coherent(4096)` per frame and dropped it
    /// on return). Indexed by descriptor slot.
    pub(crate) tx_pool: Vec<DmaBuffer>,
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
    pub rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
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
    ) -> Result<Arc<Self>, IxgbeError> {
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
        // responsive_spin_until ticks sleep_pumps so cursor / serial
        // / audio drain stay alive on a slow reset. ixgbe datasheet
        // §4.6.3.1: CTRL.RST self-clears within 1 ms typical; 100 ms
        // is the wedge threshold.
        let cleared = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(REG_CTRL) } & CTRL_RST_MASK == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !cleared {
            return Err(IxgbeError::ResetTimeout);
        }
        // Datasheet §4.6.3.2 — wait ~10 ms for FW handshake.
        // TSC-based busy_wait gives real wall-clock time vs the
        // 200_000 spin_loop estimate that varied with CPU clock.
        let tsc_hz = narf_time::calibrate_clocks();
        if tsc_hz > 0 {
            narf_time::busy_wait_cycles((tsc_hz / 1000) * 10);
        } else {
            for _ in 0..1_000_000 {
                core::hint::spin_loop();
            }
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

        // 6. Set up the TX ring (queue 0) + persistent per-slot
        //    frame buffers (audit #4).
        let tx_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
        let tx_phys = tx_ring.dma_addr().raw();
        let mut tx_pool: Vec<DmaBuffer> = Vec::with_capacity(TX_RING_LEN);
        for _ in 0..TX_RING_LEN {
            tx_pool
                .push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?);
        }
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..(TX_RING_LEN * 16) {
                core::ptr::write_volatile(tx_ring.cpu_mut_ptr_at::<u8>(i as u64), 0);
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
        // responsive_spin_until ticks sleep_pumps; failure is
        // non-fatal here (queue may come up later), matching prior
        // behaviour. 100 ms wall-clock budget.
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(TX_TXDCTL) } & TXDCTL_ENABLE != 0,
            narf_time::Deadline::after_ms(100),
        );

        // 7. RX ring + pool.
        let rx_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
        let rx_ring_phys = rx_ring.dma_addr().raw();
        let mut rx_pool = Vec::with_capacity(RX_RING_LEN);
        for i in 0..RX_RING_LEN {
            let buf = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
            let bp = buf.dma_addr().raw();
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
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(rx_ring_phys + (i * 16) as u64)
                        .kernel_mut_ptr::<RxDesc>(),
                    desc,
                );
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

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let ixgbe = Arc::new(Self {
            mmio,
            tx_ring,
            tx_pool,
            rx_ring,
            rx_pool,
            tx_tail: IrqSafeSpinLock::new(0),
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            link_up,
            did: device.id.device,
            msix: None,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn pumps
        spawn_pumps(ixgbe.clone(), rx_prod, tx_cons);

        Ok(ixgbe)
    }

    /// Read the EERD-decoded MAC bytes (Stage 2 surface).
    pub fn read_mac_eeprom(&self) -> Result<[u8; 6], IxgbeError> {
        read_mac(&self.mmio)
    }

    /// Transmit a single frame, polling the descriptor's DD bit.
    pub fn tx(&self, frame: &[u8], meta: &TxMeta) -> Result<(), IxgbeError> {
        if frame.is_empty() || frame.len() > 1518 {
            return Err(IxgbeError::FrameTooLong);
        }
        // Persistent per-slot buffer (audit #4).
        let mut tail_g = self.tx_tail.lock();
        let slot = (*tail_g) as usize % TX_RING_LEN;
        let phys = self.tx_pool[slot].dma_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked above.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile(self.tx_pool[slot].cpu_mut_ptr_at::<u8>(i as u64), *b);
            }
        }
        let ring_phys = self.tx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        let desc = if let Some(mss) = meta.tso_mss {
            AdvTxDesc::with_tso(phys, frame.len() as u16, mss)
        } else if meta.csum_l4.is_some() {
            AdvTxDesc::with_csum(phys, frame.len() as u16)
        } else {
            AdvTxDesc {
                addr: phys,
                cmd_type_len: AdvTxDesc::ctrl_word(frame.len() as u16),
                // PAYLEN field at bits [31:14] of olinfo (§7.2.3.2.4).
                olinfo: (frame.len() as u32) << 14,
            }
        };
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<AdvTxDesc>(),
                desc,
            );
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
        // Advanced write-back lays status at olinfo[3:0]
        // (§7.2.3.2.4 write-back layout). 250 ms wall-clock budget
        // covers a worst-case Tx-side congestion stall.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 12).kernel_ptr::<u32>()) } & ADVTXD_STAT_DD != 0,
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(IxgbeError::TxTimeout);
        }
        // (no scratch drop — buffer is persistent in tx_pool)
        Ok(())
    }

    /// Drain one RX frame into `out`. Returns 0 if nothing pending.
    pub fn rx_recv(&self, out: &mut [u8]) -> usize {
        let mut head_g = self.rx_head.lock();
        let head = (*head_g) as usize;
        let ring_phys = self.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let desc = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<RxDesc>())
        };
        if desc.status & RXD_STAT_DD == 0 {
            return 0;
        }
        let len = (desc.length as usize).min(out.len()).min(RX_BUF_LEN);
        let buf_phys = desc.addr;
        for (i, b) in out[..len].iter_mut().enumerate() {
            // SAFETY: identity-mapped DMA buffer; `buf_phys` is the
            // descriptor-published frame address and `i < len <= RX_BUF_LEN`,
            // so the byte read stays within the device-owned buffer.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *b = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(buf_phys + i as u64).kernel_ptr::<u8>(),
                )
            };
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
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<RxDesc>(),
                new_desc,
            );
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
        let ring_phys = self.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 12).kernel_ptr::<u8>())
        };
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
        let table = enable_msix(cap, device).map_err(|_| IxgbeError::MsixUnavailable)?;
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

impl narf_net::Interface for Ixgbe {
    fn name(&self) -> &str {
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
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ipc_ring
    }
}

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
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ipc_ring
    }
}

// ── IxgbeNic: lightweight ZST for narf-net registry ───────────────
//
// The full `Ixgbe` struct owns MMIO + DMA rings and can't be cloned.
// `IxgbeNic` is a zero-sized sentinel that delegates to the module-level
// `CONTROLLER` static, following the same pattern as `Rtl8139Nic`.

#[derive(Debug)]
pub struct IxgbeNic;

impl narf_net::Interface for IxgbeNic {
    fn name(&self) -> &str {
        with_controller(|c| name_for(c.did)).unwrap_or("ixgbe")
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

// ── EEPROM helpers ─────────────────────────────────────────────────

fn eeprom_read_word(mmio: &MmioRegion, addr: u16) -> Result<u16, IxgbeError> {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        mmio.write32(REG_EERD, eerd_start(addr));
    }
    // EEPROM read is short (microseconds typically) but the
    // helper still ticks sleep_pumps in case of a wedged chip
    // or hot-plug-during-init pathology. 50 ms wall-clock wedge
    // threshold.
    let mut last = 0u32;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            last = unsafe { mmio.read32(REG_EERD) };
            last & EERD_DONE != 0
        },
        narf_time::Deadline::after_ms(50),
    );
    if done {
        Ok(eeprom_decode(last))
    } else {
        Err(IxgbeError::EepromTimeout)
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

static CONTROLLER: IrqSafeSpinLock<Option<Arc<Ixgbe>>> = IrqSafeSpinLock::new(None);

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

    let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

    // SAFETY: `bring_up` requires exclusive ownership of the device's
    // BAR0 for init; we hold the bus `Cap<BusDeviceCap, Write>` and the
    // `CONTROLLER` guard above guarantees no other probe is racing this
    // device, so BAR0 is owned exclusively here.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev = match unsafe { Ixgbe::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    {
        // SAFETY: `dev` was just created by `bring_up` and has not been
        // published yet (it is stored into `CONTROLLER` only below), so
        // this is the only `Arc` reference; no other thread can observe
        // the `Ixgbe`, making this exclusive `&mut` to its interior sound.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let d = unsafe { &mut *(Arc::as_ptr(&dev) as *mut Ixgbe) };
        *d.rx_ipc_ring.lock() = Some(rx_cons);
        *d.tx_ipc_ring.lock() = Some(tx_prod);
    }

    *CONTROLLER.lock() = Some(dev.clone());

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, IxgbeNic);
    }

    // Spawn pumps
    spawn_pumps(dev, rx_prod, tx_cons);

    Ok(())
}

fn spawn_pumps(
    device: Arc<Ixgbe>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        ixgbe_rx_pump(d1, rx_prod).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        ixgbe_tx_pump(d2, tx_cons).await;
    });
}

async fn ixgbe_rx_pump(device: Arc<Ixgbe>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    let mut buf = [0u8; 2048];
    loop {
        let n = device.rx_recv(&mut buf);
        if n > 0 {
            let dma_buf = alloc_coherent(n, DomainId::DRIVER_0).expect("Frame alloc failed");
            let mut frame = Frame::new(dma_buf, n as u32);
            frame.payload_mut().copy_from_slice(&buf[..n]);
            let _ = rx_prod.send(frame).await;
        }
        narf_scheduler::yield_now().await;
    }
}

async fn ixgbe_tx_pump(device: Arc<Ixgbe>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.tx(frame.payload(), &TxMeta::plain());
    }
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
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

pub fn with_controller_mut<R>(f: impl FnOnce(&mut Ixgbe) -> R) -> Option<R> {
    CONTROLLER
        .lock()
        .as_mut()
        .map(|a| f(Arc::get_mut(a).expect("Ixgbe static has multiple owners")))
}
