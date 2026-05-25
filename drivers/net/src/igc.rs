//! Intel I225 / I226 family — 2.5 GbE — clean-room.
//!
//! Spec: Intel **"Ethernet Controller I225 Datasheet"** rev 1.4
//! (free PDF, intel.com — public release in March 2021) and the
//! follow-on **"Ethernet Controller I226 Datasheet"** rev 1.0
//! (June 2022). Both expose the same Foxville-family register
//! layout the original `e1000` software-developer's manual
//! describes — the I225 datasheet calls out per-block deltas
//! (advanced TX/RX descriptors, EEC vs EERD, 2.5 GbE PCS) but the
//! basic CTRL / STATUS / RAL / RAH / TCTL / RCTL / TDBAL / RDBAL
//! addresses are unchanged.
//!
//! Stage cut: bring up the controller far enough to read the MAC
//! address out of RAL/RAH, program a TX + RX legacy-descriptor
//! ring (the I225 supports the same legacy descriptor format on
//! top of the advanced one — we use legacy for clean-room
//! simplicity), and expose `tx(&[u8])` + `rx(&mut [u8])`. MSI-X +
//! advanced descriptors land in a follow-up.
//!
//! Register map subset (BAR0 + offset, all 4-byte aligned). The
//! offsets that differ from the base `e1000` driver are noted.
//!
//! | offset  | name | description                          |
//! |---------|------|--------------------------------------|
//! | 0x0000  | CTRL | Device Control                       |
//! | 0x0008  | STATUS | Device Status                      |
//! | 0x0010  | EEC  | EEPROM/Flash Control (I225 specific) |
//! | 0x0014  | EERD | EEPROM Read                          |
//! | 0x00D0  | IMS  | Interrupt Mask Set/Read              |
//! | 0x0100  | RCTL | Receive Control                      |
//! | 0x0400  | TCTL | Transmit Control                     |
//! | 0x2800  | RDBAL/H/LEN/H/T as e1000              |
//! | 0x3800  | TDBAL/H/LEN/H/T as e1000              |
//! | 0x5400  | RAL0 | Receive Address Low                  |
//! | 0x5404  | RAH0 | Receive Address High + Address Valid |

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Mirrors Linux's `igc_pci_tbl[]` in
// `drivers/net/ethernet/intel/igc/igc_main.c`. The I225 + I226
// families ship in Comet Lake / Tiger Lake / Alder Lake / Raptor
// Lake laptops as discrete 2.5G NICs and on docks; I220-V and I221-V
// are 1G "Foxville-Lite" variants on the same silicon. Stepping
// variants (LMVP / K / K2) appear on Intel NUC and embedded
// platforms. BLANK_NVM IDs are the boot-time fallback when the NVM
// hasn't been programmed (we still bind so the user can flash).

pub const IGC_VENDOR: u16 = 0x8086;

/// I225-LM (LAN-on-motherboard variant).
pub const IGC_I225_LM: u16 = 0x15F2;
/// I225-V (vPro variant).
pub const IGC_I225_V: u16 = 0x15F3;
/// I225-IT (industrial-temp).
pub const IGC_I225_IT: u16 = 0x0D9F;
/// I225-I (server / iLM).
pub const IGC_I225_I: u16 = 0x15F8;
/// I220-V (1 GbE Foxville-Lite).
pub const IGC_I220_V: u16 = 0x15F7;
/// I225-K — NUC / embedded.
pub const IGC_I225_K: u16 = 0x3100;
/// I225-K2 — NUC stepping.
pub const IGC_I225_K2: u16 = 0x3101;
/// I225-LMVP — vPro stepping.
pub const IGC_I225_LMVP: u16 = 0x5502;
/// I225 blank NVM — boot fallback.
pub const IGC_I225_BLANK_NVM: u16 = 0x15FD;
/// I226-LM (LAN-on-motherboard).
pub const IGC_I226_LM: u16 = 0x125B;
/// I226-V.
pub const IGC_I226_V: u16 = 0x125C;
/// I226-IT.
pub const IGC_I226_IT: u16 = 0x125D;
/// I226-K — NUC / embedded.
pub const IGC_I226_K: u16 = 0x3102;
/// I226-LMVP — vPro stepping.
pub const IGC_I226_LMVP: u16 = 0x5503;
/// I226 blank NVM — boot fallback.
pub const IGC_I226_BLANK_NVM: u16 = 0x125F;
/// I221-V (1 GbE).
pub const IGC_I221_V: u16 = 0x125E;

// ── Register offsets ────────────────────────────────────────────────

const REG_CTRL: u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
const REG_IMS: u64 = 0x00D0;
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

// CTRL bits.
const CTRL_RST: u32 = 1 << 26;
const CTRL_SLU: u32 = 1 << 6;

// TCTL bits.
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;

// RCTL bits.
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15; // Broadcast accept.
const RCTL_BSIZE_2K: u32 = 0; // bits[17:16] = 0 → 2 KiB

// TX descriptor flags.
const TXD_CMD_EOP: u8 = 1 << 0;
const TXD_CMD_IFCS: u8 = 1 << 1;
const TXD_CMD_RS: u8 = 1 << 3;
const TXD_STAT_DD: u8 = 1 << 0;

// Ring sizes — small but valid (must be a multiple of 8 per
// I225 datasheet §7.2.7).
const TX_RING_LEN: usize = 8;
const RX_RING_LEN: usize = 8;
const FRAME_SIZE: usize = 2048;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IgcError {
    BarMapFailed,
    ResetTimeout,
    QueueTooSmall,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct LegacyTxDesc {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    sta: u8,
    css: u8,
    special: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct LegacyRxDesc {
    addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

pub struct Igc {
    mmio: MmioRegion,
    mac: [u8; 6],
    tx_ring_buf: DmaBuffer,
    rx_ring_buf: DmaBuffer,
    rx_buf_pool: alloc::vec::Vec<DmaBuffer>,
    tx_buf: DmaBuffer,
    tx_tail: IrqSafeSpinLock<u16>,
    rx_head: IrqSafeSpinLock<u16>,
    pub ready: bool,
}

impl core::fmt::Debug for Igc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Igc")
            .field("mac", &self.mac)
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl Igc {
    /// Bring up the controller.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, IgcError> {
        // SAFETY: caller-asserted.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| IgcError::BarMapFailed)?;

        // 1. Master reset.
        // SAFETY: identity-mapped MMIO.
        let ctrl = unsafe { mmio.read32(REG_CTRL) };
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_CTRL, ctrl | CTRL_RST);
        }
        // SAFETY: identity-mapped MMIO; responsive_spin_until ticks
        // sleep_pumps so FB cursor / serial drain stay alive on a
        // slow reset. Intel I225 datasheet §8.2.3.1: CTRL.RST self-
        // clears within ~10 ms; 100 ms is the wedge threshold.
        narf_scheduler::responsive_spin_until(
            || unsafe { mmio.read32(REG_CTRL) } & CTRL_RST == 0,
            narf_time::Deadline::after_ms(100),
        );
        // SAFETY: same.
        let after = unsafe { mmio.read32(REG_CTRL) };
        if after & CTRL_RST != 0 {
            return Err(IgcError::ResetTimeout);
        }

        // 2. Clear interrupts + mask everything off (we're polling).
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_IMS, 0);
        }

        // 3. Set link up.
        // SAFETY: same.
        let ctrl = unsafe { mmio.read32(REG_CTRL) };
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_CTRL, ctrl | CTRL_SLU);
        }

        // 4. Read MAC from RAL/RAH.
        // SAFETY: same.
        let ral = unsafe { mmio.read32(REG_RAL0) };
        // SAFETY: same.
        let rah = unsafe { mmio.read32(REG_RAH0) };
        let mac = [
            (ral & 0xFF) as u8,
            ((ral >> 8) & 0xFF) as u8,
            ((ral >> 16) & 0xFF) as u8,
            ((ral >> 24) & 0xFF) as u8,
            (rah & 0xFF) as u8,
            ((rah >> 8) & 0xFF) as u8,
        ];

        // 5. Allocate ring + buffer pools.
        let tx_ring_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IgcError::BarMapFailed)?;
        let rx_ring_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IgcError::BarMapFailed)?;
        let tx_buf =
            alloc_coherent(FRAME_SIZE, DomainId::DRIVER_0).map_err(|_| IgcError::BarMapFailed)?;
        let mut rx_buf_pool: alloc::vec::Vec<DmaBuffer> =
            alloc::vec::Vec::with_capacity(RX_RING_LEN);
        for _ in 0..RX_RING_LEN {
            rx_buf_pool.push(
                alloc_coherent(FRAME_SIZE, DomainId::DRIVER_0)
                    .map_err(|_| IgcError::BarMapFailed)?,
            );
        }

        // 6. Initialise TX descriptors (zeroed by alloc_coherent).
        let tx_phys = tx_ring_buf.phys_addr().raw();
        let tx_len = (TX_RING_LEN * 16) as u32;
        // SAFETY: identity-mapped DMA, freshly zeroed.
        unsafe {
            mmio.write32(REG_TDBAL, (tx_phys & 0xFFFF_FFFF) as u32);
            mmio.write32(REG_TDBAH, (tx_phys >> 32) as u32);
            mmio.write32(REG_TDLEN, tx_len);
            mmio.write32(REG_TDH, 0);
            mmio.write32(REG_TDT, 0);
            mmio.write32(REG_TCTL, TCTL_EN | TCTL_PSP);
        }

        // 7. Initialise RX descriptors with our pre-allocated frames.
        let rx_phys = rx_ring_buf.phys_addr().raw();
        // SAFETY: identity-mapped DMA, freshly zeroed.
        unsafe {
            for i in 0..RX_RING_LEN {
                let desc = (rx_phys + (i * 16) as u64) as *mut LegacyRxDesc;
                core::ptr::write_volatile(
                    desc,
                    LegacyRxDesc {
                        addr: rx_buf_pool[i].phys_addr().raw(),
                        ..Default::default()
                    },
                );
            }
            mmio.write32(REG_RDBAL, (rx_phys & 0xFFFF_FFFF) as u32);
            mmio.write32(REG_RDBAH, (rx_phys >> 32) as u32);
            mmio.write32(REG_RDLEN, (RX_RING_LEN * 16) as u32);
            mmio.write32(REG_RDH, 0);
            mmio.write32(REG_RDT, (RX_RING_LEN - 1) as u32);
            mmio.write32(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2K);
        }

        Ok(Self {
            mmio,
            mac,
            tx_ring_buf,
            rx_ring_buf,
            rx_buf_pool,
            tx_buf,
            tx_tail: IrqSafeSpinLock::new(0),
            rx_head: IrqSafeSpinLock::new(0),
            ready: true,
        })
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub fn link_up(&self) -> bool {
        // SAFETY: identity-mapped MMIO; STATUS bit 1 = LU (link up).
        let s = unsafe { self.mmio.read32(REG_STATUS) };
        s & (1 << 1) != 0
    }

    /// Transmit a single Ethernet frame. Polls the descriptor's
    /// Done bit. Frame must fit in `FRAME_SIZE`.
    pub fn tx(&self, frame: &[u8]) -> Result<(), IgcError> {
        if frame.is_empty() || frame.len() > FRAME_SIZE {
            return Err(IgcError::QueueTooSmall);
        }
        let buf_phys = self.tx_buf.phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((buf_phys + i as u64) as *mut u8, *b);
            }
        }
        let mut tail = self.tx_tail.lock();
        let idx = *tail as usize;
        let ring_phys = self.tx_ring_buf.phys_addr().raw();
        let desc = (ring_phys + (idx * 16) as u64) as *mut LegacyTxDesc;
        // SAFETY: identity-mapped DMA, idx < TX_RING_LEN.
        unsafe {
            core::ptr::write_volatile(
                desc,
                LegacyTxDesc {
                    addr: buf_phys,
                    length: frame.len() as u16,
                    cmd: TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS,
                    ..Default::default()
                },
            );
        }
        let next = ((idx + 1) % TX_RING_LEN) as u16;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_TDT, next as u32);
        }
        // Poll for Done bit. responsive_spin_until ticks sleep_pumps.
        // 250 ms wall-clock budget covers a worst-case Tx-side
        // congestion stall on a single packet.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile((desc as *const u8).add(12)) } & TXD_STAT_DD != 0,
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(IgcError::ResetTimeout);
        }
        *tail = next;
        Ok(())
    }

    /// Receive a single frame; returns the byte count copied into
    /// `out`, or 0 if no frame is currently available.
    pub fn rx(&self, out: &mut [u8]) -> usize {
        let mut head = self.rx_head.lock();
        let idx = *head as usize;
        let ring_phys = self.rx_ring_buf.phys_addr().raw();
        let desc_ptr = (ring_phys + (idx * 16) as u64) as *mut LegacyRxDesc;
        // SAFETY: identity-mapped DMA.
        let desc = unsafe { core::ptr::read_volatile(desc_ptr) };
        // RX status DD bit (bit 0). Vendor docs reuse the e1000
        // convention.
        if desc.status & 0x01 == 0 {
            return 0;
        }
        let len = (desc.length as usize).min(out.len());
        let buf_phys = self.rx_buf_pool[idx].phys_addr().raw();
        // SAFETY: identity-mapped DMA.
        for i in 0..len {
            out[i] = unsafe { core::ptr::read_volatile((buf_phys + i as u64) as *const u8) };
        }
        // Refill descriptor: clear status + length + bump tail.
        let new_desc = LegacyRxDesc {
            addr: buf_phys,
            ..Default::default()
        };
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(desc_ptr, new_desc);
        }
        let next = ((idx + 1) % RX_RING_LEN) as u16;
        *head = next;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            self.mmio.write32(REG_RDT, ((idx) % RX_RING_LEN) as u32);
        }
        len
    }
}

// ── HwNic adapter ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct IgcNic;

impl crate::HwNic for IgcNic {
    fn name(&self) -> &'static str {
        "igc"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac()).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.link_up()).unwrap_or(false)
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::IntelIgb
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        TX_RING_LEN
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Igc>> = IrqSafeSpinLock::new(None);

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
    // SAFETY: caller-authority.
    let dev = match unsafe { Igc::bring_up(&device, &cap) } {
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

/// Every Intel device id this driver claims. Kept as a single
/// `const` so the `register_pci_driver` loop and the match-table
/// smoke test see the same list (no drift between code + test).
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    IGC_I225_LM,
    IGC_I225_V,
    IGC_I225_IT,
    IGC_I225_I,
    IGC_I220_V,
    IGC_I225_K,
    IGC_I225_K2,
    IGC_I225_LMVP,
    IGC_I225_BLANK_NVM,
    IGC_I226_LM,
    IGC_I226_V,
    IGC_I226_IT,
    IGC_I226_K,
    IGC_I226_LMVP,
    IGC_I226_BLANK_NVM,
    IGC_I221_V,
];

pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: IGC_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        IGC_I225_LM => "igc-i225-lm",
        IGC_I225_V => "igc-i225-v",
        IGC_I225_IT => "igc-i225-it",
        IGC_I225_I => "igc-i225-i",
        IGC_I220_V => "igc-i220-v",
        IGC_I225_K => "igc-i225-k",
        IGC_I225_K2 => "igc-i225-k2",
        IGC_I225_LMVP => "igc-i225-lmvp",
        IGC_I225_BLANK_NVM => "igc-i225-blank-nvm",
        IGC_I226_LM => "igc-i226-lm",
        IGC_I226_V => "igc-i226-v",
        IGC_I226_IT => "igc-i226-it",
        IGC_I226_K => "igc-i226-k",
        IGC_I226_LMVP => "igc-i226-lmvp",
        IGC_I226_BLANK_NVM => "igc-i226-blank-nvm",
        IGC_I221_V => "igc-i221-v",
        _ => "igc",
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&Igc) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
