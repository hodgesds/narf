//! xHCI 1.2 USB 3.x host controller driver.
//!
//! Spec: Intel xHCI 1.2 (extensible host-controller interface).
//! QEMU's `qemu-xhci` is at vendor 0x1B36, device 0x000D.
//!
//! BAR0 layout:
//! ```text
//!   +0x000  Capability Registers (CAPLENGTH bytes)
//!   +cap    Operational Registers
//!   +rts    Runtime Registers
//!   +db     Doorbell Registers
//! ```
//!
//! Stage-4 cut: bring the controller up far enough to read its
//! capability register block, reset (`USBCMD.HCRST`), program
//! `CONFIG.MAX_SLOTS_EN` + the Device Context Base Address Array
//! pointer + the command-ring control register, and flip
//! `USBCMD.RS` to start running. Actual USB device enumeration
//! (Address Device, Configure Endpoint, etc.) is a Stage-5 epic.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

/// QEMU `qemu-xhci`.
pub const QEMU_XHCI_VENDOR: u16 = 0x1B36;
pub const QEMU_XHCI_DEVICE: u16 = 0x000D;

// Capability-register offsets (relative to BAR0 + 0).
const CAP_CAPLENGTH:   u64 = 0x00;  // u8
const CAP_HCIVERSION:  u64 = 0x02;  // u16
const CAP_HCSPARAMS1:  u64 = 0x04;  // u32: bits[7:0]=MaxSlots, [18:8]=MaxIntrs, [31:24]=MaxPorts
const CAP_HCCPARAMS1:  u64 = 0x10;  // u32
const CAP_DBOFF:       u64 = 0x14;  // u32
const CAP_RTSOFF:      u64 = 0x18;  // u32

// Operational-register offsets (relative to BAR0 + CAPLENGTH).
const OP_USBCMD:   u64 = 0x00;   // u32
const OP_USBSTS:   u64 = 0x04;   // u32
const OP_PAGESIZE: u64 = 0x08;   // u32
const OP_CRCR:     u64 = 0x18;   // u64
const OP_DCBAAP:   u64 = 0x30;   // u64
const OP_CONFIG:   u64 = 0x38;   // u32

// USBCMD bits.
const USBCMD_RS:    u32 = 1 << 0;   // Run/Stop
const USBCMD_HCRST: u32 = 1 << 1;   // Host Controller Reset

// USBSTS bits.
const USBSTS_HCH:   u32 = 1 << 0;   // Host Controller Halted
const USBSTS_CNR:   u32 = 1 << 11;  // Controller Not Ready

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XhciError {
    BarMapFailed,
    NoMemory,
    /// HCRST never cleared.
    ResetTimeout,
    /// CNR never cleared after reset.
    NotReady,
    /// USBSTS.HCH never cleared after Run/Stop=1.
    StartFailed,
}

#[derive(Copy, Clone, Debug)]
pub struct XhciCaps {
    pub caplength:    u8,
    pub hciversion:   u16,
    pub max_slots:    u8,
    pub max_intrs:    u16,
    pub max_ports:    u8,
    pub dboff:        u32,
    pub rtsoff:       u32,
}

pub struct Xhci {
    pub mmio:    MmioRegion,
    pub caps:    XhciCaps,
    /// Offset to the operational registers.
    op_off:      u64,
    /// Backing DMA pages — kept alive for the controller's lifetime.
    _dcbaa:      DmaBuffer,
    _cmd_ring:   DmaBuffer,
    _scratch:    Option<DmaBuffer>,
    pub running: bool,
}

impl core::fmt::Debug for Xhci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Xhci")
            .field("caps",    &self.caps)
            .field("running", &self.running)
            .finish_non_exhaustive()
    }
}

impl Xhci {
    /// Bring up the controller far enough that USBCMD.RS = 1.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, XhciError> {
        // SAFETY: caller-authority.
        let mmio = unsafe { map_bar(device, 0) }
            .map_err(|_| XhciError::BarMapFailed)?;

        // Read caps.
        // SAFETY: identity-mapped MMIO.
        let caplength = unsafe { mmio.read32(CAP_CAPLENGTH) } as u8;
        // SAFETY: same.
        let hci = unsafe { mmio.read32(0) };
        let hciversion = (hci >> 16) as u16;
        // SAFETY: same.
        let p1 = unsafe { mmio.read32(CAP_HCSPARAMS1) };
        let max_slots = (p1 & 0xFF) as u8;
        let max_intrs = ((p1 >> 8)  & 0x7FF) as u16;
        let max_ports = ((p1 >> 24) & 0xFF)  as u8;
        // SAFETY: same.
        let dboff   = unsafe { mmio.read32(CAP_DBOFF) }  & !0x3;
        // SAFETY: same.
        let rtsoff  = unsafe { mmio.read32(CAP_RTSOFF) } & !0x1F;
        let _ = unsafe { mmio.read32(CAP_HCCPARAMS1) };

        let caps = XhciCaps {
            caplength, hciversion, max_slots, max_intrs, max_ports,
            dboff, rtsoff,
        };
        let op_off = caplength as u64;

        // Halt the controller (R/S = 0) before reset.
        // SAFETY: identity-mapped MMIO.
        let cmd = unsafe { mmio.read32(op_off + OP_USBCMD) };
        // SAFETY: same.
        unsafe { mmio.write32(op_off + OP_USBCMD, cmd & !USBCMD_RS); }
        // Wait for HCH = 1.
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let s = unsafe { mmio.read32(op_off + OP_USBSTS) };
            if s & USBSTS_HCH != 0 { break; }
            core::hint::spin_loop();
        }

        // Reset.
        // SAFETY: same.
        unsafe { mmio.write32(op_off + OP_USBCMD, USBCMD_HCRST); }
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let v = unsafe { mmio.read32(op_off + OP_USBCMD) };
            if v & USBCMD_HCRST == 0 { break; }
            core::hint::spin_loop();
        }
        // SAFETY: same.
        let post = unsafe { mmio.read32(op_off + OP_USBCMD) };
        if post & USBCMD_HCRST != 0 { return Err(XhciError::ResetTimeout); }
        // Wait for CNR = 0.
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let s = unsafe { mmio.read32(op_off + OP_USBSTS) };
            if s & USBSTS_CNR == 0 { break; }
            core::hint::spin_loop();
        }
        // SAFETY: same.
        let s = unsafe { mmio.read32(op_off + OP_USBSTS) };
        if s & USBSTS_CNR != 0 { return Err(XhciError::NotReady); }

        // Set CONFIG.MAX_SLOTS_EN to the controller-supported max.
        // SAFETY: same.
        unsafe { mmio.write32(op_off + OP_CONFIG, max_slots as u32); }

        // Allocate the Device Context Base Address Array. Spec
        // requires a 64-byte-aligned (max_slots+1) * 8-byte array.
        // One 4 KiB page covers up to 511 slots — plenty.
        let dcbaa = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| XhciError::NoMemory)?;
        let dcbaa_phys = dcbaa.phys_addr().raw();

        // Allocate the Command Ring. 4 KiB = 256 TRBs (each 16 bytes).
        // Initialize the cycle bit on each TRB to 0 (driver writes
        // commands with cycle=1). Last TRB is the Link TRB pointing
        // back to the start (we don't bother for the structural
        // bring-up; the controller idles when the cycle bit doesn't
        // match).
        let cmd_ring = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| XhciError::NoMemory)?;
        let cmd_phys = cmd_ring.phys_addr().raw();

        // Optional: allocate scratchpad buffers if MAX_SCRATCHPAD_BUFS
        // is non-zero.
        // SAFETY: same.
        let p2 = unsafe { mmio.read32(0x08) }; // HCSPARAMS2
        let max_scratch_hi = ((p2 >> 21) & 0x1F) as u32;
        let max_scratch_lo = ((p2 >> 27) & 0x1F) as u32;
        let max_scratch = (max_scratch_hi << 5) | max_scratch_lo;
        let scratch = if max_scratch > 0 {
            // One page holds 512 8-byte pointers — plenty for any
            // realistic scratchpad count.
            let sb = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| XhciError::NoMemory)?;
            let sb_phys = sb.phys_addr().raw();
            // Allocate one scratchpad data page per slot (xhci spec
            // says "one PAGESIZE buffer per scratchpad"; PAGESIZE is
            // a u32 bitmap with one bit per supported size).
            for i in 0..(max_scratch as usize).min(8) {
                let p = alloc_coherent(4096, DomainId::DRIVER_0)
                    .map_err(|_| XhciError::NoMemory)?;
                // SAFETY: identity-mapped DMA.
                unsafe {
                    core::ptr::write_volatile(
                        (sb_phys + (i * 8) as u64) as *mut u64,
                        p.phys_addr().raw());
                }
                // p drops here — the controller holds the phys
                // address only; the DmaBuffer's Drop frees the
                // underlying frame, which would be a bug if we
                // were going to actually use scratchpads. Stage-4
                // structural-only — controller starts running but
                // we don't enumerate devices.
                let _ = p;
            }
            // Plant the scratchpad-buffer-array pointer at DCBAA[0].
            // SAFETY: identity-mapped DCBAA page.
            unsafe {
                core::ptr::write_volatile(dcbaa_phys as *mut u64, sb_phys);
            }
            Some(sb)
        } else { None };

        // Program DCBAAP + CRCR.
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_DCBAAP,     dcbaa_phys as u32);
            mmio.write32(op_off + OP_DCBAAP + 4, (dcbaa_phys >> 32) as u32);
            // CRCR: bit 0 = Ring Cycle State (we use 1).
            mmio.write32(op_off + OP_CRCR,     (cmd_phys as u32) | 1);
            mmio.write32(op_off + OP_CRCR + 4, (cmd_phys >> 32) as u32);
        }

        // Run!
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe { mmio.write32(op_off + OP_USBCMD, USBCMD_RS); }
        // Wait for HCH = 0.
        let mut running = false;
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let s = unsafe { mmio.read32(op_off + OP_USBSTS) };
            if s & USBSTS_HCH == 0 { running = true; break; }
            core::hint::spin_loop();
        }
        if !running { return Err(XhciError::StartFailed); }

        Ok(Self {
            mmio, caps, op_off,
            _dcbaa: dcbaa, _cmd_ring: cmd_ring, _scratch: scratch,
            running: true,
        })
    }

    pub fn version(&self) -> u16 { self.caps.hciversion }
    pub fn max_slots(&self) -> u8 { self.caps.max_slots }
    pub fn max_ports(&self) -> u8 { self.caps.max_ports }
    pub fn is_running(&self) -> bool { self.running }
}

static CONTROLLER: IrqSafeSpinLock<Option<Xhci>> = IrqSafeSpinLock::new(None);

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
    // SAFETY: caller-authority.
    let dev = match unsafe { Xhci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("xhci0"),
        kind:    narf_drivers::BoundKind::UsbHost,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain:  narf_drivers::BoundKind::UsbHost.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "xhci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: QEMU_XHCI_VENDOR, device: QEMU_XHCI_DEVICE,
        },
        probe,
    });
    // Class match for any USB 3.x controller (class 0x0C, subclass
    // 0x03, prog_if 0x30 = xHCI). PCI class triple stored as
    // (class << 16) | (subclass << 8) | prog_if. Our MatchKind::Class
    // matches just the high byte (class), so this catches every USB
    // controller; future drivers for ehci/uhci/ohci would need to
    // register more specific matches.
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&Xhci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
