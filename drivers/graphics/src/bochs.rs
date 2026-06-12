//! bochs-display driver (`-device bochs-display` on QEMU q35).
//!
//! PCI vendor 0x1234, device 0x1111. Two BARs:
//!   * BAR0 — linear framebuffer (≥ 16 MiB).
//!   * BAR2 — MMIO registers; the Bochs VBE Dispi block lives at
//!     offset 0x500 inside it.
//!
//! VBE Dispi register offsets (relative to BAR2 base + 0x500):
//!   ```
//!   +0x00  ID       — read 0xB0C0..=0xB0C5 to identify
//!   +0x02  XRES
//!   +0x04  YRES
//!   +0x06  BPP
//!   +0x08  ENABLE   — bit 0: enabled, bit 6: LFB
//!   +0x0C  VIRT_WIDTH
//!   +0x0E  VIRT_HEIGHT
//!   +0x10  X_OFFSET
//!   +0x12  Y_OFFSET
//!   ```
//!
//! Init: disable, set XRES/YRES/BPP, set virt size to match, then
//! enable with LFB. After that BAR0 is a writable XRGB8888 framebuffer.

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_graphics::Framebuffer;
use narf_lib::sync::IrqSafeSpinLock;

pub const BOCHS_PCI_VENDOR: u16 = 0x1234;
pub const BOCHS_PCI_DEVICE: u16 = 0x1111;

const VBE_BASE: u64 = 0x500;
const VBE_ID: u64 = VBE_BASE;
const VBE_XRES: u64 = VBE_BASE + 0x02;
const VBE_YRES: u64 = VBE_BASE + 0x04;
const VBE_BPP: u64 = VBE_BASE + 0x06;
const VBE_ENABLE: u64 = VBE_BASE + 0x08;
const VBE_VIRT_WIDTH: u64 = VBE_BASE + 0x0C;
const VBE_VIRT_HEIGHT: u64 = VBE_BASE + 0x0E;

const VBE_ENABLE_BIT: u32 = 0x01;
const VBE_LFB_BIT: u32 = 0x40;

/// Default mode requested at probe time. 1024×768×32 fits comfortably
/// in the 16 MiB BAR0 (3 MB used) and is QEMU's bochs default.
pub const DEFAULT_WIDTH: u32 = 1024;
pub const DEFAULT_HEIGHT: u32 = 768;
pub const DEFAULT_BPP: u16 = 32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BochsError {
    BarMapFailed,
    BadId,
}

#[doc(hidden)]
pub struct BochsDisplay {
    pub width: u32,
    pub height: u32,
    /// Phys + len of BAR0 (the linear framebuffer).
    fb_region: MmioRegion,
    /// MMIO regs (BAR2). Held so its identity mapping isn't reclaimed.
    _mmio: MmioRegion,
}

impl BochsDisplay {
    /// True when BAR0 falls inside the boot PML4's low-4-GiB identity
    /// map. Above 4 GiB, the framebuffer pointer would not resolve and
    /// callers should defer drawing until an ioremap surface lands.
    pub fn fb_reachable(&self) -> bool {
        self.fb_region.phys.raw().saturating_add(self.fb_region.len) <= 0x1_0000_0000
    }
    pub fn fb_phys(&self) -> u64 {
        self.fb_region.phys.raw()
    }
}

impl core::fmt::Debug for BochsDisplay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BochsDisplay")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("fb_phys", &self.fb_region.phys)
            .finish_non_exhaustive()
    }
}

impl BochsDisplay {
    /// # Safety
    /// Caller owns the device exclusively. Identity map covers BAR0
    /// + BAR2 (Stage-1 boot PML4 covers the low 4 GiB).
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, BochsError> {
        // SAFETY: caller-owned.
        let fb_region = unsafe { map_bar(device, 0) }.map_err(|_| BochsError::BarMapFailed)?;
        // SAFETY: caller-owned.
        let mmio = unsafe { map_bar(device, 2) }.map_err(|_| BochsError::BarMapFailed)?;

        // Sanity check the VBE ID — the chip identifies itself in the
        // 0xB0C0..=0xB0C5 range.
        // SAFETY: BAR2 mapped, in-range, 16-bit register.
        let id = unsafe { mmio.read16(VBE_ID) } as u32;
        if !(0xB0C0..=0xB0C5).contains(&id) {
            return Err(BochsError::BadId);
        }

        // Read the current BGA state. On UEFI boot, edk2's GOP has
        // already configured the chip to whatever mode it picked
        // (frequently NOT 1024×768), and the bootloader handed us
        // an FB pointer + pitch that matches *that* mode. The
        // beacon registry + Limine framebuffer info are pinned to
        // those dimensions; if we then overwrite BGA with our own
        // defaults, the hardware switches resolution but every
        // higher-level consumer keeps using the pre-overwrite
        // stride → diagonal-shear text rendering, broken scrolling,
        // wrong fault-handler beacon positions. Honor the firmware
        // mode if it looks plausible.
        //
        // SAFETY: BAR2 mapped, valid offsets, exclusive owner.
        let (xres, yres, bpp) = unsafe {
            let enabled = mmio.read16(VBE_ENABLE) as u32;
            // VBE_ENABLE_BIT set = firmware already programmed a mode.
            // Treat as authoritative if dims look sane (non-zero, ≤4K).
            if enabled & VBE_ENABLE_BIT != 0 {
                let x = mmio.read16(VBE_XRES) as u32;
                let y = mmio.read16(VBE_YRES) as u32;
                let b = mmio.read16(VBE_BPP) as u16;
                if (1..=4096).contains(&x)
                    && (1..=4096).contains(&y)
                    && (b == 16 || b == 24 || b == 32)
                {
                    (x, y, b)
                } else {
                    (DEFAULT_WIDTH, DEFAULT_HEIGHT, DEFAULT_BPP)
                }
            } else {
                (DEFAULT_WIDTH, DEFAULT_HEIGHT, DEFAULT_BPP)
            }
        };

        // Only reprogram if the firmware didn't already configure a
        // sensible mode. Avoids disturbing UEFI's GOP setup.
        if (xres, yres, bpp) == (DEFAULT_WIDTH, DEFAULT_HEIGHT, DEFAULT_BPP) {
            // SAFETY: BAR2 mapped, valid offsets, exclusive owner.
            unsafe {
                let enabled = mmio.read16(VBE_ENABLE) as u32;
                if enabled & VBE_ENABLE_BIT == 0 {
                    mmio.write16(VBE_ENABLE, 0);
                    mmio.write16(VBE_XRES, DEFAULT_WIDTH as u16);
                    mmio.write16(VBE_YRES, DEFAULT_HEIGHT as u16);
                    mmio.write16(VBE_BPP, DEFAULT_BPP);
                    mmio.write16(VBE_VIRT_WIDTH, DEFAULT_WIDTH as u16);
                    mmio.write16(VBE_VIRT_HEIGHT, DEFAULT_HEIGHT as u16);
                    mmio.write16(VBE_ENABLE, (VBE_ENABLE_BIT | VBE_LFB_BIT) as u16);
                }
            }
        }

        Ok(Self {
            width: xres,
            height: yres,
            fb_region,
            _mmio: mmio,
        })
    }

    /// Borrow a `Framebuffer` view over BAR0. Caller must serialise
    /// access — there's only one scanout buffer.
    ///
    /// # Safety
    /// Caller must ensure no concurrent draw is in flight; framebuffer
    /// writes go directly through MMIO without a lock.
    pub unsafe fn framebuffer(&self) -> Framebuffer {
        // SAFETY: BAR0's phys is identity-mapped; size covers
        // width*height*4 bytes by mode-setting math (1024*768*4=3MB,
        // bochs BAR0 is at least 16 MiB).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            Framebuffer::new(
                self.fb_region.phys.raw() as *mut u32,
                self.width,
                self.height,
                self.width, // stride = width for bochs (linear, no padding)
            )
        }
    }
}

static CONTROLLER: IrqSafeSpinLock<Option<BochsDisplay>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let dev = match unsafe { BochsDisplay::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("bochs0"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(BOCHS_PCI_VENDOR),
        pci_did: Some(BOCHS_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "bochs-display",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: BOCHS_PCI_VENDOR,
            device: BOCHS_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&BochsDisplay) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

extern crate alloc;
