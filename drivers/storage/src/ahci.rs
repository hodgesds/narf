//! AHCI HBA driver (Intel ICH9 + compatible).
//!
//! Spec: AHCI base 1.3.1. QEMU's q35 AHCI controller is at
//! `8086:2922` (00:1f.2 by default); ICH9 family.
//!
//! HBA register layout (BAR5 = ABAR, MMIO):
//!
//! | offset  | name | description                       |
//! |---------|------|-----------------------------------|
//! | 0x00    | CAP  | HBA Capabilities                  |
//! | 0x04    | GHC  | Global Host Control               |
//! | 0x08    | IS   | Interrupt Status                  |
//! | 0x0C    | PI   | Ports Implemented (bitmap)        |
//! | 0x10    | VS   | AHCI Version                      |
//! | 0x100   | port[0]                                |
//! | 0x180   | port[1]                                |
//! | 0x200   | port[2]                                |
//! | ...                                              |
//!
//! Per-port (offset = 0x100 + 0x80 * n):
//!
//! | offset  | name  | description                     |
//! |---------|-------|---------------------------------|
//! | +0x00   | CLB   | Command List Base Low           |
//! | +0x04   | CLBU  | Command List Base High          |
//! | +0x08   | FB    | FIS Base Low                    |
//! | +0x0C   | FBU   | FIS Base High                   |
//! | +0x10   | IS    | Interrupt Status                |
//! | +0x14   | IE    | Interrupt Enable                |
//! | +0x18   | CMD   | Command and Status              |
//! | +0x20   | TFD   | Task File Data                  |
//! | +0x24   | SIG   | Signature (after spin-up)       |
//! | +0x28   | SSTS  | SATA Status                     |
//! | +0x2C   | SCTL  | SATA Control                    |
//! | +0x30   | SERR  | SATA Error                      |
//! | +0x34   | SACT  | SATA Active                     |
//! | +0x38   | CI    | Command Issue                   |

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::alloc_coherent;
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

pub const AHCI_VENDOR: u16 = 0x8086;
/// QEMU q35 ICH9 AHCI.
pub const AHCI_ICH9_DEV: u16 = 0x2922;
/// Real silicon ICH10 AHCI.
pub const AHCI_ICH10_DEV: u16 = 0x3A22;

const ABAR_BAR: u8 = 5;

const HBA_CAP: u64 = 0x00;
const HBA_GHC: u64 = 0x04;
const HBA_PI:  u64 = 0x0C;
const HBA_VS:  u64 = 0x10;

// GHC bits.
const GHC_HR: u32 = 1 << 0;   // HBA Reset
const GHC_AE: u32 = 1 << 31;  // AHCI Enable

// Per-port offsets.
const PORT_BASE_OFF: u64 = 0x100;
const PORT_STRIDE:   u64 = 0x80;

const PORT_CMD: u64 = 0x18;
const PORT_SIG: u64 = 0x24;
const PORT_SSTS: u64 = 0x28;
const PORT_SERR: u64 = 0x30;

// PORT_CMD bits.
const CMD_ST:  u32 = 1 << 0;   // Start
const CMD_FRE: u32 = 1 << 4;   // FIS Receive Enable
const CMD_FR:  u32 = 1 << 14;  // FIS Receive Running
const CMD_CR:  u32 = 1 << 15;  // Command List Running

/// Detected device class on a port (from PORT_SIG).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortKind {
    None,
    Sata,           // SIG = 0x00000101
    Atapi,          // SIG = 0xEB140101
    Semb,           // SIG = 0xC33C0101
    Pmp,            // SIG = 0x96690101
    Unknown(u32),
}

impl PortKind {
    fn from_sig(sig: u32, ssts: u32) -> Self {
        // SSTS DET bits[3:0] = 3 means device present + comm OK.
        if (ssts & 0x0F) != 3 { return PortKind::None; }
        match sig {
            0x0000_0101 => PortKind::Sata,
            0xEB14_0101 => PortKind::Atapi,
            0xC33C_0101 => PortKind::Semb,
            0x9669_0101 => PortKind::Pmp,
            other       => PortKind::Unknown(other),
        }
    }
}

/// One discovered port.
#[derive(Copy, Clone, Debug)]
pub struct PortInfo {
    pub index: u8,
    pub kind:  PortKind,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AhciError {
    BarMapFailed,
    /// HBA reset never cleared GHC.HR within the bounded poll.
    ResetTimeout,
    /// PORT_CMD never reported FR + CR cleared so we couldn't safely
    /// reprogram the port.
    PortIdleTimeout,
}

/// Live AHCI HBA. Stage-4 cut keeps just the MMIO + the discovered
/// port list. Per-port command-list / FIS-receive structures are
/// allocated by `claim_port` (a follow-up).
pub struct Ahci {
    mmio:  MmioRegion,
    pub cap:   u32,
    pub vs:    u32,
    pub pi:    u32,
    pub ports: alloc::vec::Vec<PortInfo>,
}

impl core::fmt::Debug for Ahci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ahci")
            .field("cap",   &format_args!("{:#x}", self.cap))
            .field("vs",    &format_args!("{:#x}", self.vs))
            .field("pi",    &format_args!("{:#x}", self.pi))
            .field("ports", &self.ports.len())
            .finish_non_exhaustive()
    }
}

impl Ahci {
    /// Bring up the HBA: reset, enable AHCI mode, enumerate
    /// implemented ports, capture each port's signature.
    ///
    /// # Safety
    /// Caller owns the device's BAR5 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, AhciError> {
        // SAFETY: caller-authority.
        let mmio = unsafe { map_bar(device, ABAR_BAR) }
            .map_err(|_| AhciError::BarMapFailed)?;

        // Force AHCI mode (some HBAs come up in legacy IDE mode).
        // SAFETY: identity-mapped MMIO.
        let ghc = unsafe { mmio.read32(HBA_GHC) };
        // SAFETY: same.
        unsafe { mmio.write32(HBA_GHC, ghc | GHC_AE); }

        // HBA Reset.
        // SAFETY: same.
        unsafe { mmio.write32(HBA_GHC, GHC_AE | GHC_HR); }
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let v = unsafe { mmio.read32(HBA_GHC) };
            if v & GHC_HR == 0 { break; }
            core::hint::spin_loop();
        }
        // SAFETY: same.
        let ghc_after = unsafe { mmio.read32(HBA_GHC) };
        if ghc_after & GHC_HR != 0 { return Err(AhciError::ResetTimeout); }
        // Re-enable AHCI mode after the reset (HR clears AE on some
        // implementations).
        // SAFETY: same.
        unsafe { mmio.write32(HBA_GHC, GHC_AE); }

        // SAFETY: same.
        let cap = unsafe { mmio.read32(HBA_CAP) };
        // SAFETY: same.
        let vs  = unsafe { mmio.read32(HBA_VS) };
        // SAFETY: same.
        let pi  = unsafe { mmio.read32(HBA_PI) };

        // Enumerate ports.
        let mut ports = alloc::vec::Vec::new();
        for n in 0..32 {
            if pi & (1u32 << n) == 0 { continue; }
            let off = PORT_BASE_OFF + (n as u64) * PORT_STRIDE;
            // SAFETY: same.
            let sig  = unsafe { mmio.read32(off + PORT_SIG)  };
            // SAFETY: same.
            let ssts = unsafe { mmio.read32(off + PORT_SSTS) };
            // Clear SERR (write-1-to-clear).
            // SAFETY: same.
            let serr = unsafe { mmio.read32(off + PORT_SERR) };
            // SAFETY: same.
            unsafe { mmio.write32(off + PORT_SERR, serr); }
            let kind = PortKind::from_sig(sig, ssts);
            ports.push(PortInfo { index: n, kind });
        }

        Ok(Self { mmio, cap, vs, pi, ports })
    }

    /// Stop a port — clears PORT_CMD.ST + PORT_CMD.FRE and waits for
    /// CR + FR to clear. Required before reprogramming CLB / FB.
    ///
    /// # Safety
    /// Caller owns the HBA exclusively; `port_index < 32`.
    pub unsafe fn port_idle(&self, port_index: u8) -> Result<(), AhciError> {
        let off = PORT_BASE_OFF + (port_index as u64) * PORT_STRIDE;
        // SAFETY: identity-mapped MMIO.
        let cmd = unsafe { self.mmio.read32(off + PORT_CMD) };
        // SAFETY: same.
        unsafe { self.mmio.write32(off + PORT_CMD, cmd & !(CMD_ST | CMD_FRE)); }
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let v = unsafe { self.mmio.read32(off + PORT_CMD) };
            if v & (CMD_FR | CMD_CR) == 0 { return Ok(()); }
            core::hint::spin_loop();
        }
        Err(AhciError::PortIdleTimeout)
    }

    /// HBA's capability bitmap.
    pub fn caps(&self) -> u32 { self.cap }

    /// AHCI version (BCD, e.g. 0x0001_0301 = v1.3.1).
    pub fn version(&self) -> u32 { self.vs }

    /// Implemented-port bitmap (PI register).
    pub fn ports_implemented(&self) -> u32 { self.pi }

    /// Issue ATA `IDENTIFY DEVICE` (opcode 0xEC) on the given port,
    /// returning the 512-byte device-data block.
    ///
    /// Stage-4 cut: allocates per-call DMA structures (command list +
    /// FIS receive + command table + 512-byte data buffer) and frees
    /// them after the response arrives. A real driver caches these
    /// per port; we trade allocations for code simplicity until the
    /// per-port BlockDevice surface lands.
    ///
    /// # Safety
    /// Caller owns the HBA + the named port exclusively; `port_idx <
    /// 32` and the port's PortKind was Sata at probe.
    pub unsafe fn identify_device(&self, port_idx: u8)
        -> Result<[u8; 512], AhciError>
    {
        let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;

        // Stop the port if it's running.
        // SAFETY: port_idx bound is the caller's contract.
        let _ = unsafe { self.port_idle(port_idx) };

        // Allocate one 4 KiB DMA page covering everything:
        //   +0x000  Command List  (1 KiB, 32 entries × 32 bytes)
        //   +0x400  Received FIS  (256 bytes)
        //   +0x500  Command Table (128 bytes — 64 cfis + 0 acmd + 16 PRDT0)
        //   +0x600  Data buffer   (512 bytes for IDENTIFY response)
        let scratch = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| AhciError::BarMapFailed)?;
        let base = scratch.phys_addr().raw();
        let cmd_list = base + 0x000;
        let fis_recv = base + 0x400;
        let cmd_tbl  = base + 0x500;
        let data_buf = base + 0x600;

        // Zero the regions we touch.
        // SAFETY: identity-mapped DMA page.
        unsafe {
            for i in 0..(0x600 + 512) {
                core::ptr::write_volatile(
                    (base + i as u64) as *mut u8, 0);
            }
        }

        // Command List entry 0: H[5..0] = FIS length in DWORDs (5
        // for H2D Register FIS), W bit = 0 (read), PRDT length = 1.
        // Fields:
        //   +0x00 u32 = (PRDT length << 16) | flags
        //   +0x04 u32 = bytes transferred (RW; HBA writes)
        //   +0x08 u64 = command-table phys
        //
        // CFL = 5 (H2D FIS = 5 DWORDs). Bits[4:0]. R=0, B=0, C=0,
        // RST=0, P=0. PRDT length = 1.
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(cmd_list as *mut u32,
                (1u32 << 16) | 5);
            core::ptr::write_volatile((cmd_list + 4) as *mut u32, 0);
            core::ptr::write_volatile((cmd_list + 8) as *mut u64, cmd_tbl);
        }

        // Command Table:
        //   +0x00..0x40  CFIS (Command FIS — 64 bytes)
        //   +0x40..0x50  ACMD (ATAPI command — 16 bytes; unused)
        //   +0x50..0x80  Reserved
        //   +0x80..0x90  PRDT entry 0 (16 bytes)
        //
        // CFIS = H2D Register FIS (FIS type 0x27):
        //   +0  type = 0x27
        //   +1  bit 7 = C (command), bits[3:0] = port multiplier
        //   +2  command = 0xEC (IDENTIFY DEVICE)
        //   +3  features (low) = 0
        // SAFETY: same DMA page.
        unsafe {
            core::ptr::write_volatile(cmd_tbl as *mut u8, 0x27);
            core::ptr::write_volatile((cmd_tbl + 1) as *mut u8, 0x80);
            core::ptr::write_volatile((cmd_tbl + 2) as *mut u8, 0xEC);
        }
        // PRDT entry 0 at +0x80 of cmd table:
        //   +0x00 u64 data base PA
        //   +0x08 u32 reserved
        //   +0x0C u32 = (Interrupt-on-completion bit 31) | (byte count - 1)
        let prdt = cmd_tbl + 0x80;
        // SAFETY: same DMA page.
        unsafe {
            core::ptr::write_volatile(prdt as *mut u64, data_buf);
            core::ptr::write_volatile((prdt + 8) as *mut u32, 0);
            core::ptr::write_volatile((prdt + 12) as *mut u32, 511);
        }

        // Program port CLB / FB.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(off + 0x00, cmd_list as u32);
            self.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
            self.mmio.write32(off + 0x08, fis_recv as u32);
            self.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        }

        // Clear PORT_IS / PORT_SERR (write-1-to-clear).
        // SAFETY: same.
        let serr = unsafe { self.mmio.read32(off + PORT_SERR) };
        // SAFETY: same.
        unsafe { self.mmio.write32(off + PORT_SERR, serr); }
        // SAFETY: same.
        unsafe { self.mmio.write32(off + 0x10, 0xFFFF_FFFF); }

        // Start the port (FRE first, then ST).
        // SAFETY: same.
        let cmd = unsafe { self.mmio.read32(off + PORT_CMD) };
        // SAFETY: same.
        unsafe { self.mmio.write32(off + PORT_CMD, cmd | CMD_FRE); }
        // SAFETY: same.
        let cmd = unsafe { self.mmio.read32(off + PORT_CMD) };
        // SAFETY: same.
        unsafe { self.mmio.write32(off + PORT_CMD, cmd | CMD_ST); }

        // Issue command 0 by writing PORT_CI bit 0.
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe { self.mmio.write32(off + 0x38, 1); }

        // Poll until CI bit clears.
        let mut ok = false;
        for _ in 0..10_000_000u32 {
            // SAFETY: same.
            let ci = unsafe { self.mmio.read32(off + 0x38) };
            // SAFETY: same.
            let tfd = unsafe { self.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {  // ERR
                return Err(AhciError::ResetTimeout);
            }
            if ci & 1 == 0 { ok = true; break; }
            core::hint::spin_loop();
        }
        if !ok {
            return Err(AhciError::ResetTimeout);
        }

        // Copy out the IDENTIFY DEVICE response.
        let mut out = [0u8; 512];
        // SAFETY: identity-mapped DMA.
        for i in 0..512usize {
            out[i] = unsafe {
                core::ptr::read_volatile((data_buf + i as u64) as *const u8)
            };
        }
        // Stop the port.
        // SAFETY: caller-asserted.
        let _ = unsafe { self.port_idle(port_idx) };
        let _ = scratch;
        Ok(out)
    }
}

/// Decode the model-number string from an IDENTIFY DEVICE response.
/// ATA strings are byte-swapped per pair (ATA-8 §7.16.7.36): byte 54
/// = char 0 high, byte 55 = char 0 low, etc. 40 bytes total.
pub fn identify_model(id: &[u8; 512]) -> [u8; 40] {
    let mut out = [b' '; 40];
    for i in 0..20 {
        out[i * 2]     = id[54 + i * 2 + 1];
        out[i * 2 + 1] = id[54 + i * 2];
    }
    out
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Ahci>> =
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
    // SAFETY: caller-authority over the device's BAR.
    let dev = match unsafe { Ahci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    Ok(())
}

pub fn register_pci_driver() {
    for did in [AHCI_ICH9_DEV, AHCI_ICH10_DEV] {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: AHCI_VENDOR, device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        AHCI_ICH9_DEV  => "ahci-ich9",
        AHCI_ICH10_DEV => "ahci-ich10",
        _              => "ahci",
    }
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&Ahci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

#[allow(dead_code)]
fn unused_silencer(mmio: &MmioRegion) {
    // Force compiler to keep compiler_fence import alive in low-cfg
    // builds.
    let _ = mmio;
    compiler_fence(Ordering::SeqCst);
}
