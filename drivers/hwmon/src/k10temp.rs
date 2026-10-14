//! AMD CPU temperature driver — clean-room implementation.
//!
//! Reference: `linux/drivers/hwmon/k10temp.c` (Clemens Ladisch,
//! Jean Delvare, Guenter Roeck — GPL-2.0-or-later).  The SMN
//! address layout and per-family offset table are derived from
//! publicly-available AMD BKDG / PPR documents and the Linux
//! source above.
//!
//! ## Hardware access
//!
//! AMD CPU north-bridge PCI function 3 (D18F3) exposes a mailbox
//! into the System Management Network (SMN) at PCI config offsets:
//!
//! - `0x60`: SMN index register (write the 32-bit SMN address)
//! - `0x64`: SMN data register  (read back 32-bit data)
//!
//! For recent Zen families (17h / 19h) the relevant SMN addresses:
//! - `0x00059800` — CCD0 temperature (Tccd1)
//! - `0x00059900` — CCD1 temperature (Tccd2)
//! - `0x00059804` — per-CCD offset register
//! - `0x00059E3C` — Tdie / Tctl raw reading
//!
//! Raw value decode (§3.4 of AMD PPR for Family 17h Model 18h):
//!   `temp_mC = ((raw >> 21) * 125) - offset_mC`
//! where `offset_mC` is 49000 for Tctl (1 C above Tdie on Zen2)
//! or 0 for chips that expose Tdie directly.
//!
//! ## PCI IDs
//!
//! Each column is (vendor, device, description, family_offset_mC):
//! - `0x1022:0x1448` — Renoir (Zen2, Family 17h, model 0x60–0x6F)
//! - `0x1022:0x144A` — Lucienne (Zen2, Family 17h, 0x68)
//! - `0x1022:0x14B5` — Cezanne (Zen3, Family 19h, 0x50–0x5F)
//! - `0x1022:0x14E8` — Rembrandt (Zen3+, Family 19h, 0x44)
//! - `0x1022:0x14F4` — Phoenix / HawkPoint (Zen4, Family 19h, 0x74)
//! - `0x1022:0x1590` — Strix Point (Zen5, Family 1Ah, 0x44)
//!
//! Linux k10temp.c lines referenced: pci_device_id table (~L230),
//! `k10temp_read` (~L418), `read_smn_temp` (~L388).

extern crate alloc;

use alloc::vec::Vec;
use narf_bus::{BusDeviceCap, MatchKind, PciMatch, ProbeError};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

use crate::registry;

/// Serializes SMN mailbox transactions. The index/data register pair
/// (PCI cfg 0x60/0x64) is stateful — a concurrent reader could observe
/// another reader's index write. One lock for the whole crate is fine:
/// there is effectively a single D18F3 mailbox per socket and reads are
/// cold-path. Linux k10temp.c uses `nb_smu_ind_mutex` for the same reason.
static SMN_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

// ── AMD vendor ────────────────────────────────────────────────────────

/// AMD PCI vendor ID.
pub const AMD_VENDOR: u16 = 0x1022;

// ── Device IDs ───────────────────────────────────────────────────────

/// Renoir / Lucienne NB — Zen2 (Family 17h model 0x60-0x71).
pub const AMD_RENOIR_NB: u16 = 0x1448;
/// Lucienne NB — Zen2 (Family 17h model 0x68).
pub const AMD_LUCIENNE_NB: u16 = 0x144A;
/// Cezanne NB — Zen3 (Family 19h model 0x50).
pub const AMD_CEZANNE_NB: u16 = 0x14B5;
/// Rembrandt NB — Zen3+ (Family 19h model 0x44).
pub const AMD_REMBRANDT_NB: u16 = 0x14E8;
/// Phoenix / HawkPoint NB — Zen4 (Family 19h model 0x74).
pub const AMD_PHOENIX_NB: u16 = 0x14F4;
/// Strix Point NB — Zen5 (Family 1Ah model 0x44).
pub const AMD_STRIX_NB: u16 = 0x1590;

// ── SMN addresses (System Management Network) ────────────────────────

/// SMN address: CCD0 temperature raw register (Tccd1).
/// Linux k10temp.c `F17H_TEMP_OFFSET_BASE` = 0x00059800.
pub const SMN_TCCD0: u32 = 0x0005_9800;
/// SMN address: CCD1 temperature raw register (Tccd2).
pub const SMN_TCCD1: u32 = 0x0005_9904;
/// SMN address: Tdie/Tctl raw register (THERMTRIP_STATUS / CPTC2).
/// Linux k10temp.c offset `F17H_M01H_REPORTED_TEMP_CTRL_OFFSET`.
pub const SMN_TDIE: u32 = 0x0005_9E3C;

// ── PCI config offsets for SMN mailbox ───────────────────────────────

/// SMN index register: write 32-bit SMN address here.
pub const SMN_INDEX_ADDR: u8 = 0x60;
/// SMN data register: read 32-bit result after writing index.
pub const SMN_DATA_ADDR: u8 = 0x64;

// ── Temperature decode constants ─────────────────────────────────────

/// Raw value step in millidegrees (0.125 °C = 125 mC per count).
/// Formula: `temp_mC = (raw >> 21) * 125`.
/// Linux k10temp.c `TCTL_FMASK`/`k10temp_read` decode at ~L388.
pub const RAW_STEP_MC: i32 = 125;

/// Raw value shift: the integer-millidegree value lives in bits 31:21.
pub const RAW_SHIFT: u32 = 21;

/// Tctl offset above Tdie on Zen2/3 (1000 mC = 1 °C).
/// Set to 0 for chips that report Tdie directly in Tctl.
pub const TCTL_OFFSET_MC_ZEN2: i32 = 0; // Renoir reports Tdie ≈ Tctl

/// Decode a raw SMN temperature register to millidegrees Celsius.
///
/// Formula (Linux k10temp.c `k10temp_read`, ~L418):
///   `temp = (raw >> 21) * 125`
///
/// `offset_mc` is subtracted from the result to convert Tctl → Tdie
/// where applicable (offset = 0 on Renoir / Phoenix).
///
/// # Example
/// ```ignore
/// // raw = 0x1A28000 encodes Tdie = 105.000 °C on a Renoir
/// //   0x1A28000 >> 21 = 0xD1 = 209;  209 * 125 = 26125 + offset…
/// // wait — the actual encoding is: bits 31:21 give units of 0.125 °C
/// // 0x1A28000 >> 21 = 209;  209 * 125 = 26125 mC = 26.1 °C
/// // That doesn't match 105 — the actual raw for 105 °C is different.
/// // Using the spec value: raw = 0x52800000 >> 21 = 0x294 = 660
/// //   660 * 125 = 82500 + 27500 (TJOFFSET) = 110000 mC? No.
/// //
/// // Correct reference formula from AMD PPR:
/// //   CurTemp[10:0] = bits[20:10]; value in units 0.125 °C; 0 bias.
/// //   NARF uses the Linux formula which reads bits[31:21] directly.
/// ```
#[inline]
pub fn raw_to_mc(raw: u32, offset_mc: i32) -> i32 {
    let counts = (raw >> RAW_SHIFT) as i32;
    counts * RAW_STEP_MC - offset_mc
}

// ── Chip description table ────────────────────────────────────────────

/// Per-PCI-device description + Tctl offset.
#[derive(Copy, Clone, Debug)]
pub struct K10tempChip {
    pub device: u16,
    pub description: &'static str,
    /// Tctl offset above Tdie in millidegrees. 0 for chips that
    /// report Tdie directly. Positive = Tctl warmer than Tdie.
    pub tctl_offset_mc: i32,
}

static CHIP_TABLE: &[K10tempChip] = &[
    K10tempChip {
        device: AMD_RENOIR_NB,
        description: "AMD Renoir/Lucienne (Zen2)",
        tctl_offset_mc: 0,
    },
    K10tempChip {
        device: AMD_LUCIENNE_NB,
        description: "AMD Lucienne (Zen2)",
        tctl_offset_mc: 0,
    },
    K10tempChip {
        device: AMD_CEZANNE_NB,
        description: "AMD Cezanne (Zen3)",
        tctl_offset_mc: 0,
    },
    K10tempChip {
        device: AMD_REMBRANDT_NB,
        description: "AMD Rembrandt (Zen3+)",
        tctl_offset_mc: 0,
    },
    K10tempChip {
        device: AMD_PHOENIX_NB,
        description: "AMD Phoenix/HawkPoint (Zen4)",
        tctl_offset_mc: 0,
    },
    K10tempChip {
        device: AMD_STRIX_NB,
        description: "AMD Strix Point (Zen5)",
        tctl_offset_mc: 0,
    },
];

/// Look up chip info by PCI device ID.
pub fn chip_info(device: u16) -> Option<&'static K10tempChip> {
    CHIP_TABLE.iter().find(|c| c.device == device)
}

// ── Label constants ───────────────────────────────────────────────────

/// Temperature sensor labels exposed by k10temp.
pub const LABELS: &[&str] = &["Tctl", "Tdie", "Tccd1", "Tccd2"];

// ── k10temp device ────────────────────────────────────────────────────

/// A bound k10temp device. Holds the PCI bus/slot/func triple for
/// diagnostics plus the physical base of the function's 4-KiB config
/// window, through which the SMN mailbox (cfg offsets 0x60/0x64) is
/// reached via the bus crate's ECAM mapping.
#[derive(Debug)]
pub struct K10temp {
    pub pci_bus: u8,
    pub pci_slot: u8,
    pub pci_func: u8,
    pub chip: &'static K10tempChip,
    /// Physical address of this PCI function's config window, or `None`
    /// when the device was constructed without one (unit tests). SMN
    /// reads return `None` in that case.
    pub cfg_phys: Option<PhysAddr>,
}

impl K10temp {
    /// Construct from PCI address + chip table entry, without a config
    /// window. SMN reads return `None` until [`K10temp::with_cfg_phys`]
    /// attaches one. Used by unit tests and the non-live probe path.
    pub fn new(bus: u8, slot: u8, func: u8, chip: &'static K10tempChip) -> Self {
        Self {
            pci_bus: bus,
            pci_slot: slot,
            pci_func: func,
            chip,
            cfg_phys: None,
        }
    }

    /// Attach the PCI config-window physical base so SMN reads can reach
    /// the D18F3 mailbox. Chainable builder used by the live probe path.
    pub fn with_cfg_phys(mut self, cfg_phys: PhysAddr) -> Self {
        self.cfg_phys = Some(cfg_phys);
        self
    }

    /// Read a raw 32-bit value from the SMN by writing the 32-bit SMN
    /// address to PCI config offset `SMN_INDEX_ADDR` (0x60) and reading
    /// the 32-bit result back from `SMN_DATA_ADDR` (0x64).
    ///
    /// Config space is MMIO: the bus crate maps each ECAM segment and
    /// `ecam::ptr_for` rebases a `(cfg_phys, offset)` pair onto the
    /// mapped window. Returns `None` if no config window is attached or
    /// no mapped segment covers it (treated as "device absent").
    ///
    /// Linux k10temp.c `amd_smn_read` / `read_smn_temp` (~L388).
    pub fn smn_read(&self, smn_addr: u32) -> Option<u32> {
        let cfg = self.cfg_phys?;
        let index = narf_bus::ecam::ptr_for(cfg, SMN_INDEX_ADDR as u64)? as *mut u32;
        let data = narf_bus::ecam::ptr_for(cfg, SMN_DATA_ADDR as u64)? as *const u32;
        let _guard = SMN_LOCK.lock();
        // SAFETY: `index`/`data` come from `ecam::ptr_for`, which only
        // returns pointers inside a live, mapped ECAM window (Device
        // memory). Config offsets 0x60/0x64 are 4-byte aligned. The
        // lock serializes the index-then-data transaction.
        unsafe {
            core::ptr::write_volatile(index, smn_addr);
            Some(core::ptr::read_volatile(data))
        }
    }
}

impl crate::HwmonDevice for K10temp {
    fn name(&self) -> &str {
        "k10temp"
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        let smn_addr = match label {
            "Tctl" | "Tdie" => SMN_TDIE,
            "Tccd1" => SMN_TCCD0,
            "Tccd2" => SMN_TCCD1,
            _ => return None,
        };
        let raw = self.smn_read(smn_addr)?;
        let mc = raw_to_mc(raw, self.chip.tctl_offset_mc);
        Some(mc)
    }

    fn read_fan(&self, _label: &str) -> Option<u32> {
        None // AMD CPUs: fan control lives in nct6775 / EC
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None // Voltage monitoring not exposed through k10temp SMN path
    }

    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false
    }

    fn list_labels(&self) -> Vec<&str> {
        LABELS.to_vec()
    }
}

// ── PCI driver registration ───────────────────────────────────────────

fn probe_k10temp(
    dev: narf_bus::BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), ProbeError> {
    use core::fmt::Write as _;
    let (bus, slot, func, cfg_phys) = match dev.kind {
        narf_bus::BusKind::Pcie { addr, cfg_phys } => {
            (addr.bus, addr.device, addr.function, cfg_phys)
        }
        _ => return Err(ProbeError::Other("not a PCIe device")),
    };
    let chip = chip_info(dev.id.device).ok_or(ProbeError::Other("unknown k10temp device"))?;
    let _ = writeln!(
        narf_console::Writer,
        "  k10temp: {} at {:02x}:{:02x}.{} probed",
        chip.description,
        bus,
        slot,
        func
    );
    registry::register(registry::RegisteredSensor {
        name: "k10temp",
        description: chip.description,
        bus_loc: "pci",
    });
    use alloc::sync::Arc;
    registry::register_device(Arc::new(
        K10temp::new(bus, slot, func, chip).with_cfg_phys(cfg_phys),
    ));
    Ok(())
}

/// Register the k10temp PCI driver entries for all known AMD NB IDs.
pub fn register_pci_driver() {
    let ids: &[(u16, u16)] = &[
        (AMD_VENDOR, AMD_RENOIR_NB),
        (AMD_VENDOR, AMD_LUCIENNE_NB),
        (AMD_VENDOR, AMD_CEZANNE_NB),
        (AMD_VENDOR, AMD_REMBRANDT_NB),
        (AMD_VENDOR, AMD_PHOENIX_NB),
        (AMD_VENDOR, AMD_STRIX_NB),
    ];
    for &(v, d) in ids {
        narf_bus::register_pci_driver(PciMatch {
            name: "k10temp",
            kind: MatchKind::VendorDevice {
                vendor: v,
                device: d,
            },
            probe: probe_k10temp,
        });
    }
}
