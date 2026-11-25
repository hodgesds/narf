//! AMD Zen CPU temperatures via the root complex's SMN mailbox.
//!
//! Reference: Linux `drivers/hwmon/k10temp.c`, `arch/x86/kernel/amd_node.c`
//! and `include/linux/pci_ids.h`. The Data Fabric function 3 identifies the
//! CPU; SMN transactions use the AMD host bridge at device 0, function 0.
//! Tctl is at 0x59800. CCD registers have a family-specific offset and a
//! separate encoding/valid bit. Only discovered CCDs are published.

extern crate alloc;

use alloc::vec::Vec;
use narf_bus::{BusDevice, BusDeviceCap, BusKind, MatchKind, PciMatch, ProbeError};
use narf_capabilities::{Cap, Write};
use narf_memory::PhysAddr;

use crate::{registry, HwmonDevice};

pub const AMD_VENDOR: u16 = 0x1022;
// Linux's Data Fabric function-3 IDs (not function 0 or function 4).
pub const AMD_RENOIR_NB: u16 = 0x144b;
pub const AMD_LUCIENNE_NB: u16 = AMD_RENOIR_NB;
pub const AMD_CEZANNE_NB: u16 = 0x166d;
pub const AMD_REMBRANDT_NB: u16 = 0x167c;
pub const AMD_RAPHAEL_NB: u16 = 0x14e3;
pub const AMD_PHOENIX_NB: u16 = 0x14f3;
pub const AMD_STRIX_NB: u16 = 0x16fb;

/// Zen reported-temperature-control register, shared by Tctl and Tdie.
pub const SMN_TDIE: u32 = 0x0005_9800;
pub const RAW_STEP_MC: i32 = 125;
pub const RAW_SHIFT: u32 = 21;
const TEMP_RANGE_SELECT: u32 = 1 << 19;
const TEMP_TJ_SELECT: u32 = 3 << 16;
const CCD_VALID: u32 = 1 << 11;
const CCD_MASK: u32 = (1 << 11) - 1;
const CCD_LABELS: [&str; 8] = [
    "Tccd1", "Tccd2", "Tccd3", "Tccd4", "Tccd5", "Tccd6", "Tccd7", "Tccd8",
];

/// Decode Zen Tctl, including the range-select / Tj-select 49 C bias.
/// A separate per-model Tctl-to-Tdie offset applies only to Tdie.
/// PCI error responses must be rejected before calling this helper.
pub fn raw_to_mc(raw: u32, offset_mc: i32) -> i32 {
    let bias = if raw & TEMP_RANGE_SELECT != 0 || raw & TEMP_TJ_SELECT == TEMP_TJ_SELECT {
        49_000
    } else {
        0
    };
    (raw >> RAW_SHIFT) as i32 * RAW_STEP_MC - bias - offset_mc
}

/// CCDs use bits 10:0 in 0.125 C units, biased by 49 C, and bit 11 valid.
/// All-ones is a PCI error response even though its valid bit is set.
pub(crate) fn ccd_to_mc(raw: u32) -> Option<i32> {
    if raw == u32::MAX || raw & CCD_VALID == 0 {
        return None;
    }
    Some((raw & CCD_MASK) as i32 * RAW_STEP_MC - 49_000)
}

#[derive(Copy, Clone, Debug)]
pub struct K10tempChip {
    pub device: u16,
    pub description: &'static str,
    pub tctl_offset_mc: i32,
    /// Offset from SMN_TDIE to CCD 0; None when Linux does not probe CCDs.
    pub ccd_offset: Option<u32>,
}

static CHIP_TABLE: &[K10tempChip] = &[
    K10tempChip {
        device: AMD_RENOIR_NB,
        description: "AMD Renoir/Lucienne (Zen2)",
        tctl_offset_mc: 0,
        ccd_offset: Some(0x154),
    },
    K10tempChip {
        device: AMD_CEZANNE_NB,
        description: "AMD Cezanne (Zen3)",
        tctl_offset_mc: 0,
        ccd_offset: Some(0x154),
    },
    K10tempChip {
        device: AMD_REMBRANDT_NB,
        description: "AMD Rembrandt (Zen3+)",
        tctl_offset_mc: 0,
        ccd_offset: Some(0x300),
    },
    K10tempChip {
        device: AMD_RAPHAEL_NB,
        description: "AMD Raphael/Granite Ridge (Zen4/Zen5)",
        tctl_offset_mc: 0,
        ccd_offset: Some(0x308),
    },
    K10tempChip {
        device: AMD_PHOENIX_NB,
        description: "AMD Phoenix/HawkPoint (Zen4)",
        tctl_offset_mc: 0,
        ccd_offset: Some(0x308),
    },
    K10tempChip {
        device: AMD_STRIX_NB,
        description: "AMD Strix Point (Zen5)",
        tctl_offset_mc: 0,
        ccd_offset: None,
    },
];

pub fn chip_info(device: u16) -> Option<&'static K10tempChip> {
    CHIP_TABLE.iter().find(|c| c.device == device)
}

/// These client parts have one Data Fabric node at bus 0, device 18h.
/// Bind its root in the same PCI segment; do not guess on multi-node layouts.
/// Linux likewise uses D0F0 host bridges, not the matched D18F3 mailbox.
pub(crate) fn smn_root(dev: &BusDevice, devices: &[BusDevice]) -> Option<BusDevice> {
    let BusKind::Pcie { addr, .. } = dev.kind else {
        return None;
    };
    if dev.id.vendor != AMD_VENDOR
        || chip_info(dev.id.device).is_none()
        || addr.bus != 0
        || addr.device != 0x18
        || addr.function != 3
    {
        return None;
    }
    devices.iter().copied().find(|candidate| {
        candidate.id.vendor == AMD_VENDOR
            && candidate.id.class >> 8 == 0x0600
            && matches!(candidate.kind, BusKind::Pcie { addr: root, .. }
                if root.segment == addr.segment && root.bus == 0
                    && root.device == 0 && root.function == 0)
    })
}

fn discover_ccds(chip: &K10tempChip, mut read: impl FnMut(u32) -> Option<u32>) -> u8 {
    let Some(offset) = chip.ccd_offset else {
        return 0;
    };
    let mut present = 0;
    for i in 0..CCD_LABELS.len() {
        if read(SMN_TDIE + offset + i as u32 * 4)
            .and_then(ccd_to_mc)
            .is_some()
        {
            present |= 1 << i;
        }
    }
    present
}

/// PCI identity names D18F3; cfg_phys names the root complex D0F0 window.
#[derive(Debug)]
pub struct K10temp {
    pub pci_bus: u8,
    pub pci_slot: u8,
    pub pci_func: u8,
    pub chip: &'static K10tempChip,
    pub cfg_phys: Option<PhysAddr>,
    ccd_present: u8,
}

impl K10temp {
    /// An unattached device returns unavailable for every reading.
    pub fn new(bus: u8, slot: u8, func: u8, chip: &'static K10tempChip) -> Self {
        Self {
            pci_bus: bus,
            pci_slot: slot,
            pci_func: func,
            chip,
            cfg_phys: None,
            ccd_present: 0,
        }
    }

    /// Attach the root complex's ECAM window and discover valid CCD sensors.
    pub fn with_cfg_phys(mut self, cfg_phys: PhysAddr) -> Self {
        self.cfg_phys = Some(cfg_phys);
        self.ccd_present = discover_ccds(self.chip, |address| self.smn_read(address));
        self
    }

    /// An SMN read through the root complex, on the shared locked
    /// index/data path ([`narf_bus::amd_smn::read`]).
    pub fn smn_read(&self, smn_addr: u32) -> Option<u32> {
        narf_bus::amd_smn::read(self.cfg_phys?, smn_addr)
    }
}

impl HwmonDevice for K10temp {
    fn name(&self) -> &str {
        "k10temp"
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        if label == "Tctl" || label == "Tdie" {
            let raw = self.smn_read(SMN_TDIE)?;
            let offset = if label == "Tdie" {
                self.chip.tctl_offset_mc
            } else {
                0
            };
            return Some(raw_to_mc(raw, offset).max(0));
        }
        let ccd = CCD_LABELS
            .iter()
            .position(|&candidate| candidate == label)?;
        if self.ccd_present & (1 << ccd) == 0 {
            return None;
        }
        let address = SMN_TDIE + self.chip.ccd_offset? + ccd as u32 * 4;
        ccd_to_mc(self.smn_read(address)?)
    }

    fn read_fan(&self, _label: &str) -> Option<u32> {
        None
    }
    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None
    }
    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false
    }

    fn list_labels(&self) -> Vec<&str> {
        let mut labels = alloc::vec!["Tctl"];
        // Like Linux, do not publish a duplicate Tdie when no offset applies.
        // read_temp("Tdie") remains available to the internal power provider.
        if self.chip.tctl_offset_mc != 0 {
            labels.push("Tdie");
        }
        for (i, label) in CCD_LABELS.iter().enumerate() {
            if self.ccd_present & (1 << i) != 0 {
                labels.push(label);
            }
        }
        labels
    }
}

fn probe_k10temp(dev: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError> {
    use core::fmt::Write as _;
    let chip = chip_info(dev.id.device).ok_or(ProbeError::NotForThisDriver)?;
    let root = smn_root(&dev, &narf_bus::devices())
        .ok_or(ProbeError::Other("k10temp: no supported AMD SMN root"))?;
    let BusKind::Pcie { addr, .. } = dev.kind else {
        return Err(ProbeError::BadDevice);
    };
    let BusKind::Pcie {
        addr: root_addr,
        cfg_phys,
    } = root.kind
    else {
        return Err(ProbeError::BadDevice);
    };
    let sensor = K10temp::new(addr.bus, addr.device, addr.function, chip).with_cfg_phys(cfg_phys);
    let temperature = sensor
        .read_temp("Tctl")
        .ok_or(ProbeError::Other("k10temp: SMN temperature unavailable"))?;
    let _ = writeln!(
        narf_console::Writer,
        "  k10temp: {} at {:?}, SMN {:?}, Tctl={} mC, CCD mask={:#04x}",
        chip.description,
        addr,
        root_addr,
        temperature,
        sensor.ccd_present
    );
    registry::register(registry::RegisteredSensor {
        name: "k10temp",
        description: chip.description,
        bus_loc: "pci",
    });
    registry::register_device(alloc::sync::Arc::new(sensor));
    Ok(())
}

pub fn register_pci_driver() {
    for chip in CHIP_TABLE {
        narf_bus::register_pci_driver(PciMatch {
            name: "k10temp",
            kind: MatchKind::VendorDevice {
                vendor: AMD_VENDOR,
                device: chip.device,
            },
            probe: probe_k10temp,
        });
    }
}

#[cfg(feature = "kernel-test")]
#[path = "k10temp_tests.rs"]
mod tests;
