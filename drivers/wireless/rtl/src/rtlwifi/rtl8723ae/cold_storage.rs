// SPDX-License-Identifier: GPL-2.0-or-later
//! Original AE cold Box retention, not calibration authority.
//! Requires init::Owner::history from the accompanying cold-history patch.
use super::{init, phy::PgStore, version::Version};
use crate::rtlwifi::prepare::Error;
use alloc::{boxed::Box, sync::Arc};
use narf_lib::sync::OnceLock;

/// Observed PCI identity from PciIo::ae_identity(), not EEPROM subvendor IDs.
/// The native constructor is deliberately in firmware_native.rs, beside the
/// existing per-access PCI capability checks, not a caller-provided array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtlwifi) struct PciIdentity {
    fields: [u16; 4],
    address: narf_bus::BusAddr,
}

impl PciIdentity {
    /// Read real config-space facts under current PCI authority. This is
    /// metadata, never a calibration or release grant. PciIo::ae_identity
    /// must call this with its OWN retained device/cap inside access().
    pub(in crate::rtlwifi) fn read(
        device: narf_bus::BusDevice,
        cap: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Result<Self, crate::rtlwifi::firmware_transport::Error> {
        use crate::rtlwifi::firmware_transport::Error;
        narf_drivers_wireless_rtw::rtw88::pci_park::invoke(cap, || {
            let id = narf_bus::pci::read_config32(cap, &device, 0).map_err(|_| Error::Access)?;
            let subsystem =
                narf_bus::pci::read_config32(cap, &device, 0x2c).map_err(|_| Error::Access)?;
            if id == u32::MAX || subsystem == u32::MAX {
                return Err(Error::Gone);
            }
            let expected = u32::from(device.id.vendor) | u32::from(device.id.device) << 16;
            if id != expected || id != 0x8723_10ec {
                return Err(Error::Access);
            }
            Ok(Self {
                fields: [
                    id as u16,
                    (id >> 16) as u16,
                    subsystem as u16,
                    (subsystem >> 16) as u16,
                ],
                address: device.addr,
            })
        })
        .map_err(|_| Error::Access)?
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtlwifi) fn fixture(address: narf_bus::BusAddr) -> Self {
        // Explicit inert fixture identity; native PciIo ALWAYS reads real PCI.
        Self {
            fields: [0x10ec, 0x8723, 0x10ec, 0x8723],
            address,
        }
    }
    pub(in crate::rtlwifi) fn address(&self) -> narf_bus::BusAddr {
        self.address
    }
}

#[derive(Debug)]
struct Original {
    owner: Box<init::Owner>,
    pci: PciIdentity,
}

/// Allocate this BEFORE taking the firmware owner's cold Box. There is no
/// Clone of Tables, PgStore or Owner. The OnceLock's actual owned Box is the
/// unique native history, shared read-only through a post-transfer Bound.
#[derive(Debug, Default)]
pub(in crate::rtlwifi) struct Storage {
    original: OnceLock<Original>,
}
impl Storage {
    pub(in crate::rtlwifi) fn empty(&self) -> bool {
        self.original.get().is_none()
    }
    /// Validate under both regular owner locks BEFORE take. The caller also
    /// rechecks Ready and executes the transfer inside current firmware source.
    pub(in crate::rtlwifi) fn accepts(owner: &init::Owner) -> bool {
        owner.phase() == init::Phase::TablesReady
            && owner.tables().is_some()
            && owner.history().is_some()
    }
    /// No allocation, await, callback or MMIO occurs here. Unexpected duplicate
    /// installation returns the exact Box to its still-retained caller; it
    /// never drops calibration/cold state while unwinding an error.
    pub(in crate::rtlwifi) fn install(
        &self,
        owner: Box<init::Owner>,
        pci: PciIdentity,
    ) -> Result<(), Box<init::Owner>> {
        if !Self::accepts(&owner) || pci.fields[..2] != [0x10ec, 0x8723] {
            return Err(owner);
        }
        self.original
            .set(Original { owner, pci })
            .map_err(|original| original.owner)
    }
    pub(in crate::rtlwifi) fn bound(self: &Arc<Self>) -> Result<Bound, Error> {
        self.original.get().ok_or(Error::State)?;
        Ok(Bound(self.clone()))
    }
}

/// Sealed post-transfer read-only view. This owns a reference to the cell
/// holding the original Box, so borrowed PG/report fields never outlive it.
/// It has no public constructor and supplies no current MMIO or RF permission.
#[derive(Clone, Debug)]
pub(in crate::rtlwifi) struct Bound(Arc<Storage>);
impl Bound {
    fn original(&self) -> &Original {
        // A Bound is constructed only after a successful OnceLock set. That
        // cell never clears/replaces its value, including in quarantine.
        self.0.original.get().expect("sealed original AE cold Box")
    }
    pub(super) fn version(&self) -> Version {
        self.original().owner.history().unwrap().version
    }
    pub(super) fn warm(&self) -> bool {
        self.original().owner.history().unwrap().mac_func_enabled
    }
    pub(super) fn ephy_retries(&self) -> u16 {
        self.original().owner.history().unwrap().ephy_retries
    }
    pub(super) fn pci(&self) -> [u16; 4] {
        self.original().pci.fields
    }
    pub(super) fn chnlval(&self) -> [u32; 2] {
        self.original().owner.tables().unwrap().chnlval
    }
    pub(super) fn pg(&self) -> &PgStore {
        &self.original().owner.tables().unwrap().bb.pg
    }
    pub(super) fn receive_config(&self) -> u32 {
        self.original().owner.tables().unwrap().receive_config
    }
    pub(super) fn cck_high_power(&self) -> bool {
        self.original().owner.tables().unwrap().bb.cck_high_power
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"AE original cold history v1");
        h.update(&self.version().raw().to_le_bytes());
        h.update(&[u8::from(self.warm())]);
        h.update(&self.ephy_retries().to_le_bytes());
        for field in self.pci() {
            h.update(&field.to_le_bytes());
        }
        for channel in self.chnlval() {
            h.update(&channel.to_le_bytes());
        }
        h.update(&[self.pg().pwrgroup_cnt]);
        for word in self.pg().origoffset.iter().flatten() {
            h.update(&word.to_le_bytes());
        }
        h.finalize()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn original_address(&self) -> usize {
        self.original().owner.as_ref() as *const init::Owner as usize
    }
}
