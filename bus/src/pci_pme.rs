//! Endpoint PCI Power Management Event registers.
//!
//! This is a child of `pci`, not a PCIe Root Port service. The caller owns
//! the endpoint's configuration authority and serializes PMCSR with its
//! power-state writer. A successful arm does not prove a platform wake route.
//! Linux: `drivers/pci/pci.c::{pci_pme_capable,__pci_pme_active}` and
//! `include/uapi/linux/pci_regs.h`.

use narf_capabilities::{Cap, CapError, CapOp, Read, Write};

use super::{cfg_read16, cfg_write16, pcie_cfg_phys, pmcsr_offset, PciError};
use crate::device::BusDevice;
use crate::registry::BusDeviceCap;

#[cfg(feature = "kernel-test")]
#[path = "pci_pme_fault.rs"]
mod fault;
#[cfg(feature = "kernel-test")]
pub use fault::{ReadbackFailure, __test_arm_readback_failure, __test_disarm_readback_failure};

const PME_ENABLE: u16 = 1 << 8;
const PME_STATUS: u16 = 1 << 15;

/// D-state from which the endpoint must be able to generate PME.
/// D3cold capability alone does not establish an auxiliary-power supply.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WakeState {
    D0 = 0,
    D1 = 1,
    D2 = 2,
    D3Hot = 3,
    D3Cold = 4,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PmeError {
    Pci(PciError),
    /// PME from the requested D-state is absent in the PM capability.
    Unsupported,
    /// Another owner already has PME enabled. Its status is left untouched.
    AlreadyEnabled,
    /// The function no longer responds or its PM capability is malformed.
    Unavailable,
    /// PMCSR did not retain the requested enable bit.
    Readback,
}

impl From<PciError> for PmeError {
    fn from(error: PciError) -> Self {
        Self::Pci(error)
    }
}

impl From<CapError> for PmeError {
    fn from(_: CapError) -> Self {
        Self::Pci(PciError::AuthorityRevoked)
    }
}

/// One bounded PM capability/PMCSR read under current endpoint authority.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// PMC.PME_Support, bit0=D0 through bit4=D3cold.
    pub supported_states: u8,
    pub enabled: bool,
    pub pending: bool,
}

impl Status {
    pub fn supports(self, state: WakeState) -> bool {
        self.supported_states & (1 << state as u8) != 0
    }
}

fn read(device: &BusDevice) -> Result<(narf_memory::PhysAddr, u64, Status), PmeError> {
    let cfg = pcie_cfg_phys(device)?;
    let off = pmcsr_offset(device)?;
    // The standard capability list bounds the header, but the complete
    // eight-byte PM capability must also fit before extended config space.
    if off > 0xfc {
        return Err(PmeError::Unavailable);
    }
    // SAFETY: both aligned words lie within the discovered PM capability.
    let (pmc, pmcsr) = unsafe { (cfg_read16(cfg, off - 2), cfg_read16(cfg, off)) };
    if !(1..=3).contains(&(pmc & 7)) || pmcsr == u16::MAX {
        return Err(PmeError::Unavailable);
    }
    Ok((
        cfg,
        off,
        Status {
            supported_states: ((pmc >> 11) & 0x1f) as u8,
            enabled: pmcsr & PME_ENABLE != 0,
            pending: pmcsr & PME_STATUS != 0,
        },
    ))
}

pub fn status(cap: &Cap<BusDeviceCap, Read>, device: &BusDevice) -> Result<Status, PmeError> {
    struct Query<'a>(&'a BusDevice);
    impl CapOp<BusDeviceCap, Read> for Query<'_> {
        type Output = Result<Status, PmeError>;
        fn execute(self, _: &Cap<BusDeviceCap, Read>) -> Result<Self::Output, CapError> {
            Ok(read(self.0).map(|(_, _, status)| status))
        }
    }
    cap.invoke(Query(device))?
}

/// Clear a stale W1C PME_Status and enable the endpoint's PME source.
/// Refuses an already-enabled source without writing it. Does not change
/// D-state, auxiliary power, upstream bridges or interrupt routing.
pub fn arm(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    state: WakeState,
) -> Result<(), PmeError> {
    struct Arm<'a>(&'a BusDevice, WakeState);
    impl CapOp<BusDeviceCap, Write> for Arm<'_> {
        type Output = Result<(), PmeError>;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
            let modify = || {
                let (cfg, off, status) = read(self.0)?;
                if !status.supports(self.1) {
                    return Err(PmeError::Unsupported);
                }
                if status.enabled {
                    return Err(PmeError::AlreadyEnabled);
                }
                // SAFETY: exact PMCSR under the caller's current Write
                // invocation; preserve D-state and all unrelated fields.
                unsafe {
                    let pmcsr = cfg_read16(cfg, off);
                    cfg_write16(cfg, off, pmcsr | PME_ENABLE | PME_STATUS);
                    #[cfg(feature = "kernel-test")]
                    if fault::fail_readback(cfg, true) {
                        return Err(PmeError::Readback);
                    }
                    let readback = cfg_read16(cfg, off);
                    if readback == u16::MAX || readback & PME_ENABLE == 0 {
                        return Err(PmeError::Readback);
                    }
                }
                Ok(())
            };
            Ok(modify())
        }
    }
    cap.invoke(Arm(device, state))?
}

/// Read terminal PME_Status, then disable PME and acknowledge that status.
/// The platform wake owner must retain its claim until this succeeds, even
/// when suspend preparation fails. A status bit does not identify a packet.
pub fn disarm(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Result<bool, PmeError> {
    let observation = disarm_observed(cap, device)?;
    observation.terminal?;
    Ok(observation.pending)
}

/// A real pre-W1C observation survives failed disable readback. The outer
/// Ok carries an observation, not terminal retirement; require terminal Ok.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DisarmObservation {
    pub pending: bool,
    pub terminal: Result<(), PmeError>,
}

pub fn disarm_observed(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Result<DisarmObservation, PmeError> {
    struct Disarm<'a>(&'a BusDevice);
    impl CapOp<BusDeviceCap, Write> for Disarm<'_> {
        type Output = Result<DisarmObservation, PmeError>;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
            let modify = || {
                let (cfg, off, status) = read(self.0)?;
                let mut pending = status.pending;
                // SAFETY: exact PMCSR under current endpoint Write
                // authority, writing one only to the W1C PME_Status bit.
                let terminal = unsafe {
                    let pmcsr = cfg_read16(cfg, off);
                    if pmcsr == u16::MAX {
                        Err(PmeError::Unavailable)
                    } else {
                        pending |= pmcsr & PME_STATUS != 0;
                        cfg_write16(cfg, off, (pmcsr & !PME_ENABLE) | PME_STATUS);
                        let readback = cfg_read16(cfg, off);
                        if readback != u16::MAX {
                            pending |= readback & PME_STATUS != 0;
                        }
                        #[cfg(feature = "kernel-test")]
                        let injected = fault::fail_readback(cfg, false);
                        #[cfg(not(feature = "kernel-test"))]
                        let injected = false;
                        if injected || readback & PME_ENABLE != 0 {
                            Err(PmeError::Readback)
                        } else {
                            Ok(())
                        }
                    }
                };
                Ok(DisarmObservation { pending, terminal })
            };
            Ok(modify())
        }
    }
    cap.invoke(Disarm(device))?
}
