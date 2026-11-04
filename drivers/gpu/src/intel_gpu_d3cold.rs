//! Runtime D3cold admission for a GT owner.
//!
//! MIT Linux b90c984d615e:
//!
//! - `xe_pm.c::xe_pm_pci_d3cold_capable`: `pcie_find_root_port` must find a
//!   root port, which must signal PME from D3cold (`pci_pme_capable(root,
//!   PCI_D3cold)`) and have ACPI `_PR3` power resources
//!   (`pci.c::pci_pr3_present`: an ACPI companion with power resources and a
//!   `_PR3` method). A root-complex integrated endpoint has no root port.
//! - `xe_pm.c::xe_pm_d3cold_allowed_toggle` (the runtime-idle callback):
//!   allowed only while capable and the VRAM in use, summed per region in
//!   whole MiB rounded up, is below `vram_threshold`
//!   (`DEFAULT_VRAM_THRESHOLD`, 300 MiB, or 0 for BMG on NUC13RNG).
//! - `xe_pci.c::xe_pci_runtime_suspend`: D3cold only when allowed, after
//!   `xe_pm_runtime_suspend` evicted all VRAM (`xe_bo_evict_all`) and
//!   suspended each GT with the system-suspend path; resume restores pinned
//!   objects early, runs the full display/GT restore and late BO restore.
//!
//! This driver never selects D3cold. The GPU function's capability covers
//! only its own config space, so the root port's PM capability is not
//! readable here; NARF evaluates no ACPI companion `_PR3`; and no
//! `narf_power::runtime_pm_pci::PciPlatformPm` provider exists to remove
//! power after D3hot. [`evaluate`] reports the first missing piece and the
//! owner registers its runtime-PM node without a platform provider, so the
//! PCI layer stops at D3hot.

use narf_bus::BusDevice;

/// `DEFAULT_VRAM_THRESHOLD` (xe_pm.h), in MiB.
pub(crate) const DEFAULT_VRAM_THRESHOLD_MB: u32 = 300;

/// A D3cold input this kernel cannot provide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Missing {
    /// Read authority over the root port's PM capability (PME_Support).
    RootPortPme,
    /// ACPI companion lookup and `_PR3` evaluation for the root port.
    Pr3,
    /// A `PciPlatformPm` provider that turns the power resources off/on.
    PlatformPower,
}

/// Why runtime D3cold is not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No root port above the function (a root-complex integrated endpoint).
    NoRootPort,
    /// The root port cannot signal PME from D3cold.
    NoRootPortPme,
    /// The root port has no `_PR3` power resources.
    NoPr3,
    /// An input this kernel cannot provide.
    Unavailable(Missing),
    /// VRAM in use is at or above the threshold.
    VramInUse { used_mb: u64, threshold_mb: u32 },
}

/// The capability inputs. `None` means the input cannot be determined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Facts {
    pub root_port: bool,
    pub root_port_pme_d3cold: Option<bool>,
    pub pr3: Option<bool>,
    pub platform_power: bool,
}

/// `xe_pm_pci_d3cold_capable`, plus the power provider the PCI layer needs.
pub(crate) fn capable(facts: Facts) -> Result<(), Refusal> {
    if !facts.root_port {
        return Err(Refusal::NoRootPort);
    }
    match facts.root_port_pme_d3cold {
        None => return Err(Refusal::Unavailable(Missing::RootPortPme)),
        Some(false) => return Err(Refusal::NoRootPortPme),
        Some(true) => {}
    }
    match facts.pr3 {
        None => return Err(Refusal::Unavailable(Missing::Pr3)),
        Some(false) => return Err(Refusal::NoPr3),
        Some(true) => {}
    }
    if !facts.platform_power {
        return Err(Refusal::Unavailable(Missing::PlatformPower));
    }
    Ok(())
}

/// `xe_pm_d3cold_allowed_toggle` for one capability result.
pub(crate) fn allowed(
    capable: Result<(), Refusal>,
    vram_used_bytes: u64,
    threshold_mb: u32,
) -> Result<(), Refusal> {
    capable?;
    let used_mb = vram_used_bytes.div_ceil(1024 * 1024);
    if used_mb < u64::from(threshold_mb) {
        Ok(())
    } else {
        Err(Refusal::VramInUse {
            used_mb,
            threshold_mb,
        })
    }
}

/// Production facts for `device`: whether a bridge sits above it (a PCIe
/// function behind a root port); every other input is unavailable.
pub(crate) fn facts_for(device: &BusDevice) -> Facts {
    Facts {
        root_port: narf_bus::pci::upstream_bridge(device).is_some(),
        root_port_pme_d3cold: None,
        pr3: None,
        platform_power: false,
    }
}

/// The production D3cold decision for `device`.
pub(crate) fn evaluate(device: &BusDevice) -> Result<(), Refusal> {
    capable(facts_for(device))
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const READY: Facts = Facts {
        root_port: true,
        root_port_pme_d3cold: Some(true),
        pr3: Some(true),
        platform_power: true,
    };

    fn smoke_d3cold_capability_refusals_follow_xe_pm_order() -> TestResult {
        assert_eq!(capable(READY), Ok(()));
        assert_eq!(
            capable(Facts {
                root_port: false,
                ..READY
            }),
            Err(Refusal::NoRootPort),
            "an integrated endpoint has no root port"
        );
        assert_eq!(
            capable(Facts {
                root_port_pme_d3cold: Some(false),
                pr3: None,
                ..READY
            }),
            Err(Refusal::NoRootPortPme),
            "PME is checked before _PR3"
        );
        assert_eq!(
            capable(Facts {
                root_port_pme_d3cold: None,
                ..READY
            }),
            Err(Refusal::Unavailable(Missing::RootPortPme))
        );
        assert_eq!(
            capable(Facts {
                pr3: Some(false),
                ..READY
            }),
            Err(Refusal::NoPr3)
        );
        assert_eq!(
            capable(Facts { pr3: None, ..READY }),
            Err(Refusal::Unavailable(Missing::Pr3))
        );
        assert_eq!(
            capable(Facts {
                platform_power: false,
                ..READY
            }),
            Err(Refusal::Unavailable(Missing::PlatformPower))
        );
        // The production facts never claim an input this kernel lacks.
        let production = Facts {
            root_port: true,
            root_port_pme_d3cold: None,
            pr3: None,
            platform_power: false,
        };
        assert_eq!(
            capable(production),
            Err(Refusal::Unavailable(Missing::RootPortPme))
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_power",
        smoke_d3cold_capability_refusals_follow_xe_pm_order
    );

    fn smoke_d3cold_vram_threshold_rounds_up_and_refuses_at_limit() -> TestResult {
        const MIB: u64 = 1024 * 1024;
        let threshold = DEFAULT_VRAM_THRESHOLD_MB;
        assert_eq!(allowed(Ok(()), 0, threshold), Ok(()));
        assert_eq!(allowed(Ok(()), 299 * MIB, threshold), Ok(()));
        // DIV_ROUND_UP: one byte past 299 MiB counts as 300 MiB.
        assert_eq!(
            allowed(Ok(()), 299 * MIB + 1, threshold),
            Err(Refusal::VramInUse {
                used_mb: 300,
                threshold_mb: 300
            })
        );
        assert_eq!(
            allowed(Ok(()), 300 * MIB, threshold),
            Err(Refusal::VramInUse {
                used_mb: 300,
                threshold_mb: 300
            })
        );
        // A zero threshold (the BMG NUC13RNG quirk) never allows D3cold.
        assert_eq!(
            allowed(Ok(()), 0, 0),
            Err(Refusal::VramInUse {
                used_mb: 0,
                threshold_mb: 0
            })
        );
        // Not capable: the capability refusal wins over any VRAM state.
        assert_eq!(
            allowed(Err(Refusal::NoRootPort), 0, threshold),
            Err(Refusal::NoRootPort)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_power",
        smoke_d3cold_vram_threshold_rounds_up_and_refuses_at_limit
    );
}
