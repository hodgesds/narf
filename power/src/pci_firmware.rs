//! Typed PCI firmware policy metadata under the delegated platform owner.
//! Exact endpoint identity is independent of an ancestor's wake route.
extern crate alloc;

use alloc::{format, string::String};
use core::fmt;
use narf_aml::Value;
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, CapError, Grant, Write};

use crate::{
    pci_wake::{self, Aml, EndpointOp, Namespace, PowerOp, Topology, WakeError},
    Power,
};

#[cfg(feature = "wake-test")]
#[path = "pci_firmware_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataError {
    Authority,
    Unavailable,
    Ambiguous,
    Firmware,
}

impl From<CapError> for MetadataError {
    fn from(_: CapError) -> Self {
        Self::Authority
    }
}

impl From<WakeError> for MetadataError {
    fn from(error: WakeError) -> Self {
        match error {
            WakeError::Authority => Self::Authority,
            WakeError::Ambiguous => Self::Ambiguous,
            WakeError::Firmware => Self::Firmware,
            _ => Self::Unavailable,
        }
    }
}

/// Known endpoint BIOS policy objects. No arbitrary AML path or evaluator
/// callback, platform capability, or ancestor-table fallback is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciMetadataKey {
    Wrds,
    Ewrd,
    Wgds,
    Ppag,
}

impl PciMetadataKey {
    fn name(self) -> &'static str {
        match self {
            Self::Wrds => "WRDS",
            Self::Ewrd => "EWRD",
            Self::Wgds => "WGDS",
            Self::Ppag => "PPAG",
        }
    }
}

/// A platform-owned exact endpoint lookup. A missing endpoint is an actual
/// optional-data absence; invalid firmware and missing/revoked authority
/// remain distinct errors. Metadata reads create no radio/transmit grant.
pub struct PciMetadata {
    platform: Cap<Power, Grant>,
    endpoint: Cap<BusDeviceCap, Write>,
    path: Option<String>,
}

impl fmt::Debug for PciMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PciMetadata")
            .field("endpoint_path", &self.path)
            .finish_non_exhaustive()
    }
}

impl PciMetadata {
    /// The existing trusted driver binding must pair the cap and device.
    /// No namespace replacement may race this facade's lifetime.
    pub fn discover(
        endpoint: &Cap<BusDeviceCap, Write>,
        device: BusDevice,
    ) -> Result<Self, MetadataError> {
        let platform = pci_wake::delegated_authority()?;
        let (segment, root_bus, hops) = endpoint.invoke(Topology(&device))??;
        let matched = endpoint.invoke(EndpointOp(|| {
            platform.invoke(PowerOp(|| {
                pci_wake::match_namespace(&Aml, segment, root_bus, &hops)
            }))?
        }))??;
        Ok(Self {
            platform,
            endpoint: *endpoint,
            path: matched.exact_endpoint,
        })
    }

    /// Cached identity only. It is not a current firmware-operation grant.
    pub fn endpoint_path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Execute only the selected known object at this exact endpoint, under
    /// both current invocations. Firmware methods may have side effects;
    /// this API does not label their execution as read-only.
    pub fn object(&self, key: PciMetadataKey) -> Result<Option<Value>, MetadataError> {
        let value = self.endpoint.invoke(EndpointOp(|| {
            self.platform.invoke(PowerOp(|| {
                let Some(path) = self.path.as_ref() else {
                    return Ok(None);
                };
                Aml.object(&format!("{path}.{}", key.name()))
            }))?
        }))??;
        Ok(value)
    }
}

/// Test-only platform grant scope; no production authority is minted.
#[cfg(feature = "wake-test")]
pub struct TestPlatformAuthority {
    previous: Option<Cap<Power, Grant>>,
}

#[cfg(feature = "wake-test")]
impl fmt::Debug for TestPlatformAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestPlatformAuthority")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "wake-test")]
impl Drop for TestPlatformAuthority {
    fn drop(&mut self) {
        *pci_wake::AUTHORITY.lock() = self.previous;
    }
}

/// # Safety
/// Serialize all platform metadata/wake owners. Complete or retire all
/// fixture-owned work and leases before dropping this scope. Namespace,
/// ECAM and firmware tables require their own matching fixture scopes.
#[cfg(feature = "wake-test")]
pub unsafe fn __test_platform_authority_scope(
    cap: &Cap<Power, Grant>,
) -> Result<TestPlatformAuthority, MetadataError> {
    cap.invoke(narf_capabilities::NoopOp)?;
    let previous = pci_wake::AUTHORITY.lock().replace(*cap);
    Ok(TestPlatformAuthority { previous })
}
