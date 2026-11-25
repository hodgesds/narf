//! The live PCI tree behind [`narf_io::p2pdma`], the P2P DMA distance
//! oracle: Linux `pci_upstream_bridge`, `pci_bridge_has_acs_redir`,
//! `pci_find_host_bridge`, `pci_host_bridge_dev` and `cpu_supports_p2pdma`
//! (`drivers/pci/p2pdma.c`, v7.4-rc4) over the bus registry.
//!
//! Every read is passive fabric metadata (bridge links, ACS Control, the
//! root bus's first function), the same class of read-only access as
//! [`crate::pci::upstream_bridge_commands`]: a provider must be able to
//! inspect bridges and a client it holds no capability for. Nothing here
//! changes ACS or any other register.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_io::p2pdma::{HostBridgeDev, P2pTopology};

use crate::device::{BusDevice, BusKind};

/// Linux `PCI_EXP_FLAGS_TYPE` and `PCI_EXP_TYPE_ROOT_PORT`.
const PCI_EXP_FLAGS_TYPE: u16 = 0x00f0;
const PCI_EXP_TYPE_ROOT_PORT: u16 = 0x4;

/// The registered PCI tree, as Linux walks it for P2P distance.
#[derive(Copy, Clone, Debug, Default)]
pub struct LiveTopology;

fn pcie(device: &BusDevice) -> Option<crate::PcieAddr> {
    match device.kind {
        BusKind::Pcie { addr, .. } => Some(addr),
        BusKind::VirtioMmio { .. } => None,
    }
}

/// The topmost registered function above `device`: its chain's root-bus
/// end (the bus Linux `pci_find_host_bridge` starts from).
fn root(device: BusDevice) -> BusDevice {
    let mut current = device;
    for _ in 0..256 {
        match crate::pci::upstream_bridge(&current) {
            Some(bridge) => current = bridge,
            None => break,
        }
    }
    current
}

/// `pci_pcie_type(dev) == PCI_EXP_TYPE_ROOT_PORT`.
fn is_root_port(device: &BusDevice) -> bool {
    let BusKind::Pcie { cfg_phys, .. } = device.kind else {
        return false;
    };
    // SAFETY: a registry-discovered PCIe function; the walker bounds reads.
    let Ok(Some(offset)) =
        (unsafe { crate::pci_cap::find_cap(device, crate::pci_express::PCIE_CAP_ID) })
    else {
        return false;
    };
    compiler_fence(Ordering::SeqCst);
    // SAFETY: the PCI Express Capabilities word (cap + 2), aligned and inside
    // the function's identity-mapped config window; read only.
    let flags = unsafe {
        match crate::ecam::ptr_for(cfg_phys, offset + 2) {
            Some(p) => core::ptr::read_volatile(p as *const u16),
            None => u16::MAX,
        }
    };
    compiler_fence(Ordering::SeqCst);
    flags != u16::MAX && (flags & PCI_EXP_FLAGS_TYPE) >> 4 == PCI_EXP_TYPE_ROOT_PORT
}

impl P2pTopology for LiveTopology {
    type Node = BusDevice;

    fn same(&self, a: BusDevice, b: BusDevice) -> bool {
        a.addr == b.addr
    }

    fn upstream_bridge(&self, node: BusDevice) -> Option<BusDevice> {
        crate::pci::upstream_bridge(&node)
    }

    fn acs_redirect(&self, node: BusDevice) -> bool {
        crate::pci_cap_ext::acs_control(&node).is_some_and(narf_io::p2pdma::acs_ctrl_redirects)
    }

    /// The root bus, `segment << 8 | bus`: NARF has one host bridge per
    /// root bus.
    fn host_bridge(&self, node: BusDevice) -> u64 {
        pcie(&root(node)).map_or(u64::MAX, |addr| {
            u64::from(addr.segment) << 8 | u64::from(addr.bus)
        })
    }

    /// The root bus's first function (lowest devfn, the order Linux
    /// enumerates `host->bus->devices`), when it is 00.0 or a Root Port.
    fn host_bridge_dev(&self, node: BusDevice) -> Option<HostBridgeDev> {
        let top = pcie(&root(node))?;
        let first = crate::registry::devices()
            .into_iter()
            .filter(|candidate| {
                pcie(candidate)
                    .is_some_and(|addr| addr.segment == top.segment && addr.bus == top.bus)
            })
            .min_by_key(|candidate| pcie(candidate).map(|addr| (addr.device, addr.function)))?;
        let addr = pcie(&first)?;
        ((addr.device == 0 && addr.function == 0) || is_root_port(&first)).then_some(
            HostBridgeDev {
                vendor: first.id.vendor,
                device: first.id.device,
            },
        )
    }

    fn cpu_supports_p2pdma(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            let cpu = narf_arch::x86_64::ident::read();
            cpu.vendor == narf_arch::x86_64::ident::Vendor::Amd && cpu.family >= 0x17
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }
}

/// Linux `pci_p2pdma_distance(provider, client)` over the live tree; `None`
/// (Linux -1) when `client` is not a PCI function or no peer path exists.
pub fn distance(provider: &BusDevice, client: Option<&BusDevice>) -> Option<u32> {
    narf_io::p2pdma::distance(&LiveTopology, *provider, client.copied())
}

/// Linux `calc_map_type_and_dist` over the live tree.
pub fn map_type(provider: &BusDevice, client: &BusDevice) -> narf_io::p2pdma::P2pMapType {
    narf_io::p2pdma::map_type_and_distance(&LiveTopology, *provider, *client).0
}

#[cfg(any(test, feature = "kernel-test"))]
mod p2pdma_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// An enumerated PCIe function without ACS redirection is distance 0
    /// from itself over bus addresses (the `calc_map_type_and_dist`
    /// same-function case; its own redirect would count), and a non-PCI
    /// client is refused.
    fn smoke_p2pdma_live_same_function_and_non_pci_client() -> TestResult {
        let devices = crate::registry::devices();
        let Some(device) = devices
            .iter()
            .find(|d| pcie(d).is_some() && !LiveTopology.acs_redirect(**d))
        else {
            return TestResult::Skip("no enumerated PCIe function without ACS redirect");
        };
        if distance(device, Some(device)) != Some(0)
            || map_type(device, device) != narf_io::p2pdma::P2pMapType::BusAddr
            || distance(device, None).is_some()
        {
            return TestResult::Fail("live same-function or non-PCI P2P distance");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bus/p2pdma",
        smoke_p2pdma_live_same_function_and_non_pci_client
    );
}
