//! PCI peer-to-peer DMA distance: whether a client function can master DMA
//! straight into a provider function's BAR, and through which path.
//!
//! This is the topology oracle of Linux `drivers/pci/p2pdma.c` (v7.4-rc4):
//! `calc_map_type_and_dist`, `pci_p2pdma_distance_many` (and the
//! `pci_p2pdma_distance` wrapper in `include/linux/pci-p2pdma.h`),
//! `pci_bridge_has_acs_redir`, `host_bridge_whitelist`,
//! `__host_bridge_whitelist`, `pci_p2pdma_whitelist` and
//! `cpu_supports_p2pdma`. It is pure: the PCI tree comes in through
//! [`P2pTopology`], which `narf_bus::p2pdma` implements over the live bus
//! registry and native fixtures implement over a modelled tree. Exporters
//! use it the way `xe_dma_buf_attach` uses `pci_p2pdma_distance`: a negative
//! Linux distance (here `None`) clears the attachment's peer-to-peer flag.
//!
//! Not modelled: the provider's `map_types` xarray (`pci_p2pdma_map_type`
//! reads the cached type back at map time; callers here keep the returned
//! [`P2pMapType`] themselves) and the `verbose` warnings.

/// Linux `PCI_ACS_RR`: ACS P2P Request Redirect (`include/uapi/linux/pci_regs.h`).
pub const PCI_ACS_RR: u16 = 0x0004;
/// Linux `PCI_ACS_CR`: ACS P2P Completion Redirect.
pub const PCI_ACS_CR: u16 = 0x0008;
/// Linux `PCI_ACS_EC`: ACS P2P Egress Control.
pub const PCI_ACS_EC: u16 = 0x0020;

/// Linux `pci_bridge_has_acs_redir` on an ACS Control value: P2P TLPs are
/// redirected upstream when request redirect, completion redirect or egress
/// control is enabled.
pub fn acs_ctrl_redirects(ctrl: u16) -> bool {
    ctrl & (PCI_ACS_RR | PCI_ACS_CR | PCI_ACS_EC) != 0
}

/// Linux `enum pci_p2pdma_map_type`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum P2pMapType {
    /// `PCI_P2PDMA_MAP_NOT_SUPPORTED`: no usable peer path.
    NotSupported,
    /// `PCI_P2PDMA_MAP_BUS_ADDR`: both functions sit below a common bridge
    /// that forwards P2P TLPs; the client targets the provider's bus address.
    BusAddr,
    /// `PCI_P2PDMA_MAP_THRU_HOST_BRIDGE`: the TLPs cross the host bridge
    /// (and any IOMMU), which must be known to route peer traffic.
    ThruHostBridge,
}

/// The device Linux `pci_host_bridge_dev` returns for a host bridge: the
/// first function on the root bus, when it is devfn 00.0 or a PCIe Root
/// Port.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HostBridgeDev {
    pub vendor: u16,
    pub device: u16,
}

/// The PCI tree the oracle walks. Every method mirrors one Linux accessor.
pub trait P2pTopology {
    /// One PCI function (Linux `struct pci_dev *`).
    type Node: Copy;
    /// Pointer equality of two `pci_dev`s.
    fn same(&self, a: Self::Node, b: Self::Node) -> bool;
    /// `pci_upstream_bridge`: the bridge whose secondary bus holds `node`,
    /// or `None` on a root bus.
    fn upstream_bridge(&self, node: Self::Node) -> Option<Self::Node>;
    /// `pci_bridge_has_acs_redir`: `node` has an ACS capability whose Control
    /// redirects P2P TLPs ([`acs_ctrl_redirects`]).
    fn acs_redirect(&self, node: Self::Node) -> bool;
    /// `pci_find_host_bridge(node->bus)` identity: equal exactly for two
    /// functions under the same host bridge.
    fn host_bridge(&self, node: Self::Node) -> u64;
    /// `pci_host_bridge_dev(pci_find_host_bridge(node->bus))`.
    fn host_bridge_dev(&self, node: Self::Node) -> Option<HostBridgeDev>;
    /// `cpu_supports_p2pdma`: an AMD Zen or newer CPU (family 0x17+) routes
    /// peer traffic through its root complex.
    fn cpu_supports_p2pdma(&self) -> bool;
}

const PCI_VENDOR_ID_INTEL: u16 = 0x8086;
const PCI_VENDOR_ID_GOOGLE: u16 = 0x1ae0;
const PCI_VENDOR_ID_NVIDIA: u16 = 0x10de;
const PCI_VENDOR_ID_ZHAOXIN: u16 = 0x1d17;
const PCI_VENDOR_ID_ALIBABA: u16 = 0x1ded;

/// One `pci_p2pdma_whitelist` entry; `device: None` is `PCI_ANY_ID`.
struct WhitelistEntry {
    vendor: u16,
    device: Option<u16>,
    /// `REQ_SAME_HOST_BRIDGE`.
    same_host_bridge: bool,
}

const fn entry(vendor: u16, device: u16, same_host_bridge: bool) -> WhitelistEntry {
    WhitelistEntry {
        vendor,
        device: Some(device),
        same_host_bridge,
    }
}

/// Linux `pci_p2pdma_whitelist`, in its order (the first vendor/device
/// match decides).
const WHITELIST: [WhitelistEntry; 33] = [
    // Intel Xeon E5/Core i7
    entry(PCI_VENDOR_ID_INTEL, 0x3c00, true),
    entry(PCI_VENDOR_ID_INTEL, 0x3c01, true),
    // Intel Xeon E7 v4/Xeon E5 v4/Xeon E3 v4/Xeon D
    entry(PCI_VENDOR_ID_INTEL, 0x6f00, true),
    // Intel Xeon E7 v3/Xeon E5 v3/Core i7
    entry(PCI_VENDOR_ID_INTEL, 0x2f00, true),
    entry(PCI_VENDOR_ID_INTEL, 0x2f01, true),
    // Intel Haswell (client)
    entry(PCI_VENDOR_ID_INTEL, 0x0c08, true),
    // Intel Skylake-E
    entry(PCI_VENDOR_ID_INTEL, 0x2030, false),
    entry(PCI_VENDOR_ID_INTEL, 0x2031, false),
    entry(PCI_VENDOR_ID_INTEL, 0x2032, false),
    entry(PCI_VENDOR_ID_INTEL, 0x2033, false),
    entry(PCI_VENDOR_ID_INTEL, 0x2020, false),
    entry(PCI_VENDOR_ID_INTEL, 0x09a2, false),
    // PCI_DEVICE_ID_INTEL_DSA_SPR0, _IAX_SPR0, _DSA_GNRD, _DSA_DMR, _IAA_DMR
    entry(PCI_VENDOR_ID_INTEL, 0x0b25, false),
    entry(PCI_VENDOR_ID_INTEL, 0x0cfe, false),
    entry(PCI_VENDOR_ID_INTEL, 0x11fb, false),
    entry(PCI_VENDOR_ID_INTEL, 0x1212, false),
    entry(PCI_VENDOR_ID_INTEL, 0x1216, false),
    // PCI_DEVICE_ID_INTEL_QAT_4XXX, _401XX, _402XX, _420XX, _6XXX
    entry(PCI_VENDOR_ID_INTEL, 0x4940, false),
    entry(PCI_VENDOR_ID_INTEL, 0x4942, false),
    entry(PCI_VENDOR_ID_INTEL, 0x4944, false),
    entry(PCI_VENDOR_ID_INTEL, 0x4946, false),
    entry(PCI_VENDOR_ID_INTEL, 0x4948, false),
    // Google SoCs.
    WhitelistEntry {
        vendor: PCI_VENDOR_ID_GOOGLE,
        device: None,
        same_host_bridge: false,
    },
    // Nvidia CPUs
    entry(PCI_VENDOR_ID_NVIDIA, 0x2f95, false),
    entry(PCI_VENDOR_ID_NVIDIA, 0x2f96, false),
    entry(PCI_VENDOR_ID_NVIDIA, 0x2f97, false),
    entry(PCI_VENDOR_ID_NVIDIA, 0x2f98, false),
    // Zhaoxin KX-6000/KH-40000/KX-6000G/KX-7000/KH-50000
    entry(PCI_VENDOR_ID_ZHAOXIN, 0x1003, true),
    entry(PCI_VENDOR_ID_ZHAOXIN, 0x1005, true),
    entry(PCI_VENDOR_ID_ZHAOXIN, 0x1006, true),
    entry(PCI_VENDOR_ID_ZHAOXIN, 0x1007, true),
    entry(PCI_VENDOR_ID_ZHAOXIN, 0x1008, false),
    // Alibaba T-HEAD Yitian 710 CPU
    entry(PCI_VENDOR_ID_ALIBABA, 0x8000, false),
];

/// Bound on any upstream walk: a segment has at most 256 buses, so an
/// acyclic bridge chain is shorter.
const MAX_DEPTH: u32 = 256;

/// Linux `__host_bridge_whitelist`.
fn host_bridge_allowed<T: P2pTopology>(
    topology: &T,
    node: T::Node,
    same_host_bridge: bool,
) -> bool {
    let Some(root) = topology.host_bridge_dev(node) else {
        return false;
    };
    for entry in &WHITELIST {
        if root.vendor != entry.vendor {
            continue;
        }
        if entry.device.is_some_and(|device| device != root.device) {
            continue;
        }
        if entry.same_host_bridge && !same_host_bridge {
            return false;
        }
        return true;
    }
    false
}

/// Linux `host_bridge_whitelist`.
fn host_bridge_whitelist<T: P2pTopology>(topology: &T, a: T::Node, b: T::Node) -> bool {
    if topology.host_bridge(a) == topology.host_bridge(b) {
        return host_bridge_allowed(topology, a, true);
    }
    host_bridge_allowed(topology, a, false) && host_bridge_allowed(topology, b, false)
}

/// Linux `calc_map_type_and_dist`: the path type and the hop count between
/// `provider` and `client`. The same function is distance 0; two functions
/// of one device are 2; two devices below one switch are 4. Without a
/// common upstream bridge, or with ACS redirection anywhere on the path
/// (both ends and the common bridge included), traffic crosses the host
/// bridge, which needs a Zen-or-newer CPU or a whitelisted host bridge.
pub fn map_type_and_distance<T: P2pTopology>(
    topology: &T,
    provider: T::Node,
    client: T::Node,
) -> (P2pMapType, u32) {
    let mut acs_count = 0u32;
    let mut dist_a = 0u32;
    let mut dist_b = 0u32;
    let mut common = None;
    let mut a = Some(provider);
    'provider: while let Some(node_a) = a {
        if dist_a > MAX_DEPTH {
            break;
        }
        dist_b = 0;
        if topology.acs_redirect(node_a) {
            acs_count += 1;
        }
        let mut bb = Some(client);
        while let Some(node_b) = bb {
            if topology.same(node_a, node_b) {
                common = Some(node_a);
                break 'provider;
            }
            if dist_b > MAX_DEPTH {
                break;
            }
            bb = topology.upstream_bridge(node_b);
            dist_b += 1;
        }
        a = topology.upstream_bridge(node_a);
        dist_a += 1;
    }
    let distance = dist_a + dist_b;
    if let Some(common) = common {
        // check_b_path_acs: the client's side up to (not including) the
        // common bridge, which the provider walk already counted.
        let mut bb = Some(client);
        let mut hops = 0;
        while let Some(node_b) = bb {
            if topology.same(common, node_b) || hops > MAX_DEPTH {
                break;
            }
            if topology.acs_redirect(node_b) {
                acs_count += 1;
            }
            bb = topology.upstream_bridge(node_b);
            hops += 1;
        }
        if acs_count == 0 {
            return (P2pMapType::BusAddr, distance);
        }
    }
    // map_through_host_bridge
    if !topology.cpu_supports_p2pdma() && !host_bridge_whitelist(topology, provider, client) {
        return (P2pMapType::NotSupported, distance);
    }
    (P2pMapType::ThruHostBridge, distance)
}

/// Linux `pci_p2pdma_distance_many`: the summed distance from `provider` to
/// every client, or `None` (Linux -1) when there is no client, a client is
/// not a PCI function (`None` entry: `find_parent_pci_dev` failed) or any
/// path is [`P2pMapType::NotSupported`].
pub fn distance_many<T: P2pTopology>(
    topology: &T,
    provider: T::Node,
    clients: &[Option<T::Node>],
) -> Option<u32> {
    if clients.is_empty() {
        return None;
    }
    let mut total = 0u32;
    for client in clients {
        let client = (*client)?;
        let (map, distance) = map_type_and_distance(topology, provider, client);
        if map == P2pMapType::NotSupported {
            return None;
        }
        total = total.saturating_add(distance);
    }
    Some(total)
}

/// Linux `pci_p2pdma_distance(provider, client)`.
pub fn distance<T: P2pTopology>(
    topology: &T,
    provider: T::Node,
    client: Option<T::Node>,
) -> Option<u32> {
    distance_many(topology, provider, &[client])
}

#[cfg(any(test, feature = "kernel-test"))]
mod p2pdma_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A modelled tree: node `i` has parent `parent[i]`, ACS redirect flag
    /// `acs[i]`; roots are host-bridge root-bus functions.
    struct Tree {
        parent: [Option<usize>; 12],
        acs: [bool; 12],
        /// Host bridge of each root (by node index of the root).
        host: [u64; 12],
        host_dev: Option<HostBridgeDev>,
        zen: bool,
    }
    impl P2pTopology for Tree {
        type Node = usize;
        fn same(&self, a: usize, b: usize) -> bool {
            a == b
        }
        fn upstream_bridge(&self, node: usize) -> Option<usize> {
            self.parent[node]
        }
        fn acs_redirect(&self, node: usize) -> bool {
            self.acs[node]
        }
        fn host_bridge(&self, mut node: usize) -> u64 {
            while let Some(parent) = self.parent[node] {
                node = parent;
            }
            self.host[node]
        }
        fn host_bridge_dev(&self, _node: usize) -> Option<HostBridgeDev> {
            self.host_dev
        }
        fn cpu_supports_p2pdma(&self) -> bool {
            self.zen
        }
    }

    // 0 root port A, 1 switch upstream port, 2/3 downstream ports,
    // 4 device X (below 2), 5 device Y (below 3), 6 function 1 of X's
    // device (below 2), 7 root port B, 8 device Z (below 7).
    fn tree() -> Tree {
        let mut parent = [None; 12];
        parent[1] = Some(0);
        parent[2] = Some(1);
        parent[3] = Some(1);
        parent[4] = Some(2);
        parent[5] = Some(3);
        parent[6] = Some(2);
        parent[8] = Some(7);
        Tree {
            parent,
            acs: [false; 12],
            host: [1; 12],
            // Intel Comet Lake host bridge: not whitelisted.
            host_dev: Some(HostBridgeDev {
                vendor: 0x8086,
                device: 0x9b33,
            }),
            zen: false,
        }
    }

    /// The distances of the `calc_map_type_and_dist` kerneldoc: same
    /// function 0, two functions of one device 2, two devices below one
    /// switch 4, all over bus addresses.
    fn smoke_p2pdma_distance_matches_linux_switch_cases() -> TestResult {
        let t = tree();
        if map_type_and_distance(&t, 4, 4) != (P2pMapType::BusAddr, 0)
            || map_type_and_distance(&t, 4, 6) != (P2pMapType::BusAddr, 2)
            || map_type_and_distance(&t, 4, 5) != (P2pMapType::BusAddr, 4)
            || distance(&t, 4, Some(5)) != Some(4)
            || distance_many(&t, 4, &[Some(5), Some(6)]) != Some(6)
        {
            return TestResult::Fail("switch-local P2P distances differ from Linux");
        }
        // find_parent_pci_dev failure and an empty client list are -1.
        if distance(&t, 4, None).is_some() || distance_many(&t, 4, &[]).is_some() {
            return TestResult::Fail("non-PCI or empty client admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "io/p2pdma",
        smoke_p2pdma_distance_matches_linux_switch_cases
    );

    /// ACS redirect on either side forces the host-bridge path; without a
    /// Zen CPU or whitelisted root it is unsupported. Disjoint root ports
    /// sum both full chains (provider 4: 4,2,1,0; client 8: 8,7 -> 4 + 2).
    fn smoke_p2pdma_acs_and_host_bridge_rules() -> TestResult {
        let mut t = tree();
        t.acs[3] = true;
        if map_type_and_distance(&t, 4, 5) != (P2pMapType::NotSupported, 4)
            || distance(&t, 4, Some(5)).is_some()
        {
            return TestResult::Fail("ACS redirect did not leave the switch path");
        }
        t.zen = true;
        if map_type_and_distance(&t, 4, 5) != (P2pMapType::ThruHostBridge, 4) {
            return TestResult::Fail("Zen CPU did not admit the host-bridge path");
        }
        // The common upstream port's own ACS counts too (provider walk).
        let mut t = tree();
        t.acs[1] = true;
        if map_type_and_distance(&t, 4, 5).0 != P2pMapType::NotSupported {
            return TestResult::Fail("common bridge ACS ignored");
        }
        let mut t = tree();
        if map_type_and_distance(&t, 4, 8) != (P2pMapType::NotSupported, 6) {
            return TestResult::Fail("cross-root-port distance or support");
        }
        // Skylake-E root (no REQ_SAME_HOST_BRIDGE) admits disjoint host bridges.
        t.host_dev = Some(HostBridgeDev {
            vendor: 0x8086,
            device: 0x2030,
        });
        t.host[7] = 2;
        if map_type_and_distance(&t, 4, 8) != (P2pMapType::ThruHostBridge, 6) {
            return TestResult::Fail("whitelisted Skylake-E root refused");
        }
        // Haswell client root requires the same host bridge.
        t.host_dev = Some(HostBridgeDev {
            vendor: 0x8086,
            device: 0x0c08,
        });
        if distance(&t, 4, Some(8)).is_some() {
            return TestResult::Fail("REQ_SAME_HOST_BRIDGE admitted two host bridges");
        }
        t.host[7] = 1;
        if distance(&t, 4, Some(8)) != Some(6) {
            return TestResult::Fail("REQ_SAME_HOST_BRIDGE refused one host bridge");
        }
        // Google is PCI_ANY_ID; a missing host-bridge device is refused.
        t.host_dev = Some(HostBridgeDev {
            vendor: 0x1ae0,
            device: 0x1234,
        });
        if distance(&t, 4, Some(8)) != Some(6) {
            return TestResult::Fail("PCI_ANY_ID whitelist entry refused");
        }
        t.host_dev = None;
        if distance(&t, 4, Some(8)).is_some() {
            return TestResult::Fail("absent host-bridge device admitted");
        }
        if !acs_ctrl_redirects(PCI_ACS_EC) || acs_ctrl_redirects(0x0053) {
            return TestResult::Fail("ACS redirect bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("io/p2pdma", smoke_p2pdma_acs_and_host_bridge_rules);
}
