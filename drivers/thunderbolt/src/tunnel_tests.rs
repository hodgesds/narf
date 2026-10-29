//! Configuration-device model: exercises ownership, rollback and handshake order.
use super::*;
use alloc::collections::BTreeMap;
use narf_kernel_test::{kernel_test_in, TestResult};

type Key = (u64, u8, u8, u16);
#[derive(Default)]
pub(crate) struct Model {
    words: BTreeMap<Key, u32>,
    fail_enable: bool,
    fail_enable_at: Option<(u64, u8)>,
    fail_disable: bool,
    pending: Option<Key>,
    pending_reads: usize,
    released_early: bool,
}
impl Model {
    pub(crate) fn get(&self, route: u64, port: u8, space: CfgSpace, offset: u16) -> u32 {
        self.words
            .get(&(route, port, space as u8, offset))
            .copied()
            .unwrap_or(0)
    }
    pub(crate) fn put(&mut self, route: u64, port: u8, space: CfgSpace, offset: u16, value: u32) {
        self.words.insert((route, port, space as u8, offset), value);
    }
    /// Arm the one-shot failure of the next adapter-disable write
    /// (the write teardown's rollback performs), modelling a
    /// transport that dies mid-teardown.
    pub(crate) fn set_fail_disable(&mut self) {
        self.fail_disable = true;
    }
    /// Arm the one-shot failure of the adapter-enable write at
    /// (`route`, `port`) — the adapter capability DWORD 0 write
    /// with bit 31 set, at the fixture adapter-cap offset 32 — with
    /// the same consumed-then-error semantics as `fail_enable`.
    pub(crate) fn set_fail_enable_at(&mut self, route: u64, port: u8) {
        self.fail_enable_at = Some((route, port));
    }
}
impl Config for Model {
    async fn read(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        len: u8,
    ) -> Result<Vec<u32>, Error> {
        let mut result = Vec::new();
        for offset in offset..offset + len as u16 {
            let key = (route, port, space as u8, offset);
            let mut value = self.get(route, port, space, offset);
            if self.pending == Some(key) {
                self.pending_reads += 1;
                if self.pending_reads <= 2 {
                    value |= 1 << 28;
                } else {
                    self.pending = None;
                }
            }
            result.push(value);
        }
        Ok(result)
    }
    async fn write(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        data: &[u32],
    ) -> Result<(), Error> {
        for (i, value) in data.iter().copied().enumerate() {
            let offset = offset + i as u16;
            // Pending is device-owned status in hop DWORD 1. Software writes
            // must not latch it into the model's persistent register value.
            let value = if space == CfgSpace::Hops && offset % 2 == 1 {
                value & !(1 << 28)
            } else {
                value
            };
            if self.fail_disable
                && space == CfgSpace::Port
                && route == 1
                && port == 5
                && offset == 32
                && value & (1 << 31) == 0
            {
                self.fail_disable = false;
                return Err(Error::Remote(1));
            }
            if space == CfgSpace::Port
                && offset == 32
                && value & (1 << 31) != 0
                && ((self.fail_enable && route == 1 && port == 5)
                    || self.fail_enable_at == Some((route, port)))
            {
                // Device consumed the write before reporting a transient error.
                self.put(route, port, space, offset, value);
                self.fail_enable = false;
                self.fail_enable_at = None;
                return Err(Error::Remote(1));
            }
            if space == CfgSpace::Port && offset == 4 && value & 1023 == 0 && self.pending.is_some()
            {
                self.released_early = true;
            }
            self.put(route, port, space, offset, value);
            if space == CfgSpace::Switch && offset == 26 {
                self.put(route, port, space, offset, 0);
                if value & 0xffff == 0x33 {
                    self.put(route, port, space, 25, 3);
                    for (i, item) in [1 | (6 << 16), 2 | (2 << 16), 3 | (12 << 16)]
                        .into_iter()
                        .enumerate()
                    {
                        self.put(route, port, space, 9 + i as u16, item);
                    }
                }
            }
            // A DP OUT adapter's CMHS (DP_STATUS_CTRL bit 25) clears
            // once the handshake completes. DP OUT adapters sit on
            // device routers here; on a host DP IN adapter the same
            // DWORD is DP_STATUS, whose bit 25 belongs to ALLOCATED_BW.
            if space == CfgSpace::Port && offset == 38 && port == 5 && route != 0 {
                self.put(route, port, space, offset, value & !(1 << 25));
            }
            if space == CfgSpace::Port && offset == 34 && port == 3 {
                let consumed = self.get(route, port, space, 33) & !(1 << 31);
                self.put(route, port, space, 33, consumed | (value & (1 << 31)));
            }
        }
        Ok(())
    }
}
pub(crate) fn model() -> (Domain, Model) {
    let mut ports = Vec::new();
    for (number, kind, cap) in [(1, 1, 0), (3, 0x200101, 32), (5, 0x0e0101, 32)] {
        ports.push(Port {
            number,
            kind,
            adapter_cap: cap,
            phy_cap: 8,
            usb4_cap: 64,
            max_in_hop: 15,
            max_out_hop: 15,
            total_credits: 64,
            secondary: false,
            retimers: Vec::new(),
            retimer_fault: None,
        });
    }
    let host = Router {
        route: 0,
        upstream: 0,
        vendor: 0x1022,
        device: 1,
        ports: ports.clone(),
    };
    ports[1].kind = 0x200102;
    ports[2].kind = 0x0e0102;
    let child = Router {
        route: 1,
        upstream: 1,
        vendor: 0x8086,
        device: 2,
        ports,
    };
    let mut m = Model::default();
    for route in [0, 1] {
        m.put(route, 5, CfgSpace::Port, 36, 2 << 12);
        m.put(route, 1, CfgSpace::Port, 4, 64 << 20);
        m.put(route, 3, CfgSpace::Port, 35, 7);
    }
    m.put(1, 5, CfgSpace::Port, 34, 1 << 6);
    (
        Domain {
            id: u32::MAX,
            routers: alloc::vec![host, child],
        },
        m,
    )
}
fn tunnel(protocol: Protocol) -> Tunnel {
    let port = if protocol == Protocol::DisplayPort {
        5
    } else {
        3
    };
    Tunnel {
        display: TunnelInfo {
            domain: u32::MAX,
            input: Endpoint { route: 0, port },
            output: Endpoint { route: 1, port },
            protocol,
            dprx_done: false,
            dp: None,
            consumed_mbps: 0,
        },
        writes: Vec::new(),
        resource: false,
        hpd_owned: false,
        bandwidth: None,
    }
}
fn usb4_tunnel_activate_drain_and_rollback() -> TestResult {
    let (d, mut m) = model();
    let mut t = tunnel(Protocol::DisplayPort);
    if narf_scheduler::block_on_spin(t.activate(&mut m, &d)).is_err() || t.writes.is_empty() {
        return TestResult::Fail("DP path activation");
    }
    // Simulate in-flight data in the child's video hop when teardown starts.
    m.pending = Some((1, 1, CfgSpace::Hops as u8, 17));
    if narf_scheduler::block_on_spin(t.teardown(&mut m, &d)).is_err()
        || m.released_early
        || m.pending_reads < 3
        || !t.writes.is_empty()
        || m.get(1, 1, CfgSpace::Port, 4) != 64 << 20
        || m.get(0, 5, CfgSpace::Hops, 18) & (1 << 31) != 0
    {
        return TestResult::Fail("path must drain before credit release");
    }
    let (d, mut m) = model();
    m.fail_enable = true;
    let mut t = tunnel(Protocol::DisplayPort);
    if narf_scheduler::block_on_spin(t.activate(&mut m, &d)) != Err(Error::Remote(1))
        || narf_scheduler::block_on_spin(t.teardown(&mut m, &d)).is_err()
        || m.get(1, 5, CfgSpace::Port, 32) & (3 << 30) != 0
        || t.resource
        || !t.writes.is_empty()
    {
        return TestResult::Fail("consumed failed write must also roll back");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_tunnel_activate_drain_and_rollback
);
fn usb4_usb3_bandwidth_and_existing_owner() -> TestResult {
    let (d, mut m) = model();
    let mut t = tunnel(Protocol::Usb3);
    if narf_scheduler::block_on_spin(t.activate(&mut m, &d)).is_err()
        || m.get(0, 3, CfgSpace::Port, 34) & 0xffffff == 0
        || m.get(0, 3, CfgSpace::Port, 34) & (1 << 31) != 0
    {
        return TestResult::Fail("USB3 allocation handshake");
    }
    if narf_scheduler::block_on_spin(t.teardown(&mut m, &d)).is_err()
        || m.get(0, 3, CfgSpace::Port, 34) != 0
        || m.get(0, 3, CfgSpace::Port, 32) != 1 << 30
    {
        return TestResult::Fail("USB3 bandwidth/valid-enable rollback");
    }
    m.put(0, 3, CfgSpace::Port, 32, 3 << 30);
    if narf_scheduler::block_on_spin(t.activate(&mut m, &d)) != Err(Error::Full)
        || !t.writes.is_empty()
        || bandwidth_units(63, 0) != Err(Error::Invalid)
    {
        return TestResult::Fail("firmware-owned tunnel or invalid scale accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_usb3_bandwidth_and_existing_owner
);

fn usb4_reconcile_retains_failed_cleanup() -> TestResult {
    let (d, mut m) = model();
    m.fail_enable = true;
    m.fail_disable = true;
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2))
        != Err(Error::Remote(1))
        || tunnels.len() != 1
        || tunnels[0].writes.is_empty()
    {
        return TestResult::Fail("failed rollback lost owned tunnel journal");
    }
    if narf_scheduler::block_on_spin(tunnels[0].teardown(&mut m, &d)).is_err()
        || !tunnels[0].writes.is_empty()
        || tunnels[0].resource
    {
        return TestResult::Fail("retry must complete retained rollback");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_reconcile_retains_failed_cleanup
);

// -- PCIe tunnelling (USB4 _OSC PCIe bit, ADP_PCIE_CS_0) -------
//
// The hop-entry expectations below are pinned against the USB4
// path configuration layout (TB_CFG_HOPS entry: DWORD 0 = next
// HopID [10:0] | out port [16:11] | initial credits [24:17] |
// enable [31]; DWORD 1 = weight [3:0] | priority [10:8] |
// ingress FC [24] | egress FC [25] | pending [28]), the protocol
// adapter ingress HopID 8, and the PCIe buffer-allocation credit
// (2) the model's router allocation table reports for protocol 2 —
// not against values read back from the production encoder.

fn pcie_port(number: u8, kind: u32, adapter_cap: u16) -> Port {
    Port {
        number,
        kind,
        adapter_cap,
        phy_cap: if kind == 1 { 8 } else { 0 },
        usb4_cap: 64,
        max_in_hop: 15,
        max_out_hop: 15,
        total_credits: 64,
        secondary: false,
        retimers: Vec::new(),
        retimer_fault: None,
    }
}

/// Two-router PCIe topology: host PCIe downstream adapter on port
/// 7, device-router PCIe upstream adapter on port 7, one lane link.
pub(crate) fn pcie_model() -> (Domain, Model) {
    let host = Router {
        route: 0,
        upstream: 0,
        vendor: 0x1022,
        device: 1,
        ports: alloc::vec![pcie_port(1, 1, 0), pcie_port(7, 0x100101, 32)],
    };
    let child = Router {
        route: 1,
        upstream: 1,
        vendor: 0x8086,
        device: 2,
        ports: alloc::vec![pcie_port(1, 1, 0), pcie_port(7, 0x100102, 32)],
    };
    let mut m = Model::default();
    for route in [0, 1] {
        m.put(route, 1, CfgSpace::Port, 4, 64 << 20);
    }
    (
        Domain {
            id: u32::MAX,
            routers: alloc::vec![host, child],
        },
        m,
    )
}

/// The hop entry programmed for ingress HopID 8 on (`route`,
/// `port`) — protocol adapters and the first allocated lane hop
/// both land on ID 8 in these fixtures.
fn hop8(m: &Model, route: u64, port: u8) -> [u32; 2] {
    [
        m.get(route, port, CfgSpace::Hops, 16),
        m.get(route, port, CfgSpace::Hops, 17),
    ]
}

fn usb4_pcie_tunnel_paths_and_adapter_enable() -> TestResult {
    // The published registries are global across fixtures in the
    // boot; start from a known-empty publication state.
    forget_domain(u32::MAX);
    let (d, mut m) = pcie_model();
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 7)).is_err()
        || tunnels.len() != 1
        || tunnels[0].display.protocol != Protocol::Pcie
        || tunnels[0].display.input != (Endpoint { route: 0, port: 7 })
        || tunnels[0].display.output != (Endpoint { route: 1, port: 7 })
    {
        return TestResult::Fail("PCIe tunnel not established through reconcile");
    }
    // Down path: (0, PCIe-DOWN) -> (1, lane); Up path: (1, PCIe-UP)
    // -> (0, lane). Adapter hops preserve the adapter's fields
    // (zero here); lane hops carry the PCIe credit and FC bits.
    if hop8(&m, 0, 7) != [0x8000_0808, 0x0200_0201]
        || hop8(&m, 1, 1) != [0x8004_3808, 0x0100_0201]
        || hop8(&m, 1, 7) != [0x8000_0808, 0x0200_0201]
        || hop8(&m, 0, 1) != [0x8004_3808, 0x0100_0201]
    {
        return TestResult::Fail("PCIe hop programming differs from the spec layout");
    }
    // ADP_PCIE_CS_0 PE set at both ends; tunnel and grant state
    // published explicitly.
    if m.get(0, 7, CfgSpace::Port, 32) != 1 << 31
        || m.get(1, 7, CfgSpace::Port, 32) != 1 << 31
        || pcie_tunnels().len() != 1
        || live_tunnel_count() != 1
        || granted_controls() != 7
        || !pcie_tunnelling_granted()
    {
        return TestResult::Fail("PCIe adapters not enabled or tunnel not published");
    }
    if narf_scheduler::block_on_spin(tunnels[0].teardown(&mut m, &d)).is_err()
        || !tunnels[0].writes.is_empty()
        || hop8(&m, 0, 7) != [0, 0]
        || hop8(&m, 1, 1) != [0, 0]
        || hop8(&m, 1, 7) != [0, 0]
        || hop8(&m, 0, 1) != [0, 0]
        || m.get(0, 7, CfgSpace::Port, 32) != 0
        || m.get(1, 7, CfgSpace::Port, 32) != 0
        || live_tunnel_count() != 0
    {
        return TestResult::Fail("PCIe teardown did not restore paths and adapters");
    }
    forget_domain(u32::MAX);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_pcie_tunnel_paths_and_adapter_enable
);

fn usb4_pcie_denied_grant_programs_nothing() -> TestResult {
    forget_domain(u32::MAX);
    let (d, mut m) = pcie_model();
    let mut tunnels = Vec::new();
    // USB3 + DisplayPort granted, PCIe denied (_OSC DWORD 2 = 0b011):
    // no PCIe programming, and the denied state is explicit.
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 3)).is_err()
        || !tunnels.is_empty()
        || !pcie_tunnels().is_empty()
        || granted_controls() != 3
        || pcie_tunnelling_granted()
    {
        return TestResult::Fail("PCIe state not explicit under a denied grant");
    }
    if hop8(&m, 0, 7) != [0, 0]
        || hop8(&m, 1, 1) != [0, 0]
        || hop8(&m, 1, 7) != [0, 0]
        || hop8(&m, 0, 1) != [0, 0]
        || m.get(0, 7, CfgSpace::Port, 32) != 0
        || m.get(1, 7, CfgSpace::Port, 32) != 0
    {
        return TestResult::Fail("PCIe path programmed without the _OSC grant");
    }
    // Same topology with the grant: the tunnel establishes, so the
    // gate is the grant, not the topology.
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 7)).is_err()
        || tunnels.len() != 1
        || m.get(1, 7, CfgSpace::Port, 32) != 1 << 31
    {
        return TestResult::Fail("PCIe tunnel not established once granted");
    }
    forget_domain(u32::MAX);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_pcie_denied_grant_programs_nothing
);

fn usb4_pcie_enable_failure_rolls_back() -> TestResult {
    forget_domain(u32::MAX);
    let (d, mut m) = pcie_model();
    // The device router consumes the PCIe-UP enable write and then
    // reports a transient error: paths and the host-side enable must
    // roll back, and the consumed write must be restored too.
    m.set_fail_enable_at(1, 7);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 7)).is_err()
        || !tunnels.is_empty()
        || !pcie_tunnels().is_empty()
    {
        return TestResult::Fail("failed PCIe enable retained the tunnel");
    }
    if hop8(&m, 0, 7) != [0, 0]
        || hop8(&m, 1, 1) != [0, 0]
        || hop8(&m, 1, 7) != [0, 0]
        || hop8(&m, 0, 1) != [0, 0]
        || m.get(0, 7, CfgSpace::Port, 32) != 0
        || m.get(1, 7, CfgSpace::Port, 32) != 0
    {
        return TestResult::Fail("consumed PCIe enable write or paths not rolled back");
    }
    forget_domain(u32::MAX);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_pcie_enable_failure_rolls_back
);

fn usb4_pcie_firmware_owned_adapter_untouched() -> TestResult {
    forget_domain(u32::MAX);
    let (d, mut m) = pcie_model();
    // Firmware already enabled the device router's PCIe adapter:
    // the CM must refuse to claim it and write nothing.
    m.put(1, 7, CfgSpace::Port, 32, 1 << 31);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 7)).is_err()
        || !tunnels.is_empty()
        || !pcie_tunnels().is_empty()
        || m.get(1, 7, CfgSpace::Port, 32) != 1 << 31
        || m.get(0, 7, CfgSpace::Port, 32) != 0
        || hop8(&m, 0, 7) != [0, 0]
        || hop8(&m, 1, 1) != [0, 0]
    {
        return TestResult::Fail("firmware-owned PCIe adapter overwritten or claimed");
    }
    forget_domain(u32::MAX);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_pcie_firmware_owned_adapter_untouched
);

/// Three-router chain: host (PCIe down) -> mid (lane ports 1 and 3,
/// optionally PCIe up/down) -> leaf at route 0x301 (PCIe up).
fn pcie_chain_model(mid_pcie: bool) -> (Domain, Model) {
    let host = Router {
        route: 0,
        upstream: 0,
        vendor: 0x1022,
        device: 1,
        ports: alloc::vec![pcie_port(1, 1, 0), pcie_port(7, 0x100101, 32)],
    };
    let mut mid_ports = alloc::vec![pcie_port(1, 1, 0), pcie_port(3, 1, 0)];
    if mid_pcie {
        mid_ports.push(pcie_port(7, 0x100102, 32));
        mid_ports.push(pcie_port(8, 0x100101, 32));
    }
    let mid = Router {
        route: 1,
        upstream: 1,
        vendor: 0x8086,
        device: 2,
        ports: mid_ports,
    };
    let leaf = Router {
        route: 0x301,
        upstream: 1,
        vendor: 0x8086,
        device: 3,
        ports: alloc::vec![pcie_port(1, 1, 0), pcie_port(7, 0x100102, 32)],
    };
    let mut m = Model::default();
    for route in [0, 1, 0x301] {
        m.put(route, 1, CfgSpace::Port, 4, 64 << 20);
    }
    (
        Domain {
            id: u32::MAX,
            routers: alloc::vec![host, mid, leaf],
        },
        m,
    )
}

// ── Tunnel suspend / resume replay (#1035) ────────────────────
//
// The PM handler verdicts are exercised through `pm_on_suspend` /
// `pm_on_resume` — the exact functions `pm.rs`'s registered
// handlers delegate to — and the quiesce/replay work through the
// service functions `topology::run` calls. The fan-out wiring of
// those verdicts is covered by the pm fixtures.

use narf_power::device_pm::DeviceSuspendError;

/// The fabric state the paths own: every Hops word plus every
/// Port word, as a register map. Switch-space words are mailbox
/// registers (router operations), not path state, and are excluded.
fn fabric(m: &Model) -> BTreeMap<Key, u32> {
    m.words
        .iter()
        .filter(|(k, _)| k.2 != CfgSpace::Switch as u8)
        .map(|(k, v)| (*k, *v))
        .collect()
}

fn fabric_diff(a: &BTreeMap<Key, u32>, b: &BTreeMap<Key, u32>) -> Vec<Key> {
    let mut keys: Vec<Key> = a.keys().chain(b.keys()).copied().collect();
    keys.sort_unstable();
    keys.dedup();
    // Compare register VALUES, not map membership. The model's map
    // records every word ever written, so a word teardown restored
    // to 0 stays present in the map while a never-written word is
    // absent — yet both read as 0 on the device, and the register
    // value is the fabric state this comparison means. Comparing
    // `Option<&u32>` instead made every restored-to-zero word (each
    // journaled hop and adapter word, the USB3 handshake words) a
    // spurious difference, so the drained fabric could never equal
    // the pre-activation fabric even with a perfect rollback.
    keys.into_iter()
        .filter(|k| a.get(k).copied().unwrap_or(0) != b.get(k).copied().unwrap_or(0))
        .collect()
}

fn usb4_tunnel_suspend_replay_cycle() -> TestResult {
    forget_domain(u32::MAX);
    __reset_pm_for_test();
    let (d, mut m) = model();
    let pre = fabric(&m);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 3)).is_err()
        || tunnels.len() != 2
    {
        return TestResult::Fail("model did not activate USB3 + DP tunnels");
    }
    let active = fabric(&m);
    if active == pre {
        return TestResult::Fail("activation programmed no path state");
    }
    // First suspend attempt: the handler latches the quiesce and
    // refuses; nothing has drained yet.
    if pm_on_suspend() != Err(DeviceSuspendError::Busy)
        || live_tunnel_count() != 2
        || !suspended_tunnels().is_empty()
    {
        return TestResult::Fail("first suspend did not latch a quiesce as Busy");
    }
    // The CM service pass drains both paths and records them.
    if narf_scheduler::block_on_spin(service_pm_suspend(&mut m, &d, &mut tunnels)).is_err()
        || !tunnels.is_empty()
        || live_tunnel_count() != 0
        || suspended_tunnels().len() != 2
    {
        return TestResult::Fail("quiesce did not drain and record the tunnels");
    }
    // Drained fabric: every path word is back at its pre-activation
    // value. The tolerated differences are words teardown
    // deliberately does not restore to the power-on value: the
    // DP-in HPD deassert (0,5,Port,35) and the CMHS handshake word
    // (1,5,Port,38) — one-way notifications, not path
    // configuration — and the USB3 adapters' resting value
    // (Port,32) = 1<<30 at both ends, the teardown contract the
    // USB3 bandwidth fixture already pins.
    let drained = fabric(&m);
    let diff = fabric_diff(&drained, &pre);
    let tolerated = [
        (0, 5, CfgSpace::Port as u8, 35),
        (1, 5, CfgSpace::Port as u8, 38),
        (0, 3, CfgSpace::Port as u8, 32),
        (1, 3, CfgSpace::Port as u8, 32),
    ];
    if diff.iter().any(|k| !tolerated.contains(k)) {
        return TestResult::Fail("quiesce did not restore the pre-activation fabric");
    }
    if pm_on_suspend() != Ok(()) {
        return TestResult::Fail("quiesced domain still vetoes suspend");
    }
    // Resume: latch, then replay against the same topology. The
    // replayed fabric must equal the originally programmed fabric
    // word-for-word — hop-for-hop — apart from the HPD deassert
    // word, which replay does not rewrite (the sink's HPD never
    // dropped in the model, so there is nothing to re-assert).
    if pm_on_resume() != Ok(()) {
        return TestResult::Fail("resume latch failed with quiesced tunnels");
    }
    if narf_scheduler::block_on_spin(service_pm_resume(&mut m, &d, &mut tunnels)).is_err()
        || tunnels.len() != 2
        || live_tunnel_count() != 2
        || !suspended_tunnels().is_empty()
    {
        return TestResult::Fail("replay did not restore the tunnels");
    }
    let replayed = fabric(&m);
    let diff = fabric_diff(&replayed, &active);
    if diff.iter().any(|k| *k != (0, 5, CfgSpace::Port as u8, 35)) {
        return TestResult::Fail("replayed fabric differs from the original programming");
    }
    // Traffic-shaping state is restored, not merely reconnected:
    // the USB3 allocation word carries the handshake allocation
    // again, and both DP adapters are enabled.
    if m.get(0, 3, CfgSpace::Port, 34) & 0x00ff_ffff == 0
        || m.get(0, 5, CfgSpace::Port, 32) & (3 << 30) != 3 << 30
        || m.get(1, 5, CfgSpace::Port, 32) & (3 << 30) != 3 << 30
    {
        return TestResult::Fail("replay did not restore credits/bandwidth and enables");
    }
    // Vanished peer: quiesce again, then resume against a topology
    // whose child router is gone. The records are torn down, not
    // replayed — nothing programmed, nothing stranded, no failure.
    if pm_on_suspend() != Err(DeviceSuspendError::Busy)
        || narf_scheduler::block_on_spin(service_pm_suspend(&mut m, &d, &mut tunnels)).is_err()
        || pm_on_suspend() != Ok(())
        || pm_on_resume() != Ok(())
    {
        return TestResult::Fail("second quiesce cycle did not latch cleanly");
    }
    let host_only = Domain {
        id: u32::MAX,
        routers: alloc::vec![d.routers[0].clone()],
    };
    if narf_scheduler::block_on_spin(service_pm_resume(&mut m, &host_only, &mut tunnels)).is_err()
        || !tunnels.is_empty()
        || live_tunnel_count() != 0
        || !suspended_tunnels().is_empty()
        || !replay_failures().is_empty()
        || pm_on_suspend() != Ok(())
    {
        return TestResult::Fail("vanished peer was replayed or stranded state");
    }
    forget_domain(u32::MAX);
    __reset_pm_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_tunnel_suspend_replay_cycle
);

fn usb4_pcie_tunnel_suspend_replay() -> TestResult {
    forget_domain(u32::MAX);
    __reset_pm_for_test();
    let (d, mut m) = pcie_model();
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 7)).is_err()
        || tunnels.len() != 1
    {
        return TestResult::Fail("PCIe tunnel not established");
    }
    if pm_on_suspend() != Err(DeviceSuspendError::Busy)
        || narf_scheduler::block_on_spin(service_pm_suspend(&mut m, &d, &mut tunnels)).is_err()
        || !tunnels.is_empty()
        || live_tunnel_count() != 0
        || suspended_tunnels().len() != 1
        || hop8(&m, 0, 7) != [0, 0]
        || hop8(&m, 1, 1) != [0, 0]
        || hop8(&m, 1, 7) != [0, 0]
        || hop8(&m, 0, 1) != [0, 0]
        || m.get(0, 7, CfgSpace::Port, 32) != 0
        || m.get(1, 7, CfgSpace::Port, 32) != 0
        || pm_on_suspend() != Ok(())
    {
        return TestResult::Fail("PCIe quiesce did not drain paths and adapters");
    }
    if pm_on_resume() != Ok(())
        || narf_scheduler::block_on_spin(service_pm_resume(&mut m, &d, &mut tunnels)).is_err()
        || tunnels.len() != 1
        || pcie_tunnels().len() != 1
        || hop8(&m, 0, 7) != [0x8000_0808, 0x0200_0201]
        || hop8(&m, 1, 1) != [0x8004_3808, 0x0100_0201]
        || hop8(&m, 1, 7) != [0x8000_0808, 0x0200_0201]
        || hop8(&m, 0, 1) != [0x8004_3808, 0x0100_0201]
        || m.get(0, 7, CfgSpace::Port, 32) != 1 << 31
        || m.get(1, 7, CfgSpace::Port, 32) != 1 << 31
    {
        return TestResult::Fail("PCIe replay did not restore the pinned hop programming");
    }
    forget_domain(u32::MAX);
    __reset_pm_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_pcie_tunnel_suspend_replay
);

fn usb4_tunnel_replay_failure_surfaces_and_retries() -> TestResult {
    forget_domain(u32::MAX);
    __reset_pm_for_test();
    let (d, mut m) = model();
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err()
        || tunnels.len() != 1
        || pm_on_suspend() != Err(DeviceSuspendError::Busy)
        || narf_scheduler::block_on_spin(service_pm_suspend(&mut m, &d, &mut tunnels)).is_err()
        || pm_on_suspend() != Ok(())
    {
        return TestResult::Fail("DP tunnel did not quiesce");
    }
    // The device router consumes the replay's adapter-enable write
    // and reports a transient error: the replay must roll back
    // (never half-up), and the tunnel must be named as a failure.
    m.fail_enable = true;
    if pm_on_resume() != Ok(())
        || narf_scheduler::block_on_spin(service_pm_resume(&mut m, &d, &mut tunnels)).is_err()
        || !tunnels.is_empty()
        || live_tunnel_count() != 0
        || !suspended_tunnels().is_empty()
        || replay_failures().len() != 1
        || m.get(1, 5, CfgSpace::Port, 32) & (3 << 30) != 0
    {
        return TestResult::Fail("failed replay was left half-up or not recorded");
    }
    // The failure is explicit in both handlers' verdicts: suspend
    // stays refused, and the resume fan-out reports DriverError —
    // while re-queueing the failed tunnel for one retry.
    if pm_on_suspend() != Err(DeviceSuspendError::Busy)
        || pm_on_resume() != Err(DeviceSuspendError::DriverError)
        || suspended_tunnels().len() != 1
        || !replay_failures().is_empty()
    {
        return TestResult::Fail("replay failure not surfaced or not re-queued");
    }
    if narf_scheduler::block_on_spin(service_pm_resume(&mut m, &d, &mut tunnels)).is_err()
        || tunnels.len() != 1
        || live_tunnel_count() != 1
        || !replay_failures().is_empty()
        || pm_on_resume() != Ok(())
    {
        return TestResult::Fail("retried replay did not restore the tunnel");
    }
    forget_domain(u32::MAX);
    __reset_pm_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_tunnel_replay_failure_surfaces_and_retries
);

fn usb4_tunnel_quiesce_failure_stays_busy() -> TestResult {
    forget_domain(u32::MAX);
    __reset_pm_for_test();
    let (d, mut m) = model();
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err()
        || tunnels.len() != 1
    {
        return TestResult::Fail("DP tunnel not established");
    }
    // The transport dies during the quiesce teardown's rollback:
    // the journal is retained, the request stays latched, and the
    // handler's verdict stays a scoped Busy — never an Ok over
    // live paths.
    m.set_fail_disable();
    if pm_on_suspend() != Err(DeviceSuspendError::Busy)
        || narf_scheduler::block_on_spin(service_pm_suspend(&mut m, &d, &mut tunnels)).is_ok()
        || tunnels.len() != 1
        || !tunnels[0].has_unrolled_writes()
        || !suspended_tunnels().is_empty()
        || pm_on_suspend() != Err(DeviceSuspendError::Busy)
    {
        return TestResult::Fail("failed quiesce was reported as suspended");
    }
    // The one-shot fault is consumed; the retried quiesce completes
    // and the cycle closes cleanly.
    if narf_scheduler::block_on_spin(service_pm_suspend(&mut m, &d, &mut tunnels)).is_err()
        || pm_on_suspend() != Ok(())
        || pm_on_resume() != Ok(())
        || narf_scheduler::block_on_spin(service_pm_resume(&mut m, &d, &mut tunnels)).is_err()
        || live_tunnel_count() != 1
    {
        return TestResult::Fail("retried quiesce/replay did not complete the cycle");
    }
    forget_domain(u32::MAX);
    __reset_pm_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_tunnel_quiesce_failure_stays_busy
);

fn usb4_pcie_nearest_ancestor_pairing() -> TestResult {
    forget_domain(u32::MAX);
    // Mid carries its own PCIe adapters: the leaf's tunnel
    // originates at mid (nearest ancestor with a downstream
    // adapter), the host's adapter serves mid's tunnel only.
    let (d, mut m) = pcie_chain_model(true);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 7)).is_err()
        || tunnels.len() != 2
        || !tunnels.iter().any(|t| {
            t.display.input == Endpoint { route: 0, port: 7 }
                && t.display.output == Endpoint { route: 1, port: 7 }
        })
        || !tunnels.iter().any(|t| {
            t.display.input == Endpoint { route: 1, port: 8 }
                && t.display.output
                    == Endpoint {
                        route: 0x301,
                        port: 7,
                    }
        })
        || pcie_tunnels().len() != 2
        || m.get(1, 8, CfgSpace::Port, 32) != 1 << 31
        || m.get(0x301, 7, CfgSpace::Port, 32) != 1 << 31
    {
        return TestResult::Fail("chained PCIe routers not paired with nearest ancestors");
    }
    forget_domain(u32::MAX);
    // Mid carries no PCIe adapters: the leaf's tunnel originates at
    // the host and transits mid's lane adapters — the forward
    // transit hop on mid's upstream lane port (out port 3) and the
    // return hop on mid's downstream lane port (out port 1) are
    // both programmed, at distinct per-port hop spaces.
    let (d, mut m) = pcie_chain_model(false);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 7)).is_err()
        || tunnels.len() != 1
        || tunnels[0].display.input != (Endpoint { route: 0, port: 7 })
        || tunnels[0].display.output
            != (Endpoint {
                route: 0x301,
                port: 7,
            })
        || hop8(&m, 1, 1) != [0x8004_1808, 0x0300_0201]
        || hop8(&m, 1, 3) != [0x8004_0808, 0x0300_0201]
    {
        return TestResult::Fail("PCIe tunnel did not span the PCIe-less intermediate router");
    }
    forget_domain(u32::MAX);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/tunnel",
    usb4_pcie_nearest_ancestor_pairing
);
