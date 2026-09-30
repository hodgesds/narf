//! Configuration-device model: exercises ownership, rollback and handshake order.
use super::*;
use alloc::collections::BTreeMap;
use narf_kernel_test::{kernel_test_in, TestResult};

type Key = (u64, u8, u8, u16);
#[derive(Default)]
pub(crate) struct Model {
    words: BTreeMap<Key, u32>,
    fail_enable: bool,
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
            if self.fail_enable
                && space == CfgSpace::Port
                && route == 1
                && port == 5
                && offset == 32
                && value & (1 << 31) != 0
            {
                // Device consumed the write before reporting a transient error.
                self.put(route, port, space, offset, value);
                self.fail_enable = false;
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
            if space == CfgSpace::Port && offset == 38 && port == 5 {
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
fn model() -> (Domain, Model) {
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
