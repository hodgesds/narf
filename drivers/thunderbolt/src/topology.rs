//! Live USB4 router enumeration. Bounded capability chains and topology depth;
//! router identities are scoped by NHI domain, never by a global last device.
use super::{
    cm::{compose_downstream, route_depth, CfgSpace},
    control::{Config, Control},
    ring::Error,
};
use alloc::vec::Vec;
use core::fmt::Write as _;
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    pub number: u8,
    pub kind: u32,
    pub adapter_cap: u16,
    pub phy_cap: u16,
    pub usb4_cap: u16,
    pub max_in_hop: u16,
    pub max_out_hop: u16,
    pub total_credits: u16,
    pub secondary: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Router {
    pub route: u64,
    pub upstream: u8,
    pub vendor: u16,
    pub device: u16,
    pub ports: Vec<Port>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    pub id: u32,
    pub routers: Vec<Router>,
}
static DOMAINS: IrqSafeSpinLock<Vec<Domain>> = IrqSafeSpinLock::new(Vec::new());
pub fn domains() -> Vec<Domain> {
    DOMAINS.lock().clone()
}

pub(crate) async fn wait_bit(
    ctl: &mut impl Config,
    route: u64,
    offset: u16,
    bit: u32,
    set: bool,
) -> Result<u32, Error> {
    let deadline = narf_time::Deadline::after_ms(500);
    loop {
        let value = ctl.read(route, 0, CfgSpace::Switch, offset, 1).await?[0];
        if (value & bit != 0) == set {
            return Ok(value);
        }
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
    }
}
pub(crate) async fn router_operation(
    ctl: &mut impl Config,
    route: u64,
    opcode: u16,
    metadata: u32,
) -> Result<(u8, u32), Error> {
    ctl.write(route, 0, CfgSpace::Switch, 25, &[metadata])
        .await?;
    ctl.write(route, 0, CfgSpace::Switch, 26, &[opcode as u32 | (1 << 31)])
        .await?;
    let value = wait_bit(ctl, route, 26, 1 << 31, false).await?;
    if value & (1 << 30) != 0 {
        return Err(Error::Remote(0xff));
    }
    let metadata = ctl.read(route, 0, CfgSpace::Switch, 25, 1).await?[0];
    Ok((((value >> 24) & 63) as u8, metadata))
}
async fn port(ctl: &mut impl Config, route: u64, number: u8) -> Result<Port, Error> {
    let hdr = ctl.read(route, number, CfgSpace::Port, 0, 8).await?;
    let mut p = Port {
        number,
        kind: hdr[2] & 0xffffff,
        adapter_cap: 0,
        phy_cap: 0,
        usb4_cap: 0,
        max_in_hop: (hdr[5] & 2047) as u16,
        max_out_hop: ((hdr[5] >> 11) & 2047) as u16,
        total_credits: ((hdr[4] >> 20) & 1023) as u16,
        secondary: false,
    };
    let mut next = (hdr[1] & 255) as u16;
    let mut seen = [false; 256];
    while next != 0 {
        if !(8..256).contains(&next) || seen[next as usize] {
            return Err(Error::Invalid);
        }
        seen[next as usize] = true;
        let cap = ctl.read(route, number, CfgSpace::Port, next, 1).await?[0];
        match (cap >> 8) & 255 {
            1 => p.phy_cap = next,
            4 => p.adapter_cap = next,
            6 => p.usb4_cap = next,
            _ => {}
        }
        next = (cap & 255) as u16;
    }
    Ok(p)
}
async fn router(
    ctl: &mut impl Config,
    route: u64,
    upstream: u8,
    controls: u32,
    configure: bool,
) -> Result<Router, Error> {
    let mut h = ctl.read(route, 0, CfgSpace::Switch, 0, 5).await?;
    let version = h[4] >> 29;
    if version == 0 {
        return Err(Error::Invalid);
    } // legacy ICM routers need their own CM.
    let count = ((h[1] >> 14) & 63) as u8;
    let upstream = if route == 0 {
        0
    } else if upstream != 0 {
        upstream
    } else {
        ((h[1] >> 8) & 63) as u8
    };
    if count == 0 || upstream > count {
        return Err(Error::Invalid);
    }
    let configure = configure
        || h[3] & (1 << 31) == 0
        || h[2] != route as u32
        || h[3] & 0x3f_ffff != (route >> 32) as u32;
    if configure {
        h[1] = (h[1] & !((7 << 20) | (63 << 8)))
            | (route_depth(route) << 20)
            | ((upstream as u32) << 8);
        h[2] = route as u32;
        h[3] = (route >> 32) as u32 | (1 << 31);
        h[4] = (h[4] & !0xffff) | 255 | ((if version == 1 { 0x10 } else { 0x20 }) << 8);
        ctl.write(route, 0, CfgSpace::Switch, 1, &h[1..5]).await?;
        if route != 0 {
            let mut config = ctl.read(route, 0, CfgSpace::Switch, 5, 1).await?[0];
            config &= !((1 << 24) | (1 << 25) | (1 << 26));
            config |= 1 << 23; // This CM only implements USB4, not TBT3.
            if controls & 1 != 0 {
                config |= 1 << 25;
            }
            ctl.write(route, 0, CfgSpace::Switch, 5, &[config]).await?;
            wait_bit(ctl, route, 6, 1 << 24, true).await?;
            ctl.write(route, 0, CfgSpace::Switch, 5, &[config | (1 << 31)])
                .await?;
            wait_bit(ctl, route, 6, 1 << 25, true).await?;
        }
    }
    let mut ports: Vec<Port> = Vec::new();
    for number in 1..=count {
        let mut p = port(ctl, route, number).await?;
        // USB4 default lane pairing matches tb_switch_default_link_ports.
        if p.kind == 1
            && ports
                .last()
                .is_some_and(|last| last.kind == 1 && !last.secondary)
        {
            p.secondary = true;
        }
        if configure && matches!(p.kind, 1 | 0x0e0101 | 0x0e0102) {
            let value = ctl.read(route, number, CfgSpace::Port, 5, 1).await?[0];
            ctl.write(route, number, CfgSpace::Port, 5, &[value & !(1 << 31)])
                .await?;
        }
        if p.kind == 1 && p.number != upstream && !p.secondary {
            // Downstream router config space remains inaccessible until LCK clears.
            let value = ctl.read(route, number, CfgSpace::Port, 4, 1).await?[0];
            if value & (1 << 31) != 0 {
                ctl.write(route, number, CfgSpace::Port, 4, &[value & !(1 << 31)])
                    .await?;
            }
        }
        ports.push(p);
    }
    Ok(Router {
        route,
        upstream,
        vendor: h[0] as u16,
        device: (h[0] >> 16) as u16,
        ports,
    })
}
async fn scan(
    ctl: &mut impl Config,
    id: u32,
    controls: u32,
    previous: &Domain,
) -> Result<Domain, Error> {
    let mut result = Domain {
        id,
        routers: Vec::new(),
    };
    let mut queue = alloc::vec![(0, 0)];
    let mut index = 0;
    while index < queue.len() {
        let (route, upstream) = queue[index];
        index += 1;
        let known = previous.routers.iter().any(|r| r.route == route);
        let router = match router(ctl, route, upstream, controls, !known).await {
            Ok(r) => r,
            Err(Error::Remote(0 | 1 | 4)) if route != 0 => continue,
            Err(e) => return Err(e),
        };
        if route_depth(route) < 5 {
            for p in &router.ports {
                if p.kind != 1 || p.number == router.upstream || p.secondary || p.phy_cap == 0 {
                    continue;
                }
                let state = ctl
                    .read(route, p.number, CfgSpace::Port, p.phy_cap + 1, 1)
                    .await?[0];
                if matches!((state >> 26) & 15, 2..=6) && queue.len() < 64 {
                    let child = compose_downstream(route, route_depth(route), p.number)
                        .ok_or(Error::Invalid)?;
                    queue.push((child, 0));
                }
            }
        }
        result.routers.push(router);
    }
    Ok(result)
}
pub(crate) async fn run(id: u32, controls: u32, ctl: &mut Control) -> Result<(), Error> {
    let mut current = Domain {
        id,
        routers: Vec::new(),
    };
    let mut tunnels = Vec::new();
    let result = async {
        loop {
            // Process detach before discovery: a replacement at the same route
            // must not inherit the previous peripheral's paths or configuration.
            for event in core::mem::take(&mut ctl.events)
                .into_iter()
                .filter(|e| e.unplug)
            {
                let subtree = current
                    .routers
                    .iter()
                    .find(|r| r.route == event.route)
                    .and_then(|r| r.ports.iter().find(|p| p.number == event.port))
                    .filter(|p| p.kind == 1)
                    .and_then(|_| {
                        compose_downstream(event.route, route_depth(event.route), event.port)
                    });
                if let Some(root) = subtree {
                    current.routers.retain(|r| !in_subtree(r.route, root));
                }
                let mut index = 0;
                while index < tunnels.len() {
                    let t: &super::tunnel::Tunnel = &tunnels[index];
                    let ends = [t.display.input, t.display.output];
                    if ends.iter().any(|e| {
                        (e.route == event.route && e.port == event.port)
                            || subtree.is_some_and(|root| in_subtree(e.route, root))
                    }) {
                        tunnels[index].teardown(ctl, &current).await?;
                        tunnels.remove(index);
                    } else {
                        index += 1;
                    }
                }
            }
            let next = scan(ctl, id, controls, &current).await?;
            let changed = next != current;
            current = next;
            super::tunnel::reconcile(ctl, &current, &mut tunnels, controls).await?;
            if changed {
                let _ = writeln!(
                    narf_console::Writer,
                    "usb4: domain {id}: {} routers",
                    current.routers.len()
                );
                let mut domains = DOMAINS.lock();
                domains.retain(|d| d.id != id);
                domains.push(current.clone());
            }
            let deadline = narf_time::Deadline::after_ms(1000);
            loop {
                ctl.poll_events()?;
                if !ctl.events.is_empty() || deadline.expired() {
                    break;
                }
                ctl.ring.wait(20).await;
            }
        }
    }
    .await;
    for tunnel in tunnels.iter_mut().rev() {
        let _ = tunnel.teardown(ctl, &current).await;
    }
    DOMAINS.lock().retain(|d| d.id != id);
    super::tunnel::forget_domain(id);
    result
}

fn in_subtree(route: u64, root: u64) -> bool {
    let depth = route_depth(root);
    if depth == 0 {
        return true;
    }
    route & ((1u64 << (depth * 8)) - 1) == root
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::super::tunnel::tests::Model;
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn usb4_live_enumeration_unlocks_and_bounds_capabilities() -> TestResult {
        let mut m = Model::default();
        for (route, count, upstream) in [(0u64, 2u32, 0u32), (1, 3, 1)] {
            m.put(route, 0, CfgSpace::Switch, 0, 0x1234_1022);
            m.put(
                route,
                0,
                CfgSpace::Switch,
                1,
                (count << 14) | (upstream << 8),
            );
            m.put(route, 0, CfgSpace::Switch, 4, 1 << 29);
            m.put(route, 0, CfgSpace::Switch, 6, (1 << 24) | (1 << 25));
            for number in 1..=count as u8 {
                m.put(route, number, CfgSpace::Port, 1, 8);
                m.put(
                    route,
                    number,
                    CfgSpace::Port,
                    2,
                    if number == 3 { 0x0e0102 } else { 1 },
                );
                m.put(route, number, CfgSpace::Port, 4, (64 << 20) | (1 << 31));
                m.put(
                    route,
                    number,
                    CfgSpace::Port,
                    5,
                    15 | (15 << 11) | (1 << 31),
                );
                m.put(
                    route,
                    number,
                    CfgSpace::Port,
                    8,
                    if number == 3 { 4 << 8 } else { 1 << 8 },
                );
                m.put(route, number, CfgSpace::Port, 9, 2 << 26);
            }
        }
        let previous = Domain {
            id: 99,
            routers: Vec::new(),
        };
        let found = match narf_scheduler::block_on_spin(scan(&mut m, 99, 3, &previous)) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("native two-router enumeration"),
        };
        if found.routers.len() != 2
            || found.routers[1].upstream != 1
            || !found.routers[0].ports[1].secondary
            || m.get(0, 1, CfgSpace::Port, 4) & (1 << 31) != 0
            || m.get(1, 3, CfgSpace::Port, 5) & (1 << 31) != 0
            || m.get(1, 0, CfgSpace::Switch, 5) & (1 << 24) != 0
        {
            return TestResult::Fail("lane pairing, unlock, hotplug or PCIe ownership");
        }
        m.put(0, 1, CfgSpace::Port, 8, (1 << 8) | 8);
        if narf_scheduler::block_on_spin(port(&mut m, 0, 1)) != Err(Error::Invalid)
            || !in_subtree(0x0301, 1)
            || in_subtree(0x0302, 1)
        {
            return TestResult::Fail("capability cycle/subtree validation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/topology",
        usb4_live_enumeration_unlocks_and_bounds_capabilities
    );
}
