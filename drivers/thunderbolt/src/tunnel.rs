//! Owned USB4 DisplayPort paths. Configuration writes are recorded for reverse
//! rollback; no enabled firmware path is overwritten. Reference: Linux path.c,
//! tunnel.c, switch.c and usb4.c in /usr/src/linux/drivers/thunderbolt.
use super::{
    cm::{route_depth, CfgSpace},
    control::Config,
    ring::Error,
    topology::{router_operation, Domain, Port, Router},
};
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub route: u64,
    pub port: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    DisplayPort,
    Usb3,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelInfo {
    pub domain: u32,
    pub input: Endpoint,
    pub output: Endpoint,
    pub protocol: Protocol,
    pub dprx_done: bool,
}
static DISPLAYS: IrqSafeSpinLock<Vec<TunnelInfo>> = IrqSafeSpinLock::new(Vec::new());
pub(crate) fn forget_domain(id: u32) {
    DISPLAYS.lock().retain(|t| t.domain != id);
}
pub fn displays() -> Vec<TunnelInfo> {
    DISPLAYS
        .lock()
        .iter()
        .filter(|t| t.protocol == Protocol::DisplayPort)
        .cloned()
        .collect()
}
pub fn usb3_tunnels() -> Vec<TunnelInfo> {
    DISPLAYS
        .lock()
        .iter()
        .filter(|t| t.protocol == Protocol::Usb3)
        .cloned()
        .collect()
}

#[derive(Clone, Debug)]
struct Hop {
    route: u64,
    input: Port,
    output: Port,
    id: u16,
    next: u16,
}
#[derive(Debug)]
struct Undo {
    endpoint: Endpoint,
    space: CfgSpace,
    offset: u16,
    words: Vec<u32>,
}
#[derive(Debug)]
pub(crate) struct Tunnel {
    pub display: TunnelInfo,
    writes: Vec<Undo>,
    resource: bool,
    hpd_owned: bool,
    bandwidth: Option<(u16, u32)>,
}

fn router(domain: &Domain, route: u64) -> Result<&Router, Error> {
    domain
        .routers
        .iter()
        .find(|r| r.route == route)
        .ok_or(Error::Invalid)
}
fn port(domain: &Domain, endpoint: Endpoint) -> Result<&Port, Error> {
    router(domain, endpoint.route)?
        .ports
        .iter()
        .find(|p| p.number == endpoint.port)
        .ok_or(Error::Invalid)
}
fn chain(domain: &Domain, input: Endpoint, output: Endpoint) -> Result<Vec<Hop>, Error> {
    let start = route_depth(input.route);
    let depth = route_depth(output.route);
    let prefix = if start == 0 {
        0
    } else {
        (1u64 << (start * 8)) - 1
    };
    if start >= depth || output.route & prefix != input.route {
        return Err(Error::Invalid);
    }
    let mut hops = Vec::new();
    for level in start..=depth {
        let route = if level == 0 {
            0
        } else {
            output.route & ((1u64 << (level * 8)) - 1)
        };
        let r = router(domain, route)?;
        let in_port = if level == start {
            input.port
        } else {
            r.upstream
        };
        let out_port = if level == depth {
            output.port
        } else {
            (output.route >> (level * 8)) as u8
        };
        hops.push(Hop {
            route,
            input: port(
                domain,
                Endpoint {
                    route,
                    port: in_port,
                },
            )?
            .clone(),
            output: port(
                domain,
                Endpoint {
                    route,
                    port: out_port,
                },
            )?
            .clone(),
            id: 0,
            next: 0,
        });
    }
    Ok(hops)
}
impl Tunnel {
    async fn change(
        &mut self,
        ctl: &mut impl Config,
        endpoint: Endpoint,
        space: CfgSpace,
        offset: u16,
        words: &[u32],
    ) -> Result<(), Error> {
        let old = ctl
            .read(
                endpoint.route,
                endpoint.port,
                space,
                offset,
                words.len() as u8,
            )
            .await?;
        // Record before attempting a write: even an error response may follow
        // a device having consumed part of the configuration transaction.
        self.writes.push(Undo {
            endpoint,
            space,
            offset,
            words: old,
        });
        ctl.write(endpoint.route, endpoint.port, space, offset, words)
            .await
    }
    async fn modify(
        &mut self,
        ctl: &mut impl Config,
        e: Endpoint,
        offset: u16,
        clear: u32,
        set: u32,
    ) -> Result<(), Error> {
        let value = ctl.read(e.route, e.port, CfgSpace::Port, offset, 1).await?[0];
        self.change(ctl, e, CfgSpace::Port, offset, &[(value & !clear) | set])
            .await
    }
    pub async fn teardown(&mut self, ctl: &mut impl Config, live: &Domain) -> Result<(), Error> {
        DISPLAYS.lock().retain(|d| {
            !(d.domain == self.display.domain
                && d.input == self.display.input
                && d.output == self.display.output)
        });
        if self.hpd_owned {
            if let Ok(source) = port(live, self.display.input) {
                let e = self.display.input;
                let value = ctl
                    .read(e.route, e.port, CfgSpace::Port, source.adapter_cap + 3, 1)
                    .await?[0];
                ctl.write(
                    e.route,
                    e.port,
                    CfgSpace::Port,
                    source.adapter_cap + 3,
                    &[value | (1 << 9)],
                )
                .await?;
            }
            self.hpd_owned = false;
        }
        // Disable adapters before paths; drain each path before returning its
        // credits. Retain the remaining journal if a drain/write fails.
        while let Some(undo) = self.writes.last() {
            if live.routers.iter().any(|r| r.route == undo.endpoint.route) {
                if undo.space == CfgSpace::Hops {
                    let e = undo.endpoint;
                    let mut words = ctl
                        .read(e.route, e.port, undo.space, undo.offset, 2)
                        .await?;
                    words[0] &= !(1 << 31);
                    ctl.write(e.route, e.port, undo.space, undo.offset, &words)
                        .await?;
                    let deadline = narf_time::Deadline::after_ms(500);
                    loop {
                        if ctl
                            .read(e.route, e.port, undo.space, undo.offset + 1, 1)
                            .await?[0]
                            & (1 << 28)
                            == 0
                        {
                            break;
                        }
                        if deadline.expired() {
                            return Err(Error::Timeout);
                        }
                        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant())
                            .await;
                    }
                }
                ctl.write(
                    undo.endpoint.route,
                    undo.endpoint.port,
                    undo.space,
                    undo.offset,
                    &undo.words,
                )
                .await?;
            }
            self.writes.pop();
        }
        if let Some((cap, old)) = self.bandwidth {
            if port(live, self.display.input).is_ok() {
                usb3_bandwidth(ctl, self.display.input, cap, Some(old)).await?;
            }
            self.bandwidth = None;
        }
        if self.resource && port(live, self.display.input).is_ok() {
            match router_operation(
                ctl,
                self.display.input.route,
                0x12,
                self.display.input.port as u32,
            )
            .await?
            {
                (0, _) => self.resource = false,
                _ => return Err(Error::Failed),
            }
        }
        Ok(())
    }
    async fn path(
        &mut self,
        ctl: &mut impl Config,
        mut hops: Vec<Hop>,
        video: bool,
    ) -> Result<(), Error> {
        let usb = self.display.protocol == Protocol::Usb3;
        let endpoint_id = if video { 9 } else { 8 };
        // Allocate a free incoming HopID on every lane; fixed IDs only apply
        // to protocol adapters. Already enabled firmware paths remain owned.
        for hop in &mut hops {
            let (first, last) = if hop.input.kind == 1 {
                (8, hop.input.max_in_hop.min(2047))
            } else {
                (endpoint_id, endpoint_id)
            };
            if hop.input.max_in_hop < first {
                return Err(Error::Invalid);
            }
            for id in first..=last {
                let h = ctl
                    .read(hop.route, hop.input.number, CfgSpace::Hops, 2 * id, 2)
                    .await?;
                if h[0] & (1 << 31) == 0 {
                    hop.id = id;
                    break;
                }
            }
            if hop.id == 0 {
                return Err(Error::Full);
            }
        }
        for index in 0..hops.len() {
            hops[index].next = hops.get(index + 1).map_or(endpoint_id, |h| h.id);
            if hops[index].next > hops[index].output.max_out_hop {
                return Err(Error::Invalid);
            }
        }
        for (index, hop) in hops.iter().enumerate() {
            let e = Endpoint {
                route: hop.route,
                port: hop.input.number,
            };
            let (status, metadata) = router_operation(ctl, hop.route, 0x33, 0).await?;
            let count = (metadata & 255) as u8;
            if status != 0 || count == 0 || count > 16 {
                return Err(Error::Invalid);
            }
            let params = ctl.read(hop.route, 0, CfgSpace::Switch, 9, count).await?;
            let credit = params
                .iter()
                .find(|w| {
                    **w & 0xffff
                        == if usb {
                            1
                        } else if video {
                            3
                        } else {
                            2
                        }
                })
                .map(|w| (w >> 16) as u16)
                .ok_or(Error::Invalid)?;
            if credit == 0 || (!video && credit > 127) {
                return Err(Error::Invalid);
            }
            if hop.input.kind == 1 {
                let nfc = ctl.read(e.route, e.port, CfgSpace::Port, 4, 1).await?[0] & 1023;
                let mut allocated = nfc;
                // Include firmware and other protocol paths in the admission
                // check, including hop zero's control-channel reservation.
                let mut offset = 0u16;
                let end = (hop.input.max_in_hop + 1) * 2;
                while offset < end {
                    let count = (end - offset).min(60) as u8;
                    let entries = ctl
                        .read(e.route, e.port, CfgSpace::Hops, offset, count)
                        .await?;
                    for entry in entries.chunks_exact(2) {
                        if entry[0] & (1 << 31) != 0 {
                            allocated += (entry[0] >> 17) & 127;
                        }
                    }
                    offset += count as u16;
                }
                if allocated + credit as u32 > hop.input.total_credits as u32 {
                    return Err(Error::Full);
                }
            }
            if video && hop.input.kind == 1 {
                let old = ctl.read(e.route, e.port, CfgSpace::Port, 4, 1).await?[0];
                let nfc = (old & 1023)
                    .checked_add(credit as u32)
                    .ok_or(Error::Invalid)?;
                // Retain space for AUX and the control path; never underflow.
                if nfc + 2 > hop.input.total_credits as u32 || nfc > 1023 {
                    return Err(Error::Full);
                }
                self.change(ctl, e, CfgSpace::Port, 4, &[(old & !1023) | nfc])
                    .await?;
            }
            let old = ctl
                .read(e.route, e.port, CfgSpace::Hops, hop.id * 2, 2)
                .await?;
            let mut words = [
                hop.next as u32 | ((hop.output.number as u32) << 11) | (1 << 31),
                (if usb { 2 } else { 1 })
                    | ((if usb {
                        3
                    } else if video {
                        1
                    } else {
                        2
                    }) << 8),
            ];
            if hop.input.kind == 1 {
                if !video {
                    words[0] |= (credit as u32) << 17;
                    words[1] |= 1 << 24;
                }
            } else {
                // USB4 protocol adapter IFC/ISE and allocated credits are
                // vendor defined. Preserve exactly those fields from hardware.
                words[0] |= old[0] & (127 << 17);
                words[1] |= old[1] & ((1 << 24) | (1 << 26));
            }
            if !video && index + 1 < hops.len() {
                words[1] |= 1 << 25;
            }
            self.change(ctl, e, CfgSpace::Hops, hop.id * 2, &words)
                .await?;
        }
        Ok(())
    }
    async fn activate(&mut self, ctl: &mut impl Config, domain: &Domain) -> Result<(), Error> {
        if self.display.protocol == Protocol::Usb3 {
            return self.activate_usb3(ctl, domain).await;
        }
        let input = self.display.input;
        let output = self.display.output;
        let source = port(domain, input)?;
        let sink = port(domain, output)?;
        for (e, p) in [(input, source), (output, sink)] {
            if p.adapter_cap == 0
                || ctl
                    .read(e.route, e.port, CfgSpace::Port, p.adapter_cap, 1)
                    .await?[0]
                    & (3 << 30)
                    != 0
            {
                return Err(Error::Full);
            }
        }
        match router_operation(ctl, input.route, 0x11, input.port as u32).await {
            Ok((0, _)) => self.resource = true,
            Err(Error::Remote(0xff)) => {}
            Ok(_) => return Err(Error::Full),
            Err(e) => return Err(e),
        }
        self.hpd_owned = true;
        let value = ctl
            .read(
                output.route,
                output.port,
                CfgSpace::Port,
                sink.adapter_cap + 6,
                1,
            )
            .await?[0];
        // CMHS/UF are a handshake, not persistent configuration to replay.
        ctl.write(
            output.route,
            output.port,
            CfgSpace::Port,
            sink.adapter_cap + 6,
            &[value | (1 << 25) | (1 << 26)],
        )
        .await?;
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            if ctl
                .read(
                    output.route,
                    output.port,
                    CfgSpace::Port,
                    sink.adapter_cap + 6,
                    1,
                )
                .await?[0]
                & (1 << 25)
                == 0
            {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
        }
        let in_cap = ctl
            .read(
                input.route,
                input.port,
                CfgSpace::Port,
                source.adapter_cap + 4,
                1,
            )
            .await?[0];
        let out_cap = ctl
            .read(
                output.route,
                output.port,
                CfgSpace::Port,
                sink.adapter_cap + 4,
                1,
            )
            .await?[0];
        // Start with legacy DP bandwidth mode. Advertise RBR, bounded by the
        // smallest lane count, to fit even a single Gen2 USB4 lane alongside
        // control and USB traffic. Higher rates require bandwidth allocation.
        let lanes = ((in_cap >> 12) & 7).min((out_cap >> 12) & 7);
        if lanes > 2 {
            return Err(Error::Invalid);
        }
        let cap = (out_cap & !((15 << 8) | (7 << 12) | (7 << 17) | (1 << 28))) | (lanes << 12);
        self.change(
            ctl,
            output,
            CfgSpace::Port,
            sink.adapter_cap + 5,
            &[in_cap & !(1 << 28)],
        )
        .await?;
        self.change(ctl, input, CfgSpace::Port, source.adapter_cap + 5, &[cap])
            .await?;
        let forward = chain(domain, input, output)?;
        self.path(ctl, forward.clone(), true).await?;
        self.path(ctl, forward.clone(), false).await?;
        let reverse = forward
            .into_iter()
            .rev()
            .map(|h| Hop {
                input: h.output,
                output: h.input,
                ..h
            })
            .collect();
        self.path(ctl, reverse, false).await?;
        self.modify(ctl, input, source.adapter_cap, 0, 3 << 30)
            .await?;
        self.modify(ctl, output, sink.adapter_cap, 0, 3 << 30)
            .await?;
        Ok(())
    }

    async fn activate_usb3(&mut self, ctl: &mut impl Config, domain: &Domain) -> Result<(), Error> {
        let input = self.display.input;
        let output = self.display.output;
        let source = port(domain, input)?;
        let sink = port(domain, output)?;
        for (e, p) in [(input, source), (output, sink)] {
            if p.adapter_cap == 0
                || ctl
                    .read(e.route, e.port, CfgSpace::Port, p.adapter_cap, 1)
                    .await?[0]
                    & (1 << 31)
                    != 0
            {
                return Err(Error::Full);
            }
        }
        if input.route == 0 {
            let old = ctl
                .read(
                    input.route,
                    input.port,
                    CfgSpace::Port,
                    source.adapter_cap + 2,
                    1,
                )
                .await?[0];
            if old & (1 << 31) != 0 {
                return Err(Error::Full);
            }
            self.bandwidth = Some((source.adapter_cap, old & 0x00ff_ffff));
            usb3_bandwidth(ctl, input, source.adapter_cap, None).await?;
        }
        let forward = chain(domain, input, output)?;
        self.path(ctl, forward.clone(), false).await?;
        let reverse = forward
            .into_iter()
            .rev()
            .map(|h| Hop {
                input: h.output,
                output: h.input,
                ..h
            })
            .collect();
        self.path(ctl, reverse, false).await?;
        self.change(ctl, input, CfgSpace::Port, source.adapter_cap, &[3 << 30])
            .await?;
        self.writes.last_mut().unwrap().words[0] |= 1 << 30;
        self.change(ctl, output, CfgSpace::Port, sink.adapter_cap, &[3 << 30])
            .await?;
        self.writes.last_mut().unwrap().words[0] |= 1 << 30;
        Ok(())
    }
}
fn bandwidth_units(scale: u32, consumed: u32) -> Result<u32, Error> {
    let unit = 512u64
        .checked_mul(1u64.checked_shl(scale).ok_or(Error::Invalid)?)
        .ok_or(Error::Invalid)?;
    let minimum = 112_500_000u64.div_ceil(unit) as u32;
    let up = minimum.max(consumed & 4095);
    let down = minimum.max((consumed >> 12) & 4095);
    if up > 4095 || down > 4095 {
        return Err(Error::Invalid);
    }
    Ok(up | (down << 12))
}
async fn usb3_bandwidth(
    ctl: &mut impl Config,
    e: Endpoint,
    cap: u16,
    restore: Option<u32>,
) -> Result<(), Error> {
    let old = ctl
        .read(e.route, e.port, CfgSpace::Port, cap + 2, 1)
        .await?[0];
    ctl.write(e.route, e.port, CfgSpace::Port, cap + 2, &[old | (1 << 31)])
        .await?;
    let result = async {
        let deadline = narf_time::Deadline::after_ms(1500);
        let consumed = loop {
            let value = ctl
                .read(e.route, e.port, CfgSpace::Port, cap + 1, 1)
                .await?[0];
            if value & (1 << 31) != 0 {
                break value;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
        };
        let allocation = match restore {
            Some(value) => value,
            None => {
                let scale = ctl
                    .read(e.route, e.port, CfgSpace::Port, cap + 3, 1)
                    .await?[0]
                    & 63;
                bandwidth_units(scale, consumed)?
            }
        };
        ctl.write(
            e.route,
            e.port,
            CfgSpace::Port,
            cap + 2,
            &[(old & !0x00ff_ffff) | (1 << 31) | allocation],
        )
        .await
    }
    .await;
    // Always release CMR, including invalid scale/timeout/error paths.
    let value = ctl
        .read(e.route, e.port, CfgSpace::Port, cap + 2, 1)
        .await?[0];
    ctl.write(
        e.route,
        e.port,
        CfgSpace::Port,
        cap + 2,
        &[value & !(1 << 31)],
    )
    .await?;
    let deadline = narf_time::Deadline::after_ms(1500);
    while ctl
        .read(e.route, e.port, CfgSpace::Port, cap + 1, 1)
        .await?[0]
        & (1 << 31)
        != 0
    {
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
    }
    result
}

pub(crate) async fn reconcile(
    ctl: &mut impl Config,
    domain: &Domain,
    tunnels: &mut Vec<Tunnel>,
    controls: u32,
) -> Result<(), Error> {
    let mut index = 0;
    while index < tunnels.len() {
        let t = &mut tunnels[index];
        let present = if t.display.protocol == Protocol::Usb3 {
            port(domain, t.display.output).is_ok() && port(domain, t.display.input).is_ok()
        } else if let Ok(p) = port(domain, t.display.output) {
            ctl.read(
                t.display.output.route,
                p.number,
                CfgSpace::Port,
                p.adapter_cap + 2,
                1,
            )
            .await?[0]
                & (1 << 6)
                != 0
        } else {
            false
        };
        if !present {
            tunnels[index].teardown(ctl, domain).await?;
            tunnels.remove(index);
        } else {
            if t.display.protocol == Protocol::DisplayPort {
                let source = port(domain, t.display.input)?;
                t.display.dprx_done = ctl
                    .read(0, source.number, CfgSpace::Port, source.adapter_cap + 7, 1)
                    .await?[0]
                    & (1 << 31)
                    != 0;
            }
            index += 1;
        }
    }
    if controls & 1 != 0 {
        for child in domain.routers.iter().filter(|r| r.route != 0) {
            let depth = route_depth(child.route);
            let parent_route = if depth == 1 {
                0
            } else {
                child.route & ((1u64 << ((depth - 1) * 8)) - 1)
            };
            let parent = router(domain, parent_route)?;
            let lane = (child.route >> ((depth - 1) * 8)) as u8;
            let Some(lane_index) = parent
                .ports
                .iter()
                .filter(|p| p.kind == 1 && !p.secondary)
                .position(|p| p.number == lane)
            else {
                continue;
            };
            let Some(source) = parent
                .ports
                .iter()
                .filter(|p| p.kind == 0x200101)
                .nth(lane_index)
            else {
                continue;
            };
            let Some(sink) = child.ports.iter().find(|p| p.kind == 0x200102) else {
                continue;
            };
            let input = Endpoint {
                route: parent_route,
                port: source.number,
            };
            let output = Endpoint {
                route: child.route,
                port: sink.number,
            };
            if tunnels
                .iter()
                .any(|t| t.display.protocol == Protocol::Usb3 && t.display.output == output)
            {
                continue;
            }
            let mut t = Tunnel {
                display: TunnelInfo {
                    domain: domain.id,
                    input,
                    output,
                    protocol: Protocol::Usb3,
                    dprx_done: false,
                },
                writes: Vec::new(),
                resource: false,
                hpd_owned: false,
                bandwidth: None,
            };
            match t.activate(ctl, domain).await {
                Ok(()) => tunnels.push(t),
                Err(e) => {
                    if let Err(cleanup) = t.teardown(ctl, domain).await {
                        tunnels.push(t);
                        return Err(cleanup);
                    }
                    if !matches!(e, Error::Full | Error::Remote(_)) {
                        return Err(e);
                    }
                }
            }
        }
    }
    if controls & 2 != 0
        && !tunnels
            .iter()
            .any(|t| t.display.protocol == Protocol::DisplayPort)
    {
        let host = router(domain, 0)?;
        'outputs: for r in domain.routers.iter().filter(|r| r.route != 0) {
            for sink in r
                .ports
                .iter()
                .filter(|p| p.kind == 0x0e0102 && p.adapter_cap != 0)
            {
                if ctl
                    .read(
                        r.route,
                        sink.number,
                        CfgSpace::Port,
                        sink.adapter_cap + 2,
                        1,
                    )
                    .await?[0]
                    & (1 << 6)
                    == 0
                {
                    continue;
                }
                for source in host.ports.iter().filter(|p| p.kind == 0x0e0101) {
                    let mut tunnel = Tunnel {
                        display: TunnelInfo {
                            domain: domain.id,
                            input: Endpoint {
                                route: 0,
                                port: source.number,
                            },
                            output: Endpoint {
                                route: r.route,
                                port: sink.number,
                            },
                            protocol: Protocol::DisplayPort,
                            dprx_done: false,
                        },
                        writes: Vec::new(),
                        resource: false,
                        hpd_owned: false,
                        bandwidth: None,
                    };
                    match tunnel.activate(ctl, domain).await {
                        Ok(()) => {
                            tunnels.push(tunnel);
                            break 'outputs;
                        }
                        Err(e) => {
                            if let Err(cleanup) = tunnel.teardown(ctl, domain).await {
                                tunnels.push(tunnel);
                                return Err(cleanup);
                            }
                            if !matches!(e, Error::Full | Error::Remote(_)) {
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }
    }
    let mut displays = DISPLAYS.lock();
    displays.retain(|d| d.domain != domain.id);
    displays.extend(tunnels.iter().map(|t| t.display.clone()));
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "tunnel_tests.rs"]
pub(crate) mod tests;
