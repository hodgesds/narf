//! Serialized configuration transactions and unsolicited hotplug demux.
use super::{
    cm::{Address, CfgSpace, Header},
    dataring::{DataRingPair, HopAllocator},
    ring::{Error, Packet, Ring},
    topology::{Domain, Port},
};
use alloc::{boxed::Box, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Event {
    pub route: u64,
    pub port: u8,
    pub unplug: bool,
}
#[derive(Debug)]
pub(crate) struct Control {
    pub ring: Ring,
    sequence: u8,
    pub events: Vec<Event>,
    /// Unsolicited XDomain frames (kinds 6/7) buffered for the
    /// XDomain engine's next pass. XDomain requests can arrive at
    /// any time, including mid-transaction; dropping one would lose
    /// a peer's login, so they are stashed rather than handled
    /// inline. Bounded like the event queue — a peer that floods
    /// the channel loses its newest frames and can retry.
    xdomain: Vec<(u8, Vec<u32>)>,
    failed: bool,
    /// NHI data-ring HopIDs currently handed out to bound peers.
    data_hops: HopAllocator,
    /// In-router DMA paths approved for bound peers, with the
    /// Hops entries they replaced (restored on release).
    bound_data: Vec<BoundData>,
}
impl Control {
    pub fn new(ring: Ring) -> Self {
        Self {
            ring,
            sequence: 0,
            events: Vec::new(),
            xdomain: Vec::new(),
            failed: false,
            data_hops: HopAllocator::new(),
            bound_data: Vec::new(),
        }
    }
    fn event(&mut self, packet: &Packet) -> Result<bool, Error> {
        if packet.words.len() < 2 {
            return Err(Error::Invalid);
        }
        if packet.kind == super::xdomain::PKG_XDOMAIN_REQ
            || packet.kind == super::xdomain::PKG_XDOMAIN_RESP
        {
            if self.xdomain.len() < 32 {
                self.xdomain.push((packet.kind, packet.words.clone()));
            }
            return Ok(true);
        }
        let header = Header::decode([packet.words[0], packet.words[1]]);
        let h = Header {
            route: header.route,
            unknown: 0,
        }
        .encode();
        if packet.kind == 5 && packet.words.len() == 3 {
            let value = packet.words[2];
            let event = Event {
                route: header.route,
                port: (value & 63) as u8,
                unplug: value & (1 << 31) != 0,
            };
            self.ring.send(
                3,
                &[
                    h[0],
                    h[1],
                    7 | ((event.port as u32) << 8) | ((if event.unplug { 3 } else { 2 }) << 30),
                ],
            )?;
            // A topology rescan is sufficient if the bounded event queue fills.
            if self.events.len() < 64 {
                self.events.push(event);
            }
            return Ok(true);
        }
        if packet.kind == 3 && packet.words.len() == 3 && packet.words[2] & 255 >= 32 {
            self.ring.send(4, &h)?;
            if self.events.len() < 64 {
                self.events.push(Event {
                    route: header.route,
                    port: ((packet.words[2] >> 8) & 63) as u8,
                    unplug: false,
                });
            }
            return Ok(true);
        }
        Ok(false)
    }
    pub fn poll_events(&mut self) -> Result<(), Error> {
        // Drain a bounded batch so a noisy peripheral cannot monopolize a poll.
        for _ in 0..32 {
            match self.ring.receive() {
                Ok(Some(packet)) => {
                    self.event(&packet)?;
                }
                Ok(None) => break,
                Err(Error::Invalid) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    async fn transaction(
        &mut self,
        route: u64,
        addr: Address,
        data: Option<&[u32]>,
    ) -> Result<Vec<u32>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if route > Header::ROUTE_MAX
            || addr.port > 63
            || addr.offset > 8191
            || addr.offset as u32 + addr.length as u32 > 8192
            || addr.length == 0
            || addr.length > 60
        {
            return Err(Error::Invalid);
        }
        let kind = if data.is_some() { 2 } else { 1 };
        let header = Header { route, unknown: 0 }.encode();
        let mut words = alloc::vec![header[0], header[1], addr.encode()];
        if let Some(data) = data {
            if data.len() != addr.length as usize {
                return Err(Error::Invalid);
            }
            words.extend_from_slice(data);
        }
        self.ring.send(kind, &words)?;
        self.failed = true;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            for _ in 0..32 {
                match self.ring.receive() {
                    Ok(Some(packet)) => {
                        if self.event(&packet)? {
                            continue;
                        }
                        if let Some(result) = match_reply(&packet, route, addr, kind) {
                            self.failed = matches!(result, Err(Error::Invalid));
                            return result;
                        }
                    }
                    Ok(None) => break,
                    Err(Error::Invalid) => continue,
                    Err(e) => {
                        self.failed = true;
                        return Err(e);
                    }
                }
            }
            if deadline.expired() {
                // No sequence-number reuse after a timed-out transaction.
                self.failed = true;
                return Err(Error::Timeout);
            }
            self.ring.wait(1).await;
        }
    }
}

/// One bound peer's approved DMA paths: the two Hops entries
/// programmed in the host router and the values they replaced,
/// so release restores the fabric exactly.
#[derive(Debug)]
struct BoundData {
    route: u64,
    tx_hop: u16,
    rx_hop: u16,
    lane_port: u8,
    nhi_port: u8,
    tx_saved: [u32; 2],
    rx_saved: [u32; 2],
}

/// The Hops entries `approve_data_paths` programmed.
#[derive(Debug)]
struct ApprovedPaths {
    tx_saved: [u32; 2],
    rx_saved: [u32; 2],
}

/// The ingress buffer credit for a host-originated data path,
/// from the host router's buffer-allocation parameters (router
/// operation 0x33 + the parameter table at Switch offset 9) —
/// the same class the crate's tunnel path model charges PCIe
/// paths against (key 2), which is the class the reference CM
/// programs XDomain DMA tunnels through (`tb_path` machinery
/// via `tb_tunnel_alloc_dma`).
async fn data_path_credit(ctl: &mut impl Config) -> Result<u16, Error> {
    let (status, metadata) = super::topology::router_operation(ctl, 0, 0x33, 0).await?;
    let count = (metadata & 255) as u8;
    if status != 0 || count == 0 || count > 16 {
        return Err(Error::Invalid);
    }
    let params = ctl.read(0, 0, CfgSpace::Switch, 9, count).await?;
    let credit = params
        .iter()
        .find(|w| **w & 0xffff == 2)
        .map(|w| (w >> 16) as u16)
        .ok_or(Error::Invalid)?;
    if credit == 0 || credit > 127 {
        return Err(Error::Invalid);
    }
    Ok(credit)
}

/// Approve the in-router DMA paths for one bound peer
/// (`tb_xdomain_enable_paths` -> `tb_tunnel_alloc_dma` in the
/// reference CM): a single Hops entry per direction in the host
/// router — the NHI adapter at the TX ring HopID, forwarding to
/// the lane adapter at the peer's announced transmit path; and
/// the lane adapter at the announced local path
/// (`TBIP_LOCAL_PATH`), forwarding to the NHI adapter at the RX
/// ring HopID. Entry construction follows the crate's tunnel
/// path model (`Tunnel::path`) for a non-video data path: the
/// lane (ingress) entry carries the buffer-allocation credit
/// and the ingress flow-control bit; the protocol-adapter entry
/// preserves the vendor ingress fields of the entry it
/// replaces. An already-enabled entry is never replaced — the
/// approval refuses, like the tunnel allocator refuses an
/// occupied HopID. Nothing is written unless both entries can
/// be claimed.
async fn approve_data_paths(
    ctl: &mut impl Config,
    lane: &Port,
    nhi_adapter: &Port,
    tx_hop: u16,
    peer_path: u32,
    rx_hop: u16,
) -> Result<ApprovedPaths, Error> {
    let local_path = super::xdomain::TBIP_LOCAL_PATH;
    // Bounds: the peer's announced path must be a usable path
    // HopID at the lane adapter (the reference hopid allocators
    // enforce the same TB_PATH_MIN_HOPID floor and adapter
    // ceiling); our ring HopID must fit the NHI adapter's
    // output range; our announced path must fit its input range.
    if peer_path < super::dataring::MIN_HOPID as u32
        || peer_path > lane.max_out_hop as u32
        || local_path > lane.max_in_hop as u32
        || rx_hop > nhi_adapter.max_out_hop
    {
        return Err(Error::Invalid);
    }
    let credit = data_path_credit(ctl).await?;
    let tx_offset = tx_hop * 2;
    let rx_offset = (local_path as u16) * 2;
    let tx_saved: [u32; 2] = ctl
        .read(0, nhi_adapter.number, CfgSpace::Hops, tx_offset, 2)
        .await?
        .try_into()
        .map_err(|_| Error::Invalid)?;
    if tx_saved[0] & (1 << 31) != 0 {
        return Err(Error::Full);
    }
    let rx_saved: [u32; 2] = ctl
        .read(0, lane.number, CfgSpace::Hops, rx_offset, 2)
        .await?
        .try_into()
        .map_err(|_| Error::Invalid)?;
    if rx_saved[0] & (1 << 31) != 0 {
        return Err(Error::Full);
    }
    // Admission, as in the tunnel path model: the adapter's
    // currently allocated credits (its NFC counter plus every
    // enabled entry's credit field) plus this path's credit
    // must fit the adapter's total.
    let nfc = ctl.read(0, lane.number, CfgSpace::Port, 4, 1).await?[0] & 1023;
    let mut allocated = nfc;
    let mut offset = 0u16;
    let end = (lane.max_in_hop + 1) * 2;
    while offset < end {
        let count = (end - offset).min(60) as u8;
        let entries = ctl
            .read(0, lane.number, CfgSpace::Hops, offset, count)
            .await?;
        for entry in entries.chunks_exact(2) {
            if entry[0] & (1 << 31) != 0 {
                allocated += (entry[0] >> 17) & 127;
            }
        }
        offset += count as u16;
    }
    if allocated + credit as u32 > lane.total_credits as u32 {
        return Err(Error::Full);
    }
    // NHI adapter entry (egress): preserve the vendor ingress
    // credit/flow-control fields, as for protocol adapters in
    // the tunnel model.
    let tx_words = [
        peer_path | ((lane.number as u32) << 11) | (tx_saved[0] & (127 << 17)) | (1 << 31),
        1 | (2 << 8) | (tx_saved[1] & ((1 << 24) | (1 << 26))),
    ];
    ctl.write(0, nhi_adapter.number, CfgSpace::Hops, tx_offset, &tx_words)
        .await?;
    // Lane adapter entry (ingress): charged the class credit,
    // ingress flow control on (single-hop path: it is both the
    // source and the destination hop of this router).
    let rx_words = [
        rx_hop as u32 | ((nhi_adapter.number as u32) << 11) | ((credit as u32) << 17) | (1 << 31),
        1 | (2 << 8) | (1 << 24),
    ];
    if let Err(e) = ctl
        .write(0, lane.number, CfgSpace::Hops, rx_offset, &rx_words)
        .await
    {
        // Roll the egress entry back so a failed approval
        // leaves no half-programmed path behind.
        let _ = ctl
            .write(0, nhi_adapter.number, CfgSpace::Hops, tx_offset, &tx_saved)
            .await;
        return Err(e);
    }
    Ok(ApprovedPaths { tx_saved, rx_saved })
}

/// Disconnect one approved Hops entry (the tunnel teardown
/// discipline): clear the enable bit, wait for the entry's
/// pending bit to drain, then restore the saved words.
async fn disconnect_data_path(
    ctl: &mut impl Config,
    port: u8,
    hop: u16,
    saved: [u32; 2],
) -> Result<(), Error> {
    let offset = hop * 2;
    let mut words = ctl.read(0, port, CfgSpace::Hops, offset, 2).await?;
    words[0] &= !(1 << 31);
    ctl.write(0, port, CfgSpace::Hops, offset, &words).await?;
    let deadline = narf_time::Deadline::after_ms(500);
    loop {
        if ctl.read(0, port, CfgSpace::Hops, offset + 1, 1).await?[0] & (1 << 28) == 0 {
            break;
        }
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
    }
    ctl.write(0, port, CfgSpace::Hops, offset, &saved).await
}

impl Control {
    /// Disconnect every approved data path (CM exit). The ring
    /// pairs themselves are owned by the peers' netdevs and stop
    /// when they drop; the controller teardown that follows
    /// revokes bus mastering, so no DMA can cross a path removed
    /// here.
    pub(crate) async fn release_all_data_links(&mut self) {
        for record in core::mem::take(&mut self.bound_data) {
            let _ = disconnect_data_path(
                &mut *self,
                record.lane_port,
                super::xdomain::TBIP_LOCAL_PATH as u16,
                record.rx_saved,
            )
            .await;
            let _ =
                disconnect_data_path(&mut *self, record.nhi_port, record.tx_hop, record.tx_saved)
                    .await;
            self.data_hops.free(record.tx_hop, true);
            self.data_hops.free(record.rx_hop, false);
        }
    }
}

/// Config-space transport used by both the native ring and device-model tests.
pub(crate) trait Config {
    async fn read(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        len: u8,
    ) -> Result<Vec<u32>, Error>;
    async fn write(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        data: &[u32],
    ) -> Result<(), Error>;
}
impl Config for Control {
    async fn read(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        len: u8,
    ) -> Result<Vec<u32>, Error> {
        self.sequence = (self.sequence + 1) & 3;
        self.transaction(
            route,
            Address {
                offset,
                length: len,
                port,
                space,
                seq: self.sequence,
            },
            None,
        )
        .await
    }
    async fn write(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        data: &[u32],
    ) -> Result<(), Error> {
        if data.len() > 60 {
            return Err(Error::Invalid);
        }
        self.sequence = (self.sequence + 1) & 3;
        self.transaction(
            route,
            Address {
                offset,
                length: data.len() as u8,
                port,
                space,
                seq: self.sequence,
            },
            Some(data),
        )
        .await
        .map(|_| ())
    }
}
/// The XDomain engine's channel over ring 0. Responses are matched
/// the reference CM's way (`tb_xdomain_match`): same protocol UUID,
/// routes equal with the reply bit (bit 63) masked on both sides —
/// sequence numbers are deliberately not part of the match.
impl super::xdomain::XdChannel for Control {
    async fn exchange(&mut self, kind: u8, words: &[u32]) -> Result<Vec<u32>, Error> {
        use super::xdomain::{decode_xd_head, ROUTE_REPLY_BIT};
        let Some(head) = decode_xd_head(words) else {
            return Err(Error::Invalid);
        };
        if words.len() < 7 {
            return Err(Error::Invalid);
        }
        let want_route = head.route & !ROUTE_REPLY_BIT;
        let want_uuid: Vec<u32> = words[3..7].to_vec();
        self.ring.send(kind, words)?;
        let deadline = narf_time::Deadline::after_ms(super::xdomain::XDP_TIMEOUT_MS);
        loop {
            for _ in 0..32 {
                match self.ring.receive() {
                    Ok(Some(packet)) => {
                        if packet.kind == super::xdomain::PKG_XDOMAIN_RESP
                            && packet.words.len() >= 7
                            && decode_xd_head(&packet.words)
                                .is_some_and(|h| h.route & !ROUTE_REPLY_BIT == want_route)
                            && packet.words[3..7] == want_uuid[..]
                        {
                            return Ok(packet.words);
                        }
                        if self.event(&packet)? {
                            continue;
                        }
                        if packet.kind == 3
                            && packet.words.len() == 3
                            && Header::decode([packet.words[0], packet.words[1]]).route
                                & !ROUTE_REPLY_BIT
                                == want_route
                        {
                            return Err(Error::Remote((packet.words[2] & 255) as u8));
                        }
                    }
                    Ok(None) => break,
                    Err(Error::Invalid) => continue,
                    Err(e) => return Err(e),
                }
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            self.ring.wait(1).await;
        }
    }

    async fn send(&mut self, kind: u8, words: &[u32]) -> Result<(), Error> {
        self.ring.send(kind, words)
    }

    fn drain(&mut self) -> Vec<(u8, Vec<u32>)> {
        core::mem::take(&mut self.xdomain)
    }
    /// Production binding (see `XdChannel::bind_data_link`):
    /// resolve the peer's lane adapter and the NHI adapter on
    /// the host router, allocate a HopID pair, create and start
    /// the data-ring pair (RX primed), then approve the
    /// in-router DMA paths — rings first, paths last, so no
    /// frame can arrive at an unprimed ring. Any failure unwinds
    /// completely (the pair's Drop stops its rings, the HopIDs
    /// return to the allocator) and the engine retries next
    /// pass.
    async fn bind_data_link(
        &mut self,
        domain: &Domain,
        route: u64,
        transmit_path: u32,
    ) -> Option<Box<dyn super::tbnet::DataLink>> {
        let host = domain.routers.iter().find(|r| r.route == 0)?;
        let lane = host
            .ports
            .iter()
            .find(|p| p.number == (route & 0xff) as u8 && p.kind == 1)?;
        let nhi_adapter = host.ports.iter().find(|p| p.kind == 2)?;
        let nhi_hops = self.ring.hops();
        let tx_hop = self.data_hops.alloc(nhi_hops, true)?;
        let Some(rx_hop) = self.data_hops.alloc(nhi_hops, false) else {
            self.data_hops.free(tx_hop, true);
            return None;
        };
        // SAFETY: this CM task exclusively owns the NHI (the
        // contract ring 0 runs under; the pair shares its BAR),
        // and both HopIDs were just allocated from this channel's
        // allocator, which is the only allocator for this NHI.
        let mut pair = match unsafe { DataRingPair::new(self.ring.bar(), nhi_hops, tx_hop, rx_hop) }
        {
            Ok(pair) => pair,
            Err(_) => {
                self.data_hops.free(tx_hop, true);
                self.data_hops.free(rx_hop, false);
                return None;
            }
        };
        pair.bind_authority(self.ring.authority());
        pair.start();
        match approve_data_paths(&mut *self, lane, nhi_adapter, tx_hop, transmit_path, rx_hop).await
        {
            Ok(approved) => {
                self.bound_data.push(BoundData {
                    route,
                    tx_hop,
                    rx_hop,
                    lane_port: lane.number,
                    nhi_port: nhi_adapter.number,
                    tx_saved: approved.tx_saved,
                    rx_saved: approved.rx_saved,
                });
                Some(Box::new(pair))
            }
            Err(_) => {
                drop(pair);
                self.data_hops.free(tx_hop, true);
                self.data_hops.free(rx_hop, false);
                None
            }
        }
    }
    /// Reverse of `bind_data_link`: disconnect the in-router
    /// paths (ingress entry first — it was written last), return
    /// the HopIDs, and only then drop the transport, whose Drop
    /// stops the rings; no frame can be routed to a ring that is
    /// stopping. Cleanup always completes even if a disconnect
    /// errors — a peer going away must not strand HopIDs.
    async fn release_data_link(&mut self, route: u64, link: Box<dyn super::tbnet::DataLink>) {
        if let Some(pos) = self.bound_data.iter().position(|b| b.route == route) {
            let record = self.bound_data.remove(pos);
            let _ = disconnect_data_path(
                &mut *self,
                record.lane_port,
                super::xdomain::TBIP_LOCAL_PATH as u16,
                record.rx_saved,
            )
            .await;
            let _ =
                disconnect_data_path(&mut *self, record.nhi_port, record.tx_hop, record.tx_saved)
                    .await;
            self.data_hops.free(record.tx_hop, true);
            self.data_hops.free(record.rx_hop, false);
        }
        drop(link);
    }
}

fn match_reply(
    packet: &Packet,
    route: u64,
    addr: Address,
    kind: u8,
) -> Option<Result<Vec<u32>, Error>> {
    if packet.words.len() < 3 {
        return None;
    }
    let h = Header::decode([packet.words[0], packet.words[1]]);
    if h.route != route {
        return None;
    }
    if packet.kind == 3 {
        if packet.words.len() != 3
            || ((packet.words[2] >> 8) & 63) != addr.port as u32
            || packet.words[2] & 255 >= 32
        {
            return None;
        }
        return Some(Err(Error::Remote((packet.words[2] & 255) as u8)));
    }
    if packet.kind != kind || Address::decode(packet.words[2]) != Some(addr) {
        return None;
    }
    let expected = if kind == 1 {
        3 + addr.length as usize
    } else {
        3
    };
    if packet.words.len() != expected {
        return Some(Err(Error::Invalid));
    }
    Some(Ok(packet.words[3..].to_vec()))
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn usb4_response_identity() -> TestResult {
        let a = Address {
            offset: 2,
            length: 1,
            port: 3,
            space: CfgSpace::Port,
            seq: 2,
        };
        let mut p = Packet {
            kind: 1,
            words: alloc::vec![0x8000_0000, 7, a.encode(), 42],
        };
        if match_reply(&p, 7, a, 1) != Some(Ok(alloc::vec![42]))
            || match_reply(&p, 8, a, 1).is_some()
        {
            return TestResult::Fail("route matching");
        }
        p.words[2] ^= 1 << 27;
        if match_reply(&p, 7, a, 1).is_some() {
            return TestResult::Fail("stale sequence accepted");
        }
        p.words[2] = a.encode();
        p.words.pop();
        if match_reply(&p, 7, a, 1) != Some(Err(Error::Invalid)) {
            return TestResult::Fail("short response accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/thunderbolt/control", usb4_response_identity);

    use super::super::{topology::Port, tunnel::tests::Model};

    /// One host-router port as the topology scan would publish
    /// it (kind 1 = lane adapter, kind 2 = NHI adapter).
    fn host_port(number: u8, kind: u32, max_in: u16, max_out: u16, credits: u16) -> Port {
        Port {
            number,
            kind,
            adapter_cap: 0,
            phy_cap: 0,
            usb4_cap: 0,
            max_in_hop: max_in,
            max_out_hop: max_out,
            total_credits: credits,
            secondary: false,
            retimers: alloc::vec![],
            retimer_fault: None,
        }
    }

    /// Approval programs exactly the two single-hop entries of
    /// the reference DMA tunnel: the NHI entry at the TX ring
    /// HopID forwards to the lane at the peer's announced path,
    /// the lane entry at the local path forwards to the NHI at
    /// the RX ring HopID carrying the class-2 credit from the
    /// model's buffer-allocation table. Disconnect restores
    /// both entries to their saved (empty) values.
    fn usb4_data_path_approval_programs_host_router() -> TestResult {
        let mut model = Model::default();
        let lane = host_port(1, 1, 15, 15, 64);
        let nhi = host_port(7, 2, 15, 15, 0);
        let approved = match narf_scheduler::block_on_spin(approve_data_paths(
            &mut model, &lane, &nhi, 8, 0xf, 9,
        )) {
            Ok(approved) => approved,
            Err(_) => return TestResult::Fail("approval refused"),
        };
        if approved.tx_saved != [0, 0] || approved.rx_saved != [0, 0] {
            return TestResult::Fail("saved entries not empty");
        }
        let tx = [
            model.get(0, 7, CfgSpace::Hops, 16),
            model.get(0, 7, CfgSpace::Hops, 17),
        ];
        if tx != [0xf | (1 << 11) | (1 << 31), 1 | (2 << 8)] {
            return TestResult::Fail("NHI entry mismatch");
        }
        let rx = [
            model.get(0, 1, CfgSpace::Hops, 30),
            model.get(0, 1, CfgSpace::Hops, 31),
        ];
        if rx
            != [
                9 | (7 << 11) | (2 << 17) | (1 << 31),
                1 | (2 << 8) | (1 << 24),
            ]
        {
            return TestResult::Fail("lane entry mismatch");
        }
        if narf_scheduler::block_on_spin(disconnect_data_path(
            &mut model,
            1,
            0xf,
            approved.rx_saved,
        ))
        .is_err()
        {
            return TestResult::Fail("lane disconnect failed");
        }
        if narf_scheduler::block_on_spin(disconnect_data_path(&mut model, 7, 8, approved.tx_saved))
            .is_err()
        {
            return TestResult::Fail("NHI disconnect failed");
        }
        if model.get(0, 7, CfgSpace::Hops, 16) == 0 && model.get(0, 1, CfgSpace::Hops, 30) == 0 {
            TestResult::Pass
        } else {
            TestResult::Fail("entries not restored")
        }
    }
    kernel_test_in!(
        "drivers/thunderbolt/control",
        usb4_data_path_approval_programs_host_router
    );

    /// Approval refuses — writing nothing — when either entry
    /// is already enabled (paths are never replaced), when the
    /// lane adapter's credit pool cannot admit the path, and
    /// when the peer's announced path falls outside the usable
    /// HopID range (reserved space or above the adapter's
    /// output ceiling).
    fn usb4_data_path_approval_refusals_write_nothing() -> TestResult {
        let lane = host_port(1, 1, 15, 15, 64);
        let nhi = host_port(7, 2, 15, 15, 0);
        // Occupied lane entry.
        let mut model = Model::default();
        model.put(0, 1, CfgSpace::Hops, 30, 1 << 31);
        let result =
            narf_scheduler::block_on_spin(approve_data_paths(&mut model, &lane, &nhi, 8, 0xf, 9));
        if !matches!(result, Err(Error::Full))
            || model.get(0, 7, CfgSpace::Hops, 16) != 0
            || model.get(0, 1, CfgSpace::Hops, 30) != (1 << 31)
        {
            return TestResult::Fail("occupied entry not refused cleanly");
        }
        // Credit-starved lane adapter (pool 1 < class credit 2).
        let mut model = Model::default();
        let starved = host_port(1, 1, 15, 15, 1);
        let result = narf_scheduler::block_on_spin(approve_data_paths(
            &mut model, &starved, &nhi, 8, 0xf, 9,
        ));
        if !matches!(result, Err(Error::Full))
            || model.get(0, 7, CfgSpace::Hops, 16) != 0
            || model.get(0, 1, CfgSpace::Hops, 30) != 0
        {
            return TestResult::Fail("credit starvation not refused cleanly");
        }
        // Announced path above the adapter ceiling, and one in
        // the reserved HopID space.
        let mut model = Model::default();
        let high =
            narf_scheduler::block_on_spin(approve_data_paths(&mut model, &lane, &nhi, 8, 16, 9));
        let low =
            narf_scheduler::block_on_spin(approve_data_paths(&mut model, &lane, &nhi, 8, 3, 9));
        if matches!(high, Err(Error::Invalid))
            && matches!(low, Err(Error::Invalid))
            && model.get(0, 7, CfgSpace::Hops, 16) == 0
            && model.get(0, 1, CfgSpace::Hops, 30) == 0
        {
            TestResult::Pass
        } else {
            TestResult::Fail("out-of-range path not refused cleanly")
        }
    }
    kernel_test_in!(
        "drivers/thunderbolt/control",
        usb4_data_path_approval_refusals_write_nothing
    );
}
