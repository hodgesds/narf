//! Retained connector slots and topology replacement for one physical MST port.
use super::*;

/// A connector is a branch's output port, not its position in a probe's vector.
/// Include the root and route so a replacement hub cannot inherit old requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MstOutputId {
    pub root: [u8; 16],
    pub branch: [u8; 16],
    pub lct: u8,
    pub rad: [u8; 8],
    pub port: u8,
}

#[derive(Clone, Debug)]
pub struct MstOutput {
    pub id: MstOutputId,
    /// The current probe's sink, or None while this connector is absent.
    pub sink: Option<dp_mst_mgr::Sink>,
    /// Empty if absent or unreadable. An unreadable EDID never shifts slots.
    pub edid: Vec<u8>,
    /// Independently admitted timings while no stream is lit on this output.
    /// Recomputed against the current configuration; empty after a reprobe.
    pub modes: Vec<Timing>,
    /// The end device's DSC decoder (`dsc::read_dsc`), read with its EDID.
    pub dsc: Option<super::dsc::MstDsc>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum ProbeState {
    #[default]
    New,
    /// Retained after cancellation/error: no replay of an uncertain session.
    Probing,
    Ready,
}

/// End-device connector slots one MST port keeps (`MstLink::outputs`).
/// Linux bounds neither: drm_dp_mst adds a connector for every output port
/// it finds. What it bounds is what lights: at most four streams (amdgpu_dm's
/// CRTCs are dc->caps.max_streams, the smaller of DCN 4.0.1's four pipes and
/// four stream encoders; `modeset::MAX_DISPLAYS`) and four payloads per
/// manager (`MAX_PAYLOADS`). Sixteen fixed slots per port give KMS stable
/// connector indices and every connector its own requests; past them a new
/// device reclaims a disconnected reservation, else stays unpublished.
pub const MST_OUTPUTS: usize = 16;

/// A port's connector slots, boxed: sixteen outputs with EDIDs and DSC
/// caps are kilobytes, too much for every holder's stack.
pub type Outputs = alloc::boxed::Box<[Option<MstOutput>; MST_OUTPUTS]>;

/// Reserve every surviving identity before admitting new ones. Disconnected
/// slots remain reserved for replug until every slot is needed by other sinks.
fn reconcile(previous: &[Option<MstOutput>; MST_OUTPUTS], topology: &Topology) -> Outputs {
    let mut out: Outputs = alloc::boxed::Box::new(previous.clone());
    for o in out.iter_mut().flatten() {
        o.sink = None;
        o.edid.clear();
        o.modes.clear();
        o.dsc = None;
    }
    let Some(root) = topology.branches.first() else {
        return out;
    };
    let devices: Vec<_> = topology
        .sinks()
        .into_iter()
        .map(|sink| {
            let branch = &topology.branches[sink.branch];
            (
                MstOutputId {
                    root: root.guid,
                    branch: branch.guid,
                    lct: branch.lct,
                    rad: branch.rad,
                    port: sink.port,
                },
                sink,
            )
        })
        .collect();
    for &(id, sink) in &devices {
        if let Some(o) = out.iter_mut().flatten().find(|o| o.id == id) {
            o.sink = Some(sink);
        }
    }
    for (id, sink) in devices {
        if out.iter().flatten().any(|o| o.id == id) {
            continue;
        }
        let slot = out.iter().position(Option::is_none).or_else(|| {
            out.iter()
                .position(|o| o.as_ref().is_some_and(|o| o.sink.is_none()))
        });
        let Some(slot) = slot else { break };
        out[slot] = Some(MstOutput {
            id,
            sink: Some(sink),
            edid: Vec::new(),
            modes: Vec::new(),
            dsc: None,
        });
    }
    out
}

impl MstLink {
    /// Coalesce connection and resource notifications. Unknown endpoints are
    /// ignored. Resource notices schedule a fresh query, not an assumed budget.
    /// Keep this separate from the probe: payload removal still needs old routes.
    pub(super) fn consume_events(&mut self) {
        for event in core::mem::take(&mut self.manager.events) {
            let (guid, port) = match event {
                dp_mst::UpRequest::ConnectionStatus { guid, port, .. }
                | dp_mst::UpRequest::ResourceStatus { guid, port, .. } => (guid, port),
            };
            let Some(branch) = self.topology.branches.iter().position(|b| b.guid == guid) else {
                continue;
            };
            let sink = dp_mst_mgr::Sink { branch, port };
            let Some(p) = self.topology.port(sink) else {
                continue;
            };
            match event {
                dp_mst::UpRequest::ConnectionStatus { .. } => self.dirty = true,
                dp_mst::UpRequest::ResourceStatus { .. } => {
                    if !p.info.input && p.info.ddps && !self.resource_ports.contains(&sink) {
                        self.resource_ports.push(sink);
                    }
                }
            }
        }
    }

    /// Query resources while the retained routes/payloads still describe the
    /// link. Add our own allocations back to the reported free PBN before
    /// comparing with the streamless probe snapshot. Our allocation notices
    /// therefore do not cause a perpetual stop/probe/relight cycle.
    pub(super) async fn refresh_resources<A: MstAux>(
        &mut self,
        aux: &mut A,
    ) -> Result<(), MstFailure<A::Error>> {
        self.require_transaction_idle()?;
        if self.dirty || self.resource_ports.is_empty() {
            self.resource_ports.clear();
            return Ok(());
        }
        let allocated: Vec<_> = self.payloads.iter().map(|p| (p.sink, p.pbn)).collect();
        // Resolve every route before starting a sideband transaction.
        let mut queries = Vec::new();
        for &sink in &self.resource_ports {
            let old = *self.topology.port(sink).ok_or(MstFailure::Invalid)?;
            let used = used_pbn(&self.topology, sink, &allocated).ok_or(MstFailure::Invalid)?;
            let branch = &self.topology.branches[sink.branch];
            queries.push((sink, branch.lct, branch.rad, old, used));
        }
        self.resource_query = true;
        for (sink, lct, rad, old, used) in queries {
            let (fec, full, free) = self
                .manager
                .path_resources(aux, lct, &rad, sink.port)
                .await?;
            let available = (u32::from(free) + used).min(u32::from(full)) as u16;
            self.dirty |= (fec, full, available) != (old.fec, old.full_pbn, old.available_pbn);
        }
        self.resource_ports.clear();
        self.resource_query = false;
        Ok(())
    }

    /// Initialize once, or replace a dirty topology only after all source and
    /// remote payload owners have been retired. Retain the old snapshot until
    /// the complete probe/EDID pass succeeds.
    pub(super) async fn prepare<A: MstAux>(
        &mut self,
        aux: &mut A,
    ) -> Result<(), MstFailure<A::Error>> {
        self.require_transaction_idle()?;
        if self.state == ProbeState::Ready && !self.dirty {
            return Ok(());
        }
        if self.state == ProbeState::Probing || self.has_stream_resources() {
            return Err(MstFailure::Invalid);
        }
        let start = self.state == ProbeState::New;
        self.state = ProbeState::Probing;
        if start {
            let mut dpcd = [0; 16];
            aux.read(0, &mut dpcd).await.map_err(MstError::Aux)?;
            // Even an initially empty branch needs D0: no stream will train
            // its link (and power its receiver) until a downstream sink arrives.
            // Power it before enabling MST and clearing the payload table.
            aux.write(0x600, &[1]).await.map_err(MstError::Aux)?;
            aux.delay(1000).await;
            let mut power = [0];
            aux.read(0x600, &mut power).await.map_err(MstError::Aux)?;
            if power[0] & 7 != 1 {
                return Err(MstFailure::Mst(MstError::Malformed));
            }
            self.manager.start(aux, &dpcd).await?;
        }
        let topology = self.manager.probe(aux).await?;
        let mut outputs = reconcile(&self.outputs, &topology);
        for output in outputs.iter_mut().flatten() {
            if let Some(sink) = output.sink {
                output.edid = read_edid(&mut self.manager, aux, &topology, sink)
                    .await
                    .unwrap_or_default();
                // validate_dsc_caps_on_connector, beside the EDID.
                output.dsc = super::dsc::read_dsc(&mut self.manager, aux, &topology, sink).await;
            }
        }
        self.topology = topology;
        self.outputs = outputs;
        self.resource_ports.clear();
        self.lost.clear();
        self.primary_replaced = false;
        self.dirty = false;
        self.state = ProbeState::Ready;
        Ok(())
    }
}

/// The same branch device in two probes: its GUID at the same route.
fn same_branch(a: &dp_mst_mgr::Branch, b: &dp_mst_mgr::Branch) -> bool {
    a.guid == b.guid && a.lct == b.lct && a.rad == b.rad
}

/// `new` renumbered so that every branch surviving from `old` (same GUID
/// and route) keeps its index: the `Sink`s of live payloads and running
/// selections stay valid, as Linux's drm_dp_mst_branch/port objects survive
/// a downstream change. New branches take vacated indices, then append;
/// unfilled vacancies become unreachable placeholders with no ports. None
/// for another primary branch.
fn keep_indices(old: &Topology, new: Topology) -> Option<Topology> {
    let (old_root, new_root) = (old.branches.first()?, new.branches.first()?);
    if !same_branch(old_root, new_root) {
        return None;
    }
    let n = new.branches.len();
    let mut map: Vec<Option<usize>> = alloc::vec![None; n];
    let mut taken = alloc::vec![false; old.branches.len()];
    for (j, b) in new.branches.iter().enumerate() {
        let i = old.branches.iter().position(|o| same_branch(o, b));
        if let Some(i) = i.filter(|&i| !taken[i]) {
            map[j] = Some(i);
            taken[i] = true;
        }
    }
    let mut free = (0..old.branches.len()).filter(|&i| !taken[i]);
    let mut next = old.branches.len();
    for slot in map.iter_mut().filter(|m| m.is_none()) {
        *slot = Some(free.next().unwrap_or_else(|| {
            next += 1;
            next - 1
        }));
    }
    let len = next;
    let mut branches: Vec<Option<dp_mst_mgr::Branch>> = alloc::vec![None; len];
    for (j, mut b) in new.branches.into_iter().enumerate() {
        for port in &mut b.ports {
            port.branch = port.branch.and_then(|c| map.get(c).copied().flatten());
        }
        branches[map[j]?] = Some(b);
    }
    Some(Topology {
        branches: branches
            .into_iter()
            .map(|b| {
                b.unwrap_or(dp_mst_mgr::Branch {
                    lct: 0,
                    rad: [0; 8],
                    guid: [0; 16],
                    ports: Vec::new(),
                })
            })
            .collect(),
    })
}

impl MstLink {
    /// A downstream change while streams run, as Linux handles a connection
    /// notification (drm_dp_mst_handle_conn_stat, then the link-address
    /// probe of new branches) without touching unaffected streams: probe
    /// the tree again, keep the surviving branches' indices, add the
    /// driver's own payloads back to each hop's reported free PBN, and
    /// adopt the new topology only when every payload's end device is still
    /// connected behind the same route with its PBN inside every hop's
    /// budget. Then the outputs and their EDID/DSC are reconciled as a
    /// fresh probe does and the session is clean (`Ok(true)`). Otherwise
    /// the old topology, its routes and the dirty mark stay for the
    /// stop/reprobe/relight path (`Ok(false)`); when what failed is only
    /// that some payloads' end devices left, those sinks are recorded in
    /// `lost` so their streams alone can be retired (Linux disables the
    /// departed connectors' CRTCs and keeps the rest), after which the next
    /// reprobe adopts the tree. A failed or cancelled probe retains the
    /// session as `prepare` does.
    pub(super) async fn reprobe_live<A: MstAux>(
        &mut self,
        aux: &mut A,
    ) -> Result<bool, MstFailure<A::Error>> {
        self.require_transaction_idle()?;
        if self.state != ProbeState::Ready || !self.dirty || !self.has_stream_resources() {
            return Err(MstFailure::Invalid);
        }
        self.state = ProbeState::Probing;
        let probed = self.manager.probe(aux).await?;
        self.state = ProbeState::Ready;
        let Some(mut topology) = keep_indices(&self.topology, probed) else {
            self.primary_replaced = true;
            return Ok(false);
        };
        let allocated: Vec<_> = self.payloads.iter().map(|p| (p.sink, p.pbn)).collect();
        let ends = topology.sinks();
        let lost: Vec<_> = allocated
            .iter()
            .map(|a| a.0)
            .filter(|sink| !ends.contains(sink))
            .collect();
        if !lost.is_empty() {
            self.lost = lost;
            return Ok(false);
        }
        // ENUM_PATH_RESOURCES reports what our own payloads left free.
        let mut credited = topology.clone();
        for (b, branch) in topology.branches.iter().enumerate() {
            for (k, port) in branch.ports.iter().enumerate() {
                let hop = dp_mst_mgr::Sink {
                    branch: b,
                    port: port.info.port,
                };
                let Some(used) = used_pbn(&topology, hop, &allocated) else {
                    return Ok(false);
                };
                let available =
                    (u32::from(port.available_pbn) + used).min(u32::from(port.full_pbn));
                credited.branches[b].ports[k].available_pbn = available as u16;
            }
        }
        topology = credited;
        for (i, &(sink, pbn)) in allocated.iter().enumerate() {
            let others: Vec<_> = allocated
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, &a)| a)
                .collect();
            if path_budget(&topology, sink, &others).is_none_or(|free| pbn > free) {
                return Ok(false);
            }
        }
        // Every live route survives (a branch keeps its index only at its
        // old GUID and route): the payload sinks stay valid as they are.
        self.state = ProbeState::Probing;
        let mut outputs = reconcile(&self.outputs, &topology);
        for output in outputs.iter_mut().flatten() {
            if let Some(sink) = output.sink {
                output.edid = read_edid(&mut self.manager, aux, &topology, sink)
                    .await
                    .unwrap_or_default();
                output.dsc = super::dsc::read_dsc(&mut self.manager, aux, &topology, sink).await;
            }
        }
        self.topology = topology;
        self.outputs = outputs;
        self.resource_ports.clear();
        self.lost.clear();
        self.dirty = false;
        self.state = ProbeState::Ready;
        Ok(true)
    }
}

fn used_pbn(
    topology: &Topology,
    hop: dp_mst_mgr::Sink,
    allocated: &[(dp_mst_mgr::Sink, u16)],
) -> Option<u32> {
    allocated.iter().try_fold(0u32, |total, &(sink, pbn)| {
        let path = topology.path(sink)?;
        total.checked_add(if path.contains(&hop) {
            u32::from(pbn)
        } else {
            0
        })
    })
}

/// Available PBN at the tightest hop, accounting for all sibling payloads
/// which share that hop. Zero means exhausted, never unspecified/unlimited.
pub(super) fn path_budget(
    topology: &Topology,
    sink: dp_mst_mgr::Sink,
    allocated: &[(dp_mst_mgr::Sink, u16)],
) -> Option<u16> {
    topology
        .path(sink)?
        .iter()
        .try_fold(u16::MAX, |budget, &hop| {
            let port = topology.port(hop)?;
            let used = used_pbn(topology, hop, allocated)?;
            let free = u32::from(port.available_pbn.min(port.full_pbn)).checked_sub(used)?;
            Some(budget.min(free as u16))
        })
}

pub(super) async fn read_edid<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    sink: dp_mst_mgr::Sink,
) -> Result<Vec<u8>, MstFailure<A::Error>> {
    let first = manager.read_edid_block(aux, topology, sink, 0).await?;
    let mut edid = first.to_vec();
    for block in 1..=first[126] {
        edid.extend_from_slice(&manager.read_edid_block(aux, topology, sink, block).await?);
    }
    Ok(edid)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::dp_mst_mgr::tests::Hub;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn run<T>(f: impl core::future::Future<Output = T>) -> T {
        narf_scheduler::block_on_spin(f)
    }

    fn navi48_mst_slots_survive_reorder_removal_and_replacement() -> TestResult {
        let mut hub = Hub::new();
        let topology = run(Manager::new().probe(&mut hub)).unwrap();
        let slots = reconcile(&Default::default(), &topology);
        let ids =
            |s: &[Option<MstOutput>; MST_OUTPUTS]| s.each_ref().map(|o| o.as_ref().map(|o| o.id));
        let original = ids(&slots);
        // A branch inserted ahead of the old child changes its Sink index.
        let mut reordered = topology.clone();
        let mut extra = reordered.branches[1].clone();
        extra.guid = [0x77; 16];
        extra.rad[0] = 0x30;
        reordered.branches.insert(1, extra);
        reordered.branches[0].ports.reverse();
        let reordered_slots = reconcile(&slots, &reordered);
        assert_eq!(ids(&reordered_slots)[..2], original[..2]);
        assert_eq!(reordered_slots[1].as_ref().unwrap().sink.unwrap().branch, 2);
        assert_eq!(reordered_slots[2].as_ref().unwrap().sink.unwrap().branch, 1);

        // Remove the entire child. Its reservation remains while the root
        // sink stays in slot 0; replug restores the same slot and identity.
        let mut removed = topology.clone();
        removed.branches.truncate(1);
        let absent = reconcile(&reordered_slots, &removed);
        assert_eq!(absent[1].as_ref().unwrap().sink, None);
        assert_eq!(ids(&absent), ids(&reordered_slots));
        let restored = reconcile(&absent, &topology);
        assert_eq!(ids(&restored)[..2], original[..2]);
        assert_eq!(restored[1].as_ref().unwrap().sink.unwrap().branch, 1);

        // A new root GUID makes every end connector a new identity, even if
        // its downstream branch GUID and route happen to match the old hub.
        let mut replacement = topology.clone();
        replacement.branches[0].guid = [0x99; 16];
        let new = reconcile(&restored, &replacement);
        for o in new.iter().flatten().filter(|o| o.sink.is_some()) {
            assert_eq!(o.id.root, [0x99; 16]);
            assert!(!original.contains(&Some(o.id)));
        }
        // More end devices than four (the pipes) take slots of their own.
        let full = reconcile(&new, &reordered);
        let survivor = full.iter().flatten().find(|o| o.sink.is_some()).unwrap().id;
        let mut wider = reordered.clone();
        for k in 0..4 {
            let mut b = wider.branches[1].clone();
            b.guid = [0x60 + k; 16];
            b.rad[0] = (4 + k) << 4;
            wider.branches.push(b);
        }
        let wide = reconcile(&full, &wider);
        assert_eq!(
            wide.iter().flatten().filter(|o| o.sink.is_some()).count(),
            wider.sinks().len()
        );
        assert!(wider.sinks().len() > 4);
        // At capacity, reclaim disconnected reservations, never a survivor.
        let mut many = reordered.clone();
        for k in 0..MST_OUTPUTS as u8 + 2 {
            let mut b = many.branches[1].clone();
            b.guid = [0x80 + k; 16];
            b.rad[0] = k;
            many.branches.push(b);
        }
        let full = reconcile(&full, &many);
        assert_eq!(
            full.iter().flatten().filter(|o| o.sink.is_some()).count(),
            MST_OUTPUTS
        );
        assert!(full
            .iter()
            .flatten()
            .any(|o| o.id == survivor && o.sink.is_some()));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dp-mst",
        navi48_mst_slots_survive_reorder_removal_and_replacement
    );

    fn notice(guid: [u8; 16], port: u8) -> dp_mst::UpRequest {
        dp_mst::UpRequest::ConnectionStatus {
            port,
            guid,
            legacy_plug: false,
            dp_plug: false,
            message_capable: false,
            input: false,
            peer_device_type: 0,
        }
    }

    fn navi48_mst_reprobe_retains_routes_until_payload_retirement() -> TestResult {
        let mut hub = Hub::new();
        hub.dpcd.insert(0, 0x14);
        hub.edid[126] = 0;
        hub.require_power = true;
        let mut link = MstLink::default();
        run(link.prepare(&mut hub)).unwrap();
        link.manager.events.clear();
        let before = link.topology.clone();
        let id = link.outputs[1].as_ref().unwrap().id;
        let sink = link.outputs[1].as_ref().unwrap().sink.unwrap();
        link.owner = Some(1);
        link.payloads.push(MstPayload {
            sink,
            vcpi: 1,
            start: 1,
            slots: 10,
            pbn: 100,
            stream: 1,
        });
        hub.child_present = false;
        link.manager.events.push(notice([0x11; 16], 2));
        link.consume_events();
        let sent = hub.requests.len();
        assert_eq!(run(link.prepare(&mut hub)), Err(MstFailure::Invalid));
        assert_eq!(hub.requests.len(), sent);
        assert_eq!(link.topology, before);
        assert!(link.dirty);
        link.owner = None;
        // A retained remote payload alone still prevents reprobe.
        assert_eq!(run(link.prepare(&mut hub)), Err(MstFailure::Invalid));
        link.payloads.clear();
        run(link.prepare(&mut hub)).unwrap();
        assert_eq!(link.topology.branches.len(), 1);
        assert_eq!(link.outputs[1].as_ref().unwrap().sink, None);
        assert_eq!(link.outputs[1].as_ref().unwrap().id, id);
        // Empty topology also keeps the session alive. Later notices arrive
        // on that manager with no running CRTC and restore the reservations.
        hub.root_sink_present = false;
        link.manager.events.push(notice([0x11; 16], 1));
        link.consume_events();
        run(link.prepare(&mut hub)).unwrap();
        assert!(link.outputs.iter().flatten().all(|o| o.sink.is_none()));
        assert_eq!(hub.dpcd[&0x111], 7);
        assert_eq!(hub.dpcd[&0x600], 1);
        hub.child_present = true;
        link.manager.events.push(notice([0x11; 16], 2));
        link.consume_events();
        run(link.prepare(&mut hub)).unwrap();
        assert_eq!(link.outputs[1].as_ref().unwrap().id, id);
        assert_eq!(link.outputs[1].as_ref().unwrap().sink, Some(sink));
        // Reprobe never repeats CLEAR_PAYLOAD_ID_TABLE or resets MSTM_CTRL.
        assert_eq!(
            hub.bodies
                .iter()
                .filter(|b| b[0] == dp_mst::CLEAR_PAYLOAD_ID_TABLE)
                .count(),
            1
        );
        let sent = hub.requests.len();
        link.manager.events.push(notice([0xaa; 16], 1));
        link.manager.events.push(dp_mst::UpRequest::ResourceStatus {
            port: 1,
            guid: [0xaa; 16],
            available_pbn: 1,
        });
        link.consume_events();
        run(link.prepare(&mut hub)).unwrap();
        assert_eq!(hub.requests.len(), sent);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dp-mst",
        navi48_mst_reprobe_retains_routes_until_payload_retirement
    );

    fn navi48_mst_resources_requery_without_relighting_own_allocations() -> TestResult {
        let mut hub = Hub::new();
        hub.dpcd.insert(0, 0x14);
        hub.edid[126] = 0;
        let mut link = MstLink::default();
        run(link.prepare(&mut hub)).unwrap();
        link.manager.events.clear();
        let before = link.topology.clone();
        let ids = link.outputs.each_ref().map(|o| o.as_ref().map(|o| o.id));
        let sink = dp_mst_mgr::Sink { branch: 1, port: 1 };
        link.owner = Some(1);
        link.payloads.push(MstPayload {
            sink,
            vcpi: 1,
            start: 1,
            slots: 20,
            pbn: 900,
            stream: 1,
        });
        // Root output 2 carries the child stream. An old/duplicated notice is
        // only a hint; query its current free capacity and add our 900 back.
        hub.resources.insert((1, 2), (2562, 1652));
        let event = dp_mst::UpRequest::ResourceStatus {
            port: 2,
            guid: [0x11; 16],
            available_pbn: 0,
        };
        link.manager.events.extend([event; 3]);
        for (guid, port) in [
            ([0x11; 16], 0),
            ([0x11; 16], 3),
            ([0x11; 16], 15),
            ([0xaa; 16], 2),
        ] {
            link.manager.events.push(dp_mst::UpRequest::ResourceStatus {
                guid,
                port,
                available_pbn: 100,
            });
        }
        link.consume_events();
        let sent = hub.requests.len();
        run(link.refresh_resources(&mut hub)).unwrap();
        assert_eq!(hub.requests.len(), sent + 1);
        assert!(!link.dirty && !link.resource_query_pending());
        assert_eq!(link.topology, before);
        // External demand has reduced the capacity. Keep every old route and
        // payload until the owner stops them, then reprobe authoritatively.
        hub.resources.insert((1, 2), (2562, 1000));
        link.manager.events.push(event);
        link.consume_events();
        run(link.refresh_resources(&mut hub)).unwrap();
        assert!(link.dirty);
        assert_eq!(link.topology, before);
        assert_eq!(run(link.prepare(&mut hub)), Err(MstFailure::Invalid));
        link.owner = None;
        link.payloads.clear();
        hub.resources.insert((1, 2), (2562, 1900));
        run(link.prepare(&mut hub)).unwrap();
        assert_eq!(path_budget(&link.topology, sink, &[]), Some(1900));
        assert_eq!(
            link.outputs.each_ref().map(|o| o.as_ref().map(|o| o.id)),
            ids
        );
        // A later all-off bandwidth loss, including zero, is not ignored.
        hub.resources.insert((1, 2), (2562, 0));
        link.manager.events.push(event);
        link.consume_events();
        run(link.refresh_resources(&mut hub)).unwrap();
        assert!(link.dirty);
        run(link.prepare(&mut hub)).unwrap();
        assert_eq!(path_budget(&link.topology, sink, &[]), Some(0));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dp-mst",
        navi48_mst_resources_requery_without_relighting_own_allocations
    );

    fn navi48_mst_path_budget_accounts_for_shared_ancestors() -> TestResult {
        let mut hub = Hub::new();
        let mut tree = run(Manager::new().probe(&mut hub)).unwrap();
        let a = dp_mst_mgr::Sink { branch: 1, port: 1 };
        let b = dp_mst_mgr::Sink { branch: 1, port: 2 };
        let mut peer = tree.branches[1].ports[1];
        peer.info.port = 2;
        tree.branches[1].ports[2] = peer;
        assert_eq!(path_budget(&tree, a, &[]), Some(2552));
        assert_eq!(path_budget(&tree, b, &[(a, 900)]), Some(1652));
        assert_eq!(path_budget(&tree, b, &[(a, 2552)]), Some(0));
        assert_eq!(path_budget(&tree, b, &[(a, 2553)]), None);
        let root_sink = dp_mst_mgr::Sink { branch: 0, port: 1 };
        assert_eq!(path_budget(&tree, b, &[(root_sink, 900)]), Some(2552));
        // Reject disconnected hops, absent parents and ambiguous parentage.
        tree.branches[0].ports[2].info.ddps = false;
        assert_eq!(path_budget(&tree, a, &[]), None);
        tree.branches[0].ports[2].info.ddps = true;
        tree.branches[0].ports[1].branch = Some(1);
        assert_eq!(path_budget(&tree, a, &[]), None);
        tree.branches[0].ports[1].branch = None;
        tree.branches[0].ports[2].branch = None;
        assert_eq!(path_budget(&tree, a, &[]), None);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dp-mst",
        navi48_mst_path_budget_accounts_for_shared_ancestors
    );

    struct Pending;
    impl MstAux for Pending {
        type Error = ();
        async fn read(&mut self, _: u32, _: &mut [u8]) -> Result<(), ()> {
            core::future::pending().await
        }
        async fn write(&mut self, _: u32, _: &[u8]) -> Result<(), ()> {
            core::future::pending().await
        }
        async fn delay(&mut self, _: u64) {}
    }
    fn navi48_mst_cancelled_probe_cannot_replay() -> TestResult {
        use core::future::Future;
        let mut hub = Hub::new();
        hub.dpcd.insert(0, 0x14);
        hub.edid[126] = 0;
        hub.require_power = true;
        for initial in [true, false] {
            let mut link = MstLink::default();
            if !initial {
                run(link.prepare(&mut hub)).unwrap();
                link.dirty = true;
            }
            let before = link.topology.clone();
            let mut aux = Pending;
            {
                let mut future = core::pin::pin!(link.prepare(&mut aux));
                let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
                assert!(future.as_mut().poll(&mut cx).is_pending());
            }
            assert_eq!(link.state, ProbeState::Probing);
            assert_eq!(link.topology, before);
            assert_eq!(run(link.prepare(&mut aux)), Err(MstFailure::Invalid));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dp-mst",
        navi48_mst_cancelled_probe_cannot_replay
    );

    /// Surviving branches keep their indices across a reprobe whose
    /// depth-first order moved them; new ones fill vacated indices, then
    /// append, and child references follow; another primary is refused.
    fn navi48_mst_reprobe_keeps_branch_indices() -> TestResult {
        let mut hub = Hub::new();
        hub.grandchild_present = true;
        let old = run(Manager::new().probe(&mut hub)).unwrap();
        assert_eq!(old.branches.len(), 3);
        // A new branch first in the walk, the grandchild's old place vacated.
        let mut new = old.clone();
        let mut extra = old.branches[1].clone();
        extra.guid = [0x77; 16];
        extra.rad[0] = 0x30;
        extra.ports.truncate(2);
        new.branches.remove(2);
        new.branches.insert(1, extra.clone());
        // Root port 2 points at the child, now index 2; its port 2 is gone.
        new.branches[0].ports[2].branch = Some(2);
        new.branches[2].ports[2].branch = None;
        new.branches[2].ports[2].info.ddps = false;
        let kept = keep_indices(&old, new).unwrap();
        assert_eq!(kept.branches.len(), 3);
        assert_eq!(kept.branches[0].guid, old.branches[0].guid);
        assert_eq!(kept.branches[1].guid, old.branches[1].guid);
        assert_eq!(kept.branches[2].guid, [0x77; 16]);
        assert_eq!(kept.branches[0].ports[2].branch, Some(1));
        let child_sink = dp_mst_mgr::Sink { branch: 1, port: 1 };
        assert_eq!(kept.port(child_sink), old.port(child_sink));
        assert!(kept.path(child_sink).is_some());
        // Removal only: the vacancy is an unreachable placeholder.
        let mut fewer = old.clone();
        fewer.branches.truncate(2);
        fewer.branches[1].ports[2].branch = None;
        let kept = keep_indices(&old, fewer).unwrap();
        assert_eq!(kept.branches.len(), 3);
        assert!(kept.branches[2].ports.is_empty());
        assert_eq!(kept.sinks().len(), 2);
        let mut other = old.clone();
        other.branches[0].guid = [0x99; 16];
        assert!(keep_indices(&old, other).is_none());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dp-mst",
        navi48_mst_reprobe_keeps_branch_indices
    );

    /// A downstream branch hot-plugged at the end of a daisy chain while
    /// streams run on the root and child sinks: the live reprobe walks the
    /// tree again (no payload-table reset), finds the grandchild at LCT 3,
    /// keeps the running payloads and their sinks, credits their PBN back
    /// to the hops they cross, and gives the new end device a connector
    /// with its EDID. Unplugging that unlit branch is adopted the same way
    /// (its connector reservation stays); losing the child, which carries a
    /// stream, or the shared hop's capacity is not, and leaves the old
    /// routes for the stop/reprobe/relight path.
    fn navi48_mst_downstream_branch_hotplug_keeps_running_streams() -> TestResult {
        let mut hub = Hub::new();
        hub.dpcd.insert(0, 0x14);
        hub.edid[126] = 0;
        let mut link = MstLink::default();
        run(link.prepare(&mut hub)).unwrap();
        link.manager.events.clear();
        let root_sink = dp_mst_mgr::Sink { branch: 0, port: 1 };
        let child_sink = dp_mst_mgr::Sink { branch: 1, port: 1 };
        link.owner = Some(0);
        link.payloads.push(MstPayload {
            sink: root_sink,
            vcpi: 1,
            start: 1,
            slots: 20,
            pbn: 900,
            stream: 0,
        });
        link.payloads.push(MstPayload {
            sink: child_sink,
            vcpi: 2,
            start: 21,
            slots: 20,
            pbn: 900,
            stream: 1,
        });
        let payloads = link.payloads.clone();
        let ids = link.outputs.each_ref().map(|o| o.as_ref().map(|o| o.id));
        // Adoption needs a dirty session with streams.
        assert_eq!(run(link.reprobe_live(&mut hub)), Err(MstFailure::Invalid));
        hub.grandchild_present = true;
        link.manager.events.push(notice([0x22; 16], 2));
        link.consume_events();
        assert!(link.dirty);
        let sent = hub.requests.len();
        assert_eq!(run(link.reprobe_live(&mut hub)), Ok(true));
        assert!(!link.dirty);
        assert_eq!(link.payloads, payloads);
        assert_eq!(link.topology.branches.len(), 3);
        let grand = dp_mst_mgr::Sink { branch: 2, port: 1 };
        assert_eq!(link.topology.sinks(), [root_sink, child_sink, grand]);
        let new_requests = &hub.requests[sent..];
        assert!(new_requests
            .iter()
            .all(|r| r.2 != dp_mst::CLEAR_PAYLOAD_ID_TABLE));
        assert!(new_requests
            .iter()
            .any(|r| (r.0, r.1[0], r.2) == (3, 0x22, dp_mst::LINK_ADDRESS)));
        // The hub reports full - 10 free; our payloads are added back, so
        // the root hop the child's stream crosses is at its full PBN.
        assert_eq!(
            link.topology
                .port(dp_mst_mgr::Sink { branch: 0, port: 2 })
                .unwrap()
                .available_pbn,
            2562
        );
        assert_eq!(
            path_budget(
                &link.topology,
                grand,
                &[(root_sink, 900), (child_sink, 900)]
            ),
            Some(2562 - 900)
        );
        for (k, id) in ids.iter().enumerate() {
            if id.is_some() {
                assert_eq!(link.outputs[k].as_ref().map(|o| o.id), *id);
            }
        }
        let g = link
            .outputs
            .iter()
            .flatten()
            .find(|o| o.sink == Some(grand))
            .unwrap();
        assert_eq!((g.id.lct, g.id.rad[0], g.id.branch), (3, 0x22, [0x55; 16]));
        assert_eq!(g.edid.len(), 128);
        let g_id = g.id;
        // The unlit grandchild leaves: adopted, its slot reserved.
        hub.grandchild_present = false;
        link.manager.events.push(notice([0x22; 16], 2));
        link.consume_events();
        assert_eq!(run(link.reprobe_live(&mut hub)), Ok(true));
        assert_eq!(link.payloads, payloads);
        let g = link
            .outputs
            .iter()
            .flatten()
            .find(|o| o.id == g_id)
            .unwrap();
        assert_eq!(g.sink, None);
        // Not enough left on the shared hop for the child's stream.
        hub.resources.insert((1, 2), (800, 0));
        link.manager.events.push(notice([0x11; 16], 2));
        link.consume_events();
        let before = link.topology.clone();
        assert_eq!(run(link.reprobe_live(&mut hub)), Ok(false));
        assert!(link.dirty);
        assert_eq!(link.topology, before);
        hub.resources.clear();
        assert!(link.lost.is_empty());
        // The child (carrying stream 1) leaves: its route is gone, and only
        // its stream is to retire.
        hub.child_present = false;
        assert_eq!(run(link.reprobe_live(&mut hub)), Ok(false));
        assert!(link.dirty);
        assert_eq!(link.topology, before);
        assert_eq!(link.payloads, payloads);
        assert_eq!(link.lost, [child_sink]);
        // Once that payload is gone the tree is adopted with the root's
        // stream still running.
        link.payloads.retain(|p| p.sink != child_sink);
        assert_eq!(run(link.reprobe_live(&mut hub)), Ok(true));
        assert!(!link.dirty && link.lost.is_empty());
        assert_eq!(link.payloads, payloads[..1]);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dp-mst",
        navi48_mst_downstream_branch_hotplug_keeps_running_streams
    );
}
