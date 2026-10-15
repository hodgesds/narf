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
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum ProbeState {
    #[default]
    New,
    /// Retained after cancellation/error: no replay of an uncertain session.
    Probing,
    Ready,
}

/// Reserve every surviving identity before admitting new ones. Disconnected
/// slots remain reserved for replug until four slots are needed by other sinks.
fn reconcile(previous: &[Option<MstOutput>; 4], topology: &Topology) -> [Option<MstOutput>; 4] {
    let mut out = previous.clone();
    for o in out.iter_mut().flatten() {
        o.sink = None;
        o.edid.clear();
        o.modes.clear();
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
        });
    }
    out
}

impl MstLink {
    /// Coalesce connection notifications. As in Linux, unknown branches are
    /// ignored; resource-status notifications currently have no policy handler.
    /// Keep this separate from the probe: payload removal still needs old routes.
    pub(super) fn consume_events(&mut self) {
        for event in core::mem::take(&mut self.manager.events) {
            if let dp_mst::UpRequest::ConnectionStatus { guid, port, .. } = event {
                if self
                    .topology
                    .branches
                    .iter()
                    .any(|b| b.guid == guid && b.ports.iter().any(|p| p.info.port == port))
                {
                    self.dirty = true;
                }
            }
        }
    }

    /// Initialize once, or replace a dirty topology only after all source and
    /// remote payload owners have been retired. Retain the old snapshot until
    /// the complete probe/EDID pass succeeds.
    pub(super) async fn prepare<A: MstAux>(
        &mut self,
        aux: &mut A,
    ) -> Result<(), MstFailure<A::Error>> {
        self.require_payload_idle()?;
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
            }
        }
        self.topology = topology;
        self.outputs = outputs;
        self.dirty = false;
        self.state = ProbeState::Ready;
        Ok(())
    }
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
        let ids = |s: &[Option<MstOutput>; 4]| s.each_ref().map(|o| o.as_ref().map(|o| o.id));
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
        // At capacity, reclaim disconnected reservations, never a survivor.
        let full = reconcile(&new, &reordered);
        let survivor = full.iter().flatten().find(|o| o.sink.is_some()).unwrap().id;
        let mut many = reordered.clone();
        for k in 0..6 {
            let mut b = many.branches[1].clone();
            b.guid = [0x80 + k; 16];
            b.rad[0] = (4 + k) << 4;
            many.branches.push(b);
        }
        let full = reconcile(&full, &many);
        assert_eq!(
            full.iter().flatten().filter(|o| o.sink.is_some()).count(),
            4
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
            guid: [0x11; 16],
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
}
