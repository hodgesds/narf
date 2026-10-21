use super::*;
use crate::dp_mst_mgr::tests::Hub;
use alloc::vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

fn run<T>(f: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

/// The hub as the AUX channel, shared with the source fake.
struct Aux<'a>(&'a RefCell<Hub>);
impl MstAux for Aux<'_> {
    type Error = ();
    async fn read(&mut self, address: u32, buf: &mut [u8]) -> Result<(), ()> {
        // The hub answers at once: complete it under the borrow.
        run(self.0.borrow_mut().read(address, buf))
    }
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), ()> {
        run(self.0.borrow_mut().write(address, data))
    }
    async fn delay(&mut self, _us: u64) {}
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    /// The source table, with the sink's payload table rows (VCPI, start
    /// slot, slots) and the sideband requests sent so far.
    Table(Vec<(u8, u8)>, usize),
    Rate(u8, (u32, u32)),
}
/// The source: its ACT makes the sink report ACT handled.
struct Source<'a> {
    hub: &'a RefCell<Hub>,
    events: Vec<Event>,
}
impl MstSource for Source<'_> {
    async fn allocation(&mut self, table: &[otg::MstAllocation]) -> Result<(), otg::Error> {
        let mut hub = self.hub.borrow_mut();
        let sent = hub.requests.len();
        hub.dpcd.insert(dp_mst_mgr::PAYLOAD_TABLE_UPDATE_STATUS, 3);
        self.events.push(Event::Table(
            table.iter().map(|a| (a.stream, a.slots)).collect(),
            sent,
        ));
        Ok(())
    }
    async fn vc_rate(&mut self, stream: u8, rate: (u32, u32)) -> Result<(), otg::Error> {
        self.events.push(Event::Rate(stream, rate));
        Ok(())
    }
}

/// Two streams' payloads added and the first removed as amdgpu drives
/// DRM's payload helpers: each add writes the payload table (VCPI, next
/// start slot, slots), then the source table with ACT, waits for ACT
/// handled, sends ALLOCATE_PAYLOAD to the sink's branch and sets the VC
/// rate; the removal zeroes the rate, sends ALLOCATE_PAYLOAD with PBN 0,
/// clears the payload's slots in DPCD, updates the source table and moves
/// the later payload down.
fn navi48_mst_payloads_like_linux() -> TestResult {
    let hub = RefCell::new(Hub::new());
    let mut aux = Aux(&hub);
    let mut link = MstLink::default();
    let mut dpcd = [0u8; 16];
    dpcd[0] = 0x12;
    run(link.manager.start(&mut aux, &dpcd)).unwrap();
    link.topology = run(link.manager.probe(&mut aux)).unwrap();
    let sinks = link.topology.sinks();
    let mut source = Source {
        hub: &hub,
        events: Vec::new(),
    };
    let sent = hub.borrow().requests.len();
    let a = run(add_payload(
        &mut link,
        &mut aux,
        &mut source,
        sinks[0],
        1,
        900,
        12,
        (11, 7),
    ));
    let b = run(add_payload(
        &mut link,
        &mut aux,
        &mut source,
        sinks[1],
        3,
        500,
        7,
        (6, 9),
    ));
    let (Ok(a), Ok(b)) = (a, b) else {
        panic!("add {a:?} {b:?}");
    };
    if (a.vcpi, a.start, b.vcpi, b.start) != (1, 1, 2, 13) {
        return TestResult::Fail("VCPI and start slots");
    }
    // The second branch is behind root port 2: its request goes there.
    let alloc: Vec<(u8, Vec<u8>)> = {
        let h = hub.borrow();
        h.requests[sent..]
            .iter()
            .zip(&h.bodies[sent..])
            .map(|(r, body)| (r.0, body.clone()))
            .collect()
    };
    if alloc
        != [
            (1, vec![0x11, 0x11, 1, 0x03, 0x84, 0]),
            (2, vec![0x11, 0x11, 2, 0x01, 0xf4, 0]),
        ]
    {
        panic!("ALLOCATE_PAYLOAD {alloc:?}");
    }
    let want = [
        Event::Table(vec![(1, 12)], sent),
        Event::Rate(1, (11, 7)),
        Event::Table(vec![(1, 12), (3, 7)], sent + 1),
        Event::Rate(3, (6, 9)),
    ];
    if source.events != want {
        panic!("source {:?}", source.events);
    }
    // The sink's payload table: VCPI, start, slots of the last write.
    let row = |h: &Hub| {
        (0..3)
            .map(|i| h.dpcd[&(dp_mst_mgr::PAYLOAD_ALLOCATE_SET + i)])
            .collect::<Vec<_>>()
    };
    if row(&hub.borrow()) != [2, 13, 7] {
        return TestResult::Fail("payload table write");
    }
    source.events.clear();
    run(remove_payload(&mut link, &mut aux, &mut source, 1, true)).unwrap();
    let h = hub.borrow();
    if h.bodies.last() != Some(&vec![0x11, 0x11, 1, 0, 0, 0])
        || row(&h) != [1, 1, 0]
        || source.events
            != [
                Event::Rate(1, (0, 0)),
                Event::Table(vec![(3, 7)], h.requests.len()),
            ]
        || link.payloads.len() != 1
        || link.payloads[0].start != 1
    {
        panic!(
            "remove {:?} {:?} {:?}",
            h.bodies.last(),
            source.events,
            link.payloads
        );
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dp-mst", navi48_mst_payloads_like_linux);

/// On a 128b/132b link there is no MTP header slot: the first payload
/// starts at slot 0 and the link's 64 slots are all the streams'
/// (drm_dp_mst_update_slots), where 8b/10b would refuse the last one.
fn navi48_uhbr_mst_payloads_start_at_slot_zero() -> TestResult {
    let hub = RefCell::new(Hub::new());
    let mut aux = Aux(&hub);
    let mut link = MstLink {
        uhbr: true,
        ..MstLink::default()
    };
    let mut dpcd = [0u8; 16];
    dpcd[0] = 0x12;
    run(link.manager.start(&mut aux, &dpcd)).unwrap();
    link.topology = run(link.manager.probe(&mut aux)).unwrap();
    let sinks = link.topology.sinks();
    let mut source = Source {
        hub: &hub,
        events: Vec::new(),
    };
    let add = |link: &mut MstLink, aux: &mut Aux, source: &mut Source, sink, stream, slots| {
        run(add_payload(
            link,
            aux,
            source,
            sink,
            stream,
            100,
            slots,
            (1, 0),
        ))
    };
    let a = add(&mut link, &mut aux, &mut source, sinks[0], 1, 12).unwrap();
    let b = add(&mut link, &mut aux, &mut source, sinks[1], 3, 52).unwrap();
    if (a.start, b.start) != (0, 12) {
        return TestResult::Fail("128b/132b start slots");
    }
    run(remove_payload(&mut link, &mut aux, &mut source, 1, true)).unwrap();
    if link.payloads[0].start != 0 {
        return TestResult::Fail("payload moved down to slot 0");
    }
    // 52 + 12 fills the link exactly; one more slot is refused.
    if add(&mut link, &mut aux, &mut source, sinks[0], 1, 12).map(|p| p.start) != Ok(52)
        || link
            .payloads
            .iter()
            .map(|p| u32::from(p.slots))
            .sum::<u32>()
            != 64
    {
        return TestResult::Fail("the full 64 slots");
    }
    run(remove_payload(&mut link, &mut aux, &mut source, 1, true)).unwrap();
    if add(&mut link, &mut aux, &mut source, sinks[0], 1, 13).is_ok() {
        return TestResult::Fail("65 slots");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    navi48_uhbr_mst_payloads_start_at_slot_zero
);

fn navi48_mst_unplug_removes_payload_without_aux() -> TestResult {
    // Every possible AUX operation fails the test: an unplug must only
    // retire source state, without waiting for remote replies or ACT status.
    struct Absent;
    impl MstAux for Absent {
        type Error = ();
        async fn read(&mut self, _: u32, _: &mut [u8]) -> Result<(), ()> {
            panic!("AUX read after unplug")
        }
        async fn write(&mut self, _: u32, _: &[u8]) -> Result<(), ()> {
            panic!("AUX write after unplug")
        }
        async fn delay(&mut self, _: u64) {
            panic!("AUX wait after unplug")
        }
    }
    let hub = RefCell::new(Hub::new());
    let topology = run(Manager::new().probe(&mut *hub.borrow_mut())).unwrap();
    let mut link = MstLink {
        topology,
        ..Default::default()
    };
    link.payloads.push(MstPayload {
        sink: link.topology.sinks()[1],
        vcpi: 1,
        start: 1,
        slots: 10,
        pbn: 100,
        stream: 3,
    });
    let mut source = Source {
        hub: &hub,
        events: Vec::new(),
    };
    run(remove_payload(
        &mut link,
        &mut Absent,
        &mut source,
        3,
        false,
    ))
    .unwrap();
    assert!(link.payloads.is_empty());
    assert_eq!(
        source.events,
        [
            Event::Rate(3, (0, 0)),
            Event::Table(Vec::new(), hub.borrow().requests.len())
        ]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    navi48_mst_unplug_removes_payload_without_aux
);

#[derive(Clone, Copy)]
enum Fault {
    Error,
    Cancel,
}
/// A deterministic failure/drop boundary on either side of every AUX/source
/// operation. Cancellation uses Pending, never a race against a hardware timer.
struct Gate {
    calls: core::cell::Cell<usize>,
    fault: Option<(usize, bool, Fault)>,
}
impl Gate {
    async fn check(&self, call: usize, after: bool) -> Result<(), ()> {
        if let Some((at, late, fault)) = self.fault {
            if call == at && late == after {
                match fault {
                    Fault::Error => return Err(()),
                    Fault::Cancel => core::future::pending::<()>().await,
                }
            }
        }
        Ok(())
    }
    async fn before(&self) -> Result<usize, ()> {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        self.check(call, false).await?;
        Ok(call)
    }
}
struct FaultAux<'a> {
    inner: Aux<'a>,
    gate: &'a Gate,
}
impl MstAux for FaultAux<'_> {
    type Error = ();
    async fn read(&mut self, at: u32, buf: &mut [u8]) -> Result<(), ()> {
        let call = self.gate.before().await?;
        self.inner.read(at, buf).await?;
        self.gate.check(call, true).await
    }
    async fn write(&mut self, at: u32, buf: &[u8]) -> Result<(), ()> {
        let call = self.gate.before().await?;
        self.inner.write(at, buf).await?;
        self.gate.check(call, true).await
    }
    async fn delay(&mut self, us: u64) {
        self.inner.delay(us).await;
    }
}
struct FaultSource<'a> {
    inner: Source<'a>,
    gate: &'a Gate,
}
impl MstSource for FaultSource<'_> {
    async fn allocation(&mut self, table: &[otg::MstAllocation]) -> Result<(), otg::Error> {
        let call = self.gate.before().await.map_err(|()| otg::Error::Busy)?;
        self.inner.allocation(table).await?;
        self.gate
            .check(call, true)
            .await
            .map_err(|()| otg::Error::Busy)
    }
    async fn vc_rate(&mut self, stream: u8, rate: (u32, u32)) -> Result<(), otg::Error> {
        let call = self.gate.before().await.map_err(|()| otg::Error::Busy)?;
        self.inner.vc_rate(stream, rate).await?;
        self.gate
            .check(call, true)
            .await
            .map_err(|()| otg::Error::Busy)
    }
}
fn poll_once<F: core::future::Future>(f: F) -> core::task::Poll<F::Output> {
    let mut f = core::pin::pin!(f);
    f.as_mut().poll(&mut core::task::Context::from_waker(
        core::task::Waker::noop(),
    ))
}
fn payload_fixture(remove: bool) -> (RefCell<Hub>, MstLink) {
    let mut hub = Hub::new();
    hub.dpcd.insert(0, 0x14);
    hub.edid[126] = 0;
    let mut link = MstLink::default();
    run(link.prepare(&mut hub)).unwrap();
    let hub = RefCell::new(hub);
    if remove {
        let sink = link.topology.sinks()[0];
        let mut source = Source {
            hub: &hub,
            events: Vec::new(),
        };
        run(add_payload(
            &mut link,
            &mut Aux(&hub),
            &mut source,
            sink,
            1,
            900,
            12,
            (11, 7),
        ))
        .unwrap();
    }
    (hub, link)
}
async fn change_payload(
    link: &mut MstLink,
    aux: &mut FaultAux<'_>,
    source: &mut FaultSource<'_>,
    remove: bool,
) -> Result<(), MstFailure<()>> {
    if remove {
        remove_payload(link, aux, source, 1, true).await
    } else {
        let sink = link.topology.sinks()[0];
        add_payload(link, aux, source, sink, 1, 900, 12, (11, 7))
            .await
            .map(|_| ())
    }
}

fn payload_faults(fault: Fault) -> TestResult {
    for remove in [false, true] {
        let (hub, mut link) = payload_fixture(remove);
        let gate = Gate {
            calls: core::cell::Cell::new(0),
            fault: None,
        };
        let mut aux = FaultAux {
            inner: Aux(&hub),
            gate: &gate,
        };
        let mut source = FaultSource {
            inner: Source {
                hub: &hub,
                events: Vec::new(),
            },
            gate: &gate,
        };
        assert_eq!(
            poll_once(change_payload(&mut link, &mut aux, &mut source, remove)),
            core::task::Poll::Ready(Ok(()))
        );
        assert_eq!(link.payload_change(), None);
        let calls = gate.calls.get();
        assert!(calls > 4);
        for call in 1..=calls {
            for after in [false, true] {
                let (hub, mut link) = payload_fixture(remove);
                let gate = Gate {
                    calls: core::cell::Cell::new(0),
                    fault: Some((call, after, fault)),
                };
                let mut aux = FaultAux {
                    inner: Aux(&hub),
                    gate: &gate,
                };
                let mut source = FaultSource {
                    inner: Source {
                        hub: &hub,
                        events: Vec::new(),
                    },
                    gate: &gate,
                };
                let result = poll_once(change_payload(&mut link, &mut aux, &mut source, remove));
                if matches!(fault, Fault::Cancel) {
                    assert!(
                        result.is_pending(),
                        "missed cancellation {call} after={after}"
                    );
                } else if result == core::task::Poll::Ready(Ok(())) {
                    // Preserve the existing best-effort remote-removal/status
                    // policy; its successful source steps complete normally.
                    assert_eq!(link.payload_change(), None);
                    continue;
                } else {
                    assert!(matches!(result, core::task::Poll::Ready(Err(_))));
                }
                let pending = if remove {
                    MstPayloadChange::Removing(1)
                } else {
                    MstPayloadChange::Adding(1)
                };
                assert_eq!(link.payload_change(), Some(pending));
                assert_eq!(link.audio_slots(1), Err(otg::Error::Busy));
                assert_eq!(link.audio_slots(3), Err(otg::Error::Busy));
                let attempted = gate.calls.get();
                let payloads = link.payloads.clone();
                let topology = link.topology.clone();
                // Neither replay nor another stream's mutation may touch the
                // source/sink after an unproven partial change.
                let sink = link.topology.sinks()[1];
                assert_eq!(
                    poll_once(add_payload(
                        &mut link,
                        &mut aux,
                        &mut source,
                        sink,
                        3,
                        500,
                        7,
                        (6, 9)
                    )),
                    core::task::Poll::Ready(Err(otg::Error::Busy.into()))
                );
                assert_eq!(
                    poll_once(remove_payload(&mut link, &mut aux, &mut source, 1, false)),
                    core::task::Poll::Ready(Err(otg::Error::Busy.into()))
                );
                for dirty in [false, true] {
                    link.dirty = dirty;
                    assert_eq!(
                        poll_once(link.prepare(&mut aux)),
                        core::task::Poll::Ready(Err(otg::Error::Busy.into()))
                    );
                }
                assert!(
                    link.has_stream_resources(),
                    "empty bookkeeping lost uncertain ownership"
                );
                assert_eq!(gate.calls.get(), attempted);
                assert_eq!(link.payload_change(), Some(pending));
                assert_eq!(link.payloads, payloads);
                assert_eq!(link.topology, topology);
            }
        }
    }
    TestResult::Pass
}
fn navi48_mst_payload_errors_quarantine_incomplete_source_and_sink_changes() -> TestResult {
    payload_faults(Fault::Error)
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    navi48_mst_payload_errors_quarantine_incomplete_source_and_sink_changes
);
fn navi48_mst_payload_cancellation_retains_even_empty_bookkeeping() -> TestResult {
    payload_faults(Fault::Cancel)
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    navi48_mst_payload_cancellation_retains_even_empty_bookkeeping
);

fn navi48_mst_payload_preflight_rejection_leaves_transaction_reusable() -> TestResult {
    let (hub, mut link) = payload_fixture(true);
    let mut aux = Aux(&hub);
    let mut source = Source {
        hub: &hub,
        events: Vec::new(),
    };
    let sink = link.topology.sinks()[1];
    let sent = hub.borrow().requests.len();
    assert_eq!(
        run(add_payload(
            &mut link,
            &mut aux,
            &mut source,
            sink,
            1,
            500,
            7,
            (6, 9)
        )),
        Err(MstFailure::Invalid)
    );
    assert_eq!(
        run(remove_payload(&mut link, &mut aux, &mut source, 3, true)),
        Err(MstFailure::Invalid)
    );
    assert_eq!(link.payload_change(), None);
    assert!(source.events.is_empty());
    assert_eq!(hub.borrow().requests.len(), sent);
    run(add_payload(
        &mut link,
        &mut aux,
        &mut source,
        sink,
        3,
        500,
        7,
        (6, 9),
    ))
    .unwrap();
    assert_eq!(link.payload_change(), None);
    run(remove_payload(&mut link, &mut aux, &mut source, 1, true)).unwrap();
    assert_eq!(link.payload_change(), None);
    assert_eq!(link.payloads.len(), 1);
    assert_eq!((link.payloads[0].stream, link.payloads[0].start), (3, 1));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    navi48_mst_payload_preflight_rejection_leaves_transaction_reusable
);

fn navi48_mst_resource_queries_retain_uncertain_transactions() -> TestResult {
    let fixture = |active| {
        let (hub, mut link) = payload_fixture(active);
        link.manager.events.clear();
        link.resource_ports.push(link.topology.sinks()[0]);
        if active {
            hub.borrow_mut().resources.insert((1, 1), (2561, 1651));
        }
        (hub, link)
    };
    for active in [false, true] {
        let (hub, mut link) = fixture(active);
        let gate = Gate {
            calls: core::cell::Cell::new(0),
            fault: None,
        };
        let mut aux = FaultAux {
            inner: Aux(&hub),
            gate: &gate,
        };
        assert_eq!(
            poll_once(link.refresh_resources(&mut aux)),
            core::task::Poll::Ready(Ok(()))
        );
        assert!(!link.dirty && !link.resource_query_pending());
        let calls = gate.calls.get();
        assert!(calls >= 4);
        for call in 1..=calls {
            for after in [false, true] {
                for fault in [Fault::Error, Fault::Cancel] {
                    let (hub, mut link) = fixture(active);
                    let topology = link.topology.clone();
                    let payloads = link.payloads.clone();
                    let gate = Gate {
                        calls: core::cell::Cell::new(0),
                        fault: Some((call, after, fault)),
                    };
                    let mut aux = FaultAux {
                        inner: Aux(&hub),
                        gate: &gate,
                    };
                    let result = poll_once(link.refresh_resources(&mut aux));
                    match fault {
                        Fault::Error => assert!(matches!(result, core::task::Poll::Ready(Err(_)))),
                        Fault::Cancel => assert!(result.is_pending()),
                    }
                    assert!(link.resource_query_pending() && link.has_stream_resources());
                    let attempted = gate.calls.get();
                    let mut source = Source {
                        hub: &hub,
                        events: Vec::new(),
                    };
                    let busy = core::task::Poll::Ready(Err(otg::Error::Busy.into()));
                    assert_eq!(poll_once(link.refresh_resources(&mut aux)), busy);
                    assert_eq!(poll_once(link.prepare(&mut aux)), busy);
                    assert_eq!(
                        poll_once(remove_payload(&mut link, &mut aux, &mut source, 1, false)),
                        busy
                    );
                    let sink = link.topology.sinks()[1];
                    assert_eq!(
                        poll_once(add_payload(
                            &mut link,
                            &mut aux,
                            &mut source,
                            sink,
                            3,
                            500,
                            7,
                            (6, 9)
                        )),
                        core::task::Poll::Ready(Err(otg::Error::Busy.into()))
                    );
                    assert_eq!(gate.calls.get(), attempted);
                    assert!(source.events.is_empty());
                    assert_eq!(link.topology, topology);
                    assert_eq!(link.payloads, payloads);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    navi48_mst_resource_queries_retain_uncertain_transactions
);

fn navi48_mst_audio_requires_completed_manager_payload() -> TestResult {
    let (_, mut link) = payload_fixture(true);
    assert_eq!(link.audio_slots(1), Err(otg::Error::Invalid));
    link.owner = Some(0);
    assert_eq!(link.audio_slots(1), Ok(12));
    assert_eq!(link.audio_slots(3), Err(otg::Error::Invalid));
    link.resource_query = true;
    assert_eq!(link.audio_slots(1), Err(otg::Error::Busy));
    link.resource_query = false;
    link.payloads.push(link.payloads[0]);
    assert_eq!(link.audio_slots(1), Err(otg::Error::Invalid));
    link.payloads.pop();
    for slots in [0, 64] {
        link.payloads[0].slots = slots;
        assert_eq!(link.audio_slots(1), Err(otg::Error::Invalid));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    navi48_mst_audio_requires_completed_manager_payload
);

/// Three streams on one link through a daisy chain (primary, child and
/// grandchild branch each with an end device) share its payload table as
/// DRM's helpers fill it: VCPIs 1..3 at consecutive start slots, each
/// ALLOCATE_PAYLOAD sent to the end device's own branch (LCT 1, 2 and 3,
/// RAD 2 and 2.2), every add checked against every hop the chain shares.
/// Removing the middle stream deallocates at the child and moves the
/// grandchild's payload down, keeping the others.
fn navi48_mst_daisy_chain_shares_one_payload_table() -> TestResult {
    let hub = RefCell::new(Hub::new());
    hub.borrow_mut().grandchild_present = true;
    let mut aux = Aux(&hub);
    let mut link = MstLink::default();
    let mut dpcd = [0u8; 16];
    dpcd[0] = 0x12;
    run(link.manager.start(&mut aux, &dpcd)).unwrap();
    link.topology = run(link.manager.probe(&mut aux)).unwrap();
    let sinks = link.topology.sinks();
    assert_eq!(sinks.len(), 3);
    let mut source = Source {
        hub: &hub,
        events: Vec::new(),
    };
    let add = |link: &mut MstLink, aux: &mut Aux, source: &mut Source, k: usize, pbn| {
        run(add_payload(
            link,
            aux,
            source,
            sinks[k],
            k as u8,
            pbn,
            10,
            (9, 1),
        ))
    };
    let sent = hub.borrow().requests.len();
    let mut starts = Vec::new();
    for k in 0..2 {
        let p = add(&mut link, &mut aux, &mut source, k, 600).unwrap();
        starts.push((p.vcpi, p.start));
    }
    // The grandchild's stream crosses the root hop the child's already
    // uses: more than what is left there is refused before any write.
    let allocated: Vec<_> = link.payloads.iter().map(|p| (p.sink, p.pbn)).collect();
    assert_eq!(
        topology::path_budget(&link.topology, sinks[2], &allocated),
        Some(2552 - 600)
    );
    let writes = hub.borrow().requests.len();
    assert!(add(&mut link, &mut aux, &mut source, 2, 2000).is_err());
    assert_eq!(hub.borrow().requests.len(), writes);
    assert_eq!(link.payload_change(), None);
    let p = add(&mut link, &mut aux, &mut source, 2, 600).unwrap();
    starts.push((p.vcpi, p.start));
    assert_eq!(starts, [(1, 1), (2, 11), (3, 21)]);
    let allocs: Vec<(u8, u8, Vec<u8>)> = {
        let h = hub.borrow();
        h.requests[sent..]
            .iter()
            .zip(&h.bodies[sent..])
            .map(|(r, b)| (r.0, r.1[0], b.clone()))
            .collect()
    };
    assert_eq!(
        allocs,
        [
            (1, 0x00, vec![0x11, 0x11, 1, 0x02, 0x58, 0]),
            (2, 0x20, vec![0x11, 0x11, 2, 0x02, 0x58, 0]),
            (3, 0x22, vec![0x11, 0x11, 3, 0x02, 0x58, 0]),
        ]
    );
    // The source table lists all three in slot order.
    assert_eq!(
        source.events.iter().rev().find_map(|e| match e {
            Event::Table(t, _) => Some(t.clone()),
            _ => None,
        }),
        Some(vec![(0, 10), (1, 10), (2, 10)])
    );
    source.events.clear();
    run(remove_payload(&mut link, &mut aux, &mut source, 1, true)).unwrap();
    let h = hub.borrow();
    let last = h
        .requests
        .iter()
        .zip(&h.bodies)
        .rev()
        .find(|(r, _)| r.2 == dp_mst::ALLOCATE_PAYLOAD);
    assert_eq!(
        last.map(|(r, b)| (r.0, r.1[0], b.clone())),
        Some((2, 0x20, vec![0x11, 0x11, 2, 0, 0, 0]))
    );
    let rows: Vec<_> = link
        .payloads
        .iter()
        .map(|p| (p.stream, p.vcpi, p.start, p.sink))
        .collect();
    assert_eq!(rows, [(0, 1, 1, sinks[0]), (2, 3, 11, sinks[2])]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    navi48_mst_daisy_chain_shares_one_payload_table
);

const PAYLOAD_VECTORS: &str = include_str!("../tests/dcn401_mst_payload/vectors.txt");

/// One `tests/dcn401_mst_payload` sequence replayed: each addition's time
/// slots (drm_dp_atomic_find_time_slots), its refusal or VCPI and start
/// slot with the payload-table row and ALLOCATE_PAYLOAD `add_payload`
/// sends, each removal's (`remove_payload`), and the final table.
fn replay_payload_vector(line: &str) -> Option<alloc::string::String> {
    use alloc::format;
    use alloc::string::String;
    let (ops, _) = line.split_once(" = ")?;
    let mut words = ops.split(' ');
    let (_, enc, kbps) = (words.next()?, words.next()?, words.next()?);
    let uhbr = enc == "u";
    let div = dp_mst::pbn_div(kbps.parse().ok()?);
    let mut payloads: Vec<MstPayload> = Vec::new();
    let mut out = String::new();
    for op in words {
        let (kind, value) = op.split_at(1);
        let value: u32 = value.parse().ok()?;
        if kind == "a" {
            let slots = dp_mst::time_slots(value, div);
            match allocate_slots(&payloads, uhbr, slots) {
                Err(SlotRefusal::NoSpace) => out += &format!(" {slots}=E28"),
                Err(SlotRefusal::TooMany) => out += &format!(" {slots}=E22"),
                Ok((vcpi, start)) => {
                    out += &format!(" {slots}=w{vcpi}.{start}.{slots}m{vcpi}.{value}");
                    payloads.push(MstPayload {
                        sink: dp_mst_mgr::Sink {
                            branch: 0,
                            port: vcpi,
                        },
                        vcpi,
                        start,
                        slots: slots as u8,
                        pbn: value as u16,
                        stream: vcpi,
                    });
                }
            }
        } else {
            let i = payloads.iter().position(|p| u32::from(p.vcpi) == value)?;
            let removed = payloads.remove(i);
            out += &format!(" m{}.0w{}.{}.0", removed.vcpi, removed.vcpi, removed.start);
            release_slots(&mut payloads, &removed);
        }
    }
    out += " |";
    let mut rows = payloads.clone();
    rows.sort_by_key(|p| p.start);
    if rows.is_empty() {
        out += " -";
    }
    for (k, p) in rows.iter().enumerate() {
        out += &format!(
            "{}{}@{}+{}",
            if k == 0 { " " } else { "," },
            p.vcpi,
            p.start,
            p.slots
        );
    }
    Some(format!("{ops} ={out}"))
}

/// The payload table bookkeeping against DRM's helpers (3000 Linux
/// sequences of stream additions and removals on one manager, both
/// channel codings): time-slot and payload-count refusals, VCPIs, start
/// slots, compaction after a removal, and what each step writes.
fn navi48_mst_payload_table_matches_linux_vectors() -> TestResult {
    let mut n = 0;
    for line in PAYLOAD_VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let got = replay_payload_vector(line);
        if got.as_deref() != Some(line) {
            panic!("payload vector\n  want {line}\n  got  {got:?}");
        }
        n += 1;
    }
    if n != 3000 {
        return TestResult::Fail("vector count");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    navi48_mst_payload_table_matches_linux_vectors
);
