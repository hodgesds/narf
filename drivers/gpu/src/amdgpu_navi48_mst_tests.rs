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
