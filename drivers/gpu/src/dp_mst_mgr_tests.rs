use super::*;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

/// A two-level MST hub: the primary branch (port 0 input, 1 an SST sink,
/// 2 a branch, 3 empty) and behind port 2 a branch with an SST sink on 1.
pub(crate) struct Hub {
    pub(crate) dpcd: BTreeMap<u32, u8>,
    down: Vec<u8>,
    rx: Rx,
    replies: VecDeque<Vec<u8>>,
    up: VecDeque<Vec<u8>>,
    up_acks: Vec<Vec<u8>>,
    fail_up_ack: bool,
    /// Each down request: LCT, RAD and body.
    pub(crate) requests: Vec<(u8, [u8; 8], u8)>,
    pub(crate) bodies: Vec<Vec<u8>>,
    pub(crate) edid: [u8; 256],
    pub(crate) root_sink_present: bool,
    pub(crate) child_present: bool,
    pub(crate) require_power: bool,
    /// Per-(LCT, port) resource replies, including zero-bandwidth paths.
    pub(crate) resources: BTreeMap<(u8, u8), (u16, u16)>,
    pub(crate) resource_reply_port: Option<u8>,
    recursive: bool,
}
const ROOT: [u8; 16] = [0x11; 16];
const CHILD: [u8; 16] = [0x22; 16];
impl Hub {
    pub(crate) fn new() -> Self {
        let mut dpcd = BTreeMap::new();
        dpcd.insert(MSTM_CAP, 1);
        let mut edid = [0u8; 256];
        for (i, b) in edid.iter_mut().enumerate() {
            *b = i as u8 ^ 0x5a;
        }
        Self {
            dpcd,
            down: Vec::new(),
            rx: Rx::default(),
            replies: VecDeque::new(),
            up: VecDeque::new(),
            up_acks: Vec::new(),
            fail_up_ack: false,
            requests: Vec::new(),
            bodies: Vec::new(),
            edid,
            root_sink_present: true,
            child_present: true,
            require_power: false,
            resources: BTreeMap::new(),
            resource_reply_port: None,
            recursive: false,
        }
    }
    fn esi(&mut self) {
        let mut v = 0;
        if !self.replies.is_empty() {
            v |= DOWN_REP_MSG_RDY;
        }
        if !self.up.is_empty() {
            v |= UP_REQ_MSG_RDY;
        }
        self.dpcd.insert(ESI0, v);
    }
    fn port(input: bool, pdt: u8, port: u8, mcs: bool, ddps: bool, guid: [u8; 16]) -> Vec<u8> {
        let mut b = vec![
            u8::from(input) << 7 | pdt << 4 | port,
            u8::from(mcs) << 7 | u8::from(ddps) << 6,
        ];
        if !input {
            b.push(0x12);
            b.extend_from_slice(&guid);
            b.push(0x11);
        }
        b
    }
    fn reply(&mut self, lct: u8, rad: [u8; 8], body: &[u8]) -> Vec<u8> {
        let kind = body[0] & 0x7f;
        let child = lct == 2 && rad[0] >> 4 == 2;
        match kind {
            LINK_ADDRESS_KIND if child && !self.recursive => {
                let mut r = vec![0x01];
                r.extend_from_slice(&CHILD);
                r.push(3);
                r.extend(Self::port(true, 2, 0, true, true, [0; 16]));
                r.extend(Self::port(false, 3, 1, false, true, [0x33; 16]));
                r.extend(Self::port(false, 0, 2, false, false, [0; 16]));
                r
            }
            LINK_ADDRESS_KIND => {
                let mut r = vec![0x01];
                r.extend_from_slice(&ROOT);
                r.push(4);
                r.extend(Self::port(true, 1, 0, false, true, [0; 16]));
                r.extend(Self::port(
                    false,
                    3,
                    1,
                    false,
                    self.root_sink_present,
                    [0x44; 16],
                ));
                r.extend(Self::port(false, 2, 2, true, self.child_present, CHILD));
                r.extend(Self::port(false, 0, 3, false, false, [0; 16]));
                r
            }
            dp_mst::ENUM_PATH_RESOURCES => {
                let port = body[1] >> 4;
                let full = 2560 + u16::from(port) + if child { 100 } else { 0 };
                let (full, available) = self
                    .resources
                    .get(&(lct, port))
                    .copied()
                    .unwrap_or((full, full - 10));
                let mut r = vec![0x10, self.resource_reply_port.unwrap_or(port) << 4 | 1];
                r.extend_from_slice(&full.to_be_bytes());
                r.extend_from_slice(&available.to_be_bytes());
                r
            }
            dp_mst::REMOTE_I2C_READ => {
                // Segment (if written) and offset, then 128 bytes.
                let port = body[1] >> 4;
                let n = usize::from(body[1] & 3);
                let mut at = 2;
                let (mut segment, mut offset) = (0, 0);
                for _ in 0..n {
                    let (dev, len) = (body[at], usize::from(body[at + 1]));
                    if dev == 0x30 {
                        segment = usize::from(body[at + 2]);
                    } else {
                        offset = usize::from(body[at + 2]);
                    }
                    at += 3 + len;
                }
                let start = (segment * 256 + offset) % 256;
                let mut r = vec![0x22, port, 128];
                r.extend_from_slice(&self.edid[start..start + 128]);
                r
            }
            dp_mst::ALLOCATE_PAYLOAD => {
                vec![kind, body[1] & 0xf0, body[2], body[3], body[4]]
            }
            _ => vec![kind],
        }
    }
}
const LINK_ADDRESS_KIND: u8 = dp_mst::LINK_ADDRESS;

fn mst_resource_replies_must_match_port_and_capacity() -> TestResult {
    let mut hub = Hub::new();
    hub.resource_reply_port = Some(7);
    assert_eq!(
        run(Manager::new().probe(&mut hub)),
        Err(MstError::Malformed)
    );
    let mut hub = Hub::new();
    hub.resources.insert((1, 1), (100, 101));
    assert_eq!(
        run(Manager::new().probe(&mut hub)),
        Err(MstError::Malformed)
    );
    let mut hub = Hub::new();
    hub.resources.insert((1, 1), (100, 0));
    let tree = run(Manager::new().probe(&mut hub)).unwrap();
    assert_eq!(
        tree.port(Sink { branch: 0, port: 1 })
            .unwrap()
            .available_pbn,
        0
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    mst_resource_replies_must_match_port_and_capacity
);

fn mst_probe_bounds_depth_and_branch_count() -> TestResult {
    let mut hub = Hub::new();
    hub.recursive = true;
    let mut mgr = Manager::new();
    assert_eq!(run(mgr.probe(&mut hub)), Err(MstError::Malformed));
    assert_eq!(
        hub.requests
            .iter()
            .filter(|r| r.2 == dp_mst::LINK_ADDRESS)
            .count(),
        15
    );
    assert!(hub.requests.iter().all(|r| (1..=15).contains(&r.0)));
    let mut topology = Topology {
        branches: vec![
            Branch {
                lct: 1,
                rad: [0; 8],
                guid: ROOT,
                ports: Vec::new()
            };
            64
        ],
    };
    let sent = hub.requests.len();
    assert!(matches!(
        run(mgr.link_address(&mut hub, 2, [0; 8], &mut topology)),
        Err(MstError::Malformed)
    ));
    assert_eq!(hub.requests.len(), sent);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    mst_probe_bounds_depth_and_branch_count
);

impl MstAux for Hub {
    type Error = ();
    async fn read(&mut self, address: u32, buf: &mut [u8]) -> Result<(), ()> {
        for (i, b) in buf.iter_mut().enumerate() {
            let at = address + i as u32;
            *b = if (dp_mst::DOWN_REP_BASE..dp_mst::DOWN_REP_BASE + 48).contains(&at) {
                let msg = self.replies.front().ok_or(())?;
                msg.get((at - dp_mst::DOWN_REP_BASE) as usize)
                    .copied()
                    .unwrap_or(0)
            } else if (dp_mst::UP_REQ_BASE..dp_mst::UP_REQ_BASE + 48).contains(&at) {
                let msg = self.up.front().ok_or(())?;
                msg.get((at - dp_mst::UP_REQ_BASE) as usize)
                    .copied()
                    .unwrap_or(0)
            } else {
                self.dpcd.get(&at).copied().unwrap_or(0)
            };
        }
        Ok(())
    }
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), ()> {
        if self.require_power
            && address == MSTM_CTRL
            && data[0] != 0
            && self.dpcd.get(&0x600) != Some(&1)
        {
            return Err(());
        }
        match address {
            ESI0 => {
                if data[0] & DOWN_REP_MSG_RDY != 0 {
                    self.replies.pop_front();
                }
                if data[0] & UP_REQ_MSG_RDY != 0 {
                    self.up.pop_front();
                }
                self.esi();
            }
            a if (dp_mst::DOWN_REQ_BASE..dp_mst::DOWN_REQ_BASE + 48).contains(&a) => {
                if a == dp_mst::DOWN_REQ_BASE {
                    self.down.clear();
                }
                self.down.extend_from_slice(data);
                let Some((hdr, n)) = dp_mst::Header::decode(&self.down) else {
                    return Ok(());
                };
                if self.down.len() < n + usize::from(hdr.msg_len) {
                    return Ok(());
                }
                let msg = core::mem::take(&mut self.down);
                assert!(self.rx.add(&msg));
                if self.rx.complete() {
                    let body = self.rx.msg[..usize::from(self.rx.len)].to_vec();
                    self.rx = Rx::default();
                    self.requests.push((hdr.lct, hdr.rad, body[0]));
                    self.bodies.push(body.clone());
                    // An unplug notice arrives during the first request.
                    if self.requests.len() == 1 {
                        let mut csn = vec![dp_mst::CONNECTION_STATUS_NOTIFY, 0x20];
                        csn.extend_from_slice(&CHILD);
                        csn.push(0x08 | 2);
                        self.up.extend(dp_mst::chunks(1, &[0; 8], false, &csn));
                    }
                    let reply = self.reply(hdr.lct, hdr.rad, &body);
                    self.replies
                        .extend(dp_mst::chunks(1, &[0; 8], false, &reply));
                    self.esi();
                }
            }
            a if (dp_mst::UP_REP_BASE..dp_mst::UP_REP_BASE + 48).contains(&a) => {
                if self.fail_up_ack {
                    return Err(());
                }
                self.up_acks.push(data.to_vec());
            }
            PAYLOAD_TABLE_UPDATE_STATUS => {
                // Write 1 to clear.
                let v = self.dpcd.get(&address).copied().unwrap_or(0) & !data[0];
                self.dpcd.insert(address, v);
            }
            _ => {
                for (i, &b) in data.iter().enumerate() {
                    self.dpcd.insert(address + i as u32, b);
                }
                if address == PAYLOAD_ALLOCATE_SET {
                    self.dpcd
                        .insert(PAYLOAD_TABLE_UPDATE_STATUS, PAYLOAD_TABLE_UPDATED);
                }
            }
        }
        Ok(())
    }
    async fn delay(&mut self, _us: u64) {}
}

/// MST bring-up and probing as Linux does it: MSTM_CTRL with MST, up
/// requests and upstream-is-source, the payload table reset; then the
/// payload ID table cleared once (broadcast), LINK_ADDRESS from the
/// primary branch and, port by port, ENUM_PATH_RESOURCES and at once the
/// LINK_ADDRESS of the branch behind (depth first); EDIDs through
/// REMOTE_I2C_READ. An up request meanwhile is acknowledged and queued.
fn dp_mst_manager_probes_like_linux() -> TestResult {
    let mut hub = Hub::new();
    let mut mgr = Manager::new();
    let mut dpcd = [0u8; 16];
    dpcd[0] = 0x12;
    if run(mgr.start(&mut hub, &dpcd)).is_err()
        || hub.dpcd.get(&MSTM_CTRL) != Some(&7)
        || (0..3)
            .map(|i| hub.dpcd[&(PAYLOAD_ALLOCATE_SET + i)])
            .collect::<Vec<_>>()
            != [0, 0, 0x3f]
    {
        return TestResult::Fail("MST start");
    }
    let topology = match run(mgr.probe(&mut hub)) {
        Ok(t) => t,
        Err(e) => panic!("probe {e:?}"),
    };
    let order: Vec<(u8, u8)> = hub.requests.iter().map(|&(lct, _, k)| (lct, k)).collect();
    use dp_mst::{CLEAR_PAYLOAD_ID_TABLE as CLR, ENUM_PATH_RESOURCES as EPR, LINK_ADDRESS as LA};
    // Root port 3 is unplugged: no ENUM_PATH_RESOURCES for it.
    if order != [(1, CLR), (1, LA), (1, EPR), (1, EPR), (2, LA), (2, EPR)] {
        panic!("request order {order:?}");
    }
    // The child is addressed as port 2 of the primary branch.
    if hub.requests[4].1[0] != 0x20 || topology.branches.len() != 2 {
        return TestResult::Fail("child branch address");
    }
    let root = &topology.branches[0];
    if root.guid != ROOT
        || root.ports.len() != 4
        || root.ports[2].branch != Some(1)
        || root.ports[1].full_pbn != 2561
        || root.ports[1].available_pbn != 2551
        || !root.ports[1].fec
        || topology.branches[1].lct != 2
        || topology.branches[1].ports[1].full_pbn != 2661
    {
        return TestResult::Fail("topology");
    }
    if topology.sinks() != [Sink { branch: 0, port: 1 }, Sink { branch: 1, port: 1 }] {
        return TestResult::Fail("end devices");
    }
    // The up request: queued, and answered with its ACK (broadcast).
    let Some(UpRequest::ConnectionStatus {
        port: 2,
        dp_plug: false,
        input: true,
        ..
    }) = mgr.events.first().copied()
    else {
        panic!("up request {:?}", mgr.events);
    };
    let ack = dp_mst::Header::decode(&hub.up_acks[0]).unwrap().0;
    if !ack.broadcast || hub.up_acks[0][3] != dp_mst::CONNECTION_STATUS_NOTIFY {
        return TestResult::Fail("up request ACK");
    }
    // EDID block 1 of the sink behind the second branch.
    let block = run(mgr.read_edid_block(&mut hub, &topology, Sink { branch: 1, port: 1 }, 1));
    if block.ok().map(|b| b[0]) != Some(128 ^ 0x5a) || hub.requests.last().unwrap().0 != 2 {
        return TestResult::Fail("remote EDID");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dp-mst", dp_mst_manager_probes_like_linux);

/// drm_dp_calculate_rad: nibble per hop, the first in the high nibble.
fn dp_mst_child_rad_like_linux() -> TestResult {
    let (lct, rad) = child_rad(1, &[0; 8], 3);
    let (lct2, rad2) = child_rad(lct, &rad, 5);
    let (lct3, rad3) = child_rad(lct2, &rad2, 7);
    if (lct, rad[0]) != (2, 0x30)
        || (lct2, rad2[0]) != (3, 0x35)
        || (lct3, &rad3[..2]) != (4, &[0x35u8, 0x70][..])
    {
        return TestResult::Fail("RAD");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dp-mst", dp_mst_child_rad_like_linux);

fn resource_notice(port: u8, pbn: u16) -> Vec<u8> {
    let mut body = vec![dp_mst::RESOURCE_STATUS_NOTIFY, port << 4];
    body.extend_from_slice(&ROOT);
    body.extend_from_slice(&pbn.to_be_bytes());
    body
}

fn up_piece(body: &[u8], first: bool, last: bool) -> Vec<u8> {
    let mut raw = dp_mst::Header {
        lct: 1,
        lcr: 6,
        broadcast: true,
        somt: first,
        eomt: last,
        msg_len: body.len() as u8 + 1,
        ..dp_mst::Header::default()
    }
    .encode();
    raw.extend_from_slice(body);
    raw.push(dp_mst::data_crc(body));
    raw
}

/// An idle service pass handles notifications, leaving an unrelated down
/// reply ready, and never consumes more than its chunk budget.
fn dp_mst_idle_poll_is_bounded_and_preserves_down_reply() -> TestResult {
    let mut hub = Hub::new();
    let mut mgr = Manager::new();
    for port in 1..=10 {
        hub.up.extend(dp_mst::chunks(
            1,
            &[0; 8],
            false,
            &resource_notice(port, 100 + u16::from(port)),
        ));
    }
    hub.replies.extend(dp_mst::chunks(
        1,
        &[0; 8],
        false,
        &[dp_mst::CLEAR_PAYLOAD_ID_TABLE],
    ));
    hub.esi();
    if run(mgr.poll_up_requests(&mut hub)) != Ok(8)
        || mgr.events.len() != 8
        || hub.up.len() != 2
        || hub.replies.len() != 1
        || hub.dpcd[&ESI0] != UP_REQ_MSG_RDY | DOWN_REP_MSG_RDY
    {
        return TestResult::Fail("idle poll exceeded budget or consumed a down reply");
    }
    if run(mgr.poll_up_requests(&mut hub)) != Ok(2)
        || run(mgr.poll_up_requests(&mut hub)) != Ok(0)
        || hub.dpcd[&ESI0] != DOWN_REP_MSG_RDY
        || hub.up_acks.len() != 10
    {
        return TestResult::Fail("idle notifications did not drain");
    }
    for (k, event) in mgr.events.iter().enumerate() {
        if *event
            != (UpRequest::ResourceStatus {
                port: k as u8 + 1,
                guid: ROOT,
                available_pbn: 101 + k as u16,
            })
        {
            return TestResult::Fail("idle event order or body");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    dp_mst_idle_poll_is_bounded_and_preserves_down_reply
);

/// A fragmented up request can outlive the down transaction carrying its
/// first chunk, then span multiple poll budgets without losing its prefix.
fn dp_mst_up_request_survives_transaction_and_poll_boundaries() -> TestResult {
    let mut hub = Hub::new();
    let mut mgr = Manager::new();
    run(mgr.probe(&mut hub)).unwrap();
    mgr.events.clear();
    hub.up_acks.clear();
    let body = resource_notice(3, 0x1234);
    hub.up.push_back(up_piece(&body[..1], true, false));
    hub.esi();
    run(mgr.transact(
        &mut hub,
        1,
        &[0; 8],
        &Request::EnumPathResources { port: 1 },
    ))
    .unwrap();
    if mgr.up.is_none() || !mgr.events.is_empty() || !hub.up_acks.is_empty() {
        return TestResult::Fail("partial notification was completed or discarded");
    }
    for k in 1..body.len() {
        hub.up
            .push_back(up_piece(&body[k..k + 1], false, k + 1 == body.len()));
    }
    hub.esi();
    for expected in [8, 8, 3] {
        if run(mgr.poll_up_requests(&mut hub)) != Ok(expected) {
            return TestResult::Fail("fragment service budget");
        }
    }
    if mgr.events
        != [UpRequest::ResourceStatus {
            port: 3,
            guid: ROOT,
            available_pbn: 0x1234,
        }]
        || mgr.up.is_some()
        || hub.up_acks.len() != 1
    {
        return TestResult::Fail("reassembled notification");
    }
    // A new MST session cannot inherit half of an old notification.
    hub.up.push_back(up_piece(&body[..1], true, false));
    hub.esi();
    run(mgr.poll_up_requests(&mut hub)).unwrap();
    run(mgr.stop(&mut hub));
    if mgr.up.is_some() || !mgr.events.is_empty() {
        return TestResult::Fail("stop retained old session notifications");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    dp_mst_up_request_survives_transaction_and_poll_boundaries
);

fn dp_mst_full_event_queue_applies_backpressure() -> TestResult {
    let mut hub = Hub::new();
    let mut mgr = Manager::new();
    run(mgr.probe(&mut hub)).unwrap();
    mgr.events.clear();
    hub.up_acks.clear();
    for k in 0..=MAX_UP_EVENTS {
        hub.up.extend(dp_mst::chunks(
            1,
            &[0; 8],
            false,
            &resource_notice(1, k as u16),
        ));
    }
    hub.esi();
    for _ in 0..MAX_UP_EVENTS / UP_CHUNKS_PER_POLL {
        run(mgr.poll_up_requests(&mut hub)).unwrap();
    }
    if run(mgr.poll_up_requests(&mut hub)) != Err(MstError::EventsFull)
        || mgr.events.len() != MAX_UP_EVENTS
        || hub.up.len() != 1
        || hub.up_acks.len() != MAX_UP_EVENTS
    {
        return TestResult::Fail("full queue dropped or acknowledged the next event");
    }
    // The other sideband channel must still complete its transaction while
    // up requests are backpressured, without discarding their pending chunk.
    if run(mgr.transact(
        &mut hub,
        1,
        &[0; 8],
        &Request::EnumPathResources { port: 1 },
    ))
    .is_err()
        || hub.up.len() != 1
        || mgr.events.len() != MAX_UP_EVENTS
    {
        return TestResult::Fail("full up queue abandoned a down transaction");
    }
    mgr.events.clear();
    if run(mgr.poll_up_requests(&mut hub)) != Ok(1)
        || mgr.events
            != [UpRequest::ResourceStatus {
                port: 1,
                guid: ROOT,
                available_pbn: MAX_UP_EVENTS as u16,
            }]
    {
        return TestResult::Fail("draining did not resume the blocked notification");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-mst",
    dp_mst_full_event_queue_applies_backpressure
);

/// Truncated connection/resource bodies used to acquire zero-filled fields
/// from the reassembly buffer, manufacturing a disconnect or resource count.
fn dp_mst_rejects_truncated_up_requests() -> TestResult {
    for (kind, len) in [
        (dp_mst::CONNECTION_STATUS_NOTIFY, 18),
        (dp_mst::RESOURCE_STATUS_NOTIFY, 19),
    ] {
        let mut hub = Hub::new();
        let mut mgr = Manager::new();
        let mut body = resource_notice(1, 123);
        body[0] = kind;
        body.truncate(len);
        hub.up.extend(dp_mst::chunks(1, &[0; 8], false, &body));
        hub.esi();
        if run(mgr.poll_up_requests(&mut hub)) != Err(MstError::Malformed)
            || !mgr.events.is_empty()
            || !hub.up_acks.is_empty()
        {
            return TestResult::Fail("truncated up request became an event");
        }
    }
    // ESI was already acknowledged when the sideband ACK failed. Keep
    // the event available to the caller despite returning the AUX error.
    let mut hub = Hub::new();
    let mut mgr = Manager::new();
    hub.fail_up_ack = true;
    hub.up
        .extend(dp_mst::chunks(1, &[0; 8], false, &resource_notice(2, 456)));
    hub.esi();
    if run(mgr.poll_up_requests(&mut hub)) != Err(MstError::Aux(()))
        || mgr.events
            != [UpRequest::ResourceStatus {
                port: 2,
                guid: ROOT,
                available_pbn: 456,
            }]
        || !hub.up.is_empty()
    {
        return TestResult::Fail("ACK failure discarded the acknowledged event");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dp-mst", dp_mst_rejects_truncated_up_requests);
