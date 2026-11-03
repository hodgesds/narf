// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CU USB packet owner (Linux rtw88/usb.c TX queue/aggregation, RX
//! split and CCX matching) over an inert receipt model. No USB device is
//! touched; nothing here runs inside an executor poll.
use super::{
    packet_core::Error,
    packet_phy::Chip,
    usb::{self, Endpoints, MAX_RECVBUF, QSEL_MGMT, TX_DESC},
    usb_packet::{transmit_packet, Owner},
};
use crate::rtl8xxxu::packet_transport::Io;
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec, vec::Vec};
use narf_drivers_usb::device::UsbError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Default)]
struct Model {
    next: u64,
    rx: Option<u64>,
    rx_result: Option<Vec<u8>>,
    posted: Vec<(u8, usize)>,
    /// Open TX receipts: id -> (dci, length).
    tx: BTreeMap<u64, (u8, usize)>,
    /// Completed TX receipt ids.
    done: Vec<u64>,
    sent: Vec<(u8, Vec<u8>)>,
    stops: Vec<u64>,
}
#[derive(Clone)]
struct Fake(Arc<IrqSafeSpinLock<Model>>);
struct Receipt(u64);
#[async_trait::async_trait]
impl Io for Fake {
    type Receipt = Receipt;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<Receipt, UsbError> {
        let mut m = self.0.lock();
        if m.rx.is_some() {
            return Err(UsbError::Stall);
        }
        m.next += 1;
        let id = m.next;
        m.rx = Some(id);
        m.posted.push((dci, length));
        Ok(Receipt(id))
    }
    fn poll_receive(&self, r: &Receipt, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
        let mut m = self.0.lock();
        if m.rx != Some(r.0) {
            return Err(UsbError::Stall);
        }
        let Some(bytes) = m.rx_result.take() else {
            return Ok(None);
        };
        out[..bytes.len()].copy_from_slice(&bytes);
        m.rx = None;
        Ok(Some(bytes.len()))
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<Receipt, UsbError> {
        let mut m = self.0.lock();
        if m.tx.values().any(|(d, _)| *d == dci) {
            return Err(UsbError::Stall);
        }
        m.next += 1;
        let id = m.next;
        m.tx.insert(id, (dci, bytes.len()));
        m.sent.push((dci, bytes.to_vec()));
        Ok(Receipt(id))
    }
    fn poll_send(&self, r: &Receipt) -> Result<Option<usize>, UsbError> {
        let mut m = self.0.lock();
        let (_, length) = *m.tx.get(&r.0).ok_or(UsbError::Stall)?;
        if let Some(at) = m.done.iter().position(|d| *d == r.0) {
            m.done.remove(at);
            m.tx.remove(&r.0);
            return Ok(Some(length));
        }
        Ok(None)
    }
    async fn stop(&self, r: &Receipt) -> Result<(), UsbError> {
        let mut m = self.0.lock();
        m.stops.push(r.0);
        if m.rx == Some(r.0) {
            m.rx = None;
            Ok(())
        } else if m.tx.remove(&r.0).is_some() {
            Ok(())
        } else {
            Err(UsbError::Stall)
        }
    }
}
impl Default for Fake {
    fn default() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model::default())))
    }
}
impl Fake {
    /// Complete every open bulk-OUT receipt on `dci`.
    fn complete_tx(&self, dci: u8) {
        let mut m = self.0.lock();
        let ids: Vec<u64> =
            m.tx.iter()
                .filter(|(_, (d, _))| *d == dci)
                .map(|(id, _)| *id)
                .collect();
        m.done.extend(ids);
    }
}

const OWN: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const PEER: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];

/// Three bulk-OUT pipes (0x02, 0x03, 0x04) and bulk-IN 0x81.
fn endpoints() -> Endpoints {
    let eps: [(u8, u8, u16); 4] = [
        (0x81, 2, 512),
        (0x02, 2, 512),
        (0x03, 2, 512),
        (0x04, 2, 512),
    ];
    let mut c = vec![9, 2, 0, 0, 1, 1, 0, 0x80, 250];
    c.extend_from_slice(&[9, 4, 0, 0, eps.len() as u8, 0xff, 0xff, 0xff, 0]);
    for (address, attributes, packet) in eps {
        let p = packet.to_le_bytes();
        c.extend_from_slice(&[7, 5, address, attributes, p[0], p[1], 0]);
    }
    let total = (c.len() as u16).to_le_bytes();
    c[2] = total[0];
    c[3] = total[1];
    Endpoints::parse(&c).expect("three-pipe vendor interface")
}
/// To-DS non-QoS DATA (BE, qsel 0 -> LOW -> pipe 2 with three pipes).
fn data(sequence: u16) -> Vec<u8> {
    let mut f = vec![0x08, 0x01, 0, 0];
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&(sequence << 4).to_le_bytes());
    f.extend_from_slice(&[0xaa; 40]);
    f
}
/// Authentication (MGMT qsel 0x12 -> HIGH -> pipe 0).
fn auth() -> Vec<u8> {
    let mut f = vec![0xb0, 0, 0, 0];
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&[0x10, 0]);
    f.extend_from_slice(&[0, 0, 1, 0, 0, 0]);
    f
}
fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn checksum_ok(desc: &[u8]) -> bool {
    let mut sum = 0u16;
    for pair in desc[..32].chunks_exact(2) {
        sum ^= u16::from_le_bytes([pair[0], pair[1]]);
    }
    // The stored checksum XORed into the folded sum cancels to zero.
    sum == 0
}
/// One RXDESC record: no driver info, OFDM6 (rate 4) or a C2H body.
fn rx_record(body: &[u8], c2h: bool) -> Vec<u8> {
    let mut r = vec![0u8; usb::RX_DESC];
    r[0..4].copy_from_slice(&(body.len() as u32).to_le_bytes());
    if c2h {
        r[8..12].copy_from_slice(&(1u32 << 28).to_le_bytes());
    } else {
        r[12..16].copy_from_slice(&4u32.to_le_bytes());
    }
    r.extend_from_slice(body);
    r
}
fn urb(records: &[Vec<u8>]) -> Vec<u8> {
    let mut u = Vec::new();
    for r in records {
        u.resize(u.len().next_multiple_of(8), 0);
        u.extend_from_slice(r);
    }
    u
}
fn owner(fake: &Fake) -> Owner<Fake> {
    let mut owner = Owner::prepare(fake.clone(), endpoints(), OWN, 0, Chip::C21).expect("prepared");
    owner.start().expect("started");
    owner
}

/// `rtw_usb_tx_write`/`rtw_usb_tx_handler`: per-pipe queues, the USB
/// qsel and checksum on every descriptor, one URB in flight per pipe, and
/// the queued tail sent as one `rtw_usb_tx_agg_skb` aggregate (count in
/// W7[31:24]) after the USB completion. Completion-only receipts never
/// claim a radio ACK.
fn smoke_rtw88_usb_packet_tx_queues_and_aggregation() -> TestResult {
    let fake = Fake::default();
    let mut owner = owner(&fake);
    if fake.0.lock().posted != [(3, MAX_RECVBUF)] {
        return TestResult::Fail("bulk-IN 0x81 (DCI 3) not posted at the 32 KiB size");
    }
    let ids = [
        owner.submit(&data(1), false).expect("first"),
        owner.submit(&data(2), false).expect("second"),
        owner.submit(&data(3), false).expect("third"),
        owner.submit(&auth(), false).expect("mgmt"),
    ];
    {
        let m = fake.0.lock();
        // Pipe 2 (0x04, DCI 8) took the first DATA alone; the MGMT pipe 0
        // (0x02, DCI 4) started independently.
        if m.sent.len() != 2 || m.sent[0].0 != 8 || m.sent[1].0 != 4 {
            return TestResult::Fail("wrong pipe kick order or endpoints");
        }
        let first = &m.sent[0].1;
        if first.len() != TX_DESC + data(1).len()
            || (word(first, 4) >> 8) & 0x1f != 0
            || !checksum_ok(&first[..TX_DESC])
        {
            return TestResult::Fail("DATA descriptor qsel or checksum");
        }
        let mgmt = &m.sent[1].1;
        if (word(mgmt, 4) >> 8) & 0x1f != u32::from(QSEL_MGMT) || !checksum_ok(&mgmt[..TX_DESC]) {
            return TestResult::Fail("MGMT descriptor qsel or checksum");
        }
    }
    fake.complete_tx(8);
    let step = owner.poll(0).expect("poll");
    if step.receipts.len() != 1
        || step.receipts[0].id != ids[0]
        || step.receipts[0].radio_acknowledged
        || step.receipts[0].bytes != data(1)
    {
        return TestResult::Fail("USB completion receipt");
    }
    {
        let m = fake.0.lock();
        let Some((8, agg)) = m.sent.get(2) else {
            return TestResult::Fail("queued DATA not aggregated on pipe 2");
        };
        let second = TX_DESC + data(2).len();
        if word(agg, 28) >> 24 != 2
            || !checksum_ok(&agg[..TX_DESC])
            || agg.len() != second.next_multiple_of(8) + TX_DESC + data(3).len()
        {
            return TestResult::Fail("aggregate count, checksum or 8-byte alignment");
        }
    }
    fake.complete_tx(8);
    fake.complete_tx(4);
    let step = owner.poll(1).expect("poll");
    let mut got: Vec<u64> = step.receipts.iter().map(|r| r.id).collect();
    got.sort_unstable();
    if got != [ids[1], ids[2], ids[3]] || !owner.ready() {
        return TestResult::Fail("aggregate and MGMT completions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_packet_tx_queues_and_aggregation
);

/// `rtw_usb_rx_handler` + `rtw_tx_report_handle`: a report-requesting
/// frame waits after its USB completion; one bulk-IN aggregate carrying a
/// CCX C2H and a DATA MPDU retires it with a radio ACK, delivers the MPDU
/// without FCS and re-posts the bulk-IN receipt.
fn smoke_rtw88_usb_packet_rx_aggregate_and_ccx_receipt() -> TestResult {
    let fake = Fake::default();
    let mut owner = owner(&fake);
    let id = owner.submit(&auth(), true).expect("report frame");
    let sequence = {
        let m = fake.0.lock();
        word(&m.sent[0].1, 24) as u8
    };
    if word(&fake.0.lock().sent[0].1, 8) & (1 << 19) == 0 || sequence & 3 != 0 {
        return TestResult::Fail("SPE_RPT or sequence alignment");
    }
    fake.complete_tx(4);
    let step = owner.poll(10).expect("poll");
    if !step.receipts.is_empty() || owner.ready() {
        return TestResult::Fail("report frame retired on USB completion alone");
    }
    // C2H_CCX_TX_RPT: id 0x03, seq, then status (byte 2) and sequence
    // (byte 8) of the report payload.
    let mut ccx = vec![0x03, 0, 0, 0, 0, 0, 0, 0, sequence, 0, 0, 0];
    ccx[2] = 0;
    let mut mpdu = data(9);
    mpdu.extend_from_slice(&[0; 4]);
    fake.0.lock().rx_result = Some(urb(&[rx_record(&ccx, true), rx_record(&mpdu, false)]));
    let step = owner.poll(20).expect("poll");
    if step.receipts.len() != 1 || step.receipts[0].id != id || !step.receipts[0].radio_acknowledged
    {
        return TestResult::Fail("CCX report did not retire the frame");
    }
    if step.c2h.len() != 1 || step.frames.len() != 1 || !step.consumed_rx {
        return TestResult::Fail("RX aggregate split");
    }
    use narf_wireless::station_security::RawFrame;
    if step.frames[0].bytes() != data(9).as_slice() {
        return TestResult::Fail("MPDU body or FCS strip");
    }
    if fake.0.lock().posted.len() != 2 || !owner.ready() {
        return TestResult::Fail("bulk-IN not re-posted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_packet_rx_aggregate_and_ccx_receipt
);

/// The CCX deadline fails the owner, a stopped owner retires its retained
/// receipts through `Io::stop`, and the descriptor builder keeps the PCI
/// profile fields while switching only qsel/MORE_DATA/checksum.
fn smoke_rtw88_usb_packet_timeout_stop_and_descriptor() -> TestResult {
    let fake = Fake::default();
    let mut owner = owner(&fake);
    owner.submit(&auth(), true).expect("report frame");
    fake.complete_tx(4);
    owner.poll(0).expect("poll");
    if owner.poll(1_000_000).err() != Some(Error::Timeout) || owner.running() {
        return TestResult::Fail("CCX deadline");
    }
    let stop = super::firmware_transport::now(owner.stop());
    if stop.is_err() || !owner.stopped() || fake.0.lock().rx.is_some() {
        return TestResult::Fail("stop did not retire the bulk-IN receipt");
    }
    let frame = data(4);
    let (pci, _) = super::packet_format::transmit_profile(
        &frame,
        OWN,
        0,
        None,
        super::packet_format::DataProfile::LEGACY,
    )
    .expect("pci descriptor");
    let (usb, qsel) = transmit_packet(
        &frame,
        OWN,
        0,
        None,
        super::packet_format::DataProfile::LEGACY,
        None,
    )
    .expect("usb packet");
    if qsel != 0 || usb[..4] != pci[..4] || usb[8..28] != pci[8..28] || usb[TX_DESC..] != frame[..]
    {
        return TestResult::Fail("USB descriptor diverged from the PCI profile fields");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_packet_timeout_stop_and_descriptor
);

/// To-DS QoS DATA, TID 0 (BE, qsel 0 -> LOW -> pipe 2 with three pipes).
fn qos(sequence: u16) -> Vec<u8> {
    let mut f = vec![0x88, 0x01, 0, 0];
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&(sequence << 4).to_le_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[0xaa; 40]);
    f
}
fn ccx(sequence: u8) -> Vec<u8> {
    vec![0x03, 0, 0, 0, 0, 0, 0, 0, sequence, 0, 0, 0]
}

/// TX A-MPDU over USB (`packet_core::Core::submit_batch` semantics on the
/// USB queues): refused without an envelope or while busy; one same-TID
/// burst on the TID pipe, each MPDU with AGG_EN/density/MAX_AGG_NUM and its
/// own CCX report, packed into one `rtw_usb_tx_agg_skb` URB; out-of-order
/// reports release receipts only in submission order.
fn smoke_rtw88_usb_packet_ampdu_batch() -> TestResult {
    use super::packet_format::{Aggregation, DataProfile};
    let fake = Fake::default();
    let mut owner = owner(&fake);
    let profile = DataProfile {
        rates: 0xfff,
        qos: true,
        mcs: 255,
        rx_mcs: 0xff,
        sgi: true,
        ldpc: false,
        stbc: false,
        acs: 0,
        fallback: false,
        bw40: false,
        band5: false,
        vht: None,
    };
    if owner.configure_data(profile).is_err() {
        return TestResult::Fail("HT QoS profile");
    }
    let frames = vec![qos(10), qos(11), qos(12)];
    if owner.submit_batch(&frames) != Err(Error::State) {
        return TestResult::Fail("batch admitted without an N21T envelope");
    }
    let envelope = Aggregation {
        density: 4,
        count: 4,
        bytes: 8191,
        airtime: 4000,
    };
    if owner.aggregation(Some(envelope)).is_err() {
        return TestResult::Fail("envelope refused while idle");
    }
    let ids = match owner.submit_batch(&frames) {
        Ok(ids) if ids.len() == 3 => ids,
        _ => return TestResult::Fail("burst refused"),
    };
    if owner.submit_batch(&frames) != Err(Error::Busy) || owner.aggregation(None).is_ok() {
        return TestResult::Fail("second burst or envelope change while busy");
    }
    {
        let m = fake.0.lock();
        let [(8, urb)] = m.sent.as_slice() else {
            return TestResult::Fail("burst not one URB on the LOW pipe (DCI 8)");
        };
        if word(urb, 28) >> 24 != 3 || !checksum_ok(&urb[..TX_DESC]) {
            return TestResult::Fail("URB aggregate count or checksum");
        }
        let mut offset = 0;
        for (i, frame) in frames.iter().enumerate() {
            let d = &urb[offset..offset + TX_DESC];
            if word(d, 8) & 0x0078_1000 != 0x0048_1000
                || word(d, 8) & (1 << 19) == 0
                || word(d, 12) >> 17 & 31 != 3
                || word(d, 24) as u8 != (i as u8) << 2
                || (word(d, 4) >> 8) & 0x1f != 0
                || urb[offset + TX_DESC..offset + TX_DESC + frame.len()] != frame[..]
            {
                return TestResult::Fail("AMPDU descriptor or body");
            }
            offset = (offset + TX_DESC + frame.len()).next_multiple_of(8);
        }
    }
    fake.complete_tx(8);
    if !owner.poll(0).expect("poll").receipts.is_empty() {
        return TestResult::Fail("burst retired on USB completion alone");
    }
    fake.0.lock().rx_result = Some(urb(&[rx_record(&ccx(8), true), rx_record(&ccx(4), true)]));
    if !owner.poll(1).expect("poll").receipts.is_empty() {
        return TestResult::Fail("later reports released before the first");
    }
    fake.0.lock().rx_result = Some(urb(&[rx_record(&ccx(0), true)]));
    let step = owner.poll(2).expect("poll");
    let got: Vec<u64> = step.receipts.iter().map(|r| r.id).collect();
    if got != ids
        || step.receipts.iter().any(|r| !r.radio_acknowledged)
        || step
            .receipts
            .iter()
            .zip(&frames)
            .any(|(r, f)| &r.bytes != f)
        || !owner.ready()
    {
        return TestResult::Fail("burst receipts not FIFO with radio ACK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_packet_ampdu_batch
);
