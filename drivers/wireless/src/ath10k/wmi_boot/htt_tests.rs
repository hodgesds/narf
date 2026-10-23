use crate::ath10k::{dma::Memory, htt_runtime as htt};
include!("htt_pfc_golden.rs");
#[derive(Debug)]
struct HttBuffer {
    bytes: Vec<u8>,
    address: u64,
}
impl Memory for HttBuffer {
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn dma_address(&self) -> u64 {
        self.address
    }
    fn read(&self, at: usize) -> u8 {
        self.bytes[at]
    }
    fn write(&mut self, at: usize, v: u8) {
        self.bytes[at] = v;
    }
}
#[derive(Debug)]
struct HttModel {
    inner: Model,
    storage: Option<htt::storage::Storage<HttBuffer>>,
    config: htt::Config,
    sequence: u8,
    stall_rx: bool,
    version: u8,
    receive_pipe: u8,
    tx_next: u64,
    stall_tx: bool,
}
impl HttModel {
    fn new(d: Dialect, c: htt::Config, hardware: HwRev) -> Self {
        let mut inner = Model::new(d);
        if c.pfc {
            inner.expected = INIT_TEN_FOUR_PFC;
        }
        Self {
            inner,
            storage: None,
            config: c,
            sequence: 0,
            stall_rx: false,
            version: 3,
            tx_next: 0x800000,
            stall_tx: false,
            receive_pipe: if matches!(hardware, HwRev::Qca6174 | HwRev::Qca9377) {
                1
            } else {
                5
            },
        }
    }
}
impl HostMemory for HttModel {
    fn retain_wmi_memory(&mut self, p: &[MemoryPlan]) -> Result<Vec<MemoryChunk>, Error> {
        self.inner.retain_wmi_memory(p)
    }
}
impl htt::HttMemory for HttModel {
    fn prepare_htt_tx(
        &mut self,
        c: htt::Config,
        p: htt::tx::Parameters,
        bytes: &[u8],
    ) -> Result<(u16, Vec<u8>), htt::Error> {
        let storage = self.storage.as_mut().ok_or(htt::Error::Memory)?;
        let tx_next = &mut self.tx_next;
        storage
            .tx
            .prepare(c, storage.fragments.as_mut(), p, bytes, |bytes| {
                let b = HttBuffer {
                    bytes: vec![0xa5; bytes],
                    address: *tx_next,
                };
                *tx_next += (bytes as u64).div_ceil(4096) * 4096;
                Ok(b)
            })
    }
    fn pop_htt_in_order(
        &mut self,
        indication: &htt::rx::InOrder,
    ) -> Result<Vec<htt::rx::Msdu>, htt::Error> {
        self.storage
            .as_mut()
            .ok_or(htt::Error::Memory)?
            .pop_in_order(indication, || true)
    }
    fn pop_htt_amsdu(&mut self) -> Result<Vec<htt::rx::Msdu>, htt::Error> {
        self.storage
            .as_mut()
            .ok_or(htt::Error::Memory)?
            .pop_amsdu(|| true)
    }
    fn complete_htt_tx(&mut self, ids: &[u16], management: bool) -> Result<(), htt::Error> {
        self.storage
            .as_mut()
            .ok_or(htt::Error::Memory)?
            .tx
            .complete(ids, management)
    }
    fn retain_htt_memory(&mut self, c: htt::Config) -> Result<htt::DmaConfig, htt::Error> {
        if self.storage.is_some() || c != self.config {
            return Err(htt::Error::Memory);
        }
        let mut address = 0x120000;
        let s = htt::storage::Storage::allocate(c, |bytes| {
            let b = HttBuffer {
                bytes: vec![0xa5; bytes],
                address,
            };
            address += (bytes as u64).div_ceil(4096) * 4096;
            Ok(b)
        })?;
        let d = s.configuration();
        self.storage = Some(s);
        Ok(d)
    }
}
impl Hif for HttModel {
    async fn poll(
        &mut self,
        _: u64,
    ) -> Result<Option<(u8, Vec<u8>)>, crate::ath10k::bmi::BmiError> {
        Ok(self.inner.rx.pop_front())
    }

    async fn receive(&mut self, b: u64) -> Result<(u8, Vec<u8>), crate::ath10k::bmi::BmiError> {
        self.inner.receive(b).await
    }
    async fn send(&mut self, pipe: u8, bytes: &[u8]) -> Result<(), crate::ath10k::bmi::BmiError> {
        use crate::ath10k::bmi::BmiError;
        if pipe != 4 {
            return self.inner.send(pipe, bytes).await;
        }
        self.inner.sent.push((pipe, bytes.to_vec()));
        if bytes.len() < 8
            || bytes[0] != 1
            || bytes[1] != 0
            || bytes[5] != self.sequence
            || bytes[2..4] != (bytes.len() as u16 - 8).to_le_bytes()
        {
            return Err(BmiError::BadResponse);
        }
        self.sequence += 1;
        let payload = &bytes[8..];
        if payload == [0, 0, 0, 0] {
            if self.storage.is_some() {
                return Err(BmiError::BadResponse);
            }
            self.inner
                .rx
                .push_back((self.receive_pipe, header(1, &[0, 1, self.version, 0])));
            return Ok(());
        }
        let storage = self.storage.as_ref().ok_or(BmiError::BadResponse)?;
        if storage.buffers.iter().filter(|b| b.is_some()).count() != 1023
            || storage
                .buffers
                .iter()
                .flatten()
                .any(|b| b.bytes.iter().any(|b| *b != 0))
            || storage.producer.bytes != [0xff, 3, 0, 0]
        {
            return Err(BmiError::BadResponse);
        }
        // The complete independent literal RX config uses the C sizeof/offsetof
        // oracle and independently fixed fixture DMA addresses.
        const RING: [u8; 40] = [
            2, 1, 0, 0, 0, 0x20, 0x12, 0, 0, 0, 0x12, 0, 0, 8, 0, 8, 0xff, 0xff, 0xff, 3, 59, 0,
            75, 0, 21, 0, 31, 0, 3, 0, 20, 0, 6, 0, 10, 0, 1, 0, 2, 0,
        ];
        let expected_fragment = if self.config.pfc {
            [
                6, 8, 1, 64, 0, 0x20, 0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc3, 9,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa0, 0x54, 0, 0x10, 2, 8, 0, 1, 0, 0, 0,
            ]
        } else {
            [
                6, 0, 1, 64, 0, 0x20, 0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x8f, 5,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            ]
        };
        if payload.first() == Some(&7) && self.version == 2 {
            let prefix = [
                7, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0,
            ];
            let frame = [
                0xb0, 0, 0, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0, 0,
            ];
            if payload.len() != 56
                || payload[..20] != prefix
                || payload[20..44] != frame
                || payload[44..] != [0; 12]
                || storage.tx.pending() != 1
            {
                return Err(BmiError::BadResponse);
            }
            self.inner.rx.push_back((
                self.receive_pipe,
                header(
                    1,
                    &[0xe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ),
            ));
            return Ok(());
        }
        if payload.first() == Some(&1) {
            let expected = if self.config.continuous {
                [
                    1, 0x44, 0, 0x0c, 14, 0, 0, 0, 0, 0x20, 0x52, 0, 0xff, 0xff, 0, 0,
                ]
            } else {
                [
                    1, 0x44, 0, 0x0c, 14, 0, 0, 0, 0, 0x10, 0x80, 0, 0xff, 0xff, 0, 0,
                ]
            };
            if storage.tx.pending() != 1
                || payload.len() != 32
                || payload[..16] != expected
                || payload[16..] != [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 8, 0, 0, 0]
            {
                return Err(BmiError::BadResponse);
            }
            if self.config.continuous {
                let ext = storage.fragments.as_ref().unwrap();
                if ext.bytes[16..24] != [0, 0, 0x80, 0, 0, 0, 14, 0] {
                    return Err(BmiError::BadResponse);
                }
            }
            if self.stall_tx {
                core::future::pending::<()>().await;
            }
            self.inner
                .rx
                .push_back((self.receive_pipe, header(1, &[7, 0, 1, 0, 0, 0, 0, 0])));
            return Ok(());
        }
        if payload.first() == Some(&6) {
            if !self.config.continuous || payload != expected_fragment {
                return Err(BmiError::BadResponse);
            }
        } else if payload.first() == Some(&2) {
            if payload != RING {
                return Err(BmiError::BadResponse);
            }
            if self.stall_rx {
                core::future::pending::<()>().await;
            }
        } else if payload != [5, 64, 3] {
            return Err(BmiError::BadResponse);
        }
        Ok(())
    }
}
fn htt_boot(
    hardware: HwRev,
    d: Dialect,
    w: u32,
    h: u32,
    pfc: bool,
) -> crate::ath10k::htt_runtime::Runtime<HttModel> {
    let features = if pfc { 1 << 13 } else { 0 };
    let config = htt::Config::new(hardware, w, h, features).unwrap();
    let mut htc = Session::new(HttModel::new(d, config, hardware), hardware);
    assert_eq!(once(htc.start()), Poll::Ready(Ok(())));
    let mut wmi = Runtime::new(htc, d, hardware, features);
    assert!(matches!(once(wmi.start()), Poll::Ready(Ok(_))));
    htt::Runtime::new(wmi, config)
}
fn smoke_ath10k_htt_composed_owned_pci_setup() -> TestResult {
    for (hw, d, w, h, pfc) in [
        (HwRev::Qca6174, Dialect::Tlv, 4, 3, false),
        (HwRev::Qca9984, Dialect::TenFour, 6, 4, false),
        (HwRev::Qca9984, Dialect::TenFour, 6, 4, true),
    ] {
        let mut htt = htt_boot(hw, d, w, h, pfc);
        if once(htt.start()) != Poll::Ready(Ok(htt::Ready { major: 3, minor: 1 })) {
            return TestResult::Fail(
                "native HTC/WMI→HTT version/retained ring/fragment/aggregation literal failed",
            );
        }
        let model = &htt.wmi.htc.transport;
        let storage = model.storage.as_ref().unwrap();
        if storage.ring.len() != 8192
            || storage.buffers.len() != 2048
            || storage.fragments.as_ref().map(|b| b.len())
                != if model.config.continuous {
                    Some(usize::from(model.config.pending) * 64)
                } else {
                    None
                }
            || storage.qstate.as_ref().map(|b| b.len()) != if pfc { Some(4772) } else { None }
        {
            return TestResult::Fail(
                "retained native HTT DMA capacities differ from admitted resources",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_composed_owned_pci_setup
);
fn smoke_ath10k_htt_cancelled_ring_config_retains_owner() -> TestResult {
    let mut runtime = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    runtime.wmi.htc.transport.stall_rx = true;
    if once(runtime.start()) != Poll::Pending || runtime.wmi.htc.transport.storage.is_none() {
        return TestResult::Fail(
            "actual HTT ring publication did not retain all DMA before cancellation",
        );
    }
    let sent = runtime.wmi.htc.transport.inner.sent.len();
    if once(runtime.start()) != Poll::Ready(Err(htt::Error::Failed))
        || runtime.wmi.htc.transport.inner.sent.len() != sent
        || runtime.ready.is_some()
        || runtime.wmi.htc.transport.storage.as_ref().unwrap().filled != 1023
    {
        return TestResult::Fail("cancelled RX ring setup replayed, recycled DMA, or opened ready");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_cancelled_ring_config_retains_owner
);
fn smoke_ath10k_htt_unsupported_version_publishes_no_packet_dma() -> TestResult {
    let mut runtime = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    runtime.wmi.htc.transport.version = 4;
    if once(runtime.start()) != Poll::Ready(Err(htt::Error::Unsupported))
        || runtime.wmi.htc.transport.storage.is_some()
        || runtime.ready.is_some()
    {
        return TestResult::Fail("unsupported HTT target version admitted packet DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_unsupported_version_publishes_no_packet_dma
);

fn smoke_ath10k_htt_payload_retained_until_terminal_tx_indication() -> TestResult {
    for (hw, d, w, h) in [
        (HwRev::Qca6174, Dialect::Tlv, 4, 3),
        (HwRev::Qca9984, Dialect::TenFour, 6, 4),
    ] {
        let mut r = htt_boot(hw, d, w, h, false);
        assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
        let p = htt::tx::Parameters {
            kind: htt::tx::Kind::Ethernet,
            vdev: 0,
            tid: 16,
            hardware_crypto: false,
        };
        if once(r.transmit(p, &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 8, 0]))
            != Poll::Ready(Ok(0))
            || r.wmi.htc.transport.storage.as_ref().unwrap().tx.pending() != 1
        {
            return TestResult::Fail(
                "HTT TX literal, fragment layout or payload retention after CE completion failed",
            );
        }
        let Poll::Ready(Ok((eid, body))) = once(r.wmi.htc.receive()) else {
            return TestResult::Fail("real HTC did not route terminal HTT TX indication");
        };
        if eid != r.wmi.htc.htt
            || r.complete_tx(&body) != Ok(0)
            || r.wmi.htc.transport.storage.as_ref().unwrap().tx.pending() != 0
        {
            return TestResult::Fail(
                "terminal HTT completion did not retire its exact payload/fragment owner",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_payload_retained_until_terminal_tx_indication
);
fn smoke_ath10k_htt_tx_cancel_and_duplicate_batch_preserve_dma() -> TestResult {
    let p = htt::tx::Parameters {
        kind: htt::tx::Kind::Ethernet,
        vdev: 0,
        tid: 16,
        hardware_crypto: false,
    };
    let frame = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 8, 0];
    let mut r = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    r.wmi.htc.transport.stall_tx = true;
    if once(r.transmit(p, &frame)) != Poll::Pending
        || r.wmi.htc.transport.storage.as_ref().unwrap().tx.pending() != 1
    {
        return TestResult::Fail("TX cancellation fixture did not publish retained packet DMA");
    }
    let sent = r.wmi.htc.transport.inner.sent.len();
    if once(r.transmit(p, &frame)) != Poll::Ready(Err(htt::Error::Failed))
        || r.wmi.htc.transport.inner.sent.len() != sent
        || r.wmi.htc.transport.storage.as_ref().unwrap().tx.pending() != 1
    {
        return TestResult::Fail("cancelled HTT TX overwrote/recycled pending packet storage");
    }
    let mut r = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    assert_eq!(once(r.transmit(p, &frame)), Poll::Ready(Ok(0)));
    if r.complete_tx(&[7, 0, 2, 0, 0, 0, 0, 0]) != Err(htt::Error::Malformed)
        || r.wmi.htc.transport.storage.as_ref().unwrap().tx.pending() != 1
    {
        return TestResult::Fail("duplicate completion batch partially retired packet DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_tx_cancel_and_duplicate_batch_preserve_dma
);

fn legacy_rx_literal() -> Vec<u8> {
    let mut body = vec![0; 52];
    body[..8].copy_from_slice(&[1, 16, 7, 0, 0, 0, 0, 1]);
    body[48..].copy_from_slice(&[1, 1, 0, 0]);
    body
}
fn smoke_ath10k_htt_native_rx_chain_copies_before_repost() -> TestResult {
    let mut r = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    let storage = r.wmi.htc.transport.storage.as_mut().unwrap();
    let head = storage.buffers[0].as_mut().unwrap();
    head.bytes[4..8].copy_from_slice(&[0, 0, 0, 0x80]);
    head.bytes[24..28].copy_from_slice(&[0xb8, 0xb, 0, 0]);
    head.bytes[10] = 1;
    head.bytes[56..60].copy_from_slice(&[0, 0xc0, 0, 0]);
    head.bytes[300..].fill(0x55);
    storage.buffers[1].as_mut().unwrap().bytes.fill(0x66);
    r.wmi
        .htc
        .transport
        .inner
        .rx
        .push_back((1, header(1, &legacy_rx_literal())));
    let Poll::Ready(Ok((eid, body))) = once(r.wmi.htc.receive()) else {
        return TestResult::Fail("HTC did not route native RX indication");
    };
    if eid != r.wmi.htc.htt {
        return TestResult::Fail("RX indication escaped its HTT endpoint");
    }
    let Ok(batch) = r.receive_legacy(&body) else {
        return TestResult::Fail("owned native RX A-MSDU/chain reap failed");
    };
    let storage = r.wmi.htc.transport.storage.as_ref().unwrap();
    if batch.peer != 7
        || batch.tid != 16
        || batch.frames.len() != 1
        || batch.frames[0].0 != 1
        || batch.frames[0].1.payload.len() != 3000
        || batch.frames[0].1.payload[..1748] != vec![0x55; 1748]
        || batch.frames[0].1.payload[1748..] != vec![0x66; 1252]
        || batch.frames[0].1.descriptor[4..8] != [0, 0, 0, 0x80]
        || storage.producer.bytes != [1, 4, 0, 0]
        || storage.order.front() != Some(&2)
        || storage.buffers[0].as_ref().unwrap().bytes[4..8] != [0; 4]
        || storage.filled != 1023
    {
        return TestResult::Fail("RX payload copy, descriptor snapshot, half-empty pool or producer repost ordering wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_native_rx_chain_copies_before_repost
);
fn smoke_ath10k_htt_incomplete_rx_preserves_ring_ownership() -> TestResult {
    let mut r = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    if !matches!(
        r.receive_legacy(&legacy_rx_literal()),
        Err(htt::Error::Malformed)
    ) {
        return TestResult::Fail("native RX consumed an uncompleted DMA descriptor");
    }
    let storage = r.wmi.htc.transport.storage.as_ref().unwrap();
    if storage.producer.bytes != [0xff, 3, 0, 0]
        || storage.order.front() != Some(&0)
        || storage.filled != 1023
        || !matches!(
            r.receive_legacy(&legacy_rx_literal()),
            Err(htt::Error::Failed)
        )
    {
        return TestResult::Fail(
            "incomplete RX changed producer/owner state or permitted ambiguous retry",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_incomplete_rx_preserves_ring_ownership
);

fn paddr_literal(address: u32, offload: bool) -> Vec<u8> {
    let mut body = vec![0x12, if offload { 0x30 } else { 0x10 }, 7, 0, 0, 0, 1, 0];
    body.extend_from_slice(&address.to_le_bytes());
    body.extend_from_slice(&[14, 0, 0, 0]);
    body
}
fn smoke_ath10k_htt_full_reorder_paddr_selects_exact_dma_owner() -> TestResult {
    let mut r = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    let storage = r.wmi.htc.transport.storage.as_mut().unwrap();
    let b = storage.buffers[37].as_mut().unwrap();
    let address = b.address as u32;
    b.bytes[4..8].copy_from_slice(&[0, 0, 0, 0x80]);
    b.bytes[56..60].copy_from_slice(&[0, 0xc0, 0, 0]);
    b.bytes[300..314].fill(0x42);
    let Ok((indication, frames)) = r.receive_in_order(&paddr_literal(address, false)) else {
        return TestResult::Fail("native full-reorder PADDR event failed");
    };
    let storage = r.wmi.htc.transport.storage.as_ref().unwrap();
    if indication.peer != 7
        || indication.tid != 16
        || frames.len() != 1
        || frames[0].payload != [0x42; 14]
        || storage.order.front() != Some(&0)
        || storage.order.back() != Some(&37)
        || storage.producer.bytes != [0, 4, 0, 0]
        || storage.buffers[0].as_ref().unwrap().bytes[4..8] != [0; 4]
    {
        return TestResult::Fail("PADDR reap used FIFO owner or failed bounded repost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_full_reorder_paddr_selects_exact_dma_owner
);
fn smoke_ath10k_htt_full_reorder_duplicate_batch_retains_all_dma() -> TestResult {
    let mut r = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    let storage = r.wmi.htc.transport.storage.as_mut().unwrap();
    let b = storage.buffers[0].as_mut().unwrap();
    let address = b.address as u32;
    b.bytes[4..8].copy_from_slice(&[0, 0, 0, 0x80]);
    let mut event = paddr_literal(address, false);
    event[6] = 2;
    let last = event[8..].to_vec();
    event.extend_from_slice(&last);
    if !matches!(r.receive_in_order(&event), Err(htt::Error::Malformed)) {
        return TestResult::Fail("duplicate full-reorder pointer accepted");
    }
    let storage = r.wmi.htc.transport.storage.as_ref().unwrap();
    if storage.producer.bytes != [0xff, 3, 0, 0]
        || storage.order.front() != Some(&0)
        || storage.buffers[0].as_ref().unwrap().bytes[4..8] != [0, 0, 0, 0x80]
    {
        return TestResult::Fail("malformed PADDR batch partially reposted DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_full_reorder_duplicate_batch_retains_all_dma
);

fn smoke_ath10k_htt_idle_poll_then_tx_completion_progress() -> TestResult {
    let mut r = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    for _ in 0..3 {
        if !matches!(once(r.poll()), Poll::Ready(Ok(htt::Event::Idle))) {
            return TestResult::Fail("idle runtime poll poisoned the established session");
        }
    }
    let p = htt::tx::Parameters {
        kind: htt::tx::Kind::Ethernet,
        vdev: 0,
        tid: 16,
        hardware_crypto: false,
    };
    assert_eq!(
        once(r.transmit(p, &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 8, 0])),
        Poll::Ready(Ok(0))
    );
    if !matches!(once(r.poll()), Poll::Ready(Ok(htt::Event::Tx(0))))
        || r.wmi.htc.transport.storage.as_ref().unwrap().tx.pending() != 0
    {
        return TestResult::Fail(
            "actual HTC runtime poll failed to route/retire terminal HTT TX completion",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_idle_poll_then_tx_completion_progress
);

fn smoke_ath10k_htt2_management_dma_and_matching_completion() -> TestResult {
    let p = htt::tx::Parameters {
        kind: htt::tx::Kind::Management,
        vdev: 0,
        tid: 17,
        hardware_crypto: false,
    };
    let frame = [
        0xb0, 0, 0, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0, 0,
    ];
    let mut r = htt_boot(HwRev::Qca988x, Dialect::Main, 1, 1, false);
    r.wmi.htc.transport.version = 2;
    assert!(matches!(
        once(r.start()),
        Poll::Ready(Ok(htt::Ready { major: 2, .. }))
    ));
    if once(r.transmit(p, &frame)) != Poll::Ready(Ok(0))
        || r.wmi.htc.transport.storage.as_ref().unwrap().tx.pending() != 1
        || !matches!(once(r.poll()), Poll::Ready(Ok(htt::Event::Tx(0))))
        || r.wmi.htc.transport.storage.as_ref().unwrap().tx.pending() != 0
    {
        return TestResult::Fail(
            "HTT2 management literal/retained DMA/correlated terminal completion failed",
        );
    }
    let mut r = htt_boot(HwRev::Qca988x, Dialect::Main, 1, 1, false);
    r.wmi.htc.transport.version = 2;
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    assert_eq!(once(r.transmit(p, &frame)), Poll::Ready(Ok(0)));
    if r.complete_tx(&[7, 0, 1, 0, 0, 0]) != Err(htt::Error::Malformed)
        || r.wmi.htc.transport.storage.as_ref().unwrap().tx.pending() != 1
    {
        return TestResult::Fail(
            "data completion retired legacy management DMA without its terminal event",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt2_management_dma_and_matching_completion
);

fn smoke_ath10k_htt_native_multi_msdu_and_offload_metadata() -> TestResult {
    let mut r = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    {
        let storage = r.wmi.htc.transport.storage.as_mut().unwrap();
        for index in 0..2 {
            let b = storage.buffers[index].as_mut().unwrap();
            b.bytes[4..8].copy_from_slice(&[0, 0, 0, 0x80]);
            b.bytes[24] = 14;
            b.bytes[56..60].copy_from_slice(&if index == 0 {
                [0, 0x40, 0, 0]
            } else {
                [0, 0x80, 0, 0]
            });
            b.bytes[300..314].fill(0x40 + index as u8);
        }
    }
    let Ok(batch) = r.receive_legacy(&legacy_rx_literal()) else {
        return TestResult::Fail("native A-MSDU first/last continuation failed");
    };
    if batch.frames.len() != 2
        || batch.frames[0].1.payload != [0x40; 14]
        || batch.frames[1].1.payload != [0x41; 14]
        || r.wmi.htc.transport.storage.as_ref().unwrap().order.front() != Some(&2)
    {
        return TestResult::Fail(
            "native A-MSDU merged distinct MSDU ownership or terminated at first",
        );
    }
    let address = {
        let b = r.wmi.htc.transport.storage.as_mut().unwrap().buffers[99]
            .as_mut()
            .unwrap();
        b.bytes[..7].copy_from_slice(&[14, 0, 7, 0, 0, 16, 3]);
        b.bytes[7..21].fill(0x53);
        b.address as u32
    };
    let Ok((_, frames)) = r.receive_in_order(&paddr_literal(address, true)) else {
        return TestResult::Fail("full-reorder offload did not use its distinct7-byte metadata");
    };
    if frames.len() != 1
        || frames[0].payload != [0x53; 14]
        || frames[0].offload
            != Some(htt::rx::Offload {
                peer: 7,
                vdev: 0,
                tid: 16,
                flags: 3,
            })
        || frames[0].descriptor != [0; 300]
    {
        return TestResult::Fail(
            "offload metadata was confused with authenticated native RX descriptor",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_native_multi_msdu_and_offload_metadata
);
fn smoke_ath10k_htt_rx_republication_requires_live_authority() -> TestResult {
    let mut r = htt_boot(HwRev::Qca6174, Dialect::Tlv, 4, 3, false);
    assert!(matches!(once(r.start()), Poll::Ready(Ok(_))));
    let storage = r.wmi.htc.transport.storage.as_mut().unwrap();
    let b = storage.buffers[0].as_mut().unwrap();
    b.bytes[4..8].copy_from_slice(&[0, 0, 0, 0x80]);
    b.bytes[24] = 14;
    b.bytes[56..60].copy_from_slice(&[0, 0xc0, 0, 0]);
    let calls = core::cell::Cell::new(0);
    let result = storage.pop_amsdu(|| {
        let at = calls.get();
        calls.set(at + 1);
        at == 0
    });
    if !matches!(result, Err(htt::Error::Memory))
        || storage.producer.bytes != [0xff, 3, 0, 0]
        || storage.order.front() != Some(&0)
        || storage.buffers[0].as_ref().unwrap().bytes[4..8] != [0, 0, 0, 0x80]
    {
        return TestResult::Fail("revocation after copy republished or retired native RX DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt-runtime",
    smoke_ath10k_htt_rx_republication_requires_live_authority
);
