use super::*;
use crate::ath10k::{bmi::BmiError, wmi_runtime as radio};
include!("radio_golden.rs");
#[path = "ap_native_tests.rs"]
mod ap_native_tests;
#[path = "host_power_tests.rs"]
mod host_power_tests;

// These pure protocol fixtures can yield after credit-only HTC progress.
// Keep polling the SAME pinned operation; once() intentionally drops a
// Pending future and is reserved below for cancellation regressions.
fn drive<F: Future>(future: F) -> Poll<F::Output> {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return Poll::Ready(result);
        }
    }
    Poll::Pending
}

#[derive(Debug)]
struct RadioModel {
    sources: Option<crate::ath10k::firmware_source::Source>,
    inner: HttModel,
    phase: u8,
    sequence: u8,
    scan: u16,
    sent: Vec<Vec<u8>>,
    native_management: Vec<Vec<u8>>,
    stall: Option<u8>,
    reason: u32,
    malformed: bool,
    default_channels: bool,
    station: Option<StationFixture>,
    management: Option<ManagementFixture>,
    management_memory: Option<radio::management::Pool<HttBuffer>>,
    management_next: u64,
    mismatch_rx: bool,
    mismatched: u32,
    mlme_beacon: Option<bool>,
    mlme: Option<mlme_tests::Fixture>,
    teardown: Option<teardown_tests::Fixture>,
    ce: Option<crate::ath10k::boot::CeFixture>,
    data: Option<data_tests::Fixture>,
    active: Option<active_scan_tests::Fixture>,
    associated: Option<associated_scan_tests::Fixture>,
    offchannel: Option<offchannel_native::Fixture>,
    ps: Option<power_save_tests::Fixture>,
    ps_default_off: bool,
    frequency: u16,
    chain_mask: u8,
    chain_sent: Vec<Vec<u8>>,
    chain_stall: Option<u8>,
    coexistence: Option<coexistence_native::Fixture>,
    host_power: HostPowerFixture,
    beacon_hint: BeaconHintFixture,
    ap: Option<ap_native_tests::Fixture>,
    wow: Option<wow_native::Fixture>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum BeaconHintFixture {
    #[default]
    Off,
    Beacon,
    Probe,
    NoForeign,
    WrongScope,
    WrongChannel,
}
#[derive(Debug, Default)]
struct HostPowerFixture {
    enabled: bool,
    eligible: bool,
    defer: bool,
    deferred: bool,
    polls: usize,
}
// SAFETY: This private firmware fixture owns its complete graph of CE-model
// Rc/RefCell buffers; no reference-counted alias escapes the model. Moving the
// graph to another CPU is safe. Device's async mutex serializes all access,
// including fixture observation; production transports have no such impl.
unsafe impl Send for RadioModel {}
impl HostMemory for RadioModel {
    fn retain_wmi_memory(&mut self, p: &[MemoryPlan]) -> Result<Vec<MemoryChunk>, Error> {
        self.inner.retain_wmi_memory(p)
    }
}
impl htt::HttMemory for RadioModel {
    fn supports_htt_pfc(&self) -> bool {
        self.inner.supports_htt_pfc()
    }
    fn publish_htt_queue_state(&mut self, bytes: &[u8]) -> Result<(), htt::Error> {
        self.check_current().map_err(|_| htt::Error::Failed)?;
        self.inner.publish_htt_queue_state(bytes)
    }
    fn pending_htt_tx(&self) -> Result<usize, htt::Error> {
        self.check_current().map_err(|_| htt::Error::Failed)?;
        self.inner.pending_htt_tx()
    }
    fn prepare_wmi_management(&mut self, bytes: &[u8]) -> Result<(u32, u64), htt::Error> {
        if self.management_memory.is_none() {
            self.management_memory = Some(radio::management::Pool::new()?);
        }
        let address = &mut self.management_next;
        self.management_memory
            .as_mut()
            .unwrap()
            .prepare(bytes, |size| {
                let result = HttBuffer {
                    bytes: vec![0xa5; size],
                    address: *address,
                };
                *address += 4096;
                Ok(result)
            })
    }
    fn complete_wmi_management(&mut self, ids: &[u32]) -> Result<(), htt::Error> {
        self.management_memory
            .as_mut()
            .ok_or(htt::Error::Memory)?
            .complete(ids)
    }
    fn retain_htt_memory(&mut self, c: htt::Config) -> Result<htt::DmaConfig, htt::Error> {
        self.inner.retain_htt_memory(c)
    }
    fn prepare_htt_tx(
        &mut self,
        c: htt::Config,
        p: htt::tx::Parameters,
        b: &[u8],
    ) -> Result<(u16, Vec<u8>), htt::Error> {
        self.inner.prepare_htt_tx(c, p, b)
    }
    fn complete_htt_tx(&mut self, ids: &[u16], m: bool) -> Result<(), htt::Error> {
        self.inner.complete_htt_tx(ids, m)
    }
    fn pop_htt_amsdu(&mut self) -> Result<Vec<htt::rx::Msdu>, htt::Error> {
        self.inner.pop_htt_amsdu()
    }
    fn pop_htt_in_order(&mut self, i: &htt::rx::InOrder) -> Result<Vec<htt::rx::Msdu>, htt::Error> {
        self.inner.pop_htt_in_order(i)
    }
}
fn add_event(model: &mut RadioModel, id: u32, body: &[u8]) {
    let mut payload = id.to_le_bytes().to_vec();
    payload.extend_from_slice(body);
    model.inner.inner.rx.push_back((2, header(2, &payload)));
}
fn scan_event(model: &mut RadioModel, kind: u32, scan: u16, request: u16) {
    let mut body = Vec::new();
    for v in [
        kind,
        model.reason,
        u32::from(model.frequency),
        u32::from(request),
        u32::from(scan),
        0,
    ] {
        body.extend_from_slice(&v.to_le_bytes());
    }
    if model.inner.inner.dialect == Dialect::Tlv {
        let mut value = Vec::new();
        item(&mut value, 36, &body);
        body = value;
    }
    add_event(
        model,
        if matches!(model.inner.inner.dialect, Dialect::Main | Dialect::Tlv) {
            0x3001
        } else {
            0x9000
        },
        &body,
    );
}
fn management(model: &mut RadioModel, bad_ie: bool) {
    let mut frame = vec![0; 36];
    frame[0] = 0x80;
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&[2, 8, 9, 10, 11, 12]);
    frame[16..22].copy_from_slice(&[2, 8, 9, 10, 11, 12]);
    frame[32] = 100;
    frame[34] = 1;
    frame.extend_from_slice(&[0, 4, b'n', b'a', b'r', b'f', 3, 1, 1]);
    if let Some(protected) = model.mlme_beacon {
        frame[34..36].copy_from_slice(&(if protected { 0x431u16 } else { 0x421 }).to_le_bytes());
        frame.extend_from_slice(&[
            1, 8, 0x82, 0x84, 0x8b, 0x96, 12, 18, 24, 36, 50, 4, 48, 72, 96, 108,
        ]);
        if protected {
            frame.extend_from_slice(&[
                48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
            ]);
        }
    }
    if model.data.as_ref().is_some_and(|d| d.automatic) {
        frame = model.data.as_ref().unwrap().beacon();
    }
    if bad_ie {
        frame.push(0xff);
    }
    if model.active.as_ref().is_some_and(|active| !active.done)
        || model.beacon_hint == BeaconHintFixture::Probe
    {
        // An active scan receives actual probe responses, including the native
        // unicast receiver, through the same management descriptor decoder.
        frame[0] = 0x50;
        frame[4..10].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    }
    management_frame(model, frame);
}
fn management_frame(model: &mut RadioModel, frame: Vec<u8>) {
    let dialect = model.inner.inner.dialect;
    let extra = usize::from(dialect == Dialect::TenFour) * 4;
    let mut head = vec![
        0;
        if dialect == Dialect::TenFour {
            28
        } else if dialect == Dialect::Tlv {
            40
        } else {
            24
        }
    ];
    u32at(
        &mut head,
        0,
        if model.frequency < 3000 {
            u32::from((model.frequency - 2407) / 5)
        } else {
            u32::from((model.frequency - 5000) / 5)
        },
    );
    u32at(&mut head, 4, 31);
    u32at(&mut head, 16 + extra, frame.len() as u32);
    let mut body = Vec::new();
    if dialect == Dialect::Tlv {
        item(&mut body, 44, &head);
        item(&mut body, 17, &frame);
    } else {
        body = head;
        body.extend_from_slice(&frame);
    }
    let id = match dialect {
        Dialect::Main | Dialect::Tlv => 0x7001,
        Dialect::TenOne => 0x900c,
        _ => 0x900b,
    };
    add_event(model, id, &body);
}
impl Hif for RadioModel {
    fn runtime_idle_supported(&self) -> bool {
        self.host_power.enabled
    }
    fn runtime_idle(&mut self, eligible: bool) {
        self.host_power.eligible = eligible;
    }
    fn take_idle_deferred(&mut self) -> bool {
        core::mem::take(&mut self.host_power.deferred)
    }
    fn nonblocking_wmi(&self) -> bool {
        self.ce.is_some()
    }
    fn current_sources(&self) -> Option<crate::ath10k::firmware_source::Source> {
        self.sources.clone()
    }
    fn source_ready(&mut self, pipe: u8) -> Result<bool, BmiError> {
        if pipe == 3 {
            if let Some(fixture) = &mut self.associated {
                if let Some((remaining, bytes)) = &mut fixture.release_after_ready {
                    let ce = self.ce.as_mut().ok_or(BmiError::Unsupported)?;
                    if ce.source_bytes(3) != *bytes {
                        return Err(BmiError::BadResponse);
                    }
                    if *remaining == 0 {
                        ce.hold_source(false);
                        fixture.release_after_ready = None;
                    } else {
                        *remaining -= 1;
                    }
                }
            }
        }
        match &mut self.ce {
            Some(ce) => ce.source_ready(pipe),
            None => Ok(true),
        }
    }
    fn begin_send(&mut self, pipe: u8, bytes: &[u8]) -> Result<(), BmiError> {
        if pipe == 3 && self.ce.is_some() {
            // Reuse the independent firmware parser/emitter below, with its
            // blocking CE wrapper detached. The actual nonblocking source
            // descriptor/bounce and terminal receipt are owned by CeFixture.
            let chain_stage =
                chains_tests::stage(self.inner.inner.dialect, bytes.get(8..).unwrap_or_default());
            let stalled = if let Some(stage) = chain_stage {
                self.chain_stall == Some(stage)
            } else {
                self.associated
                    .as_ref()
                    .is_some_and(associated_scan_tests::stall_next)
                    || self
                        .active
                        .as_ref()
                        .is_some_and(active_scan_tests::stall_next)
                    || self.stall == Some(self.phase)
            };
            let mut ce = self.ce.take().unwrap();
            let outcome = {
                let mut emit = core::pin::pin!(self.send(pipe, bytes));
                emit.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            };
            let result = match outcome {
                Poll::Ready(Ok(())) => Ok(()),
                // Only the explicit model hold may suspend the emitter;
                // its transport receipt is still the native CE below.
                Poll::Pending if stalled => Ok(()),
                Poll::Pending => Err(BmiError::BadResponse),
                Poll::Ready(Err(error)) => Err(error),
            };
            if let Err(error) = result {
                self.ce = Some(ce);
                return Err(error);
            }
            if stalled {
                ce.hold_source(true);
            }
            let result = ce.begin_send(pipe, bytes);
            self.ce = Some(ce);
            return result;
        }
        if pipe == 4 && self.ap.is_some() {
            if let Some(ce) = &mut self.ce {
                ce.begin_send(pipe, bytes)?;
            }
            return ap_native_tests::transmit(self, bytes);
        }
        if pipe != 4 || self.data.is_none() {
            return Err(BmiError::Unsupported);
        }
        if let Some(ce) = &mut self.ce {
            ce.begin_send(pipe, bytes)?;
        }
        if offchannel_native::is_htt(self, bytes) {
            return offchannel_native::htt_send(self, bytes);
        }
        if let Some(result) = data_tests::pfc_response(self, bytes) {
            return result;
        }
        data_tests::send_now(self, bytes)
    }
    fn poll_now(&mut self) -> Result<Option<(u8, Vec<u8>)>, BmiError> {
        self.host_power.deferred = false;
        if self.host_power.enabled
            && self.host_power.eligible
            && self.host_power.defer
            && self.inner.inner.rx.is_empty()
        {
            self.host_power.deferred = true;
            return Ok(None);
        }
        self.host_power.polls += 1;
        ap_native_tests::poll(self);
        if let Some(ce) = &mut self.ce {
            ce.poll_now()?;
        }
        offchannel_native::poll(self)?;
        data_tests::poll(self)?;
        match self.inner.inner.rx.pop_front() {
            Some((pipe, bytes)) => match &mut self.ce {
                Some(ce) => ce.receive(pipe, &bytes).map(Some),
                None => Ok(Some((pipe, bytes))),
            },
            None => Ok(None),
        }
    }
    async fn poll(&mut self, b: u64) -> Result<Option<(u8, Vec<u8>)>, BmiError> {
        ap_native_tests::poll(self);
        offchannel_native::poll(self)?;
        data_tests::poll(self)?;
        if self.mismatch_rx && self.inner.inner.rx.is_empty() {
            // Literal TLV management RX containing an otherwise valid Open
            // Authentication response for a different local recipient.
            let mut head = vec![0; 40];
            u32at(&mut head, 0, 1);
            u32at(&mut head, 4, 31);
            u32at(&mut head, 16, 30);
            let frame = [
                0xb0, 0, 0, 0, 4, 3, 4, 5, 6, 7, 2, 8, 9, 10, 11, 12, 2, 8, 9, 10, 11, 12, 0, 0, 0,
                0, 2, 0, 0, 0,
            ];
            let mut body = Vec::new();
            item(&mut body, 44, &head);
            item(&mut body, 17, &frame);
            add_event(self, 0x7001, &body);
            self.mismatched += 1;
        }
        match self.inner.poll(b).await? {
            Some((pipe, bytes)) if self.ce.is_some() => {
                self.ce.as_mut().unwrap().receive(pipe, &bytes).map(Some)
            }
            other => Ok(other),
        }
    }
    async fn receive(&mut self, b: u64) -> Result<(u8, Vec<u8>), BmiError> {
        let (pipe, bytes) = self.inner.receive(b).await?;
        match &mut self.ce {
            Some(ce) => ce.receive(pipe, &bytes),
            None => Ok((pipe, bytes)),
        }
    }
    async fn send(&mut self, pipe: u8, bytes: &[u8]) -> Result<(), BmiError> {
        let hold_chain = pipe == 3
            && self.chain_stall.is_some_and(|target| {
                chains_tests::stage(self.inner.inner.dialect, bytes.get(8..).unwrap_or_default())
                    == Some(target)
            });
        if let Some(ce) = &mut self.ce {
            if hold_chain {
                ce.hold_source(true);
            }
            ce.send(pipe, bytes).await?;
        }
        if pipe == 4 && offchannel_native::is_htt(self, bytes) {
            return offchannel_native::htt_send(self, bytes);
        }
        if pipe == 4 {
            if let Some(result) = data_tests::pfc_response(self, bytes) {
                return result;
            }
        }
        if pipe == 4 && self.data.is_some() {
            return data_tests::send(self, bytes).await;
        }
        if pipe == 4 && self.management.is_some() {
            return management_htt_send(self, bytes).await;
        }
        if pipe != 3 || self.inner.storage.is_none() {
            return self.inner.send(pipe, bytes).await;
        }
        if bytes.len() < 8
            || bytes[0] != 2
            || bytes[1] != 1
            || bytes[5] != self.sequence
            || bytes[2..4] != (bytes.len() as u16 - 8).to_le_bytes()
        {
            return Err(BmiError::BadResponse);
        }
        self.sequence = self.sequence.wrapping_add(1);
        if self.ap.is_some() {
            return ap_native_tests::command(self, bytes);
        }
        if wow_native::handles(self, &bytes[8..]) {
            return wow_native::send(self, bytes);
        }
        if let Some(stage) = chains_tests::stage(self.inner.inner.dialect, &bytes[8..]) {
            return chains_tests::send(self, bytes, stage).await;
        }
        if offchannel_native::handles(self, &bytes[8..]) {
            return offchannel_native::send(self, bytes);
        }
        if coexistence_native::handles(self, &bytes[8..]) {
            return coexistence_native::send(self, bytes);
        }
        if data_tests::protection_handles(self.inner.inner.dialect, &bytes[8..]) {
            return data_tests::protection_send(self, bytes).await;
        }
        if power_save_tests::handles(self.inner.inner.dialect, &bytes[8..]) {
            return power_save_tests::send(self, bytes).await;
        }
        if self.associated.as_ref().is_some_and(|fixture| {
            associated_scan_tests::handles(fixture, self.inner.inner.dialect, &bytes[8..])
        }) {
            return associated_scan_tests::send(self, bytes).await;
        }
        if self.phase >= 2
            && self.active.as_ref().is_some_and(|active| {
                active_scan_tests::handles(active, self.inner.inner.dialect, &bytes[8..])
            })
        {
            return active_scan_tests::send(self, bytes).await;
        }
        if data_tests::install_handles(self, &bytes[8..]) {
            return data_tests::install_key(self, bytes);
        }
        if data_tests::captures_management(self, &bytes[8..]) {
            return data_tests::capture_management(self, bytes);
        }
        if self.teardown.is_some() {
            return teardown_tests::send(self, bytes).await;
        }
        // A second START_SCAN before the association began (a fresh
        // scan after an earlier one on the same harness) is another
        // scan of the script, not the association's first command.
        let rescan = self.station.is_none()
            && bytes.len() >= 12
            && matches!(
                u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                0x3001 | 0x9000
            );
        if self.data.as_ref().is_some_and(|d| d.automatic) && self.phase >= 3 && !rescan {
            if self.station.is_none() {
                self.station = Some(StationFixture::new());
            }
            if self.station.as_ref().is_some_and(|s| s.phase >= 4) {
                return data_tests::control(self, bytes).await;
            }
        }
        if self.mlme.is_some() {
            return mlme_tests::send(self, bytes).await;
        }
        if self.management.is_some() {
            return management_send(self, bytes).await;
        }
        if self.station.is_some() {
            return station_send(self, bytes).await;
        }
        let dialect = self.inner.inner.dialect;
        let mut expected = match (self.phase, dialect) {
            (1, _) if self.default_channels => match dialect {
                Dialect::Main => CHANNELS_DEFAULT_MAIN,
                Dialect::Tlv => CHANNELS_DEFAULT_TLV,
                _ => CHANNELS_DEFAULT_10X,
            },
            (0, Dialect::Main) => CREATE_MAIN,
            (0, Dialect::TenOne) => CREATE_10X,
            (0, Dialect::TenTwo | Dialect::TenTwoFour) => CREATE_102,
            (0, Dialect::Tlv) => CREATE_TLV,
            (0, Dialect::TenFour) => CREATE_104,
            (1, Dialect::Main) => CHANNELS_MAIN,
            (1, Dialect::Tlv) => CHANNELS_TLV,
            (1, _) => CHANNELS_10X,
            (_, Dialect::Main) => SCAN_MAIN,
            (_, Dialect::Tlv) => SCAN_TLV,
            (_, Dialect::TenFour) => SCAN_104,
            _ => SCAN_10X,
        }
        .to_vec();
        if self.phase == 1 && self.frequency > 3000 && !self.default_channels {
            let at = if dialect == Dialect::Tlv { 48 } else { 32 };
            u32at(&mut expected, at, u32::from(self.frequency));
            u32at(&mut expected, at + 4, u32::from(self.frequency));
        }
        if self.phase == 1 && self.active.is_some() {
            expected =
                active_scan_tests::receive_on(dialect, &self.active.as_ref().unwrap().receive);
        }
        if self.phase >= 2 {
            if self.data.as_ref().is_some_and(|d| d.automatic) {
                let (base, common) = if dialect == Dialect::Tlv {
                    (8, 100)
                } else if matches!(dialect, Dialect::Main | Dialect::TenFour) {
                    (4, 64)
                } else {
                    (4, 60)
                };
                let at = base + common;
                // The one-channel passive request carries the actual AP
                // frequency rather than a generated production scan plan.
                let f = at + if dialect == Dialect::Tlv { 4 } else { 8 };
                u32at(&mut expected, f, u32::from(self.frequency));
                if dialect == Dialect::Tlv {
                    u32at(&mut expected, base + 64, 1);
                    u32at(&mut expected, at, (16 << 16) | 4);
                    expected.drain(at + 8..at + 12);
                } else {
                    u32at(&mut expected, at + 4, 1);
                    expected.drain(at + 12..at + 16);
                }
            }
            self.scan += 1;
            u32at(
                &mut expected,
                if dialect == Dialect::Tlv { 8 } else { 4 },
                0xa000 | u32::from(self.scan),
            );
        }
        self.sent.push(bytes.to_vec());
        if bytes[8..] != expected {
            return Err(BmiError::BadResponse);
        }
        let phase = self.phase;
        self.phase = self.phase.saturating_add(1);
        // The completed CE send requests one real HTC WMI credit return.
        self.inner.inner.rx.push_back((
            2,
            vec![
                2,
                2,
                8,
                0,
                8,
                0,
                0,
                0,
                1,
                4,
                0,
                0,
                2,
                bytes.len().div_ceil(256) as u8,
                0,
                0,
            ],
        ));
        if self.stall == Some(phase) {
            core::future::pending::<()>().await;
        }
        if phase >= 2 {
            scan_event(self, 2, 0xa000 | self.scan.saturating_sub(1), 0xa001);
            scan_event(self, 2, 0xa000 | self.scan, 0xa002); // wrong requestor
            scan_event(self, 1, 0xa000 | self.scan, 0xa001);
            match self.beacon_hint {
                BeaconHintFixture::Beacon | BeaconHintFixture::Probe => {
                    scan_event(self, 8, 0xa000 | self.scan, 0xa001);
                }
                BeaconHintFixture::WrongScope => {
                    scan_event(self, 8, 0xa000 | self.scan, 0xa002);
                }
                BeaconHintFixture::WrongChannel => {
                    let frequency = self.frequency;
                    self.frequency = 5200;
                    scan_event(self, 8, 0xa000 | self.scan, 0xa001);
                    self.frequency = frequency;
                }
                BeaconHintFixture::Off | BeaconHintFixture::NoForeign => {}
            }
            management(self, true);
            management(self, false);
            if self.malformed {
                add_event(
                    self,
                    if dialect == Dialect::Tlv {
                        0x3001
                    } else {
                        0x9000
                    },
                    &[0; 4],
                );
            } else {
                scan_event(self, 2, 0xa000 | self.scan, 0xa001);
            }
        }
        Ok(())
    }
}
fn radio_boot(version: u32, dialect: Dialect) -> radio::Radio<RadioModel> {
    radio_boot_features(version, dialect, 0)
}
fn radio_boot_features(version: u32, dialect: Dialect, features: u64) -> radio::Radio<RadioModel> {
    radio_boot_options(version, dialect, features, 3)
}
fn radio_boot_options(
    version: u32,
    dialect: Dialect,
    features: u64,
    major: u8,
) -> radio::Radio<RadioModel> {
    radio_boot_country(version, dialect, features, major, 0x64)
}
fn radio_boot_country(
    version: u32,
    dialect: Dialect,
    features: u64,
    major: u8,
    factory: u32,
) -> radio::Radio<RadioModel> {
    radio_boot_country_ht(version, dialect, features, major, factory, None)
}
fn radio_boot_country_ht(
    version: u32,
    dialect: Dialect,
    features: u64,
    major: u8,
    factory: u32,
    ht: Option<u32>,
) -> radio::Radio<RadioModel> {
    radio_boot_country_ht_rf(version, dialect, features, major, factory, ht, 2)
}
fn radio_boot_country_ht_rf(
    version: u32,
    dialect: Dialect,
    features: u64,
    major: u8,
    factory: u32,
    ht: Option<u32>,
    rf_chains: u32,
) -> radio::Radio<RadioModel> {
    let hardware = if dialect == Dialect::Tlv {
        HwRev::Qca6174
    } else if dialect == Dialect::TenFour {
        HwRev::Qca9984
    } else {
        HwRev::Qca988x
    };
    radio_boot_source(
        version,
        dialect,
        features,
        major,
        factory,
        ht,
        RadioSource {
            hardware,
            rf_chains,
            vht: None,
        },
    )
}
#[derive(Clone, Copy)]
struct RadioSource {
    hardware: HwRev,
    rf_chains: u32,
    vht: Option<(u32, u32)>,
}
fn radio_boot_source(
    version: u32,
    dialect: Dialect,
    features: u64,
    major: u8,
    factory: u32,
    ht: Option<u32>,
    source: RadioSource,
) -> radio::Radio<RadioModel> {
    radio_boot_source_version(version, dialect, features, (major, 1), factory, ht, source)
}
fn radio_boot_source_version(
    version: u32,
    dialect: Dialect,
    features: u64,
    htt_version: (u8, u8),
    factory: u32,
    ht: Option<u32>,
    source: RadioSource,
) -> radio::Radio<RadioModel> {
    radio_boot_source_ap(
        version,
        dialect,
        features,
        htt_version,
        factory,
        ht,
        (source, false),
    )
}
fn radio_boot_source_ap(
    version: u32,
    dialect: Dialect,
    features: u64,
    htt_version: (u8, u8),
    factory: u32,
    ht: Option<u32>,
    profile: (RadioSource, bool),
) -> radio::Radio<RadioModel> {
    let (source, ap_services) = profile;
    let RadioSource {
        hardware,
        rf_chains,
        vht,
    } = source;
    let htt_dialect = if dialect == Dialect::Tlv {
        3
    } else if dialect == Dialect::TenFour {
        4
    } else {
        1
    };
    let c = htt::Config::new(hardware, version, htt_dialect, features & (1 << 13)).unwrap();
    let mut inner = HttModel::new(dialect, c, hardware);
    if dialect == Dialect::TenFour && hardware == HwRev::Qca9888 {
        // Independent Linux resource words8/9: QCA9888 has two physical
        // chains; the default frozen10.4 fixture is QCA9984's four.
        u32at(&mut inner.inner.expected, 4 + 8 * 4, 3);
        u32at(&mut inner.inner.expected, 4 + 9 * 4, 3);
    }
    inner.inner.factory = factory;
    inner.inner.ap_services = ap_services;
    inner.inner.ht = ht;
    inner.inner.rf_chains = Some(rf_chains);
    inner.inner.vht = vht;
    let raw = features & (1 << 10) != 0;
    inner.raw = raw;
    if raw {
        let at = match dialect {
            Dialect::Main => 4 + 52,
            Dialect::TenOne | Dialect::TenTwo | Dialect::TenTwoFour => 4 + 44,
            Dialect::TenFour => 4 + 56,
            Dialect::Tlv => 4 + 32 + 4 + 52,
        };
        inner.inner.expected[at..at + 4].fill(0);
    }
    inner.version = htt_version.0;
    inner.minor = htt_version.1;
    let model = RadioModel {
        sources: None,
        inner,
        phase: 0,
        sequence: 1,
        scan: 0,
        sent: Vec::new(),
        native_management: Vec::new(),
        stall: None,
        reason: 0,
        malformed: false,
        default_channels: false,
        station: None,
        management: None,
        management_memory: None,
        management_next: 0x900000,
        mismatch_rx: false,
        mismatched: 0,
        mlme_beacon: None,
        mlme: None,
        teardown: None,
        ce: None,
        data: None,
        active: None,
        ps: None,
        wow: None,
        ps_default_off: false,
        frequency: 2412,
        chain_mask: (((1u32 << rf_chains.min(4)) - 1)
            & if dialect == Dialect::TenFour { 15 } else { 7 }) as u8,
        chain_sent: Vec::new(),
        chain_stall: None,
        coexistence: None,
        associated: None,
        offchannel: None,
        host_power: HostPowerFixture::default(),
        beacon_hint: BeaconHintFixture::Off,
        ap: None,
    };
    let mut htc = Session::new(model, hardware);
    assert_eq!(once(htc.start()), Poll::Ready(Ok(())));
    let mut wmi = Runtime::new(
        htc,
        dialect,
        hardware,
        if raw { 1 << 10 } else { 0 } | (features & (1 << 13)),
    );
    assert!(matches!(once(wmi.start()), Poll::Ready(Ok(_))));
    let mut htt = htt::Runtime::new(wmi, c);
    assert!(matches!(once(htt.start()), Poll::Ready(Ok(_))));
    radio::Radio::new(htt, dialect, features)
}
fn smoke_ath10k_composed_wmi_passive_scan_all_dialects() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        let mut r = radio_boot(version, dialect);
        if once(r.start(&[2412, 5180]))
            != Poll::Ready(Ok(radio::ScanReady {
                mac: [2, 3, 4, 5, 6, 7],
                channels: 2,
            }))
        {
            return TestResult::Fail(
                "actual HTC/WMI/HTT→scan-vdev/channel Linux golden chain failed",
            );
        }
        // A scan owner must keep the real HTT terminal completion flowing.
        let p = htt::tx::Parameters {
            kind: htt::tx::Kind::Ethernet,
            vdev: 0,
            tid: 16,
            hardware_crypto: false,
        };
        if once(
            r.htt
                .transmit(p, &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 8, 0]),
        ) != Poll::Ready(Ok(0))
        {
            return TestResult::Fail(
                "composed scan fixture could not retain a preexisting HTT packet",
            );
        }
        for _ in 0..2 {
            let Poll::Ready(Ok(report)) = drive(r.passive_scan(&[2412, 5180])) else {
                return TestResult::Fail(
                    "native WMI scan command/event/management progression failed",
                );
            };
            if report.bss.len() != 1
                || report.received != 2
                || report.ignored != 3
                || report.truncated
            {
                return TestResult::Fail(
                    "stale scan/requestor events or malformed beacon entered scan result",
                );
            }
            let b = &report.bss[0];
            if b.ssid != b"narf"
                || b.bssid != [2, 8, 9, 10, 11, 12]
                || b.frequency != 2412
                || b.snr != 31
                || b.capability != 1
                || b.beacon_interval != 100
                || b.information_elements != [0, 4, b'n', b'a', b'r', b'f', 3, 1, 1]
            {
                return TestResult::Fail("native management header or beacon IE identity mismatch");
            }
        }
        if r.htt
            .wmi
            .htc
            .transport
            .inner
            .storage
            .as_ref()
            .unwrap()
            .tx
            .pending()
            != 0
            || !matches!(r.take_event(), Some(htt::Event::Tx(0)))
        {
            return TestResult::Fail(
                "WMI scan starved HTT terminal completion or lost packet event",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_composed_wmi_passive_scan_all_dialects
);
fn smoke_ath10k_scan_cancel_or_bad_terminal_retains_radio_owner() -> TestResult {
    for stall in [0, 2] {
        let mut r = radio_boot(4, Dialect::Tlv);
        r.htt.wmi.htc.transport.stall = Some(stall);
        if stall == 0 {
            if once(r.start(&[2412, 5180])) != Poll::Pending {
                return TestResult::Fail("create cancellation fixture did not publish");
            }
            if once(r.start(&[2412, 5180])) != Poll::Ready(Err(radio::Error::Failed))
                || r.ready.is_some()
            {
                return TestResult::Fail("cancelled vdev creation replayed or admitted scan");
            }
        } else {
            assert!(matches!(once(r.start(&[2412, 5180])), Poll::Ready(Ok(_))));
            if !matches!(once(r.passive_scan(&[2412, 5180])), Poll::Pending) {
                return TestResult::Fail("scan cancellation fixture did not publish");
            }
            if !matches!(
                once(r.passive_scan(&[2412, 5180])),
                Poll::Ready(Err(radio::Error::Failed))
            ) {
                return TestResult::Fail("cancelled scan owner admitted another scan");
            }
        }
        let m = &r.htt.wmi.htc.transport;
        if m.sent.len() != usize::from(stall) + 1
            || m.inner.storage.as_ref().unwrap().filled != 1023
            || m.inner.inner.retained.is_none()
        {
            return TestResult::Fail(
                "cancelled WMI operation reused command or released mission DMA",
            );
        }
    }
    for malformed in [false, true] {
        let mut r = radio_boot(4, Dialect::Tlv);
        assert!(matches!(once(r.start(&[2412, 5180])), Poll::Ready(Ok(_))));
        let m = &mut r.htt.wmi.htc.transport;
        m.malformed = malformed;
        if !malformed {
            m.reason = 4;
        }
        let first = drive(r.passive_scan(&[2412, 5180]));
        if !matches!(
            first,
            Poll::Ready(Err(radio::Error::Firmware(4) | radio::Error::Malformed))
        ) || !matches!(
            once(r.passive_scan(&[2412, 5180])),
            Poll::Ready(Err(radio::Error::Failed))
        ) {
            return TestResult::Fail("ambiguous/failed terminal scan permitted owner reuse");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_scan_cancel_or_bad_terminal_retains_radio_owner
);
fn smoke_ath10k_scan_channel_validation_precedes_publication() -> TestResult {
    let mut r = radio_boot(4, Dialect::Tlv);
    for channels in [&[][..], &[2412, 2412], &[2413], &[5955]] {
        if !matches!(once(r.start(channels)), Poll::Ready(Err(_)))
            || !r.htt.wmi.htc.transport.sent.is_empty()
        {
            return TestResult::Fail("invalid scan channel published vdev/channel command");
        }
    }
    // A valid IEEE channel beyond SERVICE_READY's hardware range is not admitted.
    if once(r.start(&[2484])) != Poll::Ready(Err(radio::Error::Unsupported))
        || !r.htt.wmi.htc.transport.sent.is_empty()
    {
        return TestResult::Fail("firmware hardware range did not constrain passive scan");
    }
    assert!(matches!(once(r.start(&[2412, 5180])), Poll::Ready(Ok(_))));
    let sent = r.htt.wmi.htc.transport.sent.len();
    if !matches!(
        once(r.passive_scan(&[2437])),
        Poll::Ready(Err(radio::Error::Unsupported))
    ) || r.htt.wmi.htc.transport.sent.len() != sent
    {
        return TestResult::Fail("scan widened configured receive-only channel policy");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_scan_channel_validation_precedes_publication
);

fn smoke_ath10k_native_radio_hardware_channel_setup_and_scan() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        let mut r = radio_boot(version, dialect);
        r.htt.wmi.htc.transport.default_channels = true;
        if once(r.start_from_hardware())
            != Poll::Ready(Ok(radio::ScanReady {
                mac: [2, 3, 4, 5, 6, 7],
                channels: 36,
            }))
        {
            return TestResult::Fail(
                "production hardware-range channel selection differs from native Linux golden",
            );
        }
        if !matches!(drive(r.passive_scan(&[2412,5180])),Poll::Ready(Ok(report)) if report.bss.len()==1)
        {
            return TestResult::Fail(
                "native default-channel owner cannot complete correlated scan",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_native_radio_hardware_channel_setup_and_scan
);

fn smoke_ath10k_scan_keeps_owner_across_real_scheduler_yields() -> TestResult {
    let mut r = radio_boot(4, Dialect::Tlv);
    assert!(matches!(once(r.start(&[2412, 5180])), Poll::Ready(Ok(_))));
    {
        let mut scan = core::pin::pin!(r.passive_scan(&[2412, 5180]));
        let mut cx = Context::from_waker(Waker::noop());
        if scan.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail(
                "credit-only progress did not exercise real cooperative yield",
            );
        }
        if !matches!(drive(scan.as_mut()),Poll::Ready(Ok(report)) if report.bss.len()==1) {
            return TestResult::Fail("same pinned scan lost command/event ownership across yield");
        }
    }
    if !matches!(drive(r.passive_scan(&[2412,5180])),Poll::Ready(Ok(report)) if report.bss.len()==1)
    {
        return TestResult::Fail("terminal scan did not restore normal owner reuse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_scan_keeps_owner_across_real_scheduler_yields
);

#[path = "station_tests.rs"]
mod station_tests;
use station_tests::{station_send, StationFixture};

#[path = "management_tests.rs"]
mod management_tests;
use management_tests::{management_htt_send, management_send, ManagementFixture};

#[path = "mlme_tests.rs"]
mod mlme_tests;

#[path = "teardown_tests.rs"]
mod teardown_tests;

#[path = "data_tests.rs"]
mod data_tests;

#[path = "active_scan_tests.rs"]
mod active_scan_tests;
#[path = "associated_scan_tests.rs"]
mod associated_scan_tests;
#[path = "chains_tests.rs"]
mod chains_tests;
#[path = "coexistence_native.rs"]
mod coexistence_native;
#[path = "offchannel_native.rs"]
mod offchannel_native;
#[path = "power_save_tests.rs"]
mod power_save_tests;
#[path = "wow_native.rs"]
mod wow_native;

/// cfg80211 keeps one BSS table per wiphy (`scan.c::cfg80211_bss_update`):
/// a P2P_DEVICE scan merges its GO beside the netdev's results (so the P2P
/// client's station prepare finds it), while a netdev scan still replaces
/// the table it observed.
fn smoke_ath10k_p2p_device_scan_merges_shared_bss_table() -> TestResult {
    let mut r = radio_boot(4, Dialect::Tlv);
    let bss = |last: u8, frequency: u16, ie: u8| radio::ScanBss {
        bssid: [2, 0, 0, 0, 0, last],
        ssid: b"DIRECT-xy".to_vec(),
        frequency,
        snr: 30,
        capability: 1,
        beacon_interval: 100,
        information_elements: vec![ie],
    };
    if r.publish_scan_cache(&[bss(1, 2412, 1)], None, false)
        .is_err()
    {
        return TestResult::Fail("netdev scan");
    }
    if r.publish_scan_cache(&[bss(9, 2437, 9), bss(1, 2412, 7)], None, true)
        .is_err()
    {
        return TestResult::Fail("p2p device scan");
    }
    if r.information_elements([2, 0, 0, 0, 0, 9]) != Some(vec![9])
        || r.information_elements([2, 0, 0, 0, 0, 1]) != Some(vec![7])
    {
        return TestResult::Fail("p2p scan did not merge into the wiphy table");
    }
    if r.publish_scan_cache(&[bss(3, 2462, 3)], None, false)
        .is_err()
        || r.information_elements([2, 0, 0, 0, 0, 9]).is_some()
        || r.information_elements([2, 0, 0, 0, 0, 3]) != Some(vec![3])
    {
        return TestResult::Fail("netdev scan replaces unbound entries");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_device_scan_merges_shared_bss_table
);
