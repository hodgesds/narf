use super::*;
use alloc::sync::Arc;
use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[path = "active_scan_tests.rs"]
mod active_scan_tests;

#[path = "amsdu_rx_tests.rs"]
mod amsdu_rx_tests;

#[path = "dynamic_wmm_tests.rs"]
mod dynamic_wmm_tests;
#[path = "frag_tests.rs"]
mod frag_tests;
#[path = "greenfield_tests.rs"]
mod greenfield_tests;
#[path = "he_tests.rs"]
mod he_tests;
#[path = "ht20_tests.rs"]
mod ht20_tests;
#[path = "ht40_tests.rs"]
mod ht40_tests;
#[path = "ht_protection_tests.rs"]
mod ht_protection_tests;
#[path = "pmf_tests.rs"]
mod pmf_tests;
#[path = "receive_epoch_tests.rs"]
mod receive_epoch_tests;
#[path = "rx_ba_tests.rs"]
mod rx_ba_tests;
#[path = "rx_fragment_tests.rs"]
mod rx_fragment_tests;
#[path = "system_pm_tests.rs"]
mod system_pm_tests;
#[path = "tx_ba_tests.rs"]
mod tx_ba_tests;
#[path = "tx_nss_tests.rs"]
mod tx_nss_tests;
#[path = "tx_pipeline_station_tests.rs"]
mod tx_pipeline_station_tests;
#[path = "vht160_tests.rs"]
mod vht160_tests;
#[path = "vht_tests.rs"]
mod vht_tests;
#[path = "wmm_regulatory_tests.rs"]
mod wmm_regulatory_tests;
#[path = "wmm_tests.rs"]
mod wmm_tests;

fn mt76_late_preflight_retry_and_owned_start_survive_cancelled_waiter() -> TestResult {
    let allocations = Cell::new(0);
    // The exact queued-start constructor used by public provisioning must not
    // begin a session for missing or malformed firmware. A later valid pair
    // can enter the same queue without a reset or an earlier owner to recover.
    for missing in [true, false] {
        let attempt = KeyWork::prepare(
            || {
                let image = if missing {
                    Err(Error::InvalidFirmware)
                } else {
                    Firmware::prepare(&[], &[])
                }?;
                allocations.set(allocations.get() + 1);
                Ok(Session::new(Model::new(), image))
            },
            |session| alloc::boxed::Box::pin(async move { (session, Ok(())) }),
        );
        if !matches!(attempt, Err(Error::InvalidFirmware)) || allocations.get() != 0 {
            return TestResult::Fail("MT76 preflight consumed an owner before valid assets");
        }
    }
    let mut work = KeyWork::prepare(
        || {
            let image = firmware(32);
            allocations.set(allocations.get() + 1);
            Ok(Session::new(Model::new(), image))
        },
        |mut session| {
            alloc::boxed::Box::pin(async move {
                let result = async {
                    session.run().await?;
                    // Cancel a waiter between firmware DMA and radio setup.
                    narf_scheduler::yield_now().await;
                    session.initialize_radio().await.map(|_| ())
                }
                .await;
                (session, result)
            })
        },
    )
    .unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut waiter = pin!(poll_fn(|cx| work.poll(cx)));
        if waiter.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("MT76 staged startup skipped cancellation boundary");
        }
    }
    for _ in 0..1000 {
        if work.poll(&mut cx).is_ready() {
            break;
        }
    }
    let Some((mut session, result)) = work.completed.take() else {
        return TestResult::Fail("MT76 cancelled waiter lost retained initial startup");
    };
    if result.is_err()
        || allocations.get() != 1
        || !matches!(session.state, State::RadioReady(_))
        || session.security.is_some()
        || run(session.run()) != Err(Error::Busy)
    {
        return TestResult::Fail("MT76 staged startup replayed or published invalid radio state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/firmware",
    mt76_late_preflight_retry_and_owned_start_survive_cancelled_waiter
);

pub(super) fn firmware(bytes: usize) -> Firmware {
    let mut patch = vec![0u8; 96 + 64 + bytes];
    patch[44..48].copy_from_slice(&1u32.to_be_bytes());
    patch[96..100].copy_from_slice(&2u32.to_be_bytes());
    patch[100..104].copy_from_slice(&160u32.to_be_bytes());
    patch[104..108].copy_from_slice(&(bytes as u32).to_be_bytes());
    patch[108..112].copy_from_slice(&0x900000u32.to_be_bytes());
    patch[112..116].copy_from_slice(&(bytes as u32).to_be_bytes());
    patch[116..120].copy_from_slice(&u32::MAX.to_be_bytes());
    patch[160..].fill(0x55);
    let mut ram = vec![0u8; bytes + 40 + 36];
    ram[..bytes].fill(0xaa);
    ram[bytes + 16..bytes + 20].copy_from_slice(&0x400000u32.to_le_bytes());
    ram[bytes + 20..bytes + 24].copy_from_slice(&(bytes as u32).to_le_bytes());
    ram[bytes + 40 + 2] = 1;
    ram[bytes + 40 + 3] = 1;
    Firmware::prepare(&patch, &ram).unwrap()
}
fn test_permission() -> crate::mt7921::association::TxPermission {
    test_permission_for(6)
}
fn test_permission_for(channel: u8) -> crate::mt7921::association::TxPermission {
    crate::mt7921::association::TxPermission::from_domain(
        &narf_wireless::reg::RegulatoryDomain {
            country_code: *b"US",
            rules: vec![narf_wireless::reg::RegRule {
                freq_start_mhz: if channel <= 11 { 2402 } else { 5170 },
                freq_end_mhz: if channel <= 11 { 2472 } else { 5895 },
                max_bandwidth_mhz: 20,
                max_power_dbm: 17,
                flags: narf_wireless::reg::RegFlags::empty(),
            }],
        },
        channel,
    )
    .unwrap()
}

fn ap_eapol_frame(own: [u8; 6], ap: [u8; 6], pdu: &[u8]) -> Vec<u8> {
    let mut frame = super::wrap_eapol_frame(ap, own, pdu);
    frame[1] = 2; // FromDS, not a reflected station transmission.
    frame[16..22].copy_from_slice(&ap);
    frame
}

fn event(cmd: u8, seq: u8, status: u8) -> Vec<u8> {
    let mut event = vec![0; 36];
    event[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
    event[24..26].copy_from_slice(&12u16.to_le_bytes());
    event[28] = if cmd == 0x10 { 4 } else { 1 };
    event[29] = seq;
    event[32] = status;
    event
}
#[derive(Debug)]
struct Model {
    chip_id: u16,
    phy_capability: Option<[u8; 12]>,
    receive_epoch: u64,
    receive_open: bool,
    captured_packets: VecDeque<CapturedData>,
    ticks: Cell<u64>,
    tick_step_ns: u64,
    management_stall_after: Option<usize>,
    ba_error_tag: Option<u16>,
    tx_ba_offer: Option<(u16, u16)>,
    tx_ba_status: u16,
    tx_ba_fault: u8,
    tx_ba_native: bool,
    tx_ba_late_rx: VecDeque<Vec<u8>>,
    data_aggregation: Vec<bool>,
    data_ba_disabled: Vec<bool>,
    entropy_fail: bool,
    entropy_calls: usize,
    live: bool,
    owner: Retained<Lease>,
    active: bool,
    frames: Vec<(bool, Vec<u8>)>,
    replies: VecDeque<Vec<u8>>,
    loaded: bool,
    tx_stall: bool,
    completion_budget: Option<usize>,
    completion_status: u8,
    tx_stall_after: Option<usize>,
    management_resume: Option<u64>,
    management_rates: Vec<u16>,
    data_protection: Vec<bool>,
    data_qos: Vec<bool>,
    wmm_reply: Option<Vec<u8>>,
    ht_reply: Option<Vec<u8>>,
    vht_reply: Option<Vec<u8>>,
    stall_edca: bool,
    edca_progress_fault: u8,
    deny_tx_after: Option<usize>,
    tx_policy: Option<Arc<CurrentPolicy>>,
    station_channel: u8,
    rx_stall: bool,
    idle_stall: bool,
    malformed: bool,
    semaphore: u8,
    notifications: usize,
    revoke_on_submit: bool,
    wtbl_stall: bool,
    clc_result: bool,
    packets: VecDeque<Vec<u8>>,
    scan_stall: bool,
    reg_reply_fault: u8,
    resources: Arc<AtomicUsize>,
    psk: [u8; 32],
    anonce: [u8; 32],
    ap_mac: [u8; 6],
    own_mac: [u8; 6],
    access_point: Option<narf_wifi_fixtures::FakeAp>,
    recovery_trace: Vec<(&'static str, u64)>,
    reset_asserted_at: Option<u64>,
    reset_stall: bool,
    link_stall: bool,
    pm: PowerModel,
    data_tids: Vec<u8>,
    hw_amsdu: bool,
    data_amsdu: Vec<bool>,
}
/// Low-power state of the model device, for system suspend/resume.
#[derive(Debug, Default)]
struct PowerModel {
    trace: Vec<&'static str>,
    dma_enabled: bool,
    firmware_owned: bool,
    lose_dma: bool,
    lose_firmware: bool,
    firmware_own_stall: bool,
    driver_own_stall: bool,
}
impl Model {
    fn new() -> Self {
        let resources = Arc::new(AtomicUsize::new(1));
        Self {
            chip_id: 0,
            phy_capability: None,
            receive_epoch: 0,
            receive_open: false,
            captured_packets: VecDeque::new(),
            ticks: Cell::new(0),
            tick_step_ns: 1_000_000,
            management_stall_after: None,
            ba_error_tag: None,
            tx_ba_offer: None,
            tx_ba_status: 0,
            tx_ba_fault: 0,
            tx_ba_native: false,
            tx_ba_late_rx: VecDeque::new(),
            data_aggregation: Vec::new(),
            data_ba_disabled: Vec::new(),
            entropy_fail: false,
            entropy_calls: 0,
            live: true,
            owner: Retained {
                storage: Some(Lease(resources.clone())),
                published: false,
            },
            active: false,
            frames: Vec::new(),
            replies: VecDeque::new(),
            loaded: false,
            tx_stall: false,
            completion_budget: None,
            completion_status: 0,
            tx_stall_after: None,
            management_resume: None,
            management_rates: Vec::new(),
            data_protection: Vec::new(),
            data_qos: Vec::new(),
            wmm_reply: None,
            ht_reply: None,
            vht_reply: None,
            stall_edca: false,
            edca_progress_fault: 0,
            deny_tx_after: None,
            tx_policy: None,
            station_channel: 6,
            rx_stall: false,
            idle_stall: false,
            malformed: false,
            semaphore: 2,
            notifications: 0,
            revoke_on_submit: false,
            wtbl_stall: false,
            clc_result: false,
            packets: VecDeque::new(),
            scan_stall: false,
            reg_reply_fault: 0,
            resources,
            psk: [0; 32],
            anonce: [0; 32],
            ap_mac: [0; 6],
            own_mac: [0; 6],
            access_point: None,
            recovery_trace: Vec::new(),
            reset_asserted_at: None,
            reset_stall: false,
            link_stall: false,
            pm: PowerModel::default(),
            data_tids: Vec::new(),
            hw_amsdu: false,
            data_amsdu: Vec::new(),
        }
    }
}
#[derive(Debug)]
struct Lease(Arc<AtomicUsize>);

struct CurrentPolicy {
    database: narf_wireless::reg::db::Database,
    hold_bss_ack: AtomicBool,
}
impl core::fmt::Debug for CurrentPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CurrentPolicy")
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.store(0, Ordering::SeqCst);
    }
}
impl Backend for Model {
    fn chip_id(&self) -> Result<u16, Error> {
        Ok(self.chip_id)
    }
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.entropy_calls += 1;
        // Explicit deterministic model boundary, never a native fallback.
        out.fill(0x73);
        if self.entropy_fail {
            Err(Error::EntropyUnavailable)
        } else {
            Ok(())
        }
    }
    fn now_ns(&self) -> u64 {
        let now = self.ticks.get();
        self.ticks.set(now + self.tick_step_ns);
        now
    }
    fn check(&self) -> Result<(), Error> {
        if self.live {
            Ok(())
        } else {
            Err(Error::Authority)
        }
    }
    fn check_tx_permission(
        &self,
        permission: crate::mt7921::association::TxPermission,
    ) -> Result<(), Error> {
        self.check()?;
        if let Some(policy) = &self.tx_policy {
            current_station_permission(permission, policy.database.snapshot())?;
        }
        if self
            .deny_tx_after
            .is_some_and(|limit| self.frames.len() >= limit)
        {
            Err(Error::Authority)
        } else {
            Ok(())
        }
    }
    fn quiesce(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn idle(&mut self) -> Result<bool, Error> {
        Ok(!self.idle_stall)
    }
    fn initialize(&mut self) -> Result<(), Error> {
        self.recovery_trace.push(("initialize", self.ticks.get()));
        self.owner.published = true;
        Ok(())
    }
    fn request_driver_own(&mut self) -> Result<(), Error> {
        if !self.pm.driver_own_stall {
            self.pm.firmware_owned = false;
        }
        Ok(())
    }
    fn driver_owned(&mut self) -> Result<bool, Error> {
        Ok(!self.pm.firmware_owned)
    }
    fn fw_state(&mut self) -> Result<u32, Error> {
        Ok(if self.loaded { 3 } else { 1 })
    }
    fn submit(&mut self, scatter: bool, frame: &[u8]) -> Result<(), Error> {
        if self.active {
            return Err(Error::Busy);
        }
        self.active = true;
        self.frames.push((scatter, frame.to_vec()));
        if !scatter {
            let cmd = frame[36];
            if cmd == 2 {
                self.loaded = true;
            }
            if cmd != 4 {
                for _ in 0..self.notifications {
                    self.replies.push_back(event(1, 0, 0));
                }
                self.notifications = 0;
                let status = if cmd == 0x10 {
                    if frame[64] == 1 {
                        self.semaphore
                    } else {
                        3
                    }
                } else {
                    0
                };
                let mut reply = event(cmd, frame[39], status);
                if frame[43] == 7 {
                    let mut result = [0u8; 8];
                    result[0] = frame[34];
                    if frame[34..36] == [3, 0]
                        && self.ba_error_tag.is_some_and(|tag| {
                            let mut rest = &frame[56..];
                            while let Some(header) = rest.get(..4) {
                                let length =
                                    usize::from(u16::from_le_bytes([header[2], header[3]]));
                                if length < 4 || length > rest.len() {
                                    return false;
                                }
                                if header[..2] == tag.to_le_bytes() {
                                    return true;
                                }
                                rest = &rest[length..];
                            }
                            false
                        })
                    {
                        result[4..8].copy_from_slice(&1u32.to_le_bytes());
                    }
                    if frame[34..36] == [3, 0]
                        && frame
                            .get(56..64)
                            .is_some_and(|b| b[..6] == [6, 0, 12, 0, 0, 1])
                        && result[4..] == [0; 4]
                    {
                        self.tx_ba_native = frame[63] == 1;
                        if self.tx_ba_native {
                            self.packets.append(&mut self.tx_ba_late_rx);
                        }
                    }
                    reply = runtime_event(1, frame[39], 0, &result);
                } else if cmd == 3 {
                    let mut done = [0u8; 8];
                    done[0] = frame[64];
                    reply = runtime_event(0x0d, 0, 0, &done);
                } else if cmd == 0x8a {
                    let mut caps = capabilities();
                    if let Some(phy) = self.phy_capability {
                        caps[26..38].copy_from_slice(&phy);
                    }
                    if self.clc_result {
                        caps[55] |= 1;
                    }
                    reply = runtime_event(0x8a, frame[39], 0, &caps);
                } else if cmd == 0xc0 {
                    let mut reg = [0; 8];
                    reg[..4].copy_from_slice(&frame[64..68]);
                    reg[4..].copy_from_slice(&0x01020304u32.to_le_bytes());
                    reply = runtime_event(5, frame[39], 0, &reg);
                    match self.reg_reply_fault {
                        1 => reply[36] ^= 1,
                        2 => reply[28] = 6,
                        3 => {
                            reply.pop();
                            reply[24..26].copy_from_slice(&19u16.to_le_bytes());
                        }
                        _ => {}
                    }
                } else if cmd == 0xed && frame[41] == 1 {
                    let mut block = [0u8; 24];
                    block[..4].copy_from_slice(&frame[64..68]);
                    block[4] = 1;
                    block[19] = 1; // hardware type at 0x55b
                    reply = runtime_event(0xed, frame[39], 1, &block);
                } else if cmd == 0xed {
                    reply = runtime_event(0xed, frame[39], 0, &[]);
                } else if cmd == 0x5c {
                    let mut info = [0u8; 72];
                    info[6] = 68;
                    info[8] = 0x12;
                    reply = runtime_event(0x80, frame[39], 0, &info);
                }
                if self.malformed {
                    reply.truncate(10);
                }
                if !(cmd == 0x5c && frame[71] == 0
                    || cmd == 0x0f
                    || cmd == 0xca
                    || cmd == 0x5d
                    || cmd == 0x1b
                    || cmd == 0x1d
                    || cmd == 0xb0
                    || cmd == 3 && self.scan_stall)
                {
                    self.replies.push_back(reply);
                }
            }
        }
        if self
            .tx_stall_after
            .is_some_and(|limit| self.frames.len() >= limit)
        {
            self.tx_stall = true;
        }
        if self.stall_edca && frame.get(36) == Some(&0x1d) {
            self.tx_stall = true;
        }
        if self.edca_progress_fault != 0 && frame.get(36) == Some(&0x1d) {
            self.reg_reply_fault = self.edca_progress_fault;
        }
        if self.revoke_on_submit {
            self.live = false;
        }
        Ok(())
    }
    fn tx_complete(&mut self, _: bool) -> Result<bool, Error> {
        if self.tx_stall {
            Ok(false)
        } else {
            self.active = false;
            Ok(true)
        }
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let held = self.tx_policy.as_ref().is_some_and(|policy| {
            policy.hold_bss_ack.load(Ordering::SeqCst)
                && self.frames.last().is_some_and(|(_, frame)| {
                    frame.len() == 92 && frame[34..36] == [2, 0] && frame[43] == 7 && frame[88] == 1
                })
        });
        if self.rx_stall || held {
            Ok(None)
        } else {
            Ok(self.replies.pop_front())
        }
    }
    fn receive_data(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .captured_packets
            .pop_front()
            .map(|packet| packet.bytes)
            .or_else(|| self.packets.pop_front()))
    }
    fn receive_data_captured(&mut self) -> Result<Option<CapturedData>, Error> {
        if let Some(packet) = self.captured_packets.pop_front() {
            return Ok(Some(packet));
        }
        Ok(self.packets.pop_front().map(|bytes| CapturedData {
            bytes,
            epoch: self.receive_epoch,
            port_open: self.receive_open,
        }))
    }
    fn close_receive_capture(&mut self, epoch: u64) {
        self.receive_epoch = epoch;
        self.receive_open = false;
    }
    fn open_receive_capture(&mut self, epoch: u64) -> Result<(), Error> {
        self.check()?;
        if epoch == 0 || epoch != self.receive_epoch {
            return Err(Error::Busy);
        }
        self.receive_open = true;
        Ok(())
    }
    fn release(&mut self) -> Result<(), Error> {
        self.recovery_trace.push(("release", self.ticks.get()));
        self.owner.published = false;
        Ok(())
    }
    fn suspend_dma(&mut self) -> Result<(), Error> {
        self.check()?;
        self.pm.trace.push("dma-off");
        self.pm.dma_enabled = false;
        Ok(())
    }
    fn request_firmware_own(&mut self) -> Result<(), Error> {
        self.check()?;
        self.pm.trace.push("fw-own");
        if !self.pm.firmware_own_stall {
            self.pm.firmware_owned = true;
        }
        Ok(())
    }
    fn firmware_owned(&mut self) -> Result<bool, Error> {
        Ok(self.pm.firmware_owned)
    }
    fn restore_bus(&mut self) -> Result<(), Error> {
        self.check()?;
        self.pm.trace.push("bus");
        // The platform transition happened between suspend and this call.
        if self.pm.lose_firmware {
            self.loaded = false;
        }
        Ok(())
    }
    fn dma_needs_reinit(&mut self) -> Result<bool, Error> {
        Ok(self.pm.lose_dma)
    }
    fn reinit_dma(&mut self) -> Result<(), Error> {
        if self.pm.dma_enabled || !self.owner.published {
            return Err(Error::Busy);
        }
        self.pm.trace.push("reinit");
        self.pm.lose_dma = false;
        self.active = false;
        self.replies.clear();
        self.packets.clear();
        self.pm.dma_enabled = true;
        Ok(())
    }
    fn resume_dma(&mut self) -> Result<(), Error> {
        if !self.owner.published {
            return Err(Error::Busy);
        }
        self.pm.trace.push("dma-on");
        self.pm.dma_enabled = true;
        Ok(())
    }
    fn park_bus_master(&mut self) -> Result<(), Error> {
        self.recovery_trace.push(("park", self.ticks.get()));
        self.check()
    }
    fn assert_reset(&mut self) -> Result<(), Error> {
        self.reset_asserted_at = Some(self.ticks.get());
        self.recovery_trace.push(("assert", self.ticks.get()));
        self.check()
    }
    fn request_link_own(&mut self) -> Result<(), Error> {
        self.recovery_trace.push(("wake", self.ticks.get()));
        self.check()
    }
    fn link_owned(&mut self) -> Result<bool, Error> {
        Ok(!self.link_stall)
    }
    fn release_reset(&mut self) -> Result<(), Error> {
        let since = self.reset_asserted_at.ok_or(Error::Register)?;
        if self.ticks.get().saturating_sub(since) < 50_000_000 {
            return Err(Error::Register);
        }
        self.recovery_trace.push(("deassert", self.ticks.get()));
        self.check()
    }
    fn reset_done(&mut self) -> Result<bool, Error> {
        Ok(!self.reset_stall)
    }
    fn recycle(&mut self) -> Result<(), Error> {
        if self.owner.published {
            return Err(Error::Busy);
        }
        self.recovery_trace.push(("recycle", self.ticks.get()));
        self.active = false;
        self.loaded = false;
        self.replies.clear();
        self.packets.clear();
        self.tx_stall = false;
        self.rx_stall = false;
        self.management_resume = None;
        Ok(())
    }
    fn configure_mac(&mut self) -> Result<(), Error> {
        self.check()
    }
    fn clear_wtbl(&mut self, index: u8) -> Result<(), Error> {
        if index >= 20 {
            return Err(Error::Bounds);
        }
        self.check()
    }
    fn wtbl_idle(&mut self) -> Result<bool, Error> {
        Ok(!self.wtbl_stall)
    }
    fn submit_management(
        &mut self,
        frame: &[u8],
        _wcid: u16,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error> {
        self.check()?;
        self.management_rates.push(rate.hardware());
        self.frames.push((false, frame.to_vec()));
        if frame.first() == Some(&0xc0) {
            if let Some(ap) = &self.access_point {
                // The shared AP speaks auth/association/EAPOL through its
                // Authorized phase, not disconnect. This native adapter
                // validates the exact closing frame and retires that fixture
                // peer; it adds no production RX or cleanup acceptance.
                let beacon = ap.beacon();
                // Under PMF the closing deauth is CCMP protected (Protected bit).
                let protected = if ap.pmf() { 0x40 } else { 0 };
                if ap.phase() != narf_wifi_fixtures::ApPhase::Authorized
                    || frame.len() != 26
                    || frame[1..4] != [protected, 0, 0]
                    || frame[4..10] != beacon[10..16]
                    || frame[10..16] != [2, 0x11, 0x22, 0x33, 0x44, 0x55]
                    || frame[16..22] != beacon[10..16]
                    || frame[22..26] != [0, 0, 3, 0]
                {
                    return Err(Error::Bounds);
                }
                self.access_point = None;
                return Ok(());
            }
        }
        if frame.first() == Some(&0xd0) {
            if let Some(ap) = &self.access_point {
                let beacon = ap.beacon();
                let protected = if ap.pmf() { 0x40 } else { 0 };
                // SA Query Response (category 8, action 1) under PMF.
                if ap.pmf()
                    && frame.len() == 28
                    && frame[1..4] == [0x40, 0, 0]
                    && frame[4..10] == beacon[10..16]
                    && frame[16..22] == beacon[10..16]
                    && frame[24..26] == [8, 1]
                {
                    return Ok(());
                }
                if ap.phase() != narf_wifi_fixtures::ApPhase::Authorized
                    || !matches!(frame.len(), 30 | 33)
                    || frame[1..4] != [protected, 0, 0]
                    || frame[4..10] != beacon[10..16]
                    || frame[10..16] != [2, 0x11, 0x22, 0x33, 0x44, 0x55]
                    || frame[16..22] != beacon[10..16]
                {
                    return Err(Error::Bounds);
                }
                if frame.len() == 30 {
                    let parameters = u16::from_le_bytes([frame[26], frame[27]]);
                    if frame[24..26] != [3, 2]
                        || parameters & 0x7ff != 0
                        || parameters >> 12 >= 8
                        || parameters & 0x800 != 0 && parameters >> 12 != 0
                        || frame[28..30] != [39, 0]
                    {
                        return Err(Error::Bounds);
                    }
                } else if frame[24..26] == [3, 0] {
                    if frame[26] == 0 || frame[27..33] != [3, 16, 0, 0, 0, 0] {
                        return Err(Error::Bounds);
                    }
                    if let Some((window, timeout)) = self.tx_ba_offer {
                        let mut reply = vec![0; 33];
                        reply[0] = 0xd0;
                        reply[4..10].copy_from_slice(&frame[10..16]);
                        reply[10..16].copy_from_slice(&frame[4..10]);
                        reply[16..22].copy_from_slice(&frame[16..22]);
                        reply[24..27].copy_from_slice(&[3, 1, frame[26]]);
                        reply[27..29].copy_from_slice(&self.tx_ba_status.to_le_bytes());
                        reply[29..31].copy_from_slice(&(2 | window << 6).to_le_bytes());
                        reply[31..33].copy_from_slice(&timeout.to_le_bytes());
                        match self.tx_ba_fault {
                            1 => reply[26] = reply[26].wrapping_add(1),
                            2 => reply[29] |= 4,
                            3 => reply[29] |= 1,
                            4 => reply[29] &= !2,
                            5 => reply[4] ^= 2,
                            _ => {}
                        }
                        let mut native = descriptor(&reply);
                        native[4] = 1;
                        native[12..16]
                            .copy_from_slice(&(u32::from(self.station_channel) << 8).to_le_bytes());
                        if self.tx_ba_fault == 6 {
                            native[12..16].copy_from_slice(&(11u32 << 8).to_le_bytes());
                        }
                        if self.tx_ba_fault == 7 {
                            native[8..12].copy_from_slice(&0u32.to_le_bytes());
                        }
                        self.packets.push_back(native);
                    }
                } else if frame[24..26] != [3, 1] {
                    return Err(Error::Bounds);
                } else if matches!(frame[27..29], [37, 0] | [38, 0]) {
                    if frame[29] & !0x3e != 0 || frame[30..33] != [0; 3] {
                        return Err(Error::Bounds);
                    }
                } else if frame[27..29] == [0; 2] {
                    let parameters = u16::from_le_bytes([frame[29], frame[30]]);
                    let window = parameters >> 6;
                    let tid = ((parameters >> 2) & 15) as u8;
                    if parameters & 2 == 0
                        || tid >= 8
                        || !(1..=256).contains(&window) // HE peers: IEEE80211_MAX_AMPDU_BUF_HE
                        || !self.frames.iter().any(|(_, f)| {
                            f.len() == 68
                                && f[34..36] == [3, 0]
                                && f[56..60] == [6, 0, 12, 0]
                                && f[60] == tid
                                && f[62] == u8::from(parameters & 1 != 0)
                                && f[63] == 1 << tid
                                && f[66..68] == window.to_le_bytes()
                        })
                    {
                        return Err(Error::Bounds);
                    }
                } else {
                    return Err(Error::Bounds);
                }
                return Ok(()); // Bound firmware adapter, not a new AP/port authority.
            }
        }
        if let Some(ap) = &mut self.access_point {
            let replies = ap.receive(frame).map_err(|_| Error::Bounds)?;
            for mut reply in replies {
                if reply.first() == Some(&0x10) {
                    if let Some(parameters) = &self.wmm_reply {
                        reply.extend_from_slice(parameters);
                    }
                    if let Some(ht) = &self.ht_reply {
                        reply.extend_from_slice(ht);
                    }
                    if let Some(vht) = &self.vht_reply {
                        reply.extend_from_slice(vht);
                    }
                }
                let mut packet = vec![0u8; 32 + reply.len()];
                let len = packet.len();
                packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
                packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
                packet[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
                packet[12..16]
                    .copy_from_slice(&(u32::from(self.station_channel) << 8).to_le_bytes());
                packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
                if self.vht_reply.is_some() {
                    packet[24..28].copy_from_slice(&((1u32 << 24) | 11).to_le_bytes());
                    // actual basic6Mbps OFDM metadata.
                }
                packet[32..].copy_from_slice(&reply);
                self.packets.push_back(packet);
            }
            return Ok(());
        }
        if self.psk != [0u8; 32] {
            if let Some(eapol) = super::extract_eapol(frame) {
                if let Some(m2) = eapol
                    .get(4..)
                    .and_then(|b| narf_wireless::eapol::KeyFrame::decode(b, 16))
                {
                    if m2.has_mic() && !m2.key_ack() && m2.key_nonce != [0u8; 32] {
                        let snonce = m2.key_nonce;
                        struct TestHmac;
                        impl narf_wireless::eapol::HmacPrimitive for TestHmac {
                            fn out_len(&self) -> usize {
                                20
                            }
                            fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
                                narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
                            }
                        }
                        let ptk = narf_wireless::eapol::derive_ptk(
                            &TestHmac,
                            &self.psk,
                            &self.ap_mac,
                            &self.own_mac,
                            &self.anonce,
                            &snonce,
                            16,
                        );
                        let mut m3 = narf_wireless::eapol::KeyFrame::empty(16);
                        m3.descriptor_type = narf_wireless::eapol::KEY_DESCRIPTOR_RSN;
                        m3.key_information = narf_wireless::eapol::KI_KEY_TYPE_PAIRWISE
                            | narf_wireless::eapol::KI_KEY_ACK
                            | narf_wireless::eapol::KI_KEY_MIC
                            | narf_wireless::eapol::KI_INSTALL
                            | narf_wireless::eapol::KI_SECURE
                            | narf_wireless::eapol::KI_ENCRYPTED_KEY_DATA
                            | narf_wireless::eapol::KI_VERSION_HMAC_SHA1_AES;
                        m3.key_length = 16;
                        m3.replay_counter = m2.replay_counter + 1;
                        m3.key_nonce = self.anonce;
                        let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
                        let mut clear = vec![48, rsn.len() as u8];
                        clear.extend_from_slice(&rsn);
                        clear.extend_from_slice(&[221, 22, 0, 0x0f, 0xac, 1, 1, 0]);
                        clear.extend_from_slice(&[0x77; 16]);
                        if clear.len() % 8 != 0 {
                            clear.push(221);
                        }
                        while clear.len() % 8 != 0 {
                            clear.push(0);
                        }
                        m3.key_data = narf_crypto::aes_kw::aes_wrap(
                            ptk.kek.as_slice().try_into().unwrap(),
                            &clear,
                        )
                        .unwrap();
                        let mut m3_bytes = m3.into_eapol();
                        let mic_full = narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.kck, &m3_bytes);
                        m3_bytes[81..97].copy_from_slice(&mic_full[..16]);
                        let m3_frame = ap_eapol_frame(self.own_mac, self.ap_mac, &m3_bytes);
                        let mut m3_packet = vec![0u8; 32 + m3_frame.len()];
                        let len = m3_packet.len();
                        m3_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
                        m3_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
                        m3_packet[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
                        m3_packet[12..16]
                            .copy_from_slice(&(u32::from(self.station_channel) << 8).to_le_bytes());
                        m3_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
                        if self.vht_reply.is_some() {
                            m3_packet[24..28].copy_from_slice(&((1u32 << 24) | 11).to_le_bytes());
                        }
                        m3_packet[32..].copy_from_slice(&m3_frame);
                        self.packets.push_back(m3_packet);
                    }
                }
            }
        }
        Ok(())
    }
    fn submit_fragment(&mut self, frame: &[u8], wcid: u16) -> Result<(), Error> {
        self.check()?;
        crate::mt7921::packet_tx::fragment(frame, 0x1000, 1, wcid)?;
        self.frames.push((false, frame.to_vec()));
        Ok(())
    }
    fn submit_data(&mut self, frame: &[u8], protected: bool, qos: bool) -> Result<(), Error> {
        self.check()?;
        if self.access_point.as_ref().is_some_and(|ap| {
            ap.phase() != narf_wifi_fixtures::ApPhase::Authorized || ap.protected() != protected
        }) {
            return Err(Error::Bounds);
        }
        let header = crate::mt7921::packet_tx::ethernet_qos(frame, 0x1000, 1, 1, protected, qos)?;
        self.data_amsdu.push(qos && self.hw_amsdu);
        self.frames.push((false, frame.to_vec()));
        self.data_protection.push(protected);
        self.data_qos.push(qos);
        self.data_aggregation.push(false);
        self.data_ba_disabled.push(header[15] & 0x10 != 0);
        Ok(())
    }
    fn set_hw_amsdu(&mut self, enabled: bool) {
        self.hw_amsdu = enabled;
    }
    fn submit_data_tid(
        &mut self,
        frame: &[u8],
        protected: bool,
        tid: u8,
        _pipelined: bool,
    ) -> Result<(), Error> {
        if tid == 0 {
            return Err(Error::Bounds);
        }
        self.submit_data(frame, protected, true)?;
        let header = crate::mt7921::packet_tx::ethernet_tid(frame, 0x1000, 1, 1, protected, tid)?;
        self.data_tids.push(tid);
        *self.data_ba_disabled.last_mut().unwrap() = header[15] & 0x10 != 0;
        Ok(())
    }
    fn submit_data_aggregated(&mut self, frame: &[u8], protected: bool) -> Result<(), Error> {
        if !self.tx_ba_native {
            return Err(Error::Bounds);
        }
        self.submit_data(frame, protected, true)?;
        let header = crate::mt7921::packet_tx::ethernet_aggregated(frame, 0x1000, 1, protected)?;
        *self.data_aggregation.last_mut().unwrap() = true;
        *self.data_ba_disabled.last_mut().unwrap() = header[15] & 0x10 != 0;
        Ok(())
    }
    fn receive_idle(&self) -> Result<bool, Error> {
        self.check()?;
        Ok(self.packets.is_empty() && self.captured_packets.is_empty())
    }
    fn management_complete(
        &mut self,
    ) -> Result<Option<crate::mt7921::packet_tx::Completion>, Error> {
        self.check()?;
        if self
            .management_stall_after
            .is_some_and(|after| self.frames.len() >= after)
        {
            return Ok(None);
        }
        if self.tx_stall
            && self
                .management_resume
                .is_none_or(|tick| self.ticks.get() < tick)
        {
            return Ok(None);
        }
        if let Some(budget) = &mut self.completion_budget {
            if *budget == 0 {
                return Ok(None);
            }
            *budget -= 1;
        }
        Ok(Some(crate::mt7921::packet_tx::Completion {
            token: 1,
            status: self.completion_status,
        }))
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..20000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("transport wait was not bounded")
}
fn mcu_firmware_header_matches_linux_and_scatter_is_headerless() -> TestResult {
    let frame = command_frame(0x10, 15, &[1, 0, 0, 0]).unwrap();
    if frame.len() != 68
        || frame[..8] != [68, 0, 0, 0x41, 0, 0, 1, 0x80]
        || frame[32..40] != [36, 0, 0, 0x80, 0x10, 0xa0, 3, 15]
    {
        return TestResult::Fail("MCU TXD differs from Linux connac2 framing");
    }
    let mut session = Session::new(Model::new(), firmware(9000));
    let report = match run(session.run()) {
        Ok(report) => report,
        Err(_) => return TestResult::Fail("firmware boot model failed"),
    };
    let scatter: Vec<_> = session
        .backend
        .frames
        .iter()
        .filter(|frame| frame.0)
        .collect();
    if report.bytes_transferred != 18000
        || scatter.len() != 6
        || scatter
            .iter()
            .any(|(_, frame)| frame.len() > 4096 || !matches!(frame[0], 0x55 | 0xaa))
        || !session.backend.owner.published
        || !matches!(session.state, State::Ready(_))
        || run(session.run()) != Err(Error::Busy)
    {
        return TestResult::Fail("scatter framing, ownership or single-attempt state");
    }
    let commands: Vec<_> = session
        .backend
        .frames
        .iter()
        .filter(|frame| !frame.0)
        .map(|(_, frame)| frame[36])
        .collect();
    if commands != [4, 0x10, 5, 7, 0x10, 1, 2] {
        return TestResult::Fail("firmware command order differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_header_matches_linux_and_scatter_is_headerless
);

fn mcu_firmware_preflight_rejects_truncation_and_metadata_overlap() -> TestResult {
    let fw = firmware(32);
    for length in [0, 31, 92, 95, 96, 159] {
        if Firmware::prepare(&fw.patch[..length], &fw.ram).is_ok() {
            return TestResult::Fail("truncated patch accepted");
        }
    }
    let mut patch = fw.patch.to_vec();
    patch[100..104].copy_from_slice(&100u32.to_be_bytes());
    if Firmware::prepare(&patch, &fw.ram).is_ok() {
        return TestResult::Fail("patch copied its own metadata");
    }
    let mut ram = fw.ram.to_vec();
    ram[32 + 20..32 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    if Firmware::prepare(&fw.patch, &ram).is_ok() {
        return TestResult::Fail("RAM region exceeded payload");
    }
    let mut patch = fw.patch.to_vec();
    patch[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    if Firmware::prepare(&patch, &fw.ram).is_ok() {
        return TestResult::Fail("patch region count overflow");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_preflight_rejects_truncation_and_metadata_overlap
);

fn mcu_firmware_timeouts_and_revocation_preserve_published_memory() -> TestResult {
    for failure in 0..5 {
        let mut model = Model::new();
        let expected = match failure {
            0 => {
                model.tx_stall = true;
                Error::Timeout
            }
            1 => {
                model.rx_stall = true;
                Error::Timeout
            }
            2 => {
                model.malformed = true;
                Error::MalformedEvent
            }
            3 => {
                model.revoke_on_submit = true;
                Error::Authority
            }
            _ => {
                model.semaphore = 0;
                Error::Rejected(0)
            }
        };
        let resources = model.resources.clone();
        let mut session = Session::new(model, firmware(32));
        if run(session.run()) != Err(expected)
            || !matches!(session.state, State::Failed { .. })
            || run(session.run()) != Err(Error::Busy)
        {
            return TestResult::Fail("failed session continued/replayed");
        }
        drop(session);
        if resources.load(Ordering::SeqCst) != 1 {
            return TestResult::Fail("failure released published buffers");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_timeouts_and_revocation_preserve_published_memory
);

fn mcu_firmware_cancelled_future_cannot_replay_or_free_dma() -> TestResult {
    let mut model = Model::new();
    model.tx_stall = true;
    let resources = model.resources.clone();
    let mut session = Session::new(model, firmware(32));
    {
        let mut future = pin!(session.run());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("stalled submission completed");
        }
    }
    if session.state != State::Running(Stage::Restart) || run(session.run()) != Err(Error::Busy) {
        return TestResult::Fail("cancelled firmware sequence replayed");
    }
    drop(session);
    if resources.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("cancellation freed DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_cancelled_future_cannot_replay_or_free_dma
);

fn mcu_firmware_notifications_are_bounded_and_patch_skip_is_explicit() -> TestResult {
    let mut model = Model::new();
    model.notifications = 2;
    model.semaphore = 1;
    let mut session = Session::new(model, firmware(32));
    if !matches!(
        run(session.run()),
        Ok(Report {
            patch_already_loaded: true,
            bytes_transferred: 32,
            ..
        })
    ) || session.events.len() != 2
    {
        return TestResult::Fail("patch skip or notification preservation");
    }
    let mut model = Model::new();
    model.notifications = 33;
    if run(Session::new(model, firmware(32)).run()) != Err(Error::EventOverflow) {
        return TestResult::Fail("unsolicited events exhausted an unbounded queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_notifications_are_bounded_and_patch_skip_is_explicit
);

fn mcu_firmware_shutdown_frees_only_after_verified_idle() -> TestResult {
    for stuck in [false, true] {
        let model = Model::new();
        let resources = model.resources.clone();
        let mut session = Session::new(model, firmware(32));
        if run(session.run()).is_err() {
            return TestResult::Fail("setup boot failed");
        }
        session.backend.idle_stall = stuck;
        if run(session.shutdown()) != if stuck { Err(Error::Timeout) } else { Ok(()) } {
            return TestResult::Fail("shutdown idle result");
        }
        drop(session);
        if resources.load(Ordering::SeqCst) != if stuck { 1 } else { 0 } {
            return TestResult::Fail("shutdown reclaimed DMA before idle");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_shutdown_frees_only_after_verified_idle
);

// Match the installed MT7922 format-2 image layout, including its opaque
// trailer gap and the non-downloadable CLC region; no firmware bytes embedded.
fn mcu_dma_mt7922_image_layout() -> TestResult {
    let mut patch = vec![0u8; 137632];
    patch[44..48].copy_from_slice(&1u32.to_be_bytes());
    for (offset, value) in [
        (96, 0x40002u32),
        (100, 160),
        (104, 137472),
        (108, 0x900000),
        (112, 137472),
        (116, 0x01000000),
    ] {
        patch[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    let mut ram = vec![0u8; 1231252];
    let table = ram.len() - 36 - 6 * 40;
    let lengths = [341904u32, 292816, 15312, 8144, 97168, 475488];
    let addresses = [9547776u32, 33643520, 4211712, 34643968, 3760193536, 0];
    for i in 0..6 {
        let region = table + i * 40;
        ram[region + 16..region + 20].copy_from_slice(&addresses[i].to_le_bytes());
        ram[region + 20..region + 24].copy_from_slice(&lengths[i].to_le_bytes());
        ram[region + 25] = if i == 5 { 2 } else { 0 };
        ram[region + 24] = if i == 0 {
            33
        } else if i == 5 {
            64
        } else {
            1
        };
    }
    // Structural stand-in for the opaque CLC payload, with the real extent.
    ram[755344..755348].copy_from_slice(&475488u32.to_le_bytes());
    ram[755349] = 1;
    let tail = ram.len() - 36;
    ram[tail + 2] = 6;
    ram[tail + 3] = 2;
    let Ok(fw) = Firmware::prepare(&patch, &ram) else {
        return TestResult::Fail("real MT7922 layout rejected");
    };
    if fw.patch_regions.len() != 1
        || fw.patch_regions[0].mode != 0x80000009
        || fw.ram_regions.len() != 5
        || fw.override_addr != 9547776
        || fw.ram_regions.iter().any(|r| r.mode != 0x80000009)
        || fw.ram_regions.last().unwrap().bytes.end != 755344
    {
        return TestResult::Fail("MT7922 encrypted or non-downloadable regions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_dma_mt7922_image_layout
);

fn runtime_event(eid: u8, seq: u8, ext: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 36 + payload.len()];
    let len = bytes.len();
    bytes[..4].copy_from_slice(&((7u32 << 27) | len as u32).to_le_bytes());
    bytes[24..26].copy_from_slice(&((len - 24) as u16).to_le_bytes());
    bytes[28] = eid;
    bytes[29] = seq;
    bytes[32] = ext;
    bytes[36..].copy_from_slice(payload);
    bytes
}
fn capabilities() -> Vec<u8> {
    let mut bytes = vec![4, 0, 0, 0];
    for (kind, value) in [
        (7u32, &[2u8, 0x11, 0x22, 0x33, 0x44, 0x55][..]),
        (8, &[1, 1, 1, 2, 2, 0, 1, 1, 1, 1, 3, 1][..]),
        (0x18, &[1][..]),
        (0x20, &[0x56, 0x34, 0x12, 0, 0, 0, 0, 0][..]),
    ] {
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}
fn mcu_runtime_header_formats_and_status() -> TestResult {
    use super::station::Command;
    let ce = Command::Ce {
        id: 0x8a,
        query: false,
    }
    .encode(15, &[])
    .unwrap();
    let ext = Command::Extended { id: 1, query: true }
        .encode(1, &[0; 24])
        .unwrap();
    let uni = Command::Unified { id: 2 }.encode(2, &[0; 4]).unwrap();
    if ce.len() != 64
        || ce[32..40] != [32, 0, 0, 0x80, 0x8a, 0xa0, 1, 15]
        || ext[36..44] != [0xed, 0xa0, 0, 1, 0, 1, 0, 1]
        || uni.len() != 52
        || uni[32..44] != [20, 0, 2, 0, 0, 0xa0, 0, 2, 0, 0, 0, 7]
    {
        return TestResult::Fail("post-ROM CE/ext/unified wire headers");
    }
    let mut session = Session::new(Model::new(), firmware(32));
    let mut response = [0u8; 8];
    response[0] = 2;
    response[4..8].copy_from_slice(&0x12345678u32.to_le_bytes());
    session
        .backend
        .replies
        .push_back(runtime_event(1, 1, 0, &response));
    if run(session.exchange(Command::Unified { id: 2 }, &[0; 4]))
        != Err(Error::RejectedCommand(0x12345678))
    {
        return TestResult::Fail("unified rejection discarded or truncated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_runtime_header_formats_and_status
);
fn mcu_nic_capability_parser_rejects_incomplete_identity() -> TestResult {
    let bytes = capabilities();
    let info = NicCapabilities::parse(&bytes).unwrap();
    if info.mac != [2, 0x11, 0x22, 0x33, 0x44, 0x55]
        || info.phy.spatial_streams != 2
        || info.phy.bands != 3
        || !info.has_6ghz
        || info.chip_capabilities != 0x123456
    {
        return TestResult::Fail("capabilities were inferred or misdecoded");
    }
    for end in 0..bytes.len() {
        if NicCapabilities::parse(&bytes[..end]).is_ok() {
            return TestResult::Fail("truncated capability table accepted");
        }
    }
    for bad in [0u8, 1, 0xff] {
        let mut invalid = bytes.clone();
        invalid[12] = bad;
        if bad == 0 {
            invalid[12..18].fill(0);
        }
        if NicCapabilities::parse(&invalid).is_ok() {
            return TestResult::Fail("invalid MAC accepted");
        }
    }
    let mut duplicate = bytes.clone();
    duplicate[0] = 5;
    duplicate.extend_from_slice(&bytes[4..18]);
    if NicCapabilities::parse(&duplicate).is_ok() {
        return TestResult::Fail("duplicate identity accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_nic_capability_parser_rejects_incomplete_identity
);
fn mcu_post_firmware_identity_and_calibration_are_real_commands() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.initialize_radio()) != Err(Error::Busy) || !session.backend.frames.is_empty() {
        return TestResult::Fail("radio configuration before firmware-ready");
    }
    if run(session.run()).is_err() {
        return TestResult::Fail("boot failed");
    }
    let before = session.backend.frames.len();
    let info = match run(session.initialize_radio()) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("post-firmware configuration failed"),
    };
    let frames = &session.backend.frames[before..];
    if frames.len() != 4
        || frames[0].1[36] != 0x8a
        || frames[1].1[41] != 1
        || frames[1].1[64..68] != [0x50, 5, 0, 0]
        || frames[2].1[41] != 0x21
        || frames[2].1[64..] != [0, 1, 0, 0]
        || info.hardware_type != 1
        || session.state != State::RadioReady(info)
        || run(session.initialize_radio()) != Err(Error::Busy)
    {
        return TestResult::Fail("real identity/EFUSE sequence or replay guard");
    }
    if run(session.shutdown()).is_err() {
        return TestResult::Fail("shutdown failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_post_firmware_identity_and_calibration_are_real_commands
);
fn mcu_post_firmware_timeout_retains_owner_and_failure_stage() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() {
        return TestResult::Fail("boot failed");
    }
    session.backend.rx_stall = true;
    let resources = session.backend.resources.clone();
    if run(session.initialize_radio()) != Err(Error::Timeout)
        || session.state
            != (State::Failed {
                stage: Stage::NicCapabilities,
                error: Error::Timeout,
            })
        || run(session.initialize_radio()) != Err(Error::Busy)
    {
        return TestResult::Fail("configuration timeout/replay guard");
    }
    drop(session);
    if resources.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("post-firmware failure released DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_post_firmware_timeout_retains_owner_and_failure_stage
);

fn clc_table(index: u8, package: u8, byte: u8) -> Vec<u8> {
    let mut table = vec![0u8; 42];
    table[..4].copy_from_slice(&42u32.to_le_bytes());
    table[4] = index;
    table[5] = 1;
    table[6] = 1;
    table[7] = package;
    table[16..20].copy_from_slice(b"00AB");
    table[20..22].copy_from_slice(&20u16.to_le_bytes());
    table[22..].fill(byte);
    table
}
fn mcu_clc_world_limits_select_package_and_validate_before_dispatch() -> TestResult {
    let mut fw = firmware(32);
    let mut tables = clc_table(0, 0, 0xaa);
    tables.extend_from_slice(&clc_table(0, 1, 0xbb));
    tables.extend_from_slice(&clc_table(3, 0, 0xcc));
    fw.ram = tables.clone().into();
    fw.clc_regions.clear();
    fw.clc_regions.push(0..tables.len());
    let commands = match fw.world_limits(1, true) {
        Ok(commands) => commands,
        Err(_) => return TestResult::Fail("valid CLC world table rejected"),
    };
    if commands.len() != 2
        || commands[0][..14] != [1, 0, 96, 0, 0, 1, 0, 1, b'0', b'0', b'A', b'B', 0, 0]
        || commands[0][76..] != [0xbb; 20]
        || commands[1][4] != 3
        || commands[1][76..] != [0xcc; 20]
    {
        return TestResult::Fail("CLC package/country/payload/header mismatch");
    }
    for length in [0u32, 15, 1000000] {
        let mut bad = tables.clone();
        bad[..4].copy_from_slice(&length.to_le_bytes());
        if station::validate_clc_tables(&bad).is_ok() {
            return TestResult::Fail("invalid CLC table length accepted");
        }
    }
    let mut missing = clc_table(0, 0, 0);
    missing[16..18].copy_from_slice(b"US");
    fw.ram = missing.clone().into();
    fw.clc_regions.clear();
    fw.clc_regions.push(0..missing.len());
    if fw.world_limits(0, false) != Err(Error::UnsupportedFirmware) {
        return TestResult::Fail("missing world rules silently bypassed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_clc_world_limits_select_package_and_validate_before_dispatch
);

fn mcu_station_cancel_and_wtbl_timeout_are_terminal() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() {
        return TestResult::Fail("firmware boot");
    }
    session.backend.rx_stall = true;
    {
        let mut future = pin!(session.initialize_radio());
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("expected identity RX wait");
        }
    }
    if session.state != State::Running(Stage::NicCapabilities)
        || run(session.initialize_radio()) != Err(Error::Busy)
        || !session.backend.owner.published
    {
        return TestResult::Fail("cancelled initialization was replayed or freed");
    }
    let mut stalled = Session::new(Model::new(), firmware(32));
    if run(stalled.run()).is_err() {
        return TestResult::Fail("firmware boot");
    }
    stalled.backend.wtbl_stall = true;
    if run(stalled.initialize_radio()) != Err(Error::Timeout)
        || stalled.state
            != (State::Failed {
                stage: Stage::MacInitialize,
                error: Error::Timeout,
            })
    {
        return TestResult::Fail("WTBL wait was unbounded or lost stage");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_station_cancel_and_wtbl_timeout_are_terminal
);

fn mcu_clc_commands_reach_dma_and_consume_capability_requested_result() -> TestResult {
    for responses in [false, true] {
        let mut fw = firmware(32);
        let mut table = clc_table(0, 1, 0xbb);
        table.extend_from_slice(&clc_table(3, 0, 0xcc));
        fw.ram = table.clone().into();
        fw.clc_regions.push(0..table.len());
        let mut model = Model::new();
        model.clc_result = responses;
        let mut session = Session::new(model, fw);
        if run(session.run()).is_err() {
            return TestResult::Fail("boot");
        }
        let info = match run(session.initialize_radio()) {
            Ok(info) => info,
            Err(_) => return TestResult::Fail("CLC init sequence"),
        };
        if info.world_limit_commands != 2
            || info.channel_configuration != if responses { Some(0x12) } else { None }
        {
            return TestResult::Fail("CLC result expectations differ from NIC capability");
        }
        let commands: Vec<_> = session
            .backend
            .frames
            .iter()
            .filter(|(scatter, f)| !scatter && f[36] == 0x5c)
            .collect();
        if commands.len() != 2
            || commands[0].1[64 + 76..] != [0xbb; 20]
            || commands[1].1[64 + 4] != 3
            || commands[0].1[71] != u8::from(responses)
        {
            return TestResult::Fail("CLC country table never reached real command submission");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_clc_commands_reach_dma_and_consume_capability_requested_result
);

fn scan_beacon(channel: u8, ssid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 32 + 36 + 2 + ssid.len() + 3];
    let len = packet.len();
    packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    let frame = &mut packet[32..];
    frame[0] = 0x80;
    frame[10..16].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[16..22].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame[34..36].copy_from_slice(&0x11u16.to_le_bytes());
    frame[37] = ssid.len() as u8;
    frame[38..38 + ssid.len()].copy_from_slice(ssid);
    frame[38 + ssid.len()..].copy_from_slice(&[3, 1, channel]);
    packet
}
fn mcu_passive_scan_wire_layout_and_beacon_validation() -> TestResult {
    let body = scan::scan_request(127, &[1, 6, 11]).unwrap();
    if body.len() != 1186
        || body[..8] != [127, 0, 0, 1, 0, 0, 32, 1]
        || body[158..166] != [4, 3, 1, 1, 1, 6, 1, 11]
        || body[1110..1116] != [255; 6]
        || body[224..1110].iter().any(|b| *b != 0)
    {
        return TestResult::Fail("passive CONNAC2 scan wire layout");
    }
    for channels in [&[][..], &[0], &[12], &[1, 1]] {
        if scan::scan_request(1, channels).is_ok() {
            return TestResult::Fail("invalid or non-world channels accepted");
        }
    }
    let packet = scan_beacon(6, b"narf-test");
    let Some(bss) = scan::beacon(&packet, 2) else {
        return TestResult::Fail("valid beacon");
    };
    if bss.ssid != b"narf-test"
        || bss.signal_dbm != Some(-50)
        || bss.channel != 6
        || bss.beacon_interval != 100
    {
        return TestResult::Fail("RX group/IE/signal parse");
    }
    let mut forwarded = packet.clone();
    let length = forwarded.len() as u32;
    forwarded[..4].copy_from_slice(&((7u32 << 27) | (1 << 16) | length).to_le_bytes());
    if scan::beacon(&forwarded, 2).is_none() {
        return TestResult::Fail("firmware-forwarded normal beacon rejected");
    }
    for end in 0..packet.len() {
        if scan::beacon(&packet[..end], 2).is_some() {
            return TestResult::Fail("truncated beacon accepted");
        }
    }
    for (offset, mask) in [(7, 8u8), (9, 32), (10, 128), (11, 1)] {
        let mut bad = packet.clone();
        bad[offset] |= mask;
        if scan::beacon(&bad, 2).is_some() {
            return TestResult::Fail("FCS/translated/AMSDU/length error accepted");
        }
    }
    let mut bad = packet.clone();
    *bad.last_mut().unwrap() = 11;
    if scan::beacon(&bad, 2).is_some() {
        return TestResult::Fail("DS/RX channel mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_passive_scan_wire_layout_and_beacon_validation
);
fn mcu_passive_scan_dispatches_real_setup_and_deduplicates_bss() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    session.backend.packets.push_back(scan_beacon(6, &[]));
    session
        .backend
        .packets
        .push_back(scan_beacon(6, b"narf-test"));
    session
        .backend
        .packets
        .push_back(scan_beacon(11, b"off-channel"));
    session.backend.packets.push_back(vec![0; 8]);
    let before = session.backend.frames.len();
    let report = match run(session.scan_passive(&[1, 6])) {
        Ok(report) => report,
        Err(_) => return TestResult::Fail("hardware scan model failed"),
    };
    if report.bss.len() != 1
        || report.bss[0].ssid != b"narf-test"
        || report.received != 4
        || report.ignored != 1
        || report.truncated
        || !matches!(session.state, State::ScanReady(_))
    {
        return TestResult::Fail("scan observations/deduplication/state");
    }
    let frames = &session.backend.frames[before..];
    if frames.len() != 6
        || frames[0].1[34] != 1
        || frames[1].1[34] != 2
        || frames[2].1[36] != 0x0f
        || frames[3].1[41] != 0x46
        || frames[4].1[41] != 0x4e
        || frames[5].1[36] != 3
        || frames[5].1[66] != 0
        || frames[5].1[69] != 0
    {
        return TestResult::Fail("VIF/domain/MAC/RX/passive scan sequence");
    }
    for channel in frames[2].1[76..].chunks_exact(8) {
        if channel[4..8] != [2, 0, 0, 0] {
            return TestResult::Fail("channel domain allows active radiation");
        }
    }
    let before = session.backend.frames.len();
    if run(session.scan_passive(&[6])).is_err() || session.backend.frames.len() != before + 1 {
        return TestResult::Fail("repeat scan rebuilt VIF or reused stale completion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_passive_scan_dispatches_real_setup_and_deduplicates_bss
);
fn mcu_passive_scan_timeout_cancel_and_stale_completion_retain_dma() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    session.backend.scan_stall = true;
    let before = session.backend.frames.len();
    if !matches!(run(session.scan_passive(&[12])), Err(Error::Bounds))
        || session.backend.frames.len() != before
    {
        return TestResult::Fail("invalid scan published commands");
    }
    let mut done = [0u8; 8];
    done[0] = 127;
    session
        .backend
        .replies
        .push_back(runtime_event(0x0d, 0, 0, &done));
    if !matches!(run(session.scan_passive(&[1])), Err(Error::Timeout))
        || session.state
            != (State::Failed {
                stage: Stage::ScanWait,
                error: Error::Timeout,
            })
        || !session.backend.owner.published
    {
        return TestResult::Fail("stale completion accepted or timeout freed owner");
    }
    let mut cancelled = Session::new(Model::new(), firmware(32));
    if run(cancelled.run()).is_err() || run(cancelled.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    cancelled.backend.scan_stall = true;
    {
        let mut future = pin!(cancelled.scan_passive(&[1]));
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("scan should wait");
        }
    }
    if !matches!(run(cancelled.scan_passive(&[1])), Err(Error::Busy))
        || !cancelled.backend.owner.published
    {
        return TestResult::Fail("cancelled scan replayed or freed DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_passive_scan_timeout_cancel_and_stale_completion_retain_dma
);

fn mcu_live_join_open_dispatches_auth_assoc_and_sta_record() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ap = [2, 1, 2, 3, 4, 5];
    let bss = ScanBss {
        bssid: ap,
        ssid: b"narf-join".to_vec(),
        channel: 6,
        band: None,
        signal_dbm: Some(-45),
        capability: 1, // ESS, open
        beacon_interval: 100,
        information_elements: vec![
            0, 9, b'n', b'a', b'r', b'f', b'-', b'j', b'o', b'i', b'n', 1, 8, 0x82, 0x84, 0x8b,
            0x96, 12, 24, 48, 108, 3, 1, 6,
        ],
    };
    // Packet 1: unrelated beacon
    session
        .backend
        .packets
        .push_back(scan_beacon(6, b"other-bss"));

    // Packet 2: Authentication response (subtype 0xb0) from AP to own MAC
    let mut auth_resp = vec![0u8; 30];
    auth_resp[0] = 0xb0;
    auth_resp[4..10].copy_from_slice(&own);
    auth_resp[10..16].copy_from_slice(&ap);
    auth_resp[16..22].copy_from_slice(&ap);
    auth_resp[24..30].copy_from_slice(&[0, 0, 2, 0, 0, 0]); // Alg 0, Seq 2, Status 0
    let mut auth_packet = vec![0u8; 32 + auth_resp.len()];
    let len = auth_packet.len();
    auth_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    auth_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    auth_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    auth_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    auth_packet[32..].copy_from_slice(&auth_resp);
    session.backend.packets.push_back(auth_packet);

    // Packet 3: Association response (subtype 0x10) from AP to own MAC with AID 42
    let mut assoc_resp = vec![0u8; 30];
    assoc_resp[0] = 0x10;
    assoc_resp[4..10].copy_from_slice(&own);
    assoc_resp[10..16].copy_from_slice(&ap);
    assoc_resp[16..22].copy_from_slice(&ap);
    assoc_resp[24..26].copy_from_slice(&1u16.to_le_bytes()); // Capability: ESS
    assoc_resp[26..28].copy_from_slice(&0u16.to_le_bytes()); // Status: 0
    assoc_resp[28..30].copy_from_slice(&(42u16 | 0xc000).to_le_bytes()); // AID 42
    assoc_resp.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8b, 0x96]);
    let mut assoc_packet = vec![0u8; 32 + assoc_resp.len()];
    let len = assoc_packet.len();
    assoc_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    assoc_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    assoc_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    assoc_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    assoc_packet[32..].copy_from_slice(&assoc_resp);
    session.backend.packets.push_back(assoc_packet);

    let before = session.backend.frames.len();
    let res = run(session.associate_station(
        &bss,
        b"narf-join",
        crate::mt7921::association::Security::Open,
        test_permission(),
        &[],
    ));
    if res != Ok(42) {
        return TestResult::Fail("associate_station failed");
    }
    match session.state {
        State::Associated {
            peer, channel, aid, ..
        } => {
            if peer != ap || channel != 6 || aid != 42 {
                return TestResult::Fail("associated state mismatch");
            }
        }
        _ => return TestResult::Fail("session state not Associated"),
    }
    let frames = &session.backend.frames[before..];
    let ch_switch = frames.iter().find(|(scatter, f)| {
        !scatter
            && f.len() >= 42
            && f[36] == 0xed
            && f[41] == crate::mt7921::regs::MCU_EXT_CMD_CHANNEL_SWITCH
    });
    if ch_switch.is_none() {
        return TestResult::Fail("channel switch command not emitted");
    }
    // Actual unified command payload starts at48. The Open associated
    // peer has CONN_STATE_PORT_SECURE=2 and AID42, unlike initial setup.
    let sta_rec = frames.iter().find(|(scatter, f)| {
        !scatter
            && f.len() >= 168
            && f[34..36] == [3, 0]
            && f[43] == 7
            && f[64] == 2
            && f[66..68] == [42, 0]
    });
    match sta_rec {
        Some((_, frame)) if frame[80..82] == [15, 0] && frame[92..94] == [15, 0] => {}
        _ => return TestResult::Fail("native STA_REC retained optional rates removed by response"),
    }

    if run(session.disassociate_station()).is_err() {
        return TestResult::Fail("disassociate_station failed");
    }
    match session.state {
        State::ScanReady(_) => {}
        _ => return TestResult::Fail("session state not ScanReady after disassociate"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mcu_live_join_open_dispatches_auth_assoc_and_sta_record
);

fn mcu_live_join_peer_rejection_and_timeout() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ap = [2, 1, 2, 3, 4, 5];
    let bss = ScanBss {
        bssid: ap,
        ssid: b"narf-join".to_vec(),
        channel: 6,
        band: None,
        signal_dbm: Some(-45),
        capability: 1,
        beacon_interval: 100,
        information_elements: vec![
            0, 9, b'n', b'a', b'r', b'f', b'-', b'j', b'o', b'i', b'n', 1, 4, 0x82, 0x84, 0x8b,
            0x96, 3, 1, 6,
        ],
    };
    let mut auth_resp = vec![0u8; 30];
    auth_resp[0] = 0xb0;
    auth_resp[4..10].copy_from_slice(&own);
    auth_resp[10..16].copy_from_slice(&ap);
    auth_resp[16..22].copy_from_slice(&ap);
    auth_resp[24..30].copy_from_slice(&[0, 0, 2, 0, 1, 0]); // Status: 1 (rejected)
    let mut auth_packet = vec![0u8; 32 + auth_resp.len()];
    let len = auth_packet.len();
    auth_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    auth_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    auth_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    auth_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    auth_packet[32..].copy_from_slice(&auth_resp);
    session.backend.packets.push_back(auth_packet);

    let res = run(session.associate_station(
        &bss,
        b"narf-join",
        crate::mt7921::association::Security::Open,
        test_permission(),
        &[],
    ));
    if res != Err(Error::MalformedEvent) && !matches!(session.state, State::Failed { .. }) {
        return TestResult::Fail("rejection should fail join");
    }
    if !session.backend.owner.published {
        return TestResult::Fail("DMA should stay published on join failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mcu_live_join_peer_rejection_and_timeout
);

fn live_join_wpa2(channel: u8, ofdm: bool, entropy_failure: bool) -> TestResult {
    let mut model = Model::new();
    let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ap = [2, 1, 2, 3, 4, 5];
    let psk = [0x55u8; 32];
    let anonce = [0xaau8; 32];
    model.entropy_fail = entropy_failure;
    model.psk = psk;
    model.anonce = anonce;
    model.ap_mac = ap;
    model.own_mac = own;
    model.station_channel = channel;

    let mut session = Session::new(model, firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }

    let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
    let mut ies = vec![0, 9, b'n', b'a', b'r', b'f', b'-', b'j', b'o', b'i', b'n'];
    if ofdm {
        ies.extend_from_slice(&[1, 3, 0x8c, 0x98, 0xb0]);
    } else {
        ies.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8b, 0x96]);
    }
    ies.extend_from_slice(&[3, 1, channel, 48, rsn.len() as u8]);
    ies.extend_from_slice(&rsn);
    let bss = ScanBss {
        bssid: ap,
        ssid: b"narf-join".to_vec(),
        channel,
        band: None,
        signal_dbm: Some(-45),
        capability: 1 | 0x10,
        beacon_interval: 100,
        information_elements: ies,
    };

    // Select the actual observed BSS through the production scan parser.
    let mut observed = scan_beacon(channel, b"narf-join");
    observed.truncate(68);
    observed[66..68].copy_from_slice(&bss.capability.to_le_bytes());
    observed.extend_from_slice(&bss.information_elements);
    let length = observed.len();
    observed[..4].copy_from_slice(&((2u32 << 27) | length as u32).to_le_bytes());
    session.backend.packets.push_back(observed);
    let report = match run(session.scan_passive(&[channel])) {
        Ok(report) if report.bss.len() == 1 => report,
        _ => return TestResult::Fail("scan before native WPA2 join"),
    };
    let bss = &report.bss[0];

    // 1. Auth response (status 0)
    let mut auth_resp = vec![0u8; 30];
    auth_resp[0] = 0xb0;
    auth_resp[4..10].copy_from_slice(&own);
    auth_resp[10..16].copy_from_slice(&ap);
    auth_resp[16..22].copy_from_slice(&ap);
    auth_resp[24..30].copy_from_slice(&[0, 0, 2, 0, 0, 0]);
    let mut auth_packet = vec![0u8; 32 + auth_resp.len()];
    let len = auth_packet.len();
    auth_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    auth_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    auth_packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    auth_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    auth_packet[32..].copy_from_slice(&auth_resp);
    session.backend.packets.push_back(auth_packet);

    // 2. Assoc response (status 0, aid 42)
    let mut assoc_resp = vec![0u8; 30];
    assoc_resp[0] = 0x10;
    assoc_resp[4..10].copy_from_slice(&own);
    assoc_resp[10..16].copy_from_slice(&ap);
    assoc_resp[16..22].copy_from_slice(&ap);
    assoc_resp[24..26].copy_from_slice(&0x0031u16.to_le_bytes());
    assoc_resp[26..28].copy_from_slice(&0u16.to_le_bytes());
    assoc_resp[28..30].copy_from_slice(&(42u16 | 0xc000).to_le_bytes());
    assoc_resp.extend_from_slice(if ofdm {
        &[1, 3, 0x8c, 0x98, 0xb0][..]
    } else {
        &[1, 4, 0x82, 0x84, 0x8b, 0x96][..]
    });
    let mut assoc_packet = vec![0u8; 32 + assoc_resp.len()];
    let len = assoc_packet.len();
    assoc_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    assoc_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    assoc_packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    assoc_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    assoc_packet[32..].copy_from_slice(&assoc_resp);
    session.backend.packets.push_back(assoc_packet);

    // 3. EAPOL M1 from AP
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.descriptor_type = narf_wireless::eapol::KEY_DESCRIPTOR_RSN;
    m1.key_information = narf_wireless::eapol::KI_KEY_TYPE_PAIRWISE
        | narf_wireless::eapol::KI_KEY_ACK
        | narf_wireless::eapol::KI_VERSION_HMAC_SHA1_AES;
    m1.key_length = 16;
    m1.replay_counter = 1;
    m1.key_nonce = anonce;
    let m1_pdu = m1.into_eapol();
    let m1_frame = ap_eapol_frame(own, ap, &m1_pdu);
    let mut m1_packet = vec![0u8; 32 + m1_frame.len()];
    let len = m1_packet.len();
    m1_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    m1_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    m1_packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    m1_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    m1_packet[32..].copy_from_slice(&m1_frame);
    session.backend.packets.push_back(m1_packet);

    let before = session.backend.frames.len();
    let res = run(session.associate_station(
        bss,
        b"narf-join",
        crate::mt7921::association::Security::Wpa2Psk { psk },
        test_permission_for(channel),
        &[],
    ));
    if entropy_failure {
        if res != Err(Error::EntropyUnavailable)
            || !matches!(
                session.state,
                State::Failed {
                    stage: Stage::EapolHandshake,
                    error: Error::EntropyUnavailable
                }
            )
            || session.security.is_some()
            || session.backend.entropy_calls != 1
            || session.backend.frames[before..]
                .iter()
                .any(|(_, frame)| join::extract_eapol(frame).is_some())
        {
            return TestResult::Fail("entropy failure sent EAPOL or admitted station/keys");
        }
        return TestResult::Pass;
    }
    if res != Ok(42) {
        return TestResult::Fail("associate_station WPA2 failed");
    }
    match session.state {
        State::Associated {
            peer,
            channel: joined_channel,
            aid,
            ..
        } => {
            if peer != ap || joined_channel != channel || aid != 42 {
                return TestResult::Fail("associated state mismatch");
            }
        }
        _ => return TestResult::Fail("session state not Associated"),
    }

    let frames = &session.backend.frames[before..];
    let eapol_frames: Vec<_> = frames
        .iter()
        .filter_map(|(scatter, f)| {
            if !scatter {
                super::extract_eapol(f)
            } else {
                None
            }
        })
        .collect();
    if eapol_frames.len() < 2 {
        return TestResult::Fail("expected at least M2 and M4 emitted");
    }

    let secure_sta_rec = frames.iter().find(|(scatter, f)| {
        !scatter
            && f.len() >= 48
            && f[34..36] == [3, 0]
            && f[43] == 7
            && f.len() >= 48 + 44
            && f[49] == 1
            && f[f.len() - 44..f.len() - 32] == [17, 0, 44, 0, 0, 1, 0, 0, 5, 36, 0, 16]
    });
    if secure_sta_rec.is_none() {
        return TestResult::Fail("secure STA_REC with native KEY_V2 tag 17 not emitted");
    }

    let ethernet = [
        2, 1, 2, 3, 4, 5, 2, 0x11, 0x22, 0x33, 0x44, 0x55, 8, 0, 1, 2, 3,
    ];
    if run(session.send_ethernet(&ethernet)).is_err()
        || session.backend.data_protection.last() != Some(&true)
    {
        return TestResult::Fail("joined WPA2 transmit was not protected");
    }
    let mut encrypted = ccmp_packet(1, 0, false);
    encrypted[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    session.backend.packets.push_back(encrypted);
    if !matches!(session.receive_ethernet(), Ok(Some(_))) {
        return TestResult::Fail("joined WPA2 receive path");
    }
    let expected_rate = if ofdm { 75 } else { 0 };
    if session.backend.management_rates.len() < 4
        || session
            .backend
            .management_rates
            .iter()
            .any(|rate| *rate != expected_rate)
    {
        return TestResult::Fail("auth/assoc/EAPOL ignored AP basic rate");
    }

    if run(session.disassociate_station()).is_err() {
        return TestResult::Fail("disassociate_station failed");
    }
    match session.state {
        State::ScanReady(_) => {}
        _ => return TestResult::Fail("session state not ScanReady after disassociate"),
    }
    if session.backend.management_rates.last() != Some(&expected_rate) {
        return TestResult::Fail("deauthentication ignored AP basic rate");
    }
    if run(session.recover(own)).is_err()
        || session.security.is_some()
        || !matches!(session.state, State::RadioReady(_))
    {
        return TestResult::Fail("dual-band reset retained association/keys");
    }
    TestResult::Pass
}
fn mcu_live_join_wpa2_psk_dispatches_4way_handshake_and_secure_sta_record() -> TestResult {
    live_join_wpa2(6, false, false)
}
fn mt76_ofdm_only_24ghz_runs_scan_rsna_packets_disconnect_and_reset() -> TestResult {
    live_join_wpa2(6, true, false)
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mt76_ofdm_only_24ghz_runs_scan_rsna_packets_disconnect_and_reset
);
fn mt76_5ghz_runs_scan_rsna_packets_disconnect_and_reset() -> TestResult {
    live_join_wpa2(36, true, false)
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mt76_5ghz_runs_scan_rsna_packets_disconnect_and_reset
);

kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mcu_live_join_wpa2_psk_dispatches_4way_handshake_and_secure_sta_record
);

fn mcu_ethernet_tx_rx_frame_transport() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }

    let State::RadioReady(info) = session.state else {
        return TestResult::Fail("radio state");
    };
    session.station_permission = Some(test_permission());
    session.state = State::Associated {
        info,
        peer: [2, 1, 2, 3, 4, 5],
        channel: 6,
        aid: 42,
    };
    // Test TX:
    let eth = vec![
        2, 1, 2, 3, 4, 5, // DA
        2, 0x11, 0x22, 0x33, 0x44, 0x55, // SA
        0x08, 0x00, // EtherType: IPv4
        1, 2, 3, 4, 5, 6, 7, 8, // payload
    ];
    let before = session.backend.frames.len();
    if run(session.send_ethernet(&eth)).is_err() {
        return TestResult::Fail("send_ethernet failed");
    }
    if session.backend.frames.len() != before + 1 {
        return TestResult::Fail("send_ethernet frame not recorded");
    }
    let last = &session.backend.frames.last().unwrap().1;
    if last != &eth {
        return TestResult::Fail("transmitted payload mismatch");
    }

    // Test RX (CONNAC2 packet containing 802.11 QoS Data with LLC/SNAP):
    let mut dot11 = Vec::new();
    dot11.extend_from_slice(&[0x88, 0x02]); // QoS Data, from-DS
    dot11.extend_from_slice(&[0x00, 0x00]); // duration
    dot11.extend_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]); // Addr1: DA
    dot11.extend_from_slice(&[2, 1, 2, 3, 4, 5]); // Addr2: BSSID
    dot11.extend_from_slice(&[2, 1, 2, 3, 4, 5]); // Addr3: SA
    dot11.extend_from_slice(&[0x00, 0x00]); // seq
    dot11.extend_from_slice(&[0x00, 0x00]); // QoS control
    dot11.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]); // LLC/SNAP IPv4
    dot11.extend_from_slice(&[10, 20, 30, 40]); // payload

    let mut rx_packet = vec![0u8; 32 + dot11.len()];
    let len = rx_packet.len();
    rx_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    rx_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    rx_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    rx_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    rx_packet[32..].copy_from_slice(&dot11);
    session.backend.packets.push_back(rx_packet);

    let received = session
        .backend
        .receive_data()
        .expect("receive_data")
        .expect("packet present");
    let frame = super::rx_frame(&received).expect("rx_frame parse");
    let eth_out = super::to_ethernet(frame).expect("to_ethernet parse");
    if eth_out.len() != 14 + 4
        || eth_out[..6] != [2, 0x11, 0x22, 0x33, 0x44, 0x55]
        || eth_out[6..12] != [2, 1, 2, 3, 4, 5]
        || eth_out[12..14] != [0x08, 0x00]
        || eth_out[14..] != [10, 20, 30, 40]
    {
        return TestResult::Fail("translated Ethernet frame mismatch");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_ethernet_tx_rx_frame_transport
);

fn native_data_packet(qos: bool) -> Vec<u8> {
    let mut frame = vec![0u8; if qos { 26 } else { 24 }];
    frame[..2].copy_from_slice(&[if qos { 0x88 } else { 0x08 }, 0x02]);
    frame[4..10].copy_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame[10..16].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[16..22].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00, 1, 2, 3]);
    let mut packet = vec![0u8; 24];
    packet[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
    packet[..4].copy_from_slice(&((2u32 << 27) | (24 + frame.len()) as u32).to_le_bytes());
    packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    packet.extend_from_slice(&frame);
    packet
}

fn mt76_native_ethernet_conversion_rejects_unsupported_frame_layouts() -> TestResult {
    let packet = native_data_packet(true);
    let frame = &packet[24..];
    let Some(ethernet) = to_ethernet(frame) else {
        return TestResult::Fail("valid native QoS data rejected");
    };
    if ethernet
        != [
            2, 0x11, 0x22, 0x33, 0x44, 0x55, 2, 6, 7, 8, 9, 10, 0x08, 0x00, 1, 2, 3,
        ]
    {
        return TestResult::Fail("native address/SNAP conversion");
    }
    let mut invalid = Vec::new();
    invalid.push(ethernet); // An Ethernet frame is not a native 802.11 packet.
    for (offset, value) in [
        (0, 0x80),  // Beacon.
        (0, 0x48),  // Null data.
        (0, 0x89),  // Nonzero protocol version.
        (1, 0x03),  // Four-address WDS.
        (1, 0x06),  // More fragments.
        (1, 0x42),  // Protected payload without a decrypt/replay path.
        (1, 0x82),  // HT control changes header length.
        (22, 1),    // Nonzero fragment number.
        (24, 0x80), // A-MSDU requires deaggregation.
    ] {
        let mut bad = frame.to_vec();
        bad[offset] = value;
        invalid.push(bad);
    }
    // Header truncation, and a QoS body shorter than an 802.2 LLC header.
    for len in 0..29 {
        invalid.push(frame[..len].to_vec());
    }
    // An LLC body longer than ETH_DATA_LEN cannot be length-framed.
    let mut oversized = frame[..26].to_vec();
    oversized.extend_from_slice(&[0x42, 0x42, 0x03]);
    oversized.resize(26 + 1501, 0);
    invalid.push(oversized);
    for bad in invalid {
        if to_ethernet(&bad).is_some() {
            return TestResult::Fail("unsupported native frame became Ethernet");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_native_ethernet_conversion_rejects_unsupported_frame_layouts
);

/// Linux `ieee80211_data_to_8023_exthdr` / `ieee80211_get_8023_tunnel_proto`:
/// only RFC1042 (minus AARP/IPX) and bridge-tunnel SNAP are translated to an
/// EtherType; every other LLC body is delivered as an 802.3 length frame.
fn mt76_native_rx_delivers_non_rfc1042_llc_as_8023() -> TestResult {
    let packet = native_data_packet(true);
    let header = &packet[24..50];
    let convert = |body: &[u8]| {
        let mut frame = header.to_vec();
        frame.extend_from_slice(body);
        to_ethernet(&frame)
    };
    let addresses = [2, 0x11, 0x22, 0x33, 0x44, 0x55, 2, 6, 7, 8, 9, 10];
    // Bridge-tunnel SNAP strips like RFC1042.
    let Some(tunnel) = convert(&[0xaa, 0xaa, 3, 0, 0, 0xf8, 0x80, 0x9b, 7, 8]) else {
        return TestResult::Fail("bridge-tunnel SNAP rejected");
    };
    if tunnel[..12] != addresses || tunnel[12..] != [0x80, 0x9b, 7, 8] {
        return TestResult::Fail("bridge-tunnel conversion");
    }
    // AARP/IPX under RFC1042, a foreign OUI, plain 802.2 (STP) and an
    // RFC1042 header carrying a length value all keep their LLC header.
    for body in [
        &[0xaa, 0xaa, 3, 0, 0, 0, 0x80, 0xf3, 1, 2][..],
        &[0xaa, 0xaa, 3, 0, 0, 0, 0x81, 0x37, 1][..],
        &[0xaa, 0xaa, 3, 0, 0x0c, 0x07, 0x20, 0x00, 1, 2, 3][..],
        &[0x42, 0x42, 3, 0, 0, 0, 0, 0][..],
        &[0xaa, 0xaa, 3, 0, 0, 0, 0x00, 0x20][..],
        &[0xf0, 0xf0, 3][..],
    ] {
        let Some(eth) = convert(body) else {
            return TestResult::Fail("non-RFC1042 LLC body rejected");
        };
        if eth[..12] != addresses
            || eth[12..14] != (body.len() as u16).to_be_bytes()
            || eth[14..] != *body
        {
            return TestResult::Fail("802.3 length framing");
        }
    }
    // A maximal 1500-byte LLC body is representable; RFC1042 keeps its
    // existing 1500-byte payload bound after the eight-byte strip.
    let mut max = vec![0x42, 0x42, 3];
    max.resize(1500, 0);
    if convert(&max).map(|eth| eth.len()) != Some(1514) {
        return TestResult::Fail("maximal LLC body");
    }
    let mut snap = vec![0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00];
    snap.resize(1508, 0);
    if convert(&snap).map(|eth| eth.len()) != Some(1514) {
        return TestResult::Fail("maximal RFC1042 payload");
    }
    snap.push(0);
    if convert(&snap).is_some() {
        return TestResult::Fail("oversized RFC1042 payload");
    }
    // A length frame can never alias the EAPOL EtherType the station
    // reserves for its controlled port.
    let mut eapol_like = vec![0xaa, 0xaa, 3, 0, 0, 0x01, 0x88, 0x8e];
    eapol_like.extend_from_slice(&[1, 3, 0, 0]);
    match convert(&eapol_like) {
        Some(eth) if eth[12..14] == [0, 12] => {}
        _ => return TestResult::Fail("foreign-OUI EAPOL must stay length-framed"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_native_rx_delivers_non_rfc1042_llc_as_8023
);

fn mt76_receive_discards_bad_descriptors_and_other_station_frames() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    let State::RadioReady(info) = session.state else {
        return TestResult::Fail("radio state");
    };
    let packet = native_data_packet(true);
    session.backend.packets.push_back(packet.clone());
    if session.receive_ethernet() != Err(Error::Busy) || session.backend.packets.len() != 1 {
        return TestResult::Fail("unassociated receive consumed data");
    }
    session.backend.packets.clear();
    session.state = State::Associated {
        info,
        peer: [2, 1, 2, 3, 4, 5],
        channel: 6,
        aid: 42,
    };
    // This isolated decoder fixture explicitly supplies its synthetic native
    // station grant and receive generation; state alone cannot open RX.
    session.station_permission = Some(test_permission());
    session.renew_receive_epoch().unwrap();
    for (offset, value) in [
        (3, 0),       // Invalid RX packet discriminator.
        (7, 0x02),    // Descriptor integrity-error bit.
        (24, 0x80),   // Management frame.
        (25, 0x42),   // Still-protected native payload.
        (24 + 4, 4),  // Unicast to another station.
        (24 + 10, 4), // A different transmitter/AP.
        (24 + 16, 3), // Multicast source address.
    ] {
        let mut bad = packet.clone();
        bad[offset] = value;
        session.backend.packets.push_back(bad);
    }
    session.backend.packets.push_back(packet.clone());
    let expected = to_ethernet(&packet[24..]).unwrap();
    if session.receive_ethernet() != Ok(Some(expected))
        || !session.backend.packets.is_empty()
        || session.receive_ethernet() != Ok(None)
    {
        return TestResult::Fail("rejected hardware/native packets reached Ethernet");
    }
    for _ in 0..17 {
        session.backend.packets.push_back(vec![0; 32]);
    }
    session.backend.packets.push_back(packet);
    if session.receive_ethernet() != Ok(None) || session.backend.packets.len() != 2 {
        return TestResult::Fail("malformed RX burst exceeded bounded work");
    }
    if !matches!(session.receive_ethernet(), Ok(Some(_))) {
        return TestResult::Fail("valid packet stranded behind malformed burst");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_receive_discards_bad_descriptors_and_other_station_frames
);

fn descriptor(frame: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 24];
    packet[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes()); // One MPDU, no BA aggregate.
    packet[..4].copy_from_slice(&((2u32 << 27) | (24 + frame.len()) as u32).to_le_bytes());
    packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    packet.extend_from_slice(frame);
    packet
}

fn mt76_eapol_rx_requires_native_peer_and_declared_pdu() -> TestResult {
    use narf_wireless::eapol::{
        KeyFrame, KI_KEY_ACK, KI_KEY_TYPE_PAIRWISE, KI_VERSION_HMAC_SHA1_AES,
    };
    let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ap = [2, 1, 2, 3, 4, 5];
    let mut key = KeyFrame::empty(16);
    key.key_information = KI_KEY_ACK | KI_KEY_TYPE_PAIRWISE | KI_VERSION_HMAC_SHA1_AES;
    key.key_nonce = [0x55; 32];
    let pdu = key.into_eapol();
    let frame = ap_eapol_frame(own, ap, &pdu);
    let valid = descriptor(&frame);
    if join::peer_eapol(&valid, own, ap, 6) != Some(&pdu[..]) {
        return TestResult::Fail("native authenticator EAPOL rejected");
    }
    let mut padded = valid.clone();
    padded.extend_from_slice(&[0x55; 16]);
    let len = padded.len() as u32;
    padded[..4].copy_from_slice(&((2u32 << 27) | len).to_le_bytes());
    if join::peer_eapol(&padded, own, ap, 6) != Some(&pdu[..]) {
        return TestResult::Fail("EAPOL link padding entered the MIC/length extent");
    }
    for (offset, value) in [
        (3, 0),
        (7, 2),
        (24, 0x80),
        (25, 1),
        (25, 6),
        (25, 0x42),
        (28, 4),
        (34, 4),
        (40, 4),
        (46, 1),
        (54, 8),
        (57, 0),
        (58, 0xff),
    ] {
        let mut bad = valid.clone();
        bad[offset] = value;
        if join::peer_eapol(&bad, own, ap, 6).is_some() {
            return TestResult::Fail("wrong peer/layout/descriptor/length accepted as EAPOL");
        }
    }
    for end in 0..valid.len() {
        if join::peer_eapol(&valid[..end], own, ap, 6).is_some() {
            return TestResult::Fail("truncated EAPOL hardware packet accepted");
        }
    }
    let mut ethernet = vec![0; 14];
    ethernet[..6].copy_from_slice(&own);
    ethernet[6..12].copy_from_slice(&ap);
    ethernet[12..14].copy_from_slice(&[0x88, 0x8e]);
    ethernet.extend_from_slice(&pdu);
    if join::peer_eapol(&ethernet, own, ap, 6).is_some() || extract_eapol(&ethernet).is_some() {
        return TestResult::Fail("Ethernet fallback bypassed native peer validation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mt76_eapol_rx_requires_native_peer_and_declared_pdu
);

fn secure_model() -> Session<Model> {
    use crate::mt7921::association::{JoinPlan, Security};
    let mut session = Session::new(Model::new(), firmware(32));
    run(session.run()).unwrap();
    let info = run(session.initialize_radio()).unwrap();
    let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
    let mut ies = vec![
        0,
        4,
        b'n',
        b'a',
        b'r',
        b'f',
        1,
        4,
        0x82,
        0x84,
        0x8b,
        0x96,
        48,
        rsn.len() as u8,
    ];
    ies.extend_from_slice(&rsn);
    let bss = ScanBss {
        bssid: [2, 1, 2, 3, 4, 5],
        ssid: b"narf".to_vec(),
        channel: 6,
        band: None,
        signal_dbm: Some(-45),
        capability: 0x11,
        beacon_interval: 100,
        information_elements: ies,
    };
    let plan = JoinPlan::prepare(
        &bss,
        info.capabilities.mac,
        b"narf",
        Security::Wpa2Psk { psk: [0x55; 32] },
    )
    .unwrap();
    let mut security =
        join::StationSecurity::new(&bss, &plan, info.capabilities.mac, &[0x55; 32]).unwrap();
    security
        .commit_group(&narf_wireless::eapol::Gtk {
            key_id: 1,
            tx: false,
            key: vec![0x77; 16],
            rsc: 5u64.to_le_bytes(),
        })
        .unwrap();
    security.port_open = true; // This helper explicitly synthesizes an installed test port.
    session.security = Some(security);
    session.station_permission = Some(test_permission());
    session.state = State::Associated {
        info,
        peer: bss.bssid,
        channel: 6,
        aid: 42,
    };
    session.boot_started = None;
    session.renew_receive_epoch().unwrap();
    session
}

fn ccmp_packet(pn: u64, key: u8, multicast: bool) -> Vec<u8> {
    let native = native_data_packet(true);
    let mut frame = native[24..].to_vec();
    frame[1] |= 0x40;
    if multicast {
        frame[4..10].fill(0xff);
    }
    let mut packet = vec![0; 40];
    packet[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
    packet[..4].copy_from_slice(&((2u32 << 27) | (40 + frame.len()) as u32).to_le_bytes());
    packet[4..8]
        .copy_from_slice(&((4u32 << 16) | (1 << 11) | (u32::from(key) << 21)).to_le_bytes());
    packet[24..30].copy_from_slice(&pn.to_le_bytes()[..6]);
    packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    packet.extend_from_slice(&frame);
    packet
}

fn mt76_protected_rx_checks_decrypt_metadata_and_per_key_tid_replay() -> TestResult {
    let mut session = secure_model();
    session.backend.packets.push_back(native_data_packet(true)); // Plaintext IP on a secure link.
    let good = ccmp_packet(1, 0, false);
    for (offset, mask) in [(7, 2), (7, 1), (6, 1), (9, 32), (64, 0x80)] {
        let mut bad = good.clone();
        bad[offset] |= mask;
        session.backend.packets.push_back(bad);
    }
    session.backend.packets.push_back(good.clone());
    if !matches!(session.receive_ethernet(), Ok(Some(_))) {
        return TestResult::Fail("valid decrypted pairwise RX");
    }
    session.backend.packets.push_back(good);
    session.backend.packets.push_back(ccmp_packet(2, 1, false)); // Pairwise wrong key index.
    session.backend.packets.push_back(ccmp_packet(5, 1, true)); // At GTK's install RSC.
    session.backend.packets.push_back(ccmp_packet(7, 2, true)); // Unknown GTK.
    session.backend.packets.push_back(ccmp_packet(6, 1, true));
    if !matches!(session.receive_ethernet(), Ok(Some(_))) || !session.backend.packets.is_empty() {
        return TestResult::Fail("group key, plaintext or packet replay admission");
    }
    let mut malformed = ccmp_packet(100, 0, false);
    // A body shorter than an 802.2 LLC header is not an MSDU: must not
    // advance PN. (Other LLC bodies are now valid 802.3 length frames.)
    malformed.truncate(40 + 26 + 2);
    let length = malformed.len() as u32;
    malformed[..4].copy_from_slice(&((2u32 << 27) | length).to_le_bytes());
    session.backend.packets.push_back(malformed);
    session.backend.packets.push_back(ccmp_packet(2, 0, false));
    if !matches!(session.receive_ethernet(), Ok(Some(_))) {
        return TestResult::Fail("invalid body advanced replay PN");
    }
    let mut tid = ccmp_packet(1, 0, false);
    tid[64] = 1; // Independent QoS TID replay window.
    session.backend.packets.push_back(tid.clone());
    if !matches!(session.receive_ethernet(), Ok(Some(_))) {
        return TestResult::Fail("QoS TID replay window aliased");
    }
    session.backend.packets.push_back(tid);
    if session.receive_ethernet() != Ok(None) {
        return TestResult::Fail("same PN/TID replay accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_protected_rx_checks_decrypt_metadata_and_per_key_tid_replay
);

fn mt76_packet_step_advances_without_executor_and_bounds_stalled_dma() -> TestResult {
    let mut session = secure_model();
    let packet = native_data_packet(false);
    let own = &packet[28..34];
    let mut tx = vec![0; 14];
    tx[..6].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    tx[6..12].copy_from_slice(own);
    tx[12..14].copy_from_slice(&[8, 0]);
    session.backend.tx_stall = true;
    let before = session.backend.frames.len();
    let first = session.step_network(Some(&tx)).unwrap();
    if !first.transmitted || session.backend.frames.len() != before + 1 {
        return TestResult::Fail("packet not published by synchronous step");
    }
    session.backend.packets.push_back(ccmp_packet(1, 0, false));
    let second = session.step_network(Some(&tx)).unwrap();
    if second.transmitted
        || second.received.len() != 1
        || session.backend.frames.len() != before + 1
    {
        return TestResult::Fail("stalled TX reused DMA or prevented RX progress");
    }
    session.backend.tx_stall = false;
    if !session.step_network(Some(&tx)).unwrap().transmitted {
        return TestResult::Fail("synchronous step did not retire completion before new TX");
    }
    session.backend.tx_stall = true;
    session
        .backend
        .ticks
        .set(session.backend.ticks.get() + 4_000_000_000);
    if !matches!(session.step_network(None), Err(Error::Timeout))
        || !matches!(session.state, State::Failed { .. })
        || !session.backend.owner.published
    {
        return TestResult::Fail("stalled data DMA did not fail bounded with ownership retained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_packet_step_advances_without_executor_and_bounds_stalled_dma
);

fn mt76_tx_policy_requires_full_channel_and_keeps_open_tx_unprotected() -> TestResult {
    use crate::mt7921::{association::TxPermission, packet_tx};
    let rule = narf_wireless::reg::RegRule {
        freq_start_mhz: 2402,
        freq_end_mhz: 2472,
        max_bandwidth_mhz: 20,
        max_power_dbm: 17,
        flags: narf_wireless::reg::RegFlags::empty(),
    };
    let mut domain = narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![rule],
    };
    let permit = TxPermission::from_domain(&domain, 6).unwrap();
    let body = permit.rate_limits();
    if body.len() != 206
        || body[..12] != [0, 0, 0, 0, 1, 1, 1, 0, b'U', b'S', 0, 0]
        || body[44] != 6
        || body[45..] != [34; 161]
    {
        return TestResult::Fail("Linux host power ceiling command");
    }
    domain.rules[0].freq_start_mhz = 2437;
    if TxPermission::from_domain(&domain, 6).is_some() {
        return TestResult::Fail("center-only policy permitted partial 20 MHz channel");
    }
    domain.rules[0].freq_start_mhz = 2402;
    domain.rules[0].flags = narf_wireless::reg::RegFlags::DFS;
    if TxPermission::from_domain(&domain, 6).is_some() {
        return TestResult::Fail("DFS transmission without CAC");
    }
    let mut frame = vec![0; 14];
    frame[12..14].copy_from_slice(&[8, 0]);
    let open = packet_tx::ethernet(&frame, 0x1000, 1, 1, false).unwrap();
    let secure = packet_tx::ethernet(&frame, 0x1000, 1, 1, true).unwrap();
    if u32::from_le_bytes(open[12..16].try_into().unwrap()) & 2 != 0
        || u32::from_le_bytes(secure[12..16].try_into().unwrap()) & 2 != 2
    {
        return TestResult::Fail("open TX forced encryption or secure TX omitted protection");
    }
    frame[..6].fill(0xff);
    let broadcast = packet_tx::ethernet(&frame, 0x1000, 1, 1, true).unwrap();
    if u32::from_le_bytes(broadcast[8..12].try_into().unwrap()) & (1 << 10) != 0
        || u32::from_le_bytes(broadcast[12..16].try_into().unwrap()) & 3 != 2
    {
        return TestResult::Fail("Ethernet broadcast bypassed unicast AP ACK/PTK semantics");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mt76_tx_policy_requires_full_channel_and_keeps_open_tx_unprotected
);

fn mt76_retained_key_work_survives_waiter_drop_and_sync_poll_progresses() -> TestResult {
    let mut session = secure_model();
    let State::Associated { info, peer, .. } = session.state else {
        unreachable!()
    };
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    session
        .backend
        .packets
        .push_back(descriptor(&ap_eapol_frame(
            info.capabilities.mac,
            peer,
            &m1.into_eapol(),
        )));
    if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
        return TestResult::Fail("peer EAPOL was not routed to retained key work");
    }
    session.backend.tx_stall = true;
    session.backend.management_resume = Some(session.backend.ticks.get() + 200_000_000);
    let mut work = KeyWork {
        future: Some(alloc::boxed::Box::pin(async move {
            let result = session.service_keys().await;
            (session, result)
        })),
        completed: None,
    };
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut waiter = pin!(poll_fn(|cx| work.poll(cx)));
        if waiter.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("stalled key TX completed before hardware progress");
        }
    } // Cancelling the waiter must leave the driver-owned future alive.
    for _ in 0..1000 {
        if work.poll(&mut cx).is_ready() {
            break;
        }
    }
    let Some((session, result)) = work.completed.take() else {
        return TestResult::Fail("synchronous polling could not advance owned key TX");
    };
    if result.is_err()
        || !matches!(session.state, State::Associated { .. })
        || session.security.is_none()
        || session.keys_pending()
    {
        return TestResult::Fail("cancelled waiter lost RSNA state or transport owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_retained_key_work_survives_waiter_drop_and_sync_poll_progresses
);

fn mt76_peer_disconnect_stops_data_and_teardown_requires_firmware_ack() -> TestResult {
    let mut session = secure_model();
    let State::Associated { info, peer, .. } = session.state else {
        unreachable!()
    };
    let mut deauth = vec![0; 26];
    deauth[0] = 0xc0;
    deauth[4..10].copy_from_slice(&info.capabilities.mac);
    deauth[10..16].copy_from_slice(&peer);
    deauth[16..22].copy_from_slice(&peer);
    deauth[24] = 3;
    let valid = descriptor(&deauth);
    let mut other = valid.clone();
    other[34] = 4;
    session.backend.packets.push_back(other);
    session.backend.packets.push_back(valid);
    if session.receive_ethernet() != Err(Error::DeviceGone)
        || !session.peer_lost
        || !matches!(session.step_network(None), Err(Error::DeviceGone))
    {
        return TestResult::Fail("peer deauthentication did not close the packet path");
    }
    if run(session.disassociate_station()).is_err()
        || !matches!(session.state, State::ScanReady(_))
        || session.peer_lost
        || session.security.is_some()
    {
        return TestResult::Fail("acknowledged peer/key cleanup did not restore scan-ready state");
    }
    let mut session = secure_model();
    session.backend.rx_stall = true;
    if run(session.disassociate_station()) != Err(Error::Timeout)
        || !matches!(session.state, State::Failed { .. })
        || !session.backend.owner.published
    {
        return TestResult::Fail("lost teardown ACK was ignored or released uncertain DMA");
    }
    if run(session.disassociate_station()) != Err(Error::Busy) {
        return TestResult::Fail("failed teardown was reported as clean/replayable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mt76_peer_disconnect_stops_data_and_teardown_requires_firmware_ack
);

fn mt76_native_eapol_txd_sets_data_type_in_both_hardware_fields() -> TestResult {
    let mut native = vec![0u8; 32];
    native[..2].copy_from_slice(&[8, 1]);
    native[4..10].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    native[24..32].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    let txd = crate::mt7921::packet_tx::management(
        &native,
        0x1000,
        1,
        1,
        crate::mt7921::association::LegacyRate::ONE_MBPS,
    )
    .unwrap();
    let word2 = u32::from_le_bytes(txd[8..12].try_into().unwrap());
    let word7 = u32::from_le_bytes(txd[28..32].try_into().unwrap());
    if word2 & 0x30 != 0x20 || word7 & 0x30_0000 != 0x20_0000 {
        return TestResult::Fail("native EAPOL type missing from TXD2 or TXD7");
    }
    native[0] = 0xb0;
    native[1] = 0;
    let txd = crate::mt7921::packet_tx::management(
        &native,
        0x1000,
        1,
        1,
        crate::mt7921::association::LegacyRate::ONE_MBPS,
    )
    .unwrap();
    if u32::from_le_bytes(txd[8..12].try_into().unwrap()) & 0x3f != 11 {
        return TestResult::Fail("management type/subtype changed by EAPOL correction");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mt76_native_eapol_txd_sets_data_type_in_both_hardware_fields
);

fn mt76_reset_recovers_cancelled_dma_then_requires_fresh_station() -> TestResult {
    let mut session = secure_model();
    let State::Associated { info, .. } = session.state else {
        unreachable!()
    };
    session.backend.tx_stall = true;
    {
        let mut request = pin!(session.disassociate_station());
        let mut cx = Context::from_waker(Waker::noop());
        if request.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("stalled deauthentication did not suspend");
        }
    }
    let start = session.backend.recovery_trace.len();
    // These must never survive into the new MCU/RX generation.
    session.events.push_back(vec![0x77; 36]);
    session.backend.replies.push_back(vec![0x66; 36]);
    session.backend.packets.push_back(vec![0x55; 36]);
    let result = run(session.recover(info.capabilities.mac));
    let trace = &session.backend.recovery_trace[start..];
    let labels: Vec<_> = trace.iter().map(|(label, _)| *label).collect();
    if result.is_err()
        || labels
            != [
                "park",
                "wake",
                "assert",
                "deassert",
                "release",
                "recycle",
                "initialize",
            ]
        || trace[3].1.saturating_sub(trace[2].1) < 50_000_000
        || !matches!(session.state, State::RadioReady(_))
        || session.security.is_some()
        || session.station_bss.is_some()
        || !session.data_pending.is_empty()
        || !session.events.is_empty()
        || !session.backend.packets.is_empty()
        || !session.backend.owner.published
        || session.start_ethernet(&[0; 14]) != Err(Error::Busy)
    {
        return TestResult::Fail(
            "reset replayed a port/key or recycled DMA before reset/stop proof",
        );
    }
    if run(session.scan_passive(&[6])).is_err() {
        return TestResult::Fail("recovered radio cannot start a fresh scan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/recovery",
    mt76_reset_recovers_cancelled_dma_then_requires_fresh_station
);

fn mt76_reset_failure_retains_dma_and_never_recycles_descriptors() -> TestResult {
    for stall_stage in 0..3 {
        let mut session = secure_model();
        let State::Associated { info, .. } = session.state else {
            unreachable!()
        };
        let resources = session.backend.resources.clone();
        session.backend.link_stall = stall_stage == 0;
        session.backend.reset_stall = stall_stage == 1;
        session.backend.idle_stall = stall_stage == 2;
        let start = session.backend.recovery_trace.len();
        if run(session.recover(info.capabilities.mac)) != Err(Error::Timeout)
            || !matches!(session.state, State::Failed { .. })
            || !session.backend.owner.published
            || session.backend.recovery_trace[start..]
                .iter()
                .any(|(label, _)| matches!(*label, "recycle" | "initialize"))
            || session.backend.resources.load(Ordering::SeqCst) != 1
        {
            return TestResult::Fail("unproven reset/idle recycled or freed device-owned memory");
        }
        drop(session);
        if resources.load(Ordering::SeqCst) != 1 {
            return TestResult::Fail("failed reset owner released uncertain DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/recovery",
    mt76_reset_failure_retains_dma_and_never_recycles_descriptors
);

fn mt76_owned_reset_survives_cancelled_waiter() -> TestResult {
    let session = secure_model();
    let State::Associated { info, .. } = session.state else {
        unreachable!()
    };
    let mut work = KeyWork {
        future: Some(alloc::boxed::Box::pin(async move {
            let mut session = session;
            let result = session.recover(info.capabilities.mac).await.map(|_| ());
            (session, result)
        })),
        completed: None,
    };
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut waiter = pin!(poll_fn(|cx| work.poll(cx)));
        if waiter.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("reset skipped the mandatory 50ms hold");
        }
    }
    for _ in 0..1000 {
        if work.poll(&mut cx).is_ready() {
            break;
        }
    }
    let Some((session, result)) = work.completed.take() else {
        return TestResult::Fail("owned reset stopped when its waiter was cancelled");
    };
    if result.is_err()
        || !matches!(session.state, State::RadioReady(_))
        || session.security.is_some()
    {
        return TestResult::Fail(
            "retained reset completion lost the owner or reopened the old port",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/recovery",
    mt76_owned_reset_survives_cancelled_waiter
);

fn mt76_reset_rejects_changed_radio_identity() -> TestResult {
    let mut session = secure_model();
    if run(session.recover([0; 6])) != Err(Error::Bounds)
        || !matches!(session.state, State::Associated { .. })
        || session.security.is_none()
    {
        return TestResult::Fail("invalid reset identity mutated a live station");
    }
    if run(session.recover([2, 0, 0, 0, 0, 99])) != Err(Error::InvalidIdentity)
        || !matches!(
            session.state,
            State::Failed {
                error: Error::InvalidIdentity,
                ..
            }
        )
        || session.security.is_some()
    {
        return TestResult::Fail("changed post-reset MAC reused an existing network interface");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/recovery",
    mt76_reset_rejects_changed_radio_identity
);

fn mt76_unregistered_boot_failure_can_recover_before_mac_discovery() -> TestResult {
    let mut model = Model::new();
    model.tx_stall = true;
    let mut session = Session::new(model, firmware(32));
    if run(session.run()) != Err(Error::Timeout) {
        return TestResult::Fail("boot timeout fixture did not fail before radio identity");
    }
    if run(session.recover_unregistered()).is_err()
        || !matches!(session.state, State::RadioReady(_))
        || session.security.is_some()
    {
        return TestResult::Fail(
            "initial boot failure could not establish a fresh unregistered radio",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/recovery",
    mt76_unregistered_boot_failure_can_recover_before_mac_discovery
);

fn mt76_dual_band_scan_encodes_extension_and_rejects_6ghz_aliases() -> TestResult {
    let channels = crate::mt7921::channel::channels(3);
    let body = scan::scan_request(1, &channels).unwrap();
    if channels.len() != 39 || body[159] != 32 || body[826] != 7 || body[1110..1116] != [255; 6] {
        return TestResult::Fail("dual-band scan extension counts/offsets");
    }
    for (i, channel) in channels.iter().enumerate() {
        let offset = if i < 32 {
            160 + 2 * i
        } else {
            830 + 2 * (i - 32)
        };
        if body[offset..offset + 2] != [if *channel <= 11 { 1 } else { 2 }, *channel] {
            return TestResult::Fail("dual-band scan extension contents");
        }
        if scan::beacon(&scan_beacon(*channel, b"narf"), 2).map(|bss| bss.channel) != Some(*channel)
        {
            return TestResult::Fail("supported channel beacon rejected");
        }
    }
    for channel in [6, 36] {
        let mut packet = scan_beacon(channel, b"narf");
        packet[14] |= 1; // RXD3 CH_FREQ bit8: 6 GHz, never a 2.4/5 GHz alias.
        if scan::beacon(&packet, 2).is_some() {
            return TestResult::Fail("6 GHz RX channel truncated to legacy channel");
        }
    }
    let permit = test_permission_for(36);
    let power = permit.rate_limits();
    if !permit.permits(36) || permit.permits(6) || power[4..7] != [1, 2, 1] || power[44] != 36 {
        return TestResult::Fail("5 GHz power permission/band geometry");
    }
    let dfs = narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 5250,
            freq_end_mhz: 5330,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::DFS,
        }],
    };
    if crate::mt7921::association::TxPermission::from_domain(&dfs, 52).is_some() {
        return TestResult::Fail("DFS transmission admitted without CAC/radar runtime");
    }
    let mut session = Session::new(Model::new(), firmware(32));
    run(session.run()).unwrap();
    run(session.initialize_radio()).unwrap();
    let State::RadioReady(mut info) = session.state else {
        return TestResult::Fail("radio init");
    };
    info.capabilities.phy.bands = 1;
    session.state = State::RadioReady(info);
    let before = session.backend.frames.len();
    if !matches!(
        run(session.scan_passive(&[36])),
        Err(Error::InvalidIdentity)
    ) || session.backend.frames.len() != before
    {
        return TestResult::Fail("firmware-unsupported band published scan commands");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mt76_dual_band_scan_encodes_extension_and_rejects_6ghz_aliases
);

fn mt76_native_rx_binds_channel_before_eapol_and_replay() -> TestResult {
    for channel in [6u8, 36] {
        let mut session = secure_model();
        if let State::Associated {
            channel: current, ..
        } = &mut session.state
        {
            *current = channel;
        }
        for frequency in [
            if channel == 6 { 36u16 } else { 6 },
            0x100 | u16::from(channel),
            0,
        ] {
            let mut invalid = ccmp_packet(100, 0, false);
            invalid[12..16].copy_from_slice(&(u32::from(frequency) << 8).to_le_bytes());
            session.backend.packets.push_back(invalid);
        }
        let mut good = ccmp_packet(1, 0, false);
        good[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
        session.backend.packets.push_back(good);
        if !matches!(session.receive_ethernet(), Ok(Some(_))) || !session.backend.packets.is_empty()
        {
            return TestResult::Fail("off-channel RX accepted or consumed current PN");
        }
        let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
        let peer = [2, 1, 2, 3, 4, 5];
        let pdu = narf_wireless::eapol::KeyFrame::empty(16).into_eapol();
        let mut eapol = descriptor(&ap_eapol_frame(own, peer, &pdu));
        eapol[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
        if join::peer_eapol(&eapol, own, peer, channel) != Some(pdu.as_slice())
            || join::peer_eapol(&eapol, own, peer, if channel == 6 { 36 } else { 6 }).is_some()
        {
            return TestResult::Fail("EAPOL channel binding");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_native_rx_binds_channel_before_eapol_and_replay
);

fn mt76_initial_nonce_failure_never_sends_m2_or_opens_port() -> TestResult {
    live_join_wpa2(6, false, true)
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mt76_initial_nonce_failure_never_sends_m2_or_opens_port
);

fn mt76_rekey_nonce_failure_closes_authorization_before_reply() -> TestResult {
    let mut session = secure_model();
    let State::Associated { info, peer, .. } = session.state else {
        unreachable!()
    };
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    session
        .backend
        .packets
        .push_back(descriptor(&ap_eapol_frame(
            info.capabilities.mac,
            peer,
            &m1.into_eapol(),
        )));
    if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
        return TestResult::Fail("rekey M1 was not queued");
    }
    let sent = session.backend.frames.len();
    session.backend.entropy_fail = true;
    if run(session.service_keys()) != Err(Error::EntropyUnavailable)
        || session.backend.frames.len() != sent
        || session.security.is_some()
        || !matches!(
            session.state,
            State::Failed {
                stage: Stage::EapolHandshake,
                error: Error::EntropyUnavailable
            }
        )
        || session.receive_ethernet() != Err(Error::Busy)
    {
        return TestResult::Fail("rekey entropy failure emitted a reply or left port authorized");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mt76_rekey_nonce_failure_closes_authorization_before_reply
);

fn mt76_retry_preflight_until_recovers_or_terminates_on_unretryable() -> TestResult {
    let session = secure_model();
    let State::Associated {
        info: sample_info, ..
    } = session.state
    else {
        unreachable!()
    };

    // Case 1: succeeds after retries while remaining in Absent state
    let attempts = Cell::new(0);
    let waits = Cell::new(0);
    let status_val = Cell::new(BootStatus::Absent);
    let result = narf_scheduler::block_on(retry_preflight_until(
        5,
        || status_val.get(),
        || {
            let n = attempts.get();
            attempts.set(n + 1);
            async move {
                if n < 2 {
                    Err(Error::InvalidFirmware)
                } else {
                    Ok(sample_info)
                }
            }
        },
        || {
            waits.set(waits.get() + 1);
            async {}
        },
    ));
    if result != Ok(sample_info) || attempts.get() != 3 || waits.get() != 2 {
        return TestResult::Fail(
            "retry_preflight_until failed to succeed after transient preflight error",
        );
    }

    // Case 2: stops early when status transitions to unretryable Failed state
    attempts.set(0);
    waits.set(0);
    let result = narf_scheduler::block_on(retry_preflight_until(
        10,
        || {
            if attempts.get() > 1 {
                BootStatus::Retained(State::Failed {
                    stage: Stage::PatchDownload,
                    error: Error::InvalidFirmware,
                })
            } else {
                BootStatus::Absent
            }
        },
        || {
            let n = attempts.get();
            attempts.set(n + 1);
            async move { Err(Error::InvalidFirmware) }
        },
        || {
            waits.set(waits.get() + 1);
            async {}
        },
    ));
    if result != Err(Error::InvalidFirmware) || attempts.get() != 2 || waits.get() != 1 {
        return TestResult::Fail(
            "retry_preflight_until did not terminate early on unretryable status",
        );
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/firmware",
    mt76_retry_preflight_until_recovers_or_terminates_on_unretryable
);

/// Association → carrier → DHCP composition (Wi-Fi program A1,
/// issue #706): the net-stack half of the station fixtures.
#[path = "dhcp_composition_tests.rs"]
mod dhcp_composition;
