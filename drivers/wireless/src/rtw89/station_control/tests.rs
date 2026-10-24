use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
const AP: [u8; 6] = [2, 3, 5, 7, 11, 13];

struct Source {
    secure: bool,
    cut: u8,
    xtal: u8,
    rfe: u8,
}
impl Io for Source {
    fn read8(&mut self, _: u32) -> Result<u8, Error> {
        unreachable!()
    }
    fn read16(&mut self, address: u32) -> Result<u16, Error> {
        assert_eq!(address, 10);
        Ok(32)
    }
    fn read32(&mut self, _: u32) -> Result<u32, Error> {
        unreachable!()
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), Error> {
        unreachable!()
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), Error> {
        unreachable!()
    }
    fn write32(&mut self, _: u32, _: u32) -> Result<(), Error> {
        unreachable!()
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Ok(None)
    }
}
impl crate::rtw89::factory::Source for Source {
    fn profile(&self) -> (ChipId, u8) {
        (ChipId::Rtl8852B, self.cut)
    }
    async fn physical(&mut self, start: u16, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.fill(255);
        if start == 0 {
            assert_eq!(bytes.len(), 1216);
            for (index, (offset, pair)) in [
                (0x400, [2, 4]),
                (0x402, [6, 8]),
                (0x404, [10, 12]),
                (0x2b8, [255, self.xtal]),
                (0x2ca, [self.rfe, b'U']),
                (0x2cc, [b'S', 255]),
            ]
            .into_iter()
            .enumerate()
            {
                let block = offset / 8;
                let cursor = 4 + index * 4;
                bytes[cursor] = (block >> 4) as u8;
                bytes[cursor + 1] = ((block & 15) << 4) as u8 | (15 ^ (1 << ((offset % 8) / 2)));
                bytes[cursor + 2..cursor + 4].copy_from_slice(&pair);
            }
        } else {
            assert_eq!((start, bytes.len()), (0x580, 128));
            bytes[0x69] = 0xaa;
            bytes[0x6a] = 0x1f;
            if self.secure {
                bytes[0x6d] = 0x6e;
            }
        }
        Ok(())
    }
}
pub(in crate::rtw89) fn factory(secure: bool) -> Factory {
    factory_with_profile(1, 0x33, 5, secure)
}
pub(in crate::rtw89) fn factory_with_profile(cut: u8, xtal: u8, rfe: u8, secure: bool) -> Factory {
    let mut factory = Factory::default();
    narf_scheduler::block_on(factory.read(&mut Source {
        secure,
        cut,
        xtal,
        rfe,
    }))
    .unwrap();
    factory
}
#[derive(Clone, Copy)]
enum Reply {
    Success,
    Missing,
    ReceiveOnly,
    Category,
    Class,
    Function,
    Sequence,
    Failure,
}
pub(in crate::rtw89) struct Model {
    bytes: Vec<u8>,
    writes: Vec<(u32, u32)>,
    packets: Vec<Vec<u8>>,
    inside: bool,
    device: Cap<BusDeviceCap, Write>,
    qualification: Cap<narf_firmware::FirmwareBlob, Read>,
    sequence: u16,
    reply: Reply,
    aperture: usize,
    ignore: Option<u32>,
    wait: bool,
    close: Option<Admission>,
    revoke_before: bool,
    consumed: usize,
    clock: u64,
    pause_lag: u64,
    pending_pause: Option<(u64, bool)>,
    hold_pause: bool,
    revoke_on_delay: bool,
    close_on_delay: Option<Admission>,
}
impl Model {
    pub(in crate::rtw89) fn new() -> Self {
        let mut model = Self {
            bytes: vec![0; 0x40020],
            writes: Vec::new(),
            packets: Vec::new(),
            inside: false,
            device: Cap::bootstrap(),
            qualification: Cap::bootstrap(),
            sequence: 0,
            reply: Reply::Success,
            aperture: 0x40020,
            ignore: None,
            wait: false,
            close: None,
            revoke_before: false,
            consumed: 0,
            clock: 0,
            pause_lag: 0,
            pending_pause: None,
            hold_pause: false,
            revoke_on_delay: false,
            close_on_delay: None,
        };
        model.bytes[0x9eb0..0x9eb4].copy_from_slice(&3u32.to_le_bytes());
        model
    }
    pub(in crate::rtw89) fn word(&self, address: usize) -> u32 {
        u32::from_le_bytes(self.bytes[address..address + 4].try_into().unwrap())
    }
    pub(in crate::rtw89) fn packets(&self) -> &[Vec<u8>] {
        &self.packets
    }
    fn access(&self, address: u32, width: usize) -> Result<usize, Error> {
        assert!(
            self.inside,
            "control bypassed whole-operation current authority"
        );
        let address = address as usize;
        if address
            .checked_add(width)
            .is_none_or(|end| end > self.aperture)
        {
            Err(Error::Unsupported)
        } else {
            Ok(address)
        }
    }
    fn firmware_reply(&self, wire: &[u8]) -> Option<Vec<u8>> {
        let w0 = u32::from_le_bytes(wire[..4].try_into().unwrap());
        let mut identity = w0 & 0xffff;
        let mut sequence = w0 >> 24;
        match self.reply {
            Reply::Missing => return None,
            Reply::Category => identity ^= 1,
            Reply::Class => identity ^= 4,
            Reply::Function => identity ^= 256,
            Reply::Sequence => sequence ^= 1,
            _ => {}
        }
        let receive = matches!(self.reply, Reply::ReceiveOnly);
        let mut bytes = vec![0; 12];
        bytes[..4].copy_from_slice(&(if receive { 1u32 } else { 0x101u32 }).to_le_bytes());
        bytes[4..8].copy_from_slice(&12u32.to_le_bytes());
        let result = u32::from(matches!(self.reply, Reply::Failure));
        let word = identity
            | if receive {
                sequence << 16
            } else {
                result << 16 | sequence << 24
            };
        bytes[8..].copy_from_slice(&word.to_le_bytes());
        Some(bytes)
    }
}
struct InDevice<'a, F>(&'a mut Model, F);
struct InQualification<'a, F>(&'a mut Model, F);
impl<F, T> CapOp<BusDeviceCap, Write> for InDevice<'_, F>
where
    F: FnOnce(&mut Model) -> Result<T, Error>,
{
    type Output = Result<T, Error>;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
        let qualification = self.0.qualification;
        qualification.invoke(InQualification(self.0, self.1))
    }
}
impl<F, T> CapOp<narf_firmware::FirmwareBlob, Read> for InQualification<'_, F>
where
    F: FnOnce(&mut Model) -> Result<T, Error>,
{
    type Output = Result<T, Error>;
    fn execute(self, _: &Cap<narf_firmware::FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        assert!(!self.0.inside);
        self.0.inside = true;
        let result = (self.1)(self.0);
        self.0.inside = false;
        Ok(result)
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        let p = self.access(a, 1)?;
        Ok(self.bytes[p])
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        let p = self.access(a, 2)?;
        Ok(u16::from_le_bytes(self.bytes[p..p + 2].try_into().unwrap()))
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        let p = self.access(a, 4)?;
        if let Some((when, paused)) = self.pending_pause {
            if a == 0x9eb0 && self.clock >= when {
                let value = (self.word(p) & !1) | u32::from(paused);
                self.bytes[p..p + 4].copy_from_slice(&value.to_le_bytes());
                self.pending_pause = None;
            }
        }
        Ok(self.word(p))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        let p = self.access(a, 1)?;
        self.bytes[p] = v;
        Ok(())
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        let p = self.access(a, 2)?;
        self.bytes[p..p + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        let p = self.access(a, 4)?;
        self.writes.push((a, v));
        if self.ignore != Some(a) {
            self.bytes[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.clock
    }
    async fn delay_us(&mut self, us: u64) {
        assert!(
            !self.inside,
            "pause wait held current/publication transaction"
        );
        self.clock += us;
        if self.revoke_on_delay {
            self.qualification.revoke();
        }
        if let Some(admission) = self.close_on_delay.take() {
            admission.close();
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Ok(None)
    }
}
#[async_trait::async_trait]
impl Interface for Model {
    fn preflight(&mut self, indirect: bool) -> Result<(), Error> {
        self.access(if indirect { 0x4001c } else { 0xce84 }, 4)
            .map(|_| ())
    }
    fn with_current<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let device = self.device;
        device
            .invoke(InDevice(self, operation))
            .map_err(|_| Error::Access)?
    }
    async fn command(
        &mut self,
        cat: u8,
        class: u8,
        function: u8,
        body: &[u8],
        done: bool,
        admission: Option<&Admission>,
    ) -> Result<(), Error> {
        if let Some(admission) = admission {
            admission.check()?;
        }
        if self.wait {
            core::future::pending::<()>().await;
        }
        if let Some(close) = self.close.take() {
            close.close();
        }
        if self.revoke_before {
            self.qualification.revoke();
        }
        let operation = |model: &mut Self| {
            model.with_current(|model| {
                if model.sequence >= 256 {
                    return Err(Error::Terminal);
                }
                let mut bytes = vec![0; body.len() + 8];
                crate::rtw89::h2c::H2cBuilder::new(cat, class, function)
                    .with_seq(model.sequence as u8)
                    .with_done_ack(done)
                    .with_rec_ack((class == 9 && function == 8) || model.sequence % 4 == 0)
                    .build(body, &mut bytes)
                    .ok_or(Error::Unsupported)?;
                model.sequence += 1;
                model.packets.push(bytes);
                model.consumed += 1; // independent modeled CH12 terminal transport
                if class == 9 && function == 8 && !model.hold_pause {
                    model.pending_pause = Some((model.clock + model.pause_lag, body[0] & 1 != 0));
                }
                Ok(())
            })
        };
        if let Some(admission) = admission {
            admission.run(|| operation(self))?;
        } else {
            operation(self)?;
        }
        if !done {
            return Ok(());
        }
        let wire = self.packets.last().unwrap();
        let Some(response) = self.firmware_reply(wire) else {
            return Err(Error::Timeout);
        };
        let ack = crate::rtw89::rx_packet::C2h::parse(response)
            .unwrap()
            .ack()
            .unwrap()
            .unwrap();
        let word = u32::from_le_bytes(wire[..4].try_into().unwrap());
        if (ack.category, ack.class, ack.function, ack.sequence)
            != (
                (word & 3) as u8,
                ((word >> 2) & 63) as u8,
                (word >> 8) as u8,
                (word >> 24) as u8,
            )
            || ack.result != Some(0)
        {
            return Err(Error::Timeout);
        }
        Ok(())
    }
}
fn smoke_rtw8852b_station_controls_match_linux_and_keep_packet_engines_closed() -> TestResult {
    let factory = factory(false);
    let mut control = Controller::new(&factory).unwrap();
    let admission = Admission::new();
    let mut model = Model::new();
    narf_scheduler::block_on(control.initialize(&mut model, &admission)).unwrap();
    let indirect = model
        .writes
        .iter()
        .copied()
        .filter(|(a, _)| *a == 0xc04 || *a >= 0x40000)
        .collect::<Vec<_>>();
    if indirect != LINUX_TABLE_WRITES
        || model.packets.len() != 10
        || control.phase() != Phase::Passive
    {
        return TestResult::Fail("B source table/role/CAM/CCTL creation order differs");
    }
    for (index, expected) in [
        LINUX_PAUSE[0].as_slice(),
        LINUX_ROLE[0].as_slice(),
        LINUX_JOIN[0].as_slice(),
        LINUX_CAM[0].as_slice(),
        LINUX_PAYLOAD[0].as_slice(),
        LINUX_FIXED[0].as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        if model.packets[index][8..] != *expected {
            return TestResult::Fail("B initial command payload differs from original C");
        }
    }
    for (ac, expected) in LINUX_EDCA[..4].iter().enumerate() {
        if model.packets[6 + ac][8..] != *expected {
            return TestResult::Fail("B non-QoS EDCA differs from source");
        }
    }
    let peer = narf_scheduler::block_on(control.prepare_peer(&mut model, AP, &admission)).unwrap();
    if peer.current().is_err()
        || peer.own() != OWN
        || peer.bssid() != AP
        || peer.mac_id() != 0
        || model.packets[10][8..] != LINUX_CAM[1]
    {
        return TestResult::Fail("B pre-auth peer CAM/binding differs");
    }
    narf_scheduler::block_on(control.commit_peer(&mut model, AP, 42, true, &admission)).unwrap();
    if model.packets[11][8..] != LINUX_FIXED[0]
        || model.packets[12][8..] != LINUX_JOIN[1]
        || model.packets[13][8..] != LINUX_CAM[2]
        || model.word(0xc400) & (3 << 10) != 2 << 10
        || control.phase() != Phase::Associated
    {
        return TestResult::Fail("B associated media/AID/CCTL differs from source");
    }
    for (ac, expected) in LINUX_EDCA[4..].iter().enumerate() {
        if model.packets[14 + ac][8..] != *expected {
            return TestResult::Fail("B negotiated short-slot EDCA differs");
        }
    }
    narf_scheduler::block_on(control.disconnect(&mut model, &admission)).unwrap();
    if peer.current().is_ok()
        || !admission.closed()
        || control.phase() != Phase::Stopped
        || model.packets[18][8..] != LINUX_JOIN[0]
        || model.packets[19][8..] != LINUX_CAM[3]
        || model.packets[20][8..] != LINUX_ROLE[1]
        || model.packets[21][8..] != LINUX_PAUSE[1]
        || model.word(0xc000) & (1 << 29) != 0
        || model
            .writes
            .iter()
            .any(|(a, _)| matches!(a, 0xb0 | 0xb8 | 0x1190 | 0x1000 | 0xc000))
        || model.consumed != model.packets.len()
    {
        return TestResult::Fail("B terminal cleanup reopened peer or a packet engine");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_station_controls_match_linux_and_keep_packet_engines_closed
);

fn smoke_rtw8852b_station_requires_exact_execution_ack_current_authority_and_fresh_owner(
) -> TestResult {
    for reply in [
        Reply::Missing,
        Reply::ReceiveOnly,
        Reply::Category,
        Reply::Class,
        Reply::Function,
        Reply::Sequence,
        Reply::Failure,
    ] {
        let mut control = Controller::new(&factory(false)).unwrap();
        let admission = Admission::new();
        let mut model = Model::new();
        model.reply = reply;
        if narf_scheduler::block_on(control.initialize(&mut model, &admission))
            != Err(Error::Timeout)
            || !admission.closed()
            || control.phase() != Phase::Failed
            || model.packets.len() != 2
            || model.consumed != 2
        {
            return TestResult::Fail(
                "missing/foreign/receive-only/failed ACK fabricated station readiness",
            );
        }
        let count = model.writes.len();
        if narf_scheduler::block_on(control.initialize(&mut model, &Admission::new())).is_ok()
            || model.writes.len() != count
        {
            return TestResult::Fail("failed command owner replayed after uncertain execution");
        }
    }
    for device in [false, true] {
        let mut control = Controller::new(&factory(false)).unwrap();
        let admission = Admission::new();
        let mut model = Model::new();
        if device {
            model.device.revoke();
        } else {
            model.qualification.revoke();
        }
        if narf_scheduler::block_on(control.initialize(&mut model, &admission))
            != Err(Error::Access)
            || !model.writes.is_empty()
            || !model.packets.is_empty()
        {
            return TestResult::Fail(
                "revoked current authority entered station registers/commands",
            );
        }
    }
    let mut control = Controller::new(&factory(false)).unwrap();
    let admission = Admission::new();
    let mut model = Model::new();
    model.aperture = 0x1f400;
    if narf_scheduler::block_on(control.initialize(&mut model, &admission))
        != Err(Error::Unsupported)
        || !model.writes.is_empty()
    {
        return TestResult::Fail(
            "short MAC aperture partially initialized nonsecure indirect tables",
        );
    }
    let mut secure = Controller::new(&factory(true)).unwrap();
    let admission = Admission::new();
    let mut model = Model::new();
    model.aperture = 0x1f400;
    if narf_scheduler::block_on(secure.initialize(&mut model, &admission)).is_err()
        || model.writes.iter().any(|(a, _)| *a >= 0x40000)
    {
        return TestResult::Fail(
            "actual secure-fuse profile did not use source indirect-table skip",
        );
    }
    for lost in [0xc400, 0x40000, 0x40004, 0x40014, 0x4001c] {
        let mut control = Controller::new(&factory(false)).unwrap();
        let admission = Admission::new();
        let mut model = Model::new();
        model.ignore = Some(lost);
        if narf_scheduler::block_on(control.initialize(&mut model, &admission)).is_ok()
            || !admission.closed()
            || !model.packets.is_empty()
        {
            return TestResult::Fail("lost port/default table write fabricated station readiness");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_station_requires_exact_execution_ack_current_authority_and_fresh_owner
);

fn smoke_rtw8852b_pause_requires_applied_scheduler_bit_and_fresh_authority() -> TestResult {
    if LINUX_PAUSE_REGISTER != 0x9eb0 {
        return TestResult::Fail("pause bitmap no longer matches original Linux register");
    }
    let mut control = Controller::new(&factory(false)).unwrap();
    let admission = Admission::new();
    let mut model = Model::new();
    model.pause_lag = 30;
    narf_scheduler::block_on(control.initialize(&mut model, &admission)).unwrap();
    if model.clock != 30 || model.word(0x9eb0) != 2 {
        return TestResult::Fail("MACID unpause did not wait for applied bit or damaged neighbors");
    }
    narf_scheduler::block_on(control.disconnect(&mut model, &admission)).unwrap();
    if model.clock != 60 || model.word(0x9eb0) != 3 || control.phase() != Phase::Stopped {
        return TestResult::Fail("terminal MACID pause did not wait for applied bit");
    }
    for terminal in [false, true] {
        let mut control = Controller::new(&factory(false)).unwrap();
        let admission = Admission::new();
        let mut model = Model::new();
        if terminal {
            narf_scheduler::block_on(control.initialize(&mut model, &admission)).unwrap();
        }
        model.hold_pause = true;
        let result = if terminal {
            narf_scheduler::block_on(control.disconnect(&mut model, &admission))
        } else {
            narf_scheduler::block_on(control.initialize(&mut model, &admission))
        };
        if result != Err(Error::Timeout)
            || model.clock != 10_000
            || !admission.closed()
            || control.phase() != Phase::Failed
            || (!terminal && model.packets.len() != 1)
        {
            return TestResult::Fail("transport retirement fabricated applied MACID pause state");
        }
    }
    for revoke in [false, true] {
        let mut control = Controller::new(&factory(false)).unwrap();
        let admission = Admission::new();
        let mut model = Model::new();
        model.pause_lag = 30;
        model.revoke_on_delay = revoke;
        if !revoke {
            model.close_on_delay = Some(admission.clone());
        }
        let result = narf_scheduler::block_on(control.initialize(&mut model, &admission));
        if result
            != Err(if revoke {
                Error::Access
            } else {
                Error::Terminal
            })
            || !admission.closed()
            || control.phase() != Phase::Failed
            || model.packets.len() != 1
            || model.pending_pause.is_none()
        {
            return TestResult::Fail(
                "pause wait bypassed close/current-cap fence before role creation",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_pause_requires_applied_scheduler_bit_and_fresh_authority
);

fn smoke_rtw8852b_awake_source_state_required_before_first_mlme_and_peer_commit() -> TestResult {
    if LINUX_AWAKE_REGISTERS != [(0x1e8, 1 << 31), (0xca0c, 0xe)] {
        return TestResult::Fail("awake checks differ from original source register/masks");
    }
    for (address, mask) in [(0x1e8, 1u32 << 31), (0xca0c, 2), (0xca0c, 4), (0xca0c, 8)] {
        for at_commit in [false, true] {
            let mut control = Controller::new(&factory(false)).unwrap();
            let admission = Admission::new();
            let mut model = Model::new();
            let peer = if at_commit {
                narf_scheduler::block_on(control.initialize(&mut model, &admission)).unwrap();
                Some(
                    narf_scheduler::block_on(control.prepare_peer(&mut model, AP, &admission))
                        .unwrap(),
                )
            } else {
                None
            };
            model.bytes[address as usize..address as usize + 4]
                .copy_from_slice(&mask.to_le_bytes());
            let result = if at_commit {
                narf_scheduler::block_on(control.commit_peer(&mut model, AP, 42, false, &admission))
            } else {
                narf_scheduler::block_on(control.initialize(&mut model, &admission))
            };
            if result != Err(Error::Unsupported)
                || !admission.closed()
                || control.phase() != Phase::Failed
                || model.word(0xc400) & (3 << 10) != 0
                || peer.is_some_and(|peer| peer.current().is_ok())
                || model.word(0xc000) & (1 << 29) != 0
            {
                return TestResult::Fail(
                    "deep/firmwarePS state fabricated prepared/connected awake peer",
                );
            }
        }
    }
    let mut control = Controller::new(&factory(false)).unwrap();
    let admission = Admission::new();
    let mut model = Model::new();
    // Other power bits/MACIDs do not change MACID0's source awake predicate.
    model.bytes[0x1e8..0x1ec].copy_from_slice(&(1u32 << 30).to_le_bytes());
    model.bytes[0xca0c..0xca10].copy_from_slice(&0xf1u32.to_le_bytes());
    if narf_scheduler::block_on(control.initialize(&mut model, &admission)).is_err() {
        return TestResult::Fail("awake predicate rejected unrelated power bits/MACID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_awake_source_state_required_before_first_mlme_and_peer_commit
);

fn smoke_rtw8852b_peer_binding_cancellation_and_close_fence_late_completion() -> TestResult {
    let mut control = Controller::new(&factory(false)).unwrap();
    let admission = Admission::new();
    let mut model = Model::new();
    narf_scheduler::block_on(control.initialize(&mut model, &admission)).unwrap();
    if narf_scheduler::block_on(control.prepare_peer(&mut model, AP, &Admission::new())).is_ok() {
        return TestResult::Fail("fresh Admission rebound an existing MACID owner");
    }
    let peer = narf_scheduler::block_on(control.prepare_peer(&mut model, AP, &admission)).unwrap();
    let mut frame = vec![0; 24];
    frame[4..10].copy_from_slice(&AP);
    frame[10..16].copy_from_slice(&OWN);
    if !peer.admits(&frame) {
        return TestResult::Fail("source-confirmed pre-auth binding rejected exact native peer");
    }
    model.wait = true;
    let mut commit = Box::pin(control.commit_peer(&mut model, AP, 42, false, &admission));
    if !commit
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending()
    {
        return TestResult::Fail("fixture did not pause a real awaited command boundary");
    }
    drop(commit);
    if peer.current().is_ok() || !admission.closed() || control.phase() != Phase::Failed {
        return TestResult::Fail("cancelled commit retained an admitting peer token");
    }
    model.wait = false;
    narf_scheduler::block_on(control.disconnect(&mut model, &admission)).unwrap();
    if peer.admits(&frame) || admission.teardown_pending() {
        return TestResult::Fail("late cleanup receipt revived cancelled peer");
    }
    let mut control = Controller::new(&factory(false)).unwrap();
    let admission = Admission::new();
    let mut model = Model::new();
    narf_scheduler::block_on(control.initialize(&mut model, &admission)).unwrap();
    let count = model.packets.len();
    model.close = Some(admission.clone());
    if narf_scheduler::block_on(control.prepare_peer(&mut model, AP, &admission)).is_ok()
        || model.packets.len() != count
        || control.peer().is_some()
    {
        return TestResult::Fail("close while waiting allowed peer publication");
    }
    let mut control = Controller::new(&factory(false)).unwrap();
    let admission = Admission::new();
    let mut model = Model::new();
    narf_scheduler::block_on(control.initialize(&mut model, &admission)).unwrap();
    let count = model.packets.len();
    model.revoke_before = true;
    if !matches!(
        narf_scheduler::block_on(control.prepare_peer(&mut model, AP, &admission)),
        Err(Error::Access)
    ) || model.packets.len() != count
        || control.peer().is_some()
    {
        return TestResult::Fail("qualification revocation after command wait published a peer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_peer_binding_cancellation_and_close_fence_late_completion
);
