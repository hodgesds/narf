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
    chip: ChipId,
    secure: bool,
    cut: u8,
    xtal: u8,
    rfe: u8,
    own: [u8; 6],
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
        (self.chip, self.cut)
    }
    async fn physical(&mut self, start: u16, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.fill(255);
        if start == 0 {
            assert_eq!(bytes.len(), 1216);
            for (index, (offset, pair)) in [
                (0x400, [self.own[0], self.own[1]]),
                (0x402, [self.own[2], self.own[3]]),
                (0x404, [self.own[4], self.own[5]]),
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
        } else if (start, bytes.len()) == (0x5e9, 5) {
            // RTL8852A takes the direct 0x5e9 extra-bytes read (no PHY-cap
            // window): power-k marker, ECV, secure bytes, same values the
            // B/C PHY-cap windows carry at 0x5e9..0x5ee.
            bytes.copy_from_slice(&[0xaa, 0x1f, 0xff, 0xff, 0xff]);
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
    factory_with_mac(cut, xtal, rfe, secure, OWN)
}
pub(in crate::rtw89) fn factory_with_chip(chip: ChipId, secure: bool) -> Factory {
    let mut factory = Factory::default();
    narf_scheduler::block_on(factory.read(&mut Source {
        chip,
        secure,
        cut: 1,
        xtal: 0x33,
        rfe: 5,
        own: OWN,
    }))
    .unwrap();
    factory
}
pub(in crate::rtw89) fn factory_with_mac(
    cut: u8,
    xtal: u8,
    rfe: u8,
    secure: bool,
    own: [u8; 6],
) -> Factory {
    let mut factory = Factory::default();
    narf_scheduler::block_on(factory.read(&mut Source {
        chip: ChipId::Rtl8852B,
        secure,
        cut,
        xtal,
        rfe,
        own,
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
fn smoke_rtw8852b_wmm_edca_actual_ack_current_authority_and_cancel_peer_gate() -> TestResult {
    const WMM: [u8; 26] = [
        221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x81, 0, 0x62, 0x32, 47, 0, 3, 0xa4, 0, 0, 0x42, 0x43, 94,
        0, 0x27, 0xa4, 0, 0,
    ];
    let parameters = narf_wireless::wmm::Parameters::parse(&WMM)
        .unwrap()
        .unwrap();
    for case in 0..4 {
        let mut controller = Controller::new(&factory(false)).unwrap();
        let admission = Admission::new();
        let mut model = Model::new();
        narf_scheduler::block_on(controller.initialize(&mut model, &admission)).unwrap();
        let peer =
            narf_scheduler::block_on(controller.prepare_peer(&mut model, AP, &admission)).unwrap();
        narf_scheduler::block_on(controller.commit_peer(&mut model, AP, 42, false, &admission))
            .unwrap();
        let mut frame = vec![0; 26];
        frame[..2].copy_from_slice(&[0x88, 1]);
        frame[4..10].copy_from_slice(&AP);
        frame[10..16].copy_from_slice(&OWN);
        if peer.admits(&frame) {
            return TestResult::Fail("B peer admitted QoS before all EDCA acknowledgements");
        }
        let before = model.packets.len();
        if case == 1 {
            model.reply = Reply::Failure;
        } else if case == 2 {
            model.qualification.revoke();
        } else if case == 3 {
            model.wait = true;
        }
        if case == 3 {
            let mut operation =
                Box::pin(controller.configure_wmm(&mut model, parameters, false, &admission));
            if operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("B WMM command wait did not suspend");
            }
            drop(operation);
        } else {
            let result = narf_scheduler::block_on(
                controller.configure_wmm(&mut model, parameters, false, &admission),
            );
            if result.is_ok() != (case == 0) {
                return TestResult::Fail("B WMM ignored firmware ACK or current signed authority");
            }
        }
        if case == 0 {
            let expected = [0xa546u32, 0xa496, 0x005e4332, 0x002f3232];
            if model.packets.len() != before + 4 || !peer.admits(&frame) {
                return TestResult::Fail("B WMM native receipt did not seal QoS peer");
            }
            for (i, packet) in model.packets[before..].iter().enumerate() {
                if packet[8..12] != ((i as u32) << 5).to_le_bytes()
                    || packet[12..16] != expected[i].to_le_bytes()
                    || packet[16..20] != [0; 4]
                {
                    return TestResult::Fail("B WMM source EDCA H2C literal fields");
                }
            }
            frame[24] = 3;
            if peer.admits(&frame) {
                return TestResult::Fail("B WMM peer broadened BE/TID0 authority");
            }
        } else if peer.current().is_ok()
            || !admission.closed()
            || controller.phase() != Phase::Failed
            || case >= 2 && model.packets.len() != before
        {
            return TestResult::Fail("B partial/cancelled/revoked WMM revived exact peer owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/wmm",
    smoke_rtw8852b_wmm_edca_actual_ack_current_authority_and_cancel_peer_gate
);

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
            return TestResult::Fail("B initial command payload differs from the frozen reference");
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

fn smoke_rtw8852b_he_capability_and_ra_codec_match_linux_profile() -> TestResult {
    let Some(he) = local_he() else {
        return TestResult::Fail("restricted HE capability rejected by the shared API");
    };
    let body = he.capability_body();
    // ext35 + MAC6 + PHY11 + rx80/tx80 only (20MHz, no PPE).
    if body.len() != 1 + 6 + 11 + 4
        || body[0] != 35
        || body[1] & 0x01 != 1
        || body[7] & 0x0e != 0
        || body[11] & 0x01 != 0
        || body[18..22] != [0xfa, 0xff, 0xfe, 0xff]
    {
        return TestResult::Fail("HE capability is not the restricted Linux profile");
    }
    // get_mcs_ra_mask(map, 11, 2): MCS0..11 / 0..9 / 0..7 per NSS.
    if codec::he_mcs_mask(0xfffe) != 0xfff000
        || codec::he_mcs_mask(0xfffd) != 0x3ff000
        || codec::he_mcs_mask(0xfff0) != 0x0ff_0ff000
        || codec::he_mcs_mask(0xffff) != 0
    {
        return TestResult::Fail("HE MCS mask differs from get_mcs_ra_mask");
    }
    let ht = HtRa {
        peer_rx_mcs: [0xff, 0, 0, 0],
        sgi20: false,
        ldpc: false,
    };
    let he_ra = HeRa {
        peer_rx_mcs: 0xfffd,
        ldpc: true,
        dcm: false,
    };
    // OFDM-only legacy (0xff0): mode HE|OFDM, mask HE1SS MCS0..9 | SUBOFDM.
    let Some(bytes) = codec::ra_he(0xff0, ht, he_ra) else {
        return TestResult::Fail("HE RA refused");
    };
    let w = |i: usize| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    if w(0) != (0x12 << 1 | 1 << 20 | 1 << 22) || w(1) != 0x3ff010 || w(2) != 0 || w(3) != 0 {
        return TestResult::Fail("HE RA H2C fields differ");
    }
    if codec::ra_he(0, ht, he_ra).is_some() {
        return TestResult::Fail("HE RA accepted an empty legacy set");
    }
    TestResult::Pass
}

fn smoke_rtw8852b_he_htc_peer_requires_completed_he_ra_and_bound_tid() -> TestResult {
    const WMM: [u8; 26] = [
        221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x81, 0, 0x62, 0x32, 47, 0, 3, 0xa4, 0, 0, 0x42, 0x43, 94,
        0, 0x27, 0xa4, 0, 0,
    ];
    let mut controller = Controller::new(&factory(false)).unwrap();
    let admission = Admission::new();
    let mut model = Model::new();
    narf_scheduler::block_on(controller.initialize(&mut model, &admission)).unwrap();
    let peer =
        narf_scheduler::block_on(controller.prepare_peer(&mut model, AP, &admission)).unwrap();
    narf_scheduler::block_on(controller.commit_peer(&mut model, AP, 42, false, &admission))
        .unwrap();
    let wmm = narf_wireless::wmm::Parameters::parse(&WMM)
        .unwrap()
        .unwrap();
    narf_scheduler::block_on(controller.configure_wmm(&mut model, wmm, false, &admission)).unwrap();
    let mut frame = vec![0; 30];
    frame[..2].copy_from_slice(&[0x88, 0x81]);
    frame[4..10].copy_from_slice(&AP);
    frame[10..16].copy_from_slice(&OWN);
    frame[24..30].copy_from_slice(&[0x10, 0, 0x1b, 0, 0, 0]);
    if peer.admits(&frame) {
        return TestResult::Fail("WMM alone admitted an HE +HTC header");
    }
    let ht = HtRa {
        peer_rx_mcs: [0xff, 0, 0, 0],
        sgi20: false,
        ldpc: false,
    };
    let he = HeRa {
        peer_rx_mcs: 0xfffe,
        ldpc: true,
        dcm: false,
    };
    narf_scheduler::block_on(controller.configure_ra(
        &mut model,
        0xfff,
        Some(ht),
        Some(he),
        &admission,
    ))
    .unwrap();
    if !peer.admits(&frame) {
        return TestResult::Fail("completed HE RA did not admit bound +HTC TID0");
    }
    for (index, value) in [(0, 8), (24, 0x13), (24, 0), (26, 3)] {
        let mut bad = frame.clone();
        bad[index] = value;
        if peer.admits(&bad) {
            return TestResult::Fail("HE peer broadened TID/control/header admission");
        }
    }
    if peer.admits(&frame[..29]) {
        return TestResult::Fail("HE peer admitted an incomplete control field");
    }
    controller.invalidate();
    if peer.admits(&frame) {
        return TestResult::Fail("invalidated HE peer retained +HTC admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/htc",
    smoke_rtw8852b_he_htc_peer_requires_completed_he_ra_and_bound_tid
);
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_he_capability_and_ra_codec_match_linux_profile
);

#[path = "monitor_tests.rs"]
mod monitor_tests;

fn word_at(bytes: &[u8], index: usize) -> u32 {
    u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
}

fn smoke_rtw89_link_codec_macid_port_keeps_station_bytes() -> TestResult {
    // Station MACID0/port0 bytes are the parameterised forms at (0, 0).
    for paused in [false, true] {
        assert_eq!(codec::pause(paused), codec::pause_at(0, paused));
    }
    assert_eq!(codec::default_cctl(), codec::default_cctl_at(0, false));
    for ghz5 in [false, true] {
        assert_eq!(
            codec::fixed_cctl(ghz5),
            codec::fixed_cctl_at(ghz5, 0, 0, None)
        );
    }
    assert_eq!(
        codec::ba_cam(true, 1, 5, 64, 0x123),
        codec::ba_cam_at(0, true, 1, 5, 64, 0x123)
    );
    // mac.c rtw89_mac_set_macid_pause: grp = macid >> 5, sh = macid & 31.
    let pause = codec::pause_at(37, true);
    assert_eq!(word_at(&pause, 1), 1 << 5);
    assert_eq!(word_at(&pause, 5), 1 << 5);
    assert_eq!(word_at(&pause, 0) | word_at(&pause, 4), 0);
    assert_eq!(word_at(&codec::pause_at(37, false), 1), 0);
    assert_eq!(codec::pause_register(37), (0x9eb4, 1 << 5));
    // fw.c rtw89_fw_h2c_assoc_cmac_tbl for an AP peer on port 2.
    let peer = codec::fixed_cctl_at(false, 3, 2, Some(true));
    assert_eq!(word_at(&peer, 0), 3 | 1 << 7);
    assert_eq!(word_at(&peer, 5) & 7, 2);
    assert_eq!(word_at(&peer, 7) & (1 << 17), 0); // ULDL 0
    assert_ne!(word_at(&peer, 15) & (1 << 17), 0);
    assert_ne!(word_at(&peer, 13) & (1 << 12), 0); // DATA_DCM mask
    assert_ne!(word_at(&peer, 14) & (1 << 13), 0); // BSR format mask
    let vif = codec::fixed_cctl_at(false, 0, 0, Some(false));
    assert_eq!(word_at(&vif, 14) & (1 << 13), 0);
    assert_ne!(word_at(&codec::default_cctl_at(9, true), 13) & (1 << 12), 0);
    assert_eq!(word_at(&codec::default_cctl_at(9, true), 0), 9 | 1 << 7);
    // cam.c AX v0 address CAM: idx/len, net type, W8 MACID/port, AID.
    let cam = codec::cam_entry(&codec::Cam {
        macid: 4,
        port: 1,
        addr_idx: 2,
        bssid_idx: 0,
        net_type: 3,
        valid: true,
        bssid_valid: true,
        sma: OWN,
        tma: AP,
        bssid: OWN,
        aid: 0x1234,
    });
    assert_eq!(word_at(&cam, 1), 2 | 0x40 << 16);
    assert_eq!(word_at(&cam, 2) & 7, 1 | 3 << 1);
    assert_eq!(word_at(&cam, 8), 4 | 1 << 8 | 1 << 11);
    assert_eq!(word_at(&cam, 9), 2 << 16 | 0x234);
    assert_eq!(
        word_at(&cam, 13) >> 16,
        u32::from(OWN[0]) | u32::from(OWN[1]) << 8
    );
    let (dmac, cmac, _) = codec::table_init(3);
    assert_eq!(dmac, [0x1880_0030, 0x1880_0034, 0x1880_0038, 0x1880_003c]);
    assert_eq!(cmac, 0x1884_0060);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_link_codec_macid_port_keeps_station_bytes
);
fn smoke_rtw8852c_station_cctl_v1_follows_linux_cctlinfo_ud_v1() -> TestResult {
    // fw.h H2C_FUNC_MAC_CCTLINFO_UD_V1 (rtw8852c `h2c_cctl_func_id`).
    if codec::CCTL_V1 != 0x0a {
        return TestResult::Fail("C CCTL function is not CCTLINFO_UD_V1");
    }
    // Default: no TXPWR_MODE / TX path / ANTSEL setter under UD_V1; only
    // MGQ_RPT_EN (W1 bit21), DOPPLER (W7 [19:18]), TOLERENCE (W7 [27:24]).
    let d = codec::default_cctl_v1();
    let b = codec::default_cctl();
    if word_at(&d, 0) != word_at(&b, 0)
        || word_at(&d, 5) | word_at(&d, 13) != 0
        || word_at(&d, 6) | word_at(&d, 14) != 0
        || word_at(&d, 9) != 1 << 21
        || word_at(&d, 15) != 0x0f0c_0000
        || word_at(&d, 1) | word_at(&d, 7) != 0
    {
        return TestResult::Fail("C default CCTL body differs from Linux UD_V1");
    }
    for ghz5 in [false, true] {
        let v1 = codec::fixed_cctl_v1(ghz5);
        let ud = codec::fixed_cctl(ghz5);
        // Padding masks move from W7 [21:20]/[23:22]/[31:30] + W8 [29:28]
        // to W7 [7:0]; every other setter is byte-identical.
        let ud_pad7 = 3 << 20 | 3 << 22 | 3 << 30;
        if word_at(&v1, 15) != (word_at(&ud, 15) & !ud_pad7) | 0xff
            || word_at(&v1, 16) != word_at(&ud, 16) & !(3 << 28)
            || word_at(&v1, 7) & 0xff != 0
        {
            return TestResult::Fail("C assoc CCTL padding not at UD_V1 positions");
        }
        for index in (0..17).filter(|i| ![7, 8, 15, 16].contains(i)) {
            if word_at(&v1, index) != word_at(&ud, index) {
                return TestResult::Fail("C assoc CCTL changed a shared setter");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_station_cctl_v1_follows_linux_cctlinfo_ud_v1
);
fn smoke_rtw8852c_ba_cam_v0_ext_wire_and_dynamic_init_follow_fw_c() -> TestResult {
    // rtw89_fw_h2c_ba_cam, RTW89_BACAM_V0_EXT: no W0 ENTRY_IDX, W1
    // ENTRY_IDX_V1[31:28] | STD_EN; BAND 0 (mac_idx 0).
    let v0 = codec::ba_cam(true, 1, 5, 64, 0x123);
    let ext = codec::ba_cam_v0_ext(true, 7, 5, 64, 0x123);
    if word_at(&ext, 0) != word_at(&v0, 0) & !(3 << 2)
        || word_at(&ext, 1) != (7 << 28 | 1 << 8)
        || word_at(&codec::ba_cam_v0_ext(true, 0, 0, 256, 0), 0) != (1 | 1 << 1 | 4 << 16)
    {
        return TestResult::Fail("C BA CAM V0_EXT body differs from fw.c");
    }
    // Invalidation: MACID 0 and W1 ENTRY_IDX_V1 only.
    let off = codec::ba_cam_v0_ext(false, 6, 5, 64, 0x123);
    if word_at(&off, 0) != 0 || word_at(&off, 1) != 6 << 28 {
        return TestResult::Fail("C BA CAM invalidation differs");
    }
    // rtw89_fw_h2c_init_ba_cam_v0_ext: VALID, entry 8 + uid, uid.
    for uid in 0..8u8 {
        let init = codec::init_ba_cam_v0_ext(8 + uid, uid);
        if word_at(&init, 0) != 1
            || word_at(&init, 1) != (u32::from(8 + uid) << 28 | u32::from(uid))
        {
            return TestResult::Fail("C dynamic BA CAM init differs");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_ba_cam_v0_ext_wire_and_dynamic_init_follow_fw_c
);

/// AP elements for a wide-channel BSS: rates, HT Capabilities (20/40, SGI20/
/// SGI40, LDPC, RX MCS0..15), HT Operation (`secondary` 1 above / 3 below),
/// and on 5GHz VHT Capabilities (2SS MCS0..9) and VHT Operation.
fn wide_ap_ies(primary: u8, secondary: u8, vht: Option<(u8, u8)>) -> Vec<u8> {
    let mut ies = if primary > 14 {
        vec![1, 8, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c]
    } else {
        vec![1, 8, 0x82, 0x84, 0x8b, 0x96, 12, 18, 24, 36]
    };
    let mut ht = [0u8; 26];
    ht[0] = 0x63;
    ht[2] = 3;
    ht[3] = 255;
    ht[4] = 255;
    ht[15] = 1;
    ies.extend_from_slice(&[45, 26]);
    ies.extend_from_slice(&ht);
    let mut op = [0u8; 22];
    op[0] = primary;
    op[1] = secondary | if secondary != 0 { 4 } else { 0 };
    ies.extend_from_slice(&[61, 22]);
    ies.extend_from_slice(&op);
    if let Some((width, center)) = vht {
        ies.extend_from_slice(&[191, 12, 0x30, 0, 0, 0, 0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0]);
        ies.extend_from_slice(&[192, 5, width, center, 0, 0xfc, 0xff]);
    }
    ies
}

fn smoke_rtw89_b_wide_capability_offered_only_on_admitted_chandef() -> TestResult {
    use super::super::operating_channel::{Profile, Width};
    // core.c rtw89_init_ht_cap width bits over the HT20 profile.
    let Some(ht40) = local_ht40() else {
        return TestResult::Fail("HT40 capability rejected by the shared API");
    };
    let body = ht40.capability_body();
    let narrow = local_ht().capability_body();
    if u16::from_le_bytes([body[0], body[1]]) != 0x116f || body[2..] != narrow[2..] {
        return TestResult::Fail("HT40 capability is not rtw89_init_ht_cap width bits over HT20");
    }
    // rtw89_init_vht_cap restricted: RXLDPC|SGI80|RXSTBC1, no 160/TXSTBC/BF.
    let Some(vht) = local_vht80() else {
        return TestResult::Fail("VHT80 capability rejected by the shared API");
    };
    let vbody = vht.capability_body();
    if u32::from_le_bytes([vbody[0], vbody[1], vbody[2], vbody[3]]) != 0x130
        || vbody[4..6] != [0xfa, 0xff]
        || vbody[8..10] != [0xfe, 0xff]
    {
        return TestResult::Fail("VHT80 capability differs from the restricted Linux profile");
    }
    // HE PHY cap0: 40MHz-in-2.4GHz / 40-80MHz-in-5GHz; rest is HE20's.
    let (Some(he2), Some(he5), Some(he)) = (local_he_wide(false), local_he_wide(true), local_he())
    else {
        return TestResult::Fail("wide HE capability rejected");
    };
    let (b2, b5, b) = (
        he2.capability_body(),
        he5.capability_body(),
        he.capability_body(),
    );
    if b2[7] != 0x02 || b5[7] != 0x04 || b2[8..] != b[8..] || b5[8..] != b[8..] || b2[..7] != b[..7]
    {
        return TestResult::Fail("wide HE PHY cap0 differs from rtw89_init_he_cap");
    }
    // 2.4GHz HT40+ on primary 1: offered only for the admitted HT40+ profile.
    let ies = wide_ap_ies(1, 1, None);
    let Some(plus) = Profile::new_2ghz_40(1, true) else {
        return TestResult::Fail("HT40+ profile missing");
    };
    if wide_phy(&ies, 1, true, false, &[]).is_some() {
        return TestResult::Fail("wide PHY offered without an admitted profile");
    }
    let other = Profile::new_2ghz_40(5, false).unwrap();
    if wide_phy(&ies, 1, true, false, &[other]).is_some() {
        return TestResult::Fail("wide PHY offered for a different admitted chandef");
    }
    match wide_phy(&ies, 1, true, false, &[other, plus]) {
        Some((local, profile)) if profile == plus => {
            if local.he().map(|he| he.capability_body()) != Some(b2.clone()) {
                return TestResult::Fail("2.4GHz HT40 join lacks the 40MHz HE capability");
            }
        }
        _ => return TestResult::Fail("admitted HT40+ chandef not offered"),
    }
    // A 20MHz AP never maps to a wide profile.
    if wide_phy(&wide_ap_ies(1, 0, None), 1, false, false, &[plus]).is_some() {
        return TestResult::Fail("20MHz BSS offered a wide PHY");
    }
    // 5GHz VHT80 at center 42 (primary 40): 80MHz when admitted, else the
    // admitted 40MHz half, else nothing.
    let ies = wide_ap_ies(40, 3, Some((1, 42)));
    let (Some(p80), Some(p40)) = (
        Profile::new_5ghz(40, Width::Mhz80),
        Profile::new_5ghz(40, Width::Mhz40),
    ) else {
        return TestResult::Fail("5GHz wide profiles missing");
    };
    if !matches!(wide_phy(&ies, 40, true, false, &[p40, p80]), Some((_, p)) if p == p80) {
        return TestResult::Fail("admitted VHT80 chandef not offered");
    }
    if !matches!(wide_phy(&ies, 40, false, false, &[p40]), Some((_, p)) if p == p40) {
        return TestResult::Fail("admitted 40MHz half of a VHT80 BSS not offered");
    }
    if wide_phy(
        &ies,
        40,
        false,
        false,
        &[Profile::new_5ghz(44, Width::Mhz40).unwrap()],
    )
    .is_some()
    {
        return TestResult::Fail("wide PHY offered for a chandef not containing the primary");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw89_b_wide_capability_offered_only_on_admitted_chandef
);

fn smoke_rtw89_b_wide_ra_h2c_bw_sgi_and_vht_mask_match_linux() -> TestResult {
    let w = |b: &[u8; 16], i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    let ht = HtRa {
        peer_rx_mcs: [0xff, 0xff, 0, 0],
        sgi20: true,
        ldpc: true,
    };
    // get_mcs_ra_mask(map, 9, 1): MCS0..9 / 0..8 / 0..7 per NSS.
    if codec::vht_mcs_mask(0xfffe) != 0x3ff000
        || codec::vht_mcs_mask(0xfffd) != 0x1ff000
        || codec::vht_mcs_mask(0xfffa) != 0x3ff_3ff000
        || codec::vht_mcs_mask(0xffff) != 0
    {
        return TestResult::Fail("VHT MCS mask differs from get_mcs_ra_mask(.., 9, 1)");
    }
    // HT40 on 2.4GHz: HT branch body with BW_CAP=1 and SGI = HT SGI_40.
    let wide = WideRa {
        bw: 1,
        sgi: false,
        vht: None,
        fix_giltf: None,
    };
    let (Some(narrow), Some(body)) = (
        codec::ra_ht(0xfff, Some(ht)),
        codec::ra_wide(0xfff, ht, None, wide),
    ) else {
        return TestResult::Fail("HT40 RA refused");
    };
    if w(&body, 0) != (w(&narrow, 0) & !(1 << 21)) | 1 << 6 || body[4..] != narrow[4..] {
        return TestResult::Fail("HT40 RA differs from the HT branch with bw_cap 40");
    }
    // VHT80 on 5GHz (OFDM legacy 0xff0): mode VHT|OFDM, mask VHT1SS|SUBOFDM,
    // BW_CAP=2, SGI80, LDPC from the peer RXLDPC, STBC0.
    let vht = VhtRa {
        peer_rx_mcs: 0xfffe,
        ldpc: true,
    };
    let wide = WideRa {
        bw: 2,
        sgi: true,
        vht: Some(vht),
        fix_giltf: None,
    };
    let Some(body) = codec::ra_wide(0xff0, ht, None, wide) else {
        return TestResult::Fail("VHT80 RA refused");
    };
    if w(&body, 0) != (0xa << 1 | 2 << 6 | 1 << 20 | 1 << 21 | 1 << 22)
        || w(&body, 1) != 0x3ff010
        || w(&body, 2) != 0
    {
        return TestResult::Fail("VHT80 RA_MACIDCFG differs from rtw89_phy_ra_sta_update");
    }
    // HE takes precedence over VHT (HE branch body, BW_CAP=2).
    let he = HeRa {
        peer_rx_mcs: 0xfffe,
        ldpc: true,
        dcm: false,
    };
    let (Some(narrow), Some(body)) = (
        codec::ra_he(0xff0, ht, he),
        codec::ra_wide(0xff0, ht, Some(he), wide),
    ) else {
        return TestResult::Fail("HE80 RA refused");
    };
    if w(&body, 0) != w(&narrow, 0) | 2 << 6 || body[4..] != narrow[4..] {
        return TestResult::Fail("HE80 RA differs from the HE branch with bw_cap 80");
    }
    // 80MHz without VHT facts and a 20MHz "wide" RA are refused.
    if codec::ra_wide(0xff0, ht, Some(he), WideRa { vht: None, ..wide }).is_some()
        || codec::ra_wide(0xff0, ht, None, WideRa { bw: 0, ..wide }).is_some()
    {
        return TestResult::Fail("inconsistent wide RA accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw89_b_wide_ra_h2c_bw_sgi_and_vht_mask_match_linux
);

/// RTL8852C 160MHz: core.c `rtw89_init_vht_cap` / `rtw89_init_he_cap` 160MHz
/// bits over the restricted wide profile, `wide_phy` offering VHT160/HE160
/// only for an admitted 160MHz chandef (never on an RTL8852B-only admitted
/// list), and phy.c `rtw89_phy_ra_sta_update` BW_CAP 160 / SHORT_GI_160 with
/// `rtw89_phy_ra_gi_ltf`'s RTL8852C 160MHz fixed GI/LTF.
fn smoke_rtw8852c_160mhz_capability_wide_phy_and_ra_follow_linux() -> TestResult {
    use super::super::operating_channel::{Profile, Width};
    let w = |b: &[u8; 16], i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    // VHT160 = VHT80 | SUPP_CHAN_WIDTH_160MHZ (bit2) | SHORT_GI_160 (bit6),
    // same MCS maps.
    let (Some(v80), Some(v160)) = (local_vht80(), local_vht160()) else {
        return TestResult::Fail("VHT160 capability rejected by the shared API");
    };
    let (a, b) = (v80.capability_body(), v160.capability_body());
    if u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != 0x130 | 1 << 2 | 1 << 6 || a[4..] != b[4..] {
        return TestResult::Fail("VHT160 differs from rtw89_init_vht_cap 160MHz bits");
    }
    // HE160: cap0 40/80 + 160MHz-in-5G, cap8 | 20/80MHz-in-160 HE PPDU, then
    // the 80MHz maps followed by the 160MHz maps (= the 80MHz ones).
    let (Some(he5), Some(he160)) = (local_he_wide(true), local_he160()) else {
        return TestResult::Fail("HE160 capability rejected");
    };
    let (h5, h160) = (he5.capability_body(), he160.capability_body());
    if h160[7] != 0x0c
        || h160[15] != h5[15] | 0x0c
        || h160[..7] != h5[..7]
        || h160[8..15] != h5[8..15]
        || h160.len() != h5.len() + 4
        || h160[16..h5.len()] != h5[16..]
        || h160[h5.len()..] != [0xfa, 0xff, 0xfe, 0xff]
    {
        return TestResult::Fail("HE160 differs from rtw89_init_he_cap 160MHz bits");
    }
    // AP: primary 40, 160MHz BSS 36..64 (VHT cap 160 + SGI160, revised VHT
    // operation width 1, CCFS0 42 = primary80, CCFS1 50 = the 160 center).
    let mut ies = wide_ap_ies(40, 3, None);
    ies.extend_from_slice(&[191, 12, 0x74, 0, 0, 0, 0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0]);
    ies.extend_from_slice(&[192, 5, 1, 42, 50, 0xfc, 0xff]);
    let (Some(p160), Some(p80)) = (
        Profile::new_5ghz_160(40),
        Profile::new_5ghz(40, Width::Mhz80),
    ) else {
        return TestResult::Fail("5GHz 160/80MHz profiles missing");
    };
    // chan.c rtw89_get_primary_chan_idx / phy.c rtw89_phy_get_txsc at 160.
    if p160.center() != 50
        || p160.pri_ch_idx() != 6
        || p160.txsc(Width::Mhz20) != 6
        || p160.txsc(Width::Mhz40) != 12
        || p160.txsc(Width::Mhz80) != 14
        || p160.occupied() != (5170, 5330)
        || Profile::new_5ghz(40, Width::Mhz160).is_some()
        || Profile::new_wide(40, Width::Mhz160, false).is_some()
    {
        return TestResult::Fail("160MHz geometry differs from Linux or B admitted 160MHz");
    }
    // An RTL8852B-style admitted list (no 160MHz profile): the 80MHz join,
    // without any 160MHz capability bit.
    match wide_phy(&ies, 40, true, false, &[p80]) {
        Some((local, p)) if p == p80 => {
            if local.he().map(|he| he.capability_body()) != Some(h5.clone()) {
                return TestResult::Fail("80MHz join offered HE160");
            }
        }
        _ => return TestResult::Fail("admitted 80MHz half of a 160MHz BSS not offered"),
    }
    // The admitted C 160MHz chandef: VHT160 + HE160, exactly that profile.
    match wide_phy(&ies, 40, true, false, &[p80, p160]) {
        Some((local, p)) if p == p160 => {
            if local.he().map(|he| he.capability_body()) != Some(h160.clone()) {
                return TestResult::Fail("160MHz join lacks the HE160 capability");
            }
        }
        _ => return TestResult::Fail("admitted 160MHz chandef not offered"),
    }
    // An 80MHz BSS never selects the 160MHz candidate.
    if !matches!(
        wide_phy(&wide_ap_ies(40, 3, Some((1, 42))), 40, false, false, &[p80, p160]),
        Some((_, p)) if p == p80
    ) {
        return TestResult::Fail("80MHz BSS joined at 160MHz");
    }
    // RA: BW_CAP 3 and SHORT_GI_160 on the VHT branch.
    let ht = HtRa {
        peer_rx_mcs: [0xff, 0xff, 0, 0],
        sgi20: true,
        ldpc: true,
    };
    let vht = VhtRa {
        peer_rx_mcs: 0xfffe,
        ldpc: true,
    };
    let wide = WideRa {
        bw: 3,
        sgi: true,
        vht: Some(vht),
        fix_giltf: None,
    };
    let Some(body) = codec::ra_wide(0xff0, ht, None, wide) else {
        return TestResult::Fail("VHT160 RA refused");
    };
    if w(&body, 0) != (0xa << 1 | 3 << 6 | 1 << 20 | 1 << 21 | 1 << 22)
        || w(&body, 1) != 0x3ff010
        || w(&body, 3) != 0
    {
        return TestResult::Fail("VHT160 RA_MACIDCFG differs from rtw89_phy_ra_sta_update");
    }
    // HE160: HE branch, BW_CAP 3, W3 FIX_GILTF_EN | FIX_GILTF (SGI_4XHE08 1
    // or 2XHE08 3).
    let he = HeRa {
        peer_rx_mcs: 0xfffe,
        ldpc: true,
        dcm: false,
    };
    for giltf in [1u8, 3] {
        let (Some(narrow), Some(body)) = (
            codec::ra_he(0xff0, ht, he),
            codec::ra_wide(
                0xff0,
                ht,
                Some(he),
                WideRa {
                    fix_giltf: Some(giltf),
                    ..wide
                },
            ),
        ) else {
            return TestResult::Fail("HE160 RA refused");
        };
        if w(&body, 0) != (w(&narrow, 0) & !(1 << 21)) | 3 << 6 | 1 << 21
            || body[4..12] != narrow[4..12]
            || w(&body, 3) != 1 << 11 | u32::from(giltf) << 12
        {
            return TestResult::Fail("HE160 RA differs from the HE branch with bw_cap 160");
        }
    }
    // Fixed GI/LTF only on an HE 160MHz link with a defined value; 160MHz
    // needs VHT facts; widths above 160 are refused.
    if codec::ra_wide(
        0xff0,
        ht,
        None,
        WideRa {
            fix_giltf: Some(1),
            ..wide
        },
    )
    .is_some()
        || codec::ra_wide(
            0xff0,
            ht,
            Some(he),
            WideRa {
                bw: 2,
                fix_giltf: Some(1),
                ..wide
            },
        )
        .is_some()
        || codec::ra_wide(
            0xff0,
            ht,
            Some(he),
            WideRa {
                fix_giltf: Some(2),
                ..wide
            },
        )
        .is_some()
        || codec::ra_wide(0xff0, ht, Some(he), WideRa { vht: None, ..wide }).is_some()
        || codec::ra_wide(0xff0, ht, None, WideRa { bw: 4, ..wide }).is_some()
    {
        return TestResult::Fail("inconsistent 160MHz RA accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852c_160mhz_capability_wide_phy_and_ra_follow_linux
);

/// phy.c `rtw89_phy_ra_sta_update` on `RTW89_BAND_6G` for a 6GHz HE peer
/// (no HT): `mode = HE|OFDM`, SGI clear, OFDM-only legacy, LDPC/DCM from
/// HE; any CCK rate or no OFDM rate is refused.
fn smoke_rtw8852c_6ghz_ra_is_he_only_ofdm() -> TestResult {
    let he = codec::HeRa {
        peer_rx_mcs: 0xfffa,
        ldpc: true,
        dcm: false,
    };
    let Some(bytes) = codec::ra_he6(0xff0, he) else {
        return TestResult::Fail("6GHz HE-only RA refused");
    };
    let w0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    // MODE[5:1] = HE (0x10) | OFDM (0x2); SGI BIT(21) clear; LDPC BIT(22).
    if (w0 >> 1) & 0x1f != 0x12 || w0 & 1 << 21 != 0 || w0 & 1 << 22 == 0 {
        return TestResult::Fail("6GHz RA mode/SGI/LDPC");
    }
    let mask = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if mask & 0xf != 0 || mask & 0xfff000 == 0 {
        return TestResult::Fail("6GHz RA mask carries CCK or no HE MCS");
    }
    if codec::ra_he6(0xfff, he).is_some() || codec::ra_he6(0, he).is_some() {
        return TestResult::Fail("6GHz RA admitted CCK or empty legacy rates");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_6ghz_ra_is_he_only_ofdm
);
/// RTL8851B (`rx_nss` = `tx_nss` = 1): the NSS1 HE/VHT bodies differ from
/// the B/C ones only in the MCS maps, and the one-stream wide join offers
/// them, never a 160MHz candidate.
fn smoke_rtw8851b_station_offers_one_stream_he_vht() -> TestResult {
    use super::super::operating_channel::{Profile, Width};
    let (Some(he), Some(he1), Some(vht), Some(vht1)) =
        (local_he(), local_he_1ss(), local_vht80(), local_vht80_1ss())
    else {
        return TestResult::Fail("one-stream capability rejected by the shared API");
    };
    let (b, b1) = (he.capability_body(), he1.capability_body());
    let (v, v1) = (vht.capability_body(), vht1.capability_body());
    if b1.len() != b.len()
        || b1[..18] != b[..18]
        || b1[18..22] != [0xfe, 0xff, 0xfe, 0xff]
        || v1[..4] != v[..4]
        || v1[4..6] != [0xfe, 0xff]
        || v1[8..10] != [0xfe, 0xff]
    {
        return TestResult::Fail("one-stream bodies are not the NSS1 restriction");
    }
    for ghz5 in [false, true] {
        let (Some(w), Some(w1)) = (local_he_wide(ghz5), local_he_wide_1ss(ghz5)) else {
            return TestResult::Fail("one-stream wide HE rejected");
        };
        let (w, w1) = (w.capability_body(), w1.capability_body());
        if w1[..18] != w[..18] || w1[18..22] != [0xfe, 0xff, 0xfe, 0xff] {
            return TestResult::Fail("one-stream wide HE is not the NSS1 restriction");
        }
    }
    if he_fingerprint_1ss() == he_fingerprint() || wide_fingerprint_1ss() == wide_fingerprint() {
        return TestResult::Fail("one-stream programs share the two-stream identity");
    }
    let ies = wide_ap_ies(40, 3, Some((1, 42)));
    let (Some(p80), Some(p160)) = (
        Profile::new_5ghz(40, Width::Mhz80),
        Profile::new_5ghz_160(40),
    ) else {
        return TestResult::Fail("5GHz wide profiles missing");
    };
    if !matches!(wide_phy(&ies, 40, true, true, &[p80]), Some((_, p)) if p == p80) {
        return TestResult::Fail("one-stream VHT80 chandef not offered");
    }
    if wide_phy(&ies, 40, true, true, &[p160]).is_some() {
        return TestResult::Fail("one-stream station offered a 160MHz chandef");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8851b_station_offers_one_stream_he_vht
);

fn smoke_rtw8852a_station_owner_matches_b_codec_and_gates_noise() -> TestResult {
    let a_factory = factory_with_chip(ChipId::Rtl8852A, false);
    let b_factory = factory(false);
    let a = Controller::new(&a_factory).unwrap();
    let b = Controller::new(&b_factory).unwrap();
    if !a.supports_noise()
        || b.supports_noise()
        || a.own() != OWN
        || a.bacam_num() != 2
        || b.bacam_num() != 2
        || a.default_cctl() != b.default_cctl()
        || a.fixed_cctl(false) != b.fixed_cctl(false)
        || a.fixed_cctl(true) != b.fixed_cctl(true)
    {
        return TestResult::Fail("A station owner is not B's shared codec or noise gate");
    }
    if Controller::new(&Factory::default()).is_ok() {
        return TestResult::Fail("station owner admitted without a factory identity");
    }
    // The whole MAC-layer sequence must be byte-identical to B's: A shares
    // B's CCTLINFO_UD tables, BA CAM geometry and role/join/CAM commands.
    let mut a_packets = Vec::new();
    let mut b_packets = Vec::new();
    let mut a_writes = Vec::new();
    let mut b_writes = Vec::new();
    for (factory, packets, writes) in [
        (&a_factory, &mut a_packets, &mut a_writes),
        (&b_factory, &mut b_packets, &mut b_writes),
    ] {
        let mut control = Controller::new(factory).unwrap();
        let admission = Admission::new();
        let mut model = Model::new();
        narf_scheduler::block_on(control.initialize(&mut model, &admission)).unwrap();
        if control.phase() != Phase::Passive {
            return TestResult::Fail("station owner did not reach Passive");
        }
        let peer =
            narf_scheduler::block_on(control.prepare_peer(&mut model, AP, &admission)).unwrap();
        narf_scheduler::block_on(control.commit_peer(&mut model, AP, 42, true, &admission))
            .unwrap();
        if control.phase() != Phase::Associated {
            return TestResult::Fail("station owner did not reach Associated");
        }
        narf_scheduler::block_on(control.disconnect(&mut model, &admission)).unwrap();
        if control.phase() != Phase::Stopped
            || peer.current().is_ok()
            || !admission.closed()
            || model.consumed != model.packets.len()
        {
            return TestResult::Fail("station owner terminal cleanup reopened the peer");
        }
        *packets = model.packets;
        *writes = model.writes;
    }
    if a_packets != b_packets || a_writes != b_writes {
        return TestResult::Fail("A station H2C/register stream differs from B's");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_station_owner_matches_b_codec_and_gates_noise
);
