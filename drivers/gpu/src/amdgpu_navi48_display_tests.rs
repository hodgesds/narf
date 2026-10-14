use super::*;
use alloc::vec;
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    edid: Vec<u8>,
    dpcd: [u8; 16],
    extended: [u8; 16],
    segment: usize,
    offset: usize,
    mot: bool,
    commands: Vec<(u8, u8, u32, Vec<u8>)>,
    defers: usize,
    delays: usize,
    fail: Option<dmub::Error>,
    stall: Option<usize>,
    /// The repeater capability block, NACKed when absent.
    lttpr: Option<[u8; 10]>,
    /// DP_128B132B_SUPPORTED_LINK_RATES.
    uhbr: u8,
    fec: u8,
}
fn checksum(block: &mut [u8]) {
    block[127] = 0u8.wrapping_sub(block[..127].iter().fold(0u8, |s, b| s.wrapping_add(*b)));
}
fn fake(blocks: usize) -> Fake {
    let mut edid = vec![0; blocks * 128];
    edid[..8].copy_from_slice(&[0, 255, 255, 255, 255, 255, 255, 0]);
    edid[18] = 1;
    edid[19] = 4;
    edid[126] = (blocks - 1) as u8;
    for (i, block) in edid.chunks_exact_mut(128).enumerate() {
        if i != 0 {
            block[0] = 2;
            block[1] = i as u8;
        }
        checksum(block);
    }
    let mut dpcd = [0; 16];
    dpcd[..3].copy_from_slice(&[0x14, 30, 0x84]);
    dpcd[14] = 0x80;
    let mut extended = dpcd;
    extended[0] = 0x21;
    Fake {
        edid,
        dpcd,
        extended,
        segment: 9,
        offset: 0,
        mot: false,
        commands: Vec::new(),
        defers: 0,
        delays: 0,
        fail: None,
        stall: None,
        lttpr: None,
        uhbr: 0,
        fec: 0,
    }
}
impl Aux for Fake {
    async fn transfer(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), dmub::Error> {
        if self.stall == Some(self.commands.len()) {
            core::future::pending::<()>().await;
        }
        self.commands
            .push((instance, action, address, data.to_vec()));
        if let Some(error) = self.fail {
            return Err(error);
        }
        if self.defers != 0 {
            self.defers -= 1;
            return Err(dmub::Error::Aux(8));
        }
        if instance == 2 {
            return Err(dmub::Error::Aux(1));
        }
        assert_eq!(instance, 1, "connector/transmitter mistaken for AUX");
        match (action, address, data.len()) {
            // No repeater: the LTTPR capability block is NACKed.
            (0x90, 0xf0000, 10) => match self.lttpr {
                Some(caps) => data.copy_from_slice(&caps),
                None => return Err(dmub::Error::Aux(1)),
            },
            (0x90, 0x2215, 1) => data[0] = self.uhbr,
            (0x90, 0x90, 1) => data[0] = self.fec,
            (0x90, 0, 16) => data.copy_from_slice(&self.dpcd),
            (0x90, 0x2200, 16) => data.copy_from_slice(&self.extended),
            (0, 0x30, 1) => {
                assert!(!self.mot);
                self.segment = usize::from(data[0]);
            }
            (0x40, 0x50, 1) => {
                assert!(!self.mot);
                self.offset = self.segment * 256 + usize::from(data[0]);
                self.mot = true;
            }
            (0x10 | 0x50, 0x50, 16) => {
                assert!(self.mot);
                data.copy_from_slice(&self.edid[self.offset..self.offset + 16]);
                self.offset += 16;
                self.mot = action != 0x10;
            }
            (0x10, 0x50, 0) => self.mot = false,
            _ => panic!("incorrect AUX/EDID transaction"),
        }
        Ok(())
    }
    async fn delay(&mut self) {
        self.delays += 1;
    }
}
fn path(aux: u8, transmitter: u8) -> inventory::Path {
    inventory::Path {
        connector: inventory::Connector::DisplayPort,
        connector_instance: 4,
        transmitter,
        aux: Some(aux),
        hpd: 2,
        device_tag: 8,
        max_speed_mhz: 0,
    }
}
fn probe() -> Probe {
    Probe::new(vec![path(1, 3), path(2, 0)]).unwrap()
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

fn navi48_display_reads_extended_caps_segmented_edid_and_distinct_wires() -> TestResult {
    let mut p = probe();
    let mut io = fake(3);
    io.defers = 2;
    let ports = run(p.scan_with(&mut io, None::<&mut ddc::Ddc>)).unwrap();
    let connected = ports[0].sink.as_ref().unwrap();
    if ports.len() != 2
        || ports[0].path.transmitter != 3
        || connected.dpcd.unwrap()[0] != 0x21
        || connected.edid != io.edid
        || ports[1].sink != Err(Error::Transport(dmub::Error::Aux(1)))
        || p.state() != State::Ready
        || io.delays != 2
        || io.mot
    {
        return TestResult::Fail("routed sink discovery or complete EDID");
    }
    let segments: Vec<_> = io
        .commands
        .iter()
        .filter(|c| c.2 == 0x30)
        .map(|c| c.3[0])
        .collect();
    let offsets: Vec<_> = io
        .commands
        .iter()
        .filter(|c| c.1 == 0x40)
        .map(|c| c.3[0])
        .collect();
    let stops = io
        .commands
        .iter()
        .filter(|c| c.1 == 0x10 && c.3.len() == 16)
        .count();
    if segments != [0, 1] || offsets != [0, 128, 0] || stops != 3 {
        return TestResult::Fail("E-EDID segment/offset/STOP sequence");
    }
    io.extended[0] = 0x12;
    if run(p.scan_with(&mut io, None::<&mut ddc::Ddc>)).unwrap()[0]
        .sink
        .as_ref()
        .unwrap()
        .dpcd
        .unwrap()[0]
        != 0x14
    {
        return TestResult::Fail("older extended caps replaced base capabilities");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_reads_extended_caps_segmented_edid_and_distinct_wires
);

fn navi48_display_bounds_edid_defers_and_preserves_other_ports() -> TestResult {
    for case in 0..4 {
        let mut p = probe();
        let mut io = fake(2);
        let expected = match case {
            0 => {
                io.edid[130] ^= 1;
                Error::InvalidEdid
            }
            1 => {
                io.edid[0] = 1;
                checksum(&mut io.edid[..128]);
                Error::InvalidEdid
            }
            2 => {
                io.edid[126] = 32;
                checksum(&mut io.edid[..128]);
                Error::EdidTooLarge
            }
            _ => {
                io.dpcd[2] = 3;
                Error::InvalidDpcd
            }
        };
        let ports = run(p.scan_with(&mut io, None::<&mut ddc::Ddc>)).unwrap();
        if ports[0].sink != Err(expected) || ports.len() != 2 || io.mot || p.state() != State::Ready
        {
            return TestResult::Fail("malformed sink poisoned scan or EDID left I2C open");
        }
    }
    let mut p = Probe::new(vec![path(1, 3)]).unwrap();
    let mut io = fake(1);
    io.defers = 10;
    let ports = run(p.scan_with(&mut io, None::<&mut ddc::Ddc>)).unwrap();
    if io.commands.len() != 7
        || io.delays != 6
        || ports[0].sink != Err(Error::Transport(dmub::Error::Aux(8)))
    {
        return TestResult::Fail("AUX DEFER retries unbounded or wrong result");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_bounds_edid_defers_and_preserves_other_ports
);

fn navi48_display_cancellation_and_transport_failure_block_reuse() -> TestResult {
    let mut p = probe();
    let mut io = fake(1);
    io.stall = Some(6); // inside the EDID MOT sequence, after the DPCD reads
    {
        let mut future = core::pin::pin!(p.scan_with(&mut io, None::<&mut ddc::Ddc>));
        if !future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
        {
            return TestResult::Fail("cancellation fixture did not suspend");
        }
    }
    io.stall = None;
    let commands = io.commands.len();
    if p.state() != State::Scanning
        || !io.mot
        || run(p.scan_with(&mut io, None::<&mut ddc::Ddc>)) != Err(Error::Busy)
        || commands != io.commands.len()
    {
        return TestResult::Fail("cancelled I2C MOT sequence silently reused");
    }
    for error in [
        dmub::Error::Revoked,
        dmub::Error::DeviceGone,
        dmub::Error::Protocol,
        dmub::Error::CommandTimeout,
    ] {
        let mut p = probe();
        let mut io = fake(1);
        io.fail = Some(error);
        if run(p.scan_with(&mut io, None::<&mut ddc::Ddc>)) != Err(Error::Transport(error))
            || p.state() != State::Failed(Error::Transport(error))
            || run(p.scan_with(&mut io, None::<&mut ddc::Ddc>)) != Err(Error::Busy)
            || io.commands.len() != 1
        {
            return TestResult::Fail("failed transport reused or other ports accessed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_cancellation_and_transport_failure_block_reuse
);

fn navi48_display_refuses_ambiguous_or_unroutable_board_paths() -> TestResult {
    for case in 0..5 {
        let first = path(1, 3);
        let mut second = path(2, 0);
        match case {
            0 => second.aux = first.aux,
            1 => second.transmitter = first.transmitter,
            2 => second.aux = Some(4),
            3 => second.hpd = 5,
            _ => second.aux = None,
        }
        if Probe::new(vec![first, second]).is_ok() {
            return TestResult::Fail("ambiguous or nonexistent DCN4 channel admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_refuses_ambiguous_or_unroutable_board_paths
);

struct FakeHdmi {
    result: Result<Vec<u8>, ddc::Error>,
    channels: Vec<u8>,
    stall: bool,
}
impl Hdmi for FakeHdmi {
    async fn edid(&mut self, channel: u8) -> Result<Vec<u8>, ddc::Error> {
        self.channels.push(channel);
        if self.stall {
            core::future::pending::<()>().await;
        }
        self.result.clone()
    }
}
fn mixed_probe() -> Probe {
    let mut hdmi = path(0, 2);
    hdmi.connector = inventory::Connector::HdmiTypeA;
    Probe::new(vec![hdmi, path(1, 3)]).unwrap()
}
fn navi48_display_scans_hdmi_with_native_ddc_and_dp_with_aux() -> TestResult {
    for result in [
        Ok(fake(3).edid),
        Err(ddc::Error::Nack),
        Err(ddc::Error::InvalidEdid),
    ] {
        let mut p = mixed_probe();
        let mut aux = fake(1);
        let mut hdmi = FakeHdmi {
            result: result.clone(),
            channels: Vec::new(),
            stall: false,
        };
        let ports = run(p.scan_with(&mut aux, Some(&mut hdmi))).unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(
            ports[0].sink,
            result
                .map(|edid| Sink {
                    dpcd: None,
                    edid,
                    lttpr: None,
                    uhbr: 0,
                    lttpr_uhbr: None,
                    fec: false,
                })
                .map_err(Error::Ddc)
        );
        assert!(ports[1].sink.as_ref().unwrap().dpcd.is_some());
        assert_eq!(hdmi.channels, [0]);
        assert!(aux.commands.iter().all(|c| c.0 == 1));
        assert_eq!(p.state(), State::Ready);
    }
    let mut hdmi = path(0, 2);
    hdmi.connector = inventory::Connector::HdmiTypeA;
    assert!(Probe::new(vec![hdmi, path(0, 3)]).is_err());
    hdmi.aux = None;
    assert!(Probe::new(vec![hdmi]).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_scans_hdmi_with_native_ddc_and_dp_with_aux
);

fn navi48_display_ddc_fatal_error_or_cancellation_blocks_aux_and_reuse() -> TestResult {
    for error in [
        ddc::Error::Timeout,
        ddc::Error::Revoked,
        ddc::Error::Protocol,
    ] {
        let mut p = mixed_probe();
        let mut aux = fake(1);
        let mut hdmi = FakeHdmi {
            result: Err(error),
            channels: Vec::new(),
            stall: false,
        };
        assert_eq!(
            run(p.scan_with(&mut aux, Some(&mut hdmi))),
            Err(Error::Ddc(error))
        );
        assert_eq!(p.state(), State::Failed(Error::Ddc(error)));
        assert!(aux.commands.is_empty());
        assert_eq!(
            run(p.scan_with(&mut aux, Some(&mut hdmi))),
            Err(Error::Busy)
        );
        assert_eq!(hdmi.channels, [0]);
    }
    let mut p = mixed_probe();
    let mut aux = fake(1);
    let mut hdmi = FakeHdmi {
        result: Ok(fake(1).edid),
        channels: Vec::new(),
        stall: true,
    };
    {
        let mut f = core::pin::pin!(p.scan_with(&mut aux, Some(&mut hdmi)));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(p.state(), State::Scanning);
    assert!(aux.commands.is_empty());
    assert_eq!(
        run(p.scan_with(&mut aux, Some(&mut hdmi))),
        Err(Error::Busy)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_ddc_fatal_error_or_cancellation_blocks_aux_and_reuse
);

/// 128b/132b caps as retrieve_link_cap reads them: 0x2215 only from a sink
/// whose channel coding caps (here the extended copy's 0x2206) offer
/// 128b/132b, and a repeater chain's 0xF0007 rates only from revision 1.4.
fn navi48_display_reads_128b_132b_rates() -> TestResult {
    let scan = |io: &mut Fake| {
        let mut p = probe();
        let ports = run(p.scan_with(io, None::<&mut ddc::Ddc>)).unwrap();
        ports[0].sink.clone().unwrap()
    };
    let mut io = fake(1);
    io.uhbr = 0xff;
    let sink = scan(&mut io);
    if sink.uhbr != 0 || io.commands.iter().any(|c| c.2 == 0x2215) {
        return TestResult::Fail("0x2215 read without 128b/132b coding");
    }
    let mut io = fake(1);
    io.extended[6] = 3;
    io.uhbr = 0x0d;
    let mut caps = [0u8; 10];
    caps[..8].copy_from_slice(&[0x14, 0x1e, 0x80, 0x55, 4, 0, 1, 0x01]);
    io.lttpr = Some(caps);
    let sink = scan(&mut io);
    if sink.uhbr != 5 || sink.lttpr_uhbr != Some(1) || sink.lttpr != Some((0x1e, 4)) {
        return TestResult::Fail("128b/132b rates");
    }
    // A revision 1.3 chain does not bound 128b/132b rates.
    caps[0] = 0x13;
    let mut io = fake(1);
    io.extended[6] = 3;
    io.uhbr = 7;
    io.lttpr = Some(caps);
    if scan(&mut io).lttpr_uhbr.is_some() {
        return TestResult::Fail("old repeater bounds UHBR");
    }
    // DP_FEC_CAPABILITY from DPCD 1.4 on only.
    let mut io = fake(1);
    io.fec = 1;
    io.dpcd[0] = 0x12;
    io.extended[0] = 0x12;
    let old = scan(&mut io);
    let read = io.commands.iter().any(|c| c.2 == 0x90 && c.1 == 0x90);
    let mut io = fake(1);
    io.fec = 1;
    if old.fec || read || !scan(&mut io).fec {
        return TestResult::Fail("FEC capability");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_reads_128b_132b_rates
);
