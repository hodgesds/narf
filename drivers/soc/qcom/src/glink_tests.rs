//! GLINK-SMEM smokes. The remote is played by [`GlinkRemote`] over a RAM
//! SMEM region; expected wire bytes come from `qcom_glink_native.c` /
//! `qcom_glink_smem.c` (command layouts, intent and RX_DONE rules), not
//! from the code under test. No Qualcomm hardware is involved.

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use crate::fixtures::*;
use crate::glink::*;

type Cmd = (u16, u16, u32, Vec<u8>);

fn cmds(v: &[Cmd]) -> Vec<u16> {
    v.iter().map(|c| c.0).collect()
}

fn drain_events<P: GlinkPipe>(g: &mut Glink<P>) -> Vec<GlinkEvent> {
    let mut v = Vec::new();
    while let Some(e) = g.take_event() {
        v.push(e);
    }
    v
}

fn smoke_qcom_glink_smem_register_and_version() -> TestResult {
    let regs = FakeRegs::quiet();
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let k = CountingKick::default();
    let (mut g, r) = glink_smem_edge(&regs, &lr, &d, &k, 1);
    // Descriptor is 32 bytes, TX FIFO 16 KiB; rx tail / tx head zeroed.
    kt_assert_eq!(r.host_tx.1, GLINK_SMEM_TX_FIFO_SIZE);
    kt_assert_eq!(regs.get(r.desc + 4), 8);
    kt_assert_eq!(regs.get(r.desc + 8), 0);
    // `qcom_glink_send_version`: VERSION v1 with INTENT_REUSE, kicked.
    kt_assert_eq!(k.count(), 1);
    let out = r.pop();
    kt_assert_eq!(out.len(), 1);
    kt_assert_eq!(out[0].0, GLINK_CMD_VERSION);
    kt_assert_eq!(out[0].1, 1);
    kt_assert_eq!(out[0].2, GLINK_FEATURE_INTENT_REUSE);
    // TX avail holds back FIFO_FULL_RESERVE + TX_BLOCKED_CMD_RESERVE.
    kt_assert_eq!(g.pipe().tx_avail(), 16 * 1024 - 16);
    // Remote VERSION with no features → features &= 0, VERSION_ACK.
    r.push(&glink_cmd(GLINK_CMD_VERSION, 1, 0, &[]));
    g.process_rx();
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_VERSION_ACK]);
    kt_assert_eq!(out[0].2, 0);
    kt_assert_eq!(g.features(), 0);
    kt_assert_eq!(
        drain_events(&mut g),
        vec![GlinkEvent::Negotiated { features: 0 }]
    );
    // VERSION_ACK with different features → narrowed and re-sent.
    let (mut g2, r2) = {
        let regs2 = alloc::boxed::Box::leak(alloc::boxed::Box::new(FakeRegs::quiet()));
        let lr2 = alloc::boxed::Box::leak(alloc::boxed::Box::new(FakeRegs::new()));
        let d2 = alloc::boxed::Box::leak(alloc::boxed::Box::new(FakeDelay::new()));
        let k2 = alloc::boxed::Box::leak(alloc::boxed::Box::new(CountingKick::default()));
        glink_smem_edge(regs2, lr2, d2, k2, 1)
    };
    r2.pop();
    r2.push(&glink_cmd(GLINK_CMD_VERSION_ACK, 1, 0, &[]));
    g2.process_rx();
    let out = r2.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_VERSION]);
    kt_assert_eq!(out[0].2, 0);
    r2.push(&glink_cmd(GLINK_CMD_VERSION_ACK, 1, 0, &[]));
    g2.process_rx();
    kt_assert!(g2.negotiated());
    kt_assert!(r2.pop().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/soc/qcom",
    smoke_qcom_glink_smem_register_and_version
);

fn smoke_qcom_glink_remote_open_and_rx() -> TestResult {
    let regs = FakeRegs::quiet();
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let k = CountingKick::default();
    let (mut g, r) = glink_smem_edge(&regs, &lr, &d, &k, 1);
    r.pop();
    // Unclaimed remote OPEN: recorded, nothing sent, RemoteOpen event.
    let nm = b"IPCRTR\0";
    // param2 = prio << 16 | name length; the priority is ignored.
    r.push(&glink_cmd(
        GLINK_CMD_OPEN,
        3,
        (2 << 16) | nm.len() as u32,
        nm,
    ));
    g.process_rx();
    kt_assert!(r.pop().is_empty());
    kt_assert_eq!(
        drain_events(&mut g),
        vec![GlinkEvent::RemoteOpen {
            name: "IPCRTR".into()
        }]
    );
    // Driver binds: OPEN_ACK(rcid) then OPEN(lcid=1, name).
    g.accept("IPCRTR", &GLINK_DEFAULT_INTENTS).unwrap();
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_OPEN_ACK, GLINK_CMD_OPEN]);
    kt_assert_eq!(out[0].1, 3);
    kt_assert_eq!(out[1].1, 1);
    kt_assert_eq!(out[1].2, 7);
    kt_assert_eq!(&out[1].3[..], &nm[..]);
    kt_assert!(!g.is_open(1));
    // Remote OPEN_ACK → five reusable 1 KiB intents, ids 1..=5.
    r.push(&glink_cmd(GLINK_CMD_OPEN_ACK, 1, 0, &[]));
    g.process_rx();
    let out = r.pop();
    kt_assert_eq!(out.len(), 5);
    for (i, c) in out.iter().enumerate() {
        kt_assert_eq!(c.0, GLINK_CMD_INTENT);
        kt_assert_eq!(c.1, 1);
        kt_assert_eq!(c.2, 1);
        kt_assert_eq!(&c.3[..4], &1024u32.to_le_bytes()[..]);
        kt_assert_eq!(&c.3[4..], &(i as u32 + 1).to_le_bytes()[..]);
    }
    kt_assert_eq!(
        drain_events(&mut g),
        vec![GlinkEvent::Open {
            lcid: 1,
            name: "IPCRTR".into()
        }]
    );
    kt_assert_eq!(g.lcid_of("IPCRTR"), Some(1));
    // Single-chunk message on intent 2 → Data + RX_DONE_W_REUSE(lcid, 2).
    r.push(&glink_data(false, 3, 2, b"hello", 0));
    g.process_rx();
    kt_assert_eq!(
        drain_events(&mut g),
        vec![GlinkEvent::Data {
            lcid: 1,
            data: b"hello".to_vec()
        }]
    );
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_RX_DONE_W_REUSE]);
    kt_assert_eq!((out[0].1, out[0].2), (1, 2));
    // Fragmented: header-only partial (payload not yet in FIFO) waits.
    let a: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
    let first = glink_data(false, 3, 4, &a, 300);
    r.push(&first[..16]);
    g.process_rx();
    kt_assert!(r.pop().is_empty());
    kt_assert!(g.take_event().is_none());
    r.push(&first[16..]);
    r.push(&glink_data(true, 3, 4, &b, 0));
    g.process_rx();
    let mut want = a.clone();
    want.extend_from_slice(&b);
    kt_assert_eq!(
        drain_events(&mut g),
        vec![GlinkEvent::Data {
            lcid: 1,
            data: want
        }]
    );
    // Wrap the 16 KiB RX FIFO several times with 1000-byte messages.
    for n in 0..40u32 {
        let msg: Vec<u8> = (0..1000u32).map(|i| (i + n) as u8).collect();
        r.push(&glink_data(false, 3, 1 + n % 5, &msg, 0));
        g.process_rx();
        match g.take_event() {
            Some(GlinkEvent::Data { lcid: 1, data }) if data == msg => {}
            _ => return TestResult::Fail("wrapped RX message mismatch"),
        }
        r.pop();
    }
    // Chunk larger than the intent: dropped, counted.
    r.push(&glink_data(false, 3, 1, &[0u8; 1100], 0));
    g.process_rx();
    kt_assert!(g.take_event().is_none());
    kt_assert_eq!(g.stats.intent_overflow, 1);
    // Unknown liid and unknown rcid: dropped, counted, FIFO advanced.
    r.push(&glink_data(false, 3, 99, b"x", 0));
    r.push(&glink_data(false, 9, 1, b"x", 0));
    g.process_rx();
    kt_assert_eq!(g.stats.no_intent, 1);
    kt_assert_eq!(g.stats.unknown_channel, 1);
    kt_assert_eq!(g.pipe_mut().rx_avail(), 0);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_glink_remote_open_and_rx);

fn smoke_qcom_glink_tx_intents() -> TestResult {
    let regs = FakeRegs::quiet();
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let k = CountingKick::default();
    let (mut g, r) = glink_smem_edge(&regs, &lr, &d, &k, 1);
    g.accept("IPCRTR", &[(2048, 1)]).unwrap();
    let lcid = glink_remote_open(&mut g, &r, "IPCRTR", 5, &[(1024, 7), (512, 8)]).unwrap() as u32;
    kt_assert!(g.is_open(lcid));
    r.pop();
    drain_events(&mut g);
    // Smallest fitting intent: 100 bytes → iid 8 (512).
    g.send(lcid, &[0xab; 100]).unwrap();
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_TX_DATA]);
    kt_assert_eq!((out[0].1 as u32, out[0].2), (lcid, 8));
    kt_assert_eq!(&out[0].3[..8], &[100, 0, 0, 0, 0, 0, 0, 0][..]);
    kt_assert_eq!(&out[0].3[8..], &[0xab; 100][..]);
    // 800 bytes → iid 7; a further 800 finds none → RX_INTENT_REQ(800).
    g.send(lcid, &[1; 800]).unwrap();
    g.send(lcid, &[2; 800]).unwrap();
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_TX_DATA, GLINK_CMD_RX_INTENT_REQ]);
    kt_assert_eq!(out[0].2, 7);
    kt_assert_eq!((out[1].1 as u32, out[1].2), (lcid, 800));
    // Only one request outstanding.
    g.service_tx();
    kt_assert!(r.pop().is_empty());
    // Remote grants: INTENT(1024, 9) then REQ_ACK(1) → data on 9.
    let mut body = Vec::new();
    body.extend_from_slice(&1024u32.to_le_bytes());
    body.extend_from_slice(&9u32.to_le_bytes());
    r.push(&glink_cmd(GLINK_CMD_INTENT, 5, 1, &body));
    r.push(&glink_cmd(GLINK_CMD_RX_INTENT_REQ_ACK, 5, 1, &[]));
    g.process_rx();
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_TX_DATA]);
    kt_assert_eq!(out[0].2, 9);
    // RX_DONE_W_REUSE(8) frees 8; RX_DONE(9) drops 9.
    r.push(&glink_cmd(GLINK_CMD_RX_DONE_W_REUSE, 5, 8, &[]));
    r.push(&glink_cmd(GLINK_CMD_RX_DONE, 5, 9, &[]));
    g.process_rx();
    kt_assert_eq!(g.remote_intents(lcid), vec![(512, 8)]);
    // Refused request drops the message (SendFailed).
    g.send(lcid, &[3; 900]).unwrap();
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_RX_INTENT_REQ]);
    r.push(&glink_cmd(GLINK_CMD_RX_INTENT_REQ_ACK, 5, 0, &[]));
    g.process_rx();
    kt_assert_eq!(
        drain_events(&mut g),
        vec![GlinkEvent::SendFailed { lcid, len: 900 }]
    );
    // > 8 KiB: TX_DATA(8192, left 808) + TX_DATA_CONT(808, 0) on one iid.
    let mut body = Vec::new();
    body.extend_from_slice(&16384u32.to_le_bytes());
    body.extend_from_slice(&20u32.to_le_bytes());
    r.push(&glink_cmd(GLINK_CMD_INTENT, 5, 1, &body));
    g.process_rx();
    let big: Vec<u8> = (0..9000u32).map(|i| i as u8).collect();
    g.send(lcid, &big).unwrap();
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_TX_DATA, GLINK_CMD_TX_DATA_CONT]);
    kt_assert_eq!((out[0].2, out[1].2), (20, 20));
    kt_assert_eq!(&out[0].3[..8], &[0, 32, 0, 0, 0x28, 3, 0, 0][..]);
    kt_assert_eq!(&out[1].3[..8], &[0x28, 3, 0, 0, 0, 0, 0, 0][..]);
    let mut got = out[0].3[8..].to_vec();
    got.extend_from_slice(&out[1].3[8..]);
    kt_assert_eq!(got, big);
    // Not-open / too-big refusals.
    kt_assert_eq!(g.send(77, b"x"), Err(GlinkError::NoChannel(77)));
    kt_assert_eq!(g.send(lcid, &[]), Err(GlinkError::TooBig(0)));
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_glink_tx_intents);

fn smoke_qcom_glink_intent_req_backpressure_close() -> TestResult {
    let regs = FakeRegs::quiet();
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let k = CountingKick::default();
    let (mut g, r) = glink_smem_edge(&regs, &lr, &d, &k, 1);
    g.accept("IPCRTR", &[]).unwrap();
    let lcid = glink_remote_open(&mut g, &r, "IPCRTR", 2, &[(8192, 1)]).unwrap() as u32;
    r.pop();
    drain_events(&mut g);
    // Remote asks for a 4 KiB intent → INTENT(4096, one-shot) + ACK(1).
    r.push(&glink_cmd(GLINK_CMD_RX_INTENT_REQ, 2, 4096, &[]));
    g.process_rx();
    let out = r.pop();
    kt_assert_eq!(
        cmds(&out),
        vec![GLINK_CMD_INTENT, GLINK_CMD_RX_INTENT_REQ_ACK]
    );
    let liid = u32::from_le_bytes([out[0].3[4], out[0].3[5], out[0].3[6], out[0].3[7]]);
    kt_assert_eq!(&out[0].3[..4], &4096u32.to_le_bytes()[..]);
    kt_assert_eq!((out[1].1 as u32, out[1].2), (lcid, 1));
    // Data on it → RX_DONE (not reuse); the intent is gone afterwards.
    r.push(&glink_data(false, 2, liid, &[5; 3000], 0));
    g.process_rx();
    kt_assert_eq!(drain_events(&mut g).len(), 1);
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_RX_DONE]);
    kt_assert_eq!(out[0].2, liid);
    r.push(&glink_data(false, 2, liid, &[5; 8], 0));
    g.process_rx();
    kt_assert_eq!(g.stats.no_intent, 1);
    // Back-pressure: fill the FIFO without the remote draining it.
    let kicks = k.count();
    for _ in 0..3 {
        g.send(lcid, &[9; 7000]).unwrap();
        // Remote immediately frees the intent so only the FIFO limits.
        r.push(&glink_cmd(GLINK_CMD_RX_DONE_W_REUSE, 2, 1, &[]));
        g.process_rx();
    }
    kt_assert!(g.tx_backlog() > 0);
    kt_assert_eq!(g.stats.read_notify_sent, 1);
    kt_assert!(k.count() > kicks);
    // Remote drains and interrupts; the backlog goes out.
    let out = r.pop();
    kt_assert_eq!(*cmds(&out).last().unwrap(), GLINK_CMD_READ_NOTIF);
    g.process_rx();
    kt_assert_eq!(g.tx_backlog(), 0);
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_TX_DATA]);
    // Remote READ_NOTIF → host kicks.
    let kicks = k.count();
    r.push(&glink_cmd(GLINK_CMD_READ_NOTIF, 0, 0, &[]));
    g.process_rx();
    kt_assert_eq!(k.count(), kicks + 1);
    // SIGNALS → Flow event.
    r.push(&glink_cmd(GLINK_CMD_SIGNALS, 2, NATIVE_CTS_SIG, &[]));
    g.process_rx();
    kt_assert_eq!(
        drain_events(&mut g),
        vec![GlinkEvent::Flow { lcid, enable: true }]
    );
    // Remote CLOSE → CLOSE_ACK(rcid) + CLOSE(lcid); Closed event.
    r.push(&glink_cmd(GLINK_CMD_CLOSE, 2, 0, &[]));
    g.process_rx();
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_CLOSE_ACK, GLINK_CMD_CLOSE]);
    kt_assert_eq!((out[0].1, out[1].1 as u32), (2, lcid));
    kt_assert_eq!(
        drain_events(&mut g),
        vec![GlinkEvent::Closed {
            lcid,
            name: "IPCRTR".into()
        }]
    );
    kt_assert!(!g.is_open(lcid));
    kt_assert_eq!(g.send(lcid, b"x"), Err(GlinkError::NotOpen(lcid)));
    r.push(&glink_cmd(GLINK_CMD_CLOSE_ACK, lcid as u16, 0, &[]));
    g.process_rx();
    kt_assert_eq!(g.send(lcid, b"x"), Err(GlinkError::NoChannel(lcid)));
    // Unknown command stops the loop without consuming it.
    r.push(&glink_cmd(10, 0, 0, &[]));
    g.process_rx();
    kt_assert_eq!(g.stats.unknown_cmd, 1);
    kt_assert_eq!(g.pipe_mut().rx_avail(), 8);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/soc/qcom",
    smoke_qcom_glink_intent_req_backpressure_close
);

fn smoke_qcom_glink_local_open() -> TestResult {
    let regs = FakeRegs::quiet();
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let k = CountingKick::default();
    let (mut g, r) = glink_smem_edge(&regs, &lr, &d, &k, 1);
    r.pop();
    // `qcom_glink_create_local`: OPEN first, OPEN_ACK only after both
    // the remote's OPEN_ACK and its OPEN.
    let lcid = g.open("rpm_requests", &[(512, 2)]).unwrap();
    let out = r.pop();
    kt_assert_eq!(cmds(&out), vec![GLINK_CMD_OPEN]);
    kt_assert_eq!(out[0].1 as u32, lcid);
    r.push(&glink_cmd(GLINK_CMD_OPEN_ACK, lcid as u16, 0, &[]));
    g.process_rx();
    kt_assert!(r.pop().is_empty());
    let nm = b"rpm_requests\0";
    r.push(&glink_cmd(GLINK_CMD_OPEN, 6, nm.len() as u32, nm));
    g.process_rx();
    let out = r.pop();
    kt_assert_eq!(
        cmds(&out),
        vec![GLINK_CMD_OPEN_ACK, GLINK_CMD_INTENT, GLINK_CMD_INTENT]
    );
    kt_assert_eq!(out[0].1, 6);
    kt_assert!(g.is_open(lcid));
    // Names must fit GLINK_NAME_SIZE with the NUL.
    kt_assert_eq!(
        g.open("0123456789abcdef0123456789abcdef", &[]),
        Err(GlinkError::BadName)
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_glink_local_open);
