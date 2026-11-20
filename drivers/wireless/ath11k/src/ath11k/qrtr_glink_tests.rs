//! QRTR over GLINK-SMEM: the remote Q6 is played over a RAM SMEM
//! fixture (`narf_drivers_qcom_soc::fixtures::GlinkRemote`); no IPQ
//! hardware. Expected frames follow `net/qrtr/smd.c` (one QRTR packet
//! per rpmsg message) and `net/qrtr/ns.c` (HELLO answer, NEW_SERVER).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_drivers_qcom_soc::fixtures::{
    glink_data, glink_remote_open, glink_smem_edge, CountingKick, FakeDelay, FakeRegs,
};
use narf_drivers_qcom_soc::glink::*;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use super::super::qmi_client::{QmiClient, QrtrPipe};
use super::super::qrtr::*;
use super::*;

#[derive(Default)]
struct Bus {
    now: AtomicU64,
    waits: AtomicU64,
}

impl GlinkBus for &Bus {
    fn wait_irq(&self, ms: u32) -> impl Future<Output = ()> + Send {
        self.now.fetch_add(ms as u64, Ordering::Relaxed);
        self.waits.fetch_add(1, Ordering::Relaxed);
        core::future::ready(())
    }
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

fn smoke_ath11k_qrtr_over_glink_smem() -> TestResult {
    let regs = FakeRegs::quiet();
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let k = CountingKick::default();
    let bus = Bus::default();
    let (g, r) = glink_smem_edge(&regs, &lr, &d, &k, 1);
    let mut pipe = GlinkQrtr::new(g, &bus);
    // Not open yet: QRTR has no endpoint (`-ENOTCONN`).
    kt_assert_eq!(pipe.send(&[0; 32]), Err(ENOTCONN));
    // The Q6 negotiates and opens IPCRTR (rcid 4), offering a 2 KiB intent.
    let Some(lcid) = glink_remote_open(&mut pipe.glink, &r, QRTR_GLINK_CHANNEL, 4, &[(2048, 1)])
    else {
        return TestResult::Fail("no OPEN");
    };
    let lcid = lcid as u32;
    pipe.poll();
    kt_assert_eq!(pipe.lcid(), Some(lcid));
    r.pop();

    let mut client = QmiClient::new(pipe);
    client.add_lookup(0x45, 1, 0);
    // Device HELLO from node 7 arrives on host intent 1.
    let dev_ctrl = QrtrAddr {
        node: 7,
        port: QRTR_PORT_CTRL,
    };
    let host_ctrl = QrtrAddr {
        node: QRTR_NODE_BCAST,
        port: QRTR_PORT_CTRL,
    };
    let hello = encode_packet(
        QRTR_TYPE_HELLO,
        dev_ctrl,
        host_ctrl,
        false,
        &CtrlPkt::Hello.to_bytes(),
    )
    .unwrap();
    r.push(&glink_data(false, 4, 1, &hello, 0));
    client.pipe.poll();
    client.pump();
    kt_assert!(client.link().hello_seen());
    kt_assert_eq!(client.link().remote_node(), 7);
    // Host answers with its own HELLO as one TX_DATA on the 2 KiB intent,
    // after RX_DONE_W_REUSE for intent 1.
    let out = r.pop();
    let cmds: Vec<u16> = out.iter().map(|c| c.0).collect();
    kt_assert_eq!(
        cmds,
        alloc::vec![GLINK_CMD_RX_DONE_W_REUSE, GLINK_CMD_TX_DATA]
    );
    kt_assert_eq!(out[1].2, 1);
    let frame = &out[1].3[8..];
    let Ok(pkt) = decode_packet(frame) else {
        return TestResult::Fail("bad QRTR frame");
    };
    kt_assert_eq!(pkt.pkt_type, QRTR_TYPE_HELLO);
    kt_assert_eq!(pkt.dst_node, 7);
    // Device announces WLFW (service 0x45, version 1, instance 0).
    r.push(&glink_cmd_rx_done(4, 1));
    let ns = encode_packet(
        QRTR_TYPE_NEW_SERVER,
        dev_ctrl,
        host_ctrl,
        false,
        &CtrlPkt::NewServer {
            service: 0x45,
            instance: qmi_instance(1, 0),
            node: 7,
            port: 1,
        }
        .to_bytes(),
    )
    .unwrap();
    r.push(&glink_data(false, 4, 2, &ns, 0));
    client.pipe.poll();
    client.pump();
    let Some(srv) = client.server() else {
        return TestResult::Fail("no WLFW server");
    };
    kt_assert_eq!((srv.node, srv.port), (7, 1));
    // wait() takes one edge interrupt and services it.
    let waits = bus.waits.load(Ordering::Relaxed);
    narf_drivers_qcom_soc::fixtures::run(client.pipe.wait(5));
    kt_assert_eq!(bus.waits.load(Ordering::Relaxed), waits + 1);
    // Remote closes IPCRTR: endpoint gone, sends refused again.
    r.push(&narf_drivers_qcom_soc::fixtures::glink_cmd(
        GLINK_CMD_CLOSE,
        4,
        0,
        &[],
    ));
    client.pipe.poll();
    kt_assert!(client.pipe.take_closed());
    kt_assert!(!client.pipe.is_open());
    kt_assert_eq!(client.pipe.send(&[0; 32]), Err(ENOTCONN));
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_qrtr_over_glink_smem);

fn glink_cmd_rx_done(rcid: u16, iid: u32) -> Vec<u8> {
    narf_drivers_qcom_soc::fixtures::glink_cmd(GLINK_CMD_RX_DONE_W_REUSE, rcid, iid, &[])
}
