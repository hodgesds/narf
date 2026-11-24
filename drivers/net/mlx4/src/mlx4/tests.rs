//! mlx4 (ConnectX-3) driver smokes — co-located with the driver per
//! project convention; results group under `drivers/net/mlx4`.
//!
//! The device is not emulated by QEMU, so these exercise the pure
//! wire-format halves: the HCR command encoding, the firmware /
//! dev-cap / port decoders, the ICM + INIT_HCA mailbox, the EQ / CQ /
//! QP / MPT contexts, and — the acceptance that matters for this
//! driver — the TX WQE checksum-offload request and the RX CQE
//! checksum decode for TCP and UDP. End-to-end bring-up and live
//! traffic are validated on ConnectX-3 silicon at boot.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{cmd, cq, eq, fw, icm, mr, port, qp, wire, wqe};
use super::{MLX4_DEV_CX3, MLX4_DEV_CX3_PRO, MLX4_VENDOR};

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !($cond) {
            return TestResult::Fail($msg);
        }
    };
}

// ── HCR command encoding ────────────────────────────────────────────

fn smoke_mlx4_go_word_layout() -> TestResult {
    let w = cmd::go_word(cmd::CmdOp::QueryFw, 0, false, false);
    check!(w & cmd::HCR_GO != 0, "GO bit not set");
    check!(w & 0x0fff == 0x004, "opcode not in low 12 bits");
    let w2 = cmd::go_word(cmd::CmdOp::InitHca, 3, true, false);
    check!(w2 & cmd::HCR_TOGGLE != 0, "toggle not set");
    check!((w2 >> cmd::HCR_OPMOD_SHIFT) & 0xf == 3, "op_modifier misplaced");
    check!(w2 & 0x0fff == 0x007, "InitHca opcode wrong");
    TestResult::Pass
}

fn smoke_mlx4_status_decode() -> TestResult {
    // The status byte lives in the top 8 bits of the status dword.
    check!(cmd::status_of(0x1234_5678) == 0x12, "status_of wrong byte");
    check!(cmd::CmdStatus::from_raw(0).is_ok(), "0 not OK");
    check!(cmd::CmdStatus::from_raw(0x03) == cmd::CmdStatus::BadParam, "0x03 != BadParam");
    check!(
        matches!(cmd::CmdStatus::from_raw(0x7f), cmd::CmdStatus::Unknown(0x7f)),
        "unknown not surfaced"
    );
    TestResult::Pass
}

fn smoke_mlx4_is_pending() -> TestResult {
    // GO set ⇒ pending regardless of toggle.
    check!(cmd::is_pending(cmd::HCR_GO, false), "GO should be pending");
    // GO clear, echoed toggle matches posted ⇒ done.
    check!(!cmd::is_pending(0, false), "clear+match should be done");
    check!(!cmd::is_pending(cmd::HCR_TOGGLE, true), "clear+match(1) should be done");
    // GO clear, toggle mismatch ⇒ still pending.
    check!(cmd::is_pending(cmd::HCR_TOGGLE, false), "toggle mismatch pending");
    TestResult::Pass
}

// ── Firmware / dev-cap / adapter decoders ───────────────────────────

fn smoke_mlx4_query_fw_decode() -> TestResult {
    let mut mb = [0u8; 256];
    // fw_pages in the top 16 bits of the word at 0x00.
    wire::put_be16(&mut mb, 0x00, 0x0040);
    wire::put_be16(&mut mb, 0x02, 2); // major
    wire::put_be16(&mut mb, 0x04, 40); // subminor
    wire::put_be16(&mut mb, 0x06, 11); // minor
    wire::put_be16(&mut mb, 0x0a, 3); // cmd iface rev
    let fw = fw::decode_query_fw(&mb);
    check!(fw.fw_pages == 0x40, "fw_pages wrong");
    check!(fw.major == 2 && fw.minor == 11 && fw.subminor == 40, "fw ver wrong");
    check!(fw.cmd_iface_rev == 3, "cmd iface rev wrong");
    TestResult::Pass
}

fn smoke_mlx4_query_dev_cap_decode() -> TestResult {
    let mut mb = [0u8; 256];
    mb[0x37] = 0x01; // num_ports = 1
    mb[0x13] = 0x11; // max_qps log = 0x11 & 0x1f
    mb[0x1b] = 0x10; // max_cqs log
    mb[0x1f] = 0x08; // max_eqs log & 0xf
    wire::put_be16(&mut mb, 0x82, 256); // qpc_entry_sz
    wire::put_be16(&mut mb, 0x8a, 64); // cqc_entry_sz
    wire::put_be16(&mut mb, 0x88, 32); // eqc_entry_sz
    wire::put_be16(&mut mb, 0x90, 8); // mtt_entry_sz
    let dc = fw::decode_query_dev_cap(&mb);
    check!(dc.num_ports == 1, "num_ports wrong");
    check!(dc.log2_max_qps == 0x11, "max_qps wrong");
    check!(dc.qpc_entry_sz == 256, "qpc_entry_sz wrong");
    check!(dc.cqc_entry_sz == 64, "cqc_entry_sz wrong");
    check!(dc.mtt_entry_sz == 8, "mtt_entry_sz wrong");
    TestResult::Pass
}

fn smoke_mlx4_query_adapter_decode() -> TestResult {
    let mut mb = [0u8; 256];
    mb[0x10] = 5; // inta_pin
    mb[0x20] = b'M';
    mb[0x21] = b'T';
    let a = fw::decode_query_adapter(&mb);
    check!(a.inta_pin == 5, "inta_pin wrong");
    check!(&a.board_id[0..2] == b"MT", "board_id wrong");
    TestResult::Pass
}

// ── ICM / INIT_HCA ──────────────────────────────────────────────────

fn smoke_mlx4_vpm_mailbox() -> TestResult {
    let e = [
        icm::VpmEntry { virt: 0x1000, phys: 0xdead_0000 },
        icm::VpmEntry { virt: 0x2000, phys: 0xbeef_0000 },
    ];
    let mb = icm::build_vpm_mailbox(&e);
    check!(mb.len() == 2 * icm::VPM_ENTRY_LEN, "mailbox length wrong");
    check!(wire::get_be64(&mb, 0) == 0x1000, "entry0 virt wrong");
    check!(wire::get_be64(&mb, 8) == 0xdead_0000, "entry0 phys wrong");
    check!(wire::get_be64(&mb, 16) == 0x2000, "entry1 virt wrong");
    TestResult::Pass
}

fn smoke_mlx4_init_hca_layout() -> TestResult {
    let p = icm::InitHcaParams {
        qpc_base: 0x1_0000,
        log_num_qps: 7,
        cqc_base: 0x2_0000,
        log_num_cqs: 7,
        eqc_base: 0x3_0000,
        log_num_eqs: 4,
        mtt_base: 0x4_0000,
        dmpt_base: 0x5_0000,
        log_mpt_sz: 7,
        cmpt_base: 0x6_0000,
        ..icm::InitHcaParams::default()
    };
    let m = icm::build_init_hca(&p);
    check!(m[0x000] == icm::INIT_HCA_VERSION, "version byte wrong");
    // The log-count bytes (at +0x17 / +0x37 / +0x67 of the QPC section)
    // deliberately occupy the low byte of their base's 8-byte field — the
    // packed mlx4 layout, valid because ICM bases are ≥256-byte aligned.
    // So mask the low byte when checking the base, and check the log byte
    // separately.
    const BASE_MASK: u64 = 0xffff_ffff_ffff_ff00;
    check!(wire::get_be64(&m, 0x030) & BASE_MASK == 0x1_0000, "qpc_base misplaced");
    check!(m[0x037] == 7, "log_num_qps misplaced");
    check!(wire::get_be64(&m, 0x050) & BASE_MASK == 0x2_0000, "cqc_base misplaced");
    check!(m[0x057] == 7, "log_num_cqs misplaced");
    check!(wire::get_be64(&m, 0x080) & BASE_MASK == 0x3_0000, "eqc_base misplaced");
    check!(m[0x087] == 4, "log_num_eqs misplaced");
    check!(wire::get_be64(&m, 0x100) == 0x4_0000, "mtt_base misplaced");
    check!(wire::get_be64(&m, 0x0f0) == 0x5_0000, "dmpt_base misplaced");
    check!(wire::get_be64(&m, 0x108) == 0x6_0000, "cmpt_base misplaced");
    TestResult::Pass
}

fn smoke_mlx4_icm_layout_consistency() -> TestResult {
    let dc = fw::DevCap {
        qpc_entry_sz: 256,
        cqc_entry_sz: 128,
        eqc_entry_sz: 64,
        mtt_entry_sz: 8,
        dmpt_entry_sz: 64,
        cmpt_entry_sz: 64,
        auxc_entry_sz: 64,
        altc_entry_sz: 64,
        rdmarc_entry_sz: 32,
        ..fw::DevCap::default()
    };
    let counts = icm::IcmCounts::default();
    let l = icm::make_layout(&dc, &counts);
    // Regions must be page-aligned and non-overlapping / monotonic.
    let regions = l.regions();
    let mut last_end = 0u64;
    for (base, size) in regions {
        check!(base % icm::ICM_PAGE_SIZE == 0, "region base not page aligned");
        check!(base >= last_end, "regions overlap / not monotonic");
        last_end = base + size;
    }
    check!(l.total >= last_end, "total smaller than packed regions");
    // init_hca params derived from the layout agree with the regions.
    let p = l.init_hca_params(&counts, 0, 0);
    check!(p.qpc_base == l.qpc.base, "qpc base mismatch");
    check!(p.mtt_base == l.mtt.base, "mtt base mismatch");
    TestResult::Pass
}

// ── Memory region ───────────────────────────────────────────────────

fn smoke_mlx4_mtt_and_key() -> TestResult {
    check!(mr::mtt_entry(0x1000) == 0x1001, "mtt present bit missing");
    // key swizzle is an exact inverse pair.
    for ind in [0u32, 1, 0x0000_00ff, 0x00ab_cdef, 0x1234_5678] {
        let k = mr::hw_index_to_key(ind);
        check!(mr::key_to_hw_index(k) == ind, "key swizzle not invertible");
    }
    TestResult::Pass
}

fn smoke_mlx4_mpt_layout() -> TestResult {
    let m = mr::build_mpt(&mr::MptParams {
        pd: 0,
        access: mr::MLX4_PERM_LOCAL_READ | mr::MLX4_PERM_LOCAL_WRITE,
        key: mr::hw_index_to_key(0x10),
        start: 0,
        length: u64::MAX,
        mtt_addr: 0,
        page_shift: 12,
        physical: true,
    });
    let flags = wire::get_be32(&m, 0x00);
    check!(flags & mr::MLX4_MPT_FLAG_MIO != 0, "MIO not set");
    check!(flags & mr::MLX4_MPT_FLAG_REGION != 0, "REGION not set");
    check!(flags & mr::MLX4_MPT_FLAG_PHYSICAL != 0, "PHYSICAL not set for physical MR");
    check!(wire::get_be64(&m, 0x18) == u64::MAX, "length misplaced");
    check!(wire::get_be32(&m, 0x38) == 12, "entity_size (page shift) misplaced");
    TestResult::Pass
}

// ── EQ / CQ contexts + completions ──────────────────────────────────

fn smoke_mlx4_eq_context() -> TestResult {
    let c = eq::build_eq_context(&eq::EqParams {
        log_eq_size: 6,
        intr: 0,
        mtt_base: 0x1_2345_0000,
        log_page_size: 0,
    });
    check!(wire::get_be32(&c, 0x00) == 0x0000_0900, "status/state flags wrong");
    check!(c[0x0c] == 6, "log_eq_size misplaced");
    check!(c[0x1b] == 0x01, "mtt_base high byte misplaced");
    check!(wire::get_be32(&c, 0x1c) == 0x2345_0000, "mtt_base low misplaced");
    TestResult::Pass
}

fn smoke_mlx4_eqe_decode() -> TestResult {
    let mut e = [0u8; 32];
    e[0x01] = 0x09; // PORT_CHANGE
    wire::put_be32(&mut e, 0x04, 1u32 << 28); // port 1
    e[0x1f] = 0x80; // owner bit set
    let v = eq::decode_eqe(&e);
    check!(v.event_type == 0x09, "event type wrong");
    check!(v.port == 1, "port decode wrong");
    // owner=1, cons=0, nent=64 ⇒ phase 0 ⇒ owned==phase false ⇒ not SW-owned.
    check!(!eq::eqe_is_sw_owned(0x80, 0, 64), "owner phase wrong");
    check!(eq::eqe_is_sw_owned(0x00, 0, 64), "sw-owned phase wrong");
    check!(eq::eq_doorbell_word(5, true) == (5 | (1 << 31)), "doorbell word wrong");
    TestResult::Pass
}

fn smoke_mlx4_cq_context() -> TestResult {
    let c = cq::build_cq_context(&cq::CqParams {
        log_cq_size: 7,
        uar_index: 128,
        mtt_base: 0x9_0000,
        log_page_size: 0,
        comp_eqn: 0,
        db_rec_addr: 0xabcd_0000,
    });
    check!(wire::get_be32(&c, 0x0c) == (7 << 24) | 128, "logsize_usrpage wrong");
    check!(c[0x17] == 0, "comp_eqn misplaced");
    check!(wire::get_be64(&c, 0x38) == 0xabcd_0000, "db_rec_addr misplaced");
    TestResult::Pass
}

fn smoke_mlx4_cqe_ownership() -> TestResult {
    // owner bit matches consumer phase ⇒ sw-owned.
    check!(cq::cqe_is_sw_owned(0x00, 0, 128), "phase0 owned");
    check!(!cq::cqe_is_sw_owned(0x80, 0, 128), "phase0 hw-owned");
    check!(cq::cqe_is_sw_owned(0x80, 128, 128), "phase1 owned");
    TestResult::Pass
}

// ── QP context ──────────────────────────────────────────────────────

fn smoke_mlx4_qp_context() -> TestResult {
    let c = qp::build_qp_context(&qp::QpEthParams {
        pd: 0,
        uar_index: 128,
        cqn_send: 0,
        cqn_recv: 0,
        mtt_base: 0x1_0000,
        log_page_size: 0,
        log_rq_size: 5,
        log_rq_stride: 4,
        log_sq_size: 4,
        log_sq_stride: 6,
        port: 1,
        db_rec_addr: 0x8,
    });
    check!(qp::decode_service_type(&c) == 7, "service type not MLX(7)");
    check!(c[0x08] == 0xff, "mtu_msgmax not 0xff");
    check!(c[0x25] == 0x83, "sched_queue port-1 wrong");
    // RST→INIT stamps the Init state nibble in flags[31:28].
    let mb = qp::build_modify_mailbox(&c, qp::QpTransition::RstToInit, 0);
    check!(mb.len() == 8 + qp::QP_CONTEXT_LEN, "modify mailbox length");
    let flags = wire::get_be32(&mb, 8);
    check!((flags >> 28) & 0xf == qp::QpState::Init as u32, "state nibble not Init");
    TestResult::Pass
}

// ── Port ────────────────────────────────────────────────────────────

fn smoke_mlx4_set_port_general() -> TestResult {
    let m = port::build_set_port_general(1522);
    check!(m[0x03] == port::SET_PORT_GEN_ALL_VALID, "validity flags misplaced");
    check!(wire::get_be16(&m, 0x06) == 1522, "mtu misplaced");
    TestResult::Pass
}

fn smoke_mlx4_mac_table_and_roundtrip() -> TestResult {
    let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    check!(port::u64_to_mac(port::mac_to_u64(mac)) == mac, "mac round-trip");
    let mb = port::build_mac_table(&[mac], 1);
    let v = wire::get_be64(&mb, 0);
    check!(v & port::MLX4_MAC_VALID != 0, "mac valid bit");
    check!(v & port::MLX4_MAC_MASK == port::mac_to_u64(mac), "mac bytes");
    TestResult::Pass
}

fn smoke_mlx4_query_port_decode() -> TestResult {
    let mut mb = [0u8; 0x40];
    mb[0x00] = 0x80; // link up
    wire::put_be16(&mut mb, 0x02, 1500); // mtu
    mb[0x05] = 0x02; // 1G
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    wire::put_be64(&mut mb, 0x10, port::mac_to_u64(mac));
    let pi = port::decode_query_port(&mb);
    check!(pi.link_up, "link_up decode");
    check!(pi.eth_mtu == 1500, "mtu decode");
    check!(pi.mac == mac, "mac decode");
    check!(pi.speed_mbps == Some(1000), "speed decode");
    TestResult::Pass
}

// ── TX / RX datapath: the TCP/UDP acceptance ────────────────────────

fn smoke_mlx4_tx_wqe_tcp_udp_csum() -> TestResult {
    // A send WQE that requests checksum offload must set both the IP
    // and the L4 (TCP/UDP) checksum bits, carry a completion request,
    // and point its data segment at the staging buffer.
    let w = wqe::build_tx_wqe(true, true, 0xdead_beef_0000, 0x1234, 1514);
    let flags = wqe::wqe_srcrb_flags(&w);
    check!(flags & wqe::CTRL_IP_CSUM != 0, "IP csum not requested");
    check!(flags & wqe::CTRL_TCP_UDP_CSUM != 0, "L4 (TCP/UDP) csum not requested");
    check!(flags & wqe::CTRL_CQ_UPDATE != 0, "completion not requested");
    let oo = wqe::wqe_owner_opcode(&w);
    check!(oo & wqe::DESC_OWN != 0, "owner bit not set");
    check!(oo & 0x7f == wqe::OPCODE_SEND, "opcode not SEND");
    // Data segment: byte_count / lkey / addr.
    check!(wire::get_be32(&w, 0x10) == 1514, "data byte_count wrong");
    check!(wire::get_be32(&w, 0x14) == 0x1234, "data lkey wrong");
    check!(wire::get_be64(&w, 0x18) == 0xdead_beef_0000, "data addr wrong");
    // A plain (no-offload) send leaves the csum bits clear.
    let w2 = wqe::build_tx_wqe(false, false, 0, 0, 60);
    let f2 = wqe::wqe_srcrb_flags(&w2);
    check!(f2 & (wqe::CTRL_IP_CSUM | wqe::CTRL_TCP_UDP_CSUM) == 0, "csum set without request");
    check!(wqe::wqe_owner_opcode(&w2) & wqe::DESC_OWN == 0, "owner set without phase");
    check!(wqe::tx_doorbell_word(0x40) == 0x40 << 8, "tx doorbell word wrong");
    TestResult::Pass
}

fn smoke_mlx4_rx_cqe_tcp_csum_ok() -> TestResult {
    // A TCP RX completion with IP-OK and a folded checksum of 0xffff
    // reports the L4 checksum verified.
    let mut c = [0u8; 32];
    wire::put_be32(&mut c, 0x00, 0x40); // qpn
    wire::put_be16(&mut c, 0x10, cq::CQE_STATUS_TCP | cq::CQE_STATUS_IPV4 | cq::CQE_STATUS_IPOK);
    wire::put_be16(&mut c, 0x1a, 0xffff); // checksum
    wire::put_be32(&mut c, 0x14, 1480); // byte_cnt
    wire::put_be16(&mut c, 0x18, 3); // wqe_index
    c[0x1f] = 0x00; // receive (not send), sw-owned at phase 0
    let v = cq::decode_cqe(&c);
    check!(!v.is_send, "should be an RX completion");
    check!(v.qpn == 0x40, "qpn decode");
    check!(v.byte_cnt == 1480, "byte_cnt decode");
    check!(v.wqe_index == 3, "wqe_index decode");
    check!(v.ip_csum_ok(), "IP csum should be OK");
    check!(v.l4_csum_ok(), "TCP L4 csum should be OK");
    TestResult::Pass
}

fn smoke_mlx4_rx_cqe_udp_csum_ok() -> TestResult {
    let mut c = [0u8; 32];
    wire::put_be16(&mut c, 0x10, cq::CQE_STATUS_UDP | cq::CQE_STATUS_IPV4 | cq::CQE_STATUS_IPOK);
    wire::put_be16(&mut c, 0x1a, 0xffff);
    let v = cq::decode_cqe(&c);
    check!(v.l4_csum_ok(), "UDP L4 csum should be OK");
    // A non-0xffff folded checksum means the stack must re-verify.
    let mut c2 = c;
    wire::put_be16(&mut c2, 0x1a, 0x1234);
    check!(!cq::decode_cqe(&c2).l4_csum_ok(), "partial csum must not claim OK");
    // A bad-FCS completion is flagged for drop.
    let mut c3 = c;
    c3[0x13] = cq::CQE_BAD_FCS;
    check!(cq::decode_cqe(&c3).bad_fcs(), "bad FCS not flagged");
    TestResult::Pass
}

fn smoke_mlx4_rx_wqe() -> TestResult {
    let w = wqe::build_rx_wqe(0xcafe_0000, 0x1234, 2048);
    check!(wire::get_be32(&w, 0x00) == 2048, "rx byte_count wrong");
    check!(wire::get_be32(&w, 0x04) == 0x1234, "rx lkey wrong");
    check!(wire::get_be64(&w, 0x08) == 0xcafe_0000, "rx addr wrong");
    check!(wqe::rx_prod_doorbell_word(0x1_2345u32) == 0x2345, "rx prod db masks to 16 bits");
    TestResult::Pass
}

fn smoke_mlx4_tx_slot_pool() -> TestResult {
    // Claim / record / release recycles exactly the WQE's slot.
    let mut p = super::TxSlotPool::new();
    let s0 = p.claim().expect("slot 0");
    p.record(0, s0);
    let s1 = p.claim().expect("slot 1");
    p.record(1, s1);
    check!(s0 != s1, "distinct slots");
    check!(p.release(0) == Some(s0), "release returns recorded slot");
    check!(p.claim() == Some(s0), "freed slot reclaimed");
    TestResult::Pass
}

// ── PCI match table ─────────────────────────────────────────────────

fn smoke_mlx4_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let drivers = registered_pci_drivers();
    for &did in [MLX4_DEV_CX3, MLX4_DEV_CX3_PRO].iter() {
        let found = drivers.iter().any(|d| match d.kind {
            MatchKind::VendorDevice { vendor, device } => vendor == MLX4_VENDOR && device == did,
            _ => false,
        });
        if !found {
            return TestResult::Fail("ConnectX-3 device id missing from PCI match table");
        }
    }
    __reset_for_test();
    TestResult::Pass
}

kernel_test_in!("drivers/net/mlx4", smoke_mlx4_go_word_layout);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_status_decode);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_is_pending);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_query_fw_decode);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_query_dev_cap_decode);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_query_adapter_decode);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_vpm_mailbox);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_init_hca_layout);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_icm_layout_consistency);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_mtt_and_key);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_mpt_layout);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_eq_context);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_eqe_decode);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_cq_context);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_cqe_ownership);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_qp_context);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_set_port_general);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_mac_table_and_roundtrip);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_query_port_decode);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_tx_wqe_tcp_udp_csum);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_rx_cqe_tcp_csum_ok);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_rx_cqe_udp_csum_ok);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_rx_wqe);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_tx_slot_pool);
kernel_test_in!("drivers/net/mlx4", smoke_mlx4_pci_match_table);
