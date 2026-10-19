//! Per-peer REO queue and REO command tests.
//!
//! Expected values are hand-derived from Linux
//! `drivers/net/wireless/ath/ath11k/{dp.c,dp_rx.c,dp_tx.c,hal_rx.c,
//! hal.h,hal_desc.h,hal_rx.h,dp.h,wmi.c,wmi.h,core.h}`, not from the code
//! under test. The device side reads the REO command ring the host
//! programmed (base / size / entry-size registers in [`RecIo`], the HP
//! through its QMI shadow register) and writes REO status entries, in the
//! host's real DMA32 memory by physical address.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::ce::CeMsi;
use super::dp_peer::step;
use super::dp_peer::*;
use super::dp_ring::*;
use super::hal::*;
use super::hal_tests::{RecIo, WCN6855_SHADOW_REG_V2};
use super::hw::*;
use super::wmi::WmiCmd;

macro_rules! check {
    ($cond:expr, $msg:literal) => {
        if !($cond) {
            return TestResult::Fail($msg);
        }
    };
}

// ── the device side ───────────────────────────────────────────────

fn phys_rd32(pa: u64) -> u32 {
    // SAFETY: `pa` lies inside a live DMA32 coherent buffer the DP / HAL
    // under test owns (a ring, the pointer area or a queue descriptor
    // still held by the DP); the kernel direct map covers it and it is
    // 4-byte aligned.
    unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(pa).kernel_ptr::<u32>()) }
}

fn phys_wr32(pa: u64, v: u32) {
    // SAFETY: as `phys_rd32`; the model only writes words the hardware
    // owns (status entries it produces, its ring pointer).
    unsafe { core::ptr::write_volatile(narf_memory::PhysAddr::new(pa).kernel_mut_ptr::<u32>(), v) }
}

const SHADOW_BASE: u32 = 0x8fc;

fn shadow_of(target: u32) -> u32 {
    let i = WCN6855_SHADOW_REG_V2
        .iter()
        .position(|&t| t == target)
        .expect("ring pointer register in the shadow list");
    SHADOW_BASE + 4 * i as u32
}

/// One UMAC ring as the hardware sees it (`idx` = the device's pointer,
/// in words).
struct DevRing {
    base: u64,
    size: u32,
    esz: u32,
    hw_ptr: u64,
    host_reg: u32,
    idx: u32,
}

impl DevRing {
    fn publish(&self) {
        phys_wr32(self.hw_ptr, self.idx);
    }

    /// SRC ring: take one entry the host posted.
    fn consume(&mut self, io: &RecIo) -> Option<Vec<u32>> {
        if self.idx == io.reg(self.host_reg) {
            return None;
        }
        let w = (0..self.esz)
            .map(|i| phys_rd32(self.base + (self.idx as u64 + i as u64) * 4))
            .collect();
        self.idx = (self.idx + self.esz) % self.size;
        self.publish();
        Some(w)
    }

    fn consume_all(&mut self, io: &RecIo) -> Vec<Vec<u32>> {
        let mut v = Vec::new();
        while let Some(e) = self.consume(io) {
            v.push(e);
        }
        v
    }

    fn pending(&self, io: &RecIo) -> u32 {
        (io.reg(self.host_reg) + self.size - self.idx) % self.size / self.esz
    }

    /// DST ring: write one entry.
    fn produce(&mut self, io: &RecIo, w: &[u32]) -> bool {
        if (self.idx + self.esz) % self.size == io.reg(self.host_reg) {
            return false;
        }
        for (i, &v) in w.iter().enumerate() {
            phys_wr32(self.base + (self.idx as u64 + i as u64) * 4, v);
        }
        self.idx = (self.idx + self.esz) % self.size;
        self.publish();
        true
    }
}

fn reg64(io: &RecIo, lo: u32) -> u64 {
    io.reg(lo) as u64 | ((io.reg(lo + 4) as u64 & 0xff) << 32)
}

// wcn6855_regs: HAL_SEQ_WCSS_UMAC_REO_REG (0xa38000) + 0x194 / 0x3020
// (REO_CMD), + 0x4ac?: the status ring R0 is 0xa3855c, TP 0xa3b07c.
const REO_CMD_R0: u32 = 0x00a3_8194;
const REO_CMD_HP: u32 = 0x00a3_b020;
const REO_STATUS_R0: u32 = 0x00a3_855c;
const REO_STATUS_TP: u32 = 0x00a3_b07c;

/// The REO command ring (SRC; TP address at R0 + 0x1c / + 0x20).
fn reo_cmd_dev(io: &RecIo) -> DevRing {
    DevRing {
        base: reg64(io, REO_CMD_R0),
        size: (io.reg(REO_CMD_R0 + 4) >> 8) & 0xf_ffff,
        esz: io.reg(REO_CMD_R0 + 8) & 0xff,
        hw_ptr: io.reg(REO_CMD_R0 + 0x1c) as u64 | ((io.reg(REO_CMD_R0 + 0x20) as u64) << 32),
        host_reg: shadow_of(REO_CMD_HP),
        idx: 0,
    }
}

/// The REO status ring (DST; HP address at R0 + 0x14 / + 0x18).
fn reo_status_dev(io: &RecIo) -> DevRing {
    DevRing {
        base: reg64(io, REO_STATUS_R0),
        size: (io.reg(REO_STATUS_R0 + 4) >> 8) & 0xf_ffff,
        esz: io.reg(REO_STATUS_R0 + 8) & 0xff,
        hw_ptr: io.reg(REO_STATUS_R0 + 0x14) as u64 | ((io.reg(REO_STATUS_R0 + 0x18) as u64) << 32),
        host_reg: shadow_of(REO_STATUS_TP),
        idx: 0,
    }
}

/// A REO status entry: TLV tag (`HAL_SRNG_TLV_HDR_TAG`, bits 9:1), then
/// `hal_reo_status_hdr.info0` = status number | exec status << 26.
fn status_entry(tag: u32, num: u32, exec: u32) -> Vec<u32> {
    let mut w = vec![0u32; 26];
    w[0] = tag << 1;
    w[1] = num | (exec << 26);
    w
}

const UPDATE_RX_REO_QUEUE_STATUS: u32 = 0x99;
const FLUSH_CACHE_STATUS: u32 = 0x139;

fn msi() -> CeMsi {
    CeMsi {
        addr: 0xfee0_0000,
        ep_base_data: 0,
        config: &MSI_CONFIG_QCA6390,
    }
}

fn sizes(reo_cmd: u32) -> DpRingSizes {
    DpRingSizes {
        wbm_release: 16,
        tcl_cmd: 8,
        tcl_status: 8,
        tcl_data: Some(8),
        tx_comp: 16,
        reo_reinject: 8,
        rx_release: 16,
        reo_exception: 16,
        reo_cmd,
        reo_status: 256,
        reo_dst: 16,
        rxdma_buf: 16,
        rx_mac_buf: 16,
        rxdma_err_dst: 16,
        rxdma_mon_status: 8,
        tx_status_fifo: 8,
        n_link_desc: Some(64),
    }
}

struct Rig {
    hal: Hal,
    io: RecIo,
    dp: Dp,
    cmd: DevRing,
    st: DevRing,
}

const MAC_A: [u8; 6] = [0x00, 0x03, 0x7f, 0x12, 0x34, 0x56];
const MAC_B: [u8; 6] = [0x00, 0x03, 0x7f, 0x12, 0x34, 0x57];

/// HTT_T2H PEER_MAP (v1): type 3 | vdev << 8 | peer_id << 16, MAC low
/// 32 bits, MAC high 16 bits.
fn peer_map(vdev: u8, peer_id: u16, mac: &[u8; 6]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&(3u32 | (vdev as u32) << 8 | (peer_id as u32) << 16).to_le_bytes());
    m.extend_from_slice(&[mac[0], mac[1], mac[2], mac[3]]);
    m.extend_from_slice(&[mac[4], mac[5], 0, 0]);
    m
}

fn rig(reo_cmd: u32) -> Rig {
    let cfg = DpHwParams::for_rev(HwRev::Wcn6855Hw21).expect("WCN6855 DP params");
    let mut hal = Hal::new(&cfg.hw).expect("hal");
    let io = RecIo::default();
    let mut dp = Dp::alloc(&mut hal, &io, &cfg, sizes(reo_cmd), Some(msi())).expect("dp alloc");
    dp.htt_t2h_msg_handler(&peer_map(0, 3, &MAC_A))
        .expect("peer map");
    let cmd = reo_cmd_dev(&io);
    let st = reo_status_dev(&io);
    Rig {
        hal,
        io,
        dp,
        cmd,
        st,
    }
}

/// Run `ath11k_dp_peer_setup` with every WMI command succeeding;
/// returns the commands in send order.
fn full_setup(r: &mut Rig, vdev: u8, mac: [u8; 6], now: u64) -> Vec<WmiCmd> {
    let (mut op, c) = r.dp.peer_setup_begin(vdev, mac, 0);
    let mut out = vec![c];
    while let Some(c) =
        r.dp.peer_setup_next(&mut r.hal, &r.io, &mut op, now)
            .expect("peer setup step")
    {
        out.push(c);
    }
    out
}

fn w32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]])
}

fn tid_paddr(r: &Rig, mac: &[u8; 6], tid: usize) -> u64 {
    r.dp.peer_rx.peer(0, mac).expect("peer rx").rx_tid[tid].paddr
}

// ── qdesc ─────────────────────────────────────────────────────────

fn smoke_ath11k_dp_peer_qdesc_size_table() -> TestResult {
    // sizeof(hal_rx_reo_queue) = 32 words = 128 B; each
    // hal_rx_reo_queue_ext = hdr + rsvd + 15 × 8 B = 128 B.
    // ext count: ba <= 1 → 1 (QoS) / 0 (TID 16); <= 105 → 1;
    // <= 210 → 2; else 3.
    let cases: &[(u32, u8, u32)] = &[
        (0, 0, 256),
        (1, 0, 256),
        (0, 16, 128),
        (1, 16, 128),
        (2, 0, 256),
        (2, 16, 256),
        (64, 7, 256),
        (105, 0, 256),
        (106, 0, 384),
        (210, 0, 384),
        (211, 0, 512),
        (256, 0, 512),
        (256, 15, 512),
        (1024, 3, 512),
    ];
    for &(ba, tid, sz) in cases {
        check!(hal_reo_qdesc_size(ba, tid) == sz, "qdesc size table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_peer_qdesc_size_table
);

/// `hal_desc_header.info0`: owner 4 (REO) | buffer type << 4 | magic << 8.
const QDESC_HDR: u32 = 0xDDBE_EF84; // type 8, 0xDDBEEF
const EXT1_HDR: u32 = 0xADBE_EF94; // type 9, 0xADBEEF
const EXT2_HDR: u32 = 0xBDBE_EF94;
const EXT3_HDR: u32 = 0xCDBE_EF94;

fn qos_golden(tid: u32, info0: u32, info1: u32) -> Vec<u32> {
    let mut g = vec![0u32; 128];
    g[0] = QDESC_HDR;
    g[1] = tid;
    g[2] = info0;
    g[3] = info1;
    g[32] = EXT1_HDR;
    g[64] = EXT2_HDR;
    g[96] = EXT3_HDR;
    g
}

fn smoke_ath11k_dp_peer_qdesc_golden() -> TestResult {
    // TID 0, ba 1, ssn 0, PN none (ath11k_dp_peer_setup): ba 1 on a QoS
    // TID becomes 2 → BA_WINDOW_SIZE (18:11) = 1; VLD | ALDC 1 << 1 |
    // AC BE 0 | IGNORE_AMPDU (25) = 0x0200_0803; SSN 0.
    let mut w = vec![0xffff_ffffu32; 128];
    hal_reo_qdesc_setup(&mut w, 0, 1, 0, HalPnType::None);
    check!(
        w == qos_golden(0, 0x0200_0803, 0),
        "TID 0 ba 1 descriptor + 3 ext"
    );

    // TID 0, ba 64, ssn 100 (ADDBA): BA field 63 << 11 = 0x1f800;
    // info1 = SSN 100 << 1 = 0xc8.
    let mut w = vec![0u32; 128];
    hal_reo_qdesc_setup(&mut w, 0, 64, 100, HalPnType::None);
    check!(w == qos_golden(0, 0x0201_f803, 0xc8), "TID 0 ba 64 ssn 100");

    // TID 5 (AC VI 2 << 5 = 0x40), ba 64, WPA: PN_CHECK (19) | PN_SIZE 48
    // (1 << 23); ssn 0x1000 > 0xfff leaves info1 0.
    let mut w = vec![0u32; 128];
    hal_reo_qdesc_setup(&mut w, 5, 64, 0x1000, HalPnType::Wpa);
    check!(
        w == qos_golden(5, 0x0289_f843, 0),
        "TID 5 ba 64 WPA, out-of-range SSN"
    );

    // TID 6 (VO 3 << 5), ba 256 → field 255: 0x7f800.
    let mut w = vec![0u32; 128];
    hal_reo_qdesc_setup(&mut w, 6, 256, 0xfff, HalPnType::WapiEven);
    check!(
        w == qos_golden(6, 0x0207_f863, 0x1ffe),
        "TID 6 ba 256 ssn 0xfff (WAPI: no PN bits)"
    );

    // Non-QoS TID 16, ba 1: AC VO 0x60, ba stays 1 → RETRY (8), BA field
    // 0: 1 | 2 | 0x60 | 0x100 | 1 << 25 = 0x0200_0163; no ext written.
    let mut w = vec![0xffff_ffffu32; 64];
    hal_reo_qdesc_setup(&mut w, 16, 1, 0, HalPnType::None);
    let mut g = [0u32; 32];
    g[0] = QDESC_HDR;
    g[1] = 16;
    g[2] = 0x0200_0163;
    check!(w[..32] == g[..], "TID 16 descriptor");
    check!(
        w[32..].iter().all(|&v| v == 0xffff_ffff),
        "TID 16: nothing past the queue descriptor"
    );

    // ba 0 is raised to 1 (then 2 for QoS).
    let mut w = vec![0u32; 128];
    hal_reo_qdesc_setup(&mut w, 1, 0, 0, HalPnType::None);
    check!(
        w == qos_golden(1, 0x0200_0823, 0),
        "TID 1 (BK) ba 0 → window 2"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_peer_qdesc_golden);

// ── REO command descriptors ───────────────────────────────────────

fn smoke_ath11k_dp_peer_reo_cmd_desc_golden() -> TestResult {
    use reo_cmd_type as t;
    // TLV: tag << 1 | len 36 << 10 (0x9000). Command header: the ring's
    // pre-written number kept, STATUS_REQUIRED (16) cleared then set.
    let prev = 7 | (1 << 16);
    let mut blk = BlkRes::default();

    // GET_QUEUE_STATS (0x132): addr_hi (7:0) | CLEAR_STATS (8).
    let mut c = HalReoCmd {
        addr_lo: 0x1234_5600,
        addr_hi: 0x12,
        flag: HAL_REO_CMD_FLG_NEED_STATUS | HAL_REO_CMD_FLG_STATS_CLEAR,
        ..HalReoCmd::default()
    };
    check!(
        hal_reo_cmd_desc(t::GET_QUEUE_STATS, &mut c, prev, &mut blk)
            == Ok([0x9264, 0x1_0007, 0x1234_5600, 0x112, 0, 0, 0, 0, 0, 0]),
        "GET_QUEUE_STATS"
    );

    // FLUSH_CACHE (0x134) without status: header bit 16 cleared;
    // FWD_ALL_MPDUS (8) | FLUSH_WO_INVALIDATE (12) | FLUSH_ALL (14).
    let mut c = HalReoCmd {
        addr_lo: 0x0040_0180,
        addr_hi: 0,
        flag: HAL_REO_CMD_FLG_FLUSH_FWD_ALL_MPDUS
            | HAL_REO_CMD_FLG_FLUSH_NO_INVAL
            | HAL_REO_CMD_FLG_FLUSH_ALL,
        ..HalReoCmd::default()
    };
    check!(
        hal_reo_cmd_desc(t::FLUSH_CACHE, &mut c, prev, &mut blk)
            == Ok([0x9268, 7, 0x0040_0180, 0x5100, 0, 0, 0, 0, 0, 0]),
        "FLUSH_CACHE"
    );

    // BLOCK_LATER: slot = ffz(avail) → 1 with avail 0b001:
    // BLOCK_CACHE_USAGE (13) | BLOCK_RESRC_IDX 1 << 10.
    blk.avail_blk_resource = 0b001;
    let mut c = HalReoCmd {
        addr_lo: 0x80,
        addr_hi: 3,
        flag: HAL_REO_CMD_FLG_FLUSH_BLOCK_LATER | HAL_REO_CMD_FLG_NEED_STATUS,
        ..HalReoCmd::default()
    };
    check!(
        hal_reo_cmd_desc(t::FLUSH_CACHE, &mut c, 9, &mut blk)
            == Ok([0x9268, 0x1_0009, 0x80, 0x2403, 0, 0, 0, 0, 0, 0]),
        "FLUSH_CACHE block later"
    );
    check!(blk.current_blk_index == 1, "current_blk_index = slot");
    blk.avail_blk_resource = 0b111;
    check!(
        hal_reo_cmd_desc(t::FLUSH_CACHE, &mut c, 9, &mut blk)
            == Err((step::REO_CMD_NO_BLOCK_RES, errno::ENOSPC)),
        "no blocking slot: -ENOSPC"
    );

    // UPDATE_RX_REO_QUEUE (0x1a3), tid delete: UPD_VLD (9); info2
    // BA_WINDOW_SIZE = (0 → 1 → 2) - 1 = 1.
    let mut blk = BlkRes::default();
    let mut c = HalReoCmd {
        addr_lo: 0x0012_3480,
        flag: HAL_REO_CMD_FLG_NEED_STATUS,
        upd0: HAL_REO_CMD_UPD0_VLD,
        ..HalReoCmd::default()
    };
    check!(
        hal_reo_cmd_desc(t::UPDATE_RX_QUEUE, &mut c, 3, &mut blk)
            == Ok([0x9346, 0x1_0003, 0x0012_3480, 0x200, 0, 1, 0, 0, 0, 0]),
        "UPDATE_RX_QUEUE delete"
    );
    check!(c.ba_window_size == 2, "ba_window_size raised as Linux");

    // ba 64, ssn 100 (rx_tid_reo_update): UPD_BA_WINDOW_SIZE (18) |
    // UPD_SSN (26); info2 = 63 | 100 << 11.
    let mut c = HalReoCmd {
        addr_lo: 0x0012_3480,
        flag: HAL_REO_CMD_FLG_NEED_STATUS,
        upd0: HAL_REO_CMD_UPD0_BA_WINDOW_SIZE | HAL_REO_CMD_UPD0_SSN,
        upd2: 100 << 11,
        ba_window_size: 64,
        ..HalReoCmd::default()
    };
    check!(
        hal_reo_cmd_desc(t::UPDATE_RX_QUEUE, &mut c, 3, &mut blk)
            == Ok([
                0x9346,
                0x1_0003,
                0x0012_3480,
                0x0404_0000,
                0,
                0x3_203f,
                0,
                0,
                0,
                0
            ]),
        "UPDATE_RX_QUEUE ba 64 ssn 100"
    );

    // Every update bit: info0 bits 8..30 except UPD_PN_ERR (28), which
    // ath11k_hal_reo_cmd_update_rx_queue never maps; info1 = rx_queue_num | every
    // upd1 field (ALDC 3, AC 3), pn_size 48 → 1, upd2 SVLD | SSN 0xfff
    // | SEQ_2K | PN_ERR: info2 = 1 | 1 << 8 | 1 << 10 | 0xfff << 11 |
    // 1 << 23 | 1 << 24.
    let mut c = HalReoCmd {
        addr_lo: 0xdead_be80,
        addr_hi: 0x5a,
        upd0: 0x7fff_ff00,
        upd1: 0xffff_0000,
        upd2: 0x01ff_fc00,
        rx_queue_num: 0xabcd,
        pn_size: 48,
        pn: [1, 2, 3, 4],
        ..HalReoCmd::default()
    };
    check!(
        hal_reo_cmd_desc(t::UPDATE_RX_QUEUE, &mut c, 0x11, &mut blk)
            == Ok([
                0x9346,
                0x11,
                0xdead_be80,
                0x6fff_ff5a,
                0xffff_abcd,
                0x01ff_fd01,
                0,
                0,
                0,
                0
            ]),
        "UPDATE_RX_QUEUE every field (pn[] never copied)"
    );
    check!(c.pn_size == 1, "pn_size 48 → HAL_RX_REO_QUEUE_PN_SIZE_48");

    // Unsupported and unknown types.
    for ty in [t::FLUSH_QUEUE, t::UNBLOCK_CACHE, t::FLUSH_TIMEOUT_LIST] {
        check!(
            hal_reo_cmd_desc(ty, &mut c, 1, &mut blk)
                == Err((step::REO_CMD_UNSUPPORTED, EOPNOTSUPP)),
            "unsupported: -EOPNOTSUPP"
        );
    }
    check!(
        hal_reo_cmd_desc(6, &mut c, 1, &mut blk) == Err((step::REO_CMD_UNKNOWN, errno::EINVAL)),
        "unknown: -EINVAL"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_peer_reo_cmd_desc_golden
);

// ── WMI ───────────────────────────────────────────────────────────

fn smoke_ath11k_dp_peer_wmi_reorder_golden() -> TestResult {
    // struct wmi_peer_reorder_queue_setup_cmd { tlv_header; vdev_id;
    // wmi_mac_addr (6 + 2 pad); tid; queue_ptr_lo; queue_ptr_hi;
    // queue_no; ba_window_size_valid; ba_window_size } = 40 bytes.
    // TLV = WMI_TAG_REORDER_QUEUE_SETUP_CMD (0x225) << 16 | 36.
    let c = super::wmi::peer_rx_reorder_queue_setup_cmd(1, &MAC_A, 0x1_2345_6780, 6, 1, 64);
    let g: [u8; 40] = [
        0x24, 0x00, 0x25, 0x02, // tlv
        0x01, 0x00, 0x00, 0x00, // vdev_id
        0x00, 0x03, 0x7f, 0x12, 0x34, 0x56, 0x00, 0x00, // peer_macaddr
        0x06, 0x00, 0x00, 0x00, // tid
        0x80, 0x67, 0x45, 0x23, // queue_ptr_lo
        0x01, 0x00, 0x00, 0x00, // queue_ptr_hi
        0x06, 0x00, 0x00, 0x00, // queue_no = tid
        0x01, 0x00, 0x00, 0x00, // ba_window_size_valid
        0x40, 0x00, 0x00, 0x00, // ba_window_size
    ];
    check!(
        c.cmd_id == 0x6013 && c.buf == g,
        "WMI_PEER_REORDER_QUEUE_SETUP_CMDID bytes"
    );
    check!(
        c.frame()[..4] == [0x13, 0x60, 0x00, 0x00],
        "wmi_cmd_hdr command id"
    );

    // struct wmi_peer_reorder_queue_remove_cmd { tlv; vdev_id; mac;
    // tid_mask } = 20 bytes; TLV 0x226 << 16 | 16.
    let c = super::wmi::rx_reord_queue_remove_cmd(&MAC_A, 2, 0x1_ffff);
    let g: [u8; 20] = [
        0x10, 0x00, 0x26, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x7f, 0x12, 0x34, 0x56, 0x00,
        0x00, 0xff, 0xff, 0x01, 0x00,
    ];
    check!(
        c.cmd_id == 0x6014 && c.buf == g,
        "WMI_PEER_REORDER_QUEUE_REMOVE_CMDID bytes"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_peer_wmi_reorder_golden
);

// ── peer setup ────────────────────────────────────────────────────

fn smoke_ath11k_dp_peer_setup_full() -> TestResult {
    let mut r = rig(32);
    check!(
        r.cmd.esz == 10 && r.cmd.size == 320 && r.st.esz == 26,
        "REO command ring: TLV + 36 B entries"
    );
    let cmds = full_setup(&mut r, 0, MAC_A, 100);
    check!(cmds.len() == 18, "routing + 17 TID queues");

    // WMI_PEER_SET_DEFAULT_ROUTING (0x13) = DP_RX_HASH_ENABLE |
    // (mac_id + 1) << 1 = 3; wmi_peer_set_param_cmd, 24 bytes, tag 0x64.
    let g: [u8; 24] = [
        0x14, 0x00, 0x64, 0x00, 0, 0, 0, 0, 0x00, 0x03, 0x7f, 0x12, 0x34, 0x56, 0, 0, 0x13, 0, 0,
        0, 3, 0, 0, 0,
    ];
    check!(
        cmds[0].cmd_id == 0x6004 && cmds[0].buf == g,
        "default routing set_param"
    );

    for tid in 0..17usize {
        let c = &cmds[tid + 1];
        let pa = tid_paddr(&r, &MAC_A, tid);
        check!(
            c.cmd_id == 0x6013
                && w32(&c.buf, 4) == tid as u32
                && w32(&c.buf, 5) as u64 == pa & 0xffff_ffff
                && w32(&c.buf, 6) == (pa >> 32) as u32
                && w32(&c.buf, 7) == tid as u32
                && w32(&c.buf, 8) == 1
                && w32(&c.buf, 9) == 1,
            "per-TID reorder queue setup (window 1)"
        );
        check!(pa != 0 && pa % 128 == 0, "HAL_LINK_DESC_ALIGN");
        let rt = &r.dp.peer_rx.peer(0, &MAC_A).unwrap().rx_tid[tid];
        let want_sz = if tid == 16 { 128 } else { 512 };
        check!(
            rt.active && rt.size == want_sz && rt.ba_win_sz == 1 && rt.tid == tid as u8,
            "TID state: DP_BA_WIN_SZ_MAX sized for QoS"
        );
    }
    // The device reads the descriptors at the WMI addresses.
    let pa0 = tid_paddr(&r, &MAC_A, 0);
    let dev: Vec<u32> = (0..128).map(|i| phys_rd32(pa0 + 4 * i)).collect();
    check!(
        dev == qos_golden(0, 0x0200_0803, 0),
        "TID 0 queue in memory"
    );
    let pa7 = tid_paddr(&r, &MAC_A, 7);
    check!(
        phys_rd32(pa7 + 4) == 7 && phys_rd32(pa7 + 8) == 0x0200_0863,
        "TID 7 queue: VO"
    );
    let pa16 = tid_paddr(&r, &MAC_A, 16);
    check!(
        phys_rd32(pa16) == QDESC_HDR
            && phys_rd32(pa16 + 4) == 16
            && phys_rd32(pa16 + 8) == 0x0200_0163,
        "non-QoS queue in memory"
    );
    check!(
        r.dp.peer_rx.peer(0, &MAC_A).unwrap().dp_setup_done,
        "dp_setup_done (frag setup)"
    );
    check!(
        r.cmd.pending(&r.io) == 0 && r.dp.peer_rx.stats.reo_cmds_sent == 0,
        "a fresh peer sends no REO command"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_peer_setup_full);

fn smoke_ath11k_dp_peer_double_setup_update_path() -> TestResult {
    let mut r = rig(32);
    full_setup(&mut r, 0, MAC_A, 100);
    let pa0 = tid_paddr(&r, &MAC_A, 0);

    // ADDBA on TID 0: the queue exists → REO UPDATE_RX_QUEUE (ba 64, ssn
    // 100, need status), then the WMI with the same queue.
    let s =
        r.dp.ampdu_start(
            &mut r.hal,
            &r.io,
            0,
            &MAC_A,
            0,
            64,
            100,
            HalPnType::Wpa,
            200,
        )
        .expect("ampdu start");
    check!(s.updated && s.tid == 0, "update path");
    check!(
        w32(&s.cmd.buf, 5) as u64 == pa0 & 0xffff_ffff && w32(&s.cmd.buf, 9) == 64,
        "WMI: same queue, window 64"
    );
    let e = r.cmd.consume_all(&r.io);
    check!(e.len() == 1, "one REO command");
    check!(
        e[0] == [
            0x9346,
            0x1_0001, // ring slot 0 carries command number 1
            pa0 as u32,
            0x0404_0000 | (pa0 >> 32) as u32,
            0,
            0x3_203f,
            0,
            0,
            0,
            0
        ],
        "UPDATE_RX_QUEUE ba 64 ssn 100"
    );
    check!(
        tid_paddr(&r, &MAC_A, 0) == pa0
            && r.dp.peer_rx.peer(0, &MAC_A).unwrap().rx_tid[0].ba_win_sz == 64,
        "queue kept, ba_win_sz updated"
    );
    check!(
        r.dp.peer_rx.reo_cmd_list.is_empty(),
        "no handler for an update"
    );
    check!(
        r.io.reg(shadow_of(REO_CMD_HP)) == 10 && r.dp.reo_cmd_timer.started,
        "HP published through the shadow, shadow timer armed"
    );

    // A second ath11k_dp_peer_setup on the same peer: 17 updates
    // (ba 1, ssn 0), command numbers 2..18.
    let cmds = full_setup(&mut r, 0, MAC_A, 300);
    check!(cmds.len() == 18, "18 WMI commands again");
    let e = r.cmd.consume_all(&r.io);
    check!(e.len() == 17, "17 REO updates");
    for (tid, w) in e.iter().enumerate() {
        let pa = tid_paddr(&r, &MAC_A, tid);
        check!(
            w[1] == 0x1_0000 | (tid as u32 + 2)
                && w[2] == pa as u32
                && w[3] == 0x0404_0000
                && w[5] == 1,
            "update: window 1 (→ 2) ssn 0"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_peer_double_setup_update_path
);

// ── teardown ──────────────────────────────────────────────────────

fn smoke_ath11k_dp_peer_teardown_deferred_free() -> TestResult {
    let mut r = rig(128);
    full_setup(&mut r, 0, MAC_A, 0);
    let pas: Vec<u64> = (0..17).map(|t| tid_paddr(&r, &MAC_A, t)).collect();

    r.dp.peer_cleanup(&mut r.hal, &r.io, 0, &MAC_A, 1000)
        .expect("cleanup");
    let e = r.cmd.consume_all(&r.io);
    check!(e.len() == 17, "one VLD=0 update per TID");
    for (t, w) in e.iter().enumerate() {
        check!(
            *w == [
                0x9346,
                0x1_0000 | (t as u32 + 1),
                pas[t] as u32,
                0x200 | (pas[t] >> 32) as u32,
                0,
                1,
                0,
                0,
                0,
                0
            ],
            "UPDATE_RX_QUEUE VLD (tid delete)"
        );
    }
    let p = r.dp.peer_rx.peer(0, &MAC_A).unwrap();
    check!(
        !p.dp_setup_done
            && p.rx_tid
                .iter()
                .all(|t| !t.active && t.paddr == 0 && t.size == 0 && t.mem().is_none()),
        "TIDs inactive, memory moved to the command list"
    );
    check!(
        r.dp.peer_rx.reo_cmd_list.len() == 17
            && r.dp
                .peer_rx
                .reo_cmd_list
                .iter()
                .all(|c| c.handler == ReoCmdHandler::TidDel),
        "17 pending deletes"
    );

    // All succeed at t = 1000: queued for the cache flush, nothing
    // flushed yet (count 17 <= 64, none older than 1000 ms).
    for n in 1..=17 {
        check!(
            r.st.produce(&r.io, &status_entry(UPDATE_RX_REO_QUEUE_STATUS, n, 0)),
            "status"
        );
    }
    r.dp.process_reo_status_and_dispatch(&mut r.hal, &r.io, 1000);
    check!(
        r.dp.peer_rx.reo_cmd_list.is_empty()
            && r.dp.peer_rx.cache_flush_list.len() == 17
            && r.dp.peer_rx.cache_flush_count == 17,
        "deferred to reo_cmd_cache_flush_list"
    );
    check!(
        r.cmd.pending(&r.io) == 0 && r.dp.peer_rx.stats.freed == 0,
        "no flush, nothing freed"
    );
    // The memory is still the queue the device knows.
    check!(phys_rd32(pas[0]) == QDESC_HDR, "descriptor memory kept");

    // t = 2000 is not *after* ts + 1000: a new delete at 2000 flushes
    // nothing either.
    let s =
        r.dp.rx_tid_setup(&mut r.hal, &r.io, 0, &MAC_A, 3, 1, 0, HalPnType::None, 2000)
            .expect("tid 3 again");
    check!(!s.updated, "fresh queue after cleanup");
    r.dp.peer_cleanup(&mut r.hal, &r.io, 0, &MAC_A, 2000)
        .unwrap();
    check!(r.cmd.consume_all(&r.io).len() == 1, "one delete");
    r.st.produce(&r.io, &status_entry(UPDATE_RX_REO_QUEUE_STATUS, 18, 0));
    r.dp.process_reo_status_and_dispatch(&mut r.hal, &r.io, 2000);
    check!(
        r.dp.peer_rx.cache_flush_count == 18 && r.cmd.pending(&r.io) == 0,
        "time_after is strict"
    );

    // t = 2001: the 17 entries from t = 1000 have aged: each is flushed
    // in 128-byte blocks from the end (no status), then the first block
    // with status (ath11k_dp_reo_cmd_free frees on it).
    let s =
        r.dp.rx_tid_setup(&mut r.hal, &r.io, 0, &MAC_A, 4, 1, 0, HalPnType::None, 2001)
            .unwrap();
    let _ = s;
    r.dp.peer_cleanup(&mut r.hal, &r.io, 0, &MAC_A, 2001)
        .unwrap();
    check!(r.cmd.consume_all(&r.io).len() == 1, "one delete");
    r.st.produce(&r.io, &status_entry(UPDATE_RX_REO_QUEUE_STATUS, 19, 0));
    r.dp.process_reo_status_and_dispatch(&mut r.hal, &r.io, 2001);
    let e = r.cmd.consume_all(&r.io);
    check!(e.len() == 16 * 4 + 1, "QoS: 3 + 1 flushes; non-QoS: 1");
    let mut k = 0;
    let mut final_nums = Vec::new();
    for (t, &pa) in pas.iter().enumerate() {
        let blocks: &[u64] = if t == 16 { &[] } else { &[384, 256, 128] };
        for &off in blocks {
            check!(
                e[k][0] == 0x9268
                    && e[k][1] & (1 << 16) == 0
                    && e[k][2] == (pa + off) as u32
                    && e[k][3] == (pa >> 32) as u32,
                "FLUSH_CACHE block, no status"
            );
            k += 1;
        }
        check!(
            e[k][0] == 0x9268 && e[k][1] & (1 << 16) != 0 && e[k][2] == pa as u32,
            "FLUSH_CACHE first block, status"
        );
        final_nums.push(e[k][1] & 0xffff);
        k += 1;
    }
    check!(
        r.dp.peer_rx.cache_flush_count == 2
            && r.dp.peer_rx.reo_cmd_list.len() == 17
            && r.dp
                .peer_rx
                .reo_cmd_list
                .iter()
                .all(|c| c.handler == ReoCmdHandler::CmdFree),
        "two young entries stay; 17 frees pending"
    );
    check!(r.dp.peer_rx.stats.freed == 0, "freed only on status");
    for n in final_nums {
        r.st.produce(&r.io, &status_entry(FLUSH_CACHE_STATUS, n, 0));
    }
    r.dp.process_reo_status_and_dispatch(&mut r.hal, &r.io, 2002);
    check!(
        r.dp.peer_rx.stats.freed == 17 && r.dp.peer_rx.reo_cmd_list.is_empty(),
        "ath11k_dp_reo_cmd_free"
    );

    // ath11k_dp_reo_cmd_list_cleanup frees the rest.
    r.dp.reo_cmd_list_cleanup();
    check!(
        r.dp.peer_rx.stats.freed == 19 && r.dp.peer_rx.cache_flush_count == 0,
        "list cleanup"
    );
    check!(r.dp.peer_rx.stranded.is_empty(), "nothing stranded");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_peer_teardown_deferred_free
);

fn smoke_ath11k_dp_peer_flush_threshold() -> TestResult {
    // More than DP_REO_DESC_FREE_THRESHOLD (64) deferred descriptors:
    // each add beyond 64 flushes the oldest one.
    let mut r = rig(128);
    for (i, mac) in [
        [2u8, 0, 0, 0, 0, 1],
        [2, 0, 0, 0, 0, 2],
        [2, 0, 0, 0, 0, 3],
        [2, 0, 0, 0, 0, 4],
    ]
    .iter()
    .enumerate()
    {
        r.dp.htt_t2h_msg_handler(&peer_map(1, 10 + i as u16, mac))
            .unwrap();
        let (mut op, _) = r.dp.peer_setup_begin(1, *mac, 0);
        while r
            .dp
            .peer_setup_next(&mut r.hal, &r.io, &mut op, 0)
            .unwrap()
            .is_some()
        {}
    }
    let first = r.dp.peer_rx.peer(1, &[2, 0, 0, 0, 0, 1]).unwrap().rx_tid[0].paddr;
    let mut num = 0u32;
    for mac in [
        [2u8, 0, 0, 0, 0, 1],
        [2, 0, 0, 0, 0, 2],
        [2, 0, 0, 0, 0, 3],
        [2, 0, 0, 0, 0, 4],
    ] {
        r.dp.peer_cleanup(&mut r.hal, &r.io, 1, &mac, 5).unwrap();
        for _ in 0..17 {
            num += 1;
            r.st.produce(&r.io, &status_entry(UPDATE_RX_REO_QUEUE_STATUS, num, 0));
        }
        r.cmd.consume_all(&r.io);
    }
    // 68 deletes; statuses dispatched in four batches of 17.
    let mut flushes = Vec::new();
    for _ in 0..4 {
        let st = r.dp.process_reo_status(&mut r.hal, &r.io);
        for s in st.chunks(17) {
            r.dp.reo_status_handler(&mut r.hal, &r.io, s, 5);
            flushes.extend(r.cmd.consume_all(&r.io));
        }
    }
    check!(
        r.dp.peer_rx.cache_flush_count == 64,
        "back at the threshold"
    );
    check!(
        flushes.len() == 4 * 4,
        "four oldest flushed (4 commands each)"
    );
    check!(
        flushes[0][2] == (first + 384) as u32 && flushes[3][2] == first as u32,
        "oldest first"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_peer_flush_threshold
);

// ── status dispatch negatives ─────────────────────────────────────

fn smoke_ath11k_dp_peer_status_dispatch_negatives() -> TestResult {
    let mut r = rig(64);
    full_setup(&mut r, 0, MAC_A, 0);
    r.dp.peer_cleanup(&mut r.hal, &r.io, 0, &MAC_A, 10).unwrap();
    r.cmd.consume_all(&r.io);
    check!(r.dp.peer_rx.reo_cmd_list.len() == 17, "17 pending");

    // Unknown command number: ignored, list untouched.
    let st = [ReoStatus {
        tag: UPDATE_RX_REO_QUEUE_STATUS,
        cmd_num: 40,
        cmd_status: 0,
    }];
    r.dp.reo_status_handler(&mut r.hal, &r.io, &st, 10);
    check!(
        r.dp.peer_rx.stats.status_unmatched == 1 && r.dp.peer_rx.reo_cmd_list.len() == 17,
        "unknown command number"
    );

    // FAILED (2) / BLOCKED (1) / RESOURCE_BLOCKED (3): "Shouldn't
    // happen!" — Linux returns, the descriptor is not freed.
    for (n, s) in [(1u16, 2u8), (2, 1), (3, 3)] {
        let st = [ReoStatus {
            tag: UPDATE_RX_REO_QUEUE_STATUS,
            cmd_num: n,
            cmd_status: s,
        }];
        r.dp.reo_status_handler(&mut r.hal, &r.io, &st, 10);
    }
    check!(
        r.dp.peer_rx.stats.tid_del_failed == 3
            && r.dp.peer_rx.stranded.len() == 3
            && r.dp.peer_rx.cache_flush_list.is_empty()
            && r.dp.peer_rx.stats.freed == 0,
        "failed delete: kept, not deferred"
    );

    // HAL_REO_CMD_DRAIN: freed at once.
    let st = [ReoStatus {
        tag: UPDATE_RX_REO_QUEUE_STATUS,
        cmd_num: 4,
        cmd_status: reo_cmd_status::DRAIN,
    }];
    r.dp.reo_status_handler(&mut r.hal, &r.io, &st, 10);
    check!(
        r.dp.peer_rx.stats.freed == 1 && r.dp.peer_rx.reo_cmd_list.len() == 13,
        "drain frees"
    );

    // A second status for an already-handled number: unmatched.
    r.dp.reo_status_handler(&mut r.hal, &r.io, &st, 10);
    check!(
        r.dp.peer_rx.stats.status_unmatched == 2,
        "status after its command completed"
    );

    // A command without handler (REO update) has no list entry.
    full_setup(&mut r, 0, MAC_A, 20);
    let s =
        r.dp.ampdu_start(&mut r.hal, &r.io, 0, &MAC_A, 2, 32, 0, HalPnType::None, 20)
            .unwrap();
    check!(s.updated, "update path");
    let e = r.cmd.consume_all(&r.io);
    let n = (e[0][1] & 0xffff) as u16;
    let st = [ReoStatus {
        tag: UPDATE_RX_REO_QUEUE_STATUS,
        cmd_num: n,
        cmd_status: 0,
    }];
    r.dp.reo_status_handler(&mut r.hal, &r.io, &st, 20);
    check!(
        r.dp.peer_rx.stats.status_unmatched == 3 && r.dp.peer_rx.reo_cmd_list.len() == 13,
        "update status: no handler"
    );

    // Flush status not SUCCESS: still freed (ath11k_dp_reo_cmd_free).
    let mut d = RxTidData {
        tid: 0,
        paddr: 0,
        size: 128,
        ba_win_sz: 1,
        mem: Some(DmaMem::alloc(128, 128).unwrap()),
    };
    d.paddr = d.mem.as_ref().unwrap().paddr();
    let mut c = HalReoCmd {
        addr_lo: d.paddr as u32,
        flag: HAL_REO_CMD_FLG_NEED_STATUS,
        ..HalReoCmd::default()
    };
    let num =
        r.dp.send_reo_cmd(
            &mut r.hal,
            &r.io,
            reo_cmd_type::FLUSH_CACHE,
            &mut c,
            Some((ReoCmdHandler::CmdFree, d)),
            30,
        )
        .map_err(|_| ())
        .unwrap();
    let st = [ReoStatus {
        tag: FLUSH_CACHE_STATUS,
        cmd_num: num,
        cmd_status: 2,
    }];
    let freed = r.dp.peer_rx.stats.freed;
    r.dp.reo_status_handler(&mut r.hal, &r.io, &st, 30);
    check!(
        r.dp.peer_rx.stats.flush_failed == 1 && r.dp.peer_rx.stats.freed == freed + 1,
        "failed flush still frees"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_peer_status_dispatch_negatives
);

// ── REO command negatives ─────────────────────────────────────────

fn smoke_ath11k_dp_peer_reo_cmd_ring_full() -> TestResult {
    let mut r = rig(8);
    full_setup(&mut r, 0, MAC_A, 0);
    // 8 entries, one always empty: 7 commands fit.
    for _ in 0..7 {
        let mut c = HalReoCmd::default();
        check!(
            r.dp.send_reo_cmd(
                &mut r.hal,
                &r.io,
                reo_cmd_type::GET_QUEUE_STATS,
                &mut c,
                None,
                0
            )
            .is_ok(),
            "fits"
        );
    }
    let hp = r.io.reg(shadow_of(REO_CMD_HP));
    check!(hp == 70, "HP after 7 entries");
    let mut c = HalReoCmd::default();
    let e =
        r.dp.send_reo_cmd(
            &mut r.hal,
            &r.io,
            reo_cmd_type::GET_QUEUE_STATS,
            &mut c,
            None,
            0,
        )
        .err()
        .map(|(e, _)| e);
    check!(
        e == Some(TransportError::new(
            step::REO_CMD_RING_FULL,
            0,
            errno::ENOBUFS
        )),
        "-ENOBUFS"
    );
    check!(r.io.reg(shadow_of(REO_CMD_HP)) == hp, "HP unchanged");

    // A delete that cannot be queued keeps the descriptor (Linux frees
    // it while the hardware still has the queue valid).
    let pa = tid_paddr(&r, &MAC_A, 0);
    r.dp.peer_cleanup(&mut r.hal, &r.io, 0, &MAC_A, 0).unwrap();
    check!(
        r.dp.peer_rx.stranded.len() == 17
            && r.dp.peer_rx.stats.freed == 0
            && r.dp.peer_rx.reo_cmd_list.is_empty(),
        "all 17 kept"
    );
    check!(
        r.dp.peer_rx.stranded[0].paddr() == pa && phys_rd32(pa) == QDESC_HDR,
        "kept memory intact"
    );
    let p = r.dp.peer_rx.peer(0, &MAC_A).unwrap();
    check!(
        p.rx_tid.iter().all(|t| !t.active && t.paddr == 0),
        "TIDs inactive"
    );

    // Unsupported / unknown types never take an entry.
    r.cmd.consume_all(&r.io);
    let hp = r.io.reg(shadow_of(REO_CMD_HP));
    for (ty, want) in [
        (reo_cmd_type::FLUSH_QUEUE, step::REO_CMD_UNSUPPORTED),
        (reo_cmd_type::UNBLOCK_CACHE, step::REO_CMD_UNSUPPORTED),
        (reo_cmd_type::FLUSH_TIMEOUT_LIST, step::REO_CMD_UNSUPPORTED),
        (9, step::REO_CMD_UNKNOWN),
    ] {
        let mut c = HalReoCmd::default();
        let e =
            r.dp.send_reo_cmd(&mut r.hal, &r.io, ty, &mut c, None, 0)
                .err()
                .map(|(e, _)| e.step);
        check!(e == Some(want), "type rejected");
    }
    check!(
        r.io.reg(shadow_of(REO_CMD_HP)) == hp,
        "no entry taken for a rejected type"
    );

    // ATH11K_FLAG_CRASH_FLUSH: -ESHUTDOWN, handler data handed back.
    r.dp.crash_flush = true;
    let mut c = HalReoCmd::default();
    let d = RxTidData {
        tid: 1,
        paddr: 0,
        size: 0,
        ba_win_sz: 0,
        mem: None,
    };
    match r.dp.send_reo_cmd(
        &mut r.hal,
        &r.io,
        reo_cmd_type::UPDATE_RX_QUEUE,
        &mut c,
        Some((ReoCmdHandler::TidDel, d)),
        0,
    ) {
        Err((e, Some(back))) => check!(
            e.step == step::REO_CMD_SHUTDOWN && e.errno == errno::ESHUTDOWN && back.tid == 1,
            "-ESHUTDOWN"
        ),
        _ => return TestResult::Fail("crash flush must refuse"),
    }
    check!(r.dp.peer_rx.reo_cmd_list.is_empty(), "nothing queued");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_peer_reo_cmd_ring_full
);

// ── setup failures / unwinding ────────────────────────────────────

fn smoke_ath11k_dp_peer_setup_unwind() -> TestResult {
    // Peer not HTT-mapped: -ENOENT at the first TID.
    let mut r = rig(64);
    let (mut op, _) = r.dp.peer_setup_begin(0, MAC_B, 0);
    let e = r.dp.peer_setup_next(&mut r.hal, &r.io, &mut op, 0);
    check!(
        e == Err(TransportError::new(step::PEER_NOT_FOUND, 0, ENOENT)),
        "unknown peer: -ENOENT"
    );
    check!(
        r.dp.peer_setup_next(&mut r.hal, &r.io, &mut op, 0) == Ok(None),
        "a failed setup stays finished"
    );
    check!(
        r.dp.peer_cleanup(&mut r.hal, &r.io, 0, &MAC_B, 0)
            .map_err(|e| e.step)
            == Err(step::PEER_NOT_FOUND),
        "cleanup of an unknown peer"
    );
    check!(
        r.dp.ampdu_stop(&mut r.hal, &r.io, 0, &MAC_B, 0, 0)
            .map_err(|e| e.step)
            == Err(step::PEER_NOT_FOUND),
        "ampdu stop on an unknown peer"
    );
    check!(
        r.dp.rx_tid_setup(&mut r.hal, &r.io, 0, &MAC_A, 17, 1, 0, HalPnType::None, 0)
            .map_err(|e| e.step)
            == Err(step::BAD_TID),
        "TID 17 refused"
    );

    // Default routing WMI fails: nothing to undo.
    let (op, _) = r.dp.peer_setup_begin(0, MAC_A, 0);
    let e = r.dp.peer_setup_wmi_failed(&mut r.hal, &r.io, &op, 110, 0);
    check!(
        e == TransportError::new(step::WMI_SEND, 0xff, 110),
        "routing failure"
    );
    check!(r.cmd.pending(&r.io) == 0, "no REO command");

    // WMI for TID 5 (fresh) fails: TID 5 freed at once
    // (ath11k_dp_rx_tid_mem_free), then peer_clean deletes 5 (inactive,
    // skipped), 4, 3, 2, 1, 0.
    let (mut op, _) = r.dp.peer_setup_begin(0, MAC_A, 0);
    for _ in 0..6 {
        r.dp.peer_setup_next(&mut r.hal, &r.io, &mut op, 0)
            .unwrap()
            .unwrap();
    }
    let pas: Vec<u64> = (0..6).map(|t| tid_paddr(&r, &MAC_A, t)).collect();
    let e = r.dp.peer_setup_wmi_failed(&mut r.hal, &r.io, &op, 110, 0);
    check!(
        e == TransportError::new(step::WMI_SEND, 5, 110),
        "TID 5 failure"
    );
    let d = r.cmd.consume_all(&r.io);
    check!(d.len() == 5, "five deletes");
    for (i, w) in d.iter().enumerate() {
        check!(
            w[2] == pas[4 - i] as u32 && w[3] == 0x200,
            "deletes from TID 4 down to 0"
        );
    }
    check!(r.dp.peer_rx.stats.freed == 1, "TID 5 freed");
    let p = r.dp.peer_rx.peer(0, &MAC_A).unwrap();
    check!(
        p.rx_tid.iter().all(|t| !t.active) && p.rx_tid[6].size == 0,
        "TIDs 6..16 never set up"
    );
    check!(!p.dp_setup_done, "no frag setup");

    // Update path: WMI for TID 2 fails while its queue exists → TID 2 is
    // not freed but deleted with 1 and 0.
    let mut r = rig(64);
    full_setup(&mut r, 0, MAC_A, 0);
    let (mut op, _) = r.dp.peer_setup_begin(0, MAC_A, 0);
    for _ in 0..3 {
        r.dp.peer_setup_next(&mut r.hal, &r.io, &mut op, 0)
            .unwrap()
            .unwrap();
    }
    check!(r.cmd.consume_all(&r.io).len() == 3, "three updates");
    let pa2 = tid_paddr(&r, &MAC_A, 2);
    r.dp.peer_setup_wmi_failed(&mut r.hal, &r.io, &op, 110, 0);
    let d = r.cmd.consume_all(&r.io);
    check!(
        d.len() == 3 && d[0][2] == pa2 as u32 && d[0][3] == 0x200,
        "TID 2, 1, 0 deleted"
    );
    check!(
        r.dp.peer_rx.stats.freed == 0 && r.dp.peer_rx.reo_cmd_list.len() == 3,
        "update-path queue goes through the delete"
    );
    let p = r.dp.peer_rx.peer(0, &MAC_A).unwrap();
    check!(
        (3..17).all(|t| p.rx_tid[t].active),
        "TIDs above the failure untouched"
    );

    // REO update failure inside setup (ring full) unwinds TID t..0.
    let mut r = rig(8);
    full_setup(&mut r, 0, MAC_A, 0);
    for _ in 0..6 {
        let mut c = HalReoCmd::default();
        let _ = r.dp.send_reo_cmd(
            &mut r.hal,
            &r.io,
            reo_cmd_type::GET_QUEUE_STATS,
            &mut c,
            None,
            0,
        );
    }
    let (mut op, _) = r.dp.peer_setup_begin(0, MAC_A, 0);
    check!(
        r.dp.peer_setup_next(&mut r.hal, &r.io, &mut op, 0).is_ok(),
        "TID 0 update takes the last slot"
    );
    let e = r.dp.peer_setup_next(&mut r.hal, &r.io, &mut op, 0);
    check!(
        e.map_err(|e| e.step) == Err(step::REO_CMD_RING_FULL),
        "TID 1 update: ring full"
    );
    check!(
        r.dp.peer_rx.stranded.len() == 2,
        "TID 1 and 0 deletes cannot be queued: kept"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_peer_setup_unwind);

// ── ADDBA stop, unmap ─────────────────────────────────────────────

fn smoke_ath11k_dp_peer_ampdu_stop_and_unmap() -> TestResult {
    let mut r = rig(64);
    // Inactive TID: nothing to do.
    check!(
        r.dp.ampdu_stop(&mut r.hal, &r.io, 0, &MAC_A, 5, 0) == Ok(None),
        "no queue: no-op"
    );
    full_setup(&mut r, 0, MAC_A, 0);
    let pa0 = tid_paddr(&r, &MAC_A, 0);
    let pa5 = tid_paddr(&r, &MAC_A, 5);
    let c =
        r.dp.ampdu_stop(&mut r.hal, &r.io, 0, &MAC_A, 5, 0)
            .unwrap()
            .expect("WMI");
    // Linux updates peer->rx_tid (TID 0) with window 1, no SSN.
    let e = r.cmd.consume_all(&r.io);
    check!(
        e.len() == 1 && e[0][2] == pa0 as u32 && e[0][3] == 1 << 18 && e[0][5] == 1,
        "REO update on TID 0's queue (Linux quirk)"
    );
    check!(
        w32(&c.buf, 4) == 5 && w32(&c.buf, 5) == pa5 as u32 && w32(&c.buf, 9) == 1,
        "WMI: TID 5's queue, window 1"
    );

    // HTT PEER_UNMAP with live queues: the descriptors are kept.
    let unmap = (4u32 | 3 << 16).to_le_bytes();
    r.dp.htt_t2h_msg_handler(&unmap).unwrap();
    check!(
        r.dp.peer_rx.peer(0, &MAC_A).is_none()
            && r.dp.peer_rx.stranded.len() == 17
            && r.dp.peer_rx.stats.freed == 0,
        "unmapped peer's queues kept"
    );
    // A re-mapped peer starts fresh.
    r.dp.htt_t2h_msg_handler(&peer_map(0, 9, &MAC_A)).unwrap();
    let cmds = full_setup(&mut r, 0, MAC_A, 0);
    check!(
        cmds.len() == 18 && r.cmd.pending(&r.io) == 0,
        "fresh setup after re-map (no update path)"
    );
    check!(
        r.dp.peer_rx.peer(0, &MAC_A).unwrap().peer_id == 9,
        "new peer id"
    );

    // ath11k_mac_peer_cleanup_all.
    r.dp.peer_cleanup_all(&mut r.hal, &r.io, 0);
    check!(
        r.cmd.consume_all(&r.io).len() == 17
            && r.dp.peer_rx.peers.is_empty()
            && r.dp.peers.is_empty(),
        "cleanup all"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_peer_ampdu_stop_and_unmap
);
