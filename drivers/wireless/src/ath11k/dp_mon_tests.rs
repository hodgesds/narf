//! Monitor-mode receive (`dp_mon`): the rxdma1 monitor destination path
//! on an IPQ8074-profile DP (RAM-backed HAL, the device side modelled
//! on the HTT SRING_SETUP rings). Fixture-only; nothing here has run on
//! IPQ / QCN9074 silicon.

use alloc::vec;
use alloc::vec::Vec;
use core::mem::offset_of;

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use super::dp::*;
use super::dp_mon::*;
use super::dp_ring::*;
use super::dp_tests::{lmac, phys_wr32, phys_write, rig_for_rev, DevRing, Rig};
use super::hal::field_prep;
use super::hal_tests::RecIo;
use super::htt::HttRingId;
use super::hw::HwRev;
use super::ipq8074::{HalRxDescIpq8074, RxMpduStartIpq8074, RxMsduStartIpq8074};

pub(super) const SIZES: DpRingSizes = DpRingSizes {
    wbm_release: 16,
    tcl_cmd: 8,
    tcl_status: 8,
    tcl_data: Some(8),
    tx_comp: 16,
    reo_reinject: 8,
    rx_release: 16,
    reo_exception: 16,
    reo_cmd: 8,
    reo_status: 16,
    reo_dst: 16,
    rxdma_buf: 16,
    rx_mac_buf: 16,
    rxdma_err_dst: 16,
    rxdma_mon_status: 8,
    rxdma_mon_buf: 8,
    rxdma_mon_dst: 8,
    rxdma_mon_desc: 8,
    tx_status_fifo: 8,
    n_link_desc: Some(64),
};

/// The device side of one pdev's monitor rings, found by HTT ring id in
/// its SRING_SETUP batch.
pub(super) struct MonRings {
    pub(super) buf: DevRing,
    pub(super) dst: DevRing,
    pub(super) desc: DevRing,
    pub(super) status: DevRing,
}

pub(super) fn mon_rings(msgs: &[Vec<u8>]) -> MonRings {
    let find = |id: HttRingId| {
        let m = msgs
            .iter()
            .find(|m| (m[2] as u32) == id as u32)
            .expect("monitor SRING_SETUP");
        lmac(m)
    };
    MonRings {
        buf: find(HttRingId::RxdmaMonitorBuf),
        dst: find(HttRingId::RxdmaMonitorDest),
        desc: find(HttRingId::RxdmaMonitorDesc),
        status: find(HttRingId::RxdmaMonitorStatus),
    }
}

const fn tlv_hdr(tag: u32, len: u32) -> u32 {
    (tag << 1) | (len << 10)
}

/// A DONE status buffer: `HAL_RX_STATUS_BUFFER_DONE`, `HAL_RX_PPDU_START`
/// (`ppdu_id`), `HAL_PHYRX_RSSI_LEGACY` (`rssi_comb`, when given) and
/// `HAL_RX_PPDU_END_STATUS_DONE`.
pub(super) fn write_status(pa: u64, ppdu_id: u32, rssi_comb: Option<u8>) {
    let mut w: Vec<u32> = vec![tlv_hdr(status_tag::RX_STATUS_BUFFER_DONE, 0)];
    w.extend_from_slice(&[tlv_hdr(status_tag::RX_PPDU_START, 12), ppdu_id, 0, 0]);
    if let Some(r) = rssi_comb {
        w.push(tlv_hdr(status_tag::PHYRX_RSSI_LEGACY, 144));
        let mut v = [0u32; 36];
        v[35] = (r as u32) << 8;
        w.extend_from_slice(&v);
    }
    w.push(tlv_hdr(status_tag::RX_PPDU_END_STATUS_DONE, 0));
    for (i, v) in w.iter().enumerate() {
        phys_wr32(pa + 4 * i as u64, *v);
    }
}

/// An IPQ8074 RX descriptor (`struct hal_rx_desc_ipq8074`) with the
/// fields the monitor path reads: MPDU_START tag + PPDU id, decap
/// format, `phy_meta_data`.
pub(super) fn ipq8074_desc(ppdu_id: u16, decap: u32, meta: u32) -> Vec<u8> {
    let mut b = vec![0u8; HalRxDescIpq8074::SIZE];
    let put = |b: &mut [u8], off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(
        &mut b,
        offset_of!(HalRxDescIpq8074, mpdu_start_tag),
        &tlv_hdr(status_tag::RX_MPDU_START, 0).to_le_bytes(),
    );
    let mpdu = offset_of!(HalRxDescIpq8074, mpdu_start);
    put(
        &mut b,
        mpdu + offset_of!(RxMpduStartIpq8074, phy_ppdu_id),
        &ppdu_id.to_le_bytes(),
    );
    let msdu = offset_of!(HalRxDescIpq8074, msdu_start);
    put(
        &mut b,
        msdu + offset_of!(RxMsduStartIpq8074, info2),
        &field_prep(RX_MSDU_START_INFO2_DECAP_FORMAT, decap).to_le_bytes(),
    );
    put(
        &mut b,
        msdu + offset_of!(RxMsduStartIpq8074, phy_meta_data),
        &meta.to_le_bytes(),
    );
    b
}

/// A beacon-shaped RAW MPDU of `len` bytes including a 4-byte FCS.
pub(super) fn raw_mpdu(len: usize) -> Vec<u8> {
    let mut f = vec![0x80, 0x00, 0, 0];
    f.extend_from_slice(&[0xff; 6]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0xaa]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0xaa]);
    f.extend_from_slice(&[0x10, 0x00]);
    while f.len() < len {
        f.push(f.len() as u8);
    }
    f
}

/// Lay one MPDU into monitor buffers (`desc ‖ payload` each, the first
/// `DP_RX_BUFFER_SIZE - hal_desc_sz` payload bytes per buffer), write
/// the MSDU link descriptor taken from the desc ring, and return the
/// link's ring words for the destination entry.
pub(super) fn lay_mpdu(
    io: &RecIo,
    rings: &mut MonRings,
    desc: &[u8],
    mpdu: &[u8],
) -> ([u32; 2], usize) {
    let per = DP_RX_BUFFER_SIZE as usize - desc.len();
    let chunks: Vec<&[u8]> = mpdu.chunks(per).collect();
    let link = rings
        .desc
        .consume(io)
        .expect("posted monitor link descriptor");
    let (link_pa, _, _) = buf_addr_get(link[0], link[1]);
    for (i, c) in chunks.iter().enumerate() {
        let b = rings.buf.consume(io).expect("posted monitor buffer");
        let (pa, cookie, mgr) = buf_addr_get(b[0], b[1]);
        let mut bytes = desc.to_vec();
        bytes.extend_from_slice(c);
        phys_write(pa, &bytes);
        let w = buf_addr_words(pa, cookie, mgr);
        let cont = if i + 1 < chunks.len() {
            RX_MSDU_DESC_INFO0_MSDU_CONTINUATION
        } else {
            0
        };
        let info0 = cont | field_prep(RX_MSDU_DESC_INFO0_MSDU_LENGTH, mpdu.len() as u32);
        let base = link_pa + 4 * (8 + 4 * i as u64);
        phys_wr32(base, w[0]);
        phys_wr32(base + 4, w[1]);
        phys_wr32(base + 8, info0);
    }
    // No next link descriptor.
    phys_wr32(link_pa + 4, 0);
    phys_wr32(link_pa + 8, 0);
    ([link[0], link[1]], chunks.len())
}

/// The REO-entrance destination entry for `link` (one MSDU, pushed by
/// routing instruction).
pub(super) fn dst_entry(link: [u32; 2]) -> [u32; 8] {
    let mut e = [0u32; 8];
    e[0] = link[0];
    e[1] = link[1];
    e[2] = field_prep(RX_MPDU_DESC_INFO0_MSDU_COUNT, 1);
    e[6] = field_prep(
        HAL_REO_ENTR_RING_INFO1_RXDMA_PUSH_REASON,
        reo::PUSH_REASON_ROUTING_INSTRUCTION,
    );
    e
}

/// Status ring PPDU done → destination ring MPDU popped over two
/// continuation buffers → RAW merge (FCS stripped) → one monitor frame
/// with the descriptor's channel and the status RSSI, which encodes as
/// radiotap. The link descriptor returns to the desc ring and both
/// buffers are replenished.
fn smoke_ath11k_dp_mon_dest_rxdma1_deliver() -> TestResult {
    let Rig {
        mut hal,
        io,
        mut dp,
        msgs,
    } = rig_for_rev(SIZES, HwRev::Ipq8074);
    kt_assert!(dp.monitor_capable());
    let mut r = mon_rings(&msgs);
    let buf_posted = r.buf.pending(&io);
    let desc_posted = r.desc.pending(&io);
    kt_assert!(dp.set_monitor_started(0, true));

    let s = r.status.consume(&io).expect("status buffer");
    write_status(buf_addr_get(s[0], s[1]).0, 7, Some(40));
    // `ath11k_hal_srng_src_peek` reaches a status buffer only once the
    // device has moved past it.
    r.status.consume(&io).expect("next status buffer");
    let mpdu = raw_mpdu(1700);
    let desc = ipq8074_desc(7, decap::RAW as u32, (5180 << 16) | 36);
    let (link, nbufs) = lay_mpdu(&io, &mut r, &desc, &mpdu);
    kt_assert_eq!(nbufs, 2);
    kt_assert!(r.dst.produce(&io, &dst_entry(link)));

    let mut budget = 8;
    dp.process_mon_rings_for(&mut hal, &io, 0, 0, &mut budget);
    let frames = dp.take_mon_rx();
    kt_assert_eq!(frames.len(), 1);
    let f = &frames[0];
    kt_assert_eq!(f.frame, mpdu[..mpdu.len() - HAL_RX_FCS_LEN].to_vec());
    kt_assert_eq!(f.freq_mhz, Some(5180));
    kt_assert_eq!(f.signal_dbm, Some(-55));
    kt_assert_eq!(f.mac_id, 0);
    let st = dp.mon_stats_for(0).unwrap().clone();
    kt_assert_eq!(st.status_ppdu_done, 1);
    kt_assert_eq!(st.dest_mpdu_done, 1);
    kt_assert_eq!(st.dest_ppdu_done, 1);
    kt_assert_eq!(r.desc.pending(&io), desc_posted, "link descriptor returned");
    kt_assert_eq!(r.buf.pending(&io), buf_posted, "both buffers replenished");
    kt_assert_eq!(r.dst.pending(&io), 0, "destination entry consumed");
    let rt = narf_wireless::monitor::encode(
        &f.frame,
        narf_wireless::monitor::Metadata {
            frequency_mhz: f.freq_mhz.unwrap(),
            signal_dbm: f.signal_dbm,
        },
    );
    kt_assert!(rt.is_ok_and(|b| b.len() == f.frame.len() + 15 && b[0] == 0));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_mon_dest_rxdma1_deliver
);

/// Monitor not started: the status buffer feeds only statistics and the
/// destination ring is left untouched. A destination MPDU whose PPDU id
/// is ahead of the status ring ends the pass without delivery.
fn smoke_ath11k_dp_mon_dest_gating() -> TestResult {
    let Rig {
        mut hal,
        io,
        mut dp,
        msgs,
    } = rig_for_rev(SIZES, HwRev::Ipq8074);
    let mut r = mon_rings(&msgs);
    let s = r.status.consume(&io).unwrap();
    write_status(buf_addr_get(s[0], s[1]).0, 3, None);
    let s2 = r.status.consume(&io).unwrap();
    let desc = ipq8074_desc(3, decap::RAW as u32, 36);
    let (link, _) = lay_mpdu(&io, &mut r, &desc, &raw_mpdu(64));
    kt_assert!(r.dst.produce(&io, &dst_entry(link)));
    let mut budget = 8;
    dp.process_mon_rings_for(&mut hal, &io, 0, 0, &mut budget);
    kt_assert!(dp.take_mon_rx().is_empty());
    kt_assert_eq!(r.dst.pending(&io), 1, "dst untouched while stopped");

    // Started, but the status PPDU (2) is behind the MPDU's (3).
    kt_assert!(dp.set_monitor_started(0, true));
    write_status(buf_addr_get(s2[0], s2[1]).0, 2, None);
    r.status.consume(&io).unwrap();
    let mut budget = 8;
    dp.process_mon_rings_for(&mut hal, &io, 0, 0, &mut budget);
    kt_assert!(dp.take_mon_rx().is_empty());
    kt_assert_eq!(r.dst.pending(&io), 1, "entry held for its PPDU");
    kt_assert_eq!(dp.mon_stats_for(0).unwrap().dest_mpdu_done, 0);
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_mon_dest_gating);

/// `parse_mon_ppdu` and the `phy_meta_data` channel decode.
fn smoke_ath11k_dp_mon_status_parse_and_freq() -> TestResult {
    kt_assert_eq!(rx_h_ppdu_freq(1), Some(2412));
    kt_assert_eq!(rx_h_ppdu_freq(14), Some(2484));
    kt_assert_eq!(rx_h_ppdu_freq(149), Some(5745));
    kt_assert_eq!(rx_h_ppdu_freq((5955 << 16) | 1), Some(5955));
    kt_assert_eq!(rx_h_ppdu_freq(0), None);
    let mem = super::hal::DmaMem::alloc(DP_RX_BUFFER_SIZE as usize, 8).unwrap();
    write_status(mem.paddr(), 0x1234, Some(10));
    let p = parse_mon_ppdu(&mem);
    kt_assert_eq!(p.status, HalMonStatus::PpduDone);
    kt_assert_eq!(p.info.ppdu_id, 0x1234);
    kt_assert_eq!(p.info.rssi_comb, Some(10));
    mem.wr32(0, tlv_hdr(status_tag::DUMMY, 0));
    kt_assert_eq!(parse_mon_ppdu(&mem).status, HalMonStatus::BufDone);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_mon_status_parse_and_freq
);

/// A `struct hal_rx_desc_qcn9074` with the monitor fields (as
/// [`ipq8074_desc`]).
fn qcn9074_desc(ppdu_id: u16, decap: u32, meta: u32) -> Vec<u8> {
    use super::qcn9074::{HalRxDescQcn9074, RxMpduStartQcn9074, RxMsduStartQcn9074};
    let mut b = vec![0u8; HalRxDescQcn9074::SIZE];
    let put = |b: &mut [u8], off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(
        &mut b,
        offset_of!(HalRxDescQcn9074, mpdu_start_tag),
        &tlv_hdr(status_tag::RX_MPDU_START, 0).to_le_bytes(),
    );
    let mpdu = offset_of!(HalRxDescQcn9074, mpdu_start);
    put(
        &mut b,
        mpdu + offset_of!(RxMpduStartQcn9074, phy_ppdu_id),
        &ppdu_id.to_le_bytes(),
    );
    let msdu = offset_of!(HalRxDescQcn9074, msdu_start);
    put(
        &mut b,
        msdu + offset_of!(RxMsduStartQcn9074, info2),
        &field_prep(RX_MSDU_START_INFO2_DECAP_FORMAT, decap).to_le_bytes(),
    );
    put(
        &mut b,
        msdu + offset_of!(RxMsduStartQcn9074, phy_meta_data),
        &meta.to_le_bytes(),
    );
    b
}

/// A `struct hal_sw_monitor_ring` entry.
fn sw_mon_entry(link: [u32; 2], status: [u32; 2], end_of_ppdu: bool, ppdu_id: u32) -> [u32; 8] {
    let mut e = [0u32; 8];
    e[0] = link[0];
    e[1] = link[1];
    e[2] = field_prep(RX_MPDU_DESC_INFO0_MSDU_COUNT, (!end_of_ppdu) as u32);
    e[4] = status[0];
    e[5] = status[1];
    e[6] = field_prep(
        HAL_SW_MON_RING_INFO0_RXDMA_PUSH_REASON,
        reo::PUSH_REASON_ROUTING_INSTRUCTION,
    ) | field_prep(HAL_SW_MON_RING_INFO0_STATUS_BUF_CNT, 1)
        | if end_of_ppdu {
            HAL_SW_MON_RING_INFO0_END_OF_PPDU
        } else {
            0
        };
    e[7] = field_prep(HAL_SW_MON_RING_INFO1_PHY_PPDU_ID, ppdu_id);
    e
}

/// QCN9074 full monitor: the MPDU entries of a PPDU collect until the
/// END_OF_PPDU entry, which holds the destination ring on its status
/// buffer; the status reap MATCHes that buffer and delivers the PPDU's
/// MPDUs. A PPDU whose status buffer is ahead (LEAD) is dropped.
fn smoke_ath11k_dp_full_mon_qcn9074() -> TestResult {
    let Rig {
        mut hal,
        io,
        mut dp,
        msgs,
    } = rig_for_rev(SIZES, HwRev::Qcn9074Hw10);
    kt_assert!(dp.monitor_capable() && dp.cfg.full_monitor_mode);
    let mut r = mon_rings(&msgs);
    kt_assert!(dp.set_monitor_started(0, true));
    let s = r.status.consume(&io).unwrap();
    let status_pa = buf_addr_get(s[0], s[1]).0;
    write_status(status_pa, 9, Some(30));
    r.status.consume(&io).unwrap();
    let mpdu = raw_mpdu(100);
    let desc = qcn9074_desc(9, decap::RAW as u32, 6);
    let (link, _) = lay_mpdu(&io, &mut r, &desc, &mpdu);
    kt_assert!(r.dst.produce(&io, &sw_mon_entry(link, [0, 0], false, 9)));
    kt_assert!(r
        .dst
        .produce(&io, &sw_mon_entry([0, 0], [s[0], s[1]], true, 9)));
    let mut budget = 8;
    dp.process_mon_rings_for(&mut hal, &io, 0, 0, &mut budget);
    let frames = dp.take_mon_rx();
    kt_assert_eq!(frames.len(), 1);
    kt_assert_eq!(
        frames[0].frame,
        mpdu[..mpdu.len() - HAL_RX_FCS_LEN].to_vec()
    );
    kt_assert_eq!(frames[0].freq_mhz, Some(2437));
    kt_assert_eq!(frames[0].signal_dbm, Some(-65));
    let pdev = dp.pdev.as_ref().unwrap();
    kt_assert!(!pdev.mon.hold_mon_dst_ring);
    kt_assert_eq!(pdev.mon.stats.dest_ppdu_done, 1);
    kt_assert_eq!(pdev.mon.stats.dest_mpdu_done, 1);
    kt_assert_eq!(r.dst.pending(&io), 0);

    // A status buffer for PPDU 12 while the destination PPDU is 10:
    // LEAD → the held MPDU is dropped.
    let s = r.status.consume(&io).unwrap();
    write_status(buf_addr_get(s[0], s[1]).0, 12, None);
    r.status.consume(&io).unwrap();
    let (link, _) = lay_mpdu(&io, &mut r, &qcn9074_desc(10, 0, 6), &raw_mpdu(80));
    kt_assert!(r.dst.produce(&io, &sw_mon_entry(link, [0, 0], false, 10)));
    let other = buf_addr_words(0x1000, 0, 0);
    kt_assert!(r.dst.produce(&io, &sw_mon_entry([0, 0], other, true, 10)));
    let mut budget = 8;
    dp.process_mon_rings_for(&mut hal, &io, 0, 0, &mut budget);
    kt_assert!(dp.take_mon_rx().is_empty());
    let pdev = dp.pdev.as_ref().unwrap();
    kt_assert!(!pdev.mon.hold_mon_dst_ring && pdev.mon.full_mon_mpdus.is_empty());
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_full_mon_qcn9074);

/// `ath11k_dp_tx_htt_monitor_mode_ring_config` on QCN9074: the full
/// monitor mode config first, then the monitor buffer ring and status
/// ring filters; reset restores the default status filter.
fn smoke_ath11k_dp_mon_ring_config_msgs() -> TestResult {
    let Rig { hal, dp, .. } = rig_for_rev(SIZES, HwRev::Qcn9074Hw10);
    let word = |m: &[u8], i: usize| u32::from_le_bytes(m[4 * i..4 * i + 4].try_into().unwrap());
    let on = dp.monitor_mode_ring_config_msgs(&hal, 0, false).unwrap();
    kt_assert_eq!(on.len(), 3);
    kt_assert_eq!(word(&on[0], 0), 0x17);
    kt_assert_eq!(word(&on[0], 1), 1 | (2 << 3) | (1 << 1) | (1 << 2));
    let f = super::htt::MONITOR_MODE_BUF_FILTER;
    kt_assert_eq!(word(&on[1], 0) & 0xff, 0xc);
    kt_assert_eq!(word(&on[1], 1) & 0xffff, DP_RXDMA_REFILL_RING_SIZE);
    kt_assert_eq!(
        [
            word(&on[1], 2),
            word(&on[1], 3),
            word(&on[1], 4),
            word(&on[1], 5),
            word(&on[1], 6)
        ],
        [
            f.pkt_filter_flags0,
            f.pkt_filter_flags1,
            f.pkt_filter_flags2,
            f.pkt_filter_flags3,
            f.rx_filter
        ]
    );
    // HTT_RX_MON_MO_MGMT_PKT_FILTER_TLV_FLAGS0_BEACON / _RESERVED_7.
    kt_assert!(f.pkt_filter_flags0 & (1 << 26) != 0 && f.pkt_filter_flags0 & (1 << 23) != 0);
    kt_assert_eq!(
        word(&on[2], 6),
        super::htt::HTT_RX_MON_FILTER_TLV_FLAGS_MON_STATUS_RING
    );
    let off = dp.monitor_mode_ring_config_msgs(&hal, 0, true).unwrap();
    kt_assert_eq!(word(&off[0], 1), 1 | (2 << 3));
    kt_assert_eq!(word(&off[1], 2) | word(&off[1], 6), 0);
    kt_assert_eq!(
        word(&off[2], 6),
        super::htt::MON_STATUS_FILTER_DEFAULT.rx_filter
    );
    kt_assert!(dp.monitor_mode_ring_config_msgs(&hal, 1, false).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_mon_ring_config_msgs
);
