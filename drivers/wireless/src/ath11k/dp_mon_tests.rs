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
    let desc = ipq8074_desc(3, decap::RAW as u32, 36);
    let (link, _) = lay_mpdu(&io, &mut r, &desc, &raw_mpdu(64));
    kt_assert!(r.dst.produce(&io, &dst_entry(link)));
    let mut budget = 8;
    dp.process_mon_rings_for(&mut hal, &io, 0, 0, &mut budget);
    kt_assert!(dp.take_mon_rx().is_empty());
    kt_assert_eq!(r.dst.pending(&io), 1, "dst untouched while stopped");

    // Started, but the status PPDU (2) is behind the MPDU's (3).
    kt_assert!(dp.set_monitor_started(0, true));
    let s = r.status.consume(&io).unwrap();
    write_status(buf_addr_get(s[0], s[1]).0, 2, None);
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
