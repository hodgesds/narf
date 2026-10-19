//! RX fragment reassembly — the defragmentation ath11k does in the host
//! for 802.11 fragments the REO hands to the exception ring.
//!
//! | NARF | Linux `dp_rx.c` |
//! |---|---|
//! | [`Dp::rx_err_buf`] | `ath11k_dp_process_rx_err_buf` |
//! | [`Dp::frag_h_mpdu`] | `ath11k_dp_rx_frag_h_mpdu` (+ `ath11k_dp_rx_h_sort_frags`) |
//! | `Dp::defrag_validate_incr_pn` | `ath11k_dp_rx_h_defrag_validate_incr_pn` (+ `ath11k_dp_rx_h_get_pn`) |
//! | `Dp::defrag` | `ath11k_dp_rx_h_defrag` (+ `ath11k_dp_rx_h_undecap_frag`) |
//! | `Dp::defrag_reo_reinject` | `ath11k_dp_rx_h_defrag_reo_reinject` |
//! | [`Dp::frags_cleanup`] | `ath11k_dp_rx_frags_cleanup` |
//! | [`Dp::peer_frags_flush`] | `ath11k_peer_frags_flush` |
//! | [`Dp::service_frag_timers`] | `ath11k_dp_rx_frag_timer` (`rx_tid->frag_timer`) |
//!
//! The fragments are raw 802.11 MPDUs behind their RX descriptor (one
//! MSDU per link descriptor). Once every fragment of a sequence is in
//! (the bitmap covers `0..=last_frag_no`), the PNs must increase by one
//! (CCMP / GCMP), the crypto fields between fragments are stripped, the
//! payloads joined behind the first fragment's header (More Fragments
//! cleared), and the MPDU re-enters the REO through the reinject
//! (SW2REO) ring in a fresh buffer of the refill ring's IDR, named by the
//! first fragment's link descriptor. It comes back on a REO destination
//! ring as a raw MPDU ([`super::dp_ring`] undecaps it).
//!
//! Deliberate deviation: the reinjected buffer's id is allocated from 1
//! like every refill buffer (Linux `idr_alloc(.., 0, ..)` hands out id 0,
//! which `ath11k_dp_process_rx` then skips as invalid, losing the frame).

extern crate alloc;

use alloc::vec::Vec;

use super::dp::*;
use super::dp_peer::IEEE80211_NUM_TIDS;
use super::dp_ring::{
    buf_addr_get, buf_addr_words, enc, ieee80211_da_sa, ieee80211_hdrlen, Dp, RxBuf,
    DP_RXDMA_BUF_COOKIE_BUF_ID, DP_RXDMA_BUF_COOKIE_PDEV_ID, HAL_WBM_REL_BM_ACT_PUT_IN_IDLE,
    IEEE80211_FCTL_ORDER, IEEE80211_QOS_CTL_LEN, IEEE80211_QOS_CTL_TID_MASK,
    IEEE80211_STYPE_QOS_DATA, RX_DESC_DECRYPT_STATUS_CODE_OK,
};
use super::hal::{field_get, field_prep, genmask, DmaMem, Hal};
use super::hw::rbm;
use super::power::ChipIo;
use narf_crypto::michael_mic::michael_mic;

/// `ATH11K_DP_RX_FRAGMENT_TIMEOUT_MS` — `2 * HZ` jiffies, i.e. 2 s.
pub const ATH11K_DP_RX_FRAGMENT_TIMEOUT_MS: u64 = 2000;
/// `IEEE80211_SCTL_FRAG`.
pub const IEEE80211_SCTL_FRAG: u16 = 0x000f;
/// `IEEE80211_FCTL_MOREFRAGS`.
pub const IEEE80211_FCTL_MOREFRAGS: u16 = 0x0400;
/// `FCS_LEN`.
pub const FCS_LEN: usize = 4;
/// `IEEE80211_CCMP_MIC_LEN`, reused as `MICHAEL_MIC_LEN` by TKIP.
pub const TKIP_MIC_LEN: usize = narf_crypto::michael_mic::MIC_LEN;
/// `IEEE80211_TKIP_ICV_LEN`.
pub const TKIP_ICV_LEN: usize = 4;

pub const EINVAL: i32 = 22;
pub const ENOENT: i32 = 2;
pub const ENOMEM: i32 = 12;
pub const ENOSPC: i32 = 28;

/// `RX_FLAG_*` bits `ath11k_dp_rx_h_undecap_frag` / `_undecap_raw` test.
pub mod rx_flag {
    pub const MIC_STRIPPED: u32 = 1 << 0;
    pub const ICV_STRIPPED: u32 = 1 << 1;
    pub const IV_STRIPPED: u32 = 1 << 2;
}

/// `ath11k_dp_rx_crypto_mic_len`.
pub fn crypto_mic_len(enctype: u32) -> usize {
    match enctype {
        enc::CCMP_128 => 8,
        enc::CCMP_256 | enc::GCMP_128 | enc::AES_GCMP_256 => 16,
        _ => 0,
    }
}

/// `ath11k_dp_rx_crypto_param_len`.
pub fn crypto_param_len(enctype: u32) -> usize {
    match enctype {
        enc::TKIP_NO_MIC | enc::TKIP_MIC | enc::CCMP_128 | enc::CCMP_256 => 8,
        enc::GCMP_128 | enc::AES_GCMP_256 => 8,
        _ => 0,
    }
}

/// `ath11k_dp_rx_crypto_icv_len`.
pub fn crypto_icv_len(enctype: u32) -> usize {
    match enctype {
        enc::TKIP_NO_MIC | enc::TKIP_MIC => TKIP_ICV_LEN,
        _ => 0,
    }
}

/// `ath11k_dp_rx_h_mpdu_start_enctype`.
pub fn mpdu_start_enctype(d: &HalRxDescWcn6855) -> u32 {
    if !d.encrypt_valid() {
        return enc::OPEN;
    }
    d.encrypt_type()
}

/// `ath11k_dp_rx_h_attn_is_decrypted`.
pub fn attn_is_decrypted(d: &HalRxDescWcn6855) -> bool {
    field_get(RX_ATTENTION_INFO2_DCRYPT_STATUS_CODE, d.attention.info2)
        == RX_DESC_DECRYPT_STATUS_CODE_OK
}

/// `ath11k_dp_rx_h_attn_is_mcbc`.
pub fn attn_is_mcbc(d: &HalRxDescWcn6855) -> bool {
    d.first_msdu() && d.attention.info1 & RX_ATTENTION_INFO1_MCAST_BCAST != 0
}

fn fc_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// The fragment number of the 802.11 header after the descriptor
/// (`ath11k_dp_rx_h_mpdu_start_frag_no`).
fn frag_no(msdu: &[u8], desc_sz: usize) -> u16 {
    fc_at(msdu, desc_sz + 22) & IEEE80211_SCTL_FRAG
}

/// `ath11k_dp_rx_h_get_pn`: the 48-bit PN of a CCMP / GCMP header
/// behind the 802.11 header.
fn get_pn(msdu: &[u8], desc_sz: usize) -> Option<u64> {
    let fc = fc_at(msdu, desc_sz);
    let e = msdu.get(desc_sz + ieee80211_hdrlen(fc)..)?;
    if e.len() < 8 {
        return None;
    }
    Some(
        e[0] as u64
            | (e[1] as u64) << 8
            | (e[4] as u64) << 16
            | (e[5] as u64) << 24
            | (e[6] as u64) << 32
            | (e[7] as u64) << 40,
    )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&l, &r) in left.iter().zip(right) {
        diff |= l ^ r;
    }
    diff == 0
}

/// Verify the retained Michael MIC in a decrypted raw TKIP MPDU.
///
/// `frame` starts at the 802.11 header and retains the firmware layout
/// `header || TKIP IV || data || Michael || ICV || FCS`. The returned offset
/// names the eight-byte Michael MIC, which the caller removes after a
/// successful check. This is also used for ordinary (non-fragmented) raw
/// MPDUs because NARF has no mac80211 layer after ath11k DP.
pub fn verify_tkip_mic_frame(frame: &[u8], key: &[u8; 8]) -> Option<usize> {
    if frame.len() < 24 {
        return None;
    }
    let fc = fc_at(frame, 0);
    let hdr_len = ieee80211_hdrlen(fc);
    let head_len = hdr_len.checked_add(crypto_param_len(enc::TKIP_MIC))?;
    let tail_len = TKIP_MIC_LEN
        .checked_add(TKIP_ICV_LEN)?
        .checked_add(FCS_LEN)?;
    let mic_start = frame.len().checked_sub(tail_len)?;
    if mic_start < head_len || frame.len() < hdr_len {
        return None;
    }
    let (da, sa) = ieee80211_da_sa(frame)?;
    let tid = if fc & IEEE80211_STYPE_QOS_DATA != 0 {
        let ht_control_len = if fc & IEEE80211_FCTL_ORDER != 0 { 4 } else { 0 };
        let qos = hdr_len.checked_sub(IEEE80211_QOS_CTL_LEN + ht_control_len)?;
        *frame.get(qos)? & IEEE80211_QOS_CTL_TID_MASK as u8
    } else {
        0
    };
    let expected = michael_mic(key, &da, &sa, tid, &frame[head_len..mic_start]);
    constant_time_eq(&expected, &frame[mic_start..mic_start + TKIP_MIC_LEN]).then_some(mic_start)
}

impl Dp {
    /// Linux `ath11k_dp_process_rx_err_buf`: take the exception ring's
    /// buffer `buf_id`; unless `drop`, hand it (descriptor + `msdu_len`
    /// bytes) to [`Dp::frag_h_mpdu`], whose failure frees it and returns
    /// the link descriptor. `true` = reaped (Linux returns 0).
    pub(super) fn rx_err_buf(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        ring_desc: &[u32; 16],
        buf_id: u32,
        drop: bool,
    ) -> bool {
        let Some(data) = self.take_rx_buf(buf_id) else {
            // "rx err buf with invalid buf_id"
            self.stats.rx_invalid_cookie += 1;
            return false;
        };
        if drop {
            return true;
        }
        let desc_sz = self.cfg.hal_desc_sz;
        let Some(rxd) = HalRxDescWcn6855::from_bytes(&data) else {
            return true;
        };
        let msdu_len = rxd.msdu_len() as usize;
        if msdu_len + desc_sz > DP_RX_BUFFER_SIZE as usize {
            // "invalid msdu leng": freed, the link descriptor kept (as
            // Linux).
            self.stats.rx_invalid_len += 1;
            return true;
        }
        let msdu = data[..desc_sz + msdu_len].to_vec();
        if self.frag_h_mpdu(hal, io, msdu, ring_desc).is_err() {
            self.stats.rx_err_frags_dropped += 1;
            let _ = self.link_desc_return(
                hal,
                io,
                [ring_desc[0], ring_desc[1]],
                HAL_WBM_REL_BM_ACT_PUT_IN_IDLE,
            );
        }
        true
    }

    /// Linux `ath11k_dp_rx_frag_h_mpdu`: file the fragment under its
    /// peer / TID (a new sequence number flushes what was there), keep
    /// the first fragment's ring entry (its link descriptor carries the
    /// reinjection) and return the others' link descriptors; when the
    /// set is complete, reassemble and reinject. `Err` = the caller frees
    /// the fragment and returns its link descriptor.
    pub fn frag_h_mpdu(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        msdu: Vec<u8>,
        ring_desc: &[u32; 16],
    ) -> Result<(), i32> {
        let desc_sz = self.cfg.hal_desc_sz;
        // NARF-stricter: a descriptor and a 24-byte header.
        if msdu.len() < desc_sz + 24 {
            return Err(EINVAL);
        }
        let rxd = HalRxDescWcn6855::from_bytes(&msdu).ok_or(EINVAL)?;
        let peer_id = rxd.mpdu_peer_id();
        let tid = rxd.mpdu_tid() as usize;
        let seqno = rxd.mpdu_start_seq_no();
        let frag = frag_no(&msdu, desc_sz);
        let more_frags = fc_at(&msdu, desc_sz) & IEEE80211_FCTL_MOREFRAGS != 0;
        // "Multicast/Broadcast fragments are not expected"
        if attn_is_mcbc(&rxd) {
            return Err(EINVAL);
        }
        let info1 = rxd.mpdu_start.info1;
        if info1 & RX_MPDU_START_INFO1_MPDU_SEQ_CTRL_VALID == 0
            || info1 & RX_MPDU_START_INFO1_MPDU_FCTRL_VALID == 0
            || tid > IEEE80211_NUM_TIDS
        {
            return Err(EINVAL);
        }
        // "received unfragmented packet in reo exception ring"
        if frag == 0 && !more_frags {
            return Err(EINVAL);
        }
        // ath11k_peer_find_by_id
        let Some(pi) = self.peer_rx.peers.iter().position(|p| p.peer_id == peer_id) else {
            return Err(ENOENT);
        };
        if !self.peer_rx.peers[pi].dp_setup_done {
            // "The peer %pM [%d] has uninitialized datapath"
            return Err(ENOENT);
        }
        {
            let t = &self.peer_rx.peers[pi].rx_tid[tid];
            if t.rx_frags.is_empty() || seqno != t.cur_sn {
                // "Flush stored fragments and start a new sequence"
                self.frags_cleanup(hal, io, pi, tid, true);
                self.peer_rx.peers[pi].rx_tid[tid].cur_sn = seqno;
            }
        }
        let t = &mut self.peer_rx.peers[pi].rx_tid[tid];
        if t.rx_frag_bitmap & (1 << frag) != 0 {
            // "Fragment already present"
            return Err(EINVAL);
        }
        // __fls(bitmap): the highest fragment number held.
        let fls = 15 - t.rx_frag_bitmap.leading_zeros() as u16;
        if t.rx_frag_bitmap == 0 || frag > fls {
            t.rx_frags.push(msdu);
        } else {
            // ath11k_dp_rx_h_sort_frags
            let pos = t
                .rx_frags
                .iter()
                .position(|s| frag_no(s, desc_sz) >= frag)
                .unwrap_or(t.rx_frags.len());
            t.rx_frags.insert(pos, msdu);
        }
        t.rx_frag_bitmap |= 1 << frag;
        if !more_frags {
            t.last_frag_no = frag as u8;
        }
        if frag == 0 {
            t.dst_ring_desc = Some(*ring_desc);
        } else {
            let _ = self.link_desc_return(
                hal,
                io,
                [ring_desc[0], ring_desc[1]],
                HAL_WBM_REL_BM_ACT_PUT_IN_IDLE,
            );
        }
        let now = self.now_ms;
        let t = &mut self.peer_rx.peers[pi].rx_tid[tid];
        if t.last_frag_no == 0 || t.rx_frag_bitmap != genmask(t.last_frag_no as u32, 0) as u16 {
            // mod_timer(&rx_tid->frag_timer, jiffies + ..._TIMEOUT_MS)
            t.frag_timer = Some(now + ATH11K_DP_RX_FRAGMENT_TIMEOUT_MS);
            return Ok(());
        }
        t.frag_timer = None;
        let ok = self.defrag_validate_incr_pn(pi, tid)
            && match self.defrag(pi, tid) {
                Some(skb) => self.defrag_reo_reinject(hal, io, pi, tid, skb).is_ok(),
                None => false,
            };
        if ok {
            self.stats.rx_defrag_reinjected += 1;
            self.frags_cleanup(hal, io, pi, tid, false);
        } else {
            // err_frags_cleanup: the set is dropped, frag 0's link
            // descriptor returned; the call still succeeds.
            self.stats.rx_defrag_dropped += 1;
            self.frags_cleanup(hal, io, pi, tid, true);
        }
        Ok(())
    }

    /// Linux `ath11k_dp_rx_frags_cleanup` on `peer_rx.peers[pi].rx_tid[tid]`.
    pub fn frags_cleanup(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        pi: usize,
        tid: usize,
        rel_link_desc: bool,
    ) {
        let t = &mut self.peer_rx.peers[pi].rx_tid[tid];
        let d = t.dst_ring_desc.take();
        t.cur_sn = 0;
        t.last_frag_no = 0;
        t.rx_frag_bitmap = 0;
        t.rx_frags.clear();
        if let (Some(d), true) = (d, rel_link_desc) {
            let _ = self.link_desc_return(hal, io, [d[0], d[1]], HAL_WBM_REL_BM_ACT_PUT_IN_IDLE);
        }
    }

    /// Linux `ath11k_peer_frags_flush` (`ath11k_mac_op_set_key` before a
    /// pairwise key install: "all frags in the new frag list belong to
    /// the same key").
    pub fn peer_frags_flush(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        vdev_id: u8,
        addr: &[u8; 6],
    ) {
        let Some(pi) = self
            .peer_rx
            .peers
            .iter()
            .position(|p| p.vdev_id == vdev_id && p.addr == *addr)
        else {
            return;
        };
        for tid in 0..=IEEE80211_NUM_TIDS {
            self.peer_rx.peers[pi].rx_tid[tid].frag_timer = None;
            self.frags_cleanup(hal, io, pi, tid, true);
        }
    }

    /// `ath11k_dp_rx_frag_timer` for every armed TID whose timer expired:
    /// an incomplete set is dropped (frag 0's link descriptor returned).
    pub fn service_frag_timers(&mut self, hal: &mut Hal, io: &impl ChipIo, now_ms: u64) {
        for pi in 0..self.peer_rx.peers.len() {
            for tid in 0..=IEEE80211_NUM_TIDS {
                let t = &mut self.peer_rx.peers[pi].rx_tid[tid];
                match t.frag_timer {
                    Some(at) if now_ms >= at => t.frag_timer = None,
                    _ => continue,
                }
                if t.last_frag_no != 0
                    && t.rx_frag_bitmap == genmask(t.last_frag_no as u32, 0) as u16
                {
                    continue;
                }
                self.stats.rx_defrag_timeout += 1;
                self.frags_cleanup(hal, io, pi, tid, true);
            }
        }
    }

    /// Linux `ath11k_dp_rx_h_defrag_validate_incr_pn`: CCMP / GCMP
    /// fragments must carry consecutive PNs.
    fn defrag_validate_incr_pn(&self, pi: usize, tid: usize) -> bool {
        let desc_sz = self.cfg.hal_desc_sz;
        let frags = &self.peer_rx.peers[pi].rx_tid[tid].rx_frags;
        let Some(first) = frags.first() else {
            return false;
        };
        let Some(d) = HalRxDescWcn6855::from_bytes(first) else {
            return false;
        };
        let et = mpdu_start_enctype(&d);
        if !matches!(
            et,
            enc::CCMP_128 | enc::CCMP_256 | enc::GCMP_128 | enc::AES_GCMP_256
        ) {
            return true;
        }
        let Some(mut last) = get_pn(first, desc_sz) else {
            return false;
        };
        for f in &frags[1..] {
            match get_pn(f, desc_sz) {
                Some(cur) if cur == last + 1 => last = cur,
                _ => return false,
            }
        }
        true
    }

    /// Linux `ath11k_dp_rx_h_verify_tkip_mic`.  The first fragment retains
    /// its descriptor, 802.11 header and TKIP IV; `_undecap_frag` removes
    /// those fields only from later fragments.  After joining, this is the
    /// exact `header || IV || data || Michael || ICV || FCS` layout Linux
    /// verifies before it reinjects the MPDU.
    ///
    /// Returns the Michael-MIC offset when the host-held receive direction
    /// verifies.  The caller removes the MIC before the reinjected packet
    /// reaches raw undecapsulation, mirroring mac80211's MMIC-stripped path.
    fn verify_tkip_mic(&self, pi: usize, msdu: &[u8]) -> Option<usize> {
        let desc_sz = self.cfg.hal_desc_sz;
        let frame = msdu.get(desc_sz..)?;
        let key_holder = self.peer_rx.peers.get(pi)?.tkip_rx_mic?;
        let key = key_holder.bytes();
        verify_tkip_mic_frame(frame, key).map(|mic_start| desc_sz + mic_start)
    }

    /// Linux `ath11k_dp_rx_h_defrag` (+ `ath11k_dp_rx_h_undecap_frag`):
    /// the reassembled MPDU behind the first fragment's descriptor, or
    /// `None` when it cannot be delivered.
    fn defrag(&mut self, pi: usize, tid: usize) -> Option<Vec<u8>> {
        let desc_sz = self.cfg.hal_desc_sz;
        let mut frags = core::mem::take(&mut self.peer_rx.peers[pi].rx_tid[tid].rx_frags);
        let n = frags.len();
        if n == 0 {
            return None;
        }
        // Linux keeps `is_decrypted` across the walk (not reset per
        // fragment); kept.
        let mut is_decrypted = false;
        let mut first_enc = enc::OPEN;
        for (i, skb) in frags.iter_mut().enumerate() {
            let mut flags = 0;
            let d = HalRxDescWcn6855::from_bytes(skb)?;
            let enctype = mpdu_start_enctype(&d);
            if i == 0 {
                first_enc = enctype;
            }
            if enctype != enc::OPEN {
                is_decrypted = attn_is_decrypted(&d);
            }
            if is_decrypted {
                if i != 0 {
                    flags |= rx_flag::IV_STRIPPED;
                }
                if i != n - 1 {
                    flags |= rx_flag::ICV_STRIPPED | rx_flag::MIC_STRIPPED;
                }
            }
            let fc = fc_at(skb, desc_sz);
            let hdr_len = ieee80211_hdrlen(fc);
            // "RX fragments are always raw packets"
            if i != n - 1 {
                let l = skb.len().checked_sub(FCS_LEN)?;
                skb.truncate(l);
            }
            undecap_frag(skb, desc_sz, enctype, flags)?;
            if i != 0 {
                if skb.len() < desc_sz + hdr_len {
                    return None;
                }
                skb.drain(..desc_sz + hdr_len);
            }
        }
        let mut it = frags.into_iter();
        let mut first = it.next()?;
        for s in it {
            first.extend_from_slice(&s);
        }
        let fc = fc_at(&first, desc_sz) & !IEEE80211_FCTL_MOREFRAGS;
        first[desc_sz..desc_sz + 2].copy_from_slice(&fc.to_le_bytes());
        // Linux has firmware decrypt the fragments but verifies their one
        // software Michael MIC before reinjection.  It belongs before the
        // final ICV/FCS, so leave those two fields for raw undecapsulation.
        if first_enc == enc::TKIP_MIC {
            let mic_start = self.verify_tkip_mic(pi, &first)?;
            first.drain(mic_start..mic_start + TKIP_MIC_LEN);
        }
        Some(first)
    }

    /// Linux `ath11k_dp_rx_h_defrag_reo_reinject`: rewrite the first
    /// fragment's MSDU link descriptor to name `skb` (a new refill-ring
    /// buffer id), fix the descriptor's MSDU length and queue the MPDU on
    /// the REO reinject ring with the REO queue of the first fragment's
    /// ring entry.
    fn defrag_reo_reinject(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        pi: usize,
        tid: usize,
        mut skb: Vec<u8>,
    ) -> Result<(), i32> {
        let desc_sz = self.cfg.hal_desc_sz;
        let t = &self.peer_rx.peers[pi].rx_tid[tid];
        let d = t.dst_ring_desc.ok_or(EINVAL)?;
        let cur_sn = t.cur_sn;
        // ath11k_hal_rx_reo_ent_paddr_get
        let (link_pa, desc_bank, _) = buf_addr_get(d[0], d[1]);
        let bank = self.link_desc_banks.get(desc_bank as usize).ok_or(EINVAL)?;
        // msdu_link->msdu_link[0] (words 8..12 of hal_rx_msdu_link).
        let info0 = bank.rd(link_pa, 10).ok_or(EINVAL)?;
        let dst_idx = field_get(RX_MSDU_DESC_INFO0_REO_DEST_IND, info0);
        for w in 8..12 {
            bank.wr(link_pa, w, 0).ok_or(EINVAL)?;
        }
        let len = (skb.len() - desc_sz) as u32;
        let msdu_info = RX_MSDU_DESC_INFO0_FIRST_MSDU_IN_MPDU
            | RX_MSDU_DESC_INFO0_LAST_MSDU_IN_MPDU
            | field_prep(RX_MSDU_DESC_INFO0_MSDU_LENGTH, len)
            | field_prep(RX_MSDU_DESC_INFO0_REO_DEST_IND, dst_idx)
            | RX_MSDU_DESC_INFO0_VALID_SA
            | RX_MSDU_DESC_INFO0_VALID_DA;
        bank.wr(link_pa, 10, msdu_info).ok_or(EINVAL)?;
        // ath11k_dp_rxdesc_set_msdu_len (msdu_start.info1 at byte 104).
        let off = core::mem::offset_of!(HalRxDescWcn6855, msdu_start) + 4;
        let mut i1 = u32::from_le_bytes([skb[off], skb[off + 1], skb[off + 2], skb[off + 3]]);
        i1 = (i1 & !RX_MSDU_START_INFO1_MSDU_LENGTH)
            | field_prep(RX_MSDU_START_INFO1_MSDU_LENGTH, len);
        skb[off..off + 4].copy_from_slice(&i1.to_le_bytes());

        let mut mem =
            DmaMem::alloc(skb.len(), DP_RX_BUFFER_ALIGN_SIZE as usize).map_err(|_| ENOMEM)?;
        mem.write_bytes(0, &skb);
        let paddr = mem.paddr();
        let rx_buf_rbm = self.cfg.hal_params.rx_buf_rbm;
        let pdev = self.pdev.as_mut().ok_or(EINVAL)?;
        let mac_id = pdev.mac_id;
        let max = pdev.rx_refill_buf_ring.bufs_max * 3;
        let buf_id = pdev
            .rx_refill_buf_ring
            .bufs
            .alloc(
                RxBuf {
                    mem,
                    paddr,
                    frag_len: Some(skb.len() as u32),
                },
                1,
                max,
            )
            .map_err(|_| ENOMEM)?;
        let cookie = field_prep(DP_RXDMA_BUF_COOKIE_PDEV_ID, mac_id)
            | field_prep(DP_RXDMA_BUF_COOKIE_BUF_ID, buf_id);
        let w = buf_addr_words(paddr, cookie, rx_buf_rbm);
        let bank = &self.link_desc_banks[desc_bank as usize];
        bank.wr(link_pa, 8, w[0]).ok_or(EINVAL)?;
        bank.wr(link_pa, 9, w[1]).ok_or(EINVAL)?;

        let id = self.reo_reinject_ring.ring_id;
        hal.access_begin(id);
        let Some(e) = hal.src_get_next_entry(id) else {
            hal.access_end(io, id);
            if let Some(p) = self.pdev.as_mut() {
                p.rx_refill_buf_ring.bufs.remove(buf_id);
            }
            return Err(ENOSPC);
        };
        let link = buf_addr_words(link_pa, desc_bank, rbm::WBM_IDLE_DESC_LIST);
        let mpdu_info = field_prep(RX_MPDU_DESC_INFO0_MSDU_COUNT, 1)
            | field_prep(RX_MPDU_DESC_INFO0_SEQ_NUM, cur_sn as u32)
            | RX_MPDU_DESC_INFO0_VALID_SA
            | RX_MPDU_DESC_INFO0_VALID_DA
            | RX_MPDU_DESC_INFO0_RAW_MPDU
            | RX_MPDU_DESC_INFO0_VALID_PN;
        let info0 = field_prep(
            HAL_REO_ENTR_RING_INFO0_QUEUE_ADDR_HI,
            field_get(HAL_REO_DEST_RING_INFO0_QUEUE_ADDR_HI, d[7]),
        ) | field_prep(HAL_REO_ENTR_RING_INFO0_DEST_IND, dst_idx);
        hal.desc_wr(
            id,
            e,
            &[link[0], link[1], mpdu_info, d[3], d[6], info0, 0, 0],
        );
        hal.access_end(io, id);
        Ok(())
    }
}

/// Linux `ath11k_dp_rx_h_undecap_frag` on a fragment (descriptor at the
/// front, the 802.11 header at `desc_sz`).
fn undecap_frag(skb: &mut Vec<u8>, desc_sz: usize, enctype: u32, flags: u32) -> Option<()> {
    if flags == 0 {
        return Some(());
    }
    if flags & rx_flag::MIC_STRIPPED != 0 {
        let l = skb.len().checked_sub(crypto_mic_len(enctype))?;
        skb.truncate(l);
    }
    if flags & rx_flag::ICV_STRIPPED != 0 {
        let l = skb.len().checked_sub(crypto_icv_len(enctype))?;
        skb.truncate(l);
    }
    if flags & rx_flag::IV_STRIPPED != 0 {
        let hdr_len = ieee80211_hdrlen(fc_at(skb, desc_sz));
        let crypto_len = crypto_param_len(enctype);
        if skb.len() < desc_sz + hdr_len + crypto_len {
            return None;
        }
        // memmove(data + desc + crypto, data + desc, hdr_len);
        // skb_pull(crypto_len)
        skb.copy_within(desc_sz..desc_sz + hdr_len, desc_sz + crypto_len);
        skb.drain(..crypto_len);
    }
    Some(())
}

/// Linux `ath11k_dp_rx_h_undecap_raw` for a unicast MPDU (MSDU first and
/// last): the FCS goes; a decrypted frame (`RX_FLAG_IV_STRIPPED`, as
/// `ath11k_dp_rx_h_mpdu` sets for unicast) also loses its MIC / ICV and
/// IV. Group-addressed decrypted frames keep their IV in Linux
/// (`fill_crypto_hdr`) for mac80211: `None` (not convertible here).
pub fn undecap_raw(mpdu: &[u8], enctype: u32, decrypted: bool, is_mcbc: bool) -> Option<Vec<u8>> {
    let mut f = mpdu.get(..mpdu.len().checked_sub(FCS_LEN)?)?.to_vec();
    if !decrypted {
        return Some(f);
    }
    if is_mcbc {
        return None;
    }
    let l = f
        .len()
        .checked_sub(crypto_mic_len(enctype) + crypto_icv_len(enctype))?;
    f.truncate(l);
    if f.len() < 2 {
        return None;
    }
    let hdr_len = ieee80211_hdrlen(fc_at(&f, 0));
    let crypto_len = crypto_param_len(enctype);
    if f.len() < hdr_len + crypto_len {
        return None;
    }
    f.copy_within(..hdr_len, crypto_len);
    f.drain(..crypto_len);
    Some(f)
}
