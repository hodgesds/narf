//! Monitor-mode receive: the rxdma1 monitor destination path of Linux
//! `drivers/net/wireless/ath/ath11k/dp_rx.c` (the multi-pdev parts with
//! `hw_params.rxdma1_enable && supports_monitor`: IPQ8074, IPQ6018 and
//! QCN9074).
//!
//! | NARF | Linux |
//! |---|---|
//! | [`Dp::process_mon_rings_for`] | `ath11k_dp_rx_process_mon_rings` |
//! | [`Dp::process_mon_status_on`] | `ath11k_dp_rx_process_mon_status` (monitor half; peer statistics stay in `reap_mon_status_on`) |
//! | [`parse_mon_ppdu`] | `ath11k_hal_rx_parse_mon_status` (PPDU id / done / combined RSSI) |
//! | [`Dp::mon_dest_process`] | `ath11k_dp_rx_mon_dest_process` |
//! | [`Dp::mon_mpdu_pop`] | `ath11k_dp_rx_mon_mpdu_pop` (+ `ath11k_hal_rx_msdu_list_get`, `ath11k_dp_rx_mon_comp_ppduid`, `ath11k_dp_mon_get_buf_len`) |
//! | [`Dp::mon_link_desc_return`] | `ath11k_dp_rx_monitor_link_desc_return` |
//! | [`Dp::mon_deliver`] | `ath11k_dp_rx_mon_deliver` (+ `ath11k_dp_rx_mon_merg_msdus`, `ath11k_dp_rx_h_ppdu`'s channel) |
//!
//! The result is a [`MonRxFrame`] per 802.11 frame: the MPDU without FCS
//! plus the receive facts radiotap may carry (`ath11k_update_radiotap`:
//! channel, `rssi_comb + ATH11K_DEFAULT_NOISE_FLOOR`). The runtime routes
//! it to the pdev's monitor interface, which wraps it with
//! `narf_wireless::monitor::encode`.
//!
//! Deviations, each because NARF has no mac80211 behind the driver:
//! - Linux hands every buffer of the MSDU chain to mac80211 as its own
//!   skb (`RX_FLAG_AMSDU_MORE`); NARF joins continuation buffers into one
//!   MSDU and, for RAW decap, the MSDUs into the one MPDU they form.
//! - FCS-failed MPDUs are dropped: mac80211 gives them only to monitors
//!   with `MONITOR_FLAG_FCSFAIL`, which NARF does not accept.
//! - Payload offsets use `hw_params.hal_desc_sz` throughout; Linux's
//!   `ath11k_dp_rx_mon_mpdu_pop` sizes a buffer with
//!   `sizeof(struct hal_rx_desc)` (the WCN6855 union maximum) but strips
//!   `hal_desc_sz`, which leaves stale tail bytes on the 384-byte
//!   descriptor parts.
//! - A destination entry Linux would `continue` on without advancing
//!   (`MON_DEST_RING_STUCK_MAX_CNT`) is retried at most once per ring
//!   entry per pass, so a duplicated link descriptor cannot spin forever.

extern crate alloc;

use alloc::vec::Vec;

use super::dp::*;
use super::dp_ring::*;
use super::hal::{field_get, genmask, DmaMem, Hal, HalRingType, TransportError};
use super::htt::{self, RxRingTlvFilter};
use super::hw::rbm;
use super::power::ChipIo;
use super::rx_descriptor::RxDescriptor;

/// `DP_NOT_PPDU_ID_WRAP_AROUND`.
pub const DP_NOT_PPDU_ID_WRAP_AROUND: u32 = 20000;
/// `DP_RX_DESC_COOKIE_MAX` (`DP_RX_DESC_COOKIE_INDEX_MAX |
/// DP_RX_DESC_COOKIE_POOL_ID_MAX`).
pub const DP_RX_DESC_COOKIE_MAX: u32 = 0x3ffff | 0x1c_0000;
/// `MON_DEST_RING_STUCK_MAX_CNT`.
pub const MON_DEST_RING_STUCK_MAX_CNT: u32 = 16;
/// `ATH11K_DP_RX_FULL_MON_PPDU_ID_WRAP`.
pub const ATH11K_DP_RX_FULL_MON_PPDU_ID_WRAP: u16 = 32535;
/// `HAL_RX_FCS_LEN`.
pub const HAL_RX_FCS_LEN: usize = 4;
/// `ATH11K_DEFAULT_NOISE_FLOOR` (dBm).
pub const ATH11K_DEFAULT_NOISE_FLOOR: i32 = -95;
/// `ATH11K_MIN_6G_FREQ` / `ATH11K_MAX_6G_FREQ` (core.h).
pub const ATH11K_MIN_6G_FREQ: u32 = 5925;
pub const ATH11K_MAX_6G_FREQ: u32 = 7115;
/// Monitor frames held for the runtime between service passes (the
/// skb backlog Linux bounds with `netdev_max_backlog`).
pub const MON_RX_QUEUE_MAX: usize = 256;

/// `HAL_RX_PPDU_START_INFO0_PPDU_ID`.
pub const HAL_RX_PPDU_START_INFO0_PPDU_ID: u32 = genmask(15, 0);
/// `struct hal_rx_phyrx_rssi_legacy_info`: `info0` at byte 140, the
/// combined RSSI in bits 15:8 (`HAL_RX_PHYRX_RSSI_LEGACY_INFO_INFO0_RSSI_COMB`).
const RSSI_LEGACY_BYTES: usize = 144;
const RSSI_LEGACY_INFO0: usize = 140;

/// `struct hal_sw_monitor_ring` (full monitor) word fields.
pub const HAL_SW_MON_RING_INFO0_RXDMA_PUSH_REASON: u32 = genmask(1, 0);
pub const HAL_SW_MON_RING_INFO0_RXDMA_ERROR_CODE: u32 = genmask(6, 2);
pub const HAL_SW_MON_RING_INFO0_STATUS_BUF_CNT: u32 = genmask(15, 12);
pub const HAL_SW_MON_RING_INFO0_END_OF_PPDU: u32 = 1 << 16;
pub const HAL_SW_MON_RING_INFO1_PHY_PPDU_ID: u32 = genmask(15, 0);

/// `enum hal_reo_entr_rxdma_ecode` values that drop a monitor MPDU.
const RXDMA_ECODE_OVERFLOW_ERR: u32 = 0;
const RXDMA_ECODE_MPDU_LEN_ERR: u32 = 1;
const RXDMA_ECODE_FLUSH_REQUEST_ERR: u32 = 13;

/// `enum dp_mon_status_buf_state`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MonBufState {
    /// PPDU id matches in dst ring and status ring (Linux zero value).
    #[default]
    Match,
    /// Status ring DMA is not done.
    NoDma,
    /// Status ring is lagging: reap the status ring.
    Lag,
    /// Status ring is leading: reap the dst ring and drop.
    Lead,
    /// Replenish the monitor status ring.
    Replenish,
}

/// `enum hal_rx_mon_status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HalMonStatus {
    #[default]
    PpduNotDone,
    PpduDone,
    BufDone,
}

/// The monitor fields of `struct hal_rx_mon_ppdu_info` NARF uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MonPpduInfo {
    pub ppdu_id: u32,
    /// `rssi_comb`; `None` when no `HAL_PHYRX_RSSI_LEGACY` TLV was seen
    /// (Linux reports its zeroed field as `-95 dBm`; NARF never
    /// synthesizes a signal for radiotap).
    pub rssi_comb: Option<u8>,
}

/// One DONE status buffer's monitor view, in ring order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MonStatusBuf {
    pub status: HalMonStatus,
    pub info: MonPpduInfo,
}

/// `struct hal_sw_mon_ring_entries` (full monitor).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SwMonEntries {
    pub mon_dst_paddr: u64,
    pub mon_status_paddr: u64,
    pub mon_dst_sw_cookie: u32,
    pub mon_status_sw_cookie: u32,
    pub dst_buf_addr_info: [u32; 2],
    pub status_buf_count: u32,
    pub ppdu_id: u32,
    pub msdu_cnt: u32,
    pub end_of_ppdu: bool,
    pub drop_ppdu: bool,
}

/// `struct ath11k_pdev_mon_stats` (the counters the ported paths keep).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MonStats {
    pub status_ppdu_done: u32,
    pub dest_ppdu_done: u32,
    pub dest_mpdu_done: u32,
    pub dest_mpdu_drop: u32,
    pub dup_mon_linkdesc_cnt: u32,
    pub dup_mon_buf_cnt: u32,
    pub dest_mon_stuck: u32,
    pub dest_mon_not_reaped: u32,
    /// NARF: link descriptors the monitor desc ring had no room for.
    pub link_desc_return_fail: u32,
    /// NARF: link descriptors outside every monitor bank.
    pub link_desc_lookup_fail: u32,
    /// NARF: MPDUs `ath11k_dp_rx_mon_merg_msdus` refused (MPDU length
    /// error, unsupported decap, truncated buffer).
    pub merge_fail: u32,
    /// NARF: FCS-failed MPDUs (see the module deviations).
    pub fcs_err_dropped: u32,
    /// NARF: frames dropped because the runtime had not drained the
    /// monitor queue.
    pub queue_full: u32,
    /// Monitor frames queued for the interface.
    pub delivered: u32,
}

/// One popped monitor buffer: its bytes up to `hal_desc_sz + l3 pad +
/// fragment length` (`ath11k_dp_pkt_set_pktlen`) and whether its MSDU
/// continues in the next buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonMsdu {
    pub data: Vec<u8>,
    pub continuation: bool,
}

/// `struct ath11k_mon_data` (per pdev).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonData {
    /// `ATH11K_FLAG_MONITOR_STARTED`.
    pub started: bool,
    /// `mon_ppdu_status == DP_PPDU_STATUS_DONE`.
    pub ppdu_done: bool,
    /// `mon_ppdu_info`: the last status buffer's parse.
    pub ppdu_info: MonPpduInfo,
    pub last_linkdesc_paddr: u64,
    pub last_buf_cookie: u32,
    /// `dp->mon_dest_ring_stuck_cnt`.
    pub dest_ring_stuck_cnt: u32,
    // Full monitor (`hw_params.full_monitor_mode`).
    pub buf_state: MonBufState,
    pub hold_mon_dst_ring: bool,
    pub mon_status_paddr: u64,
    pub sw: SwMonEntries,
    /// `dp_full_mon_mpdu_list` (Linux keeps it on `ath11k_dp`; NARF keeps
    /// it with the pdev whose destination ring produced it).
    pub full_mon_mpdus: Vec<Vec<MonMsdu>>,
    pub stats: MonStats,
}

impl Default for MonData {
    fn default() -> Self {
        Self::new()
    }
}

impl MonData {
    /// `ath11k_dp_rx_pdev_mon_status_attach` + `_mon_attach`.
    pub fn new() -> MonData {
        MonData {
            started: false,
            ppdu_done: false,
            ppdu_info: MonPpduInfo::default(),
            last_linkdesc_paddr: 0,
            last_buf_cookie: DP_RX_DESC_COOKIE_MAX + 1,
            dest_ring_stuck_cnt: 0,
            buf_state: MonBufState::default(),
            hold_mon_dst_ring: false,
            mon_status_paddr: 0,
            sw: SwMonEntries::default(),
            full_mon_mpdus: Vec::new(),
            stats: MonStats::default(),
        }
    }
}

/// A monitor-mode 802.11 frame for the pdev's monitor interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonRxFrame {
    /// The pdev (`mac_id`) whose destination ring produced it.
    pub mac_id: u32,
    /// The MPDU (RAW) or the 802.11-headed MSDU (native Wi-Fi), no FCS.
    pub frame: Vec<u8>,
    /// `ath11k_dp_rx_h_ppdu` channel; `None` where Linux falls back to
    /// `ar->rx_channel` (the configured monitor channel).
    pub freq_mhz: Option<u32>,
    /// `ath11k_update_radiotap`: `rssi_comb + ATH11K_DEFAULT_NOISE_FLOOR`
    /// when the PPDU's status carried an RSSI.
    pub signal_dbm: Option<i8>,
}

/// `ath11k_hal_rx_parse_mon_status` reduced to the monitor fields: walk
/// the status TLVs until `HAL_RX_PPDU_END_STATUS_DONE` / tag 0
/// (PPDU done) or `HAL_DUMMY` (buffer done). `HAL_RX_PPDU_END` skips only
/// its classification overview, as Linux does. TLVs shorter than the
/// fields read are skipped rather than read past.
pub fn parse_mon_ppdu(mem: &DmaMem) -> MonStatusBuf {
    const TLV_HEADER_BYTES: usize = 4;
    let mut out = MonStatusBuf::default();
    let mut off = 0usize;
    while off + TLV_HEADER_BYTES <= mem.len() && off < DP_RX_BUFFER_SIZE as usize {
        let header = mem.rd32(off / 4);
        let tag = field_get(HAL_TLV_HDR_TAG, header);
        let declared = field_get(HAL_TLV_HDR_LEN, header) as usize;
        let value_off = off + TLV_HEADER_BYTES;
        let tlv_len = if tag == status_tag::RX_PPDU_END {
            4
        } else {
            declared
        };
        let fits = |n: usize| tlv_len >= n && value_off + n <= mem.len();
        match tag {
            status_tag::RX_PPDU_START if fits(4) => {
                out.info.ppdu_id =
                    field_get(HAL_RX_PPDU_START_INFO0_PPDU_ID, mem.rd32(value_off / 4));
            }
            status_tag::PHYRX_RSSI_LEGACY if fits(RSSI_LEGACY_BYTES) => {
                let info0 = mem.rd32((value_off + RSSI_LEGACY_INFO0) / 4);
                out.info.rssi_comb = Some(((info0 >> 8) & 0xff) as u8);
            }
            status_tag::DUMMY => {
                out.status = HalMonStatus::BufDone;
                return out;
            }
            status_tag::RX_PPDU_END_STATUS_DONE | 0 => {
                out.status = HalMonStatus::PpduDone;
                return out;
            }
            _ => {}
        }
        let Some(next) = value_off.checked_add(tlv_len) else {
            break;
        };
        off = (next + (HAL_TLV_ALIGN - 1)) & !(HAL_TLV_ALIGN - 1);
    }
    out
}

/// `ath11k_dp_rx_mon_update_status_buf_state`: the PPDU id in the
/// status buffer's second TLV (`HAL_RX_PPDU_START`) against the
/// full-monitor destination entry's, with the 16-bit wrap window.
pub fn update_status_buf_state(mon: &mut MonData, mem: &DmaMem) {
    if mem.len() < 4 {
        return;
    }
    let first_len = field_get(HAL_TLV_HDR_LEN, mem.rd32(0)) as usize;
    let second = 4 + first_len;
    if second % 4 != 0 || second + 8 > mem.len() {
        return;
    }
    if field_get(HAL_TLV_HDR_TAG, mem.rd32(second / 4)) != status_tag::RX_PPDU_START {
        return;
    }
    let ppdu_id = field_get(HAL_RX_PPDU_START_INFO0_PPDU_ID, mem.rd32(second / 4 + 1)) as u16;
    let dst = mon.sw.ppdu_id as u16;
    if dst < ppdu_id {
        mon.buf_state = MonBufState::Lead;
        if ppdu_id - dst > ATH11K_DP_RX_FULL_MON_PPDU_ID_WRAP {
            mon.buf_state = MonBufState::Lag;
        }
    } else if dst > ppdu_id {
        mon.buf_state = MonBufState::Lag;
        if dst - ppdu_id > ATH11K_DP_RX_FULL_MON_PPDU_ID_WRAP {
            mon.buf_state = MonBufState::Lead;
        }
    }
}

/// `ath11k_dp_rx_h_ppdu`'s channel from `rx_msdu_start.phy_meta_data`
/// (channel number in bits 7:0, center frequency in 31:16).
pub fn rx_h_ppdu_freq(meta: u32) -> Option<u32> {
    let channel = meta & 0xff;
    let center = meta >> 16;
    if (ATH11K_MIN_6G_FREQ..=ATH11K_MAX_6G_FREQ).contains(&center) {
        Some(center)
    } else if (1..=14).contains(&channel) {
        // ieee80211_channel_to_frequency(NL80211_BAND_2GHZ)
        Some(if channel == 14 {
            2484
        } else {
            2407 + 5 * channel
        })
    } else if (36..=177).contains(&channel) {
        Some(5000 + 5 * channel)
    } else {
        None
    }
}

/// `ath11k_dp_rx_mon_comp_ppduid`: a destination MPDU whose PPDU id is
/// ahead of the status ring's ends this PPDU (returns the new id); one
/// far behind is skipped (`rx_bufs_used += 1`).
fn comp_ppduid(msdu_ppdu_id: u32, ppdu_id: &mut u32, rx_bufs_used: &mut u32) -> u32 {
    if *ppdu_id < msdu_ppdu_id && msdu_ppdu_id - *ppdu_id < DP_NOT_PPDU_ID_WRAP_AROUND {
        *ppdu_id = msdu_ppdu_id;
        msdu_ppdu_id
    } else if *ppdu_id > msdu_ppdu_id && *ppdu_id - msdu_ppdu_id > DP_NOT_PPDU_ID_WRAP_AROUND {
        *rx_bufs_used += 1;
        *ppdu_id = msdu_ppdu_id;
        msdu_ppdu_id
    } else {
        0
    }
}

/// `ath11k_dp_mon_set_frag_len` with `hal_desc_sz`.
fn set_frag_len(desc_sz: usize, total_len: &mut u32, frag_len: &mut u32) {
    let max = DP_RX_BUFFER_SIZE - desc_sz as u32;
    if *total_len >= max {
        *frag_len = max;
        *total_len -= max;
    } else {
        *frag_len = *total_len;
        *total_len = 0;
    }
}

/// `ath11k_dp_mon_get_buf_len`.
fn get_buf_len(
    desc_sz: usize,
    msdu_flags: u32,
    is_frag: &mut bool,
    total_len: &mut u32,
    frag_len: &mut u32,
    msdu_cnt: &mut u32,
) {
    let msdu_len = field_get(RX_MSDU_DESC_INFO0_MSDU_LENGTH, msdu_flags);
    if msdu_flags & RX_MSDU_DESC_INFO0_MSDU_CONTINUATION != 0 {
        if !*is_frag {
            *total_len = msdu_len;
            *is_frag = true;
        }
        set_frag_len(desc_sz, total_len, frag_len);
    } else {
        if *is_frag {
            set_frag_len(desc_sz, total_len, frag_len);
        } else {
            *frag_len = msdu_len;
        }
        *is_frag = false;
        *msdu_cnt = msdu_cnt.wrapping_sub(1);
    }
}

/// One `struct hal_rx_msdu_link` read from a monitor link-descriptor
/// bank: its MSDU entries (`ath11k_hal_rx_msdu_list_get`: buffer cookie
/// and `rx_msdu_desc.info0`, up to the first zero address) and the next
/// link descriptor's `buf_addr_info`.
struct MonLink {
    msdus: Vec<(u32, u32)>,
    next: [u32; 2],
}

fn mon_link_read(banks: &[LinkDescBank], bank: u32, paddr: u64) -> Option<MonLink> {
    let b = banks.get(bank as usize)?;
    if paddr < b.paddr
        || paddr + HAL_LINK_DESC_SIZE as u64 > b.paddr + (b.size - b.align_bytes) as u64
    {
        return None;
    }
    // desc_hdr (word 0), buf_addr_info (1, 2), info0 (3), pn (4..8), then
    // six hal_rx_msdu_details of 4 words: buf_addr_info, rx_msdu_desc.
    let next = [b.rd(paddr, 1)?, b.rd(paddr, 2)?];
    let mut msdus = Vec::new();
    for i in 0..HAL_NUM_RX_MSDUS_PER_LINK_DESC {
        let w0 = b.rd(paddr, 8 + 4 * i)?;
        if field_get(BUFFER_ADDR_INFO0_ADDR, w0) == 0 {
            break;
        }
        let cookie = field_get(BUFFER_ADDR_INFO1_SW_COOKIE, b.rd(paddr, 9 + 4 * i)?);
        msdus.push((cookie, b.rd(paddr, 10 + 4 * i)?));
    }
    Some(MonLink { msdus, next })
}

/// `ieee80211_is_data_qos`.
fn is_data_qos(fc: u16) -> bool {
    fc & 0x00fc == 0x0088
}

impl Dp {
    /// Run `f` on pdev `mac_id` taken out of its slot (so `f` may borrow
    /// `self` mutably too), then put it back in the same slot.
    pub(super) fn with_pdev<R>(
        &mut self,
        mac_id: u32,
        f: impl FnOnce(&mut Self, &mut PdevDp) -> R,
    ) -> Option<R> {
        if self.pdev.as_ref().is_some_and(|p| p.mac_id == mac_id) {
            let mut pdev = self.pdev.take()?;
            let r = f(self, &mut pdev);
            self.pdev = Some(pdev);
            return Some(r);
        }
        let idx = self.extra_pdevs.iter().position(|p| p.mac_id == mac_id)?;
        let mut pdev = self.extra_pdevs.remove(idx);
        let r = f(self, &mut pdev);
        self.extra_pdevs.insert(idx, pdev);
        Some(r)
    }

    /// Whether the part has the monitor destination path this module
    /// ports (`rxdma1_enable && supports_monitor`).
    pub fn monitor_capable(&self) -> bool {
        self.cfg.rxdma1_enable && self.cfg.supports_monitor
    }

    /// `ATH11K_FLAG_MONITOR_STARTED` of pdev `mac_id`.
    pub fn monitor_started(&self, mac_id: u32) -> bool {
        self.pdevs()
            .find(|p| p.mac_id == mac_id)
            .is_some_and(|p| p.mon.started)
    }

    /// Set / clear `ATH11K_FLAG_MONITOR_STARTED` (`ath11k_mac_monitor_start`
    /// / `_stop`). Starting resets the PPDU state to
    /// `DP_PPDU_STATUS_START`; stopping discards a held full-monitor PPDU
    /// and the frames not yet taken for this pdev.
    pub fn set_monitor_started(&mut self, mac_id: u32, started: bool) -> bool {
        let found = self
            .with_pdev(mac_id, |_, pdev| {
                pdev.mon.started = started;
                pdev.mon.ppdu_done = false;
                if !started {
                    pdev.mon.hold_mon_dst_ring = false;
                    pdev.mon.full_mon_mpdus.clear();
                }
            })
            .is_some();
        if found && !started {
            self.mon_rx.retain(|f| f.mac_id != mac_id);
        }
        found
    }

    /// Linux `ath11k_dp_tx_htt_monitor_mode_ring_config(ar, reset)` for
    /// pdev `mac_id`, as the H2T messages in Linux's order: the
    /// full-monitor mode config (`full_monitor_mode` parts), the monitor
    /// buffer ring's RX_RING_SELECTION_CFG (FP + MO of every frame type, or
    /// all-zero on reset) and one per monitor status ring (the monitor
    /// TLVs, or `ath11k_mac_mon_status_filter_default` on reset). Linux
    /// passes `DP_RXDMA_REFILL_RING_SIZE` as the buffer size of both.
    pub fn monitor_mode_ring_config_msgs(
        &self,
        hal: &Hal,
        mac_id: u32,
        reset: bool,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let pdev = self
            .pdevs()
            .find(|p| p.mac_id == mac_id)
            .ok_or(TransportError::new(
                step::NOT_SET_UP,
                3,
                super::hal::errno::EINVAL,
            ))?;
        let rmb = self.cfg.rx_mac_buf_ring;
        let mut out = Vec::new();
        if self.cfg.full_monitor_mode {
            out.push(htt::rx_full_mon_setup_msg(mac_id, !reset).to_vec());
        }
        // Without rxdma1 Linux programs the rx_mac_buf rings in monitor
        // mode only; no such part has `supports_monitor`.
        if let Some(buf) = pdev.rxdma_mon_buf_ring.as_ref() {
            let filter = if reset {
                RxRingTlvFilter::default()
            } else {
                htt::MONITOR_MODE_BUF_FILTER
            };
            out.push(
                htt::rx_filter_setup_msg(
                    hal,
                    rmb,
                    buf.refill_buf_ring.ring_id,
                    mac_id,
                    HalRingType::RxdmaMonitorBuf,
                    DP_RXDMA_REFILL_RING_SIZE,
                    &filter,
                )?
                .to_vec(),
            );
        }
        let filter = if reset {
            htt::MON_STATUS_FILTER_DEFAULT
        } else {
            htt::MONITOR_MODE_STATUS_FILTER
        };
        for (i, r) in pdev.rx_mon_status_refill_ring.iter().enumerate() {
            out.push(
                htt::rx_filter_setup_msg(
                    hal,
                    rmb,
                    r.refill_buf_ring.ring_id,
                    mac_id + i as u32,
                    HalRingType::RxdmaMonitorStatus,
                    DP_RXDMA_REFILL_RING_SIZE,
                    &filter,
                )?
                .to_vec(),
            );
        }
        Ok(out)
    }

    /// Monitor counters of pdev `mac_id`.
    pub fn mon_stats_for(&self, mac_id: u32) -> Option<&MonStats> {
        self.pdevs()
            .find(|p| p.mac_id == mac_id)
            .map(|p| &p.mon.stats)
    }

    /// Take the monitor frames delivered since the last call.
    pub fn take_mon_rx(&mut self) -> Vec<MonRxFrame> {
        self.mon_rx.drain(..).collect()
    }

    /// Linux `ath11k_dp_rx_process_mon_rings` for pdev `mac_id`, RXDMA
    /// ring `rxdma_idx` (the per-pdev monitor part of
    /// `ath11k_dp_service_srng`). Returns the status buffers reaped.
    pub fn process_mon_rings_for(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        mac_id: u32,
        rxdma_idx: u32,
        budget: &mut u32,
    ) -> u32 {
        self.with_pdev(mac_id, |dp, pdev| {
            if pdev.mon.started && dp.cfg.full_monitor_mode {
                dp.full_mon_process_rx_on(pdev, hal, io, rxdma_idx, budget)
            } else {
                dp.process_mon_status_on(pdev, hal, io, rxdma_idx, budget)
            }
        })
        .unwrap_or(0)
    }

    /// Linux `ath11k_dp_rx_process_mon_status`: reap the status ring;
    /// for each status buffer that completes a PPDU while the monitor is
    /// started and the PPDU state is `START`, process the destination
    /// ring (`ath11k_dp_rx_mon_dest_process`, non-full-monitor parts).
    pub fn process_mon_status_on(
        &mut self,
        pdev: &mut PdevDp,
        hal: &mut Hal,
        io: &impl ChipIo,
        rxdma_idx: u32,
        budget: &mut u32,
    ) -> u32 {
        let mut status = Vec::new();
        let mac_id = pdev.mac_id;
        let reaped = self.reap_mon_status_on(pdev, hal, io, mac_id, rxdma_idx, budget, &mut status);
        for s in status {
            // memset(ppdu_info) per buffer, then the parse.
            pdev.mon.ppdu_info = s.info;
            if pdev.mon.started && !pdev.mon.ppdu_done && s.status == HalMonStatus::PpduDone {
                pdev.mon.stats.status_ppdu_done += 1;
                pdev.mon.ppdu_done = true;
                if !self.cfg.full_monitor_mode {
                    self.mon_dest_process(pdev, hal, io);
                    pdev.mon.ppdu_done = false;
                }
            }
        }
        reaped
    }

    /// Linux `ath11k_dp_rx_mon_dest_process` (rxdma1): pop the MPDUs of
    /// the status ring's PPDU off the monitor destination ring, deliver
    /// them, and replenish the monitor buffer ring with what was used.
    pub fn mon_dest_process(&mut self, pdev: &mut PdevDp, hal: &mut Hal, io: &impl ChipIo) {
        let Some(dst) = pdev.rxdma_mon_dst_ring else {
            return;
        };
        let id = dst.ring_id;
        hal.access_begin(id);
        let mut ppdu_id = pdev.mon.ppdu_info.ppdu_id;
        let mut rx_bufs_used = 0u32;
        let mut stuck_retries = 0u32;
        while let Some(off) = hal.dst_peek(id) {
            let ent: [u32; 8] = core::array::from_fn(|i| hal.desc_rd(id, off, i as u32));
            let mut chain = None;
            let mut npackets = 0u32;
            let used =
                self.mon_mpdu_pop(pdev, hal, io, &ent, &mut chain, &mut npackets, &mut ppdu_id);
            rx_bufs_used += used;
            if used != 0 {
                pdev.mon.dest_ring_stuck_cnt = 0;
            } else {
                pdev.mon.dest_ring_stuck_cnt += 1;
                pdev.mon.stats.dest_mon_not_reaped += 1;
            }
            if pdev.mon.dest_ring_stuck_cnt > MON_DEST_RING_STUCK_MAX_CNT {
                pdev.mon.stats.dest_mon_stuck += 1;
                pdev.mon.ppdu_info.ppdu_id = ppdu_id;
                // Linux `continue`s on the same entry; bound the retries.
                stuck_retries += 1;
                if stuck_retries > dst.num_entries {
                    break;
                }
                continue;
            }
            if ppdu_id != pdev.mon.ppdu_info.ppdu_id {
                pdev.mon.ppdu_done = false;
                break;
            }
            if let Some(chain) = chain {
                self.mon_deliver(pdev, chain);
                pdev.mon.stats.dest_mpdu_done += 1;
            }
            hal.dst_get_next_entry(id);
        }
        hal.access_end(io, id);
        if rx_bufs_used != 0 {
            pdev.mon.stats.dest_ppdu_done += 1;
            let mgr = self.cfg.hal_params.rx_buf_rbm;
            let mac_id = pdev.mac_id;
            if let Some(ring) = pdev.rxdma_mon_buf_ring.as_mut() {
                self.rxbufs_replenish(hal, io, mac_id, ring, rx_bufs_used, mgr);
            }
        }
    }

    /// Linux `ath11k_dp_rx_mon_mpdu_pop` (rxdma1): walk the MSDU link
    /// descriptors of one destination entry, take each buffer off the
    /// monitor buffer ring and return each link descriptor to the
    /// monitor desc ring. `chain` is `Some` only when Linux would have
    /// both a head and a tail MSDU. Returns the buffers used.
    #[allow(clippy::too_many_arguments)]
    pub fn mon_mpdu_pop(
        &mut self,
        pdev: &mut PdevDp,
        hal: &mut Hal,
        io: &impl ChipIo,
        ent: &[u32; 8],
        chain: &mut Option<Vec<MonMsdu>>,
        npackets: &mut u32,
        ppdu_id: &mut u32,
    ) -> u32 {
        let desc_sz = self.cfg.hal_desc_sz;
        let rev = self.cfg.hw.hw_rev;
        let (mut paddr, mut sw_cookie, _rbm) = buf_addr_get(ent[0], ent[1]);
        let mut msdu_cnt = field_get(RX_MPDU_DESC_INFO0_MSDU_COUNT, ent[2]);
        let mut last_buf_addr = [ent[0], ent[1]];
        let mut drop_mpdu = false;
        if field_get(HAL_REO_ENTR_RING_INFO1_RXDMA_PUSH_REASON, ent[6])
            == reo::PUSH_REASON_ERR_DETECTED
        {
            let code = field_get(HAL_REO_ENTR_RING_INFO1_RXDMA_ERROR_CODE, ent[6]);
            if matches!(
                code,
                RXDMA_ECODE_FLUSH_REQUEST_ERR | RXDMA_ECODE_MPDU_LEN_ERR | RXDMA_ECODE_OVERFLOW_ERR
            ) {
                drop_mpdu = true;
                pdev.mon.stats.dest_mpdu_drop += 1;
            }
        }
        let mut is_frag = false;
        let mut is_first_msdu = true;
        let (mut total_len, mut frag_len) = (0u32, 0u32);
        let mut rx_bufs_used = 0u32;
        let mut head: Vec<MonMsdu> = Vec::new();
        // Linux's `msdu` after the loop (`*tail_msdu = msdu`).
        let mut tail = false;
        loop {
            if pdev.mon.last_linkdesc_paddr == paddr {
                pdev.mon.stats.dup_mon_linkdesc_cnt += 1;
                return rx_bufs_used;
            }
            let Some(link) = mon_link_read(&pdev.mon_link_desc_banks, sw_cookie, paddr) else {
                pdev.mon.stats.link_desc_lookup_fail += 1;
                return rx_bufs_used;
            };
            for &(cookie, msdu_flags) in &link.msdus {
                if pdev.mon.last_buf_cookie == cookie {
                    drop_mpdu = true;
                    pdev.mon.stats.dup_mon_buf_cnt += 1;
                    continue;
                }
                let buf_id = field_get(DP_RXDMA_BUF_COOKIE_BUF_ID, cookie);
                let Some(ring) = pdev.rxdma_mon_buf_ring.as_mut() else {
                    return rx_bufs_used;
                };
                'next: {
                    let Some(buf) = ring.bufs.find(buf_id) else {
                        self.stats.rx_invalid_cookie += 1;
                        tail = false;
                        break 'next;
                    };
                    if drop_mpdu {
                        tail = false;
                        break 'next;
                    }
                    let mut desc_bytes = alloc::vec![0u8; desc_sz.min(buf.mem.len())];
                    buf.mem.read_bytes(0, &mut desc_bytes);
                    let Some(rxd) = RxDescriptor::decode(rev, &desc_bytes) else {
                        tail = false;
                        break 'next;
                    };
                    let l2 = rxd.l3_pad_bytes() as usize;
                    if is_first_msdu {
                        if rxd.mpdu_start_tag() != status_tag::RX_MPDU_START {
                            drop_mpdu = true;
                            tail = false;
                            pdev.mon.last_linkdesc_paddr = paddr;
                            break 'next;
                        }
                        let msdu_ppdu_id = rxd.mpdu_ppdu_id() as u32;
                        if comp_ppduid(msdu_ppdu_id, ppdu_id, &mut rx_bufs_used) != 0 {
                            if rx_bufs_used != 0 {
                                drop_mpdu = true;
                                tail = false;
                                break 'next;
                            }
                            return rx_bufs_used;
                        }
                        pdev.mon.last_linkdesc_paddr = paddr;
                        is_first_msdu = false;
                    }
                    get_buf_len(
                        desc_sz,
                        msdu_flags,
                        &mut is_frag,
                        &mut total_len,
                        &mut frag_len,
                        &mut msdu_cnt,
                    );
                    let size = (desc_sz + l2 + frag_len as usize).min(buf.mem.len());
                    let mut data = alloc::vec![0u8; size];
                    buf.mem.read_bytes(0, &mut data);
                    head.push(MonMsdu {
                        data,
                        continuation: msdu_flags & RX_MSDU_DESC_INFO0_MSDU_CONTINUATION != 0,
                    });
                    tail = true;
                }
                // next_msdu:
                pdev.mon.last_buf_cookie = cookie;
                rx_bufs_used += 1;
                ring.bufs.remove(buf_id);
            }
            let (next_paddr, next_cookie, _) = buf_addr_get(link.next[0], link.next[1]);
            paddr = next_paddr;
            sw_cookie = next_cookie;
            self.mon_link_desc_return(pdev, hal, io, last_buf_addr);
            last_buf_addr = link.next;
            if paddr == 0 || msdu_cnt == 0 {
                break;
            }
        }
        if msdu_cnt == 0 {
            *npackets = 1;
        }
        if tail && !head.is_empty() {
            *chain = Some(head);
        }
        rx_bufs_used
    }

    /// Linux `ath11k_dp_rx_monitor_link_desc_return` (rxdma1): copy the
    /// processed link descriptor's `buf_addr_info` into the next entry of
    /// the pdev's monitor desc ring.
    pub fn mon_link_desc_return(
        &mut self,
        pdev: &mut PdevDp,
        hal: &mut Hal,
        io: &impl ChipIo,
        buf_addr_info: [u32; 2],
    ) -> bool {
        let Some(ring) = pdev.rxdma_mon_desc_ring else {
            return false;
        };
        let id = ring.ring_id;
        hal.access_begin(id);
        let ok = match hal.src_get_next_entry(id) {
            Some(off) => {
                hal.desc_wr(id, off, &buf_addr_info);
                true
            }
            None => {
                pdev.mon.stats.link_desc_return_fail += 1;
                false
            }
        };
        hal.access_end(io, id);
        ok
    }

    /// Linux `ath11k_dp_rx_mon_deliver` → `ath11k_dp_rx_mon_merg_msdus`
    /// and `ath11k_update_radiotap`: strip each buffer's descriptor and L3
    /// pad, build the 802.11 frame(s) and queue them for the runtime.
    pub fn mon_deliver(&mut self, pdev: &mut PdevDp, chain: Vec<MonMsdu>) {
        let desc_sz = self.cfg.hal_desc_sz;
        let rev = self.cfg.hw.hw_rev;
        let Some(head) = chain
            .first()
            .and_then(|m| RxDescriptor::decode(rev, &m.data))
        else {
            pdev.mon.stats.merge_fail += 1;
            return;
        };
        let attention = head.attention();
        let fcs_err = attn_mpdu_err(&head) & DP_RX_MPDU_ERR_FCS != 0;
        let info1 = attention.info1;
        if info1 & RX_ATTENTION_INFO1_MPDU_LEN_ERR != 0 {
            pdev.mon.stats.merge_fail += 1;
            return;
        }
        let freq_mhz = rx_h_ppdu_freq(head.msdu_freq());
        // ath11k_dp_rx_msdus_set_payload on every buffer.
        let mut payloads: Vec<(Vec<u8>, bool)> = Vec::with_capacity(chain.len());
        for m in &chain {
            let Some(d) = RxDescriptor::decode(rev, &m.data) else {
                pdev.mon.stats.merge_fail += 1;
                return;
            };
            let start = desc_sz + d.l3_pad_bytes() as usize;
            if start > m.data.len() {
                pdev.mon.stats.merge_fail += 1;
                return;
            }
            payloads.push((m.data[start..].to_vec(), m.continuation));
        }
        // Join continuation buffers into their MSDU.
        let mut msdus: Vec<Vec<u8>> = Vec::new();
        let mut open = false;
        for (p, cont) in payloads {
            if open {
                if let Some(last) = msdus.last_mut() {
                    last.extend_from_slice(&p);
                }
            } else {
                msdus.push(p);
            }
            open = cont;
        }
        let frames: Vec<Vec<u8>> = match head.decap_type() {
            decap::RAW => {
                let mut mpdu: Vec<u8> = msdus.concat();
                if mpdu.len() < HAL_RX_FCS_LEN {
                    pdev.mon.stats.merge_fail += 1;
                    return;
                }
                mpdu.truncate(mpdu.len() - HAL_RX_FCS_LEN);
                alloc::vec![mpdu]
            }
            decap::NATIVE_WIFI => {
                // `hdr_desc` is the head MSDU's payload start; a QoS data
                // header is restored in front of every MSDU (push 2 +
                // copy `sizeof(struct ieee80211_qos_hdr)`).
                const QOS_HDR: usize = 26;
                const NWIFI_HDR: usize = 24;
                let hdr: Vec<u8> = msdus.first().map(|m| m.to_vec()).unwrap_or_default();
                let qos = hdr.len() >= 2 && is_data_qos(u16::from_le_bytes([hdr[0], hdr[1]]));
                if qos && hdr.len() < QOS_HDR {
                    pdev.mon.stats.merge_fail += 1;
                    return;
                }
                let mut out = Vec::with_capacity(msdus.len());
                for m in msdus {
                    if qos {
                        if m.len() < NWIFI_HDR {
                            pdev.mon.stats.merge_fail += 1;
                            return;
                        }
                        let mut f = Vec::with_capacity(m.len() + 2);
                        f.extend_from_slice(&hdr[..QOS_HDR]);
                        f.extend_from_slice(&m[NWIFI_HDR..]);
                        out.push(f);
                    } else {
                        out.push(m);
                    }
                }
                out
            }
            _ => {
                pdev.mon.stats.merge_fail += 1;
                return;
            }
        };
        if fcs_err {
            pdev.mon.stats.fcs_err_dropped += frames.len() as u32;
            return;
        }
        let signal_dbm = pdev
            .mon
            .ppdu_info
            .rssi_comb
            .map(|r| (r as i32 + ATH11K_DEFAULT_NOISE_FLOOR).clamp(-128, 127) as i8);
        for frame in frames {
            if self.mon_rx.len() >= MON_RX_QUEUE_MAX {
                pdev.mon.stats.queue_full += 1;
                continue;
            }
            pdev.mon.stats.delivered += 1;
            self.mon_rx.push_back(MonRxFrame {
                mac_id: pdev.mac_id,
                frame,
                freq_mhz,
                signal_dbm,
            });
        }
    }

    /// `ath11k_hal_rx_sw_mon_ring_buf_paddr_get`: a full-monitor
    /// destination entry (`struct hal_sw_monitor_ring`, 8 words).
    pub fn sw_mon_entries(ent: &[u32; 8]) -> SwMonEntries {
        let (mon_dst_paddr, mon_dst_sw_cookie, _) = buf_addr_get(ent[0], ent[1]);
        let (mon_status_paddr, mon_status_sw_cookie, _) = buf_addr_get(ent[4], ent[5]);
        SwMonEntries {
            mon_dst_paddr,
            mon_status_paddr,
            mon_dst_sw_cookie,
            mon_status_sw_cookie,
            dst_buf_addr_info: [ent[0], ent[1]],
            status_buf_count: field_get(HAL_SW_MON_RING_INFO0_STATUS_BUF_CNT, ent[6]),
            ppdu_id: field_get(HAL_SW_MON_RING_INFO1_PHY_PPDU_ID, ent[7]),
            msdu_cnt: field_get(RX_MPDU_DESC_INFO0_MSDU_COUNT, ent[2]),
            end_of_ppdu: false,
            drop_ppdu: false,
        }
    }

    /// Linux `ath11k_dp_rx_full_mon_mpdu_pop`: as [`Self::mon_mpdu_pop`]
    /// for a SW monitor ring entry, without the PPDU-id comparison (the
    /// entry carries its status buffer instead). An END_OF_PPDU entry
    /// pops nothing.
    pub fn full_mon_mpdu_pop(
        &mut self,
        pdev: &mut PdevDp,
        hal: &mut Hal,
        io: &impl ChipIo,
        ent: &[u32; 8],
        chain: &mut Option<Vec<MonMsdu>>,
    ) -> u32 {
        let desc_sz = self.cfg.hal_desc_sz;
        let rev = self.cfg.hw.hw_rev;
        pdev.mon.sw = Self::sw_mon_entries(ent);
        let mut sw_cookie = pdev.mon.sw.mon_dst_sw_cookie;
        let mut last_buf_addr = pdev.mon.sw.dst_buf_addr_info;
        let mut msdu_cnt = pdev.mon.sw.msdu_cnt;
        let mut rx_bufs_used = 0u32;
        pdev.mon.sw.end_of_ppdu = ent[6] & HAL_SW_MON_RING_INFO0_END_OF_PPDU != 0;
        if pdev.mon.sw.end_of_ppdu {
            return rx_bufs_used;
        }
        let mut drop_mpdu = false;
        if field_get(HAL_SW_MON_RING_INFO0_RXDMA_PUSH_REASON, ent[6])
            == reo::PUSH_REASON_ERR_DETECTED
        {
            let code = field_get(HAL_SW_MON_RING_INFO0_RXDMA_ERROR_CODE, ent[6]);
            if matches!(
                code,
                RXDMA_ECODE_FLUSH_REQUEST_ERR | RXDMA_ECODE_MPDU_LEN_ERR | RXDMA_ECODE_OVERFLOW_ERR
            ) {
                pdev.mon.stats.dest_mpdu_drop += 1;
                drop_mpdu = true;
            }
        }
        let mut is_frag = false;
        let mut is_first_msdu = true;
        let (mut total_len, mut frag_len) = (0u32, 0u32);
        let mut head: Vec<MonMsdu> = Vec::new();
        let mut tail = false;
        loop {
            let paddr = pdev.mon.sw.mon_dst_paddr;
            let Some(link) = mon_link_read(&pdev.mon_link_desc_banks, sw_cookie, paddr) else {
                pdev.mon.stats.link_desc_lookup_fail += 1;
                return rx_bufs_used;
            };
            for &(cookie, msdu_flags) in &link.msdus {
                let buf_id = field_get(DP_RXDMA_BUF_COOKIE_BUF_ID, cookie);
                let Some(ring) = pdev.rxdma_mon_buf_ring.as_mut() else {
                    return rx_bufs_used;
                };
                'next: {
                    // idr_find + idr_remove up front.
                    let Some(buf) = ring.bufs.remove(buf_id) else {
                        self.stats.rx_invalid_cookie += 1;
                        tail = false;
                        break 'next;
                    };
                    if drop_mpdu {
                        // Linux frees the skb but leaves `msdu` set.
                        msdu_cnt = msdu_cnt.wrapping_sub(1);
                        tail = true;
                        break 'next;
                    }
                    let mut desc_bytes = alloc::vec![0u8; desc_sz.min(buf.mem.len())];
                    buf.mem.read_bytes(0, &mut desc_bytes);
                    let Some(rxd) = RxDescriptor::decode(rev, &desc_bytes) else {
                        tail = false;
                        break 'next;
                    };
                    let l2 = rxd.l3_pad_bytes() as usize;
                    if is_first_msdu {
                        if rxd.mpdu_start_tag() != status_tag::RX_MPDU_START {
                            drop_mpdu = true;
                            tail = false;
                            break 'next;
                        }
                        is_first_msdu = false;
                    }
                    get_buf_len(
                        desc_sz,
                        msdu_flags,
                        &mut is_frag,
                        &mut total_len,
                        &mut frag_len,
                        &mut msdu_cnt,
                    );
                    let size = (desc_sz + l2 + frag_len as usize).min(buf.mem.len());
                    let mut data = alloc::vec![0u8; size];
                    buf.mem.read_bytes(0, &mut data);
                    head.push(MonMsdu {
                        data,
                        continuation: msdu_flags & RX_MSDU_DESC_INFO0_MSDU_CONTINUATION != 0,
                    });
                    tail = true;
                }
                rx_bufs_used += 1;
            }
            let (next_paddr, next_cookie, _) = buf_addr_get(link.next[0], link.next[1]);
            pdev.mon.sw.mon_dst_paddr = next_paddr;
            pdev.mon.sw.mon_dst_sw_cookie = next_cookie;
            sw_cookie = next_cookie;
            self.mon_link_desc_return(pdev, hal, io, last_buf_addr);
            last_buf_addr = link.next;
            if next_paddr == 0 || msdu_cnt == 0 {
                break;
            }
        }
        if tail && !head.is_empty() {
            *chain = Some(head);
        }
        rx_bufs_used
    }

    /// Linux `ath11k_dp_full_mon_process_rx`: unless a PPDU is held for
    /// its status buffers, pop the destination ring's MPDUs into the
    /// PPDU list until an END_OF_PPDU entry, which holds the ring and
    /// records the status buffer to match; then reap the status ring
    /// ([`Self::process_full_mon_status_ring_on`]).
    pub fn full_mon_process_rx_on(
        &mut self,
        pdev: &mut PdevDp,
        hal: &mut Hal,
        io: &impl ChipIo,
        rxdma_idx: u32,
        budget: &mut u32,
    ) -> u32 {
        if !pdev.mon.hold_mon_dst_ring {
            if let Some(dst) = pdev.rxdma_mon_dst_ring {
                let id = dst.ring_id;
                let mut rx_bufs_used = 0u32;
                hal.access_begin(id);
                while let Some(off) = hal.dst_peek(id) {
                    let ent: [u32; 8] = core::array::from_fn(|i| hal.desc_rd(id, off, i as u32));
                    let mut chain = None;
                    rx_bufs_used += self.full_mon_mpdu_pop(pdev, hal, io, &ent, &mut chain);
                    let mut break_dst_ring = false;
                    if !pdev.mon.sw.end_of_ppdu {
                        if let Some(c) = chain {
                            pdev.mon.full_mon_mpdus.push(c);
                        }
                    } else if pdev.mon.sw.ppdu_id == 0 && pdev.mon.sw.mon_status_paddr == 0 {
                        break_dst_ring = true;
                    } else {
                        pdev.mon.stats.dest_ppdu_done += 1;
                        pdev.mon.ppdu_done = false;
                        pdev.mon.buf_state = MonBufState::Lag;
                        pdev.mon.mon_status_paddr = pdev.mon.sw.mon_status_paddr;
                        pdev.mon.hold_mon_dst_ring = true;
                    }
                    hal.dst_get_next_entry(id);
                    if break_dst_ring {
                        break;
                    }
                }
                hal.access_end(io, id);
                if rx_bufs_used != 0 {
                    let mac_id = pdev.mac_id;
                    if let Some(ring) = pdev.rxdma_mon_buf_ring.as_mut() {
                        self.rxbufs_replenish(hal, io, mac_id, ring, rx_bufs_used, rbm::SW3_BM);
                    }
                }
            }
        }
        self.process_full_mon_status_ring_on(pdev, hal, io, rxdma_idx, budget)
    }

    /// Linux `ath11k_dp_rx_process_full_mon_status_ring`: while the
    /// destination ring is held, reap status buffers one at a time; on a
    /// MATCH reap the PPDU's remaining status buffers and deliver its
    /// MPDUs, on a LEAD (or no status buffer) drop them.
    pub fn process_full_mon_status_ring_on(
        &mut self,
        pdev: &mut PdevDp,
        hal: &mut Hal,
        io: &impl ChipIo,
        rxdma_idx: u32,
        _budget: &mut u32,
    ) -> u32 {
        let mut work = 0u32;
        while pdev.mon.hold_mon_dst_ring {
            let mut one = 1u32;
            let mut quota = self.process_mon_status_on(pdev, hal, io, rxdma_idx, &mut one);
            if pdev.mon.buf_state == MonBufState::Match {
                let count = pdev.mon.sw.status_buf_count;
                if count > 1 {
                    let mut c = count;
                    quota += self.process_mon_status_on(pdev, hal, io, rxdma_idx, &mut c);
                }
                self.full_mon_deliver_ppdu(pdev);
                pdev.mon.hold_mon_dst_ring = false;
            } else if pdev.mon.mon_status_paddr == 0 || pdev.mon.buf_state == MonBufState::Lead {
                pdev.mon.sw.drop_ppdu = true;
                pdev.mon.hold_mon_dst_ring = false;
            }
            if quota == 0 {
                break;
            }
            work += quota;
        }
        if pdev.mon.sw.drop_ppdu {
            // ath11k_dp_rx_full_mon_drop_ppdu
            pdev.mon.full_mon_mpdus.clear();
        }
        work
    }

    /// Linux `ath11k_dp_rx_full_mon_deliver_ppdu`.
    fn full_mon_deliver_ppdu(&mut self, pdev: &mut PdevDp) {
        for chain in core::mem::take(&mut pdev.mon.full_mon_mpdus) {
            self.mon_deliver(pdev, chain);
            pdev.mon.stats.dest_mpdu_done += 1;
        }
    }
}
