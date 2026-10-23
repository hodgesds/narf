//! The running device: the data path wired into bring-up, and the
//! runtime that owns the core + DP after it — Linux's `ath11k_dp_*`
//! calls from `core.c`, the DP ext interrupts of `pcic.c`, the NAPI poll
//! (`ath11k_pcic_ext_grp_napi_poll` → `ath11k_dp_service_srng`), the DP /
//! monitor timers, and the WMI / data-path services `mac.c` uses
//! ([`super::mac::WmiPort`], [`super::mac::DataPort`]).
//!
//! | NARF | Linux |
//! |---|---|
//! | [`DpHooks`] `dp_alloc` | `ath11k_dp_alloc` (after `ath11k_ce_init_pipes`) |
//! | `pdev_reo_setup` | `ath11k_dp_pdev_reo_setup` (after service ready) |
//! | `htt_ver_req` | `ath11k_dp_tx_htt_h2t_ver_req_msg` (3 s, major 3) |
//! | `pdev_create` | `ath11k_core_pdev_create` → `ath11k_dp_pdev_alloc` (HTT SRING_SETUP ×7) |
//! | `irq_enable` | `ath11k_hif_irq_enable` → `ath11k_pcic_ext_irq_enable` |
//! | [`install_dp_irq_handlers`] | `ath11k_pcic_ext_irq_config` (one vector per group with rings: `(grp % num_vectors) + base_vector` of the "DP" user) |
//! | [`Rt::service`] | `ath11k_pcic_ce_tasklet` + `ath11k_pcic_ext_grp_napi_poll` + `ath11k_dp_shadow_timer_handler` + `ath11k_dp_service_mon_ring` |
//! | [`Port`] as `WmiPort` | `ath11k_wmi_cmd_send`, the WMI RX dispatcher, `ath11k_mac_mgmt_tx_wmi`, `wmi_process_mgmt_tx_comp` |
//! | [`Port`] as `DataPort` | `ath11k_dp_tx_htt_h2t_ppdu_stats_req`, `ath11k_mac_config_mon_status_default`, `ath11k_dp_vdev_tx_attach`, `ath11k_wait_for_peer_common`, `ath11k_dp_peer_setup` / `_cleanup`, `ath11k_dp_peer_rx_pn_replay_config`, host TKIP fragment-MIC state, `ieee80211_tx_control_port`, the control-port RX |
//!
//! Ownership (AGENTS.md: no lock across `.await`): [`Shared`] holds the
//! [`Rt`] (core + DP + station data state) in an async [`Mutex`] that
//! every user holds only for a synchronous step; waiting happens on the
//! interrupt source ([`DpIrq::wait`]) with the lock released. Each locked
//! step first services the hardware ([`Rt::service`]: CE → HTC/WMI/HTT
//! routing → DP groups → timers), so whichever task waits drives the
//! device, and nothing depends on another task being scheduled. The few
//! `DataPort` / `WmiPort` calls that are synchronous in Linux
//! (`vdev_tx_attach`, `peer_cleanup`, `set_authorized`, `mgmt_tx_done`,
//! `set_sta_wme`) are queued ([`SyncOp`]) and applied, in order, at the
//! start of the next locked step.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_lib::mutex::{Mutex, MutexGuard};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::diag::{self, WifiStage};

use super::ce::{self, CeIrq, CeMsi, MsiCeIrq};
use super::core::{Ath11kCore, CeHif, CoreHooks, FirmwareCrashDump, FwNotice, Hif, QmiFw};
use super::dp_ring::{
    enc, DpHwParams, DpRingSizes, DpServiceOutput, Idr, MichaelMicFailure, RxMsdu, RxPpduStats,
    TxEncap, TxMeta, VifTx, RX_PPDU_MAX_CHAINS,
};
use super::dp_ring::{Dp, ETH_HLEN, ETH_P_PAE};
use super::hal::{DmaMem, TransportError};
use super::htt::{self, HttPpduRate, HttPpduStats, HttTarget, HTT_TARGET_VERSION_TIMEOUT_MS};
use super::hw::{MsiConfig, RingMask, ATH11K_EXT_IRQ_GRP_NUM_MAX};
use super::mac::{BssSurvey, DataPort, DeviceCaps, MbssidBeaconSet, WmiPort, RTS_THRESHOLD_OFF};
use super::mac_peer::{ChanDef, Width, LEGACY_RATES};
use super::mhi_host::MhiNotify;
use super::power::ChipIo;
use super::tx_hdr::{self, ApTx, SeqState, StaTx};
use super::txq::{self, Queued, TxQueues, TxStatus};
use super::wmi::{self, ServiceReady, WmiCmd};

/// Failing-step codes for the integration (250–269).
pub mod step {
    /// No DP parameters for this chip (`DpHwParams::for_rev`; detail =
    /// hw_rev index).
    pub const DP_UNSUPPORTED: u32 = 250;
    /// A DP hook ran without the DP allocated (detail = hook: 1 REO
    /// setup, 2 HTT version, 3 pdev create).
    pub const DP_MISSING: u32 = 251;
    /// HTT VERSION_REQ could not be sent (detail = the core step).
    pub const HTT_VER_SEND: u32 = 252;
    /// An HTT SRING_SETUP could not be sent (detail = message index << 16
    /// | the core step).
    pub const SRING_SETUP_SEND: u32 = 253;
    /// No "DP" MSI user (`ath11k_pcic_get_user_msi_assignment` fails;
    /// detail = vectors granted).
    pub const DP_IRQ_CONFIG: u32 = 254;
    /// The bring-up events the mac layer needs are missing (detail bits:
    /// 1 SERVICE_READY_EXT, 2 READY, 4 no pdev).
    pub const MAC_CAPS: u32 = 255;
    /// The netdev could not join the capability-gated interface registry
    /// (detail: 1 no authority, 2 revoked, 3 duplicate name). Not fatal:
    /// the kernel stack path (`narf_net::iface`) is registered.
    pub const NET_REGISTER: u32 = 256;
    /// Interface down (`ieee80211_do_stop`) could not delete the vdev
    /// (console only, Linux warns; detail = the errno).
    pub const IF_DOWN_VDEV_DELETE: u32 = 257;
    /// `ath11k_core_reset` declined a reset after repeated failed
    /// recoveries (`ATH11K_RESET_MAX_FAIL_COUNT_*`; detail = failures in a
    /// row).
    pub const RECOVERY_LIMIT: u32 = 258;
    /// Recovery: the power cycle or the QMI handshake to FW_INIT_DONE
    /// failed (detail = inner step << 16 | inner detail & 0xffff).
    pub const RECOVERY_FW: u32 = 259;
    /// Recovery: `ath11k_core_qmi_firmware_ready` failed on the restarted
    /// firmware (detail = core step << 16 | detail & 0xffff).
    pub const RECOVERY_CORE: u32 = 260;
    /// Recovery: the mac layer did not come back (detail 1 the open path
    /// — `ath11k_mac_op_start` + `add_interface` — failed, 3 device caps).
    pub const RECOVERY_MAC: u32 = 261;
}

/// `ATH11K_RESET_MAX_FAIL_COUNT_FIRST`.
pub const ATH11K_RESET_MAX_FAIL_COUNT_FIRST: u32 = 3;
/// `ATH11K_RESET_MAX_FAIL_COUNT_FINAL`.
pub const ATH11K_RESET_MAX_FAIL_COUNT_FINAL: u32 = 5;
/// `ATH11K_RESET_FAIL_TIMEOUT_HZ` (20 s).
pub const ATH11K_RESET_FAIL_TIMEOUT_MS: u64 = 20_000;
pub const ESHUTDOWN: i32 = 108;

pub const ETIMEDOUT: i32 = 110;
pub const ENOSPC: i32 = 28;
pub const EIO: i32 = 5;
pub const ENOTCONN: i32 = 107;
pub const ENOENT: i32 = 2;
pub const ENODEV: i32 = 19;
/// Stable identity source for physical WCN6855 radios.  nl80211's `phyN`
/// grouping must survive virtual-interface creation and deletion.
static NEXT_RADIO_ID: AtomicU64 = AtomicU64::new(1);

/// The `i`th contiguous 20-MHz channel range of `def`.  80+80 has two
/// independently regulated ranges; every other valid chandef has one.
fn chandef_segment(def: &ChanDef, i: usize) -> Option<(u32, u32)> {
    let first = match def.width {
        Width::W20NoHt | Width::W20 => (def.freq, 0),
        Width::W40 => (def.center_freq1, 10),
        Width::W80 => (def.center_freq1, 30),
        Width::W160 => (def.center_freq1, 70),
        Width::W80P80 => (def.center_freq1, 30),
    };
    match (def.width, i) {
        (_, 0) => Some(first),
        (Width::W80P80, 1) => Some((def.center_freq2, 30)),
        _ => None,
    }
}

/// Whether two channel definitions share at least one physical 20-MHz
/// subchannel.  The ranges have the exact 10/30/70-MHz centres prescribed by
/// cfg80211, so interval overlap is equivalent to subchannel overlap here.
fn chandef_overlaps(a: &ChanDef, b: &ChanDef) -> bool {
    for i in 0..2 {
        let Some((a_center, a_span)) = chandef_segment(a, i) else {
            continue;
        };
        let (a_lo, a_hi) = (
            a_center.saturating_sub(a_span),
            a_center.saturating_add(a_span),
        );
        for j in 0..2 {
            let Some((b_center, b_span)) = chandef_segment(b, j) else {
                continue;
            };
            let (b_lo, b_hi) = (
                b_center.saturating_sub(b_span),
                b_center.saturating_add(b_span),
            );
            if a_lo <= b_hi && b_lo <= a_hi {
                return true;
            }
        }
    }
    false
}

/// `ATH11K_WOW_RETRY_NUM` (`wow.h`).
pub const ATH11K_WOW_RETRY_NUM: u32 = 3;
/// `ATH11K_WOW_RETRY_WAIT_MS` (`wow.h`).
pub const ATH11K_WOW_RETRY_WAIT_MS: u32 = 200;
/// `ath11k_wow_enable` / `ath11k_wow_wakeup` wait up to 3 HZ, i.e. three
/// seconds on the normal 1 kHz kernel tick.
pub const ATH11K_WOW_COMPLETION_TIMEOUT_MS: u32 = 3_000;
/// Linux QCA6390/WCN6855 resource request and retained host capacity.
/// A vdev remains owned
/// by one netdev from WMI_VDEV_CREATE until its delete completion; the radio
/// never aliases station/AP state between these slots.
pub const WCN6855_MAX_VDEVS: usize = 4;

// `struct hal_tx_rate_stats.info0` in Linux's `ath11k/hal_desc.h`. The WBM
// release records a PHY rate for the first MSDU of a PPDU; firmware-native
// HTT completions do not carry this field.
const TX_RATE_BW: u32 = 0x0000_0006;
const TX_RATE_PKT_TYPE: u32 = 0x0000_0078;
const TX_RATE_SGI: u32 = 0x0000_0600;
const TX_RATE_MCS: u32 = 0x0000_7800;
const TX_RATE_OFDMA: u32 = 0x0000_8000;
const TX_RATE_TONES_IN_RU: u32 = 0x0fff_0000;

const TX_RATE_PKT_11A: u32 = 0;
const TX_RATE_PKT_11B: u32 = 1;
const TX_RATE_PKT_11N: u32 = 2;
const TX_RATE_PKT_11AC: u32 = 3;
const TX_RATE_PKT_11AX: u32 = 4;

// `struct rx_msdu_start.info3` in `ath11k/rx_desc.h`. Unlike a TX WBM
// release, an RX descriptor carries its receive stream bitmap directly.
const RX_RATE_PKT_TYPE: u32 = 0x0000_0f00;
const RX_RATE_SGI: u32 = 0x0000_6000;
const RX_RATE_MCS: u32 = 0x0007_8000;
const RX_RATE_BW: u32 = 0x0018_0000;
const RX_RATE_MIMO_SS_BITMAP: u32 = 0xff00_0000;

/// Convert a valid WBM `hal_tx_rate_stats.info0` into the cfg80211-style
/// rate report that `NL80211_CMD_GET_STATION` carries. `nss` is the AP's
/// negotiated receive stream count (`ath11k_sta::peer_nss` in Linux); this
/// completion format supplies no separate NSS field.
///
/// The bitrate arithmetic matches `cfg80211_calculate_bitrate_*`, so the
/// numeric `BITRATE32` value and the MCS/GI/RU attributes agree exactly.
pub(super) fn tx_rate_info(rate_stats: u32, nss: u8) -> Option<narf_wireless::RateInfo> {
    use super::hal::field_get;

    let width_mhz = match field_get(TX_RATE_BW, rate_stats) {
        0 => 20,
        1 => 40,
        2 => 80,
        3 => 160,
        _ => return None,
    };
    let he_ru_alloc = (rate_stats & TX_RATE_OFDMA != 0)
        .then(|| he_ru_alloc(field_get(TX_RATE_TONES_IN_RU, rate_stats) as u16));
    phy_rate_info(
        field_get(TX_RATE_PKT_TYPE, rate_stats),
        field_get(TX_RATE_MCS, rate_stats) as u8,
        field_get(TX_RATE_SGI, rate_stats) as u8,
        width_mhz,
        nss,
        he_ru_alloc,
    )
}

/// Linux `ath11k_update_per_peer_tx_stats`'s PPDU-rate conversion.  Unlike a
/// WBM release record, HTT supplies its own NSS, HE DCM and RU span, so this
/// is the authoritative current unicast TX rate when PPDU accounting is
/// enabled.
pub(super) fn ppdu_rate_info(rate: HttPpduRate) -> Option<narf_wireless::RateInfo> {
    let width_mhz = match rate.bandwidth {
        2 => 20,
        3 => 40,
        4 => 80,
        5 => 160,
        _ => return None,
    };
    let he_ru_alloc = (rate.preamble == TX_RATE_PKT_11AX as u8 && rate.ru_end >= rate.ru_start)
        .then(|| he_ru_alloc(rate.ru_end - rate.ru_start + 1));
    let mut decoded = phy_rate_info(
        rate.preamble as u32,
        rate.mcs,
        rate.gi,
        width_mhz,
        rate.nss,
        he_ru_alloc,
    )?;
    decoded.he_dcm = rate.dcm;
    Some(decoded)
}

/// Linux `DECLARE_EWMA(avg_rssi, 10, 8)` for the raw RSSI value stored in
/// `hal_rx_mon_ppdu_info`. Keep its 10 fractional bits until reporting: a
/// firmware that advertises db2dbm encodes negative dBm in the same u8 bit
/// pattern, so converting only after averaging is significant.
fn ppdu_rssi_ewma_add(average: &mut Option<u32>, sample: u8) {
    let scaled = (sample as u32) << 10;
    *average = Some(match *average {
        Some(previous) => previous.saturating_mul(255).saturating_add(scaled) / 256,
        None => scaled,
    });
}

/// `ath11k_mac_op_sta_statistics`'s db2dbm conversion for combined RSSI.
fn ppdu_rssi_dbm(raw: u8, db2dbm: bool) -> i8 {
    let signal = if db2dbm {
        raw as i8 as i32
    } else {
        raw as i32 + wmi::ATH11K_DEFAULT_NOISE_FLOOR
    };
    signal.clamp(i8::MIN as i32, i8::MAX as i32) as i8
}

fn ppdu_rssi_ewma_dbm(average: Option<u32>, db2dbm: bool) -> Option<i8> {
    average.map(|raw| ppdu_rssi_dbm((raw >> 10) as u8, db2dbm))
}

/// `ath11k_mac_put_chain_rssi`: firmware marks an unavailable receive chain
/// with one of these sentinel values.  Do not expose a nested nl80211 chain
/// member for it; `NL80211_STA_INFO_CHAIN_SIGNAL` is sparse by design.
fn ppdu_chain_rssi_dbm(raw: u8) -> Option<i8> {
    const ATH11K_DEFAULT_NOISE_FLOOR_DBM: i8 = wmi::ATH11K_DEFAULT_NOISE_FLOOR as i8;
    let signal = raw as i8;
    (!matches!(signal, 0 | -1 | ATH11K_DEFAULT_NOISE_FLOOR_DBM | i8::MIN)).then_some(signal)
}

/// Decode an RX MSDU descriptor's PHY fields as `ath11k_dp_rx_h_rate` does.
/// The WCN6855 fast RX descriptor has no HE OFDMA RU allocation, so HE
/// receive rates are reported at their full received bandwidth.
pub(super) fn rx_rate_info(msdu_info3: u32) -> Option<narf_wireless::RateInfo> {
    use super::hal::field_get;

    let width_mhz = match field_get(RX_RATE_BW, msdu_info3) {
        0 => 20,
        1 => 40,
        2 => 80,
        3 => 160,
        _ => return None,
    };
    let nss = (field_get(RX_RATE_MIMO_SS_BITMAP, msdu_info3) as u8).count_ones() as u8;
    phy_rate_info(
        field_get(RX_RATE_PKT_TYPE, msdu_info3),
        field_get(RX_RATE_MCS, msdu_info3) as u8,
        field_get(RX_RATE_SGI, msdu_info3) as u8,
        width_mhz,
        nss,
        None,
    )
}

/// Shared cfg80211 rate conversion for the WBM TX and fast-RX descriptor
/// layouts. `he_ru_alloc` is present only for a TX completion.
fn phy_rate_info(
    pkt_type: u32,
    mcs: u8,
    sgi: u8,
    width_mhz: u16,
    nss: u8,
    he_ru_alloc: Option<u8>,
) -> Option<narf_wireless::RateInfo> {
    let mut rate = narf_wireless::RateInfo {
        width_mhz,
        ..Default::default()
    };

    match pkt_type {
        TX_RATE_PKT_11A | TX_RATE_PKT_11B => {
            // `ATH11K_HW_RATECODE_CCK_SHORT_PREAM_MASK` is bit 2. It is
            // encoded in a CCK hardware rate code, not a short GI.
            let hw_rate = (if pkt_type == TX_RATE_PKT_11B {
                mcs & !0x04
            } else {
                mcs
            }) as u32;
            let rates = if pkt_type == TX_RATE_PKT_11B {
                &LEGACY_RATES[..4]
            } else {
                &LEGACY_RATES[4..]
            };
            let &(bitrate_100kbps, _) = rates.iter().find(|&&(_, code)| code == hw_rate)?;
            rate.bitrate_100kbps = bitrate_100kbps as u32;
        }
        TX_RATE_PKT_11N => {
            if mcs > 7 || !(1..=8).contains(&nss) {
                return None;
            }
            let ht_mcs = mcs.saturating_add(8 * (nss - 1));
            rate.ht_mcs = Some(ht_mcs);
            rate.short_gi = sgi != 0;
            rate.bitrate_100kbps = ht_bitrate_100kbps(mcs, nss, width_mhz, rate.short_gi)?;
        }
        TX_RATE_PKT_11AC => {
            if mcs > 9 || !(1..=8).contains(&nss) {
                return None;
            }
            rate.vht_mcs = Some((mcs, nss));
            rate.short_gi = sgi != 0;
            rate.bitrate_100kbps = vht_bitrate_100kbps(mcs, nss, width_mhz, rate.short_gi)?;
        }
        TX_RATE_PKT_11AX => {
            if mcs > 11 || !(1..=8).contains(&nss) {
                return None;
            }
            // `HAL_TX_RATE_STATS_SGI_04US` is not an HE GI. Linux's
            // ath11k converter defaults that unsupported encoding to 0.8 µs.
            let gi = match sgi {
                2 => 1, // 1.6 µs
                3 => 2, // 3.2 µs
                _ => 0, // 0.8 µs
            };
            rate.he_mcs = Some((mcs, nss, gi));
            rate.he_ru_alloc = he_ru_alloc;
            rate.bitrate_100kbps = he_bitrate_100kbps(mcs, nss, gi, width_mhz, he_ru_alloc)?;
        }
        _ => return None,
    }
    Some(rate)
}

/// Linux's `ath11k_mac_he_ru_tones_to_nl80211_he_ru_alloc`: values are the
/// UAPI enum ordinals, not literal tone counts.
fn he_ru_alloc(tones: u16) -> u8 {
    match tones {
        26 => 0,
        52 => 1,
        106 => 2,
        242 => 3,
        484 => 4,
        996 => 5,
        1_992 => 6,
        _ => 0,
    }
}

fn ht_bitrate_100kbps(mcs: u8, nss: u8, width_mhz: u16, short_gi: bool) -> Option<u32> {
    const RATE: [[u32; 8]; 2] = [
        [
            6_500_000, 13_000_000, 19_500_000, 26_000_000, 39_000_000, 52_000_000, 58_500_000,
            65_000_000,
        ],
        [
            13_500_000,
            27_000_000,
            40_500_000,
            54_000_000,
            81_000_000,
            108_000_000,
            121_500_000,
            135_000_000,
        ],
    ];
    let width = match width_mhz {
        20 => 0,
        40 => 1,
        _ => return None,
    };
    let mut bitrate = RATE[width][mcs as usize].saturating_mul(nss as u32);
    if short_gi {
        bitrate = bitrate / 9 * 10;
    }
    Some((bitrate + 50_000) / 100_000)
}

fn vht_bitrate_100kbps(mcs: u8, nss: u8, width_mhz: u16, short_gi: bool) -> Option<u32> {
    const RATE: [[u32; 10]; 4] = [
        [
            6_500_000, 13_000_000, 19_500_000, 26_000_000, 39_000_000, 52_000_000, 58_500_000,
            65_000_000, 78_000_000, 86_500_000,
        ],
        [
            13_500_000,
            27_000_000,
            40_500_000,
            54_000_000,
            81_000_000,
            108_000_000,
            121_500_000,
            135_000_000,
            162_000_000,
            180_000_000,
        ],
        [
            29_300_000,
            58_500_000,
            87_800_000,
            117_000_000,
            175_500_000,
            234_000_000,
            263_300_000,
            292_500_000,
            351_000_000,
            390_000_000,
        ],
        [
            58_500_000,
            117_000_000,
            175_500_000,
            234_000_000,
            351_000_000,
            468_000_000,
            526_500_000,
            585_000_000,
            702_000_000,
            780_000_000,
        ],
    ];
    let width = match width_mhz {
        20 => 0,
        40 => 1,
        80 => 2,
        160 => 3,
        _ => return None,
    };
    let mut bitrate = RATE[width][mcs as usize].saturating_mul(nss as u32);
    if short_gi {
        bitrate = bitrate / 9 * 10;
    }
    Some((bitrate + 50_000) / 100_000)
}

fn he_bitrate_100kbps(
    mcs: u8,
    nss: u8,
    gi: u8,
    width_mhz: u16,
    he_ru_alloc: Option<u8>,
) -> Option<u32> {
    // `cfg80211_calculate_bitrate_he`'s base 1SS rates in bps for
    // 0.8 / 1.6 / 3.2 µs GI, followed by its integer scaling formula.
    const MCS_DIVISOR: [u64; 12] = [
        102_399, 51_201, 34_134, 25_599, 17_067, 12_801, 11_377, 10_239, 8_532, 7_680, 6_828, 6_144,
    ];
    const RATE_160: [u64; 3] = [960_777_777, 907_400_000, 816_666_666];
    const RATE_996: [u64; 3] = [480_388_888, 453_700_000, 408_333_333];
    const RATE_484: [u64; 3] = [229_411_111, 216_666_666, 195_000_000];
    const RATE_242: [u64; 3] = [114_711_111, 108_333_333, 97_500_000];
    const RATE_106: [u64; 3] = [40_000_000, 37_777_777, 34_000_000];
    const RATE_52: [u64; 3] = [18_820_000, 17_777_777, 16_000_000];
    const RATE_26: [u64; 3] = [9_411_111, 8_888_888, 8_000_000];

    let gi = gi as usize;
    let base = match he_ru_alloc {
        Some(6) => RATE_160[gi],
        Some(5) => RATE_996[gi],
        Some(4) => RATE_484[gi],
        Some(3) => RATE_242[gi],
        Some(2) => RATE_106[gi],
        Some(1) => RATE_52[gi],
        Some(0) => RATE_26[gi],
        Some(_) => return None,
        None => match width_mhz {
            20 => RATE_242[gi],
            40 => RATE_484[gi],
            80 => RATE_996[gi],
            160 => RATE_160[gi],
            _ => return None,
        },
    };
    let bitrate = base
        .saturating_mul(6_144)
        .checked_div(MCS_DIVISOR[mcs as usize])?
        .saturating_mul(nss as u64)
        / 8;
    Some((bitrate / 10_000) as u32)
}

/// `NAPI_POLL_WEIGHT`.
pub const NAPI_BUDGET: u32 = 64;
/// NAPI re-polls of one group in one pass before yielding.
pub const DP_MAX_ROUNDS: u32 = 8;
/// `ATH11K_MON_TIMER_INTERVAL` (ms).
pub const ATH11K_MON_TIMER_INTERVAL: u64 = 10;
/// `DP_MON_SERVICE_BUDGET`.
pub const DP_MON_SERVICE_BUDGET: u32 = 128;
/// `ATH11K_TX_MGMT_NUM_PENDING_MAX`.
pub const ATH11K_TX_MGMT_NUM_PENDING_MAX: u32 = 512;
/// Interval of the runtime loop and the longest a waiter sleeps between
/// services (the DP shadow timers need ≤ 10 ms; Linux's monitor reap
/// timer is 10 ms).
pub const SERVICE_SLICE_MS: u32 = 10;
/// QMI transport service interval after bring-up.
pub const QMI_SERVICE_MS: u64 = 100;
/// Bound on queued EAPOL frames (iwlwifi / mac80211's control port keep
/// a short queue; the supplicant handles one exchange at a time).
pub const EAPOL_QUEUE_MAX: usize = 16;
/// Bound on received data frames waiting for the interface pump.
pub const RX_QUEUE_MAX: usize = 1024;
/// `ATH11K_FLUSH_TIMEOUT` (5 s).
pub const ATH11K_FLUSH_TIMEOUT_MS: u32 = 5000;

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(narf_console::Writer, "  ath11k: {}", args);
}

// ── DP ext interrupts (pcic.c `ath11k_pcic_ext_irq_config`) ────────

/// `ab->hw_params.ring_mask->*[grp]` has a ring: Linux gives the group
/// `num_irq = 1`, else no interrupt.
pub fn group_has_rings(mask: &RingMask, grp: usize) -> bool {
    grp < ATH11K_EXT_IRQ_GRP_NUM_MAX
        && (mask.tx[grp]
            | mask.rx[grp]
            | mask.rx_err[grp]
            | mask.rx_wbm_rel[grp]
            | mask.reo_status[grp]
            | mask.rxdma2host[grp]
            | mask.host2rxdma[grp]
            | mask.rx_mon_status[grp])
            != 0
}

/// `ath11k_pcic_ext_irq_config`: the MSI vector (relative to the
/// device's first vector) ext group `grp` interrupts on —
/// `(i % num_vectors) + base_vector` of the "DP" user — or `None` for a
/// group without rings or without a DP user.
///
/// WCN6855 (`ath11k_msi_config` QCA6390 table: DP = 18 vectors from 14;
/// `ath11k_hw_ring_mask_qca6390`): groups 0–2 and 4–10 → vectors 14–16
/// and 18–24; group 3 has no ring. The ring side programs the matching
/// MSI data (`ath11k_dp_srng_msi_setup`: `group % 18 + 14 + ep_base`).
pub fn dp_irq_vector(mask: &RingMask, config: &MsiConfig, grp: usize) -> Option<u32> {
    if !group_has_rings(mask, grp) {
        return None;
    }
    let (num_vectors, _user_base_data, base_vector) = config.user_assignment("DP", 0)?;
    if num_vectors == 0 {
        return None;
    }
    Some((grp as u32 % num_vectors) + base_vector)
}

/// Handler cookie for device vector `i`: the bitmask of ext groups on it.
pub fn dp_vector_cookie(mask: &RingMask, config: &MsiConfig, i: u32) -> Option<u64> {
    let mut m = 0u64;
    for grp in 0..ATH11K_EXT_IRQ_GRP_NUM_MAX {
        if dp_irq_vector(mask, config, grp) == Some(i) {
            m |= 1 << grp;
        }
    }
    (m != 0).then_some(m)
}

/// Ext groups whose MSI fired and the runtime has not serviced.
static DP_IRQ_PENDING: AtomicU32 = AtomicU32::new(0);
/// `ATH11K_FLAG_EXT_IRQ_ENABLED`.
static DP_IRQ_ENABLED: AtomicBool = AtomicBool::new(false);
static DP_IRQS_INSTALLED: AtomicBool = AtomicBool::new(false);
/// DP interrupts delivered (any DP vector).
pub static DP_MSI_FIRES: AtomicU64 = AtomicU64::new(0);

/// `ath11k_pcic_ext_interrupt_handler`: note the groups (cookie) and
/// wake the device owner, whose service pass is the NAPI poll. Ignored
/// while ext interrupts are disabled, as Linux. MSI is edge-triggered,
/// so there is no per-group mask to set (Linux `disable_irq_nosync` →
/// NAPI → `enable_irq`).
fn dp_msi_irq(cookie: u64) -> narf_interrupts::IrqStatus {
    if !DP_IRQ_ENABLED.load(Ordering::Acquire) {
        return narf_interrupts::IrqStatus::Handled;
    }
    DP_MSI_FIRES.fetch_add(1, Ordering::Relaxed);
    DP_IRQ_PENDING.fetch_or(cookie as u32, Ordering::AcqRel);
    ce::wake_waiters();
    narf_interrupts::IrqStatus::Handled
}

/// `true` while DP groups are pending (the CE wait future resolves on it).
pub(crate) fn dp_irq_pending() -> bool {
    DP_IRQ_PENDING.load(Ordering::Acquire) != 0
}

/// Hook the DP vectors (`ath11k_pcic_ext_irq_config`). Idempotent; the
/// handlers stay inert until [`set_dp_irqs_enabled`].
pub fn install_dp_irq_handlers(
    mask: &RingMask,
    config: &'static MsiConfig,
    base_irq: u8,
    n_vectors: u8,
) -> Result<(), TransportError> {
    if config.user_assignment("DP", 0).is_none() {
        return Err(TransportError::new(
            step::DP_IRQ_CONFIG,
            n_vectors as u32,
            ENOENT,
        ));
    }
    if DP_IRQS_INSTALLED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    for i in 0..n_vectors {
        if let Some(cookie) = dp_vector_cookie(mask, config, i as u32) {
            narf_interrupts::install_handler_named(base_irq + i, "ath11k-dp", cookie, dp_msi_irq);
        }
    }
    Ok(())
}

/// `ath11k_pcic_ext_irq_enable` / `_disable`.
pub fn set_dp_irqs_enabled(on: bool) {
    DP_IRQ_ENABLED.store(on, Ordering::Release);
}

/// Register access the runtime can move between tasks.
pub trait RtIo: ChipIo + Send + 'static {}
impl<T: ChipIo + Send + 'static> RtIo for T {}

/// A QMI session the runtime can move between tasks.
pub trait RtQmi: QmiFw + Send + 'static {}
impl<T: QmiFw + Send + 'static> RtQmi for T {}

/// The device's interrupt + time source after bring-up: the CE side
/// ([`CeIrq`]) plus the DP ext groups. `wait` must resolve on either.
/// Cloned into [`Shared`] so tasks wait without holding the core.
pub trait DpIrq: CeIrq + Clone + Send + Sync + 'static {
    /// Take the bitmask of ext groups that interrupted.
    fn take_dp_pending(&self) -> u32;
}

impl DpIrq for MsiCeIrq {
    fn take_dp_pending(&self) -> u32 {
        DP_IRQ_PENDING.swap(0, Ordering::AcqRel)
    }
}

// ── the DP hooks of `ath11k_core_qmi_firmware_ready` ──────────────

/// [`CoreHooks`] with the real data path.
#[allow(missing_debug_implementations)]
pub struct DpHooks {
    /// `None` = the chip's DP is not ported (fails `dp_alloc`).
    pub cfg: Option<DpHwParams>,
    /// Detail for [`step::DP_UNSUPPORTED`].
    pub hw_rev: u32,
    pub sizes: DpRingSizes,
    pub msi: Option<CeMsi>,
    pub dp: Option<Dp>,
    /// `HTT_TARGET_VERSION_TIMEOUT_HZ`.
    pub htt_version_timeout_ms: u64,
    /// Ext interrupts enabled (`irq_enable` ran).
    pub irqs_enabled: bool,
}

impl DpHooks {
    pub fn new(
        cfg: Option<DpHwParams>,
        hw_rev: u32,
        sizes: DpRingSizes,
        msi: Option<CeMsi>,
    ) -> Self {
        DpHooks {
            cfg,
            hw_rev,
            sizes,
            msi,
            dp: None,
            htt_version_timeout_ms: HTT_TARGET_VERSION_TIMEOUT_MS,
            irqs_enabled: false,
        }
    }
}

fn missing(hook: u32) -> TransportError {
    TransportError::new(step::DP_MISSING, hook, ENODEV)
}

impl<Io: ChipIo, Irq: CeIrq, Q: QmiFw> CoreHooks<CeHif<Io, Irq>, Q> for DpHooks {
    fn dp_alloc(&mut self, core: &mut Ath11kCore<CeHif<Io, Irq>, Q>) -> Result<(), TransportError> {
        let Some(cfg) = self.cfg else {
            return Err(TransportError::new(
                step::DP_UNSUPPORTED,
                self.hw_rev,
                95, // -EOPNOTSUPP
            ));
        };
        let hif = &mut core.hif;
        // Dp::alloc latches + prints its own failures.
        self.dp = Some(Dp::alloc(
            &mut hif.ce.hal,
            &hif.io,
            &cfg,
            self.sizes,
            self.msi,
        )?);
        Ok(())
    }

    fn pdev_reo_setup(
        &mut self,
        core: &mut Ath11kCore<CeHif<Io, Irq>, Q>,
    ) -> Result<(), TransportError> {
        let dp = self.dp.as_mut().ok_or(missing(1))?;
        let hif = &mut core.hif;
        dp.pdev_reo_setup(&mut hif.ce.hal, &hif.io)
    }

    async fn htt_ver_req(
        &mut self,
        core: &mut Ath11kCore<CeHif<Io, Irq>, Q>,
    ) -> Result<(), TransportError> {
        let dp = self.dp.as_mut().ok_or(missing(2))?;
        // ath11k_dp_htt_connect set dp->eid.
        dp.htt.eid = core.htt_ep.map(|e| e.eid);
        // init_completion(&dp->htt_tgt_version_received)
        dp.htt = HttTarget {
            eid: dp.htt.eid,
            ..HttTarget::default()
        };
        core.htt_send(&htt::ver_req_msg())
            .map_err(|e| TransportError::new(step::HTT_VER_SEND, e.step, e.errno))?;
        let deadline = core
            .hif
            .now_ms()
            .saturating_add(self.htt_version_timeout_ms);
        loop {
            // ath11k_dp_htt_htc_t2h_msg_handler for everything queued.
            while let Some(m) = core.take_htt() {
                if dp.htt_t2h_msg_handler(&m).is_err() {
                    dp.stats.htt_unhandled += 1;
                }
            }
            if dp.htt.version_ok()? {
                log(format_args!(
                    "htt: target version {}.{}",
                    dp.htt.ver_major, dp.htt.ver_minor
                ));
                return Ok(());
            }
            let now = core.hif.now_ms();
            if now >= deadline {
                log(format_args!("htt target version request timed out"));
                return Err(HttTarget::timeout_error());
            }
            core.pump((deadline - now).min(super::core::CORE_SLICE_MS) as u32)
                .await;
        }
    }

    async fn pdev_create(
        &mut self,
        core: &mut Ath11kCore<CeHif<Io, Irq>, Q>,
    ) -> Result<(), TransportError> {
        let dp = self.dp.as_mut().ok_or(missing(3))?;
        let hif = &mut core.hif;
        // ath11k_dp_pdev_alloc (pdev 0; latches + prints its failures).
        let msgs = dp.pdev_alloc(&mut hif.ce.hal, &hif.io, 0)?;
        // ath11k_dp_tx_htt_srng_setup per ring, in Linux's order; the
        // first failure ends the pdev alloc.
        for (i, m) in msgs.iter().enumerate() {
            core.htt_send(m).map_err(|e| {
                TransportError::new(
                    step::SRING_SETUP_SEND,
                    (i as u32) << 16 | (e.step & 0xffff),
                    e.errno,
                )
            })?;
        }
        // ath11k_mac_register is the caller's (the mac layer is built on
        // the runtime once the core is ready).
        Ok(())
    }

    fn irq_enable(&mut self, _core: &mut Ath11kCore<CeHif<Io, Irq>, Q>) {
        set_dp_irqs_enabled(true);
        self.irqs_enabled = true;
        diag::set_wifi_stage(WifiStage::DataPath);
    }
}

// ── the runtime ───────────────────────────────────────────────────

/// Station data-path state (the `ath11k_vif` / `ath11k_sta` / mac80211
/// `sta_info` fields the TX and RX paths read).
#[derive(Debug, Default)]
pub struct LinkState {
    /// `vif->addr`.
    pub own: [u8; 6],
    /// `ath11k_dp_vdev_tx_attach` result (+ the BSS peer's AST).
    pub vif: Option<VifTx>,
    /// The AP (BSS peer) once HTT-mapped.
    pub bss: Option<[u8; 6]>,
    /// `WLAN_STA_AUTHORIZED` / `peer->is_authorized`.
    pub authorized: bool,
    /// `sta->sta.wme`.
    pub wme: bool,
    /// `sdata->u.mgd.use_4addr`: use ToDS+FromDS headers for bridged
    /// station traffic and announce a newly enabled state with a four-address
    /// Null frame.
    pub four_addr: bool,
    /// A pairwise key is installed.
    pub ptk: bool,
    pub seq: SeqState,
    /// Received EAPOL frames (802.3) for the supplicant.
    /// EAPOL frames as 802.3 with whether the MPDU was decrypted
    /// (`enum frame_encryption` for wpa_supplicant).
    pub eapol_rx: VecDeque<(Vec<u8>, bool)>,
    /// `sta->deflink.status_stats.last_ack_signal` / `last_ack` (ms).
    pub last_ack_signal: Option<i32>,
    pub last_ack_ms: Option<u64>,
    /// Last valid `hal_tx_rate_stats.info0` for the associated AP. It is
    /// decoded with the negotiated NSS when GET_STATION snapshots it.
    pub last_tx_rate: Option<u32>,
    /// PPDU's complete rate report.  This takes precedence over the WBM
    /// fallback because it contains the actual NSS and HE RU/DCM fields.
    pub last_ppdu_tx_rate: Option<narf_wireless::RateInfo>,
    /// `ath11k_sta::tx_duration`: cumulative FES airtime from completed
    /// firmware PPDU statistics indications (microseconds).
    pub tx_duration_us: u64,
    /// Last non-zero combined RSSI from a completed monitor-status PPDU.
    pub last_ppdu_signal_dbm: Option<i8>,
    /// Linux `ewma_avg_rssi`'s raw, Q10 accumulator.
    pub ppdu_rssi_ewma: Option<u32>,
    /// `ewma_avg_rssi_read`, converted according to the firmware service
    /// bitmap and ready for `NL80211_STA_INFO_SIGNAL_AVG`.
    pub ppdu_signal_avg_dbm: Option<i8>,
    /// `HAL_PHYRX_RSSI_LEGACY` primary-20 RSSI by receive chain. Hardware
    /// only publishes them when `HW_DB2DBM_CONVERSION_SUPPORT` is present.
    pub chain_signal_dbm: [Option<i8>; RX_PPDU_MAX_CHAINS],
    /// `ath11k_sta::rx_duration`: cumulative monitor-status PPDU airtime.
    pub rx_duration_us: u64,
    /// `rx_msdu_start.info3` from the last accepted MSDU from the AP.
    pub last_rx_rate: Option<u32>,
    /// Received data frames (Ethernet II) for the interface, with
    /// `ath11k_dp_rx_h_csum_offload`'s verdict (`CHECKSUM_UNNECESSARY`).
    pub data_rx: VecDeque<(Vec<u8>, bool)>,
}

/// One associated receiver on a running AP or P2P GO vdev. This is runtime
/// packet-routing state only: MAC/WMI owns association capabilities and key
/// material, while this state records what header construction and controlled
/// port admission need.
#[derive(Debug, PartialEq, Eq)]
pub struct ApTxPeer {
    pub addr: [u8; 6],
    pub wme: bool,
    pub authorized: bool,
    pub ptk: bool,
    pub seq: SeqState,
    /// Completed unicast MSDUs addressed to this client.
    pub tx_packets: u32,
    /// Firmware-reported retry attempts beyond the first.
    pub tx_retries: u32,
    /// Completed unicast MSDUs without an ACK.
    pub tx_failed: u32,
    /// Decapsulated MSDUs accepted from this client, including EAPOL.
    pub rx_packets: u32,
    /// Last PPDU rate programmed by firmware for this client.
    pub last_tx_rate: Option<narf_wireless::RateInfo>,
    /// Cumulative PPDU FES airtime for this client (microseconds).
    pub tx_duration_us: u64,
    /// RX monitor-status statistics have the same peer granularity as the
    /// transmitted PPDU fields above.
    pub last_ppdu_signal_dbm: Option<i8>,
    pub ppdu_rssi_ewma: Option<u32>,
    pub ppdu_signal_avg_dbm: Option<i8>,
    pub chain_signal_dbm: [Option<i8>; RX_PPDU_MAX_CHAINS],
    pub rx_duration_us: u64,
}

/// Native-Wi-Fi data state for a beaconing AP / GO. It deliberately does not
/// reuse [`LinkState`]: a station has one BSS peer, whereas an AP selects a
/// receiver from each Ethernet destination and sends group traffic with its
/// GTK and interface sequence counter.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApTxState {
    pub vdev_id: u32,
    pub bssid: [u8; 6],
    pub privacy: bool,
    pub gtk_installed: bool,
    pub group_seq: SeqState,
    pub peers: Vec<ApTxPeer>,
}

/// Runtime-owned state for one firmware vdev.  Linux keeps the equivalent
/// state below its `ath11k_vif` / mac80211 vif; NARF keeps a compact entry
/// per WCN6855 vdev because all four slots share one core/DP runtime.
#[derive(Debug, Default)]
pub struct VdevRuntime {
    /// Station data path, including its native-Wi-Fi VIF attachment.
    pub link: LinkState,
    /// The vdev was created with an AP/GO role and therefore owns a self
    /// peer before `WMI_VDEV_UP` makes it beaconing.
    pub ap_configured: bool,
    /// Active AP/GO data-path state, present only after VDEV_UP.
    pub ap: Option<ApTxState>,
    /// Per-vif mac80211 TXQs and their queue-stop reasons.  CSA/CAC on one
    /// AP must never stop another concurrent vdev's traffic.
    pub txq: TxQueues,
    /// `local->ack_status_frames` for this vif: ACK id → TCL MSDU id.
    pub ack_frames: Idr<Option<u32>>,
    /// Completed requested TX statuses for this vif only.
    pub ack_status: VecDeque<(u32, TxStatus)>,
    /// Locally detected TKIP Michael failures awaiting the netdev's
    /// cfg80211 `MICHAEL_MIC_FAILURE` notification.
    pub mic_failures: VecDeque<MichaelMicFailure>,
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtStats {
    pub passes: u32,
    pub dp_irqs: [u32; ATH11K_EXT_IRQ_GRP_NUM_MAX],
    /// DP work found on a group whose MSI had not fired.
    pub dp_polled_without_irq: u32,
    pub htt_rx: u32,
    pub htt_bad: u32,
    pub rx_data: u32,
    pub rx_eapol: u32,
    pub rx_dropped_unauth: u32,
    pub rx_dropped_not_ours: u32,
    pub rx_dropped_echo: u32,
    /// EAPOL to neither our address nor the PAE group address
    /// (`ieee80211_frame_allowed`).
    pub rx_dropped_eapol_da: u32,
    pub rx_dropped_short: u32,
    pub rx_queue_full: u32,
    pub tx_data: u32,
    pub tx_eapol: u32,
    /// Directed Null / QoS Null AP-liveness probes.
    pub tx_nullfunc: u32,
    pub tx_failed: u32,
    /// Frames dropped from the TX queues (`fq` overlimit, purge).
    pub tx_queue_dropped: u32,
    pub tx_completed: u32,
    /// `ieee80211_tx_status_ext` outcomes of completed MSDUs.
    pub tx_status_acked: u32,
    pub tx_status_noack: u32,
    pub tx_status_dropped: u32,
    /// Aggregate retries reported in TQM TX completions
    /// (`HAL_WBM_RELEASE_INFO1_TRANSMIT_COUNT - 1`).
    pub tx_retries: u32,
    pub mgmt_tx: u32,
    pub mgmt_tx_done: u32,
    pub mgmt_tx_unknown: u32,
    pub reo_status: u32,
    /// `ab->stats.fw_crash_counter`.
    pub fw_crash_counter: u32,
    /// Recoveries that brought the device back.
    pub recoveries: u32,
}

/// `ath11k_core_reset`'s bookkeeping (`fail_cont_count`,
/// `reset_fail_timeout`), kept across recoveries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResetState {
    /// Recoveries that failed in a row.
    pub fail_cont_count: u32,
    /// No further reset before this (ms) once `fail_cont_count` reached
    /// `ATH11K_RESET_MAX_FAIL_COUNT_FIRST`.
    pub reset_fail_timeout: u64,
}

/// `ar->txmgmt_idr` + `num_pending_mgmt_tx`.
#[derive(Debug, Default)]
pub struct MgmtTx {
    /// The DMA extent and owning vdev.  WMI completion carries only a
    /// descriptor id, so retaining the owner is necessary to wake the right
    /// concurrent MAC instance.
    pub bufs: Idr<MgmtTxBuf>,
    pub pending: u32,
}

#[derive(Debug)]
pub struct MgmtTxBuf {
    _mem: DmaMem,
    vdev_id: u32,
}

/// The core + DP + station state after bring-up (`struct ath11k_base` /
/// `struct ath11k` as the running driver sees them).
#[allow(missing_debug_implementations)]
pub struct Rt<Io: RtIo, Irq: DpIrq, Q: RtQmi> {
    pub core: Ath11kCore<CeHif<Io, Irq>, Q>,
    pub dp: Dp,
    /// The three independently addressable vdev slots NARF currently admits.
    /// Entry index always equals its WMI `vdev_id`.
    pub vdevs: Vec<VdevRuntime>,
    pub mgmt: MgmtTx,
    pub stats: RtStats,
    /// `mon_reap_timer` armed (next expiry).
    pub mon_reap_at: Option<u64>,
    /// `ath11k_wow_op_suspend` completed the MHI-M3 handoff.  While set,
    /// the runtime must not poll CE/DP rings or run their shadow timers:
    /// their MMIO writes are invalid until `ath11k_hif_resume` restores M0.
    wowlan_suspended: bool,
    /// Whether the monitor-status reap timer was active immediately before
    /// the WoW handoff.  Its deadline is restarted, rather than replayed,
    /// after MHI resumes.
    wowlan_mon_reap_active: bool,
    qmi_service_at: u64,
    /// A firmware crash / restart the transport reported, not yet acted
    /// on.
    pub fw_notice: Option<FwNotice>,
    /// `ATH11K_FLAG_CRASH_FLUSH`: waits end, WMI / DP sends fail with
    /// `-ESHUTDOWN` until the restart.
    pub crash_flush: bool,
    pub reset: ResetState,
    /// WMI events are routed here before an individual `Port` consumes one.
    /// A WMI event for vdev 1 must not be consumed and discarded by a task
    /// currently waiting on vdev 0.
    events: Vec<VecDeque<Vec<u8>>>,
}

/// A synchronous port call, applied at the next locked step.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyncOp {
    MgmtTxDone(u32),
    VdevTxAttach {
        vdev_id: u32,
        addr: [u8; 6],
        ap: bool,
    },
    ApStarted {
        vdev_id: u32,
        bssid: [u8; 6],
        privacy: bool,
    },
    ApStopped {
        vdev_id: u32,
    },
    ApChannelSwitching {
        vdev_id: u32,
        blocked: bool,
    },
    ApDfsCac {
        vdev_id: u32,
        running: bool,
    },
    ApStationAdded {
        vdev_id: u32,
        addr: [u8; 6],
        wme: bool,
    },
    ApStationRemoved {
        vdev_id: u32,
        addr: [u8; 6],
    },
    ApGroupKey {
        vdev_id: u32,
        installed: bool,
    },
    PeerCleanup {
        vdev_id: u32,
        addr: [u8; 6],
    },
    SetAuthorized {
        vdev_id: u32,
        addr: [u8; 6],
        on: bool,
    },
    StaWme {
        vdev_id: u32,
        addr: [u8; 6],
        wme: bool,
    },
    StaFourAddr {
        vdev_id: u32,
        enabled: bool,
    },
    FragsFlush {
        vdev_id: u32,
        addr: [u8; 6],
    },
}

fn is_multicast(a: &[u8]) -> bool {
    a[0] & 1 != 0
}

/// `pae_group_addr` of `ieee80211_frame_allowed` (IEEE 802.1X PAE group
/// address 01-80-C2-00-00-03).
pub const PAE_GROUP_ADDR: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03];

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Rt<Io, Irq, Q> {
    /// A runtime over a ready core and its DP.
    pub fn new(core: Ath11kCore<CeHif<Io, Irq>, Q>, dp: Dp) -> Self {
        let own = core.mac_addr.unwrap_or_default();
        let mut vdevs = Vec::with_capacity(WCN6855_MAX_VDEVS);
        for _ in 0..WCN6855_MAX_VDEVS {
            vdevs.push(VdevRuntime {
                link: LinkState {
                    own,
                    ..LinkState::default()
                },
                ..VdevRuntime::default()
            });
        }
        let mut events = Vec::with_capacity(WCN6855_MAX_VDEVS);
        for _ in 0..WCN6855_MAX_VDEVS {
            events.push(VecDeque::new());
        }
        Rt {
            core,
            dp,
            vdevs,
            mgmt: MgmtTx::default(),
            stats: RtStats::default(),
            mon_reap_at: None,
            wowlan_suspended: false,
            wowlan_mon_reap_active: false,
            qmi_service_at: 0,
            fw_notice: None,
            crash_flush: false,
            reset: ResetState::default(),
            events,
        }
    }

    pub(crate) fn vdev(&self, vdev_id: u32) -> Option<&VdevRuntime> {
        self.vdevs.get(vdev_id as usize)
    }

    pub(crate) fn vdev_mut(&mut self, vdev_id: u32) -> Option<&mut VdevRuntime> {
        self.vdevs.get_mut(vdev_id as usize)
    }

    pub fn now_ms(&self) -> u64 {
        (self.core.hif.clock)()
    }

    /// The mac layer's view of the device (`ath11k_mac_register` inputs).
    pub fn device_caps(&self) -> Result<DeviceCaps, TransportError> {
        device_caps(&self.core)
    }

    fn apply(&mut self, op: SyncOp) {
        let now = self.now_ms();
        match op {
            SyncOp::MgmtTxDone(id) => {
                // wmi_process_mgmt_tx_comp: idr_find + idr_remove +
                // dma_unmap; num_pending_mgmt_tx--.
                if self.mgmt.bufs.remove(id).is_some() {
                    self.mgmt.pending = self.mgmt.pending.saturating_sub(1);
                    self.stats.mgmt_tx_done += 1;
                } else {
                    self.stats.mgmt_tx_unknown += 1;
                }
            }
            SyncOp::VdevTxAttach { vdev_id, addr, ap } => {
                // ath11k_dp_vdev_tx_attach + ath11k_dp_update_vdev_search
                // (pdev 0; WCN6855 has no HTT peer map v2).
                let htt_peer_map_v2 = self.dp.cfg.htt_peer_map_v2;
                let Some(vdev) = self.vdev_mut(vdev_id) else {
                    return;
                };
                vdev.link.vif = Some(VifTx::attach(vdev_id as u8, 0, htt_peer_map_v2));
                vdev.link.own = addr;
                vdev.ap_configured = ap;
                vdev.ap = None;
            }
            SyncOp::ApStarted {
                vdev_id,
                bssid,
                privacy,
            } => {
                if let Some(vdev) = self.vdev_mut(vdev_id).filter(|vdev| vdev.ap_configured) {
                    vdev.ap = Some(ApTxState {
                        vdev_id,
                        bssid,
                        privacy,
                        ..ApTxState::default()
                    });
                }
            }
            SyncOp::ApStopped { vdev_id } => {
                if let Some(vdev) = self
                    .vdev_mut(vdev_id)
                    .filter(|vdev| vdev.ap.as_ref().is_some_and(|ap| ap.vdev_id == vdev_id))
                {
                    vdev.ap = None;
                    // A failed CSA tears the AP down; do not leave the
                    // per-vif queue-stop bit behind for its next start.
                    vdev.txq.wake(TxQueues::vif_queues(), txq::reason::CSA);
                    vdev.txq.wake(TxQueues::vif_queues(), txq::reason::DFS_CAC);
                }
            }
            SyncOp::ApChannelSwitching { vdev_id, blocked } => {
                if let Some(vdev) = self
                    .vdev_mut(vdev_id)
                    .filter(|vdev| vdev.ap.as_ref().is_some_and(|ap| ap.vdev_id == vdev_id))
                {
                    if blocked {
                        vdev.txq.stop(TxQueues::vif_queues(), txq::reason::CSA);
                    } else {
                        vdev.txq.wake(TxQueues::vif_queues(), txq::reason::CSA);
                    }
                }
            }
            SyncOp::ApDfsCac { vdev_id, running } => {
                if let Some(vdev) = self
                    .vdev_mut(vdev_id)
                    .filter(|vdev| vdev.ap.as_ref().is_some_and(|ap| ap.vdev_id == vdev_id))
                {
                    if running {
                        vdev.txq.stop(TxQueues::vif_queues(), txq::reason::DFS_CAC);
                    } else {
                        vdev.txq.wake(TxQueues::vif_queues(), txq::reason::DFS_CAC);
                    }
                }
            }
            SyncOp::ApStationAdded { vdev_id, addr, wme } => {
                if let Some(ap) = self
                    .vdev_mut(vdev_id)
                    .and_then(|vdev| vdev.ap.as_mut())
                    .filter(|ap| ap.vdev_id == vdev_id)
                {
                    if let Some(peer) = ap.peers.iter_mut().find(|peer| peer.addr == addr) {
                        peer.wme = wme;
                    } else {
                        ap.peers.push(ApTxPeer {
                            addr,
                            wme,
                            authorized: false,
                            ptk: false,
                            seq: SeqState::default(),
                            tx_packets: 0,
                            tx_retries: 0,
                            tx_failed: 0,
                            rx_packets: 0,
                            last_tx_rate: None,
                            tx_duration_us: 0,
                            last_ppdu_signal_dbm: None,
                            ppdu_rssi_ewma: None,
                            ppdu_signal_avg_dbm: None,
                            chain_signal_dbm: [None; RX_PPDU_MAX_CHAINS],
                            rx_duration_us: 0,
                        });
                    }
                }
            }
            SyncOp::ApStationRemoved { vdev_id, addr } => {
                if let Some(ap) = self
                    .vdev_mut(vdev_id)
                    .and_then(|vdev| vdev.ap.as_mut())
                    .filter(|ap| ap.vdev_id == vdev_id)
                {
                    ap.peers.retain(|peer| peer.addr != addr);
                }
            }
            SyncOp::ApGroupKey { vdev_id, installed } => {
                if let Some(ap) = self
                    .vdev_mut(vdev_id)
                    .and_then(|vdev| vdev.ap.as_mut())
                    .filter(|ap| ap.vdev_id == vdev_id)
                {
                    ap.gtk_installed = installed;
                }
            }
            SyncOp::PeerCleanup { vdev_id, addr } => {
                let hif = &mut self.core.hif;
                if let Err(e) =
                    self.dp
                        .peer_cleanup(&mut hif.ce.hal, &hif.io, vdev_id as u8, &addr, now)
                {
                    // ath11k_dp_peer_cleanup: "failed to lookup peer".
                    log(format_args!(
                        "dp peer cleanup: step {} (-{})",
                        e.step, e.errno
                    ));
                }
            }
            SyncOp::SetAuthorized { vdev_id, addr, on } => {
                if let Some(vdev) = self.vdev_mut(vdev_id) {
                    if vdev.link.bss == Some(addr) {
                        vdev.link.authorized = on;
                    }
                    if let Some(peer) = vdev
                        .ap
                        .as_mut()
                        .and_then(|ap| ap.peers.iter_mut().find(|peer| peer.addr == addr))
                    {
                        peer.authorized = on;
                    }
                }
            }
            SyncOp::StaWme { vdev_id, addr, wme } => {
                if let Some(vdev) = self.vdev_mut(vdev_id) {
                    if vdev.link.bss == Some(addr) {
                        vdev.link.wme = wme;
                    }
                }
            }
            SyncOp::StaFourAddr { vdev_id, enabled } => {
                if let Some(vdev) = self.vdev_mut(vdev_id) {
                    vdev.link.four_addr = enabled;
                }
                if enabled {
                    // `ieee80211_send_4addr_nullfunc`: best effort, no
                    // control-path waiter. The builder selects the exact
                    // 30-byte FromDS|ToDS Null frame from the state above.
                    let _ = self.tx_nullfunc_status_for(vdev_id);
                }
            }
            SyncOp::FragsFlush { vdev_id, addr } => {
                let hif = &mut self.core.hif;
                self.dp
                    .peer_frags_flush(&mut hif.ce.hal, &hif.io, vdev_id as u8, &addr);
            }
        }
    }

    /// HTT T2H for the DP (`ath11k_dp_htt_htc_t2h_msg_handler`).
    fn route_htt(&mut self) {
        while let Some(m) = self.core.take_htt() {
            self.stats.htt_rx += 1;
            if self.dp.htt_t2h_msg_handler(&m).is_err() {
                self.stats.htt_bad += 1;
            }
            while let Some(ppdu) = self.dp.take_ppdu_stats() {
                self.ppdu_stats_one(ppdu);
            }
        }
    }

    /// Apply one PPDU after the DP's bounded fragment window has closed it.
    /// This is `ath11k_htt_update_ppdu_stats` / its per-peer updater: only a
    /// valid user-rate TLV refreshes the station's rate and FES airtime, and
    /// MU users each receive the same physical PPDU duration.
    fn ppdu_stats_one(&mut self, ppdu: HttPpduStats) {
        for user in ppdu.users {
            let Some(rate) = user.rate.and_then(ppdu_rate_info) else {
                continue;
            };
            let Some(peer) = self.dp.peer_by_id(user.peer_id).copied() else {
                continue;
            };
            let vdev_id = peer.vdev_id as u32;
            let duration = ppdu.tx_duration_us.unwrap_or_default() as u64;
            let bss_peer = self
                .vdev(vdev_id)
                .is_some_and(|vdev| vdev.link.bss == Some(peer.addr));
            if bss_peer {
                if let Some(vdev) = self.vdev_mut(vdev_id) {
                    vdev.link.last_ppdu_tx_rate = Some(rate);
                    vdev.link.tx_duration_us = vdev.link.tx_duration_us.saturating_add(duration);
                }
                continue;
            }
            if let Some(ap_peer) = self
                .vdev_mut(vdev_id)
                .and_then(|vdev| vdev.ap.as_mut())
                .filter(|ap| ap.vdev_id == vdev_id)
                .and_then(|ap| ap.peers.iter_mut().find(|known| known.addr == peer.addr))
            {
                ap_peer.last_tx_rate = Some(rate);
                ap_peer.tx_duration_us = ap_peer.tx_duration_us.saturating_add(duration);
            }
        }
    }

    /// Apply the peer-facing subset of a completed monitor-status PPDU.
    /// This is `ath11k_dp_rx_update_peer_stats` after
    /// `ath11k_hal_rx_parse_mon_status`: PPDU duration is charged even when
    /// RSSI is zero, combined RSSI updates the raw EWMA, and chain values are
    /// reported only by firmware that explicitly supplies dBm values.
    fn drain_rx_ppdu_stats(&mut self) {
        while let Some(ppdu) = self.dp.take_rx_ppdu_stats() {
            self.rx_ppdu_stats_one(ppdu);
        }
    }

    fn rx_ppdu_stats_one(&mut self, ppdu: RxPpduStats) {
        let Some(peer) = self.dp.peer_by_id(ppdu.peer_id).copied() else {
            return;
        };
        let db2dbm = self
            .core
            .svc_map
            .test(super::wmi_ids::WMI_TLV_SERVICE_HW_DB2DBM_CONVERSION_SUPPORT);
        let duration = ppdu.rx_duration_us.unwrap_or_default() as u64;
        let chain_signal_dbm = if db2dbm {
            ppdu.rssi_chain_pri20
                .map(|rssi| rssi.and_then(ppdu_chain_rssi_dbm))
        } else {
            [None; RX_PPDU_MAX_CHAINS]
        };
        let vdev_id = peer.vdev_id as u32;
        let bss_peer = self
            .vdev(vdev_id)
            .is_some_and(|vdev| vdev.link.bss == Some(peer.addr));
        if bss_peer {
            if let Some(vdev) = self.vdev_mut(vdev_id) {
                vdev.link.rx_duration_us = vdev.link.rx_duration_us.saturating_add(duration);
                let raw = ppdu.rssi_comb.unwrap_or_default();
                vdev.link.last_ppdu_signal_dbm = (raw != 0).then(|| ppdu_rssi_dbm(raw, db2dbm));
                ppdu_rssi_ewma_add(&mut vdev.link.ppdu_rssi_ewma, raw);
                vdev.link.ppdu_signal_avg_dbm =
                    ppdu_rssi_ewma_dbm(vdev.link.ppdu_rssi_ewma, db2dbm);
                vdev.link.chain_signal_dbm = chain_signal_dbm;
            }
            return;
        }
        if let Some(ap_peer) = self
            .vdev_mut(vdev_id)
            .and_then(|vdev| vdev.ap.as_mut())
            .filter(|ap| ap.vdev_id == vdev_id)
            .and_then(|ap| ap.peers.iter_mut().find(|known| known.addr == peer.addr))
        {
            ap_peer.rx_duration_us = ap_peer.rx_duration_us.saturating_add(duration);
            let raw = ppdu.rssi_comb.unwrap_or_default();
            ap_peer.last_ppdu_signal_dbm = (raw != 0).then(|| ppdu_rssi_dbm(raw, db2dbm));
            ppdu_rssi_ewma_add(&mut ap_peer.ppdu_rssi_ewma, raw);
            ap_peer.ppdu_signal_avg_dbm = ppdu_rssi_ewma_dbm(ap_peer.ppdu_rssi_ewma, db2dbm);
            ap_peer.chain_signal_dbm = chain_signal_dbm;
        }
    }

    /// Deliver one decapsulated AP/GO MSDU. Any known associated client may
    /// send EAPOL while its controlled port is closed; other traffic requires
    /// that client's authorization. Unlike station RX, an AP accepts an
    /// arbitrary Ethernet destination so bridging/routing can decide whether
    /// the frame stays local or leaves another interface.
    fn rx_ap_msdu(&mut self, vdev_id: u32, m: RxMsdu) {
        let csum_ok = m.csum_ok;
        let peer_id = m.peer_id;
        let f = m.frame;
        if f.len() < ETH_HLEN {
            self.stats.rx_dropped_short += 1;
            return;
        }
        let Some(peer) = self.dp.peer_by_id(peer_id).copied() else {
            self.stats.rx_dropped_not_ours += 1;
            return;
        };
        let Some((bssid, authorized)) = self.vdev(vdev_id).and_then(|vdev| {
            let ap = vdev.ap.as_ref().filter(|ap| ap.vdev_id == vdev_id)?;
            let station = ap.peers.iter().find(|station| station.addr == peer.addr)?;
            Some((ap.bssid, station.authorized))
        }) else {
            self.stats.rx_dropped_not_ours += 1;
            return;
        };
        // A locally transmitted group frame can return through the receive
        // path. Never hand that echo to the bridge again.
        if f[6..12] == bssid {
            self.stats.rx_dropped_echo += 1;
            return;
        }
        let eapol = u16::from_be_bytes([f[12], f[13]]) == ETH_P_PAE;
        if !eapol && !authorized {
            self.stats.rx_dropped_unauth += 1;
            return;
        }
        let index = vdev_id as usize;
        if index >= self.vdevs.len() {
            self.stats.rx_dropped_not_ours += 1;
            return;
        }
        let vdev = &mut self.vdevs[index];
        if vdev.link.data_rx.len() >= RX_QUEUE_MAX {
            self.stats.rx_queue_full += 1;
            return;
        }
        if eapol {
            self.stats.rx_eapol += 1;
        } else {
            self.stats.rx_data += 1;
        }
        if let Some(station) = vdev.ap.as_mut().and_then(|ap| {
            ap.peers
                .iter_mut()
                .find(|station| station.addr == peer.addr)
        }) {
            station.rx_packets = station.rx_packets.saturating_add(1);
        }
        vdev.link.data_rx.push_back((f, csum_ok));
    }

    /// Classify one delivered MSDU (mac80211 RX for a station:
    /// `ieee80211_accept_frame`, `ieee80211_data_to_8023`'s echo check,
    /// `ieee80211_frame_allowed` — EAPOL only to our address or the PAE
    /// group address, whatever its protection; everything else through
    /// `ieee80211_802_1x_port_control` — then
    /// `ieee80211_deliver_skb_to_local_stack`: the control port protocol
    /// goes to the supplicant (`control_port_over_nl80211`), the rest to
    /// the stack). Which EAPOL source the supplicant accepts is its own
    /// rule (wpa_supplicant's `last_eapol_matches_bssid`; `mac.rs`).
    fn rx_msdu(&mut self, m: RxMsdu) {
        let peer_id = m.peer_id;
        let Some(peer) = self.dp.peer_by_id(peer_id).copied() else {
            self.stats.rx_dropped_not_ours += 1;
            return;
        };
        let vdev_id = peer.vdev_id as u32;
        if self.vdev(vdev_id).is_some_and(|vdev| vdev.ap.is_some()) {
            self.rx_ap_msdu(vdev_id, m);
            return;
        }
        let csum_ok = m.csum_ok;
        let decrypted = m.decrypted;
        let rate_info = m.rate_info;
        let f = m.frame;
        if f.len() < ETH_HLEN {
            self.stats.rx_dropped_short += 1;
            return;
        }
        let index = vdev_id as usize;
        if index >= self.vdevs.len() {
            self.stats.rx_dropped_not_ours += 1;
            return;
        }
        let vdev = &mut self.vdevs[index];
        let own = vdev.link.own;
        let (da, sa) = (&f[0..6], &f[6..12]);
        if is_multicast(da) && sa == own {
            // Our own group frame relayed by the AP.
            self.stats.rx_dropped_echo += 1;
            return;
        }
        if !is_multicast(da) && da != own {
            self.stats.rx_dropped_not_ours += 1;
            return;
        }
        // `ath11k_dp_rx_h_rate` receives PHY data with every fast-RX
        // descriptor. Keep it only for the BSS peer after the local-address
        // checks, so another peer or a relayed echo cannot alter STA_INFO.
        if vdev.link.bss == Some(peer.addr) {
            vdev.link.last_rx_rate = Some(rate_info);
        }
        if u16::from_be_bytes([f[12], f[13]]) == ETH_P_PAE {
            if da != own && da != PAE_GROUP_ADDR {
                self.stats.rx_dropped_eapol_da += 1;
                return;
            }
            self.stats.rx_eapol += 1;
            if vdev.link.eapol_rx.len() >= EAPOL_QUEUE_MAX {
                vdev.link.eapol_rx.pop_front();
            }
            vdev.link.eapol_rx.push_back((f, decrypted));
        } else if vdev.link.authorized {
            if vdev.link.data_rx.len() >= RX_QUEUE_MAX {
                self.stats.rx_queue_full += 1;
                return;
            }
            self.stats.rx_data += 1;
            vdev.link.data_rx.push_back((f, csum_ok));
        } else {
            self.stats.rx_dropped_unauth += 1;
        }
    }

    fn handle_dp_output(&mut self, out: DpServiceOutput, now: u64) {
        for m in out.rx {
            self.rx_msdu(m);
        }
        // Buffers are released inside the completion handler; each MSDU's
        // status goes to ieee80211_tx_status_ext.
        self.stats.tx_completed += out.tx_done.len() as u32;
        for c in &out.tx_done {
            self.tx_status_one(c, now);
        }
        if !out.reo_status.is_empty() {
            self.stats.reo_status += out.reo_status.len() as u32;
            let hif = &mut self.core.hif;
            self.dp
                .reo_status_handler(&mut hif.ce.hal, &hif.io, &out.reo_status, now);
        }
    }

    /// One service pass: the CE tasklet work (+ HTC / WMI / HTT
    /// routing), every DP ext group's NAPI poll (the interrupting ones
    /// first counted, all of them polled — the poll fallback), the DP
    /// shadow timers, the monitor-status reap timer, and the QMI
    /// transport. Synchronous.
    pub fn service(&mut self) {
        self.stats.passes += 1;
        if self.wowlan_suspended {
            // Linux stopped CE/DP shadow timers and disabled their IRQs
            // before entering M3.  Do not let NARF's poll fallback turn a
            // quiet WoW transport back into regular MMIO traffic.
            return;
        }
        let now = self.now_ms();
        let ce_pending = self.core.hif.irq.take_pending();
        {
            let hif = &mut self.core.hif;
            hif.ce.service(&hif.io, ce_pending);
        }
        self.core.drain_rx();
        self.route_htt();

        self.dp.now_ms = now;
        let mask = *self.dp.cfg.hw.ring_mask;
        let pending = self.core.hif.irq.take_dp_pending();
        for grp in 0..ATH11K_EXT_IRQ_GRP_NUM_MAX {
            if !group_has_rings(&mask, grp) {
                continue;
            }
            let fired = pending & (1 << grp) != 0;
            if fired {
                self.stats.dp_irqs[grp] += 1;
            }
            for _ in 0..DP_MAX_ROUNDS {
                let out = {
                    let hif = &mut self.core.hif;
                    self.dp
                        .service_srng(&mut hif.ce.hal, &hif.io, grp, NAPI_BUDGET)
                };
                let work = out.work_done as usize + out.tx_done.len() + out.reo_status.len();
                if work != 0 && !fired {
                    self.stats.dp_polled_without_irq += 1;
                }
                // napi_complete_done when under budget; else re-poll.
                let again = out.work_done >= NAPI_BUDGET;
                self.handle_dp_output(out, now);
                if !again {
                    break;
                }
            }
        }
        for failure in self.dp.take_mic_failures() {
            const MAX_PENDING_MIC_FAILURES: usize = 32;
            if let Some(vdev) = self.vdev_mut(failure.vdev_id as u32) {
                if vdev.mic_failures.len() == MAX_PENDING_MIC_FAILURES {
                    vdev.mic_failures.pop_front();
                }
                vdev.mic_failures.push_back(failure);
            }
        }
        {
            let hif = &mut self.core.hif;
            self.dp.service_shadow_timers(&mut hif.ce.hal, &hif.io, now);
            self.dp.service_frag_timers(&mut hif.ce.hal, &hif.io, now);
        }
        // ath11k_dp_service_mon_ring (non-full-monitor: status rings).
        if let Some(at) = self.mon_reap_at {
            if now >= at {
                for j in 0..self.dp.cfg.num_rxdma_per_pdev {
                    let mut budget = DP_MON_SERVICE_BUDGET;
                    let hif = &mut self.core.hif;
                    self.dp
                        .reap_mon_status(&mut hif.ce.hal, &hif.io, j, &mut budget);
                }
                self.mon_reap_at = Some(now + ATH11K_MON_TIMER_INTERVAL);
            }
        }
        self.drain_rx_ppdu_stats();
        // The MHI controller + QMI handle: on their interrupt, else every
        // QMI_SERVICE_MS (the poll fallback).
        if self.core.qmi.irq_pending() || now >= self.qmi_service_at {
            if let Some(n) = self.core.qmi.service() {
                self.fw_notify(n);
            }
            self.qmi_service_at = now + QMI_SERVICE_MS;
        }
    }

    /// The software half of Linux's `ath11k_ce_stop_shadow_timers` +
    /// `ath11k_dp_stop_shadow_timers`, immediately before MHI M3.
    fn suspend_for_wowlan(&mut self) {
        self.core.hif.ce.stop_shadow_timers();
        self.dp.stop_shadow_timers();
        self.wowlan_mon_reap_active = self.mon_reap_at.take().is_some();
        self.wowlan_suspended = true;
    }

    /// Re-enable normal runtime servicing after MHI returns to M0/M2.  The
    /// hardware owns current ring pointers, so shadow timers restart only on
    /// a later TX; monitor reaping resumes with a fresh interval.
    fn resume_from_wowlan(&mut self) {
        self.wowlan_suspended = false;
        if self.wowlan_mon_reap_active {
            self.mon_reap_at = Some(self.now_ms() + ATH11K_MON_TIMER_INTERVAL);
            self.wowlan_mon_reap_active = false;
        }
    }

    /// What the transport reported, as Linux handles it at once: a reset
    /// request goes through `ath11k_core_reset`'s failure gate; then
    /// CRASH_FLUSH + RECOVERY and `ath11k_core_pre_reconfigure_recovery`
    /// (for SERVER_EXIT that is the QMI event work's; for a reset the
    /// reset work's first step). The recovery itself runs from the
    /// runtime loop ([`Shared::take_fw_notice`]). While one is pending,
    /// further notices are dropped.
    fn fw_notify(&mut self, n: FwNotice) {
        if self.fw_notice.is_some() {
            return;
        }
        if let FwNotice::Reset(_) = n {
            let fails = self.reset.fail_cont_count;
            let now = self.now_ms();
            if fails >= ATH11K_RESET_MAX_FAIL_COUNT_FINAL
                || (fails >= ATH11K_RESET_MAX_FAIL_COUNT_FIRST
                    && now < self.reset.reset_fail_timeout)
            {
                TransportError::new(step::RECOVERY_LIMIT, fails, ETIMEDOUT)
                    .report("ath11k reset (too many failed recoveries)");
                return;
            }
        }
        log(format_args!("firmware crashed: {:?}, recovering", n));
        self.fw_notice = Some(n);
        self.pre_reconfigure_recovery();
    }

    /// Linux `ath11k_core_pre_reconfigure_recovery` (+ setting
    /// `ATH11K_FLAG_CRASH_FLUSH`): `fw_crash_counter`++, queues stopped
    /// (TX fails with `-ESHUTDOWN`), every waiter released (the mac
    /// layer's event / peer / EAPOL waits end, WMI sends stop retrying),
    /// pending management frames freed
    /// (`ath11k_mac_tx_mgmt_pending_free`), the station data state dropped
    /// with the firmware's peer. Nothing is freed that the hardware may
    /// still use: rings and buffers wait for the restart.
    pub fn pre_reconfigure_recovery(&mut self) {
        self.crash_flush = true;
        self.core.hif.ce.crash_flush = true;
        self.dp.crash_flush = true;
        self.stats.fw_crash_counter += 1;
        // `ieee80211_stop_queues` / `ath11k_mac_drain_tx` apply to every
        // vif attached to this radio, not merely the first station vdev.
        for vdev in &mut self.vdevs {
            vdev.txq.stop(TxQueues::vif_queues(), txq::reason::DRIVER);
            let pending: Vec<u32> = vdev.ack_frames.ids().collect();
            for id in pending {
                vdev.ack_frames.remove(id);
                vdev.ack_status.push_back((id, TxStatus::DROPPED));
            }
        }
        self.mgmt = MgmtTx::default();
        for vdev in &mut self.vdevs {
            let own = vdev.link.own;
            vdev.link = LinkState {
                own,
                ..LinkState::default()
            };
            vdev.ap_configured = false;
            vdev.ap = None;
        }
        for events in &mut self.events {
            events.clear();
        }
        diag::note_wifi_crash();
    }

    /// Transmit an Ethernet frame on the active station or AP/GO vif. The
    /// station arm uses ToDS; the AP arm selects an associated receiver (or
    /// its GTK for a group receiver) and uses FromDS. Both reach
    /// `ath11k_dp_tx` with NATIVE_WIFI encapsulation. `csum_partial` is
    /// `skb->ip_summed == CHECKSUM_PARTIAL` (the seed is already in the
    /// frame, [`super::tx_offload::csum_partial_prepare`]).
    pub fn tx_eth(&mut self, eth: &[u8], csum_partial: bool) -> Result<u32, i32> {
        self.tx_eth_for(0, eth, csum_partial)
    }

    /// The vdev-qualified transmit half.  The shared TCL ring sees the
    /// selected `VifTx` in every descriptor, while header construction and
    /// controlled-port admission remain isolated to that vdev.
    pub fn tx_eth_for(&mut self, vdev_id: u32, eth: &[u8], csum_partial: bool) -> Result<u32, i32> {
        self.tx_eth_for_flags(vdev_id, eth, csum_partial, false)
    }

    /// As [`Self::tx_eth_for`], with the per-frame
    /// `IEEE80211_TX_INTFL_DONT_ENCRYPT` control-port flag. Ordinary stack
    /// TX always uses the public wrapper above and therefore cannot bypass
    /// installed data keys.
    fn tx_eth_for_flags(
        &mut self,
        vdev_id: u32,
        eth: &[u8],
        csum_partial: bool,
        no_encrypt: bool,
    ) -> Result<u32, i32> {
        if self.crash_flush {
            // ath11k_dp_tx: "if (unlikely(CRASH_FLUSH)) return -ESHUTDOWN".
            return Err(ESHUTDOWN);
        }
        let (vif, built) = {
            let Some(vdev) = self.vdev_mut(vdev_id) else {
                return Err(ENODEV);
            };
            if let Some(ap) = vdev.ap.as_mut() {
                if eth.len() < ETH_HLEN {
                    return Err(EIO);
                }
                let vif = vdev.link.vif.ok_or(ENOTCONN)?;
                if is_multicast(&eth[..6]) {
                    if ap.privacy && !ap.gtk_installed && !no_encrypt {
                        return Err(ENOTCONN);
                    }
                    let sta = ApTx {
                        own: ap.bssid,
                        wme: true,
                        authorized: true,
                        protected: ap.gtk_installed && !no_encrypt,
                    };
                    (vif, tx_hdr::build_ap_data(eth, &sta, &mut ap.group_seq)?)
                } else {
                    let Some(peer) = ap.peers.iter_mut().find(|peer| peer.addr == eth[..6]) else {
                        return Err(ENOENT);
                    };
                    let sta = ApTx {
                        own: ap.bssid,
                        wme: peer.wme,
                        authorized: peer.authorized,
                        protected: peer.ptk && !no_encrypt,
                    };
                    (vif, tx_hdr::build_ap_data(eth, &sta, &mut peer.seq)?)
                }
            } else {
                let (Some(vif), Some(bssid)) = (vdev.link.vif, vdev.link.bss) else {
                    // ieee80211_build_hdr: no chanctx / not associated.
                    return Err(ENOTCONN);
                };
                let sta = StaTx {
                    own: vdev.link.own,
                    bssid,
                    wme: vdev.link.wme,
                    four_addr: vdev.link.four_addr,
                    authorized: vdev.link.authorized,
                    protected: vdev.link.ptk && !no_encrypt,
                };
                (vif, tx_hdr::build_sta_data(eth, &sta, &mut vdev.link.seq)?)
            }
        };
        let meta = TxMeta {
            encap: TxEncap::NativeWifi,
            priority: built.tid as u32,
            queue: built.ac,
            // hw_ops->get_ring_selector (ath11k_hw_ipq8074_get_tcl_ring_selector:
            // smp_processor_id()); WCN6855 has one TCL data ring
            // (tcl2wbm_rbm_map_ipq5018), so `% num_tx_rings` picks ring 0.
            ring_selector: narf_lib::percpu::current_cpu() as u32,
            // NETIF_F_HW_CSUM (`tx_offload::OFFLOADS`).
            csum_partial,
            pdev_idx: 0,
            lmac_id: 0,
        };
        let now = self.now_ms();
        let hif = &mut self.core.hif;
        match self
            .dp
            .tx(&mut hif.ce.hal, &hif.io, &vif, &meta, &built.frame, now)
        {
            Ok(id) => {
                if eth.len() >= ETH_HLEN && u16::from_be_bytes([eth[12], eth[13]]) == ETH_P_PAE {
                    self.stats.tx_eapol += 1;
                } else {
                    self.stats.tx_data += 1;
                }
                Ok(id)
            }
            Err(e) => {
                self.stats.tx_failed += 1;
                Err(e.errno)
            }
        }
    }

    /// `ieee80211_nullfunc_get` → `ath11k_dp_tx` with
    /// `IEEE80211_TX_CTL_REQ_TX_STATUS`: a directed AP-liveness probe.
    /// The returned ACK id is completed by [`Self::tx_status_one`].
    pub fn tx_nullfunc_status(&mut self) -> Result<u32, i32> {
        self.tx_nullfunc_status_for(0)
    }

    pub fn tx_nullfunc_status_for(&mut self, vdev_id: u32) -> Result<u32, i32> {
        let (id, vif, built) = {
            let Some(vdev) = self.vdev_mut(vdev_id) else {
                return Err(ENODEV);
            };
            let id = vdev
                .ack_frames
                .alloc(None, txq::ACK_ID_START, txq::ACK_ID_END)
                .map_err(|_| ENOSPC)?;
            let (Some(vif), Some(bssid)) = (vdev.link.vif, vdev.link.bss) else {
                vdev.ack_frames.remove(id);
                return Err(ENOTCONN);
            };
            let sta = StaTx {
                own: vdev.link.own,
                bssid,
                wme: vdev.link.wme,
                four_addr: vdev.link.four_addr,
                authorized: vdev.link.authorized,
                protected: vdev.link.ptk,
            };
            (id, vif, tx_hdr::build_sta_nullfunc(&sta))
        };
        let meta = TxMeta {
            encap: TxEncap::NativeWifi,
            priority: built.tid as u32,
            queue: built.ac,
            ring_selector: narf_lib::percpu::current_cpu() as u32,
            csum_partial: false,
            pdev_idx: 0,
            lmac_id: 0,
        };
        let now = self.now_ms();
        let hif = &mut self.core.hif;
        match self
            .dp
            .tx(&mut hif.ce.hal, &hif.io, &vif, &meta, &built.frame, now)
        {
            Ok(desc_id) => {
                let msdu = super::hal::field_get(super::dp_ring::DP_TX_DESC_ID_MSDU_ID, desc_id);
                if let Some(slot) = self
                    .vdev_mut(vdev_id)
                    .and_then(|vdev| vdev.ack_frames.find_mut(id))
                {
                    *slot = Some(msdu);
                }
                self.stats.tx_nullfunc += 1;
                Ok(id)
            }
            Err(e) => {
                self.stats.tx_failed += 1;
                // This is an immediate submission failure, not a completed
                // requested frame. Do not leave a DROPPED status queued for
                // a caller that receives the error synchronously.
                if let Some(vdev) = self.vdev_mut(vdev_id) {
                    vdev.ack_frames.remove(id);
                }
                Err(e.errno)
            }
        }
    }

    /// One completion's status (`ath11k_dp_tx_htt_tx_complete_buf` /
    /// `ath11k_dp_tx_complete_msdu`, [`txq::tx_status`]) into mac80211's
    /// `__ieee80211_tx_status`: the station's ack statistics and, for a
    /// frame whose sender asked, `ieee80211_report_ack_skb`.
    fn tx_status_one(&mut self, c: &super::dp_ring::TxCompletion, now: u64) {
        let completed_peer = self.dp.peer_by_id(c.peer_id).copied();
        let vdev_id = completed_peer.map(|peer| peer.vdev_id as u32);
        let sta = completed_peer.is_some_and(|peer| {
            self.vdev(peer.vdev_id as u32)
                .is_some_and(|vdev| vdev.link.bss == Some(peer.addr))
        });
        let db2dbm = self
            .core
            .svc_map
            .test(super::wmi_ids::WMI_TLV_SERVICE_HW_DB2DBM_CONVERSION_SUPPORT);
        let has_vif = vdev_id
            .and_then(|vdev_id| self.vdev(vdev_id))
            .is_some_and(|vdev| vdev.link.vif.is_some());
        let st = txq::tx_status(c.acked, c.ack_rssi, db2dbm, has_vif, sta);
        if st.dropped {
            self.stats.tx_status_dropped += 1;
        } else if st.acked {
            self.stats.tx_status_acked += 1;
        } else {
            self.stats.tx_status_noack += 1;
        }
        // Firmware HTT completions do not contain a transmit count (zero
        // here); TQM completions report their total attempts. Match
        // ath11k_dp_tx_cache_peer_stats: attempts after the first are
        // retries, and completions without a valid station are not charged.
        if !st.dropped {
            self.stats.tx_retries += c.try_cnt.saturating_sub(1) as u32;
        }
        if let (Some(peer), Some(vdev)) = (completed_peer, vdev_id.and_then(|id| self.vdev_mut(id)))
        {
            if st.acked {
                vdev.link.last_ack_ms = Some(now);
                vdev.link.last_ack_signal = st.ack_signal;
            }
            if let Some(ap) = vdev
                .ap
                .as_mut()
                .filter(|ap| ap.vdev_id == peer.vdev_id as u32)
            {
                if let Some(ap_peer) = ap.peers.iter_mut().find(|known| known.addr == peer.addr) {
                    if !st.dropped {
                        ap_peer.tx_packets = ap_peer.tx_packets.saturating_add(1);
                        ap_peer.tx_retries = ap_peer
                            .tx_retries
                            .saturating_add(c.try_cnt.saturating_sub(1) as u32);
                        if !st.acked {
                            ap_peer.tx_failed = ap_peer.tx_failed.saturating_add(1);
                        }
                    }
                }
            }
        }
        // Linux's `ath11k_dp_tx_update_txcompl` consumes the first MSDU's
        // WBM rate record for each PPDU. HTT completions do not provide a
        // rate record, and an invalid peer must not overwrite the AP's last
        // known bitrate.
        if !st.dropped
            && c.flags & super::dp_ring::HAL_TX_STATUS_FLAGS_FIRST_MSDU != 0
            && c.rate_stats != 0
        {
            if let Some(vdev) = vdev_id.and_then(|id| self.vdev_mut(id)) {
                vdev.link.last_tx_rate = Some(c.rate_stats);
            }
        }
        for vdev in &mut self.vdevs {
            let ack_id = vdev
                .ack_frames
                .ids()
                .find(|&id| vdev.ack_frames.find(id) == Some(&Some(c.msdu_id)));
            if let Some(id) = ack_id {
                vdev.ack_frames.remove(id);
                vdev.ack_status.push_back((id, st));
                break;
            }
        }
    }

    /// `ieee80211_report_used_skb(.., dropped = true)` for a frame whose
    /// sender asked for the status and that never reached TCL.
    fn ack_dropped(&mut self, vdev_id: u32, ack_id: Option<u32>) {
        if let Some(id) = ack_id {
            if let Some(vdev) = self.vdev_mut(vdev_id) {
                if vdev.ack_frames.remove(id).is_some() {
                    vdev.ack_status.push_back((id, TxStatus::DROPPED));
                }
            }
        }
    }

    /// `ieee80211_subif_start_xmit` up to the TXQ: drop when neither an
    /// associated station nor a beaconing AP data state exists, otherwise
    /// queue by 802.1D/WMM AC. Destination selection and the final controlled
    /// port check happen in [`Self::tx_eth`] immediately before DP TX.
    pub fn tx_enqueue(&mut self, eth: Vec<u8>, csum_partial: bool) -> Result<(), i32> {
        self.tx_enqueue_for(0, eth, csum_partial)
    }

    pub fn tx_enqueue_for(
        &mut self,
        vdev_id: u32,
        eth: Vec<u8>,
        csum_partial: bool,
    ) -> Result<(), i32> {
        self.tx_enqueue_ack(vdev_id, eth, csum_partial, false, None)
    }

    fn tx_enqueue_ack(
        &mut self,
        vdev_id: u32,
        eth: Vec<u8>,
        csum_partial: bool,
        no_encrypt: bool,
        ack_id: Option<u32>,
    ) -> Result<(), i32> {
        let now = self.now_ms();
        let Some(vdev) = self.vdev_mut(vdev_id) else {
            return Err(ENODEV);
        };
        if vdev.link.vif.is_none() || (vdev.link.bss.is_none() && vdev.ap.is_none()) {
            self.stats.tx_failed += 1;
            self.ack_dropped(vdev_id, ack_id);
            return Err(ENOTCONN);
        }
        let wme = vdev.ap.is_some() || vdev.link.wme;
        let (tid, _) = tx_hdr::select_queue(&eth, wme);
        let dropped = vdev.txq.enqueue(
            tid,
            now,
            Queued {
                eth,
                csum_partial,
                no_encrypt,
                ack_id,
            },
        );
        self.stats.tx_queue_dropped += dropped.len() as u32;
        for d in dropped {
            self.ack_dropped(vdev_id, d.ack_id);
        }
        Ok(())
    }

    /// As [`Self::tx_enqueue`] with `IEEE80211_TX_CTL_REQ_TX_STATUS`
    /// (`ieee80211_store_ack_skb`): returns the ack id the status is
    /// reported under ([`Self::ack_status`]).
    pub fn tx_enqueue_status(&mut self, eth: Vec<u8>) -> Result<u32, i32> {
        self.tx_enqueue_status_for(0, eth)
    }

    pub fn tx_enqueue_status_for(&mut self, vdev_id: u32, eth: Vec<u8>) -> Result<u32, i32> {
        self.tx_enqueue_status_no_encrypt_for(vdev_id, eth, false)
    }

    /// As [`Self::tx_enqueue_status_for`], preserving the explicit
    /// `NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT` request until header build.
    pub fn tx_enqueue_status_no_encrypt_for(
        &mut self,
        vdev_id: u32,
        eth: Vec<u8>,
        no_encrypt: bool,
    ) -> Result<u32, i32> {
        let Some(vdev) = self.vdev_mut(vdev_id) else {
            return Err(ENODEV);
        };
        let id = vdev
            .ack_frames
            .alloc(None, txq::ACK_ID_START, txq::ACK_ID_END)
            .map_err(|_| ENOSPC)?;
        self.tx_enqueue_ack(vdev_id, eth, false, no_encrypt, Some(id))?;
        Ok(id)
    }

    /// `ieee80211_handle_wake_tx_queue`: hand every frame whose hardware
    /// queue is not stopped to `ath11k_mac_op_tx` → `ath11k_dp_tx`, VO
    /// first. Within an AC the active TID TXQs and their fq_codel flows are
    /// scheduled fairly. A frame the DP refuses (`-ENOSPC` with the TX IDR full,
    /// `-ENOMEM` with the TCL ring full) is freed, as
    /// `ath11k_mac_op_tx` does with `ieee80211_free_txskb`. Returns the
    /// frames the DP accepted.
    pub fn tx_push(&mut self) -> u32 {
        self.tx_push_for(0)
    }

    pub fn tx_push_for(&mut self, vdev_id: u32) -> u32 {
        let mut sent = 0;
        let now = self.now_ms();
        loop {
            let (f, dropped) = match self.vdev_mut(vdev_id) {
                Some(vdev) => {
                    let f = vdev.txq.dequeue(now).map(|(_, frame)| frame);
                    (f, vdev.txq.take_dropped())
                }
                None => (None, Vec::new()),
            };
            self.stats.tx_queue_dropped = self
                .stats
                .tx_queue_dropped
                .saturating_add(dropped.len() as u32);
            for dropped in dropped {
                self.ack_dropped(vdev_id, dropped.ack_id);
            }
            let Some(f) = f else { break };
            match self.tx_eth_for_flags(vdev_id, &f.eth, f.csum_partial, f.no_encrypt) {
                Ok(desc_id) => {
                    sent += 1;
                    if let Some(id) = f.ack_id {
                        let msdu =
                            super::hal::field_get(super::dp_ring::DP_TX_DESC_ID_MSDU_ID, desc_id);
                        if let Some(slot) = self
                            .vdev_mut(vdev_id)
                            .and_then(|vdev| vdev.ack_frames.find_mut(id))
                        {
                            *slot = Some(msdu);
                        }
                    }
                }
                Err(_) => self.ack_dropped(vdev_id, f.ack_id),
            }
        }
        sent
    }

    /// `ieee80211_stop_queues_by_reason(hw, queues, reason, false)`.
    pub fn stop_queues(&mut self, queues: u32, reason: u32) {
        self.stop_queues_for(0, queues, reason);
    }

    pub fn stop_queues_for(&mut self, vdev_id: u32, queues: u32, reason: u32) {
        if let Some(vdev) = self.vdev_mut(vdev_id) {
            vdev.txq.stop(queues, reason);
        }
    }

    /// `ieee80211_wake_queues_by_reason`: clear the reason and drain what
    /// the queues now allow (`_ieee80211_wake_txqs`, AC order).
    pub fn wake_queues(&mut self, queues: u32, reason: u32) -> u32 {
        self.wake_queues_for(0, queues, reason)
    }

    pub fn wake_queues_for(&mut self, vdev_id: u32, queues: u32, reason: u32) -> u32 {
        if let Some(vdev) = self.vdev_mut(vdev_id) {
            vdev.txq.wake(queues, reason);
        }
        self.tx_push_for(vdev_id)
    }

    /// `ieee80211_purge_sta_txqs` (each purged frame freed:
    /// `ieee80211_free_txskb`).
    pub fn purge_txqs(&mut self) -> u32 {
        self.purge_txqs_for(0)
    }

    pub fn purge_txqs_for(&mut self, vdev_id: u32) -> u32 {
        let mut n = 0;
        while let Some(f) = self.vdev_mut(vdev_id).and_then(|vdev| vdev.txq.take_any()) {
            self.ack_dropped(vdev_id, f.ack_id);
            n += 1;
        }
        self.stats.tx_queue_dropped += n;
        n
    }

    /// `ath11k_mac_mgmt_tx` + the first half of `ath11k_mac_mgmt_tx_wmi`:
    /// a TX buffer id and DMA copy of `frame`, and the
    /// `WMI_MGMT_TX_SEND_CMDID` to send. The frame first gets the
    /// sequence number mac80211's TX path gives it
    /// ([`tx_hdr::tx_h_sequence`]: the vif counter non-QoS data uses).
    pub fn mgmt_tx_prepare(
        &mut self,
        vdev_id: u32,
        frame: &[u8],
        chanfreq: Option<u32>,
    ) -> Result<(u32, WmiCmd), i32> {
        if self.mgmt.pending >= ATH11K_TX_MGMT_NUM_PENDING_MAX {
            // "mgmt tx queue is full"
            return Err(ENOSPC);
        }
        let mut frame = frame.to_vec();
        let Some(vdev) = self.vdev_mut(vdev_id) else {
            return Err(ENODEV);
        };
        tx_hdr::tx_h_sequence(&mut frame, &mut vdev.link.seq);
        let frame = &frame[..];
        let mut mem = DmaMem::alloc(frame.len().max(4), 4).map_err(|_| EIO)?;
        mem.write_bytes(0, frame);
        let paddr = mem.paddr();
        let id = self
            .mgmt
            .bufs
            .alloc(
                MgmtTxBuf { _mem: mem, vdev_id },
                0,
                ATH11K_TX_MGMT_NUM_PENDING_MAX,
            )
            .map_err(|_| ENOSPC)?;
        // `ath11k_wmi_mgmt_send`: channel frequency is set only for a
        // management frame issued during ROC. `tx_params_valid` controls
        // the unrelated CFR-capture TLV, so it remains false here.
        Ok((
            id,
            wmi::mgmt_send_cmd(vdev_id, id, frame, paddr, chanfreq.unwrap_or(0), false),
        ))
    }

    /// Free outstanding management buffers belonging to one vdev during
    /// `remove_interface`.  Management completions identify only a shared
    /// descriptor id, so resetting the whole IDR here would incorrectly
    /// cancel sibling AP/STA vdevs.
    pub fn drop_vdev_mgmt(&mut self, vdev_id: u32) {
        let ids: Vec<u32> = self
            .mgmt
            .bufs
            .ids()
            .filter(|id| {
                self.mgmt
                    .bufs
                    .find(*id)
                    .is_some_and(|buffer| buffer.vdev_id == vdev_id)
            })
            .collect();
        for id in ids {
            if self.mgmt.bufs.remove(id).is_some() {
                self.mgmt.pending = self.mgmt.pending.saturating_sub(1);
            }
        }
    }

    fn queue_event(&mut self, vdev_id: u32, frame: Vec<u8>) {
        let Some(queue) = self.events.get_mut(vdev_id as usize) else {
            return;
        };
        const MAX_PENDING_WMI_EVENTS: usize = 128;
        if queue.len() == MAX_PENDING_WMI_EVENTS {
            queue.pop_front();
        }
        queue.push_back(frame);
    }

    fn broadcast_event(&mut self, frame: Vec<u8>) {
        for vdev_id in 0..self.events.len() as u32 {
            self.queue_event(vdev_id, frame.clone());
        }
    }

    /// Drain the firmware event FIFO once and route every vdev-addressed
    /// event before any individual [`Port`] waiter consumes it.  WMI
    /// management RX has only a pdev identity in this firmware ABI, exactly
    /// as Linux passes it once into mac80211's shared hardware instance, so
    /// it is broadcast to the active vdev MAC instances; their normal
    /// address/BSS filters select the relevant frame.
    fn route_wmi_events(&mut self) {
        while let Some(event) = self.core.take_event() {
            let frame = event.frame;
            let target = match wmi::decode_event(&frame) {
                Ok(wmi::WmiEvent::VdevStartResp(event)) => Some(event.vdev_id),
                Ok(wmi::WmiEvent::VdevStopped(vdev_id)) => Some(vdev_id),
                Ok(wmi::WmiEvent::VdevDeleteResp(vdev_id)) => Some(vdev_id),
                Ok(wmi::WmiEvent::PeerDeleteResp(event)) => Some(event.vdev_id),
                Ok(wmi::WmiEvent::PeerAssocConf(event)) => Some(event.vdev_id),
                Ok(wmi::WmiEvent::InstallKeyCompl(event)) => Some(event.vdev_id),
                Ok(wmi::WmiEvent::GtkOffloadStatus(event)) => Some(event.vdev_id),
                Ok(wmi::WmiEvent::WowWakeup(event)) => Some(event.vdev_id),
                Ok(wmi::WmiEvent::Scan(event)) => Some(event.vdev_id),
                Ok(wmi::WmiEvent::Roam(event)) => Some(event.vdev_id),
                Ok(wmi::WmiEvent::MgmtTxCompl(event)) => self
                    .mgmt
                    .bufs
                    .find(event.desc_id)
                    .map(|buffer| buffer.vdev_id),
                Ok(wmi::WmiEvent::PeerStaKickout(addr)) => self
                    .dp
                    .peers
                    .iter()
                    .find(|peer| peer.addr == addr)
                    .map(|peer| peer.vdev_id as u32),
                // Pdev-wide notifications (including the untagged MGMT_RX,
                // DFS radar and regulatory events) are shared by every
                // active vdev on this radio.
                _ => None,
            };
            if let Some(vdev_id) = target {
                self.queue_event(vdev_id, frame);
            } else {
                self.broadcast_event(frame);
            }
        }
    }

    fn take_vdev_event(&mut self, vdev_id: u32) -> Option<Vec<u8>> {
        self.route_wmi_events();
        self.events.get_mut(vdev_id as usize)?.pop_front()
    }
}

/// [`DeviceCaps`] from the core's bring-up events.
pub fn device_caps<H: Hif, Q: QmiFw>(
    core: &Ath11kCore<H, Q>,
) -> Result<DeviceCaps, TransportError> {
    let mut missing = 0;
    if core.svc_ext.is_none() {
        missing |= 1;
    }
    if core.ready.is_none() {
        missing |= 2;
    }
    if missing != 0 {
        return Err(TransportError::new(step::MAC_CAPS, missing, ENODEV));
    }
    let sr = ServiceReady {
        caps: Some(core.target_caps),
        fw_build_vers: core.fw_build_vers,
        svc_map: core.svc_map,
        bitmap_seen: true,
    };
    DeviceCaps::from_events(
        &sr,
        core.svc_ext.as_ref().unwrap(),
        core.ready.as_ref().unwrap(),
        &core.svc_map,
    )
    .ok_or(TransportError::new(step::MAC_CAPS, 4, ENODEV))
}

/// [`Shared::lock`]'s guard: the runtime, present (a recovery that owns it
/// makes `lock` wait instead).
#[allow(missing_debug_implementations)]
pub struct RtGuard<'a, Io: RtIo, Irq: DpIrq, Q: RtQmi>(MutexGuard<'a, Option<Rt<Io, Irq, Q>>>);

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> core::ops::Deref for RtGuard<'_, Io, Irq, Q> {
    type Target = Rt<Io, Irq, Q>;
    fn deref(&self) -> &Rt<Io, Irq, Q> {
        match self.0.as_ref() {
            Some(rt) => rt,
            // RtGuard is only built over a present runtime and the slot
            // only changes through the mutex it holds.
            None => unreachable!("RtGuard over an empty runtime slot"),
        }
    }
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> core::ops::DerefMut for RtGuard<'_, Io, Irq, Q> {
    fn deref_mut(&mut self) -> &mut Rt<Io, Irq, Q> {
        match self.0.as_mut() {
            Some(rt) => rt,
            None => unreachable!("RtGuard over an empty runtime slot"),
        }
    }
}

/// A recovered device: what `ath11k_mac_register` / `ieee80211_restart_hw`
/// rebuild the mac layer from.
#[allow(missing_debug_implementations)]
pub struct Recovered {
    pub caps: DeviceCaps,
    pub reg_info: Option<alloc::boxed::Box<wmi::RegInfo>>,
}

/// One pdev-wide DFS non-occupancy period.  Linux carries this through the
/// shared wiphy; NARF MAC instances have per-vdev wiphy snapshots, so the
/// physical-radio owner retains the authoritative restriction here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RadioDfsNop {
    def: ChanDef,
    deadline: u64,
}

/// An acquired hardware scan-engine claim. Synchronous nl80211 scan futures
/// can be cancelled at any await point, so drop queues ordered WMI
/// cancellation on the vdev worker rather than releasing a still-live
/// firmware scan to a sibling.
#[allow(missing_debug_implementations)]
pub struct ScanLease<Io: RtIo, Irq: DpIrq, Q: RtQmi> {
    shared: Arc<Shared<Io, Irq, Q>>,
    vdev_id: u32,
    active: bool,
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> ScanLease<Io, Irq, Q> {
    /// Claim the physical scan engine for `vdev_id`, returning `None` when a
    /// sibling vdev owns an in-flight scan or remain-on-channel request.
    pub fn acquire(shared: Arc<Shared<Io, Irq, Q>>, vdev_id: u32) -> Option<Self> {
        shared.claim_scan(vdev_id).then_some(ScanLease {
            shared,
            vdev_id,
            active: true,
        })
    }

    /// Complete a scan request that returned normally. This is the only
    /// immediate-release path: dropped futures must let the runtime abort
    /// firmware's still-live scan before another vdev may acquire it.
    pub fn complete(&mut self) {
        if self.active {
            self.shared.release_scan(self.vdev_id);
            self.active = false;
        }
    }
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Drop for ScanLease<Io, Irq, Q> {
    fn drop(&mut self) {
        if self.active {
            self.shared.request_scan_cancel(self.vdev_id);
        }
    }
}

/// The runtime as tasks share it.
#[allow(missing_debug_implementations)]
pub struct Shared<Io: RtIo, Irq: DpIrq, Q: RtQmi> {
    /// `None` while a recovery owns the runtime ([`Self::recover_device`]).
    pub rt: Mutex<Option<Rt<Io, Irq, Q>>>,
    /// The interrupt source, outside the lock (waits never hold it).
    pub irq: Irq,
    pub clock: fn() -> u64,
    /// `get_random_bytes`.
    pub rng: fn(&mut [u8]),
    /// WMI endpoint `max_msg_len`.
    pub max_msg_len: u32,
    /// `WMI_SEND_TIMEOUT_HZ`.
    pub wmi_send_ms: u64,
    pub slice_ms: u32,
    /// One stable `struct wiphy` identity for all this radio's vdevs.
    pub radio_id: u64,
    /// Firmware vdev slots currently owned by NARF netdevs.  Slot zero is
    /// reserved for the initial `wlan%d`; NARF currently admits three.
    vdev_slots: AtomicU32,
    /// The `NL80211_IFTYPE_*` role assigned to each reserved vdev slot.
    /// This is kept beside the allocator rather than on each netdev so a
    /// concurrent `NEW_INTERFACE` or down-only `SET_INTERFACE` cannot
    /// advertise a combination cfg80211 would have rejected.  Zero is an
    /// unassigned slot (including the small create-before-register window).
    vdev_iftypes: IrqSafeSpinLock<[u32; WCN6855_MAX_VDEVS]>,
    /// Netdev identity assigned to each vdev. MBSSID's TX_IFINDEX has to
    /// resolve to another AP vdev of this *same* radio; keeping this beside
    /// the physical allocator makes that check independent of the global
    /// interface registry and resilient to a simultaneous delete.
    vdev_bindings: IrqSafeSpinLock<[VdevBinding; WCN6855_MAX_VDEVS]>,
    /// Primary operating frequency of each live station or beaconing AP/GO
    /// vdev. `0` means that the slot has no channel context. This serializes
    /// channel-context reservations so sibling netdevs cannot overcommit
    /// WCN6855's dual-channel profile.
    operating_channels: IrqSafeSpinLock<[u32; WCN6855_MAX_VDEVS]>,
    /// The transmitter's generated regular/EMA template set, indexed by its
    /// vdev. A non-transmitting AP consumes this before its first VDEV_UP;
    /// it is deliberately not sent again after that vdev is up because that
    /// target sequence is known to crash firmware.
    mbssid_beacons: IrqSafeSpinLock<[Option<MbssidBeaconSet>; WCN6855_MAX_VDEVS]>,
    /// For a non-transmitting AP vdev, the selected transmitting vdev. This
    /// makes DEL_INTERFACE of a transmitting virtual interface tear down its
    /// dependent profiles as cfg80211 requires.
    mbssid_transmitters: IrqSafeSpinLock<[Option<u32>; WCN6855_MAX_VDEVS]>,
    /// Last accepted WCN6855 BIOS SAR table. SAR is pdev-wide rather than
    /// vdev-wide, so the physical runtime owns the authoritative desired
    /// state and the first MAC opener replays it after a firmware reset.
    bios_sar_table: IrqSafeSpinLock<Option<[u8; wmi::BIOS_SAR_TABLE_LEN]>>,
    /// Latest pdev BSS-channel counter snapshot per frequency. Linux's
    /// `get_survey` has a synchronous completion wait; NARF queues that WMI
    /// request onto the radio worker and returns this safe cached snapshot.
    bss_surveys: IrqSafeSpinLock<Vec<BssSurvey>>,
    /// Coalesced `GET_SURVEY` refresh demand from synchronous netlink dumps.
    bss_survey_requested: AtomicBool,
    /// Desired pdev chain masks selected through `NL80211_CMD_SET_WIPHY`.
    /// They outlive WMI restart so every freshly-created MAC derives the
    /// same HT/VHT/HE NSS policy before it adds a vdev.
    antenna_config: IrqSafeSpinLock<Option<((u32, u32), u32)>>,
    /// Monotonic desired-state generation. Each MAC tracks this to rebuild
    /// its host capability maps; the first live pdev worker programs WMI.
    /// Generation already claimed for pdev WMI programming. Keeping this
    /// radio-wide avoids sending the identical physical mask once per vdev.
    antenna_programmed_generation: AtomicU32,
    /// `WIPHY_RTS_THRESHOLD` retained across vdev churn and recovery.
    rts_config: IrqSafeSpinLock<(u32, u32)>,
    /// Generation for each MAC to apply `WMI_VDEV_PARAM_RTS_THRESHOLD` to
    /// its live vdev exactly once.
    /// Number of open MAC vdevs sharing the physical pdev start sequence.
    /// `ath11k_mac_op_start` programs pdev-wide state once, whereas every
    /// open netdev separately creates a WMI vdev.
    radio_mac_users: AtomicU32,
    /// A physical WCN6855 has one firmware hardware-scan engine.  Zero
    /// means free; otherwise the stored value is `vdev_id + 1` so scan and
    /// remain-on-channel cannot be started concurrently by sibling netdevs.
    scan_owner: AtomicU32,
    /// Scan futures cancelled by their caller. The runtime worker consumes a
    /// bit, sends the matching WMI scan-stop, and only then releases the
    /// physical engine.
    scan_cancel: AtomicU32,
    /// DFS non-occupancy periods on the one physical WCN6855 pdev.  This is
    /// deliberately independent of each [`Mac`](super::mac::Mac)'s wiphy
    /// snapshot, which is replaced during recovery and virtual-vdev churn.
    dfs_nops: IrqSafeSpinLock<Vec<RadioDfsNop>>,
    /// The most recent RDDM-backed device coredump.  Like Linux
    /// `devcoredump`, this moves the crash payload out of the transport
    /// before reset and retains it independently of the restarted radio.
    firmware_crash_dump: IrqSafeSpinLock<Option<FirmwareCrashDump>>,
    ops: IrqSafeSpinLock<VecDeque<SyncOp>>,
    /// A recovery failed: the device is gone until the next probe.
    dead: AtomicBool,
    /// What a failed recovery left (the firmware was given its memory and
    /// rings; never freed).
    parked: IrqSafeSpinLock<Vec<alloc::boxed::Box<dyn core::any::Any + Send>>>,
}

#[derive(Clone, Copy, Default)]
struct VdevBinding {
    name: Option<&'static str>,
    mac: [u8; 6],
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Shared<Io, Irq, Q> {
    pub fn new(rt: Rt<Io, Irq, Q>, rng: fn(&mut [u8])) -> Arc<Self> {
        let irq = rt.core.hif.irq.clone();
        let clock = rt.core.hif.clock;
        let max_msg_len = rt.core.wmi_ep.map_or(0, |e| e.max_msg_len);
        let wmi_send_ms = rt.core.cfg.wmi_send_ms;
        Arc::new(Shared {
            rt: Mutex::new(Some(rt)),
            irq,
            clock,
            rng,
            max_msg_len,
            wmi_send_ms,
            slice_ms: SERVICE_SLICE_MS,
            radio_id: NEXT_RADIO_ID.fetch_add(1, Ordering::Relaxed),
            vdev_slots: AtomicU32::new(1),
            // The physical/root netdev begins as a station.  It may change
            // role only while down through `assign_vdev_iftype` below.
            vdev_iftypes: IrqSafeSpinLock::new(core::array::from_fn(
                |i| if i == 0 { 2 } else { 0 },
            )),
            vdev_bindings: IrqSafeSpinLock::new([VdevBinding::default(); WCN6855_MAX_VDEVS]),
            operating_channels: IrqSafeSpinLock::new([0; WCN6855_MAX_VDEVS]),
            mbssid_beacons: IrqSafeSpinLock::new(core::array::from_fn(|_| None)),
            mbssid_transmitters: IrqSafeSpinLock::new([None; WCN6855_MAX_VDEVS]),
            bios_sar_table: IrqSafeSpinLock::new(None),
            bss_surveys: IrqSafeSpinLock::new(Vec::new()),
            bss_survey_requested: AtomicBool::new(false),
            antenna_config: IrqSafeSpinLock::new(None),
            antenna_programmed_generation: AtomicU32::new(0),
            rts_config: IrqSafeSpinLock::new((RTS_THRESHOLD_OFF, 0)),
            radio_mac_users: AtomicU32::new(0),
            scan_owner: AtomicU32::new(0),
            scan_cancel: AtomicU32::new(0),
            dfs_nops: IrqSafeSpinLock::new(Vec::new()),
            firmware_crash_dump: IrqSafeSpinLock::new(None),
            ops: IrqSafeSpinLock::new(VecDeque::new()),
            dead: AtomicBool::new(false),
            parked: IrqSafeSpinLock::new(Vec::new()),
        })
    }

    /// A recovery failed; nothing will bring the device back.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// Reserve one free WCN6855 WMI vdev id for a newly-created netdev.
    /// The compare-exchange makes concurrent NEW_INTERFACE requests choose
    /// different slots without taking the async runtime mutex.
    pub fn reserve_vdev(&self) -> Option<u32> {
        let allowed = (1u32 << WCN6855_MAX_VDEVS) - 1;
        let mut current = self.vdev_slots.load(Ordering::Acquire);
        loop {
            let free = (!current) & allowed;
            if free == 0 {
                return None;
            }
            let vdev_id = free.trailing_zeros();
            let next = current | (1 << vdev_id);
            match self.vdev_slots.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(vdev_id),
                Err(observed) => current = observed,
            }
        }
    }

    /// Assign a role to a reserved slot if it still fits the WCN6855
    /// interface combination published through nl80211.  The role groups
    /// mirror WCN6855's `ath11k_mac_setup_iface_combinations`: at most two
    /// stations (the target advertises dual-station support), four
    /// AP/client/GO vdevs collectively, and one P2P-device vdev.
    ///
    /// A vdev is assigned before registration and changed only while down,
    /// so this lock is never held across WMI work or an await.
    pub fn assign_vdev_iftype(&self, vdev_id: u32, iftype: u32) -> bool {
        if (vdev_id as usize) >= WCN6855_MAX_VDEVS || !matches!(iftype, 2 | 3 | 8 | 9 | 10) {
            return false;
        }
        let mut roles = self.vdev_iftypes.lock();
        let old = roles[vdev_id as usize];
        roles[vdev_id as usize] = iftype;
        let mut station = 0usize;
        let mut ap_client_go = 0usize;
        let mut p2p_device = 0usize;
        for role in roles.iter().copied() {
            match role {
                2 => station += 1,
                3 | 8 | 9 => ap_client_go += 1,
                10 => p2p_device += 1,
                0 => {}
                _ => unreachable!("role was validated before publication"),
            }
        }
        if station <= 2 && ap_client_go <= WCN6855_MAX_VDEVS && p2p_device <= 1 {
            true
        } else {
            roles[vdev_id as usize] = old;
            false
        }
    }

    /// Release an unconfigured or fully removed virtual vdev.  The initial
    /// netdev owns vdev zero for the physical radio lifetime.
    pub fn release_vdev(&self, vdev_id: u32) {
        if vdev_id != 0 && (vdev_id as usize) < WCN6855_MAX_VDEVS {
            self.vdev_iftypes.lock()[vdev_id as usize] = 0;
            self.vdev_bindings.lock()[vdev_id as usize] = VdevBinding::default();
            self.mbssid_beacons.lock()[vdev_id as usize] = None;
            let mut transmitters = self.mbssid_transmitters.lock();
            transmitters[vdev_id as usize] = None;
            for transmitter in transmitters.iter_mut() {
                if *transmitter == Some(vdev_id) {
                    *transmitter = None;
                }
            }
            self.clear_operating_channel(vdev_id);
            self.vdev_slots.fetch_and(!(1 << vdev_id), Ordering::AcqRel);
        }
    }

    /// Publish the netdev identity immediately after construction. The slot
    /// has already been reserved, so this never races a new allocation.
    pub fn bind_vdev(&self, vdev_id: u32, name: &'static str, mac: [u8; 6]) {
        if (vdev_id as usize) < WCN6855_MAX_VDEVS {
            self.vdev_bindings.lock()[vdev_id as usize] = VdevBinding {
                name: Some(name),
                mac,
            };
        }
    }

    /// Resolve a TX_IFINDEX's netdev name to this radio's firmware vdev and
    /// BSSID. A name belonging to a different wiphy cannot be found here.
    pub fn vdev_for_name(&self, name: &str) -> Option<(u32, [u8; 6])> {
        self.vdev_bindings
            .lock()
            .iter()
            .enumerate()
            .find_map(|(vdev_id, binding)| {
                (binding.name == Some(name)).then_some((vdev_id as u32, binding.mac))
            })
    }

    /// Store the transmitting AP's generated template set after its first
    /// successful start or beacon update.
    pub fn set_mbssid_beacons(&self, vdev_id: u32, beacons: Option<MbssidBeaconSet>) {
        if (vdev_id as usize) < WCN6855_MAX_VDEVS {
            self.mbssid_beacons.lock()[vdev_id as usize] = beacons;
        }
    }

    /// Snapshot a transmitter's templates without holding a spin lock over
    /// any WMI wait in the non-transmitting vdev's start path.
    pub fn mbssid_beacons(&self, vdev_id: u32) -> Option<MbssidBeaconSet> {
        self.mbssid_beacons
            .lock()
            .get(vdev_id as usize)
            .cloned()
            .flatten()
    }

    /// Record or clear a non-transmitting vdev's selected transmitter. This
    /// is publication-only state; template lifetime remains tracked by
    /// [`Self::mbssid_beacons`].
    pub fn set_mbssid_transmitter(&self, vdev_id: u32, transmitter: Option<u32>) {
        if (vdev_id as usize) < WCN6855_MAX_VDEVS
            && transmitter.is_none_or(|tx| (tx as usize) < WCN6855_MAX_VDEVS)
        {
            self.mbssid_transmitters.lock()[vdev_id as usize] = transmitter;
        }
    }

    /// Names of virtual profiles that cfg80211 must remove with the named
    /// transmitting interface. The binding snapshot avoids holding either
    /// spin lock while a caller unregisters interfaces or queues WMI work.
    pub fn mbssid_dependents(&self, transmitter: u32) -> Vec<&'static str> {
        let transmitters = *self.mbssid_transmitters.lock();
        let bindings = *self.vdev_bindings.lock();
        transmitters
            .iter()
            .enumerate()
            .filter_map(|(vdev_id, selected)| {
                (*selected == Some(transmitter))
                    .then(|| bindings[vdev_id].name)
                    .flatten()
            })
            .collect()
    }

    /// Reserve `frequency_mhz` as one vdev's operating channel and return
    /// the frequency it replaces. The caller restores that value if its WMI
    /// transaction fails. Equal frequencies share a context; a third
    /// distinct context is refused before firmware sees the request.
    ///
    /// Pending association and CSA requests count as their requested
    /// context. This conservatively closes a sibling-vdev race; failure
    /// paths restore the old context, and stop/recovery clear it.
    pub fn reserve_operating_channel(&self, vdev_id: u32, frequency_mhz: u32) -> Option<u32> {
        if (vdev_id as usize) >= WCN6855_MAX_VDEVS || frequency_mhz == 0 {
            return None;
        }
        let mut channels = self.operating_channels.lock();
        let old = channels[vdev_id as usize];
        channels[vdev_id as usize] = frequency_mhz;
        let mut distinct = [0u32; WCN6855_MAX_VDEVS];
        let mut count = 0usize;
        for frequency in channels.iter().copied().filter(|frequency| *frequency != 0) {
            if !distinct[..count].contains(&frequency) {
                distinct[count] = frequency;
                count += 1;
            }
        }
        if count <= 2 {
            Some(old)
        } else {
            channels[vdev_id as usize] = old;
            None
        }
    }

    /// Undo a failed operating-channel transition. The calling netdev's MAC
    /// mutex serializes transitions from that vdev.
    pub fn restore_operating_channel(&self, vdev_id: u32, frequency_mhz: u32) {
        if (vdev_id as usize) < WCN6855_MAX_VDEVS {
            self.operating_channels.lock()[vdev_id as usize] = frequency_mhz;
        }
    }

    /// Forget a vdev's channel context once its station link or AP carrier
    /// is gone. This is deliberately idempotent for disconnect/recovery.
    pub fn clear_operating_channel(&self, vdev_id: u32) {
        self.restore_operating_channel(vdev_id, 0);
    }

    /// Request one coalesced active-channel survey refresh. This is called
    /// from the synchronous generic-netlink dump path; the next vdev worker
    /// owns the WMI send and event dispatch.
    pub fn request_bss_survey(&self) {
        self.bss_survey_requested.store(true, Ordering::Release);
    }

    /// Claim a pending survey request for one runtime worker.
    pub fn take_bss_survey_request(&self) -> bool {
        self.bss_survey_requested.swap(false, Ordering::AcqRel)
    }

    /// Replace this frequency's cached pdev counters after WMI validation.
    pub fn update_bss_survey(&self, survey: BssSurvey) {
        let mut surveys = self.bss_surveys.lock();
        if let Some(existing) = surveys
            .iter_mut()
            .find(|existing| existing.frequency_mhz == survey.frequency_mhz)
        {
            *existing = survey;
        } else {
            surveys.push(survey);
        }
    }

    /// Snapshot cached counters for a synchronous `GET_SURVEY` dump.
    pub fn bss_surveys(&self) -> Vec<BssSurvey> {
        self.bss_surveys.lock().clone()
    }

    /// Store a physical chain-mask policy. The generation makes every live
    /// MAC rebuild its host-side rates/capabilities before its next use.
    pub fn set_antenna_masks(&self, tx: u32, rx: u32) {
        let mut config = self.antenna_config.lock();
        let generation = config
            .as_ref()
            .map(|(_, generation)| generation.wrapping_add(1))
            .unwrap_or(1);
        *config = Some(((tx, rx), generation));
    }

    /// Snapshot the selected masks together with their generation.
    pub fn antenna_config(&self) -> Option<((u32, u32), u32)> {
        *self.antenna_config.lock()
    }

    /// Claim the one pdev WMI update for a desired mask generation. Only a
    /// MAC that is already part of a live started radio may claim it; a
    /// closed-radio policy is sent by its eventual `start_inner` instead.
    pub fn claim_antenna_programming(&self, generation: u32) -> bool {
        let mut seen = self.antenna_programmed_generation.load(Ordering::Acquire);
        loop {
            if seen == generation {
                return false;
            }
            match self.antenna_programmed_generation.compare_exchange_weak(
                seen,
                generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => seen = observed,
            }
        }
    }

    /// Store the all-vdev RTS policy and publish a generation for each live
    /// MAC worker to apply to its own WMI vdev.
    pub fn set_rts_threshold(&self, threshold: u32) {
        let mut config = self.rts_config.lock();
        config.0 = threshold;
        config.1 = config.1.wrapping_add(1);
    }

    /// Snapshot the retained RTS threshold and its update generation.
    pub fn rts_config(&self) -> (u32, u32) {
        *self.rts_config.lock()
    }

    /// All active physical channel contexts, used to mark survey records as
    /// `SURVEY_INFO_IN_USE`. Equal contexts naturally collapse at encoding.
    pub fn operating_channels(&self) -> [u32; WCN6855_MAX_VDEVS] {
        *self.operating_channels.lock()
    }

    /// Store the complete desired pdev SAR table after nl80211 validated a
    /// replacement request. The caller applies the same bytes to firmware on
    /// its ordered vdev worker; this copy is intentionally retained across a
    /// reset because firmware loses all pdev policy state there.
    pub fn set_bios_sar_table(&self, table: [u8; wmi::BIOS_SAR_TABLE_LEN]) {
        *self.bios_sar_table.lock() = Some(table);
    }

    /// Snapshot the pdev-wide SAR policy for initial start / recovery replay.
    pub fn bios_sar_table(&self) -> Option<[u8; wmi::BIOS_SAR_TABLE_LEN]> {
        *self.bios_sar_table.lock()
    }

    /// Clear a slot's old event and DP-local state before a newly allocated
    /// virtual netdev may bind it. `reserve_vdev` has already made this slot
    /// exclusive; a busy/recovering runtime asks NEW_INTERFACE to retry
    /// rather than letting an old VDEV_DELETE or scan event reach its new
    /// owner.
    pub fn prepare_vdev_slot(&self, vdev_id: u32) -> bool {
        let Some(mut g) = self.try_lock() else {
            return false;
        };
        let own = g.core.mac_addr.unwrap_or_default();
        {
            let Some(slot) = g.vdev_mut(vdev_id) else {
                return false;
            };
            *slot = VdevRuntime {
                link: LinkState {
                    own,
                    ..LinkState::default()
                },
                ..VdevRuntime::default()
            };
        }
        if let Some(events) = g.events.get_mut(vdev_id as usize) {
            events.clear();
        }
        true
    }

    /// Claim the pdev-wide MAC start sequence. `true` means the caller is
    /// the first open vif and must send `ath11k_mac_op_start`'s WMI setup.
    pub fn acquire_radio_mac(&self) -> bool {
        self.radio_mac_users.fetch_add(1, Ordering::AcqRel) == 0
    }

    /// Drop one open vif. `true` means the caller was last and must perform
    /// the pdev-wide `ath11k_mac_op_stop` cleanup.
    pub fn release_radio_mac(&self) -> bool {
        self.radio_mac_users.fetch_sub(1, Ordering::AcqRel) == 1
    }

    /// Claim the pdev-wide hardware scan engine for one vdev.  Firmware uses
    /// a fixed scan id on WCN6855, so accepting overlapping scan or ROC
    /// commands would make event completion ownership ambiguous.
    pub fn claim_scan(&self, vdev_id: u32) -> bool {
        self.scan_owner
            .compare_exchange(
                0,
                vdev_id.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Release a scan claim after terminal scan/ROC completion.  A stale
    /// release from another vdev is deliberately ignored.
    pub fn release_scan(&self, vdev_id: u32) {
        let owner = vdev_id.saturating_add(1);
        let _ = self
            .scan_owner
            .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Whether this vdev owns the radio scan engine.
    pub fn owns_scan(&self, vdev_id: u32) -> bool {
        self.scan_owner.load(Ordering::Acquire) == vdev_id.saturating_add(1)
    }

    /// Request ordered cancellation for a dropped normal-scan future. The
    /// physical ownership deliberately remains live until the vdev worker
    /// stops firmware's fixed-id scan.
    pub fn request_scan_cancel(&self, vdev_id: u32) {
        if (vdev_id as usize) < WCN6855_MAX_VDEVS {
            self.scan_cancel.fetch_or(1 << vdev_id, Ordering::Release);
        }
    }

    /// Take one vdev's queued cancellation request.
    pub fn take_scan_cancel(&self, vdev_id: u32) -> bool {
        if (vdev_id as usize) >= WCN6855_MAX_VDEVS {
            return false;
        }
        let bit = 1 << vdev_id;
        self.scan_cancel.fetch_and(!bit, Ordering::AcqRel) & bit != 0
    }

    /// `cfg80211` wiphy-wide DFS NOP check.  Expiry is evaluated at use time
    /// so removal of the vdev that observed radar cannot leave a stale radio
    /// restriction, nor can it make another vdev legal before 30 minutes.
    pub fn dfs_nop_active(&self, def: &ChanDef) -> bool {
        let now = self.now_ms();
        let mut nops = self.dfs_nops.lock();
        nops.retain(|nop| now < nop.deadline);
        nops.iter().any(|nop| chandef_overlaps(&nop.def, def))
    }

    /// Publish a radar-triggered NOP for every present and future vdev of
    /// this radio. Repeated radar reports for one chandef extend the same
    /// restriction rather than accumulating indistinguishable records.
    pub fn record_dfs_nop(&self, def: ChanDef, deadline: u64) {
        let now = self.now_ms();
        let mut nops = self.dfs_nops.lock();
        nops.retain(|nop| now < nop.deadline);
        if let Some(nop) = nops.iter_mut().find(|nop| nop.def == def) {
            nop.deadline = nop.deadline.max(deadline);
        } else {
            nops.push(RadioDfsNop { def, deadline });
        }
    }

    /// Take the latest RDDM-backed device coredump. The dump is independent
    /// of firmware lifetime and is therefore still valid after recovery;
    /// taking it transfers ownership to the diagnostic/export consumer.
    pub fn take_firmware_crash_dump(&self) -> Option<FirmwareCrashDump> {
        self.firmware_crash_dump.lock().take()
    }

    fn publish_firmware_crash_dump(&self, dump: FirmwareCrashDump) {
        *self.firmware_crash_dump.lock() = Some(dump);
    }

    /// Give up on the device, keeping what the firmware was given.
    pub fn park(&self, what: alloc::boxed::Box<dyn core::any::Any + Send>) {
        self.parked.lock().push(what);
        self.dead.store(true, Ordering::Release);
    }

    /// The firmware notice to recover from, once (the runtime loop's
    /// `ath11k_core_reset` / `restart_work` trigger).
    pub async fn take_fw_notice(&self) -> Option<FwNotice> {
        let mut g = self.lock().await;
        g.fw_notice.take()
    }

    /// Linux `ath11k_mac_op_reconfig_complete` on a reset: the recovery
    /// succeeded, `fail_cont_count` = 0.
    pub async fn reconfig_complete(&self) {
        let mut g = self.lock().await;
        g.reset.fail_cont_count = 0;
        g.stats.recoveries += 1;
        // ieee80211_reconfig → ieee80211_wake_queues_by_reason(DRIVER) for
        // every attached virtual interface on this physical radio.
        for vdev_id in 0..g.vdevs.len() as u32 {
            g.wake_queues_for(vdev_id, TxQueues::vif_queues(), txq::reason::DRIVER);
        }
    }

    /// A recovery attempt failed (`ath11k_core_reset`'s
    /// `fail_cont_count` / `reset_fail_timeout`); the runtime, if present,
    /// remembers it.
    fn recovery_failed(rt: &mut Rt<Io, Irq, Q>) {
        rt.reset.fail_cont_count += 1;
        rt.reset.reset_fail_timeout = rt.now_ms() + ATH11K_RESET_FAIL_TIMEOUT_MS;
    }

    /// The device half of a crash recovery: `ath11k_core_reset` (interrupts off,
    /// `ath11k_hif_power_down` + `ath11k_hif_power_up` for a reset), the
    /// QMI event work to FW_INIT_DONE, then `ath11k_core_restart` →
    /// `ath11k_core_reconfigure_on_crash` — after the device was reset or
    /// restarted its firmware, so nothing freed here is still used by the
    /// hardware: `ath11k_dp_pdev_free`, `ath11k_ce_cleanup_pipes`,
    /// `ath11k_wmi_detach`, `ath11k_dp_pdev_reo_cleanup`, `ath11k_dp_free`,
    /// `ath11k_hal_srng_clear`, CRASH_FLUSH cleared and
    /// `ath11k_core_qmi_firmware_ready` over the same transport and QMI
    /// session (new DP, HTC, WMI). The runtime is taken out of the slot
    /// for the whole of it (no lock is held across the awaits; `lock`
    /// callers wait). On failure the step is latched, what the firmware
    /// was given is parked and the device is marked dead.
    pub async fn recover_device(&self, notice: FwNotice) -> Result<Recovered, TransportError> {
        self.rebuild_after_transport_reset(
            matches!(notice, FwNotice::Reset(_)),
            true,
            matches!(notice, FwNotice::Reset(MhiNotify::EeRddm)),
        )
        .await
    }

    /// Recreate firmware, CE/DP and WMI after the non-WoW system-suspend
    /// HIF power cycle. This is structurally the same reconstruction as
    /// `restart_work`, but it must not count toward the crash-reset failure
    /// throttling or be reported as a firmware failure.
    pub async fn resume_after_system_suspend(&self) -> Result<Recovered, TransportError> {
        self.rebuild_after_transport_reset(true, false, false).await
    }

    /// The common reconstruction tail for a firmware-reset recovery and an
    /// expected system-suspend cold cycle. `record_recovery_failure` is true
    /// only for a transport-reported crash: system resume failures still park
    /// the unsafe runtime, but never consume reset-throttle budget.
    async fn rebuild_after_transport_reset(
        &self,
        power_cycle: bool,
        record_recovery_failure: bool,
        collect_crash_dump: bool,
    ) -> Result<Recovered, TransportError> {
        // Firmware lost all pdev state. Recreated MAC instances must elect a
        // fresh first opener rather than inheriting the old open-vif count.
        self.radio_mac_users.store(0, Ordering::Release);
        self.scan_owner.store(0, Ordering::Release);
        self.scan_cancel.store(0, Ordering::Release);
        self.bss_survey_requested.store(false, Ordering::Release);
        // Desired controls survive a firmware reset, but no newly rebuilt
        // pdev has received their current antenna generation yet.
        self.antenna_programmed_generation
            .store(0, Ordering::Release);
        *self.operating_channels.lock() = [0; WCN6855_MAX_VDEVS];
        self.bss_surveys.lock().clear();
        *self.mbssid_beacons.lock() = core::array::from_fn(|_| None);
        *self.mbssid_transmitters.lock() = [None; WCN6855_MAX_VDEVS];
        let taken = self.rt.lock().await.take();
        let Some(mut rt) = taken else {
            return Err(TransportError::new(step::RECOVERY_CORE, 0, ENODEV));
        };
        // ath11k_hif_irq_disable + ath11k_hif_ce_irq_disable.
        set_dp_irqs_enabled(false);
        ce::set_ce_irqs_enabled(false);
        if collect_crash_dump {
            // `ath11k_pci_coredump_download` waits for BHIe RX before
            // `ath11k_core_reset` turns the radio over. A failed diagnostic
            // capture is reported by the transport but never prevents the
            // safety-critical reset/recovery sequence.
            rt.core.qmi.collect_crash_dump().await;
            if let Some(dump) = rt.core.qmi.take_crash_dump() {
                self.publish_firmware_crash_dump(dump);
            }
        }
        if let Err(e) = rt.core.qmi.recover(power_cycle).await {
            let te = TransportError::new(
                step::RECOVERY_FW,
                (e.step & 0xffff) << 16 | (e.detail & 0xffff),
                e.errno,
            );
            te.report("ath11k recovery: firmware");
            if record_recovery_failure {
                Self::recovery_failed(&mut rt);
            }
            self.park(alloc::boxed::Box::new(rt));
            return Err(te);
        }
        // restart_work → ath11k_core_reconfigure_on_crash.
        let Rt {
            core,
            mut dp,
            vdevs,
            stats,
            reset,
            ..
        } = rt;
        let (dp_cfg, sizes, msi) = (dp.cfg, dp.sizes, dp.msi());
        let (mut hif, qmi, cfg) = core.into_parts();
        dp.pdev_free(&mut hif.ce.hal);
        hif.ce.cleanup_pipes();
        dp.pdev_reo_cleanup(&mut hif.ce.hal);
        dp.free(&mut hif.ce.hal);
        hif.ce.hal.srng_clear();
        hif.ce.crash_flush = false;
        let mut core = match Ath11kCore::new(hif, qmi, cfg) {
            Ok(c) => c,
            Err((e, hif, qmi)) => {
                let te = TransportError::new(
                    step::RECOVERY_CORE,
                    (e.step & 0xffff) << 16 | (e.detail & 0xffff),
                    e.errno,
                );
                te.report("ath11k recovery: core");
                self.park(alloc::boxed::Box::new((hif, qmi)));
                return Err(te);
            }
        };
        let mut hooks = DpHooks::new(Some(dp_cfg), 0, sizes, msi);
        let r = core.qmi_firmware_ready(&mut hooks).await;
        let dp = hooks.dp.take();
        let (core, dp) = match (r, dp) {
            (Ok(()), Some(dp)) => (core, dp),
            (r, dp) => {
                let e = r
                    .err()
                    .unwrap_or(TransportError::new(step::DP_MISSING, 0, ENODEV));
                let te = TransportError::new(
                    step::RECOVERY_CORE,
                    (e.step & 0xffff) << 16 | (e.detail & 0xffff),
                    e.errno,
                );
                te.report("ath11k recovery: core");
                self.park(alloc::boxed::Box::new((core, dp)));
                return Err(te);
            }
        };
        let mut rt = Rt::new(core, dp);
        // mac80211's queues (still stopped for the driver) and the
        // statuses not yet reported survive the restart.  Keep that state
        // per vdev so a restart cannot deliver vdev 1's requested-TX
        // completion to vdev 0.
        rt.vdevs = vdevs;
        rt.stats = stats;
        rt.reset = reset;
        let r = match rt.device_caps() {
            Ok(caps) => Ok(Recovered {
                caps,
                reg_info: rt.core.reg_info.clone(),
            }),
            Err(e) => {
                TransportError::new(step::RECOVERY_MAC, 3, e.errno).report("ath11k recovery: caps");
                Err(e)
            }
        };
        if r.is_err() && record_recovery_failure {
            Self::recovery_failed(&mut rt);
        }
        *self.rt.lock().await = Some(rt);
        r
    }

    pub fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    /// Queue a synchronous port call.
    pub fn push_op(&self, op: SyncOp) {
        self.ops.lock().push_back(op);
    }

    fn take_ops(&self) -> VecDeque<SyncOp> {
        core::mem::take(&mut *self.ops.lock())
    }

    /// Lock the runtime and apply the queued synchronous calls. While a
    /// recovery owns the runtime this waits for it (on a dead device,
    /// forever: nothing will come back).
    pub async fn lock(&self) -> RtGuard<'_, Io, Irq, Q> {
        loop {
            {
                let mut g = self.rt.lock().await;
                if let Some(rt) = g.as_mut() {
                    for op in self.take_ops() {
                        rt.apply(op);
                    }
                    return RtGuard(g);
                }
            }
            if self.is_dead() {
                core::future::pending::<()>().await;
            }
            self.irq.wait(self.slice_ms).await;
        }
    }

    /// [`Self::lock`] without waiting (sync callers: the netdev drain
    /// hook); `None` while busy or recovering.
    pub fn try_lock(&self) -> Option<RtGuard<'_, Io, Irq, Q>> {
        let mut g = self.rt.try_lock()?;
        let rt = g.as_mut()?;
        for op in self.take_ops() {
            rt.apply(op);
        }
        Some(RtGuard(g))
    }

    /// Service the device until `f` yields or `timeout_ms` passes (0 =
    /// one pass), sleeping on the interrupt source between passes.
    pub async fn wait_until<T: Send>(
        &self,
        timeout_ms: u32,
        mut f: impl FnMut(&mut Rt<Io, Irq, Q>) -> Option<T> + Send,
    ) -> Option<T> {
        let deadline = self.now_ms().saturating_add(timeout_ms as u64);
        loop {
            let (r, flushed) = {
                let mut g = self.lock().await;
                g.service();
                (f(&mut g), g.crash_flush)
            };
            if r.is_some() {
                return r;
            }
            // ath11k_core_pre_reconfigure_recovery completes every
            // waiter: none outlives a crash.
            if flushed {
                return None;
            }
            let now = self.now_ms();
            if now >= deadline {
                return None;
            }
            self.irq
                .wait(((deadline - now) as u32).min(self.slice_ms))
                .await;
        }
    }

    /// `ath11k_wmi_cmd_send`: retry while HTC lacks credits (or the CE
    /// ring is full without credit flow) for `WMI_SEND_TIMEOUT_HZ`.
    pub async fn wmi_send(&self, cmd: &WmiCmd) -> Result<(), i32> {
        enum Try {
            Done,
            Retry(i32),
            Fail(i32),
        }
        let deadline = self.now_ms().saturating_add(self.wmi_send_ms);
        loop {
            let t = {
                let mut g = self.lock().await;
                g.service();
                match g.core.wmi_cmd_try_send(cmd) {
                    Ok(()) => Try::Done,
                    // "if (ret && CRASH_FLUSH) ret = -ESHUTDOWN"
                    Err(_) if g.crash_flush => Try::Fail(ESHUTDOWN),
                    Err(e) if g.core.wmi_send_retryable(e) => Try::Retry(e),
                    Err(e) => Try::Fail(e),
                }
            };
            match t {
                Try::Done => return Ok(()),
                Try::Fail(e) => return Err(e),
                Try::Retry(e) => {
                    let now = self.now_ms();
                    if now >= deadline {
                        log(format_args!(
                            "wmi command {:#x} timeout (-{})",
                            cmd.cmd_id, e
                        ));
                        return Err(e);
                    }
                    self.irq
                        .wait(((deadline - now) as u32).min(self.slice_ms))
                        .await;
                }
            }
        }
    }

    /// Discard an earlier WoW completion before issuing a new enable or wake
    /// command.  Linux reinitialises the relevant completion object at this
    /// boundary so a stale firmware response cannot satisfy a later command.
    pub async fn clear_wow_control_completions(&self) {
        let mut g = self.lock().await;
        let _ = g.core.take_htc_suspend_complete();
        let _ = g.core.take_wow_wakeup();
    }

    /// Wait for `SEND_SUSPEND_COMPLETE` or `NACK_SUSPEND` from HTC endpoint
    /// zero while continuing to service CE/HTC/WMI/DP.  `None` means the
    /// three-second Linux timeout or a crash-flush; `Some(false)` is a NACK
    /// that the WoW owner retries after 200 ms.
    pub async fn wait_wow_suspend_complete(&self) -> Option<bool> {
        self.wait_until(ATH11K_WOW_COMPLETION_TIMEOUT_MS, |rt| {
            rt.core.take_htc_suspend_complete()
        })
        .await
    }

    /// Wait for `WMI_WOW_WAKEUP_HOST_EVENTID` while keeping the device
    /// runtime alive.  The event, rather than HTC endpoint-zero's
    /// diagnostic `WAKEUP_FROM_SUSPEND`, is what `ath11k_wow_wakeup` waits
    /// for in Linux.  Unlike a suspend NACK there is no retry response.
    pub async fn wait_wow_wakeup_complete(&self) -> Option<wmi::WowWakeup> {
        self.wait_until(ATH11K_WOW_COMPLETION_TIMEOUT_MS, |rt| {
            rt.core.take_wow_wakeup()
        })
        .await
    }

    /// Send HTT messages in order (no credit flow on HTT); the first
    /// failure is returned.
    async fn htt_send_all(&self, msgs: &[Vec<u8>]) -> Result<(), i32> {
        let mut g = self.lock().await;
        for m in msgs {
            g.core.htt_send(m).map_err(|e| e.errno)?;
        }
        Ok(())
    }

    /// Received data frames waiting for the interface (Ethernet II +
    /// the hardware checksum verdict).
    pub async fn take_rx(&self) -> Vec<(Vec<u8>, bool)> {
        self.take_rx_for(0).await
    }

    /// As [`Self::take_rx`], but only for a selected firmware vdev.
    pub async fn take_rx_for(&self, vdev_id: u32) -> Vec<(Vec<u8>, bool)> {
        let mut g = self.lock().await;
        g.service();
        g.vdev_mut(vdev_id)
            .map(|vdev| vdev.link.data_rx.drain(..).collect())
            .unwrap_or_default()
    }

    /// Frames from the interface (`(Ethernet, CHECKSUM_PARTIAL)`): queue
    /// each on its AC, push what the hardware queues allow, service.
    /// Returns each frame's enqueue result.
    pub async fn tx_frames(&self, frames: Vec<(Vec<u8>, bool)>) -> Vec<Result<(), i32>> {
        self.tx_frames_for(0, frames).await
    }

    /// As [`Self::tx_frames`], but enqueue solely on `vdev_id`'s TXQs.
    pub async fn tx_frames_for(
        &self,
        vdev_id: u32,
        frames: Vec<(Vec<u8>, bool)>,
    ) -> Vec<Result<(), i32>> {
        self.tx_frames_with_flags_for(
            vdev_id,
            frames
                .into_iter()
                .map(|(eth, csum_partial)| (eth, csum_partial, false))
                .collect(),
        )
        .await
    }

    /// As [`Self::tx_frames_for`], with the already-validated
    /// `IEEE80211_TX_INTFL_DONT_ENCRYPT` decision for each Ethernet frame.
    /// This private driver-side extension is necessary because association
    /// level `CONTROL_PORT_NO_ENCRYPT` is applied to ordinary netdev frames
    /// before the async TXQ crosses into the runtime.
    pub async fn tx_frames_with_flags_for(
        &self,
        vdev_id: u32,
        frames: Vec<(Vec<u8>, bool, bool)>,
    ) -> Vec<Result<(), i32>> {
        let mut g = self.lock().await;
        let r = frames
            .into_iter()
            .map(|(eth, csum, no_encrypt)| g.tx_enqueue_ack(vdev_id, eth, csum, no_encrypt, None))
            .collect();
        g.tx_push_for(vdev_id);
        g.service();
        r
    }

    /// Queue one control-port Ethernet frame with an explicit
    /// `IEEE80211_TX_INTFL_DONT_ENCRYPT` request. This mirrors the normal
    /// stack TXQ path but keeps the nl80211 per-frame flag out of the public
    /// netdev data path.
    pub async fn tx_control_port_for(
        &self,
        vdev_id: u32,
        eth: Vec<u8>,
        no_encrypt: bool,
    ) -> Result<(), i32> {
        let mut g = self.lock().await;
        let result = g.tx_enqueue_ack(vdev_id, eth, false, no_encrypt, None);
        g.tx_push_for(vdev_id);
        g.service();
        result
    }

    /// Queue an Ethernet frame with `IEEE80211_TX_CTL_REQ_TX_STATUS` and
    /// return the private ACK-status ID. The caller later consumes it with
    /// [`Self::take_eth_tx_status_for`]; unlike
    /// [`Self::send_eth_tx_status_for`], this never waits in the runtime
    /// worker that must itself continue servicing WBM completions.
    pub async fn enqueue_eth_tx_status_for(
        &self,
        vdev_id: u32,
        eth: Vec<u8>,
        no_encrypt: bool,
    ) -> Result<u32, i32> {
        let mut g = self.lock().await;
        let id = g.tx_enqueue_status_no_encrypt_for(vdev_id, eth, no_encrypt)?;
        g.tx_push_for(vdev_id);
        g.service();
        Ok(id)
    }

    /// Consume a completed requested-TX status without waiting. This is the
    /// asynchronous counterpart of [`Self::send_eth_tx_status_for`] for
    /// nl80211 control-port frames: an interface worker polls it between
    /// normal device-service slices and publishes the matching cookie.
    pub async fn take_eth_tx_status_for(&self, vdev_id: u32, id: u32) -> Option<TxStatus> {
        let mut g = self.lock().await;
        g.service();
        let vdev = g.vdev_mut(vdev_id)?;
        let i = vdev
            .ack_status
            .iter()
            .position(|(ack_id, _)| *ack_id == id)?;
        vdev.ack_status.remove(i).map(|(_, status)| status)
    }

    /// Drain this vdev's locally detected TKIP Michael failures. The
    /// netdev calls it after every runtime service slice and publishes the
    /// corresponding cfg80211 MLME event without taking the MAC mutex.
    pub async fn take_mic_failures_for(&self, vdev_id: u32) -> Vec<MichaelMicFailure> {
        let mut g = self.lock().await;
        g.service();
        g.vdev_mut(vdev_id)
            .map(|vdev| vdev.mic_failures.drain(..).collect())
            .unwrap_or_default()
    }

    /// Send an Ethernet frame asking for its TX status and wait ≤
    /// `timeout_ms` for it (`ieee80211_tx_control_port` with a cookie →
    /// `cfg80211_control_port_tx_status`, the mlme probe's
    /// `ieee80211_sta_tx_notify`). `Err(ETIMEDOUT)` frees the ack id.
    pub async fn send_eth_tx_status(&self, eth: &[u8], timeout_ms: u32) -> Result<TxStatus, i32> {
        self.send_eth_tx_status_for(0, eth, timeout_ms).await
    }

    /// As [`Self::send_eth_tx_status`], with the completion namespace and
    /// TXQ selected by `vdev_id`.
    pub async fn send_eth_tx_status_for(
        &self,
        vdev_id: u32,
        eth: &[u8],
        timeout_ms: u32,
    ) -> Result<TxStatus, i32> {
        let id = {
            let mut g = self.lock().await;
            let id = g.tx_enqueue_status_for(vdev_id, eth.to_vec())?;
            g.tx_push_for(vdev_id);
            g.service();
            id
        };
        let r = self
            .wait_until(timeout_ms, |rt| {
                let vdev = rt.vdev_mut(vdev_id)?;
                let i = vdev.ack_status.iter().position(|(a, _)| *a == id)?;
                vdev.ack_status.remove(i).map(|(_, s)| s)
            })
            .await;
        match r {
            Some(s) => Ok(s),
            None => {
                if let Some(vdev) = self.lock().await.vdev_mut(vdev_id) {
                    vdev.ack_frames.remove(id);
                }
                Err(ETIMEDOUT)
            }
        }
    }

    /// Send the mac80211 connection-monitor Null / QoS Null probe and
    /// return its requested TX status. The ID is removed on timeout, just
    /// as [`Self::send_eth_tx_status`] does for a control-port frame.
    pub async fn probe_ap(&self, timeout_ms: u32) -> Result<TxStatus, i32> {
        self.probe_ap_for(0, timeout_ms).await
    }

    /// As [`Self::probe_ap`], but issue the nullfunc on `vdev_id`.
    pub async fn probe_ap_for(&self, vdev_id: u32, timeout_ms: u32) -> Result<TxStatus, i32> {
        let id = {
            let mut g = self.lock().await;
            let id = g.tx_nullfunc_status_for(vdev_id)?;
            g.service();
            id
        };
        let r = self
            .wait_until(timeout_ms, |rt| {
                let vdev = rt.vdev_mut(vdev_id)?;
                let i = vdev.ack_status.iter().position(|(a, _)| *a == id)?;
                vdev.ack_status.remove(i).map(|(_, s)| s)
            })
            .await;
        match r {
            Some(s) => Ok(s),
            None => {
                if let Some(vdev) = self.lock().await.vdev_mut(vdev_id) {
                    vdev.ack_frames.remove(id);
                }
                Err(ETIMEDOUT)
            }
        }
    }

    /// `ieee80211_flush_queues(local, sdata, drop)` for the station vif:
    /// stop the vif's hardware queues (`QUEUE_STOP_REASON_FLUSH`), purge
    /// the TXQs when `drop`, `drv_flush` (`ath11k_mac_op_flush`: nothing
    /// when `drop`, else `ath11k_mac_flush_tx_complete` — wait ≤ 5 s each
    /// for no pending data and no pending management frame), wake.
    pub async fn flush_queues(&self, drop: bool) {
        self.flush_queues_for(0, drop).await;
    }

    /// As [`Self::flush_queues`], scoped to one vdev's mac80211 TXQs.
    /// The pdev completion rings and WMI management queue remain physical
    /// radio resources, so their drain waits intentionally stay shared.
    pub async fn flush_queues_for(&self, vdev_id: u32, drop: bool) {
        let q = TxQueues::vif_queues();
        {
            let mut g = self.lock().await;
            g.stop_queues_for(vdev_id, q, txq::reason::FLUSH);
            if drop {
                g.purge_txqs_for(vdev_id);
            }
        }
        if !drop {
            let data = self
                .wait_until(ATH11K_FLUSH_TIMEOUT_MS, |rt| {
                    (rt.dp.pdev.as_ref().map_or(0, |p| p.num_tx_pending) == 0).then_some(())
                })
                .await;
            if data.is_none() {
                log(format_args!("failed to flush transmit queue"));
            }
            let mgmt = self
                .wait_until(ATH11K_FLUSH_TIMEOUT_MS, |rt| {
                    (rt.mgmt.pending == 0).then_some(())
                })
                .await;
            if mgmt.is_none() {
                log(format_args!("failed to flush mgmt transmit queue"));
            }
        }
        let mut g = self.lock().await;
        g.wake_queues_for(vdev_id, q, txq::reason::FLUSH);
        g.service();
    }
}

/// The ports the mac layer drives (`Mac<Port, Port>`).
#[allow(missing_debug_implementations)]
pub struct Port<Io: RtIo, Irq: DpIrq, Q: RtQmi>(
    pub Arc<Shared<Io, Irq, Q>>,
    /// The only WMI vdev this port is allowed to consume or mutate.
    pub u32,
);

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Clone for Port<Io, Irq, Q> {
    fn clone(&self) -> Self {
        Port(self.0.clone(), self.1)
    }
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> WmiPort for Port<Io, Irq, Q> {
    async fn send(&self, cmd: WmiCmd) -> Result<(), i32> {
        self.0.wmi_send(&cmd).await
    }

    async fn next_event(&self, timeout_ms: u32) -> Option<Vec<u8>> {
        self.0
            .wait_until(timeout_ms, |rt| rt.take_vdev_event(self.1))
            .await
    }

    async fn mgmt_tx(&self, vdev_id: u32, frame: &[u8], chanfreq: Option<u32>) -> Result<u32, i32> {
        if vdev_id != self.1 {
            // A MAC instance may never submit management traffic through a
            // sibling's port; this would otherwise make completion routing
            // non-deterministic on a concurrent radio.
            return Err(ENODEV);
        }
        let (id, cmd) = {
            let mut g = self.0.lock().await;
            g.mgmt_tx_prepare(vdev_id, frame, chanfreq)?
        };
        match self.0.wmi_send(&cmd).await {
            Ok(()) => {
                let mut g = self.0.lock().await;
                g.mgmt.pending += 1;
                g.stats.mgmt_tx += 1;
                Ok(id)
            }
            Err(e) => {
                // err_unmap_buf / err_free_idr.
                let mut g = self.0.lock().await;
                g.mgmt.bufs.remove(id);
                Err(e)
            }
        }
    }

    fn mgmt_tx_done(&self, desc_id: u32) {
        self.0.push_op(SyncOp::MgmtTxDone(desc_id));
    }

    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }

    fn max_msg_len(&self) -> u32 {
        self.0.max_msg_len
    }

    fn random_bytes(&self, out: &mut [u8]) {
        (self.0.rng)(out)
    }
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> DataPort for Port<Io, Irq, Q> {
    async fn ppdu_stats_req(&self) -> Result<(), i32> {
        // ath11k_dp_tx_htt_h2t_ppdu_stats_req(ar, HTT_PPDU_STATS_TAG_DEFAULT)
        let msgs: Vec<Vec<u8>> = {
            let g = self.0.lock().await;
            htt::ppdu_stats_cfg_msgs(
                0,
                g.dp.cfg.num_rxdma_per_pdev,
                htt::HTT_PPDU_STATS_TAG_DEFAULT,
            )
            .iter()
            .map(|m| m.to_vec())
            .collect()
        };
        self.0.htt_send_all(&msgs).await
    }

    async fn mon_status_default(&self, enable: bool) -> Result<(), i32> {
        let mut g = self.0.lock().await;
        let msgs = {
            let rt = &mut *g;
            rt.dp
                .mon_status_default_msgs(&rt.core.hif.ce.hal, enable)
                .map_err(|e| e.errno)?
        };
        // Linux keeps going and returns the last ring's result.
        let mut ret = Ok(());
        for m in &msgs {
            ret = g.core.htt_send(m).map_err(|e| e.errno);
        }
        if enable && !g.dp.cfg.rxdma1_enable {
            // mod_timer(&ab->mon_reap_timer, …) (deleted only by
            // ath11k_mac_op_stop / ath11k_dp_free).
            let now = g.now_ms();
            g.mon_reap_at = Some(now + ATH11K_MON_TIMER_INTERVAL);
        }
        ret
    }

    fn vdev_tx_attach(&self, vdev_id: u32, addr: [u8; 6], ap: bool) {
        self.0.push_op(SyncOp::VdevTxAttach { vdev_id, addr, ap });
    }

    fn ap_started(&self, vdev_id: u32, bssid: [u8; 6], privacy: bool) {
        self.0.push_op(SyncOp::ApStarted {
            vdev_id,
            bssid,
            privacy,
        });
    }

    fn ap_stopped(&self, vdev_id: u32) {
        self.0.push_op(SyncOp::ApStopped { vdev_id });
    }

    fn ap_channel_switching(&self, vdev_id: u32, blocked: bool) {
        self.0
            .push_op(SyncOp::ApChannelSwitching { vdev_id, blocked });
    }

    fn ap_dfs_cac(&self, vdev_id: u32, running: bool) {
        self.0.push_op(SyncOp::ApDfsCac { vdev_id, running });
    }

    fn dfs_nop_active(&self, def: &ChanDef) -> bool {
        self.0.dfs_nop_active(def)
    }

    fn record_dfs_nop(&self, def: ChanDef, deadline: u64) {
        self.0.record_dfs_nop(def, deadline);
    }

    fn ap_station_added(&self, vdev_id: u32, addr: [u8; 6], wme: bool) {
        self.0
            .push_op(SyncOp::ApStationAdded { vdev_id, addr, wme });
    }

    fn ap_station_removed(&self, vdev_id: u32, addr: [u8; 6]) {
        self.0.push_op(SyncOp::ApStationRemoved { vdev_id, addr });
    }

    fn ap_group_key(&self, vdev_id: u32, installed: bool) {
        self.0.push_op(SyncOp::ApGroupKey { vdev_id, installed });
    }

    async fn wait_peer_mapped(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        mapped: bool,
        timeout_ms: u32,
    ) -> Result<(), i32> {
        self.0
            .wait_until(timeout_ms, |rt| {
                let peer = rt
                    .dp
                    .peers
                    .iter()
                    .find(|p| p.vdev_id as u32 == vdev_id && p.addr == addr)
                    .copied();
                match (peer, mapped) {
                    (Some(p), true) => {
                        if rt.vdev(vdev_id).is_some_and(|vdev| vdev.ap_configured) {
                            // AP peers are selected from the AP table after
                            // their WMI association completes; do not make a
                            // client look like the one station BSS peer.
                            return Some(());
                        }
                        // ath11k_peer_create (STA vif): arvif->ast_hash /
                        // ast_idx from the BSS peer.
                        if let Some(v) =
                            rt.vdev_mut(vdev_id).and_then(|vdev| vdev.link.vif.as_mut())
                        {
                            v.ast_hash = p.ast_hash;
                            v.ast_idx = p.hw_peer_id;
                        }
                        if let Some(vdev) = rt.vdev_mut(vdev_id) {
                            vdev.link.bss = Some(addr);
                        }
                        Some(())
                    }
                    (None, false) => {
                        if rt.vdev(vdev_id).is_some_and(|vdev| vdev.ap_configured) {
                            return Some(());
                        }
                        if let Some(vdev) = rt
                            .vdev_mut(vdev_id)
                            .filter(|vdev| vdev.link.bss == Some(addr))
                        {
                            vdev.link.bss = None;
                            vdev.link.authorized = false;
                            vdev.link.ptk = false;
                            vdev.link.wme = false;
                            vdev.link.last_tx_rate = None;
                            vdev.link.last_ppdu_tx_rate = None;
                            vdev.link.last_rx_rate = None;
                            vdev.link.tx_duration_us = 0;
                            vdev.link.last_ppdu_signal_dbm = None;
                            vdev.link.ppdu_rssi_ewma = None;
                            vdev.link.ppdu_signal_avg_dbm = None;
                            vdev.link.chain_signal_dbm = [None; RX_PPDU_MAX_CHAINS];
                            vdev.link.rx_duration_us = 0;
                            vdev.link.seq.sta_destroyed();
                        }
                        Some(())
                    }
                    _ => None,
                }
            })
            .await
            .ok_or(ETIMEDOUT)
    }

    async fn peer_setup(&self, vdev_id: u32, addr: [u8; 6]) -> Result<(), i32> {
        // ath11k_dp_peer_setup(ar, vdev_id, addr): reo_dest = mac_id + 1.
        let (mut op, cmd) = {
            let g = self.0.lock().await;
            g.dp.peer_setup_begin(vdev_id as u8, addr, 0)
        };
        // WMI_PEER_SET_DEFAULT_ROUTING: "failed to set default routing".
        self.0.wmi_send(&cmd).await?;
        loop {
            let next = {
                let mut g = self.0.lock().await;
                let now = g.now_ms();
                let rt = &mut *g;
                let hif = &mut rt.core.hif;
                rt.dp
                    .peer_setup_next(&mut hif.ce.hal, &hif.io, &mut op, now)
            };
            match next {
                Ok(Some(cmd)) => {
                    if let Err(e) = self.0.wmi_send(&cmd).await {
                        let mut g = self.0.lock().await;
                        let now = g.now_ms();
                        let rt = &mut *g;
                        let hif = &mut rt.core.hif;
                        let te = rt
                            .dp
                            .peer_setup_wmi_failed(&mut hif.ce.hal, &hif.io, &op, e, now);
                        return Err(te.errno);
                    }
                }
                Ok(None) => return Ok(()),
                Err(te) => return Err(te.errno),
            }
        }
    }

    fn peer_cleanup(&self, vdev_id: u32, addr: [u8; 6]) {
        self.0.push_op(SyncOp::PeerCleanup { vdev_id, addr });
    }

    async fn rx_pn_replay_config(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        cipher: u32,
        key_len: usize,
        key_idx: u8,
        pairwise: bool,
        install: bool,
    ) -> Result<(), i32> {
        let mut g = self.0.lock().await;
        let now = g.now_ms();
        let rsn = matches!(
            cipher,
            wmi::cipher::AES_CCM | wmi::cipher::TKIP | wmi::cipher::AES_GCM
        );
        let r = {
            let rt = &mut *g;
            let hif = &mut rt.core.hif;
            rt.dp.pn_replay_config(
                &mut hif.ce.hal,
                &hif.io,
                vdev_id as u8,
                &addr,
                rsn,
                pairwise,
                install,
                now,
            )
        };
        r.map_err(|e| e.errno)?;
        // ath11k_mac_op_set_key: peer->sec_type / sec_type_grp
        // (ath11k_dp_tx_get_encrypt_type), and mac80211's PTK slot that
        // makes data Protected.
        let sec = match cipher {
            wmi::cipher::AES_CCM if key_len == 32 => enc::CCMP_256,
            wmi::cipher::AES_CCM => enc::CCMP_128,
            wmi::cipher::TKIP => enc::TKIP_MIC,
            wmi::cipher::AES_GCM if key_len == 32 => enc::AES_GCMP_256,
            wmi::cipher::AES_GCM => enc::GCMP_128,
            _ => enc::OPEN,
        };
        if let Some(p) =
            g.dp.peers
                .iter()
                .find(|p| p.vdev_id as u32 == vdev_id && p.addr == addr)
                .copied()
        {
            if install {
                let (u, m) = if pairwise {
                    (sec, p.sec_type_grp)
                } else {
                    (p.sec_type, sec)
                };
                g.dp.set_peer_sec_type(p.peer_id, u, m);
            }
            g.dp.set_peer_key_index(p.peer_id, pairwise, install.then_some(key_idx));
        }
        if pairwise {
            if let Some(vdev) = g.vdev_mut(vdev_id) {
                if vdev.link.bss == Some(addr) {
                    vdev.link.ptk = install;
                }
                if let Some(ap) = vdev.ap.as_mut().filter(|ap| ap.vdev_id == vdev_id) {
                    if let Some(peer) = ap.peers.iter_mut().find(|peer| peer.addr == addr) {
                        peer.ptk = install;
                    }
                }
            }
        }
        Ok(())
    }

    async fn tkip_rx_mic_config(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        key: Option<[u8; 8]>,
    ) -> Result<(), i32> {
        let mut g = self.0.lock().await;
        g.dp.tkip_rx_mic_config(vdev_id as u8, &addr, key)
    }

    async fn send_eth(&self, frame: &[u8]) -> Result<(), i32> {
        // ieee80211_tx_control_port → the TXQ like any data frame.
        self.0
            .tx_frames_for(self.1, alloc::vec![(frame.to_vec(), false)])
            .await
            .pop()
            .unwrap_or(Err(EIO))
    }

    async fn probe_ap(&self, timeout_ms: u32) -> Result<TxStatus, i32> {
        self.0.probe_ap_for(self.1, timeout_ms).await
    }

    async fn flush_tx(&self) {
        self.0.flush_queues_for(self.1, false).await;
    }

    async fn recv_eapol(&self, timeout_ms: u32) -> Option<(Vec<u8>, bool)> {
        self.0
            .wait_until(timeout_ms, |rt| {
                rt.vdev_mut(self.1)
                    .and_then(|vdev| vdev.link.eapol_rx.pop_front())
            })
            .await
    }

    fn set_authorized(&self, addr: [u8; 6], authorized: bool) {
        self.0.push_op(SyncOp::SetAuthorized {
            vdev_id: self.1,
            addr,
            on: authorized,
        });
    }

    fn set_sta_wme(&self, addr: [u8; 6], wme: bool) {
        self.0.push_op(SyncOp::StaWme {
            vdev_id: self.1,
            addr,
            wme,
        });
    }

    fn set_sta_four_addr(&self, enabled: bool) {
        self.0.push_op(SyncOp::StaFourAddr {
            vdev_id: self.1,
            enabled,
        });
    }

    fn peer_frags_flush(&self, vdev_id: u32, addr: [u8; 6]) {
        self.0.push_op(SyncOp::FragsFlush { vdev_id, addr });
    }

    async fn ampdu_rx_start(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        tid: u8,
        buf_size: u16,
        ssn: u16,
    ) -> Result<(), i32> {
        // ath11k_dp_rx_ampdu_start: ath11k_peer_rx_tid_setup(.., tid,
        // buf_size, ssn, arsta->pn_type); arsta->pn_type is WPA once a
        // CCMP / TKIP / GCMP pairwise key is installed.
        let setup = {
            let mut g = self.0.lock().await;
            let now = g.now_ms();
            let pn = if g.vdev(vdev_id).is_some_and(|vdev| {
                vdev.link.bss == Some(addr) && vdev.link.ptk
                    || vdev.ap.as_ref().is_some_and(|ap| {
                        ap.vdev_id == vdev_id
                            && ap.peers.iter().any(|peer| peer.addr == addr && peer.ptk)
                    })
            }) {
                super::dp_peer::HalPnType::Wpa
            } else {
                super::dp_peer::HalPnType::None
            };
            let rt = &mut *g;
            let hif = &mut rt.core.hif;
            rt.dp
                .ampdu_start(
                    &mut hif.ce.hal,
                    &hif.io,
                    vdev_id as u8,
                    &addr,
                    tid,
                    buf_size,
                    ssn,
                    pn,
                    now,
                )
                .map_err(|e| e.errno)?
        };
        if let Err(e) = self.0.wmi_send(&setup.cmd).await {
            // "failed to setup rx reorder queue": ath11k_dp_rx_tid_mem_free.
            let mut g = self.0.lock().await;
            g.dp.rx_tid_wmi_failed(vdev_id as u8, &addr, &setup);
            return Err(e);
        }
        Ok(())
    }

    async fn ampdu_rx_stop(&self, vdev_id: u32, addr: [u8; 6], tid: u8) -> Result<(), i32> {
        let cmd = {
            let mut g = self.0.lock().await;
            let now = g.now_ms();
            let rt = &mut *g;
            let hif = &mut rt.core.hif;
            rt.dp
                .ampdu_stop(&mut hif.ce.hal, &hif.io, vdev_id as u8, &addr, tid, now)
                .map_err(|e| e.errno)?
        };
        match cmd {
            // "failed to send wmi to delete rx tid".
            Some(c) => self.0.wmi_send(&c).await,
            None => Ok(()),
        }
    }
}

// ── PCI: from a ready core to `wlan%d` ────────────────────────────

/// The hardware runtime.
pub type PciShared = Shared<super::core::Bar0, MsiCeIrq, super::pci::Wlfw>;

impl Shared<super::core::Bar0, MsiCeIrq, super::pci::Wlfw> {
    /// Linux's WoW suspend transport tail: stop host CE/DP delivery, then
    /// enter MHI M3.  The runtime is temporarily removed from its slot so no
    /// async mutex is held while MHI waits for its own interrupt-driven state
    /// transition; callers trying to service the runtime wait as they do
    /// during recovery.
    pub async fn wowlan_hif_suspend(&self) -> Result<(), i32> {
        let mut rt = loop {
            let mut slot = self.rt.lock().await;
            if let Some(rt) = slot.take() {
                break rt;
            }
            drop(slot);
            if self.is_dead() {
                return Err(EIO);
            }
            self.irq.wait(self.slice_ms).await;
        };

        // `ath11k_ce_stop_shadow_timers` + `ath11k_dp_stop_shadow_timers`,
        // then `ath11k_hif_irq_disable` + `ath11k_hif_ce_irq_disable`, all
        // precede `ath11k_hif_suspend`. MHI's vectors stay live for the M3
        // ACK, but normal CE/DP servicing is now inert.
        rt.suspend_for_wowlan();
        set_dp_irqs_enabled(false);
        ce::set_ce_irqs_enabled(false);
        let result = rt
            .core
            .qmi
            .client
            .pipe
            .system_suspend()
            .await
            .map_err(|e| e.errno);
        if result.is_err() {
            // `ath11k_wow_op_suspend`'s hif-failure edge immediately heads
            // to WoW wakeup; the transport must remain serviceable for that
            // cleanup attempt.
            ce::set_ce_irqs_enabled(true);
            set_dp_irqs_enabled(true);
            rt.resume_from_wowlan();
        }
        *self.rt.lock().await = Some(rt);
        result
    }

    /// Linux's WoW resume transport head: force MHI to M0 (WCN6855 can be
    /// functional without reporting M3), then restore CE and DP delivery
    /// before WMI receives `WMI_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID`.
    pub async fn wowlan_hif_resume(&self) -> Result<(), i32> {
        let mut rt = loop {
            let mut slot = self.rt.lock().await;
            if let Some(rt) = slot.take() {
                break rt;
            }
            drop(slot);
            if self.is_dead() {
                return Err(EIO);
            }
            self.irq.wait(self.slice_ms).await;
        };

        let result = rt
            .core
            .qmi
            .client
            .pipe
            .system_resume_force()
            .await
            .map_err(|e| e.errno);
        if result.is_ok() {
            // NARF has no separately owned RX pktlog task to restart; CE's
            // HTT packet-log pipe is serviced by the normal runtime loop.
            rt.resume_from_wowlan();
            ce::set_ce_irqs_enabled(true);
            set_dp_irqs_enabled(true);
        }
        *self.rt.lock().await = Some(rt);
        result
    }

    /// The late half of Linux's non-WoW system suspend
    /// (`ath11k_core_suspend_late`): after cfg80211/mac80211 stopped the
    /// station, stop all regular CE/DP activity and power down the PCI/MHI
    /// transport. The runtime remains in its slot but is inert until the
    /// paired resume reconstruction takes ownership of it.
    pub async fn system_hif_power_down(&self) -> Result<(), i32> {
        let mut rt = loop {
            let mut slot = self.rt.lock().await;
            if let Some(rt) = slot.take() {
                break rt;
            }
            drop(slot);
            if self.is_dead() {
                return Err(EIO);
            }
            self.irq.wait(self.slice_ms).await;
        };

        // `ath11k_core_suspend_default` stopped CE/DP shadow timers before
        // this late callback. Reuse the same software gate as the WoW M3
        // path: no periodic service may touch a controller that has reset
        // and released its MHI contexts.
        rt.suspend_for_wowlan();
        set_dp_irqs_enabled(false);
        ce::set_ce_irqs_enabled(false);
        rt.core
            .qmi
            .client
            .pipe
            .power_down_for_system_suspend()
            .await;
        *self.rt.lock().await = Some(rt);
        Ok(())
    }
}

/// A runtime whose mac layer failed to come up (kept: the firmware owns
/// memory and rings it was given).
static STRANDED_RT: IrqSafeSpinLock<Option<Arc<PciShared>>> = IrqSafeSpinLock::new(None);

/// After `ath11k_core_qmi_firmware_ready`: `ath11k_mac_register` (the
/// mac layer from the bring-up events), then the netdev and its tasks.
/// The hardware starts when the interface goes up (`ieee80211_do_open`
/// → `ath11k_mac_op_start` + `ath11k_mac_op_add_interface`, in
/// [`super::iface`]). Failures are latched by the layer that failed;
/// nothing here panics or blocks the caller (it runs in the
/// probe-spawned MHI task).
pub async fn start_pci(core: super::core::PciCore, dp: Dp) {
    let rt = Rt::new(core, dp);
    let caps = match rt.device_caps() {
        Ok(c) => c,
        Err(e) => {
            e.report("ath11k mac register");
            *STRANDED_RT.lock() = Some(Shared::new(rt, narf_crypto::fill_random_bytes));
            return;
        }
    };
    let initial_reg = rt.core.reg_info.clone();
    let shared = Shared::new(rt, narf_crypto::fill_random_bytes);
    let mac = super::mac::Mac::new(
        Port(shared.clone(), 0),
        Port(shared.clone(), 0),
        caps.clone(),
        super::mac::MacConfig::wcn6855(),
        initial_reg.as_deref(),
    );
    let m = caps.mac_addr;
    let name = super::iface::register_pci(shared, mac, m);
    log(format_args!(
        "{}: registered, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (data path up; starts on IFF_UP)",
        name, m[0], m[1], m[2], m[3], m[4], m[5]
    ));
}
