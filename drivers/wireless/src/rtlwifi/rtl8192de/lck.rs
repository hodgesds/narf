// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE LC calibration (`rtl92d_phy_lc_calibrate`) + LCK reload.
//!
//! Exact Linux v6.1 `drivers/net/wireless/realtek/rtlwifi/rtl8192de/phy.c`:
//!
//! - `rtl92d_phy_lc_calibrate` (phy.c:2632) via `_rtl92d_phy_lc_calibrate`
//!   (2624) and `_rtl92d_phy_lc_calibrate_sw` (2520): wait while
//!   `act_scanning` (up to 2000 µs), set `lck_inprogress`, single-PHY
//!   calibrates 2 paths, dual-MAC 1 path; `0xd03` / `REG_TXPAUSE`
//!   handling; `RFPGA0_ANALOGPARAMETER4` `0xF00000`; per-path RF_AC
//!   standby; RF_SYN_G7 BIT(17); RF_CHNLBW `0x08000`; poll RF_SYN_G6
//!   BIT(11) with `mdelay(50)` up to 800 ms; curve-count reads via RF
//!   `0x3F` / `0x4D` / `0x4F` / `0x50`; curve-index calc; LCK reload.
//! - `_rtl92d_phy_calc_curvindex` (2436) + `targetchnl_2g[14]` /
//!   `targetchnl_5g[221]` (phy.c:109-161) + the 5 GHz legality list
//!   `channel5g[49]` (`core.c:16-24`).
//! - `_rtl92d_phy_reload_lck_setting` (2461): RF_SYN_G4 `0x3f800` gets
//!   the curve index for the current channel; the dual-dual branches
//!   use `_rtl92d_phy_enable_rf_env` / `_rtl92d_phy_restore_rf_env`
//!   (phy.c:1132/1168), ported here as [`enable_rf_env`] /
//!   [`restore_rf_env`].
//! - The channel-switch LCK wait (`_rtl92d_phy_sw_chnl_step_by_step`,
//!   phy.c:2842-2845: `while (lck_inprogress && timecount < 1000)
//!   mdelay(50)`) is [`wait_lck_clear`]; [`super::channel::switch_channel`]
//!   calls it first, mirroring Linux's order.
//! - The `rtl92de_hw_init` dual-dual RF-ready poll (hw.c:1002-1024:
//!   RF `0x2a` BIT(11) up to 10000x, `udelay(MAX_STALL_TIME)` = 50 µs)
//!   is [`wait_dualphy_rf_ready`].
//!
//! The `targetchnl` / `channel5g` tables are transcribed verbatim by a
//! generator (`gen_lck_tables.py` in the lane scratchpad, parsing the
//! Linux sources above) and verified by an independent checker
//! (`check_lck_tables.py`, re-parses the C sources and diffs every
//! entry against this file); they are never hand-copied.
//!
//! Merge-order note: draft PR #1927 (the #1888 lane) creates
//! `drivers/wireless/src/rtlwifi/rtl8192de/calib.rs` with the IQK
//! reload. This lane deliberately does NOT create that file; LC
//! calibration lives here (`lck.rs`) so the two land without a path
//! collision, and the two calibration pieces may want one home once
//! both land.
//!
//! Not this step: the `rtl92de_hw_init` orchestrator call itself
//! (blocked on #1889 Prepared integration / orchestrator landing) —
//! [`lc_calibrate`] is exposed standalone first, and
//! [`wait_dualphy_rf_ready`] is the hw_init follow-on step.

use super::phy::{self, Path};
use super::{Band, MacPhyMode, RfType};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `TARGET_CHNL_NUM_5G` (`rtl8192de/phy.c:24`).
pub const TARGET_CHNL_NUM_5G: usize = 221;
/// `TARGET_CHNL_NUM_2G` (`rtl8192de/phy.c:25`).
pub const TARGET_CHNL_NUM_2G: usize = 14;
/// `CV_CURVE_CNT` (`rtl8192de/phy.c:26`): 64 curve points, 128 counts.
pub const CV_CURVE_CNT: usize = 64;

/// RF registers (`rtl8192de/reg.h`).
pub const RF_AC: u32 = 0x00;
pub const RF_SYN_G4: u32 = 0x28;
pub const RF_SYN_G6: u32 = 0x2a;
pub const RF_SYN_G7: u32 = 0x2b;

/// Curve-count RF registers (`rtl8192de/phy.c:2579-2592`, raw in Linux).
pub const RF_LCK_CURVE_SEL: u32 = 0x3f;
pub const RF_LCK_CURVE_TRIG: u32 = 0x4d;
pub const RF_LCK_CURVE_CNT_LO: u32 = 0x4f;
pub const RF_LCK_CURVE_CNT_HI: u32 = 0x50;

/// `REG_TXPAUSE` (`rtl8192de/reg.h:229`).
pub const REG_TXPAUSE: u16 = 0x0522;

/// Continuous-TX status byte (`rtl8192de/phy.c:2533`, raw `0xd03` in
/// Linux; bits `0x70` mean continuous TX is active).
pub const REG_CONT_TX: u16 = 0x0d03;
/// Continuous-TX active bits in [`REG_CONT_TX`].
pub const CONT_TX_ACTIVE: u8 = 0x70;
/// Continuous-TX bits cleared while calibrating (`phy.c:2538`).
pub const CONT_TX_CLEAR: u8 = 0x8f;

/// RF AGC-core registers holding the per-path RF mode
/// (`rtl8192de/reg.h:1102/1104`).
pub const ROFDM0_XAAGCCORE1: u16 = 0x0c50;
pub const ROFDM0_XBAGCCORE1: u16 = 0x0c58;

/// RF mode value written back before restoring the original mode
/// (`rtl8192de/phy.c:2612`).
pub const RF_MODE_RESTORE: u8 = 0x50;

/// RF standby value written to RF_AC (`phy.c:2547`, `0x010000`).
pub const RF_AC_STANDBY: u32 = 0x0001_0000;
/// RF_SYN_G4 curve-index mask in the LCK reload (`phy.c:2495`).
pub const RELOAD_SYN_G4_MASK: u32 = 0x3f800;
/// RF_CHNLBW LC-calibration-begin bit (`phy.c:2557-2560`, `0x08000`).
pub const CHNLBW_LC_BEGIN: u32 = 0x08000;

/// `rtl92d_phy_lc_calibrate` scan wait bound (`phy.c:2637`): 2000 µs.
pub const SCAN_WAIT_US: u32 = 2000;
/// Scan-wait step (`phy.c:2638-2641`): `udelay(50)`.
pub const SCAN_STEP_US: u32 = 50;
/// LC poll timeout (`phy.c:2530`): 800 ms.
pub const POLL_TIMEOUT_MS: u16 = 800;
/// LC poll step (`phy.c:2568-2571`): `mdelay(50)`.
pub const POLL_STEP_MS: u16 = 50;
/// Channel-switch LCK wait bound (`phy.c:2842`): 1000 ms.
pub const SW_CHNL_LCK_WAIT_MS: u32 = 1000;
/// Channel-switch LCK wait step (`phy.c:2843`): `mdelay(50)`.
pub const SW_CHNL_LCK_STEP_MS: u32 = 50;
/// Dual-dual RF-ready poll bound (`hw.c:1006`): 10000 iterations.
pub const DUALPHY_POLL_ITERS: u32 = 10_000;
/// Dual-dual RF-ready poll step (`MAX_STALL_TIME`, `phy.h:24`): 50 µs.
pub const DUALPHY_POLL_STEP_US: u64 = 50;

/// `targetchnl_5g[221]` (Linux `rtl8192de/phy.c:109-156`).
pub const TARGETCHNL_5G: [u32; 221] = [
    0x06235, 0x0621c, 0x06203, 0x061ea, 0x061d1, 0x061b8, 0x0619f, 0x06186, 0x0616d, 0x06155,
    0x0613c, 0x06123, 0x0610b, 0x060f2, 0x060da, 0x060c2, 0x060bd, 0x06091, 0x06079, 0x06060,
    0x06048, 0x06030, 0x06018, 0x06000, 0x05fe8, 0x05fd0, 0x05fb8, 0x05fa0, 0x05f89, 0x05f71,
    0x05f59, 0x05f41, 0x05f2a, 0x05f12, 0x05efb, 0x05ee3, 0x05ecc, 0x05eb5, 0x05e9d, 0x05e86,
    0x05e6f, 0x05e57, 0x05e40, 0x05e29, 0x05e12, 0x05dfb, 0x05de4, 0x05dcd, 0x05db6, 0x05d9f,
    0x05d89, 0x05d72, 0x05d5b, 0x05d44, 0x05d2e, 0x05d17, 0x05d01, 0x05cea, 0x05cd4, 0x05cbd,
    0x05ca7, 0x05c91, 0x05c7a, 0x05c64, 0x05c4e, 0x05c38, 0x05c22, 0x05c0c, 0x05bf5, 0x05bdf,
    0x05bca, 0x05bb4, 0x05b9e, 0x05b88, 0x05b72, 0x05b5c, 0x05b47, 0x05b31, 0x05b1b, 0x05b06,
    0x05af0, 0x05adb, 0x05ac5, 0x05ab0, 0x05a9a, 0x05a85, 0x05a70, 0x05a5a, 0x05a45, 0x05a30,
    0x05a1b, 0x05a06, 0x059f1, 0x059db, 0x059c6, 0x059b2, 0x0599d, 0x05988, 0x05973, 0x0595e,
    0x05949, 0x05935, 0x05920, 0x0590b, 0x058f7, 0x058e2, 0x058cd, 0x058b9, 0x058a4, 0x05890,
    0x0587c, 0x05867, 0x05853, 0x0583f, 0x0582a, 0x05816, 0x05802, 0x057ee, 0x057da, 0x057c5,
    0x057b1, 0x0579d, 0x05789, 0x05776, 0x05762, 0x0574e, 0x05740, 0x05726, 0x05712, 0x056ff,
    0x056eb, 0x056d7, 0x056c4, 0x056b0, 0x0569d, 0x05689, 0x05676, 0x05662, 0x0564f, 0x0563b,
    0x05628, 0x05615, 0x05601, 0x055ee, 0x055db, 0x055c8, 0x055b5, 0x055a1, 0x0558e, 0x0557b,
    0x05568, 0x05555, 0x05542, 0x0552f, 0x0551d, 0x0550a, 0x054f7, 0x054e4, 0x054d1, 0x054bf,
    0x054ac, 0x05499, 0x05487, 0x05474, 0x05462, 0x0544f, 0x0543d, 0x0542a, 0x05418, 0x05405,
    0x053f3, 0x053e1, 0x053ce, 0x053bc, 0x053aa, 0x05398, 0x05385, 0x05373, 0x05361, 0x0534f,
    0x0533d, 0x0532b, 0x05319, 0x05307, 0x052f5, 0x052e3, 0x052d1, 0x052bf, 0x052ae, 0x0529c,
    0x0528a, 0x05278, 0x05267, 0x05255, 0x05243, 0x05232, 0x05220, 0x0520f, 0x051fd, 0x051ec,
    0x0644f, 0x06435, 0x0641b, 0x06401, 0x063e7, 0x063cd, 0x063b3, 0x06399, 0x0637f, 0x06366,
    0x0634c, 0x06332, 0x06319, 0x062ff, 0x062e6, 0x062cc, 0x062b3, 0x0629a, 0x06280, 0x06267,
    0x0624e,
];

/// `targetchnl_2g[14]` (Linux `rtl8192de/phy.c:158-161`, channels 1-14).
pub const TARGETCHNL_2G: [u32; 14] = [
    0x065e4, 0x065ae, 0x06578, 0x06543, 0x0650d, 0x064d8, 0x064a4, 0x0646f, 0x0643a, 0x06406,
    0x063d2, 0x0639e, 0x0636b, 0x062f0,
];

/// Legal 5 GHz channels (Linux `core.c:16-24` `channel5g[49]`).
pub const CHANNEL_5G: [u8; 49] = [
    36, 38, 40, 42, 44, 46, 48, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 116,
    118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159,
    161, 165, 167, 169, 171, 173, 175, 177,
];

/// LC-calibration state: the per-band curve-index tables Linux keeps
/// as `curveindex_5g[221]` / `curveindex_2g[14]` statics (phy.c:105-107)
/// plus the `lck_inprogress` flag (`rtl92d_phy_lc_calibrate`,
/// phy.c:2644/2655). The caller owns this struct and passes the
/// `in_progress` snapshot to [`super::channel::switch_channel`], which
/// waits it out before switching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lck {
    pub curveindex_5g: [u32; TARGET_CHNL_NUM_5G],
    pub curveindex_2g: [u32; TARGET_CHNL_NUM_2G],
    pub in_progress: bool,
}

impl Lck {
    pub fn new() -> Self {
        Self {
            curveindex_5g: [0; TARGET_CHNL_NUM_5G],
            curveindex_2g: [0; TARGET_CHNL_NUM_2G],
            in_progress: false,
        }
    }
}

impl Default for Lck {
    fn default() -> Self {
        Self::new()
    }
}

/// Inputs to [`lc_calibrate`] / [`lc_calibrate_sw`] beyond the
/// [`Lck`] state. `rf_type` selects the path count (2T2R = 2 paths,
/// 1T1R = 1, as `IS_92D_SINGLEPHY(version)` does in Linux);
/// `interface_index` is `rtlhal->interfaceindex` (0 = MAC0, 1 = MAC1);
/// `mode` is `rtlhal->macphymode` (the reload's dual-dual branches need
/// it); `current_channel` is `rtlphy->current_channel`; `band` is
/// `rtlhal->current_bandtype`; `init_ready` is `rtlpci->init_ready`,
/// which gates the LC-begin RF writes; `act_scanning` is the mac80211
/// scan flag the top level waits out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LcConfig {
    pub rf_type: RfType,
    pub mode: MacPhyMode,
    pub interface_index: u8,
    pub current_channel: u8,
    pub band: Band,
    pub init_ready: bool,
    pub act_scanning: bool,
}

/// Outcome of [`lc_calibrate`]: the scan wait actually spent, and the
/// per-path LC poll time in ms (Linux's `timecount`) plus whether the
/// poll timed out (BIT(11) never set; Linux proceeds regardless).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LcOutcome {
    pub scan_wait_us: u32,
    pub path_count: usize,
    pub poll_ms: [u16; 2],
    pub poll_timed_out: [bool; 2],
}

fn abs_diff(a: u32, b: u32) -> u32 {
    a.abs_diff(b)
}

/// `_rtl92d_is_legal_5g_channel` (`rtl8192de/phy.c:2422-2431`).
pub fn is_legal_5g_channel(channel: u8) -> bool {
    CHANNEL_5G.contains(&channel)
}

/// `_rtl92d_phy_calc_curvindex` (`rtl8192de/phy.c:2433-2459`): for each
/// target channel, the curve-count index `j` (of `2 * CV_CURVE_CNT`)
/// whose count is closest to the target; the first minimum wins (the
/// strict `<` comparison). On 5 GHz, channels outside [`CHANNEL_5G`]
/// are skipped and keep their previous index, as in Linux.
/// `targetchnl` / `curveindex` are the `TARGETCHNL_*` statics and the
/// matching [`Lck`] table; shorter slices truncate the walk.
pub fn calc_curvindex(
    targetchnl: &[u32],
    curvecount_val: &[u32; CV_CURVE_CNT * 2],
    is5g: bool,
    curveindex: &mut [u32],
) {
    for (i, (target, slot)) in targetchnl.iter().zip(curveindex.iter_mut()).enumerate() {
        if is5g && !is_legal_5g_channel((i + 1) as u8) {
            continue;
        }
        let mut smallest = u32::MAX;
        *slot = 0;
        for (j, count) in curvecount_val.iter().enumerate() {
            let diff = abs_diff(*target, *count);
            if diff < smallest {
                *slot = j as u32;
                smallest = diff;
            }
        }
    }
}

/// `_rtl92d_phy_enable_rf_env` (`rtl8192de/phy.c:1132-1157`): save the
/// RFENV control bits from the path's `rfintfs` register, then set
/// RFENV enable + output-high. Returns the saved value for
/// [`restore_rf_env`]. `BRFSI_RFENV` is `phy::BRFSI_RFENV` (`0x10`).
pub async fn enable_rf_env(io: &impl Io, path: Path) -> Result<u32, Error> {
    let regs = path.regs();
    let saved = if path == Path::A {
        phy::get_bb(io, regs.rfintfs, phy::BRFSI_RFENV)?
    } else {
        phy::get_bb(io, regs.rfintfs, phy::BRFSI_RFENV << 16)?
    };
    phy::set_bb(io, regs.rfintfe, phy::BRFSI_RFENV << 16, 0x1)?;
    io.delay_us(1).await;
    phy::set_bb(io, regs.rfintfo, phy::BRFSI_RFENV, 0x1)?;
    io.delay_us(1).await;
    Ok(saved)
}

/// `_rtl92d_phy_restore_rf_env` (`rtl8192de/phy.c:1168-1187`): restore
/// the RFENV control bits saved by [`enable_rf_env`].
pub fn restore_rf_env(io: &impl Io, path: Path, saved: u32) -> Result<(), Error> {
    let regs = path.regs();
    let mask = if path == Path::A {
        phy::BRFSI_RFENV
    } else {
        phy::BRFSI_RFENV << 16
    };
    phy::set_bb(io, regs.rfintfs, mask, saved)
}

/// The RF path the LCK reload writes (`_rtl92d_phy_reload_lck_setting`,
/// phy.c:2466-2471): path A on 5 GHz; on 2.4 GHz path B for single-PHY
/// (2T2R), path A otherwise.
pub fn reload_path(band: Band, rf_type: RfType) -> Path {
    match band {
        Band::On5Ghz => Path::A,
        Band::On2Ghz => {
            if rf_type == RfType::TwoT2R {
                Path::B
            } else {
                Path::A
            }
        }
    }
}

/// `_rtl92d_phy_reload_lck_setting` (`rtl8192de/phy.c:2461-2518`):
/// write the curve index for `channel` into RF_SYN_G4 (`0x3f800`) on
/// the reload path. The dual-dual branches enable the other PHY first
/// (and power it down after), with the RF-env save/restore around the
/// write; the `during_mac*init_radio*` flags are transient to this
/// call, as in Linux. `Err(Error::State)` when the channel has no
/// curve-index slot (channel 0, or past the band table).
pub async fn reload_lck_setting(
    io: &impl Io,
    lck: &Lck,
    band: Band,
    rf_type: RfType,
    mode: MacPhyMode,
    interface_index: u8,
    channel: u8,
) -> Result<(), Error> {
    let erfpath = reload_path(band, rf_type);
    let idx = usize::from(channel.checked_sub(1).ok_or(Error::State)?);
    match band {
        Band::On5Ghz => {
            let curve = *lck.curveindex_5g.get(idx).ok_or(Error::State)?;
            let mut need_powerdown = false;
            let mut during_mac1init_radioa = false;
            if mode == MacPhyMode::DualMacDualPhy && interface_index == 1 {
                need_powerdown = phy::enable_anotherphy(io, false).await?;
                during_mac1init_radioa = true;
            }
            let mut saved = 0;
            if need_powerdown {
                saved = enable_rf_env(io, erfpath).await?;
            }
            phy::set_rf(io, erfpath, RF_SYN_G4, RELOAD_SYN_G4_MASK, curve).await?;
            if need_powerdown {
                restore_rf_env(io, erfpath, saved)?;
            }
            if during_mac1init_radioa {
                phy::powerdown_anotherphy(io, false).await?;
            }
        }
        Band::On2Ghz => {
            let curve = *lck.curveindex_2g.get(idx).ok_or(Error::State)?;
            let mut need_powerdown = false;
            let mut during_mac0init_radiob = false;
            if mode == MacPhyMode::DualMacDualPhy && interface_index == 0 {
                need_powerdown = phy::enable_anotherphy(io, true).await?;
                during_mac0init_radiob = true;
            }
            let mut saved = 0;
            if need_powerdown {
                saved = enable_rf_env(io, erfpath).await?;
            }
            phy::set_rf(io, erfpath, RF_SYN_G4, RELOAD_SYN_G4_MASK, curve).await?;
            if need_powerdown {
                restore_rf_env(io, erfpath, saved)?;
            }
            if during_mac0init_radiob {
                phy::powerdown_anotherphy(io, true).await?;
            }
        }
    }
    Ok(())
}

/// `_rtl92d_phy_lc_calibrate_sw` (`rtl8192de/phy.c:2520-2622`), the
/// per-path LC calibration. `init_ready` gates the LC-begin RF writes
/// (SYN_G7 BIT(17) clear + CHNLBW `0x08000` set), exactly as Linux's
/// `rtlpci->init_ready` does. The poll returns `poll_timed_out` when
/// RF_SYN_G6 BIT(11) never sets within 800 ms; calibration proceeds
/// regardless, as in Linux. The curve-index tables in `lck` are
/// updated in place, and the LCK setting is reloaded for
/// `cfg.current_channel` at the end.
pub async fn lc_calibrate_sw(
    io: &impl Io,
    lck: &mut Lck,
    cfg: &LcConfig,
) -> Result<LcOutcome, Error> {
    let path_count = cfg.rf_type.paths();
    let tmpreg = io.read8(REG_CONT_TX)?;
    if tmpreg & CONT_TX_ACTIVE != 0 {
        io.write8(REG_CONT_TX, tmpreg & CONT_TX_CLEAR)?;
    } else {
        io.write8(REG_TXPAUSE, 0xff)?;
    }
    phy::set_bb(io, phy::RFPGA0_ANALOGPARAMETER4, 0xf00000, 0x0f)?;
    let mut outcome = LcOutcome {
        scan_wait_us: 0,
        path_count,
        poll_ms: [0; 2],
        poll_timed_out: [false; 2],
    };
    let mut rf_mode = [0u8; 2];
    for (index, mode) in rf_mode.iter_mut().enumerate().take(path_count) {
        let path = if index == 0 { Path::A } else { Path::B };
        let offset = if index == 0 {
            ROFDM0_XAAGCCORE1
        } else {
            ROFDM0_XBAGCCORE1
        };
        *mode = io.read8(offset)?;
        phy::set_rf(io, path, RF_AC, phy::RFREG_OFFSET_MASK, RF_AC_STANDBY).await?;
        if cfg.init_ready {
            phy::set_rf(io, path, RF_SYN_G7, 1 << 17, 0x0).await?;
            phy::set_rf(io, path, phy::RF_CHNLBW, CHNLBW_LC_BEGIN, 0x01).await?;
        }
        let mut timecount: u16 = 0;
        let mut u4tmp = phy::get_rf(io, path, RF_SYN_G6, phy::RFREG_OFFSET_MASK).await?;
        while u4tmp & (1 << 11) == 0 && timecount <= POLL_TIMEOUT_MS {
            io.delay_us(u64::from(POLL_STEP_MS) * 1000).await;
            timecount += POLL_STEP_MS;
            u4tmp = phy::get_rf(io, path, RF_SYN_G6, phy::RFREG_OFFSET_MASK).await?;
        }
        outcome.poll_ms[index] = timecount;
        outcome.poll_timed_out[index] = u4tmp & (1 << 11) == 0;
        let _ = phy::get_rf(io, path, RF_SYN_G4, phy::RFREG_OFFSET_MASK).await?;
        let mut curvecount_val = [0u32; CV_CURVE_CNT * 2];
        phy::set_rf(io, path, phy::RF_CHNLBW, CHNLBW_LC_BEGIN, 0x0).await?;
        for i in 0..CV_CURVE_CNT {
            let i = i as u32;
            phy::set_rf(io, path, RF_LCK_CURVE_SEL, 0x7f, i).await?;
            phy::set_rf(io, path, RF_LCK_CURVE_TRIG, phy::RFREG_OFFSET_MASK, 0x0).await?;
            let readval =
                phy::get_rf(io, path, RF_LCK_CURVE_CNT_LO, phy::RFREG_OFFSET_MASK).await?;
            curvecount_val[2 * i as usize + 1] = (readval & 0xfffe0) >> 5;
            let readval2 = phy::get_rf(io, path, RF_LCK_CURVE_CNT_HI, 0xffc00).await?;
            curvecount_val[2 * i as usize] = ((readval & 0x1f) << 10) | readval2;
        }
        if index == 0 && cfg.interface_index == 0 {
            calc_curvindex(
                &TARGETCHNL_5G,
                &curvecount_val,
                true,
                &mut lck.curveindex_5g,
            );
        } else {
            calc_curvindex(
                &TARGETCHNL_2G,
                &curvecount_val,
                false,
                &mut lck.curveindex_2g,
            );
        }
        phy::set_rf(io, path, RF_SYN_G7, 1 << 17, 0x1).await?;
    }
    for (index, mode) in rf_mode.iter().enumerate().take(path_count) {
        let offset = if index == 0 {
            ROFDM0_XAAGCCORE1
        } else {
            ROFDM0_XBAGCCORE1
        };
        io.write8(offset, RF_MODE_RESTORE)?;
        io.write8(offset, *mode)?;
    }
    if tmpreg & CONT_TX_ACTIVE != 0 {
        io.write8(REG_CONT_TX, tmpreg)?;
    } else {
        io.write8(REG_TXPAUSE, 0x00)?;
    }
    phy::set_bb(io, phy::RFPGA0_ANALOGPARAMETER4, 0xf00000, 0x00)?;
    reload_lck_setting(
        io,
        lck,
        cfg.band,
        cfg.rf_type,
        cfg.mode,
        cfg.interface_index,
        cfg.current_channel,
    )
    .await?;
    Ok(outcome)
}

/// `rtl92d_phy_lc_calibrate` (`rtl8192de/phy.c:2632-2657`): wait while
/// `act_scanning` (up to 2000 µs in 50 µs steps), then run the
/// per-path calibration with `lck.in_progress` set for the duration
/// (cleared again even on error, as Linux clears it after the call).
/// The path count follows the RF type: single-PHY (2T2R) calibrates 2
/// paths, dual-MAC (1T1R) 1 path. A set `act_scanning` snapshot waits
/// the full bound; the live caller re-checks the mac80211 flag before
/// calling, as `channel::configure` documents for its station path.
pub async fn lc_calibrate(io: &impl Io, lck: &mut Lck, cfg: &LcConfig) -> Result<LcOutcome, Error> {
    let mut waited: u32 = 0;
    while cfg.act_scanning && waited < SCAN_WAIT_US {
        io.delay_us(u64::from(SCAN_STEP_US)).await;
        waited += SCAN_STEP_US;
    }
    lck.in_progress = true;
    let result = lc_calibrate_sw(io, lck, cfg).await;
    lck.in_progress = false;
    let mut outcome = result?;
    outcome.scan_wait_us = waited;
    Ok(outcome)
}

/// The channel-switch LCK wait (`_rtl92d_phy_sw_chnl_step_by_step`,
/// phy.c:2842-2845): while LCK calibration is in progress, wait in
/// 50 ms steps up to 1000 ms. The flag is a snapshot owned by the
/// caller (`Lck.in_progress`, set/cleared by [`lc_calibrate`]); a set
/// snapshot waits the full bound, since the flag cannot be re-read
/// through the snapshot. [`super::channel::switch_channel`] calls this
/// first, mirroring Linux's order.
pub async fn wait_lck_clear(io: &impl Io, lck_inprogress: bool) -> Result<(), Error> {
    let mut timecount: u32 = 0;
    while lck_inprogress && timecount < SW_CHNL_LCK_WAIT_MS {
        io.delay_us(u64::from(SW_CHNL_LCK_STEP_MS) * 1000).await;
        timecount += SW_CHNL_LCK_STEP_MS;
    }
    Ok(())
}

/// The `rtl92de_hw_init` dual-dual RF-ready poll (`hw.c:1002-1024`):
/// poll RF `0x2a` (RF_SYN_G6) BIT(11) on path A every
/// `MAX_STALL_TIME` (50 µs) up to 10000 times. Returns `true` when the
/// bit sets (RF LO ready); `false` on timeout, in which case Linux
/// clears `init_ready` and aborts init.
pub async fn wait_dualphy_rf_ready(io: &impl Io) -> Result<bool, Error> {
    for _ in 0..DUALPHY_POLL_ITERS {
        io.delay_us(DUALPHY_POLL_STEP_US).await;
        let tmp = phy::get_rf(io, Path::A, RF_SYN_G6, phy::RFREG_OFFSET_MASK).await?;
        if tmp & (1 << 11) != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}
