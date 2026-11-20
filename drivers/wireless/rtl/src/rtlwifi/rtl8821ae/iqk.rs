// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE path-A IQ calibration and its DM trigger.
//!
//! Exact register effects of `rtl8821ae/phy.c::_rtl8821ae_phy_iq_calibrate`:
//! `_rtl8821ae_iqk_backup_{macbb,afe,rf}`, `_rtl8821ae_iqk_configure_mac`,
//! `_rtl8821ae_iqk_tx(RF90_PATH_A)` (LOK, TX IQK, RX-mode TXK, RX IQK, ten
//! rounds, pairwise averaging, `_rtl8821ae_iqk_{tx,rx}_fill_iqc`) and
//! `_rtl8821ae_iqk_restore_{rf,afe,macbb}`. [`LinkedInterval`] is
//! `dm.c::rtl8821ae_dm_iq_calibrate`: Linux runs IQK once, on the second
//! DM watchdog period after `link_state >= MAC80211_LINKED`.
//!
//! Scope and deliberate differences from Linux (documented in
//! `drivers/wireless/specification/rtlwifi.md`):
//!
//! - All three `current_chan_bw` branches: the post-LOK RF `0x18[11:10]`
//!   restore (40 MHz: 1, 80 MHz: 0, 20 MHz: untouched) and, at 80 MHz,
//!   Linux's `vdf_enable` paths: three-tone TX VDF (`0xce8[31]`, delay term
//!   `tx_dt` in `0xce8[29:16]`) and three-tone RX VDF (RX-mode TXK + RX IQK
//!   per tone, `rx_dt` in `0xce8[13:0]`, `0xce8[30]` on the third tone).
//!   The VDF `vdf_x`/`vdf_y` scratch is shared between the TX and RX loops
//!   exactly as Linux's stack arrays are, so a failed RX tone leaves the
//!   TX-loop sample in its slot.
//! - Backup sets: the register lists are the full intended Linux sets — 11
//!   MAC/BB registers including `0x82c` and the 12 listed AFE registers. The
//!   helper-scope `MACBB_REG_NUM 10` / `AFE_REG_NUM 14` defines in `phy.c`
//!   are never used for these lists; no register-0 access is made.
//! - Linux also reads RF path B into `rfb_backup`, which it never restores
//!   or uses; that read only rewrites the path-B HSSI read address and is
//!   omitted on this 1T1R chip.
//! - TX and RX-mode-TXK completion: Linux tests `~iqk_ready` and `~tx_fail`
//!   on 0/1 values, which is always true, so every TX one-shot is taken on
//!   its first attempt without a ready/fail gate. That is the behaviour
//!   validated on Linux hardware and is kept (the status reads are still
//!   issued). The RX check (`rx_fail == 0`, up to 10 retries) is real.
//! - Linux stores RX results at index `cal` but averages indices
//!   `0..rx_average`, reading uninitialised slots after any failed RX round.
//!   Here only the successful RX samples, in round order, are averaged.

use super::envelope::Width;
use super::phy::{get_bb, rf_read, set_bb, set_rf};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;
use alloc::vec::Vec;

/// Intended `backup_macbb_reg` (all 11 values, incl. `0x82c`).
pub const MACBB_REGS: [u16; 11] = [
    0xb00, 0x520, 0x550, 0x808, 0x90c, 0xc00, 0xc50, 0xe00, 0xe50, 0x838, 0x82c,
];
/// Intended `backup_afe_reg` (the 12 listed registers).
pub const AFE_REGS: [u16; 12] = [
    0xc5c, 0xc60, 0xc64, 0xc68, 0xc6c, 0xc70, 0xc74, 0xc78, 0xc7c, 0xc80, 0xc84, 0xcb8,
];
/// `backup_rf_reg` (path A).
pub const RF_REGS: [u32; 3] = [0x65, 0x8f, 0x00];
/// `cal_num`.
pub const CAL_NUM: usize = 10;
const RF_FULL: u32 = 0x000f_ffff;
const PAGE_SEL: u16 = 0x82c;
const PAGE_BIT: u32 = 1 << 31;
/// IQK result register and its 11-bit result field.
const IQK_RESULT: u16 = 0xd00;
const RESULT_FIELD: u32 = 0x07ff_0000;
/// One-shot settle (`mdelay(10)`).
const ONE_SHOT_US: u64 = 10_000;
/// VDF control register (page C1).
const VDF: u16 = 0xce8;
/// `tx_dt` / `rx_dt` divisors of `_rtl8821ae_iqk_tx`.
pub const TX_DT_DIV: i32 = 15708;
pub const RX_DT_DIV: i32 = 13823;

/// What `_rtl8821ae_iqk_{tx,rx}_fill_iqc` was asked to program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fill {
    /// Two rounds agreed; their average was filled.
    Matched { x: i32, y: i32 },
    /// Samples existed but no pair agreed: the identity `0x200, 0` was filled.
    Identity,
    /// No sample: Linux leaves the compensation register untouched.
    Untouched,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub tx: Fill,
    pub rx: Fill,
    /// Successful TX / RX rounds out of [`CAL_NUM`].
    pub tx_rounds: u8,
    pub rx_rounds: u8,
}

/// `dm.c::rtl8821ae_dm_iq_calibrate` watchdog counter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkedInterval(u8);

impl LinkedInterval {
    /// One DM watchdog period. Returns true exactly when Linux would run
    /// `rtl8821ae_phy_iq_calibrate`: the second linked period. Losing the link
    /// re-arms it. Linux only calls this when RF is on and firmware is not in
    /// power save (`rtl8821ae_dm_watchdog`); the caller applies that gate.
    pub fn tick(&mut self, linked: bool) -> bool {
        if !linked {
            self.0 = 0;
            return false;
        }
        if self.0 < 3 {
            self.0 += 1;
        }
        self.0 == 2
    }
    pub fn count(&self) -> u8 {
        self.0
    }
}

fn page(io: &impl Io, c1: bool) -> Result<(), Error> {
    set_bb(io, PAGE_SEL, PAGE_BIT, u32::from(c1))
}

fn w(io: &impl Io, at: u16, value: u32) -> Result<(), Error> {
    io.write32(at, value)?;
    Ok(())
}

/// Sign-extended 11-bit result (`get_bbreg(0xd00, 0x07ff0000) << 21 >> 21`
/// on a C `int`).
fn result(io: &impl Io, select: u32) -> Result<i32, Error> {
    w(io, 0xcb8, select)?;
    let raw = get_bb(io, IQK_RESULT, RESULT_FIELD)?;
    Ok(((raw << 21) as i32) >> 21)
}

/// `0x980` one-shot, 10 ms, `0xcb8 = 0`, then the (unconditional, see module
/// doc) `0xd00[10]` ready read.
async fn one_shot(io: &impl Io) -> Result<(), Error> {
    w(io, 0x980, 0xfa00_0000)?;
    w(io, 0x980, 0xf800_0000)?;
    io.delay_us(ONE_SHOT_US).await;
    w(io, 0xcb8, 0)?;
    let _ready = get_bb(io, IQK_RESULT, 1 << 10)?;
    Ok(())
}

/// `tx_dt[cal]` / `rx_dt[cal]` from the first two VDF tones' Y samples
/// (`_rtl8821ae_iqk_tx`). Linux keeps samples as `raw << 21`, so
/// `vdf_y >> 20` is twice the signed 11-bit value; C `int` division
/// truncates toward zero and `>> 1` is arithmetic, as in Rust.
pub fn vdf_dt(y0: i32, y1: i32, divisor: i32) -> i32 {
    let dt = 2 * y1 - 2 * y0;
    let dt = (16 * dt) * 10000 / divisor;
    (dt >> 1) + (dt & 1)
}

/// RX one-shot with Linux's real `rx_fail` check: up to 10 attempts, the
/// RX IQC reset to identity after each failure.
async fn rx_shot(io: &impl Io) -> Result<Option<(i32, i32)>, Error> {
    for _ in 0..10 {
        one_shot(io).await?;
        if get_bb(io, IQK_RESULT, 1 << 11)? == 0 {
            return Ok(Some((result(io, 0x0600_0000)?, result(io, 0x0800_0000)?)));
        }
        set_bb(io, 0xc10, 0x0000_03ff, 0x200 >> 1)?;
        set_bb(io, 0xc10, 0x03ff_0000, 0)?;
    }
    Ok(None)
}

/// TX-type one-shot: Linux's `~tx_fail` gate is always true.
async fn tx_shot(io: &impl Io) -> Result<(i32, i32), Error> {
    one_shot(io).await?;
    let _fail = get_bb(io, IQK_RESULT, 1 << 12)?;
    Ok((result(io, 0x0200_0000)?, result(io, 0x0400_0000)?))
}

async fn rf_all(io: &impl Io, rows: &[(u32, u32)]) -> Result<(), Error> {
    for &(offset, value) in rows {
        set_rf(io, offset, RF_FULL, value).await?;
    }
    Ok(())
}

const RXK1_RF: [(u32, u32); 3] = [(0x30, 0x30000), (0x31, 0x00029), (0x32, 0xd7ffb)];
const RXK_RF: [(u32, u32); 7] = [
    (0xef, 0x80000),
    (0x30, 0x30000),
    (0x31, 0x0002f),
    (0x32, 0xfffbb),
    (0x8f, 0x88001),
    (0x65, 0x931d8),
    (0xef, 0x00000),
];

/// RX-mode TXK RF setting (RXK step 1), page C.
async fn rxk1_rf(io: &impl Io, reg65: u32) -> Result<(), Error> {
    page(io, false)?;
    set_rf(io, 0xef, RF_FULL, 0x80000).await?;
    rf_all(io, &RXK1_RF).await?;
    rf_all(io, &[(0x65, reg65), (0x8f, 0x8a001), (0xef, 0x00000)]).await
}

/// RX IQK RF setting and the RX-mode TXK result loaded into `0x978`.
async fn rxk_rf(io: &impl Io, rxk_x: i32, rxk_y: i32) -> Result<(), Error> {
    page(io, false)?;
    rf_all(io, &RXK_RF).await?;
    set_bb(io, 0x978, 0x03ff_8000, rxk_x as u32 & 0x7ff)?;
    set_bb(io, 0x978, 0x0000_07ff, rxk_y as u32 & 0x7ff)?;
    set_bb(io, 0x978, 1 << 31, 1)?;
    set_bb(io, 0x97c, 1 << 31, 0)
}

/// `if (vdf_enable)` TX IQK: three tones on page C1, the third with the
/// `tx_dt` delay term. Returns the third tone's sample (`tx_x0[cal]`).
async fn tx_vdf(io: &impl Io, vdf: &mut [(i32, i32); 3]) -> Result<(i32, i32), Error> {
    for k in 0..3 {
        match k {
            0 => {
                w(io, 0xc80, 0x1800_8c38)?;
                w(io, 0xc84, 0x3800_8c38)?;
                set_bb(io, VDF, 1 << 31, 0)?;
            }
            1 => {
                set_bb(io, 0xc80, 1 << 28, 0)?;
                set_bb(io, 0xc84, 1 << 28, 0)?;
                set_bb(io, VDF, 1 << 31, 0)?;
            }
            _ => {
                let dt = vdf_dt(vdf[0].1, vdf[1].1, TX_DT_DIV);
                w(io, 0xc80, 0x1800_8c20)?;
                w(io, 0xc84, 0x3800_8c20)?;
                set_bb(io, VDF, 1 << 31, 1)?;
                set_bb(io, VDF, 0x3fff_0000, dt as u32 & 0x3fff)?;
            }
        }
        w(io, 0xcb8, 0x0010_0000)?;
        vdf[k] = tx_shot(io).await?;
    }
    Ok(vdf[2])
}

/// `if (vdf_enable == 1)` RX path: TX VDF off, three tones of RX-mode TXK
/// and RX IQK, the third with `rx_dt` and RX VDF on, then TX VDF back on.
/// Returns `(rx_x0[cal], rx_y0[cal])` when the third tone's RX IQK passed
/// (`rx0iqkok` is the last tone's outcome).
async fn rx_vdf(
    io: &impl Io,
    reg65: u32,
    vdf: &mut [(i32, i32); 3],
) -> Result<Option<(i32, i32)>, Error> {
    set_bb(io, VDF, 1 << 31, 0)?;
    let mut ok = false;
    for k in 0..3 {
        rxk1_rf(io, reg65).await?;
        set_bb(io, 0xcb8, 0xf, 0xd)?;
        w(io, 0x978, 0x2900_2000)?;
        w(io, 0x97c, 0xa900_2000)?;
        w(io, 0x984, 0x0046_a910)?;
        w(io, 0x90c, 0x0000_8000)?;
        w(io, 0xb00, 0x0300_0100)?;
        page(io, true)?;
        match k {
            0 => {
                w(io, 0xc80, 0x1800_8c38)?;
                w(io, 0xc84, 0x3800_8c38)?;
                set_bb(io, VDF, 1 << 30, 0)?;
            }
            1 => {
                w(io, 0xc80, 0x0800_8c38)?;
                w(io, 0xc84, 0x2800_8c38)?;
                set_bb(io, VDF, 1 << 30, 0)?;
            }
            _ => {
                let dt = vdf_dt(vdf[0].1, vdf[1].1, RX_DT_DIV);
                w(io, 0xc80, 0x1800_8c20)?;
                w(io, 0xc84, 0x3800_8c20)?;
                set_bb(io, VDF, 0x0000_3fff, dt as u32 & 0x3fff)?;
            }
        }
        w(io, 0xc88, 0x8216_03e0)?;
        w(io, 0xc8c, 0x6816_3e96)?;
        w(io, 0xcb8, 0x0010_0000)?;
        let (rxk_x, rxk_y) = tx_shot(io).await?;

        rxk_rf(io, rxk_x, rxk_y).await?;
        set_bb(io, 0xcb8, 0xf, 0xe)?;
        w(io, 0x90c, 0x0000_8000)?;
        w(io, 0x984, 0x0046_a911)?;
        page(io, true)?;
        set_bb(io, 0xc80, 1 << 29, 1)?;
        set_bb(io, 0xc84, 1 << 29, 0)?;
        w(io, 0xc88, 0x0214_0119)?;
        w(io, 0xc8c, 0x2816_0d00)?;
        if k == 2 {
            set_bb(io, VDF, 1 << 30, 1)?;
        }
        w(io, 0xcb8, 0x0010_0000)?;
        let sample = rx_shot(io).await?;
        if let Some(s) = sample {
            vdf[k] = s;
        }
        ok = sample.is_some();
    }
    set_bb(io, VDF, 1 << 31, 1)?;
    Ok(ok.then_some(vdf[2]))
}

/// One `while (cal < cal_num)` round of `_rtl8821ae_iqk_tx` (path A) at
/// `current_chan_bw` = `width`. Returns the TX sample and the RX sample if
/// RX IQK passed.
async fn round(
    io: &impl Io,
    band_5g: bool,
    width: Width,
) -> Result<((i32, i32), Option<(i32, i32)>), Error> {
    let reg65 = rf_read(io, 0x65).await?;
    // Path-A LOK: AFE all on.
    page(io, false)?;
    w(io, 0xc60, 0x7777_7777)?;
    w(io, 0xc64, 0x7777_7777)?;
    for at in [0xc68, 0xc6c, 0xc70, 0xc74, 0xc78, 0xc7c, 0xc80, 0xc84] {
        w(io, at, 0x1979_1979)?;
    }
    set_bb(io, 0xc00, 0xf, 0x4)?;
    set_bb(io, 0xc5c, 0x0700_0000, 0x7)?;
    set_rf(io, 0xef, RF_FULL, 0x80002).await?;
    set_rf(io, 0x18, 0x00c00, 0x3).await?;
    rf_all(
        io,
        &[
            (0x30, 0x20000),
            (0x31, 0x0003f),
            (0x32, 0xf3fc3),
            (0x65, 0x931d5),
            (0x8f, 0x8a001),
        ],
    )
    .await?;
    set_bb(io, 0xcb8, 0xf, 0xd)?;
    w(io, 0x90c, 0x0000_8000)?;
    w(io, 0xb00, 0x0300_0100)?;
    set_bb(io, 0xc94, 1, 1)?;
    w(io, 0x978, 0x2900_2000)?;
    w(io, 0x97c, 0xa900_2000)?;
    w(io, 0x984, 0x0046_2910)?;
    page(io, true)?;
    w(io, 0xc88, 0x8214_03f4)?;
    w(io, 0xc8c, if band_5g { 0x6816_3e96 } else { 0x2816_3e96 })?;
    w(io, 0xc80, 0x1800_8c10)?;
    w(io, 0xc84, 0x3800_8c10)?;
    w(io, 0xcb8, 0x0010_0000)?;
    w(io, 0x980, 0xfa00_0000)?;
    w(io, 0x980, 0xf800_0000)?;
    io.delay_us(ONE_SHOT_US).await;
    w(io, 0xcb8, 0)?;
    page(io, false)?;
    // Load LOK: RF 0x58[18:9] = RF 0x08[19:10].
    let lok = (rf_read(io, 0x08).await? & 0xffc00) >> 10;
    set_rf(io, 0x58, 0x7fe00, lok).await?;
    // `switch (current_chan_bw)`: 40 MHz restores RF 0x18[11:10] = 1,
    // 80 MHz = 0; 20 MHz has no case.
    match width {
        Width::W20 => {}
        Width::W40Above | Width::W40Below => set_rf(io, 0x18, 0x00c00, 0x1).await?,
        Width::W80 => set_rf(io, 0x18, 0x00c00, 0x0).await?,
    }
    page(io, true)?;

    // TX RF setting and TX IQK.
    page(io, false)?;
    rf_all(
        io,
        &[
            (0xef, 0x80000),
            (0x30, 0x20000),
            (0x31, 0x0003f),
            (0x32, 0xf3fc3),
            (0x65, 0x931d5),
            (0x8f, 0x8a001),
            (0xef, 0x00000),
        ],
    )
    .await?;
    w(io, 0x90c, 0x0000_8000)?;
    w(io, 0xb00, 0x0300_0100)?;
    set_bb(io, 0xc94, 1, 1)?;
    w(io, 0x978, 0x2900_2000)?;
    w(io, 0x97c, 0xa900_2000)?;
    w(io, 0x984, 0x0046_a910)?;
    page(io, true)?;
    w(io, 0xc88, 0x8214_03f1)?;
    w(io, 0xc8c, if band_5g { 0x4016_3e96 } else { 0x0016_3e96 })?;
    if width == Width::W80 {
        let mut vdf = [(0, 0); 3];
        let tx = tx_vdf(io, &mut vdf).await?;
        let rx = rx_vdf(io, reg65, &mut vdf).await?;
        page(io, false)?;
        set_rf(io, 0x65, RF_FULL, reg65).await?;
        return Ok((tx, rx));
    }
    w(io, 0xc80, 0x1800_8c10)?;
    w(io, 0xc84, 0x3800_8c10)?;
    w(io, 0xcb8, 0x0010_0000)?;
    let tx = tx_shot(io).await?;

    // RX-mode TXK (RXK step 1).
    rxk1_rf(io, reg65).await?;
    w(io, 0x90c, 0x0000_8000)?;
    w(io, 0xb00, 0x0300_0100)?;
    w(io, 0x984, 0x0046_a910)?;
    page(io, true)?;
    w(io, 0xc80, 0x1800_8c10)?;
    w(io, 0xc84, 0x3800_8c10)?;
    w(io, 0xc88, 0x8216_03e0)?;
    w(io, 0xcb8, 0x0010_0000)?;
    let (rxk_x, rxk_y) = tx_shot(io).await?;

    // RX IQK.
    rxk_rf(io, rxk_x, rxk_y).await?;
    w(io, 0x90c, 0x0000_8000)?;
    w(io, 0x984, 0x0046_a911)?;
    page(io, true)?;
    w(io, 0xc80, 0x3800_8c10)?;
    w(io, 0xc84, 0x1800_8c10)?;
    w(io, 0xc88, 0x0214_0119)?;
    w(io, 0xc8c, 0x2816_0d00)?;
    w(io, 0xcb8, 0x0010_0000)?;
    let rx = rx_shot(io).await?;
    page(io, false)?;
    set_rf(io, 0x65, RF_FULL, reg65).await?;
    Ok((tx, rx))
}

/// First pair of samples within `(-limit, limit)` on both axes, averaged as
/// Linux (`int` division truncating toward zero).
pub fn agree(samples: &[(i32, i32)], limit: i32) -> Option<(i32, i32)> {
    for (i, a) in samples.iter().enumerate() {
        for b in &samples[i + 1..] {
            let (dx, dy) = (a.0 - b.0, a.1 - b.1);
            if dx > -limit && dx < limit && dy > -limit && dy < limit {
                return Some(((a.0 + b.0) / 2, (a.1 + b.1) / 2));
            }
        }
    }
    None
}

/// `_rtl8821ae_iqk_tx_fill_iqc(RF90_PATH_A)`.
fn tx_fill(io: &impl Io, x: i32, y: i32) -> Result<(), Error> {
    page(io, true)?;
    w(io, 0xc90, 0x0000_0080)?;
    w(io, 0xcc4, 0x2004_0000)?;
    w(io, 0xcc8, 0x2000_0000)?;
    set_bb(io, 0xccc, 0x0000_07ff, y as u32)?;
    set_bb(io, 0xcd4, 0x0000_07ff, x as u32)
}

/// `_rtl8821ae_iqk_rx_fill_iqc(RF90_PATH_A)`.
fn rx_fill(io: &impl Io, x: i32, y: i32) -> Result<(), Error> {
    page(io, false)?;
    set_bb(io, 0xc10, 0x0000_03ff, (x >> 1) as u32)?;
    set_bb(io, 0xc10, 0x03ff_0000, (y >> 1) as u32)
}

async fn restore(
    io: &impl Io,
    macbb: &[u32; 11],
    afe: &[u32; 12],
    rf: &[u32; 3],
) -> Result<(), Error> {
    // _rtl8821ae_iqk_restore_rf (path A).
    page(io, false)?;
    for (offset, value) in RF_REGS.iter().zip(rf) {
        set_rf(io, *offset, RF_FULL, *value).await?;
    }
    // _rtl8821ae_iqk_restore_afe.
    page(io, false)?;
    for (at, value) in AFE_REGS.iter().zip(afe) {
        w(io, *at, *value)?;
    }
    page(io, true)?;
    for (at, value) in [
        (0xc80, 0),
        (0xc84, 0),
        (0xc88, 0),
        (0xc8c, 0x3c00_0000),
        (0xc90, 0x0000_0080),
        (0xc94, 0),
        (0xcc4, 0x2004_0000),
        (0xcc8, 0x2000_0000),
        (0xcb8, 0),
    ] {
        w(io, at, value)?;
    }
    // _rtl8821ae_iqk_restore_macbb.
    page(io, false)?;
    for (at, value) in MACBB_REGS.iter().zip(macbb) {
        w(io, *at, *value)?;
    }
    Ok(())
}

/// `_rtl8821ae_phy_iq_calibrate` on the currently programmed 20 MHz channel.
/// On an I/O error the backed-up state is still restored (best effort)
/// before the error is returned.
pub async fn calibrate(io: &impl Io, band_5g: bool) -> Result<Report, Error> {
    calibrate_at(io, band_5g, Width::W20).await
}

/// [`calibrate`] at the programmed `current_chan_bw` (20, 40 or 80 MHz).
pub async fn calibrate_at(io: &impl Io, band_5g: bool, width: Width) -> Result<Report, Error> {
    let mut macbb = [0u32; 11];
    let mut afe = [0u32; 12];
    let mut rf = [0u32; 3];
    page(io, false)?;
    for (slot, at) in macbb.iter_mut().zip(MACBB_REGS) {
        *slot = io.read32(at)?;
    }
    page(io, false)?;
    for (slot, at) in afe.iter_mut().zip(AFE_REGS) {
        *slot = io.read32(at)?;
    }
    page(io, false)?;
    for (slot, offset) in rf.iter_mut().zip(RF_REGS) {
        *slot = rf_read(io, offset).await?;
    }
    let outcome = run(io, band_5g, width).await;
    let restored = restore(io, &macbb, &afe, &rf).await;
    let report = outcome?;
    restored?;
    Ok(report)
}

async fn run(io: &impl Io, band_5g: bool, width: Width) -> Result<Report, Error> {
    // _rtl8821ae_iqk_configure_mac.
    page(io, false)?;
    io.write8(0x522, 0x3f)?;
    set_bb(io, 0x550, (1 << 11) | (1 << 3), 0)?;
    io.write8(0x808, 0)?;
    set_bb(io, 0x838, 0xf, 0xc)?;

    let mut tx = Vec::with_capacity(CAL_NUM);
    let mut rx = Vec::with_capacity(CAL_NUM);
    for _ in 0..CAL_NUM {
        let (t, r) = round(io, band_5g, width).await?;
        tx.push(t);
        if let Some(r) = r {
            rx.push(r);
        }
    }
    let tx_fill_kind = match agree(&tx, 3) {
        Some((x, y)) => {
            tx_fill(io, x, y)?;
            Fill::Matched { x, y }
        }
        None => {
            tx_fill(io, 0x200, 0)?;
            Fill::Identity
        }
    };
    let rx_fill_kind = if rx.is_empty() {
        Fill::Untouched
    } else if let Some((x, y)) = agree(&rx, 4) {
        rx_fill(io, x, y)?;
        Fill::Matched { x, y }
    } else {
        rx_fill(io, 0x200, 0)?;
        Fill::Identity
    };
    Ok(Report {
        tx: tx_fill_kind,
        rx: rx_fill_kind,
        tx_rounds: tx.len() as u8,
        rx_rounds: rx.len() as u8,
    })
}
