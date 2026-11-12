// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A (BE) BB/RF/NCTL table application + power-trim application.
//!
//! The firmware-element half already exists: `radio_assets` admits
//! Rtl8922A and retains the BB / BB-gain / RADIO_A idx0 / RADIO_B idx1 /
//! NCTL tables (no static fallback), `radio_power_be::Plan` programs TX
//! power, and `efuse_be::BeFactory::power_trim` parses the trim. This
//! module is the application half: it turns the retained tables into the
//! exact ordered register programs Linux executes, and drives them over
//! the same `radio_init::Interface` the AX chips use.
//!
//! Linux order (torvalds/linux @ cbbddb6-era tree, local
//! `linux-rtw89-src` 067c5c2 where `phy.c:1885` / `phy.c:2005` match
//! the cited line numbers; `phy.c` `rtw89_phy_dm_init` at :8254):
//!
//! * `rtw89_phy_init_bb_reg` (`phy.c:1885`): BB table, then
//!   `rtw89_chip_init_txpwr_unit`, then BB-gain table, then
//!   `rtw89_phy_bb_reset`. For 8922A the middle two collapse:
//!   `.init_txpwr_unit` is NULL (`rtw8922a.c:3154`) and
//!   `rtw8922a_bb_reset` is an empty function (`rtw8922a.c:1923`),
//!   so the BB step is table + gain-decode only — recorded here, not
//!   invented as register writes.
//! * `rtw89_phy_init_rf_reg` (`phy.c:2005`): per RF path, the
//!   `rf_radio[path]` table (element idx == path for BE, so RADIO_A
//!   idx0 then RADIO_B idx1), each followed by its H2C RF-page upload
//!   (`rtw89_phy_config_rf_reg_fw`). `by_acv` is false: it is set only
//!   for RTL8922D.
//! * `rtw89_phy_init_rf_nctl` (`phy.c`): `rtw89_phy_preinit_rf_nctl_ax`
//!   with the P1 reset (the chip is not RTL8851B) and no second
//!   `R_IOQ_IQK_DPK` write (that is RTL8852B/BT-only), then the NCTL
//!   table; `rtw8922a_chip_info.nctl_post_table` is NULL
//!   (`rtw8922a.c:3246`), so there is no post-table step.
//! * `rtw89_phy_dm_init` continues with `rtw8922a_set_txpwr_ctrl`
//!   (which is only `rtw8922a_set_txpwr_ref`, `rtw8922a.c:2554`,
//!   both reference fields zero) and `rtw8922a_power_trim`
//!   (`rtw8922a.c:1042`): PA-bias trim then pad-bias trim, each the
//!   2G/5G nibble split of one trim byte onto `RR_BIASA` (`reg.h:8693`).
//!
//! Still NOT here (the BE DM owner that consumes this plan does not
//! exist yet): `rtw8922a_bb_sethw`, the PHYSTS/DIG/CFO/EDCCA DM
//! sub-inits, `rtw8922a_rfk_init`, and `rtw8922a_bb_cfg_txrx_path`
//! (channel-dependent `hal_reset` + TMAC path tables). The plan and
//! the `Board::new_be` identity are the table-application half of
//! #1906; the live DM owner is a follow-up.
use super::{
    efuse_be::PowerTrim,
    mac::ChipId,
    power,
    radio_assets::Assets,
    radio_gain::{self, Gain},
    radio_init,
    radio_table::{self, Pair},
};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Table(radio_table::Error),
    Gain(radio_gain::Error),
    Profile,
    Init(radio_init::Error),
    Register(power::Error),
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Register(e)
    }
}
/// `RR_BIASA` (`reg.h:8693`): the RF register both bias trims write.
pub(super) const RR_BIASA: u32 = 0x60;
/// `RR_BIASA_TXG_V1` `GENMASK(3, 0)` (`reg.h:8699`): PA-bias 2G nibble.
const RR_BIASA_TXG_V1: u32 = 0x000f;
/// `RR_BIASA_TXA_V1` `GENMASK(11, 8)` (`reg.h:8697`): PA-bias 5G nibble.
const RR_BIASA_TXA_V1: u32 = 0x0f00;
/// `RR_BIASD_TXG_V1` `GENMASK(7, 4)` (`reg.h:8698`): pad-bias 2G nibble.
const RR_BIASD_TXG_V1: u32 = 0x00f0;
/// `RR_BIASD_TXA_V1` `GENMASK(15, 12)` (`reg.h:8696`): pad-bias 5G nibble.
const RR_BIASD_TXA_V1: u32 = 0xf000;
/// `R_BE_PWR_REF_CTRL` (`reg.h:8468`): the `rtw8922a_set_txpwr_ref`
/// register. `B_BE_PWR_REF_CTRL_OFDM` is `GENMASK(9, 1)` = 0x3fe,
/// `B_BE_PWR_REF_CTRL_CCK` is `GENMASK(18, 10)` = 0x7fc00
/// (`reg.h:8469..8470`); Linux writes both fields zero.
pub(super) const TXPWR_REF_FIELDS: [(u32, u32, u32); 2] =
    [(0x11a20, 0x3fe, 0), (0x11a20, 0x7fc00, 0)];
/// The five selected BE table programs plus the decoded BB gain, in
/// `rtw89_phy_init_bb_reg` / `rtw89_phy_init_rf_reg` application order.
pub(super) struct Tables {
    bb: Vec<Pair>,
    gain_program: Vec<Pair>,
    gain: Gain,
    rf: [Vec<Pair>; 2],
    nctl: Vec<Pair>,
}
impl Tables {
    /// Select every BE program from the retained firmware tables for
    /// one (RFE, cut) headline, and decode the BB-gain program before
    /// any PHY write — the same preflight `radio_init::Init::prepare`
    /// performs for the AX chips. Refused unless the assets are the
    /// 8922A five-table set.
    pub(super) fn from_assets(assets: &Assets, rfe: u8, cut: u8) -> Result<Self, Error> {
        if assets.chip() != ChipId::Rtl8922A {
            return Err(Error::Profile);
        }
        let mut programs: [Vec<Pair>; 5] = core::array::from_fn(|_| Vec::new());
        for (i, program) in programs.iter_mut().enumerate() {
            *program = radio_table::program(assets.table(i).ok_or(Error::Profile)?, rfe, cut)
                .map_err(Error::Table)?;
        }
        // Validate the BB and NCTL programs before the first PHY write.
        radio_init::validate_bb(&programs[0]).map_err(Error::Init)?;
        radio_init::validate_bb(&programs[4]).map_err(Error::Init)?;
        let gain = Gain::decode(&programs[1], rfe).map_err(Error::Gain)?;
        let [bb, gain_program, rf_a, rf_b, nctl] = programs;
        Ok(Self {
            bb,
            gain_program,
            gain,
            rf: [rf_a, rf_b],
            nctl,
        })
    }
    pub(super) fn bb(&self) -> &[Pair] {
        &self.bb
    }
    pub(super) fn gain_program(&self) -> &[Pair] {
        &self.gain_program
    }
    pub(super) fn gain(&self) -> &Gain {
        &self.gain
    }
    pub(super) fn rf(&self, path: usize) -> &[Pair] {
        &self.rf[path]
    }
    pub(super) fn nctl(&self) -> &[Pair] {
        &self.nctl
    }
    /// H2C RF-page bytes for one path program (no RF write), rebuilt
    /// from the same retained signed tables — the `noio` half of
    /// `rtw89_phy_init_rf_reg`.
    pub(super) fn rf_pages(&self, path: usize) -> Result<Vec<u8>, Error> {
        radio_init::rf_pages(&self.rf[path]).map_err(Error::Init)
    }
}
/// `rtw8922a_pa_bias_trim` then `rtw8922a_pad_bias_trim`
/// (`rtw8922a.c:965..1040`), as (RF path, `RR_BIASA`, mask, value)
/// writes in Linux order: PA bias for both paths first (2G low nibble
/// onto `TXG_V1`, 5G high nibble onto `TXA_V1`), then pad bias for
/// both paths (2G onto `BIASD_TXG_V1`, 5G onto `BIASD_TXA_V1`).
/// Empty when the PHY-cap flag says the trims are unprogrammed:
/// Linux gates BOTH applications on the one `pg_pa_bias_trim` flag
/// (`phycap[0] != 0xFF` at 0x1700), so an unprogrammed board writes
/// nothing rather than a default bias.
pub(super) fn power_trim_writes(trim: &PowerTrim) -> Vec<(u8, u32, u32, u32)> {
    let mut out = Vec::new();
    if !trim.pg_pa_pad {
        return out;
    }
    for path in 0..2u8 {
        let pa = trim.pa_bias[usize::from(path)];
        out.push((path, RR_BIASA, RR_BIASA_TXG_V1, u32::from(pa & 0x0f)));
        out.push((path, RR_BIASA, RR_BIASA_TXA_V1, u32::from(pa >> 4)));
    }
    for path in 0..2u8 {
        let pad = trim.pad_bias[usize::from(path)];
        out.push((path, RR_BIASA, RR_BIASD_TXG_V1, u32::from(pad & 0x0f)));
        out.push((path, RR_BIASA, RR_BIASD_TXA_V1, u32::from(pad >> 4)));
    }
    out
}
/// Apply the selected BE tables in Linux order: BB program (the
/// TX-power-unit step is a NULL no-op and the BB reset is an empty
/// function for 8922A, so neither writes), RF path A then B with
/// their H2C page uploads, then the NCTL table after its BE preinit.
/// The BB-gain program is decoded by [`Tables::from_assets`], not
/// written here — it feeds later gain compensation, as in
/// `radio_init::Init::prepare` for the AX chips.
///
/// # Safety
/// Same contract as `radio_init::Init::prepare`: the caller owns the
/// full PHY aperture, current authority and exclusive radio/reset/
/// power ownership, and terminalizes on cancellation or failure.
pub(super) async unsafe fn apply_tables(
    io: &mut impl radio_init::Interface,
    tables: &Tables,
) -> Result<(), Error> {
    radio_init::bb(io, tables.bb()).await.map_err(Error::Init)?;
    // `rtw89_phy_init_rf_reg` walks `rf_radio[path]` in path order;
    // for BE the element idx equals the path (RADIO_A idx0, RADIO_B
    // idx1), unlike C's `{radiob, radioa}` static order.
    for path in 0..2usize {
        let program = tables.rf(path);
        for &Pair(address, value) in program {
            if address == 0xfe {
                io.delay_us(50_000).await;
            } else {
                io.radio_write(path as u8, address, 0xfffff, value)
                    .await
                    .map_err(Error::Init)?;
            }
        }
        for (page, bytes) in radio_init::rf_pages(program)
            .map_err(Error::Init)?
            .chunks(2000)
            .enumerate()
        {
            io.radio_page(path as u8, page as u8, bytes)
                .await
                .map_err(Error::Init)?;
        }
    }
    radio_init::nctl_be(io, tables.nctl())
        .await
        .map_err(Error::Init)?;
    Ok(())
}
/// Drive the [`power_trim_writes`] over the RF transport: the
/// application half of `rtw8922a_power_trim`.
///
/// # Safety
/// Same contract as [`apply_tables`].
pub(super) async unsafe fn apply_power_trim(
    io: &mut impl radio_init::Interface,
    trim: &PowerTrim,
) -> Result<(), Error> {
    for (path, address, mask, value) in power_trim_writes(trim) {
        io.radio_write(path, address, mask, value)
            .await
            .map_err(Error::Init)?;
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::vec;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};
    // Synthetic 8922A element container, built the same way as the
    // `radio_assets` BE fixture: MFW header + five aid-0 PHY elements
    // (BB id 2, GAIN id 3, RADIO_A id 4 idx0, RADIO_B id 5 idx1, NCTL
    // id 8) plus the retained TXPWR element id 9. Table bytes are
    // Linux-shaped (addr, value) pairs, not real firmware bytes: the
    // test proves selection/order/application, and the real tables
    // arrive only through the signed container.
    const MFW: usize = 16;
    const INFO: usize = 16;
    const HEADER: usize = 32;
    const SIZE: usize = 4;
    const AID: usize = 12;
    const INDEX: usize = 24;
    fn container() -> Vec<u8> {
        let mut bytes = vec![0; MFW + INFO + 16];
        bytes[0] = 255;
        bytes[1] = 1;
        bytes[MFW + 4..MFW + 8].copy_from_slice(&((MFW + INFO) as u32).to_le_bytes());
        bytes[MFW + 8..MFW + 12].copy_from_slice(&16u32.to_le_bytes());
        bytes
    }
    fn add(bytes: &mut Vec<u8>, id: u32, idx: u8, payload: &[u8]) {
        let start = bytes.len();
        bytes.resize(start + HEADER, 0);
        bytes[start..start + 4].copy_from_slice(&id.to_le_bytes());
        bytes[start + SIZE..start + SIZE + 4]
            .copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[start + AID..start + AID + 2].copy_from_slice(&0u16.to_le_bytes());
        bytes[start + INDEX] = idx;
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().div_ceil(16) * 16, 0);
    }
    fn pair(a: u32, v: u32) -> Vec<u8> {
        [a.to_le_bytes(), v.to_le_bytes()].concat()
    }
    fn assets() -> Assets {
        // BB: two writes + a 0xfe delay row; GAIN: one LNA row (kind 0,
        // band 0, path 0, subtype 0) decoding to lna[0][0][..4];
        // RF A: RR_BIASA write + one page entry; RF B: RR_BIASA write;
        // NCTL: one write.
        let mut bytes = container();
        let bb = [
            pair(0x100, 0x11111111),
            pair(0x104, 0x22222222),
            pair(0xfe, 0),
        ]
        .concat();
        add(&mut bytes, 2, 0, &bb);
        add(&mut bytes, 3, 0, &pair(0x00000000, 0x01020304));
        add(
            &mut bytes,
            4,
            0,
            &[pair(0x60, 0x5), pair(0x100, 0x00c0ffee)].concat(),
        );
        add(&mut bytes, 5, 1, &pair(0x60, 0x6));
        add(&mut bytes, 8, 0, &pair(0x100, 0xaaaa0000));
        add(&mut bytes, 9, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        Assets::parse_for(ChipId::Rtl8922A, &bytes).unwrap()
    }
    fn trim() -> PowerTrim {
        PowerTrim {
            thermal: [0, 0],
            pg_thermal: true,
            pa_bias: [0x53, 0xa6],
            pad_bias: [0x21, 0x94],
            pg_pa_pad: true,
        }
    }
    fn smoke_rtw89_be_tables_select_five_programs_and_decode_gain() -> TestResult {
        let assets = assets();
        let Ok(tables) = Tables::from_assets(&assets, 1, 0) else {
            return TestResult::Fail("8922A five-table set did not select");
        };
        if tables.bb()
            != [
                Pair(0x100, 0x11111111),
                Pair(0x104, 0x22222222),
                Pair(0xfe, 0),
            ]
            || tables.gain_program() != [Pair(0x00000000, 0x01020304)]
            || tables.gain().lna[0][0][..4] != [4, 3, 2, 1]
            || tables.rf(0) != [Pair(0x60, 0x5), Pair(0x100, 0x00c0ffee)]
            || tables.rf(1) != [Pair(0x60, 0x6)]
            || tables.nctl() != [Pair(0x100, 0xaaaa0000)]
        {
            return TestResult::Fail("8922A program selection or gain decode wrong");
        }
        // RF page bytes: only the >= 0x100 entry packs, as
        // `(address << 20) | data`, little-endian.
        let Ok(pages) = tables.rf_pages(0) else {
            return TestResult::Fail("8922A RF-A pages refused");
        };
        if pages != ((0x100u32 << 20) | 0x00c0ffee).to_le_bytes()
            || !tables.rf_pages(1).unwrap().is_empty()
        {
            return TestResult::Fail("8922A RF page packing wrong");
        }
        // A C container (RADIO_A idx1 / RADIO_B idx0) must not select
        // as a BE table set: idx must equal path.
        let mut bytes = container();
        add(&mut bytes, 2, 0, &pair(0x100, 1));
        add(&mut bytes, 3, 0, &pair(0, 1));
        add(&mut bytes, 4, 1, &pair(0x60, 1));
        add(&mut bytes, 5, 0, &pair(0x60, 1));
        add(&mut bytes, 8, 0, &pair(0x100, 1));
        if Tables::from_assets(&Assets::parse_for(ChipId::Rtl8852C, &bytes).unwrap(), 1, 0).is_ok()
        {
            return TestResult::Fail("C assets selected as BE tables");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_be_tables_select_five_programs_and_decode_gain
    );
    fn smoke_rtw89_be_power_trim_writes_follow_linux_nibble_split() -> TestResult {
        let writes = power_trim_writes(&trim());
        let expected: [(u8, u32, u32, u32); 8] = [
            (0, 0x60, 0x000f, 3),
            (0, 0x60, 0x0f00, 5),
            (1, 0x60, 0x000f, 6),
            (1, 0x60, 0x0f00, 0xa),
            (0, 0x60, 0x00f0, 1),
            (0, 0x60, 0xf000, 2),
            (1, 0x60, 0x00f0, 4),
            (1, 0x60, 0xf000, 9),
        ];
        if writes != expected {
            return TestResult::Fail(
                "8922A PA/pad bias trim did not split 2G-low/5G-high nibbles onto the V1 RR_BIASA fields",
            );
        }
        // Unprogrammed PHY-cap flag: both trims write nothing.
        let mut unprogrammed = trim();
        unprogrammed.pg_pa_pad = false;
        if !power_trim_writes(&unprogrammed).is_empty() {
            return TestResult::Fail("unprogrammed 8922A bias trim wrote a default bias");
        }
        // `rtw8922a_set_txpwr_ctrl` is only the zeroed reference fields.
        if TXPWR_REF_FIELDS != [(0x11a20, 0x3fe, 0), (0x11a20, 0x7fc00, 0)] {
            return TestResult::Fail("8922A TX-power reference fields wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_be_power_trim_writes_follow_linux_nibble_split
    );
    struct Model {
        words: Vec<u32>,
        bb_writes: Vec<(u32, u32)>,
        rf_writes: Vec<(u8, u32, u32, u32)>,
        pages: Vec<(u8, u8, Vec<u8>)>,
        delays: Vec<u64>,
        now: u64,
    }
    impl Model {
        fn new() -> Self {
            Self {
                words: vec![0; 0x20000 / 4],
                bb_writes: Vec::new(),
                rf_writes: Vec::new(),
                pages: Vec::new(),
                delays: Vec::new(),
                now: 0,
            }
        }
    }
    impl power::Io for Model {
        fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
            Err(power::Error::Access)
        }
        fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
            Err(power::Error::Access)
        }
        fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
            Ok(self.words[a as usize / 4])
        }
        fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
            Err(power::Error::Access)
        }
        fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
            Err(power::Error::Access)
        }
        fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
            self.words[a as usize / 4] = v;
            self.bb_writes.push((a, v));
            Ok(())
        }
        fn now_us(&self) -> u64 {
            self.now
        }
        async fn delay_us(&mut self, us: u64) {
            self.delays.push(us);
            self.now += us;
        }
        async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
            Err(power::Error::Unsupported)
        }
    }
    impl radio_init::Interface for Model {
        async fn radio_write(
            &mut self,
            path: u8,
            address: u32,
            mask: u32,
            value: u32,
        ) -> Result<(), radio_init::Error> {
            self.rf_writes.push((path, address, mask, value));
            Ok(())
        }
        async fn radio_page(
            &mut self,
            path: u8,
            page: u8,
            bytes: &[u8],
        ) -> Result<(), radio_init::Error> {
            self.pages.push((path, page, bytes.to_vec()));
            Ok(())
        }
    }
    fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
        let mut f = pin!(f);
        match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }
    fn smoke_rtw89_be_apply_tables_and_trim_drive_linux_order() -> TestResult {
        let tables = Tables::from_assets(&assets(), 1, 0).unwrap();
        let mut io = Model::new();
        // SAFETY: fixture-owned model; no real hardware, no live owner.
        let applied = ready(unsafe { apply_tables(&mut io, &tables) });
        if applied != Some(Ok(())) {
            return TestResult::Fail("8922A table application failed on the fixture");
        }
        // BB first: the two BB writes at the PHY aperture, in order.
        if io.bb_writes[..2] != [(0x10100, 0x11111111), (0x10104, 0x22222222)] {
            return TestResult::Fail("8922A BB program not written first at the PHY aperture");
        }
        // RF A (idx0 == path 0) before RF B, each with the full-field
        // mask, then one H2C page per path that has page entries.
        if io.rf_writes[..2] != [(0, 0x60, 0xfffff, 0x5), (0, 0x100, 0xfffff, 0x00c0ffee)]
            || io.rf_writes[2] != (1, 0x60, 0xfffff, 0x6)
            || io.pages.len() != 1
            || io.pages[0].0 != 0
            || io.pages[0].2 != ((0x100u32 << 20) | 0x00c0ffee).to_le_bytes()
        {
            return TestResult::Fail("8922A RF A/B order or H2C page upload wrong");
        }
        // NCTL last: BE preinit set-bits (0x10c60, 0x10c6c, 0x158ac,
        // 0x178ac — no second 0x10c60 write), the 0x18000 = 8 config
        // write, the 0x18080 poll write, then the NCTL table write.
        let preinit: Vec<(u32, u32)> = io
            .bb_writes
            .iter()
            .copied()
            .filter(|(a, _)| matches!(a, 0x10c60 | 0x10c6c | 0x158ac | 0x178ac | 0x18000 | 0x18080))
            .collect();
        if preinit
            != [
                (0x10c60, 3),
                (0x10c6c, 1),
                (0x158ac, 0x08000000),
                (0x178ac, 0x08000000),
                (0x18000, 8),
                (0x18080, 4),
            ]
            || io.bb_writes.last() != Some(&(0x10100, 0xaaaa0000))
            || io.delays != [50_000, 1]
        {
            return TestResult::Fail("8922A NCTL preinit/poll/table order wrong");
        }
        // Power trim after the tables: PA then pad, path A then B.
        let mut io = Model::new();
        // SAFETY: fixture-owned model; no real hardware, no live owner.
        let trimmed = ready(unsafe { apply_power_trim(&mut io, &trim()) });
        if trimmed != Some(Ok(()))
            || io.rf_writes
                != [
                    (0, 0x60, 0x000f, 3),
                    (0, 0x60, 0x0f00, 5),
                    (1, 0x60, 0x000f, 6),
                    (1, 0x60, 0x0f00, 0xa),
                    (0, 0x60, 0x00f0, 1),
                    (0, 0x60, 0xf000, 2),
                    (1, 0x60, 0x00f0, 4),
                    (1, 0x60, 0xf000, 9),
                ]
        {
            return TestResult::Fail("8922A power-trim RF writes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_be_apply_tables_and_trim_drive_linux_order
    );
}
