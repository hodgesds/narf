// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Inert register model for the antenna-diversity tick: reads return the
/// last written word (0 by default), writes are traced, every access
/// admitted; no RF or sequencing behaviour.
struct Model {
    words: Vec<u32>,
    trace: Vec<(u32, u32)>,
}
impl Model {
    fn new() -> Self {
        Self {
            words: alloc::vec![0; 0x20000 / 4],
            trace: Vec::new(),
        }
    }
    fn word(&self, address: u32) -> u32 {
        self.words[address as usize / 4]
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
        Ok(self.word(a))
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.words[a as usize / 4] = v;
        self.trace.push((a, v));
        Ok(())
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        Ok(())
    }
    async fn rf_read(&mut self, _: u8, _: u32, _: u32) -> Result<u32, Error> {
        Ok(0)
    }
    async fn rf_write(&mut self, _: u8, _: u32, _: u32, _: u32) -> Result<(), Error> {
        Ok(())
    }
    async fn begin(&mut self, _: crate::rtw89::rfk::Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn end(&mut self, _: crate::rtw89::rfk::Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        Ok(0)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
        Ok(())
    }
}

fn calibration(thermal: u8, pa: u8) -> factory_51::Calibration {
    factory_51::Calibration {
        thermal: 0,
        tssi_cck: [0; 6],
        tssi_mcs: [0; 19],
        tssi_trim: [0; 8],
        trim_programmed: false,
        thermal_trim: thermal,
        thermal_programmed: thermal != 255,
        pa_bias: pa,
        pa_programmed: pa != 255,
        gain_offset: [0; 5],
        offset_valid: false,
        gain_comp: [0; 5],
        comp_valid: false,
        adc_td: 0,
    }
}

fn smoke_rtw89_n51_dm_init_txrx_path_and_power_trim_follow_rtw8851b() -> TestResult {
    let gain = Gain::default();
    let cal = calibration(0x0b, 0x5a);
    let inputs = channel_51::Inputs {
        gain: &gain,
        calibration: &cal,
        bases: [0, 0],
    };
    // rtw8851b_bb_ctrl_rx_path(RF_A) prefix.
    let fields = txrx_path_fields(Profile::INITIAL, &inputs);
    let head = [
        (PHY + 0x49c4, 0xf, 1),
        (PHY + 0x49c0, 0x3_c000, 1),
        (PHY + 0x49c0, 0x3c_0000, 1),
        (PHY + 0x0d18, 0x300, 0),
        (PHY + 0x0d18, 0x60_0000, 0),
        (PHY + 0x0d80, 0x3fc0, 4),
        (PHY + 0x0d80, 0x1_c000, 0),
        (PHY + 0x0d80, 0x380_0000, 0),
    ];
    if fields[..8] != head {
        return TestResult::Fail("ctrl_rx_path RF_A prefix differs from rtw8851b");
    }
    // No efuse gain: set_gain_offset writes nothing; then RSTB 1/3, the
    // rx_nss 1 limits and R_MAC_SEL MAC_SEL_MOD 0.
    let tail = [
        (PHY + 0x58dc, 0xc000_0000, 1),
        (PHY + 0x58dc, 0xc000_0000, 3),
        (PHY + 0x0d18, 0x300, 0),
        (PHY + 0x0d18, 0x60_0000, 0),
        (PHY + 0x0d80, 0x1_c000, 0),
        (PHY + 0x0d80, 0x380_0000, 0),
        (PHY + 0x09a4, 0x1c, 0),
    ];
    if fields[8..] != tail {
        return TestResult::Fail("cfg_txrx_path tail differs from rtw8851b");
    }
    // Valid gain comp inserts the R_P0_AGC_RSVD byte between them.
    let mut comp = cal;
    comp.comp_valid = true;
    comp.gain_comp[0] = -3;
    let inputs = channel_51::Inputs {
        gain: &gain,
        calibration: &comp,
        bases: [0, 0],
    };
    let with = txrx_path_fields(Profile::INITIAL, &inputs);
    if with[8] != (PHY + 0x4acc, 0xff, (-12i32) as u32) || with.len() != fields.len() + 1 {
        return TestResult::Fail("2.4GHz set_gain_offset comp not in cfg_txrx_path");
    }
    // rtw8851b_power_trim: __thm_setting(0x0b) = (1 << 3) | 5 = 0xd on
    // path A; PA bias 0x5a -> 2G 0xa, 5G 0x5. Unprogrammed writes nothing.
    let expected = [
        (0, 0x43, 0xf_0000, 0xd),
        (0, 0x60, 0xf000, 0xa),
        (0, 0x60, 0xf_0000, 0x5),
    ];
    if power_trim_writes(&cal) != expected {
        return TestResult::Fail("power trim differs from rtw8851b_power_trim");
    }
    if !power_trim_writes(&calibration(255, 255)).is_empty() {
        return TestResult::Fail("unprogrammed trim wrote RF");
    }
    // set_txpwr_ctrl: B_AX_PWR_REF 0 then path-A OFDM/CCK reference words.
    let mut refs = Vec::new();
    let _ = radio_power_c::reference_51(|a, m, v| {
        refs.push((a, m, v));
        Ok(())
    });
    let word = (172 << 18) | (312 << 9);
    if refs
        != [
            (0xd200, 0x0fff_fc00, 0),
            (PHY + 0x5804, 0x07ff_ffff, word),
            (PHY + 0x5808, 0x07ff_ffff, word),
        ]
    {
        return TestResult::Fail("txpwr reference differs from rtw8851b_set_txpwr_ref");
    }
    // mac.c rtw89_mac_setup_phycap: one-path ant_diversity = rfe % 3 == 2.
    if !antenna_diversity(2) || !antenna_diversity(53) || antenna_diversity(1) {
        return TestResult::Fail("antenna diversity RFE rule differs from mac.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_dm_init_txrx_path_and_power_trim_follow_rtw8851b
);

fn smoke_rtw89_n51_radio_owner_starts_new() -> TestResult {
    let radio = Radio::default();
    if radio.state() != State::New
        || radio.channel().is_some()
        || radio.bases().is_some()
        || radio.epoch() != 0
        || radio.tracker().is_some()
        || radio.antdiv().is_some()
        || radio.antdiv_training()
        || radio.antdiv_period_ms() != 0
        || radio.init().results().is_some()
        || radio.rfk().state() != ChannelState::New
    {
        return TestResult::Fail("fresh RTL8851B radio owner is not New");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_radio_owner_starts_new
);

/// phy.c `rtw89_phy_antdiv_parse` / `_track` / `antdiv_work` through the
/// retained owner: PPDU observations feed the target stats, a target-RSSI
/// move starts training with the 30 ms collect step, the odd step swaps
/// to the aux antenna and programs ANTSEL, and the decision step picks
/// the antenna with the better EVM and programs it. The ANTSEL program
/// is `set_ant` for TX on RF_B (default AUX): CGCS_CTRL + RX_ORI +
/// TX_ORI on AUX, RX_ALT on MAIN (`R_P0_ANTSEL` 0x1586C = 0x21010).
fn smoke_rtw89_n51_antdiv_parse_and_periodic_track_drive_ant_sel() -> TestResult {
    use crate::rtw89::rx_packet::{AntDivObservation, PpduClass};
    // No retained owner: observations are dropped, ticks are no-ops.
    let mut radio = Radio::default();
    let mut io = Model::new();
    radio.parse_ppdu(AntDivObservation {
        class: PpduClass::Ofdm,
        rssi: 60,
        evm: 0,
    });
    if radio.antdiv_tick(&mut io).is_err()
        || radio.antdiv().is_some()
        || radio.antdiv_training()
        || radio.antdiv_period_ms() != 0
        || !io.trace.is_empty()
    {
        return TestResult::Fail("antenna diversity ran without a retained owner");
    }
    // Retained owner on RF_A.
    let mut radio = Radio {
        antdiv: Some(antdiv_51::AntDiv::new(antdiv_51::RF_A, antdiv_51::RF_A)),
        ..Radio::default()
    };
    let observe = |radio: &mut Radio, rssi: u8, evm: u8| {
        for _ in 0..5 {
            radio.parse_ppdu(AntDivObservation {
                class: PpduClass::Ofdm,
                rssi,
                evm,
            });
        }
    };
    // Target RSSI 60 vs previous 0 starts training: count-0 step opens
    // the collect gate for 30 ms and programs nothing.
    observe(&mut radio, 60, 0);
    if radio.antdiv_tick(&mut io).is_err()
        || !radio.antdiv_training()
        || radio.antdiv_period_ms() != 30
        || !io.trace.is_empty()
    {
        return TestResult::Fail("target RSSI move did not start antdiv training");
    }
    // Main window (RF_A, RSSI 70, EVM 5), then the odd step swaps to the
    // aux antenna for 110 ms and programs ANTSEL.
    observe(&mut radio, 70, 5);
    if radio.antdiv_tick(&mut io).is_err()
        || !radio.antdiv_training()
        || radio.antdiv_period_ms() != 110
        || io.word(0x1_586c) != 0x21010
        || radio.antdiv().unwrap().antenna_rx() != antdiv_51::RF_B
    {
        return TestResult::Fail("antdiv training step did not swap and program ANTSEL");
    }
    // First aux window (RF_B, RSSI 40, EVM 30): the even step re-opens
    // the collect gate for 30 ms.
    observe(&mut radio, 40, 30);
    if radio.antdiv_tick(&mut io).is_err()
        || !radio.antdiv_training()
        || radio.antdiv_period_ms() != 30
        || io.word(0x1_586c) != 0x21010
    {
        return TestResult::Fail("antdiv training step did not re-open collection");
    }
    // Second aux window: the decision step picks RF_B on EVM
    // (30 vs main 5, over the threshold 8) and programs it.
    observe(&mut radio, 40, 30);
    if radio.antdiv_tick(&mut io).is_err()
        || radio.antdiv_training()
        || radio.antdiv_period_ms() != 0
        || io.word(0x1_586c) != 0x21010
        || radio.antdiv().unwrap().antenna_rx() != antdiv_51::RF_B
        || radio.antdiv().unwrap().antenna_tx() != antdiv_51::RF_B
    {
        return TestResult::Fail("antdiv decision did not pick the better-EVM antenna");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_antdiv_parse_and_periodic_track_drive_ant_sel
);
