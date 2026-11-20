//! Host rate adaptation (`rtl8xxxu/8188e.c`) regressions. Pure state, so
//! these run on both architectures without device fixtures.
use super::packet_codec::{self, Kind};
use super::rate_adaptation::{
    level, level_mask, signal, signal_to_snr, Level, RateAdaptation, Rssi,
};
use narf_kernel_test::{kernel_test_in, TestResult};

const HT_MASK: u32 = 0xff5 | 0xff << 12;
/// One TX_RPT2 item for MACID 0: retry[0] (u16), retry[1..4], drop.
fn item(ok: u16, retries: [u8; 4], drop: u8) -> [u8; 8] {
    let o = ok.to_le_bytes();
    [
        o[0], o[1], retries[0], retries[1], retries[2], retries[3], drop, 0,
    ]
}
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    f().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}

fn smoke_rtl8188eu_ra_drops_and_shortens_report_time() -> TestResult {
    check(|| {
        let mut ra = RateAdaptation::new();
        ra.update_rate_mask(HT_MASK, false);
        if ra.tx_rate() != 19 {
            return Err("init_all/update_rate_mask did not start at MCS7");
        }
        // All-drop report: nsc_down collapses, rate_down to MCS6 and the
        // report period steps down from 1200 ms (0x927c) to 1000 ms.
        let bad = item(0, [0; 4], 20);
        if ra.report2(8, 1, &bad) != Some(0x7a12) || ra.tx_rate() != 18 {
            return Err("first loss report did not rate_down/DECREASE_TIMING");
        }
        // ra_drop_after_down skips exactly one decision.
        if ra.report2(8, 1, &bad).is_some() || ra.tx_rate() != 18 {
            return Err("ra_drop_after_down did not hold one report");
        }
        if ra.report2(8, 1, &bad) != Some(0x61a8) || ra.tx_rate() != 17 {
            return Err("second decision did not step down again");
        }
        // Clean traffic: nsc_up exceeds n_threshold_high, rate_up resets the
        // report period to 200 ms.
        ra.report2(8, 1, &item(200, [0; 4], 0)); // drop_after_down
        if ra.report2(8, 1, &item(200, [0; 4], 0)) != Some(0x186a) || ra.tx_rate() != 18 {
            return Err("clean report did not rate_up/DEFAULT_TIMING");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/rate",
    smoke_rtl8188eu_ra_drops_and_shortens_report_time
);

fn smoke_rtl8188eu_ra_rejects_invalid_reports_and_clamps_mask() -> TestResult {
    check(|| {
        let mut ra = RateAdaptation::new();
        ra.update_rate_mask(0xff5, false);
        // A legacy peer never sees the init_all MCS7 decision.
        if ra.tx_rate() != 11 {
            return Err("legacy mask did not clamp the initial decision");
        }
        let bad = item(0, [0; 4], 20);
        // Item 0 invalid in macid_valid: no decision, only the first
        // minimum-report-time write (1200 ms).
        if ra.report2(8, 0, &bad) != Some(0x927c) || ra.tx_rate() != 11 {
            return Err("invalid MACID 0 report changed the decision");
        }
        // Short report (no complete item) and a zero-total item: no change.
        if ra.report2(7, 1, &bad).is_some() || ra.report2(8, 1, &item(0, [0; 4], 0)).is_some() {
            return Err("short or empty report rewrote REG_TX_REPORT_TIME");
        }
        if ra.tx_rate() != 11 {
            return Err("empty report changed the rate");
        }
        // Lowest rate is a floor.
        let mut low = RateAdaptation::new();
        low.update_rate_mask(0x1, false);
        for _ in 0..8 {
            low.report2(8, 1, &bad);
        }
        if low.tx_rate() != 0 {
            return Err("rate_down passed the lowest rate");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/rate",
    smoke_rtl8188eu_ra_rejects_invalid_reports_and_clamps_mask
);

fn smoke_rtl8188eu_ra_rssi_levels_and_masks() -> TestResult {
    check(|| {
        let mut phy = [0u8; 32];
        phy[4] = 0x80;
        if signal(&phy, 12, 0) != Some(-46) {
            return Err("OFDM pwdb_all signal");
        }
        phy[5] = 2 << 5 | 3;
        if signal(&phy, 0, 0) != Some(6) || signal(&phy, 0, 9) != Some(-19) {
            return Err("rtl8188e_cck_rssi TSMC/SMIC LNA/VGA");
        }
        if signal(&[], 12, 0).is_some() {
            return Err("missing PHY status produced a signal");
        }
        let mut rssi = Rssi::default();
        rssi.add(-46);
        rssi.add(-60);
        if rssi.signal() != -46 {
            return Err("DECLARE_EWMA(rssi, 10, 16) average");
        }
        if signal_to_snr(-46) != 54 || signal_to_snr(-120) != 0 || signal_to_snr(5) != 100 {
            return Err("rtl8xxxu_signal_to_snr clamp");
        }
        if level(Level::Init, -46) != Level::High
            || level(Level::High, -52) != Level::Mid
            || level(Level::Mid, -46) != Level::Mid
            || level(Level::Mid, -40) != Level::High
            || level(Level::Low, -76) != Level::Low
        {
            return Err("rtl8xxxu_refresh_rate_mask hysteresis");
        }
        if level_mask(Level::High, 0xfff, 0xff, true) != 0x000f0000
            || level_mask(Level::Mid, 0xfff, 0xff, true) != 0x000ff000
            || level_mask(Level::Low, 0xfff, 0xff, true) != 0x000ff005
            || level_mask(Level::High, 0xfff, 0, false) != 0xf00
            || level_mask(Level::Low, 0xfff, 0, false) != 0xff5
            || level_mask(Level::Low, 0xf, 0, false) != 0xd
            || level_mask(Level::Low, 0xff0, 0xff, true) != 0xff0 | 0xff << 12
        {
            return Err("BGN/BG/B/GN rate bitmaps");
        }
        let mut ra = RateAdaptation::new();
        ra.update_rate_mask(level_mask(Level::High, 0xfff, 0xff, true), false);
        ra.set_rssi(54);
        if ra.mask() != 0x000f0000 || ra.tx_rate() != 19 {
            return Err("high-level HT mask lost MCS7");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/rate",
    smoke_rtl8188eu_ra_rssi_levels_and_masks
);

fn smoke_rtl8188eu_ra_txdesc_enables_fallback_and_pt_stage() -> TestResult {
    check(|| {
        let mut frame = alloc::vec![0x88, 1, 0, 0];
        frame.extend_from_slice(&[2; 18]);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(&[0xaa; 16]);
        let mut packet =
            packet_codec::transmit_rate(&frame, Kind::Data, 17).map_err(|_| "codec")?;
        let dw4 = |p: &[u8]| u32::from_le_bytes(p[16..20].try_into().unwrap());
        if dw4(&packet) & (1 << 10) == 0 {
            return Err("fixed-rate DATA lost DISABLE_DATA_FB");
        }
        packet_codec::adaptive_fields(&mut packet, 5);
        let dw5 = u32::from_le_bytes(packet[20..24].try_into().unwrap());
        if dw4(&packet) & (1 << 10) != 0
            || (dw4(&packet) >> 15) & 7 != 5
            || dw4(&packet) & (1 << 8) == 0
            || dw5 != 0x0001ff00 | 17
        {
            return Err("adaptive DATA descriptor fields");
        }
        let xor = packet[..32]
            .chunks_exact(2)
            .fold(0u16, |v, b| v ^ u16::from_le_bytes([b[0], b[1]]));
        if xor != 0 {
            return Err("adaptive descriptor checksum");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/rate",
    smoke_rtl8188eu_ra_txdesc_enables_fallback_and_pt_stage
);
