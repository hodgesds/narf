// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure `rtlwifi/base.c::rtl_watchdog_wq_callback` four-period traffic
//! arithmetic. Hardware causes and frame admission remain chip-owned.

/// Source `link_info.{busytraffic,tx_busy_traffic,rx_busy_traffic}`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::rtlwifi) struct Traffic {
    pub(in crate::rtlwifi) busy: bool,
    pub(in crate::rtlwifi) tx_busy: bool,
    pub(in crate::rtlwifi) rx_busy: bool,
}
/// Actual current event counters and the four source period slots. A TX
/// observation is an actual source data-queue DOK cause, never a doorbell,
/// generic host DD or an on-air ACK. RX is good unicast DATA only.
#[derive(Debug, Default)]
pub(in crate::rtlwifi) struct History {
    tx: u32,
    rx: u32,
    tx_periods: [u32; 4],
    rx_periods: [u32; 4],
}
impl History {
    pub(in crate::rtlwifi) fn observe_tx_dok(&mut self, causes: u32) {
        self.tx = self.tx.saturating_add(causes);
    }
    pub(in crate::rtlwifi) fn observe_unicast_data_rx(&mut self) {
        self.rx = self.rx.saturating_add(1);
    }
    /// Source shifts only for a linked station. The history and current
    /// counters stay owned across later hardware failure; this is no receipt.
    pub(in crate::rtlwifi) fn snapshot(&mut self, linked: bool) -> Traffic {
        if !linked {
            return Traffic::default();
        }
        self.tx_periods.copy_within(1..4, 0);
        self.rx_periods.copy_within(1..4, 0);
        self.tx_periods[3] = self.tx;
        self.rx_periods[3] = self.rx;
        let tx = self.tx_periods.iter().map(|v| u64::from(*v)).sum::<u64>() / 4;
        let rx = self.rx_periods.iter().map(|v| u64::from(*v)).sum::<u64>() / 4;
        let busy = rx > 100 || tx > 100;
        Traffic {
            busy,
            // The source's TX-heavy branch assigns false. Preserve that
            // observable quirk; do not silently replace it with tx>rx.
            tx_busy: false,
            rx_busy: busy && rx > tx,
        }
    }
    /// Source tail resets these only after the watchdog work.
    pub(in crate::rtlwifi) fn finish_period(&mut self) {
        self.tx = 0;
        self.rx = 0;
    }
}

#[cfg(any(test, feature = "kernel-test"))]
fn smoke_rtlwifi_source_four_period_traffic_retains_history() -> narf_kernel_test::TestResult {
    use narf_kernel_test::{kt_assert, kt_assert_eq, TestResult};
    let mut history = History::default();
    history.observe_tx_dok(404);
    kt_assert_eq!(history.snapshot(false), Traffic::default());
    kt_assert_eq!(
        history.snapshot(true),
        Traffic {
            busy: true,
            tx_busy: false,
            rx_busy: false
        }
    );
    history.finish_period();
    // Four-slot mean retains a source period after current counters reset.
    for _ in 0..3 {
        kt_assert!(history.snapshot(true).busy);
        history.finish_period();
    }
    kt_assert!(!history.snapshot(true).busy);
    for _ in 0..404 {
        history.observe_unicast_data_rx();
    }
    let sample = history.snapshot(true);
    kt_assert!(sample.busy && sample.rx_busy && !sample.tx_busy);
    TestResult::Pass
}
#[cfg(any(test, feature = "kernel-test"))]
narf_kernel_test::kernel_test_in! {"drivers/wireless/rtlwifi",smoke_rtlwifi_source_four_period_traffic_retains_history}
