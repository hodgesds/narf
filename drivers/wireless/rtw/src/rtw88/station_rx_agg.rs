// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux `main.c::rtw_watch_dog_work` -> `rtw_hci_dynamic_rx_agg(rtwdev,
//! tx_unicast_mbps >= 1 || rx_unicast_mbps >= 1)` for the retained station.
//! The period's unicast DATA byte counts (`RTW_TP_SHIFT`: bytes/2s -> Mbps)
//! select aggregation on or off; PCI's `dynamic_rx_agg` is a no-op and USB
//! programs `rtw_usb_dynamic_rx_agg_v1`. The register write is issued only
//! when the selection changes (the v1 sequence is idempotent, so the
//! programmed state equals Linux's per-period rewrite).
use super::*;

/// `main.h` `RTW_TP_SHIFT`.
const TP_SHIFT: u32 = 18;
/// `RTW_WATCH_DOG_DELAY_TIME` (2 s).
const PERIOD_MS: u64 = 2_000;

#[derive(Default)]
pub(super) struct RxAgg {
    next: u64,
    tx: u64,
    rx: u64,
    /// Last programmed selection; `None` until the first period.
    on: Option<bool>,
}
impl RxAgg {
    pub(super) fn tx(&mut self, len: usize) {
        self.tx = self.tx.saturating_add(len as u64);
    }
    pub(super) fn rx(&mut self, len: usize) {
        self.rx = self.rx.saturating_add(len as u64);
    }
    /// Close one elapsed period: the selection to program, if it changed.
    pub(super) fn period(&mut self, now: u64) -> Option<bool> {
        if now < self.next {
            return None;
        }
        self.next = now.saturating_add(PERIOD_MS);
        let enable = core::mem::take(&mut self.tx) >> TP_SHIFT >= 1
            || core::mem::take(&mut self.rx) >> TP_SHIFT >= 1;
        (self.on != Some(enable)).then_some(enable)
    }
    pub(super) fn programmed(&mut self, enable: bool) {
        self.on = Some(enable);
    }
}
impl State {
    /// One `rtw_hci_dynamic_rx_agg` period inside the station admission.
    /// Linux skips the whole watchdog while scanning
    /// (`RTW_FLAG_SCANNING`); the established/ready station does too.
    pub(super) async fn dynamic_rx_agg(&mut self, io: &mut impl Io) -> Result<(), Error> {
        // `rtw_pci_ops.dynamic_rx_agg` is NULL: PCI never enters (its MMIO
        // stream is unchanged).
        if !matches!(io.hci(), crate::rtw88::mac::Hci::Usb { .. }) {
            return Ok(());
        }
        if !self.established || !self.ready() || self.admission.closed() {
            return Ok(());
        }
        let now = self.now()?;
        let Some(enable) = self.rx_agg.period(now) else {
            return Ok(());
        };
        let admission = self.admission.clone();
        let result = firmware_transport::enclosed(|op| admission.run(op), async {
            io.station_allowed()?;
            Ok(io.dynamic_rx_agg(enable).await)
        })
        .await
        .and_then(|r| r)
        .map_err(Error::Native);
        match result {
            Ok(()) => {
                self.rx_agg.programmed(enable);
                Ok(())
            }
            Err(e) => {
                self.fail(io);
                Err(e)
            }
        }
    }
}
