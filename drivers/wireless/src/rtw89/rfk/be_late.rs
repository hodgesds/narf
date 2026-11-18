// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Source cold SCC `rtw8922a_rfk_init_late`: PRE/MCC, DACK58ms,
//! RXDCK128ms. Separate from the channel RFK receipt and never station-ready.
use super::{
    be_features::Features,
    be_notify::{self, Context},
    be_rfk::{self, Report, ReportKind, REPORT_KINDS},
    Error, Interface,
};
use crate::rtw89::operating_channel_c::Profile;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::rtw89) enum State {
    #[default]
    New,
    Busy,
    Calibrated,
}
#[derive(Default)]
pub(in crate::rtw89) struct Late {
    state: State,
    records: [Option<Report>; REPORT_KINDS],
}
impl Late {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtw89) fn fixture_packet_refusal_metadata() -> Self {
        Self {
            state: State::Calibrated,
            ..Self::default()
        }
    }
    pub(in crate::rtw89) fn state(&self) -> State {
        self.state
    }
    pub(in crate::rtw89) fn report(&self, kind: ReportKind) -> Option<Report> {
        self.records[kind as usize]
    }
    async fn record(
        &mut self,
        io: &mut impl Interface,
        kind: ReportKind,
        body: &[u8],
        timeout: u64,
    ) -> Result<(), Error> {
        let report = be_rfk::run(io, kind.func(), body, timeout).await?;
        self.records[kind as usize] = Some(report);
        be_rfk::check(report)?;
        Ok(())
    }
    /// # Safety
    /// Actual qualified cold SCC RTL8922A after all source prerequisites of
    /// its measured full or explicitly partial DM/RF program and
    /// rtw8922a_rfk_init software state initialization. N22P's native partial
    /// profile explicitly permits this packet-closed init-late divergence;
    /// it is not a complete Linux DM/HCI/RUNNING/BTC or station receipt.
    /// `profile` and RFE
    /// are actual source channel/factory facts; features belong to the current
    /// firmware. No SER/recovery or second producer. Every register/H2C/C2H
    /// effect must remain current-admitted; error/cancellation terminalizes
    /// the enclosing native radio and retains every DMA allocation.
    pub(in crate::rtw89) async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        profile: Profile,
        rfe: u8,
        features: Features,
        context: &Context,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        if crate::rtw89::channel_be::set_channel_rf_value(profile).is_none() {
            return Err(Error::Policy);
        }
        io.admit()?;
        self.state = State::Busy;
        if let Some(report) = be_notify::pre(io, features, context, rfe).await? {
            self.records[ReportKind::PreNtfy as usize] = Some(report);
            be_rfk::check(report)?;
        }
        be_notify::mcc(io, features, context).await?;
        self.record(io, ReportKind::Dack, &be_rfk::dack_body(0), 58)
            .await?;
        let band = profile.band() as u8;
        let bw = profile.width() as u8;
        let channel = profile.center();
        let v0 = be_rfk::rxdck_v0_body(0, band, bw, channel, false);
        let current = be_rfk::rxdck_body(0, band, bw, channel, false, false);
        self.record(
            io,
            ReportKind::RxDck,
            if features.rxdck_v0 {
                &v0[..]
            } else {
                &current[..]
            },
            128,
        )
        .await?;
        io.admit()?;
        self.state = State::Calibrated;
        Ok(())
    }
}
