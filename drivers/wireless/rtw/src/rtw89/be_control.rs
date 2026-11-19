// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Serialized native BE H2C/RFK-report control ownership over retained CH12.
//! Source: fw.c::h2c_pkt_set_hdr, pci.c::fwcmd_submit, phy.c::rfk_report_prep
//! and ::rfk_report_wait. The RFK report has no command tag; only one current
//! command can own its report. An unsolicited/duplicate report is refused.
use super::{
    checked_fwdl_8922a::FirmwareRx,
    completion_8922a::RoutedC2h,
    fwcmd_8922a::{self, FramedH2c, H2cCmd},
    h2c::H2cSeqAllocator,
    power,
    rfk::be_rfk::{self, Report, ReportKind},
};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Io(power::Error),
    State,
    Geometry,
    Memory,
    UnexpectedReport,
    UnexpectedAck,
    FirmwareReturn(u8),
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Io(e)
    }
}
pub(super) trait Interface {
    /// Original complete FW/System/closed TRX and current control authority;
    /// RF callers additionally require their live signed full-program grant.
    fn active(&mut self) -> Result<(), power::Error>;
    /// Contains descriptor+command bytes, owned before its first doorbell.
    fn submit(&mut self, bytes: &[u8]) -> Result<(), power::Error>;
    fn consumed(&mut self) -> Result<bool, power::Error>;
    fn receive(&mut self) -> Result<FirmwareRx, power::Error>;
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_control_tests.rs"]
mod tests;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    Idle,
    Issuing,
    Awaiting {
        kind: ReportKind,
        command: FramedH2c,
    },
    AwaitingAck {
        command: FramedH2c,
        kind: AckKind,
    },
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AckKind {
    Receive,
    Done,
}
pub(super) struct Control {
    state: State,
    seq: H2cSeqAllocator,
    issued: u16,
    events: Vec<RoutedC2h>,
    report: Option<Report>,
    ack: Option<Option<u8>>,
}
impl Default for Control {
    fn default() -> Self {
        Self {
            state: State::Idle,
            seq: H2cSeqAllocator::new(),
            issued: 0,
            events: Vec::new(),
            report: None,
            ack: None,
        }
    }
}
impl Control {
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn events(&self) -> &[RoutedC2h] {
        &self.events
    }
    pub(super) fn poison(&mut self) {
        self.state = State::Failed;
    }
    fn receive(&mut self, io: &mut impl Interface, expected: bool) -> Result<(), Error> {
        io.active()?;
        let batch = io.receive()?;
        for event in batch.c2h {
            if let Some(ack) = event.ack {
                if let State::AwaitingAck { command, kind } = self.state {
                    if !fwcmd_8922a::matches_ack(&ack, &command)
                        || ack.result.is_some() != (kind == AckKind::Done)
                        || self.ack.is_some()
                    {
                        return Err(Error::UnexpectedAck);
                    }
                    self.ack = Some(ack.result);
                    continue;
                } else {
                    // No-ACK source commands never acquire an ACK ticket.
                    // Includes a delayed duplicate after prior completion.
                    return Err(Error::UnexpectedAck);
                }
            }
            if let Some(report) = be_rfk::parse_c2h_report(&event.c2h.bytes) {
                if !expected || self.report.replace(report).is_some() {
                    return Err(Error::UnexpectedReport);
                }
            } else {
                if self.events.len() >= 1024 {
                    return Err(Error::Memory);
                }
                self.events.try_reserve(1).map_err(|_| Error::Memory)?;
                self.events.push(event);
            }
        }
        Ok(())
    }
    fn issue(
        &mut self,
        io: &mut impl Interface,
        command: H2cCmd,
        payload: &[u8],
        ack: Option<AckKind>,
    ) -> Result<FramedH2c, Error> {
        io.active()?;
        let length = 8usize.checked_add(payload.len()).ok_or(Error::Geometry)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| Error::Memory)?;
        bytes.resize(length, 0);
        let (framed, length) = fwcmd_8922a::frame_h2c(
            &self.seq,
            command,
            payload,
            ack == Some(AckKind::Receive),
            ack == Some(AckKind::Done),
            &mut bytes,
        )
        .ok_or(Error::Geometry)?;
        self.issued += 1; // Never replay a sequence after an uncertain effect.
        let desc = fwcmd_8922a::fwcmd_txdesc(length, false).ok_or(Error::Geometry)?;
        let mut packet = Vec::new();
        packet
            .try_reserve_exact(desc.len() + length)
            .map_err(|_| Error::Memory)?;
        packet.extend_from_slice(&desc);
        packet.extend_from_slice(&bytes[..length]);
        io.active()?;
        io.submit(&packet)?;
        Ok(framed)
    }
    /// Frame/send exactly one current command. BE never forces AX's receive
    /// ACK-every-fourth quirk. The native closed bootstrap retains every map
    /// regardless of acknowledgements; transport consumption is not execution.
    ///
    /// # Safety
    /// Caller has current authority for the actual command semantics on this
    /// exact original firmware/controller. RF-table/calibration commands need
    /// the full signed program/policy/coexistence grant at every effect, not
    /// the historical N22A-v1 subset record or a prior metadata check. Caller
    /// terminalizes the enclosing operation if its future is dropped.
    pub(super) unsafe fn send(
        &mut self,
        io: &mut impl Interface,
        command: H2cCmd,
        payload: &[u8],
        expected: Option<ReportKind>,
    ) -> Result<FramedH2c, Error> {
        if self.state != State::Idle {
            return Err(Error::State);
        }
        let rfk = command.cat == 2 && command.class == 0xb;
        if self.issued >= 256
            || payload.len() > fwcmd_8922a::MAX_PAYLOAD_LEN
            || rfk && expected.is_none()
            || expected.is_some_and(|kind| {
                command.cat != 2 || command.class != 0xb || command.func != kind.func()
            })
        {
            return Err(Error::Geometry);
        }
        self.state = State::Issuing;
        let result = (|| {
            self.receive(io, false)?;
            self.report = None;
            let framed = self.issue(io, command, payload, None)?;
            if let Some(kind) = expected {
                self.state = State::Awaiting {
                    kind,
                    command: framed,
                };
            } else {
                self.wait_consumed(io)?;
                self.receive(io, false)?;
                io.active()?;
                self.state = State::Idle;
            }
            Ok(framed)
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    /// Source commands that explicitly request DONE_ACK use this separate
    /// receipt path. RFK commands retain their report protocol and ACK bits.
    /// RP consumption and exact successful DONE_ACK are independently needed.
    /// # Safety
    /// Same original live command-semantic/current-grant contract as send.
    /// Caller retains all DMA and terminalizes error/cancellation; this cannot
    /// authorize a new command kind through a prior N22P scope.
    pub(super) unsafe fn send_done(
        &mut self,
        io: &mut impl Interface,
        command: H2cCmd,
        payload: &[u8],
        timeout_ms: u64,
    ) -> Result<FramedH2c, Error> {
        // SAFETY: unchanged exact source DONE/current ownership contract.
        unsafe { self.send_ack(io, command, payload, timeout_ms, AckKind::Done) }
    }
    /// Exact source REC_ACK only. Successful receipt proves matching REC and
    /// actual RP consumption, never firmware execution or pause application.
    /// # Safety
    /// Same exact original command-semantic authority and retention as send.
    pub(super) unsafe fn send_rec(
        &mut self,
        io: &mut impl Interface,
        command: H2cCmd,
        payload: &[u8],
        timeout_ms: u64,
    ) -> Result<FramedH2c, Error> {
        // SAFETY: caller supplies the actual REC-only source command.
        unsafe { self.send_ack(io, command, payload, timeout_ms, AckKind::Receive) }
    }
    unsafe fn send_ack(
        &mut self,
        io: &mut impl Interface,
        command: H2cCmd,
        payload: &[u8],
        timeout_ms: u64,
        kind: AckKind,
    ) -> Result<FramedH2c, Error> {
        if self.state != State::Idle {
            return Err(Error::State);
        }
        if self.issued >= 256
            || payload.len() > fwcmd_8922a::MAX_PAYLOAD_LEN
            || command.cat == 2 && command.class == 0xb
            || !(1..=1000).contains(&timeout_ms)
        {
            self.poison();
            return Err(Error::Geometry);
        }
        self.state = State::Issuing;
        let result = (|| {
            // No cached/unsolicited acknowledgement can qualify this issue.
            let old = self.events.len();
            self.receive(io, false)?;
            if self.events[old..].iter().any(|event| event.ack.is_some()) {
                return Err(Error::UnexpectedAck);
            }
            self.ack = None;
            let command = self.issue(io, command, payload, Some(kind))?;
            self.state = State::AwaitingAck { command, kind };
            let mut error = None;
            let done = narf_scheduler::responsive_spin_until(
                || {
                    let result = (|| {
                        io.active()?;
                        self.receive(io, false)?;
                        let consumed = io.consumed()?;
                        if let Some(Some(code)) = self.ack {
                            if code != 0 {
                                return Err(Error::FirmwareReturn(code));
                            }
                        }
                        Ok::<bool, Error>(consumed && self.ack.is_some())
                    })();
                    match result {
                        Ok(done) => done,
                        Err(e) => {
                            error = Some(e);
                            true
                        }
                    }
                },
                narf_time::Deadline::after_ms(timeout_ms),
            );
            if let Some(error) = error {
                return Err(error);
            }
            if !done {
                return Err(power::Error::Timeout.into());
            }
            io.active()?;
            self.state = State::Idle;
            Ok(command)
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    fn wait_consumed(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        let mut error = None;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let result = (|| {
                    io.active()?;
                    io.consumed()
                })();
                match result {
                    Ok(done) => done,
                    Err(e) => {
                        error = Some(e);
                        true
                    }
                }
            },
            narf_time::Deadline::after_us(1_000_000),
        );
        if let Some(error) = error {
            return Err(error.into());
        }
        if !done {
            return Err(power::Error::Timeout.into());
        }
        Ok(())
    }
    /// A source report cannot identify its command by kind or H2C sequence.
    /// Require the retained single-outstanding ticket, actual command RP
    /// consumption and exactly one fresh RFK report. Failure/timeout forbids
    /// all later commands; no old report is reused by a replacement attempt.
    pub(super) fn await_report(
        &mut self,
        io: &mut impl Interface,
        kind: ReportKind,
        timeout_ms: u64,
    ) -> Result<Report, Error> {
        if !matches!(self.state,State::Awaiting{kind:expected,..} if expected==kind) {
            self.poison();
            return Err(Error::State);
        }
        if !(1..=1000).contains(&timeout_ms) {
            self.poison();
            return Err(Error::Geometry);
        }
        let result = (|| {
            let mut error = None;
            let done = narf_scheduler::responsive_spin_until(
                || {
                    let result = (|| {
                        io.active()?;
                        self.receive(io, true)?;
                        let consumed = io.consumed()?;
                        Ok::<bool, Error>(consumed && self.report.is_some())
                    })();
                    match result {
                        Ok(done) => done,
                        Err(e) => {
                            error = Some(e);
                            true
                        }
                    }
                },
                narf_time::Deadline::after_us(timeout_ms * 1000),
            );
            if let Some(error) = error {
                return Err(error);
            }
            if !done {
                return Err(power::Error::Timeout.into());
            }
            io.active()?;
            let report = self.report.take().ok_or(Error::UnexpectedReport)?;
            self.state = if report.state == be_rfk::ReportState::Ok {
                State::Idle
            } else {
                State::Failed
            };
            Ok(report)
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
}
