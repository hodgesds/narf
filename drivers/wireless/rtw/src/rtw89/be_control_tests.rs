// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use crate::rtw89::{completion_8922a::Route, rx_packet::C2h};
use alloc::{collections::VecDeque, vec};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Default)]
struct Model {
    packets: Vec<Vec<u8>>,
    queue: VecDeque<RoutedC2h>,
    reply: Option<Report>,
    count: usize,
    fail_at: Option<usize>,
    failed: bool,
    consumption_polls: usize,
    done_reply: Option<DoneReply>,
}
#[derive(Clone, Copy)]
enum DoneReply {
    Ok,
    WrongSequence,
    WrongFunction,
    Duplicate,
    ReceiveOnly,
    ReceiveDuplicate,
    Failed,
}
impl Model {
    fn access(&mut self) -> Result<(), power::Error> {
        if self.failed {
            return Err(power::Error::Access);
        }
        self.count += 1;
        if self.fail_at == Some(self.count) {
            self.failed = true;
            return Err(power::Error::Access);
        }
        Ok(())
    }
    fn good() -> Self {
        Self {
            reply: Some(Report {
                state: be_rfk::ReportState::Ok,
                version: 7,
            }),
            ..Self::default()
        }
    }
}
fn event(report: Report) -> RoutedC2h {
    let state = match report.state {
        be_rfk::ReportState::Start => 0,
        be_rfk::ReportState::Ok => 1,
        be_rfk::ReportState::Fail => 2,
        be_rfk::ReportState::Timeout => 3,
        be_rfk::ReportState::H2cCmdErr => 4,
    };
    RoutedC2h {
        route: Route::OutsrcPhy { class: 9, func: 0 },
        c2h: C2h::parse(vec![0x26, 0, 0, 0, 10, 0, 0, 0, state, report.version]).unwrap(),
        ack: None,
    }
}
impl Interface for Model {
    fn active(&mut self) -> Result<(), power::Error> {
        self.access()
    }
    fn submit(&mut self, bytes: &[u8]) -> Result<(), power::Error> {
        self.access()?;
        self.packets.push(bytes.to_vec());
        self.consumption_polls = 0;
        if let Some(report) = self.reply {
            self.queue.push_back(event(report));
        }
        if let Some(reply) = self.done_reply {
            let header = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
            let command = FramedH2c {
                seq: (header >> 24) as u8,
                cat: (header & 3) as u8,
                class: ((header >> 2) & 63) as u8,
                func: (header >> 8) as u8,
            };
            self.queue.push_back(done_event(command, reply));
            if matches!(reply, DoneReply::Duplicate) {
                self.queue.push_back(done_event(command, DoneReply::Ok));
            }
            if matches!(reply, DoneReply::ReceiveDuplicate) {
                self.queue
                    .push_back(done_event(command, DoneReply::ReceiveOnly));
            }
        }
        Ok(())
    }
    fn consumed(&mut self) -> Result<bool, power::Error> {
        self.access()?;
        self.consumption_polls += 1;
        Ok(self.consumption_polls >= 2)
    }
    fn receive(&mut self) -> Result<FirmwareRx, power::Error> {
        self.access()?;
        let messages: Vec<_> = self.queue.drain(..).collect();
        Ok(FirmwareRx {
            work: messages.len(),
            c2h: messages,
            ..Default::default()
        })
    }
}
fn done_event(mut command: FramedH2c, reply: DoneReply) -> RoutedC2h {
    if matches!(reply, DoneReply::WrongSequence) {
        command.seq = command.seq.wrapping_add(1);
    }
    if matches!(reply, DoneReply::WrongFunction) {
        command.func ^= 1;
    }
    let received = matches!(reply, DoneReply::ReceiveOnly | DoneReply::ReceiveDuplicate);
    let mut bytes = vec![0; 12];
    bytes[..4].copy_from_slice(&(1u32 | if received { 0 } else { 1 << 8 }).to_le_bytes());
    bytes[4..8].copy_from_slice(&12u32.to_le_bytes());
    let word = u32::from(command.cat)
        | (u32::from(command.class) << 2)
        | (u32::from(command.func) << 8)
        | if received {
            u32::from(command.seq) << 16
        } else {
            (u32::from(command.seq) << 24)
                | if matches!(reply, DoneReply::Failed) {
                    7 << 16
                } else {
                    0
                }
        };
    bytes[8..12].copy_from_slice(&word.to_le_bytes());
    let c2h = C2h::parse(bytes).unwrap();
    let ack = c2h.ack().unwrap();
    RoutedC2h {
        route: Route::Mac {
            class: 0,
            func: u8::from(!received),
        },
        c2h,
        ack,
    }
}

fn smoke_rtw8922a_native_requested_done_ack_needs_exact_fresh_success_and_rp() -> TestResult {
    let command = H2cCmd {
        cat: 2,
        class: 0x12,
        func: 3,
    };
    let mut control = Control::default();
    let mut io = Model {
        done_reply: Some(DoneReply::Ok),
        ..Default::default()
    };
    // SAFETY: actual framing/parser/control owner over inert retained RAM.
    let sent = unsafe { control.send_done(&mut io, command, &[1, 2], 5) };
    kt_assert!(sent.is_ok());
    kt_assert_eq!(io.consumption_polls, 2);
    kt_assert_eq!(control.state(), State::Idle);
    let hdr = u32::from_le_bytes(io.packets[0][28..32].try_into().unwrap());
    kt_assert_eq!(hdr & ((1 << 14) | (1 << 15)), 1 << 15);
    for mode in [
        DoneReply::WrongSequence,
        DoneReply::WrongFunction,
        DoneReply::Duplicate,
        DoneReply::ReceiveOnly,
        DoneReply::Failed,
    ] {
        let mut owner = Control::default();
        let mut model = Model {
            done_reply: Some(mode),
            ..Default::default()
        };
        // SAFETY: negative RAM-only command response; no device authority.
        kt_assert!(unsafe { owner.send_done(&mut model, command, &[], 5) }.is_err());
        kt_assert_eq!(owner.state(), State::Failed);
        let effects = model.packets.len();
        // SAFETY: a failed command owner must refuse any replay.
        kt_assert!(unsafe { owner.send_done(&mut model, command, &[], 5) }.is_err());
        kt_assert_eq!(model.packets.len(), effects);
    }
    let mut stale = Model {
        done_reply: Some(DoneReply::Ok),
        ..Default::default()
    };
    stale.queue.push_back(done_event(
        FramedH2c {
            seq: 0,
            cat: 2,
            class: 0x12,
            func: 3,
        },
        DoneReply::Ok,
    ));
    let mut owner = Control::default();
    // SAFETY: inherited response fixture must fail before a command issue.
    kt_assert!(unsafe { owner.send_done(&mut stale, command, &[], 5) }.is_err());
    kt_assert!(stale.packets.is_empty());
    // A duplicate delivered after the previous success is still unexpected;
    // it cannot be cached as receipt for a later RFK/no-ACK source command.
    let completed = sent.unwrap();
    io.queue.push_back(done_event(completed, DoneReply::Ok));
    let count = io.packets.len();
    // SAFETY: the original RAM-only transport and command owner stay owned;
    // its stale queued response must refuse before issuing the RFK command.
    // The model's report does not grant native command-semantic authority.
    kt_assert!(unsafe { control.send(&mut io, PRE, &[], Some(ReportKind::PreNtfy)) }.is_err());
    kt_assert_eq!(control.state(), State::Failed);
    kt_assert_eq!(io.packets.len(), count);
    let mut success = Model {
        done_reply: Some(DoneReply::Ok),
        ..Default::default()
    };
    let mut ticket = Control::default();
    // SAFETY: this fresh ticket exclusively owns the inert framing/response
    // model for the whole call; no device DMA or firmware execution is claimed.
    kt_assert!(unsafe { ticket.send_done(&mut success, command, &[], 5) }.is_ok());
    for at in 1..=success.count {
        let mut model = Model {
            done_reply: Some(DoneReply::Ok),
            fail_at: Some(at),
            ..Default::default()
        };
        let mut ticket = Control::default();
        // SAFETY: the fresh RAM-only transport retains all submitted bytes
        // and injects one checked failure. The owner must remain Failed and
        // no physical source, mapping or command authority is synthesized.
        kt_assert!(unsafe { ticket.send_done(&mut model, command, &[], 5) }.is_err());
        kt_assert_eq!(ticket.state(), State::Failed);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_native_requested_done_ack_needs_exact_fresh_success_and_rp
);
fn smoke_rtw8922a_native_requested_rec_ack_is_receipt_not_done() -> TestResult {
    let command = crate::rtw89::link_h2c_8922a::CMD_MACID_PAUSE_SLEEP;
    kt_assert_eq!((command.rec_ack, command.done_ack), (true, false));
    kt_assert_eq!(
        (
            crate::rtw89::link_h2c_8922a::CMD_DMAC_V2.rec_ack,
            crate::rtw89::link_h2c_8922a::CMD_DMAC_V2.done_ack
        ),
        (false, false)
    );
    let mut owner = Control::default();
    let mut io = Model {
        done_reply: Some(DoneReply::ReceiveOnly),
        ..Default::default()
    };
    // SAFETY: actual source framing/parser owner over inert command model.
    kt_assert!(unsafe { owner.send_rec(&mut io, command.cmd, &[0; 256], 5) }.is_ok());
    kt_assert_eq!(io.consumption_polls, 2);
    let header = u32::from_le_bytes(io.packets[0][28..32].try_into().unwrap());
    kt_assert_eq!(header & ((1 << 14) | (1 << 15)), 1 << 14);
    for mode in [DoneReply::Ok, DoneReply::ReceiveDuplicate] {
        let mut owner = Control::default();
        let mut io = Model {
            done_reply: Some(mode),
            ..Default::default()
        };
        // SAFETY: exact source REC-only command over the exclusively owned
        // inert response queue. Wrong-kind/duplicate receipts must poison
        // this ticket; neither modeled RP nor REC implies device execution.
        kt_assert!(unsafe { owner.send_rec(&mut io, command.cmd, &[0; 256], 5) }.is_err());
        kt_assert_eq!(owner.state(), State::Failed);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_native_requested_rec_ack_is_receipt_not_done
);
const PRE: H2cCmd = H2cCmd {
    cat: 2,
    class: 0xb,
    func: 8,
};
fn smoke_rtw8922a_native_control_literal_framing_single_report_and_sequence() -> TestResult {
    let mut control = Control::default();
    let mut model = Model::good();
    // SAFETY: inert command/DMA protocol model, no hardware or emission.
    let result = unsafe { control.send(&mut model, PRE, &[1, 2, 3], Some(ReportKind::PreNtfy)) };
    kt_assert_eq!(
        result,
        Ok(FramedH2c {
            seq: 0,
            cat: 2,
            class: 0xb,
            func: 8
        })
    );
    kt_assert_eq!(
        &model.packets[0][..24],
        &[11, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
    );
    kt_assert_eq!(
        &model.packets[0][24..],
        &[0x2e, 8, 0, 0, 11, 0, 0, 0, 1, 2, 3]
    );
    kt_assert!(matches!(
        control.state(),
        State::Awaiting {
            kind: ReportKind::PreNtfy,
            ..
        }
    ));
    kt_assert_eq!(
        control.await_report(&mut model, ReportKind::PreNtfy, 5),
        Ok(Report {
            state: be_rfk::ReportState::Ok,
            version: 7
        })
    );
    kt_assert_eq!(model.consumption_polls, 2);
    kt_assert_eq!(control.state(), State::Idle);
    model.reply = None;
    // Source MCC notification has no RFK report wait and no forced ACK.
    // SAFETY: private inert model; literal transport body only, no hardware.
    let mcc = unsafe {
        control.send(
            &mut model,
            H2cCmd {
                cat: 2,
                class: 0xa,
                func: 0xf,
            },
            &[4, 5],
            None,
        )
    };
    kt_assert_eq!(
        mcc,
        Ok(FramedH2c {
            seq: 1,
            cat: 2,
            class: 0xa,
            func: 0xf
        })
    );
    kt_assert_eq!(
        &model.packets[1][24..],
        &[0x2a, 0xf, 0, 1, 10, 0, 0, 0, 4, 5]
    );
    kt_assert_eq!(control.state(), State::Idle);
    // Neither an old report nor a duplicate can supply a later command fact.
    let mut stale = Model::good();
    stale.queue.push_back(event(stale.reply.unwrap()));
    let mut owner = Control::default();
    // SAFETY: stale-report negative model with no device.
    let result = unsafe { owner.send(&mut stale, PRE, &[], Some(ReportKind::PreNtfy)) };
    kt_assert_eq!(result, Err(Error::UnexpectedReport));
    kt_assert!(stale.packets.is_empty());
    let mut duplicate = Model::good();
    let mut owner = Control::default();
    // SAFETY: inert duplicate-report model.
    let sent = unsafe { owner.send(&mut duplicate, PRE, &[], Some(ReportKind::PreNtfy)) };
    kt_assert!(sent.is_ok());
    duplicate.queue.push_back(event(duplicate.reply.unwrap()));
    kt_assert_eq!(
        owner.await_report(&mut duplicate, ReportKind::PreNtfy, 5),
        Err(Error::UnexpectedReport)
    );
    kt_assert_eq!(owner.state(), State::Failed);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_native_control_literal_framing_single_report_and_sequence
);
fn smoke_rtw8922a_native_control_failure_report_timeout_and_no_replay() -> TestResult {
    let mut good = Model::good();
    let mut control = Control::default();
    // SAFETY: inert successful model used only to bound the failure matrix.
    let issued = unsafe { control.send(&mut good, PRE, &[0; 4], Some(ReportKind::PreNtfy)) };
    kt_assert!(issued.is_ok());
    let send_accesses = good.count;
    kt_assert!(control
        .await_report(&mut good, ReportKind::PreNtfy, 5)
        .is_ok());
    for at in 1..=good.count {
        let mut io = Model {
            fail_at: Some(at),
            ..Model::good()
        };
        let mut owner = Control::default();
        // SAFETY: independent inert first-error command model.
        let send = unsafe { owner.send(&mut io, PRE, &[0; 4], Some(ReportKind::PreNtfy)) };
        if at <= send_accesses {
            kt_assert!(send.is_err());
        } else {
            kt_assert!(send.is_ok());
            kt_assert!(owner.await_report(&mut io, ReportKind::PreNtfy, 5).is_err());
        }
        kt_assert_eq!(owner.state(), State::Failed);
        let effects = io.packets.len();
        // SAFETY: same failed inert owner; retry must be refused.
        let retry = unsafe { owner.send(&mut io, PRE, &[0; 4], Some(ReportKind::PreNtfy)) };
        kt_assert_eq!(retry, Err(Error::State));
        kt_assert_eq!(io.packets.len(), effects);
    }
    let mut fail = Model {
        reply: Some(Report {
            state: be_rfk::ReportState::Fail,
            version: 3,
        }),
        ..Model::default()
    };
    let mut owner = Control::default();
    // SAFETY: non-OK report model with no hardware.
    let sent = unsafe { owner.send(&mut fail, PRE, &[], Some(ReportKind::PreNtfy)) };
    kt_assert!(sent.is_ok());
    kt_assert_eq!(
        owner.await_report(&mut fail, ReportKind::PreNtfy, 5),
        fail.reply.ok_or(Error::State)
    );
    kt_assert_eq!(owner.state(), State::Failed); // still return report for source per-kind record
    let mut timeout = Model::default();
    let mut owner = Control::default();
    // SAFETY: no-report model; preserve actual source5ms timeout/refusal.
    let sent = unsafe { owner.send(&mut timeout, PRE, &[], Some(ReportKind::PreNtfy)) };
    kt_assert!(sent.is_ok());
    kt_assert_eq!(
        owner.await_report(&mut timeout, ReportKind::PreNtfy, 5),
        Err(Error::Io(power::Error::Timeout))
    );
    kt_assert_eq!(owner.state(), State::Failed);
    let mut io = Model::default();
    let mut owner = Control {
        issued: 256,
        ..Default::default()
    };
    // SAFETY: inert exhausted-sequence model.
    let sent = unsafe { owner.send(&mut io, PRE, &[], Some(ReportKind::PreNtfy)) };
    kt_assert_eq!(sent, Err(Error::Geometry));
    kt_assert!(io.packets.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_native_control_failure_report_timeout_and_no_replay
);
