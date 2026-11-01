//! One BMG PCODE port owner for discovery and package PL1 transactions.
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad xe_pcode.c,
//! xe_pcode_api.h and xe_hwmon.c. One bounded post OR poll per service.
//!
//! intel_gpu::probe returns GT-only probe_discrete before constructing the
//! integrated display Controller. Existing intel_gpu_pcode callers belong to
//! integrated modeset::program_watermarks; GuC/SLPC/dGPU PM use no PCODE port.
//! Future dGPU PCODE clients must join this owner before being admitted.

use super::Io;

pub(super) const MAILBOX: u64 = 0x138124;
pub(super) const DATA0: u64 = 0x138128;
pub(super) const DATA1: u64 = 0x13812c;
const READY: u32 = 1 << 31;
const TIMEOUT_NS: u64 = 1_000_000; // xe_pcode_read and PL_WRITE_MBX_TIMEOUT_MS

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    Access,
    ForeignBusy,
    Identity,
    Timeout,
    Status(u8),
    Data,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Client {
    Fan,
    Thermal,
    Power,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Reply {
    None,
    One,
    Two,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Command {
    pub(super) client: Client,
    pub(super) word: u32,
    pub(super) input: [u32; 2],
    pub(super) reply: Reply,
}
#[derive(Clone, Copy, Debug)]
struct Pending {
    command: Command,
    posted_at: u64,
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Mailbox {
    pending: Option<Pending>,
    fault: Option<Fault>,
}
impl Mailbox {
    pub(super) fn available(&self) -> bool {
        self.pending.is_none() && self.fault.is_none()
    }
    pub(super) fn fault(&self) -> Option<Fault> {
        self.fault
    }
    pub(super) fn access_lost(&mut self) {
        self.fault = Some(Fault::Access);
        self.pending = None;
    }
    pub(super) fn step(
        &mut self,
        next: Option<Command>,
        now: u64,
        io: &mut impl Io,
    ) -> Option<(Client, Result<[u32; 2], Fault>)> {
        if self.fault.is_some() {
            return None;
        }
        let command = self.pending.map(|p| p.command).or(next)?;
        let result = if let Some(pending) = self.pending {
            match self.poll(pending, now, io) {
                Ok(None) => return None,
                Ok(Some(data)) => Ok(data),
                Err(error) => Err(error),
            }
        } else {
            match self.post(command, now, io) {
                Ok(()) => return None,
                Err(error) => Err(error),
            }
        };
        self.pending = None;
        if let Err(error) = result {
            // A completed error status/data error retains software ownership
            // of an idle port. An ambiguous transfer quarantines the port.
            if !matches!(error, Fault::Status(_) | Fault::Data) {
                self.fault = Some(error)
            }
        }
        Some((command.client, result))
    }
    fn post(&mut self, command: Command, now: u64, io: &mut impl Io) -> Result<(), Fault> {
        let mailbox = io
            .read(MAILBOX)
            .filter(|&v| v != u32::MAX)
            .ok_or(Fault::Access)?;
        if mailbox & READY != 0 {
            return Err(Fault::ForeignBusy);
        }
        if !io.write(DATA0, command.input[0])
            || !io.write(DATA1, command.input[1])
            || !io.write(MAILBOX, READY | command.word)
        {
            return Err(Fault::Access);
        }
        self.pending = Some(Pending {
            command,
            posted_at: now,
        });
        Ok(())
    }
    fn poll(
        &self,
        pending: Pending,
        now: u64,
        io: &mut impl Io,
    ) -> Result<Option<[u32; 2]>, Fault> {
        let mailbox = io
            .read(MAILBOX)
            .filter(|&v| v != u32::MAX)
            .ok_or(Fault::Access)?;
        if mailbox & READY != 0 {
            if mailbox & 0x00ff_ffff != pending.command.word {
                return Err(Fault::Identity);
            }
            if now < pending.posted_at || now - pending.posted_at >= TIMEOUT_NS {
                return Err(Fault::Timeout);
            }
            return Ok(None);
        }
        // Completion guarantees low8 status only, never a command echo.
        let status = (mailbox & 0xff) as u8;
        if status != 0 {
            return Err(Fault::Status(status));
        }
        let mut data = [0; 2];
        if !matches!(pending.command.reply, Reply::None) {
            data[0] = io.read(DATA0).ok_or(Fault::Access)?;
        }
        if matches!(pending.command.reply, Reply::Two) {
            data[1] = io.read(DATA1).ok_or(Fault::Access)?;
        }
        if !matches!(pending.command.reply, Reply::None) && io.read(MAILBOX) != Some(mailbox) {
            return Err(Fault::Identity);
        }
        if data.contains(&u32::MAX) {
            return Err(Fault::Data);
        }
        Ok(Some(data))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Discovery {
    stage: u8,
    fault: Option<Fault>,
    pub(super) fans: Option<u8>,
    limits: Option<[u8; 5]>,
}
impl Discovery {
    pub(super) fn command(&self) -> Option<Command> {
        let (client, word, reply) = match self.stage {
            0 => (Client::Fan, 0x047d, Reply::One),
            1 => (Client::Thermal, 0x25, Reply::Two),
            _ => return None,
        };
        Some(Command {
            client,
            word,
            input: [0; 2],
            reply,
        })
    }
    pub(super) fn complete(&mut self, client: Client, result: Result<[u32; 2], Fault>) {
        let expected = match self.stage {
            0 => Client::Fan,
            1 => Client::Thermal,
            _ => return,
        };
        if client != expected {
            self.fault = Some(Fault::Identity);
            return;
        }
        match result {
            Err(error) => self.fault = Some(error),
            Ok(data) if client == Client::Fan => {
                if data[0] <= 3 {
                    self.fans = Some(data[0] as u8)
                } else {
                    self.fault = Some(Fault::Data)
                }
            }
            Ok([data0, data1]) => {
                self.limits = Some([
                    data0 as u8,
                    (data0 >> 8) as u8,
                    (data0 >> 16) as u8,
                    (data0 >> 24) as u8,
                    data1 as u8,
                ])
            }
        }
        self.stage += 1;
    }
    pub(super) fn limit(&self, attribute: &str) -> Option<u32> {
        let index = match attribute {
            "temp2_emergency" => 0,
            "temp2_crit" => 1,
            "temp3_emergency" => 2,
            "temp2_max" => 3,
            "temp3_crit" => 4,
            _ => return None,
        };
        let value = self.limits?[index];
        (value != 0).then_some(u32::from(value) * 1000)
    }
    pub(super) fn status(&self, mailbox: &Mailbox) -> alloc::string::String {
        if let Some(fault) = mailbox.fault().or(self.fault) {
            alloc::format!("failed {fault:?}\n")
        } else if self.stage == 2 {
            "ready\n".into()
        } else {
            "discovering\n".into()
        }
    }
}
