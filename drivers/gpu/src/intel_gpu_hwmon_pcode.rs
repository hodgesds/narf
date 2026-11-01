//! BMG read-only PCODE discovery. MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad
//! xe_pcode.c::{xe_pcode_read,__pcode_mailbox_rw,pcode_mailbox_status},
//! xe_hwmon.c::{xe_hwmon_pcode_read_fan_control,xe_hwmon_pcode_read_thermal_info},
//! xe_pcode_api.h. One bounded step per retained GT service poll, no spinning.
//!
//! This port is exclusive to this service on the admitted dGPU path:
//! intel_gpu::probe returns probe_discrete before constructing the integrated
//! display Controller; probe_discrete installs a GT-only card with display=None.
//! Existing intel_gpu_pcode callers are integrated modeset::program_watermarks
//! only. GuC boot, SLPC and dGPU PM do not use the PCODE port. Any future dGPU
//! PCODE owner must join this transaction owner before it may be admitted.

use super::Io;

pub(super) const MAILBOX: u64 = 0x138124;
pub(super) const DATA0: u64 = 0x138128;
pub(super) const DATA1: u64 = 0x13812c;
const READY: u32 = 1 << 31;
const FAN_COUNT: u32 = 0x047d;
const THERMAL_LIMITS: u32 = 0x25;
// xe_pcode_read's timeout is 1 ms. A late service poll first tests completion;
// only an observed still-busy command can time out and quarantine this owner.
const TIMEOUT_NS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Access,
    ForeignBusy,
    Identity,
    Timeout,
    Status(u8),
    Data,
}
#[derive(Clone, Copy, Debug)]
struct Pending {
    command: u32,
    posted_at: u64,
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Discovery {
    stage: u8,
    pending: Option<Pending>,
    poisoned: bool,
    fault: Option<Fault>,
    pub(super) fans: Option<u8>,
    // pkg shutdown, pkg critical, memory shutdown, pkg max, memory critical.
    limits: Option<[u8; 5]>,
}
impl Discovery {
    pub(super) fn step(&mut self, now: u64, io: &mut impl Io) {
        if self.poisoned || self.stage >= 2 {
            return;
        }
        if let Some(pending) = self.pending {
            let Some(mailbox) = io.read(MAILBOX).filter(|&v| v != u32::MAX) else {
                self.poison(Fault::Access);
                return;
            };
            if mailbox & READY != 0 {
                // While busy, the request fields still identify our post.
                if mailbox & 0x00ff_ffff != pending.command {
                    self.poison(Fault::Identity);
                } else if now < pending.posted_at || now - pending.posted_at >= TIMEOUT_NS {
                    self.poison(Fault::Timeout);
                }
                return;
            }
            // Completed PCODE only guarantees low8 status, not a command echo.
            // Never interpret DATA without a software-owned post in this epoch.
            let status = (mailbox & 0xff) as u8;
            if status != 0 {
                self.fault = Some(Fault::Status(status));
                self.advance();
                return;
            }
            let Some(data0) = io.read(DATA0) else {
                self.poison(Fault::Access);
                return;
            };
            let data1 = if self.stage == 1 {
                io.read(DATA1)
            } else {
                Some(0)
            };
            let Some(data1) = data1 else {
                self.poison(Fault::Access);
                return;
            };
            // Detect an unexpected new command while copying the tiny reply.
            if io.read(MAILBOX) != Some(mailbox) {
                self.poison(Fault::Identity);
                return;
            }
            if data0 == u32::MAX || data1 == u32::MAX {
                self.fault = Some(Fault::Data);
            } else if self.stage == 0 {
                // Only three fan registers are source-defined. Do not let a
                // firmware count expand MMIO or manufacture extra channels.
                if data0 <= 3 {
                    self.fans = Some(data0 as u8);
                } else {
                    self.fault = Some(Fault::Data);
                }
            } else {
                self.limits = Some([
                    data0 as u8,
                    (data0 >> 8) as u8,
                    (data0 >> 16) as u8,
                    (data0 >> 24) as u8,
                    data1 as u8,
                ]);
            }
            self.advance();
            return;
        }
        let Some(mailbox) = io.read(MAILBOX).filter(|&v| v != u32::MAX) else {
            self.poison(Fault::Access);
            return;
        };
        if mailbox & READY != 0 {
            self.poison(Fault::ForeignBusy);
            return;
        }
        let command = if self.stage == 0 {
            FAN_COUNT
        } else {
            THERMAL_LIMITS
        };
        if !io.write(DATA0, 0) || !io.write(DATA1, 0) || !io.write(MAILBOX, READY | command) {
            self.poison(Fault::Access);
            return;
        }
        self.pending = Some(Pending {
            command,
            posted_at: now,
        });
    }
    fn advance(&mut self) {
        self.pending = None;
        self.stage += 1;
    }
    fn poison(&mut self, fault: Fault) {
        self.fault = Some(fault);
        self.poisoned = true;
        self.pending = None;
        // Previously confirmed independent metadata remains usable in this
        // epoch, but no new command may consume a late/unrelated reply.
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
    pub(super) fn status(&self) -> alloc::string::String {
        use alloc::format;
        if let Some(fault) = self.fault {
            format!("failed {fault:?}\n")
        } else if self.stage == 2 {
            "ready\n".into()
        } else {
            "discovering\n".into()
        }
    }
}
