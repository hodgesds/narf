//! GSP CPU sequencer — execute the `GSP_RUN_CPU_SEQUENCER` commands.
//!
//! During boot the GSP firmware sends the host a `RUN_CPU_SEQUENCER`
//! event carrying a buffer of opcodes (register pokes + a SEC2→GSP
//! "resume" dance) that the host must execute for the GSP to finish
//! coming up. Cite `/usr/src/linux` `rm/r535/gsp.c::
//! r535_gsp_msg_run_cpu_sequencer` + `nvrm/gsp.h` + nova-core
//! `gsp/sequencer.rs`.
//!
//! The opcode **decode** is pure and unit-tested; the **execute**
//! (register pokes, Falcon ops) is hardware and cannot run under QEMU.

#![allow(dead_code)]

use alloc::vec::Vec;

use narf_driver_runtime::MmioRegion;

use crate::falcon::{Falcon, FALCON_BASE_GSP, FALCON_BASE_SEC2, FALCON_MAILBOX0, FALCON_MAILBOX1};

// ── Opcodes (GSP_SEQ_BUF_OPCODE) ─────────────────────────────────

pub const OP_REG_WRITE: u32 = 0;
pub const OP_REG_MODIFY: u32 = 1;
pub const OP_REG_POLL: u32 = 2;
pub const OP_DELAY_US: u32 = 3;
pub const OP_REG_STORE: u32 = 4;
pub const OP_CORE_RESET: u32 = 5;
pub const OP_CORE_START: u32 = 6;
pub const OP_CORE_WAIT_FOR_HALT: u32 = 7;
pub const OP_CORE_RESUME: u32 = 8;

/// One decoded sequencer command. Cite `GSP_SEQUENCER_BUFFER_CMD`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SeqCmd {
    RegWrite {
        addr: u32,
        val: u32,
    },
    RegModify {
        addr: u32,
        mask: u32,
        val: u32,
    },
    RegPoll {
        addr: u32,
        mask: u32,
        val: u32,
        timeout_us: u32,
    },
    DelayUs {
        us: u32,
    },
    RegStore {
        addr: u32,
        index: u32,
    },
    CoreReset,
    CoreStart,
    CoreWaitForHalt,
    CoreResume,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SeqError {
    /// Command ran past the end of the buffer.
    Truncated,
    /// Opcode value 9+ is undefined.
    BadOpcode(u32),
    /// A `REG_POLL` did not reach its expected value in budget.
    PollTimeout(u32),
    /// The GSP CPU did not halt in budget (`CORE_WAIT_FOR_HALT`).
    HaltTimeout,
    /// `CORE_RESUME`: the boot-stage-3 handoff did not assert.
    ResumeTimeout,
    /// `CORE_RESUME`: SEC2 left a non-zero MAILBOX0.
    Sec2Failed(u32),
    /// `CORE_RESUME`: the GSP RISC-V core did not come active.
    RiscvInactive,
}

/// Payload size, in 32-bit words, for an opcode (not counting the
/// opcode word itself). Cite `GSP_SEQUENCER_PAYLOAD_SIZE_DWORDS`.
pub const fn payload_dwords(opcode: u32) -> Option<usize> {
    Some(match opcode {
        OP_REG_WRITE | OP_REG_STORE => 2,
        OP_REG_MODIFY => 3,
        OP_REG_POLL => 5,
        OP_DELAY_US => 1,
        OP_CORE_RESET | OP_CORE_START | OP_CORE_WAIT_FOR_HALT | OP_CORE_RESUME => 0,
        _ => return None,
    })
}

fn rd(buf: &[u8], w: usize) -> Option<u32> {
    let o = w * 4;
    buf.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Decode one command from the front of `buf`; returns the command and
/// the number of **bytes** it occupies (opcode word + payload).
pub fn decode_cmd(buf: &[u8]) -> Result<(SeqCmd, usize), SeqError> {
    let opcode = rd(buf, 0).ok_or(SeqError::Truncated)?;
    let pdw = payload_dwords(opcode).ok_or(SeqError::BadOpcode(opcode))?;
    let total_bytes = (1 + pdw) * 4;
    if buf.len() < total_bytes {
        return Err(SeqError::Truncated);
    }
    let cmd = match opcode {
        OP_REG_WRITE => SeqCmd::RegWrite {
            addr: rd(buf, 1).unwrap(),
            val: rd(buf, 2).unwrap(),
        },
        OP_REG_MODIFY => SeqCmd::RegModify {
            addr: rd(buf, 1).unwrap(),
            mask: rd(buf, 2).unwrap(),
            val: rd(buf, 3).unwrap(),
        },
        OP_REG_POLL => SeqCmd::RegPoll {
            addr: rd(buf, 1).unwrap(),
            mask: rd(buf, 2).unwrap(),
            val: rd(buf, 3).unwrap(),
            timeout_us: rd(buf, 4).unwrap(),
            // word 5 is the (unused) `error` field.
        },
        OP_DELAY_US => SeqCmd::DelayUs {
            us: rd(buf, 1).unwrap(),
        },
        OP_REG_STORE => SeqCmd::RegStore {
            addr: rd(buf, 1).unwrap(),
            index: rd(buf, 2).unwrap(),
        },
        OP_CORE_RESET => SeqCmd::CoreReset,
        OP_CORE_START => SeqCmd::CoreStart,
        OP_CORE_WAIT_FOR_HALT => SeqCmd::CoreWaitForHalt,
        OP_CORE_RESUME => SeqCmd::CoreResume,
        other => return Err(SeqError::BadOpcode(other)),
    };
    Ok((cmd, total_bytes))
}

/// Decode a whole command buffer. `cmd_dwords` is the firmware's
/// `cmdIndex` watermark (the total number of 32-bit words the commands
/// occupy); decoding stops once that many words have been consumed.
/// Cite the C loop `while (ptr < seq->cmdIndex)`.
pub fn decode_all(buf: &[u8], cmd_dwords: u32) -> Result<Vec<SeqCmd>, SeqError> {
    let mut cmds = Vec::new();
    let mut word = 0usize;
    while word < cmd_dwords as usize {
        let (cmd, bytes) = decode_cmd(buf.get(word * 4..).ok_or(SeqError::Truncated)?)?;
        cmds.push(cmd);
        word += bytes / 4;
    }
    Ok(cmds)
}

// ── Execute (hardware; QEMU cannot exercise this) ────────────────
//
// Register offsets relative to a Falcon base (GSP = 0x110000,
// SEC2 = 0x840000) unless an absolute BAR0 offset is noted.

const FLCN_CPUCTL: u64 = 0x100;
const FLCN_CPUCTL_ALIAS: u64 = 0x130;
const FLCN_OS: u64 = 0x080;
const FLCN_ENGINE: u64 = 0x3c0;
const FLCN_FBIF_CTL: u64 = 0x624;
const FLCN_DMACTL: u64 = 0x10c;
const CPUCTL_ALIAS_EN: u32 = 1 << 6;
const CPUCTL_STARTCPU: u32 = 1 << 1;
const CPUCTL_HALTED: u32 = 1 << 4;
const FBIF_CTL_ALLOW_PHYS_NO_CTX: u32 = 1 << 7;
const ENGINE_RESET: u32 = 1 << 0;

/// Absolute BAR0: `NV_PGC6_BSI_SECURE_SCRATCH_14`; bit 26 =
/// boot-stage-3 handoff (set by GSP-RM on resume).
const RESUME_SCRATCH: u64 = 0x0011_80f8;
const RESUME_HANDOFF_BIT: u32 = 1 << 26;

/// Spin until `(read32(off) & mask) == val`, bounded by `budget`
/// iterations.
///
/// # Safety
/// `off` is within the BAR0 window.
unsafe fn poll(bar0: &MmioRegion, off: u64, mask: u32, val: u32, budget: u32) -> bool {
    for _ in 0..budget {
        // SAFETY: caller's responsibility.
        if unsafe { bar0.read32(off) } & mask == val {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Execute one sequencer command. `budget` bounds every poll loop (a
/// coarse stand-in for the firmware's microsecond timeouts — the
/// caller should size it generously). `REG_STORE` reads the register
/// but does not write it back to the GSP save area (the save area is
/// in the shared RPC buffer; wiring it back is a follow-up, matching
/// nova-core's current simplification).
///
/// # Safety
/// `bar0` is the mapped BAR0 window and the caller owns the GSP + SEC2
/// Falcons exclusively.
pub unsafe fn execute(
    cmd: &SeqCmd,
    bar0: &MmioRegion,
    libos_dma: u64,
    app_version: u32,
    budget: u32,
) -> Result<(), SeqError> {
    let gsp = Falcon::new(bar0, FALCON_BASE_GSP, "gsp-seq");
    let sec2 = Falcon::new(bar0, FALCON_BASE_SEC2, "sec2-seq");
    // SAFETY: caller owns BAR0 + both Falcons.
    unsafe {
        match *cmd {
            SeqCmd::RegWrite { addr, val } => bar0.write32(addr as u64, val),
            SeqCmd::RegModify { addr, mask, val } => {
                let cur = bar0.read32(addr as u64);
                bar0.write32(addr as u64, (cur & !mask) | (val & mask));
            }
            SeqCmd::RegPoll {
                addr,
                mask,
                val,
                timeout_us,
            } => {
                let _ = bar0.read32(addr as u64); // one dummy read, per C
                if !poll(bar0, addr as u64, mask, val, budget.max(timeout_us)) {
                    return Err(SeqError::PollTimeout(addr));
                }
            }
            SeqCmd::DelayUs { us } => {
                for _ in 0..us {
                    core::hint::spin_loop();
                }
            }
            SeqCmd::RegStore { addr, .. } => {
                let _ = bar0.read32(addr as u64);
            }
            SeqCmd::CoreReset => {
                gsp.wr32(FLCN_ENGINE, ENGINE_RESET);
                for _ in 0..budget.min(10_000) {
                    core::hint::spin_loop();
                }
                gsp.wr32(FLCN_ENGINE, 0);
                let ctl = gsp.rd32(FLCN_FBIF_CTL);
                gsp.wr32(FLCN_FBIF_CTL, ctl | FBIF_CTL_ALLOW_PHYS_NO_CTX);
                gsp.wr32(FLCN_DMACTL, 0);
            }
            SeqCmd::CoreStart => core_start(&gsp),
            SeqCmd::CoreWaitForHalt => {
                if !poll(
                    bar0,
                    FALCON_BASE_GSP + FLCN_CPUCTL,
                    CPUCTL_HALTED,
                    CPUCTL_HALTED,
                    budget,
                ) {
                    return Err(SeqError::HaltTimeout);
                }
            }
            SeqCmd::CoreResume => {
                // 1. reset GSP engine.
                gsp.wr32(FLCN_ENGINE, ENGINE_RESET);
                for _ in 0..budget.min(10_000) {
                    core::hint::spin_loop();
                }
                gsp.wr32(FLCN_ENGINE, 0);
                // 2. libOS DMA addr → GSP mailboxes.
                gsp.wr32(FALCON_MAILBOX0, libos_dma as u32);
                gsp.wr32(FALCON_MAILBOX1, (libos_dma >> 32) as u32);
                // 3. start SEC2.
                core_start(&sec2);
                // 4. wait for boot-stage-3 handoff.
                if !poll(
                    bar0,
                    RESUME_SCRATCH,
                    RESUME_HANDOFF_BIT,
                    RESUME_HANDOFF_BIT,
                    budget,
                ) {
                    return Err(SeqError::ResumeTimeout);
                }
                // 5. SEC2 must leave MAILBOX0 == 0.
                let sec2_mbox = sec2.rd32(FALCON_MAILBOX0);
                if sec2_mbox != 0 {
                    return Err(SeqError::Sec2Failed(sec2_mbox));
                }
                // 6. app_version → GSP OS register.
                gsp.wr32(FLCN_OS, app_version);
                // 7. GSP RISC-V must be active.
                if !crate::gsp_boot::riscv_active(bar0.read32(crate::gsp_boot::GSP_RISCV_STATUS)) {
                    return Err(SeqError::RiscvInactive);
                }
            }
        }
    }
    Ok(())
}

/// `CORE_START` for a Falcon: write STARTCPU through the alias register
/// if CPUCTL.alias_en is set, else directly.
///
/// # Safety
/// Caller owns the Falcon.
unsafe fn core_start(f: &Falcon) {
    // SAFETY: caller's responsibility.
    unsafe {
        if f.rd32(FLCN_CPUCTL) & CPUCTL_ALIAS_EN != 0 {
            f.wr32(FLCN_CPUCTL_ALIAS, CPUCTL_STARTCPU);
        } else {
            f.wr32(FLCN_CPUCTL, CPUCTL_STARTCPU);
        }
    }
}
