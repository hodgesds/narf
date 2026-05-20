//! AMD System Management Unit (SMU) mailbox protocol.
//!
//! The SMU is the on-die microcontroller that governs DCN
//! clocks (DISPCLK, DPPCLK, DCFCLK), GFX clocks (GFXCLK, SOCCLK),
//! memory clocks (UCLK / FCLK), power states (PPT, fan curves),
//! and thermal throttling. Every DCN modeset depends on the SMU
//! first programming DISPCLK to a value the requested pixel
//! clock can decimate down from; without the SMU bring-up,
//! `set_mode` programs a black screen.
//!
//! ## Protocol
//!
//! All modern AMD silicon (Vega, Navi, Phoenix, Strix) uses a
//! three-register mailbox in the MP1 IP block:
//!
//! | offset | name             | direction | meaning |
//! |--------|------------------|-----------|---------|
//! | 0x66   | MP1_C2PMSG_66    | host → SMU | argument (single u32) |
//! | 0x82   | MP1_C2PMSG_82    | host → SMU | message id (single u32) |
//! | 0x90   | MP1_C2PMSG_90    | SMU → host | response (single u32; 1 = OK, non-zero = error code) |
//!
//! Per `drivers/gpu/drm/amd/pm/swsmu/smu_cmn.c::smu_cmn_send_msg_without_waiting`,
//! the protocol is:
//!
//!   1. **Handshake**. Poll `MP1_C2PMSG_90` until it's non-zero
//!      (SMU is ready to take a new message). 0 = busy / not yet
//!      initialised; non-zero = idle. Bound the spin since a
//!      wedged SMU never raises this.
//!   2. **Clear**. Write 0 to `MP1_C2PMSG_90` so the next response
//!      can be observed as a 0→1 transition.
//!   3. **Argument**. Write the u32 argument to `MP1_C2PMSG_66`.
//!      Messages that take no argument still write 0 (per Linux).
//!   4. **Message**. Write the message id to `MP1_C2PMSG_82`. This
//!      is the trigger; the SMU sees the write and starts servicing.
//!   5. **Poll**. Spin on `MP1_C2PMSG_90` until non-zero. The value
//!      is the response code: 1 = OK, anything else = SMU-defined
//!      error (typically maps to `SmuError::*`).
//!   6. **Read result** (optional). For messages that return a
//!      value (e.g. `GetSmuVersion`), read `MP1_C2PMSG_66` after
//!      step 5.
//!
//! Linux references:
//! - `drivers/gpu/drm/amd/pm/swsmu/smu_cmn.c`
//! - `drivers/gpu/drm/amd/pm/swsmu/smu13/smu_v13_0.c` (Phoenix)
//! - `drivers/gpu/drm/amd/pm/swsmu/smu12/smu_v12_0.c` (Renoir / Cezanne)
//! - `drivers/gpu/drm/amd/pm/inc/smu_v13_0_4_ppsmc.h` (Phoenix PPSMC_MSG_*)
//! - `drivers/gpu/drm/amd/pm/inc/smu_v12_0_ppsmc.h` (Renoir PPSMC_MSG_*)
//!
//! NARF is GPL-2.0-or-later (relicensed 2026-05-20); the above
//! source files are read directly as references.

extern crate alloc;

// ── Register offsets (relative to MP1 IP-block base) ───────────────

/// MP1_C2PMSG_66 — argument register (host → SMU).
pub const MP1_C2PMSG_ARG_REL: u32 = 0x29C + 66 * 4;
/// MP1_C2PMSG_82 — message-id register (host → SMU).
pub const MP1_C2PMSG_MSG_REL: u32 = 0x29C + 82 * 4;
/// MP1_C2PMSG_90 — response register (SMU → host).
pub const MP1_C2PMSG_RESP_REL: u32 = 0x29C + 90 * 4;

// ── Response codes ──────────────────────────────────────────────────

/// Success. Returned in MP1_C2PMSG_90 after a successful command.
pub const SMU_RESP_OK: u32 = 1;
/// Command-rejected. SMU didn't recognise / can't honour the message.
pub const SMU_RESP_FAIL: u32 = 0xFF;
/// Unknown command id.
pub const SMU_RESP_UNKNOWN_CMD: u32 = 0xFE;
/// Argument out of range.
pub const SMU_RESP_BAD_PRM: u32 = 0xFD;

// ── PPSMC_MSG_* — shared message ids (post-Vega) ────────────────────
//
// The exact message-id space is per-family. The values below are
// the subset that matches across SMU 12.0 (Renoir) and SMU 13.0
// (Phoenix) — the ones Linux fans across both families. Each
// per-family ppsmc header adds its own messages on top.

/// `PPSMC_MSG_TestMessage` — handshake / responsiveness check.
/// Echoes the argument back as the response.
pub const PPSMC_MSG_TEST_MESSAGE: u32 = 0x01;
/// `PPSMC_MSG_GetSmuVersion` — returns the SMU firmware version
/// in MP1_C2PMSG_66 after RESP indicates OK.
pub const PPSMC_MSG_GET_SMU_VERSION: u32 = 0x02;
/// `PPSMC_MSG_GetDriverIfVersion` — returns the driver-interface
/// schema version. Caller checks this matches the
/// driver-side `*_ppsmc.h` it was compiled against.
pub const PPSMC_MSG_GET_DRIVER_IF_VERSION: u32 = 0x03;
/// `PPSMC_MSG_SetDriverDramAddrHigh` — programs the high 32 bits
/// of the driver-side DRAM address the SMU should use for its
/// shared-state-table transfers.
pub const PPSMC_MSG_SET_DRIVER_DRAM_ADDR_HIGH: u32 = 0x09;
/// `PPSMC_MSG_SetDriverDramAddrLow` — low 32 bits of the same.
pub const PPSMC_MSG_SET_DRIVER_DRAM_ADDR_LOW: u32 = 0x0A;
/// `PPSMC_MSG_TransferTableSmu2Dram` — copies an SMU-internal
/// table out to the driver-supplied DRAM buffer. Argument names
/// which table (each chip has its own enum).
pub const PPSMC_MSG_TRANSFER_TABLE_SMU2DRAM: u32 = 0x0B;
/// `PPSMC_MSG_TransferTableDram2Smu` — opposite direction.
pub const PPSMC_MSG_TRANSFER_TABLE_DRAM2SMU: u32 = 0x0C;
/// `PPSMC_MSG_PowerUpGfx` — wake the GFX block. Renoir / Phoenix
/// share this id.
pub const PPSMC_MSG_POWER_UP_GFX: u32 = 0x14;
/// `PPSMC_MSG_PowerDownGfx` — sleep the GFX block.
pub const PPSMC_MSG_POWER_DOWN_GFX: u32 = 0x15;
/// `PPSMC_MSG_AllowGfxOff` / `PPSMC_MSG_DisallowGfxOff` — gate
/// the SMU's per-frame GFX-off heuristic.
pub const PPSMC_MSG_ALLOW_GFX_OFF: u32 = 0x16;
pub const PPSMC_MSG_DISALLOW_GFX_OFF: u32 = 0x17;
/// `PPSMC_MSG_PowerUpVcn` / `PPSMC_MSG_PowerDownVcn` — wake / sleep
/// the video codec block.
pub const PPSMC_MSG_POWER_UP_VCN: u32 = 0x18;
pub const PPSMC_MSG_POWER_DOWN_VCN: u32 = 0x19;
/// `PPSMC_MSG_PrepareMp1ForUnload` — quiesce the SMU before kexec /
/// driver reload so the next bring-up doesn't see stale state.
pub const PPSMC_MSG_PREPARE_MP1_FOR_UNLOAD: u32 = 0x35;

// ── Errors ──────────────────────────────────────────────────────────

/// SMU mailbox errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SmuError {
    /// Handshake (step 1) didn't see RESP go non-zero within the
    /// bound. Typically means the SMU firmware never loaded
    /// (PSP didn't bring it up) or the MP1 base address is wrong.
    HandshakeTimeout,
    /// Step 5 didn't see RESP go non-zero within the bound.
    /// The SMU latched the message but never responded. Wedged.
    ResponseTimeout,
    /// SMU responded with a non-OK code.
    Rejected(u32),
    /// Caller's MP1 base address is `None` (typically the chip's
    /// IP discovery binary didn't enumerate MP1, or `bring_up`
    /// hasn't run yet).
    NoMp1Base,
}

// ── Mailbox primitive ───────────────────────────────────────────────

/// Caller's view of MMIO read/write. Plugged in by the driver
/// glue so the protocol is testable against a mock without
/// needing real silicon. Same pattern as
/// [`crate::amdgpu_atom_vm::AtomState`].
pub trait SmuMmio {
    /// Read `mp1_base + offset` (in register-bus address space).
    fn read(&mut self, mp1_base_plus_offset: u32) -> u32;
    /// Write `mp1_base + offset`.
    fn write(&mut self, mp1_base_plus_offset: u32, value: u32);
}

/// Maximum iterations the handshake / response polls take before
/// giving up. Each iteration costs whatever the caller's `read`
/// closure costs; on real silicon this works out to a few hundred
/// microseconds total which is well within the SMU's spec'd
/// 5 ms response window.
pub const SMU_POLL_BUDGET: u32 = 1_000_000;

/// Send a one-shot message to the SMU, return the response code
/// (`SMU_RESP_OK = 1` on success) and the read-back argument
/// register value. For messages that take no argument, `arg = 0`.
///
/// Sequence per `drivers/gpu/drm/amd/pm/swsmu/smu_cmn.c::smu_cmn_send_msg_without_waiting`
/// + `smu_cmn_wait_for_response`:
///
///   1. Poll RESP non-zero (handshake).
///   2. Write 0 to RESP.
///   3. Write `arg` to ARG.
///   4. Write `msg` to MSG.
///   5. Poll RESP non-zero (response ready).
///   6. Read ARG back (some messages return data here).
pub fn send_message<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    msg: u32,
    arg: u32,
) -> Result<(u32, u32), SmuError> {
    let resp_off = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg_off = mp1_base + MP1_C2PMSG_ARG_REL;
    let msg_off = mp1_base + MP1_C2PMSG_MSG_REL;

    // Step 1: handshake.
    let mut i = 0u32;
    loop {
        if mmio.read(resp_off) != 0 {
            break;
        }
        i += 1;
        if i >= SMU_POLL_BUDGET {
            return Err(SmuError::HandshakeTimeout);
        }
    }

    // Step 2: clear.
    mmio.write(resp_off, 0);
    // Step 3: argument.
    mmio.write(arg_off, arg);
    // Step 4: trigger.
    mmio.write(msg_off, msg);

    // Step 5: poll for response.
    let mut i = 0u32;
    let resp = loop {
        let v = mmio.read(resp_off);
        if v != 0 {
            break v;
        }
        i += 1;
        if i >= SMU_POLL_BUDGET {
            return Err(SmuError::ResponseTimeout);
        }
    };

    if resp != SMU_RESP_OK {
        return Err(SmuError::Rejected(resp));
    }

    // Step 6: read ARG.
    let out = mmio.read(arg_off);
    Ok((resp, out))
}

/// Convenience wrapper: send a message that's expected to succeed
/// AND return a data value in the ARG register (e.g.
/// `GetSmuVersion`).
pub fn send_message_get<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    msg: u32,
    arg: u32,
) -> Result<u32, SmuError> {
    send_message(mmio, mp1_base, msg, arg).map(|(_resp, out)| out)
}

/// Send a no-return-value message. Useful for the half-dozen
/// power / clock / state messages that don't read anything back.
pub fn send_message_void<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    msg: u32,
    arg: u32,
) -> Result<(), SmuError> {
    send_message(mmio, mp1_base, msg, arg).map(|_| ())
}

pub mod test_support {
    //! Test scaffolding exposed for smokes in this crate and
    //! adjacent driver crates. Not part of the production driver
    //! surface.
    use super::*;

    /// Mock MMIO that scripts a sequence of (offset, expected-read-value)
    /// pairs and captures writes. Lets each test stage a deterministic
    /// SMU response without needing real silicon.
    #[derive(Debug)]
    pub struct MockSmu {
        /// Per-offset queued reads. `pop_front` on each read.
        pub reads: alloc::collections::VecDeque<(u32, u32)>,
        pub writes: alloc::vec::Vec<(u32, u32)>,
    }
    impl MockSmu {
        #[allow(dead_code)]
        pub fn new() -> Self {
            Self {
                reads: alloc::collections::VecDeque::new(),
                writes: alloc::vec::Vec::new(),
            }
        }
        #[allow(dead_code)]
        pub fn stage_read(&mut self, off: u32, val: u32) {
            self.reads.push_back((off, val));
        }
    }
    impl SmuMmio for MockSmu {
        fn read(&mut self, off: u32) -> u32 {
            // Honour the order the test queued reads. Unknown
            // offset → 0 so the handshake spin observes "busy".
            let mut i = 0;
            while i < self.reads.len() {
                if self.reads[i].0 == off {
                    return self.reads.remove(i).map(|(_, v)| v).unwrap_or(0);
                }
                i += 1;
            }
            0
        }
        fn write(&mut self, off: u32, v: u32) {
            self.writes.push((off, v));
        }
    }
}

pub use test_support::MockSmu;
