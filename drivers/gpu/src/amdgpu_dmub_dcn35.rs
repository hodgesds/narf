//! DCN 3.5 (Strix Point) DMUB owner: attach, reset and mailbox setup,
//! following Linux `dmub_dcn35.c`.
//!
//! The command transport itself is the shared `amdgpu_dmub::Dmub`: every
//! DMCUB register it reads sits at the same offset in
//! `dcn_3_5_0_offset.h` as in `dcn_3_1_4_offset.h`, and the 3.5 inbox ABI
//! is the same 64-byte ring. What is 3.5-specific — and lives here — is the
//! reset sequence (`dmub_dcn35_reset`), the mailbox programming
//! (`dmub_dcn35_setup_mailbox`), and the attach gate that admits only
//! (3, 5, 0).
//!
//! Differences from the 3.2 owner (`amdgpu_dmub_dcn32`), all from
//! `dmub_dcn35.c`:
//!
//! * The STOP_FW poll is three separate loops — GPINT ack, then
//!   `SCRATCH7` for `STOP_FW_RESPONSE`, then `DMCUB_CNTL` for
//!   `PWAIT_MODE_STATUS` — where 3.2 checks the last two together.
//! * The reset does NOT disable cache windows CW2–CW7. Linux's 3.5
//!   reset has no such step; the Loader's direct-load path still
//!   clears stale windows itself (see `amdgpu_dmub_boot`).
//! * The reset *release* (`dmub_dcn35_reset_release`) additionally
//!   disables the LONO clock gates in `DMU_CLK_CNTL` and writes the
//!   hub reset at `MMHUBBUB_SOFT_RESET` 0x341, not 0x342. The release
//!   itself lives in the Loader's `configure()` (which performs the
//!   same steps for every version), so the 3.5-only pieces are gated
//!   there on the DCN version — see `amdgpu_dmub_boot::Loader`.
//!
//! HPD subscriptions are OUT of scope for this lane (the IH lane owns
//! them); this module never arms an HPD interrupt.

use super::amdgpu_dmub::{dmub_ip, Dmub, Error};
use crate::amdgpu::AmdGpu;

/// `regDMCUB_CNTL` — `DMCUB_ENABLE` is bit 16, `DMCUB_PWAIT_MODE_STATUS`
/// is bit 20 (`dcn_3_5_0_sh_mask.h`).
const CNTL: u32 = 0x1f6;
const ENABLE: u32 = 1 << 16;
const PWAIT_MODE: u32 = 1 << 20;
/// `regDMCUB_CNTL2` — `DMCUB_SOFT_RESET` is bit 0.
const CNTL2: u32 = 0x200;
const SOFT_RESET: u32 = 1;
/// `regDMCUB_SCRATCH0` — cleared by reset.
const SCRATCH0: u32 = 0x1e3;
/// `regDMCUB_SCRATCH7` — the STOP_FW reply lands here.
const SCRATCH7: u32 = 0x1ea;
/// `regDMCUB_GPINT_DATAIN1` — the GPINT command register.
const GPINT_DATAIN1: u32 = 0x1f8;
/// `regDMCUB_INBOX1_BASE_ADDRESS` / `regDMCUB_INBOX1_SIZE`.
const INBOX1_BASE: u32 = 0x1d4;
const INBOX1_SIZE: u32 = 0x1d5;
/// `regDMCUB_INBOX1_WPTR` / `regDMCUB_INBOX1_RPTR`.
const INBOX1_WPTR: u32 = 0x1d6;
const INBOX1_RPTR: u32 = 0x1d7;
/// `regDMCUB_OUTBOX0_WPTR` / `regDMCUB_OUTBOX0_RPTR`.
const OUTBOX0_WPTR: u32 = 0x1da;
const OUTBOX0_RPTR: u32 = 0x1db;
/// `regDMCUB_OUTBOX1_WPTR` / `regDMCUB_OUTBOX1_RPTR`.
const OUTBOX1_WPTR: u32 = 0x1de;
const OUTBOX1_RPTR: u32 = 0x1df;

/// GPINT STOP_FW command: status bit 28 set, command code 2 in bits 23:16
/// (`dmub_cmd.h`: `DMUB_GPINT__STOP_FW = 2`). Same encoding the DCN 3.1.4
/// boot loader uses.
const STOP_CMD: u32 = (1 << 28) | (2 << 16);
/// GPINT ack, per `dmub_dcn35_is_gpint_acked`: the register equals the
/// issued command with the status bit cleared.
const STOP_ACK: u32 = 2 << 16;
/// `DMUB_GPINT__STOP_FW_RESPONSE` (`dmub_cmd.h:1494`).
const STOP_RESPONSE: u32 = 0xDEADDEAD;

/// Stop poll budget. Linux gives the firmware 1 s at a 1 µs cadence per
/// poll loop; NARF's DCN 3.1.4 boot loader polls on a 100 ms deadline, so
/// the 3.5 reset matches the in-tree precedent rather than Linux's second.
const STOP_DEADLINE_MS: u64 = 100;

/// Minimal register access for the reset / mailbox sequences. The caller
/// owns the DCN BASE_IDX 2 window; `reg` is a dword id in that window
/// (`dcn_3_5_0_offset.h`, `*_BASE_IDX` 2).
pub trait DmubIo {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
}

fn update(io: &mut impl DmubIo, reg: u32, mask: u32, bits: u32) {
    let old = io.read(reg);
    io.write(reg, (old & !mask) | bits);
}

/// What `reset` found. `was_running` is true when DMCUB was enabled and
/// out of reset, i.e. when a STOP_FW round-trip actually ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetReport {
    pub was_running: bool,
}

/// Reset DMCUB, following Linux `dmub_dcn35_reset` step for step:
///
/// 1. When DMCUB is enabled and out of reset, issue GPINT STOP_FW and
///    poll, each inside its own 100 ms deadline: first the GPINT ack
///    (the command register reads back with the status bit cleared),
///    then `DMCUB_SCRATCH7` for `STOP_FW_RESPONSE`, then `DMCUB_CNTL`
///    for `PWAIT_MODE_STATUS`. A timeout returns `Err(Error::Timeout)`
///    before anything is reset — Linux would force the reset here
///    ("DMCUB is likely hung"); NARF fails closed instead, matching
///    the 3.2 owner's precedent.
/// 2. When DMCUB was enabled, assert `DMCUB_SOFT_RESET` and clear
///    `DMCUB_ENABLE`. Already-stopped firmware skips this: asserting
///    reset on a stopped block is not part of the Linux sequence.
/// 3. Zero the INBOX1 / OUTBOX0 / OUTBOX1 ring pointers and SCRATCH0.
///    Unlike 3.2, the cache windows are NOT disabled here — Linux's
///    3.5 reset has no such step.
/// 4. Clear the GPINT command manually so the block does not reset again.
///
/// The caller must hold exclusive ownership of DMCUB for the whole call.
pub async fn reset(io: &mut impl DmubIo) -> Result<ResetReport, Error> {
    let enabled = io.read(CNTL) & ENABLE != 0;
    let in_reset = io.read(CNTL2) & SOFT_RESET != 0;
    let mut was_running = false;
    if enabled && !in_reset {
        was_running = true;
        io.write(GPINT_DATAIN1, STOP_CMD);
        let polls: [fn(&mut dyn DmubIo) -> bool; 3] = [
            |io| io.read(GPINT_DATAIN1) == STOP_ACK,
            |io| io.read(SCRATCH7) == STOP_RESPONSE,
            |io| io.read(CNTL) & PWAIT_MODE != 0,
        ];
        for done in polls {
            let deadline = narf_time::Deadline::after_ms(STOP_DEADLINE_MS);
            loop {
                if done(io) {
                    break;
                }
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
            }
        }
    }
    if enabled {
        update(io, CNTL2, SOFT_RESET, SOFT_RESET);
        update(io, CNTL, ENABLE, 0);
    }
    for reg in [
        INBOX1_WPTR,
        INBOX1_RPTR,
        OUTBOX1_WPTR,
        OUTBOX1_RPTR,
        OUTBOX0_WPTR,
        OUTBOX0_RPTR,
        SCRATCH0,
    ] {
        io.write(reg, 0);
    }
    io.write(GPINT_DATAIN1, 0);
    Ok(ResetReport { was_running })
}

/// Program the INBOX1 mailbox, following Linux
/// `dmub_dcn35_setup_mailbox`: base address plus size (`top - base`).
/// The size bounds mirror the shared transport's `mailbox_offset`
/// (128..=16384 bytes, 64-byte aligned); anything else is refused
/// before a register is written.
pub fn setup_mailbox(io: &mut impl DmubIo, inbox_base: u32, inbox_size: u32) -> Result<(), Error> {
    if !(128..=16384).contains(&inbox_size) || inbox_size % 64 != 0 {
        return Err(Error::Invalid);
    }
    io.write(INBOX1_BASE, inbox_base);
    io.write(INBOX1_SIZE, inbox_size);
    Ok(())
}

/// Attach the shared DMUB transport to a DCN 3.5 GPU. The version gate
/// admits only (3, 5, 0); anything else — including DCN 3.2, which has
/// its own attach path — is refused before any register is read.
///
/// # Safety
/// Caller exclusively owns the GPU's DMUB mailbox for the returned
/// object's lifetime, including power management and firmware replacement.
pub unsafe fn attach(gpu: &AmdGpu) -> Result<Dmub, Error> {
    let ip = dmub_ip(gpu)?;
    if (ip.major, ip.minor, ip.revision) != (3, 5, 0) {
        return Err(Error::Unsupported);
    }
    // SAFETY: same contract as `Dmub::attach`.
    unsafe { Dmub::attach(gpu) }
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Register file that records every write, so the tests can prove a
    /// STOP_FW was issued (and not just that the end state looks right).
    struct Regs {
        words: [u32; 0x400],
        writes: Vec<(u32, u32)>,
        /// Emulate the DMCUB firmware acking a GPINT command by clearing
        /// the command's status bit (STOP_CMD reads back as STOP_ACK).
        /// Real hardware does this; a dumb store would leave the ack
        /// poll in `reset()` spinning until its deadline.
        ack_gpint: bool,
    }
    impl Regs {
        fn new() -> Self {
            Self {
                words: [0; 0x400],
                writes: Vec::new(),
                ack_gpint: true,
            }
        }
    }
    impl DmubIo for Regs {
        fn read(&mut self, reg: u32) -> u32 {
            self.words[reg as usize]
        }
        fn write(&mut self, reg: u32, value: u32) {
            let stored = if reg == GPINT_DATAIN1 && value == STOP_CMD && self.ack_gpint {
                STOP_ACK
            } else {
                value
            };
            self.words[reg as usize] = stored;
            self.writes.push((reg, value));
        }
    }

    fn dcn35_reset_stops_running_firmware() -> TestResult {
        let mut io = Regs::new();
        io.words[CNTL as usize] = ENABLE | PWAIT_MODE;
        io.words[GPINT_DATAIN1 as usize] = STOP_ACK;
        io.words[SCRATCH7 as usize] = STOP_RESPONSE;
        // Stale ring pointers a reset must clear. Unlike 3.2, stale
        // cache-window tops are NOT touched by the 3.5 reset.
        for reg in [INBOX1_WPTR, INBOX1_RPTR, OUTBOX1_WPTR, OUTBOX1_RPTR] {
            io.words[reg as usize] = 64;
        }
        io.words[0x1af] = 0x1234_0000 | (1 << 31);
        let report = match narf_scheduler::block_on_spin(reset(&mut io)) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("reset of running firmware failed"),
        };
        if !report.was_running
            || !io.writes.contains(&(GPINT_DATAIN1, STOP_CMD))
            || io.words[CNTL as usize] & ENABLE != 0
            || io.words[CNTL2 as usize] & SOFT_RESET == 0
            || io.words[GPINT_DATAIN1 as usize] != 0
            || io.words[0x1af] != 0x1234_0000 | (1 << 31)
        {
            return TestResult::Fail("running-firmware stop sequence");
        }
        for reg in [
            INBOX1_WPTR,
            INBOX1_RPTR,
            OUTBOX1_WPTR,
            OUTBOX1_RPTR,
            OUTBOX0_WPTR,
            OUTBOX0_RPTR,
            SCRATCH0,
        ] {
            if io.words[reg as usize] != 0 {
                return TestResult::Fail("ring pointers / scratch not zeroed");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub-dcn35",
        dcn35_reset_stops_running_firmware
    );

    fn dcn35_reset_on_stopped_firmware_issues_no_stop() -> TestResult {
        let mut io = Regs::new();
        // Already stopped: ENABLE clear, soft reset already asserted.
        io.words[CNTL2 as usize] = SOFT_RESET;
        let report = match narf_scheduler::block_on_spin(reset(&mut io)) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("reset of stopped firmware failed"),
        };
        if report.was_running
            || io.writes.contains(&(GPINT_DATAIN1, STOP_CMD))
            || io.words[CNTL2 as usize] != SOFT_RESET
        {
            return TestResult::Fail("stopped firmware must see no STOP_FW");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub-dcn35",
        dcn35_reset_on_stopped_firmware_issues_no_stop
    );

    fn dcn35_reset_times_out_when_firmware_never_halts() -> TestResult {
        let mut io = Regs::new();
        io.words[CNTL as usize] = ENABLE;
        // GPINT never acks the STOP_FW: the ack poll in loop 1 times out.
        io.ack_gpint = false;
        match narf_scheduler::block_on_spin(reset(&mut io)) {
            Err(Error::Timeout) => TestResult::Pass,
            _ => TestResult::Fail("unresponsive firmware must time out"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub-dcn35",
        dcn35_reset_times_out_when_firmware_never_halts
    );

    fn dcn35_reset_times_out_when_scratch_never_replies() -> TestResult {
        let mut io = Regs::new();
        io.words[CNTL as usize] = ENABLE | PWAIT_MODE;
        io.words[GPINT_DATAIN1 as usize] = STOP_ACK;
        // SCRATCH7 never becomes STOP_RESPONSE.
        match narf_scheduler::block_on_spin(reset(&mut io)) {
            Err(Error::Timeout) => TestResult::Pass,
            _ => TestResult::Fail("firmware without a STOP_FW reply must time out"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub-dcn35",
        dcn35_reset_times_out_when_scratch_never_replies
    );

    fn dcn35_setup_mailbox_programs_inbox1() -> TestResult {
        let mut io = Regs::new();
        if setup_mailbox(&mut io, 0x6400_0000, 8192).is_err()
            || io.words[INBOX1_BASE as usize] != 0x6400_0000
            || io.words[INBOX1_SIZE as usize] != 8192
        {
            return TestResult::Fail("mailbox base/size not programmed");
        }
        // Bad sizes are refused before any register is written.
        let written = io.writes.len();
        for bad in [0, 64, 100, 16385, 8191] {
            if setup_mailbox(&mut io, 0x6400_0000, bad).is_ok() || io.writes.len() != written {
                return TestResult::Fail("bad mailbox size accepted");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub-dcn35",
        dcn35_setup_mailbox_programs_inbox1
    );

    fn dcn35_attach_admits_only_3_5() -> TestResult {
        use crate::amdgpu::{ChipInfo, Family, AMD_VENDOR, STRIX_POINT};
        use crate::amdgpu_discovery::{IpBlock, HW_ID_DCN, MAX_BASE_ADDRS};
        use narf_bus::MmioRegion;
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let gpu = |minor: u8, revision: u8| AmdGpu {
            fb_bar: region,
            regs: region,
            chip: ChipInfo {
                vid: AMD_VENDOR,
                did: STRIX_POINT,
                family: Family::Strix,
                asic: "strix",
                fw_name: "amdgpu/strix.bin",
                fw_list: &[],
                revision: 0,
                rev_id: 0,
                mall_size: 0,
            },
            vram: Default::default(),
            mode: None,
            backlight_percent: None,
            fw_loaded: false,
            ip_blocks: alloc::vec![IpBlock {
                hw_id: HW_ID_DCN,
                instance: 0,
                major: 3,
                minor,
                revision,
                sub_revision: 0,
                variant: 0,
                base_addrs: [0; MAX_BASE_ADDRS],
                num_bases: 3,
            }],
            vbios: None,
            gc_info: None,
        };
        // DCN 3.1.4 / 3.2.0 are refused at the version gate, before any
        // register is read; DCN 3.5.1 never reaches the gate at all.
        // SAFETY: refused before dereferencing the register mapping.
        for (minor, revision) in [(1u8, 4u8), (2u8, 0u8), (5u8, 1u8)] {
            let g = gpu(minor, revision);
            // SAFETY: refused before dereferencing the register mapping.
            if !matches!(unsafe { attach(&g) }, Err(Error::Unsupported)) {
                return TestResult::Fail("non-3.5 DCN admitted by the 3.5 attach");
            }
        }
        // DCN 3.5.0 passes the gate: with a zero-length register
        // window the shared attach then fails on bounds (Invalid), not
        // on the version — proving the gate admitted it.
        let g = gpu(5, 0);
        // SAFETY: zero-length window, attach fails before any access.
        if !matches!(unsafe { attach(&g) }, Err(Error::Invalid)) {
            return TestResult::Fail("DCN 3.5 attach did not reach the transport");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub-dcn35",
        dcn35_attach_admits_only_3_5
    );
}
