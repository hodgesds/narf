//! DCN 3.2 (Navi31 / Navi32 3.2.0, Navi33 3.2.1) DMUB owner: attach, reset
//! and mailbox setup, following Linux `dmub_dcn32.c`.
//!
//! The command transport itself is the shared `amdgpu_dmub::Dmub`: every
//! DMCUB register it reads sits at the same offset in `dcn_3_2_0_offset.h`
//! / `dcn_3_2_1_offset.h` as in `dcn_3_1_4_offset.h`, and the 3.2 inbox ABI
//! is the same 64-byte ring. What is 3.2-specific — and lives here — is the
//! reset sequence (`dmub_dcn32_reset`), the mailbox programming
//! (`dmub_dcn32_setup_mailbox`), and the attach gate that admits only
//! (3, 2, 0) / (3, 2, 1).
//!
//! HPD subscriptions are OUT of scope for this lane (the IH lane owns
//! them); this module never arms an HPD interrupt.

use super::amdgpu_dmub::{dmub_ip, Dmub, Error};
use crate::amdgpu::AmdGpu;

/// `regDMCUB_CNTL` — `DMCUB_ENABLE` is bit 16, `DMCUB_PWAIT_MODE_STATUS`
/// is bit 20 (`dcn_3_2_0_sh_mask.h`).
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
/// `regDMCUB_REGION3_CW2_TOP_ADDRESS` .. `regDMCUB_REGION3_CW7_TOP_ADDRESS`
/// — consecutive, `DMCUB_REGION3_CWn_ENABLE` is bit 31 in each.
const CW2_TOP: u32 = 0x1af;
const CW7_TOP: u32 = 0x1b4;
const CW_ENABLE: u32 = 1 << 31;

/// GPINT STOP_FW command: status bit 28 set, command code 2 in bits 23:16
/// (`dmub_cmd.h`: `DMUB_GPINT__STOP_FW = 2`). Same encoding the DCN 3.1.4
/// boot loader uses.
const STOP_CMD: u32 = (1 << 28) | (2 << 16);
/// `DMUB_GPINT__STOP_FW_RESPONSE` (`dmub_cmd.h:1494`).
const STOP_RESPONSE: u32 = 0xDEADDEAD;

/// Stop poll budget. Linux gives the firmware 1 s at a 1 µs cadence;
/// NARF's DCN 3.1.4 boot loader polls on the same 100 ms deadline this
/// uses, so the 3.2 reset matches the in-tree precedent rather than
/// Linux's second.
const STOP_DEADLINE_MS: u64 = 100;

/// Minimal register access for the reset / mailbox sequences. The caller
/// owns the DCN BASE_IDX 2 window; `reg` is a dword id in that window
/// (`dcn_3_2_0_offset.h`, `*_BASE_IDX` 2).
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

/// Reset DMCUB, following Linux `dmub_dcn32_reset` step for step:
///
/// 1. When DMCUB is enabled and out of reset, issue GPINT STOP_FW and
///    poll `DMCUB_SCRATCH7` for `STOP_FW_RESPONSE` and `DMCUB_CNTL`
///    for `PWAIT_MODE_STATUS`, both inside one 100 ms deadline.
///    A timeout returns `Err(Error::Timeout)` before anything is reset —
///    Linux would `BREAK_TO_DEBUGGER()` here; NARF fails closed instead.
/// 2. When DMCUB was enabled, assert `DMCUB_SOFT_RESET` and clear
///    `DMCUB_ENABLE`. Already-stopped firmware skips this: asserting
///    reset on a stopped block is not part of the Linux sequence.
/// 3. Disable cache windows CW2–CW7 (clear the ENABLE bit, keep the top
///    address — the image this reset precedes does not use them).
/// 4. Zero the INBOX1 / OUTBOX0 / OUTBOX1 ring pointers and SCRATCH0.
/// 5. Clear the GPINT command manually so the block does not reset again.
///
/// The caller must hold exclusive ownership of DMCUB for the whole call.
pub async fn reset(io: &mut impl DmubIo) -> Result<ResetReport, Error> {
    let enabled = io.read(CNTL) & ENABLE != 0;
    let in_reset = io.read(CNTL2) & SOFT_RESET != 0;
    let mut was_running = false;
    if enabled && !in_reset {
        was_running = true;
        io.write(GPINT_DATAIN1, STOP_CMD);
        let deadline = narf_time::Deadline::after_ms(STOP_DEADLINE_MS);
        loop {
            if io.read(SCRATCH7) == STOP_RESPONSE && io.read(CNTL) & PWAIT_MODE != 0 {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    if enabled {
        update(io, CNTL2, SOFT_RESET, SOFT_RESET);
        update(io, CNTL, ENABLE, 0);
    }
    for reg in CW2_TOP..=CW7_TOP {
        update(io, reg, CW_ENABLE, 0);
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
/// `dmub_dcn32_setup_mailbox`: base address plus size (`top - base`).
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

/// Attach the shared DMUB transport to a DCN 3.2 GPU. The version gate
/// admits only (3, 2, 0) / (3, 2, 1); anything else — including DCN 3.1.4,
/// which has its own attach path — is refused before any register is read.
///
/// # Safety
/// Caller exclusively owns the GPU's DMUB mailbox for the returned
/// object's lifetime, including power management and firmware replacement.
pub unsafe fn attach(gpu: &AmdGpu) -> Result<Dmub, Error> {
    let ip = dmub_ip(gpu)?;
    if !matches!((ip.major, ip.minor, ip.revision), (3, 2, 0) | (3, 2, 1)) {
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
    }
    impl Regs {
        fn new() -> Self {
            Self {
                words: [0; 0x400],
                writes: Vec::new(),
            }
        }
    }
    impl DmubIo for Regs {
        fn read(&mut self, reg: u32) -> u32 {
            self.words[reg as usize]
        }
        fn write(&mut self, reg: u32, value: u32) {
            self.words[reg as usize] = value;
            self.writes.push((reg, value));
        }
    }

    fn dcn32_reset_stops_running_firmware() -> TestResult {
        let mut io = Regs::new();
        io.words[CNTL as usize] = ENABLE | PWAIT_MODE;
        io.words[SCRATCH7 as usize] = STOP_RESPONSE;
        // Stale window tops + ring pointers a reset must clear.
        for reg in CW2_TOP..=CW7_TOP {
            io.words[reg as usize] = 0x1234_0000 | CW_ENABLE;
        }
        for reg in [INBOX1_WPTR, INBOX1_RPTR, OUTBOX1_WPTR, OUTBOX1_RPTR] {
            io.words[reg as usize] = 64;
        }
        let report = match narf_scheduler::block_on_spin(reset(&mut io)) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("reset of running firmware failed"),
        };
        if !report.was_running
            || !io.writes.contains(&(GPINT_DATAIN1, STOP_CMD))
            || io.words[CNTL as usize] & ENABLE != 0
            || io.words[CNTL2 as usize] & SOFT_RESET == 0
            || io.words[GPINT_DATAIN1 as usize] != 0
        {
            return TestResult::Fail("running-firmware stop sequence");
        }
        for reg in CW2_TOP..=CW7_TOP {
            // ENABLE bit cleared, top address preserved.
            if io.words[reg as usize] & CW_ENABLE != 0
                || io.words[reg as usize] & !CW_ENABLE != 0x1234_0000
            {
                return TestResult::Fail("cache-window disable must keep the top address");
            }
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
        "drivers/gpu/amdgpu-dmub-dcn32",
        dcn32_reset_stops_running_firmware
    );

    fn dcn32_reset_on_stopped_firmware_issues_no_stop() -> TestResult {
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
        "drivers/gpu/amdgpu-dmub-dcn32",
        dcn32_reset_on_stopped_firmware_issues_no_stop
    );

    fn dcn32_reset_times_out_when_firmware_never_halts() -> TestResult {
        let mut io = Regs::new();
        io.words[CNTL as usize] = ENABLE;
        // SCRATCH7 never becomes STOP_RESPONSE.
        match narf_scheduler::block_on_spin(reset(&mut io)) {
            Err(Error::Timeout) => TestResult::Pass,
            _ => TestResult::Fail("unresponsive firmware must time out"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub-dcn32",
        dcn32_reset_times_out_when_firmware_never_halts
    );

    fn dcn32_setup_mailbox_programs_inbox1() -> TestResult {
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
        "drivers/gpu/amdgpu-dmub-dcn32",
        dcn32_setup_mailbox_programs_inbox1
    );

    fn dcn32_attach_admits_only_3_2() -> TestResult {
        use crate::amdgpu::{ChipInfo, Family, AMD_VENDOR, NAVI31};
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
                did: NAVI31,
                family: Family::Navi3,
                asic: "navi31",
                fw_name: "amdgpu/navi31.bin",
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
        // DCN 3.1.4 is refused at the version gate, before any register
        // is read; DCN 3.5 never reaches the gate at all.
        // SAFETY: refused before dereferencing the register mapping.
        for (minor, revision) in [(1u8, 4u8), (3u8, 5u8)] {
            let g = gpu(minor, revision);
            // SAFETY: refused before dereferencing the register mapping.
            if !matches!(unsafe { attach(&g) }, Err(Error::Unsupported)) {
                return TestResult::Fail("non-3.2 DCN admitted by the 3.2 attach");
            }
        }
        // DCN 3.2.0 / 3.2.1 pass the gate: with a zero-length register
        // window the shared attach then fails on bounds (Invalid), not
        // on the version — proving the gate admitted them.
        for revision in [0, 1] {
            let g = gpu(2, revision);
            // SAFETY: zero-length window, attach fails before any access.
            if !matches!(unsafe { attach(&g) }, Err(Error::Invalid)) {
                return TestResult::Fail("DCN 3.2 attach did not reach the transport");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub-dcn32",
        dcn32_attach_admits_only_3_2
    );
}
