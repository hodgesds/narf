//! AMD Platform Security Processor (PSP) MP0 mailbox protocol.
//!
//! The PSP is the on-die security microcontroller. After the
//! boot ROM hands control off, the host driver must load each IP
//! block's signed firmware blob *through* the PSP — DCN, SMU,
//! GFX, SDMA, VCN, RLC. The PSP verifies the signature, programs
//! the target block's microcode region, and acks. Nothing
//! downstream comes up until the PSP ack lands.
//!
//! ## Protocol
//!
//! The MP0 mailbox is a small set of scratch registers exposed
//! in the MP0 IP-block window. The host writes the image
//! address + command into specific slots and polls a single
//! response slot:
//!
//! | offset | name             | direction  | meaning |
//! |--------|------------------|------------|---------|
//! | 0x64   | MP0_C2PMSG_64    | host → PSP | image phys lo (low 32 bits) |
//! | 0x67   | MP0_C2PMSG_67    | host → PSP | image phys hi (high 32 bits) |
//! | 0x69   | MP0_C2PMSG_69    | host → PSP | (cmd) | (size << 8) — trigger |
//! | 0x64   | MP0_C2PMSG_64    | PSP → host | bit31 = done; bits[30:0] = status |
//!
//! Slot 64 doubles as input (phys lo) on entry and output
//! (status word) on completion — the host writes it first, then
//! polls it after writing slot 69.
//!
//! Per [`crate::amdgpu::AmdGpu::load_firmware`] and the
//! Linux reference (`drivers/gpu/drm/amd/amdgpu/psp_v*.c`,
//! `psp_gfx_if.h`):
//!
//!   1. Write phys-lo to MP0_C2PMSG_64.
//!   2. Write phys-hi to MP0_C2PMSG_67.
//!   3. Write `(cmd) | (size << 8)` to MP0_C2PMSG_69 — trigger.
//!   4. Poll MP0_C2PMSG_64; loop until bit 31 is set (done).
//!   5. Inspect bits[30:0]: 0 = success; non-zero = PSP-defined
//!      status code (rejection / sig fail / OOM in PSP TMR / etc).
//!
//! Linux references (post 2026-05-20 GPL relicense allows direct
//! citation):
//! - `drivers/gpu/drm/amd/amdgpu/psp_v11_0.c` (Navi 1)
//! - `drivers/gpu/drm/amd/amdgpu/psp_v12_0.c` (Renoir)
//! - `drivers/gpu/drm/amd/amdgpu/psp_v13_0.c` (Phoenix)
//! - `drivers/gpu/drm/amd/amdgpu/psp_gfx_if.h` (command ids)

extern crate alloc;

// ── Register offsets (relative to MP0 IP-block base) ───────────────

/// MP0_C2PMSG base offset within the MP0 register window. The
/// per-slot offset is `MP0_C2PMSG_REL + N*4`.
pub const MP0_C2PMSG_REL: u32 = 0x0000_029C;
/// MP0_C2PMSG_64 — phys-lo on input, status word on output.
pub const MP0_C2PMSG_64_REL: u32 = MP0_C2PMSG_REL + 64 * 4;
/// MP0_C2PMSG_67 — phys-hi.
pub const MP0_C2PMSG_67_REL: u32 = MP0_C2PMSG_REL + 67 * 4;
/// MP0_C2PMSG_69 — `(cmd) | (size << 8)` trigger word.
pub const MP0_C2PMSG_69_REL: u32 = MP0_C2PMSG_REL + 69 * 4;

// ── Status word bits ────────────────────────────────────────────────

/// Bit 31 of MP0_C2PMSG_64 after a command — set by PSP when the
/// command has been serviced.
pub const PSP_STATUS_DONE_BIT: u32 = 1 << 31;
/// Bits[30:0] of MP0_C2PMSG_64 — PSP-defined status code (0 = OK).
pub const PSP_STATUS_CODE_MASK: u32 = 0x7FFF_FFFF;

// ── Command codes (cmd low byte of MP0_C2PMSG_69) ───────────────────
//
// The cmd code occupies bits[7:0] of the trigger word; the image
// size in pages or bytes is shifted into bits[31:8] (size << 8).
//
// Mapping mirrors `drivers/gpu/drm/amd/amdgpu/psp_gfx_if.h`
// `enum psp_gfx_cmd_id` verbatim. **The pre-relicense scaffold
// had LOAD_IP_FW = 0x05 wrong** — 0x05 is SETUP_TMR. The correct
// value (and the one Linux actually sends to PSP for IP firmware
// loads) is 0x06. Re-verified against psp_gfx_if.h on
// torvalds/linux 6.10+ (see audit, 2026-05-21).

/// `GFX_CMD_ID_LOAD_TA = 0x01` — load a Trusted Application.
pub const PSP_CMD_LOAD_TA: u32 = 0x01;
/// `GFX_CMD_ID_UNLOAD_TA = 0x02` — unload a previously-loaded TA.
pub const PSP_CMD_UNLOAD_TA: u32 = 0x02;
/// `GFX_CMD_ID_INVOKE_CMD = 0x03` — invoke a command on a loaded TA.
pub const PSP_CMD_INVOKE_CMD: u32 = 0x03;
/// `GFX_CMD_ID_LOAD_ASD = 0x04` — load Authenticated Secure
/// Driver. Used by GFX9-era APUs (Renoir/Cezanne/Green Sardine);
/// GFX11+ uses LOAD_TOC instead.
pub const PSP_CMD_LOAD_ASD: u32 = 0x04;
/// `GFX_CMD_ID_SETUP_TMR = 0x05` — allocate the Trusted Memory
/// Region for the PSP-side firmware staging area. Sent before the
/// big IP-firmware loop.
pub const PSP_CMD_SETUP_TMR: u32 = 0x05;
/// `GFX_CMD_ID_LOAD_IP_FW = 0x06` — load IP-block firmware (DCN,
/// SMU, GFX, SDMA, VCN, RLC, ...). The generic firmware-load
/// command every bring-up step iterates.
pub const PSP_CMD_LOAD_IP_FW: u32 = 0x06;
/// `GFX_CMD_ID_DESTROY_TMR = 0x07` — release the trusted memory region.
pub const PSP_CMD_DESTROY_TMR: u32 = 0x07;
/// `GFX_CMD_ID_SAVE_RESTORE = 0x08` — save/restore IP-block state
/// for suspend/resume.
pub const PSP_CMD_SAVE_RESTORE: u32 = 0x08;
/// `GFX_CMD_ID_LOAD_TOC = 0x20` — load the firmware table-of-
/// contents blob. GFX11+ (Phoenix / Strix); GFX9-era APUs skip.
pub const PSP_CMD_LOAD_TOC: u32 = 0x20;
/// `GFX_CMD_ID_AUTOLOAD_RLC = 0x21` — kick PSP-managed RLC
/// autoload after the IP-firmware loop. GFX11+ only.
pub const PSP_CMD_AUTOLOAD_RLC: u32 = 0x21;
/// `GFX_CMD_ID_BOOT_CFG = 0x22` — query / set the boot
/// configuration (RAS, secure boot enables). Optional;
/// bring-up doesn't strictly need it.
pub const PSP_CMD_BOOT_CFG: u32 = 0x22;

/// Maximum image size encodable in the trigger word. The cmd code
/// is in bits[7:0]; the size lives in bits[31:8] so anything
/// larger than 16 MiB overflows the field.
pub const PSP_MAX_IMAGE_SIZE: u32 = 0x00FF_FFFF;

// ── Errors ──────────────────────────────────────────────────────────

/// PSP mailbox errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PspError {
    /// Step 4 didn't see DONE bit within the poll budget.
    /// Typically means PSP firmware never came up (no power, MP0
    /// base wrong) or the image was malformed enough to wedge
    /// the verifier.
    Timeout,
    /// PSP set DONE but reported a non-zero status code. The
    /// concrete code is PSP-version-specific; common ones are
    /// signature failure, TMR exhaustion, or unknown command.
    Rejected(u32),
    /// Image size doesn't fit in the trigger-word field.
    ImageTooLarge,
    /// Image size is zero (no firmware payload).
    EmptyImage,
    /// MP0 base address is unknown. Typically the chip's IP
    /// discovery binary didn't enumerate MP0, or `bring_up` ran
    /// against pre-discovery silicon with no fallback entry.
    NoMp0Base,
}

// ── Mailbox primitive ───────────────────────────────────────────────

/// Caller's view of MMIO read/write. Plugged in by the driver
/// glue so the protocol is testable against a mock without
/// needing real silicon. Same pattern as [`crate::amdgpu_smu::SmuMmio`].
pub trait PspMmio {
    /// Read `mp0_base + offset` (register-bus address space).
    fn read(&mut self, mp0_base_plus_offset: u32) -> u32;
    /// Write `mp0_base + offset`.
    fn write(&mut self, mp0_base_plus_offset: u32, value: u32);
}

/// Iteration cap on the done-poll. On real silicon a single MMIO
/// read costs ~1 µs and PSP TA-load latency is ~50 ms typical /
/// ~500 ms worst case; one million iterations is the matching
/// upper bound for an empty-cost mock.
pub const PSP_POLL_BUDGET: u32 = 1_000_000;

/// Program the image phys address + cmd, poll for the done bit,
/// and return the PSP status code on success.
///
/// `phys` is the bus-physical address of the image; `size` is in
/// bytes (must fit in `PSP_MAX_IMAGE_SIZE`). `cmd` is one of the
/// `PSP_CMD_*` constants — bring-up paths use `PSP_CMD_LOAD_IP_FW`.
///
/// Returns the raw status code (always 0 here; PSP-rejected
/// commands surface as [`PspError::Rejected`]). Sequence:
///
///   1. Write `phys` lo to MP0_C2PMSG_64.
///   2. Write `phys` hi to MP0_C2PMSG_67.
///   3. Write `(cmd) | (size << 8)` to MP0_C2PMSG_69 — trigger.
///   4. Poll MP0_C2PMSG_64 until bit 31 set.
///   5. Check bits[30:0] for the status code.
pub fn send_command<M: PspMmio>(
    mmio: &mut M,
    mp0_base: u32,
    cmd: u32,
    phys: u64,
    size: u32,
) -> Result<u32, PspError> {
    if size == 0 {
        return Err(PspError::EmptyImage);
    }
    if size > PSP_MAX_IMAGE_SIZE {
        return Err(PspError::ImageTooLarge);
    }

    let lo_off = mp0_base + MP0_C2PMSG_64_REL;
    let hi_off = mp0_base + MP0_C2PMSG_67_REL;
    let trig_off = mp0_base + MP0_C2PMSG_69_REL;

    // Steps 1-2: phys lo / hi.
    mmio.write(lo_off, phys as u32);
    mmio.write(hi_off, (phys >> 32) as u32);
    // Step 3: trigger.
    let trigger = (cmd & 0xFF) | (size << 8);
    mmio.write(trig_off, trigger);

    // Step 4: poll for done.
    let mut i = 0u32;
    let status = loop {
        let v = mmio.read(lo_off);
        if v & PSP_STATUS_DONE_BIT != 0 {
            break v;
        }
        i += 1;
        if i >= PSP_POLL_BUDGET {
            return Err(PspError::Timeout);
        }
    };

    // Step 5: inspect bits[30:0].
    let code = status & PSP_STATUS_CODE_MASK;
    if code != 0 {
        return Err(PspError::Rejected(code));
    }
    Ok(code)
}

/// Convenience wrapper for the bring-up bring-up `LOAD_IP_FW` path.
pub fn load_ip_firmware<M: PspMmio>(
    mmio: &mut M,
    mp0_base: u32,
    phys: u64,
    size: u32,
) -> Result<(), PspError> {
    send_command(mmio, mp0_base, PSP_CMD_LOAD_IP_FW, phys, size).map(|_| ())
}

pub mod test_support {
    //! Test scaffolding exposed for smokes in this crate and
    //! adjacent driver crates. Not part of the production driver
    //! surface.
    use super::*;

    /// Mock MMIO. The test stages reads-per-offset and inspects
    /// writes after `send_command` returns.
    #[derive(Debug)]
    pub struct MockPsp {
        pub reads: alloc::collections::VecDeque<(u32, u32)>,
        pub writes: alloc::vec::Vec<(u32, u32)>,
    }
    impl MockPsp {
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
    impl PspMmio for MockPsp {
        fn read(&mut self, off: u32) -> u32 {
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

pub use test_support::MockPsp;
