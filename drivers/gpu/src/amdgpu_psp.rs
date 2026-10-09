//! AMD Platform Security Processor (PSP) MP0 mailbox.
//!
//! The PSP is the on-die security microcontroller. After the boot ROM hands
//! control off, the host driver must load each IP block's signed firmware
//! blob *through* the PSP — DCN, SMU, GFX, SDMA, VCN, RLC. The PSP verifies
//! the signature, programs the target block's microcode region, and acks.
//! Nothing downstream comes up until the PSP ack lands.
//!
//! ## Two paths, and only one of them is a mailbox
//!
//! The MP0 C2PMSG scratch registers carry exactly three things
//! (`psp_v13_0.c`):
//!
//! | register | use |
//! |----------|-----|
//! | C2PMSG_81 | sign of life — non-zero means sOS is already up |
//! | C2PMSG_36 | bootloader: the component's address **>> 20** |
//! | C2PMSG_35 | bootloader: a [`bootloader_cmd`] value; poll bit 31 here |
//! | C2PMSG_69/70/71 | ring create: ring address lo, hi, size in bytes |
//! | C2PMSG_64 | ring create: `ring_type << 16`; poll bit 31 here |
//!
//! Everything else — `LOAD_IP_FW`, `LOAD_TA`, `LOAD_ASD`, `LOAD_TOC`,
//! `AUTOLOAD_RLC`, `SETUP_TMR` — travels as a `struct psp_gfx_cmd_resp`
//! written into the **GPCOM ring buffer**, not into any register. The
//! [`gfx_cmd_id`] constants below are the `cmd_id` field of that structure.
//! [`crate::amdgpu_psp_ring`] is the module that implements that path, and it
//! is the one the live bring-up uses.
//!
//! LINUX-GAP: [`send_command`] described a fourth path that does not exist in
//! any `psp_v*.c` — image address split lo/hi across C2PMSG_64 and _67, a
//! `cmd | size << 8` trigger word in C2PMSG_69, and the completion polled back
//! out of C2PMSG_64. C2PMSG_67 is not addressed by the driver at all; no
//! command word packs a size; and the one command register that is polled for
//! completion is the one it was written to, never a different slot. It now
//! refuses rather than writing that sequence to live registers; the real
//! mailbox operations are [`bootloader_load_component`] and [`ring_create`].
//!
//! Linux references:
//! - `drivers/gpu/drm/amd/amdgpu/psp_v13_0.c` (Phoenix, MP0 13.0.4)
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_psp.h` (mailbox flags, bootloader cmds)
//! - `drivers/gpu/drm/amd/amdgpu/psp_gfx_if.h` (ring command ids, status masks)
//! - `drivers/gpu/drm/amd/include/asic_reg/mp/mp_13_0_4_offset.h` (registers)

extern crate alloc;

// ── Register offsets (relative to the MP0 IP-block base) ──────────

/// `regMP0_SMN_C2PMSG_0` is dword `0x0040` at BASE_IDX 1, and the slots are
/// one dword apart — `regMP0_SMN_C2PMSG_35` is `0x0063`, `_64` is `0x0080`,
/// `_69` is `0x0085`. As a byte offset within the window that is `0x100`, and
/// slot `N` is `MP0_C2PMSG_REL + N * 4`.
pub const MP0_C2PMSG_REL: u32 = 0x0000_0100;
/// `regMP0_SMN_C2PMSG_35` — the bootloader command, and where its completion
/// is polled.
pub const MP0_C2PMSG_35_REL: u32 = MP0_C2PMSG_REL + 35 * 4;
/// `regMP0_SMN_C2PMSG_36` — the bootloader component's address, shifted right
/// by twenty. The component must therefore sit on a 1 MiB boundary.
pub const MP0_C2PMSG_36_REL: u32 = MP0_C2PMSG_REL + 36 * 4;
/// `regMP0_SMN_C2PMSG_64` — the ring-create command, and where its completion
/// is polled. Also the slot the host waits on for sOS to be ready for a ring.
pub const MP0_C2PMSG_64_REL: u32 = MP0_C2PMSG_REL + 64 * 4;
/// `regMP0_SMN_C2PMSG_69`/`_70`/`_71` — ring address low, high, and size.
pub const MP0_C2PMSG_69_REL: u32 = MP0_C2PMSG_REL + 69 * 4;
pub const MP0_C2PMSG_70_REL: u32 = MP0_C2PMSG_REL + 70 * 4;
pub const MP0_C2PMSG_71_REL: u32 = MP0_C2PMSG_REL + 71 * 4;
/// `regMP0_SMN_C2PMSG_81` — sign of life. `psp_v13_0_is_sos_alive` treats any
/// non-zero value as "the trusted OS is already running".
pub const MP0_C2PMSG_81_REL: u32 = MP0_C2PMSG_REL + 81 * 4;
/// Retained so the invented layout cannot be reintroduced by name: the driver
/// never writes `regMP0_SMN_C2PMSG_67`.
pub const MP0_C2PMSG_67_REL: u32 = MP0_C2PMSG_REL + 67 * 4;

// ── Status word bits ────────────────────────────────────────────────

/// `GFX_FLAG_RESPONSE` / `GFX_CMD_RESPONSE_MASK`: the PSP sets bit 31 of the
/// command register it was given when it has serviced that command.
pub const PSP_STATUS_DONE_BIT: u32 = 0x8000_0000;
/// `GFX_CMD_STATUS_MASK` — the status code is the low **sixteen** bits, not
/// bits 30:0. `GFX_CMD_RESERVED_MASK` (`0x7FF0_0000`) covers most of what sits
/// between, so masking 30:0 would read reserved bits as a failure code.
pub const PSP_STATUS_CODE_MASK: u32 = 0x0000_FFFF;
/// `MBOX_TOS_RESP_MASK` / `MBOX_TOS_READY_MASK`: what `psp_wait_for` compares
/// against the response flag.
pub const PSP_STATUS_WAIT_MASK: u32 = PSP_STATUS_DONE_BIT | PSP_STATUS_CODE_MASK;

// ── Bootloader commands (C2PMSG_35) ───────────────────────────────

/// `enum psp_bootloader_cmd`. These are the only command values the MP0
/// mailbox itself accepts for loading a blob, and each loads one specific
/// bootloader component — never an arbitrary IP firmware.
pub mod bootloader_cmd {
    pub const LOAD_SYSDRV: u32 = 0x0001_0000;
    pub const LOAD_SOSDRV: u32 = 0x0002_0000;
    pub const LOAD_KEY_DATABASE: u32 = 0x0008_0000;
    pub const LOAD_SOCDRV: u32 = 0x000B_0000;
    pub const LOAD_DBGDRV: u32 = 0x000C_0000;
    pub const LOAD_INTFDRV: u32 = 0x000D_0000;
    pub const LOAD_RASDRV: u32 = 0x000E_0000;
    pub const LOAD_IPKEYMGRDRV: u32 = 0x000F_0000;
    pub const DRAM_LONG_TRAIN: u32 = 0x0010_0000;
    pub const DRAM_SHORT_TRAIN: u32 = 0x0020_0000;
    pub const LOAD_TOS_SPL_TABLE: u32 = 0x1000_0000;
    pub const LOAD_SPDMDRV: u32 = 0x2000_0000;
}

// ── Ring control commands (C2PMSG_64) ─────────────────────────────

/// `enum psp_gfx_ctrl_cmd_id`, written to C2PMSG_64 to create or tear down
/// the PSP command rings. Note the values are already shifted: the id lives
/// in bits 31:16, which is why `psp_v13_0_ring_create` writes
/// `ring_type << 16`.
pub mod gfx_ctrl_cmd_id {
    pub const INIT_RBI_RING: u32 = 0x0001_0000;
    pub const INIT_GPCOM_RING: u32 = 0x0002_0000;
    pub const DESTROY_RINGS: u32 = 0x0003_0000;
    pub const CAN_INIT_RINGS: u32 = 0x0004_0000;
    pub const ENABLE_INT: u32 = 0x0005_0000;
    pub const DISABLE_INT: u32 = 0x0006_0000;
    pub const MODE1_RST: u32 = 0x0007_0000;
    pub const GBR_IH_SET: u32 = 0x0008_0000;
    pub const CONSUME_CMD: u32 = 0x0009_0000;
    pub const DESTROY_GPCOM_RING: u32 = 0x000C_0000;
}

// ── Ring command ids (GPCOM ring buffer, NOT a register) ──────────

/// `enum psp_gfx_cmd_id`. These are the `cmd_id` field of a
/// `struct psp_gfx_cmd_resp` placed in the GPCOM ring buffer — see
/// [`crate::amdgpu_psp_ring`]. Writing one of these to a C2PMSG register does
/// nothing: the mailbox commands are [`bootloader_cmd`] and
/// [`gfx_ctrl_cmd_id`].
pub mod gfx_cmd_id {
    pub const LOAD_TA: u32 = 0x01;
    pub const UNLOAD_TA: u32 = 0x02;
    pub const INVOKE_CMD: u32 = 0x03;
    pub const LOAD_ASD: u32 = 0x04;
    pub const SETUP_TMR: u32 = 0x05;
    pub const LOAD_IP_FW: u32 = 0x06;
    pub const DESTROY_TMR: u32 = 0x07;
    pub const SAVE_RESTORE: u32 = 0x08;
    pub const SETUP_VMR: u32 = 0x09;
    pub const DESTROY_VMR: u32 = 0x0A;
    pub const PROG_REG: u32 = 0x0B;
    pub const GET_FW_ATTESTATION: u32 = 0x0F;
    pub const LOAD_TOC: u32 = 0x20;
    pub const AUTOLOAD_RLC: u32 = 0x21;
    pub const BOOT_CFG: u32 = 0x22;
}

pub use gfx_cmd_id::{
    AUTOLOAD_RLC as PSP_CMD_AUTOLOAD_RLC, BOOT_CFG as PSP_CMD_BOOT_CFG,
    DESTROY_TMR as PSP_CMD_DESTROY_TMR, INVOKE_CMD as PSP_CMD_INVOKE_CMD,
    LOAD_ASD as PSP_CMD_LOAD_ASD, LOAD_IP_FW as PSP_CMD_LOAD_IP_FW, LOAD_TA as PSP_CMD_LOAD_TA,
    LOAD_TOC as PSP_CMD_LOAD_TOC, SAVE_RESTORE as PSP_CMD_SAVE_RESTORE,
    SETUP_TMR as PSP_CMD_SETUP_TMR, UNLOAD_TA as PSP_CMD_UNLOAD_TA,
};

/// A bootloader component's address is shifted right by twenty, so the top of
/// the addressable range is what a u32 of megabytes covers. Images themselves
/// have no size field in the mailbox at all.
pub const PSP_BOOTLOADER_ALIGN: u64 = 1 << 20;

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
    /// A bootloader component's address was not 1 MiB aligned, so the
    /// `>> 20` the mailbox applies would discard part of it.
    Misaligned,
    /// The requested command is a GPCOM ring command, not a mailbox command.
    /// See [`send_command`].
    NotAMailboxCommand,
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

/// The real MP0 mailbox write-then-poll: write `value` to `cmd_reg`, then
/// poll that same register until bit 31 is set, and read the status out of
/// the low sixteen bits. `psp_wait_for` waits on the register the command was
/// written to — never a different slot.
fn mailbox_wait<M: PspMmio>(mmio: &mut M, cmd_reg: u32, value: u32) -> Result<(), PspError> {
    mmio.write(cmd_reg, value);
    let mut i = 0u32;
    let status = loop {
        let v = mmio.read(cmd_reg);
        if v & PSP_STATUS_DONE_BIT != 0 {
            break v;
        }
        i += 1;
        if i >= PSP_POLL_BUDGET {
            return Err(PspError::Timeout);
        }
    };
    let code = status & PSP_STATUS_CODE_MASK;
    if code != 0 {
        return Err(PspError::Rejected(code));
    }
    Ok(())
}

/// `psp_v13_0_is_sos_alive`: a non-zero sign-of-life register means the
/// trusted OS is already running and the bootloader loads must be skipped.
pub fn is_sos_alive<M: PspMmio>(mmio: &mut M, mp0_base: u32) -> bool {
    mmio.read(mp0_base + MP0_C2PMSG_81_REL) != 0
}

/// `psp_v13_0_bootloader_load_component`: hand one bootloader component to the
/// boot ROM. The address goes to C2PMSG_36 **shifted right by twenty**, the
/// command to C2PMSG_35, and C2PMSG_35 is then polled — there is no size and
/// no high-half register.
///
/// `cmd` is a [`bootloader_cmd`] value. `phys` must be 1 MiB aligned, since
/// the low twenty bits are discarded by the shift rather than rounded.
pub fn bootloader_load_component<M: PspMmio>(
    mmio: &mut M,
    mp0_base: u32,
    cmd: u32,
    phys: u64,
    size: u32,
) -> Result<(), PspError> {
    if size == 0 {
        return Err(PspError::EmptyImage);
    }
    if phys % PSP_BOOTLOADER_ALIGN != 0 {
        return Err(PspError::Misaligned);
    }
    mmio.write(mp0_base + MP0_C2PMSG_36_REL, (phys >> 20) as u32);
    mailbox_wait(mmio, mp0_base + MP0_C2PMSG_35_REL, cmd)
}

/// `psp_v13_0_ring_create` (the non-SR-IOV path): wait for sOS to be ready on
/// C2PMSG_64, publish the ring address and size across C2PMSG_69/70/71, then
/// write `ring_type << 16` to C2PMSG_64 and poll it.
///
/// `ring_type` is the unshifted `enum psp_ring_type`; the shift is applied
/// here, matching the `psp_ring_reg << 16` in Linux.
pub fn ring_create<M: PspMmio>(
    mmio: &mut M,
    mp0_base: u32,
    ring_phys: u64,
    ring_size_bytes: u32,
    ring_type: u32,
) -> Result<(), PspError> {
    if ring_size_bytes == 0 {
        return Err(PspError::EmptyImage);
    }
    // Wait for the trusted OS to be ready before publishing anything.
    let ready_reg = mp0_base + MP0_C2PMSG_64_REL;
    let mut i = 0u32;
    while mmio.read(ready_reg) & PSP_STATUS_DONE_BIT == 0 {
        i += 1;
        if i >= PSP_POLL_BUDGET {
            return Err(PspError::Timeout);
        }
    }
    mmio.write(mp0_base + MP0_C2PMSG_69_REL, ring_phys as u32);
    mmio.write(mp0_base + MP0_C2PMSG_70_REL, (ring_phys >> 32) as u32);
    mmio.write(mp0_base + MP0_C2PMSG_71_REL, ring_size_bytes);
    mailbox_wait(mmio, ready_reg, ring_type << 16)
}

/// Send a ring-control command (`GFX_CTRL_CMD_ID_*`) on C2PMSG_64. The values
/// in [`gfx_ctrl_cmd_id`] are already positioned in bits 31:16.
pub fn ring_control<M: PspMmio>(
    mmio: &mut M,
    mp0_base: u32,
    ctrl_cmd: u32,
) -> Result<(), PspError> {
    mailbox_wait(mmio, mp0_base + MP0_C2PMSG_64_REL, ctrl_cmd)
}

/// Refuses, and says why.
///
/// LINUX-GAP: there is no MP0 mailbox command that loads an arbitrary IP
/// firmware. `GFX_CMD_ID_LOAD_IP_FW` and its siblings are the `cmd_id` of a
/// `psp_gfx_cmd_resp` structure placed in the GPCOM ring buffer, which
/// [`crate::amdgpu_psp_ring`] builds and which the live bring-up path uses.
/// The sequence this used to perform — address split across C2PMSG_64/_67, a
/// `cmd | size << 8` trigger in C2PMSG_69, completion read back out of
/// C2PMSG_64 — appears in no `psp_v*.c` and would have written a size into a
/// register the PSP does not read as one. It refuses rather than doing that
/// to live silicon.
pub fn send_command<M: PspMmio>(
    _mmio: &mut M,
    _mp0_base: u32,
    _cmd: u32,
    _phys: u64,
    _size: u32,
) -> Result<u32, PspError> {
    Err(PspError::NotAMailboxCommand)
}

/// Refuses; see [`send_command`].
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
    impl Default for MockPsp {
        fn default() -> Self {
            Self::new()
        }
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
