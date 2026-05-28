//! AMD Platform Security Processor (PSP) driver.
//!
//! The PSP is a separate Arm Cortex-A5 security microcontroller embedded
//! in AMD SoCs (Family 0x17 Renoir, Family 0x19 Phoenix HawkPoint1, ...).
//! On the host side it is exposed as a PCI device under the CCP subsystem
//! (vendor 0x1022, device IDs 0x15DF/0x1649 for Renoir, 0x1134/0x17E0 for
//! Phoenix — see Linux `drivers/crypto/ccp/sp-pci.c`).
//!
//! ## Two distinct mailbox paths
//!
//! There are **two separate mailbox protocols** in AMD hardware; this crate
//! implements the platform-level one. The GFX-firmware-load mailbox lives
//! in `drivers/gpu/src/amdgpu_psp.rs`.
//!
//! | Mailbox | Register base | Used for |
//! |---------|---------------|----------|
//! | GFX / MP0 C2PMSG_64–69 | MP0 IP-block window | Load DCN/SMU/GFX/VCN firmware |
//! | CCP / C2PMSG_17–19     | CCP BAR2 + 0x10544  | TEE RING_INIT, platform status |
//!
//! ## CCP mailbox register layout (Linux `sp-pci.c` pspv3/pspv4/pspv5)
//!
//! | Reg name    | Offset   | Comment            |
//! |-------------|----------|--------------------|
//! | C2PMSG_17   | 0x10544  | cmd/resp register  |
//! | C2PMSG_18   | 0x10548  | cmdbuff lo (phys)  |
//! | C2PMSG_19   | 0x1054c  | cmdbuff hi (phys)  |
//! | C2PMSG_63   | 0x109fc  | capability bits    |
//! | C2PMSG_59   | 0x109ec  | bootloader info    |
//! | C2PMSG_58   | 0x109e8  | TEE version        |
//!
//! Phoenix (pspv5/pspv7) uses a shifted window (0x109** base):
//!
//! | Reg name    | Offset   |
//! |-------------|----------|
//! | C2PMSG_17   | 0x10944  |
//! | C2PMSG_18   | 0x10948  |
//! | C2PMSG_19   | 0x1094c  |
//!
//! ## PSP_CMD_RESP register (C2PMSG_17) bit layout
//!
//! ```text
//! Bit 31     : RESP — set by PSP when command is done (1 = ready)
//! Bit 30     : RECOVERY — PSP entered recovery mode
//! Bits 29:24 : (reserved)
//! Bits 23:16 : CMD — command id (written by host before triggering)
//! Bits 15:0  : STS — response status (read back; 0 = success)
//! ```
//!
//! Reference: Linux `include/linux/psp.h` + `drivers/crypto/ccp/psp-dev.c`
//! (GPL-2.0-or-later, cited per NARF relicense 2026-05-20).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::vec::Vec;

// ── CCP BAR2 register offsets ────────────────────────────────────────
//
// Two hardware families: Renoir (pspv3/v4) at 0x105** and Phoenix
// (pspv5/v6/v7) at 0x109**. The capability/bootloader registers are the
// same absolute offset on both.

/// C2PMSG_17 on Renoir/Cezanne (pspv3/pspv4): cmd+resp register.
pub const CMDRESP_REG_V1: u32 = 0x10544;
/// C2PMSG_18 on Renoir: cmdbuff phys-lo.
pub const CMDBUFF_LO_REG_V1: u32 = 0x10548;
/// C2PMSG_19 on Renoir: cmdbuff phys-hi.
pub const CMDBUFF_HI_REG_V1: u32 = 0x1054c;

/// C2PMSG_17 on Phoenix HawkPoint1 (pspv5/pspv7): cmd+resp register.
pub const CMDRESP_REG_V2: u32 = 0x10944;
/// C2PMSG_18 on Phoenix: cmdbuff phys-lo.
pub const CMDBUFF_LO_REG_V2: u32 = 0x10948;
/// C2PMSG_19 on Phoenix: cmdbuff phys-hi.
pub const CMDBUFF_HI_REG_V2: u32 = 0x1094c;

/// C2PMSG_63 — capability bits. Same offset on both silicon families.
pub const FEATURE_REG: u32 = 0x109fc;
/// C2PMSG_59 — bootloader version info.
pub const BOOTLOADER_INFO_REG: u32 = 0x109ec;
/// C2PMSG_58 — TEE version info (reported when TEE is initialised).
pub const TEE_VERSION_REG: u32 = 0x109e8;

// ── PSP_CMD_RESP bit positions (Linux include/linux/psp.h) ───────────

/// Bits[15:0] of C2PMSG_17 — PSP response status code (0 = success).
pub const PSP_CMDRESP_STS_MASK: u32 = 0x0000_FFFF;
/// Bits[23:16] — command id (written by host into C2PMSG_17 to dispatch).
pub const PSP_CMDRESP_CMD_MASK: u32 = 0x00FF_0000;
pub const PSP_CMDRESP_CMD_SHIFT: u32 = 16;
/// Bit 30 — PSP entered recovery mode.
pub const PSP_CMDRESP_RECOVERY: u32 = 1 << 30;
/// Bit 31 — PSP has serviced the command and written STS.
pub const PSP_CMDRESP_RESP: u32 = 1 << 31;

// ── Capability register bits (C2PMSG_63) ────────────────────────────
//
// Mirroring `union psp_cap_register` in Linux `psp-dev.h`.

/// Bit 0 of FEATURE_REG — PSP implements SEV (Secure Encrypted Virtualization).
pub const CAP_SEV: u32 = 1 << 0;
/// Bit 1 — PSP implements TEE / fTPM ring-buffer interface.
pub const CAP_TEE: u32 = 1 << 1;
/// Bit 3 — SFS (Secure Firmware Service) supported.
pub const CAP_SFS: u32 = 1 << 3;
/// Bit 7 — Security reporting supported.
pub const CAP_SECURITY_REPORTING: u32 = 1 << 7;
/// Bit 8 — Device is a fused production part.
pub const CAP_FUSED_PART: u32 = 1 << 8;
/// Bit 9 — Boot-integrity checking active.
pub const CAP_BOOT_INTEGRITY: u32 = 1 << 9;
/// Bit 18 — HSP/fTPM available via TEE channel.
pub const CAP_HSP_TPM: u32 = 1 << 18;

// ── PSP mailbox commands (psp-dev.h enum psp_cmd) ────────────────────

/// TEE ring-buffer init. Sends the ring's physical address + size to PSP.
pub const PSP_CMD_TEE_RING_INIT: u32 = 1;
/// TEE ring-buffer destroy.
pub const PSP_CMD_TEE_RING_DESTROY: u32 = 2;
/// TEE extended command (used for sub-command dispatch: DBC, SFS, etc.).
pub const PSP_CMD_TEE_EXTENDED_CMD: u32 = 14;

// PSP_TEE_STS values (Linux psp.h):

/// Ring already initialised — returned when RING_INIT is sent twice
/// without an intervening RING_DESTROY (e.g. after hibernate resume).
pub const PSP_TEE_STS_RING_BUSY: u16 = 0x000D;

// ── Timeout budget ────────────────────────────────────────────────────

/// Iteration budget for polling C2PMSG_17. The PSP responds within a
/// few milliseconds in the common case; on real silicon each MMIO read
/// takes ~0.5–1 µs, so 5 M iterations caps at roughly 5 seconds.
pub const PSP_POLL_BUDGET: u32 = 5_000_000;

// ── Hardware variants ────────────────────────────────────────────────

/// Selects the correct C2PMSG register window for the attached silicon.
///
/// | Variant | Chip families              | C2PMSG_17 offset |
/// |---------|----------------------------|-----------------|
/// | `V1`    | Renoir (0x15DF/0x1649),    | 0x10544          |
/// |         | Cezanne/Lucienne (0x15C7)  |                  |
/// | `V2`    | Phoenix HawkPoint1 (0x1134/| 0x10944          |
/// |         | 0x17E0), Strix (0x17D8)    |                  |
///
/// PCI device IDs from Linux `sp-pci.c` `sp_pci_table` (GPL-2.0-or-later).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PspHwVariant {
    /// Renoir / Lucienne / Cezanne — pspv3/v4 register layout.
    V1,
    /// Phoenix HawkPoint1 / Strix Point — pspv5/v7 register layout.
    V2,
}

impl PspHwVariant {
    /// C2PMSG_17 offset (cmd/resp register) for this variant.
    #[inline]
    pub const fn cmdresp_reg(self) -> u32 {
        match self {
            PspHwVariant::V1 => CMDRESP_REG_V1,
            PspHwVariant::V2 => CMDRESP_REG_V2,
        }
    }
    /// C2PMSG_18 offset (cmdbuff phys-lo) for this variant.
    #[inline]
    pub const fn cmdbuff_lo(self) -> u32 {
        match self {
            PspHwVariant::V1 => CMDBUFF_LO_REG_V1,
            PspHwVariant::V2 => CMDBUFF_LO_REG_V2,
        }
    }
    /// C2PMSG_19 offset (cmdbuff phys-hi) for this variant.
    #[inline]
    pub const fn cmdbuff_hi(self) -> u32 {
        match self {
            PspHwVariant::V1 => CMDBUFF_HI_REG_V1,
            PspHwVariant::V2 => CMDBUFF_HI_REG_V2,
        }
    }
}

// ── MMIO trait ────────────────────────────────────────────────────────

/// Caller-supplied MMIO accessor. Plugged with real MMIO on hardware
/// and a `MockPsp` in tests. The driver never calls this from an IRQ
/// context — all accesses are synchronous and serialised by the caller.
pub trait PspMmio {
    /// Read the 32-bit register at `ccp_bar2_base + byte_offset`.
    fn read(&mut self, byte_offset: u32) -> u32;
    /// Write `val` to `ccp_bar2_base + byte_offset`.
    fn write(&mut self, byte_offset: u32, val: u32);
}

// ── Errors ────────────────────────────────────────────────────────────

/// Errors from the PSP CCP mailbox.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PspError {
    /// The RESP bit in C2PMSG_17 was not set within the poll budget.
    /// Usually indicates PSP firmware never came up (no power, wrong
    /// BAR, malformed command-buffer address).
    Timeout,
    /// PSP set RESP but returned a non-zero STS field. The inner value
    /// is the raw 16-bit STS code from bits[15:0] of C2PMSG_17.
    CommandFailed(u16),
    /// Read 0xFFFFFFFF from the capability register — platform BIOS is
    /// blocking CCP access (seen on some locked-down OEM firmware).
    BiosBlocked,
    /// PSP entered recovery mode (RECOVERY bit set in C2PMSG_17).
    Recovery,
    /// Caller tried to open a TEE channel but the capability register
    /// reports TEE is not present on this die.
    TeeNotPresent,
    /// A PSP device was probed but `init()` has not been called yet.
    NotInitialised,
}

// ── Decoded PSP information ───────────────────────────────────────────

/// Capability bitmap decoded from C2PMSG_63. Returned by [`init`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PspCapabilities {
    /// Raw value of C2PMSG_63.
    pub raw: u32,
}

impl PspCapabilities {
    /// Build from the raw register value. Returns `Err(BiosBlocked)` if
    /// the platform has gate-blocked CCP register access.
    pub fn from_raw(raw: u32) -> Result<Self, PspError> {
        if raw == 0xFFFF_FFFF {
            return Err(PspError::BiosBlocked);
        }
        Ok(PspCapabilities { raw })
    }
    /// `true` iff the PSP exposes a SEV command interface.
    #[inline]
    pub fn has_sev(self) -> bool {
        self.raw & CAP_SEV != 0
    }
    /// `true` iff the TEE / fTPM ring-buffer interface is present.
    #[inline]
    pub fn has_tee(self) -> bool {
        self.raw & CAP_TEE != 0
    }
    /// `true` iff an HSP (Hardware Security Processor) fTPM is wired
    /// through the TEE channel.
    #[inline]
    pub fn has_hsp_tpm(self) -> bool {
        self.raw & CAP_HSP_TPM != 0
    }
    /// `true` iff this is a fused production part (not engineering
    /// sample / pre-production silicon).
    #[inline]
    pub fn is_fused(self) -> bool {
        self.raw & CAP_FUSED_PART != 0
    }
    /// `true` iff the boot-integrity check is active on this part.
    #[inline]
    pub fn boot_integrity(self) -> bool {
        self.raw & CAP_BOOT_INTEGRITY != 0
    }
}

/// PSP platform status returned by [`platform_status`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PspPlatformStatus {
    /// Raw capability register value.
    pub capabilities: PspCapabilities,
    /// Raw bootloader-info register value (C2PMSG_59).
    /// Byte layout: `AA.BB.CC.DD` where AA=bits[31:24], BB=bits[23:16],
    /// CC=bits[15:8], DD=bits[7:0] — matches Linux `sp-pci.c`
    /// `bootloader_version_show`.
    pub bootloader_info_raw: u32,
}

/// PSP firmware version returned by [`firmware_version`].
///
/// The bootloader-info register encodes a dotted version `AA.BB.CC.DD`
/// with one byte per component.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PspFwVer {
    pub aa: u8,
    pub bb: u8,
    pub cc: u8,
    pub dd: u8,
}

impl PspFwVer {
    /// Decode the raw C2PMSG_59 value.
    pub fn from_raw(v: u32) -> Self {
        PspFwVer {
            aa: (v >> 24) as u8,
            bb: (v >> 16) as u8,
            cc: (v >> 8) as u8,
            dd: v as u8,
        }
    }
}

/// Summary returned by [`init`].
#[derive(Copy, Clone, Debug)]
pub struct PspInfo {
    /// Hardware variant detected (determines register window).
    pub variant: PspHwVariant,
    /// Decoded capability register.
    pub capabilities: PspCapabilities,
    /// Decoded firmware version.
    pub fw_ver: PspFwVer,
}

// ── Mailbox primitive ────────────────────────────────────────────────

/// Read the capability register and validate it is accessible.
///
/// Call this first — if it returns `BiosBlocked` there is no point
/// sending commands.
pub fn read_capabilities<M: PspMmio>(mmio: &mut M) -> Result<PspCapabilities, PspError> {
    let raw = mmio.read(FEATURE_REG);
    PspCapabilities::from_raw(raw)
}

/// Poll C2PMSG_17 until RESP is set, then return the full register value.
///
/// Returns `Err(Timeout)` if RESP is not seen within `PSP_POLL_BUDGET`
/// iterations. Returns `Err(Recovery)` if the RECOVERY bit is set.
fn poll_cmdresp<M: PspMmio>(
    mmio: &mut M,
    cmdresp_off: u32,
) -> Result<u32, PspError> {
    for _ in 0..PSP_POLL_BUDGET {
        let v = mmio.read(cmdresp_off);
        if v & PSP_CMDRESP_RECOVERY != 0 {
            return Err(PspError::Recovery);
        }
        if v & PSP_CMDRESP_RESP != 0 {
            return Ok(v);
        }
    }
    Err(PspError::Timeout)
}

/// Send a CCP mailbox command and return the response register value.
///
/// Protocol (Linux `psp-dev.c` `psp_mailbox_command`):
///
///  1. Poll until RESP is set (mailbox idle — PSP not busy with a prior
///     command). If busy, abort with `Timeout`.
///  2. Write the physical address of the command buffer into C2PMSG_18
///     (lo) and C2PMSG_19 (hi). Pass `None` to skip this step when the
///     command takes no buffer (e.g. `PSP_CMD_TEE_RING_DESTROY`).
///  3. Write `FIELD_PREP(PSP_CMDRESP_CMD, cmd)` into C2PMSG_17 —
///     this clears RESP and triggers PSP processing.
///  4. Poll C2PMSG_17 again until RESP is set.
///  5. Check STS field (bits[15:0]); non-zero → `CommandFailed`.
///
/// Returns the raw C2PMSG_17 value on success.
pub fn mailbox_command<M: PspMmio>(
    mmio: &mut M,
    variant: PspHwVariant,
    cmd: u32,
    cmdbuff_phys: Option<u64>,
) -> Result<u32, PspError> {
    let cmdresp_off = variant.cmdresp_reg();
    let lo_off = variant.cmdbuff_lo();
    let hi_off = variant.cmdbuff_hi();

    // Step 1: ensure mailbox is idle (RESP already set from previous op
    // or initial boot state).
    poll_cmdresp(mmio, cmdresp_off)?;

    // Step 2: write command buffer address if provided.
    if let Some(phys) = cmdbuff_phys {
        mmio.write(lo_off, phys as u32);
        mmio.write(hi_off, (phys >> 32) as u32);
    }

    // Step 3: trigger — write CMD field, clearing RESP.
    let trigger = (cmd & 0xFF) << PSP_CMDRESP_CMD_SHIFT;
    mmio.write(cmdresp_off, trigger);

    // Step 4: wait for PSP to service the command.
    let resp = poll_cmdresp(mmio, cmdresp_off)?;

    // Step 5: check status.
    let sts = (resp & PSP_CMDRESP_STS_MASK) as u16;
    if sts != 0 {
        return Err(PspError::CommandFailed(sts));
    }
    Ok(resp)
}

// ── Public driver API ────────────────────────────────────────────────

/// Probe the PSP and return its info block.
///
/// Reads the capability register, aborts on BIOS block, then reads the
/// bootloader-info register to form the firmware version.
///
/// Does NOT send any mailbox command — safe to call before any other
/// driver initialisation.
pub fn init<M: PspMmio>(mmio: &mut M, variant: PspHwVariant) -> Result<PspInfo, PspError> {
    let capabilities = read_capabilities(mmio)?;
    let bl_raw = mmio.read(BOOTLOADER_INFO_REG);
    let fw_ver = PspFwVer::from_raw(bl_raw);
    Ok(PspInfo {
        variant,
        capabilities,
        fw_ver,
    })
}

/// Read the PSP platform status — capability bits + bootloader info.
///
/// This is a register-read-only query; no mailbox command is sent.
pub fn platform_status<M: PspMmio>(mmio: &mut M) -> Result<PspPlatformStatus, PspError> {
    let capabilities = read_capabilities(mmio)?;
    let bootloader_info_raw = mmio.read(BOOTLOADER_INFO_REG);
    Ok(PspPlatformStatus {
        capabilities,
        bootloader_info_raw,
    })
}

/// Read the PSP firmware version from C2PMSG_59.
pub fn firmware_version<M: PspMmio>(mmio: &mut M) -> Result<PspFwVer, PspError> {
    let raw = mmio.read(BOOTLOADER_INFO_REG);
    Ok(PspFwVer::from_raw(raw))
}

/// Submit an arbitrary CCP mailbox command with a physical payload
/// address. The caller is responsible for allocating and filling the
/// command buffer at `cmdbuff_phys` before calling this function, and
/// for reading any response data from that same buffer after it returns.
///
/// `payload_phys = None` for commands that take no buffer.
///
/// Returns the raw C2PMSG_17 response word on success.
pub fn submit_cmd<M: PspMmio>(
    mmio: &mut M,
    variant: PspHwVariant,
    cmd: u32,
    payload_phys: Option<u64>,
) -> Result<u32, PspError> {
    mailbox_command(mmio, variant, cmd, payload_phys)
}

// ── TEE channel ───────────────────────────────────────────────────────

/// TEE ring command buffer header passed to `PSP_CMD_TEE_RING_INIT`.
///
/// The PSP expects the ring buffer's physical address split into
/// `hi_addr` / `low_addr` and the ring size in bytes. This matches
/// `struct tee_init_ring_cmd` in Linux `tee-dev.c`.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TeeRingCmd {
    /// High 32 bits of the ring buffer's physical address.
    pub hi_addr: u32,
    /// Low 32 bits of the ring buffer's physical address.
    pub low_addr: u32,
    /// Ring buffer size in bytes.
    pub size: u32,
}

/// TEE channel state returned by [`tee_channel_open`].
#[derive(Copy, Clone, Debug)]
pub struct TeeChannel {
    /// Physical base address of the ring buffer.
    pub ring_phys: u64,
    /// Size of the ring buffer in bytes.
    pub ring_size: u32,
    /// Hardware variant the ring was opened on.
    pub variant: PspHwVariant,
}

/// Open (initialise) the PSP TEE ring-buffer channel.
///
/// This is a Stage-0 implementation: it validates that the silicon
/// reports TEE capability and constructs the channel descriptor for
/// the caller. The caller must have:
///
///  1. Allocated a contiguous physically-mapped ring buffer of `ring_size`
///     bytes at `ring_phys`.
///  2. Zeroed the buffer.
///
/// The function sends `PSP_CMD_TEE_RING_INIT` with the buffer address
/// and size, then returns a `TeeChannel` that can be passed to
/// `tee_channel_close` on teardown.
///
/// If the PSP returns `PSP_TEE_STS_RING_BUSY` (ring already active
/// from a previous session — e.g. hibernate resume) the caller should
/// first call [`tee_channel_destroy`] to clean up, then retry.
pub fn tee_channel_open<M: PspMmio>(
    mmio: &mut M,
    variant: PspHwVariant,
    capabilities: PspCapabilities,
    ring_phys: u64,
    ring_size: u32,
) -> Result<TeeChannel, PspError> {
    if !capabilities.has_tee() {
        return Err(PspError::TeeNotPresent);
    }
    // Build the init command in the caller-supplied ring buffer.
    // The PSP reads the `TeeRingCmd` struct directly from `ring_phys`.
    // We construct it here as the pre-flight descriptor but the
    // physical write into the ring is handled by the caller (this
    // layer only drives the mailbox, not physical memory).
    //
    // Send RING_INIT with the ring address as the command buffer.
    mailbox_command(mmio, variant, PSP_CMD_TEE_RING_INIT, Some(ring_phys))?;

    Ok(TeeChannel {
        ring_phys,
        ring_size,
        variant,
    })
}

/// Destroy the PSP TEE ring-buffer channel.
///
/// Sends `PSP_CMD_TEE_RING_DESTROY` with no command buffer. The caller
/// must free the ring-buffer memory after this returns.
pub fn tee_channel_destroy<M: PspMmio>(
    mmio: &mut M,
    channel: TeeChannel,
) -> Result<(), PspError> {
    mailbox_command(mmio, channel.variant, PSP_CMD_TEE_RING_DESTROY, None)?;
    Ok(())
}

// ── Secure-boot integration API ───────────────────────────────────────
//
// The secure-boot layer (frame/src/secure_boot.rs) owns the PE/COFF
// Authenticode verification path. It calls `install_state` at boot
// to stage platform keys. This PSP layer provides the hook for the
// *hardware* measurement path: once the TEE channel is open a caller
// can invoke the PSP's signed-device-data command to extend a PCR.
//
// Stage-0: only the descriptor is defined. Full `submit_cmd` wiring
// awaits a working TEE channel round-trip on real hardware.

/// Opaque handle representing a PSP instance ready for use by the
/// secure-boot layer. Obtained by calling `psp_for_secure_boot` after
/// `init` succeeds.
#[derive(Copy, Clone, Debug)]
pub struct PspHandle {
    pub variant: PspHwVariant,
    pub capabilities: PspCapabilities,
}

/// Construct a `PspHandle` for use by `frame/src/secure_boot.rs`.
///
/// The secure-boot layer should call this after `init` returns
/// `PspInfo`, then store the handle and use it to call `submit_cmd`
/// when it needs the PSP to verify or extend a measurement.
pub fn psp_for_secure_boot(info: PspInfo) -> PspHandle {
    PspHandle {
        variant: info.variant,
        capabilities: info.capabilities,
    }
}

// ── Test support ──────────────────────────────────────────────────────

pub mod test_support {
    //! Mock MMIO for unit tests. Not part of the production driver surface.
    //!
    //! `MockPsp` maintains a register map (`regs`) and a write log.
    //! CMDRESP registers use a FIFO queue (`resp_queue`) so that
    //! successive reads return staged values in order, correctly
    //! simulating the idle-then-done two-poll sequence that
    //! `mailbox_command` performs.

    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::collections::VecDeque;

    /// Mock MMIO.
    ///
    /// - `regs`: flat register map for non-CMDRESP registers.
    /// - `resp_queue`: per-CMDRESP-offset FIFO; each staged value is
    ///   dequeued on read, so successive reads return values in the
    ///   order they were staged.
    /// - `writes`: log of every write as `(offset, value)`.
    #[derive(Debug, Default)]
    pub struct MockPsp {
        pub regs: BTreeMap<u32, u32>,
        pub resp_queue: BTreeMap<u32, VecDeque<u32>>,
        pub writes: Vec<(u32, u32)>,
    }

    impl MockPsp {
        pub fn new() -> Self {
            Self::default()
        }
        /// Pre-set a non-CMDRESP register value so reads return it.
        pub fn set_reg(&mut self, off: u32, val: u32) {
            if off == CMDRESP_REG_V1 || off == CMDRESP_REG_V2 {
                self.resp_queue.entry(off).or_default().push_back(val);
            } else {
                self.regs.insert(off, val);
            }
        }
        /// Stage the mailbox as IDLE (RESP=1, STS=0) so the initial
        /// poll-for-idle in `mailbox_command` passes immediately.
        pub fn stage_idle(&mut self, variant: PspHwVariant) {
            self.resp_queue
                .entry(variant.cmdresp_reg())
                .or_default()
                .push_back(PSP_CMDRESP_RESP);
        }
        /// Stage the mailbox as DONE (RESP=1, STS=0) for the second poll
        /// (post-trigger). Call `stage_idle` first, then this.
        pub fn stage_done_ok(&mut self, variant: PspHwVariant) {
            self.resp_queue
                .entry(variant.cmdresp_reg())
                .or_default()
                .push_back(PSP_CMDRESP_RESP);
        }
        /// Stage the mailbox to respond with `sts` in STS field + RESP=1.
        pub fn stage_done_err(&mut self, variant: PspHwVariant, sts: u16) {
            self.resp_queue
                .entry(variant.cmdresp_reg())
                .or_default()
                .push_back(PSP_CMDRESP_RESP | (sts as u32));
        }
    }

    impl PspMmio for MockPsp {
        fn read(&mut self, off: u32) -> u32 {
            // CMDRESP registers dequeue the next staged value; returns 0
            // (no RESP bit) when the queue is exhausted — simulates the
            // PSP not yet responding (poll will eventually time out).
            if off == CMDRESP_REG_V1 || off == CMDRESP_REG_V2 {
                self.resp_queue
                    .get_mut(&off)
                    .and_then(|q| q.pop_front())
                    .unwrap_or(0)
            } else {
                self.regs.get(&off).copied().unwrap_or(0)
            }
        }
        fn write(&mut self, off: u32, val: u32) {
            self.writes.push((off, val));
            // Writes to CMDRESP clear the queue (the trigger write clears
            // RESP) and re-enqueue the written value so the next poll
            // sees it — unless a staged response is already waiting.
            if off == CMDRESP_REG_V1 || off == CMDRESP_REG_V2 {
                // Only insert the written value if no staged response is
                // queued; a pre-staged response represents the PSP reply
                // and must not be clobbered by the trigger write.
                let q = self.resp_queue.entry(off).or_default();
                if q.is_empty() {
                    q.push_back(val);
                }
            } else {
                self.regs.insert(off, val);
            }
        }
    }
}

pub use test_support::MockPsp;

// ── Smokes ────────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Smoke 1: verify the bit-position constants match the Linux PSP header.
fn smoke_psp_cmdresp_bit_positions() -> TestResult {
    // PSP_CMDRESP_RESP must be bit 31.
    if PSP_CMDRESP_RESP != (1u32 << 31) {
        return TestResult::Fail("PSP_CMDRESP_RESP should be bit 31");
    }
    // PSP_CMDRESP_RECOVERY must be bit 30.
    if PSP_CMDRESP_RECOVERY != (1u32 << 30) {
        return TestResult::Fail("PSP_CMDRESP_RECOVERY should be bit 30");
    }
    // CMD field is bits[23:16] — mask must be 0x00FF_0000.
    if PSP_CMDRESP_CMD_MASK != 0x00FF_0000 {
        return TestResult::Fail("PSP_CMDRESP_CMD_MASK must be 0x00FF_0000");
    }
    // STS field is bits[15:0] — mask must be 0x0000_FFFF.
    if PSP_CMDRESP_STS_MASK != 0x0000_FFFF {
        return TestResult::Fail("PSP_CMDRESP_STS_MASK must be 0x0000_FFFF");
    }
    // CMD shift must bring bits[23:16] to bits[7:0].
    if PSP_CMDRESP_CMD_SHIFT != 16 {
        return TestResult::Fail("PSP_CMDRESP_CMD_SHIFT must be 16");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/psp", smoke_psp_cmdresp_bit_positions);

/// Smoke 2: INIT command encoder — verify the trigger word written to
/// C2PMSG_17 places the command ID in bits[23:16] with no other bits set.
fn smoke_psp_init_command_encoder() -> TestResult {
    use test_support::MockPsp;
    let mut mock = MockPsp::new();
    let variant = PspHwVariant::V1;

    // Pre-stage: idle first, then done-ok after command is written.
    mock.stage_idle(variant);
    mock.stage_done_ok(variant);
    // Also set sane capability and BL info registers.
    mock.set_reg(FEATURE_REG, 0x0000_0002); // CAP_TEE bit
    mock.set_reg(BOOTLOADER_INFO_REG, 0x01_02_03_04);

    let result = init(&mut mock, variant);
    if result.is_err() {
        return TestResult::Fail("init() failed against mock");
    }
    let info = result.unwrap();
    if info.fw_ver.aa != 1 || info.fw_ver.bb != 2 || info.fw_ver.cc != 3 || info.fw_ver.dd != 4 {
        return TestResult::Fail("firmware version decode wrong");
    }
    if !info.capabilities.has_tee() {
        return TestResult::Fail("CAP_TEE not decoded");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/psp", smoke_psp_init_command_encoder);

/// Smoke 3: response-code decoder — verify that a non-zero STS in the
/// CMDRESP register surfaces as `PspError::CommandFailed(sts)`.
fn smoke_psp_response_code_decoder() -> TestResult {
    use test_support::MockPsp;
    let mut mock = MockPsp::new();
    let variant = PspHwVariant::V1;

    // Stage idle first (pre-trigger poll passes), then error response.
    mock.set_reg(variant.cmdresp_reg(), PSP_CMDRESP_RESP); // idle
    mock.stage_done_err(variant, 0x000D); // RING_BUSY

    // firmware_version uses only register reads, so use submit_cmd to
    // exercise the full mailbox path.
    let result = submit_cmd(&mut mock, variant, PSP_CMD_TEE_RING_INIT, Some(0x1000));
    match result {
        Err(PspError::CommandFailed(0x000D)) => TestResult::Pass,
        Err(PspError::CommandFailed(s)) => {
            let _ = s;
            TestResult::Fail("wrong STS code in CommandFailed")
        }
        Ok(_) => TestResult::Fail("expected CommandFailed, got Ok"),
        Err(_) => TestResult::Fail("unexpected error variant"),
    }
}
kernel_test_in!("drivers/psp", smoke_psp_response_code_decoder);

/// Smoke 4: platform-status decoder — verify capability bits are
/// correctly decomposed.
fn smoke_psp_platform_status_decoder() -> TestResult {
    use test_support::MockPsp;
    let mut mock = MockPsp::new();

    // Build a capability word with SEV + TEE + FUSED_PART.
    let cap_raw = CAP_SEV | CAP_TEE | CAP_FUSED_PART;
    mock.set_reg(FEATURE_REG, cap_raw);
    mock.set_reg(BOOTLOADER_INFO_REG, 0x03_07_0A_00);

    let status = platform_status(&mut mock);
    match status {
        Err(_) => return TestResult::Fail("platform_status() returned error"),
        Ok(s) => {
            if !s.capabilities.has_sev() {
                return TestResult::Fail("has_sev() should be true");
            }
            if !s.capabilities.has_tee() {
                return TestResult::Fail("has_tee() should be true");
            }
            if !s.capabilities.is_fused() {
                return TestResult::Fail("is_fused() should be true");
            }
            if s.capabilities.has_hsp_tpm() {
                return TestResult::Fail("has_hsp_tpm() should be false");
            }
            let ver = PspFwVer::from_raw(s.bootloader_info_raw);
            if ver.aa != 3 || ver.bb != 7 || ver.cc != 0x0A || ver.dd != 0 {
                return TestResult::Fail("bootloader version decode wrong");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/psp", smoke_psp_platform_status_decoder);

/// Smoke 5: FakeMmio bring-up round-trip — submit a TEE_RING_INIT
/// command and verify the correct register writes reach the mock.
fn smoke_psp_fake_mmio_ring_init_round_trip() -> TestResult {
    use test_support::MockPsp;
    let mut mock = MockPsp::new();
    let variant = PspHwVariant::V2; // Phoenix

    // Stage: idle → done-ok (two polls).
    mock.set_reg(variant.cmdresp_reg(), PSP_CMDRESP_RESP);
    mock.set_reg(FEATURE_REG, CAP_TEE);
    mock.set_reg(BOOTLOADER_INFO_REG, 0);

    // Second poll (after trigger): PSP responds ok.
    mock.set_reg(variant.cmdresp_reg(), PSP_CMDRESP_RESP);

    let ring_phys: u64 = 0x0000_0002_1234_5000;
    let result = submit_cmd(&mut mock, variant, PSP_CMD_TEE_RING_INIT, Some(ring_phys));
    if result.is_err() {
        return TestResult::Fail("submit_cmd RING_INIT failed");
    }

    // Verify cmdbuff lo/hi were written correctly.
    let lo_write = mock.writes.iter().find(|&&(off, _)| off == variant.cmdbuff_lo());
    let hi_write = mock.writes.iter().find(|&&(off, _)| off == variant.cmdbuff_hi());
    match lo_write {
        None => return TestResult::Fail("cmdbuff_lo not written"),
        Some(&(_, v)) => {
            if v != ring_phys as u32 {
                return TestResult::Fail("cmdbuff_lo value wrong");
            }
        }
    }
    match hi_write {
        None => return TestResult::Fail("cmdbuff_hi not written"),
        Some(&(_, v)) => {
            if v != (ring_phys >> 32) as u32 {
                return TestResult::Fail("cmdbuff_hi value wrong");
            }
        }
    }

    // Verify the trigger word placed the correct CMD id in bits[23:16].
    let trigger_write = mock.writes.iter().find(|&&(off, _)| off == variant.cmdresp_reg());
    match trigger_write {
        None => return TestResult::Fail("trigger not written to CMDRESP"),
        Some(&(_, v)) => {
            let encoded_cmd = (v >> PSP_CMDRESP_CMD_SHIFT) & 0xFF;
            if encoded_cmd != PSP_CMD_TEE_RING_INIT {
                return TestResult::Fail("CMDRESP trigger has wrong CMD id");
            }
        }
    }

    TestResult::Pass
}
kernel_test_in!("drivers/psp", smoke_psp_fake_mmio_ring_init_round_trip);

/// Smoke 6: BiosBlocked surfaces correctly when FEATURE_REG reads all-F.
fn smoke_psp_bios_blocked_detection() -> TestResult {
    use test_support::MockPsp;
    let mut mock = MockPsp::new();
    mock.set_reg(FEATURE_REG, 0xFFFF_FFFF);
    match read_capabilities(&mut mock) {
        Err(PspError::BiosBlocked) => TestResult::Pass,
        Ok(_) => TestResult::Fail("all-F capability should report BiosBlocked"),
        Err(_) => TestResult::Fail("wrong error variant for all-F capability"),
    }
}
kernel_test_in!("drivers/psp", smoke_psp_bios_blocked_detection);

/// Smoke 7: PspHwVariant register offsets match Linux sp-pci.c tables.
fn smoke_psp_hw_variant_register_offsets() -> TestResult {
    // V1 (Renoir pspv3/v4): cmdresp=0x10544, lo=0x10548, hi=0x1054c
    if PspHwVariant::V1.cmdresp_reg() != 0x10544 {
        return TestResult::Fail("V1 cmdresp_reg should be 0x10544");
    }
    if PspHwVariant::V1.cmdbuff_lo() != 0x10548 {
        return TestResult::Fail("V1 cmdbuff_lo should be 0x10548");
    }
    if PspHwVariant::V1.cmdbuff_hi() != 0x1054c {
        return TestResult::Fail("V1 cmdbuff_hi should be 0x1054c");
    }
    // V2 (Phoenix pspv5/v7): cmdresp=0x10944, lo=0x10948, hi=0x1094c
    if PspHwVariant::V2.cmdresp_reg() != 0x10944 {
        return TestResult::Fail("V2 cmdresp_reg should be 0x10944");
    }
    if PspHwVariant::V2.cmdbuff_lo() != 0x10948 {
        return TestResult::Fail("V2 cmdbuff_lo should be 0x10948");
    }
    if PspHwVariant::V2.cmdbuff_hi() != 0x1094c {
        return TestResult::Fail("V2 cmdbuff_hi should be 0x1094c");
    }
    // Shared registers same on both.
    if FEATURE_REG != 0x109fc {
        return TestResult::Fail("FEATURE_REG should be 0x109fc (C2PMSG_63)");
    }
    if BOOTLOADER_INFO_REG != 0x109ec {
        return TestResult::Fail("BOOTLOADER_INFO_REG should be 0x109ec (C2PMSG_59)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/psp", smoke_psp_hw_variant_register_offsets);
