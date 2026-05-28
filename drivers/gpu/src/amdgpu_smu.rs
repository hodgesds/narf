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

// ── PMFW upload (Phoenix-class) ────────────────────────────────────
//
// SMU PMFW load on Phoenix/Strix is host-resident: the kernel
// supplies a signed `smu_*.bin` blob and the on-die MP1 ROM
// stages it via a two-step mailbox handshake. Renoir/Cezanne
// keep SMU PMFW in BIOS so the host never touches the PMFW;
// only the message API (above) is used.
//
// The handshake (Linux `smu_v14_0.c::smu_v14_0_load_microcode`):
//   1. Program PMFW phys lo in `MP1_C2PMSG_64` (slot 64).
//   2. Program PMFW phys hi in `MP1_C2PMSG_65` (slot 65).
//   3. Program PMFW byte size in the ARG register.
//   4. Send `PPSMC_MSG_LoadMicrocode` (0x02 on smu_v14, distinct
//      from `GetSmuVersion` 0x02 on Renoir's smu_v12 — the same
//      numeric id with different semantics per chip).
//   5. Poll RESP for OK / error code.
//
// MP1_C2PMSG_64 / 65 sit at offset 0x29C + 64*4 / + 65*4 in the
// MP1 register window. Slot 64 doubles as the PMFW-phys-lo input
// + the response status when an LoadMicrocode call completes —
// same dual-use shape as PSP's MP0_C2PMSG_64.

/// MP1_C2PMSG_64 — PMFW phys-lo on input; never used for other
/// SMU messages so collisions with `send_message_*` are
/// structurally impossible (those use slot 90).
pub const MP1_C2PMSG_PMFW_LO_REL: u32 = 0x29C + 64 * 4;
/// MP1_C2PMSG_65 — PMFW phys-hi.
pub const MP1_C2PMSG_PMFW_HI_REL: u32 = 0x29C + 65 * 4;

/// `PPSMC_MSG_LoadMicrocode` — Phoenix-class only (smu_v14+).
/// Tells the MP1 ROM to start consuming the PMFW image at the
/// phys address just programmed. Argument = image size in bytes.
pub const PPSMC_MSG_LOAD_MICROCODE_PHOENIX: u32 = 0x02;

/// Errors specific to the PMFW upload path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PmfwError {
    /// MP1 mailbox didn't respond within the polling window.
    /// Indicates the SMU isn't running, the MP1 base is wrong, or
    /// the PMFW blob is bad enough to wedge the loader.
    Timeout,
    /// SMU responded but reported a non-OK status code.
    /// Codes are smu-version-specific; common are sig-fail / OOM.
    Rejected(u32),
    /// Image phys is 0 (caller forgot to alloc DMA-coherent),
    /// or size is 0 / > 16 MiB (won't fit in the size field).
    BadImage,
}

/// Upload a PMFW image via the MP1 mailbox + LoadMicrocode
/// message. Phoenix-class chips (smu_v14+) only; Renoir-class
/// reject the call because their MP1 expects PMFW from BIOS.
///
/// Pre-conditions handled by the caller:
///   - `image_phys` must be a DMA-coherent + 4-KiB-aligned
///     address holding the raw PMFW payload (sans NARF trailer).
///   - `size_bytes` is the raw payload size in bytes; the trailer
///     decode happens upstream, this function gets the unwrapped
///     payload region only.
pub fn load_pmfw<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    image_phys: u64,
    size_bytes: u32,
) -> Result<(), PmfwError> {
    if image_phys == 0 || size_bytes == 0 || size_bytes > 16 * 1024 * 1024 {
        return Err(PmfwError::BadImage);
    }

    // Steps 1-2: phys lo/hi into PMFW slots.
    mmio.write(mp1_base + MP1_C2PMSG_PMFW_LO_REL, image_phys as u32);
    mmio.write(mp1_base + MP1_C2PMSG_PMFW_HI_REL, (image_phys >> 32) as u32);

    // Clear the response slot so we can distinguish "we got an
    // answer to THIS call" from "stale OK from a previous call".
    mmio.write(mp1_base + MP1_C2PMSG_RESP_REL, 0);

    // Step 3: program the size argument.
    mmio.write(mp1_base + MP1_C2PMSG_ARG_REL, size_bytes);

    // Step 4: kick the LoadMicrocode message. This atomically
    // triggers the SMU's PMFW state machine.
    mmio.write(
        mp1_base + MP1_C2PMSG_MSG_REL,
        PPSMC_MSG_LOAD_MICROCODE_PHOENIX,
    );

    // Step 5: poll for the OK / error code. PMFW load typically
    // completes within ~100 ms (the SMU verifies the signature
    // and stages the image into MP1-internal SRAM before
    // executing). Bound the spin so a wedged SMU doesn't hang
    // the boot.
    for _ in 0..SMU_POLL_BUDGET {
        let resp = mmio.read(mp1_base + MP1_C2PMSG_RESP_REL);
        if resp == 0 {
            continue;
        }
        if resp == SMU_RESP_OK {
            return Ok(());
        }
        return Err(PmfwError::Rejected(resp));
    }
    Err(PmfwError::Timeout)
}

// ── DPM clock control messages ─────────────────────────────────────
//
// These messages take a packed argument:
//   bits[31:16] = frequency in MHz (or DPM level for *_ByIndex)
//   bits[15:0]  = clock id (PPCLK_*)
//
// Renoir / Phoenix share the high-level message ids below; the
// concrete PPCLK_* enum values differ per chip and are kept in
// the chip's PPSMC header. We expose a small set of canonical ids
// the bring-up arc uses (GFXCLK / UCLK / DCEFCLK / SOCCLK / FCLK).

/// `PPSMC_MSG_SetSoftMinByFreq` — lower bound on the DPM ladder for
/// a clock. Argument packs (freq_mhz << 16) | clk_id.
pub const PPSMC_MSG_SET_SOFT_MIN_BY_FREQ: u32 = 0x21;
/// `PPSMC_MSG_SetSoftMaxByFreq` — upper bound for a clock.
pub const PPSMC_MSG_SET_SOFT_MAX_BY_FREQ: u32 = 0x22;
/// `PPSMC_MSG_SetHardMinByFreq` — hard lower bound (won't drop below).
pub const PPSMC_MSG_SET_HARD_MIN_BY_FREQ: u32 = 0x23;
/// `PPSMC_MSG_GetDpmFreqByIndex` — read the DPM-level → freq map
/// for a clock. Argument packs (level << 16) | clk_id; result in ARG.
pub const PPSMC_MSG_GET_DPM_FREQ_BY_INDEX: u32 = 0x24;
/// `PPSMC_MSG_GetMaxDpmFreq` — highest DPM-level freq for a clock.
pub const PPSMC_MSG_GET_MAX_DPM_FREQ: u32 = 0x25;
/// `PPSMC_MSG_GetMinDpmFreq` — lowest DPM-level freq for a clock.
pub const PPSMC_MSG_GET_MIN_DPM_FREQ: u32 = 0x26;

// Canonical PPCLK_* clock ids — values match Renoir's
// smu_v12_0_ppsmc.h. Phoenix renumbers some; callers that care
// about the chip-specific id should look up via per-chip table.

/// `PPCLK_GFXCLK` — GPU shader clock.
pub const SMU_CLK_GFXCLK: u32 = 0;
/// `PPCLK_VCLK` — VCN video-decode clock.
pub const SMU_CLK_VCLK: u32 = 1;
/// `PPCLK_DCLK` — VCN decode-only clock.
pub const SMU_CLK_DCLK: u32 = 2;
/// `PPCLK_ECLK` — VCN encode clock.
pub const SMU_CLK_ECLK: u32 = 3;
/// `PPCLK_SOCCLK` — fabric SoC clock.
pub const SMU_CLK_SOCCLK: u32 = 4;
/// `PPCLK_UCLK` — memory clock (DDR4 / LPDDR5).
pub const SMU_CLK_UCLK: u32 = 5;
/// `PPCLK_FCLK` — Infinity Fabric clock (Zen-side).
pub const SMU_CLK_FCLK: u32 = 6;
/// `PPCLK_DCEFCLK` — Display engine fabric clock (Vega+).
pub const SMU_CLK_DCEFCLK: u32 = 7;

/// Pack `(freq_mhz, clk_id)` into the argument format expected by
/// the SET_*_BY_FREQ messages.
pub fn pack_clk_arg(clk_id: u32, freq_mhz: u32) -> u32 {
    (freq_mhz << 16) | (clk_id & 0xFFFF)
}

/// Pack `(dpm_level, clk_id)` for GET_DPM_FREQ_BY_INDEX.
pub fn pack_dpm_arg(clk_id: u32, dpm_level: u32) -> u32 {
    (dpm_level << 16) | (clk_id & 0xFFFF)
}

/// Convenience: program a clock's soft min/max in one shot.
/// Internal SMU state retains the bounds across power-state
/// transitions until the next set_clock_range call.
pub fn set_clock_range<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    clk_id: u32,
    min_mhz: u32,
    max_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(
        mmio,
        mp1_base,
        PPSMC_MSG_SET_SOFT_MIN_BY_FREQ,
        pack_clk_arg(clk_id, min_mhz),
    )?;
    send_message_void(
        mmio,
        mp1_base,
        PPSMC_MSG_SET_SOFT_MAX_BY_FREQ,
        pack_clk_arg(clk_id, max_mhz),
    )?;
    Ok(())
}

// ── Thermal ────────────────────────────────────────────────────────

/// `PPSMC_MSG_GetCurrentTemperature` — returns the GPU package
/// temperature in tenths-of-a-degree Celsius (d°C) via ARG. The
/// concrete ID below is the value Linux uses on Renoir; Phoenix
/// renumbers a few SMU messages but this one is stable.
pub const PPSMC_MSG_GET_CURRENT_TEMPERATURE: u32 = 0x36;

/// Read the GPU package temperature in milli-degrees Celsius.
/// The SMU reports tenths (d°C); we scale by 100 to land in m°C
/// so the value composes with k10temp's reading without unit drift.
pub fn read_gpu_temperature_millicelsius<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
) -> Result<i32, SmuError> {
    let raw = send_message_get(mmio, mp1_base, PPSMC_MSG_GET_CURRENT_TEMPERATURE, 0)?;
    // d°C → m°C: multiply by 100. Cast to i32 — the SMU never
    // returns negative temps in operation but the OS surface
    // wants a signed type for consistency with k10temp.
    Ok((raw as i32) * 100)
}

/// Read the highest DPM-level frequency for `clk_id` (in MHz).
pub fn get_max_dpm_freq<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    clk_id: u32,
) -> Result<u32, SmuError> {
    send_message_get(mmio, mp1_base, PPSMC_MSG_GET_MAX_DPM_FREQ, clk_id)
}

/// Read the DPM-level → frequency map: returns the frequency of
/// DPM level `dpm_level` for `clk_id`.
pub fn get_dpm_freq_by_index<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    clk_id: u32,
    dpm_level: u32,
) -> Result<u32, SmuError> {
    send_message_get(
        mmio,
        mp1_base,
        PPSMC_MSG_GET_DPM_FREQ_BY_INDEX,
        pack_dpm_arg(clk_id, dpm_level),
    )
}

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

// ── Per-family driver-interface schema versions ────────────────────
//
// The SMU exposes a driver-IF schema version through
// PPSMC_MSG_GET_DRIVER_IF_VERSION. The host driver must compile
// against a matching ppsmc.h; a mismatch means the SMU will
// interpret message ids and argument layouts differently than the
// driver expects, so subsequent commands corrupt SMU state. Linux
// rejects bring-up with -EOPNOTSUPP on mismatch (see
// `smu_check_fw_version` in `smu_v*_0.c`); we match that posture.
//
// Values per Linux:
//   smu_v12_0.h:        SMU12_DRIVER_IF_VERSION   (Renoir / Lucienne / Cezanne)
//   smu_v13_0_4.h:      SMU_13_0_4_DRIVER_IF_VERSION (Phoenix / HawkPoint1)

/// Renoir / Lucienne / Cezanne (SMU 12.0). Matches Linux
/// `drivers/gpu/drm/amd/pm/swsmu/inc/smu_v12_0.h`.
pub const SMU12_DRIVER_IF_VERSION: u32 = 0x0F;
/// Phoenix HawkPoint1 / Phoenix2 (SMU 13.0.4). Matches Linux
/// `drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu_v13_0_4.h`.
pub const SMU_13_0_4_DRIVER_IF_VERSION: u32 = 0x07;

// ── Bring-up sequence ──────────────────────────────────────────────

/// Snapshot of what the host learned during SMU bring-up. Returned
/// from `bring_up` so the caller can stash it on the driver state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SmuInfo {
    /// SMU firmware version (BCD-packed major.minor.rev typically).
    pub smu_version: u32,
    /// Driver-IF schema version the SMU reports.
    pub driver_if_version: u32,
}

/// Bring-up errors. Distinct from [`SmuError`] because these are
/// higher-level handshake failures, not mailbox-level errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BringUpError {
    /// A mailbox-level error happened during one of the bring-up
    /// steps. The wrapped step is the first one that failed.
    Mailbox(SmuError, BringUpStep),
    /// `GET_DRIVER_IF_VERSION` returned a value the driver wasn't
    /// compiled to handle. The wrapped values are
    /// `(smu_reported, host_expected)`.
    DriverIfMismatch(u32, u32),
    /// `TEST_MESSAGE` didn't echo the host-supplied argument. SMU
    /// is responsive but mis-behaving.
    TestMessageEchoMismatch { sent: u32, got: u32 },
}

/// Which step in the bring-up sequence faulted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BringUpStep {
    TestMessage,
    GetSmuVersion,
    GetDriverIfVersion,
}

/// Canonical SMU bring-up sequence. PSP must have loaded SMU
/// firmware before this is called; caller verifies that
/// out-of-band.
///
/// Steps:
///   1. `PPSMC_MSG_TestMessage` with a host-chosen sentinel.
///      The SMU echoes the argument back via ARG. Confirms the
///      mailbox is alive end-to-end before trusting any future
///      response.
///   2. `PPSMC_MSG_GetSmuVersion` — stash the firmware version
///      so logs / version-coupling enforcement can use it.
///   3. `PPSMC_MSG_GetDriverIfVersion` — verify against the
///      schema version the host was compiled for. Mismatch fails
///      bring-up; downstream message argument layouts are not
///      compatible.
///
/// Real bring-up also programs `SetDriverDramAddr{High,Low}` so
/// the SMU can DMA shared-state tables to host RAM, but that
/// allocation lives in the driver core — kept out of this
/// pure-protocol module.
pub fn bring_up<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    expected_driver_if_version: u32,
) -> Result<SmuInfo, BringUpError> {
    // Step 1: TestMessage with a sentinel argument.
    let sentinel: u32 = 0xDEAD_BEEF;
    let echoed = send_message_get(mmio, mp1_base, PPSMC_MSG_TEST_MESSAGE, sentinel)
        .map_err(|e| BringUpError::Mailbox(e, BringUpStep::TestMessage))?;
    if echoed != sentinel {
        return Err(BringUpError::TestMessageEchoMismatch {
            sent: sentinel,
            got: echoed,
        });
    }

    // Step 2: GetSmuVersion.
    let smu_version = send_message_get(mmio, mp1_base, PPSMC_MSG_GET_SMU_VERSION, 0)
        .map_err(|e| BringUpError::Mailbox(e, BringUpStep::GetSmuVersion))?;

    // Step 3: GetDriverIfVersion and check.
    let driver_if_version =
        send_message_get(mmio, mp1_base, PPSMC_MSG_GET_DRIVER_IF_VERSION, 0)
            .map_err(|e| BringUpError::Mailbox(e, BringUpStep::GetDriverIfVersion))?;
    if driver_if_version != expected_driver_if_version {
        return Err(BringUpError::DriverIfMismatch(
            driver_if_version,
            expected_driver_if_version,
        ));
    }

    Ok(SmuInfo {
        smu_version,
        driver_if_version,
    })
}

// ── Version detection ───────────────────────────────────────────────

/// Which SMU firmware generation is running on this chip.
///
/// The version is detected at bring-up by inspecting the
/// `driver_if_version` returned by `PPSMC_MSG_GetDriverIfVersion`.
/// Each family has a distinct expected constant (see
/// `SMU12_DRIVER_IF_VERSION` and `SMU_13_0_4_DRIVER_IF_VERSION`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SmuVersion {
    /// SMU 12.0 — Renoir / Lucienne / Cezanne (Family 0x17).
    V12,
    /// SMU 13.0.4 — Phoenix / HawkPoint1 (Family 0x1A, 1002:1900).
    V13,
}

impl SmuVersion {
    /// Identify the SMU generation from a `driver_if_version` value
    /// as reported by `PPSMC_MSG_GetDriverIfVersion`. Returns `None`
    /// if the version is not one NARF currently handles.
    pub fn from_driver_if(driver_if: u32) -> Option<Self> {
        if driver_if == SMU12_DRIVER_IF_VERSION {
            Some(SmuVersion::V12)
        } else if driver_if == SMU_13_0_4_DRIVER_IF_VERSION {
            Some(SmuVersion::V13)
        } else {
            None
        }
    }
}

// ── Canonical message enum ──────────────────────────────────────────

/// Canonical SMU messages that NARF exposes, independent of the
/// per-version numeric id. Each variant maps to a different u32
/// opcode on SMU12 vs SMU13 — the per-version modules hold the
/// lookup tables.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PpsmcMsg {
    TestMessage,
    GetSmuVersion,
    GetDriverIfVersion,
    GetGfxclkFrequency,
    GetFclkFrequency,
    SetSoftMinGfxclk,
    SetSoftMaxGfxClk,
    SetHardMinGfxClk,
    SetSoftMinFclk,
    SetSoftMaxFclk,
    SetHardMinFclk,
    SetSoftMinSocclk,
    SetSoftMaxSocclk,
    AllowGfxOff,
    DisallowGfxOff,
    PrepareMp1ForUnload,
    PowerUpGfx,
    SetDriverDramAddrHigh,
    SetDriverDramAddrLow,
    TransferTableSmu2Dram,
    TransferTableDram2Smu,
}

// ── Clock domain enum ───────────────────────────────────────────────

/// Clock domains queryable / constrainable via the SMU mailbox.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClockDomain {
    /// GFX shader clock.
    Gfxclk,
    /// Fabric clock (Infinity Fabric).
    Fclk,
    /// SoC / fabric SoC clock.
    Socclk,
    /// Unified memory controller clock (DDR / LPDDR).
    Uclk,
    /// VCN video clock.
    Vclk,
    /// VCN decode clock.
    Dclk,
}

// ── SMU firmware version struct ─────────────────────────────────────

/// Decoded SMU firmware version.
///
/// The SMU encodes its version in a single 32-bit word:
///   bits[31:24] = major
///   bits[23:16] = minor
///   bits[15:8]  = revision
///   bits[7:0]   = reserved / build
///
/// Linux references: `smu_v12_0.c` / `smu_v13_0_4_ppt.c` — the raw
/// `smc_fw_version` field is read-back as-is; the BCD decode is
/// display-only in Linux. We store and surface the raw word too.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SmuFwVersion {
    /// Major version (bits 31:24).
    pub major: u8,
    /// Minor version (bits 23:16).
    pub minor: u8,
    /// Revision (bits 15:8).
    pub revision: u8,
    /// Raw packed u32 as returned by GetSmuVersion / GetPmfwVersion.
    pub raw: u32,
}

impl SmuFwVersion {
    /// Decode from the raw 32-bit register value returned by
    /// `PPSMC_MSG_GetSmuVersion` / `PPSMC_MSG_GetPmfwVersion`.
    pub fn from_raw(raw: u32) -> Self {
        SmuFwVersion {
            major: (raw >> 24) as u8,
            minor: (raw >> 16) as u8,
            revision: (raw >> 8) as u8,
            raw,
        }
    }
}

// ── Version-dispatched public API ───────────────────────────────────

/// Detect the SMU generation by querying the driver-IF version.
///
/// Sends `GetDriverIfVersion` and maps the returned value to a
/// [`SmuVersion`] variant. Returns `None` if the version is
/// unrecognised (e.g. older Vega-class hardware).
///
/// The caller is responsible for ensuring the SMU mailbox is alive
/// (PSP has loaded the firmware) before calling this; use
/// `bring_up` for a full handshake.
pub fn detect_version<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
) -> Option<SmuVersion> {
    let driver_if = send_message_get(mmio, mp1_base, PPSMC_MSG_GET_DRIVER_IF_VERSION, 0).ok()?;
    SmuVersion::from_driver_if(driver_if)
}

/// Translate a canonical [`PpsmcMsg`] to the numeric id for the
/// given `version` and dispatch it to the SMU. Returns the ARG
/// register read-back on success.
///
/// Returns `SmuError::Rejected` with a synthetic code of 0xFE
/// (`SMU_RESP_UNKNOWN_CMD`) if the message is unsupported on this
/// version.
pub fn send_msg<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    version: SmuVersion,
    msg: PpsmcMsg,
    arg: u32,
) -> Result<u32, SmuError> {
    use crate::amdgpu_smu_v12;
    use crate::amdgpu_smu_v13;
    let id = match version {
        SmuVersion::V12 => amdgpu_smu_v12::msg_id(msg),
        SmuVersion::V13 => amdgpu_smu_v13::msg_id(msg),
    };
    match id {
        Some(id) => send_message_get(mmio, mp1_base, id, arg),
        None => Err(SmuError::Rejected(SMU_RESP_UNKNOWN_CMD)),
    }
}

/// Read the SMU firmware version as a decoded [`SmuFwVersion`].
pub fn get_fw_version<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    version: SmuVersion,
) -> Result<SmuFwVersion, SmuError> {
    let raw = send_msg(mmio, mp1_base, version, PpsmcMsg::GetSmuVersion, 0)?;
    Ok(SmuFwVersion::from_raw(raw))
}

/// Read the GPU temperature in milli-degrees Celsius.
///
/// The SMU reports temperature in tenths-of-a-degree (d°C) via the
/// `GetCurrentTemperature` message. We scale by 100 to land in m°C
/// so the value composes with k10temp readings without unit drift.
///
/// NOTE: this uses the existing raw `PPSMC_MSG_GET_CURRENT_TEMPERATURE`
/// constant (0x36) which is stable across SMU12 and SMU13. If future
/// silicon renumbers it, promote it into the per-version tables.
pub fn get_temperature_milli_c<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
) -> Result<i32, SmuError> {
    read_gpu_temperature_millicelsius(mmio, mp1_base)
}

/// Read the current clock frequency for `domain` in MHz.
///
/// Dispatches the appropriate per-version GET message. Returns
/// `SmuError::Rejected(SMU_RESP_UNKNOWN_CMD)` for domains that must
/// be read via the shared-state-table path (SOCCLK, UCLK, VCLK, DCLK
/// on both versions).
pub fn get_clock_mhz<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    version: SmuVersion,
    domain: ClockDomain,
) -> Result<u32, SmuError> {
    use crate::amdgpu_smu_v12;
    use crate::amdgpu_smu_v13;
    let id = match version {
        SmuVersion::V12 => amdgpu_smu_v12::get_current_clk_msg(domain),
        SmuVersion::V13 => amdgpu_smu_v13::get_current_clk_msg(domain),
    };
    match id {
        Some(id) => send_message_get(mmio, mp1_base, id, 0),
        None => Err(SmuError::Rejected(SMU_RESP_UNKNOWN_CMD)),
    }
}

/// Set a P-state constraint on `domain`.
///
/// Programs both the soft-min and soft-max for the clock domain. Pass
/// `None` for either bound to leave it unchanged.
///
/// Dispatches version-specific messages. Logs both steps; if the
/// first (min) succeeds but the second (max) fails, the min constraint
/// is already committed to the SMU — the caller owns recovery.
pub fn set_clock_constraint<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    version: SmuVersion,
    domain: ClockDomain,
    min_mhz: Option<u32>,
    max_mhz: Option<u32>,
) -> Result<(), SmuError> {
    use crate::amdgpu_smu_v12;
    use crate::amdgpu_smu_v13;
    let (min_id, max_id) = {
        let pair = match version {
            SmuVersion::V12 => amdgpu_smu_v12::set_range_msgs(domain),
            SmuVersion::V13 => amdgpu_smu_v13::set_range_msgs(domain),
        };
        match pair {
            Some(p) => p,
            None => return Err(SmuError::Rejected(SMU_RESP_UNKNOWN_CMD)),
        }
    };
    if let Some(min) = min_mhz {
        send_message_void(mmio, mp1_base, min_id, min)?;
    }
    if let Some(max) = max_mhz {
        send_message_void(mmio, mp1_base, max_id, max)?;
    }
    Ok(())
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
