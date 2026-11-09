//! Host-interface command (HIC) transport, SW/FW semaphore, and
//! PHY token for the firmware-controlled PHYs (X550EM_A, E610).
//!
//! Grounding:
//! - The command structure, flow, and checksum: 82599 Datasheet
//!   rev. 2.6 §10.5.3 (manageability host interface) and X550
//!   Datasheet rev. 2.7 §11.8.2.1 (host-interface flow) +
//!   §8.2.2.20.5 (HICR bit table). The 82599 has no EEE of its
//!   own — this transport is the channel the FW-PHY EEE
//!   activities travel on, and the same registers carry the
//!   X550EM_A PHY token.
//! - The semaphore state machine and the PHY-token command:
//!   Linux ixgbe @ cbbddb6 (`ixgbe_common.c`
//!   `ixgbe_acquire_swfw_sync` / `ixgbe_get_eeprom_semaphore`,
//!   `ixgbe_x540.c` `ixgbe_acquire_swfw_sync_X540` /
//!   `ixgbe_get_swfw_sync_semaphore`, `ixgbe_x550.c`
//!   `ixgbe_get_phy_token` / `ixgbe_put_phy_token` /
//!   `ixgbe_acquire_swfw_sync_x550em_a`, `ixgbe_type.h`
//!   register/bit defines). ⚠️ These register addresses and
//!   the token command are Linux-transcribed: the SWSM /
//!   SW_FW_SYNC addresses do not appear in the datasheet
//!   extractions consulted for this lane, and the 82599
//!   datasheet §10.5.4 describes the semaphore only in prose.
//!   They are labeled `Linux-transcribed` at each definition.
//!
//! What Linux does that this module mirrors:
//! - `ixgbe_host_interface_command` / `ixgbe_hic_unlocked`:
//!   clear FWSTS.FWRI, check HICR.EN, write the command block
//!   to the FLEX_MNG RAM, set HICR.C, poll for C to clear and
//!   SV to set, read the response back. The datasheet caps a
//!   command at 252 data bytes + the 4-byte header (§10.5.3.5);
//!   this transport enforces it (fail-closed) even though
//!   Linux allows up to 1792 bytes for other commands.
//! - `ixgbe_acquire_swfw_sync_X540` (the variant all
//!   HIC-using parts point at): take the SWSM.SMBI +
//!   SWFW_SYNC.REGSMP hardware semaphores, claim the
//!   requested GSSR bits (SW bit + FW bit at mask<<5),
//!   force-claim on expiry. The generic 82599 variant
//!   (`ixgbe_acquire_swfw_sync`, SMBI + SWESMBI) is NOT
//!   implemented: no in-tree part issues HIC through it.
//! - `ixgbe_acquire_swfw_sync_x550em_a`: the X540 acquire
//!   plus the PHY token (HIC command 0x0A) for the shared
//!   MDIO, retried up to 1000 times at 5 ms.
//!
//! Timing: Linux sleeps between semaphore retries (5–10 ms)
//! and after a successful claim (5–6 ms). This module waits
//! with `responsive_spin_until` (which ticks the sleep pumps,
//! per the repo rule against hand-rolled MMIO spin loops)
//! instead of sleeping: the inter-retry wait polls the
//! resource bits so it returns early when the holder
//! releases, and the post-claim sleep is skipped — the
//! register write itself is the handoff. The retry budgets
//! (200 acquire iterations, 200 ms semaphore phases) are
//! Linux's.

use super::queues::RegBank;

/// Manageability RAM base: the command block is written here
/// (82599 §10.5.3: data RAM 0x15800–0x15EFF; X550 §8.2.2.20.5:
/// RAM_SPACE spans CSR 0x15800–0x15EFC).
pub const REG_FLEX_MNG: u64 = 0x15800;
/// Host Interface Control Register (82599 §10.5.3.4, X550
/// §8.2.2.20.5).
pub const REG_HICR: u64 = 0x15F00;
/// Firmware Status 0 (82599 §10.5.3.4 names FWS0R at 0x15F0C;
/// the FWRI bit below is Linux-transcribed).
pub const REG_FWSTS: u64 = 0x15F0C;

/// HICR: host-interface RAM area provided (X550 §8.2.2.20.5).
pub const HICR_EN: u32 = 1 << 0;
/// HICR: driver sets when the command block is in ARC RAM;
/// firmware clears when done (X550 §8.2.2.20.5).
pub const HICR_C: u32 = 1 << 1;
/// HICR: valid status in the CSR area; valid only when C is
/// cleared; driver reads only (X550 §8.2.2.20.5).
pub const HICR_SV: u32 = 1 << 2;

/// FWSTS: firmware-reset-indication, clear-by-write-one.
/// ⚠️ Linux-transcribed (`ixgbe_type.h` FWSTS_FWRI 0x200):
/// the 82599 datasheet names the FWS0R register but this
/// extraction does not give the FWRI bit position.
pub const FWSTS_FWRI: u32 = 0x0000_0200;

/// Datasheet command cap (§10.5.3.5): 252 data bytes + the
/// 4-byte header = 256 bytes = 64 dwords.
pub const HIC_MAX_DWORDS: usize = 64;
/// Maximum data bytes in one command block (§10.5.3.5).
pub const HIC_MAX_DATA_BYTES: usize = 252;

/// FW-PHY request command id (`ixgbe_type.h`
/// FW_PHY_ACT_REQ_CMD). The request buffer is
/// `FW_PHY_ACT_REQ_LEN` (20) bytes: 4-byte header + 4-byte
/// port/activity word + 4 data dwords.
pub const FW_PHY_ACT_REQ_CMD: u8 = 5;
/// Checksum byte meaning "do not check" (X550 §11.8.2.1 /
/// Table 11-47: "If the value is 0xFF, the checksum is not
/// checked by the firmware"). Linux uses it for every HIC
/// request (`ixgbe_type.h` FW_DEFAULT_CHECKSUM).
pub const HIC_CHECKSUM_SKIP: u8 = 0xFF;

/// SWSM register, 82599/X540/X550/X550EM_x
/// (Linux-transcribed, `ixgbe_type.h` IXGBE_SWSM_8259X).
pub const REG_SWSM: u64 = 0x10140;
/// SWSM register, X550EM_a (Linux-transcribed,
/// `ixgbe_type.h` IXGBE_SWSM_X550EM_a).
pub const REG_SWSM_X550EM_A: u64 = 0x15F70;
/// SW_FW_SYNC (GSSR) register, 82599/X540/X550/X550EM_x
/// (Linux-transcribed, `ixgbe_type.h` IXGBE_GSSR).
pub const REG_SWFW_SYNC: u64 = 0x10160;
/// SW_FW_SYNC (GSSR) register, X550EM_a (Linux-transcribed,
/// `ixgbe_type.h` IXGBE_SWFW_SYNC_X550EM_a).
pub const REG_SWFW_SYNC_X550EM_A: u64 = 0x15F78;

/// SWSM: driver semaphore bit (test-and-set on read).
/// Linux-transcribed (`ixgbe_type.h` IXGBE_SWSM_SMBI).
pub const SWSM_SMBI: u32 = 1 << 0;
/// SWSM: firmware semaphore bit. Used only by the generic
/// 82599 acquire, which this module does not implement.
/// Linux-transcribed (`ixgbe_type.h` IXGBE_SWSM_SWESMBI).
pub const SWSM_SWESMBI: u32 = 1 << 1;

/// SW_FW_SYNC: register semaphore bit 31 (test-and-set on
/// read). Linux-transcribed (`ixgbe_type.h`
/// IXGBE_SWFW_REGSMP).
pub const SWFW_REGSMP: u32 = 1 << 31;

/// GSSR resource bits (Linux-transcribed, `ixgbe_type.h`).
pub const GSSR_EEP_SM: u32 = 0x0001;
pub const GSSR_PHY0_SM: u32 = 0x0002;
pub const GSSR_PHY1_SM: u32 = 0x0004;
pub const GSSR_MAC_CSR_SM: u32 = 0x0008;
pub const GSSR_FLASH_SM: u32 = 0x0010;
pub const GSSR_NVM_PHY_MASK: u32 = 0x000F;
/// GSSR: software management resource — the bit the HIC
/// path claims. It has no FW bit pair (it is SW-only).
pub const GSSR_SW_MNG_SM: u32 = 0x0400;
pub const GSSR_I2C_MASK: u32 = 0x1800;
/// GSSR: shared-PHY token bit (X550EM_a only).
pub const GSSR_TOKEN_SM: u32 = 0x4000_0000;

/// PHY-token HIC command (Linux-transcribed,
/// `ixgbe_type.h` FW_PHY_TOKEN_* / `ixgbe_x550.c`
/// `ixgbe_get_phy_token`).
pub const FW_PHY_TOKEN_REQ_CMD: u8 = 0x0A;
pub const FW_PHY_TOKEN_REQ_LEN: u8 = 2;
pub const FW_PHY_TOKEN_REQ: u8 = 0;
pub const FW_PHY_TOKEN_REL: u8 = 1;
pub const FW_PHY_TOKEN_OK: u8 = 1;
pub const FW_PHY_TOKEN_RETRY: u8 = 0x80;
/// Token retry pacing: 5 ms between attempts, up to 1000
/// attempts (5 s total). Linux-transcribed.
pub const FW_PHY_TOKEN_DELAY_MS: u64 = 5;
pub const FW_PHY_TOKEN_RETRIES: u32 = 1000;

/// Semaphore phase budget: Linux polls each phase 2000
/// times at 50–100 µs, i.e. ~100–200 ms.
pub const SWFW_SEM_TIMEOUT_MS: u64 = 200;
/// SWFW acquire iteration budget (Linux:
/// `ixgbe_acquire_swfw_sync_X540`, 200 iterations).
pub const SWFW_ACQUIRE_RETRIES: u32 = 200;
/// Inter-retry wait inside the SWFW acquire (Linux sleeps
/// 5–10 ms; this module polls the resource bits for up to
/// 10 ms and returns early when they clear).
pub const SWFW_RETRY_WAIT_MS: u64 = 10;

/// HIC command return status: success (X550 Table 11-48 /
/// `ixgbe_type.h` CEM_RESP_STATUS_SUCCESS).
pub const HIC_RET_SUCCESS: u8 = 0x1;

/// Host-interface transport failures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HicError {
    /// Request empty, over the 64-dword datasheet cap, or
    /// its header buf_len over the 252-byte datasheet cap.
    BadLength,
    /// HICR.EN clear: the host interface is not provided.
    NotEnabled,
    /// HICR.C never cleared within the deadline.
    Timeout,
    /// C cleared but HICR.SV clear: no valid status.
    NoStatus,
    /// FWSTS.FWRI set after the command: the command may
    /// have failed (datasheet §11.8.2.1 step 6).
    FwReset,
    /// The response is larger than the caller's buffer.
    ResponseTooBig,
    /// A SWFW semaphore was not granted (Linux `-EBUSY`).
    SemaphoreBusy,
    /// The PHY token answered RETRY and the retry budget
    /// ran out (Linux `-EAGAIN` converted).
    TokenRetry,
    /// The PHY token answered a non-OK, non-RETRY status.
    TokenError,
    /// A FW-PHY activity answered a non-SUCCESS return
    /// status on every retry (Linux `-EIO`).
    ActivityFailed,
}

impl HicError {
    /// Static message for the `IxgbeError::Other` mapping.
    pub fn as_str(self) -> &'static str {
        match self {
            HicError::BadLength => "hic bad length",
            HicError::NotEnabled => "hic not enabled",
            HicError::Timeout => "hic timeout",
            HicError::NoStatus => "hic no status",
            HicError::FwReset => "hic firmware reset indicated",
            HicError::ResponseTooBig => "hic response too big",
            HicError::SemaphoreBusy => "hic swfw semaphore busy",
            HicError::TokenRetry => "hic phy token retry exhausted",
            HicError::TokenError => "hic phy token error",
            HicError::ActivityFailed => "hic fw-phy activity failed",
        }
    }
}

/// Pack a HIC header word: byte0 command, byte1 buffer
/// length (data bytes after the header), byte2 reserved,
/// byte3 checksum. Requests use the skip-checksum 0xFF
/// (X550 Table 11-47).
pub fn hic_header(cmd: u8, buf_len: u8) -> u32 {
    (cmd as u32) | ((buf_len as u32) << 8) | ((HIC_CHECKSUM_SKIP as u32) << 24)
}

/// Datasheet §10.5.3.7 checksum: the 8-bit sum, no carry,
/// over every byte except the checksum itself, negated so
/// the total (including the checksum byte) sums to 0.
pub fn hic_checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
    0u8.wrapping_sub(sum)
}

/// Header byte0: the command id.
pub fn hic_cmd(header: u32) -> u8 {
    (header & 0xFF) as u8
}

/// Header byte1: the data length in bytes (excluding the
/// 4-byte header).
pub fn hic_buf_len(header: u32) -> u8 {
    ((header >> 8) & 0xFF) as u8
}

/// Header byte2: the return status (responses only).
pub fn hic_ret_status(header: u32) -> u8 {
    ((header >> 16) & 0xFF) as u8
}

/// Build a FW-PHY activity request (`ixgbe_type.h`
/// `ixgbe_hic_phy_activity_req`, 24 bytes / 6 dwords):
/// header word, port/activity word (port byte0, pad byte1,
/// activity id LE16 bytes 2–3), then the 4 data words in
/// big-endian byte order (the firmware reads them as BE32).
pub fn build_phy_activity_req(activity: u16, lan_id: u8, data: [u32; 4]) -> [u32; 6] {
    let header = hic_header(FW_PHY_ACT_REQ_CMD, 20);
    let port_activity = (lan_id as u32) | ((activity as u32) << 16);
    [
        header,
        port_activity,
        data[0].swap_bytes(),
        data[1].swap_bytes(),
        data[2].swap_bytes(),
        data[3].swap_bytes(),
    ]
}

/// Parse a FW-PHY activity response: the header word plus
/// the 4 data words, each BE-decoded. The return status
/// must be SUCCESS (0x1); anything else is the activity's
/// failure, reported without the data.
pub fn parse_phy_activity_resp(words: &[u32]) -> Result<[u32; 4], HicError> {
    if words.len() < 5 {
        return Err(HicError::BadLength);
    }
    if hic_ret_status(words[0]) != HIC_RET_SUCCESS {
        return Err(HicError::ActivityFailed);
    }
    Ok([
        words[1].swap_bytes(),
        words[2].swap_bytes(),
        words[3].swap_bytes(),
        words[4].swap_bytes(),
    ])
}

/// The unlocked host-interface command (Linux
/// `ixgbe_hic_unlocked` + the 82599 §10.5.3.3 / X550
/// §11.8.2.1 flow): clear FWSTS.FWRI, require HICR.EN,
/// write the request dwords to the FLEX_MNG RAM, set
/// HICR.C, poll for C to clear, require SV (and no FWRI),
/// read the response back. Returns the response dword
/// count. `deadline` bounds the C-clear poll (Linux waits
/// up to 500 ms: "command should complete within half a
/// second").
pub fn host_interface_command<B: RegBank>(
    bank: &mut B,
    request: &[u32],
    response: &mut [u32],
    deadline: narf_time::Deadline,
) -> Result<usize, HicError> {
    if request.is_empty()
        || request.len() > HIC_MAX_DWORDS
        || hic_buf_len(request[0]) as usize > HIC_MAX_DATA_BYTES
    {
        return Err(HicError::BadLength);
    }
    // NOTE: the header buf_len field is NOT required to equal
    // the buffer length: the PHY-token request carries
    // buf_len 2 (port + command type) in an 8-byte,
    // dword-aligned buffer. Linux validates only the buffer
    // length (non-zero, dword-aligned, within its cap).
    // (1) Clear FWSTS.FWRI by writing it back set
    // (clear-by-write-one), exactly as Linux does.
    let fwsts = bank.read32(REG_FWSTS);
    bank.write32(REG_FWSTS, fwsts | FWSTS_FWRI);
    // (3) The host interface must be provided.
    if bank.read32(REG_HICR) & HICR_EN == 0 {
        return Err(HicError::NotEnabled);
    }
    // (4) Write the command block to the shared RAM.
    for (i, word) in request.iter().enumerate() {
        bank.write32(REG_FLEX_MNG + (i as u64) * 4, *word);
    }
    // (5) Set the Command bit; this interrupts the ARC.
    let hicr = bank.read32(REG_HICR);
    bank.write32(REG_HICR, hicr | HICR_C);
    // (7) Poll for the firmware to clear the Command bit.
    let cleared =
        narf_scheduler::responsive_spin_until(|| bank.read32(REG_HICR) & HICR_C == 0, deadline);
    if !cleared {
        return Err(HicError::Timeout);
    }
    // (6) A set FWRI means the command may have failed.
    if bank.read32(REG_FWSTS) & FWSTS_FWRI != 0 {
        return Err(HicError::FwReset);
    }
    // (8) SV must be set for the status to be valid.
    if bank.read32(REG_HICR) & HICR_SV == 0 {
        return Err(HicError::NoStatus);
    }
    // Read the response back: header dword first, then the
    // buf_len payload dwords (rounded up).
    let header = bank.read32(REG_FLEX_MNG);
    let data_len = hic_buf_len(header) as usize;
    let total = 1 + data_len.div_ceil(4);
    if total > response.len() {
        return Err(HicError::ResponseTooBig);
    }
    response[0] = header;
    for (i, slot) in response.iter_mut().enumerate().take(total).skip(1) {
        *slot = bank.read32(REG_FLEX_MNG + (i as u64) * 4);
    }
    Ok(total)
}

/// Take the hardware semaphores guarding SW_FW_SYNC access
/// (Linux `ixgbe_get_swfw_sync_semaphore`): first SWSM.SMBI
/// (driver-vs-driver, test-and-set on read), then
/// SWFW_SYNC.REGSMP (SW-vs-FW, test-and-set on read).
/// Each phase gets the Linux-scale budget
/// (`SWFW_SEM_TIMEOUT_MS`). A phase-2 timeout releases both
/// bits first, as Linux does.
pub fn acquire_swfw_sync_semaphore<B: RegBank>(
    bank: &mut B,
    swsm: u64,
    swfw_sync: u64,
    timeout_ms: u64,
) -> Result<(), HicError> {
    let smbi_free = narf_scheduler::responsive_spin_until(
        || bank.read32(swsm) & SWSM_SMBI == 0,
        narf_time::Deadline::after_ms(timeout_ms),
    );
    if !smbi_free {
        return Err(HicError::SemaphoreBusy);
    }
    let regsmp_free = narf_scheduler::responsive_spin_until(
        || bank.read32(swfw_sync) & SWFW_REGSMP == 0,
        narf_time::Deadline::after_ms(timeout_ms),
    );
    if !regsmp_free {
        release_swfw_sync_semaphore(bank, swsm, swfw_sync);
        return Err(HicError::SemaphoreBusy);
    }
    Ok(())
}

/// Release both hardware semaphores (Linux
/// `ixgbe_release_swfw_sync_semaphore`): clear REGSMP in
/// SW_FW_SYNC and SMBI in SWSM.
pub fn release_swfw_sync_semaphore<B: RegBank>(bank: &mut B, swsm: u64, swfw_sync: u64) {
    let sync = bank.read32(swfw_sync);
    bank.write32(swfw_sync, sync & !SWFW_REGSMP);
    let swsm_v = bank.read32(swsm);
    bank.write32(swsm, swsm_v & !SWSM_SMBI);
}

/// Wait up to `ms` milliseconds for a condition, ticking
/// the sleep pumps (the repo's `responsive_spin_until`
/// idiom used as a bounded sleep when there is nothing to
/// poll on — e.g. the PHY-token 5 ms pacing).
fn wait_ms(ms: u64) {
    let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(ms));
}

/// Acquire the SW/FW sync for `mask` (Linux
/// `ixgbe_acquire_swfw_sync_X540`, the variant the
/// X540/X550/X550EM_x/X550EM_a/E610 parts all point at).
/// The SW_MNG bit is SW-only (no FW pair); the NVM/PHY
/// bits have FW pairs at mask<<5, and EEP_SM additionally
/// watches FLASH_SM. On expiry the caller force-claims the
/// SW bits when only FW/HW hold them (assumed malfunction),
/// or releases the SW bits another SW holds and reports
/// busy — both exactly as Linux does. `retries` is the
/// iteration budget (Linux: 200).
pub fn acquire_swfw_sync<B: RegBank>(
    bank: &mut B,
    swsm: u64,
    swfw_sync: u64,
    mask: u32,
    retries: u32,
) -> Result<(), HicError> {
    let mut swmask = mask & GSSR_NVM_PHY_MASK;
    let swi2c_mask = mask & GSSR_I2C_MASK;
    let mut fwmask = swmask << 5;
    // SW_MNG_SM has no FW bit pair; it joins swmask only.
    if mask & GSSR_SW_MNG_SM != 0 {
        swmask |= GSSR_SW_MNG_SM;
    }
    swmask |= swi2c_mask;
    fwmask |= swi2c_mask << 2;
    let hwmask = if swmask & GSSR_EEP_SM != 0 {
        GSSR_FLASH_SM
    } else {
        0
    };
    let wanted = fwmask | swmask | hwmask;
    for _ in 0..retries {
        acquire_swfw_sync_semaphore(bank, swsm, swfw_sync, SWFW_SEM_TIMEOUT_MS)?;
        let sync = bank.read32(swfw_sync);
        if sync & wanted == 0 {
            bank.write32(swfw_sync, sync | swmask);
            release_swfw_sync_semaphore(bank, swsm, swfw_sync);
            return Ok(());
        }
        release_swfw_sync_semaphore(bank, swsm, swfw_sync);
        // Wait for the holder to release (up to 10 ms),
        // returning early when the bits clear.
        let _ = narf_scheduler::responsive_spin_until(
            || bank.read32(swfw_sync) & wanted == 0,
            narf_time::Deadline::after_ms(SWFW_RETRY_WAIT_MS),
        );
    }
    // Expired: assume FW/HW malfunction and claim the SW
    // bits anyway — unless another SW holds them, in which
    // case release the SW bits we do not own and report busy.
    acquire_swfw_sync_semaphore(bank, swsm, swfw_sync, SWFW_SEM_TIMEOUT_MS)?;
    let sync = bank.read32(swfw_sync);
    if sync & (fwmask | hwmask) != 0 {
        bank.write32(swfw_sync, sync | swmask);
        release_swfw_sync_semaphore(bank, swsm, swfw_sync);
        return Ok(());
    }
    if sync & swmask != 0 {
        let mut rmask =
            GSSR_EEP_SM | GSSR_PHY0_SM | GSSR_PHY1_SM | GSSR_MAC_CSR_SM | GSSR_SW_MNG_SM;
        if swi2c_mask != 0 {
            rmask |= GSSR_I2C_MASK;
        }
        release_swfw_sync(bank, swsm, swfw_sync, rmask);
        release_swfw_sync_semaphore(bank, swsm, swfw_sync);
        return Err(HicError::SemaphoreBusy);
    }
    release_swfw_sync_semaphore(bank, swsm, swfw_sync);
    Err(HicError::SemaphoreBusy)
}

/// Release the SW/FW sync for `mask` (Linux
/// `ixgbe_release_swfw_sync_X540`): take the semaphores,
/// clear our SW bits in SW_FW_SYNC, release the
/// semaphores. A semaphore failure on entry is ignored,
/// as in Linux (the release still attempts the clear).
pub fn release_swfw_sync<B: RegBank>(bank: &mut B, swsm: u64, swfw_sync: u64, mask: u32) {
    let mut swmask = mask & (GSSR_NVM_PHY_MASK | GSSR_SW_MNG_SM);
    if mask & GSSR_I2C_MASK != 0 {
        swmask |= mask & GSSR_I2C_MASK;
    }
    let _ = acquire_swfw_sync_semaphore(bank, swsm, swfw_sync, SWFW_SEM_TIMEOUT_MS);
    let sync = bank.read32(swfw_sync);
    bank.write32(swfw_sync, sync & !swmask);
    release_swfw_sync_semaphore(bank, swsm, swfw_sync);
}

/// Get the shared-PHY token (Linux `ixgbe_get_phy_token`):
/// HIC command 0x0A, 2 data bytes (port number, REQ=0).
/// OK (1) grants the token; RETRY (0x80) means another
/// function holds it; anything else is an error.
pub fn get_phy_token<B: RegBank>(
    bank: &mut B,
    lan_id: u8,
    deadline: narf_time::Deadline,
) -> Result<(), HicError> {
    let request = [
        hic_header(FW_PHY_TOKEN_REQ_CMD, FW_PHY_TOKEN_REQ_LEN),
        (lan_id as u32) | ((FW_PHY_TOKEN_REQ as u32) << 8),
    ];
    let mut response = [0u32; 2];
    host_interface_command(bank, &request, &mut response, deadline)?;
    match hic_ret_status(response[0]) {
        FW_PHY_TOKEN_OK => Ok(()),
        FW_PHY_TOKEN_RETRY => Err(HicError::TokenRetry),
        _ => Err(HicError::TokenError),
    }
}

/// Put the shared-PHY token back (Linux
/// `ixgbe_put_phy_token`): same command with REL=1.
pub fn put_phy_token<B: RegBank>(
    bank: &mut B,
    lan_id: u8,
    deadline: narf_time::Deadline,
) -> Result<(), HicError> {
    let request = [
        hic_header(FW_PHY_TOKEN_REQ_CMD, FW_PHY_TOKEN_REQ_LEN),
        (lan_id as u32) | ((FW_PHY_TOKEN_REL as u32) << 8),
    ];
    let mut response = [0u32; 2];
    host_interface_command(bank, &request, &mut response, deadline)?;
    if hic_ret_status(response[0]) == FW_PHY_TOKEN_OK {
        Ok(())
    } else {
        Err(HicError::TokenError)
    }
}

/// X550EM_a SWFW acquire (Linux
/// `ixgbe_acquire_swfw_sync_x550em_a`): the X540 acquire
/// for the non-token bits, then the PHY token, retried on
/// RETRY up to `token_retries` times at 5 ms. A failed
/// token attempt releases the non-token bits first.
pub fn acquire_swfw_sync_x550em_a<B: RegBank>(
    bank: &mut B,
    lan_id: u8,
    mask: u32,
    token_retries: u32,
) -> Result<(), HicError> {
    let hmask = mask & !GSSR_TOKEN_SM;
    let mut remaining = token_retries;
    loop {
        if hmask != 0 {
            acquire_swfw_sync(
                bank,
                REG_SWSM_X550EM_A,
                REG_SWFW_SYNC_X550EM_A,
                hmask,
                SWFW_ACQUIRE_RETRIES,
            )?;
        }
        if mask & GSSR_TOKEN_SM == 0 {
            return Ok(());
        }
        let deadline = narf_time::Deadline::after_ms(500);
        match get_phy_token(bank, lan_id, deadline) {
            Ok(()) => return Ok(()),
            Err(HicError::TokenRetry) => {
                if hmask != 0 {
                    release_swfw_sync(bank, REG_SWSM_X550EM_A, REG_SWFW_SYNC_X550EM_A, hmask);
                }
                if remaining == 0 {
                    return Err(HicError::TokenRetry);
                }
                remaining -= 1;
                wait_ms(FW_PHY_TOKEN_DELAY_MS);
            }
            Err(e) => return Err(e),
        }
    }
}

/// X550EM_a SWFW release (Linux
/// `ixgbe_release_swfw_sync_x550em_a`): put the token back
/// first, then release the non-token bits. Token errors on
/// release are ignored, as in Linux.
pub fn release_swfw_sync_x550em_a<B: RegBank>(bank: &mut B, lan_id: u8, mask: u32) {
    if mask & GSSR_TOKEN_SM != 0 {
        let deadline = narf_time::Deadline::after_ms(500);
        let _ = put_phy_token(bank, lan_id, deadline);
    }
    let hmask = mask & !GSSR_TOKEN_SM;
    if hmask != 0 {
        release_swfw_sync(bank, REG_SWSM_X550EM_A, REG_SWFW_SYNC_X550EM_A, hmask);
    }
}

/// One FW-PHY activity behind the full guard (Linux
/// `ixgbe_fw_phy_activity`): acquire the SW_MNG resource
/// (plus the PHY token on X550EM_a), issue the activity,
/// retry up to 50 times while the firmware answers a
/// non-SUCCESS return status, release on every path.
/// Transport errors return immediately; only a
/// non-SUCCESS return status is retried.
pub fn fw_phy_activity<B: RegBank>(
    bank: &mut B,
    lan_id: u8,
    activity: u16,
    data: [u32; 4],
    x550em_a: bool,
    deadline: narf_time::Deadline,
) -> Result<[u32; 4], HicError> {
    let (swsm, swfw_sync, mask) = if x550em_a {
        (
            REG_SWSM_X550EM_A,
            REG_SWFW_SYNC_X550EM_A,
            GSSR_SW_MNG_SM | GSSR_TOKEN_SM,
        )
    } else {
        (REG_SWSM, REG_SWFW_SYNC, GSSR_SW_MNG_SM)
    };
    if x550em_a {
        acquire_swfw_sync_x550em_a(bank, lan_id, mask, FW_PHY_TOKEN_RETRIES)?;
    } else {
        acquire_swfw_sync(bank, swsm, swfw_sync, mask, SWFW_ACQUIRE_RETRIES)?;
    }
    let request = build_phy_activity_req(activity, lan_id, data);
    let mut response = [0u32; 6];
    let mut last = Err(HicError::ActivityFailed);
    for _ in 0..50 {
        match host_interface_command(bank, &request, &mut response, deadline) {
            Ok(_) => match parse_phy_activity_resp(&response) {
                Ok(decoded) => {
                    if x550em_a {
                        release_swfw_sync_x550em_a(bank, lan_id, mask);
                    } else {
                        release_swfw_sync(bank, swsm, swfw_sync, mask);
                    }
                    return Ok(decoded);
                }
                Err(e) => last = Err(e),
            },
            Err(e) => {
                if x550em_a {
                    release_swfw_sync_x550em_a(bank, lan_id, mask);
                } else {
                    release_swfw_sync(bank, swsm, swfw_sync, mask);
                }
                return Err(e);
            }
        }
    }
    if x550em_a {
        release_swfw_sync_x550em_a(bank, lan_id, mask);
    } else {
        release_swfw_sync(bank, swsm, swfw_sync, mask);
    }
    last
}
