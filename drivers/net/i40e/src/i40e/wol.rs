//! Wake-on-LAN for the Intel X710/XL710 (`i40e`) family (issue #792).
//!
//! Linux reference: `drivers/net/ethernet/intel/i40e/i40e_ethtool.c`
//! (`i40e_get_wol` / `i40e_set_wol`), `i40e_main.c`
//! (`i40e_enable_mc_magic_wake`, `i40e_io_suspend`,
//! `i40e_shutdown`, probe WoL enable), `i40e_common.c`
//! (`i40e_aq_mac_address_write`, `i40e_get_hw_cap` — the
//! `partition_id` derivation), `i40e_adminq_cmd.h`
//! (`i40e_aqc_mac_address_write`, `I40E_AQC_OPC_MAC_ADDRESS_WRITE`
//! `0x0108`, `I40E_AQC_OPC_NVM_READ` `0x0701`),
//! `i40e_register.h` (`I40E_PFPM_APM`, `I40E_PFPM_WUFC`),
//! `i40e_type.h` (`I40E_SR_NVM_WAKE_ON_LAN`, `I40E_HW_CAP_*`),
//! and `include/uapi/linux/ethtool.h` (`WAKE_MAGIC`).
//!
//! The family wakes on magic packet only, and only on the
//! controlling PF: `i40e_get_wol` reports `supported = 0` when the
//! NVM WoL word (`I40E_SR_NVM_WAKE_ON_LAN`, `0x19`) has this port's
//! bit set (ON = WoL *disabled* for that port) or when
//! `partition_id != 1`, where
//! `partition_id = (pf_id / num_ports) + 1`. `i40e_set_wol`
//! rejects anything but `WAKE_MAGIC` with `-EOPNOTSUPP`, and
//! rejects outright when the PF is not the main VSI or the
//! partition is not 1.
//!
//! The arming sequence (`i40e_io_suspend`) is two parts: when the
//! firmware reports the `WOL_MC_MAGIC_PKT_WAKE` capability and WoL
//! is enabled, `i40e_enable_mc_magic_wake` issues two
//! `mac_address_write` (0x0108) commands — first `LAA_WOL`
//! (`0x4000`), then `MC_MAG_EN | WOL_PRESERVE_ON_PFR |
//! UPDATE_MC_MAG` (`0xC300`) — and then the PF programs
//! `PFPM_APM = APME` and `PFPM_WUFC = MAG` (both 0 when WoL is
//! off). The PFPM writes happen regardless of the AQ outcome;
//! Linux ignores the `enable_mc_magic_wake` status in the suspend
//! path.
//!
//! The board record (`WolBoard`) is the platform-supplied input
//! for the gates, mirroring ixgbe's `WolBoardCap` pattern: the
//! NVM word, the partition-1 flag and the MC-magic-wake capability
//! are discovered by a future NVM / function-capabilities lane
//! (`aq_read_nvm` `0x0701` for word `0x19`; `num_ports` from the
//! `PRTGEN_CNF` port-enable count), and until that lane lands the
//! default record reports WoL unsupported rather than claiming
//! support the driver cannot prove. The pure gate logic and the
//! AQ / PFPM wire formats are fixture-tested here; the live
//! `Hardware` methods only run them against firmware.

// ── ethtool WAKE_* (include/uapi/linux/ethtool.h) ───────────────────

/// Wake on magic packet — the only filter this family arms.
pub const WAKE_MAGIC: u32 = 1 << 5;

// ── PFPM registers (i40e_register.h) ────────────────────────────────

/// `I40E_PFPM_APM` — PF power-management APM register.
pub const REG_PFPM_APM: u64 = 0x000B_8080;
/// `I40E_PFPM_APM_APME` — APM enable (bit 0).
pub const PFPM_APM_APME: u32 = 1 << 0;
/// `I40E_PFPM_WUFC` — PF wake-up filter control.
pub const REG_PFPM_WUFC: u64 = 0x0006_B400;
/// `I40E_PFPM_WUFC_MAG` — magic-packet wake (bit 1).
pub const PFPM_WUFC_MAG: u32 = 1 << 1;

// ── NVM (i40e_type.h) ───────────────────────────────────────────────

/// `I40E_SR_NVM_WAKE_ON_LAN` — NVM word `0x19`; one bit per port,
/// ON = WoL disabled for that port.
pub const NVM_WAKE_ON_LAN_WORD: u16 = 0x19;

// ── mac_address_write command flags (i40e_adminq_cmd.h) ─────────────

/// `I40E_AQC_MC_MAG_EN` — enable multicast + magic-packet wake.
pub const AQC_MC_MAG_EN: u16 = 0x0100;
/// `I40E_AQC_WOL_PRESERVE_ON_PFR` — keep WoL config across PF reset.
pub const AQC_WOL_PRESERVE_ON_PFR: u16 = 0x0200;
/// `I40E_AQC_WRITE_TYPE_LAA_ONLY`.
pub const AQC_WRITE_TYPE_LAA_ONLY: u16 = 0x0000;
/// `I40E_AQC_WRITE_TYPE_LAA_WOL`.
pub const AQC_WRITE_TYPE_LAA_WOL: u16 = 0x4000;
/// `I40E_AQC_WRITE_TYPE_UPDATE_MC_MAG`.
pub const AQC_WRITE_TYPE_UPDATE_MC_MAG: u16 = 0xC000;

// ── Board record (platform-supplied gates) ──────────────────────────

/// What the platform layer knows about this PF's WoL posture.
/// Mirrors ixgbe's `WolBoardCap`: the record is supplied
/// explicitly (via `I40eNic::set_wol_board`) and defaults to
/// unsupported — fail closed until the NVM / capabilities lane
/// populates it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WolBoard {
    /// `partition_id == 1` (the controlling PF), from
    /// `(pf_id / num_ports) + 1`.
    pub partition_id_one: bool,
    /// NVM WoL word (`0x19`) as read from the shadow RAM: bit per
    /// port, ON = WoL disabled for that port.
    pub nvm_word: u16,
    /// Firmware `WOL_MC_MAGIC_PKT_WAKE` capability
    /// (`I40E_HW_CAP_WOL_MC_MAGIC_PKT_WAKE`): the `mac_address_write`
    /// magic-wake programming is meaningful.
    pub mc_magic_wake: bool,
}

/// Live WoL state on the NIC: the stored enable plus the board record.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WolState {
    /// WoL enabled via `set_wol`.
    pub enabled: bool,
    /// Platform-supplied gates.
    pub board: WolBoard,
}

/// Whether this PF may offer WoL at all (Linux `i40e_get_wol`):
/// controlling PF (`partition_id == 1`) and the NVM word's bit
/// for this port clear. Ports beyond the NVM word's width are
/// unsupported.
pub const fn wol_supported(board: &WolBoard, port: u8) -> bool {
    if !board.partition_id_one || port >= 16 {
        return false;
    }
    (board.nvm_word >> port) & 1 == 0
}

/// The `ethtool` `supported` mask for this PF: magic only, when
/// the gates permit it — otherwise 0.
pub const fn wol_supported_opts(board: &WolBoard, port: u8) -> u32 {
    if wol_supported(board, port) {
        WAKE_MAGIC
    } else {
        0
    }
}

/// Map the stored enable to `ethtool` `wolopts` (Linux
/// `i40e_get_wol`: `wolopts = wol_en ? WAKE_MAGIC : 0`, reported
/// as 0 when the gates do not permit WoL).
pub const fn wol_opts(board: &WolBoard, port: u8, wol_en: bool) -> u32 {
    if wol_supported(board, port) && wol_en {
        WAKE_MAGIC
    } else {
        0
    }
}

/// Set-side validation failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WolError {
    /// WoL is not offered on this PF, or the request asked for a
    /// filter this family cannot arm.
    Unsupported,
}

/// Validate an `ethtool` `wolopts` word the way Linux
/// `i40e_set_wol` does: the gates must permit WoL on this PF, and
/// the word must carry nothing but `WAKE_MAGIC`. Returns the new
/// enable on success.
pub const fn set_wol(board: &WolBoard, port: u8, wolopts: u32) -> Result<bool, WolError> {
    if !wol_supported(board, port) {
        return Err(WolError::Unsupported);
    }
    if wolopts & !WAKE_MAGIC != 0 {
        return Err(WolError::Unsupported);
    }
    Ok(wolopts & WAKE_MAGIC != 0)
}

// ── mac_address_write wire format (i40e_aq_mac_address_write) ───────

/// Build the 16 direct-command parameter bytes for a
/// `mac_address_write` (0x0108): `command_flags` (LE, bytes 0..2),
/// `mac_sah = mac[0] << 8 | mac[1]` (LE, bytes 2..4),
/// `mac_sal = mac[2] << 24 | mac[3] << 16 | mac[4] << 8 | mac[5]`
/// (LE, bytes 4..8); the rest reserved (zero).
pub const fn mac_address_write_params(flags: u16, mac: [u8; 6]) -> [u8; 16] {
    let sah: u16 = ((mac[0] as u16) << 8) | mac[1] as u16;
    let sal: u32 =
        ((mac[2] as u32) << 24) | ((mac[3] as u32) << 16) | ((mac[4] as u32) << 8) | mac[5] as u32;
    let flags = flags.to_le_bytes();
    let sah = sah.to_le_bytes();
    let sal = sal.to_le_bytes();
    [
        flags[0], flags[1], sah[0], sah[1], sal[0], sal[1], sal[2], sal[3], 0, 0, 0, 0, 0, 0, 0, 0,
    ]
}

/// The two `mac_address_write` steps of `i40e_enable_mc_magic_wake`,
/// as `(command_flags, mac)` pairs: first `LAA_WOL`, then
/// `MC_MAG_EN | WOL_PRESERVE_ON_PFR | UPDATE_MC_MAG`.
pub const fn mc_magic_wake_steps(mac: [u8; 6]) -> [(u16, [u8; 6]); 2] {
    [
        (AQC_WRITE_TYPE_LAA_WOL, mac),
        (
            AQC_MC_MAG_EN | AQC_WOL_PRESERVE_ON_PFR | AQC_WRITE_TYPE_UPDATE_MC_MAG,
            mac,
        ),
    ]
}

// ── Suspend PFPM program (i40e_io_suspend, pure) ─────────────────────

/// The `(PFPM_APM, PFPM_WUFC)` words the suspend path writes:
/// `APME` / `MAG` when WoL is enabled, both 0 otherwise. Linux
/// writes these regardless of the `enable_mc_magic_wake` outcome.
pub const fn suspend_pfpm(wol_en: bool) -> (u32, u32) {
    if wol_en {
        (PFPM_APM_APME, PFPM_WUFC_MAG)
    } else {
        (0, 0)
    }
}

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const BOARD_OK: WolBoard = WolBoard {
        partition_id_one: true,
        nvm_word: 0,
        mc_magic_wake: true,
    };

    fn smoke_i40e_wol_gates() -> TestResult {
        // Controlling PF, NVM clear: supported.
        if !wol_supported(&BOARD_OK, 0) {
            return TestResult::Fail("controlling PF with clear NVM must support WoL");
        }
        if wol_supported_opts(&BOARD_OK, 0) != WAKE_MAGIC {
            return TestResult::Fail("supported mask is not WAKE_MAGIC on a permitted PF");
        }
        // Non-controlling partition: unsupported.
        let board = WolBoard {
            partition_id_one: false,
            ..BOARD_OK
        };
        if wol_supported(&board, 0) || wol_supported_opts(&board, 0) != 0 {
            return TestResult::Fail("non-controlling partition must not support WoL");
        }
        // NVM bit set for this port: unsupported (ON = disabled).
        let board = WolBoard {
            nvm_word: 1 << 1,
            ..BOARD_OK
        };
        if wol_supported(&board, 1) {
            return TestResult::Fail("NVM WoL-disabled bit for this port must gate WoL off");
        }
        if !wol_supported(&board, 0) {
            return TestResult::Fail("NVM bit for another port must not gate this port off");
        }
        // Port beyond the NVM word: unsupported.
        if wol_supported(&BOARD_OK, 16) {
            return TestResult::Fail("port >= 16 must not support WoL");
        }
        // Default board record: fail closed.
        if wol_supported(&WolBoard::default(), 0) {
            return TestResult::Fail("default board record must not support WoL");
        }
        // get mapping: wolopts follows the enable only when permitted.
        if wol_opts(&BOARD_OK, 0, true) != WAKE_MAGIC || wol_opts(&BOARD_OK, 0, false) != 0 {
            return TestResult::Fail("wolopts mapping wrong on a permitted PF");
        }
        if wol_opts(&WolBoard::default(), 0, true) != 0 {
            return TestResult::Fail("wolopts must be 0 on an unpermitted PF");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_i40e_wol_gates);

    fn smoke_i40e_wol_set_validation() -> TestResult {
        if set_wol(&BOARD_OK, 0, WAKE_MAGIC) != Ok(true) {
            return TestResult::Fail("WAKE_MAGIC did not enable WoL");
        }
        if set_wol(&BOARD_OK, 0, 0) != Ok(false) {
            return TestResult::Fail("zero wolopts did not disable WoL");
        }
        // Anything but WAKE_MAGIC is rejected.
        for bad in [0x01, 0x02, 0x04, 0x08, 0x10, 0x40, 0x80] {
            if set_wol(&BOARD_OK, 0, bad) != Err(WolError::Unsupported) {
                return TestResult::Fail("non-magic wolopt was not rejected");
            }
            if set_wol(&BOARD_OK, 0, WAKE_MAGIC | bad) != Err(WolError::Unsupported) {
                return TestResult::Fail("magic+other wolopt was not rejected");
            }
        }
        // Ungated PF: rejected outright.
        if set_wol(&WolBoard::default(), 0, WAKE_MAGIC) != Err(WolError::Unsupported) {
            return TestResult::Fail("set_wol on an unpermitted PF was not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_i40e_wol_set_validation);

    fn smoke_i40e_wol_aq_format() -> TestResult {
        // mac_address_write params for 00:11:22:33:44:55, LAA_WOL.
        let params =
            mac_address_write_params(AQC_WRITE_TYPE_LAA_WOL, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // flags 0x4000 LE, sah 0x0011 LE, sal 0x22334455 LE.
        let want: [u8; 16] = [
            0x00, 0x40, 0x11, 0x00, 0x55, 0x44, 0x33, 0x22, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        if params != want {
            return TestResult::Fail("mac_address_write params layout wrong");
        }
        // The two enable_mc_magic_wake steps.
        let steps = mc_magic_wake_steps([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        if steps[0].0 != 0x4000 {
            return TestResult::Fail("first magic-wake step is not LAA_WOL (0x4000)");
        }
        if steps[1].0 != 0xC300 {
            return TestResult::Fail("second magic-wake step is not 0xC300");
        }
        if steps[0].1 != steps[1].1 {
            return TestResult::Fail("magic-wake steps must carry the same MAC");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_i40e_wol_aq_format);

    fn smoke_i40e_wol_suspend_pfpm() -> TestResult {
        if suspend_pfpm(true) != (0x1, 0x2) {
            return TestResult::Fail("armed suspend PFPM words are not (APME, MAG)");
        }
        if suspend_pfpm(false) != (0, 0) {
            return TestResult::Fail("unarmed suspend PFPM words are not (0, 0)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_i40e_wol_suspend_pfpm);
}
