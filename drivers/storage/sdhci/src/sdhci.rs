//! SD Host Controller — clean-room.
//!
//! Reference: **"SD Host Controller Simplified Specification"
//! Version 3.00**, SD Association (free PDF, sdcard.org). Section
//! numbers in comments below refer to this spec. The SD Physical
//! Layer Simplified Specification (also free) covers the protocol
//! sequence (CMD0 / CMD8 / ACMD41 / CMD2 / CMD3 / CMD7 / CMD17 /
//! CMD24).
//!   <https://www.sdcard.org/downloads/pls/>
//!
//! ## Layout
//!
//! BAR0 is the SDHCI MMIO window. The first 0x100 bytes are the
//! standard register block:
//!
//! | offset | name              | width |
//! |--------|-------------------|-------|
//! | 0x00   | SDMA System Addr  | u32   |
//! | 0x04   | Block Size        | u16   |
//! | 0x06   | Block Count       | u16   |
//! | 0x08   | Argument          | u32   |
//! | 0x0C   | Transfer Mode     | u16   |
//! | 0x0E   | Command           | u16   |
//! | 0x10   | Response 0..3     | u32×4 |
//! | 0x20   | Buffer Data Port  | u32   |
//! | 0x24   | Present State     | u32   |
//! | 0x28   | Host Control 1    | u8    |
//! | 0x29   | Power Control     | u8    |
//! | 0x2A   | Block Gap Control | u8    |
//! | 0x2B   | Wakeup Control    | u8    |
//! | 0x2C   | Clock Control     | u16   |
//! | 0x2E   | Timeout Control   | u8    |
//! | 0x2F   | Software Reset    | u8    |
//! | 0x30   | Normal Int Status | u16   |
//! | 0x32   | Error Int Status  | u16   |
//! | 0x40   | Capabilities      | u64   |
//!
//! Stage cut: bring up the host controller, supply a 400 kHz init
//! clock, run the SD identification sequence (CMD0 / CMD8 /
//! ACMD41 with S18R / CMD2 / CMD3 / CMD7), then negotiate the data
//! path (#837): raise the SD clock to the 25 MHz default-speed
//! maximum from the Capabilities base clock, switch the card + host
//! to a 4-bit bus (ACMD51 SCR probe, ACMD6 SET_BUS_WIDTH), and serve
//! multi-block CMD18 / CMD25 transfers — SDMA / ADMA2 through a
//! host-owned coherent bounce buffer when the Capabilities say the
//! host can, PIO multi-block otherwise. Single-block CMD17 / CMD24
//! PIO (`read_block` / `write_block`) remains for 1-block callers.
//!
//! UHS-I (#838): when the card reports S18A in its ACMD41 OCR and
//! the host Capabilities report 1.8 V support, the driver issues
//! CMD11 and runs the Linux `sdhci_do_start_signal_voltage_switch`
//! sequence (stop SD clock, DAT[3:0] == 0 check, HOST_CONTROL2
//! 1.8 V signalling enable, 5 ms settle, restart clock, DAT[3:0]
//! == 1 check), then queries the card's UHS modes with CMD6
//! (check) and switches to the best mode the card, the host
//! Capabilities_1, and the base clock all admit (SDR104 > DDR50 >
//! SDR50 > SDR25; SDR12-only cards stay at 3.3 V default speed),
//! executing CMD19 tuning where the mode needs it. A voltage-switch
//! failure power-cycles the card and re-runs identification +
//! negotiation without UHS, so the card stays usable at 3.3 V.
//!
//! What stays out: eMMC-specific paths (#827, incl. HS200/HS400);
//! 3.3 V High-Speed 50 MHz (CMD6 switch-function at 3.3 V) is a
//! follow-on, not part of this data path; CMD6 driver-strength /
//! current-limit selection is not programmed (cards stay at their
//! default); re-tuning (SDHCI Capabilities re-tuning modes/timer)
//! is not wired — tuning runs once at bring-up.

use core::sync::atomic::AtomicBool;

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent_masked, DmaBuffer, DmaDirection};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::req_gate::ReqGate;
use narf_drivers_storage_core::sd_proto::{R1Status, Scr, SwitchStatus};
use narf_drivers_storage_core::sd_proto::{ACMD41_S18R, OCR_S18A};

// SDHCI is a PCI class 0x08 / subclass 0x05 device. Each silicon
// vendor has its own VID/DID, but the class triple is universally
// matched by the "SD host" backstop. We list the most common
// QEMU + real-hardware ids explicitly so the bus probe can pick
// them by name.

/// "Generic" SD Host Controller PCI class triple (08:05:01 —
/// SDHCI). Matched as a class backstop.
pub const SDHCI_PCI_CLASS: u8 = 0x08;
pub const SDHCI_PCI_SUBCLASS: u8 = 0x05;

/// Standard register offsets (SDHCI 3.00 §2).
const REG_SDMA_ADDR: u64 = 0x00;
const REG_BLOCK_SIZE: u64 = 0x04;
const REG_BLOCK_COUNT: u64 = 0x06;
const REG_ARGUMENT: u64 = 0x08;
const REG_TRANSFER_MODE: u64 = 0x0C;
const REG_COMMAND: u64 = 0x0E;
const REG_RESPONSE_0: u64 = 0x10;
const REG_BUFFER_PORT: u64 = 0x20;
const REG_PRESENT_STATE: u64 = 0x24;
const REG_HOST_CONTROL_1: u64 = 0x28;
const REG_POWER_CONTROL: u64 = 0x29;
const REG_CLOCK_CONTROL: u64 = 0x2C;
const REG_TIMEOUT_CTRL: u64 = 0x2E;
const REG_SOFT_RESET: u64 = 0x2F;
const REG_NORMAL_INT_STS: u64 = 0x30;
const REG_ERROR_INT_STS: u64 = 0x32;
const REG_NORMAL_INT_EN: u64 = 0x34;
const REG_ERROR_INT_EN: u64 = 0x36;
const REG_CAPABILITIES: u64 = 0x40;
const REG_ADMA_ERROR: u64 = 0x54;
const REG_ADMA_ADDR: u64 = 0x58;
const REG_ADMA_ADDR_HI: u64 = 0x5C;
const REG_HOST_VERSION: u64 = 0xFE;
/// Host Control 2 (§2.2.15; bit values shared with
/// `drivers/sdio/src/sdhci/regs.rs`, same SDHCI lineage).
const REG_HOST_CONTROL_2: u64 = 0x3E;
/// Capabilities 1 — the high dword of the 64-bit Capabilities
/// register (§2.2.25): UHS mode support + re-tuning fields.
const REG_CAPABILITIES_1: u64 = 0x44;

// Capabilities register bits (§2.2.24; bit values shared with
// `drivers/sdio/src/sdhci/regs.rs`, same SDHCI lineage).
const CAPS_CLOCK_BASE_MASK: u32 = 0x0000_FF00; // v3.00+ base clock, bits [15:8], MHz.
const CAPS_CLOCK_BASE_SHIFT: u32 = 8;
const CAPS_CLOCK_BASE_MASK_V2: u32 = 0x0000_3F00; // spec ≤ 2.00, bits [13:8].
const CAPS_CAN_DO_ADMA2: u32 = 0x0008_0000;
const CAPS_CAN_DO_SDMA: u32 = 0x0040_0000;
const CAPS_CAN_64BIT: u32 = 0x1000_0000;
/// Capabilities bit 26 — the host can supply 1.8 V signalling
/// (SDHCI 3.00 §2.2.24; Linux `SDHCI_CAN_VDD_180`, gated by
/// `sdhci_do_start_signal_voltage_switch`'s `SDHCI_SIGNALING_180`).
const CAPS_CAN_VDD_180: u32 = 0x0400_0000;

// Capabilities 1 bits (§2.2.25; bit values shared with
// `drivers/sdio/src/sdhci/regs.rs`).
/// Host supports UHS SDR50 (Capabilities bit 32).
const CAPS1_SUPPORT_SDR50: u32 = 0x0000_0001;
/// Host supports UHS SDR104 (Capabilities bit 33).
const CAPS1_SUPPORT_SDR104: u32 = 0x0000_0002;
/// Host supports UHS DDR50 (Capabilities bit 34).
const CAPS1_SUPPORT_DDR50: u32 = 0x0000_0004;
/// "Use Tuning for SDR50" (Capabilities bit 45): SDR50 needs
/// CMD19 tuning on this host (Linux `SDHCI_SDR50_NEEDS_TUNING`).
const CAPS1_TUNING_SDR50: u32 = 0x0000_2000;

// Host Control 2 bits (§2.2.15; bit values shared with
// `drivers/sdio/src/sdhci/regs.rs`).
/// UHS Mode Select field, bits [2:0].
const HC2_UHS_MASK: u16 = 0x0007;
/// 1.8 V Signalling Enable, bit 3.
const HC2_VDD_180: u16 = 0x0008;
/// Execute Tuning, bit 6.
const HC2_EXEC_TUNING: u16 = 0x0040;
/// Sampling Clock Select / tuned clock, bit 7.
const HC2_TUNED_CLK: u16 = 0x0080;

// Host version (low byte of REG_HOST_VERSION): 0 = 1.00, 1 = 2.00,
// 2 = 3.00, 3 = 4.00.
const SPEC_200: u8 = 1;
const SPEC_300: u8 = 2;

// Host Control 1 bits (§2.2.8).
const HC_4BIT_BUS: u8 = 1 << 1;
const HC_DMA_MASK: u8 = 0x18;
const HC_DMA_SDMA: u8 = 0x00;
const HC_DMA_ADMA32: u8 = 0x10;
const HC_DMA_ADMA64: u8 = 0x18;

// ADMA2 descriptor constants (SDHCI 3.00 §1.13; values shared with
// `drivers/sdio/src/sdhci/adma.rs`, same Linux lineage).
/// ADMA2 descriptor size, 32-bit table (8 bytes).
const ADMA_DESC_SIZE_32: usize = 8;
/// ADMA2 descriptor size, 64-bit table (12 bytes).
const ADMA_DESC_SIZE_64: usize = 12;
/// Attribute: TRAN + Valid (`ADMA2_TRAN_VALID`).
const ADMA_ATTR_TRAN_VALID: u16 = 0x21;
/// Attribute: NOP + End + Valid (terminating descriptor).
const ADMA_ATTR_NOP_END_VALID: u16 = 0x03;
/// SDMA buffer boundary the driver programs (512 KiB, boundary
/// argument 7 — `SDHCI_DEFAULT_BOUNDARY_ARG` in sdio regs).
const SDMA_BOUNDARY_SIZE: u64 = 512 * 1024;
const SDMA_BOUNDARY_ARG: u16 = 7;

/// SD clock targets.
const INIT_CLOCK_HZ: u32 = 400_000;
/// Default-speed maximum (SD Physical Layer Spec: default-speed
/// mode runs to 25 MHz; above that the card needs the UHS-I switch
/// in `negotiate_uhs`, or the 3.3 V high-speed switch follow-on).
const DATA_CLOCK_HZ: u32 = 25_000_000;

/// UHS-I voltage-switch waits (Linux
/// `sdhci_do_start_signal_voltage_switch` `usleep_range` values;
/// the simplified SD spec leaves §4.2.4.2 timing blank).
/// 5 ms after enabling 1.8 V signalling, before restarting the
/// SD clock; 1 ms after restarting it, before the DAT[3:0] check.
const VOLTAGE_SWITCH_SETTLE_MS: u64 = 5;
const VOLTAGE_SWITCH_DAT_MS: u64 = 1;
/// Power-cycle wait in the voltage-switch failure path (Linux:
/// "Wait for 1ms as per the spec").
const POWER_CYCLE_MS: u64 = 1;

/// CMD19 tuning (Linux `sdhci_execute_tuning`,
/// `MAX_TUNING_LOOP`): the host may ask for up to 40 CMD19s, and
/// the total time the card spends responding must stay under
/// 150 ms (SDHCI spec; Linux `timeout = 150`).
const TUNING_MAX_LOOPS: usize = 40;
const TUNING_BUDGET_MS: u64 = 150;
/// CMD19 tuning-block length in bytes (SD Physical Layer Spec
/// §4.2.4.5; fixed, CMD16 not required).
const TUNING_BLOCK_LEN: usize = 64;
/// Largest divisor the 10-bit divider field encodes (spec 3.00+).
const MAX_DIV_SPEC_300: u32 = 2046;
/// Largest divisor for spec ≤ 2.00.
const MAX_DIV_SPEC_200: u32 = 256;

/// Bytes moved through the DMA bounce buffer per chunk (64 blocks —
/// the same 32 KiB `MAX_TRANSFER` the SDIO DMA engine uses).
const DMA_CHUNK_BYTES: usize = 32 * 1024;
/// Blocks per multi-block chunk (DMA or PIO): bounds one command's
/// polled wait and keeps a chunk inside one bounce buffer.
const CHUNK_BLOCKS: usize = DMA_CHUNK_BYTES / 512;
/// ADMA descriptor-table allocation: 8 descriptor slots at the
/// widest (64-bit) size — one TRAN + terminator are used per chunk.
const ADMA_TABLE_BYTES: usize = 8 * ADMA_DESC_SIZE_64;

// Software-reset bits (§2.2.16): write-1 self-clearing.
const SRST_ALL: u8 = 1 << 0;
const SRST_CMD: u8 = 1 << 1;
const SRST_DAT: u8 = 1 << 2;

// Clock control bits (§2.2.14).
const CLK_INTERNAL_EN: u16 = 1 << 0; // Internal clock enable.
const CLK_INTERNAL_STABLE: u16 = 1 << 1;
const CLK_SD_EN: u16 = 1 << 2; // SD-clock to card output.

// Power control bits (§2.2.10).
const POWER_ON: u8 = 1 << 0;
const POWER_3V3: u8 = 0b111 << 1; // 3.3V

// Present state bits (§2.2.9).
const PSTATE_CMD_INHIBIT: u32 = 1 << 0;
const PSTATE_DAT_INHIBIT: u32 = 1 << 1;
/// DAT Line Signal Level, bits [23:20] — the live level of
/// DAT[3:0], read by the voltage-switch sequence (Linux
/// `SDHCI_DATA_LVL_MASK`, shift 20).
const PSTATE_DAT_LVL_MASK: u32 = 0x00F0_0000;
const PSTATE_DAT_LVL_SHIFT: u32 = 20;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const PSTATE_BUFFER_READ_EN: u32 = 1 << 11;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const PSTATE_BUFFER_WRITE_EN: u32 = 1 << 10;
const PSTATE_CARD_INSERTED: u32 = 1 << 16;

// Normal interrupt status bits (§2.2.18).
const NIS_CMD_COMPLETE: u16 = 1 << 0;
const NIS_TRANSFER_COMPLETE: u16 = 1 << 1;
const NIS_DMA_INTERRUPT: u16 = 1 << 3;
const NIS_BUFFER_WRITE_READY: u16 = 1 << 4;
const NIS_BUFFER_READ_READY: u16 = 1 << 5;
const NIS_ERROR: u16 = 1 << 15;

// Error interrupt status bits (§2.2.19).
const EIS_ADMA_ERROR: u16 = 1 << 9;

// Command response types (§2.2.6).
const RESP_NONE: u16 = 0b00;
const RESP_136: u16 = 0b01;
const RESP_48: u16 = 0b10;
const RESP_48_BUSY: u16 = 0b11;

// Command flags (§2.2.6 cont).
const CMD_CRC_EN: u16 = 1 << 3;
const CMD_INDEX_EN: u16 = 1 << 4;
const CMD_DATA_PRES: u16 = 1 << 5;

// Transfer mode bits (§2.2.5).
const TM_DMA: u16 = 1 << 0;
const TM_BLOCK_COUNT_EN: u16 = 1 << 1;
const TM_AUTO_CMD12: u16 = 1 << 2;
const TM_DATA_DIR_READ: u16 = 1 << 4;
const TM_MULTI_BLOCK: u16 = 1 << 5;

/// SD command index → encoded register write per §2.2.6.
fn make_cmd(idx: u8, resp_kind: u16, has_data: bool) -> u16 {
    let mut v = (idx as u16) << 8 | resp_kind;
    // CRC + index check are required for most R1/R3/R6 paths; the
    // spec says they're enabled per response-type table 2-19.
    match resp_kind {
        RESP_136 => v |= CMD_CRC_EN,
        RESP_48 => v |= CMD_CRC_EN | CMD_INDEX_EN,
        RESP_48_BUSY => v |= CMD_CRC_EN | CMD_INDEX_EN,
        _ => {}
    }
    if has_data {
        v |= CMD_DATA_PRES;
    }
    v
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SdhciError {
    BarMapFailed,
    /// Software reset never cleared within the spin budget.
    ResetTimeout,
    /// Card-presence bit was 0 after power-up.
    NoCard,
    /// CMD line stayed busy past CMD_INHIBIT.
    CmdInhibitTimeout,
    /// CMD didn't complete within the bounded poll.
    CmdTimeout,
    /// Hardware reported an error in Error Int Status.
    DeviceError(u16),
    /// Buffer ready never asserted on a PIO transfer.
    PioStall,
    /// Caller-supplied buffer is the wrong size.
    BadLength,
    /// The internal clock never reported stable after a divider
    /// change (SD clock still enabled at the requested divider —
    /// see [`Sdhci::set_clock`]).
    ClockTimeout,
    /// The controller reported an ADMA error; the value is the
    /// ADMA Error Status register (§2.2.21).
    AdmaError(u16),
    /// A DMA transfer never reached Transfer Complete.
    DmaTimeout,
    /// CMD11 was rejected with an R1 error: the card never started
    /// the voltage switch and is still at 3.3 V — no recovery is
    /// needed, UHS is simply skipped.
    VoltageSwitchRejected,
    /// The voltage switch failed after CMD11 was accepted (a DAT
    /// line check failed, or CMD11 itself timed out): the card's
    /// signalling state is unknown, so the caller must power-cycle
    /// the card and re-identify (Linux returns `-EAGAIN` here and
    /// the core retries with S18R = 0).
    VoltageSwitchFailed,
    /// CMD19 tuning never completed (Execute Tuning stayed set past
    /// the loop/budget limit, or the tuned-clock bit never set).
    TuningFailed,
}

/// Host data-path DMA mode, selected from Capabilities at bring-up
/// (same selection rule as `drivers/sdio/src/sdhci/adma.rs`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaMode {
    /// Single-address SDMA with a 32-bit system address.
    Sdma,
    /// ADMA2, 32-bit descriptors.
    Adma32,
    /// ADMA2, 12-byte 64-bit descriptors.
    Adma64,
}

impl DmaMode {
    pub const fn is_adma(self) -> bool {
        matches!(self, Self::Adma32 | Self::Adma64)
    }
    pub const fn desc_size(self) -> usize {
        match self {
            Self::Adma64 => ADMA_DESC_SIZE_64,
            _ => ADMA_DESC_SIZE_32,
        }
    }
    /// Bus-address mask the bounce buffer must fit under (64-bit
    /// only for 64-bit ADMA).
    pub const fn dma_mask(self) -> u64 {
        match self {
            Self::Adma64 => u64::MAX,
            _ => u32::MAX as u64,
        }
    }
    /// HOST_CONTROL DMA select for this mode.
    pub const fn host_control(self) -> u8 {
        match self {
            Self::Sdma => HC_DMA_SDMA,
            Self::Adma32 => HC_DMA_ADMA32,
            Self::Adma64 => HC_DMA_ADMA64,
        }
    }
}

/// DMA mode selection from the host spec version + Capabilities
/// (Linux `sdhci_setup_host` DMA flags, as in sdio `adma::select`):
/// ADMA2 from spec ≥ 2.00 + `CAPS_CAN_DO_ADMA2`, 64-bit when
/// `CAPS_CAN_64BIT`; SDMA from `CAPS_CAN_DO_SDMA` on a host without
/// 64-bit addressing (a 64-bit host without v4 mode has no 32-bit
/// SDMA address register); ADMA preferred over SDMA. `None` keeps
/// PIO.
pub const fn select_dma_mode(spec_version: u8, caps: u32) -> Option<DmaMode> {
    let bits64 = caps & CAPS_CAN_64BIT != 0;
    if spec_version >= SPEC_200 && caps & CAPS_CAN_DO_ADMA2 != 0 {
        return Some(if bits64 {
            DmaMode::Adma64
        } else {
            DmaMode::Adma32
        });
    }
    if caps & CAPS_CAN_DO_SDMA != 0 && !bits64 {
        return Some(DmaMode::Sdma);
    }
    None
}

/// UHS-I bus speed mode (SD Physical Layer Spec §4.2.4 /
/// Table 4-10, Function Group 1 access mode; Linux
/// `UHS_*_BUS_SPEED` + `SD_MODE_UHS_*`).
///
/// The `u8` values are the CMD6 Function Group 1 function numbers
/// (0 = SDR12, 1 = SDR25, 2 = SDR50, 3 = SDR104, 4 = DDR50) and
/// double as the HOST_CONTROL2 UHS Mode Select values (§2.2.15) —
/// the two encodings agree by spec design.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UhsMode {
    Sdr12,
    Sdr25,
    Sdr50,
    Sdr104,
    Ddr50,
}

impl UhsMode {
    /// CMD6 Function Group 1 function number (== HOST_CONTROL2
    /// UHS Mode Select value).
    pub const fn function(self) -> u8 {
        match self {
            Self::Sdr12 => 0,
            Self::Sdr25 => 1,
            Self::Sdr50 => 2,
            Self::Sdr104 => 3,
            Self::Ddr50 => 4,
        }
    }

    /// Maximum SD clock for the mode (SD Physical Layer Spec
    /// §4.2.4 / Linux `UHS_*_MAX_DTR`): SDR12 25 MHz, SDR25
    /// 50 MHz, SDR50 100 MHz, SDR104 208 MHz, DDR50 50 MHz.
    pub const fn max_clock_hz(self) -> u32 {
        match self {
            Self::Sdr12 => 25_000_000,
            Self::Sdr25 => 50_000_000,
            Self::Sdr50 => 100_000_000,
            Self::Sdr104 => 208_000_000,
            Self::Ddr50 => 50_000_000,
        }
    }

    /// HOST_CONTROL2 UHS Mode Select value for this mode.
    pub const fn host_control2(self) -> u16 {
        self.function() as u16
    }

    /// Whether the mode needs CMD19 tuning on this host (Linux
    /// `sdhci_execute_tuning`): SDR104 always; SDR50 / DDR50
    /// only when the host reports "Use Tuning for SDR50"
    /// (Capabilities bit 45). SDR12 / SDR25 use fixed sampling.
    pub const fn needs_tuning(self, caps1_tuning_sdr50: bool) -> bool {
        match self {
            Self::Sdr104 => true,
            Self::Sdr50 | Self::Ddr50 => caps1_tuning_sdr50,
            Self::Sdr12 | Self::Sdr25 => false,
        }
    }
}

/// CMD6 (SWITCH_FUNC) argument (SD Physical Layer Spec §4.3.10;
/// Linux `drivers/mmc/core/sd_ops.c` `mmc_sd_switch` lineage):
/// bit 31 is the mode (0 = check, 1 = switch), each function
/// group occupies 4 bits (group 1 in [3:0], group 2 in [7:4],
/// …), and every group except the target keeps 0xF ("no change").
pub const fn cmd6_arg(switch: bool, group: u8, value: u8) -> u32 {
    let mode = if switch { 1u32 << 31 } else { 0 };
    let shift = (group as u32) * 4;
    let others = 0x00FF_FFFFu32 & !(0xFu32 << shift);
    mode | others | ((value as u32 & 0xF) << shift)
}

/// Pick the best UHS-I mode the card, the host, and the base clock
/// all admit (Linux `sd_update_bus_speed_mode` preference order:
/// SDR104 > DDR50 > SDR50 > SDR25).
///
/// `card_support` is the CMD6 status[13] Function Group 1
/// bitmask; `caps1` is the Capabilities_1 register; `base_hz` is
/// the host base clock. A mode is admitted only when the card
/// reports it, the host Capabilities_1 reports it (SDR25 needs no
/// Capabilities_1 bit — it is the baseline 1.8 V mode of a v3.00+
/// host), and the base clock can actually reach the mode's maximum
/// rate (a slower clock would make the mode no faster than the one
/// below it). SDR12 is never picked: it runs at the same 25 MHz as
/// default speed, so switching voltage for it buys nothing.
/// Returns `None` when no UHS mode is admissible — the caller
/// stays at 3.3 V default speed.
pub const fn select_uhs_mode(card_support: u8, caps1: u32, base_hz: u32) -> Option<UhsMode> {
    // SDR104: card bit 3 + host bit + 208 MHz base.
    if card_support & (1 << 3) != 0
        && caps1 & CAPS1_SUPPORT_SDR104 != 0
        && base_hz >= UhsMode::Sdr104.max_clock_hz()
    {
        return Some(UhsMode::Sdr104);
    }
    // DDR50: card bit 4 + host bit + 50 MHz base.
    if card_support & (1 << 4) != 0
        && caps1 & CAPS1_SUPPORT_DDR50 != 0
        && base_hz >= UhsMode::Ddr50.max_clock_hz()
    {
        return Some(UhsMode::Ddr50);
    }
    // SDR50: card bit 2 + host bit + 100 MHz base.
    if card_support & (1 << 2) != 0
        && caps1 & CAPS1_SUPPORT_SDR50 != 0
        && base_hz >= UhsMode::Sdr50.max_clock_hz()
    {
        return Some(UhsMode::Sdr50);
    }
    // SDR25: card bit 1 + 50 MHz base (no host Capabilities_1 bit).
    if card_support & (1 << 1) != 0 && base_hz >= UhsMode::Sdr25.max_clock_hz() {
        return Some(UhsMode::Sdr25);
    }
    None
}

/// Clock divider for `target_hz` from `base_hz` (Linux
/// `sdhci_calc_clk`, as in sdio `host.rs::clock_divisor`): the
/// divided clock is `base / divisor`, so the divisor is
/// `ceil(base / target)`, rounded up to an even number on spec
/// 3.00+ (every even divisor is representable) or a power of two
/// on spec ≤ 2.00. Returns 1 when the base already meets the
/// target (divider 1 = base clock, the minimum the field holds).
pub const fn clock_divisor(base_hz: u32, target_hz: u32, spec_300: bool) -> u32 {
    if target_hz == 0 || base_hz <= target_hz {
        return 1;
    }
    let div = base_hz.div_ceil(target_hz);
    if spec_300 {
        div.next_multiple_of(2).min(MAX_DIV_SPEC_300)
    } else {
        div.next_power_of_two().min(MAX_DIV_SPEC_200)
    }
}

/// Encode a divisor into the CLOCK_CONTROL divider field (10-bit
/// split encoding: low 8 bits in [15:8], high 2 bits in [7:6]).
/// The field holds `divisor / 2` ("divide by 2*d" encoding).
pub const fn clock_control_word(divisor: u32) -> u16 {
    let d = (divisor >> 1) as u16;
    ((d & 0xFF) << 8) | ((d >> 8) & 0x03) << 6
}

/// Write one ADMA2 descriptor into `table` at `index` (same layout
/// as sdio `adma::write_desc`: little-endian attribute, length,
/// low address, high address for 64-bit descriptors). A length of
/// 65536 encodes as 0.
pub fn write_adma_desc(
    table: &mut [u8],
    index: usize,
    desc_size: usize,
    addr: u64,
    len: usize,
    attr: u16,
) -> Result<(), SdhciError> {
    let at = index * desc_size;
    let desc = table
        .get_mut(at..at + desc_size)
        .ok_or(SdhciError::BadLength)?;
    if desc_size == ADMA_DESC_SIZE_32 && addr > u64::from(u32::MAX) {
        return Err(SdhciError::BadLength);
    }
    desc[0..2].copy_from_slice(&attr.to_le_bytes());
    desc[2..4].copy_from_slice(&(len as u16).to_le_bytes());
    desc[4..8].copy_from_slice(&(addr as u32).to_le_bytes());
    if desc_size == ADMA_DESC_SIZE_64 {
        desc[8..12].copy_from_slice(&((addr >> 32) as u32).to_le_bytes());
    }
    Ok(())
}

/// Read one ADMA2 descriptor back (attribute, length, address);
/// `len` 0 means 65536 for a TRAN descriptor. Test/fixture use.
pub fn read_adma_desc(table: &[u8], index: usize, desc_size: usize) -> Option<(u16, u16, u64)> {
    let at = index * desc_size;
    let desc = table.get(at..at + desc_size)?;
    let attr = u16::from_le_bytes([desc[0], desc[1]]);
    let len = u16::from_le_bytes([desc[2], desc[3]]);
    let mut addr = u64::from(u32::from_le_bytes([desc[4], desc[5], desc[6], desc[7]]));
    if desc_size == ADMA_DESC_SIZE_64 {
        addr |= u64::from(u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]])) << 32;
    }
    Some((attr, len, addr))
}

/// Host-owned DMA buffers for one controller: a coherent bounce
/// buffer every DMA data command goes through (caller slices are
/// ordinary kernel memory, never handed to the device — the sdio
/// `Engine` pattern) plus, for ADMA, the descriptor table. The
/// bounce buffer is page-aligned, so the ADMA align-buffer path is
/// never taken; a chunk is one segment, one TRAN descriptor.
pub struct DmaEngine {
    mode: DmaMode,
    /// Descriptor table (ADMA only); absent for SDMA.
    table: Option<DmaBuffer>,
    bounce: DmaBuffer,
}

impl core::fmt::Debug for DmaEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmaEngine")
            .field("mode", &self.mode)
            .field("bounce_len", &self.bounce.len())
            .finish_non_exhaustive()
    }
}

impl DmaEngine {
    /// Allocate the bounce buffer (and the ADMA table) below the
    /// mode's DMA mask. `Err` means "this mode cannot be used" —
    /// the caller falls back (ADMA → SDMA → PIO).
    pub fn new(mode: DmaMode) -> Result<Self, ()> {
        let mask = mode.dma_mask();
        let table = if mode.is_adma() {
            let t = alloc_coherent_masked(ADMA_TABLE_BYTES, DomainId::DRIVER_0, mask)
                .map_err(|_| ())?;
            if t.dma_addr().raw() & 0x7 != 0 || t.len() < ADMA_TABLE_BYTES {
                return Err(());
            }
            Some(t)
        } else {
            None
        };
        let bounce =
            alloc_coherent_masked(DMA_CHUNK_BYTES, DomainId::DRIVER_0, mask).map_err(|_| ())?;
        if bounce.len() < DMA_CHUNK_BYTES
            || bounce.dma_addr().raw() & 0x3 != 0
            || bounce
                .dma_addr()
                .raw()
                .checked_add(DMA_CHUNK_BYTES as u64 - 1)
                .is_none_or(|end| end > mask)
        {
            return Err(());
        }
        Ok(Self {
            mode,
            table,
            bounce,
        })
    }

    pub fn mode(&self) -> DmaMode {
        self.mode
    }

    /// Bus address of the bounce buffer.
    pub fn bounce_addr(&self) -> u64 {
        self.bounce.dma_addr().raw()
    }

    /// Bus address of the descriptor table, if ADMA.
    pub fn table_addr(&self) -> Option<u64> {
        self.table.as_ref().map(|t| t.dma_addr().raw())
    }

    /// Build the single-segment ADMA table for a chunk at the
    /// bounce address: one TRAN descriptor + a NOP/END terminator.
    /// Callers must fence (SeqCst) after this before the ADMA
    /// address / COMMAND register writes, so the descriptor stores
    /// are visible to the device.
    pub fn build_table(&mut self, len: usize) -> Result<(), SdhciError> {
        let Some(table) = self.table.as_mut() else {
            return Err(SdhciError::BadLength);
        };
        let desc_size = self.mode.desc_size();
        let addr = self.bounce_addr();
        let slice = table.as_mut_slice();
        write_adma_desc(slice, 0, desc_size, addr, len, ADMA_ATTR_TRAN_VALID)?;
        write_adma_desc(slice, 1, desc_size, 0, 0, ADMA_ATTR_NOP_END_VALID)?;
        Ok(())
    }

    /// Descriptor `index` of the current table (tests/diagnostics).
    pub fn descriptor(&self, index: usize) -> Option<(u16, u16, u64)> {
        let table = self.table.as_ref()?;
        read_adma_desc(table.as_slice(), index, self.mode.desc_size())
    }
}

/// Negotiated data-path profile, for diagnostics and tests.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DataPath {
    /// SD clock actually programmed, in Hz.
    pub clock_hz: u32,
    /// Negotiated bus width: 1 or 4.
    pub bus_width: u8,
    /// DMA mode admitted at bring-up; `None` is PIO.
    pub dma_mode: Option<DmaMode>,
    /// UHS-I mode negotiated at bring-up; `None` is default speed
    /// at 3.3 V signalling.
    pub uhs_mode: Option<UhsMode>,
}

impl DataPath {
    /// The identification profile: 400 kHz, 1-bit, PIO, 3.3 V.
    pub const fn identification() -> Self {
        Self {
            clock_hz: INIT_CLOCK_HZ,
            bus_width: 1,
            dma_mode: None,
            uhs_mode: None,
        }
    }
}

/// One multi-block chunk's payload: a read destination or a write
/// source, exactly `blocks * 512` bytes. The chunk fns only read
/// from a write payload, so `write_blocks` passes its caller slice
/// straight through with no per-chunk copy.
enum ChunkIo<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

impl<'a> ChunkIo<'a> {
    const fn is_read(&self) -> bool {
        matches!(self, Self::Read(_))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SdCard {
    /// Card RCA (relative card address) negotiated via CMD3.
    pub rca: u16,
    /// CID register read via CMD2 (response 136).
    pub cid: [u32; 4],
    /// Response from CMD8 — non-zero implies SD spec ≥ 2.0 (the
    /// card supports CMD8 and matches our voltage check).
    pub if_cond_match: bool,
    /// CCS bit from ACMD41 — 1 = SDHC/SDXC (block-addressed),
    /// 0 = SDSC (byte-addressed).
    pub ccs: bool,
    /// S18A bit from the ACMD41 OCR (bit 24) — the card accepts a
    /// switch to 1.8 V signalling (SD Physical Layer Spec
    /// §4.2.4.1). The gate for CMD11: a card that reports 0 here
    /// must never be sent CMD11.
    pub s18a: bool,
    /// Card capacity in 512-byte blocks.
    pub capacity_blocks: u64,
}

/// Register-access seam for the SDHCI register file.
///
/// All hardware access goes through this trait: production uses
/// [`MmioTransport`] over the BAR0 [`MmioRegion`]; kernel-test
/// fixtures model the register file + card behind the same seam
/// (the `RtsxTransport` pattern from the sibling RTSX driver), so
/// the whole identify → publish conversation runs without silicon.
pub trait SdhciTransport: Send + Sync + core::fmt::Debug {
    /// Read the 8-bit register at BAR0 `offset`.
    fn read8(&self, offset: u64) -> u8;
    /// Read the 16-bit register at BAR0 `offset`.
    fn read16(&self, offset: u64) -> u16;
    /// Read the 32-bit register at BAR0 `offset`.
    fn read32(&self, offset: u64) -> u32;
    /// Write the 8-bit register at BAR0 `offset`.
    fn write8(&self, offset: u64, value: u8);
    /// Write the 16-bit register at BAR0 `offset`.
    fn write16(&self, offset: u64, value: u16);
    /// Write the 32-bit register at BAR0 `offset`.
    fn write32(&self, offset: u64, value: u32);
}

/// Production [`SdhciTransport`]: the controller's BAR0 MMIO window.
#[derive(Debug)]
struct MmioTransport {
    region: MmioRegion,
}

impl SdhciTransport for MmioTransport {
    fn read8(&self, offset: u64) -> u8 {
        // SAFETY: offsets are the SDHCI register block (§2) inside
        // the BAR0 window `bring_up` mapped; the controller is
        // exclusively owned by this driver.
        unsafe { self.region.read8(offset) }
    }
    fn read16(&self, offset: u64) -> u16 {
        // SAFETY: same as `read8`.
        unsafe { self.region.read16(offset) }
    }
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: same as `read8`.
        unsafe { self.region.read32(offset) }
    }
    fn write8(&self, offset: u64, value: u8) {
        // SAFETY: same as `read8`.
        unsafe { self.region.write8(offset, value) }
    }
    fn write16(&self, offset: u64, value: u16) {
        // SAFETY: same as `read8`.
        unsafe { self.region.write16(offset, value) }
    }
    fn write32(&self, offset: u64, value: u32) {
        // SAFETY: same as `read8`.
        unsafe { self.region.write32(offset, value) }
    }
}

pub struct Sdhci {
    io: alloc::sync::Arc<dyn SdhciTransport>,
    pub card: IrqSafeSpinLock<Option<SdCard>>,
    /// Negotiated data-path profile (identification profile until
    /// `negotiate_data_path` runs). Short critical sections only —
    /// never held across a register wait.
    path: IrqSafeSpinLock<DataPath>,
    /// DMA engine admitted at bring-up (bounce buffer + ADMA
    /// table). Locked only for the short prepare/complete phases
    /// of a transfer — never across the completion poll.
    dma: IrqSafeSpinLock<Option<DmaEngine>>,
    /// Serialises polled SD transfers across callers. Spun on WITHOUT
    /// masking interrupts — see [`crate::req_gate::ReqGate`] for why
    /// this replaces holding `CONTROLLER` across a multi-block PIO
    /// loop (each block issues polled commands with 100 ms–1 s
    /// deadlines; the aggregate hold scales with the block count).
    req_gate: AtomicBool,
}

impl core::fmt::Debug for Sdhci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sdhci")
            .field("probed_card", &self.card.lock().is_some())
            .field("data_path", &*self.path.lock())
            .finish_non_exhaustive()
    }
}

impl Sdhci {
    /// Bring up the host controller: software reset, supply 400 kHz
    /// init clock, set 3.3V, run the SD identification sequence.
    /// Returns the populated `SdCard`.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively for the duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, SdhciError> {
        // SAFETY: caller-asserted.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| SdhciError::BarMapFailed)?;
        let me = Sdhci {
            io: alloc::sync::Arc::new(MmioTransport { region: mmio }),
            card: IrqSafeSpinLock::new(None),
            path: IrqSafeSpinLock::new(DataPath::identification()),
            dma: IrqSafeSpinLock::new(None),
            req_gate: AtomicBool::new(false),
        };

        // AMD FCH SDHCI quirk: on Renoir / Phoenix / older FCH parts
        // (1022:7906 / 1022:1611 / 1022:1612 / 1022:14CC / 1022:14E7
        // and friends), SRST_ALL does NOT self-clear from certain
        // sticky DATA-line states. The controller hangs the bring-up
        // path with a ResetTimeout. Linux works around this in
        // `drivers/mmc/host/sdhci-pci-core.c:amd_sdhci_reset` with a
        // full PCI power-state cycle BEFORE the soft reset — we do
        // the same here, scoped to AMD vendor.
        //
        // D3hot is sufficient; D3cold (which Linux uses) would need
        // ACPI _PS3/_PS0 power-resource manipulation that NARF
        // doesn't wire today. D3hot clears the controller's volatile
        // state without dropping the link, and is enough on the AMD
        // FCH parts in practice.
        if device.id.vendor == 0x1022 {
            // Power-cycle errors are non-fatal — fall through to the
            // soft-reset attempt regardless. The user-visible signal
            // is "no PM cap" (CapNotPresent), which can happen on
            // QEMU's emulated SDHCI.
            if let Err(e) = narf_bus::pci::pm_d3hot_cycle(cap, device) {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  sdhci: AMD pre-reset PM cycle skipped: {:?}",
                    e,
                );
            }
        }

        // 1. Software reset — Reset All (§3.6).
        me.io.write8(REG_SOFT_RESET, SRST_ALL);
        // responsive_spin_until ticks sleep_pumps every ~4096 iters
        // so the FB cursor / serial drain stay alive during the
        // reset. SDHCI 4.20 §3.6 says SRST_ALL self-clears within
        // 100 ms on a healthy controller.
        let done = narf_scheduler::responsive_spin_until(
            || me.io.read8(REG_SOFT_RESET) & SRST_ALL == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !done {
            return Err(SdhciError::ResetTimeout);
        }

        // 2. Power-on at 3.3V.
        me.io.write8(REG_POWER_CONTROL, POWER_3V3 | POWER_ON);

        // 3. Internal clock enable + supply 400 kHz init clock.
        //    `set_clock` derives the divider from the Capabilities
        //    base clock (or the legacy 0x80 divider when the base
        //    is unknown) and always enables the SD clock — the
        //    stable timeout is ignored here exactly as before, so
        //    a slow controller still comes up.
        let _ = me.set_clock(INIT_CLOCK_HZ);

        // 4. Default DTOCV = 0xE (max timeout).
        me.io.write8(REG_TIMEOUT_CTRL, 0x0E);

        // 5. Enable normal + error interrupt status reporting (we
        //    poll, but the status bits only set when enabled).
        me.io.write16(REG_NORMAL_INT_EN, 0xFFFF);
        me.io.write16(REG_ERROR_INT_EN, 0xFFFF);

        // 6. Card-present check.
        let pstate = me.io.read32(REG_PRESENT_STATE);
        if pstate & PSTATE_CARD_INSERTED == 0 {
            return Err(SdhciError::NoCard);
        }

        // 7. Run the SD identification sequence.
        // SAFETY: `me.io` is the SDHCI register window set up above
        // and `identify_sequence` runs here at bring-up (its other
        // call sites are resume re-identification, #839, and the
        // voltage-switch recovery path after a power cycle),
        // satisfying its single-caller ownership precondition,
        // with no transfer in flight.
        let card = unsafe { me.identify_sequence() }?;
        *me.card.lock() = Some(card);
        // Negotiate the data path (clock raise, bus width, DMA).
        // Best-effort by design: any step that fails leaves the
        // identification profile in place and the card stays usable.
        me.negotiate_data_path();
        Ok(me)
    }

    /// Wait for both CMD_INHIBIT and (when issuing a data-bearing
    /// command) DAT_INHIBIT to clear.
    fn wait_idle(&self, with_data: bool) -> Result<(), SdhciError> {
        let mask = if with_data {
            PSTATE_CMD_INHIBIT | PSTATE_DAT_INHIBIT
        } else {
            PSTATE_CMD_INHIBIT
        };
        // responsive_spin_until keeps cursor/FB/serial alive on a
        // stuck controller. SDHCI 4.20 §3.7: any in-flight command
        // must complete within the data-timeout window programmed
        // in REG_TIMEOUT_CTRL. 1 s is a comfortable upper bound for
        // the longest plausible card response.
        let done = narf_scheduler::responsive_spin_until(
            || self.io.read32(REG_PRESENT_STATE) & mask == 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if done {
            Ok(())
        } else {
            Err(SdhciError::CmdInhibitTimeout)
        }
    }

    /// Issue a command + poll until cmd-complete.
    /// Returns the 32-bit response (low 32 bits for R1/R3/R6/R7;
    /// for R2, callers read all four response registers via
    /// `read_response_136`). Thin wrapper over [`Self::cmd_inner`]
    /// for commands with no data phase of their own.
    // Wide signature mirrors the SDHCI command/transfer register set
    // (idx, arg, response kind, data flag, transfer mode, block size/count).
    #[allow(clippy::too_many_arguments)]
    fn cmd(
        &self,
        idx: u8,
        arg: u32,
        resp_kind: u16,
        has_data: bool,
        transfer: u16,
        block_size: u16,
        block_cnt: u16,
    ) -> Result<u32, SdhciError> {
        self.cmd_inner(
            idx, arg, resp_kind, has_data, transfer, block_size, block_cnt,
        )
    }

    /// Issue a command + poll until cmd-complete, programming the
    /// block size / count / transfer-mode registers first when the
    /// command carries data. Returns the 32-bit response. The data
    /// phase (PIO drain or DMA completion wait) is the caller's job
    /// — `cmd` is this same function for commands whose data phase
    /// is handled elsewhere, and multi-block transfers call it
    /// directly so they can run their own data phase afterwards.
    // Wide signature mirrors the SDHCI command/transfer register set
    // (idx, arg, response kind, data flag, transfer mode, block size/count).
    #[allow(clippy::too_many_arguments)]
    fn cmd_inner(
        &self,
        idx: u8,
        arg: u32,
        resp_kind: u16,
        has_data: bool,
        transfer: u16,
        block_size: u16,
        block_cnt: u16,
    ) -> Result<u32, SdhciError> {
        self.wait_idle(has_data)?;
        // Clear status bits (write-1-clear).
        self.io.write16(REG_NORMAL_INT_STS, 0xFFFF);
        self.io.write16(REG_ERROR_INT_STS, 0xFFFF);
        // Program block size / count first when there's data.
        if has_data {
            self.io.write16(REG_BLOCK_SIZE, block_size);
            self.io.write16(REG_BLOCK_COUNT, block_cnt);
            self.io.write16(REG_TRANSFER_MODE, transfer);
        }
        self.io.write32(REG_ARGUMENT, arg);
        self.io
            .write16(REG_COMMAND, make_cmd(idx, resp_kind, has_data));
        // Poll for command-complete (or error). responsive_spin_until
        // ticks sleep_pumps so cursor/FB/serial stay alive. 1 s
        // wall-clock budget is comfortably above the longest
        // plausible single-command latency.
        let done = narf_scheduler::responsive_spin_until(
            || self.io.read16(REG_NORMAL_INT_STS) & (NIS_CMD_COMPLETE | NIS_ERROR) != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::CmdTimeout);
        }
        let nis = self.io.read16(REG_NORMAL_INT_STS);
        if nis & NIS_ERROR != 0 {
            let eis = self.io.read16(REG_ERROR_INT_STS);
            return Err(SdhciError::DeviceError(eis));
        }
        // Clear cmd-complete; preserve other bits for the data path.
        self.io.write16(REG_NORMAL_INT_STS, NIS_CMD_COMPLETE);
        let r0 = self.io.read32(REG_RESPONSE_0);
        Ok(r0)
    }

    /// Read all four 32-bit response slots (R2 / CID / CSD).
    fn read_response_136(&self) -> [u32; 4] {
        let mut r = [0u32; 4];
        for (i, slot) in r.iter_mut().enumerate() {
            // `REG_RESPONSE_0 + i*4` for `i` in 0..4 covers the four
            // contiguous 32-bit response registers (R2 / CID / CSD).
            *slot = self.io.read32(REG_RESPONSE_0 + (i as u64) * 4);
        }
        r
    }

    /// Run the SD identification sequence.
    ///
    /// # Safety
    /// MMIO ownership; called at bring-up, again on resume
    /// re-identification (#839), and after a power cycle by the
    /// voltage-switch recovery path — never concurrently, never
    /// while a transfer is in flight.
    unsafe fn identify_sequence(&self) -> Result<SdCard, SdhciError> {
        // CMD0 (GO_IDLE_STATE) — no response.
        let _ = self.cmd(0, 0, RESP_NONE, false, 0, 0, 0)?;

        // CMD8 (SEND_IF_COND) — checks SD spec ≥ 2.0 + voltage.
        // Argument: 0x1AA = (3.3V supplied) | (check pattern 0xAA).
        // R7 response. Cards that don't support it fail with timeout
        // — we treat that as if_cond_match=false.
        let if_cond_match = match self.cmd(8, 0x1AA, RESP_48, false, 0, 0, 0) {
            Ok(r) => (r & 0xFF) == 0xAA,
            Err(_) => false,
        };

        // ACMD41 (SD_SEND_OP_COND): repeat CMD55 + CMD41 until
        // the response's busy bit (bit 31) is set.
        let mut acmd41_arg = 0x4000_0000u32; // HCS=1 (host supports SDHC).
        // S18R=1: ask the card whether it accepts a switch to
        // 1.8 V signalling (SD Physical Layer Spec §4.2.4.1; Linux
        // sets it whenever the host supports a UHS-I mode). Inert
        // for cards that do not support the switch — they answer
        // S18A=0 and the driver never sends CMD11.
        acmd41_arg |= ACMD41_S18R;
        if if_cond_match {
            acmd41_arg |= 0x0030_0000;
        } // 3.3V window.
        let mut ocr = 0u32;
        for _ in 0..1_000u32 {
            // CMD55 (APP_CMD).
            let _ = self.cmd(55, 0, RESP_48, false, 0, 0, 0)?;
            ocr = self.cmd(41, acmd41_arg, RESP_48, false, 0, 0, 0)?;
            if ocr & 0x8000_0000 != 0 {
                break;
            }
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }
        }
        if ocr & 0x8000_0000 == 0 {
            return Err(SdhciError::CmdTimeout);
        }
        let ccs = ocr & 0x4000_0000 != 0;
        let s18a = ocr & OCR_S18A != 0;

        // CMD2 (ALL_SEND_CID) — 136-bit response.
        let _ = self.cmd(2, 0, RESP_136, false, 0, 0, 0)?;
        let cid = self.read_response_136();

        // CMD3 (SEND_RELATIVE_ADDR) — RCA in R6 high half.
        let r6 = self.cmd(3, 0, RESP_48, false, 0, 0, 0)?;
        let rca = (r6 >> 16) as u16;

        // CMD9 (SEND_CSD) — 136-bit response. Addressed by RCA in Standby state.
        let _ = self.cmd(9, (rca as u32) << 16, RESP_136, false, 0, 0, 0)?;
        let csd_raw = self.read_response_136();
        let csd = crate::sd_proto::Csd::parse_shifted(&csd_raw).unwrap_or_default();
        let capacity_blocks = csd.capacity_bytes / 512;

        // CMD7 (SELECT/DESELECT_CARD) — move card to TRAN state so
        // subsequent CMD17/24 are accepted.
        let _ = self.cmd(7, (rca as u32) << 16, RESP_48_BUSY, false, 0, 0, 0)?;

        // Set block size to 512 (CMD16). SDHC ignores this for block
        // addressing but sending it is harmless.
        let _ = self.cmd(16, 512, RESP_48, false, 0, 0, 0)?;

        Ok(SdCard {
            rca,
            cid,
            if_cond_match,
            ccs,
            s18a,
            capacity_blocks,
        })
    }

    /// Base clock in Hz from the Capabilities register (spec 3.00+:
    /// bits [15:8] × 1 MHz; spec ≤ 2.00: bits [13:8] × 1 MHz).
    /// 0 when the controller reports no base clock.
    fn caps_base_clock_hz(caps: u32, spec_version: u8) -> u32 {
        let mhz = if spec_version >= SPEC_300 {
            (caps & CAPS_CLOCK_BASE_MASK) >> CAPS_CLOCK_BASE_SHIFT
        } else {
            (caps & CAPS_CLOCK_BASE_MASK_V2) >> CAPS_CLOCK_BASE_SHIFT
        };
        mhz * 1_000_000
    }

    /// Program the SD clock to at most `target_hz` from the
    /// Capabilities base clock: stop the SD clock, write the
    /// divider + internal-clock enable, wait up to 150 ms for the
    /// stable bit (SDHCI 4.20 §2.2.14 cap), then enable the SD
    /// clock. Returns the actual programmed rate — 0 when the base
    /// clock is unknown (the legacy 0x80 divider is programmed
    /// instead, targeting ≤ 400 kHz across the typical 25–100 MHz
    /// range). `Err(ClockTimeout)` means the stable bit never
    /// asserted; the SD clock is still enabled at the requested
    /// divider, exactly as the original init code did — callers
    /// that need a confirmed rate treat the error as "rate
    /// unconfirmed" and fall back.
    pub fn set_clock(&self, target_hz: u32) -> Result<u32, SdhciError> {
        // Capabilities + spec version are read-only registers, so
        // they are read fresh here rather than snapshotted.
        let caps = self.io.read32(REG_CAPABILITIES);
        let spec_version = (self.io.read16(REG_HOST_VERSION) & 0xFF) as u8;
        let base_hz = Self::caps_base_clock_hz(caps, spec_version);
        let (div_word, actual) = if base_hz == 0 {
            // No base clock reported: the legacy safe divider
            // (divisor 256) from the original bring-up.
            (clock_control_word(256), 0)
        } else {
            let div = clock_divisor(base_hz, target_hz, spec_version >= SPEC_300);
            (clock_control_word(div), base_hz / div)
        };
        // Full-word write: divider + internal enable, SD clock
        // stopped while the divider changes.
        self.io
            .write16(REG_CLOCK_CONTROL, div_word | CLK_INTERNAL_EN);
        // responsive_spin_until keeps cursor/FB/serial alive while
        // waiting for the internal clock to stabilise.
        let stable = narf_scheduler::responsive_spin_until(
            || self.io.read16(REG_CLOCK_CONTROL) & CLK_INTERNAL_STABLE != 0,
            narf_time::Deadline::after_ms(150),
        );
        let v = self.io.read16(REG_CLOCK_CONTROL);
        self.io.write16(REG_CLOCK_CONTROL, v | CLK_SD_EN);
        if stable {
            Ok(actual)
        } else {
            Err(SdhciError::ClockTimeout)
        }
    }

    /// The negotiated data-path profile (identification profile
    /// until `negotiate_data_path` runs).
    pub fn data_path(&self) -> DataPath {
        *self.path.lock()
    }

    /// Issue an application command: CMD55 (APP_CMD, addressed by
    /// RCA) followed by `idx` with `arg`. Returns `idx`'s response.
    fn app_cmd(&self, idx: u8, arg: u32, rca: u16) -> Result<u32, SdhciError> {
        let _ = self.cmd(55, (rca as u32) << 16, RESP_48, false, 0, 0, 0)?;
        self.cmd(idx, arg, RESP_48, false, 0, 0, 0)
    }

    /// Read the card's SCR via ACMD51 (SEND_SCR, 8-byte data block).
    /// The card must already be selected (CMD7 done — ACMD6/51 are
    /// only valid in transfer state).
    fn read_scr(&self) -> Result<Scr, SdhciError> {
        let rca = self.card.lock().ok_or(SdhciError::NoCard)?.rca;
        let _ = self.cmd(55, (rca as u32) << 16, RESP_48, false, 0, 0, 0)?;
        let r = self.cmd(51, 0, RESP_48, true, TM_DATA_DIR_READ, 8, 1)?;
        if (R1Status { raw: r }).has_error() {
            // The value is the R1 status low half, not an EIS code.
            return Err(SdhciError::DeviceError(r as u16));
        }
        let mut bytes = [0u8; 8];
        self.read_data_pio(&mut bytes)?;
        Ok(Scr::parse(&bytes))
    }

    /// Drain a short PIO data block (multiple of 4 bytes) from the
    /// Buffer Data Port after its command completed: wait for
    /// buffer-read-ready, read the words, wait for transfer
    /// complete. Used for the 8-byte SCR (ACMD51).
    fn read_data_pio(&self, out: &mut [u8]) -> Result<(), SdhciError> {
        if out.is_empty() || out.len() % 4 != 0 {
            return Err(SdhciError::BadLength);
        }
        let done = narf_scheduler::responsive_spin_until(
            || self.io.read16(REG_NORMAL_INT_STS) & (NIS_BUFFER_READ_READY | NIS_ERROR) != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        let nis = self.io.read16(REG_NORMAL_INT_STS);
        if nis & NIS_ERROR != 0 {
            let eis = self.io.read16(REG_ERROR_INT_STS);
            return Err(SdhciError::DeviceError(eis));
        }
        self.io.write16(REG_NORMAL_INT_STS, NIS_BUFFER_READ_READY);
        for chunk in out.chunks_mut(4) {
            let w = self.io.read32(REG_BUFFER_PORT);
            chunk.copy_from_slice(&w.to_le_bytes()[..chunk.len()]);
        }
        let done = narf_scheduler::responsive_spin_until(
            || self.io.read16(REG_NORMAL_INT_STS) & NIS_TRANSFER_COMPLETE != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        self.io.write16(REG_NORMAL_INT_STS, NIS_TRANSFER_COMPLETE);
        Ok(())
    }

    /// Spin for `ms` milliseconds while ticking the sleep pumps
    /// (the `responsive_spin_until(|| false, …)` delay pattern the
    /// SDIO stack uses for its microsecond delays).
    fn sleep_ms(ms: u64) {
        let _ = narf_scheduler::responsive_spin_until(
            || false,
            narf_time::Deadline::after_ms(ms),
        );
    }

    /// Issue CMD6 (SWITCH_FUNC) and read back the 64-byte switch
    /// status (SD Physical Layer Spec §4.3.10; Linux
    /// `mmc_sd_switch`). `switch` selects mode 1 (install the
    /// function) vs mode 0 (query); `group` is the 0-based function
    /// group (0 = access mode / bus speed), `value` the function.
    /// The card must be selected (CMD7 done).
    fn cmd6_status(&self, switch: bool, group: u8, value: u8) -> Result<SwitchStatus, SdhciError> {
        let arg = cmd6_arg(switch, group, value);
        // Block size 64 + the SDMA boundary field, as Linux
        // programs `SDHCI_MAKE_BLKSZ(7, 64)` for its 64-byte
        // switch/tuning transfers.
        let blksz = ((SDMA_BOUNDARY_ARG & 0x7) << 12) | 64;
        let r = self.cmd(6, arg, RESP_48, true, TM_DATA_DIR_READ, blksz, 1)?;
        if (R1Status { raw: r }).has_error() {
            return Err(SdhciError::DeviceError(r as u16));
        }
        let mut bytes = [0u8; 64];
        self.read_data_pio(&mut bytes)?;
        Ok(SwitchStatus::parse(&bytes))
    }

    /// Power-cycle the card after a failed voltage switch (Linux
    /// failure arm): POWER_ON off, 1 ms, POWER_ON on, preserving
    /// the 3.3 V field. Returns the recovery-required error.
    fn voltage_switch_power_cycle(&self) -> SdhciError {
        let pwr = self.io.read8(REG_POWER_CONTROL);
        self.io.write8(REG_POWER_CONTROL, pwr & !POWER_ON);
        Self::sleep_ms(POWER_CYCLE_MS);
        self.io.write8(REG_POWER_CONTROL, pwr | POWER_ON);
        SdhciError::VoltageSwitchFailed
    }

    /// Run the 1.8 V signalling switch on the host side, after
    /// CMD11 was accepted (Linux
    /// `sdhci_do_start_signal_voltage_switch`, 1.8 V arm): stop
    /// the SD clock, check DAT[3:0] == 0, enable 1.8 V signalling
    /// in HOST_CONTROL2, wait 5 ms, restart the SD clock, wait
    /// 1 ms, check DAT[3:0] == 1.
    ///
    /// POWER_CONTROL is deliberately untouched: the card supply
    /// stays 3.3 V (the SD card's operating range is 2.7–3.6 V);
    /// the 1.8 V signalling rail is the controller's own
    /// HOST_CONTROL2-switched rail (on AMD FCH hosts Linux leaves
    /// vqmmc unmodelled and the switch is exactly this register
    /// dance). On failure the card is power-cycled by
    /// `voltage_switch_power_cycle` and `VoltageSwitchFailed` is
    /// returned; the caller must re-identify.
    fn switch_signal_voltage(&self) -> Result<(), SdhciError> {
        use core::fmt::Write as _;
        // Stop the SD clock, keeping the divider + internal clock.
        let clk = self.io.read16(REG_CLOCK_CONTROL);
        self.io.write16(REG_CLOCK_CONTROL, clk & !CLK_SD_EN);
        // The card drives DAT[3:0] low after accepting CMD11.
        let pstate = self.io.read32(REG_PRESENT_STATE);
        if (pstate & PSTATE_DAT_LVL_MASK) >> PSTATE_DAT_LVL_SHIFT != 0 {
            let _ = writeln!(
                narf_console::Writer,
                "  sdhci: DAT lines not low after CMD11; power-cycling",
            );
            return Err(self.voltage_switch_power_cycle());
        }
        // Enable 1.8 V signalling.
        let ctrl2 = self.io.read16(REG_HOST_CONTROL_2);
        self.io.write16(REG_HOST_CONTROL_2, ctrl2 | HC2_VDD_180);
        // Wait 5 ms for the rail to settle.
        Self::sleep_ms(VOLTAGE_SWITCH_SETTLE_MS);
        // The enable must have stuck.
        let ctrl2 = self.io.read16(REG_HOST_CONTROL_2);
        if ctrl2 & HC2_VDD_180 == 0 {
            let _ = writeln!(
                narf_console::Writer,
                "  sdhci: 1.8 V signalling enable did not stick; power-cycling",
            );
            return Err(self.voltage_switch_power_cycle());
        }
        // Restart the SD clock and wait 1 ms.
        let clk = self.io.read16(REG_CLOCK_CONTROL);
        self.io.write16(REG_CLOCK_CONTROL, clk | CLK_SD_EN);
        Self::sleep_ms(VOLTAGE_SWITCH_DAT_MS);
        // Completion is checked by DAT[3:0] high (SD Physical
        // Layer Spec §4.2.4.1: any bit may be checked; Linux
        // requires all four).
        let pstate = self.io.read32(REG_PRESENT_STATE);
        if (pstate & PSTATE_DAT_LVL_MASK) == PSTATE_DAT_LVL_MASK {
            return Ok(());
        }
        let _ = writeln!(
            narf_console::Writer,
            "  sdhci: DAT lines not high after 1.8 V switch; power-cycling",
        );
        Err(self.voltage_switch_power_cycle())
    }

    /// Program the HOST_CONTROL2 UHS Mode Select field for `mode`,
    /// preserving the 1.8 V signalling enable and the tuning bits.
    fn set_uhs_host_mode(&self, mode: UhsMode) {
        let ctrl2 = self.io.read16(REG_HOST_CONTROL_2);
        self.io
            .write16(REG_HOST_CONTROL_2, (ctrl2 & !HC2_UHS_MASK) | mode.host_control2());
    }

    /// Execute CMD19 tuning for `mode` (Linux
    /// `sdhci_execute_tuning`): set Execute Tuning in
    /// HOST_CONTROL2, issue CMD19 (64-byte tuning block) until the
    /// host clears Execute Tuning or the 40-iteration / 150 ms
    /// budget is spent, then require the tuned-clock bit. Modes
    /// that do not need tuning return `Ok` immediately. On failure
    /// Execute Tuning + Tuned Clock are cleared (fixed sampling)
    /// and `TuningFailed` is returned.
    fn execute_tuning(&self, mode: UhsMode, caps1: u32) -> Result<(), SdhciError> {
        use core::fmt::Write as _;
        if !mode.needs_tuning(caps1 & CAPS1_TUNING_SDR50 != 0) {
            return Ok(());
        }
        let ctrl2 = self.io.read16(REG_HOST_CONTROL_2);
        self.io.write16(REG_HOST_CONTROL_2, ctrl2 | HC2_EXEC_TUNING);
        let budget = narf_time::Deadline::after_ms(TUNING_BUDGET_MS);
        let mut tuned = false;
        for _ in 0..TUNING_MAX_LOOPS {
            // CMD19: R1 + 64-byte tuning block, PIO, DMA off,
            // multi-block off — the block-size register carries
            // the boundary field as for CMD6.
            let blksz = ((SDMA_BOUNDARY_ARG & 0x7) << 12) | 64;
            let ok = match self.cmd(19, 0, RESP_48, true, TM_DATA_DIR_READ, blksz, 1) {
                Ok(r) if !(R1Status { raw: r }).has_error() => true,
                _ => false,
            };
            if ok {
                let mut block = [0u8; TUNING_BLOCK_LEN];
                if self.read_data_pio(&mut block).is_ok() {
                    let ctrl2 = self.io.read16(REG_HOST_CONTROL_2);
                    if ctrl2 & HC2_EXEC_TUNING == 0 {
                        tuned = ctrl2 & HC2_TUNED_CLK != 0;
                        break;
                    }
                }
            }
            if budget.expired() {
                break;
            }
        }
        if tuned {
            return Ok(());
        }
        // Fall back to fixed sampling: clear both tuning bits.
        let ctrl2 = self.io.read16(REG_HOST_CONTROL_2);
        self.io
            .write16(REG_HOST_CONTROL_2, ctrl2 & !(HC2_EXEC_TUNING | HC2_TUNED_CLK));
        let _ = writeln!(
            narf_console::Writer,
            "  sdhci: tuning failed for {:?}; fixed sampling",
            mode,
        );
        Err(SdhciError::TuningFailed)
    }

    /// Negotiate UHS-I after the bus-width step (Linux
    /// `mmc_sd_init_uhs_card` order: bus width, then mode select,
    /// then bus-speed switch, then tuning).
    ///
    /// Returns `Ok` for every outcome except a voltage-switch
    /// failure that needs a power-cycle + re-identification, which
    /// is `Err(VoltageSwitchFailed)` (the card was already
    /// power-cycled by `switch_signal_voltage` /
    /// `voltage_switch_power_cycle`).
    fn negotiate_uhs(
        &self,
        caps: u32,
        caps1: u32,
        spec_version: u8,
        base_hz: u32,
        path: &mut DataPath,
    ) -> Result<(), SdhciError> {
        use core::fmt::Write as _;
        // Gates: v3.00+ host, 1.8 V-capable host, a base clock to
        // raise from, and a card that accepts the switch (S18A).
        // Any gate closed leaves the card at 3.3 V default speed.
        if spec_version < SPEC_300 || caps & CAPS_CAN_VDD_180 == 0 || base_hz == 0 {
            return Ok(());
        }
        let s18a = self.card.lock().map(|c| c.s18a).unwrap_or(false);
        if !s18a {
            return Ok(());
        }
        // 1. CMD11: the card starts the voltage switch on an R1.
        match self.cmd(11, 0, RESP_48, false, 0, 0, 0) {
            Ok(r) if !(R1Status { raw: r }).has_error() => {}
            Ok(_) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  sdhci: CMD11 rejected; staying 3.3 V",
                );
                return Ok(());
            }
            Err(_) => {
                // No response to CMD11: the spec says power-cycle
                // (SD Physical Layer Spec §4.2.4.4).
                let _ = writeln!(
                    narf_console::Writer,
                    "  sdhci: CMD11 timed out; power-cycling",
                );
                return Err(self.voltage_switch_power_cycle());
            }
        }
        // 2. Host-side switch (clock stop, DAT checks, 1.8 V
        // enable, clock restart). Failure already power-cycled.
        self.switch_signal_voltage()?;
        // 3. CMD6 check: which UHS modes does the card offer at
        // 1.8 V? (At 3.3 V the SDR50/SDR104/DDR50 bits read 0 —
        // Linux queries only after the switch for this reason.)
        let support = match self.cmd6_status(false, 0, 0) {
            Ok(status) => status.group1_support(),
            Err(_) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  sdhci: CMD6 query failed; staying SDR12 at 1.8 V",
                );
                path.uhs_mode = Some(UhsMode::Sdr12);
                return Ok(());
            }
        };
        let Some(mode) = select_uhs_mode(support, caps1, base_hz) else {
            // No mode above SDR12 is admissible (SDR12-only card,
            // or the base clock cannot reach SDR25): stay in the
            // post-switch default, SDR12 at 1.8 V.
            path.uhs_mode = Some(UhsMode::Sdr12);
            return Ok(());
        };
        // 4. CMD6 switch to the mode; on rejection fall back to
        // SDR25, then to the SDR12 the switch already left us in.
        let mut settled = mode;
        match self.cmd6_status(true, 0, mode.function()) {
            Ok(status) if status.group1_function() == mode.function() => {}
            _ => match self.cmd6_status(true, 0, UhsMode::Sdr25.function()) {
                Ok(status) if status.group1_function() == UhsMode::Sdr25.function() => {
                    settled = UhsMode::Sdr25;
                }
                _ => {
                    settled = UhsMode::Sdr12;
                }
            },
        }
        // 5. Host side: UHS mode bits, then the mode clock
        // (Linux `sd_set_bus_speed_mode`: switch, timing, clock).
        // A clock that cannot be confirmed leaves the UHS state
        // unproven — power-cycle and re-identify at 3.3 V rather
        // than serve I/O at an unconfirmed rate.
        self.set_uhs_host_mode(settled);
        match self.set_clock(settled.max_clock_hz()) {
            Ok(actual) if actual != 0 => path.clock_hz = actual,
            _ => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  sdhci: UHS clock raise unconfirmed; power-cycling",
                );
                return Err(self.voltage_switch_power_cycle());
            }
        }
        // 6. Tuning where the mode needs it. A tuning failure in
        // SDR50/SDR104 falls back to SDR25 (re-switch + re-clock,
        // confirmed by the status read); DDR50 keeps fixed
        // sampling with a warning, as Linux does. If even the
        // SDR25 re-switch cannot be confirmed, the card is left in
        // an untuned high mode — power-cycle and re-identify at
        // 3.3 V instead of serving I/O on an unproven sampling
        // point.
        if settled.needs_tuning(caps1 & CAPS1_TUNING_SDR50 != 0) {
            match self.execute_tuning(settled, caps1) {
                Ok(()) => {}
                Err(_) if settled == UhsMode::Ddr50 => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  sdhci: DDR50 tuning failed; fixed sampling",
                    );
                }
                Err(_) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  sdhci: tuning failed; falling back to SDR25",
                    );
                    let confirmed = matches!(
                        self.cmd6_status(true, 0, UhsMode::Sdr25.function()),
                        Ok(status) if status.group1_function() == UhsMode::Sdr25.function()
                    );
                    if !confirmed {
                        return Err(self.voltage_switch_power_cycle());
                    }
                    self.set_uhs_host_mode(UhsMode::Sdr25);
                    match self.set_clock(UhsMode::Sdr25.max_clock_hz()) {
                        Ok(actual) if actual != 0 => path.clock_hz = actual,
                        _ => {
                            let _ = writeln!(
                                narf_console::Writer,
                                "  sdhci: SDR25 fallback clock unconfirmed; power-cycling",
                            );
                            return Err(self.voltage_switch_power_cycle());
                        }
                    }
                    settled = UhsMode::Sdr25;
                }
            }
        }
        path.uhs_mode = Some(settled);
        let _ = writeln!(
            narf_console::Writer,
            "  sdhci: UHS-I {:?} at {} kHz",
            settled,
            path.clock_hz / 1000,
        );
        Ok(())
    }

    /// Negotiate the post-identification data path, in the order
    /// Linux's `mmc_sd_init_card` uses: raise the clock, then
    /// read the SCR and widen the bus, then negotiate UHS-I, then
    /// admit DMA. Best-effort throughout — any step that fails
    /// logs and leaves the identification profile for that
    /// dimension in place, so the card stays usable at 400 kHz /
    /// 1-bit / PIO. A voltage-switch failure is the one exception:
    /// it power-cycles the card and re-runs identification +
    /// negotiation without UHS (see `negotiate_data_path_inner`).
    /// Returns the negotiated profile and records it on the
    /// controller.
    pub fn negotiate_data_path(&self) -> DataPath {
        use core::fmt::Write as _;
        let (path, needs_recovery) = self.negotiate_data_path_inner(true);
        if !needs_recovery {
            return path;
        }
        // Recovery: the card was already power-cycled. Bring it
        // back at 3.3 V: clear the 1.8 V signalling enable,
        // restart the init clock, re-identify, and negotiate the
        // data path without UHS.
        let ctrl2 = self.io.read16(REG_HOST_CONTROL_2);
        self.io.write16(REG_HOST_CONTROL_2, ctrl2 & !HC2_VDD_180);
        let _ = self.set_clock(INIT_CLOCK_HZ);
        // SAFETY: same MMIO ownership as the bring-up call; the
        // power cycle returned the card to idle, and this runs
        // exactly once for this failure, never concurrently with
        // another identify or transfer.
        match unsafe { self.identify_sequence() } {
            Ok(card) => {
                *self.card.lock() = Some(card);
                let (path, _) = self.negotiate_data_path_inner(false);
                let _ = writeln!(
                    narf_console::Writer,
                    "  sdhci: recovered at 3.3 V after voltage-switch failure",
                );
                path
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  sdhci: re-identify after voltage-switch failure failed: {:?}",
                    e,
                );
                path
            }
        }
    }

    /// The negotiate steps shared by the first attempt (with UHS)
    /// and the post-failure recovery (without). Returns the profile
    /// plus whether the caller must run the recovery path.
    fn negotiate_data_path_inner(&self, try_uhs: bool) -> (DataPath, bool) {
        use core::fmt::Write as _;
        // Capabilities + spec version are read-only registers.
        let caps = self.io.read32(REG_CAPABILITIES);
        let caps1 = self.io.read32(REG_CAPABILITIES_1);
        let spec_version = (self.io.read16(REG_HOST_VERSION) & 0xFF) as u8;
        let base_hz = Self::caps_base_clock_hz(caps, spec_version);
        let mut path = DataPath::identification();

        // 1. Clock raise to the 25 MHz default-speed maximum.
        if base_hz == 0 {
            let _ = writeln!(
                narf_console::Writer,
                "  sdhci: no base clock in Capabilities; staying at 400 kHz",
            );
        } else {
            match self.set_clock(DATA_CLOCK_HZ) {
                Ok(actual) if actual != 0 => path.clock_hz = actual,
                Ok(_) => {}
                Err(_) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  sdhci: clock raise failed; restoring 400 kHz",
                    );
                    let _ = self.set_clock(INIT_CLOCK_HZ);
                }
            }
        }

        // 2. Bus width: SCR probe, then ACMD6 + host control.
        match self.read_scr() {
            Ok(scr) if scr.supports_4bit() => {
                let rca = self.card.lock().map(|c| c.rca).unwrap_or(0);
                match self.app_cmd(6, 2, rca) {
                    Ok(r) if !(R1Status { raw: r }).has_error() => {
                        let hc = self.io.read8(REG_HOST_CONTROL_1);
                        self.io.write8(REG_HOST_CONTROL_1, hc | HC_4BIT_BUS);
                        path.bus_width = 4;
                    }
                    _ => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "  sdhci: ACMD6 4-bit switch rejected; staying 1-bit",
                        );
                    }
                }
            }
            Ok(_) => {}
            Err(_) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  sdhci: SCR read failed; staying 1-bit",
                );
            }
        }

        // 3. UHS-I: CMD11 voltage switch + CMD6 mode switch +
        // CMD19 tuning. A failure here either leaves the card at
        // 3.3 V (rejection) or needs the recovery path.
        if try_uhs {
            if let Err(e) = self.negotiate_uhs(caps, caps1, spec_version, base_hz, &mut path) {
                debug_assert_eq!(e, SdhciError::VoltageSwitchFailed);
                return (path, true);
            }
        }

        // 4. DMA admission: ADMA preferred, SDMA, else PIO.
        // Guarded by `is_none` so a recovery re-negotiation never
        // admits a second engine over the first.
        if self.dma.lock().is_none() {
            if let Some(mode) = select_dma_mode(spec_version, caps) {
                match DmaEngine::new(mode) {
                    Ok(engine) => {
                        *self.dma.lock() = Some(engine);
                        path.dma_mode = Some(mode);
                    }
                    Err(()) => {
                        // ADMA allocation failure falls back to SDMA
                        // when the caps allow it on a 32-bit host.
                        if mode.is_adma()
                            && caps & CAPS_CAN_DO_SDMA != 0
                            && caps & CAPS_CAN_64BIT == 0
                        {
                            if let Ok(engine) = DmaEngine::new(DmaMode::Sdma) {
                                *self.dma.lock() = Some(engine);
                                path.dma_mode = Some(DmaMode::Sdma);
                            }
                        }
                        if path.dma_mode.is_none() {
                            let _ = writeln!(
                                narf_console::Writer,
                                "  sdhci: DMA buffers unavailable; PIO data path",
                            );
                        }
                    }
                }
            }
        }

        {
            *self.path.lock() = path;
        }
        let _ = writeln!(
            narf_console::Writer,
            "  sdhci: data path {} kHz, {}-bit, {:?}, UHS {:?}",
            path.clock_hz / 1000,
            path.bus_width,
            path.dma_mode,
            path.uhs_mode,
        );
        (path, false)
    }

    /// Set (or clear) the HOST_CONTROL DMA select for a transfer.
    /// PIO transfers clear it — the select is meaningless without
    /// TRNS_DMA, and a stale ADMA select would misdirect the next
    /// DMA transfer's address programming.
    fn set_dma_select(&self, mode: Option<DmaMode>) {
        let hc = self.io.read8(REG_HOST_CONTROL_1);
        let sel = mode.map(|m| m.host_control()).unwrap_or(0);
        self.io
            .write8(REG_HOST_CONTROL_1, (hc & !HC_DMA_MASK) | sel);
    }

    /// Wait for a data transfer to complete after its command
    /// completed. `sdma_next` is `Some` for an SDMA transfer: on a
    /// DMA interrupt (512 KiB boundary) the SDMA address is
    /// reprogrammed to the next boundary and the wait continues
    /// (Linux `sdhci_data_irq` boundary restart).
    fn wait_transfer_complete(&self, sdma_next: Option<&mut u64>) -> Result<(), SdhciError> {
        let done = narf_scheduler::responsive_spin_until(
            || {
                self.io.read16(REG_NORMAL_INT_STS)
                    & (NIS_TRANSFER_COMPLETE | NIS_ERROR | NIS_DMA_INTERRUPT)
                    != 0
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::DmaTimeout);
        }
        loop {
            let nis = self.io.read16(REG_NORMAL_INT_STS);
            if nis & NIS_ERROR != 0 {
                let eis = self.io.read16(REG_ERROR_INT_STS);
                self.io.write16(REG_NORMAL_INT_STS, NIS_ERROR);
                if eis & EIS_ADMA_ERROR != 0 {
                    let aerr = self.io.read32(REG_ADMA_ERROR) as u16;
                    return Err(SdhciError::AdmaError(aerr));
                }
                return Err(SdhciError::DeviceError(eis));
            }
            if nis & NIS_DMA_INTERRUPT != 0 {
                self.io.write16(REG_NORMAL_INT_STS, NIS_DMA_INTERRUPT);
                if let Some(next) = sdma_next {
                    *next = (*next & !(SDMA_BOUNDARY_SIZE - 1)) + SDMA_BOUNDARY_SIZE;
                    self.io.write32(REG_SDMA_ADDR, *next as u32);
                }
                // Keep waiting for transfer complete.
                let done = narf_scheduler::responsive_spin_until(
                    || {
                        self.io.read16(REG_NORMAL_INT_STS)
                            & (NIS_TRANSFER_COMPLETE | NIS_ERROR | NIS_DMA_INTERRUPT)
                            != 0
                    },
                    narf_time::Deadline::after_ms(1_000),
                );
                if !done {
                    return Err(SdhciError::DmaTimeout);
                }
                continue;
            }
            if nis & NIS_TRANSFER_COMPLETE != 0 {
                self.io.write16(REG_NORMAL_INT_STS, NIS_TRANSFER_COMPLETE);
                return Ok(());
            }
            return Err(SdhciError::DmaTimeout);
        }
    }

    /// Wait for the Buffer Data Port to be ready for one PIO block.
    fn wait_buffer_ready(&self, read: bool) -> Result<(), SdhciError> {
        let want = if read {
            NIS_BUFFER_READ_READY
        } else {
            NIS_BUFFER_WRITE_READY
        };
        let done = narf_scheduler::responsive_spin_until(
            || self.io.read16(REG_NORMAL_INT_STS) & (want | NIS_ERROR) != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        let nis = self.io.read16(REG_NORMAL_INT_STS);
        if nis & NIS_ERROR != 0 {
            let eis = self.io.read16(REG_ERROR_INT_STS);
            return Err(SdhciError::DeviceError(eis));
        }
        self.io.write16(REG_NORMAL_INT_STS, want);
        Ok(())
    }

    /// Reset the CMD + DAT lines after a failed DMA transfer
    /// (best-effort: a stuck reset never fails the transfer that
    /// already failed) and latch the controller to PIO for the
    /// rest of the boot — the Linux ADMA-error fallback.
    fn dma_failed_fallback_pio(&self) {
        self.io.write8(REG_SOFT_RESET, SRST_CMD | SRST_DAT);
        let _ = narf_scheduler::responsive_spin_until(
            || self.io.read8(REG_SOFT_RESET) & (SRST_CMD | SRST_DAT) == 0,
            narf_time::Deadline::after_ms(100),
        );
        *self.dma.lock() = None;
        self.path.lock().dma_mode = None;
        self.set_dma_select(None);
    }

    /// One multi-block PIO chunk (2..=CHUNK_BLOCKS blocks) via
    /// CMD18 (read) or CMD25 (write) with Block Count Enable +
    /// Auto-CMD12.
    fn transfer_pio_chunk(
        &self,
        lba: u32,
        blocks: usize,
        mut io: ChunkIo<'_>,
        ccs: bool,
    ) -> Result<(), SdhciError> {
        let arg = if ccs { lba } else { lba.saturating_mul(512) };
        let read = io.is_read();
        let (idx, tm) = if read {
            (18, TM_DATA_DIR_READ)
        } else {
            (25, 0)
        };
        let tm = tm | TM_BLOCK_COUNT_EN | TM_AUTO_CMD12 | TM_MULTI_BLOCK;
        self.set_dma_select(None);
        let _ = self.cmd_inner(idx, arg, RESP_48, true, tm, 512, blocks as u16)?;
        for b in 0..blocks {
            self.wait_buffer_ready(read)?;
            let off = b * 512;
            match &mut io {
                ChunkIo::Read(out) => {
                    for i in 0..128usize {
                        let w = self.io.read32(REG_BUFFER_PORT);
                        out[off + i * 4..off + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
                    }
                }
                ChunkIo::Write(data) => {
                    for i in 0..128usize {
                        let w = u32::from_le_bytes([
                            data[off + i * 4],
                            data[off + i * 4 + 1],
                            data[off + i * 4 + 2],
                            data[off + i * 4 + 3],
                        ]);
                        self.io.write32(REG_BUFFER_PORT, w);
                    }
                }
            }
        }
        self.wait_transfer_complete(None)
    }

    /// Prepare one DMA chunk: copy write data into the bounce
    /// buffer, sync it for the device, build the ADMA table.
    /// Returns the mode + bounce/table addresses. The engine lock
    /// is held only for this short phase.
    fn dma_prepare_chunk(
        &self,
        len: usize,
        write_data: Option<&[u8]>,
    ) -> Result<(DmaMode, u64, Option<u64>), SdhciError> {
        use core::sync::atomic::{compiler_fence, Ordering};
        let mut guard = self.dma.lock();
        let engine = guard.as_mut().ok_or(SdhciError::BadLength)?;
        let mode = engine.mode();
        if let Some(data) = write_data {
            engine.bounce.as_mut_slice()[..len].copy_from_slice(&data[..len]);
        }
        compiler_fence(Ordering::SeqCst);
        engine.bounce.sync_for_device(
            0,
            len,
            if write_data.is_some() {
                DmaDirection::ToDevice
            } else {
                DmaDirection::FromDevice
            },
        );
        compiler_fence(Ordering::SeqCst);
        let bounce_addr = engine.bounce_addr();
        let table_addr = if mode.is_adma() {
            engine.build_table(len)?;
            // Descriptor stores must be visible before the
            // ADMA-address / COMMAND register writes.
            core::sync::atomic::fence(Ordering::SeqCst);
            engine.table_addr()
        } else {
            None
        };
        Ok((mode, bounce_addr, table_addr))
    }

    /// Complete one DMA chunk: sync the bounce buffer for the CPU
    /// and copy read data out. Short engine-lock phase.
    fn dma_complete_chunk(&self, len: usize, read_out: Option<&mut [u8]>) {
        use core::sync::atomic::{compiler_fence, Ordering};
        let mut guard = self.dma.lock();
        let Some(engine) = guard.as_mut() else {
            return;
        };
        compiler_fence(Ordering::SeqCst);
        engine.bounce.sync_for_cpu(
            0,
            len,
            if read_out.is_some() {
                DmaDirection::FromDevice
            } else {
                DmaDirection::ToDevice
            },
        );
        compiler_fence(Ordering::SeqCst);
        if let Some(out) = read_out {
            out[..len].copy_from_slice(&engine.bounce.as_slice()[..len]);
        }
    }

    /// One multi-block DMA chunk (2..=CHUNK_BLOCKS blocks) via
    /// CMD18/CMD25 with TRNS_DMA. Programs the SDMA address or the
    /// ADMA table address + HOST_CONTROL select before issuing the
    /// command, then waits for transfer complete (restarting SDMA
    /// at 512 KiB boundaries).
    fn transfer_dma_chunk(
        &self,
        lba: u32,
        blocks: usize,
        io: ChunkIo<'_>,
        ccs: bool,
    ) -> Result<(), SdhciError> {
        let arg = if ccs { lba } else { lba.saturating_mul(512) };
        let len = blocks * 512;
        let read = io.is_read();
        let (mode, bounce_addr, table_addr) = self.dma_prepare_chunk(
            len,
            match &io {
                ChunkIo::Read(_) => None,
                ChunkIo::Write(data) => Some(*data),
            },
        )?;
        // Program the DMA address + host select before COMMAND.
        if mode.is_adma() {
            let table = table_addr.ok_or(SdhciError::BadLength)?;
            self.io.write32(REG_ADMA_ADDR, table as u32);
            if mode == DmaMode::Adma64 {
                self.io.write32(REG_ADMA_ADDR_HI, (table >> 32) as u32);
            }
        } else {
            self.io.write32(REG_SDMA_ADDR, bounce_addr as u32);
        }
        self.set_dma_select(Some(mode));
        let (idx, tm) = if read {
            (18, TM_DATA_DIR_READ)
        } else {
            (25, 0)
        };
        let tm = tm | TM_DMA | TM_BLOCK_COUNT_EN | TM_AUTO_CMD12 | TM_MULTI_BLOCK;
        // SDMA boundary value: the controller stops at 512 KiB
        // boundaries (Block Size register field); program it with
        // the block size, as Linux `sdhci_set_block_info` does.
        let blksz = ((SDMA_BOUNDARY_ARG & 0x7) << 12) | 512;
        if let Err(e) = self.cmd_inner(idx, arg, RESP_48, true, tm, blksz, blocks as u16) {
            self.dma_failed_fallback_pio();
            return Err(e);
        }
        let mut sdma_next = bounce_addr;
        let wait = self.wait_transfer_complete(if mode == DmaMode::Sdma {
            Some(&mut sdma_next)
        } else {
            None
        });
        match wait {
            Ok(()) => {
                self.dma_complete_chunk(
                    len,
                    match io {
                        ChunkIo::Read(out) => Some(out),
                        ChunkIo::Write(_) => None,
                    },
                );
                Ok(())
            }
            Err(e) => {
                self.dma_failed_fallback_pio();
                Err(e)
            }
        }
    }

    /// One multi-block chunk (2..=CHUNK_BLOCKS blocks): DMA when an
    /// engine is admitted, PIO otherwise. A failed DMA chunk resets
    /// the data lines, latches PIO, and retries once via PIO — the
    /// card error underneath (if any) then surfaces from the PIO
    /// attempt instead of the DMA machinery.
    fn transfer_chunk(
        &self,
        lba: u32,
        blocks: usize,
        io: ChunkIo<'_>,
        ccs: bool,
    ) -> Result<(), SdhciError> {
        if self.dma.lock().is_some() {
            match self.transfer_dma_chunk(lba, blocks, io, ccs) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // DMA failed and latched PIO (or the command
                    // itself failed before any data moved): retry
                    // once via PIO so a DMA-engine fault does not
                    // fail an otherwise servable transfer. A card
                    // error fails identically on the retry.
                    if self.dma.lock().is_some() {
                        return Err(e);
                    }
                    return self.transfer_pio_chunk(lba, blocks, io, ccs);
                }
            }
        }
        self.transfer_pio_chunk(lba, blocks, io, ccs)
    }

    /// Read `out.len() / 512` blocks starting at `lba` (CMD18
    /// multi-block chunks, CMD17 for a trailing single block).
    /// `lba` is the block number for SDHC cards; for SDSC cards
    /// (`ccs=0`) it is pre-multiplied by 512 per chunk, as in
    /// `read_block`.
    pub fn read_blocks(&self, lba: u32, out: &mut [u8]) -> Result<(), SdhciError> {
        if out.is_empty() || out.len() % 512 != 0 {
            return Err(SdhciError::BadLength);
        }
        let n_blocks = out.len() / 512;
        let ccs = self.card.lock().ok_or(SdhciError::NoCard)?.ccs;
        let mut done = 0usize;
        while done < n_blocks {
            let chunk = (n_blocks - done).min(CHUNK_BLOCKS);
            let chunk_lba = lba.checked_add(done as u32).ok_or(SdhciError::BadLength)?;
            let range = done * 512..(done + chunk) * 512;
            if chunk == 1 {
                let mut block = [0u8; 512];
                self.read_block(chunk_lba, &mut block)?;
                out[range].copy_from_slice(&block);
            } else {
                self.transfer_chunk(chunk_lba, chunk, ChunkIo::Read(&mut out[range]), ccs)?;
            }
            done += chunk;
        }
        Ok(())
    }

    /// Write `data.len() / 512` blocks starting at `lba` (CMD25
    /// multi-block chunks, CMD24 for a trailing single block).
    pub fn write_blocks(&self, lba: u32, data: &[u8]) -> Result<(), SdhciError> {
        if data.is_empty() || data.len() % 512 != 0 {
            return Err(SdhciError::BadLength);
        }
        let n_blocks = data.len() / 512;
        let ccs = self.card.lock().ok_or(SdhciError::NoCard)?.ccs;
        let mut done = 0usize;
        while done < n_blocks {
            let chunk = (n_blocks - done).min(CHUNK_BLOCKS);
            let chunk_lba = lba.checked_add(done as u32).ok_or(SdhciError::BadLength)?;
            let range = done * 512..(done + chunk) * 512;
            if chunk == 1 {
                let mut block = [0u8; 512];
                block.copy_from_slice(&data[range.clone()]);
                self.write_block(chunk_lba, &block)?;
            } else {
                self.transfer_chunk(chunk_lba, chunk, ChunkIo::Write(&data[range]), ccs)?;
            }
            done += chunk;
        }
        Ok(())
    }

    /// Read a single 512-byte block via PIO. `lba` is the block
    /// number for SDHC cards; for SDSC cards (`ccs=0`) it's
    /// pre-multiplied by 512 to produce a byte address.
    pub fn read_block(&self, lba: u32, out: &mut [u8; 512]) -> Result<(), SdhciError> {
        let card = self.card.lock().ok_or(SdhciError::NoCard)?;
        let arg = if card.ccs { lba } else { lba * 512 };

        // CMD17 (READ_SINGLE_BLOCK) with data-direction read.
        let tm = TM_DATA_DIR_READ;
        let _ = self.cmd(17, arg, RESP_48, true, tm, 512, 1)?;

        // Wait for buffer-read-ready, then drain 512 / 4 = 128
        // u32 words from the buffer port. responsive_spin_until keeps
        // the FB cursor / serial drain alive on a slow controller.
        // 1 s budget covers the worst plausible read latency.
        let done = narf_scheduler::responsive_spin_until(
            || self.io.read16(REG_NORMAL_INT_STS) & (NIS_BUFFER_READ_READY | NIS_ERROR) != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        let nis = self.io.read16(REG_NORMAL_INT_STS);
        if nis & NIS_ERROR != 0 {
            let eis = self.io.read16(REG_ERROR_INT_STS);
            return Err(SdhciError::DeviceError(eis));
        }
        self.io.write16(REG_NORMAL_INT_STS, NIS_BUFFER_READ_READY);
        for i in 0..128usize {
            let w = self.io.read32(REG_BUFFER_PORT);
            let bytes = w.to_le_bytes();
            out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        // Wait for transfer-complete. 1 s wall-clock budget.
        let done = narf_scheduler::responsive_spin_until(
            || self.io.read16(REG_NORMAL_INT_STS) & NIS_TRANSFER_COMPLETE != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        self.io.write16(REG_NORMAL_INT_STS, NIS_TRANSFER_COMPLETE);
        Ok(())
    }

    /// Write a single 512-byte block via PIO. Mirror of `read_block`.
    pub fn write_block(&self, lba: u32, data: &[u8; 512]) -> Result<(), SdhciError> {
        let card = self.card.lock().ok_or(SdhciError::NoCard)?;
        let arg = if card.ccs { lba } else { lba * 512 };
        let _ = self.cmd(24, arg, RESP_48, true, /*tm*/ 0, 512, 1)?;

        // Wait for buffer-write-ready, push 128 u32 words.
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay
        // alive. 1 s wall-clock budget.
        let done = narf_scheduler::responsive_spin_until(
            || self.io.read16(REG_NORMAL_INT_STS) & (NIS_BUFFER_WRITE_READY | NIS_ERROR) != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        let nis = self.io.read16(REG_NORMAL_INT_STS);
        if nis & NIS_ERROR != 0 {
            let eis = self.io.read16(REG_ERROR_INT_STS);
            return Err(SdhciError::DeviceError(eis));
        }
        self.io.write16(REG_NORMAL_INT_STS, NIS_BUFFER_WRITE_READY);
        for i in 0..128usize {
            let bytes: [u8; 4] = [
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ];
            let w = u32::from_le_bytes(bytes);
            self.io.write32(REG_BUFFER_PORT, w);
        }
        let done = narf_scheduler::responsive_spin_until(
            || self.io.read16(REG_NORMAL_INT_STS) & NIS_TRANSFER_COMPLETE != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        self.io.write16(REG_NORMAL_INT_STS, NIS_TRANSFER_COMPLETE);
        Ok(())
    }
}

// ── Driver-match registration ────────────────────────────────────────

/// Slot for the live host controller produced by `probe`. Held only
/// long enough to read the installed device's address
/// (`probed_sdhci`) — NEVER across a transfer, whose polled SD
/// commands run 100 ms–1 s deadlines per block. See
/// [`crate::req_gate`] for the livelock this prevents.
static CONTROLLER: IrqSafeSpinLock<Option<Sdhci>> = IrqSafeSpinLock::new(None);

/// The probed host controller, WITHOUT holding `CONTROLLER` for the
/// caller's use of it.
///
/// `CONTROLLER` is taken only long enough to read the address of the
/// installed device, then released, so a multi-block PIO loop runs
/// with interrupts enabled.
///
/// # Why the reference stays valid
///
/// The `Option` is written exactly once: [`probe`] returns early when
/// a controller is already installed, and nothing ever stores `None`
/// back. The `Sdhci` therefore is never moved, replaced or dropped
/// after its single install, so a shared reference to it stays valid
/// for the rest of the boot. `smoke_sdhci_device_address_is_stable`
/// pins that invariant, because it is the kind of assumption a later
/// "support hot-unplug" change would silently invalidate. There is no
/// `&mut` path into the slot at all — every `Sdhci` method takes
/// `&self` (card state lives behind its own inner lock).
fn probed_sdhci() -> Option<&'static Sdhci> {
    let ptr: *const Sdhci = {
        let g = CONTROLLER.lock();
        match g.as_ref() {
            Some(d) => d as *const Sdhci,
            None => return None,
        }
    };
    // SAFETY: install-once, never-moved, never-dropped — see above.
    Some(unsafe { &*ptr })
}

/// The installed controller's address, or `None` before probe. Test
/// hook for the install-once invariant `probed_sdhci` relies on.
#[doc(hidden)]
pub fn dbg_device_addr() -> Option<usize> {
    CONTROLLER
        .lock()
        .as_ref()
        .map(|d| d as *const Sdhci as usize)
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    use core::fmt::Write as _;
    // Class match catches all of class 0x08 (system peripheral).
    // Filter to subclass 0x05 (SD host controller) here. A
    // non-SDHCI system peripheral is a decline, not a failure:
    // this driver never engaged the device, so the dispatcher
    // may fall through to another candidate (bus spec §9.3).
    let subclass = ((device.id.class >> 8) & 0xFF) as u8;
    if subclass != SDHCI_PCI_SUBCLASS {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over BAR0.
    let dev = match unsafe { Sdhci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(e) => {
            // Surface the specific bring-up failure mode so a real-HW
            // "BadDevice" trace tells us whether it's BAR map / reset
            // timeout / etc. instead of the generic bus log line.
            let _ = writeln!(
                narf_console::Writer,
                "  sdhci: {:04x}:{:04x} bring_up failed: {:?}",
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    *CONTROLLER.lock() = Some(dev);

    if let Some(card) = CONTROLLER.lock().as_ref().unwrap().card.lock().as_ref() {
        publish_card(card.capacity_blocks);
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("sd0"),
        kind: narf_drivers::BoundKind::Block,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Block.default_domain(),
    });
    // #839: join the device_pm suspend/resume fan-out (idempotent
    // on the name, so a re-probe re-registers the same handlers).
    pm::register();
    Ok(())
}

/// Publish an identified card as the `sdhci0` block device and scan
/// it for partitions, registering `sdhci0p<N>` children — the same
/// publication contract MSC / AHCI / NVMe follow (#834). A card
/// whose CSD decoded to zero blocks is never published; a card with
/// no readable partition table (blank card, superfloppy layout)
/// just keeps its bare whole-disk entry, so the scan is
/// best-effort and its error is dropped, exactly as at the other
/// call sites.
fn publish_card(capacity_blocks: u64) {
    if capacity_blocks == 0 {
        return;
    }
    let block_dev = alloc::sync::Arc::new(SdhciBlockDevice { capacity_blocks });
    narf_block::registry::register_block_device("sdhci0", block_dev.clone());
    let _ = narf_block::partition::scan_and_register_partitions(block_dev, "sdhci0");
}

struct SdhciBlockDevice {
    capacity_blocks: u64,
}

impl narf_block::registry::BlockDeviceSync for SdhciBlockDevice {
    // NOTE (#841): flush/capabilities/write_fua are intentionally
    // the trait defaults. This driver binds SD memory cards only,
    // and the SD protocol exposes no host-visible volatile-write-
    // cache flush: a write is durable once the card leaves
    // programming state, so the no-op flush is the write-through
    // treatment, not a vacuous advertisement — and default
    // write_fua (write + flush) is sound for the same reason.
    fn lba_size(&self) -> u32 {
        512
    }

    fn capacity(&self) -> u64 {
        self.capacity_blocks
    }

    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::registry::BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let needed = n_blocks as usize * 512;
        if out.len() < needed {
            return Err(narf_block::registry::BlockIoError::BufferTooSmall);
        }
        let max_lba = self.capacity_blocks.saturating_sub(n_blocks as u64);
        if lba > max_lba {
            return Err(narf_block::registry::BlockIoError::OutOfRange);
        }
        // `read_blocks` takes the block LBA and translates the
        // start address once per chunk (block address for SDHC,
        // byte address for SDSC); the card auto-increments within
        // a CMD18, so the whole request is one multi-block call
        // chain, not a command per block.
        let start =
            u32::try_from(lba).map_err(|_| narf_block::registry::BlockIoError::OutOfRange)?;
        with_controller(|ctrl| {
            ctrl.read_blocks(start, &mut out[..needed])
                .map_err(|_| narf_block::registry::BlockIoError::DriverError)?;
            Ok(())
        })
        .unwrap_or(Err(narf_block::registry::BlockIoError::DriverError))
    }

    fn write(
        &self,
        lba: u64,
        n_blocks: u16,
        data: &[u8],
    ) -> Result<(), narf_block::registry::BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let needed = n_blocks as usize * 512;
        if data.len() < needed {
            return Err(narf_block::registry::BlockIoError::BufferTooSmall);
        }
        let max_lba = self.capacity_blocks.saturating_sub(n_blocks as u64);
        if lba > max_lba {
            return Err(narf_block::registry::BlockIoError::OutOfRange);
        }

        let start =
            u32::try_from(lba).map_err(|_| narf_block::registry::BlockIoError::OutOfRange)?;
        with_controller(|ctrl| {
            ctrl.write_blocks(start, &data[..needed])
                .map_err(|_| narf_block::registry::BlockIoError::DriverError)?;
            Ok(())
        })
        .unwrap_or(Err(narf_block::registry::BlockIoError::DriverError))
    }
}

pub fn register_pci_driver() {
    // Class-match backstop covers every SDHCI implementation. The
    // probe itself filters to subclass 0x05 (SD host controller)
    // since MatchKind::Class only checks the base class byte.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "sdhci",
        kind: narf_bus::MatchKind::Class {
            class: SDHCI_PCI_CLASS,
            mask: 0xFF,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed controller, if any.
///
/// Holds the device's request gate — not the `CONTROLLER` spinlock —
/// for the duration of `f`, so a multi-block PIO closure waits out
/// its 100 ms–1 s per-command polls with interrupts enabled while
/// still excluding every other user of the controller. Callers must
/// not re-enter `with_controller` from inside `f` — the gate is not
/// reentrant.
pub fn with_controller<R>(f: impl FnOnce(&Sdhci) -> R) -> Option<R> {
    let ctrl = probed_sdhci()?;
    // #839: a system-suspended controller refuses new I/O; a transfer
    // already past this check holds the request gate the suspend
    // handler waits on, and completes before the suspend proceeds.
    if pm::is_system_suspended() {
        return None;
    }
    let _gate = ReqGate::acquire(&ctrl.req_gate);
    // #839: re-check under the gate — the idle monitor may have gated
    // the controller after the suspend check; ungate (re-init +
    // re-identify + verify) before touching the hardware, and fail
    // the I/O if the ungate fails.
    if pm::is_runtime_gated() {
        pm::resume_locked(ctrl).ok()?;
    }
    let r = f(ctrl);
    pm::mark_busy();
    Some(r)
}

/// Test hook: install a controller built on a fixture
/// [`SdhciTransport`], with no card identified yet — the fixture
/// then runs the real `identify_sequence` against its modelled
/// register file. Mirrors the RTSX driver's `__install_for_test`.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __install_for_test(transport: alloc::sync::Arc<dyn SdhciTransport>) {
    *CONTROLLER.lock() = Some(Sdhci {
        io: transport,
        card: IrqSafeSpinLock::new(None),
        path: IrqSafeSpinLock::new(DataPath::identification()),
        dma: IrqSafeSpinLock::new(None),
        req_gate: AtomicBool::new(false),
    });
}

/// Test hook: drop the installed controller (fixture teardown), so
/// a fixture's controller never leaks into later suites.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}

#[cfg(any(test, feature = "kernel-test"))]
mod fixture_tests;

/// Device power management: system suspend/resume + runtime idle
/// gating (#839). The logic lives here so the data-path / init
/// regions of this file stay untouched by the PM lane.
pub mod pm;
