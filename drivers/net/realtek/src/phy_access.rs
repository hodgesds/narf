//! RTL8127 PHY access — OCP register window, firmware interpreter,
//! and the PHY-config table walker.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 `drivers/net/ethernet/realtek/` (GPL-2.0; NARF is
//! GPL-2.0-or-later so adaptation is permitted):
//!
//! - `r8169_main.c` — `r8168_phy_ocp_read` / `_write`,
//!   `r8168_mac_ocp_read` / `_write`, `r8168g_mdio_read` / `_write`,
//!   `mac_mcu_read` / `_write`, `r8169_mdio_read_reg_c45` /
//!   `_write_c45`, `r8169_apply_firmware`.
//! - `r8169_firmware.c` — the container format, `rtl_fw_format_ok`,
//!   `rtl_fw_data_ok`, `rtl_fw_write_firmware`.
//!
//! ## There is no MDIO bus here
//!
//! This family has no conventional MDIO controller. Every PHY access
//! lands in one 32-bit window, `GPHY_OCP` at BAR2 offset 0xB8: write
//! `OCPAR_FLAG | (addr << 15) | data` to write, write `addr << 15`
//! and poll for the flag to come back to read. Everything above that
//! is address arithmetic:
//!
//! - **Paged C22 access** (`phy_modify_paged(page, reg, …)`) is
//!   `ocp_base = page << 4`, then `ocp_base + (reg - 0x10) * 2`. The
//!   `- 0x10` applies only when a page is selected; page 0 means
//!   `OCP_STD_PHY_BASE` with the register *not* rebased, which is the
//!   one asymmetry in the scheme.
//! - **MMD VEND2 access** (`rtl8125_phy_param`) does not go through
//!   the MMD indirection registers at all. Linux's
//!   `r8169_mdio_write_reg_c45` routes `MDIO_MMD_VEND2` straight to
//!   `r8168_phy_ocp_write(regnum)`, so `0xb87c` / `0xb87e` are raw
//!   OCP addresses.
//!
//! So [`PhyAccess`] is the whole "MDIO layer": one accessor plus the
//! address translation, and every entry in
//! [`crate::rtl8127::PHY_CONFIG_TABLE`] becomes one or two OCP transactions.
//!
//! ## Firmware is optional
//!
//! `r8169_apply_firmware` runs the blob only `if (tp->rtl_fw)` and
//! the PHY-config table is applied either way. This mirrors that: a
//! missing `rtl_nic/rtl8127a-1.fw` is reported and skipped, not
//! fatal. The blob is a PHY-MCU patch; without it the table still
//! programs the registers it names.

use alloc::vec::Vec;

use narf_bus::MmioRegion;

use crate::phy::{Phy, PhyLink};

// ── PHY paged-register access types ─────────────────────────────────
// Shared by the whole family (RTL8125 / RTL8126 / RTL8127 /
// RTL8168G): "page" is the value written to MII register 0x1F.
// Previously defined separately in `rtl8127.rs` and `rtl8126.rs`
// (the 8126 copy used a `u8` register, which cannot hold the
// MMD register the `Rtl8125Param` form modifies); one definition
// now serves every driver.

/// One entry in a static PHY configuration table.
///
/// The `page` / `reg` pair is interpreted per [`PhyConfigKind`]:
///
/// | kind | `page` | `reg` |
/// |---|---|---|
/// | `ModifyPaged` / `WritePaged` | MDIO page written to reg 0x1F | register in that page |
/// | `R8168gParam` | `parm`, written to reg 0x13 of page 0x0a43 | always 0x14, the register modified |
/// | `Rtl8125Param` | `parm`, written to MMD VEND2 reg 0xb87c | always 0xb87e, the register modified |
///
/// `reg` is a `u16` because the MMD register the `Rtl8125Param` form
/// modifies (0xb87e) does not fit a `u8`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PhyConfigEntry {
    /// MDIO page, or the `parm` selector for the `*Param` kinds.
    pub page: u16,
    /// Register within the page, or the fixed register the `*Param`
    /// kinds modify.
    pub reg: u16,
    /// Bits to clear (ANDed inverted with current value).
    pub mask: u16,
    /// Bits to set (ORed after masking).
    pub val: u16,
    /// Entry kind.
    pub kind: PhyConfigKind,
}

/// Which PHY-access flavour this entry uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhyConfigKind {
    /// `phy_modify_paged(page, reg, mask, val)`.
    ModifyPaged,
    /// `phy_write_paged(page, reg, val)` — `ModifyPaged` with
    /// `mask = 0xFFFF`.
    WritePaged,
    /// `r8168g_phy_param(parm, mask, val)` — page 0x0a43, reg 0x13 =
    /// parm, modify reg 0x14.
    R8168gParam,
    /// `rtl8125_phy_param(parm, mask, val)` — MMD VEND2 registers
    /// 0xb87c / 0xb87e.
    Rtl8125Param,
}

// ── OCP windows (BAR2) ──────────────────────────────────────────────

/// `OCPDR` — MAC on-chip-peripheral data register.
pub const REG_OCPDR: u64 = 0xB0;
/// `GPHY_OCP` — PHY on-chip-peripheral window.
pub const REG_GPHY_OCP: u64 = 0xB8;
/// `OCPAR_FLAG` — set on a write; the device clears it when the
/// transaction retires, and sets it when a read's data is ready.
pub const OCPAR_FLAG: u32 = 0x8000_0000;
/// Address shift within the OCP window.
pub const OCP_ADDR_SHIFT: u32 = 15;
/// `OCP_STD_PHY_BASE` — the base selected by writing page 0 to MII
/// register 0x1F.
pub const OCP_STD_PHY_BASE: u16 = 0xA400;

/// MII register that selects the page.
pub const MII_PAGE_SELECT: u16 = 0x1F;
/// First register of the paged vendor window. Paged access rebases
/// registers by this much; see [`PhyAccess::mdio_write`].
pub const MII_PAGED_BASE: u16 = 0x10;

/// Linux polls the OCP completion 10 times at 25 µs. The budget here
/// is rounded up for spin granularity.
pub const OCP_TIMEOUT_MS: u64 = 2;

/// Longest single `PHY_DELAY_MS` this interpreter will honour.
///
/// The opcode's operand is 16 bits, so a corrupt blob could ask for
/// 65 seconds and hang boot in a spin loop. Real Realtek firmware
/// delays are in the low tens of milliseconds.
pub const MAX_FIRMWARE_DELAY_MS: u64 = 500;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhyError {
    /// OCP address was odd or did not fit 16 bits. `GPHY_OCP` packs
    /// the address at bit 15, so bit 0 and anything above bit 16
    /// would corrupt the transaction — Linux's
    /// `rtl_ocp_reg_failure` rejects the same shape.
    BadOcpAddress(u32),
    /// The device never retired an OCP transaction.
    OcpTimeout,
    /// The device never raised the PHYAR completion flag for a
    /// Clause-22 MDIO read.
    PhyarTimeout,
    /// Firmware container was too short, misaligned, or failed its
    /// checksum.
    BadFirmwareFormat,
    /// Firmware contained an opcode this interpreter does not know,
    /// or a jump that leaves the program.
    BadFirmwareOpcode(u32),
    /// A paged access named a register below the paged window.
    BadPagedRegister(u16),
    /// An EEE advertisement write did not read back the value
    /// written — the PHY did not accept the advertisement.
    EeeAdvertMismatch,
}

/// `rtl_ocp_reg_failure` — an OCP address must be even and fit 16
/// bits.
pub const fn ocp_addr_ok(addr: u32) -> bool {
    addr & 0xFFFF_0001 == 0
}

// ── PHY / MAC OCP access ────────────────────────────────────────────

/// A PHY access session over one controller's register window.
///
/// Carries `ocp_base`, the page latched by the last
/// `mdio_write(0x1F, page)`. Linux keeps it on `tp` for the same
/// reason: the firmware interpreter's `PHY_MDIO_CHG` opcode switches
/// between the PHY and MAC-MCU accessors mid-program, and both read
/// the same latched base.
#[derive(Debug)]
pub struct PhyAccess<'a> {
    mmio: &'a MmioRegion,
    ocp_base: u16,
}

impl<'a> PhyAccess<'a> {
    /// Start a session. The base begins at `OCP_STD_PHY_BASE`, which
    /// is where a page-0 select leaves it.
    pub fn new(mmio: &'a MmioRegion) -> Self {
        Self {
            mmio,
            ocp_base: OCP_STD_PHY_BASE,
        }
    }

    /// Current `ocp_base`.
    pub fn ocp_base(&self) -> u16 {
        self.ocp_base
    }

    /// `r8168_phy_ocp_write`.
    pub fn phy_ocp_write(&self, addr: u32, data: u16) -> Result<(), PhyError> {
        if !ocp_addr_ok(addr) {
            return Err(PhyError::BadOcpAddress(addr));
        }
        // SAFETY: `self.mmio` is the controller's mapped BAR2 and
        // `REG_GPHY_OCP` is inside it — the caller checked the BAR
        // length at bring-up.
        unsafe {
            self.mmio.write32(
                REG_GPHY_OCP,
                OCPAR_FLAG | (addr << OCP_ADDR_SHIFT) | data as u32,
            )
        };
        // The device clears the flag when the write retires.
        let done = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: as above.
                let v = unsafe { self.mmio.read32(REG_GPHY_OCP) };
                v & OCPAR_FLAG == 0
            },
            narf_time::Deadline::after_ms(OCP_TIMEOUT_MS),
        );
        if !done {
            return Err(PhyError::OcpTimeout);
        }
        Ok(())
    }

    /// `r8168_phy_ocp_read`.
    pub fn phy_ocp_read(&self, addr: u32) -> Result<u16, PhyError> {
        if !ocp_addr_ok(addr) {
            return Err(PhyError::BadOcpAddress(addr));
        }
        // SAFETY: as above.
        unsafe { self.mmio.write32(REG_GPHY_OCP, addr << OCP_ADDR_SHIFT) };
        // For a read the device *sets* the flag when data is ready —
        // the opposite polarity from a write.
        let ready = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: as above.
                let v = unsafe { self.mmio.read32(REG_GPHY_OCP) };
                v & OCPAR_FLAG != 0
            },
            narf_time::Deadline::after_ms(OCP_TIMEOUT_MS),
        );
        if !ready {
            return Err(PhyError::OcpTimeout);
        }
        // SAFETY: as above.
        Ok((unsafe { self.mmio.read32(REG_GPHY_OCP) } & 0xFFFF) as u16)
    }

    /// Read-modify-write one OCP register.
    pub fn phy_ocp_modify(&self, addr: u32, mask: u16, set: u16) -> Result<(), PhyError> {
        let cur = self.phy_ocp_read(addr)?;
        self.phy_ocp_write(addr, (cur & !mask) | set)
    }

    /// `__r8168_mac_ocp_write`. Unlike the PHY window this has no
    /// completion flag to wait on.
    pub fn mac_ocp_write(&self, addr: u32, data: u16) -> Result<(), PhyError> {
        if !ocp_addr_ok(addr) {
            return Err(PhyError::BadOcpAddress(addr));
        }
        // SAFETY: as above; `REG_OCPDR` is in BAR2.
        unsafe {
            self.mmio.write32(
                REG_OCPDR,
                OCPAR_FLAG | (addr << OCP_ADDR_SHIFT) | data as u32,
            )
        };
        Ok(())
    }

    /// `__r8168_mac_ocp_read`.
    pub fn mac_ocp_read(&self, addr: u32) -> Result<u16, PhyError> {
        if !ocp_addr_ok(addr) {
            return Err(PhyError::BadOcpAddress(addr));
        }
        // SAFETY: as above.
        unsafe { self.mmio.write32(REG_OCPDR, addr << OCP_ADDR_SHIFT) };
        // SAFETY: as above.
        Ok((unsafe { self.mmio.read32(REG_OCPDR) } & 0xFFFF) as u16)
    }

    /// OCP address for a `(page, register)` MDIO pair.
    ///
    /// Writing page 0 selects `OCP_STD_PHY_BASE` and leaves the
    /// register un-rebased; any other page rebases by
    /// [`MII_PAGED_BASE`]. Getting that asymmetry wrong shifts every
    /// paged access by 0x20 bytes.
    pub const fn paged_addr(page: u16, reg: u16) -> Result<u32, PhyError> {
        if page == 0 {
            return Ok(OCP_STD_PHY_BASE as u32 + reg as u32 * 2);
        }
        if reg < MII_PAGED_BASE {
            return Err(PhyError::BadPagedRegister(reg));
        }
        Ok(((page as u32) << 4) + (reg as u32 - MII_PAGED_BASE as u32) * 2)
    }

    /// `r8168g_mdio_write`.
    pub fn mdio_write(&mut self, reg: u16, val: u16) -> Result<(), PhyError> {
        if reg == MII_PAGE_SELECT {
            self.ocp_base = if val != 0 { val << 4 } else { OCP_STD_PHY_BASE };
            return Ok(());
        }
        let r = if self.ocp_base != OCP_STD_PHY_BASE {
            if reg < MII_PAGED_BASE {
                return Err(PhyError::BadPagedRegister(reg));
            }
            reg - MII_PAGED_BASE
        } else {
            reg
        };
        self.phy_ocp_write(self.ocp_base as u32 + r as u32 * 2, val)
    }

    /// `r8168g_mdio_read`.
    pub fn mdio_read(&self, reg: u16) -> Result<u16, PhyError> {
        if reg == MII_PAGE_SELECT {
            return Ok(if self.ocp_base == OCP_STD_PHY_BASE {
                0
            } else {
                self.ocp_base >> 4
            });
        }
        let r = if self.ocp_base != OCP_STD_PHY_BASE {
            if reg < MII_PAGED_BASE {
                return Err(PhyError::BadPagedRegister(reg));
            }
            reg - MII_PAGED_BASE
        } else {
            reg
        };
        self.phy_ocp_read(self.ocp_base as u32 + r as u32 * 2)
    }

    // ── PHYAR Clause-22 MDIO window ──────────────────────────────
    //
    // The OCP window above is NOT the only route to the PHY. The
    // controller also exposes a Clause-22 MDIO window at BAR2 offset
    // 0x60 (`PHYAR`, Linux `r8169_main.c`): write
    // `FLAG | (reg << 16) | data` to write, write `reg << 16` and
    // poll for the flag to come back to read. Linux's `phy_*` ops
    // all travel this window; the OCP window is an alternate route
    // to the same register file that only expresses registers at or
    // above 0x10 in a non-zero page. The 8168 tables need this
    // window for page-5 registers 0x05/0x06 (the `d_param` helpers)
    // and for the Clause-45 MMD write in the 8168e/8111e table.
    //
    // Unlike the OCP `mdio_write` tracker, PHYAR page state lives
    // in the PHY's own page register: writing 0x1F here really
    // selects the page for subsequent reads/writes, so callers
    // that select a page must restore it, exactly as Linux's
    // `phy_select_page` / `phy_restore_page` pair does.

    /// `PHYAR` — Clause-22 MDIO window.
    pub const PHYAR_REG: u64 = 0x60;
    /// `PHYAR_FLAG` — set on a write; the device sets it when a
    /// read's data is ready.
    pub const PHYAR_FLAG: u32 = 0x8000_0000;
    /// Register field mask within the PHYAR command word.
    pub const PHYAR_REG_MASK: u16 = 0x1F;
    /// Register field shift within the PHYAR command word.
    pub const PHYAR_REG_SHIFT: u32 = 16;
    /// Budget for the PHYAR read-completion poll. Linux waits
    /// 25 × 20 µs; the budget here is rounded up for spin
    /// granularity, as with [`OCP_TIMEOUT_MS`].
    pub const PHYAR_TIMEOUT_MS: u64 = 2;
    /// Delay required after a PHYAR read completes, before the next
    /// command is sent (Linux `r8169_mdio_read_reg`).
    pub const PHYAR_POST_READ_DELAY_US: u64 = 20;

    /// Pure packing for a PHYAR write command. Kept separate from
    /// [`Self::phyar_write`] so tests can pin the wire format
    /// without MMIO.
    pub const fn phyar_write_cmd(reg: u16, val: u16) -> u32 {
        Self::PHYAR_FLAG
            | (((reg & Self::PHYAR_REG_MASK) as u32) << Self::PHYAR_REG_SHIFT)
            | val as u32
    }

    /// Pure packing for a PHYAR read command.
    pub const fn phyar_read_cmd(reg: u16) -> u32 {
        ((reg & Self::PHYAR_REG_MASK) as u32) << Self::PHYAR_REG_SHIFT
    }

    /// `r8169_mdio_write_reg` — one Clause-22 write. Fire-and-
    /// forget, as in Linux: no completion poll on the write path.
    pub fn phyar_write(&self, reg: u16, val: u16) -> Result<(), PhyError> {
        // SAFETY: `self.mmio` is the controller's mapped BAR2 and
        // `PHYAR_REG` is inside it — the caller checked the BAR
        // length at bring-up.
        unsafe {
            self.mmio
                .write32(Self::PHYAR_REG, Self::phyar_write_cmd(reg, val))
        };
        Ok(())
    }

    /// `r8169_mdio_read_reg` — one Clause-22 read: command, poll
    /// for the completion flag, then the mandated post-read delay
    /// before the next command.
    pub fn phyar_read(&self, reg: u16) -> Result<u16, PhyError> {
        // SAFETY: as above.
        unsafe {
            self.mmio
                .write32(Self::PHYAR_REG, Self::phyar_read_cmd(reg))
        };
        let ready = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: as above.
                let v = unsafe { self.mmio.read32(Self::PHYAR_REG) };
                v & Self::PHYAR_FLAG != 0
            },
            narf_time::Deadline::after_ms(Self::PHYAR_TIMEOUT_MS),
        );
        if !ready {
            return Err(PhyError::PhyarTimeout);
        }
        // SAFETY: as above.
        let data = (unsafe { self.mmio.read32(Self::PHYAR_REG) } & 0xFFFF) as u16;
        // The 20 µs post-read delay, expressed as a spin to the
        // deadline: the condition never becomes true, so this
        // simply waits out the interval.
        let _ = narf_scheduler::responsive_spin_until(
            || false,
            narf_time::Deadline::after_us(Self::PHYAR_POST_READ_DELAY_US),
        );
        Ok(data)
    }

    /// Read-modify-write one Clause-22 register:
    /// `(current & !mask) | set`, matching Linux `phy_modify`.
    pub fn phyar_modify(&self, reg: u16, mask: u16, set: u16) -> Result<(), PhyError> {
        let cur = self.phyar_read(reg)?;
        self.phyar_write(reg, (cur & !mask) | set)
    }

    /// `mac_mcu_write`. Note the address arithmetic differs from the
    /// PHY path: no rebase and no doubling.
    pub fn mac_mcu_write(&mut self, reg: u16, val: u16) -> Result<(), PhyError> {
        if reg == MII_PAGE_SELECT {
            self.ocp_base = val << 4;
            return Ok(());
        }
        self.mac_ocp_write(self.ocp_base as u32 + reg as u32, val)
    }

    /// `mac_mcu_read`.
    pub fn mac_mcu_read(&self, reg: u16) -> Result<u16, PhyError> {
        self.mac_ocp_read(self.ocp_base as u32 + reg as u32)
    }
}

// ── Firmware container ──────────────────────────────────────────────

/// `struct fw_info` is 45 bytes: `magic:u32`, `version[32]`,
/// `fw_start:le32`, `fw_len:le32`, `chksum:u8`.
pub const FW_INFO_BYTES: usize = 45;
/// Offset of `fw_start` within `fw_info`.
pub const FW_INFO_START_OFF: usize = 36;
/// Offset of `fw_len`.
pub const FW_INFO_LEN_OFF: usize = 40;
/// One opcode is a little-endian dword.
pub const FW_OPCODE_BYTES: usize = 4;

/// Parse a `rtl_nic/*.fw` container into its opcode stream.
///
/// Two layouts, distinguished by the first dword —
/// `rtl_fw_format_ok`:
///
/// - **Non-zero magic**: the file is a bare opcode array. Its length
///   must be a whole number of opcodes.
/// - **Zero magic**: a 45-byte `fw_info` header precedes the opcodes.
///   Every byte of the *whole file* must sum to zero mod 256, and
///   `fw_start` / `fw_len` bound the opcode slice.
pub fn parse_firmware(bytes: &[u8]) -> Result<Vec<u32>, PhyError> {
    if bytes.len() < FW_OPCODE_BYTES {
        return Err(PhyError::BadFirmwareFormat);
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    let (start, count) = if magic == 0 {
        if bytes.len() < FW_INFO_BYTES {
            return Err(PhyError::BadFirmwareFormat);
        }
        // The checksum covers the entire file, header included, and
        // the trailing `chksum` byte is chosen to make it come out
        // zero.
        let sum = bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        if sum != 0 {
            return Err(PhyError::BadFirmwareFormat);
        }
        let start = u32::from_le_bytes([
            bytes[FW_INFO_START_OFF],
            bytes[FW_INFO_START_OFF + 1],
            bytes[FW_INFO_START_OFF + 2],
            bytes[FW_INFO_START_OFF + 3],
        ]) as usize;
        let len = u32::from_le_bytes([
            bytes[FW_INFO_LEN_OFF],
            bytes[FW_INFO_LEN_OFF + 1],
            bytes[FW_INFO_LEN_OFF + 2],
            bytes[FW_INFO_LEN_OFF + 3],
        ]) as usize;
        if start > bytes.len() {
            return Err(PhyError::BadFirmwareFormat);
        }
        if len > (bytes.len() - start) / FW_OPCODE_BYTES {
            return Err(PhyError::BadFirmwareFormat);
        }
        (start, len)
    } else {
        if bytes.len() % FW_OPCODE_BYTES != 0 {
            return Err(PhyError::BadFirmwareFormat);
        }
        (0, bytes.len() / FW_OPCODE_BYTES)
    };

    let mut code = Vec::with_capacity(count);
    for i in 0..count {
        let o = start + i * FW_OPCODE_BYTES;
        code.push(u32::from_le_bytes([
            bytes[o],
            bytes[o + 1],
            bytes[o + 2],
            bytes[o + 3],
        ]));
    }
    Ok(code)
}

// Opcodes — `enum rtl_fw_opcode`.
/// Read a PHY register into the scratch value.
pub const PHY_READ: u32 = 0x0;
/// OR an immediate into the scratch value.
pub const PHY_DATA_OR: u32 = 0x1;
/// AND an immediate into the scratch value.
pub const PHY_DATA_AND: u32 = 0x2;
/// Jump backwards.
pub const PHY_BJMPN: u32 = 0x3;
/// Switch between the PHY and MAC-MCU accessors.
pub const PHY_MDIO_CHG: u32 = 0x4;
/// Reset the read counter.
pub const PHY_CLEAR_READCOUNT: u32 = 0x7;
/// Write an immediate to a register.
pub const PHY_WRITE: u32 = 0x8;
/// Skip the next opcode if the read count matches.
pub const PHY_READCOUNT_EQ_SKIP: u32 = 0x9;
/// Skip N opcodes if the scratch value matches.
pub const PHY_COMP_EQ_SKIPN: u32 = 0xA;
/// Skip N opcodes if the scratch value does not match.
pub const PHY_COMP_NEQ_SKIPN: u32 = 0xB;
/// Write the scratch value to a register.
pub const PHY_WRITE_PREVIOUS: u32 = 0xC;
/// Skip N opcodes unconditionally.
pub const PHY_SKIPN: u32 = 0xD;
/// Delay.
pub const PHY_DELAY_MS: u32 = 0xE;

/// Decode an opcode word into `(opcode, regno, data)`.
pub const fn decode_action(action: u32) -> (u32, u16, u16) {
    (
        action >> 28,
        ((action & 0x0FFF_0000) >> 16) as u16,
        (action & 0x0000_FFFF) as u16,
    )
}

/// `rtl_fw_data_ok` — reject unknown opcodes and any jump that would
/// leave the program, before a single register is touched.
pub fn validate_firmware(code: &[u32]) -> Result<(), PhyError> {
    for (index, action) in code.iter().copied().enumerate() {
        let (opcode, regno, data) = decode_action(action);
        match opcode {
            PHY_READ | PHY_DATA_OR | PHY_DATA_AND | PHY_CLEAR_READCOUNT | PHY_WRITE
            | PHY_WRITE_PREVIOUS | PHY_DELAY_MS => {}
            PHY_MDIO_CHG => {
                if data > 1 {
                    return Err(PhyError::BadFirmwareOpcode(action));
                }
            }
            PHY_BJMPN => {
                if regno as usize > index {
                    return Err(PhyError::BadFirmwareOpcode(action));
                }
            }
            PHY_READCOUNT_EQ_SKIP => {
                if index + 2 >= code.len() {
                    return Err(PhyError::BadFirmwareOpcode(action));
                }
            }
            PHY_COMP_EQ_SKIPN | PHY_COMP_NEQ_SKIPN | PHY_SKIPN => {
                if index + 1 + regno as usize >= code.len() {
                    return Err(PhyError::BadFirmwareOpcode(action));
                }
            }
            _ => return Err(PhyError::BadFirmwareOpcode(action)),
        }
    }
    Ok(())
}

/// Which accessor the interpreter is currently writing through.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum FwTarget {
    Phy,
    MacMcu,
}

impl PhyAccess<'_> {
    /// `rtl_fw_write_firmware` — run a validated opcode stream.
    ///
    /// Call [`validate_firmware`] first; this assumes the bounds it
    /// checks, which is what keeps the jump arithmetic from leaving
    /// the slice.
    pub fn run_firmware(&mut self, code: &[u32]) -> Result<(), PhyError> {
        let mut predata: u16 = 0;
        let mut count: u32 = 0;
        let mut target = FwTarget::Phy;
        let mut i: usize = 0;

        while i < code.len() {
            let (opcode, regno, data) = decode_action(code[i]);
            // C mutates `index` inside the loop and then runs the
            // `index++` of the `for`. Computing the successor up
            // front says the same thing without the two-step.
            let mut next = i + 1;

            match opcode {
                PHY_READ => {
                    predata = match target {
                        FwTarget::Phy => self.mdio_read(regno)?,
                        FwTarget::MacMcu => self.mac_mcu_read(regno)?,
                    };
                    count += 1;
                }
                PHY_DATA_OR => predata |= data,
                PHY_DATA_AND => predata &= data,
                PHY_BJMPN => next = i - regno as usize,
                PHY_MDIO_CHG => {
                    target = if data != 0 {
                        FwTarget::MacMcu
                    } else {
                        FwTarget::Phy
                    };
                }
                PHY_CLEAR_READCOUNT => count = 0,
                PHY_WRITE => match target {
                    FwTarget::Phy => self.mdio_write(regno, data)?,
                    FwTarget::MacMcu => self.mac_mcu_write(regno, data)?,
                },
                PHY_READCOUNT_EQ_SKIP => {
                    if count == data as u32 {
                        next = i + 2;
                    }
                }
                PHY_COMP_EQ_SKIPN => {
                    if predata == data {
                        next = i + 1 + regno as usize;
                    }
                }
                PHY_COMP_NEQ_SKIPN => {
                    if predata != data {
                        next = i + 1 + regno as usize;
                    }
                }
                PHY_WRITE_PREVIOUS => match target {
                    FwTarget::Phy => self.mdio_write(regno, predata)?,
                    FwTarget::MacMcu => self.mac_mcu_write(regno, predata)?,
                },
                PHY_SKIPN => next = i + 1 + regno as usize,
                PHY_DELAY_MS => {
                    let ms = (data as u64).min(MAX_FIRMWARE_DELAY_MS);
                    let _ = narf_scheduler::responsive_spin_until(
                        || false,
                        narf_time::Deadline::after_ms(ms),
                    );
                }
                _ => return Err(PhyError::BadFirmwareOpcode(code[i])),
            }
            i = next;
        }

        // `r8169_apply_firmware`: "at least one firmware doesn't
        // reset tp->ocp_base", so the caller's next paged access
        // would land wherever the blob left it.
        self.ocp_base = OCP_STD_PHY_BASE;
        Ok(())
    }

    /// Apply one [`PhyConfigEntry`].
    pub fn apply_entry(&mut self, e: PhyConfigEntry) -> Result<(), PhyError> {
        match e.kind {
            PhyConfigKind::ModifyPaged => {
                let addr = Self::paged_addr(e.page, e.reg)?;
                self.phy_ocp_modify(addr, e.mask, e.val)
            }
            PhyConfigKind::WritePaged => {
                let addr = Self::paged_addr(e.page, e.reg)?;
                self.phy_ocp_write(addr, e.val)
            }
            PhyConfigKind::R8168gParam => {
                // `r8168g_phy_param`: select page 0x0a43, write the
                // parameter selector to reg 0x13, modify reg 0x14.
                let sel = Self::paged_addr(R8168G_PARAM_PAGE, R8168G_PARAM_SEL_REG)?;
                self.phy_ocp_write(sel, e.page)?;
                let addr = Self::paged_addr(R8168G_PARAM_PAGE, e.reg)?;
                self.phy_ocp_modify(addr, e.mask, e.val)
            }
            PhyConfigKind::Rtl8125Param => {
                // `rtl8125_phy_param`: MMD VEND2 0xb87c selects, 0xb87e
                // is the data. Both are raw OCP addresses — see the
                // module docs on why there is no MMD indirection.
                self.phy_ocp_write(RTL8125_PARAM_SEL_ADDR, e.page)?;
                self.phy_ocp_modify(e.reg as u32, e.mask, e.val)
            }
        }
    }

    /// Apply a whole PHY-config table in order.
    pub fn apply_config_table(&mut self, table: &[PhyConfigEntry]) -> Result<(), PhyError> {
        for e in table.iter().copied() {
            self.apply_entry(e)?;
        }
        Ok(())
    }
}

/// Page `r8168g_phy_param` selects.
pub const R8168G_PARAM_PAGE: u16 = 0x0A43;
/// Register the parameter selector is written to.
pub const R8168G_PARAM_SEL_REG: u16 = 0x13;
/// MMD VEND2 register `rtl8125_phy_param` writes its selector to.
pub const RTL8125_PARAM_SEL_ADDR: u32 = 0xB87C;
/// MMD VEND2 register `rtl8125_phy_param` modifies.
pub const RTL8125_PARAM_DATA_ADDR: u32 = 0xB87E;

// ── EEE advertisement (emulated AN MMD registers) ─────────────────
// The RTL8125/RTL8126 internal PHYs expose no MMD registers, so
// Linux's realtek PHY driver emulates the standard AN MMD EEE
// registers on vendor-specific paged registers and the generic
// EEE path drives them. The same mapping, through this crate's
// paged OCP window:

/// Page of the emulated AN MMD EEE advertisement register
/// (7.60): `rtlgen_read_mmd` / `rtlgen_write_mmd` select page
/// 0xa5d, register 0x10.
pub const EEE_ADV_PAGE: u16 = 0x0A5D;
/// Register of the emulated AN MMD EEE advertisement (7.60).
pub const EEE_ADV_REG: u16 = 0x10;
/// Page of the emulated AN MMD EEE advertisement 2 register
/// (7.62) for the NBase-T PHY: `rtl8125_read_mmd` /
/// `rtl8125_write_mmd` select page 0xa6d, register 0x12.
/// (The sibling 7.63 link-partner ability 2 lives at page 0xa6d,
/// register 0x10, and 7.61 at page 0xa5d, register 0x11 — both
/// read-only here, so no writer names them.)
pub const EEE_ADV2_PAGE: u16 = 0x0A6D;
/// Register of the emulated AN MMD EEE advertisement 2 (7.62).
pub const EEE_ADV2_REG: u16 = 0x12;
/// Clause 22 control register (page 0, register 0).
pub const MII_BMCR_REG: u16 = 0;
/// BMCR bit 12: auto-negotiation enable (IEEE 802.3 Clause 22).
pub const BMCR_ANENABLE: u16 = 0x1000;
/// BMCR bit 9: restart auto-negotiation. Self-clearing; only
/// takes effect while auto-negotiation is enabled.
pub const BMCR_ANRESTART: u16 = 0x0200;

/// BMCR value that restarts auto-negotiation, or `None` when
/// auto-negotiation is disabled (bit 12 clear): setting the
/// restart bit alone would be a no-op there, and forcing
/// auto-negotiation on would override a forced-speed link.
/// Every other BMCR bit passes through untouched.
pub const fn bmcr_restart_value(bmcr: u16) -> Option<u16> {
    if bmcr & BMCR_ANENABLE == 0 {
        None
    } else {
        Some(bmcr | BMCR_ANRESTART)
    }
}

impl PhyAccess<'_> {
    /// Program the emulated AN MMD EEE advertisement registers
    /// for `caps`: read each register, write it only when it
    /// differs from the target word, and read back every written
    /// register to confirm it stuck.
    ///
    /// Returns whether any register changed. The caller restarts
    /// auto-negotiation only then — mirroring phylib's
    /// `genphy_config_eee_advert` changed-check — so re-running
    /// over already-programmed registers is a silent no-op, and
    /// an EEE-off board (all-false caps over reset-default
    /// registers) sees no writes at all.
    pub fn advertise_eee(&self, caps: crate::features::EeeCaps) -> Result<bool, PhyError> {
        let adv = crate::features::eee_adv(caps);
        let adv2 = crate::features::eee_adv2(caps);
        let mut changed = false;
        for (page, reg, target) in [
            (EEE_ADV_PAGE, EEE_ADV_REG, adv),
            (EEE_ADV2_PAGE, EEE_ADV2_REG, adv2),
        ] {
            let addr = Self::paged_addr(page, reg)?;
            if self.phy_ocp_read(addr)? != target {
                self.phy_ocp_write(addr, target)?;
                if self.phy_ocp_read(addr)? != target {
                    return Err(PhyError::EeeAdvertMismatch);
                }
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Restart auto-negotiation so a changed EEE advertisement is
    /// carried in the next exchange. Reads BMCR through the
    /// page-0 window and restarts only when auto-negotiation is
    /// enabled; a forced-speed link keeps its configuration and
    /// picks the advertisement up at its next autonegotiation
    /// instead. Returns whether autonegotiation was restarted.
    pub fn restart_aneg(&self) -> Result<bool, PhyError> {
        let addr = Self::paged_addr(0, MII_BMCR_REG)?;
        let bmcr = self.phy_ocp_read(addr)?;
        match bmcr_restart_value(bmcr) {
            Some(next) => {
                self.phy_ocp_write(addr, next)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

// ── Shared PHY trait (`narf_drivers_net_core::phy::Phy`) ─────────────
// The family adopts the shared trait (issue #790) over this
// accessor. The OCP window encodes the page in the *address*
// (see the module docs), so the paged accessors are stateless
// address arithmetic — they never touch the latched `ocp_base`
// the firmware interpreter / config-table paths use, and never
// touch the PHY's own page register. `read_reg` / `write_reg`
// are page-0 by construction for the same reason. The MMD
// accessors use the trait's Clause-22 indirection default:
// the PHY's 0x0D/0x0E registers are the standard MMD control /
// data pair, and Linux's `r8169_mdio_read_reg_c45` /
// `_write_c45` prove the silicon implements the sequence.
// The emulated-AN MMD mapping (7.60 → page 0xa5d reg 0x10,
// 7.62 → page 0xa6d reg 0x12, …) is NOT overridden here: the
// EEE advertisement path (`advertise_eee`) already programs
// those paged registers directly, and the #794 EEE surface
// decides the override. This lane only proves the transport.

/// Page of the `rtlgen` negotiated-speed register (Linux
/// `drivers/net/phy/realtek.c`, `rtlgen_read_status`, v6.12:
/// `phy_read_paged(phydev, 0xa43, 0x12)`).
pub const RTLGEN_SPEED_PAGE: u16 = 0x0A43;
/// Register of the `rtlgen` negotiated-speed word.
pub const RTLGEN_SPEED_REG: u16 = 0x12;
/// Mask selecting the speed field (Linux `RTLGEN_SPEED_MASK`
/// 0x0630).
pub const RTLGEN_SPEED_MASK: u16 = 0x0630;

/// Decode a `rtlgen` speed word (page 0xa43, register 0x12)
/// into a negotiated rate. Table is Linux `rtlgen_decode_speed`
/// verbatim: 0x0000 → 10, 0x0010 → 100, 0x0020 → 1000,
/// 0x0200 → 10000, 0x0210 → 2500, 0x0220 → 5000. Bits outside
/// the mask are ignored; a masked value with no table entry
/// (e.g. 0x0400) decodes to `None` — the caller keeps its
/// in-band rate rather than inventing one.
pub const fn rtlgen_decode_speed(val: u16) -> Option<u32> {
    match val & RTLGEN_SPEED_MASK {
        0x0000 => Some(10),
        0x0010 => Some(100),
        0x0020 => Some(1000),
        0x0200 => Some(10000),
        0x0210 => Some(2500),
        0x0220 => Some(5000),
        _ => None,
    }
}

/// Apply a raw `rtlgen` speed word to a Clause-22 [`PhyLink`]
/// (pure, fixture-tested): a decodable word replaces the
/// Clause-22 speed — the PHY's own negotiated-rate register
/// outranks the LPA/GBSR resolution, exactly as Linux's
/// `rtlgen_read_status` lets `rtlgen_decode_speed` overwrite
/// `genphy_read_status`'s result. An undecodable word leaves
/// the Clause-22 result untouched. Duplex always stays with
/// the Clause-22 resolution: the speed word carries none. A
/// down link stays down whatever the word says: the speed word
/// is a negotiated-rate register, and a down link has no
/// negotiated rate to report.
pub fn rtlgen_apply_speed(c22: PhyLink, speed_val: u16) -> PhyLink {
    if !c22.link_up {
        return c22;
    }
    match rtlgen_decode_speed(speed_val) {
        Some(speed) => PhyLink {
            speed_mbps: Some(speed),
            ..c22
        },
        None => c22,
    }
}

impl Phy for PhyAccess<'_> {
    type Error = PhyError;

    /// Stateless page-0 read: `OCP_STD_PHY_BASE + reg * 2`.
    /// Never consults the latched `ocp_base`, so a config-table
    /// or firmware pass mid-program cannot divert this read.
    fn read_reg(&self, reg: u8) -> Result<u16, PhyError> {
        self.phy_ocp_read(OCP_STD_PHY_BASE as u32 + u32::from(reg) * 2)
    }

    /// Stateless page-0 write.
    fn write_reg(&self, reg: u8, val: u16) -> Result<(), PhyError> {
        self.phy_ocp_write(OCP_STD_PHY_BASE as u32 + u32::from(reg) * 2, val)
    }

    /// Stateless paged read: `paged_addr(page, reg)` is the
    /// whole operation — no page-register write, no restore.
    fn read_paged(&self, page: u16, reg: u8) -> Result<u16, PhyError> {
        let addr = Self::paged_addr(page, u16::from(reg))?;
        self.phy_ocp_read(addr)
    }

    /// Stateless paged write.
    fn write_paged(&self, page: u16, reg: u8, val: u16) -> Result<(), PhyError> {
        let addr = Self::paged_addr(page, u16::from(reg))?;
        self.phy_ocp_write(addr, val)
    }

    /// Linux `rtlgen_read_status`: the standard Clause-22
    /// decode, then — link up only — the 0xa43/0x12 speed word
    /// overrides the rate. The `rtl822x_read_status` extra (LP
    /// 10GBT advertisement at page 0xa5d reg 0x13) is not
    /// needed here: it feeds the partner advertisement, not
    /// the local negotiated rate.
    fn read_status(&self) -> Result<PhyLink, PhyError> {
        let c22 = crate::phy::read_status_c22(self)?;
        if !c22.link_up {
            return Ok(c22);
        }
        let val = self.read_paged(RTLGEN_SPEED_PAGE, RTLGEN_SPEED_REG as u8)?;
        Ok(rtlgen_apply_speed(c22, val))
    }
}

// ── Fixtures ────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::*;

    fn smoke_phy_eee_paged_addrs() -> TestResult {
        // The page/register constants must equal the mapping
        // Linux's realtek PHY driver emulates — the test pins
        // literals, not the constants, so a wrong constant fails
        // here instead of agreeing with itself.
        if EEE_ADV_PAGE != 0x0a5d || EEE_ADV_REG != 0x10 {
            return TestResult::Fail("EEE ADV mapping is not page 0xa5d reg 0x10");
        }
        if EEE_ADV2_PAGE != 0x0a6d || EEE_ADV2_REG != 0x12 {
            return TestResult::Fail("EEE ADV2 mapping is not page 0xa6d reg 0x12");
        }
        // Paged address arithmetic: page << 4, register rebased
        // by 0x10 and doubled (two bytes per register).
        if PhyAccess::paged_addr(0x0a5d, 0x10) != Ok(0xa5d0) {
            return TestResult::Fail("7.60 emulation must land at OCP 0xa5d0");
        }
        if PhyAccess::paged_addr(0x0a6d, 0x12) != Ok(0xa6d4) {
            return TestResult::Fail("7.62 emulation must land at OCP 0xa6d4");
        }
        // Page 0 selects the standard base with no rebase — the
        // BMCR restart reads/writes OCP 0xA400.
        if PhyAccess::paged_addr(0, MII_BMCR_REG) != Ok(OCP_STD_PHY_BASE as u32) {
            return TestResult::Fail("BMCR must land at OCP_STD_PHY_BASE");
        }
        // A register below the paged window is rejected, not
        // silently wrapped.
        if PhyAccess::paged_addr(0x0a5d, 0x0f) != Err(PhyError::BadPagedRegister(0x0f)) {
            return TestResult::Fail("paged_addr admitted a register below 0x10");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/realtek-phy-access", smoke_phy_eee_paged_addrs);

    fn smoke_phy_bmcr_restart_value() -> TestResult {
        // Auto-negotiation enabled: restart bit set, every other
        // bit preserved.
        if bmcr_restart_value(0x1000) != Some(0x1200) {
            return TestResult::Fail("BMCR restart must set bit 9 on AN-enabled BMCR");
        }
        if bmcr_restart_value(0x1140) != Some(0x1340) {
            return TestResult::Fail("BMCR restart must preserve unrelated bits");
        }
        if bmcr_restart_value(0x1200) != Some(0x1200) {
            return TestResult::Fail("BMCR restart must be idempotent");
        }
        // Auto-negotiation disabled: no restart, even when the
        // restart bit itself is already set — forcing AN on
        // would override a forced-speed link.
        if bmcr_restart_value(0x0000).is_some() || bmcr_restart_value(0x0200).is_some() {
            return TestResult::Fail("BMCR restart must refuse AN-disabled BMCR");
        }
        if BMCR_ANENABLE != 0x1000 || BMCR_ANRESTART != 0x0200 {
            return TestResult::Fail("BMCR bits are not 12 (AN enable) / 9 (restart)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-phy-access",
        smoke_phy_bmcr_restart_value
    );

    // ── Shared PHY trait fixtures (issue #790) ──────────────────
    // The fake below is built from the spec itself (IEEE 802.3
    // Clause 22 register map + Clause-45-over-22 indirection
    // sequence + Linux `rtlgen_decode_speed` table), never from
    // this crate's constants: every expected value is a literal
    // taken from the standard / Linux source, so the trait and
    // the fake cannot agree on a wrong constant and pass.

    /// A Clause-22 PHY register file in memory, implementing the
    /// shared [`Phy`] trait. Models page 0 (the standard
    /// registers) and page 0xa43 (the `rtlgen` speed word), the
    /// page register at 0x1F, and the Clause-45 MMD indirection
    /// state machine on 0x0D/0x0E for MMD 7. It does NOT model
    /// the BMSR latch-low quirk (both reads return the stored
    /// word): the double-read discipline lives in the trait's
    /// code, and the fake's job is the decode, not the silicon
    /// timing.
    struct FakeMdio {
        /// Page-0 registers, indexed by register number.
        page0: core::cell::Cell<[u16; 32]>,
        /// Page 0xa43 register 0x12 (`rtlgen` speed word).
        speed_word: core::cell::Cell<u16>,
        /// Currently-selected page (register 0x1F).
        page: core::cell::Cell<u16>,
        /// MMD 7 register file (regs 0..=63).
        mmd7: core::cell::Cell<[u16; 64]>,
        /// MMD device selected by the last 0x0D write.
        mmd_dev: core::cell::Cell<u16>,
        /// MMD register selected by the last 0x0E write in the
        /// address phase.
        mmd_reg: core::cell::Cell<u16>,
        /// `true` once a 0x0D write carried the 0x4000 data-phase bit.
        mmd_data_phase: core::cell::Cell<bool>,
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum FakeError {
        UnmodeledPage(u16),
    }

    impl FakeMdio {
        /// Page-0 words: BMSR, ANAR, GBCR, LPA, GBSR, BMCR as the
        /// test needs them; everything else zero.
        fn new(bmsr: u16, anar: u16, gbcr: u16, lpa: u16, gbsr: u16, bmcr: u16) -> Self {
            let mut page0 = [0u16; 32];
            page0[0x00] = bmcr;
            page0[0x01] = bmsr;
            page0[0x02] = 0x001c;
            page0[0x03] = 0xc914;
            page0[0x04] = anar;
            page0[0x05] = lpa;
            page0[0x09] = gbcr;
            page0[0x0a] = gbsr;
            FakeMdio {
                page0: core::cell::Cell::new(page0),
                speed_word: core::cell::Cell::new(0),
                page: core::cell::Cell::new(0),
                mmd7: core::cell::Cell::new([0u16; 64]),
                mmd_dev: core::cell::Cell::new(0),
                mmd_reg: core::cell::Cell::new(0),
                mmd_data_phase: core::cell::Cell::new(false),
            }
        }
    }

    impl crate::phy::Phy for FakeMdio {
        type Error = FakeError;

        fn read_reg(&self, reg: u8) -> Result<u16, FakeError> {
            let page = self.page.get();
            if page == 0 {
                if reg == 0x0e && self.mmd_data_phase.get() {
                    // Data-phase read: the selected MMD register.
                    if self.mmd_dev.get() == 7 {
                        return Ok(self.mmd7.get()[usize::from(self.mmd_reg.get()) & 63]);
                    }
                    return Ok(0);
                }
                if reg == 0x0e {
                    return Ok(self.mmd_reg.get());
                }
                return Ok(self.page0.get()[usize::from(reg) & 31]);
            }
            if page == 0x0a43 {
                if reg == 0x12 {
                    return Ok(self.speed_word.get());
                }
                return Ok(0);
            }
            Err(FakeError::UnmodeledPage(page))
        }

        fn write_reg(&self, reg: u8, val: u16) -> Result<(), FakeError> {
            let page = self.page.get();
            if reg == 0x1f {
                self.page.set(val);
                return Ok(());
            }
            if page == 0 {
                if reg == 0x0d {
                    self.mmd_dev.set(val & 0x1f);
                    self.mmd_data_phase.set(val & 0x4000 != 0);
                    return Ok(());
                }
                if reg == 0x0e {
                    if self.mmd_data_phase.get() {
                        if self.mmd_dev.get() == 7 {
                            let mut mmd7 = self.mmd7.get();
                            mmd7[usize::from(self.mmd_reg.get()) & 63] = val;
                            self.mmd7.set(mmd7);
                        }
                    } else {
                        self.mmd_reg.set(val);
                    }
                    return Ok(());
                }
                let mut page0 = self.page0.get();
                page0[usize::from(reg) & 31] = val;
                self.page0.set(page0);
                return Ok(());
            }
            if page == 0x0a43 {
                if reg == 0x12 {
                    self.speed_word.set(val);
                    return Ok(());
                }
                return Ok(());
            }
            Err(FakeError::UnmodeledPage(page))
        }
    }

    fn smoke_phy_rtlgen_decode_speed() -> TestResult {
        // Linux `rtlgen_decode_speed` table, pinned as literals
        // (mask 0x0630 applied first — bits outside the mask
        // must not change the verdict).
        if RTLGEN_SPEED_MASK != 0x0630 {
            return TestResult::Fail("RTLGEN_SPEED_MASK is not 0x0630");
        }
        if RTLGEN_SPEED_PAGE != 0x0a43 || RTLGEN_SPEED_REG != 0x12 {
            return TestResult::Fail("rtlgen speed word is not page 0xa43 reg 0x12");
        }
        for (word, want) in [
            (0x0000u16, Some(10u32)),
            (0x0010, Some(100)),
            (0x0020, Some(1000)),
            (0x0200, Some(10000)),
            (0x0210, Some(2500)),
            (0x0220, Some(5000)),
            (0x0400, None),
            (0x0230, None),
            (0x0630, None),
        ] {
            if rtlgen_decode_speed(word) != want {
                return TestResult::Fail("rtlgen_decode_speed disagrees with the Linux table");
            }
        }
        // Bits outside the mask are ignored: 0x0210 | 0x09c0 is
        // still 2500.
        if rtlgen_decode_speed(0x0210 | 0x09c0) != Some(2500) {
            return TestResult::Fail("rtlgen_decode_speed let out-of-mask bits change the rate");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-phy-access",
        smoke_phy_rtlgen_decode_speed
    );

    fn smoke_phy_rtlgen_apply_speed() -> TestResult {
        use crate::phy::PhyLink;
        use narf_net::iface::LinkDuplex;
        // A decodable word replaces the Clause-22 speed and
        // keeps its duplex; an undecodable word keeps the
        // Clause-22 result whole.
        let c22 = PhyLink::up(Some(1000), Some(LinkDuplex::Full));
        let over = rtlgen_apply_speed(c22, 0x0210);
        if over.speed_mbps != Some(2500) || over.duplex != Some(LinkDuplex::Full) {
            return TestResult::Fail(
                "rtlgen 0x0210 must override the rate to 2500, keeping duplex",
            );
        }
        let kept = rtlgen_apply_speed(c22, 0x0400);
        if kept != c22 {
            return TestResult::Fail("undecodable rtlgen word must keep the Clause-22 result");
        }
        // A down link stays down whatever the word says.
        if rtlgen_apply_speed(PhyLink::DOWN, 0x0210) != PhyLink::DOWN {
            return TestResult::Fail("rtlgen apply must not resurrect a down link");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-phy-access",
        smoke_phy_rtlgen_apply_speed
    );

    fn smoke_phy_trait_c22_read_status() -> TestResult {
        use crate::phy::{phy_id_valid, Phy, PhyLink};
        use narf_net::iface::LinkDuplex;
        // BMSR 0x0024 = link up + autoneg complete; our ANAR
        // advertises all 10/100, GBCR 1000 full; the partner
        // offers 100 full + 1000 full → 1000 full wins.
        let phy = FakeMdio::new(0x0024, 0x01e1, 0x0200, 0x01c1, 0x0800, 0x1000);
        let link = match phy.read_status() {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("trait read_status failed on a healthy fake"),
        };
        if !link.link_up || link.speed_mbps != Some(1000) || link.duplex != Some(LinkDuplex::Full) {
            return TestResult::Fail("trait read_status did not resolve 1000/Full");
        }
        // Partner offers 10 half only → 10 half, even though we
        // advertise faster modes.
        let phy = FakeMdio::new(0x0024, 0x01e1, 0x0200, 0x0020, 0x0000, 0x1000);
        let link = match phy.read_status() {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("trait read_status failed on the 10HD fake"),
        };
        if link.speed_mbps != Some(10) || link.duplex != Some(LinkDuplex::Half) {
            return TestResult::Fail("trait read_status did not resolve 10/Half");
        }
        // Link down: BMSR 0x0000 → DOWN, speed/duplex unknown.
        let phy = FakeMdio::new(0x0000, 0x01e1, 0x0200, 0x01c1, 0x0800, 0x1000);
        let link = match phy.read_status() {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("trait read_status failed on the down fake"),
        };
        if link != PhyLink::DOWN {
            return TestResult::Fail("trait read_status must report DOWN on a down link");
        }
        // Autoneg incomplete (BMSR 0x0004): forced BMCR
        // 0x1140 = AN enable + 1000 + full → 1000/Full.
        let phy = FakeMdio::new(0x0004, 0x01e1, 0x0200, 0x0000, 0x0000, 0x1140);
        let link = match phy.read_status() {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("trait read_status failed on the forced fake"),
        };
        if link.speed_mbps != Some(1000) || link.duplex != Some(LinkDuplex::Full) {
            return TestResult::Fail("trait read_status did not fall back to forced BMCR");
        }
        // PHY identification: the fake carries 0x001cc914
        // (RTL8211DN); an all-ones ID is the no-device signature.
        let phy = FakeMdio::new(0x0024, 0x01e1, 0x0200, 0x01c1, 0x0800, 0x1000);
        match phy.read_phy_id() {
            Ok(0x001c_c914) => {}
            _ => return TestResult::Fail("trait read_phy_id did not compose 0x001cc914"),
        }
        if !phy_id_valid(0x001c_c914) || phy_id_valid(0) || phy_id_valid(0xffff_ffff) {
            return TestResult::Fail("trait phy_id_valid misjudged an ID");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-phy-access",
        smoke_phy_trait_c22_read_status
    );

    fn smoke_phy_trait_paged_and_mmd() -> TestResult {
        use crate::phy::Phy;
        // Paged access: the rtlgen speed word lives at page
        // 0xa43 reg 0x12; the access must restore page 0, so a
        // BMSR read afterwards still sees the page-0 word.
        let phy = FakeMdio::new(0x0024, 0x01e1, 0x0200, 0x01c1, 0x0800, 0x1000);
        phy.speed_word.set(0x0210);
        match phy.read_paged(0x0a43, 0x12) {
            Ok(0x0210) => {}
            _ => return TestResult::Fail("trait read_paged did not return the speed word"),
        }
        match phy.read_reg(0x01) {
            Ok(0x0024) => {}
            _ => return TestResult::Fail("trait read_paged did not restore page 0"),
        }
        // A paged write lands in the same register.
        if phy.write_paged(0x0a43, 0x12, 0x0220).is_err() {
            return TestResult::Fail("trait write_paged failed");
        }
        match phy.read_paged(0x0a43, 0x12) {
            Ok(0x0220) => {}
            _ => return TestResult::Fail("trait write_paged did not stick"),
        }
        // MMD via Clause-22 indirection: write 7.62 = 0x0003,
        // read it back; the fake's 0x0D/0x0E state machine is
        // the IEEE sequence, not this crate's constants.
        if phy.write_mmd(7, 62, 0x0003).is_err() {
            return TestResult::Fail("trait write_mmd failed");
        }
        match phy.read_mmd(7, 62) {
            Ok(0x0003) => {}
            _ => return TestResult::Fail("trait read_mmd did not return the written word"),
        }
        // An unmodeled page is an error, not a silent wrap.
        if phy.read_paged(0x0a44, 0x12).is_ok() {
            return TestResult::Fail("trait read_paged admitted an unmodeled page");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-phy-access",
        smoke_phy_trait_paged_and_mmd
    );

    fn smoke_phy_trait_eee_shared_surface() -> TestResult {
        use crate::phy::{
            eee_mmd_adv_words, eee_modes_from_mmd, eee_status_from, EEE_ADV_100M, EEE_ADV_1G,
            EEE_ADV_2_5G, EEE_MMD_ADV, EEE_MMD_ADV2, EEE_MMD_DEV, EEE_MMD_LP_ADV, EEE_MMD_LP_ADV2,
        };
        use narf_net::nic::EeeStatus;
        // The shared constants are pinned as literals, not read
        // back from the constants: a wrong register number must
        // fail here instead of agreeing with the trait.
        if EEE_MMD_DEV != 7
            || EEE_MMD_ADV != 60
            || EEE_MMD_LP_ADV != 61
            || EEE_MMD_ADV2 != 62
            || EEE_MMD_LP_ADV2 != 63
        {
            return TestResult::Fail("shared EEE MMD device/registers are not 7/60-63");
        }
        if EEE_ADV_100M != 8 || EEE_ADV_1G != 16 || EEE_ADV_2_5G != 32 {
            return TestResult::Fail("shared EEE mode bits are not 8/16/32");
        }
        // Pure decode/encode, pinned as literals (Linux mdio.h
        // bit map: 7/60 bit 1 = 100M, bit 2 = 1G, 7/62 bit 0
        // = 2.5G — the same values e1000/igb/igc already decode).
        if eee_modes_from_mmd(0x0006, 0x0001) != 0x38
            || eee_modes_from_mmd(0x0002, 0x0000) != EEE_ADV_100M
            || eee_modes_from_mmd(0x0000, 0x0000) != 0
        {
            return TestResult::Fail("shared EEE MMD mode decode wrong");
        }
        // Bits outside the three known modes never leak: 10GT
        // (7/60 bit 3) and 5G (7/62 bit 1) plus reserved bits.
        if eee_modes_from_mmd(0xFFF9, 0xFFFE) != 0
            || eee_modes_from_mmd(0x000E, 0x0002) != (EEE_ADV_100M | EEE_ADV_1G)
        {
            return TestResult::Fail("shared EEE decode leaked non-EEE bits");
        }
        if eee_mmd_adv_words(0x38) != (0x0006, 0x0001)
            || eee_mmd_adv_words(EEE_ADV_100M | EEE_ADV_1G) != (0x0006, 0x0000)
            || eee_mmd_adv_words(0) != (0, 0)
        {
            return TestResult::Fail("shared EEE MMD advertisement words wrong");
        }
        // PHY-side status: active is the negotiated
        // intersection; tx_lpi is always false (MAC-side).
        if eee_status_from(0x38, 0x18)
            != (EeeStatus {
                advertised: 0x38,
                partner: 0x18,
                active: true,
                tx_lpi: false,
            })
            || eee_status_from(0x18, 0x20).active
            || eee_status_from(0, 0).active
        {
            return TestResult::Fail("shared EEE status derivation wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-phy-access",
        smoke_phy_trait_eee_shared_surface
    );

    fn smoke_phy_trait_eee_end_to_end() -> TestResult {
        use crate::phy::{Phy, EEE_ADV_100M, EEE_ADV_1G, EEE_ADV_2_5G};
        // Set-then-read round-trip through the trait's MMD
        // transport on the scripted fake: the words on the wire
        // are the spec's, the decode is the shared one.
        let phy = FakeMdio::new(0x0024, 0x01e1, 0x0200, 0x01c1, 0x0800, 0x1000);
        if phy
            .set_eee_advertisement(EEE_ADV_100M | EEE_ADV_1G | EEE_ADV_2_5G)
            .is_err()
        {
            return TestResult::Fail("trait set_eee_advertisement failed");
        }
        match (phy.read_mmd(7, 60), phy.read_mmd(7, 62)) {
            (Ok(0x0006), Ok(0x0001)) => {}
            _ => return TestResult::Fail("trait set_eee_advertisement wrote wrong MMD words"),
        }
        match phy.eee_advertisement() {
            Ok(0x38) => {}
            _ => return TestResult::Fail("trait eee_advertisement did not read back 0x38"),
        }
        // Partner advertises 100M+1G only: status is active on
        // the intersection, tx_lpi false (PHY-side read).
        if phy.write_mmd(7, 61, 0x0006).is_err() || phy.write_mmd(7, 63, 0x0000).is_err() {
            return TestResult::Fail("trait write_mmd failed for the partner words");
        }
        match phy.eee_partner() {
            Ok(0x18) => {}
            _ => return TestResult::Fail("trait eee_partner did not decode 0x18"),
        }
        match phy.eee_status() {
            Ok(s) if s.active && s.advertised == 0x38 && s.partner == 0x18 && !s.tx_lpi => {}
            _ => return TestResult::Fail("trait eee_status wrong for a negotiated link"),
        }
        // Disable: words cleared, status inactive.
        if phy.set_eee_advertisement(0).is_err() {
            return TestResult::Fail("trait set_eee_advertisement(0) failed");
        }
        match phy.eee_advertisement() {
            Ok(0) => {}
            _ => return TestResult::Fail("trait eee_advertisement nonzero after disable"),
        }
        match phy.eee_status() {
            Ok(s) if !s.active => {}
            _ => return TestResult::Fail("trait eee_status active after disable"),
        }
        // Disjoint partner: advertised 100M only, partner 1G
        // only → not active, even though both advertise EEE.
        if phy.set_eee_advertisement(EEE_ADV_100M).is_err() || phy.write_mmd(7, 61, 0x0004).is_err()
        {
            return TestResult::Fail("trait EEE setup failed for the disjoint case");
        }
        match phy.eee_status() {
            Ok(s) if !s.active && s.advertised == EEE_ADV_100M && s.partner == EEE_ADV_1G => {}
            _ => return TestResult::Fail("trait eee_status active on disjoint advertisements"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-phy-access",
        smoke_phy_trait_eee_end_to_end
    );

    fn smoke_phy_shared_eee_matches_realtek_words() -> TestResult {
        use crate::features::{eee_adv, eee_adv2, eee_lpi_caps};
        use crate::phy::eee_modes_from_mmd;
        // Cross-party check: the Realtek caps-based encode
        // (`features::eee_adv` / `eee_adv2`, grounded in Linux
        // `rtl_set_eee_txidle_timer` / `rtlgen` caps) and the
        // shared decode must agree on the modes the shared
        // surface knows. The 5G (ver 70/80) and 10G (ver 80)
        // words are deliberately outside the shared decode —
        // they must be ignored, not misdecoded.
        for (ver, want_adv, want_adv2, want_modes) in [
            (61u32, 0x0006u16, 0x0000u16, 0x18u32),
            (63, 0x0006, 0x0001, 0x38),
            (70, 0x0006, 0x0003, 0x38),
            (80, 0x000e, 0x0003, 0x38),
        ] {
            let caps = eee_lpi_caps(ver);
            if eee_adv(caps) != want_adv || eee_adv2(caps) != want_adv2 {
                return TestResult::Fail("Realtek EEE words disagree with the pinned table");
            }
            if eee_modes_from_mmd(want_adv, want_adv2) != want_modes {
                return TestResult::Fail("shared EEE decode disagrees with the Realtek words");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/realtek-phy-access",
        smoke_phy_shared_eee_matches_realtek_words
    );

    fn smoke_phy_merge_sample() -> TestResult {
        use crate::phy::{merge_phy_sample, PhyLink};
        use crate::publish::LinkSample;
        use narf_net::iface::LinkDuplex;
        // In-band lower bound 1000 + PHY 2500/Full → 2500/Full.
        let base = LinkSample::up(Some(1000), Some(LinkDuplex::Full));
        let merged = merge_phy_sample(base, PhyLink::up(Some(2500), Some(LinkDuplex::Full)));
        if merged.speed_mbps != Some(2500) || merged.duplex != Some(LinkDuplex::Full) {
            return TestResult::Fail("merge must let a proven PHY rate win");
        }
        // PHY proves carrier but not the rate → the in-band
        // bound survives.
        let merged = merge_phy_sample(base, PhyLink::up(None, Some(LinkDuplex::Full)));
        if merged.speed_mbps != Some(1000) {
            return TestResult::Fail("merge must keep the in-band bound on an unproven PHY rate");
        }
        // PHY down always wins.
        if merge_phy_sample(base, PhyLink::DOWN) != LinkSample::DOWN {
            return TestResult::Fail("merge must report DOWN on a down PHY link");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/realtek-phy-access", smoke_phy_merge_sample);
}
