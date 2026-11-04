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
        if paged_addr(0x0a5d, 0x10) != Ok(0xa5d0) {
            return TestResult::Fail("7.60 emulation must land at OCP 0xa5d0");
        }
        if paged_addr(0x0a6d, 0x12) != Ok(0xa6d4) {
            return TestResult::Fail("7.62 emulation must land at OCP 0xa6d4");
        }
        // Page 0 selects the standard base with no rebase — the
        // BMCR restart reads/writes OCP 0xA400.
        if paged_addr(0, MII_BMCR_REG) != Ok(OCP_STD_PHY_BASE as u32) {
            return TestResult::Fail("BMCR must land at OCP_STD_PHY_BASE");
        }
        // A register below the paged window is rejected, not
        // silently wrapped.
        if paged_addr(0x0a5d, 0x0f) != Err(PhyError::BadPagedRegister(0x0f)) {
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
    kernel_test_in!("drivers/net/realtek-phy-access", smoke_phy_bmcr_restart_value);
}
