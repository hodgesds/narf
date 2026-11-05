//! RTL8168 / RTL8111-family PHY init tables for the r8169 driver.
//!
//! The r8169 bring-up decodes the MAC version from TxConfig's XID
//! field but programs no PHY registers today; this module closes
//! that gap for every 8168-lineage revision the driver binds
//! (VER 17–52 in Linux's dispatch, minus the revisions whose config
//! is NULL). Each revision gets the sequence Linux's
//! `r8169_phy_config.c` runs for it, expressed as an ordered list
//! of [`PhyStep`]s plus, where Linux itself branches on hardware
//! state, a small amount of code ([`configure_phy_8168`] handles
//! the efuse branch, the conditional firmware load, and the two
//! read-modify branches).
//!
//! ## Grounding — read before reusing a value
//!
//! No public RTL8168 datasheet with these tables could be found;
//! every value below is grounded in Linux's `r8169_phy_config.c`
//! (local tree `linux2` @ cbbddb6) and re-expressed here as data
//! in NARF's own step model — never copied as code. The second
//! source for the *mechanisms* (not the values) is the public
//! register documentation: the PHYAR Clause-22 window and the OCP
//! paged-address arithmetic are described in
//! [`crate::phy_access`], and the single Clause-45 write (MMD 7,
//! register 60 = EEE Advertisement, IEEE 802.3az) is confirmed by
//! public PHY register maps (Microchip AN6475/AN4286, TI
//! DP83826/DP83825 datasheets: MMD 7, 0x3C = EEE Advertisement).
//! Tables that exist only in Linux are marked as such in the
//! per-table comments; a future datasheet find should re-verify
//! them against silicon.
//!
//! ## Two windows onto the same register file
//!
//! Linux's `phy_*` ops all travel the PHYAR Clause-22 window
//! (BAR2 0x60), where the page is PHY state selected by writing
//! register 0x1F. NARF's OCP window (BAR2 0xB8) reaches the *same*
//! registers by absolute `(page, reg)` address — but only for
//! registers at or above 0x10 in a non-zero page (page 0 takes any
//! register). So each Linux op becomes:
//!
//! - an OCP step ([`PhyStep::Ocp`]) when its `(page, reg)` is
//!   OCP-expressible, or
//! - a PHYAR step ([`PhyStep::Write`] / [`PhyStep::Modify`] /
//!   [`PhyStep::PagedWrite`] / [`PhyStep::PagedModify`]) when it
//!   is not — page-5 registers 0x05/0x06, and low registers in a
//!   non-zero page.
//!
//! Page-select writes (`phy_write(0x1F, X)`) are emitted as
//! [`PhyStep::Select`] steps so the PHYAR page register always
//! holds the page the following PHYAR steps assume; OCP steps
//! ignore it. The executor tracks the page in software, starting
//! from an explicit page-0 select, so every function starts and
//! ends with the page register at 0 — the same invariant Linux's
//! sequences maintain (each ends with a select back to page 0,
//! directly or through a restore).
//!
//! ## Firmware
//!
//! Revisions that load firmware do so through the same registry
//! mechanism as the 8125 driver: the blob name comes from the
//! chip's XID (Linux's chip table), a missing blob is logged and
//! skipped, and a failed load is logged and skipped — the table
//! still programs the registers it names. Blobs are deployment
//! data, not in the repo.

use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_bus::MmioRegion;

use crate::phy_access::{PhyAccess, PhyConfigEntry, PhyConfigKind, PhyError};

// ── Step model ────────────────────────────────────────────────────

/// One PHY programming step, in source order. OCP steps and PHYAR
/// steps may interleave freely: both windows address the same
/// register file, and the order of steps is the order of
/// transactions on the wire.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhyStep {
    /// One OCP transaction: a paged write/modify, or a
    /// `r8168g_phy_param` (page 0x0a43, reg 0x13 = parm, modify
    /// reg 0x14 — already an OCP form in [`crate::phy_access`]).
    Ocp(PhyConfigEntry),
    /// Write `0x1F = page` through PHYAR: selects the page for
    /// subsequent PHYAR steps.
    Select(u16),
    /// PHYAR write to `reg` in the currently selected page.
    Write { reg: u16, val: u16 },
    /// PHYAR read-modify-write in the currently selected page:
    /// `(current & !mask) | val`.
    Modify { reg: u16, mask: u16, val: u16 },
    /// PHYAR select-`page`, write, restore previous page
    /// (Linux `phy_write_paged` for a low register).
    PagedWrite { page: u16, reg: u16, val: u16 },
    /// PHYAR select-`page`, modify, restore previous page
    /// (Linux `phy_modify_paged` for a low register).
    PagedModify {
        page: u16,
        reg: u16,
        mask: u16,
        val: u16,
    },
    /// `r8168d_phy_param(parm, mask, val)`: select page 5, write
    /// reg 0x05 = parm, modify reg 0x06, restore previous page.
    DParam { parm: u16, mask: u16, val: u16 },
    /// `r8168d_modify_extpage(ext, reg, mask, val)`: select page
    /// 7, write reg 0x1E = ext, modify reg, restore previous page.
    ExtPage {
        ext: u16,
        reg: u16,
        mask: u16,
        val: u16,
    },
    /// `phy_write_mmd(AN, EEE_ADV, 0)`: Clause-45 write clearing
    /// the MMD 7 EEE advertisement register, via the Clause-22
    /// MMD access protocol (0x0D = devad, 0x0E = regnum, 0x0D =
    /// 0x4000 | devad, 0x0E = data). Only the 8168e/8111e table
    /// uses it, where the tracked page is 0.
    MmdAnEeeAdvClear,
    /// `r8169_apply_firmware`: load this chip's blob by XID, or
    /// log-and-continue when the registry has no blob for it.
    Firmware,
}

/// OCP paged write: `phy_write_paged(page, reg, val)`.
const fn wp(page: u16, reg: u16, val: u16) -> PhyStep {
    PhyStep::Ocp(PhyConfigEntry {
        page,
        reg,
        mask: 0xFFFF,
        val,
        kind: PhyConfigKind::WritePaged,
    })
}

/// OCP paged modify: `phy_modify_paged(page, reg, mask, val)`.
const fn mp(page: u16, reg: u16, mask: u16, val: u16) -> PhyStep {
    PhyStep::Ocp(PhyConfigEntry {
        page,
        reg,
        mask,
        val,
        kind: PhyConfigKind::ModifyPaged,
    })
}

/// OCP `r8168g_phy_param(parm, mask, val)`.
const fn gp(parm: u16, mask: u16, val: u16) -> PhyStep {
    PhyStep::Ocp(PhyConfigEntry {
        page: parm,
        reg: 0x14,
        mask,
        val,
        kind: PhyConfigKind::R8168gParam,
    })
}

/// PHYAR page select: `phy_write(0x1F, page)`.
const fn sel(page: u16) -> PhyStep {
    PhyStep::Select(page)
}

/// PHYAR write in the currently selected page.
const fn wr(reg: u16, val: u16) -> PhyStep {
    PhyStep::Write { reg, val }
}

/// PHYAR modify in the currently selected page.
const fn md(reg: u16, mask: u16, val: u16) -> PhyStep {
    PhyStep::Modify { reg, mask, val }
}

/// PHYAR paged write for a low register.
const fn pwr(page: u16, reg: u16, val: u16) -> PhyStep {
    PhyStep::PagedWrite { page, reg, val }
}

/// PHYAR paged modify for a low register.
const fn pmd(page: u16, reg: u16, mask: u16, val: u16) -> PhyStep {
    PhyStep::PagedModify {
        page,
        reg,
        mask,
        val,
    }
}

/// `r8168d_phy_param`.
const fn dp(parm: u16, mask: u16, val: u16) -> PhyStep {
    PhyStep::DParam { parm, mask, val }
}

/// `r8168d_modify_extpage`.
const fn ep(ext: u16, reg: u16, mask: u16, val: u16) -> PhyStep {
    PhyStep::ExtPage {
        ext,
        reg,
        mask,
        val,
    }
}

// ── Executor ──────────────────────────────────────────────────────

/// Runs [`PhyStep`] lists against one controller, tracking the
/// PHYAR page register in software. The tracker starts at 0 and
/// [`configure_phy_8168`] selects page 0 first, so the tracker's
/// value always equals the hardware page register: OCP steps
/// never touch it, and every select goes through [`Self::select`]
/// (directly, or via the save/restore helpers).
struct Seq<'a> {
    access: PhyAccess<'a>,
    page: u16,
}

impl<'a> Seq<'a> {
    fn new(mmio: &'a MmioRegion) -> Self {
        Self {
            access: PhyAccess::new(mmio),
            page: 0,
        }
    }

    fn select(&mut self, page: u16) -> Result<(), PhyError> {
        self.access.phyar_write(0x1F, page)?;
        self.page = page;
        Ok(())
    }

    fn run(&mut self, steps: &[PhyStep], txcfg: u32) -> Result<(), PhyError> {
        for step in steps {
            match *step {
                PhyStep::Ocp(e) => {
                    self.access.apply_entry(e)?;
                }
                PhyStep::Select(page) => self.select(page)?,
                PhyStep::Write { reg, val } => {
                    self.access.phyar_write(reg, val)?;
                }
                PhyStep::Modify { reg, mask, val } => {
                    self.access.phyar_modify(reg, mask, val)?;
                }
                PhyStep::PagedWrite { page, reg, val } => {
                    let prev = self.page;
                    self.select(page)?;
                    self.access.phyar_write(reg, val)?;
                    self.select(prev)?;
                }
                PhyStep::PagedModify {
                    page,
                    reg,
                    mask,
                    val,
                } => {
                    let prev = self.page;
                    self.select(page)?;
                    self.access.phyar_modify(reg, mask, val)?;
                    self.select(prev)?;
                }
                PhyStep::DParam { parm, mask, val } => {
                    let prev = self.page;
                    self.select(5)?;
                    self.access.phyar_write(0x05, parm)?;
                    self.access.phyar_modify(0x06, mask, val)?;
                    self.select(prev)?;
                }
                PhyStep::ExtPage {
                    ext,
                    reg,
                    mask,
                    val,
                } => {
                    let prev = self.page;
                    self.select(7)?;
                    self.access.phyar_write(0x1E, ext)?;
                    self.access.phyar_modify(reg, mask, val)?;
                    self.select(prev)?;
                }
                PhyStep::MmdAnEeeAdvClear => {
                    // Clause-45 write via Clause-22 MMD access
                    // registers, at the current page (0 in the
                    // only table that uses this step).
                    self.access.phyar_write(0x0D, MDIO_MMD_AN)?;
                    self.access.phyar_write(0x0E, MDIO_AN_EEE_ADV)?;
                    self.access.phyar_write(0x0D, 0x4000 | MDIO_MMD_AN)?;
                    self.access.phyar_write(0x0E, 0)?;
                }
                PhyStep::Firmware => load_8168_firmware(&mut self.access, txcfg),
            }
        }
        Ok(())
    }

    /// PHYAR read in the currently selected page.
    fn read(&self, reg: u16) -> Result<u16, PhyError> {
        self.access.phyar_read(reg)
    }

    /// OCP read of one paged register (Linux `phy_read_paged`).
    fn read_paged(&self, page: u16, reg: u16) -> Result<u16, PhyError> {
        let addr = PhyAccess::paged_addr(page, reg)?;
        self.access.phy_ocp_read(addr)
    }
}

/// MMD device address for auto-negotiation (IEEE 802.3 Clause 45).
const MDIO_MMD_AN: u16 = 7;
/// EEE advertisement register within MMD 7 (IEEE 802.3az).
const MDIO_AN_EEE_ADV: u16 = 60;

// ── Firmware ──────────────────────────────────────────────────────

/// `(mask, value, blob)` rows mirroring Linux's chip table for
/// the 8168 range. The `(mask, value)` pairs are the same ones
/// [`crate::features::mac_version_from_xid`] matches on; only
/// rows that name a blob are listed, and a chip with no row here
/// loads no firmware (matching Linux, where `tp->rtl_fw` is NULL
/// for those chips).
const FW_TABLE: &[(u32, u32, &str)] = &[
    (0x7cf, 0x54a, "rtl_nic/rtl8168fp-3.fw"),
    (0x7cf, 0x541, "rtl_nic/rtl8168h-2.fw"),
    (0x7cf, 0x6c0, "rtl_nic/rtl8168h-2.fw"),
    (0x7cf, 0x5c8, "rtl_nic/rtl8411-2.fw"),
    (0x7cf, 0x509, "rtl_nic/rtl8168g-3.fw"),
    (0x7cf, 0x4c0, "rtl_nic/rtl8168g-2.fw"),
    (0x7c8, 0x488, "rtl_nic/rtl8411-1.fw"),
    (0x7cf, 0x481, "rtl_nic/rtl8168f-2.fw"),
    (0x7cf, 0x480, "rtl_nic/rtl8168f-1.fw"),
    (0x7c8, 0x2c8, "rtl_nic/rtl8168e-3.fw"),
    (0x7cf, 0x2c1, "rtl_nic/rtl8168e-1.fw"),
    (0x7c8, 0x2c0, "rtl_nic/rtl8168e-2.fw"),
    (0x7cf, 0x281, "rtl_nic/rtl8168d-1.fw"),
    (0x7c8, 0x280, "rtl_nic/rtl8168d-2.fw"),
];

/// Blob name for an extracted XID (`(txcfg >> 20) & 0xfcf`, the
/// same extraction [`crate::features::mac_version_from_xid`]
/// uses), or `None` when the chip loads no firmware.
pub const fn firmware_name_for_xid(xid: u32) -> Option<&'static str> {
    let mut i = 0;
    while i < FW_TABLE.len() {
        let (mask, val, name) = FW_TABLE[i];
        if xid & mask == val {
            return Some(name);
        }
        i += 1;
    }
    None
}

/// Fetch, parse, and run this chip's firmware blob, if the
/// firmware registry has it. Missing, malformed, or failed blobs
/// are logged and skipped — never fatal to bring-up, matching
/// Linux (`r8169_apply_firmware` runs only `if (tp->rtl_fw)`)
/// and the 8125 driver's precedent.
fn load_8168_firmware(phy: &mut PhyAccess, txcfg: u32) {
    let xid = (txcfg >> 20) & 0xfcf;
    let Some(name) = firmware_name_for_xid(xid) else {
        return;
    };
    let Some(auth) = narf_firmware::trusted_loader_authority() else {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8168: no firmware authority; skipping {}",
            name,
        );
        return;
    };
    let Some(auth) = auth.derive().ok() else {
        return;
    };
    let code = (|| -> Option<Vec<u32>> {
        let cap = narf_firmware::open(name, &auth).ok()?;
        let view = narf_firmware::view_of(&cap).ok()?;
        match crate::phy_access::parse_firmware(view.bytes) {
            Ok(c) => Some(c),
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  rtl8168: {} failed its format check: {:?}",
                    name,
                    e,
                );
                None
            }
        }
    })();
    let Some(code) = code else { return };
    if let Err(e) = crate::phy_access::validate_firmware(&code) {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8168: {} rejected: {:?}",
            name,
            e,
        );
        return;
    }
    match phy.run_firmware(&code) {
        Ok(()) => {
            let _ = writeln!(
                narf_console::Writer,
                "  rtl8168: applied firmware ({} opcodes)",
                code.len(),
            );
        }
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  rtl8168: firmware aborted at an opcode: {:?}; PHY may be partly patched",
                e,
            );
        }
    }
}

// ── EFUSE ─────────────────────────────────────────────────────────

/// `EFUSEAR` — MAC EFUSE access register (BAR2 offset 0xDC).
const REG_EFUSEAR: u64 = 0xDC;
/// `EFUSEAR_FLAG` — set by the device when the read is done.
const EFUSEAR_FLAG: u32 = 0x8000_0000;
/// `EFUSEAR_REG_MASK` — register-address field mask.
const EFUSEAR_REG_MASK: u32 = 0x03FF;
/// `EFUSEAR_REG_SHIFT` — register-address field shift.
const EFUSEAR_REG_SHIFT: u32 = 8;

/// `rtl8168d_efuse_read`: write the register address (a read
/// command, flag bit clear), wait up to 100 × 300 µs for the done
/// flag, return the low byte — or 0xFF on timeout (Linux's `~0`
/// for its `u8` return).
fn efuse_read(mmio: &MmioRegion, reg_addr: u16) -> u8 {
    // SAFETY: `mmio` is the controller's mapped BAR2 and
    // `REG_EFUSEAR` is inside it — the caller checked the BAR
    // length at bring-up.
    unsafe {
        mmio.write32(
            REG_EFUSEAR,
            ((reg_addr as u32) & EFUSEAR_REG_MASK) << EFUSEAR_REG_SHIFT,
        )
    };
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: as above.
            let v = unsafe { mmio.read32(REG_EFUSEAR) };
            v & EFUSEAR_FLAG != 0
        },
        narf_time::Deadline::after_ms(30),
    );
    if !done {
        return 0xFF;
    }
    // SAFETY: as above.
    (unsafe { mmio.read32(REG_EFUSEAR) } & 0xFF) as u8
}

// ── Shared subsequences ─────────────────────────────────────────────
// Linux-only values (see module docs). Each is one Linux helper
// inlined once and reused by every revision that calls it.

// `rtl8168f_config_eee_phy`: extpage 0x20 reg 0x15 bit 8 set,
// then `d_param` 0x8b85 bit 13 set.
// Only referenced by the cfg(test) shared_helpers_pinned pin below; clippy-kernel
// never compiles that helper, so the const reads as dead there. Kept (not deleted
// or cfg-gated) so the documented rtl8168f_config_eee_phy subsequence stays
// available to the test pin in every build.
#[allow(dead_code)]
const F_EEE: &[PhyStep] = &[ep(0x0020, 0x15, 0x0000, 0x0100), dp(0x8b85, 0x0000, 0x2000)];

// `rtl8168g_config_eee_phy`: page 0x0a43 reg 0x11 bit 4 set.
const G_EEE: &[PhyStep] = &[mp(0x0a43, 0x11, 0x0000, 0x0010)];

// `rtl8168h_config_eee_phy`: the G EEE step, then page 0xa4a
// reg 0x11 bit 9 set and page 0xa42 reg 0x14 bit 7 set.
const H_EEE: &[PhyStep] = &[
    mp(0x0a43, 0x11, 0x0000, 0x0010),
    mp(0x0a4a, 0x11, 0x0000, 0x0200),
    mp(0x0a42, 0x14, 0x0000, 0x0080),
];

// `rtl8168g_phy_adjust_10m_aldps`.
const G_10M_ALDPS: &[PhyStep] = &[
    mp(0x0bcc, 0x14, 0x0100, 0x0000),
    mp(0x0a44, 0x11, 0x0000, 0x00c0),
    gp(0x8084, 0x6000, 0x0000),
    mp(0x0a43, 0x10, 0x0000, 0x1003),
];

// `rtl8168g_disable_aldps`: page 0x0a43 reg 0x10 bit 2 clear.
const G_DISABLE_ALDPS: &[PhyStep] = &[mp(0x0a43, 0x10, 0x0004, 0x0000)];

// `rtl8168g_enable_gphy_10m`: page 0x0a44 reg 0x11 bit 11 set.
const G_ENABLE_10M: &[PhyStep] = &[mp(0x0a44, 0x11, 0x0000, 0x0800)];

// `rtl8168f_hw_phy_config`, the F core shared by the 8168f/8111f
// revisions and RTL8411: delay-cap param, auto-speed-down
// extpage, 10M EEE waveform param, then the F EEE helper.
const F_CORE: &[PhyStep] = &[
    dp(0x8b80, 0x0000, 0x0006),
    ep(0x002d, 0x18, 0x0000, 0x0010),
    mp(0x0000, 0x14, 0x0000, 0x8000),
    dp(0x8b86, 0x0000, 0x0001),
    ep(0x0020, 0x15, 0x0000, 0x0100),
    dp(0x8b85, 0x0000, 0x2000),
];

// ── Per-revision tables (Linux-only values) ───────────────────────
// Page tracking: every list starts with the PHYAR page at 0
// (established by `configure_phy_8168`'s opening select) and
// leaves it at 0. Low registers in a non-zero page become PHYAR
// steps (`wr`/`md` after the preceding `sel`, `pwr`/`pmd` for
// paged ops); everything else becomes an OCP step with its page
// explicit. Batch page-select entries become `sel` steps.

// RTL8168b/8111b (VER 17): one paged write.
const BEF: &[PhyStep] = &[wp(0x0001, 0x10, 0xf41b)];

// RTL8168cp/8111cp step 1 (VER 18): a page-0 write, then a low
// paged write.
const CP1: &[PhyStep] = &[wp(0x0000, 0x1d, 0x0f00), pwr(0x0002, 0x0c, 0x1ec8)];

// RTL8168cp/8111cp step 2 (VER 23, 24): two page-0 bit sets,
// then a paged write.
const CP2: &[PhyStep] = &[
    mp(0x0000, 0x14, 0x0000, 0x0020),
    mp(0x0000, 0x0d, 0x0000, 0x0020),
    wp(0x0001, 0x1d, 0x3d98),
];

// RTL8168c/8111c step 1 (VER 19): batch plus two page-0 bit sets.
// The batch's page-2 low registers travel PHYAR (after `sel(2)`);
// the page-1 register 0x12 and page-3 registers travel OCP.
const C1: &[PhyStep] = &[
    sel(0x0001),
    wp(0x0001, 0x12, 0x2300),
    sel(0x0002),
    wr(0x00, 0x88d4),
    wr(0x01, 0x82b1),
    wr(0x03, 0x7002),
    wr(0x08, 0x9e30),
    wr(0x09, 0x01f0),
    wr(0x0a, 0x5500),
    wr(0x0c, 0x00c8),
    sel(0x0003),
    wp(0x0003, 0x12, 0xc096),
    wp(0x0003, 0x16, 0x000a),
    sel(0x0000),
    sel(0x0000),
    wp(0x0000, 0x09, 0x2000),
    wp(0x0000, 0x09, 0x0000),
    mp(0x0000, 0x14, 0x0000, 0x0020),
    mp(0x0000, 0x0d, 0x0000, 0x0020),
];

// RTL8168c/8111c step 2 (VER 20): batch plus three page-0 bit
// sets. Page-1 low registers travel PHYAR; 0x1d and the page-3
// register travel OCP.
const C2: &[PhyStep] = &[
    sel(0x0001),
    wp(0x0001, 0x12, 0x2300),
    wr(0x03, 0x802f),
    wr(0x02, 0x4f02),
    wr(0x01, 0x0409),
    wr(0x00, 0xf099),
    wr(0x04, 0x9800),
    wr(0x04, 0x9000),
    wp(0x0001, 0x1d, 0x3d98),
    sel(0x0002),
    wr(0x0c, 0x7eb8),
    wr(0x06, 0x0761),
    sel(0x0003),
    wp(0x0003, 0x16, 0x0f0a),
    sel(0x0000),
    mp(0x0000, 0x16, 0x0000, 0x0001),
    mp(0x0000, 0x14, 0x0000, 0x0020),
    mp(0x0000, 0x0d, 0x0000, 0x0020),
];

// RTL8168c/8111c step 3 (VER 21, 22): batch plus three page-0
// bit sets.
const C3: &[PhyStep] = &[
    sel(0x0001),
    wp(0x0001, 0x12, 0x2300),
    wp(0x0001, 0x1d, 0x3d98),
    sel(0x0002),
    wr(0x0c, 0x7eb8),
    wr(0x06, 0x5461),
    sel(0x0003),
    wp(0x0003, 0x16, 0x0f0a),
    sel(0x0000),
    mp(0x0000, 0x16, 0x0000, 0x0001),
    mp(0x0000, 0x14, 0x0000, 0x0020),
    mp(0x0000, 0x0d, 0x0000, 0x0020),
];

// RTL8168dp/8111dp (VER 28): paged write, extpage, page-0 bit
// set. No firmware for this chip.
const D4: &[PhyStep] = &[
    wp(0x0001, 0x17, 0x0cc0),
    ep(0x002d, 0x18, 0xffff, 0x0040),
    mp(0x0000, 0x0d, 0x0000, 0x0020),
];

// RTL8168e/8111e step 1 (VER 32, 33): firmware first, then the
// delay-cap param, the channel-estimation batch (page-1 low
// registers via PHYAR), three extpages, a low paged modify,
// auto-speed-down, two params, an extpage, a low paged write,
// and the MMD EEE-advertisement clear.
const E1: &[PhyStep] = &[
    PhyStep::Firmware,
    dp(0x8b80, 0xffff, 0xc896),
    sel(0x0001),
    wr(0x0b, 0x6c20),
    wr(0x07, 0x2872),
    wp(0x0001, 0x1c, 0xefff),
    sel(0x0003),
    wp(0x0003, 0x14, 0x6420),
    sel(0x0000),
    ep(0x002f, 0x15, 0xffff, 0x1919),
    ep(0x00ac, 0x18, 0xffff, 0x0006),
    ep(0x0023, 0x17, 0x0000, 0x0006),
    pmd(0x0002, 0x08, 0x7f00, 0x8000),
    ep(0x002d, 0x18, 0x0000, 0x0050),
    mp(0x0000, 0x14, 0x0000, 0x8000),
    dp(0x8b86, 0x0000, 0x0001),
    dp(0x8b85, 0x2000, 0x0000),
    ep(0x0020, 0x15, 0x1100, 0x0000),
    pwr(0x0006, 0x00, 0x5a00),
    PhyStep::MmdAnEeeAdvClear,
];

// RTL8168evl/8111evl (VER 34): firmware first, then an extpage,
// a low paged write, three green params, the 4-corner block
// (page-5 param write plus a page-5 bit set), auto-speed-down,
// two params, the F EEE helper, and the green-feature block.
const E2: &[PhyStep] = &[
    PhyStep::Firmware,
    ep(0x00ac, 0x18, 0xffff, 0x0006),
    pwr(0x0003, 0x09, 0xa20f),
    dp(0x8b5b, 0xffff, 0x9222),
    dp(0x8b6d, 0xffff, 0x8000),
    dp(0x8b76, 0xffff, 0x8000),
    sel(0x0005),
    wr(0x05, 0x8b80),
    mp(0x0005, 0x17, 0x0000, 0x0006),
    sel(0x0000),
    ep(0x002d, 0x18, 0x0000, 0x0010),
    mp(0x0000, 0x14, 0x0000, 0x8000),
    dp(0x8b86, 0x0000, 0x0001),
    dp(0x8b85, 0x0000, 0x4000),
    ep(0x0020, 0x15, 0x0000, 0x0100),
    dp(0x8b85, 0x0000, 0x2000),
    sel(0x0003),
    mp(0x0003, 0x19, 0x0000, 0x0001),
    mp(0x0003, 0x10, 0x0000, 0x0400),
    sel(0x0000),
    pmd(0x0005, 0x01, 0x0000, 0x0100),
];

// RTL8168f/8111f step 1 (VER 35): firmware, channel-estimation
// paged write, four green params, two green extpages, a 10M
// green param, an RTCT paged write, the F core, and the 2-pair
// param. The F core itself ends with the F EEE helper.
const F1_PRE: &[PhyStep] = &[
    PhyStep::Firmware,
    pwr(0x0003, 0x09, 0xa20f),
    dp(0x8b55, 0xffff, 0x0000),
    dp(0x8b5e, 0xffff, 0x0000),
    dp(0x8b67, 0xffff, 0x0000),
    dp(0x8b70, 0xffff, 0x0000),
    ep(0x0078, 0x17, 0xffff, 0x0000),
    ep(0x0078, 0x19, 0xffff, 0x00fb),
    dp(0x8b79, 0xffff, 0xaa00),
    pwr(0x0003, 0x01, 0x328a),
];
const F1_POST: &[PhyStep] = &[dp(0x8b85, 0x0000, 0x4000)];

// RTL8168f/8111f step 2 (VER 36): firmware, then the F core.
const F2_PRE: &[PhyStep] = &[PhyStep::Firmware];

// RTL8411 (VER 38): firmware, the F core, the 2-pair param,
// channel-estimation paged write, four green params, two green
// extpages (0x00aa on reg 0x19, not the F1 value 0x00fb), a 10M
// green param, an RTCT paged write, seven more green params,
// the same-seed param, and the green-feature block (bits
// *cleared*, opposite to the E2 block). The firmware step is
// run separately so the F core lands between it and the rest.
const M8411_PRE: &[PhyStep] = &[
    dp(0x8b85, 0x0000, 0x4000),
    pwr(0x0003, 0x09, 0xa20f),
    dp(0x8b55, 0xffff, 0x0000),
    dp(0x8b5e, 0xffff, 0x0000),
    dp(0x8b67, 0xffff, 0x0000),
    dp(0x8b70, 0xffff, 0x0000),
    ep(0x0078, 0x17, 0xffff, 0x0000),
    ep(0x0078, 0x19, 0xffff, 0x00aa),
    dp(0x8b79, 0xffff, 0xaa00),
    pwr(0x0003, 0x01, 0x328a),
    dp(0x8b54, 0x0800, 0x0000),
    dp(0x8b5d, 0x0800, 0x0000),
    dp(0x8a7c, 0x0100, 0x0000),
    dp(0x8a7f, 0x0000, 0x0100),
    dp(0x8a82, 0x0100, 0x0000),
    dp(0x8a85, 0x0100, 0x0000),
    dp(0x8a88, 0x0100, 0x0000),
    dp(0x8b85, 0x0000, 0x8000),
];
const M8411_POST: &[PhyStep] = &[
    sel(0x0003),
    mp(0x0003, 0x19, 0x0001, 0x0000),
    mp(0x0003, 0x10, 0x0400, 0x0000),
    sel(0x0000),
];

// RTL8168g/8111g step 2, RTL8168gu/8111gu, RTL8411b (VER 42,
// 43, 44): firmware, then the G EEE helper.
const G2: &[PhyStep] = &[PhyStep::Firmware, mp(0x0a43, 0x11, 0x0000, 0x0010)];

// RTL8168ep/8111ep step 2 (VER 51): 10M/ALDPS adjust, UC LPF
// param, RGMII page modify, 21 channel-estimation params, the
// force-PWM block, ALDPS disable, and the G EEE helper. No
// firmware for this chip.
const EP2_MID: &[PhyStep] = &[
    gp(0x8012, 0x0000, 0x8000),
    mp(0x0c42, 0x11, 0x2000, 0x4000),
    gp(0x80f3, 0xff00, 0x8b00),
    gp(0x80f0, 0xff00, 0x3a00),
    gp(0x80ef, 0xff00, 0x0500),
    gp(0x80f6, 0xff00, 0x6e00),
    gp(0x80ec, 0xff00, 0x6800),
    gp(0x80ed, 0xff00, 0x7c00),
    gp(0x80f2, 0xff00, 0xf400),
    gp(0x80f4, 0xff00, 0x8500),
    gp(0x8110, 0xff00, 0xa800),
    gp(0x810f, 0xff00, 0x1d00),
    gp(0x8111, 0xff00, 0xf500),
    gp(0x8113, 0xff00, 0x6100),
    gp(0x8115, 0xff00, 0x9200),
    gp(0x810e, 0xff00, 0x0400),
    gp(0x810c, 0xff00, 0x7c00),
    gp(0x810b, 0xff00, 0x5a00),
    gp(0x80d1, 0xff00, 0xff00),
    gp(0x80cd, 0xff00, 0x9e00),
    gp(0x80d3, 0xff00, 0x0e00),
    gp(0x80d5, 0xff00, 0xca00),
    gp(0x80d7, 0xff00, 0x8400),
];
const EP2_PWM: &[PhyStep] = &[
    sel(0x0bcd),
    wp(0x0bcd, 0x14, 0x5065),
    wp(0x0bcd, 0x14, 0xd065),
    sel(0x0bc8),
    wp(0x0bc8, 0x12, 0x00ed),
    sel(0x0bcd),
    wp(0x0bcd, 0x14, 0x1065),
    wp(0x0bcd, 0x14, 0x9065),
    wp(0x0bcd, 0x14, 0x1065),
    sel(0x0000),
];

// RTL8117 (VER 52): 21 channel-estimation params, the enable
// param, 10M enable, another param, ALDPS disable, and the H
// EEE helper. No firmware for this chip.
const M8117_CHN: &[PhyStep] = &[
    gp(0x808e, 0xff00, 0x4800),
    gp(0x8090, 0xff00, 0xcc00),
    gp(0x8092, 0xff00, 0xb000),
    gp(0x8088, 0xff00, 0x6000),
    gp(0x808b, 0x3f00, 0x0b00),
    gp(0x808d, 0x1f00, 0x0600),
    gp(0x808c, 0xff00, 0xb000),
    gp(0x80a0, 0xff00, 0x2800),
    gp(0x80a2, 0xff00, 0x5000),
    gp(0x809b, 0xf800, 0xb000),
    gp(0x809a, 0xff00, 0x4b00),
    gp(0x809d, 0x3f00, 0x0800),
    gp(0x80a1, 0xff00, 0x7000),
    gp(0x809f, 0x1f00, 0x0300),
    gp(0x809e, 0xff00, 0x8800),
    gp(0x80b2, 0xff00, 0x2200),
    gp(0x80ad, 0xf800, 0x9800),
    gp(0x80af, 0x3f00, 0x0800),
    gp(0x80b3, 0xff00, 0x6f00),
    gp(0x80b1, 0x1f00, 0x0300),
    gp(0x80b0, 0xff00, 0x9300),
    gp(0x8011, 0x0000, 0x0800),
];
const M8117_TAIL: &[PhyStep] = &[gp(0x8016, 0x0000, 0x0400)];

// ── Conditional revisions ───────────────────────────────────────────
// These share the d_1 batch and branch on hardware state, so they
// are code, not tables. The batch itself is a table.

// `rtl8168d_1_phy_reg_init_0`, shared by the d_1 and d_2
// revisions: channel estimation (page-1 low registers via
// PHYAR), the Tx-error page-2 write, the page-5 param segment
// (plain PHYAR writes, not a read-modify `d_param`), the
// bad-cable SNR register, and the final page-0 write.
const D1_BATCH: &[PhyStep] = &[
    sel(0x0001),
    wr(0x06, 0x4064),
    wr(0x07, 0x2863),
    wr(0x08, 0x059c),
    wr(0x09, 0x26b4),
    wr(0x0a, 0x6a19),
    wr(0x0b, 0xdcc8),
    wp(0x0001, 0x10, 0xf06d),
    wp(0x0001, 0x14, 0x7f68),
    wp(0x0001, 0x18, 0x7fd9),
    wp(0x0001, 0x1c, 0xf0ff),
    wp(0x0001, 0x1d, 0x3d9c),
    sel(0x0003),
    wp(0x0003, 0x12, 0xf49f),
    wp(0x0003, 0x13, 0x070b),
    wp(0x0003, 0x1a, 0x05ad),
    wp(0x0003, 0x14, 0x94c0),
    sel(0x0002),
    wr(0x06, 0x5561),
    sel(0x0005),
    wr(0x05, 0x8332),
    wr(0x06, 0x5561),
    sel(0x0001),
    wp(0x0001, 0x17, 0x0cc0),
    sel(0x0000),
    wp(0x0000, 0x0d, 0xf880),
];

// `rtl8168d_1_common`: a paged write, a param, then — only when
// the low byte of page-2 register 0x0D is not already 0x6C —
// eight writes stepping that register's low byte 0x65..0x6C.
fn d_1_common(seq: &mut Seq, txcfg: u32) -> Result<(), PhyError> {
    seq.run(
        &[pwr(0x0002, 0x05, 0x669a), dp(0x8330, 0xffff, 0x669a)],
        txcfg,
    )?;
    seq.select(2)?;
    let val = seq.read(0x0d)?;
    if val & 0x00ff != 0x006c {
        let base = val & 0xff00;
        for set in [
            0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006a, 0x006b, 0x006c,
        ] {
            seq.access.phyar_write(0x0d, base | set)?;
        }
    }
    Ok(())
}

// `rtl8168d_apply_firmware_cond`: read page-5 register 0x06
// (after selecting the param 0x001B); load firmware only when
// it equals `expected`, otherwise warn. The page register is
// left at 0 either way.
fn apply_firmware_cond(seq: &mut Seq, expected: u16, txcfg: u32) -> Result<(), PhyError> {
    seq.run(&[sel(0x0005), wr(0x05, 0x001b)], txcfg)?;
    let reg_val = seq.read(0x06)?;
    seq.select(0)?;
    if reg_val == expected {
        load_8168_firmware(&mut seq.access, txcfg);
    } else {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8168: chipset not ready for firmware (page-5 reg 0x06 = {:#06x}, expected {:#06x})",
            reg_val, expected,
        );
    }
    Ok(())
}

// RTL8168d/8111d step 1 (VER 25).
fn config_d_1(seq: &mut Seq, mmio: &MmioRegion, txcfg: u32) -> Result<(), PhyError> {
    seq.run(D1_BATCH, txcfg)?;
    seq.run(
        &[
            sel(0x0002),
            md(0x0b, 0x00ef, 0x0010),
            md(0x0c, 0x5d00, 0xa200),
        ],
        txcfg,
    )?;
    if efuse_read(mmio, 0x01) == 0xb1 {
        d_1_common(seq, txcfg)?;
    } else {
        seq.run(
            &[pwr(0x0002, 0x05, 0x6662), dp(0x8330, 0xffff, 0x6662)],
            txcfg,
        )?;
    }
    seq.run(
        &[
            sel(0x0002),
            md(0x0d, 0x0000, 0x0300),
            md(0x0f, 0x0000, 0x0010),
            sel(0x0002),
            md(0x02, 0x0600, 0x0100),
            md(0x03, 0xe000, 0x0000),
            sel(0x0000),
        ],
        txcfg,
    )?;
    apply_firmware_cond(seq, 0xbf00, txcfg)
}

// RTL8168d/8111d step 2 (VER 26).
fn config_d_2(seq: &mut Seq, mmio: &MmioRegion, txcfg: u32) -> Result<(), PhyError> {
    seq.run(D1_BATCH, txcfg)?;
    if efuse_read(mmio, 0x01) == 0xb1 {
        d_1_common(seq, txcfg)?;
    } else {
        seq.run(
            &[pwr(0x0002, 0x05, 0x2642), dp(0x8330, 0xffff, 0x2642)],
            txcfg,
        )?;
    }
    seq.run(
        &[
            sel(0x0002),
            md(0x02, 0x0600, 0x0100),
            md(0x03, 0xe000, 0x0000),
            sel(0x0000),
            pmd(0x0002, 0x0f, 0x0000, 0x0017),
        ],
        txcfg,
    )?;
    apply_firmware_cond(seq, 0xb300, txcfg)
}

// The 8168g/8111g SWR-efficiency block (shared by G1 only):
// two page 0x0bcd writes, one page 0x0bc8 write, three more page
// 0x0bcd writes, then back to page 0.
const G1_SWR: &[PhyStep] = &[
    sel(0x0bcd),
    wp(0x0bcd, 0x14, 0x5065),
    wp(0x0bcd, 0x14, 0xd065),
    sel(0x0bc8),
    wp(0x0bc8, 0x11, 0x5655),
    sel(0x0bcd),
    wp(0x0bcd, 0x14, 0x1065),
    wp(0x0bcd, 0x14, 0x9065),
    wp(0x0bcd, 0x14, 0x1065),
    sel(0x0000),
];

// RTL8168g/8111g step 1 (VER 40): firmware, two read-branches
// off page 0x0a46, auto-speed-down, 10M/ALDPS adjust, EEE
// auto-fallback, UC LPF param, RGMII modify, the SWR block,
// ALDPS disable, and the G EEE helper.
fn config_g_1(seq: &mut Seq, txcfg: u32) -> Result<(), PhyError> {
    seq.run(&[PhyStep::Firmware], txcfg)?;
    let v = seq.read_paged(0x0a46, 0x10)?;
    seq.run(
        &[if v & 0x0100 != 0 {
            mp(0x0bcc, 0x12, 0x8000, 0x0000)
        } else {
            mp(0x0bcc, 0x12, 0x0000, 0x8000)
        }],
        txcfg,
    )?;
    let v = seq.read_paged(0x0a46, 0x13)?;
    seq.run(
        &[if v & 0x0100 != 0 {
            mp(0x0c41, 0x15, 0x0000, 0x0002)
        } else {
            mp(0x0c41, 0x15, 0x0002, 0x0000)
        }],
        txcfg,
    )?;
    seq.run(&[mp(0x0a44, 0x11, 0x0000, 0x000c)], txcfg)?;
    seq.run(G_10M_ALDPS, txcfg)?;
    seq.run(&[mp(0x0a4b, 0x11, 0x0000, 0x0004)], txcfg)?;
    seq.run(&[gp(0x8012, 0x0000, 0x8000)], txcfg)?;
    seq.run(&[mp(0x0c42, 0x11, 0x2000, 0x4000)], txcfg)?;
    seq.run(G1_SWR, txcfg)?;
    seq.run(G_DISABLE_ALDPS, txcfg)?;
    seq.run(G_EEE, txcfg)
}

// RTL8168h/8111h step 2 (VER 46, 48): firmware, two params, a
// page modify, 10M enable, the ADC-bias ioffset block (MAC OCP
// reads 0xdd02/0xdd00; skipped when the computed ioffset is
// 0xFFFF), the rlen block (TX LPF corner from page 0x0bcd
// register 0x16's low nibble), two disables, ALDPS disable, and
// the G EEE helper.
fn config_h_2(seq: &mut Seq, txcfg: u32) -> Result<(), PhyError> {
    seq.run(&[PhyStep::Firmware], txcfg)?;
    seq.run(
        &[
            gp(0x808a, 0x003f, 0x000a),
            gp(0x0811, 0x0000, 0x0800),
            mp(0x0a42, 0x16, 0x0000, 0x0002),
        ],
        txcfg,
    )?;
    seq.run(G_ENABLE_10M, txcfg)?;
    seq.access.mac_ocp_write(0xdd02, 0x807d)?;
    let data1 = seq.access.mac_ocp_read(0xdd02)?;
    let data2 = seq.access.mac_ocp_read(0xdd00)?;
    let mut ioffset = (data2 >> 1) & 0x7ff8;
    ioffset |= data2 & 0x0007;
    if data1 & 0x0080 != 0 {
        ioffset |= 0x8000;
    }
    if ioffset != 0xffff {
        seq.run(&[wp(0x0bcf, 0x16, ioffset)], txcfg)?;
    }
    let data = seq.read_paged(0x0bcd, 0x16)? & 0x000f;
    let rlen = data.saturating_sub(3);
    let data = rlen | (rlen << 4) | (rlen << 8) | (rlen << 12);
    seq.run(&[wp(0x0bcd, 0x17, data)], txcfg)?;
    seq.run(
        &[
            mp(0x0a44, 0x11, 0x0080, 0x0000),
            mp(0x0a43, 0x10, 0x0001, 0x0000),
        ],
        txcfg,
    )?;
    seq.run(G_DISABLE_ALDPS, txcfg)?;
    seq.run(G_EEE, txcfg)
}

// ── Dispatch ──────────────────────────────────────────────────────

/// The per-revision program for a MAC version number. Pure-table
/// revisions are named by their table; revisions that branch on
/// hardware state are named by their config function.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Revision {
    Bef,
    Cp1,
    Cp2,
    C1,
    C2,
    C3,
    D1,
    D2,
    D4,
    E1,
    E2,
    F1,
    F2,
    M8411,
    G1,
    G2,
    H2,
    Ep2,
    M8117,
}

/// Linux's `r8169_phy_config` dispatch, restricted to the
/// revisions this driver binds. `None` covers the NULL entries
/// (VER 10, 31) and every version with no 8168 table — those
/// chips get no PHY programming, not an error.
pub const fn revision_for(ver: u32) -> Option<Revision> {
    match ver {
        17 => Some(Revision::Bef),
        18 => Some(Revision::Cp1),
        19 => Some(Revision::C1),
        20 => Some(Revision::C2),
        21 | 22 => Some(Revision::C3),
        23 | 24 => Some(Revision::Cp2),
        25 => Some(Revision::D1),
        26 => Some(Revision::D2),
        28 => Some(Revision::D4),
        32 | 33 => Some(Revision::E1),
        34 => Some(Revision::E2),
        35 => Some(Revision::F1),
        36 => Some(Revision::F2),
        38 => Some(Revision::M8411),
        40 => Some(Revision::G1),
        42..=44 => Some(Revision::G2),
        46 | 48 => Some(Revision::H2),
        51 => Some(Revision::Ep2),
        52 => Some(Revision::M8117),
        _ => None,
    }
}

/// Program the PHY for this chip's MAC version, in Linux's
/// order. `mac_version` is the already-decoded
/// [`crate::features::mac_version_from_xid`] result; `txcfg` is
/// the raw TxConfig value the firmware lookup extracts the XID
/// from. Unknown versions and chips without a table are logged
/// and skipped — bring-up continues without PHY programming, as
/// it does today. A step error aborts the sequence and is
/// returned; the wire-in logs it and continues bring-up.
pub fn configure_phy_8168(
    mmio: &MmioRegion,
    mac_version: Option<u32>,
    txcfg: u32,
) -> Result<(), PhyError> {
    let Some(ver) = mac_version else {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8168: unknown MAC version; skipping PHY tables",
        );
        return Ok(());
    };
    let Some(rev) = revision_for(ver) else {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8168: no PHY table for MAC version {}; skipping",
            ver,
        );
        return Ok(());
    };
    let mut seq = Seq::new(mmio);
    // Establish the page-0 invariant the tracker assumes.
    seq.select(0)?;
    match rev {
        Revision::Bef => seq.run(BEF, txcfg),
        Revision::Cp1 => seq.run(CP1, txcfg),
        Revision::Cp2 => seq.run(CP2, txcfg),
        Revision::C1 => seq.run(C1, txcfg),
        Revision::C2 => seq.run(C2, txcfg),
        Revision::C3 => seq.run(C3, txcfg),
        Revision::D1 => config_d_1(&mut seq, mmio, txcfg),
        Revision::D2 => config_d_2(&mut seq, mmio, txcfg),
        Revision::D4 => seq.run(D4, txcfg),
        Revision::E1 => seq.run(E1, txcfg),
        Revision::E2 => seq.run(E2, txcfg),
        Revision::F1 => {
            seq.run(F1_PRE, txcfg)?;
            seq.run(F_CORE, txcfg)?;
            seq.run(F1_POST, txcfg)
        }
        Revision::F2 => {
            seq.run(F2_PRE, txcfg)?;
            seq.run(F_CORE, txcfg)
        }
        Revision::M8411 => {
            seq.run(&[PhyStep::Firmware], txcfg)?;
            seq.run(F_CORE, txcfg)?;
            seq.run(M8411_PRE, txcfg)?;
            seq.run(M8411_POST, txcfg)
        }
        Revision::G1 => config_g_1(&mut seq, txcfg),
        Revision::G2 => seq.run(G2, txcfg),
        Revision::H2 => config_h_2(&mut seq, txcfg),
        Revision::Ep2 => {
            seq.run(G_10M_ALDPS, txcfg)?;
            seq.run(EP2_MID, txcfg)?;
            seq.run(EP2_PWM, txcfg)?;
            seq.run(G_DISABLE_ALDPS, txcfg)?;
            seq.run(G_EEE, txcfg)
        }
        Revision::M8117 => {
            seq.run(M8117_CHN, txcfg)?;
            seq.run(G_ENABLE_10M, txcfg)?;
            seq.run(M8117_TAIL, txcfg)?;
            seq.run(G_DISABLE_ALDPS, txcfg)?;
            seq.run(H_EEE, txcfg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phy_access::PhyAccess;

    #[test]
    fn phyar_command_packing() {
        // Write: FLAG | (reg << 16) | data; read: (reg << 16).
        assert_eq!(PhyAccess::phyar_write_cmd(0x05, 0x8332), 0x8005_8332);
        assert_eq!(PhyAccess::phyar_read_cmd(0x1f), 0x001f_0000);
        // The register field is 5 bits; wider values are masked.
        assert_eq!(PhyAccess::phyar_write_cmd(0x3f, 0xffff), 0x801f_ffff);
        assert_eq!(PhyAccess::phyar_read_cmd(0x20), 0x0000_0000);
    }

    #[test]
    fn revision_dispatch_covers_the_bound_family() {
        // (VER, expected revision), mirroring Linux's dispatch.
        let cases: &[(u32, Revision)] = &[
            (17, Revision::Bef),
            (18, Revision::Cp1),
            (19, Revision::C1),
            (20, Revision::C2),
            (21, Revision::C3),
            (22, Revision::C3),
            (23, Revision::Cp2),
            (24, Revision::Cp2),
            (25, Revision::D1),
            (26, Revision::D2),
            (28, Revision::D4),
            (32, Revision::E1),
            (33, Revision::E1),
            (34, Revision::E2),
            (35, Revision::F1),
            (36, Revision::F2),
            (38, Revision::M8411),
            (40, Revision::G1),
            (42, Revision::G2),
            (43, Revision::G2),
            (44, Revision::G2),
            (46, Revision::H2),
            (48, Revision::H2),
            (51, Revision::Ep2),
            (52, Revision::M8117),
        ];
        for (ver, want) in cases {
            assert_eq!(revision_for(*ver), Some(*want), "VER {}", ver);
        }
    }

    #[test]
    fn revision_dispatch_rejects_non_8168_versions() {
        // NULL-config entries in Linux's dispatch.
        assert_eq!(revision_for(10), None);
        assert_eq!(revision_for(31), None);
        // Fast-Ethernet families: different PCI IDs, never bound
        // by this driver, so no table here.
        for ver in [7, 8, 9, 29, 30, 37, 39] {
            assert_eq!(revision_for(ver), None, "VER {}", ver);
        }
        // 8125/8126/8127 territory and nonsense.
        for ver in [0, 1, 60, 61, 63, 64, 100] {
            assert_eq!(revision_for(ver), None, "VER {}", ver);
        }
    }

    #[test]
    fn bef_table_is_one_paged_write() {
        assert_eq!(BEF, &[wp(0x0001, 0x10, 0xf41b)]);
    }

    #[test]
    fn c3_table_pinned_value_for_value() {
        assert_eq!(
            C3,
            &[
                sel(0x0001),
                wp(0x0001, 0x12, 0x2300),
                wp(0x0001, 0x1d, 0x3d98),
                sel(0x0002),
                wr(0x0c, 0x7eb8),
                wr(0x06, 0x5461),
                sel(0x0003),
                wp(0x0003, 0x16, 0x0f0a),
                sel(0x0000),
                mp(0x0000, 0x16, 0x0000, 0x0001),
                mp(0x0000, 0x14, 0x0000, 0x0020),
                mp(0x0000, 0x0d, 0x0000, 0x0020),
            ]
        );
    }

    #[test]
    fn e1_table_shape() {
        // Firmware first, MMD clear last.
        assert_eq!(E1.len(), 20);
        assert_eq!(E1[0], PhyStep::Firmware);
        assert_eq!(E1[E1.len() - 1], PhyStep::MmdAnEeeAdvClear);
        assert_eq!(E1[1], dp(0x8b80, 0xffff, 0xc896));
        assert_eq!(E1[E1.len() - 2], pwr(0x0006, 0x00, 0x5a00));
    }

    #[test]
    fn ep2_channel_params_count() {
        // UC LPF param + RGMII modify + 21 channel params.
        assert_eq!(EP2_MID.len(), 23);
        assert_eq!(EP2_MID[0], gp(0x8012, 0x0000, 0x8000));
        assert_eq!(EP2_MID[1], mp(0x0c42, 0x11, 0x2000, 0x4000));
        assert_eq!(EP2_MID[EP2_MID.len() - 1], gp(0x80d7, 0xff00, 0x8400));
    }

    #[test]
    fn f1_and_8411_differ_on_the_green_extpage() {
        // The one value that separates the F1 and 8411 green
        // tables: reg 0x19 of extpage 0x78.
        assert!(F1_PRE.contains(&ep(0x0078, 0x19, 0xffff, 0x00fb)));
        assert!(M8411_PRE.contains(&ep(0x0078, 0x19, 0xffff, 0x00aa)));
        assert!(!M8411_PRE.contains(&ep(0x0078, 0x19, 0xffff, 0x00fb)));
        // The 8411 middle slice carries no firmware step: the
        // dispatch runs firmware, then the F core, then this.
        assert!(!M8411_PRE.contains(&PhyStep::Firmware));
    }

    #[test]
    fn g2_table_is_firmware_plus_g_eee() {
        assert_eq!(G2, &[PhyStep::Firmware, mp(0x0a43, 0x11, 0x0000, 0x0010),]);
    }

    #[test]
    fn shared_helpers_pinned() {
        assert_eq!(
            F_EEE,
            &[ep(0x0020, 0x15, 0x0000, 0x0100), dp(0x8b85, 0x0000, 0x2000),]
        );
        assert_eq!(
            H_EEE,
            &[
                mp(0x0a43, 0x11, 0x0000, 0x0010),
                mp(0x0a4a, 0x11, 0x0000, 0x0200),
                mp(0x0a42, 0x14, 0x0000, 0x0080),
            ]
        );
        assert_eq!(F_CORE.len(), 6);
        assert_eq!(F_CORE[0], dp(0x8b80, 0x0000, 0x0006));
        assert_eq!(F_CORE[F_CORE.len() - 1], dp(0x8b85, 0x0000, 0x2000));
    }

    #[test]
    fn d1_batch_shape() {
        assert_eq!(D1_BATCH.len(), 26);
        assert_eq!(D1_BATCH[0], sel(0x0001));
        assert_eq!(D1_BATCH[D1_BATCH.len() - 1], wp(0x0000, 0x0d, 0xf880));
        // The page-5 param segment inside the batch: plain
        // writes, not a read-modify `d_param`.
        assert_eq!(D1_BATCH[19], sel(0x0005));
        assert_eq!(D1_BATCH[20], wr(0x05, 0x8332));
        assert_eq!(D1_BATCH[21], wr(0x06, 0x5561));
    }

    #[test]
    fn firmware_names_follow_the_chip_table() {
        // Masked XIDs, as `mac_version_from_xid` produces them.
        assert_eq!(firmware_name_for_xid(0x54a), Some("rtl_nic/rtl8168fp-3.fw"));
        assert_eq!(firmware_name_for_xid(0x54b), None);
        assert_eq!(firmware_name_for_xid(0x541), Some("rtl_nic/rtl8168h-2.fw"));
        assert_eq!(firmware_name_for_xid(0x6c0), Some("rtl_nic/rtl8168h-2.fw"));
        assert_eq!(firmware_name_for_xid(0x5c8), Some("rtl_nic/rtl8411-2.fw"));
        assert_eq!(firmware_name_for_xid(0x488), Some("rtl_nic/rtl8411-1.fw"));
        assert_eq!(firmware_name_for_xid(0x481), Some("rtl_nic/rtl8168f-2.fw"));
        assert_eq!(firmware_name_for_xid(0x480), Some("rtl_nic/rtl8168f-1.fw"));
        assert_eq!(firmware_name_for_xid(0x2c8), Some("rtl_nic/rtl8168e-3.fw"));
        assert_eq!(firmware_name_for_xid(0x2c1), Some("rtl_nic/rtl8168e-1.fw"));
        assert_eq!(firmware_name_for_xid(0x2c0), Some("rtl_nic/rtl8168e-2.fw"));
        assert_eq!(firmware_name_for_xid(0x281), Some("rtl_nic/rtl8168d-1.fw"));
        assert_eq!(firmware_name_for_xid(0x280), Some("rtl_nic/rtl8168d-2.fw"));
        // Chips with no blob row: 8168ep, 8168dp, 8168c/cp.
        assert_eq!(firmware_name_for_xid(0x502), None);
        assert_eq!(firmware_name_for_xid(0x28a), None);
        assert_eq!(firmware_name_for_xid(0x3c0), None);
    }
}
