//! ixgbe EEE control/status — Linux-faithful model, live
//! FW-PHY/ACI transports, X550 MAC EEE status read-only.
//!
//! Grounding: Linux ixgbe @ cbbddb6 (`ixgbe_ethtool.c`
//! `ixgbe_get_eee` / `ixgbe_set_eee` / `ixgbe_get_eee_fw` /
//! `ixgbe_validate_keee`, `ixgbe_main.c` `ixgbe_set_eee_capable`,
//! `ixgbe_x550.c` FW-PHY identification, `ixgbe_e610.c`
//! `ixgbe_setup_eee_e610`, `ixgbe_type.h` LINK_SPEED bits +
//! FW-PHY activity constants, `ixgbe_type_e610.h` ACI bits).
//!
//! Datasheet grounding, per part (issue #1265):
//! - 82599: the 82599 Datasheet rev. 2.6 (322429-007) has NO
//!   EEE at all — zero matches for "Energy Efficient
//!   Ethernet", "Low Power Idle", "802.3az", or "LPI" in the
//!   full text, and its implemented-spec list cites IEEE
//!   802.3-2005 (which predates 802.3az). The 82599 MAC has
//!   no EEE/LPI registers; any EEE would be external-PHY
//!   via MDIO Clause 45. Auto-neg is Clause 73 / Clause 37
//!   only.
//! - X540: no MAC EEE registers found, and Intel ARK lists
//!   "Intel® Ethernet Power Management: No" for the X540.
//! - X550: the EEE register block (EEER, EEE_SU, EEE_STAT,
//!   TLPIC, RLPIC) IS datasheet-grounded — X550 Datasheet
//!   rev. 2.7 (333369-009) §5.3.6 + Table 8-26 — and lives
//!   in `regs.rs`. BUT the X550 Specification Update (rev
//!   2.9) errata-disables it: "Energy Efficient Ethernet
//!   (EEE) is not enabled in the X550. The X550 does not
//!   negotiate to or transition to EEE mode with a
//!   EEE-capable link partner." The registers are the
//!   control/status surface (readable); the live EEE paths
//!   are the FW-PHY and ACI transports, exactly as Linux
//!   does them. FORCE_TLPI has no defined bit position —
//!   it appears only in §5.3.6.1 prose — so it is never
//!   programmed.
//! - The host-interface flow (§10.5.3.3 / X550 §11.8.2.1),
//!   command structure, checksum rule (§10.5.3.7), and the
//!   HICR bit table (§8.2.2.20.5) are datasheet-grounded
//!   and implemented in `hic.rs`.
//! - ⚠️ The FW-PHY activity constants, the ACI register
//!   addresses/opcodes/descriptor layout, and the SWSM /
//!   SW_FW_SYNC semaphore addresses remain
//!   Linux-transcribed (no public X550EM_A / E610
//!   datasheet); each is labeled where it is defined.
//!
//! The central Linux fact this module mirrors: ixgbe EEE has NO
//! MAC register programming. There is no EEER/LPI register block
//! in Linux ixgbe (the `IXGBE_MDIO_AUTO_NEG_EEE_ADVT` constant
//! is defined but never referenced anywhere in the tree), and
//! `ixgbe_get_eee` returns `-EOPNOTSUPP` unless the device is
//! EEE-capable AND its PHY is firmware-controlled. EEE lives in
//! two transports, both implemented in this lane:
//!
//! - FW-PHY (X550EM_A 1G_T): link-partner EEE advertisement is
//!   read back through a firmware PHY activity (`FW_PHY_ACT_UD_2`,
//!   host-interface command with 4 data words), and the
//!   advertised speeds are re-applied at link setup through the
//!   `FW_PHY_ACT_SETUP_LINK_EEE` flag. The X550 FW-PHY defaults
//!   are 100M + 1G, supported and advertised.
//! - ACI (E610): `setup_eee` reads PHY caps, copies them into a
//!   set-PHY-config command with LINK + AUTO_LINK_UPDT, sets the
//!   EEE-capability bits for the advertised speeds, and issues
//!   the command. E610 EEE covers only speeds above 1G.
//!
//! What this module implements, completely and
//! fixture-tested: the control/status model Linux owns in
//! software — the speed sets, the capability gate (exactly
//! Linux's device switch), the enable/disable semantics
//! (advertised = supported, or 0), the validation rules
//! (`validate_keee`: TX-LPI enable/timer and the advertised set
//! are NOT independently settable; only the enabled flag moves),
//! the FW-PHY link-partner decode, and the ACI capability-word
//! computation — plus the live transports (`hic.rs`, `aci.rs`)
//! and the live flows below (`configure_fw_phy`,
//! `status_fw_phy`, `configure_e610`, `status_e610`), which
//! `Ixgbe::configure_eee` / `Ixgbe::eee_status_live` wrap.
//! Live link re-application after a set is the setup-link
//! activity itself (FW-PHY) / set_phy_cfg + restart-AN (ACI);
//! Linux additionally resets the link, which this driver does
//! not do — the reset is a vehicle, not an extra EEE step.
//! The X550 MAC LPI status surface (`lpi_status_read`) is a
//! read-only observation path, gated to the X550 DID whose
//! datasheet defines the block.

use super::aci;
use super::hic;
use super::queues::RegBank;
use super::regs;

/// Link-speed bits, Linux `IXGBE_LINK_SPEED_*` values
/// (`ixgbe_type.h`).
pub const EEE_SPEED_10M: u32 = 0x0002;
pub const EEE_SPEED_100M: u32 = 0x0008;
pub const EEE_SPEED_1G: u32 = 0x0020;
pub const EEE_SPEED_10G: u32 = 0x0080;
pub const EEE_SPEED_2_5G: u32 = 0x0400;
pub const EEE_SPEED_5G: u32 = 0x0800;

/// Device ids Linux marks EEE-capable (`ixgbe_main.c`
/// `ixgbe_set_eee_capable`). Note the in-tree X550EM_X (0x15AB)
/// is a DIFFERENT part from X550EM_A_1G_T (0x15E4) and is NOT
/// in this set.
pub const DEV_X550EM_A_1G_T: u16 = 0x15E4;
pub const DEV_X550EM_A_1G_T_L: u16 = 0x15E5;
pub const DEV_E610_BACKPLANE: u16 = 0x57AE;
pub const DEV_E610_SFP: u16 = 0x57AF;
pub const DEV_E610_10G_T: u16 = 0x57B0;
pub const DEV_E610_2_5G_T: u16 = 0x57B1;

/// FW-PHY activity ids (`ixgbe_type.h`).
pub const FW_PHY_ACT_UD_2: u16 = 0x1002;
/// Flag on the setup-link activity carrying EEE (`ixgbe_type.h`).
pub const FW_PHY_ACT_SETUP_LINK_EEE: u32 = 1 << 20;

/// FW-PHY UD_2 link-partner EEE bits (`ixgbe_type.h`).
pub const UD_2_100M_TX_EEE: u32 = 1 << 1;
pub const UD_2_1G_T_EEE: u32 = 1 << 2;
pub const UD_2_10G_T_EEE: u32 = 1 << 3;
pub const UD_2_1G_KX_EEE: u32 = 1 << 4;
pub const UD_2_10G_KX4_EEE: u32 = 1 << 5;
pub const UD_2_10G_KR_EEE: u32 = 1 << 6;

/// ACI EEE-capability bits (`ixgbe_type_e610.h`). Note the
/// E610 setup path maps only 2.5G/5G/10G advertised speeds;
/// 100M/1G advertised speeds set no bit.
pub const ACI_EEE_EN_100BASE_TX: u16 = 1 << 0;
pub const ACI_EEE_EN_1000BASE_T: u16 = 1 << 1;
pub const ACI_EEE_EN_10GBASE_T: u16 = 1 << 2;
pub const ACI_EEE_EN_5GBASE_T: u16 = 1 << 11;
pub const ACI_EEE_EN_2_5GBASE_T: u16 = 1 << 12;
/// ACI set-PHY-config flags `setup_eee` always sets
/// (`ixgbe_type_e610.h`).
pub const ACI_PHY_ENA_LINK: u16 = 1 << 3;
pub const ACI_PHY_ENA_AUTO_LINK_UPDT: u16 = 1 << 5;

/// FW-PHY activity ids (`ixgbe_type.h`). All
/// Linux-transcribed.
pub const FW_PHY_ACT_SETUP_LINK: u16 = 2;
pub const FW_PHY_ACT_GET_LINK_INFO: u16 = 3;
pub const FW_PHY_ACT_GET_PHY_INFO: u16 = 7;

/// Setup-link data word (`ixgbe_type.h` /
/// `ixgbe_x550.c` `ixgbe_setup_fw_link`).
/// Pause field shift (pause values below).
pub const FW_PHY_ACT_SETUP_LINK_PAUSE_SHIFT: u32 = 16;
pub const FW_PHY_ACT_SETUP_LINK_PAUSE_NONE: u32 = 0;
pub const FW_PHY_ACT_SETUP_LINK_PAUSE_TX: u32 = 1;
pub const FW_PHY_ACT_SETUP_LINK_PAUSE_RX: u32 = 2;
pub const FW_PHY_ACT_SETUP_LINK_PAUSE_RXTX: u32 = 3;
/// High-power + autoneg bits: always set by Linux's
/// setup-link.
pub const FW_PHY_ACT_SETUP_LINK_HP: u32 = 1 << 19;
pub const FW_PHY_ACT_SETUP_LINK_AN: u32 = 1 << 22;
/// Response word0 meaning "link down"
/// (`ixgbe_type.h` FW_PHY_ACT_SETUP_LINK_RSP_DOWN).
pub const FW_PHY_ACT_SETUP_LINK_RSP_DOWN: u32 = 1 << 0;

/// GET_LINK_INFO info[0] bits (`ixgbe_type.h`).
pub const FW_PHY_ACT_GET_LINK_INFO_EEE: u32 = 1 << 19;
pub const FW_PHY_ACT_GET_LINK_INFO_FC_TX: u32 = 1 << 20;
pub const FW_PHY_ACT_GET_LINK_INFO_FC_RX: u32 = 1 << 21;
pub const FW_PHY_ACT_GET_LINK_INFO_POWER: u32 = 1 << 22;
pub const FW_PHY_ACT_GET_LINK_INFO_AN_COMPLETE: u32 = 1 << 24;
pub const FW_PHY_ACT_GET_LINK_INFO_LP_FC_TX: u32 = 1 << 28;
pub const FW_PHY_ACT_GET_LINK_INFO_LP_FC_RX: u32 = 1 << 29;

/// GET_PHY_INFO info-word masks (`ixgbe_type.h`).
/// info[0] bits [11:0] are the FW speed bits; bits
/// [31:16] are the PHY id high half; info[1] bits
/// [15:0] are the PHY id low half.
pub const FW_PHY_INFO_SPEED_MASK: u32 = 0xFFF;
pub const FW_PHY_INFO_ID_HI_MASK: u32 = 0xFFFF_0000;
pub const FW_PHY_INFO_ID_LO_MASK: u32 = 0x0000_FFFF;
/// PHY id revision mask (`ixgbe_type.h`
/// IXGBE_PHY_REVISION_MASK).
pub const PHY_REVISION_MASK: u32 = 0xFFFF_FFF0;

/// FW speed bits, in `ixgbe_fw_map` order
/// (`ixgbe_type.h` FW_PHY_ACT_LINK_SPEED_*): the bit
/// positions the firmware uses in the speeds mask and
/// the setup-link word.
pub const FW_LINK_SPEED_10: u32 = 1 << 0;
pub const FW_LINK_SPEED_100: u32 = 1 << 1;
pub const FW_LINK_SPEED_1G: u32 = 1 << 2;
pub const FW_LINK_SPEED_2_5G: u32 = 1 << 3;
pub const FW_LINK_SPEED_5G: u32 = 1 << 4;
pub const FW_LINK_SPEED_10G: u32 = 1 << 5;

/// Map one `EEE_SPEED_*` link-speed bit to its FW speed
/// bit (`ixgbe_fw_map`); unknown bits map to 0.
pub fn fw_speed_bit(link_speed: u32) -> u32 {
    match link_speed {
        EEE_SPEED_10M => FW_LINK_SPEED_10,
        EEE_SPEED_100M => FW_LINK_SPEED_100,
        EEE_SPEED_1G => FW_LINK_SPEED_1G,
        EEE_SPEED_2_5G => FW_LINK_SPEED_2_5G,
        EEE_SPEED_5G => FW_LINK_SPEED_5G,
        EEE_SPEED_10G => FW_LINK_SPEED_10G,
        _ => 0,
    }
}

/// Map a FW speeds mask to the `EEE_SPEED_*` set
/// (`ixgbe_fw_map` in reverse).
pub fn link_speeds_from_fw(fw_bits: u32) -> EeeSpeeds {
    let mut speeds = 0u32;
    if fw_bits & FW_LINK_SPEED_10 != 0 {
        speeds |= EEE_SPEED_10M;
    }
    if fw_bits & FW_LINK_SPEED_100 != 0 {
        speeds |= EEE_SPEED_100M;
    }
    if fw_bits & FW_LINK_SPEED_1G != 0 {
        speeds |= EEE_SPEED_1G;
    }
    if fw_bits & FW_LINK_SPEED_2_5G != 0 {
        speeds |= EEE_SPEED_2_5G;
    }
    if fw_bits & FW_LINK_SPEED_5G != 0 {
        speeds |= EEE_SPEED_5G;
    }
    if fw_bits & FW_LINK_SPEED_10G != 0 {
        speeds |= EEE_SPEED_10G;
    }
    EeeSpeeds(speeds)
}

/// Map a `EEE_SPEED_*` set to its FW speed bits.
pub fn fw_speed_bits(speeds: EeeSpeeds) -> u32 {
    let mut bits = 0u32;
    for speed in [
        EEE_SPEED_10M,
        EEE_SPEED_100M,
        EEE_SPEED_1G,
        EEE_SPEED_2_5G,
        EEE_SPEED_5G,
        EEE_SPEED_10G,
    ] {
        if speeds.contains(speed) {
            bits |= fw_speed_bit(speed);
        }
    }
    bits
}

/// The FW-PHY identification result (Linux
/// `ixgbe_get_phy_id_fw`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PhyInfo {
    /// Speeds the PHY supports (FW mask → link speeds).
    pub speeds_supported: EeeSpeeds,
    /// Autoneg-advertised speeds: Linux sets these equal
    /// to the supported speeds at identification.
    pub autoneg_advertised: EeeSpeeds,
    /// PHY id (high half from info[0], low half masked by
    /// the revision mask from info[1]).
    pub phy_id: u32,
}

/// Decode a GET_PHY_INFO response (Linux
/// `ixgbe_get_phy_id_fw`): speeds from info[0] &
/// `FW_PHY_INFO_SPEED_MASK` through the fw map, id from
/// the two halves. The EEE speeds are NOT decoded here:
/// Linux hardcodes them to 100M|1G for this PHY.
pub fn phy_info_decode(info: [u32; 4]) -> PhyInfo {
    let speeds = link_speeds_from_fw(info[0] & FW_PHY_INFO_SPEED_MASK);
    let phy_id =
        (info[0] & FW_PHY_INFO_ID_HI_MASK) | (info[1] & FW_PHY_INFO_ID_LO_MASK & PHY_REVISION_MASK);
    PhyInfo {
        speeds_supported: speeds,
        autoneg_advertised: speeds,
        phy_id,
    }
}

/// Pause mode from a GET_LINK_INFO info[0] word
/// (FC_TX / FC_RX bits → the setup-link pause values).
pub fn pause_from_link_info(info0: u32) -> u32 {
    let tx = info0 & FW_PHY_ACT_GET_LINK_INFO_FC_TX != 0;
    let rx = info0 & FW_PHY_ACT_GET_LINK_INFO_FC_RX != 0;
    match (tx, rx) {
        (true, true) => FW_PHY_ACT_SETUP_LINK_PAUSE_RXTX,
        (true, false) => FW_PHY_ACT_SETUP_LINK_PAUSE_TX,
        (false, true) => FW_PHY_ACT_SETUP_LINK_PAUSE_RX,
        (false, false) => FW_PHY_ACT_SETUP_LINK_PAUSE_NONE,
    }
}

/// Build the setup-link data words (Linux
/// `ixgbe_setup_fw_link`): pause << 16, the FW bits of
/// the autoneg-advertised speeds, HP + AN always, and the
/// EEE flag iff the EEE advertised set is non-empty.
/// Words 1–3 are zero.
pub fn setup_link_data(advertised_eee: EeeSpeeds, pause: u32, autoneg: EeeSpeeds) -> [u32; 4] {
    let mut word0 = (pause & 0x3) << FW_PHY_ACT_SETUP_LINK_PAUSE_SHIFT;
    word0 |= fw_speed_bits(autoneg);
    word0 |= FW_PHY_ACT_SETUP_LINK_HP | FW_PHY_ACT_SETUP_LINK_AN;
    if !advertised_eee.is_empty() {
        word0 |= FW_PHY_ACT_SETUP_LINK_EEE;
    }
    [word0, 0, 0, 0]
}

/// True when a setup-link response word0 is the
/// link-down response (Linux compares for equality with
/// `FW_PHY_ACT_SETUP_LINK_RSP_DOWN`, not just the bit).
pub fn setup_link_is_down(response_word0: u32) -> bool {
    response_word0 == FW_PHY_ACT_SETUP_LINK_RSP_DOWN
}

/// A set of EEE link speeds, as Linux `phy.eee_speeds_*` words.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EeeSpeeds(pub u32);

impl EeeSpeeds {
    /// No speeds.
    pub const EMPTY: Self = Self(0);

    /// True when the set is empty.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// True when `speed` (one of the `EEE_SPEED_*` bits) is set.
    pub fn contains(self, speed: u32) -> bool {
        self.0 & speed != 0
    }

    /// Union of two sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersection of two sets.
    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// Link-partner EEE modes, decoded from the FW-PHY UD_2 word.
/// These are NARF-local mode flags (bit positions are ours, not
/// wire values); the UD_2 wire bits are the `UD_2_*` constants.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LpModes(pub u32);

impl LpModes {
    /// No modes.
    pub const EMPTY: Self = Self(0);

    /// True when the set is empty.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// True when `mode` (one of the `LP_*` bits) is set.
    pub fn contains(self, mode: u32) -> bool {
        self.0 & mode != 0
    }
}

/// Link-partner mode flags (NARF-local numbering).
pub const LP_100BASE_T: u32 = 1 << 0;
pub const LP_1000BASE_T: u32 = 1 << 1;
pub const LP_10000BASE_T: u32 = 1 << 2;
pub const LP_1000BASE_KX: u32 = 1 << 3;
pub const LP_10000BASE_KX4: u32 = 1 << 4;
pub const LP_10000BASE_KR: u32 = 1 << 5;

/// Decode the FW-PHY UD_2 info word into link-partner modes
/// (Linux `ixgbe_lp_map`, `ixgbe_get_eee_fw`).
pub fn lp_modes_from_ud2(info0: u32) -> LpModes {
    let mut modes = 0u32;
    if info0 & UD_2_100M_TX_EEE != 0 {
        modes |= LP_100BASE_T;
    }
    if info0 & UD_2_1G_T_EEE != 0 {
        modes |= LP_1000BASE_T;
    }
    if info0 & UD_2_10G_T_EEE != 0 {
        modes |= LP_10000BASE_T;
    }
    if info0 & UD_2_1G_KX_EEE != 0 {
        modes |= LP_1000BASE_KX;
    }
    if info0 & UD_2_10G_KX4_EEE != 0 {
        modes |= LP_10000BASE_KX4;
    }
    if info0 & UD_2_10G_KR_EEE != 0 {
        modes |= LP_10000BASE_KR;
    }
    LpModes(modes)
}

/// Link-speed set → ethtool mode names, in Linux `ixgbe_ls_map`
/// order (10/100/1000/2500/5000/10000).
pub fn speed_mode_names(speeds: EeeSpeeds) -> alloc::vec::Vec<&'static str> {
    let mut names = alloc::vec::Vec::new();
    if speeds.contains(EEE_SPEED_10M) {
        names.push("10baseT");
    }
    if speeds.contains(EEE_SPEED_100M) {
        names.push("100baseT");
    }
    if speeds.contains(EEE_SPEED_1G) {
        names.push("1000baseT");
    }
    if speeds.contains(EEE_SPEED_2_5G) {
        names.push("2500baseT");
    }
    if speeds.contains(EEE_SPEED_5G) {
        names.push("5000baseT");
    }
    if speeds.contains(EEE_SPEED_10G) {
        names.push("10000baseT");
    }
    names
}

/// Link-partner mode set → ethtool mode names, in Linux
/// `ixgbe_lp_map` order.
pub fn lp_mode_names(modes: LpModes) -> alloc::vec::Vec<&'static str> {
    let mut names = alloc::vec::Vec::new();
    if modes.contains(LP_100BASE_T) {
        names.push("100baseT");
    }
    if modes.contains(LP_1000BASE_T) {
        names.push("1000baseT");
    }
    if modes.contains(LP_10000BASE_T) {
        names.push("10000baseT");
    }
    if modes.contains(LP_1000BASE_KX) {
        names.push("1000baseKX");
    }
    if modes.contains(LP_10000BASE_KX4) {
        names.push("10000baseKX4");
    }
    if modes.contains(LP_10000BASE_KR) {
        names.push("10000baseKR");
    }
    names
}

/// Exactly Linux's `ixgbe_set_eee_capable` device switch: only
/// the X550EM_A 1G_T parts and the E610 parts are EEE-capable.
/// Every in-tree device id (82599EB, X540, X550, X550EM_X)
/// returns false here — matching Linux's `-EOPNOTSUPP` for
/// those parts.
pub fn eee_capable(did: u16) -> bool {
    matches!(
        did,
        DEV_X550EM_A_1G_T
            | DEV_X550EM_A_1G_T_L
            | DEV_E610_BACKPLANE
            | DEV_E610_SFP
            | DEV_E610_10G_T
            | DEV_E610_2_5G_T
    )
}

/// True when `did` is one of the E610 parts (ACI transport).
pub fn is_e610(did: u16) -> bool {
    matches!(
        did,
        DEV_E610_BACKPLANE | DEV_E610_SFP | DEV_E610_10G_T | DEV_E610_2_5G_T
    )
}

/// X550 FW-PHY defaults (`ixgbe_x550.c`): 100M + 1G, supported
/// and advertised.
pub fn x550em_a_defaults() -> (EeeSpeeds, EeeSpeeds) {
    let speeds = EeeSpeeds(EEE_SPEED_100M | EEE_SPEED_1G);
    (speeds, speeds)
}

/// E610 defaults (`ixgbe_e610.c`): the 2.5G_T part supports
/// only 2.5G; every other E610 part supports 2.5G + 5G + 10G.
/// EEE covers only speeds above 1G on E610. Returns
/// (supported, advertised); advertised starts at supported.
pub fn e610_defaults(is_2_5g_t: bool) -> (EeeSpeeds, EeeSpeeds) {
    let speeds = if is_2_5g_t {
        EeeSpeeds(EEE_SPEED_2_5G)
    } else {
        EeeSpeeds(EEE_SPEED_2_5G | EEE_SPEED_5G | EEE_SPEED_10G)
    };
    (speeds, speeds)
}

/// ACI EEE-capability word for an advertised set, exactly
/// Linux `ixgbe_setup_eee_e610`'s mapping: 2.5G → BIT(12),
/// 5G → BIT(11), 10G → BIT(2). 100M/1G advertised speeds set
/// no bit (E610 EEE never covers them).
pub fn aci_eee_cap(advertised: EeeSpeeds) -> u16 {
    let mut cap = 0u16;
    if advertised.contains(EEE_SPEED_2_5G) {
        cap |= ACI_EEE_EN_2_5GBASE_T;
    }
    if advertised.contains(EEE_SPEED_5G) {
        cap |= ACI_EEE_EN_5GBASE_T;
    }
    if advertised.contains(EEE_SPEED_10G) {
        cap |= ACI_EEE_EN_10GBASE_T;
    }
    cap
}

/// The EEE control/status state for one device, mirroring
/// Linux `phy.eee_speeds_*` + the `ethtool_keee` fields
/// `get_eee` reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EeeState {
    /// Speeds the hardware can do EEE on.
    pub supported: EeeSpeeds,
    /// Speeds currently advertised (empty when disabled).
    pub advertised: EeeSpeeds,
    /// Link-partner advertised modes (FW-PHY UD_2 decode;
    /// empty until a FW query populates it).
    pub lp_advertised: LpModes,
    /// TX LPI timer as `get_eee` reports it. Linux's FW path
    /// leaves it 0; the E610 path reports the firmware EEE
    /// entry delay when enabled. It is never independently
    /// settable (see `validate_request`).
    pub tx_lpi_timer: u32,
    /// Firmware-reported EEE-active bit, when the transport
    /// provides one. `None` (the FW-PHY path) means
    /// `active()` is computed from advertised ∩
    /// link-partner; `Some(b)` (the ACI path) means the
    /// firmware's get_link_info eee_status ACTIVE bit is
    /// the answer — the ACI path has no link-partner modes
    /// to intersect, and 2.5G/5G have no UD_2 partner bits
    /// at all, so the computation cannot reproduce it.
    pub fw_active: Option<bool>,
}

impl EeeState {
    /// Fresh state from a supported/advertised pair, link
    /// partner unknown, timer 0, no firmware active bit.
    pub fn new(supported: EeeSpeeds, advertised: EeeSpeeds) -> Self {
        Self {
            supported,
            advertised,
            lp_advertised: LpModes::EMPTY,
            tx_lpi_timer: 0,
            fw_active: None,
        }
    }

    /// `eee_enabled`: non-empty advertised set
    /// (`ixgbe_get_eee_fw`).
    pub fn enabled(self) -> bool {
        !self.advertised.is_empty()
    }

    /// `tx_lpi_enabled`: Linux always reports it equal to
    /// `eee_enabled`.
    pub fn tx_lpi_enabled(self) -> bool {
        self.enabled()
    }

    /// `eee_active`: the firmware-reported bit when the
    /// transport provides one (`fw_active`), else
    /// advertised ∩ link-partner non-empty, over link
    /// modes (`ixgbe_get_eee_fw`). Only the T speeds can
    /// intersect: 100M ↔ 100baseT, 1G ↔ 1000baseT,
    /// 10G ↔ 10000baseT. 2.5G/5G have no UD_2 partner bits,
    /// and KX/KR partner modes never match a T advertisement.
    pub fn active(self) -> bool {
        if let Some(fw) = self.fw_active {
            return fw;
        }
        (self.advertised.contains(EEE_SPEED_100M) && self.lp_advertised.contains(LP_100BASE_T))
            || (self.advertised.contains(EEE_SPEED_1G)
                && self.lp_advertised.contains(LP_1000BASE_T))
            || (self.advertised.contains(EEE_SPEED_10G)
                && self.lp_advertised.contains(LP_10000BASE_T))
    }

    /// Apply Linux `set_eee`'s enable semantics: enabled →
    /// advertised = supported; disabled → advertised = empty.
    /// This changes only the modeled set. The live flows
    /// (`configure_fw_phy` / `configure_e610`) re-apply the
    /// advertised set to the firmware right after calling
    /// this; this method alone does not touch hardware.
    pub fn set_enabled(&mut self, enable: bool) {
        self.advertised = if enable {
            self.supported
        } else {
            EeeSpeeds::EMPTY
        };
    }
}

/// The ethtool-visible EEE snapshot (`ETHTOOL_GEEE` fields).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EeeStatus {
    /// Speeds the hardware can do EEE on.
    pub supported: EeeSpeeds,
    /// Speeds currently advertised.
    pub advertised: EeeSpeeds,
    /// Link-partner advertised modes.
    pub lp_advertised: LpModes,
    /// Whether EEE is enabled (advertised non-empty).
    pub enabled: bool,
    /// Whether TX LPI is enabled (always == enabled).
    pub tx_lpi_enabled: bool,
    /// TX LPI timer as reported.
    pub tx_lpi_timer: u32,
    /// Whether EEE is active (advertised ∩ partner non-empty).
    pub active: bool,
}

impl From<EeeState> for EeeStatus {
    fn from(state: EeeState) -> Self {
        Self {
            supported: state.supported,
            advertised: state.advertised,
            lp_advertised: state.lp_advertised,
            enabled: state.enabled(),
            tx_lpi_enabled: state.tx_lpi_enabled(),
            tx_lpi_timer: state.tx_lpi_timer,
            active: state.active(),
        }
    }
}

/// A set-EEE request, mirroring `ethtool_keee` fields
/// `validate_keee` inspects.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EeeRequest {
    /// Desired enabled flag (the only field that may move).
    pub enabled: bool,
    /// Must equal the stored TX-LPI flag.
    pub tx_lpi_enabled: bool,
    /// Must equal the stored TX-LPI timer.
    pub tx_lpi_timer: u32,
    /// Must equal the stored advertised set.
    pub advertised: EeeSpeeds,
}

/// `validate_keee` failure modes, in Linux's check order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EeeError {
    /// Device is not EEE-capable (`-EOPNOTSUPP`).
    NotCapable,
    /// TX-LPI enable differs from stored (`-EINVAL`).
    TxLpiMismatch,
    /// TX-LPI timer differs from stored (`-EINVAL`).
    TxLpiTimerMismatch,
    /// Advertised set differs from stored (`-EINVAL`).
    AdvertisedMismatch,
    /// Enabled flag already equals stored (`-EALREADY`,
    /// converted to success by the caller).
    AlreadyEnabled,
}

/// Mirror Linux `ixgbe_validate_keee`, in its check order:
/// capability → TX-LPI enable → TX-LPI timer → advertised
/// set → already-enabled. The only request that passes is
/// one that changes nothing except the enabled flag.
pub fn validate_request(
    capable: bool,
    stored: &EeeState,
    req: &EeeRequest,
) -> Result<(), EeeError> {
    if !capable {
        return Err(EeeError::NotCapable);
    }
    if stored.tx_lpi_enabled() != req.tx_lpi_enabled {
        return Err(EeeError::TxLpiMismatch);
    }
    if stored.tx_lpi_timer != req.tx_lpi_timer {
        return Err(EeeError::TxLpiTimerMismatch);
    }
    if stored.advertised != req.advertised {
        return Err(EeeError::AdvertisedMismatch);
    }
    if stored.enabled() == req.enabled {
        return Err(EeeError::AlreadyEnabled);
    }
    Ok(())
}

// ── Live flows (RegBank-generic; `Ixgbe` wraps these) ───────────────

/// Live-flow failures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EeeLiveError {
    /// A host-interface transport failure.
    Hic(hic::HicError),
    /// An ACI transport failure.
    Aci(aci::AciError),
    /// The firmware reports the part cannot do EEE: an
    /// invalid PHY id on the FW-PHY path, or no EEE
    /// support in the E610 device capabilities.
    NotCapable,
}

impl From<hic::HicError> for EeeLiveError {
    fn from(e: hic::HicError) -> Self {
        EeeLiveError::Hic(e)
    }
}

impl From<aci::AciError> for EeeLiveError {
    fn from(e: aci::AciError) -> Self {
        EeeLiveError::Aci(e)
    }
}

impl EeeLiveError {
    /// Static message for the `IxgbeError::Other` mapping.
    pub fn as_str(self) -> &'static str {
        match self {
            EeeLiveError::Hic(e) => e.as_str(),
            EeeLiveError::Aci(e) => e.as_str(),
            EeeLiveError::NotCapable => "eee not capable",
        }
    }
}

/// HIC command deadline (Linux `IXGBE_HI_COMMAND_TIMEOUT`:
/// 500 ms — the datasheet's "within half a second").
fn hic_deadline() -> narf_time::Deadline {
    narf_time::Deadline::after_ms(500)
}

/// ACI sync-phase deadline: a NARF wedge threshold (see
/// `aci.rs`; Linux polls up to 100 s).
fn aci_sync_deadline() -> narf_time::Deadline {
    narf_time::Deadline::after_ms(10_000)
}

/// ACI async-phase deadline: a NARF wedge threshold (see
/// `aci.rs`; Linux polls up to 150 s).
fn aci_async_deadline() -> narf_time::Deadline {
    narf_time::Deadline::after_ms(30_000)
}

/// Configure EEE on a FW-PHY part (X550EM_A 1G_T/L;
/// Linux `ixgbe_set_eee` + `ixgbe_setup_fw_link` +
/// `ixgbe_get_phy_id_fw`): identify the PHY for the
/// autoneg set, model the enable, preserve the current
/// pause mode from GET_LINK_INFO (falling back to NONE
/// when the link is down or the query fails — Linux's set
/// does not require the link to be up), and re-apply with
/// the setup-link activity carrying the EEE flag. The
/// setup-link activity IS the re-application: Linux
/// additionally resets the link, which this driver does
/// not do — the reset is a vehicle, not an extra EEE step.
pub fn configure_fw_phy<B: RegBank>(
    bank: &mut B,
    lan_id: u8,
    enable: bool,
) -> Result<EeeState, EeeLiveError> {
    let info = hic::fw_phy_activity(
        bank,
        lan_id,
        FW_PHY_ACT_GET_PHY_INFO,
        [0; 4],
        true,
        hic_deadline(),
    )?;
    let phy = phy_info_decode(info);
    if phy.phy_id == 0 || phy.phy_id == PHY_REVISION_MASK {
        return Err(EeeLiveError::NotCapable);
    }
    let (supported, advertised) = x550em_a_defaults();
    let mut state = EeeState::new(supported, advertised);
    state.set_enabled(enable);
    let pause = match hic::fw_phy_activity(
        bank,
        lan_id,
        FW_PHY_ACT_GET_LINK_INFO,
        [0; 4],
        true,
        hic_deadline(),
    ) {
        Ok(link) => pause_from_link_info(link[0]),
        Err(_) => FW_PHY_ACT_SETUP_LINK_PAUSE_NONE,
    };
    let data = setup_link_data(state.advertised, pause, phy.autoneg_advertised);
    let resp = hic::fw_phy_activity(
        bank,
        lan_id,
        FW_PHY_ACT_SETUP_LINK,
        data,
        true,
        hic_deadline(),
    )?;
    if setup_link_is_down(resp[0]) {
        return Err(EeeLiveError::Hic(hic::HicError::ActivityFailed));
    }
    Ok(state)
}

/// Query the live EEE status on a FW-PHY part (Linux
/// `ixgbe_get_eee_fw`): start from the stored state, or
/// from identification defaults when nothing was ever
/// configured, then refresh the link-partner modes from
/// the UD_2 activity. The TX-LPI timer stays 0 on this
/// path, as in Linux.
pub fn status_fw_phy<B: RegBank>(
    bank: &mut B,
    lan_id: u8,
    stored: Option<EeeState>,
) -> Result<EeeState, EeeLiveError> {
    let mut state = match stored {
        Some(s) => s,
        None => {
            let info = hic::fw_phy_activity(
                bank,
                lan_id,
                FW_PHY_ACT_GET_PHY_INFO,
                [0; 4],
                true,
                hic_deadline(),
            )?;
            let phy = phy_info_decode(info);
            if phy.phy_id == 0 || phy.phy_id == PHY_REVISION_MASK {
                return Err(EeeLiveError::NotCapable);
            }
            let (supported, advertised) = x550em_a_defaults();
            EeeState::new(supported, advertised)
        }
    };
    let ud2 = hic::fw_phy_activity(bank, lan_id, FW_PHY_ACT_UD_2, [0; 4], true, hic_deadline())?;
    state.lp_advertised = lp_modes_from_ud2(ud2[0]);
    state.fw_active = None;
    Ok(state)
}

/// Configure EEE on an E610 part (Linux
/// `ixgbe_set_eee_e610` + `ixgbe_setup_eee_e610`): the
/// firmware must report EEE support in the device
/// capabilities (`caps_buf` must hold
/// `aci::ACI_MAX_BUFFER_SIZE` bytes), then get_phy_caps
/// (ACTIVE_CFG) is copied into set_phy_cfg with LINK +
/// AUTO_LINK_UPDT and the EEE-capability bits for the
/// advertised speeds, and autoneg is restarted with the
/// link enabled — the restart is the re-application
/// (Linux does it via reset/reinit; this module issues
/// the restart directly). The TX-LPI timer is the
/// firmware EEE entry delay when enabled.
pub fn configure_e610<B: RegBank>(
    bank: &mut B,
    lan_id: u8,
    did: u16,
    enable: bool,
    caps_buf: &mut [u8],
) -> Result<EeeState, EeeLiveError> {
    let eee_support =
        aci::find_dev_cap_eee(bank, caps_buf, aci_sync_deadline(), aci_async_deadline())?;
    if !eee_support {
        return Err(EeeLiveError::NotCapable);
    }
    let (supported, advertised) = e610_defaults(did == DEV_E610_2_5G_T);
    let mut state = EeeState::new(supported, advertised);
    state.set_enabled(enable);
    let mut pcaps_buf = [0u8; aci::PHY_CAPS_DATA_LEN];
    let mut desc = aci::get_phy_caps_desc(false, aci::ACI_REPORT_ACTIVE_CFG);
    let mut caps_wrapper = aci::AciBuf {
        data: &mut pcaps_buf,
        len: aci::PHY_CAPS_DATA_LEN,
        host_to_fw: false,
    };
    aci::aci_send_cmd(
        bank,
        &mut desc,
        Some(&mut caps_wrapper),
        aci_sync_deadline(),
        aci_async_deadline(),
    )?;
    let pcaps = aci::parse_phy_caps(&pcaps_buf)?;
    // The capability gate above already required
    // eee_support, so the full 26-byte buffer (with the
    // trailing eee_entry_delay field) is always used.
    let mut cfg_buf = aci::build_set_phy_cfg(
        &pcaps,
        (aci::ACI_PHY_ENA_LINK | aci::ACI_PHY_ENA_AUTO_LINK_UPDT) as u8,
        aci_eee_cap(state.advertised),
        true,
    );
    let mut set_desc = aci::set_phy_cfg_desc(lan_id);
    let mut set_wrapper = aci::AciBuf {
        data: &mut cfg_buf,
        len: aci::SET_PHY_CFG_DATA_LEN,
        host_to_fw: true,
    };
    aci::aci_send_cmd(
        bank,
        &mut set_desc,
        Some(&mut set_wrapper),
        aci_sync_deadline(),
        aci_async_deadline(),
    )?;
    let mut an_desc = aci::restart_an_desc(true, lan_id);
    aci::aci_send_cmd(
        bank,
        &mut an_desc,
        None,
        aci_sync_deadline(),
        aci_async_deadline(),
    )?;
    state.tx_lpi_timer = if enable {
        pcaps.eee_entry_delay as u32
    } else {
        0
    };
    state.fw_active = None;
    Ok(state)
}

/// Query the live EEE status on an E610 part (Linux
/// `ixgbe_get_eee_e610`): get_link_info (LSE_DIS — no
/// event subscription) gives the firmware's enabled and
/// active bits; the model is synced to the enabled bit
/// (an out-of-band disable clears the advertised set, an
/// out-of-band enable restores it), the active bit is
/// stored as `fw_active`, and the TX-LPI timer is the
/// entry delay from the active PHY caps when enabled.
pub fn status_e610<B: RegBank>(
    bank: &mut B,
    lan_id: u8,
    did: u16,
    stored: Option<EeeState>,
) -> Result<EeeState, EeeLiveError> {
    let mut state = match stored {
        Some(s) => s,
        None => {
            let (supported, advertised) = e610_defaults(did == DEV_E610_2_5G_T);
            EeeState::new(supported, advertised)
        }
    };
    let mut link_buf = [0u8; aci::LINK_STATUS_DATA_LEN];
    let mut desc = aci::get_link_status_desc(false, lan_id);
    let mut wrapper = aci::AciBuf {
        data: &mut link_buf,
        len: aci::LINK_STATUS_DATA_LEN,
        host_to_fw: false,
    };
    aci::aci_send_cmd(
        bank,
        &mut desc,
        Some(&mut wrapper),
        aci_sync_deadline(),
        aci_async_deadline(),
    )?;
    let link = aci::parse_link_status(&link_buf)?;
    let fw_enabled = link.eee_status & aci::ACI_LINK_EEE_ENABLED != 0;
    let fw_active = link.eee_status & aci::ACI_LINK_EEE_ACTIVE != 0;
    if fw_enabled && state.advertised.is_empty() {
        state.advertised = state.supported;
    } else if !fw_enabled {
        state.advertised = EeeSpeeds::EMPTY;
    }
    state.fw_active = Some(fw_active);
    if fw_enabled {
        let mut pcaps_buf = [0u8; aci::PHY_CAPS_DATA_LEN];
        let mut pdesc = aci::get_phy_caps_desc(false, aci::ACI_REPORT_ACTIVE_CFG);
        let mut pwrap = aci::AciBuf {
            data: &mut pcaps_buf,
            len: aci::PHY_CAPS_DATA_LEN,
            host_to_fw: false,
        };
        aci::aci_send_cmd(
            bank,
            &mut pdesc,
            Some(&mut pwrap),
            aci_sync_deadline(),
            aci_async_deadline(),
        )?;
        let pcaps = aci::parse_phy_caps(&pcaps_buf)?;
        state.tx_lpi_timer = pcaps.eee_entry_delay as u32;
    } else {
        state.tx_lpi_timer = 0;
    }
    Ok(state)
}

// ── X550 MAC LPI observation ─────────────────────────────────────────

/// X550 MAC LPI status (X550 Datasheet rev. 2.7 §5.3.6.5,
/// Table 8-26). The counts are the TLPIC/RLPIC LPI-entry
/// event counters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LpiStatus {
    /// EEE negotiated on the link (EEE_STAT.EEE_NEG).
    pub negotiated: bool,
    /// The partner is in Rx LPI (EEE_STAT.RX_LPI_STATUS).
    pub rx_lpi: bool,
    /// This port is in Tx LPI (EEE_STAT.TX_LPI_STATUS).
    pub tx_lpi: bool,
    /// Tx LPI entry events (TLPIC; read-clear).
    pub tx_lpi_count: u32,
    /// Rx LPI entry events (RLPIC; read-clear).
    pub rx_lpi_count: u32,
}

/// Read the X550 MAC LPI status registers. NOTE:
/// TLPIC/RLPIC are cleared on read, so this call resets
/// both counters. The caller gates on the X550 DID: the
/// block is defined for the X550 by the datasheet, and
/// the spec-update errata disables the feature, so the
/// bits read 0 on X550 silicon — the registers are still
/// the observation surface.
pub fn lpi_status_read<B: RegBank>(bank: &B) -> LpiStatus {
    let stat = bank.read32(regs::REG_EEE_STAT);
    LpiStatus {
        negotiated: stat & regs::EEE_STAT_EEE_NEG != 0,
        rx_lpi: stat & regs::EEE_STAT_RX_LPI_STATUS != 0,
        tx_lpi: stat & regs::EEE_STAT_TX_LPI_STATUS != 0,
        tx_lpi_count: bank.read32(regs::REG_EEE_TLPIC),
        rx_lpi_count: bank.read32(regs::REG_EEE_RLPIC),
    }
}
