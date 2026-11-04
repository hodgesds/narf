//! ixgbe EEE control/status — Linux-faithful model, no MAC registers.
//!
//! Grounding: Linux ixgbe @ cbbddb6 (`ixgbe_ethtool.c`
//! `ixgbe_get_eee` / `ixgbe_set_eee` / `ixgbe_get_eee_fw` /
//! `ixgbe_validate_keee`, `ixgbe_main.c` `ixgbe_set_eee_capable`,
//! `ixgbe_x550.c` FW-PHY identification, `ixgbe_e610.c`
//! `ixgbe_setup_eee_e610`, `ixgbe_type.h` LINK_SPEED bits +
//! FW-PHY activity constants, `ixgbe_type_e610.h` ACI bits).
//!
//! ⚠️ DATASHEET GROUNDING NOT MET. The issue asks for datasheet
//! grounding for EEE control/status, and no 82599/X540/X550
//! datasheet copy exists in this workspace (searched; only an
//! unrelated Intel GPU PDF turned up). Every value below is
//! Linux-transcribed. Re-grounding against the datasheet stays a
//! named follow-up, and the maintainer may bounce this module on
//! that ground alone.
//!
//! The central Linux fact this module mirrors: ixgbe EEE has NO
//! MAC register programming. There is no EEER/LPI register block
//! in Linux ixgbe (the `IXGBE_MDIO_AUTO_NEG_EEE_ADVT` constant
//! is defined but never referenced anywhere in the tree), and
//! `ixgbe_get_eee` returns `-EOPNOTSUPP` unless the device is
//! EEE-capable AND its PHY is firmware-controlled. EEE lives in
//! two transports this driver does not have yet:
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
//! What this module DOES implement, completely and
//! fixture-tested: the control/status model Linux owns in
//! software — the speed sets, the capability gate (exactly
//! Linux's device switch), the enable/disable semantics
//! (advertised = supported, or 0), the validation rules
//! (`validate_keee`: TX-LPI enable/timer and the advertised set
//! are NOT independently settable; only the enabled flag moves),
//! the FW-PHY link-partner decode, and the ACI capability-word
//! computation. What it does NOT implement (follow-ups, stated in
//! the spec §13f): the FW-PHY activity transport, the ACI
//! transport, and live link re-application after a set (Linux
//! resets the link; this driver has no EEE link-reapply hook).
//! Until those transports land, `Ixgbe::configure_eee` returns
//! `UnsupportedDevice` on every in-tree device id — which is
//! exactly Linux's verdict for those parts, not a stub: the
//! capability table below is the reason, and it is tested.

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
}

impl EeeState {
    /// Fresh state from a supported/advertised pair, link
    /// partner unknown, timer 0.
    pub fn new(supported: EeeSpeeds, advertised: EeeSpeeds) -> Self {
        Self {
            supported,
            advertised,
            lp_advertised: LpModes::EMPTY,
            tx_lpi_timer: 0,
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

    /// `eee_active`: advertised ∩ link-partner non-empty, over
    /// link modes (`ixgbe_get_eee_fw`). Only the T speeds can
    /// intersect: 100M ↔ 100baseT, 1G ↔ 1000baseT,
    /// 10G ↔ 10000baseT. 2.5G/5G have no UD_2 partner bits,
    /// and KX/KR partner modes never match a T advertisement.
    pub fn active(self) -> bool {
        (self.advertised.contains(EEE_SPEED_100M) && self.lp_advertised.contains(LP_100BASE_T))
            || (self.advertised.contains(EEE_SPEED_1G)
                && self.lp_advertised.contains(LP_1000BASE_T))
            || (self.advertised.contains(EEE_SPEED_10G)
                && self.lp_advertised.contains(LP_10000BASE_T))
    }

    /// Apply Linux `set_eee`'s enable semantics: enabled →
    /// advertised = supported; disabled → advertised = empty.
    /// This changes only the modeled set. Linux additionally
    /// resets the link so firmware re-applies the advertised
    /// set; that re-application is the caller's job (no EEE
    /// link-reapply hook exists in-tree yet).
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
