// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Signed measured envelope for the exact B cold/calibration recipe. This
//! grants calibration only: neither packet TX nor autonomous ACK/CTS emission.
//!
//! RTL8852C has its own format (magic `N5CB` v1, `rtw8852c-cal-v1-<mac>.bin`)
//! over its own identity ([`Board::new_c`]); a B record never admits C and
//! vice versa. RTL8851B likewise has `N51B` v1 (`rtw8851b-cal-v1-<mac>.bin`)
//! over [`Board::new_51`]. RTL8922A likewise has `N22A` v1
//! (`rtw8922a-cal-v1-<mac>.bin`, NARF-local record magic, not a Linux
//! constant) over [`Board::new_be`]. All admit only the cold
//! channel-1/20MHz span 2402..2422.
use super::{efuse_be::BeFactory, factory::Factory, mac::ChipId, radio_assets::Assets};
use alloc::format;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
const LENGTH: usize = 96;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Firmware(FirmwareError),
    Authority,
    Unsigned,
    Format,
    Identity,
    Policy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Board {
    identity: [u8; 32],
    mac: [u8; 6],
    device: u16,
    chip: ChipId,
}
/// RTL8852C cold calibration recipe (Linux 7.3-rc4 call chain). NARF has no
/// static rtw8852c_table.c copy: every table byte the recipe programs comes
/// from the bound firmware container (`Assets::bind`) and the bound factory.
const C_RECIPE: &[u8] = b"rtw89_mac_init(C) then phy.c rtw89_phy_dm_init: rtw89_phy_init_bb_reg, rtw8852c_init_txpwr_unit, rtw8852c_bb_reset_all, rtw89_phy_init_rf_reg {radiob,radioa}, rtw8852c_bb_sethw, physts/dig(V1 cckpd)/cfo/edcca init, rtw89_phy_init_rf_nctl (no second IOQ write), rtw8852c_rfk_init (dpk_init, _rck A/B, _dac_cal, _rx_dck recover), rtw8852c_set_txpwr_ctrl, rtw8852c_power_trim, rtw8852c_bb_cfg_txrx_path(RF_AB)";
/// RTL8852C WLAN-only coexistence owner (`coex_native::Coex::prepare_c`).
const C_COEX_RECIPE: &[u8] = b"rtw89_btc_ntfy_init WL-only: rtw8852c_btc_set_rfe, rtw8852c_btc_init_cfg (rtw89_mac_coex_init_v1 RTK inner, wl_pri TX_RESP/BEACON, RR_WLSEL 0, trx mask, break 0xf0ffffff, BT cnt en|rst), scbd 0x4003, cxinit v0, cxctrl v1, txpwr ctrl off, _set_ant WONLY gnt_v1 0x57ddf + plt 0x111, OFF_BT policy";
/// RTL8851B cold calibration recipe (Linux 7.3-rc4 call chain, RF path A
/// only). As for C, every table byte comes from the bound firmware
/// container (`Assets::bind`) and the bound factory.
const N51_RECIPE: &[u8] = b"rtw89_mac_init(8851B) then phy.c rtw89_phy_dm_init: rtw89_phy_init_bb_reg, rtw8851b_init_txpwr_unit, rtw8851b_bb_reset (S0 HW-SI only), rtw89_phy_init_rf_reg {radioa}, rtw8851b_bb_sethw (rtw8851b_bb_gpio_init path A), physts/dig(cckpd every cut)/cfo(hw comp)/edcca init, no antdiv RFE, rtw89_phy_init_rf_nctl (no P1 reset, no second IOQ write) + rtw8851b_nctl_post_defs, rtw8851b_rfk_init (lck_init, dpk_init by_rate_dpd, aack, _rck A, _dac_cal, rx_dck), rtw8851b_set_txpwr_ctrl, rtw8851b_power_trim (path A), rtw8851b_bb_cfg_txrx_path(RF_A)";
/// RTL8922A cold calibration recipe (Linux `rtw89_phy_dm_init` call
/// chain, `phy.c:8254`, restricted to the steps this identity binds).
/// NARF has no static rtw8922a_table.c copy: every table byte the recipe
/// programs comes from the bound firmware container (`Assets::bind`)
/// and the bound BE factory. The steps after the NCTL table —
/// `rtw8922a_bb_sethw`, the PHYSTS/DIG/CFO/EDCCA DM sub-inits,
/// `rtw8922a_rfk_init`, `rtw8922a_bb_cfg_txrx_path` — are NOT bound by
/// this identity (no BE DM owner exists yet), and neither is coexistence:
/// NARF has no BE BTC protocol row, so `rtw8922a_btc_set_rfe` /
/// `btc_init_cfg` is not covered here.
const BE_RECIPE: &[u8] = b"rtw89_mac_init(8922A) then phy.c rtw89_phy_dm_init: rtw89_phy_init_bb_reg (BB table; init_txpwr_unit NULL; BB-gain table; bb_reset empty), rtw89_phy_init_rf_reg {radioa idx0, radiob idx1}, rtw89_phy_init_rf_nctl (P1 reset, no second IOQ write; nctl_post_table NULL), rtw8922a_set_txpwr_ctrl (txpwr_ref OFDM/CCK zero), rtw8922a_power_trim (PA-bias then pad-bias RR_BIASA V1)";
/// RTL8851B WLAN-only coexistence recipe the native owner runs at core.c
/// `rtw89_btc_ntfy_init` (rtw8851b.c `rtw8851b_btc_set_rfe` +
/// `rtw8851b_btc_init_cfg`, single WL RF path S0).
const N51_COEX_RECIPE: &[u8] = b"rtw89_btc_ntfy_init WL-only: rtw8851b_btc_set_rfe (rfe 3n+1 ant num 1 shared bt0 BTG wa 1, 3n+3 num 2 dedicated bt0 alone sw external, 3n+2 dedicated + diversity ant_info div bit; single_pos/btg_pos S0, stream 1; rfe 0 refused), rtw8851b_btc_init_cfg (rtw89_mac_coex_init RTK inner without PTA_WL_TX_EN/RSP_CHK_BTCCA, wl_pri TX_RESP/BEACON, path A RR_WLSEL 0 + LUTWE trx mask SS 0x5ff RX 0x5df TX 0x55f shared/0x5ff, group remap +3 shared, break 0xf0ffffff, BT cnt en|rst), scbd 0x4003, cxinit v0 (adie kt = XTAL_SI_CV acv), cxctrl v1, txpwr ctrl off, _set_ant WONLY (cfg_gnt 0x77007700, ctrl path, plut 0x111), OFF_BT policy";
impl Board {
    pub fn new(
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
    ) -> Result<Self, Error> {
        let identity = factory.identity().ok_or(Error::Identity)?;
        let calibration = identity.calibration();
        if device.vendor != 0x10ec
            || !matches!(device.device, 0xb852 | 0xb85b)
            || identity.chip() != ChipId::Rtl8852B
            || !calibration.valid
            || calibration.rfe_type == 255
        {
            return Err(Error::Identity);
        }
        // This exact source-selected firmware ABI supports TDMA3 and slot1.
        super::coex_native::Protocol::for_version(assets.firmware_version())
            .ok_or(Error::Identity)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852B cold ch1 legacy20 awake WLAN-only calibration v1");
        hash.update(b"CMAC TXEN=0; NCTL RCK DACK RXDCK; no ordinary packet/response grant");
        hash.update(&super::rfk_tables::RECIPE);
        hash.update(&super::phy_operating::RECIPE);
        hash.update(&super::coex_native::RECIPE);
        hash.update(&device.vendor.to_le_bytes());
        hash.update(&device.device.to_le_bytes());
        hash.update(&device.subsystem_vendor.to_le_bytes());
        hash.update(&device.subsystem_id.to_le_bytes());
        hash.update(factory.logical().ok_or(Error::Identity)?);
        hash.update(factory.b_phycap().ok_or(Error::Identity)?);
        hash.update(&[identity.cut(), calibration.rfe_type, identity.xtal()]);
        assets
            .bind(&mut hash, calibration.rfe_type, identity.cut())
            .map_err(|_| Error::Identity)?;
        Ok(Self {
            identity: hash.finalize(),
            mac: identity.mac(),
            device: device.device,
            chip: ChipId::Rtl8852B,
        })
    }
    /// RTL8852C cold channel-1 calibration identity (rtw8852ce.c
    /// `rtw89_8852ce_id_table`: 10ec:c852 only): the C factory logical map
    /// and 0x60-byte PHY-cap window, cut/RFE/XTAL, the bound C firmware
    /// container tables, the C recipe and the C coexistence owner with its
    /// firmware BTC ABI row (`coex_native::ProtocolC`).
    pub fn new_c(
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
    ) -> Result<Self, Error> {
        let identity = factory.identity().ok_or(Error::Identity)?;
        let calibration = identity.calibration();
        if device.vendor != 0x10ec
            || device.device != 0xc852
            || identity.chip() != ChipId::Rtl8852C
            || assets.chip() != ChipId::Rtl8852C
            || !calibration.valid
            || calibration.rfe_type == 255
        {
            return Err(Error::Identity);
        }
        // coex.c rtw89_btc_ver_defs: only a known C BTC ABI row.
        let protocol = super::coex_native::ProtocolC::for_version(assets.firmware_version())
            .ok_or(Error::Identity)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852C cold ch1 20MHz awake WLAN-only calibration v1");
        hash.update(b"CMAC TXEN=0; NCTL RCK DACK RXDCK; no ordinary packet/response grant");
        hash.update(C_RECIPE);
        hash.update(C_COEX_RECIPE);
        hash.update(&[protocol.tag()]);
        hash.update(&device.vendor.to_le_bytes());
        hash.update(&device.device.to_le_bytes());
        hash.update(&device.subsystem_vendor.to_le_bytes());
        hash.update(&device.subsystem_id.to_le_bytes());
        hash.update(factory.logical().ok_or(Error::Identity)?);
        hash.update(factory.c_phycap().ok_or(Error::Identity)?);
        hash.update(&[identity.cut(), calibration.rfe_type, identity.xtal()]);
        assets
            .bind(&mut hash, calibration.rfe_type, identity.cut())
            .map_err(|_| Error::Identity)?;
        Ok(Self {
            identity: hash.finalize(),
            mac: identity.mac(),
            device: device.device,
            chip: ChipId::Rtl8852C,
        })
    }
    /// RTL8851B cold channel-1 calibration identity (rtw8851be.c
    /// `rtw89_8851be_id_table`: 10ec:b851 only): the RTL8851B factory
    /// logical map and 128-byte PHY-cap window (0x580), cut/RFE/XTAL, the
    /// bound container tables (BB/GAIN/RADIO_A/NCTL), the RTL8851B recipe
    /// and coexistence owner with its firmware BTC ABI row
    /// (`coex_native::Protocol51`). An antenna-diversity RFE
    /// (`rfe_type % 3 == 2`) is admitted through the `antdiv_51`
    /// owner composed by `radio_51::prepare_controls`.
    pub fn new_51(
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
    ) -> Result<Self, Error> {
        let identity = factory.identity().ok_or(Error::Identity)?;
        let calibration = identity.calibration();
        if device.vendor != 0x10ec
            || device.device != 0xb851
            || identity.chip() != ChipId::Rtl8851B
            || assets.chip() != ChipId::Rtl8851B
            || !calibration.valid
            || calibration.rfe_type == 255
            || calibration.rfe_type == 0
        {
            return Err(Error::Identity);
        }
        // coex.c rtw89_btc_ver_defs: only a known RTL8851B BTC ABI row.
        super::coex_native::Protocol51::for_version(assets.firmware_version())
            .ok_or(Error::Identity)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8851B cold ch1 20MHz awake WLAN-only calibration v1;RF path A");
        hash.update(b"CMAC TXEN=0; NCTL AACK RCK DACK RXDCK; no ordinary packet/response grant");
        hash.update(N51_RECIPE);
        hash.update(N51_COEX_RECIPE);
        hash.update(&device.vendor.to_le_bytes());
        hash.update(&device.device.to_le_bytes());
        hash.update(&device.subsystem_vendor.to_le_bytes());
        hash.update(&device.subsystem_id.to_le_bytes());
        hash.update(factory.logical().ok_or(Error::Identity)?);
        hash.update(factory.n51_phycap().ok_or(Error::Identity)?);
        hash.update(&[identity.cut(), calibration.rfe_type, identity.xtal()]);
        assets
            .bind(&mut hash, calibration.rfe_type, identity.cut())
            .map_err(|_| Error::Identity)?;
        Ok(Self {
            identity: hash.finalize(),
            mac: identity.mac(),
            device: device.device,
            chip: ChipId::Rtl8851B,
        })
    }
    /// RTL8922A cold channel-1 calibration identity (Linux `rtw8922ae.c`
    /// `rtw89_8922ae_id_table`: 10ec:8922; NARF `mac.rs` also admits
    /// 10ec:892b): the BE factory identity (MAC, RFE, crystal cap,
    /// 0x38-byte PHY-cap window, cut) and the bound container tables
    /// (BB/GAIN/RADIO_A idx0/RADIO_B idx1/NCTL) under the BE recipe.
    /// `BeFactory::read` already fails malformed maps, so the gates
    /// here are the AX mirrors: RFE 255 refused, and a missing cut
    /// (`cv` None) refused — there is no cut to bind the tables
    /// against. No BE coexistence row exists in NARF, so unlike
    /// `new_c` this binds no BTC ABI (see `BE_RECIPE`).
    pub fn new_be(
        factory: &BeFactory,
        device: narf_bus::DeviceId,
        assets: &Assets,
    ) -> Result<Self, Error> {
        if device.vendor != 0x10ec
            || !matches!(device.device, 0x8922 | 0x892b)
            || assets.chip() != ChipId::Rtl8922A
            || factory.rfe_type == 255
        {
            return Err(Error::Identity);
        }
        let cut = factory.cv.ok_or(Error::Identity)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8922A cold ch1 20MHz awake WLAN-only calibration v1;RF paths A+B");
        hash.update(b"CMAC TXEN=0; NCTL RCK DACK RXDCK; no ordinary packet/response grant");
        hash.update(BE_RECIPE);
        hash.update(&device.vendor.to_le_bytes());
        hash.update(&device.device.to_le_bytes());
        hash.update(&device.subsystem_vendor.to_le_bytes());
        hash.update(&device.subsystem_id.to_le_bytes());
        hash.update(&factory.phycap);
        hash.update(&factory.mac);
        hash.update(&[cut, factory.rfe_type, factory.xtal_cap]);
        assets
            .bind(&mut hash, factory.rfe_type, cut)
            .map_err(|_| Error::Identity)?;
        Ok(Self {
            identity: hash.finalize(),
            mac: factory.mac,
            device: device.device,
            chip: ChipId::Rtl8922A,
        })
    }
    /// Record magic and firmware-name chip of this board's family.
    fn family(self) -> (&'static [u8; 4], &'static str) {
        match self.chip {
            ChipId::Rtl8852C => (b"N5CB", "8852c"),
            ChipId::Rtl8851B => (b"N51B", "8851b"),
            ChipId::Rtl8922A => (b"N22A", "8922a"),
            _ => (b"N52B", "8852b"),
        }
    }
    pub(super) fn mac(self) -> [u8; 6] {
        self.mac
    }
    pub fn identity(self) -> [u8; 32] {
        self.identity
    }
}
struct Current;
impl CapOp<FirmwareBlob, Read> for Current {
    type Output = ();
    fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<(), CapError> {
        Ok(())
    }
}
pub(super) struct Calibration {
    board: Board,
    authority: Cap<FirmwareBlob, Read>,
    antenna_qdb: i16,
    qualified_qdbm: i16,
    calibration_peak_qdbm: i16,
    // An explicit inert fixture can carry its own fixed host policy. The
    // registered loader always leaves this None and uses the real database.
    #[cfg(any(test, feature = "kernel-test"))]
    model_domain: Option<narf_wireless::reg::RegulatoryDomain>,
}
struct Decode(Board);
impl CapOp<FirmwareBlob, Read> for Decode {
    type Output = Result<Calibration, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
            Calibration::from_verified(view.bytes, view.signer, self.0, *cap)
        })())
    }
}
impl Calibration {
    pub fn load(board: Board) -> Result<Self, Error> {
        let m = board.mac;
        let name = format!(
            "rtw89/rtw{}-cal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            board.family().1,
            m[0],
            m[1],
            m[2],
            m[3],
            m[4],
            m[5]
        );
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let cap = narf_firmware::open(&name, &loader).map_err(Error::Firmware)?;
        cap.invoke(Decode(board)).map_err(|_| Error::Authority)?
    }
    fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        board: Board,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        signer.ok_or(Error::Unsigned)?;
        if bytes.len() != LENGTH
            || &bytes[..4] != board.family().0
            || bytes[4..8] != [1, 0, 96, 0]
            || bytes[8..12] != (LENGTH as u32).to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != board.device.to_le_bytes()
            || bytes[54..58] != [1, 20, 1, 0]
            || bytes[64..] != [0; 32]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != board.identity || bytes[48..54] != board.mac {
            return Err(Error::Identity);
        }
        let signed = |at| i16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let antenna_qdb = signed(58);
        let qualified_qdbm = signed(60);
        let calibration_peak_qdbm = signed(62);
        if !(0..=256).contains(&antenna_qdb)
            || !(-512..=256).contains(&qualified_qdbm)
            || !(-512..=256).contains(&calibration_peak_qdbm)
        {
            return Err(Error::Format);
        }
        Ok(Self {
            board,
            authority,
            antenna_qdb,
            qualified_qdbm,
            calibration_peak_qdbm,
            #[cfg(any(test, feature = "kernel-test"))]
            model_domain: None,
        })
    }
    pub fn current(&self) -> Result<(), Error> {
        self.authority
            .invoke(Current)
            .map_err(|_| Error::Authority)?;
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(domain) = self.model_domain.as_ref() {
            return self.check(domain);
        }
        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Policy)?;
        self.check(&domain)
    }
    /// Keep actual publication inside this exact signed capability invocation.
    /// Metadata/current-policy sampling alone cannot authorize later MMIO.
    pub fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::power::Error>,
    ) -> Result<T, super::power::Error> {
        struct Invoke<'a, F> {
            qualification: &'a Calibration,
            operation: F,
        }
        impl<T, F: FnOnce() -> Result<T, super::power::Error>> CapOp<FirmwareBlob, Read> for Invoke<'_, F> {
            type Output = Result<T, super::power::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    #[cfg(any(test, feature = "kernel-test"))]
                    if let Some(domain) = self.qualification.model_domain.as_ref() {
                        self.qualification
                            .check(domain)
                            .map_err(|_| super::power::Error::Access)?;
                        return (self.operation)();
                    }
                    let domain = narf_wireless::reg::db::ensure_domain()
                        .map_err(|_| super::power::Error::Access)?;
                    self.qualification
                        .check(&domain)
                        .map_err(|_| super::power::Error::Access)?;
                    (self.operation)()
                })())
            }
        }
        self.authority
            .invoke(Invoke {
                qualification: self,
                operation,
            })
            .map_err(|_| super::power::Error::Access)?
    }
    fn check(&self, domain: &narf_wireless::reg::RegulatoryDomain) -> Result<(), Error> {
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Policy);
        }
        let mut ceiling = None;
        for (index, rule) in domain.rules.iter().enumerate() {
            if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
                continue;
            }
            if rule.freq_start_mhz > 2402
                || rule.freq_end_mhz < 2422
                // cfg80211 reg_get_max_bandwidth (AUTO_BW run, NO_160MHZ
                // cap) must allow this 20MHz channel; NO_160MHZ and
                // AUTO_BW restrict nothing else at 20MHz.
                || domain.max_bandwidth(index) < 20
                || rule.flags.bits() & !PLAIN_RULE_FLAGS != 0
            {
                return Err(Error::Policy);
            }
            let power = i16::from(rule.max_power_dbm) * 4;
            ceiling = Some(ceiling.map_or(power, |old: i16| old.min(power)));
        }
        let ceiling = ceiling.ok_or(Error::Policy)?.min(self.qualified_qdbm);
        if i32::from(self.calibration_peak_qdbm) + i32::from(self.antenna_qdb) > i32::from(ceiling)
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
    pub fn matches(&self, board: Board) -> bool {
        self.board == board
    }
}
/// Rule flags a plain 20MHz span may carry: NO_P2P, AUTO_BW, NO_160MHZ.
/// DFS, NO_IR and every other (or unknown) bit is refused.
const PLAIN_RULE_FLAGS: u32 = narf_wireless::reg::RegFlags::NO_P2P.bits()
    | narf_wireless::reg::RegFlags::AUTO_BW.bits()
    | narf_wireless::reg::RegFlags::NO_160MHZ.bits();
#[cfg(any(test, feature = "kernel-test"))]
#[path = "calibration_policy/tests.rs"]
pub(super) mod tests;
