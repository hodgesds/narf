// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE packet owner: TX descriptor fill and RX descriptor query.
//!
//! Linux `rtl92de_tx_fill_desc` / `rtl92d_rx_query_desc` over the
//! `trx.rs` layouts. Descriptor field positions are the `trx.rs` fill
//! rules; every value the fill programs is one Linux sets on the same
//! path.
//!
//! ## Admission (fail-closed)
//!
//! [`Owner`] can only be built from a successful firmware download
//! (`firmware_transport::Info`, obtainable only from `run_8192de`)
//! plus a [`super::envelope::Permission`]. There is no channel grant
//! in step 2: the 8192DE has no in-tree factory table, so — mirroring
//! the 8723AE — admission is firmware `Info` + envelope `Permission`
//! alone. Transmit goes through [`Owner::fill_tx_slot`], which refuses
//! unless the frame's operating point equals the permission's point
//! and the rate is admitted by the permission. 5 GHz frames are
//! admitted on a 5 GHz permission (step-5 envelope); the descriptor
//! 5 GHz rate floor lives in [`super::trx`].
//!
//! There is deliberately NO RX C2H dispatch: Linux's 92D RX query has
//! no C2H bit (unlike the 8723BE's `rpt_sel`), and the 8192DE is not a
//! Bluetooth combo part, so there is no coexistence owner to feed and
//! no C2H queue. [`Owner::service_rx`] decodes a delivered RX
//! descriptor and returns the frame; the caller strips the trailing
//! FCS and handles `hw_error` frames. The TX-report *request* side
//! (SPE_RPT / SW_DEFINE, [`Owner::next_report_sn`]) is implemented;
//! matching a returned report needs the C2H path, which does not
//! exist for 92D in-tree, and is a follow-up.
//!
//! ## Single-segment scope
//!
//! This pass fills single-MPDU descriptors only (`firstseg` +
//! `lastseg`, no fragmentation, no AMPDU aggregation). The
//! station-owner decisions are wired through [`TxFrame`] and the
//! installed [`Link`]: AMPDU flag + density (caller asserts the
//! frame is aggregated under an operational BA session), RDG + HTC
//! (behind `rdg_en`, which upstream never sets), the LPS hardware
//! sequence rule (behind the link's `fwctrl_lps`), encryption
//! `sectype` from the key cipher, TX-report requests (EAPOL or
//! nullfunc), and rate-id / MAC-id from the H2C rate-mask send
//! ([`Link::from_rate_mask`]). Ring-slot allocation,
//! descriptor-ring base programming, the doorbell, and OWN
//! publication stay with the caller: this module fills a
//! caller-provided [`super::trx::TxDesc`] (OWN left clear) and the
//! future `Prepared::Chip::Rtl8192de` packet path owns the rings.
//! No `Prepared` signature changes in this lane.
//!
//! ## Rate numbering
//!
//! Descriptor `hw_rate` values are the `wifi.h` `DESC_RATE*` codes
//! (1M `0x00` … 54M `0x0b`, MCS0-7 continuing at `0x0c`), which is
//! exactly the envelope's full-order rate numbering (CCK 0..3, OFDM
//! 4..11, HT MCS0-7 12..19) — so
//! [`super::envelope::Permission::admits`] gates the descriptor rate
//! directly.
//!
//! ## Rate-id / MAC-id rules (`_rtl_txrate_selectmode`,
//! `rtl_get_tcb_desc`)
//!
//! The DE driver always runs with `useramask` set
//! ([`super::lifecycle`]), so the descriptor rate id is the
//! rate-table index directly (no `0x0c +` offset). Management /
//! control / beacon frames take rate id MC (7) with MAC id 0 and
//! the driver rate; data frames take the link's index and MAC id,
//! with the driver rate for special data and nullfunc and the
//! firmware rate (`use_driver_rate = false`) for ordinary unicast
//! DATA under an installed link. A station never stores a
//! rate-table index in Linux (the mask send stores it only when
//! `macid != 0`), so a station link's index is the mode fallback
//! ([`rate_index_for_mode`]): N 2.4 GHz → NGB (0), N 5 GHz → NG
//! (1), G → GB (4), B → B (6), A → G (5).

use super::envelope::{Operating, Permission};
use super::h2c::{self, RateMask};
use super::rate::WirelessMode;
use super::trx::{self, RxStatus, TxDesc, TxParams};
use super::MacPhyMode;
use crate::rtlwifi::firmware_transport::Info;

/// Frame class for the firmware queue-select mapping
/// (`_rtl92de_map_hwqueue_to_fwqueue`: beacon → `QSLT_BEACON`,
/// management / control → `QSLT_MGNT`, data → priority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameClass {
    /// Beacon frame.
    Beacon,
    /// Management frame.
    Mgmt,
    /// Control frame.
    Ctl,
    /// Data frame with 802.11d priority (TID) 0..7.
    Data {
        /// Traffic identifier / priority.
        priority: u8,
    },
}

impl FrameClass {
    /// Firmware queue selector for the class.
    pub const fn queue_sel(self) -> u8 {
        match self {
            FrameClass::Beacon => trx::QSLT_BEACON,
            FrameClass::Mgmt | FrameClass::Ctl => trx::QSLT_MGNT,
            FrameClass::Data { priority } => priority & 7,
        }
    }
}

/// RTS/CTS parameters for a TX descriptor (`ptcb_desc` RTS fields).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rts {
    /// `rts_enable && !cts_enable` → `rts_en`.
    pub rts_enable: bool,
    /// `rts_enable || cts_enable` → `hwrts_en`.
    pub cts_enable: bool,
    /// Short preamble (legacy RTS rate) / short GI (HT RTS rate):
    /// `trx::TxDesc::fill` selects by the RTS rate, so one flag
    /// covers both.
    pub rts_short: bool,
    /// `rts_rate` (descriptor rate code).
    pub rts_rate: u8,
    /// `rts_sc` (sub-carrier).
    pub rts_sc: u8,
    /// `rts_stbc`.
    pub rts_stbc: bool,
}

/// One single-MPDU TX frame to fill a descriptor for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxFrame {
    /// Operating point the frame transmits on (must equal the
    /// permission's point).
    pub op: Operating,
    /// Frame class (queue selector).
    pub class: FrameClass,
    /// Payload length in bytes (packet size and buffer size).
    pub len: usize,
    /// DMA address of the payload buffer (32-bit; `trx.h` dword 8).
    pub buf_addr: u32,
    /// Descriptor rate code (full-order rate, see the module docs).
    /// For an adaptive frame this is the caller's highest N rate
    /// (or the 11M / 54M fallback for a non-HT peer), which the
    /// firmware then paces; for a driver-rate frame it is the rate
    /// the firmware transmits at.
    pub rate: u8,
    /// Sequence number (`seq_ctrl >> 4`, 12 bits).
    pub seq: u16,
    /// `use_shortgi || use_shortpreamble` → the short bit.
    pub short: bool,
    /// RTS/CTS parameters, or `None` for no RTS/CTS.
    pub rts: Option<Rts>,
    /// Next descriptor address for the ring link (dword 10); 0
    /// terminates.
    pub next_desc: u32,
    /// Current wireless mode, for the rate-id fallback
    /// ([`rate_index_for_mode`]).
    pub mode: WirelessMode,
    /// Key cipher for the `sectype` field (software-crypto profiles
    /// pass [`KeyCipher::None`]).
    pub cipher: KeyCipher,
    /// AMPDU density (`sta->ht_cap.ampdu_density`) when this frame
    /// is aggregated under an operational BA session (`Some`), or
    /// `None` for a plain frame. The owner does not track BA
    /// sessions; the caller asserts aggregation.
    pub ampdu_density: Option<u8>,
    /// Ordinary unicast DATA under an installed link: the firmware
    /// paces the rate (`use_driver_rate = false`). Without a link
    /// this falls back to the driver rate.
    pub adaptive: bool,
    /// EAPOL frame (`ether_type` `0x888e` after the SNAP prefix):
    /// a TX-report frame.
    pub eapol: bool,
    /// Nullfunc frame: a TX-report frame.
    pub nullfunc: bool,
    /// `mac->rdg_en` (QoS data only; upstream never sets it).
    pub rdg_en: bool,
}

/// Key cipher for the `sectype` descriptor field
/// (`rtl92de_tx_fill_desc`: WEP40 / WEP104 / TKIP → 1, CCMP → 3,
/// no hardware key → 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyCipher {
    None,
    Wep,
    Tkip,
    Ccmp,
}

impl KeyCipher {
    /// The `sectype` descriptor value for this cipher.
    pub const fn sectype(self) -> u8 {
        match self {
            KeyCipher::None => 0,
            KeyCipher::Wep | KeyCipher::Tkip => 1,
            KeyCipher::Ccmp => 3,
        }
    }
}

/// `rtl_is_tx_report_skb`: an EAPOL frame or a nullfunc frame
/// requests a TX report from the firmware.
pub const fn wants_tx_report(eapol: bool, nullfunc: bool) -> bool {
    eapol || nullfunc
}

/// `ETH_P_PAE` (EAPOL ether type, for the caller's frame
/// classification).
pub const ETH_P_PAE: u16 = 0x888e;

/// The station link state installed by the H2C rate-mask send
/// (see [`h2c::update_hal_rate_mask`]): the rate-table index and
/// MAC id the descriptors carry, the peer's AMPDU density, and the
/// firmware-LPS flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    /// Effective rate-table index (see [`Link::from_rate_mask`]).
    pub ratr_index: u8,
    /// MAC id from the rate-mask send (0 for a station).
    pub mac_id: u8,
    /// `sta->ht_cap.ampdu_density`.
    pub ampdu_density: u8,
    /// `ppsc->fwctrl_lps` (non-QoS frames take the LPS hwseq rule).
    pub fwctrl_lps: bool,
}

/// The `_rtl_txrate_selectmode` mode fallback for a station under
/// `useramask` (92D has no VHT, so no AC indices): N 2.4 GHz → NGB
/// (0), N 5 GHz → NG (1), G → GB (4), B → B (6), A → G (5); an
/// unknown mode takes NGB.
pub const fn rate_index_for_mode(mode: WirelessMode) -> u8 {
    match mode {
        WirelessMode::N24g => h2c::RATR_INX_WIRELESS_NGB,
        WirelessMode::N5g => h2c::RATR_INX_WIRELESS_NG,
        WirelessMode::G => h2c::RATR_INX_WIRELESS_GB,
        WirelessMode::B => h2c::RATR_INX_WIRELESS_B,
        WirelessMode::A => h2c::RATR_INX_WIRELESS_G,
        WirelessMode::Unknown => h2c::RATR_INX_WIRELESS_NGB,
    }
}

impl Link {
    /// Effective descriptor values from a rate-mask send. A
    /// multi-station link (`mac_id != 0`, AP / adhoc) keeps the
    /// firmware's stored index; a station (`mac_id == 0`) never
    /// stores one in Linux, so the mode fallback applies instead.
    pub fn from_rate_mask(mask: RateMask, mode: WirelessMode) -> Self {
        let ratr_index = if mask.mac_id == 0 {
            rate_index_for_mode(mode)
        } else {
            mask.ratr_index
        };
        Self {
            ratr_index,
            mac_id: mask.mac_id,
            ampdu_density: 0,
            fwctrl_lps: false,
        }
    }
}

/// Packet-path error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No firmware admission, no envelope permission, or a
    /// permission mismatch for the operating point / rate.
    NotAdmitted,
    /// Frame length invalid (zero or wider than the 16-bit size
    /// fields), or a descriptor / buffer pair that cannot hold the
    /// payload.
    Frame,
    /// The RX descriptor is still hardware-owned (`RxStatus::parse`
    /// returned `None`); the caller must not service the slot yet.
    NotReady,
}

/// One decoded RX frame: status plus the payload slice (which still
/// carries the trailing FCS; the caller strips it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxFrame<'a> {
    /// Decoded RX status.
    pub status: RxStatus,
    /// Payload bytes.
    pub payload: &'a [u8],
}

/// The DE packet owner: firmware admission + envelope permission,
/// plus the installed link, the MAC/PHY mode, and the TX-report
/// sequence counter.
#[derive(Debug)]
pub struct Owner {
    /// Firmware download result (proof of admission).
    firmware: Info,
    /// Admitted operating point + rates for this board.
    permission: Permission,
    /// Installed link (`None` until the H2C rate-mask send).
    link: Option<Link>,
    /// MAC/PHY mode (for the dual-MAC MCS7 short-GI rule; bound
    /// by the radio owner, defaulting to single-MAC).
    mode: MacPhyMode,
    /// `rtlpriv->tx_report` sequence counter
    /// (`rtl_get_tx_report_sn`: `(++sn & 0x3f) << 2`).
    report_sn: u16,
}

impl Owner {
    /// Admit a packet owner: only a successful `run_8192de` result
    /// plus a minted envelope permission can construct one. No link
    /// is installed yet (pass-1 descriptor values) and the mode
    /// defaults to single-MAC; the radio owner binds both.
    pub fn admit(firmware: Info, permission: Permission) -> Self {
        Self {
            firmware,
            permission,
            link: None,
            mode: MacPhyMode::SingleMacSinglePhy,
            report_sn: 0,
        }
    }

    /// Firmware version admitted (for logging / diagnostics).
    pub fn firmware_version(&self) -> u16 {
        self.firmware.version
    }

    /// The admitted permission.
    pub fn permission(&self) -> Permission {
        self.permission
    }

    /// Bind the MAC/PHY mode (dual-MAC MCS7 short-GI rule).
    pub fn bind_mode(&mut self, mode: MacPhyMode) {
        self.mode = mode;
    }

    /// The bound mode.
    pub fn mode(&self) -> MacPhyMode {
        self.mode
    }

    /// The installed link, if any.
    pub fn link(&self) -> Option<Link> {
        self.link
    }

    /// Install a link directly (the caller computed it, e.g. from a
    /// rate-mask send).
    pub fn bind_link(&mut self, link: Link) {
        self.link = Some(link);
    }

    /// Install a link from a rate-mask send: the effective
    /// rate-id / MAC-id from [`Link::from_rate_mask`], with the
    /// peer's AMPDU density and the firmware-LPS flag.
    pub fn install_rate_mask(
        &mut self,
        mask: RateMask,
        mode: WirelessMode,
        ampdu_density: u8,
        fwctrl_lps: bool,
    ) {
        let mut link = Link::from_rate_mask(mask, mode);
        link.ampdu_density = ampdu_density;
        link.fwctrl_lps = fwctrl_lps;
        self.link = Some(link);
    }

    /// Next TX-report sequence (`rtl_get_tx_report_sn`):
    /// `(++sn & 0x3f) << 2`. `SW_DEFINE` bits 11:8 and 1:0 stay
    /// zero (reserved for driver padding and firmware).
    pub fn next_report_sn(&mut self) -> u16 {
        self.report_sn = self.report_sn.wrapping_add(1);
        (self.report_sn & 0x3f) << 2
    }

    /// Admission gate: the operating point must equal the permission's
    /// point and the rate must be admitted by the permission.
    pub fn admit_tx(&self, op: Operating, rate: u8) -> Result<(), Error> {
        if op != self.permission.operating() || !self.permission.admits(rate) {
            return Err(Error::NotAdmitted);
        }
        Ok(())
    }

    /// Fill a TX descriptor for an admitted frame; refused before
    /// any descriptor byte is written when admission fails or the
    /// length is invalid. OWN is left clear: the caller publishes
    /// the slot after the payload buffer is visible, and sets the
    /// ring link from `tx.next_desc` (written here). Takes `&mut`
    /// for the TX-report sequence counter.
    pub fn fill_tx_slot(&mut self, slot: &mut TxDesc, tx: &TxFrame) -> Result<(), Error> {
        self.admit_tx(tx.op, tx.rate)?;
        if tx.len == 0 || tx.len > 0xffff {
            return Err(Error::Frame);
        }
        let (rts_enable, cts_enable, rts_rate, rts_sc, rts_short, rts_stbc) = match tx.rts {
            Some(r) => (
                r.rts_enable,
                r.cts_enable,
                r.rts_rate,
                r.rts_sc,
                r.rts_short,
                r.rts_stbc,
            ),
            None => (false, false, 0, 0, false, false),
        };
        let forty = tx.op.forty();
        let is_data = matches!(tx.class, FrameClass::Data { .. });
        // Rate-id / MAC-id + driver-rate rule (see the module docs):
        // management / control / beacon take MC (7) with MAC id 0
        // and the driver rate; data takes the link's index and MAC
        // id, driver rate for special data / nullfunc, firmware rate
        // for ordinary unicast DATA under an installed link. No link
        // yet: pass-1 values (rate id 0, MAC id 0, driver rate).
        let (rate_id, mac_id, use_driver_rate, packet_bw_40) = match (is_data, tx.adaptive) {
            (false, _) => (h2c::RATR_INX_WIRELESS_MC, 0, true, false),
            (true, false) => match self.link {
                Some(link) => (link.ratr_index, link.mac_id, true, forty),
                None => (0, 0, true, forty),
            },
            (true, true) => match self.link {
                Some(link) => (link.ratr_index, link.mac_id, false, forty),
                None => (0, 0, true, forty),
            },
        };
        // `useramask` is always set on this chip, so the rule is the
        // identity (kept explicit: the `0x0c +` offset never applies).
        let (rate_id, mac_id) = trx::rate_id_macid(true, rate_id, mac_id);
        let (spe_rpt, sw_define) = if wants_tx_report(tx.eapol, tx.nullfunc) {
            (true, self.next_report_sn())
        } else {
            (false, 0)
        };
        *slot = TxDesc::fill(&TxParams {
            pkt_size: tx.len as u16,
            queue_sel: tx.class.queue_sel(),
            macid: mac_id,
            rate_id,
            hw_rate: tx.rate,
            use_driver_rate,
            disable_fallback: false,
            use_shortgi: tx.short,
            use_shortpreamble: tx.short,
            bw_40: forty,
            packet_bw_40,
            cur_40_prime_sc: tx.op.prime_sc(),
            ampdu: tx.ampdu_density.is_some(),
            ampdu_density: tx.ampdu_density.unwrap_or(0),
            sec_type: tx.cipher.sectype(),
            qos_data: is_data,
            seq: tx.seq,
            rts_enable,
            cts_enable,
            rts_rate,
            rts_sc,
            rts_stbc,
            rts_use_shortpreamble: rts_short,
            rts_use_shortgi: rts_short,
            buffer_len: tx.len as u16,
            buffer_addr: tx.buf_addr,
            band_5g: tx.op.is_5ghz(),
            dual_mac_dual_phy: self.mode == MacPhyMode::DualMacDualPhy,
            fwctrl_lps: self.link.map(|link| link.fwctrl_lps).unwrap_or(false),
            rdg_en: tx.rdg_en,
            spe_rpt,
            sw_define,
        });
        slot.set_next(tx.next_desc);
        Ok(())
    }

    /// Decode one delivered RX descriptor from its ring slot (`dw`)
    /// against its buffer. A hardware-owned slot is [`Error::NotReady`].
    /// A short buffer is [`Error::Frame`]. A normal frame is returned
    /// with its payload slice for the caller to deliver (FCS still
    /// attached; `hw_error` frames are the caller's to drop).
    pub fn service_rx<'a>(&self, dw: &[u32; 8], buffer: &'a [u8]) -> Result<RxFrame<'a>, Error> {
        let status = RxStatus::parse(dw).ok_or(Error::NotReady)?;
        let start = status.payload_offset();
        let end = start
            .checked_add(usize::from(status.length))
            .ok_or(Error::Frame)?;
        let payload = buffer.get(start..end).ok_or(Error::Frame)?;
        Ok(RxFrame { status, payload })
    }
}
