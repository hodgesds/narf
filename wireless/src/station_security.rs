//! Retained WPA2-PSK or WPA3-SAE/CCMP owner. Shared Supplicant owns EAPOL
//! authentication; this unit binds native peers, packet keys and exact
//! reply-delivery commits. A SAE association (AKM 8/24) negotiates PMF:
//! the M3/group IGTK is retained for BIP and unicast robust management
//! frames are CCMP-protected (IEEE802.11-2020 11.13, 12.5.3, 12.5.4).
use crate::eapol::{EapolRx, EapolRxError, Gtk, KeyMgmt, RsnaParams, Supplicant};
use crate::packet_key::{self, Key, Role};
use alloc::{boxed::Box, vec, vec::Vec};
use zeroize::{Zeroize, Zeroizing};

/// Native receive admission supplied by the hardware adapter. The adapter
/// must bind the descriptor to its current peer/channel/profile, reject
/// transport/CRC/fragment errors, and retain the original native 802.11 bytes.
/// That includes a +HTC QoS DATA MPDU's Order bit and four-octet HT Control
/// field: `Security` skips HT Control and masks Order from the CCMP AAD
/// itself, so a station advertising HTC_HE keeps receiving such traffic.
/// Hardware-decrypted data is admitted only through the `*_decrypted`
/// entry points of an owner built `with_hardware_keys`; firmware-decapsulated
/// data is never admitted. This trait grants no radio, key, carrier or
/// controlled-port authority.
pub trait RawFrame {
    fn bytes(&self) -> &[u8];
    /// True only for an original MPDU in this adapter's admitted PHY profile.
    fn unmodified(&self) -> bool;
    /// Exact current physical link/peer context proven by an MLD adapter's
    /// native descriptor owner. It is never derived from an untrusted frame
    /// link-id byte. Ordinary non-MLD adapters retain the default `None`.
    fn mld_context(&self) -> Option<crate::association::mlo::Context> {
        None
    }
}

const HISTORY: usize = 16;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    State,
    Profile,
    Protocol,
    Allocation,
    Entropy,
    KeyReuse,
    Crypto(packet_key::Error),
}
/// A received management frame after PMF admission.
#[derive(Debug, PartialEq, Eq)]
pub enum MgmtRx {
    /// Dropped: unprotected robust frame under PMF, failed CCMP/BIP, a
    /// replay, or another peer.
    Ignored,
    /// The admitted frame with Protected cleared and CCMP header/MIC or
    /// MMIE removed (non-robust frames are returned unchanged).
    Frame(Vec<u8>),
}
#[derive(Debug, PartialEq, Eq)]
pub enum Rx {
    Ignored,
    ReplyReady,
    Data(Vec<u8>),
}
struct Slot {
    material: Zeroizing<[u8; 16]>,
    key: Key,
}
struct Group {
    id: u8,
    material: Zeroizing<[u8; 16]>,
    rsc: u64,
}
struct IgtkChange {
    id: u16,
    material: Zeroizing<[u8; 16]>,
    ipn: u64,
}
struct Change {
    pair: Option<Zeroizing<[u8; 16]>>,
    group: Option<Group>,
    igtk: Option<IgtkChange>,
    opens: bool,
}
struct Pending {
    frame: Vec<u8>,
    /// The same reply for a device that encrypts in hardware (native-WiFi
    /// decap): the header, with Protected when `frame` is protected, then the
    /// plaintext MSDU without CCMP header or MIC.
    device: Vec<u8>,
    change: Change,
}
/// How a data MSDU is protected for transmit.
#[derive(Clone, Copy)]
enum Protect {
    Software,
    HeaderOnly,
    Device,
}
/// One device key-cache entry for an owner built `with_hardware_keys`
/// (mac80211 `ieee80211_key_enable_hw_accel` -> `drv_set_key(SET_KEY)`).
/// Emitted once per committed material change, pairwise before group, after
/// the reply that commits it reached terminal delivery. IGTK is never
/// emitted: BIP stays in software, as ath10k/ath11k `set_key` return 1 for
/// every BIP suite. The driver reports the device's completion with
/// `key_installed(token)`; until then that slot stays software-only.
pub struct KeyInstall {
    pub pairwise: bool,
    pub key_id: u8,
    pub material: Zeroizing<[u8; 16]>,
    pub token: u32,
}
impl core::fmt::Debug for KeyInstall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyInstall")
            .field("pairwise", &self.pairwise)
            .field("key_id", &self.key_id)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}
/// Current CCMP-128 temporal keys for a device that must decrypt on its
/// own while the host is suspended (Linux rtw88 `wow.c` AOAC: the WoW
/// firmware decrypts through the security CAM that `sec.c::rtw_sec_write_cam`
/// filled from mac80211's keys). Group keys are listed by key id; IGTK is
/// never included (BIP stays in software, rtw88 `set_key` returns
/// `-EOPNOTSUPP` for every BIP suite).
pub struct SuspendKeys {
    pub pairwise: Zeroizing<[u8; 16]>,
    pub groups: Vec<(u8, Zeroizing<[u8; 16]>)>,
}
impl core::fmt::Debug for SuspendKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let ids: Vec<u8> = self.groups.iter().map(|(id, _)| *id).collect();
        f.debug_struct("SuspendKeys")
            .field("groups", &ids)
            .finish_non_exhaustive()
    }
}
/// Packet-number state matching a [`SuspendKeys`] snapshot (Linux
/// `rtw89/wow.c::rtw89_wow_get_key_info_iter`: `ptk_tx_iv`, `ptk_rx_iv`,
/// `gtk_rx_iv[keyidx]`). Each receive floor is the highest data PN the
/// host accepted under that key; the device must accept only larger PNs.
/// PNs are not secret; the struct is wiped on drop with the keys anyway.
#[derive(Debug)]
pub struct SuspendFloors {
    pub pairwise_tx: u64,
    pub pairwise_rx: u64,
    pub groups: Vec<(u8, u64)>,
}
impl Drop for SuspendFloors {
    fn drop(&mut self) {
        self.pairwise_tx.zeroize();
        self.pairwise_rx.zeroize();
        for (id, pn) in self.groups.iter_mut() {
            id.zeroize();
            pn.zeroize();
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hardware {
    Absent,
    Pending(u32),
    Installed,
}
/// Device key-cache mirror. A slot is `Installed` only when the device
/// confirmed the host's *current* material for it; any newer commit returns
/// it to `Pending`, so device-decrypted frames under a stale device key are
/// never checked against the fresh key's replay window.
struct Offload {
    installs: Vec<KeyInstall>,
    next: u32,
    pair: Hardware,
    group: [Hardware; 4],
}
/// Remember rejected retired material for the full owner lifetime. An old
/// TK cannot reappear in a fresh Key with reset PN/replay state. History is
/// bounded; exhausting it terminates the owner rather than evicting evidence.
pub struct Security {
    own: [u8; 6],
    peer: [u8; 6],
    supplicant: Supplicant,
    pair: Option<Slot>,
    group: [Option<Slot>; 4],
    history: Vec<Zeroizing<[u8; 16]>>,
    pending: Option<Pending>,
    established: bool,
    failed: bool,
    sequence: u16,
    qos_sequence: [u16; 16],
    spp_amsdu: bool,
    /// PMF negotiated (SAE): IGTK required, robust management protected.
    pmf: bool,
    igtk: crate::mfp::MfpKeyStore,
    /// EtherType Protocol Discrimination framing (`JoinPlan::epd()`).
    epd: bool,
    mld: Option<Box<crate::association::mlo::Context>>,
    fragment_rx: Option<Box<fragment::Receive>>,
    offload: Option<Box<Offload>>,
}
impl core::fmt::Debug for Security {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StationSecurity")
            .field("port_open", &self.port_open())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
fn ie(id: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > 255 {
        return Err(Error::Profile);
    }
    let mut out = vec![id, body.len() as u8];
    out.extend_from_slice(body);
    Ok(out)
}
/// True when the station RSNE's single AKM is SAE (8) or SAE-EXT-KEY (24).
fn sae_rsne(station_rsne: &[u8]) -> bool {
    use crate::rsn::{self, Suite};
    crate::rsn::RsnIe::decode_body(station_rsne).is_some_and(|rsne| {
        rsne.akms == [Suite::standard(rsn::AKM_SAE)]
            || rsne.akms == [Suite::standard(rsn::AKM_SAE_EXT_KEY)]
    })
}
fn unicast(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
impl Security {
    /// Caller supplies the already-negotiated station/AP RSNE bodies from
    /// the immutable join candidate, plus the retained device/AP identities.
    pub fn new(
        own: [u8; 6],
        peer: [u8; 6],
        pmk: &[u8; 32],
        station_rsne: &[u8],
        ap_rsne: &[u8],
        ap_rsnxe: Option<&[u8]>,
        sequence: u16,
    ) -> Result<Self, Error> {
        let owner = Self::new_inner(
            own,
            peer,
            pmk,
            station_rsne,
            None,
            ap_rsne,
            ap_rsnxe,
            sequence,
        )?;
        if sae_rsne(station_rsne) {
            // SAE needs its RSNXE and the PMF owner: use `new_sae`.
            return Err(Error::Profile);
        }
        Ok(owner)
    }
    /// A WPA3-SAE owner: `pmk` is the accepted `SaeSession` PMK, the
    /// station RSNE/RSNXE are `JoinPlan::rsn_body()` and the plan's
    /// `SaeJoin::station_rsnxe()` (both repeated in message 2/4).
    #[allow(clippy::too_many_arguments)]
    pub fn new_sae(
        own: [u8; 6],
        peer: [u8; 6],
        pmk: &[u8; 32],
        station_rsne: &[u8],
        station_rsnxe: Option<&[u8]>,
        ap_rsne: &[u8],
        ap_rsnxe: Option<&[u8]>,
        sequence: u16,
    ) -> Result<Self, Error> {
        let owner = Self::new_inner(
            own,
            peer,
            pmk,
            station_rsne,
            station_rsnxe,
            ap_rsne,
            ap_rsnxe,
            sequence,
        )?;
        if !owner.pmf || !sae_rsne(station_rsne) {
            return Err(Error::Profile);
        }
        Ok(owner)
    }
    /// True for a PMF association: SAE, or WPA2-PSK whose station and AP
    /// RSNEs both set MFPC (`JoinPlan::pmf()`).
    pub fn pmf(&self) -> bool {
        self.pmf
    }
    /// Opt into this exact negotiated single-link context before any EAPOL
    /// work. Physical source/PN/key ownership keeps the MACs passed to
    /// `new`/`new_sae`; unicast DATA uses the logical MLD crypto addresses
    /// only after that admission. Group/management stay physical. No RF grant.
    pub fn with_mld(mut self, context: crate::association::mlo::Context) -> Result<Self, Error> {
        if self.own != context.own_link()
            || self.peer != context.peer_link()
            || self.mld.is_some()
            || !self.pmf
            || self.pending.is_some()
            || self.pair.is_some()
        {
            return Err(Error::Profile);
        }
        self.supplicant
            .configure_mld(context)
            .map_err(|_| Error::Profile)?;
        self.mld = Some(Box::new(context));
        Ok(self)
    }
    pub fn mld(&self) -> Option<&crate::association::mlo::Context> {
        self.mld.as_deref()
    }
    fn admitted_link(&self, mpdu: &impl RawFrame) -> bool {
        mpdu.mld_context() == self.mld.as_deref().copied()
    }
    fn logical_own(&self) -> [u8; 6] {
        self.mld
            .as_deref()
            .map_or(self.own, |context| context.own_mld())
    }
    fn authenticator(&self) -> [u8; 6] {
        self.mld
            .as_deref()
            .map_or(self.peer, |context| context.peer_mld())
    }
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        own: [u8; 6],
        peer: [u8; 6],
        pmk: &[u8; 32],
        station_rsne: &[u8],
        station_rsnxe: Option<&[u8]>,
        ap_rsne: &[u8],
        ap_rsnxe: Option<&[u8]>,
        sequence: u16,
    ) -> Result<Self, Error> {
        if station_rsnxe.is_some_and(|b| b.is_empty() || usize::from(b[0] & 15) + 1 != b.len()) {
            return Err(Error::Profile);
        }
        if station_rsne.len() > 255
            || ap_rsne.len() > 255
            || ap_rsnxe.is_some_and(|b| b.len() > 255)
            || !unicast(own)
            || !unicast(peer)
            || own == peer
            || sequence > 4095
        {
            return Err(Error::Profile);
        }
        // The station RSNE is the canonical WPA2-PSK/CCMP body, optionally
        // advertising SPP A-MSDU Capable (RSN Capabilities bit10), or the
        // JoinPlan SAE body: CCMP-128, AKM 8 or 24, MFPC|MFPR, at most the
        // one SAE PMKID and the default BIP-CMAC-128.
        use crate::rsn::{self, Suite};
        let station = crate::rsn::RsnIe::decode_body(station_rsne).ok_or(Error::Profile)?;
        let ccmp = Suite::standard(rsn::CIPHER_CCMP_128);
        let mfp = rsn::RSN_CAP_MFP_REQUIRED | rsn::RSN_CAP_MFP_CAPABLE;
        let key_mgmt = match station.akms.as_slice() {
            [akm] if *akm == Suite::standard(rsn::AKM_SAE) => KeyMgmt::Sae,
            [akm] if *akm == Suite::standard(rsn::AKM_SAE_EXT_KEY) => KeyMgmt::SaeExtKey,
            [akm] if *akm == Suite::standard(rsn::AKM_PSK_SHA256) => KeyMgmt::PskSha256,
            _ => KeyMgmt::Psk,
        };
        let ap = crate::rsn::RsnIe::decode_body(ap_rsne).ok_or(Error::Profile)?;
        // WPA2-PSK with `JoinOptions::pmf` (ieee80211w=1/2): PMF is in force
        // when both RSNEs set MFPC (IEEE802.11-2020 12.6.3, wpa_supplicant
        // `wpa_sm_set_ap_rsn_ie` / `sm->mgmt_group_cipher`).
        let station_mfp = station.rsn_capabilities & mfp;
        let pmf = key_mgmt.sae()
            || (station_mfp & rsn::RSN_CAP_MFP_CAPABLE != 0
                && ap.rsn_capabilities & rsn::RSN_CAP_MFP_CAPABLE != 0);
        if key_mgmt.sae() {
            if station.group_cipher != ccmp
                || station.pairwise_ciphers != [ccmp]
                || station.rsn_capabilities != mfp
                || station.pmkids.len() > 1
                || station
                    .group_management_cipher
                    .is_some_and(|c| c != Suite::standard(rsn::CIPHER_BIP_CMAC_128))
            {
                return Err(Error::Profile);
            }
        } else {
            // Canonical WPA2-PSK/CCMP with AKM 2 or 6, optional SPP A-MSDU
            // Capable and the `Pmf` MFPC / MFPC|MFPR bits.
            let mut canonical = crate::rsn::RsnIe::wpa2_psk_ccmp();
            canonical.akms = vec![Suite::standard(key_mgmt.suite_type())];
            canonical.rsn_capabilities =
                station.rsn_capabilities & (crate::rsn::RSN_CAP_SPP_AMSDU_CAPABLE | mfp);
            if station != canonical || station_mfp == rsn::RSN_CAP_MFP_REQUIRED {
                return Err(Error::Profile);
            }
        }
        let ap_mfp_ok = if pmf {
            ap.rsn_capabilities & rsn::RSN_CAP_MFP_CAPABLE != 0
                && ap
                    .group_management_cipher
                    .is_none_or(|c| c == Suite::standard(rsn::CIPHER_BIP_CMAC_128))
                // A station requiring PMF needs the AP's MFPC (checked above);
                // an AP requiring it needs ours.
                && (ap.rsn_capabilities & rsn::RSN_CAP_MFP_REQUIRED == 0
                    || station_mfp & rsn::RSN_CAP_MFP_CAPABLE != 0)
        } else {
            ap.rsn_capabilities & rsn::RSN_CAP_MFP_REQUIRED == 0
                && station_mfp & rsn::RSN_CAP_MFP_REQUIRED == 0
        };
        if ap.group_cipher != ccmp
            || !ap.pairwise_ciphers.contains(&ccmp)
            || !ap.akms.contains(&Suite::standard(key_mgmt.suite_type()))
            || ap.rsn_capabilities & rsn::RSN_CAP_NO_PAIRWISE != 0
            || !ap_mfp_ok
            || ap_rsnxe.is_some_and(|b| b.is_empty() || usize::from(b[0] & 15) + 1 != b.len())
        {
            return Err(Error::Profile);
        }
        Ok(Self {
            own,
            peer,
            supplicant: Supplicant::new(peer, own, [0; 32]).with_rsna(RsnaParams {
                key_mgmt,
                pmk: pmk.to_vec(),
                assoc_ie: {
                    let mut assoc = ie(48, station_rsne)?;
                    if let Some(rsnxe) = station_rsnxe {
                        assoc.extend_from_slice(&ie(244, rsnxe)?);
                    }
                    assoc
                },
                ap_rsn_ie: ie(48, ap_rsne)?,
                ap_rsnxe: ap_rsnxe.map(|b| ie(244, b)).transpose()?,
                pairwise_key_len: 16,
                group_key_len: 16,
                mgmt_group_key_len: pmf.then_some(16),
                pmf,
            }),
            pair: None,
            group: core::array::from_fn(|_| None),
            history: Vec::new(),
            pending: None,
            established: false,
            failed: false,
            sequence,
            qos_sequence: [sequence; 16],
            // IEEE802.11-2020 12.5.3.3.3: SPP A-MSDU applies only when both
            // STAs advertise SPP A-MSDU Capable.
            spp_amsdu: station.rsn_capabilities
                & ap.rsn_capabilities
                & rsn::RSN_CAP_SPP_AMSDU_CAPABLE
                != 0,
            pmf,
            igtk: crate::mfp::MfpKeyStore::new(),
            epd: false,
            mld: None,
            fragment_rx: None,
            offload: None,
        })
    }
    /// Opt into device key offload before any EAPOL work (Linux ath10k
    /// `cryptmode=0` beside a RAW receive decap). Software CCMP stays the
    /// fallback for every frame the device did not handle: committed keys are
    /// reported through `take_key_installs`, and only a slot whose current
    /// material the driver confirmed with `key_installed` admits
    /// header-only transmit or device-decrypted receive. Not for MLD owners.
    pub fn with_hardware_keys(mut self) -> Result<Self, Error> {
        if self.mld.is_some() || self.pair.is_some() || self.pending.is_some() {
            return Err(Error::Profile);
        }
        self.offload = Some(Box::new(Offload {
            installs: Vec::new(),
            next: 1,
            pair: Hardware::Absent,
            group: [Hardware::Absent; 4],
        }));
        Ok(self)
    }
    pub fn hardware_keys(&self) -> bool {
        self.offload.is_some()
    }
    /// Drain committed key-cache entries for the device, oldest first.
    pub fn take_key_installs(&mut self) -> Vec<KeyInstall> {
        self.offload
            .as_mut()
            .map(|o| core::mem::take(&mut o.installs))
            .unwrap_or_default()
    }
    /// The device confirmed entry `token`. True when it still names the
    /// current material of its slot, which then admits offload; a stale
    /// confirmation (a newer commit replaced that slot) changes nothing.
    pub fn key_installed(&mut self, token: u32) -> bool {
        let Some(offload) = self.offload.as_mut().filter(|_| !self.failed) else {
            return false;
        };
        for slot in core::iter::once(&mut offload.pair).chain(offload.group.iter_mut()) {
            if *slot == Hardware::Pending(token) {
                *slot = Hardware::Installed;
                return true;
            }
        }
        false
    }
    /// The device rejected or never confirmed `token`: that slot remains
    /// software-only until a later commit (mac80211 keeps a key in software
    /// when `drv_set_key` fails).
    pub fn key_install_failed(&mut self, token: u32) {
        if let Some(offload) = self.offload.as_mut() {
            for slot in core::iter::once(&mut offload.pair).chain(offload.group.iter_mut()) {
                if *slot == Hardware::Pending(token) {
                    *slot = Hardware::Absent;
                }
            }
        }
    }
    fn offloaded(&self, group: Option<u8>) -> bool {
        self.offload.as_ref().is_some_and(|o| match group {
            None => o.pair == Hardware::Installed,
            Some(id) => o.group.get(usize::from(id)) == Some(&Hardware::Installed),
        })
    }
    /// The current pairwise key is in the device: data may use
    /// `transmit_ethernet_offload` and protected management
    /// `protect_management_offload`.
    pub fn pairwise_offloaded(&self) -> bool {
        self.port_open() && self.offloaded(None)
    }
    fn offload_commit(&mut self, pairwise: bool, key_id: u8, material: &[u8; 16]) {
        let Some(offload) = self.offload.as_mut() else {
            return;
        };
        let token = offload.next;
        offload.next = offload.next.wrapping_add(1).max(1);
        let slot = if pairwise {
            &mut offload.pair
        } else {
            &mut offload.group[usize::from(key_id)]
        };
        *slot = Hardware::Pending(token);
        offload.installs.push(KeyInstall {
            pairwise,
            key_id,
            material: Zeroizing::new(*material),
            token,
        });
    }
    /// Frame MSDUs with EtherType Protocol Discrimination (IEEE802.11-2020
    /// 5.1.4: the MSDU starts with a two-octet EtherType instead of the
    /// RFC1042 LLC/SNAP header) for a BSS whose plan reports
    /// `JoinPlan::epd()`. Must be chosen before the first EAPOL frame;
    /// A-MSDU transmit/receive (RFC1042 subframes) is refused in EPD mode.
    pub fn with_epd(mut self, enabled: bool) -> Self {
        self.epd = enabled;
        self
    }
    pub fn epd(&self) -> bool {
        self.epd
    }
    /// The MSDU header for `ethertype` in the negotiated discrimination.
    fn msdu_header(&self, ethertype: u16) -> Vec<u8> {
        let mut out = if self.epd {
            Vec::with_capacity(2)
        } else {
            vec![0xaa, 0xaa, 3, 0, 0, 0]
        };
        out.extend_from_slice(&ethertype.to_be_bytes());
        out
    }
    /// Convert one `Rx::Data` frame (a normalized FromDS 802.11 DATA frame)
    /// into Ethernet-II (DA = Address1, SA = Address3) using this owner's
    /// LPD or EPD discrimination. Drivers of an EPD BSS must use this
    /// instead of an RFC1042-only conversion.
    pub fn ethernet(&self, frame: &[u8]) -> Option<Vec<u8>> {
        let offset = match frame.first()? {
            8 => 24,
            0x88 => 26,
            _ => return None,
        };
        if frame.len() < offset || frame[1] & 3 != 2 {
            return None;
        }
        let (ethertype, header) = self.msdu_type(&frame[offset..])?;
        let mut out = Vec::with_capacity(frame.len());
        if self.mld.is_some() && frame[4..10] == self.own {
            out.extend_from_slice(&self.logical_own());
        } else {
            out.extend_from_slice(&frame[4..10]);
        }
        out.extend_from_slice(&frame[16..22]);
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(&frame[offset + header..]);
        Some(out)
    }
    /// The EtherType and payload offset of an MSDU body.
    fn msdu_type(&self, body: &[u8]) -> Option<(u16, usize)> {
        if self.epd {
            let t = u16::from_be_bytes([*body.first()?, *body.get(1)?]);
            // An EPD MSDU carries an EtherType, never a length.
            (t >= 0x600).then_some((t, 2))
        } else {
            let snap = body.get(..8)?;
            (snap[..6] == [0xaa, 0xaa, 3, 0, 0, 0])
                .then(|| (u16::from_be_bytes([snap[6], snap[7]]), 8))
        }
    }
    /// True when both the retained station and AP RSNEs advertised SPP
    /// A-MSDU Capable, so pairwise CCMP authenticates A-MSDU Present.
    pub fn spp_amsdu(&self) -> bool {
        self.spp_amsdu
    }
    pub fn port_open(&self) -> bool {
        !self.failed
            && self.established
            && self.pending.is_none()
            && self.pair.is_some()
            && self.group.iter().any(Option::is_some)
    }
    /// A reply still awaits terminal delivery, or M2 has been delivered and
    /// the retained supplicant still awaits M3. During an established rekey,
    /// the old-key controlled port may reopen before this exchange finishes.
    /// Drivers use this independently of carrier/port state for their timeout.
    /// Snapshot of the current temporal keys for a suspend window in which
    /// the device decrypts by itself ([`SuspendKeys`]). Only a settled open
    /// port qualifies: no reply awaiting delivery, no handshake in flight, no
    /// MLD owner. The host keeps every PN and replay floor unchanged; the
    /// caller must not let the device transmit protected frames under these
    /// keys, so host transmit PNs stay unique after resume.
    pub fn suspend_keys(&self) -> Option<SuspendKeys> {
        if !self.port_open() || self.handshake_active() || self.mld.is_some() {
            return None;
        }
        let pair = self.pair.as_ref()?;
        let groups = self
            .group
            .iter()
            .enumerate()
            .filter_map(|(id, slot)| {
                slot.as_ref()
                    .map(|slot| (id as u8, Zeroizing::new(*slot.material)))
            })
            .collect();
        Some(SuspendKeys {
            pairwise: Zeroizing::new(*pair.material),
            groups,
        })
    }
    /// Replay floors and transmit PN for the same settled-port window as
    /// [`Self::suspend_keys`] (same preconditions, same key set). Reading
    /// them changes no PN or replay state.
    pub fn suspend_floors(&self) -> Option<SuspendFloors> {
        if !self.port_open() || self.handshake_active() || self.mld.is_some() {
            return None;
        }
        let pair = self.pair.as_ref()?;
        let groups = self
            .group
            .iter()
            .enumerate()
            .filter_map(|(id, slot)| {
                slot.as_ref()
                    .map(|slot| (id as u8, slot.key.data_replay_floor()))
            })
            .collect();
        Some(SuspendFloors {
            pairwise_tx: pair.key.transmit_pn(),
            pairwise_rx: pair.key.data_replay_floor(),
            groups,
        })
    }
    pub fn handshake_active(&self) -> bool {
        !self.failed
            && (self.pending.is_some()
                || self.supplicant.state == crate::eapol::FourWayState::WaitM3)
    }
    pub fn fail(&mut self) {
        self.failed = true;
        self.established = false;
        if let Some(offload) = self.offload.as_mut() {
            offload.installs.clear();
        }
        if let Some(cache) = self.fragment_rx.as_mut() {
            cache.clear();
        }
        if let Some(pair) = self.pair.as_ref() {
            pair.key.retire_fragment_identity();
        }
    }
    pub fn pending_frame(&self) -> Option<&[u8]> {
        if self.failed {
            None
        } else {
            self.pending.as_ref().map(|p| p.frame.as_slice())
        }
    }
    fn normalize(
        &mut self,
        mpdu: &impl RawFrame,
        decrypted: bool,
    ) -> Result<Option<Vec<u8>>, Error> {
        if !self.admitted_link(mpdu) {
            return Ok(None);
        }
        let raw = mpdu.bytes();
        // +HTC QoS DATA (IEEE802.11-2020 9.2.4.1.10, mac80211
        // `ieee80211_hdrlen`): the Order bit marks a four-octet HT Control
        // field after QoS Control. CCMP excludes it from the AAD and masks
        // Order for QoS data (12.5.3.3.3, mac80211 `ccmp_gcmp_aad`), so the
        // MPDU is processed as the equivalent 26-octet header with Order
        // clear; the HT Control field (link adaptation only) is dropped.
        // Order on non-QoS DATA (strictly ordered service) stays refused.
        let stripped;
        let b = if mpdu.unmodified() && raw.len() >= 30 && raw[0] == 0x88 && raw[1] & 0x80 != 0 {
            let mut v = Vec::with_capacity(raw.len() - 4);
            v.extend_from_slice(&raw[..26]);
            v[1] &= !0x80;
            v.extend_from_slice(&raw[30..]);
            stripped = v;
            stripped.as_slice()
        } else {
            raw
        };
        if !mpdu.unmodified()
            || b.len() < 24
            || b.len() > 4096
            || !matches!(b[0], 8 | 0x88)
            || b[1] & 0x87 != 2
            || b[22] & 15 != 0
            || b[10..16] != self.peer
            || !unicast(b[16..22].try_into().unwrap())
            || b[4..10] != self.own && b[4] & 1 == 0
        {
            return Ok(None);
        }
        let length = if b[0] == 0x88 { 26 } else { 24 };
        if b.len() < length || length == 26 && b[24] & 0x80 != 0 {
            return Ok(None);
        }
        if b[1] & 0x40 == 0 {
            return Ok((!decrypted).then(|| b.to_vec()));
        }
        let wire = b.get(length..).ok_or(Error::Protocol)?;
        let key_id = wire.get(3).ok_or(Error::Protocol)? >> 6;
        if decrypted && !self.offloaded((b[4] & 1 != 0).then_some(key_id)) {
            // The device may still hold an older key for this slot.
            return Ok(None);
        }
        let slot = if b[4] & 1 != 0 {
            self.group[usize::from(key_id)].as_mut()
        } else {
            if key_id != 0 {
                return Ok(None);
            }
            self.pair.as_mut()
        };
        let Some(slot) = slot else { return Ok(None) };
        let mut wire = wire.to_vec();
        let opened = if decrypted {
            slot.key.accept_decrypted(&b[..length], &wire)
        } else {
            slot.key.unprotect(&b[..length], &mut wire)
        };
        let plaintext = match opened {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let mut normalized = b[..length].to_vec();
        normalized[1] &= !0x40;
        normalized.extend_from_slice(&plaintext);
        Ok(Some(normalized))
    }
    /// A caller obtains fresh_snonce from the CSPRNG, never frame contents.
    /// Pending replies are serialized through the same retained transport TX owner.
    pub fn receive(&mut self, mpdu: &impl RawFrame, fresh_snonce: [u8; 32]) -> Result<Rx, Error> {
        self.receive_with_nonce(mpdu, || Some(fresh_snonce))
    }
    /// Receive one original protected QoS A-MSDU after the driver proves its
    /// actual native HT/peer/channel/descriptor profile. The established
    /// controlled port and current installed PTK/GTK are required before
    /// any crypto or replay state can change. Malformed input is ignored;
    /// complete authenticated subframes are returned as Ethernet-II frames.
    /// A-MSDU cannot supply EAPOL or drive the retained supplicant/rekey.
    pub fn receive_amsdu(&mut self, mpdu: &impl RawFrame) -> Result<Option<Vec<Vec<u8>>>, Error> {
        Ok(self
            .receive_amsdu_with(mpdu, packet_key::AmsduAdmission::new())?
            .map(|r| r.frames))
    }
    /// Admit normal/BlockAck-policy original A-MSDUs only after the driver
    /// proves a live BA agreement and releases this MPDU in native SN order.
    /// Default receive_amsdu remains normal-ACK-only; no header is rewritten.
    pub fn receive_amsdu_block_ack(
        &mut self,
        mpdu: &impl RawFrame,
    ) -> Result<Option<Vec<Vec<u8>>>, Error> {
        Ok(self
            .receive_amsdu_with(mpdu, packet_key::AmsduAdmission::new().with_block_ack(true))?
            .map(|r| r.frames))
    }
    /// Receive an original protected A-MSDU under the explicit ack-policy,
    /// EOSP and size opt-ins the driver's native receive path has proved.
    /// The same port/peer/key/replay rules as `receive_amsdu` apply, and the
    /// result carries the original TID, Ack Policy and EOSP facts.
    pub fn receive_amsdu_with(
        &mut self,
        mpdu: &impl RawFrame,
        admission: packet_key::AmsduAdmission,
    ) -> Result<Option<packet_key::AmsduReceive>, Error> {
        self.receive_amsdu_checked(mpdu, admission, false)
    }
    /// `receive_amsdu_with` for one device-decrypted original A-MSDU
    /// (CCMP header kept, MIC removed); same slot/replay rules as
    /// `receive_decrypted_with_nonce`.
    pub fn receive_amsdu_decrypted_with(
        &mut self,
        mpdu: &impl RawFrame,
        admission: packet_key::AmsduAdmission,
    ) -> Result<Option<packet_key::AmsduReceive>, Error> {
        if self.offload.is_none() {
            return Err(Error::State);
        }
        self.receive_amsdu_checked(mpdu, admission, true)
    }
    fn receive_amsdu_checked(
        &mut self,
        mpdu: &impl RawFrame,
        admission: packet_key::AmsduAdmission,
        decrypted: bool,
    ) -> Result<Option<packet_key::AmsduReceive>, Error> {
        if !self.port_open() {
            return Err(Error::State);
        }
        if !self.admitted_link(mpdu) {
            return Ok(None);
        }
        if self.epd {
            return Ok(None);
        }
        let raw = mpdu.bytes();
        // +HTC QoS DATA: drop the HT Control field and Order bit (see
        // `normalize`); CCMP authenticates the same AAD either way.
        let stripped;
        let bytes = if raw.len() >= 30 && raw[0] == 0x88 && raw[1] & 0x80 != 0 {
            let mut v = Vec::with_capacity(raw.len() - 4);
            v.extend_from_slice(&raw[..26]);
            v[1] &= !0x80;
            v.extend_from_slice(&raw[30..]);
            stripped = v;
            stripped.as_slice()
        } else {
            raw
        };
        // A device-decrypted aggregate carries no MIC (8 octets fewer).
        let overhead = if decrypted { 8 } else { 16 };
        if !mpdu.unmodified()
            || decrypted && bytes.get(1).is_none_or(|b| b & 0x40 == 0)
            || !(26 + overhead + 22..=26 + overhead + admission.limit().bytes())
                .contains(&bytes.len())
        {
            return Ok(None);
        }
        let header = &bytes[..26];
        if packet_key::aggregate_header_with(header, admission).is_err()
            || header[10..16] != self.peer
            || !unicast(header[16..22].try_into().unwrap())
            || header[4..10] != self.own && header[4] & 1 == 0
        {
            return Ok(None);
        }
        let wire = &bytes[26..];
        let id = usize::from(wire[3] >> 6);
        if decrypted && !self.offloaded((header[4] & 1 != 0).then_some(id as u8)) {
            return Ok(None);
        }
        let slot = if header[4] & 1 != 0 {
            self.group[id].as_mut()
        } else if id == 0 {
            self.pair.as_mut()
        } else {
            None
        };
        let Some(slot) = slot else {
            return Ok(None);
        };
        Ok(if decrypted {
            slot.key
                .accept_decrypted_amsdu_with(header, wire, admission)
        } else {
            slot.key.unprotect_amsdu_with(header, wire, admission)
        }
        .ok())
    }
    pub fn receive_with_nonce(
        &mut self,
        mpdu: &impl RawFrame,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Rx, Error> {
        self.receive_checked(mpdu, fresh_snonce, false)
    }
    /// `receive_with_nonce` for one device-decrypted MPDU (Protected still
    /// set, CCMP header kept, MIC removed: Linux htt_rx.c
    /// `ath10k_htt_rx_h_undecap_raw` with `is_decrypted`). Only a
    /// `with_hardware_keys` owner whose matching slot is confirmed installed
    /// admits it; the PN must pass the same replay counter as software CCMP.
    pub fn receive_decrypted_with_nonce(
        &mut self,
        mpdu: &impl RawFrame,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Rx, Error> {
        if self.offload.is_none() {
            return Err(Error::State);
        }
        self.receive_checked(mpdu, fresh_snonce, true)
    }
    fn receive_checked(
        &mut self,
        mpdu: &impl RawFrame,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
        decrypted: bool,
    ) -> Result<Rx, Error> {
        let result = self.receive_inner(mpdu, fresh_snonce, decrypted);
        if result.as_ref().is_err_and(|e| *e != Error::State) {
            self.fail();
        }
        result
    }
    fn receive_inner(
        &mut self,
        mpdu: &impl RawFrame,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
        decrypted: bool,
    ) -> Result<Rx, Error> {
        if self.failed || self.pending.is_some() {
            return Err(Error::State);
        }
        let protected = mpdu.bytes().get(1).is_some_and(|b| b & 0x40 != 0);
        let Some(frame) = self.normalize(mpdu, decrypted)? else {
            return Ok(Rx::Ignored);
        };
        self.receive_normalized(frame, protected, fresh_snonce)
    }
    fn receive_normalized(
        &mut self,
        frame: Vec<u8>,
        protected: bool,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Rx, Error> {
        let offset = if frame[0] == 0x88 { 26 } else { 24 };
        let Some((ethertype, header)) = self.msdu_type(&frame[offset..]) else {
            return Ok(Rx::Ignored);
        };
        if ethertype != 0x888e {
            return if self.port_open() && protected {
                Ok(Rx::Data(frame))
            } else {
                Ok(Rx::Ignored)
            };
        }
        // Only the negotiated authenticator's unicast native FromDS EAPOL
        // reaches the supplicant. A group/source alias never becomes EAPOL.
        if frame[4..10] != self.own || frame[16..22] != self.authenticator() {
            return Ok(Rx::Ignored);
        }
        let pdu = &frame[offset + header..];
        if pdu.len() < 4
            || !(1..=3).contains(&pdu[0])
            || pdu[1] != 3
            || usize::from(u16::from_be_bytes([pdu[2], pdu[3]])) + 4 != pdu.len()
        {
            return Ok(Rx::Ignored);
        }
        let processed = match self
            .supplicant
            .rx_eapol_with_nonce(pdu, protected, fresh_snonce)
        {
            Ok(rx) => rx,
            Err(EapolRxError::Drop(_)) => return Ok(Rx::Ignored),
            Err(EapolRxError::NonceUnavailable) => return Err(Error::Entropy),
            Err(_) => {
                self.fail();
                return Err(Error::Protocol);
            }
        };
        let pmf = self.pmf;
        let first = self.pair.is_none();
        let (reply, pair, gtk, igtk, opens) = match processed {
            EapolRx::Pairwise1(m1) => (m1.reply, None, None, None, false),
            EapolRx::Pairwise3(mut m3) => {
                // Without PMF an IGTK is a protocol error; with PMF the
                // first M3 must deliver it (IEEE802.11-2020 12.7.6.4).
                if !m3.secure || m3.igtk.is_some() && !pmf || pmf && first && m3.igtk.is_none() {
                    if let Some(t) = &mut m3.tk {
                        t.zeroize();
                    }
                    if let Some(g) = &mut m3.gtk {
                        g.key.zeroize();
                    }
                    if let Some(igtk) = &mut m3.igtk {
                        igtk.key.zeroize();
                    }
                    self.fail();
                    return Err(Error::Protocol);
                }
                (m3.reply, m3.tk, m3.gtk, m3.igtk, true)
            }
            EapolRx::Group1(mut g) => {
                if !self.established || g.igtk.is_some() && !pmf || matches!(g.igtk, Some(Err(())))
                {
                    if let Some(gtk) = &mut g.gtk {
                        gtk.key.zeroize();
                    }
                    if let Some(Ok(Some(igtk))) = &mut g.igtk {
                        igtk.key.zeroize();
                    }
                    self.fail();
                    return Err(Error::Protocol);
                }
                let igtk = match g.igtk {
                    Some(Ok(igtk)) => igtk,
                    _ => None,
                };
                (g.reply, None, g.gtk, igtk, false)
            }
        };
        let igtk = igtk
            .map(|mut k: crate::eapol::Igtk| {
                let result = if !(4..=5).contains(&k.key_id) || k.key.len() != 16 {
                    Err(Error::Protocol)
                } else {
                    let mut ipn = [0; 8];
                    ipn[..6].copy_from_slice(&k.ipn);
                    Ok(IgtkChange {
                        id: k.key_id,
                        material: Zeroizing::new(k.key.as_slice().try_into().unwrap()),
                        ipn: u64::from_le_bytes(ipn),
                    })
                };
                k.key.zeroize();
                result
            })
            .transpose()?;
        let pair = pair.map(Zeroizing::new);
        let gtk = gtk
            .map(|mut g: Gtk| {
                let result = if g.key_id > 3 || g.key.len() != 16 || g.rsc[6..] != [0, 0] {
                    Err(Error::Protocol)
                } else {
                    Ok(Group {
                        id: g.key_id,
                        material: Zeroizing::new(g.key.as_slice().try_into().unwrap()),
                        rsc: u64::from_le_bytes(g.rsc),
                    })
                };
                g.key.zeroize();
                result
            })
            .transpose()?;
        let pair = pair
            .map(|p| {
                p.as_slice()
                    .try_into()
                    .map(Zeroizing::new)
                    .map_err(|_| Error::Protocol)
            })
            .transpose()?;
        let change = Change {
            pair,
            group: gtk,
            igtk,
            opens,
        };
        if let Err(error) = self.validate_change(&change) {
            self.fail();
            return Err(error);
        }
        let mut header = vec![8, 1, 0, 0];
        header.extend_from_slice(&self.peer);
        header.extend_from_slice(&self.own);
        header.extend_from_slice(&self.authenticator());
        header.extend_from_slice(&(self.sequence << 4).to_le_bytes());
        self.sequence = (self.sequence + 1) & 4095;
        let mut body = self.msdu_header(0x888e);
        body.extend_from_slice(&reply);
        // During a PTK rekey, M2/M4 use the still-installed old packet key.
        // The shared supplicant's newly verified PTK is committed below only
        // after this exact old-key-protected reply reaches terminal delivery.
        let (frame, device) = if let Some(old) = &mut self.pair {
            header[1] |= 0x40;
            let wire = old.key.protect(&header, &body).map_err(Error::Crypto)?;
            let mut device = header.clone();
            device.extend_from_slice(&body);
            header.extend_from_slice(&wire);
            (header, device)
        } else {
            header.extend_from_slice(&body);
            (header.clone(), header)
        };
        self.pending = Some(Pending {
            frame,
            device,
            change,
        });
        Ok(Rx::ReplyReady)
    }
    /// Ring clients submit Ethernet data only. Native EAPOL is exclusively
    /// generated by the retained supplicant, before this controlled port.
    pub fn transmit_ethernet(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, Error> {
        self.transmit_ethernet_inner(ethernet, None, None, Protect::Software)
    }
    /// Header-only form of `transmit_ethernet`/`transmit_ethernet_qos`
    /// (`tid`) for the device's confirmed current pairwise key: the Protected
    /// header and CCMP header with a PN from the shared counter, then the
    /// plaintext MSDU; the device appends the MIC (mac80211
    /// `IEEE80211_KEY_FLAG_GENERATE_IV`). `State` when the pairwise slot is
    /// not offloaded, in which case the caller uses the software form.
    pub fn transmit_ethernet_offload(
        &mut self,
        ethernet: &[u8],
        tid: Option<u8>,
    ) -> Result<Vec<u8>, Error> {
        if !self.pairwise_offloaded() {
            return Err(Error::State);
        }
        if tid.is_some_and(|tid| tid > 15) {
            return Err(Error::Profile);
        }
        self.transmit_ethernet_inner(ethernet, tid, None, Protect::HeaderOnly)
    }
    /// Device-encrypted form of `transmit_ethernet`/`transmit_ethernet_qos`
    /// (`tid`) for a device that owns the transmit PN of the confirmed
    /// current pairwise key (Linux ath10k native-WiFi TX: mac80211 sets
    /// Protected and leaves IV and MIC to hardware when the key carries no
    /// `GENERATE_IV`): the Protected header, then the plaintext MSDU. No
    /// packet-key PN is consumed. `State` when the pairwise slot is not
    /// offloaded.
    pub fn transmit_ethernet_device(
        &mut self,
        ethernet: &[u8],
        tid: Option<u8>,
    ) -> Result<Vec<u8>, Error> {
        if !self.pairwise_offloaded() {
            return Err(Error::State);
        }
        if tid.is_some_and(|tid| tid > 15) {
            return Err(Error::Profile);
        }
        self.transmit_ethernet_inner(ethernet, tid, None, Protect::Device)
    }
    /// Form the QoS header before CCMP authenticates its TID and nonce. The
    /// caller must separately own negotiated WMM/EDCA and native QoS admission.
    /// This helper grants no PHY/aggregation/U-APSD or packet-queue capability.
    pub fn transmit_ethernet_qos(&mut self, ethernet: &[u8], tid: u8) -> Result<Vec<u8>, Error> {
        if tid > 15 {
            return Err(Error::Profile);
        }
        self.transmit_ethernet_inner(ethernet, Some(tid), None, Protect::Software)
    }
    /// Form HE +HTC QoS DATA before CCMP encryption. `control` is the
    /// little-endian four-octet HE-variant HT Control field; the caller owns
    /// HE negotiation, rate-fallback fencing and the control's contents.
    /// Order and EOSP are set as in mac80211's HE A-Control transmit path.
    /// HT Control, Order and EOSP are excluded from the CCMP AAD, while the
    /// TID, addresses and payload retain the ordinary protection and PN.
    pub fn transmit_ethernet_qos_htc(
        &mut self,
        ethernet: &[u8],
        tid: u8,
        control: [u8; 4],
    ) -> Result<Vec<u8>, Error> {
        if tid > 15 || control[0] & 3 != 3 {
            return Err(Error::Profile);
        }
        self.transmit_ethernet_inner(ethernet, Some(tid), Some(control), Protect::Software)
    }
    /// Aggregate station-originated Ethernet-II frames into one protected
    /// QoS A-MSDU MPDU for `tid` (IEEE802.11-2020 9.3.2.2.2). Every frame
    /// must carry this station's SA and an ordinary Ethernet-II protocol; the
    /// control port, tunnels and VLAN-encapsulated control ports are rejected,
    /// so EAPOL is never aggregated. The outer Address3 is the BSSID per Table
    /// 9-30, Normal Ack is used and one QoS SN plus one PN are consumed. The
    /// caller must hold a peer-advertised `limit` and its own negotiated
    /// PHY/aggregation/queue admission; this grants none of them.
    pub fn transmit_amsdu_qos(
        &mut self,
        frames: &[&[u8]],
        tid: u8,
        limit: crate::amsdu::Limit,
    ) -> Result<Vec<u8>, Error> {
        if !self.port_open() {
            return Err(Error::State);
        }
        if tid > 15 || self.epd {
            return Err(Error::Profile);
        }
        let body =
            crate::amsdu::encode(frames, self.logical_own(), limit).map_err(|_| Error::Profile)?;
        let mut header = vec![0x88, 0x41, 0, 0];
        header.extend_from_slice(&self.peer);
        header.extend_from_slice(&self.own);
        header.extend_from_slice(&self.peer);
        let sequence = self.qos_sequence[usize::from(tid)];
        header.extend_from_slice(&(sequence << 4).to_le_bytes());
        header.extend_from_slice(&[0x80 | tid, 0]);
        let result = self
            .pair
            .as_mut()
            .ok_or(Error::State)?
            .key
            .protect_amsdu(&header, &body, limit);
        let wire = match result {
            Ok(wire) => wire,
            Err(error) => {
                self.fail();
                return Err(Error::Crypto(error));
            }
        };
        self.qos_sequence[usize::from(tid)] = (sequence + 1) & 4095;
        header.extend_from_slice(&wire);
        Ok(header)
    }
    /// Sample the next exact QoS SN without consuming it or a key PN.
    /// Native BA callers must freeze their producer and drain all preceding
    /// packets before using it as an ADDBA SSN; this value grants no BA or
    /// native queue authority. Non-QoS/EAPOL traffic cannot advance it.
    pub fn next_qos_sequence(&self, tid: u8) -> Result<u16, Error> {
        let sequence = self
            .qos_sequence
            .get(usize::from(tid))
            .ok_or(Error::Profile)?;
        if !self.port_open() {
            return Err(Error::State);
        }
        Ok(*sequence)
    }
    /// Reserve the shared non-QoS DATA/EAPOL sequence number for a native
    /// plaintext control frame, such as mac80211's off-channel Null function.
    /// This consumes no packet-key PN and changes no key or replay state.
    /// QoS Null uses SN0 without calling this helper. The caller must prove
    /// the exact frame, current peer/profile/policy and native queue authority.
    pub fn reserve_plain_control_sequence(&mut self) -> Result<u16, Error> {
        if !self.port_open() || self.handshake_active() {
            return Err(Error::State);
        }
        let sequence = self.sequence;
        self.sequence = (sequence + 1) & 4095;
        Ok(sequence)
    }
    fn transmit_ethernet_inner(
        &mut self,
        ethernet: &[u8],
        tid: Option<u8>,
        control: Option<[u8; 4]>,
        protect: Protect,
    ) -> Result<Vec<u8>, Error> {
        if !self.port_open() {
            return Err(Error::State);
        }
        if !(14..=1514).contains(&ethernet.len())
            || ethernet[6..12] != self.logical_own()
            || ethernet[..6] == [0; 6]
        {
            return Err(Error::Profile);
        }
        let protocol = u16::from_be_bytes([ethernet[12], ethernet[13]]);
        if protocol < 0x600 || matches!(protocol, 0x888e | 0x80f3 | 0x8137) {
            return Err(Error::Profile);
        }
        let mut header = vec![if tid.is_some() { 0x88 } else { 8 }, 0x41, 0, 0];
        header.extend_from_slice(&self.peer);
        header.extend_from_slice(&self.own);
        header.extend_from_slice(&ethernet[..6]);
        let sequence = tid.map_or(self.sequence, |tid| self.qos_sequence[usize::from(tid)]);
        header.extend_from_slice(&(sequence << 4).to_le_bytes());
        if let Some(tid) = tid {
            header.extend_from_slice(&[tid | if control.is_some() { 0x10 } else { 0 }, 0]);
        }
        if let Some(control) = control {
            header[1] |= 0x80;
            header.extend_from_slice(&control);
        }
        if let Some(tid) = tid {
            self.qos_sequence[usize::from(tid)] = (sequence + 1) & 4095;
        } else {
            self.sequence = (sequence + 1) & 4095;
        }
        let mut body = self.msdu_header(protocol);
        body.extend_from_slice(&ethernet[14..]);
        let key = &mut self.pair.as_mut().ok_or(Error::State)?.key;
        let result = match protect {
            Protect::Software => key.protect(&header, &body),
            Protect::HeaderOnly => key.protect_header(&header, &body),
            Protect::Device => Ok(body),
        };
        let wire = match result {
            Ok(wire) => wire,
            Err(error) => {
                self.fail();
                return Err(Error::Crypto(error));
            }
        };
        header.extend_from_slice(&wire);
        Ok(header)
    }
    fn validate_change(&mut self, c: &Change) -> Result<(), Error> {
        let mut fresh = 0;
        if let Some(material) = &c.pair {
            if self
                .pair
                .as_ref()
                .is_none_or(|old| *old.material != **material)
            {
                if self.history.iter().any(|old| **old == **material) {
                    return Err(Error::KeyReuse);
                }
                fresh += 1;
            }
        }
        if let Some(group) = &c.group {
            if self.group[usize::from(group.id)]
                .as_ref()
                .is_none_or(|old| *old.material != *group.material)
            {
                if self.history.iter().any(|old| **old == *group.material)
                    || c.pair.as_ref().is_some_and(|p| **p == *group.material)
                {
                    return Err(Error::KeyReuse);
                }
                fresh += 1;
            }
        }
        if let Some(igtk) = &c.igtk {
            if self
                .igtk
                .find_by_key_id(igtk.id)
                .is_none_or(|old| old.key != *igtk.material)
            {
                if self.history.iter().any(|old| **old == *igtk.material)
                    || c.pair.as_ref().is_some_and(|p| **p == *igtk.material)
                    || c.group
                        .as_ref()
                        .is_some_and(|g| *g.material == *igtk.material)
                {
                    return Err(Error::KeyReuse);
                }
                fresh += 1;
            }
        }
        if c.opens && c.pair.is_none() && self.pair.is_none()
            || c.opens && self.pmf && c.igtk.is_none() && self.igtk.active.is_none()
            || self.history.len() + fresh > HISTORY
        {
            return Err(Error::Protocol);
        }
        self.history
            .try_reserve(fresh)
            .map_err(|_| Error::Allocation)
    }
    /// The packet owner has proved exact terminal host delivery. This never
    /// treats submission, a quiet poll or an on-air guess as M4 completion.
    pub fn reply_delivered(&mut self, native_bytes: usize) -> Result<(), Error> {
        if self.mld.is_some() {
            return Err(Error::Profile);
        }
        self.reply_delivered_inner(native_bytes, false)
    }
    /// The pending reply in the form a hardware-encrypting device transmits
    /// (Linux ath10k native-WiFi: no software crypto in that decap). A
    /// reply protected under the current pairwise key is available only
    /// while that key is confirmed in the device; otherwise `None`.
    pub fn pending_frame_device(&self) -> Option<&[u8]> {
        if self.failed || self.offload.is_none() {
            return None;
        }
        let pending = self.pending.as_ref()?;
        if pending.device.get(1).is_some_and(|fc| fc & 0x40 != 0) && !self.offloaded(None) {
            return None;
        }
        Some(pending.device.as_slice())
    }
    /// Terminal delivery of `pending_frame_device`'s exact bytes.
    pub fn reply_delivered_device(&mut self, native_bytes: usize) -> Result<(), Error> {
        if self.mld.is_some() || self.offload.is_none() {
            return Err(Error::Profile);
        }
        self.reply_delivered_inner(native_bytes, true)
    }
    /// The native owner proves terminal delivery on this exact negotiated
    /// link/peer. Wrong context leaves the real pending reply/key work retained.
    pub fn reply_delivered_mld(
        &mut self,
        context: &crate::association::mlo::Context,
        native_bytes: usize,
    ) -> Result<(), Error> {
        if self.mld.as_deref() != Some(context) {
            return Err(Error::Profile);
        }
        self.reply_delivered_inner(native_bytes, false)
    }
    fn reply_delivered_inner(&mut self, native_bytes: usize, device: bool) -> Result<(), Error> {
        if self.failed {
            return Err(Error::State);
        }
        let Some(pending) = self.pending.take() else {
            return Err(Error::State);
        };
        let sent = if device {
            &pending.device
        } else {
            &pending.frame
        };
        if sent.len() != native_bytes {
            self.fail();
            return Err(Error::Protocol);
        }
        let mld = self.mld.as_deref().copied();
        if let Some(material) = pending.change.pair {
            if self
                .pair
                .as_ref()
                .is_none_or(|old| *old.material != *material)
            {
                if let Some(cache) = self.fragment_rx.as_mut() {
                    cache.clear();
                }
            }
            if let Some(old) = &mut self.pair {
                if *old.material == *material {
                    old.key.reinstall(&material, 0).map_err(Error::Crypto)?;
                } else {
                    let key = Key::new(&material, 0, Role::Pairwise, self.own, self.peer, 0)
                        .and_then(|key| key.with_spp_amsdu(self.spp_amsdu))
                        .and_then(|key| key.with_mld_context(mld.as_ref()))
                        .map_err(Error::Crypto)?;
                    self.history.push(Zeroizing::new(*material));
                    self.offload_commit(true, 0, &material);
                    self.pair = Some(Slot { material, key });
                }
            } else {
                let key = Key::new(&material, 0, Role::Pairwise, self.own, self.peer, 0)
                    .and_then(|key| key.with_spp_amsdu(self.spp_amsdu))
                    .and_then(|key| key.with_mld_context(mld.as_ref()))
                    .map_err(Error::Crypto)?;
                self.history.push(Zeroizing::new(*material));
                self.offload_commit(true, 0, &material);
                self.pair = Some(Slot { material, key });
            }
            self.supplicant.pairwise_key_installed();
        }
        if let Some(group) = pending.change.group {
            let at = usize::from(group.id);
            if self.group[at]
                .as_ref()
                .is_none_or(|old| *old.material != *group.material)
            {
                let key = Key::new(
                    &group.material,
                    group.id,
                    Role::Group,
                    self.own,
                    self.peer,
                    group.rsc,
                )
                .and_then(|key| key.with_mld_context(mld.as_ref()))
                .map_err(Error::Crypto)?;
                self.history.push(Zeroizing::new(*group.material));
                self.offload_commit(false, group.id, &group.material);
                self.group[at] = Some(Slot {
                    material: group.material,
                    key,
                });
            }
            let material = &self.group[at].as_ref().unwrap().material;
            self.supplicant
                .group_keys_installed(Some(material.as_slice()), None);
        }
        if let Some(igtk) = pending.change.igtk {
            if self
                .igtk
                .find_by_key_id(igtk.id)
                .is_none_or(|old| old.key != *igtk.material)
            {
                self.igtk
                    .install_active(*igtk.material, igtk.id)
                    .map_err(|_| Error::Protocol)?;
                if let Some(active) = self.igtk.active.as_mut() {
                    // The KDE IPN is the last IPN the AP used; mac80211
                    // seeds rx_pn with it and requires a strictly larger IPN.
                    active.rx_pn = igtk.ipn;
                }
                self.history.push(Zeroizing::new(*igtk.material));
            }
            self.supplicant
                .group_keys_installed(None, Some(igtk.material.as_slice()));
        }
        self.established |= pending.change.opens;
        Ok(())
    }
    /// Robust management frames per Linux `_ieee80211_is_robust_mgmt_frame`.
    fn robust(frame: &[u8]) -> bool {
        match frame[0] {
            0xa0 | 0xc0 => true,
            0xd0 => {
                frame[1] & 0x40 != 0
                    || frame
                        .get(24)
                        .is_some_and(|c| !matches!(*c, 4 | 7 | 11 | 15 | 20 | 21 | 22 | 127))
            }
            _ => false,
        }
    }
    /// Admit one received management MPDU from the AP under the negotiated
    /// PMF policy (mac80211 `ieee80211_drop_unencrypted_mgmt`,
    /// `ieee80211_crypto_ccmp_decrypt`, `ieee80211_crypto_aes_cmac_decrypt`):
    /// once the PTK is installed, unicast robust frames must be
    /// CCMP-protected with it and group robust frames must carry a valid
    /// BIP MMIE under the installed IGTK. Before keys, or without PMF,
    /// unprotected frames pass unchanged; deauthentication and SA Query
    /// policy remains the MLME owner's.
    fn management_admitted(&self, mpdu: &impl RawFrame) -> bool {
        let b = mpdu.bytes();
        self.admitted_link(mpdu)
            && mpdu.unmodified()
            && (24..=4096).contains(&b.len())
            && b[0] & 0x0c == 0
            && b[1] & 0x07 == 0
            && b[22] & 15 == 0
            && b[10..16] == self.peer
            && b[16..22] == self.peer
            && (b[4..10] == self.own || b[4] & 1 != 0)
    }
    /// A device-decrypted unicast robust management frame (Linux wmi.c
    /// `ath10k_wmi_rx_is_decrypted`: Protected still set, CCMP header kept;
    /// the driver removed the MIC). mac80211 then only checks the PN against
    /// the pairwise key's management replay counter, as here. Only a PMF
    /// owner with the current pairwise key confirmed in the device admits it.
    pub fn receive_management_decrypted(&mut self, mpdu: &impl RawFrame) -> Result<MgmtRx, Error> {
        if self.failed || self.offload.is_none() {
            return Err(Error::State);
        }
        let b = mpdu.bytes();
        if !self.management_admitted(mpdu)
            || b[1] & 0x40 == 0
            || b[4] & 1 != 0
            || !self.pmf
            || !Self::robust(b)
            || !self.offloaded(None)
        {
            return Ok(MgmtRx::Ignored);
        }
        let Some(pair) = self.pair.as_mut() else {
            return Ok(MgmtRx::Ignored);
        };
        Ok(
            match pair.key.accept_decrypted_management(&b[..24], &b[24..]) {
                Ok(plain) => {
                    let mut out = b[..24].to_vec();
                    out[1] &= !0x40;
                    out.extend_from_slice(&plain);
                    MgmtRx::Frame(out)
                }
                Err(_) => MgmtRx::Ignored,
            },
        )
    }
    pub fn receive_management(&mut self, mpdu: &impl RawFrame) -> Result<MgmtRx, Error> {
        if self.failed {
            return Err(Error::State);
        }
        if !self.management_admitted(mpdu) {
            return Ok(MgmtRx::Ignored);
        }
        let b = mpdu.bytes();
        let protected = b[1] & 0x40 != 0;
        if !self.pmf || self.pair.is_none() || !Self::robust(b) {
            return Ok(if protected {
                MgmtRx::Ignored
            } else {
                MgmtRx::Frame(b.to_vec())
            });
        }
        if b[4] & 1 != 0 {
            // Group-addressed robust frame: unprotected with a BIP MMIE.
            if protected {
                return Ok(MgmtRx::Ignored);
            }
            return Ok(
                match crate::mfp::verify_inbound(&mut self.igtk, &b[..24], &b[24..]) {
                    Ok(body) => {
                        let mut out = b[..24].to_vec();
                        out.extend_from_slice(body);
                        MgmtRx::Frame(out)
                    }
                    Err(_) => MgmtRx::Ignored,
                },
            );
        }
        if !protected {
            return Ok(MgmtRx::Ignored);
        }
        let Some(pair) = self.pair.as_mut() else {
            return Ok(MgmtRx::Ignored);
        };
        let mut wire = b[24..].to_vec();
        match pair.key.unprotect_management(&b[..24], &mut wire) {
            Ok(plain) => {
                let mut out = b[..24].to_vec();
                out[1] &= !0x40;
                out.extend_from_slice(&plain);
                Ok(MgmtRx::Frame(out))
            }
            Err(_) => Ok(MgmtRx::Ignored),
        }
    }
    /// CCMP-protect one unicast robust management frame (Deauthentication,
    /// Disassociation or a robust Action) to the AP after the controlled
    /// port opened under PMF. `frame` is the unprotected MPDU with the
    /// caller's sequence number; the PN is consumed even if the transport
    /// later drops the frame.
    pub fn protect_management(&mut self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        self.protect_management_checked(frame, false)
    }
    /// Header-only form of `protect_management` for the device's confirmed
    /// current pairwise key (mac80211 `IEEE80211_KEY_FLAG_GENERATE_IV_MGMT`):
    /// the device appends the MIC. `State` when not offloaded.
    pub fn protect_management_offload(&mut self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.offloaded(None) {
            return Err(Error::State);
        }
        self.protect_management_checked(frame, true)
    }
    fn protect_management_checked(
        &mut self,
        frame: &[u8],
        offload: bool,
    ) -> Result<Vec<u8>, Error> {
        if !self.pmf || !self.port_open() {
            return Err(Error::State);
        }
        if !(25..=4096).contains(&frame.len())
            || frame[0] & 0x0c != 0
            || frame[1] & 0x47 != 0
            || frame[22] & 15 != 0
            || !Self::robust(frame)
            || frame[4..10] != self.peer
            || frame[10..16] != self.own
            || frame[16..22] != self.peer
        {
            return Err(Error::Profile);
        }
        let mut header = frame[..24].to_vec();
        header[1] |= 0x40;
        let key = &mut self.pair.as_mut().ok_or(Error::State)?.key;
        let wire = if offload {
            key.protect_management_header(&header, &frame[24..])
        } else {
            key.protect_management(&header, &frame[24..])
        }
        .map_err(Error::Crypto)?;
        header.extend_from_slice(&wire);
        Ok(header)
    }
}
impl Drop for Security {
    fn drop(&mut self) {
        if let Some(r) = &mut self.supplicant.rsna {
            r.pmk.zeroize();
        }
        for p in [&mut self.supplicant.ptk, &mut self.supplicant.tptk]
            .into_iter()
            .flatten()
        {
            p.kck.zeroize();
            p.kek.zeroize();
            p.tk.zeroize();
        }
        for key in [&mut self.supplicant.gtk, &mut self.supplicant.igtk]
            .into_iter()
            .flatten()
        {
            key.zeroize();
        }
        self.supplicant.snonce.zeroize();
        for igtk in [&mut self.igtk.active, &mut self.igtk.next]
            .into_iter()
            .flatten()
        {
            igtk.key.zeroize();
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "station_security_tests.rs"]
mod tests;

#[path = "station_security_fragment.rs"]
pub mod fragment;
