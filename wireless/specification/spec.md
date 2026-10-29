# wireless — Specification

> Status: **v0.1** (Stage 4 design draft).
> 
> Architecture for wireless networking in the NARF ecosystem. Extends
> `net/spec` with 802.11-specific control plane, capability-gated
> scan/associate flows, and SoftMAC support.

## 0. References (public-only)

The original protocol modules used the public references below. The
current nl80211 integration also uses Linux UAPI definitions, and the
iwlwifi hardware implementation uses the local Linux Intel firmware API
headers and transport source under the repository's GPL-2.0 licensing.

- **IEEE Std 802.11-2020** — Wireless LAN MAC and Physical Layer
  specifications. IEEE Standards Association.
  - §9 (Frame Formats) — drives `mlme.rs` (Frame Control,
    management headers, IE/TLV layout).
  - §12.4 (SAE) — WPA3 Simultaneous Authentication of Equals,
    referenced for future EAPOL extensions.
  - §12.7 (Keys and key distribution) — drives `eapol.rs` PRF,
    PTK derivation, and the 4-Way Handshake state machine.
- **IEEE Std 802.1X-2020** — Port-Based Network Access Control.
  §11.3 (EAPOL frame format) — drives the EAPOL header in `eapol.rs`.
- **IEEE Std 802.11-2020 §12.5.3** — CCMP (CTR-with-CBC-MAC). Drives
  `ccmp.rs`: §12.5.3.2 (CCMP header), §12.5.3.3.3 (AAD construction),
  §12.5.3.3.4 (nonce construction), §12.5.3.4.4 (replay window).
  AES-CCM block primitive is injected through the `AesCcm` trait —
  production wires AES-128-CCM from `narf-crypto`.
- **IEEE Std 802.11-2020 §9.4.2.24** — RSN Information Element.
  Drives `rsn.rs`: §9.4.2.24.1 (frame layout), §9.4.2.24.2 (cipher
  suite OUI/type table), §9.4.2.24.3 (AKM types), §9.4.2.24.4 (RSN
  Capabilities bits including MFP-required / MFP-capable / OCV).
- **IEEE Std 802.11-2020 §12.4** — Simultaneous Authentication of
  Equals (SAE / WPA3). §12.4.4 (Hash-to-Element), §12.4.5 (commit
  + confirm exchange), §12.4.7.4 (frame layout), §12.4.8.6 (state
  machine) — drives `sae.rs`. ECC group + MAC primitives are injected
  through `EccGroup` and `MacPrimitive` traits so the protocol
  state machine compiles without dragging in a bignum library;
  production wires P-256 + HMAC-SHA256 from `narf-crypto`.

## 1. Purpose & scope

**Owns:**
- The **Wireless Interface Trait** (`WirelessIface`) extending `NetIface`.
- **Wireless Capabilities** (`WirelessCap<T, R>`) for scan, associate, and monitor operations.
- **Scan/Associate Protocol** — high-level async API for discovery and connection.
- **802.11 Frame Parsing** — (SoftMAC specific) building and parsing management frames.

**Does NOT own:**
- Userspace supplicant policy — credential selection, network profiles and
  connection policy live in userspace (e.g. wpa_supplicant / NetworkManager
  over nl80211). The RSNA supplicant itself — the WPA2/WPA3 4-way and
  group-key handshakes and SAE — is in-kernel (see §5 and decision §8.3);
  userspace supplies credentials (passphrase, PMK, SAE password) through
  nl80211 `CONNECT`, or drives the handshake itself only on
  external-supplicant drivers (§3.4).
- Regulatory domain enforcement — the driver/firmware is responsible for hardware limits; the kernel validates against a signed database.
- L3+ networking — lives in stack daemons via `net/spec`.

## 2. Design Principles

1. **In-Kernel MLME**: The 802.11 station MLME and the RSNA supplicant run in-kernel (shared `narf-wireless` code for SoftMAC families; firmware supplicants for FullMAC families), behind the nl80211 control plane. Userspace configures and observes; it is not in the association or handshake path (decision §8.3, superseding §8.1).
2. **Capability-Gated**: Discovery (scanning) is a distinct right from connectivity (association).
3. **Zero-Copy Hot Path**: Data frames use the standard `net/spec` Narf-Rings; management frames use a separate `MgmtRing`.
4. **Documented hardware contracts**: Record the source of firmware wire
   layouts and validate their version before use.

## 3. Public Interface

nl80211 scan caches and pending-operation guards bind the netdev's current
ifindex and namespace as well as its name. Removing and recreating a same-named
interface cannot inherit its predecessor's BSS facts, suppress fresh discovery,
or let a late old operation release the replacement's busy guard. Scan dumps,
station signal fallback and SME/CONNECT lookups respect that lifetime; native
driver permissions and association receipts remain separately required.
Stale operation admission fails before cache mutation. Asynchronous scan and
CONNECT continuations recheck the captured identity before further dispatch,
cache updates and events; retired completions cannot clear a replacement's
connection owner or emit CONNECT/PORT_AUTHORIZED for an old index.
Userspace-SME futures check that identity before each native poll and notification.
Connection-owner grants and teardown claims also carry distinct monotonic
tokens: reusing the same socket port ID on a live netdev cannot let an older
queued release or held teardown act on the new grant. Owner/port mutations
validate identity under the owner lock, and replacement or namespace movement
resets peer, control-port and cached power-save state.

`association::phy::{LocalHt, LocalVht, LocalPhy}` describes a native driver's
implemented directional RX/TX limits. Checked HT20/HT40/VHT80/VHT160 constructors
encode only local equal-modulation HT MCS0..31, directional VHT MCS/NSS maps,
GI and aggregation limits. Local HT RX/TX include mandatory MCS0..7.
`with_tx_stbc(enabled)` on both local types advertises HT/VHT Tx STBC (bit7);
negotiated `tx_stbc()` additionally needs the bound peer's Rx STBC field in
the original offer and the response, as mac80211/ht.c and vht.c copy peer
Rx STBC only for a local Tx STBC transmitter (`HtNegotiation::
peer_rx_stbc_streams`). `LocalVht::with_beamforming(VhtBeamforming)`
advertises checked SU beamformee (2..8 STS), SU beamformer (2..8 sounding
dimensions) and MU beamformee roles; MU beamformer is AP-only and never
emitted. `su_beamformee`/`su_beamformer`/`mu_beamformee` require the
complementary AP role in offer and response (vht.c
ieee80211_vht_cap_ie_to_sta_vht_cap), and `Offer::advertised_vht_capability`
(the request IE) drops beamformee roles the AP cannot sound, as
mlme.c ieee80211_add_vht_ie does. HT TxBF stays zero, as in mac80211.
Native NDPA/NDP feedback, steering, STBC encoding and the single MU-MIMO
owner are backend responsibilities. Large A-MSDU limits are described with
the shared A-MSDU owner below.
`LocalVht::with_160mhz(rx_sgi160, tx_sgi160)` opts into contiguous160 and
directional SGI160. Existing constructors retain their80MHz ceiling;
`LocalPhy::vht160` requires both this explicit promise and an HT40 companion,
and `vht80` rejects a mismatched160 local promise.
`LocalHt::with_ldpc(rx, tx)` and `LocalVht::with_ldpc(rx, tx)` opt into
directional LDPC, defaulting off in existing constructors. The emitted HT
LDPC/VHT RXLDPC bits describe local receive support only. Negotiated
`rx_ldpc()` preserves that promise; `tx_ldpc()` requires actual local TX
support plus AP RX support in both scan and bound response. A response cannot
enable TX LDPC omitted by the initial offer. Native coding/decoder programming
and source authority remain each backend's responsibility.
`with_rx_stbc(enabled)` on both local types optionally advertises one STBC
receive data stream, exposed by negotiated `rx_stbc()`. It defaults off,
does not enable transmit STBC and does not imply two data-stream reception.
The native decoder must validate space-time stream metadata and the actual
data-MCS/width limits before replay or packet publication.
`LocalHt::with_greenfield(rx, tx)` explicitly opts into the HT greenfield
decoder/transmitter, defaulting off for existing local constructors. Bit4
advertises the local RX promise; `tx_greenfield()` additionally requires the
bound AP's RX bit in both original offer and response. `rx_greenfield()`
retains the independent local decoder promise. Native HT mode3 admission,
rate/space-time-stream/coding bounds and peer programming belong to the driver.
`with_tx_selection` checks a nonempty subset of actual TX support for rate
selection without changing capability IEs or granting transmit authority.
These factual values are not capabilities and
grant no channel, power, key, BA, controlled-port or publication authority.
`ApElements::parse` validates an entire IE stream of at most2048 bytes with
exact singleton HT Capabilities/Operation and VHT Capabilities/Operation pairs.
`observe_with_phy` and `JoinPlan::prepare_with_phy` opt into this admission;
the latter reparses the actual BSS and retains its own `Offer` bound to its
addresses, primary channel and original mode/rate offer. Legacy entry points
retain their existing membership-selector rejection.

`Offer::from_elements(local, ies, primary)` supplies the same pure PHY selection
for a native FullMAC AP IE snapshot. It bounds the complete stream to2048 bytes,
derives HT/VHT membership selectors internally with the existing rate parser,
requires one nonempty Supported Rates IE and known nonzero basic/legacy rates,
and rejects duplicate/malformed rate elements, unsupported mandatory selectors
and5GHz CCK basic rates. `offer.response_elements(ies)` derives response selectors
and intersects the original offer, including occupied channels, basic MCS,
directional TX maps/GI/LDPC and width limits. These APIs do not synthesize a
BSS or response and do not prove peer/status, SSID, security, legacy-rate
agreement, native channel, firmware completion, power, key or port authority.
The FullMAC owner must retain and check those independent native facts.

The opt-in path admits mandatory HT127/VHT126 membership selectors only with
the corresponding complete compatible PHY, while preserving actual legacy
basic rates for management frames. HE (122), EHT (121) and UHR (120) are
admitted only with that PHY negotiated, SAE-H2E (123) only for an H2E
`SecurityMode::Wpa3Sae` plan and EPD (124) only with the `JoinOptions::epd`
opt-in (see the HE, EHT, UHR, SAE and EPD paragraphs below). GLK (125) and
unknown mandatory values fail closed: Linux mac80211 also never adds GLK
("We do not support EPD or GLK", mlme.c), and the IEEE802.11-2020 General
Link (802.11ak) bridged-link operation has no open reference implementation
in this tree, so GLK admission is inapplicable and its ledger row was
removed (2026-10-28). Optional unflagged values grant no
membership. Present malformed or orphan PHY elements fail instead of becoming
legacy fallback. Missing optional PHY can retain legacy operation. Generated
local capability IEs are protocol-owned; caller HT/VHT capabilities and, on
this path, HT/VHT Operation IEs are rejected before first transmission.

**HE admission (`association::he`).** `LocalHe::new(mac_cap: [u8; 6],
phy_cap: [u8; 11], rx80: u16, tx80: u16) -> Result<LocalHe, Error>` takes a
driver's station-iftype HE Capabilities (IEEE802.11ax-2021 9.4.2.248; the
same octets mt76/rtw89/iwlwifi/ath11k already keep per band). Maps use the
VHT 2-bit encoding and must include single-stream HE-MCS0..7. PHY B0/B7
(reserved), B3/B4 (owned by `with_160mhz(rx, tx)` / `with_80p80(rx, tx)`,
which add the matching MCS/NSS maps) and B55 (owned by
`with_ppe_thresholds(&[u8])`, length checked with
`ieee80211_he_ppe_size`) must be clear, as must the non-AP-reserved MU
Beamformer bit. `LocalPhy::with_he(LocalHe) -> Result<LocalPhy, Error>` opts
any existing HT/VHT profile into HE (HE160 needs the VHT160 opt-in);
`LocalPhy::he()` returns it. `HeCapability::parse` / `HeOperation::parse`
(element-ID-extension 35/36, exposed through `ApElements::he_capability()`
and `he_operation()`) apply the exact `ieee80211_he_mcs_nss_size`,
`ieee80211_he_ppe_size` and `ieee80211_he_oper_size` extents; trailing or
missing octets, duplicates, an HE capability without HE operation or HT, and
six-GHz Operation Information (this plan admits only 2.4/5GHz) are malformed.
Reserved Operation bits are ignored on reception (IEEE802.11-2020 9.2.2).
Negotiation mirrors mac80211: HE is skipped (VHT/HT retained) when the AP
lacks HE, a 5GHz BSS has no negotiated VHT, the AP's own maps lack HE-MCS0..7
or its Basic HE-MCS/NSS set (`ieee80211_verify_peer_he_mcs_support`), or no
local RX/TX map pair covers that set (`ieee80211_verify_sta_he_mcs_support`,
STRICT, so the iPhone all-zero quirk is not accepted). Embedded VHT Operation
Information must agree with the VHT Operation element and is refused on
2.4GHz. `Offer/Negotiated::he() -> Option<&HeNegotiation>` reports
`width()` (the HT/VHT selection narrowed to both Channel Width Sets: B1 for
2.4GHz40, B2/B3/B4 for 5GHz40-80/160/80+80), `discontiguous()`,
`tx_mcs_map()` (local TX ∩ AP RX at that width,
`ieee80211_he_mcs_intersection`), `rx_mcs_map()`, `peer_mcs_maps()`,
`peer_capability()`, `operation()` (BSS color/partial/disabled, default PE
duration, TWT required, TXOP RTS threshold, ER SU disable, basic set,
co-hosted indicator), `local_capability()` and directional
`tx_ldpc/rx_ldpc/tx_stbc/rx_stbc/su_beamformee/su_beamformer/mu_beamformee/
htc_he/twt_requester`. The association request carries the local HE
Capabilities element only when HE was negotiated (`ieee80211_add_he_ie`);
an HE offer requires HE in the response and vice versa, and a response can
neither widen the HE width nor enable a TX map entry or directional feature
the scan offer did not allow. Drivers still program HE peer records, BSS
color, PPE/OFDMA/TWT state and regulatory/power authority themselves.

**EHT admission (`association::eht`, IEEE Std 802.11be-2024).**
`LocalEht::new(mac_cap: [u8; 2], phy_cap: [u8; 9], le80: [u8; 3])`,
`LocalEht::twenty_only(mac, phy, [u8; 4])`, `with_160mhz([u8; 3])` and
`with_ppe_thresholds(&[u8])` describe the station's EHT Capabilities
(9.4.2.323; each MCS/NSS octet is RX max NSS | TX max NSS << 4, single-stream
MCS0-7 required, 6GHz 320MHz and reserved B0 refused).
`LocalPhy::with_eht(LocalEht)` requires `with_he` and the set form
`ieee80211_eht_mcs_nss_size` derives from the local HE Channel Width Set.
`EhtCapability::parse(body, he_phy0, from_ap)` / `EhtOperation::parse`
(extension 108/106; `ApElements::eht_capability()/eht_operation()`) use the
exact Linux extents, refuse PPE fields above `IEEE80211_EHT_PPE_THRES_MAX_LEN`,
and an EHT element without HE, or a capability without operation, is
malformed. EHT is negotiated only on top of HE (mac80211
`ieee80211_determine_ap_chan`) when the Basic EHT-MCS/NSS set fits the local
<=80 and (with HE160) 160MHz sets (`ieee80211_verify_sta_eht_mcs_support`);
otherwise HE is kept. EHT Operation Information must equal the HT/VHT-selected
channel (CCFS0 = channel or primary80 centre, CCFS1 = 160 centre) without
punctured subchannels: wider, punctured or 80+80 EHT operation, which this
2.4/5GHz plan cannot represent, also falls back to HE.
`Offer/Negotiated::eht() -> Option<&EhtNegotiation>` reports `width()` (the HE
width), `tx_max_nss()`/`rx_max_nss()` per MCS0-7/8-9/10-11/12-13 range (local
TX limited by AP RX, eht.c `ieee80211_eht_cap_ie_to_sta_eht_cap`),
`su_beamformee()/su_beamformer()`, `peer_capability()`, `operation()` and
`local_capability()`. The request carries EHT Capabilities only when EHT
was negotiated; responses must keep EHT and cannot raise TX NSS or roles.
Multi-link (MLO) association is not part of `JoinPlan`.

**UHR admission (`association::uhr`, IEEE P802.11bn D1.3 draft).**
`UhrCapability::parse(body, from_ap)` / `UhrOperation::parse` implement the
draft UHR Capabilities/Operation (extension 152/151) layouts exactly as Linux
`ieee80211_uhr_capa_size_ok` / `ieee80211_uhr_oper_size_ok` (DBE capability
maps for APs only; DPS, NPCA (+bitmap), P-EDCA, DBE (+bitmap) operation
fields); `ApElements::basic_multi_link()` records a Basic Multi-Link element.
`LocalUhr::new(mac_cap: [u8; 6], phy_cap: u32)` and
`LocalPhy::with_uhr(LocalUhr)` (needs EHT) describe the station.
Admission mirrors mac80211 `check_uhr`: EHT negotiated, UHR Operation plus a
Basic Multi-Link element, the AP UHR Capabilities outside beacons, NPCA only
when the AP supports it on an80/160MHz channel with the NPCA primary in the
opposite half and unpunctured (`cfg80211_chandef_add_npca` /
`cfg80211_chandef_npca_valid`), and DBE operation consistent with the DBE
bandwidth field and the AP's DBE capability (DBE widening is not applied).
Because UHR operation is an MLD association, `JoinPlan` (single-link) never
negotiates UHR and its UHR selector stays fail-closed; a native owner whose
firmware associates as a non-AP MLD asserts
`LocalUhr::for_mld_association()` and uses `Offer::from_elements`, whose
`Offer/Negotiated::uhr() -> Option<&UhrNegotiation>` reports the peer
capability, operation and the usable `npca_channel()` (only when the local
STA supports NPCA). A response must keep or omit UHR consistently.

**EPD (`association::JoinOptions`).** `JoinPlan::prepare_with_options(bss,
own, ssid, security, Option<LocalPhy>, JoinOptions { epd })` is the
additive entry point for native framing opt-ins. With `epd` the request sets
the Capability Information EPD subfield (bit13, IEEE802.11-2020 9.4.1.4) and
an EPD-mandatory BSS (selector 124, which must also advertise bit13) is
admitted; the response must keep bit13. `JoinPlan::epd()` is true only for
such a BSS, and the owner then builds `station_security::Security` with
`with_epd(true)`: every MSDU, EAPOL included, carries a bare two-octet
EtherType (5.1.4 EtherType Protocol Discrimination) instead of RFC1042,
length values and RFC1042 MSDUs are ignored, RFC1042 A-MSDU transmit/receive
is refused, and `Security::ethernet(frame)` converts admitted data in either
discrimination. A BSS that does not mandate EPD keeps LPD framing.
`JoinOptions` is built from `JoinOptions::default()` with the
`with_epd(bool)`, `with_akms(AkmSet)` and `with_pmf(Pmf)` builders (or
`..Default::default()`); every field defaults to the earlier behaviour.

**AKM capability and WPA2 PMF (`association::{AkmSet, Pmf}`).**
`JoinOptions::akms: AkmSet` declares the AKM suites the owner's key path
implements (cfg80211 `wiphy->akm_suites`): `AkmSet::{NONE, PSK, PSK_SHA256,
SAE, SAE_EXT_KEY, LEGACY, ALL}` with `with`, `without` and
`contains_suite(u8)`. The default `AkmSet::LEGACY` (PSK, SAE, SAE-EXT-KEY)
keeps the earlier selection. The plan picks the most preferred AKM the AP and
the set share, in wpa_supplicant `wpa_pick_key_mgmt` order (SAE-EXT-KEY under
H2E, SAE, PSK-SHA256, PSK). A driver without AKM 24's group-19 HMAC-SHA-256
EAPOL MIC passes `AkmSet::LEGACY.without(AkmSet::SAE_EXT_KEY)` and an AP that
offers AKM 8 and 24 joins with AKM 8. If no AKM is shared, the result is
`UnsupportedSecurity`. `JoinOptions::pmf: Pmf` is wpa_supplicant `ieee80211w`
for `SecurityMode::Wpa2Psk`:
- `Disabled` is the default and keeps the earlier no-MFPC body, refusing an
  MFPR AP.
- `Optional` advertises MFPC.
- `Required` advertises MFPC|MFPR and refuses an AP without MFPC.

PMF is in force when both RSNEs set MFPC; the AP's group management cipher
must then be the default BIP-CMAC-128. With `AkmSet::PSK_SHA256` the plan
also negotiates AKM 6 (PSK-SHA256), so PMF-required WPA2 APs that offer only
AKM 6 can be joined as Linux does. `JoinPlan::akm() -> Option<KeyMgmt>` and
`JoinPlan::pmf() -> bool` (always true for SAE) report the outcome.
`rsn_body()` returns the negotiated RSNE, and an association-response RSNE
must repeat it. `Security::new` accepts that RSNE (AKM 2/6, MFPC,
MFPC|MFPR, SPP) and `Security::pmf()` is then true when both sides set
MFPC: the IGTK is required in M3, BIP and unicast robust-frame CCMP apply as
for SAE. `Security::new_sae` refuses non-SAE AKMs.

**6 GHz band identity (`association::{channel, six_ghz}`, `reg`).**
`channel::Band` gains `Ghz6`. `channel::band(u8)` still classifies only the
2.4/5 GHz legacy numbering and never returns it.
- `channel::frequency_in(Band, u8) -> Option<u32>` is cfg80211
  `ieee80211_channel_to_freq_khz` in MHz (6 GHz: 5950 + 5n MHz, channel 2 =
  5935 MHz).
- `channel::from_frequency_band(mhz) -> Option<(Band, u8)>` is the inverse.
- `channel::valid_6ghz(u8)` tests a 6 GHz channel number.

`association::Bss` gains `band: Option<Band>`. `None` means the 2.4/5 GHz
numbering, so existing literals add `band: None`. `Bss::band()` returns the
explicit band or the derived one, and `Bss::frequency_mhz()` returns the
primary frequency. `observe` records the explicit band. `prepare`,
`prepare_with_phy` and `prepare_with_options` stay 2.4/5 GHz plans and
refuse a BSS whose explicit band disagrees with `channel::band(channel)`,
so a 6 GHz channel 1 is never joined as 2412 MHz. Only `prepare_6ghz`
(below) joins a 6 GHz BSS.
The `scan::BssInfo.frequency_mhz` scan identity is unchanged.

`he::HeOperation::parse` accepts 6 GHz Operation Information and exposes it
as `six_ghz_operation() -> Option<six_ghz::He6GhzOperation>`. The 2.4/5 GHz
`phy::ApElements` parser still refuses an HE Operation that carries it.

`six_ghz::He6GhzOperation { primary, control, ccfs0, ccfs1, min_rate }`
provides:
- `channel() -> Result<SixGhzChannel, Error>`: mac80211
  `ieee80211_chandef_he_6ghz_oper`, HE-only path. It returns 20/40/80/160 or
  80+80 MHz, `center_mhz` and `center2_mhz`, with the primary validated
  inside an aligned span.
- `regulatory_info()`.
- `power_type(no_afc_client) -> Option<reg::PowerType6Ghz>`: cfg80211
  `cfg80211_6ghz_power_type`, Linux v7.2 four-bit REG_INFO, where Indoor SP
  falls back to LPI under NO_6GHZ_AFC_CLIENT.
- `duplicate_beacon()`.

`six_ghz::He6GhzCapability` (element ID extension 59,
`EXT_HE_6GHZ_CAPABILITIES`; `parse`, `new`, `bits`, `min_mpdu_start`,
`max_ampdu_len_exp`, `max_mpdu_len`, `sm_ps`, `rd_responder`, `element()`)
is the band capability. `ieee80211_put_he_6ghz_cap` builds it from the
station's own values.

`six_ghz::admit(ies, primary) -> Result<SixGhzBss, Error>` is mac80211
`ieee80211_determine_chan_mode` for 6 GHz. HE Capabilities, HE 6 GHz Band
Capabilities and an HE Operation with 6 GHz information whose primary equals
the receive channel are all required, there is no legacy fallback, and every
element appears once. A missing capability is `UnsupportedRates`. The result
`SixGhzBss` carries both HE elements, the band capability, the 6 GHz
operation, the channel and the power type.
`six_ghz::admit_with_rule(ies, primary, &RegRule)` also applies cfg80211
`cfg80211_6ghz_power_type_valid` (`UnsupportedRates` on a power mismatch).

`reg::RegFlags` gains `NO_6GHZ_VLP_CLIENT` and `NO_6GHZ_AFC_CLIENT` (NRGD flag
bits 4 and 5; nl80211 `NL80211_RRF_NO_6GHZ_*_CLIENT`). It is joined by
`reg::PowerType6Ghz { Lpi, Sp, Vlp }` and the `RegRule` methods
`covers_mhz`, `no_6ghz_afc_client` and `allows_6ghz_client(PowerType6Ghz)`.
`RegRule` also derives `Debug`, `PartialEq` and `Eq`.

**6 GHz JoinPlan (`JoinPlan::prepare_6ghz`, `six_ghz::{SixGhzLocal,
SixGhzPlan, SixGhzOperatingChannel, SixGhzWidth, plan}`).** Drivers that
associate through firmware can still use `six_ghz::admit` alone for the
station-side admission facts.
- `six_ghz::SixGhzLocal::new(LocalHe, He6GhzCapability, RegRule)` holds the
  station's 6 GHz HE profile, its band capability (`sband_iftype_data.
  he_6ghz_capa`; zero is refused) and the regulatory rule covering the BSS
  primary. `with_eht(LocalEht)` adds EHT. `transmitted_capability()` is
  mac80211 `ieee80211_put_he_6ghz_cap` with SMPS off (SM PS = disabled).
  `regulatory_connectivity()` is `ieee80211_put_reg_conn` (LPI valid/set, SP
  valid, SP set unless `NO_6GHZ_AFC_CLIENT`).
- `eht::LocalEht::with_320mhz([u8; 3])` adds the 6 GHz 320 MHz set and PHY
  B1 (it needs the 160 MHz set). `width320()` reports it, and
  `phy::LocalPhy::with_eht` (2.4/5 GHz) refuses such a profile.
  `eht::EhtNegotiation::width320()` is true for a 320 MHz selection, whose
  `width()` reports `OneSixty`.
- `JoinPlan::prepare_6ghz(bss, own, ssid, security, &SixGhzLocal,
  JoinOptions)` needs `bss.band == Some(Band::Ghz6)` and a 6 GHz channel. It
  calls `six_ghz::plan`, which is mac80211 `ieee80211_determine_chan_mode`
  for `NL80211_BAND_6GHZ`. That applies `admit_with_rule` against the rule,
  covering power types LPI/SP/VLP, where SP needs AFC and is refused under
  `NO_6GHZ_AFC_CLIENT` (Indoor SP then falls back to LPI). The channel comes
  from the 6 GHz Operation Information (`ieee80211_chandef_he_6ghz_oper`),
  or from EHT Operation Information when local EHT and both AP EHT elements
  are present. The EHT channel must contain the HE channel (STRICT "HE/EHT
  incompatible", `InvalidBss`), and a punctured or 80+80 EHT BSS is joined
  as HE. The channel is then narrowed to both stations' Channel Width Set:
  HE B2 (40/80), B3 (160), B4 (80+80), and EHT B1 for 320 MHz, which needs
  negotiated EHT. HE is mandatory, so no usable HE is `UnsupportedRates`.
  Rates are OFDM-only, as on 5 GHz.
- 6 GHz security: Linux v7.2 mac80211/cfg80211 do not enforce the
  802.11ax 6 GHz security rule on the station side; wpa_supplicant's 6 GHz
  BSS filter does. NARF has no separate BSS filter, so `prepare_6ghz`
  refuses `Open` and `Wpa2Psk` (`UnsupportedSecurity`) and requires
  `Wpa3Sae` to resolve to hash-to-element. SAE already requires an
  MFP-capable AP and sends MFPC|MFPR (PMF required). OWE is not a
  `SecurityMode`.
- The association request carries no HT or VHT element. After RSNE/RSNXE
  it sends HE Capabilities, HE 6 GHz Band Capabilities (ext 59), Non-AP STA
  Regulatory Connectivity (ext 137, `six_ghz::EXT_NON_AP_STA_REG_CON`) and,
  when negotiated, EHT Capabilities. `append_sme_ies` refuses HT/VHT
  Capabilities/Operation on a 6 GHz plan. The association response must
  carry no HT/VHT element, exactly one HE Capabilities and one HE
  Operation, and an RSNE that repeats the request's.
- `JoinPlan::six_ghz() -> Option<&SixGhzPlan>` is `None` for 2.4/5 GHz
  plans. The state is boxed, adding 8 bytes to `JoinPlan`. `SixGhzPlan`
  exposes `operation()` (`He6GhzOperation`), `power_type()`,
  `channel() -> &SixGhzOperatingChannel` (`primary`, `primary_mhz`,
  `width: SixGhzWidth { Twenty, Forty, Eighty, OneSixty, ThreeTwenty }`,
  `discontiguous`, `center`/`center_mhz`, `center2`/`center2_mhz`),
  `width()`, `peer_capability()` and `local_capability()` (the AP's and the
  transmitted `He6GhzCapability`, for STA_REC_HE_6G), `regulatory_
  connectivity()`, `he() -> &HeNegotiation` (at most 160 MHz) and
  `eht() -> Option<&EhtNegotiation>`.

2.4/5 GHz plans are byte-for-byte unchanged.

**Colocated 6 GHz scan (`scan::{parse_colocated_aps, plan_6ghz_scan,
ColocatedAp, Scan6GhzPlan, Scan6GhzTarget, short_ssid, is_psc_6ghz}`).**
- `parse_colocated_aps(ies) -> Vec<ColocatedAp>` is cfg80211
  `cfg80211_parse_colocated_ap` (Linux v7.2 net/wireless/scan.c). It reads
  the Reduced Neighbor Report elements (`EID_REDUCED_NEIGHBOR_REPORT` = 201)
  of one 2.4/5 GHz beacon or probe response and keeps only TBTT-type entries
  with a 6 GHz operating class (131..=135, 137), a TBTT length of 8, 9 or at
  least 12, a valid unicast BSSID and the colocated-AP bit. Disabled MLD
  links and repeated BSSID/channel pairs are dropped. A malformed RNR, or a
  missing or oversized SSID element, yields nothing.
- `ColocatedAp` carries `bssid`, `channel`/`frequency_mhz`, `short_ssid`
  (reported, or the reporter's when `same_ssid`), `ssid` (when
  `same_ssid`), the BSS-parameter flags (`oct_recommended`, `same_ssid`,
  `multi_bss`, `transmitted_bssid`, `unsolicited_probe`, `colocated_ess`)
  and `psd_20` (`PSD_RESERVED` when absent).
- `plan_6ghz_scan(&ScanRequest, &[ColocatedAp], bssid) -> Scan6GhzPlan` is
  `cfg80211_scan_6ghz`. Without `ScanRequest::colocated_6ghz` it scans
  every requested 6 GHz frequency and produces no targets. With it, PSC
  channels (`is_psc_6ghz`: channel % 16 == 5) are scanned blind unless a
  directed one-SSID scan found a colocated-ESS AP with that SSID. Each
  colocated AP on a requested channel that matches the SSIDs
  (`cfg80211_find_ssid_match`, by SSID or `short_ssid()` CRC-32) and the
  optional BSSID becomes a `Scan6GhzTarget` (`frequency_mhz`, `channel`,
  `bssid`, `short_ssid`, `unsolicited_probe`, `psd_20`, `psc_no_listen`).
  Channel usability stays with the driver.
- `ScanResult` gains `colocated_6ghz: Vec<ColocatedAp>`, so a driver that
  honours `colocated_6ghz` can return the APs it collected. `BssInfo` and
  `ScanRequest` are unchanged.

**WPA3-SAE JoinPlan (`association::{SaePwe, SaeJoin, SaeStep}`).**
`SecurityMode::Wpa3Sae { pwe: SaePwe }` (`HuntAndPeck` / `HashToElement` /
`Both` = wpa_supplicant `sae_pwe` 0/1/2; `is_sae()`, `is_rsn()`; `is_wpa2()`
stays PSK-only) admits APs as wpa_supplicant with `ieee80211w=2`: Privacy,
CCMP-128 group/pairwise, no No-Pairwise, AP MFPC, default or BIP-CMAC-128
group management cipher, and AKM 24 (SAE-EXT-KEY) preferred under H2E, else
AKM 8. The AP RSNXE (one checked element) supplies SAE H2E; the SAE-H2E
membership selector requires it and an H2E PWE (`UnsupportedRates`
otherwise, like mac80211's selector subset check). `JoinPlan::sae() ->
Option<&SaeJoin>` exposes `akm()`, `h2e()`, `akm_suite_selector()`,
`pmkid()`, `station_rsne(pmkid)` and `station_rsnxe()` (H2E for sae_pwe 1/2,
`wpa_gen_rsnxe`). The driver builds the `SaeSession` (H2E or
hunting-and-pecking per `h2e()`, `with_akm_suite_selector` for AKM 24) and
its Commit from its own entropy, then calls
`start_sae_authentication(&SaeSession) -> Result<&[u8], Error>` (binds the
MAC pair, PWE method and AKM selector; SAE-PK sessions are refused because
KeyAuth verification needs the caller's password) and feeds frames to
`sae_authentication_response(&[u8], &mut SaeSession) ->
Result<SaeStep, Error>`: `Transmit` (Confirm, or a Commit carrying an
anti-clogging token, at most `MAX_ANTI_CLOGGING` = 3 rounds, group 19 only),
`Ignored` (other peers, a reflected Commit, a retransmitted peer Commit) or
`Associate` (the association request with the SAE PMKID spliced into its
RSNE). Status codes other than 0/126/76 are terminal `Rejected`; a Commit
status that disagrees with the PWE method or a Confirm before the peer
Commit is `Protocol`. `sae_pending_frame()` supplies retransmissions;
`start_authentication`/`authentication_response` refuse SAE plans. The PMK
never enters the plan. `rsn_body()` returns the PMKID-bearing RSNE for the
supplicant; an association-response RSNE must repeat it.
`station_security::Security::new_sae(own, peer, pmk, station_rsne,
station_rsnxe, ap_rsne, ap_rsnxe, sequence)` is the matching PMF owner (see
3.4.2). AKM 24 uses `eapol::KeyMgmt::SaeExtKey` (group 19: KCK/KEK/MIC 16,
HMAC-SHA-256-128 version-0 MIC, hostap `wpa_eapol_key_mic`), and
`SaeSession::with_akm_suite_selector([u8; 4])` adds/validates the AKM Suite
Selector element (hostap `sae_write_commit` / `sae_parse_commit`; H2E only).

`offered_phy()` and `negotiated_phy()` expose read-only directional HT/VHT
facts, the selected width/center and complete occupied20MHz channel set.
TX intersects local implementation with AP RX from both scan and response;
local advertised RX limits and AP TX metadata remain independent. Strict
HT Basic MCS and both-direction VHT Basic MCS/NSS checks apply, including
the all-eight-NSS requirement of VHT basic map0. Selected HT requires a bound
complete response pair. VHT width0 delegates to HT; contiguous80MHz validates
all four canonical constituents and the matching HT40 primary pair.
Contiguous160 uses canonical centers50/114/163, all eight20MHz constituents,
the actual HT40 pair and a valid peer160-width capability. Both deprecated
width2/seg0 and revised width1/primary80-seg0/full160-seg1 encodings are
checked. An80MHz local station may select the actual primary80 half while
advertising only80MHz support. `Width::OneSixty` exposes the eight-channel
selection to the native owner. Reserved width encodings remain unsupported.
`LocalVht::with_80p80` opts into discontiguous80+80 (Supported Channel Width
Set2). The revised width1 encoding with a non-adjacent second CCFS, or
deprecated width3, selects two canonical80 segments with the primary in
seg0; adjacent/overlapping/noncanonical segments, or an AP without 80+80
support, fail closed. The selection reports `Width::OneSixty` (VHT-SIG-A
CBW160/80+80), `discontiguous()`, `center_channel()` = seg0 and
`secondary_center_channel()`; `occupied_channels()` lists all eight. A
local station without the opt-in uses the primary80 segment.
`LocalVht::with_extended_nss_bw(true)` declares VHT Extended NSS BW Capable
(Linux IEEE80211_HW_SUPPORTS_VHT_EXT_NSS_BW): the AP's Extended NSS BW
Support is then interpreted per IEEE802.11-2020 Table 9-272, including the
HT Operation CCFS2 second segment where mac80211 ieee80211_chandef_vht_oper
uses it, and the 160/80+80 TX map is truncated to the AP's reduced NSS
(cfg80211 ieee80211_get_vht_max_nss); reserved supported-width/ext
combinations fail closed. A non-capable station reads the AP field as0, so
APs advertising Extended NSS BW are admitted with their legacy width.
SGI160 transmit use cannot gain a peer capability omitted from the original
scan offer.
A response may narrow the original occupied set but cannot expand it. All
address/status/AID/security/rate/membership/PHY checks precede one atomic
rate/PHY/Associated transition; failure leaves old rates and no partial PHY
result. Drivers must separately reconfigure native state on narrowing, program
protection/EDCA/peer records, enforce current regulatory and measured power
authority for every occupied channel, and complete key/port transactions.

`wmm::{Parameters, Ac, Error, INFORMATION}` parses one WMM v1 Parameter
element in a complete IE stream of at most4096 bytes. It validates exact
OUI/type/subtype/version/length/reserved fields and four distinct ACIs, and
returns canonical BE/BK/VI/VO rows (AIFSN, ECW exponents, TXOP in32us units,
ACM), the AP parameter-set count and U-APSD bit. `Ac::cw_min/cw_max` expand
the checked four-bit exponents. Information-only or absent WMM returns None;
duplicates including Information+Parameter reject. ECW0 and ACM remain wire
facts, not an admission decision. Drivers bind the actual association response,
select hardware queues, enforce BE/TSPEC/regulatory/power policy and retain
native ownership themselves. The fixed station Information IE requests no
U-APSD or service period. This parser grants no association, radio or TX authority.

`association::{Bss, JoinPlan, SecurityMode, Phase}` supplies the shared
legacy SoftMAC management plan extracted from MT76. It validates bounded AP
IEs, SSID, supported/basic rates and Open or WPA2-PSK/CCMP negotiation, builds
open-authentication and association requests, and binds responses to the
local/AP addresses, transaction phase, status and AID. `SecurityMode` carries
no PMK. Fragmented responses (including a final fragment with nonzero
SequenceControl fragment number) leave the phase unchanged.
`mgmt_defrag::Reassembler` is the admission path for them: it reassembles
unprotected unicast management MPDUs per IEEE802.11-2020 10.6/10.7 with
mac80211 ieee80211_rx_h_defragment's four-entry round-robin cache,
two-second lifetime and consecutive fragment numbers within one TA/SN/frame
type. Gaps, duplicates and foreign fragments are dropped without disturbing
buffered sequences; group-addressed or protected fragments and results above
4096 bytes are refused. The result is the first fragment's header with More
Fragments cleared plus the concatenated bodies, which the plan admits like an
unfragmented response. The native owner still binds channel/peer, CRC and
Retry duplicate detection before pushing.
`append_sme_ies` accepts checked optional elements before first TX;
`legacy_rates()` returns IEEE-rate bitmaps rather than hardware indices.
Before association those bitmaps describe the offered scan-time set. A
successful legacy association response must contain one nonempty Supported
Rates element (at most eight rates) and at most one nonempty Extended Supported
Rates element. Negotiation intersects the response with the actual offer,
preserves every beacon-mandatory basic rate and admits a new basic rate only
if it was offered. Unknown mandatory rates/membership selectors, empty
intersections, lost mandatory rates and mandatory CCK on 5GHz fail closed.
Missing Basic flags retain beacon requirements. Malformed or duplicate rate
elements fail the transaction; neither the AID nor rate bitmaps commit until
all checks pass. A matching invalid response leaves the plan Failed and its
old bitmaps unchanged. Response rates cannot grant PHY, key or port authority.
`association::channel` exposes the existing 2.4/5GHz legacy 20MHz geometry.
Drivers retain their own rate-index mapping, radio/regulatory authority,
firmware peer records, retained supplicant, key installation and controlled
port. `Associated` alone grants none of those. MT76 preserves its existing
public driver API through a wrapper; RTL8188EU uses the common plan directly.

`association::observe(&impl RawFrame, channel, own, signal_dbm)` decodes a
bounded unmodified legacy beacon/probe response into `ObservedBss`, retaining
the original IEs and AP RSNE/RSNXE bodies plus IEEE supported/basic rate
bitmaps. It binds receiver/transmitter/BSSID and optional DS channel IEs to
the supplied retained radio channel; malformed or duplicate SSID/rate/security
elements, fragments, modified RX and unsupported mandatory rates fail.
The caller supplies native signal converted to dBm, or None. Hardware
channel/PHY qualification, mandatory driver rates, signed radio policy,
connection state and transmit/key authority remain driver-owned. Observed
facts still pass through `JoinPlan` security and association negotiation.

`wireless::register_initcalls()` installs the bootstrap `trusted_net_authority` into `narf_net`
and registers nl80211 during boot initialization, ensuring network interface registration authority
is available before any device driver probes.

### 3.1 Interface Specialization

```rust
pub struct WirelessIfaceInfo {
    pub base: IfaceInfo,
    pub bands: Vec<WirelessBand>,    // 2.4 GHz, 5 GHz, 6 GHz
    pub modes: WirelessModes,        // Station, AP, P2P, Monitor
    pub hw_caps: HwCaps,             // HT (802.11n), VHT (ac), HE (ax), EHT (be)
}
```

`WirelessNetIface::tx_ring_for_ac(AccessCategory)` exposes separate Ethernet
producers for Background, BestEffort, Video and Voice. The default implementation
returns the ordinary `Interface::tx_ring()` for drivers with one queue.
The iwlwifi MLD implementation owns four Narf-Rings, each with an async TX
consumer and its negotiated hardware queue. AP admission control may downgrade
a class; non-WMM links use the best-effort hardware queue. The generic network
interface's `tx_ring()` remains the BestEffort ring.

`WirelessNetIface::max_scan_ssids() -> u8` reports the active-scan SSID limit,
including wildcard entries. The conservative default is zero (passive-only).
nl80211 advertises this exact limit in `MAX_NUM_SCAN_SSIDS` and rejects explicit
requests which exceed it before driver dispatch. A CONNECT without a cached BSS
chooses a directed active scan only when the limit is nonzero; otherwise it
requests passive discovery without SSID entries and applies the requested SSID,
BSSID, frequency and security filters to the observed results. This does not
downgrade explicit active scans or grant probe-transmit authority. Intel exposes
20 entries; ath10k, ath11k and the shared CYW/BCM FullMAC facade expose 16.
MT76 and AR9285 expose four; the initial Realtek profiles advertise zero.

`WirelessNetIface::phy_capabilities(band_mhz) -> Option<PhyCapabilities>`
returns band-specific IEEE HT (26-byte) and optional VHT (12-byte) capability
bodies. The default returns `None`. Band identifiers are 2400, 5000, and
6000 MHz. Six-GHz HE capability bodies remain driver-specific until the
generic interface grows an HE representation.
Drivers must restrict these capabilities to implemented PHY modes and their
NVM/antenna limits; `HwCaps` remains a summary. The iwlwifi Sc profile exposes
up to two streams, HT20/40 and VHT20/40/80, with firmware TX A-MPDU and host
RX Block Ack reordering. Actual association intersects AP capabilities and
regulatory permission before programming firmware.

`WirelessNetIface::supports_gtk_rekey_offload()` and
`set_gtk_rekey_data(GtkRekeyData)` model mac80211's `set_rekey_data` hook.
`GtkRekeyData` contains a 16-byte KEK, 16-byte KCK, optional AKM and the
eight-byte **big-endian** nl80211 replay counter. The generic interface never
logs or returns KEK/KCK. `NL80211_CMD_SET_REKEY_OFFLOAD` accepts this data
only on an associated, administratively-up interface; the driver retains it
until its low-power lifecycle enables firmware offload. After firmware
rekeying, `notify_gtk_rekey` multicasts the same command with only the AP MAC
and nested `REKEY_DATA_REPLAY_CTR`, matching `cfg80211_gtk_rekey_notify`.

`ScanRequest::frequencies_mhz`, `BssInfo::frequency_mhz`,
`AssociateRequest::frequency_mhz` and the userspace-SME
`MlmeAuthRequest::frequency_mhz` / `MlmeAssocRequest::frequency_mhz`
(AUTHENTICATE / ASSOCIATE's `NL80211_ATTR_WIPHY_FREQ`) are the authoritative
centre-frequency identities in MHz. `BssInfo::channel` remains the IEEE channel number for
presentation and legacy callers, but is not sufficient to distinguish 6 GHz
from the same numbered 2.4/5 GHz channels. A scan request that supplies
frequencies uses them in preference to its legacy `channels` list; an
association must retain the selected BSS's exact frequency.

`ApConfig::frequency_mhz` follows the same rule: `START_AP` retains the
exact `NL80211_ATTR_WIPHY_FREQ`, not only its derived channel number, because
6 GHz channel 1 is otherwise indistinguishable from 2.4 GHz channel 1.
`ApConfig::{channel_width,center_freq1_mhz,center_freq2_mhz}` retain the
`NL80211_ATTR_CHANNEL_WIDTH` channel definition. Drivers validate its
geometry and every constituent regulatory channel; 20/40/80/160 and 80+80
must never be silently reduced to a different on-air BSS.
`MbssidSupport` exposes a physical wiphy's
`NL80211_ATTR_MBSSID_CONFIG` maxima. When present, `START_AP` accepts the
nested MBSSID role (`INDEX`, optional self `TX_IFINDEX`, or a distinct
transmitting `TX_IFINDEX`), complete `MBSSID_ELEMS`, and EMA's matching
`EMA_RNR_ELEMS`. The generic layer validates profile count, same/different
ifindex form, EMA periodicity and complete RNR IE framing; the driver must
also verify that the named transmitter is an AP on the same physical wiphy.
`ApConfig` retains these values so the driver can form the transmitter's
ordinary or per-profile EMA beacon templates. Deleting a transmitting virtual
interface also deletes its non-transmitting profiles, as cfg80211 specifies.
`FilsDiscoveryConfig` and `UnsolBcastProbeRespConfig` retain the complete
six-GHz discovery templates supplied by `START_AP`; their 10,000-TU / 20-TU
interval and Linux frame-size bounds are checked at the netlink boundary.
`SET_BEACON` preserves per-attribute presence through
`set_ap_discovery`: an empty nested attribute is an explicit disable/delete,
while an absent attribute leaves that discovery family unchanged. A
`CHANNEL_SWITCH` may carry the unsolicited-probe form; it becomes active only
after the driver has moved the AP vdev to the requested chandef.
`FtmResponderConfig` represents the enabled nested
`NL80211_ATTR_FTM_RESPONDER` form and its optional LCI/Civic Measurement
Report bodies. A driver advertises it only when it can enable the target's
responder role; `START_AP`, `SET_BEACON`, and a post-switch beacon retain and
apply the request in their normal ordered AP transaction.
`ApConfig::twt_responder` represents START_AP's empty
`NL80211_ATTR_TWT_RESPONDER` flag. A driver advertises this only when it can
enable its AP responder role; it applies the target's pdev-wide default TWT
engine after the AP is live and disables it as the AP stops.
`HeObssPdConfig` represents `START_AP`'s nested `NL80211_ATTR_HE_OBSS_PD`
spatial-reuse policy: mandatory SR control, optional 1..=20 offsets, and the
two exact eight-byte SRG bitmaps. It is pdev-scoped target state even though
cfg80211 supplies it with one AP request; a driver applies the threshold,
per-AC and SR-prohibit settings after that AP vdev is live, followed by the
six SRG/non-SRG bitmap commands when firmware supports SRG reuse.
`HeBssColorConfig` represents the mandatory 1..=63 color plus the disabled
and partial flags of `NL80211_ATTR_HE_BSS_COLOR`. A driver that advertises
`NL80211_EXT_FEATURE_BSS_COLOR` must retain the value on `START_AP`,
`SET_BEACON`, and a post-switch beacon, and apply it only after the relevant
AP vdev start/restart. The exact firmware operation may require both
collision-detection configuration and a separate vdev color parameter; the
partial flag is retained even on targets whose WMI representation omits it.
Target collision indications are coalesced with mac80211's 500-ms rule and
published as the MLME multicast `NL80211_CMD_OBSS_COLOR_COLLISION`, carrying
the interface index and native-endian 64-bit `NL80211_ATTR_OBSS_COLOR_BITMAP`.
An MBSSID transmitter mirrors each stable color/enabled update to its live
non-transmitting profiles through their own driver-control streams, matching
mac80211's shared transmitting-BSS configuration while preserving ordered
firmware access per vdev.
`ColorChangeConfig` models AP-only `NL80211_CMD_COLOR_CHANGE_REQUEST`: it
keeps the normal post-change beacon separately from the nested temporary
countdown beacon, validates one native-endian beacon counter offset and an
optional Probe-Response offset, and retains an optional unsolicited broadcast
Probe-Response update. A BSS-color-capable driver rejects P2P-GO,
non-transmitting MBSSID, concurrent color-change and CSA requests. It emits
MLME `COLOR_CHANGE_STARTED` (with the u32 count), then `COMPLETED` after it
installs the normal template and enables the requested color; a failed queued
transition restores the retained template/color and emits `ABORTED`.
`set_beacon(head, tail)` preserves attribute presence (`None` means unchanged;
an empty supplied vector clears that template piece). `WirelessNetIface`
provides a down-only `set_iftype(NL80211_IFTYPE_*)` hook for drivers with
multiple WMI vdev roles; it must reject a type change while a vdev exists.

### 3.1.1 Physical wiphys and virtual interfaces

`WirelessNetIface::wiphy_id() -> u64` identifies the physical radio, not a
netdev. The wireless registry groups every registered interface by that id:
`GET_WIPHY` emits one physical record per group, while `GET_INTERFACE` emits
each visible netdev with that group's `WIPHY` value and an interface-unique
`WDEV` id. The default `wiphy_id` is a stable name hash for simple drivers;
multi-vdev hardware must override it with its physical-radio identity.

Drivers which can create firmware vdevs opt in through
`supports_virtual_interfaces`, `new_virtual_interface(name, iftype, mac)`,
and `delete_virtual_interface`. `NL80211_CMD_NEW_INTERFACE` is addressed to
the physical `WIPHY`; it validates the requested name, supported iftype and
unicast MAC before delegating allocation. `NL80211_CMD_DEL_INTERFACE` is
addressed to the target `IFINDEX`. It removes the interface from generic
discovery immediately; a driver whose teardown waits for firmware completes
the vdev's asynchronous stop before releasing its hardware slot. The base
physical netdev is never deletable through this virtual-interface hook.

`WirelessNetIface::station_info() -> Option<StationInfo>` supplies the
measurements `GET_STATION` may truthfully publish. `RateInfo` reports the
calculated rate in 100 kb/s plus exactly one PHY family: legacy (no MCS), HT
(`ht_mcs`), VHT (`vht_mcs = MCS, NSS`), or HE (`he_mcs = MCS, NSS, GI`, where
GI is the `nl80211_he_gi` ordinal). An HE rate also carries its explicit
`he_dcm` boolean, which nl80211 serializes as `NL80211_RATE_INFO_HE_DCM` even
when clear. `width_mhz` is 20/40/80/160 for a full channel rate. HE OFDMA
instead sets `he_ru_alloc` to the
`nl80211_he_ru_alloc` ordinal (26 through 2×996 tones); nl80211 emits
`HE_RU_ALLOC` and deliberately omits a width attribute in that case. A driver
leaves unavailable TX or RX measurements absent rather than inferring them.
`StationInfo::{tx_duration_us,rx_duration_us}`, when present, are the u64
`NL80211_STA_INFO_{TX,RX}_DURATION` aggregate PPDU airtimes in microseconds;
neither is a packet-count-derived estimate. `chain_signal_dbm` is the indexed
eight-chain `NL80211_STA_INFO_CHAIN_SIGNAL` nested array; unavailable chains
remain absent rather than being fabricated from combined signal.

`WirelessNetIface::supports_survey()` and `survey_info() -> Vec<SurveyInfo>`
opt a physical radio into dump-only `GET_SURVEY`.  Each `SurveyInfo` describes
one enabled channel and may provide its signed dBm noise floor plus the
monotonic millisecond `TIME`, `TIME_BUSY`, `TIME_RX`, and `TIME_TX` counters;
the generic layer emits only measurements the driver supplied.  It marks
`IN_USE` from the physical radio's current channel context, rather than from a
cached sample, so a record remains useful before its first hardware update.

`WirelessNetIface::antenna_info() -> Option<AntennaInfo>` publishes current
and immutable available TX/RX chain masks. `SET_WIPHY` normalizes an all-ones
TX/RX pair to those available masks, rejects zero or unavailable bits, and
calls `set_antenna(tx, rx)` only when both halves are supplied. A driver that
returns `rts_threshold()` also accepts `SET_WIPHY`'s u32 RTS value through
`set_rts_threshold`; radio-wide policies must be retained for recovery and
for later virtual-interface creation. `SET_WIPHY`'s
`NL80211_ATTR_WIPHY_FRAG_THRESHOLD` goes to
`WirelessNetIface::set_fragmentation_threshold(u32) -> Result<(), i32>` after
`nl80211_set_wiphy`'s validation: values below 256 are `-EINVAL`, `u32::MAX`
disables fragmentation, and other values are rounded down to an even length.
The default is `-EOPNOTSUPP` (ath11k keeps it because its target firmware
cannot transmit More Fragments frames). A driver that implements the setter
reports the retained value through `fragmentation_threshold()`, and a wiphy
that reports one also advertises `SET_WIPHY`.

`TxBitrateMask` / `TxBitrateBand` carry the complete nested
`NL80211_ATTR_TX_RATES` request: the `nl80211_band` ordinal selects one band,
and optional legacy, ten-byte HT, eight-u16 VHT, GI, eight-u16 HE, HE-GI and
HE-LTF fields retain their nl80211 representation. A missing band or PHY
field means cfg80211's automatic negotiated-rate set; an empty outer list
resets every band to that default. `supports_tx_bitrate_mask` advertises
`NL80211_CMD_SET_TX_BITRATE_MASK`; its setter receives validated HT/VHT/HE
wire fields only after the netlink layer has rejected malformed field sizes,
invalid GI/LTF ordinals, duplicate nested attributes, and unsupported EHT
rate fields. A driver applies the selected active-band policy to every live
peer and retains it for new associations and hardware recovery. It must
return `-EPERM` when no channel context exists rather than guessing a band.

`WirelessNetIface::tx_power_dbm() -> Option<i32>` is the non-blocking
effective transmit-power snapshot for one netdev. When present,
`GET_INTERFACE` serializes it as `NL80211_ATTR_WIPHY_TX_POWER_LEVEL` in
signed mBm (`dbm * 100`), exactly as cfg80211's `get_tx_power` callback
result. The getter is observational only; its caller is a generic-netlink
read path and must never wait for a firmware statistics transaction.

`supports_station_tx_power()` advertises
`NL80211_EXT_FEATURE_STA_TX_PWR`; `StationTxPower` preserves the automatic,
limited-dBm, and fixed `NL80211_ATTR_STA_TX_POWER_SETTING` forms. A limited
setting requires the signed-16-bit `NL80211_ATTR_STA_TX_POWER`; a stray power
attribute without a setting is ignored as Linux's parser does. Both
`NEW_STATION`/`SET_STATION` for AP clients and `SET_STATION` on a managed
station validate the physical wiphy feature before reaching the driver. The
driver receives the named associated peer, returns its native dBm-range errno,
and retains a managed-station request for reassociation/recovery. `Fixed`
remains a distinct request because Linux ath11k accepts its enum form but
rejects the absent dBm value with `-EINVAL`.

`WirelessNetIface::{supports_four_addr_station,four_addr_enabled,set_four_addr}`
model managed-station `NL80211_ATTR_4ADDR`. `GET_INTERFACE` and interface
lifecycle replies always include the u8 state, as `nl80211_send_iface` does.
`SET_INTERFACE` accepts an enabled state only for a driver-supported station
interface (cfg80211's internal `WIPHY_FLAG_4ADDR_STATION` rule); a disable is
a harmless no-op outside station mode. A supporting driver retains the state
across association/recovery, programs its associated peer, builds
ToDS|FromDS data headers with the original Ethernet source in address four,
and sends mac80211's unencrypted 30-byte four-address Null notification when
the state becomes active.

For nl80211 scans, a nonempty nested SSID list requests active scanning;
empty SSID entries are wildcard probes and can coexist with directed SSIDs.
`CONNECT` accepts an SSID with optional BSSID/frequency constraints. It selects
the strongest matching Open/WPA2 BSS from the cache, or performs a bounded
scan first, rechecking the request's authority before association.

### 3.2 Wireless Capabilities

```rust
pub enum WirelessRight {
    Scan,        // Trigger scans, read BSSID list
    Associate,   // Connect/Disconnect from AP
    Config,      // Change channel, power, etc.
    Monitor,     // Enter monitor mode, receive all management frames
}

pub type Cap<WirelessIface, R> = ...;
```

### 3.3 Control Plane (Async)

```rust
pub async fn scan(cap: &Cap<WirelessIface, Scan>) -> Result<Vec<BssInfo>, WirelessError>;
pub async fn associate(cap: &Cap<WirelessIface, Associate>, req: AssocReq) -> Result<(), WirelessError>;
pub async fn set_phy_config(cap: &Cap<WirelessIface, Config>, cfg: PhyCfg) -> Result<(), WirelessError>;
```

### 3.4 Linux nl80211 compatibility

The wireless subsystem registers the `nl80211` generic-netlink family through
the `net/` family registry. Read-only `GET_WIPHY` and `GET_INTERFACE` point and
dump requests enumerate the canonical wireless-interface registry and emit
Linux `NEW_WIPHY` / `NEW_INTERFACE` records. Wiphy records carry a nested
band description with HT/VHT capabilities, MCS sets, HT A-MPDU factor and
density when supplied by `phy_capabilities()`. VHT is absent from the
2.4 GHz band. Capability integers use native netlink byte order; IEEE MCS
arrays retain their wire layout. A 6-GHz `WirelessBand` is emitted as
`NL80211_BAND_6GHZ` (including the 5935-MHz channel-two special case), rather
than being collapsed into or omitted from the 5-GHz record. Wiphy records also
carry a nested
`SUPPORTED_COMMANDS` list, and `GET_PROTOCOL_FEATURES` returns a zero bitmap
instead of claiming optional split-dump behavior NARF does not implement.
The family also implements `TRIGGER_SCAN`, `GET_SCAN`, `CONNECT`,
`DISCONNECT`, `SET_INTERFACE`, physical-radio `SET_WIPHY`, per-netdev
`SET_TX_BITRATE_MASK`, `GET_STATION` and range-capable `SET_CQM` (plus the userspace-SME and AP
commands below), and the `config`, `scan`, `regulatory`, `mlme`, `vendor` and
`nan` multicast groups; none of the groups carries `GENL_MCAST_CAP_*`, so any
socket may join them, as with Linux `genl_bind`.

**Permissions** follow Linux generic netlink exactly. Each `GenlOperation`
carries its `nl80211_ops` `.flags` (`narf_net::netlink_generic::
GENL_ADMIN_PERM` / `GENL_UNS_ADMIN_PERM`), reported in `CTRL_ATTR_OP_FLAGS`.
`genl_family_rcv_msg`'s order is kept: unknown family -ENOENT, op not in the
table for the requested do/dump -EOPNOTSUPP, then the permission check
-EPERM, and only then attribute validation and the device lookup
(`nl80211_pre_doit`, -EINVAL / -ENODEV). `GENL_ADMIN_PERM` needs
`netlink_capable(skb, CAP_NET_ADMIN)` — CAP_NET_ADMIN in the initial user
namespace held by both the socket's opener (`f_cred`, recorded at
`socket()`) and the sender; `GENL_UNS_ADMIN_PERM` needs
`netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN)` over the socket's
network namespace. The socket layer supplies both verdicts in
`RequestContext::{init_net_admin, net_admin}`, the same helpers rtnetlink uses.

| Command | Linux flag | NARF check |
|---|---|---|
| GET_WIPHY, GET_INTERFACE, GET_SCAN, GET_STATION, GET_PROTOCOL_FEATURES, GET_REG, GET_POWER_SAVE | none | none |
| TRIGGER_SCAN, CONNECT, DISCONNECT, SET_INTERFACE | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
| SET_KEY, NEW_KEY, DEL_KEY, SET_PMKSA, DEL_PMKSA, FLUSH_PMKSA, CONTROL_PORT_FRAME, SET_POWER_SAVE, SET_REKEY_OFFLOAD | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
| AUTHENTICATE, ASSOCIATE, DEAUTHENTICATE, DISASSOCIATE, REGISTER_FRAME, FRAME | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
| SET_BEACON, START_AP, STOP_AP, NEW/SET/DEL_STATION | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
| EXTERNAL_AUTH | `GENL_ADMIN_PERM` | `init_net_admin` or delegated handle |

A capable sender acts on any wireless interface of its own namespace with the
interface's kernel-held handle (`narf_net::kernel_admin`), so a namespace move
or removal during an asynchronous operation still revokes it. NARF's
explicitly delegated, interface-bound `AdminHandle` remains an alternative:
the generic-netlink layer lets a request carrying one through
(`RequestContext::capable == false`) and the handler then requires the handle
to cover the named interface (-EPERM otherwise, after -EINVAL / -ENODEV —
NARF-only ordering, since Linux has no such handle). Revoked, cross-interface
or cross-namespace handles are rejected; supplying an attribute never conveys
authority.

**Supplicant interop.** `GET_WIPHY` resolves its wiphy as
`__cfg80211_rdev_from_attrs` (WIPHY, WDEV or IFINDEX; none -EINVAL, not found
-ENODEV) and a dump is narrowed as `nl80211_dump_wiphy_parse` does.
`SET_INTERFACE` to the current type is a no-op. A driver that implements
`set_iftype` may change between its advertised types only while its netdev and
vdev are down; unsupported or active-vdev changes are -EOPNOTSUPP / -EBUSY.
`WirelessNetIface::cipher_suites() -> &'static [u32]` is the source of truth
for both `GET_WIPHY`'s `NL80211_ATTR_CIPHER_SUITES` and CONNECT / NEW_KEY
validation. Its default external-supplicant profile remains CCMP-128 plus
BIP-CMAC-128; a hardware driver overrides it only after its firmware key
install, data descriptor, and host or firmware MFP owner implement the advertised suite.
The ath11k WCN6855 profile supplies Linux's nine-suite set: TKIP, CCMP-128/
256, GCMP-128/256, BIP-CMAC-128/256, and BIP-GMAC-128/256.
`4ADDR` follows the selected wiphy's managed-station capability: an enabled
request needs station mode plus `supports_four_addr_station()`, while a clear
outside station mode is harmless.
`TRIGGER_SCAN` accepts `SCAN_FLAGS` FLUSH / AP / COLOCATED_6GHZ (a NARF scan
always replaces the cached results) and refuses feature-gated flags and
FREQ_KHZ with -EOPNOTSUPP, probe IEs past the advertised maximum of 0 with
-EINVAL. The exception is `NL80211_SCAN_FLAG_RANDOM_SN` (bit 11), which is
accepted when `WirelessNetIface::supports_scan_random_sn()` is true. Such a
wiphy advertises `NL80211_EXT_FEATURE_SCAN_RANDOM_SN` (extended bit 29), and
the request reaches the driver as
`scan_with_flags(ScanRequest, scan::ScanFlags { random_sn })`. The default
implementation forwards to `scan`. Requests without a flag still call `scan`.
`ScanFlags` sits beside `ScanRequest` rather than inside it, so the many
existing request literals stay valid. `CONNECT` accepts the attributes wpa_supplicant and NetworkManager
always send (`MAC_HINT`, `WIPHY_FREQ_HINT`, `BG_SCAN_PERIOD`, `PREV_BSSID`,
HT/VHT capability + mask, `CONTROL_PORT`, `CONTROL_PORT_ETHERTYPE` = ETH_P_PAE,
`CONTROL_PORT_NO_ENCRYPT`, `SOCKET_OWNER`, `EXTERNAL_AUTH_SUPPORT`, `SAE_PWE`,
`MLO_SUPPORT`, `CONTROL_PORT_OVER_NL80211`, `CONTROL_PORT_NO_PREAUTH`) with
`nl80211_connect` / `nl80211_crypto_settings`' checks; hints and overrides
steer nothing. `USE_MFP` is `enum nl80211_mfp` (REQUIRED = 1; OPTIONAL = 2).
OPTIONAL requires explicit default-false `supports_optional_mfp()` plus PSK
and required-PMF offload; a complete native owner advertises extended bit21.
A PMK needs `4WAY_HANDSHAKE_STA_PSK` and a SAE
password `SAE_OFFLOAD` (-EINVAL otherwise); pairwise / group ciphers must be
wiphy cipher suites (-EINVAL). CONNECT accepts up to five pairwise selectors,
while direct ASSOCIATE accepts one, as `nl80211_crypto_settings` does.
`CONTROL_PORT_OVER_NL80211` needs
`SOCKET_OWNER` (-EINVAL), then the ext feature (-EOPNOTSUPP). For the PMK
path the RSN element in `NL80211_ATTR_IE` must describe CCMP/PSK. Required
PMF additionally needs the explicit default-false
`WirelessNetIface::supports_wpa2_mfp_offload() -> bool` and `USE_MFP=1`;
cipher advertisement alone cannot grant this association capability. The
required profile demands one RSNE with exactly MFPC|MFPR, no additional
caller security promises such as OCV, no PMKIDs, and BIP-CMAC-128 (explicit
or the IEEE default when omitted). Its fixed PSK/CCMP body accepts only
20/22/26-byte extents, with no partial/trailing fields, and the complete IE
stream is bounded at 2048 bytes. Missing capability, missing/contradictory
RSNE or unsupported suite remains closed. OPTIONAL additionally requires
`USE_MFP=2` and one canonical MFPC-only RSNE with the same bounded BIP formats,
no PMKIDs/OCV and no MFPR. Missing/NO-MFP policy cannot carry that optional
promise. It is admitted only to the firmware PSK path, keeping SAE, Open,
external-supplicant and direct ASSOCIATE policies unchanged. The complete
original RSNE survives into `AssociateRequest::ie`; it supplies requested
policy, not a negotiated-PMF proof. Native response/handshake evidence remains
the opted-in driver's obligation, including any explicit interoperability limits.
Other offload drivers retain their no-required/optional-PMF defaults. Every element
is carried in `AssociateRequest::ie`, and an
offloading driver replaces RSNE / RSNXE with its own and forwards the rest
(`ieee80211_mgd_assoc`). A successful offloaded
WPA2-PSK / SAE connect emits `CONNECT` (with `WIPHY`, `MAC`, `STATUS_CODE`)
and then `PORT_AUTHORIZED` (`cfg80211_port_authorized`), which wpa_supplicant
waits for under `WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK`. `GET_SCAN` marks the
associated BSS with `NL80211_BSS_STATUS_ASSOCIATED`; `GET_STATION` reports the
AP (do needs `MAC`, -ENOENT for another peer) with the signal of its last scan
record only.

One native CONNECT admission smoke covers these capability/attribute/RSNE
boundaries, including literal explicit/default BIP and unsupported-cipher-only
profiles. The CYW43439 and BCM43602 native transport tests pass raw CONNECT
attributes through the production parser and execution path into their real
FullMAC Station, checking native MFP/association receipts and controlled-port
state. A test-only entry point supplies the fixture's registered, currently
valid admin capability; it does not change production authority or dispatch.

**Two driver modes.** A handshake-offloading driver (iwlwifi, mt7921)
advertises `4WAY_HANDSHAKE_STA_PSK` (and `SAE_OFFLOAD`): wpa_supplicant derives
the PMK and passes it in CONNECT, the driver's in-kernel supplicant runs the
4-way and group-key handshakes and rekeys, then PORT_AUTHORIZED. An
**external-supplicant** driver (`supports_external_supplicant()`, ath11k —
the mac80211 model) runs no supplicant: wpa_supplicant does the handshake
itself, which is also what 802.1X/EAP (WPA-Enterprise) needs. A driver that
also runs its SME in userspace (`supports_userspace_mlme()`) advertises
AUTHENTICATE / ASSOCIATE and `NL80211_FEATURE_SAE` and never the handshake
offloads (wpa_supplicant with `WPA_DRIVER_FLAGS_SME` passes no PMK yet, with
`4WAY_HANDSHAKE_STA_PSK`, ignores EAPOL), so wpa_supplicant runs SAE in
userspace over AUTHENTICATE as on Linux. The external mode is:

- **Association.** CONNECT with a protected network and neither PMK nor SAE
  password (Open System auth only), or the AUTHENTICATE / ASSOCIATE pair,
  becomes `SecurityConfig::External(ExternalSecurity { use_mfp, privacy,
  control_port })` / `MlmeAssocRequest { control_port, privacy, .. }`; the
  supplicant's RSNE / RSNXE travel in the elements. With
  NL80211_ATTR_CONTROL_PORT the port stays closed after association
  (`IEEE80211_STA_CONTROL_PORT`); without it the AP is authorized at once.
  The interface counts as connected (`connected_bssid`, `wdev->connected`)
  from association on.
- **Keys.** NEW_KEY / SET_KEY / DEL_KEY follow `nl80211_parse_key` (nested
  `NL80211_ATTR_KEY` or the old attributes, the policies' -ERANGE bounds),
  `cfg80211_validate_key_settings` (pairwise index 0 — no Extended Key ID —,
  group 0..=5, BIP index 4/5, suite-specific key / RSC lengths, and the
  selected wiphy's advertised cipher set; -EINVAL),
  `nl80211_key_allowed` (-ENOLINK unless connected), no MLO link
  (-EINVAL), then `WirelessNetIface::add_key` / `del_key` (mac80211:
  -ENOENT for a peer that is not the associated AP or a key that is not
  installed; a group key with a MAC -ENOENT). SET_KEY records a default key;
  a default-management IGTK additionally calls
  `WirelessNetIface::set_default_mgmt_key` so an AP selects the BIP transmit
  key. `KEY_MODE = SET_TX` is -EINVAL (no Extended Key ID).
- **GTK low-power rekey.** `SET_REKEY_OFFLOAD` takes nested KEK (16 bytes),
  KCK (16 bytes), replay counter (8 bytes) and optional AKM exactly as
  `nl80211_set_rekey_data` does; missing required material is -EINVAL and a
  wrong fixed length is -ERANGE. It requires an up, connected station and a
  driver that advertises the command, otherwise -ENETDOWN, -ENOTCONN or
  -EOPNOTSUPP. It retains the material for the driver's suspend/WoW path;
  it does not alter the awake userspace-supplicant Group Key Handshake.
- **Wake-on-WLAN.** `GET_WOWLAN` returns the retained
  `WirelessNetIface::wowlan_config`; `SET_WOWLAN` validates the driver
  advertised `WowlanSupport` and retains or clears a `WowlanConfig`. The
  ath11k profile accepts disconnect, magic-packet, GTK-rekey failure, and up
  to 22 masked byte patterns (each at most 128 bytes, with a same-length
  mask); unsupported trigger families are -EOPNOTSUPP and malformed nesting
  or geometry is -EINVAL/-ERANGE. Setting the configuration only changes the
  pending policy — it does not issue firmware commands while the interface is
  awake. System PM selects the retained policy at suspend: configured WoW
  preserves the associated firmware transport; absent WoW disconnects and
  cold-cycles the interface. `GET_WOWLAN` therefore reports configuration,
  not a promise that the platform is currently asleep.
- **Scheduled scan.** A wiphy whose
  `WirelessNetIface::sched_scan_support() -> Option<SchedScanSupport>` is
  `Some` advertises `NL80211_CMD_START_SCHED_SCAN` / `STOP_SCHED_SCAN` (75 /
  76, `GENL_UNS_ADMIN_PERM`). It also advertises its limits: MAX_NUM_SCHED_SCAN_SSIDS,
  MAX_SCHED_SCAN_IE_LEN, MAX_MATCH_SETS, the three plan limits,
  SCHED_SCAN_MAX_REQS = 1 and, with `random_mac`,
  `NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR`. These replace the WoWLAN
  net-detect defaults. `SchedScanSupport { max_match_sets, max_ssids,
  max_ie_len, max_scan_plans, max_plan_interval_secs, max_plan_iterations,
  max_frequencies, random_mac }` has `SchedScanSupport::NET_DETECT`, the
  limits the net-detect parser has always applied.

  START parses the request with the same `nl80211_parse_sched_scan` parser
  that WoWLAN net-detect uses. IFINDEX, SOCKET_OWNER and SCHED_SCAN_MULTI are
  also allowed. The result is passed to `start_sched_scan(SchedScanRequest)`
  (`SchedScanRequest = NetDetectConfig`), and the START event is multicast on
  "scan". STOP (an optional COOKIE must be the legacy request id 0, otherwise
  -ENOENT) calls `stop_sched_scan()` and multicasts SCHED_SCAN_STOPPED. Both
  driver hooks default to -EOPNOTSUPP.

  The driver reports matches with `nl80211::notify_sched_scan_results(name)`
  (`cfg80211_sched_scan_results`, CMD 77) and a firmware-initiated end with
  `nl80211::notify_sched_scan_stopped(name)` (CMD 78).
- **BIOS SAR.** A driver with `WirelessNetIface::sar_capability()` includes
  its fixed range table in the nested `NL80211_ATTR_SAR_SPEC` of GET_WIPHY
  and advertises `NL80211_CMD_SET_SAR_SPECS`. The command is wiphy-wide:
  it accepts only the advertised type plus a non-duplicate subset of range
  indices and signed quarter-dBm power values, then calls
  `set_sar_power_limits`. Omitted ranges clear the host SAR limitation and a
  subsequent successful request replaces the whole target table. The driver
  retains and reapplies the resulting pdev state after a cold resume or
  firmware recovery.
- **AP vdev control.** An AP-capable driver accepts `START_AP`, `STOP_AP`,
  `SET_BEACON`, and NEW/SET/DEL_STATION only when its current iftype is AP.
  They retain the caller's ordered command in the driver's runtime queue so a
  generic-netlink syscall never re-enters the async executor. The queue runs
  each firmware transaction in order and reports a completed AP through the
  normal carrier state; a later command therefore cannot overtake its
  `WMI_VDEV_START`, beacon-template, or peer operation.
  A driver that advertises `MbssidSupport` must program its firmware's
  transmitting/non-transmitting role at vdev start, carry the transmitter
  BSSID plus profile index/count in the non-transmitting vdev-up operation,
  and retain the transmitter's complete raw MBSSID/EMA beacon family. EMA
  templates target the transmitting vdev; a non-transmitting profile waits
  for that family before its first start. Replacement templates are never
  sent to an already-up non-transmitting vdev when firmware forbids that
  sequence.
  A six-GHz driver that advertises the FILS-discovery and unsolicited broadcast
  Probe Response extended features accepts their nested templates in
  `START_AP` and `SET_BEACON`; it must apply FILS before unsolicited Probe
  Response when both intervals are nonzero, and send a zero-interval disable
  when neither is configured. A CSA-provided unsolicited-response change is
  retained until the post-switch vdev restart succeeds.
  A driver with an FTM responder role advertises
  `NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER`, accepts the enabled nested FTM
  responder form (optional LCI/Civic bodies) in AP beacon operations, and
  applies it only after the corresponding AP-vdev start/restart.
  A TWT-responder-capable AP accepts the empty `NL80211_ATTR_TWT_RESPONDER`
  flag on START_AP and, after vdev-up, enables the target's default pdev TWT
  engine. It sends the matching disable on AP stop; command failure does not
  roll a completed AP transition back.
  A driver that accepts `NL80211_ATTR_HE_OBSS_PD` validates the mandatory SR
  control and optional 1..=20 offsets / exact eight-byte bitmaps from
  `START_AP`. It applies the pdev-wide spatial-reuse state after the AP vdev
  is live, using the target's legacy non-SRG threshold form when SRG reuse is
  unavailable and its full threshold/bitmap sequence when it is available.
  A driver with HE BSS-color offload advertises
  `NL80211_EXT_FEATURE_BSS_COLOR`, validates the nested 1..=63 color and
  empty disabled/partial flags, and applies the resulting AP color only after
  the corresponding vdev start/restart. Command failures are reported without
  rolling back an otherwise complete AP transition.
  It also accepts AP-only `NL80211_CMD_COLOR_CHANGE_REQUEST`: a nested
  temporary beacon/Probe-Response countdown is active while count is above
  one, the ordinary post-change beacon then replaces it, and the requested
  color is enabled. Started/completed/aborted notifications use the nl80211
  MLME group; an active CSA and a non-transmitting MBSSID profile are refused.
  `StationConfig` preserves the associated client's legacy rates, capability
  bits, extended capability bytes, HT/VHT/HE/6-GHz capability bodies, and
  WMM indication and the nested U-APSD AC bitmap / maximum-service-period
  request. The driver intersects capabilities with its radio before peer
  association; a missing SET_STATION field leaves retained values unchanged.
  An AP-UAPSD-capable driver advertises `NL80211_ATTR_SUPPORT_AP_UAPSD`, sets
  the peer APSD/host-rate flags, then programs the target's AP-PS peer UAPSD,
  max-SP and disabled-SIFS parameters after association; target firmware owns
  client buffering and beacon TIM maintenance.
- **Station inspection.** `GET_STATION` names the connected AP for a station
  interface and names / dumps associated clients for AP or P2P GO. A client
  record includes the driver-observed AP client RX/TX MSDU, retry and failed
  completion counters plus any PPDU-backed signal, chain signal, rate and
  duration telemetry its firmware supplies.
- **Port.** SET_STATION on a station interface is `ieee80211_change_station`
  for the AP (`CFG80211_STA_AP_STA`): MAC required (-EINVAL), STA_FLAGS2
  (short -ERANGE, the invalid bit -EINVAL) or the old STA_FLAGS, -ENOENT for
  another peer, any flag but AUTHORIZED, a listen interval, an AID, rates or
  capabilities -EINVAL; then `set_port_authorized`. A supported
  `STA_TX_POWER_SETTING` additionally updates that AP peer's automatic or
  limited-power policy; the fixed ath11k form is -EINVAL.
- **PMKSA.** SET / DEL / FLUSH_PMKSA check their attributes (PMKID -EINVAL /
  short -ERANGE, MAC or the FILS triple -EINVAL) and then are -EOPNOTSUPP:
  mac80211 has no PMKSA operations; the supplicant keeps its cache.
- **EAPOL.** Received control-port frames go to the connection owner as a
  unicast NL80211_CMD_CONTROL_PORT_FRAME (WIPHY, IFINDEX, WDEV, MAC = source,
  CONTROL_PORT_ETHERTYPE, CONTROL_PORT_NO_ENCRYPT when not decrypted, FRAME
  = the PDU after the Ethernet header; `rx_control_port`, -ENOENT /
  dropped without an owner) when the association asked for
  CONTROL_PORT_OVER_NL80211 (pre-authentication frames too unless
  CONTROL_PORT_NO_PREAUTH), else up the netdev with the destination set to
  our address, where a PF_PACKET socket on ETH_P_PAE (wpa_supplicant's
  `l2_packet`) reads it. CONTROL_PORT_FRAME TX (`nl80211_tx_control_port`:
  the ext feature -EOPNOTSUPP, FRAME / MAC / ETHERTYPE -EINVAL, not
  connected -ENOTCONN; the driver: a protocol other than the association's
  or ETH_P_PREAUTH -EINVAL) requests its WBM completion under the same
  extended-ACK cookie (`NLMSGERR_ATTR_COOKIE`) unless DONT_WAIT_FOR_ACK.
  Drivers that advertise CONTROL_PORT_OVER_NL80211_TX_STATUS multicast
  CONTROL_PORT_FRAME_TX_STATUS on the MLME group when that completion arrives:
  WIPHY, IFINDEX, WDEV, the full Ethernet FRAME, COOKIE, and ACK only on a
  peer acknowledgement. The direct CONTROL_PORT_FRAME
  CONTROL_PORT_NO_ENCRYPT attribute is a per-frame
  `IEEE80211_TX_INTFL_DONT_ENCRYPT` request through the driver's TXQ. The
  same CONNECT/ASSOCIATE attribute is retained as the association policy and
  applies to ordinary netdev frames only when their EtherType equals the
  configured control-port EtherType, as mac80211 does. Either form clears the
  802.11 Protected bit even after a PTK exists. EAPOL sent through the netdev
  passes the closed port; frames otherwise leave unprotected until a pairwise
  key is installed. A local TKIP Michael MIC failure is dropped and multicast
  as NL80211_CMD_MICHAEL_MIC_FAILURE on the MLME group with WIPHY, IFINDEX,
  source MAC, KEY_TYPE, and the installed KEY_IDX when the target stripped the
  frame IV (KEY_SEQ is absent, matching cfg80211's NULL-TSC form).
- **Ordering.** The netlink syscall cannot wait for the device: these
  methods are synchronous, validate what mac80211 rejects before the driver,
  and the driver applies them on its own task strictly in request order
  (key installs, authorization, control-port TX), so M4 leaves before the
  PTK it precedes and data before the keys requested ahead of it.

**Connection owner.** `SOCKET_OWNER` on CONNECT / ASSOCIATE makes the
sender's port (`RequestContext::portid`) the connection owner
(`conn_owner_nlportid`): ASSOCIATE, DEAUTHENTICATE, DISASSOCIATE and
DISCONNECT from another socket are -EPERM, a failed connect result or a
disconnect clears it, CONTROL_PORT_FRAME RX is unicast to it, and closing
that socket (`NETLINK_URELEASE`, `narf_net::netlink_generic::notify_release`
from the socket layer) disconnects the interface
(`cfg80211_autodisconnect_wk`, reason DEAUTH_LEAVING).

**Userspace SME.** AUTHENTICATE follows `nl80211_authenticate`
(NEED_NETDEV_UP -ENETDOWN; MAC, AUTH_TYPE, SSID, WIPHY_FREQ -EINVAL; a WEP
key -EINVAL; no driver op -EOPNOTSUPP; AUTH_TYPE past SAE -EINVAL — FILS and
EPPKE are not advertised; SAE without AUTH_DATA or AUTH_DATA without SAE
-EINVAL, AUTH_DATA shorter than 4 -ERANGE; LOCAL_STATE_CHANGE a no-op; the
BSS must be in the scan results, -ENOENT; already connected to it
-EALREADY). The driver's answer is published as NL80211_CMD_AUTHENTICATE
(WIPHY, IFINDEX, FRAME) or, on timeout, with TIMED_OUT + MAC. ASSOCIATE
follows `nl80211_associate` (owner -EPERM, SSID -EINVAL, a
non-inheritance element -EINVAL, USE_MFP other than NO / REQUIRED -EINVAL,
HT/VHT overrides without masks -EINVAL, MAC + WIPHY_FREQ -EINVAL, the
scan entry -ENOENT, crypto settings, connected to another BSS -EALREADY);
when PREV_BSSID is present it must identify the associated BSS displaced by
this SME authentication; the driver emits a Reassociation Request with that
current-AP address and accepts only a Reassociation Response. If the AP
rejects it, NARF retries once as a plain Association Request before reporting
the denial, as cfg80211's SME does;
the response is published as NL80211_CMD_ASSOCIATE (FRAME, REQ_IE = the
SME's elements) followed by the CONNECT result. A temporary status-30
response carrying Timeout Interval type Association Comeback instead emits
NL80211_CMD_ASSOC_COMEBACK (WIPHY, IFINDEX, MAC and TIMEOUT in TUs), leaves
the connection owner intact, and lets the supplicant schedule the next
ASSOCIATE; it does not publish CONNECT. DEAUTHENTICATE /
DISASSOCIATE need MAC and a non-zero REASON_CODE (-EINVAL); DISASSOCIATE
while not connected to that BSS is -ENOTCONN. A driver that reports its own
disconnects publishes DEAUTHENTICATE / DISASSOCIATE with the frame and then
DISCONNECT for every loss (`notify_mlme_disconnect`; wpa_supplicant's SME
ignores DISCONNECT and acts on the DEAUTHENTICATE frame).

**Other commands.** GET_REG returns the global domain (the installed
deployment policy, else cfg80211's `world_regdom`), or with WIPHY that
wiphy's own (`regulatory_domain()`); the dump lists the global domain then
each wiphy domain with WIPHY and WIPHY_SELF_MANAGED_REG. SET_POWER_SAVE /
GET_POWER_SAVE need `power_save_default()` (mac80211's `set_power_mgmt`,
else -EOPNOTSUPP), keep `wdev->ps` (on by default,
CONFIG_CFG80211_DEFAULT_PS) and call the driver only on a change; PS_STATE
missing -EINVAL, past ENABLED -ERANGE. GET_INTERFACE carries
NL80211_ATTR_WDEV (`wiphy << 32 | 1`). GET_STATION's STA_INFO carries what
`station_info()` tracks (signal, average / ACK signal, indexed chain signal,
TX / RX bitrate with `nl80211_put_sta_rate`'s attributes, packet / retry /
failure counters, and RX / TX PPDU duration), the scan record's signal
otherwise. A driver leaves an unavailable measurement absent rather than
synthesising one.

The common CYW43439/BCM43602 FullMAC station supplies an awake power-save
default and accepts PS changes through its retained control worker. GET reports
the accepted desired policy; the station's applied state changes only after
correlated PM_FAST/PM_OFF and sleep-retention replies. Requests coalesce and
an in-flight completion preserves a newer desired policy. Firmware failure or
cancelled command ownership closes carrier and queued TX and prevents session
reuse. This ordinary firmware station power save does not suspend the host bus
or provide system suspend/WoW. Native SDPCM and PCIe-msgbuf models cover the
commands, failures and Open/WPA2 DHCP/IP traffic with power save enabled.

Ath10k RAW/non-PFC images without `NO_PS` also expose an awake default. Their
retained worker submits the six-dialect native station-PS parameters and mode,
with the awake default or explicit prejoin intent applied before carrier. Its applied diagnostic
records submission rather than a firmware sleep acknowledgement. Desired intent
coalesces without losing a newer request. Current policy and host closure fence
each command poll; failure/cancellation closes admission and retains DMA. Actual
DTIM, energy behavior and host-bus/system suspend remain separate acceptance.

`SET_CQM` accepts the station/P2P-client RSSI form: a binary native-endian
signed threshold array plus its required native-endian u32 hysteresis. Values
must be non-positive and strictly increasing. A zero/empty array disables it;
a multi-value array requires CQM_RSSI_LIST. The software mac80211 path uses
the associated AP's four-sample 1/16-dBm beacon EWMA. A singleton evaluates
the configured threshold and hysteresis; a list maintains the adjacent
low/high interval around the last CQM level and re-centres it after each
crossing. It multicasts `NOTIFY_CQM` with nested threshold-event and RSSI-level
attributes after releasing its driver lock.

When `supports_ack_signal()` is true, `EXT_FEATURES` carries
ACK_SIGNAL_SUPPORT and `GET_STATION` may carry the last successful TX ACK's
signal in `NL80211_STA_INFO_ACK_SIGNAL`; it remains absent until a valid
completion provides it.

When `supports_scan_dwell()` is true, `EXT_FEATURES` carries SET_SCAN_DWELL.
`TRIGGER_SCAN` accepts native-endian `MEASUREMENT_DURATION` (u16 TUs) and its
zero-length `_MANDATORY` flag. The request retains both; ath11k applies a
nonzero duration to every active/passive WMI dwell field and bounds its scan
timeout with Linux's per-channel event-overhead calculation.

`WirelessNetIface::max_scan_ie_len()` supplies the native-endian u16
`NL80211_ATTR_MAX_SCAN_IE_LEN` and the parser's pre-dispatch byte limit.
Its compatibility default is 512; ath10k overrides it with its firmware's
256-byte budget. Longer `NL80211_ATTR_IE` input returns -EINVAL before driver
dispatch. On an active ath11k scan the accepted bytes are
appended after the host's standard Probe Request rates/capabilities and sent
as WMI's extra-IE array. Ath10k validates complete probe elements, rejects
firmware-owned SSID/rate elements and passive extra-IE requests, and copies
accepted bytes into its retained six-dialect active-scan plan before I/O.

`WirelessNetIface::nl80211_feature_flags()` returns only defined physical
`NL80211_FEATURE_*` bits; the generic wiphy response combines them with its
SME and random-MAC bits. ath11k exposes AP-vif scans, AP in-place channel
width changes, firmware TPC report power insertion, and static SMPS. It adds
dynamic SMPS only when the negotiated firmware HT capability has
`WMI_HT_CAP_DYNAMIC_SMPS`.

An AP-capable driver may expose `max_ap_assoc_sta()`; a nonzero value is
serialized as `NL80211_ATTR_MAX_AP_ASSOC_STA`. It is an advertised physical
limit rather than a reservation: concurrent firmware peer use can still make
an individual `NEW_STATION` fail, as cfg80211 permits.

`iftype_extended_capabilities()` returns the cfg80211 default and explicit
per-role Extended Capabilities records. nl80211 serializes each as an
`IFTYPE`, `EXT_CAPA`, and equally long `EXT_CAPA_MASK` triplet nested under
`NL80211_ATTR_IFTYPE_EXT_CAPA`. `wiphy_extended_capabilities()` independently
supplies the top-level `EXT_CAPA`/`EXT_CAPA_MASK` pair. Malformed unequal
records are omitted.
ath11k supplies Linux's default, station, and AP records for extended channel
switching, MBSSID, operating-mode notification, TWT requester/responder, and
EMA capability.

`wiphy_mac_addresses()` supplies a multi-vdev radio's preallocated address
pool; a pool with more than one member is emitted as nested
`NL80211_ATTR_MAC_ADDRS`, alongside the physical base `MAC`. A nonzero
`max_csa_counters()` advertises `MAX_CSA_COUNTERS`; a driver that can send
management frames on an active off-channel ROC context sets
`OFFCHANNEL_TX_OK` through `supports_offchannel_mgmt_tx()`.

The common wiphy discovery fields retain Linux/mac80211 defaults unless a
driver exposes a mutable implementation: retry-short = 7, retry-long = 4,
coverage class = 0, and a disabled fragmentation threshold (`u32::MAX`).
ath11k exposes the latter state while rejecting a threshold change, and
retains its separately mutable RTS threshold.  WoW network-detect discovery
uses the UAPI's exact u8 (`MAX_NUM_SCHED_SCAN_SSIDS`/`MAX_MATCH_SETS`) and
u16 (`MAX_SCHED_SCAN_IE_LEN`) payload widths.

`GET_SURVEY` is a dump operation when `supports_survey()` is true.  Every
`NEW_SURVEY_RESULTS` reply contains its IFINDEX and one nested
`NL80211_ATTR_SURVEY_INFO` record with `FREQUENCY`, optional `NOISE`,
`IN_USE`, and the available survey-time attributes.  A driver may use an
ordered asynchronous control worker for a target refresh: its dump returns
the last complete physical-radio snapshot and queues one coalesced refresh,
instead of re-entering an IRQ/WMI completion wait from the generic-netlink
handler.  Consequently the next dump observes the completed refresh; callers
must not interpret a missing time field as a zero counter.

An ath11k low-power owner calls its MAC's GTK-offload helper at the WoW
boundary: enable serializes WCN6855's `WMI_GTK_OFFLOAD_CMDID` with the saved
KEK/KCK and a little-endian firmware replay counter; resume first requests
status, then disables the engine. `WMI_GTK_OFFLOAD_STATUS_EVENTID` updates the
saved counter and publishes the big-endian nested replay counter above. The
registered async system-PM hook programs all WoW triggers/offloads and waits
for the HTC suspend acknowledgement before MHI M3; it restores M0 plus CE/DP
delivery, waits for the WMI host-wakeup event, then removes temporary state.
Without a retained WoW configuration it follows cfg80211/mac80211's normal
disconnect plus cold HIF/MHI reset/reconfigure route instead.

Driver coverage: ath11k implements the external mode, the userspace SME,
power save, its regulatory domain and completion-backed STA_INFO signal, ACK
signal, TX / RX packet, failure and retry counters. Its first-MSDU TQM WBM
completion decodes a TX bitrate (legacy / HT / VHT / HE, including HE OFDMA
RUs) with the association's negotiated NSS, while its fast-RX descriptor
decodes the received packet type / MCS / GI / bandwidth / stream bitmap into
RX bitrate. Fast RX has no HE RU allocation, so an HE RX rate reports its full
received bandwidth (matching `ath11k_dp_rx_h_rate`). Both descriptor mappings
still await on-card qualification. iwlwifi and mt7921
stay handshake-offload drivers: their firmware paths run the handshake
themselves, so they do not claim `supports_external_supplicant()` (NEW_KEY
and the other external commands are -EOPNOTSUPP from nl80211, and a
`SecurityConfig::External` reaching them is `WirelessError::NotSupported`);
they ignore `AssociateRequest::ie` (their firmware builds the Association
Request) and have no SET_POWER_SAVE.

Deviations kept: a NEW_KEY whose firmware install fails is reported to the caller as success
(the driver applies it after the syscall returned); the ASSOCIATE event's
REQ_IE is userspace's elements, not the whole frame body mac80211 built;
NARF's older attribute helpers answer a short fixed-size attribute with
-EINVAL where the policy says -ERANGE (the new commands use -ERANGE).

Mutating requests validate attributes, reserve one operation per interface,
then run the native async method in the executor. Netlink ACK acknowledges
acceptance; completion is a scan-results/aborted, connect-status, or
disconnect event. Cancellation releases the operation reservation. Scan
dumps are bounded to 256 BSS records and preserve original AP information
elements through `WirelessNetIface::scan_information_elements`.
Interface and wiphy queries are namespace-filtered; events use the same
namespace and cannot follow an interface across a namespace move.
Drivers that implement `reports_disconnect_events()` emit link-loss and
local-teardown notifications themselves through
`notify_disconnect(name, reason, from_ap)` (`nl80211_send_disconnected`:
`REASON_CODE` omitted when 0, `DISCONNECTED_BY_AP` when the AP sent the
Deauthentication / Disassociation), so the control bridge does not emit a
second local-disconnect event.

### 3.4.1 CCMP packet helpers (`ccmp.rs`)

`build_aad` authenticates the three addresses, fragment number and optional
Address4 / QoS TID. It excludes Duration/HT Control, mutes data subtype bits
4–6 (preserving the QoS indicator), Retry/PM/MoreData and QoS Order, and
forces Protected. Management subtype and non-QoS Order remain authenticated.
`station_security::Security` receives +HTC QoS DATA (Order set; the
four-octet HT Control field follows QoS Control, mac80211
`ieee80211_hdrlen`) on both the MSDU and the A-MSDU path. It authenticates
the MPDU as the equivalent 26-octet header with Order clear, which gives the
same AAD and nonce, and drops the HT Control field. The `RawFrame` contract
therefore keeps HT Control and Order unmodified, and advertising HTC_HE
loses no AP traffic. Order on non-QoS DATA is still refused.
`build_nonce` includes the transmitter address and big-endian 48-bit PN.
`protect` / `unprotect` take an `AesCcm` backend and are both fallible: a
backend seal/open refusal propagates as `CcmpError` (`TooLong` for a body
beyond the CCM two-octet length bound) with the frame body left unmodified —
datapath adapters must never convert a refusal into a panic. `unprotect`
checks a copy of `ReplayWindow` and commits it only after MIC verification. Authentication
failure leaves ciphertext and replay state unchanged when the backend honors
its verify-before-mutation contract. The caller must validate complete MAC
header bounds, key role/ID, native station addresses, nonce uniqueness and
PN exhaustion, and retain independent replay trackers per key/TID (including
a separate non-QoS tracker). These helpers do not grant controlled-port access.

### 3.4.2 Retained native station security

`packet_key::{Key, Role}` owns a software CCMP key's immutable peer/KeyID
binding, non-wrapping 48-bit transmit PN and eighteen receive replay trackers
(sixteen QoS TIDs, non-QoS and robust management). Pairwise keys transmit only local ToDS data;
group keys are receive-only. Full header, fragment, A-MSDU and CCMP extents
are checked before crypto; identical-key reinstall preserves counters, and
authentication failure changes neither replay state nor ciphertext.

`amsdu::{decode, MAX_BYTES, MAX_SUBFRAMES}` supplies bounded station-side
plaintext A-MSDU decoding into complete Ethernet-II frames. The caller binds
the local station and outer native receiver before parsing; this helper grants
no PHY, association, crypto or controlled-port authority. The default HT limit
is3839 bytes, with work bounded by3839/22 minimum-size subframes. Every subframe
has an exact14-byte DA/SA/length header,8..1508-byte RFC1042 body and complete
inter-subframe alignment. IEEE padding bytes are opaque; a last subframe has
no trailing padding. A malformed later subframe returns no partial result.
Unicast outer RA binds inner unicast DA to the local station while permitting
multicast DA as Linux's station check_da rule does. Multicast outer RA binds
every inner DA to that exact receiver. Each SA must be nonlocal unicast.
RFC1042 first-subframe DA ambiguity (aggregation-bit injection), malformed SNAP,
length protocols, legacy AARP/IPX tunnel exceptions, EAPOL/preauthentication and
VLAN-encapsulated control ports are rejected. Ordinary Ethernet-II VLAN data
is retained with at most two customer/provider tags.

`Key::unprotect_amsdu(header, wire)` is a distinct opt-in software CCMP receive
operation. It requires an original protected26-byte FromDS QoS DATA header
with A-MSDU-present, no fragments/Address4/HT-control/EOSP/alternate ACK policy,
and the key's retained native station/peer/role/KeyID. It authenticates the
entire aggregate using the original IEEE CCMP header/TID/nonce into scratch,
validates and allocates every subframe, then commits exactly one existing
key/TID replay update. All failures preserve caller ciphertext and replay
state. Aggregates and standalone QoS MPDUs share the same sixteen replay
trackers, key epochs and GTK RSC floors. Ordinary CCMP masks A-MSDU-present
in AAD; the parser's RFC1042 DA check supplies the Linux aggregation-injection
mitigation without changing interoperable AAD.
SPP A-MSDU (RSN Capabilities bit10, IEEE802.11-2020 9.4.2.24.4) is negotiated
only when both RSNEs advertise it: `JoinPlan::enable_spp_amsdu` patches the
request RSNE before first TX, `station_security::Security::new` accepts that
station RSNE and reports `spp_amsdu()`, and its pairwise `Key::with_spp_amsdu`
keeps A-MSDU Present in the CCMP AAD (12.5.3.3.3; mac80211 wpa.c
ccmp_gcmp_aad with `spp_amsdu`, `ccmp::build_aad_spp_amsdu`). Group keys keep
the ordinary AAD. A flipped A-MSDU Present bit then fails the MIC.
WPA3-SAE/PMF: `Security::new_sae(own, peer, pmk, station_rsne,
station_rsnxe, ap_rsne, ap_rsnxe, sequence)` accepts exactly the JoinPlan SAE
station RSNE (CCMP-128, AKM 8 or 24, MFPC|MFPR, at most one PMKID, default
BIP-CMAC-128) against an AP RSNE offering that AKM with MFPC, and runs the
shared supplicant with `pmf`, a16-octet IGTK and the station RSNXE repeated in
M2 (`Security::new` refuses SAE profiles; `new_sae` refuses PSK). The first
M3 must carry an IGTK KDE (IEEE802.11-2020 12.7.6.4); Group Key messages may
rotate it. IGTKs pass the same key-reuse history and are installed into an
`mfp::MfpKeyStore` with `rx_pn` = KDE IPN only after exact reply delivery.
`pmf()` reports the mode. `receive_management(&impl RawFrame) ->
Result<MgmtRx, Error>` applies mac80211 `ieee80211_drop_unencrypted_mgmt`
once the PTK is installed: unicast robust frames (Deauthentication,
Disassociation, Action except the Linux `_ieee80211_is_robust_mgmt_frame`
non-robust categories) must be CCMP-protected with the pairwise key and pass
a dedicated management replay counter (`Key::protect_management` /
`unprotect_management`: management nonce flag and unmasked subtype AAD);
group robust frames must carry a valid BIP-CMAC-128 MMIE with an IPN above the
installed one. Failures and unprotected robust frames are `Ignored`;
non-robust and pre-key frames pass unchanged. `protect_management(&[u8])`
CCMP-protects a station Deauthentication/Disassociation/robust Action to the
AP after the PMF port opens. SA Query and deauthentication policy remain the
MLME owner's.
The original `protect`/`unprotect` continue rejecting A-MSDU headers.
`amsdu::Limit` names the HT3839/HT7935 A-MSDU and VHT3895/7991/11454 MPDU
sizes (body bound = MPDU minus the46-byte protected QoS/CCMP/FCS overhead);
`decode_with_limit` and `AmsduAdmission::with_limit` admit a larger aggregate
only under the size the station actually advertised. Transmit uses
`amsdu::encode` (zero inter-subframe padding, the receive-side DA/SA/protocol
rules, peer limit), `Key::protect_amsdu` (ToDS, Normal Ack, Address3 = BSSID
per Table 9-30 as mac80211 ieee80211_amsdu_prepare_head writes it) and
`Security::transmit_amsdu_qos`, which consumes one QoS SN and one PN and never
aggregates the control port. Hardware-deaggregated RX and BA sessions remain
separate native ownership contracts.

`Key::unprotect_amsdu_block_ack` is an additional opt-in after a driver proves
a live unicast BA agreement and releases the whole original MPDU in SN order.
It accepts both normal ACK and BlockAck QoS policy (`0x80`/`0xe0` aggregate
high nibbles), retaining the original header, TID, CCMP key/PN and atomic
whole-aggregate validation. `Key::unprotect_amsdu_with`/
`Security::receive_amsdu_with` take an explicit `AmsduAdmission`: No Ack
(unicast and group, as mac80211 ieee80211_set_qos_hdr marks group QoS data),
No Explicit Ack and BlockAck (unicast only) and EOSP (IEEE802.11-2020
9.2.4.5.3/9.2.4.5.4) are each separate opt-ins, and `AmsduReceive` returns
the frames with the original TID, `AckPolicy` and EOSP bit for the driver's
U-APSD owner. Multicast BlockAck stays refused. The existing aggregate
methods keep their normal-ACK/BlockAck-only profiles and ordinary packet
methods keep rejecting aggregates. The helper supplies no BA session, native
completion or ordering proof.

`reorder::Reorder<T>` supplies a bounded opaque native-MPDU sequence owner,
independent of crypto, radio, policy and controlled-port authority. Construction
requires window1..64 and a positive hole timeout. Its slots are heap allocated;
no generic64-item stack array is formed. Offloaded RX BA has no notification
SSN, so the first native-admitted frame initializes the12-bit head, matching
mac80211's auto_seq behavior. A separately validated native BAR may establish
or advance the head through `advance(sequence, now_ns)`. The driver retains
peer/TID/session/generation proof and supplies current monotonic nanoseconds.

`push(sequence, now_ns, item)` returns ordered original items across contiguous
sequence numbers and drives hole expiry. Duplicate, old and exactly-half-range
ambiguous input drops only that incoming item, without replacing queued bytes
or refreshing their age. Future out-of-window input releases older buffered
ownership in sequence order and advances through holes to retain at most the
negotiated window. Independent slot indexing handles non-power-of-two windows
across4095→0. `expire(now_ns)` advances expired holes during idle progress;
an older buffered arrival cannot be held indefinitely by newer nearer frames.
`advance` releases buffered items before its validated BAR head and contiguous
items afterward; old/half-range BARs cannot move backward. Output allocation
uses try_reserve before any state mutation; all three operations return typed
Window/Timeout/Sequence/Allocation errors as applicable.

`clear` discards every buffered item, retains allocation and resets auto-sequence;
`retire` consumes the owner. Drop never implicitly delivers data. `head`,
`window` and `buffered` are diagnostic facts, not capabilities. Drivers must
buffer original MPDUs here before CCMP/PN processing, authenticate only released
items, and enforce current key/port/policy before publication. Native HTT BA,
PPDU ownership, BAR input, key/reply epoch flushing, peer unmap and terminal
teardown remain driver responsibilities. Nine native Rust smokes cover all
window sizes, original-item order, holes/duplicates/late arrivals, half-range
ambiguity, wrap with window3, bounded future advance, BAR, oldest timeout and
clear/retire/drop ownership.

`station_security::{Security, RawFrame, Rx}` composes the shared WPA2-PSK
supplicant with those keys. Drivers supply already-negotiated station/AP RSNEs
and original descriptor-validated native MPDUs. `RawFrame::unmodified()` must
reject hardware-decrypted/decapsulated packets and frames outside the adapter's
admitted peer/channel/PHY profile before nonce or key state can advance. The
security owner additionally checks native addresses, DS direction, fragments,
EAPOL envelope and negotiated crypto. It grants no radio or carrier authority.

`receive_with_nonce` lazily requests fallible secure SNonce material through
the existing supplicant contract. `pending_frame` retains each exact M2/M4 or
group-key response; the transport calls `reply_delivered(native_bytes)` only
after a matching terminal delivery receipt. Submission and DMA consumption
alone cannot commit keys or open the controlled port. Old-key rekey replies
remain protected with the installed key until that receipt; identical key
retries preserve PN/replay state. A bounded owner-lifetime history rejects
retired temporal-key reuse. Exhaustion, entropy or protocol failures close
admission, and key/nonce material is zeroized on drop. `transmit_ethernet`
accepts local Ethernet data only while authorized and consumes its PN before
transport publication. Each driver's stop/cancellation/DMA ownership remains
that driver's responsibility.

`Security::transmit_ethernet_qos(ethernet, tid)` preserves those same controlled
port, Ethernet/EAPOL and key-lifetime checks while accepting TID0–15. It builds
the full 26-byte QoS header before packet-key CCMP protection, so both the TID
AAD and nonce priority authenticate the actual transmitted header. QoS and
legacy frames consume the same installed key's monotonically increasing TX PN;
invalid TIDs do not consume sequence/PN state. Each caller must independently
prove AP WMM negotiation, native EDCA/descriptor/peer admission and applicable
policy. This shared cryptographic formatter grants no HT, aggregation, U-APSD,
role or radio capability.

QoS sequence numbers use sixteen independent12-bit counters, separate from
the non-QoS data/EAPOL counter. Each begins at the constructor's checked seed
and persists across key replacements. `next_qos_sequence(tid)` is a
side-effect-free sample of the exact next QoS SN: invalid TIDs return Profile,
and a closed/pending/failed port returns State. Native TX BA owners must freeze
replenishment and drain previous packets before using that sample as an ADDBA
starting sequence. `transmit_ethernet_qos` consumes the selected counter while
forming the original header before CCMP; protected headers are never rewritten.
The sample alone grants no aggregation, native completion or transmit authority.

`Security::receive_amsdu(&impl RawFrame)` composes that aggregate key operation
with the existing currently-open controlled port and installed pairwise/group
slots. It returns `Option<Vec<Vec<u8>>>` of complete Ethernet-II subframes and
preserves the existing `Rx` enum and ordinary receive path. Closed, failed or
pending-reply owners return State before key/replay work; invalid raw/native
headers, MICs, key identities, replay or subframe geometry return None without
altering a live owner. An aggregate cannot deliver EAPOL to the supplicant,
install a key, commit an M4 reply or revive a port. The driver must independently
prove negotiated HT, original native PHY/peer/channel/TID/CRC admission and
current policy before calling and again before publishing returned frames.
Open station owners may call the plaintext parser only after their own native
association/controlled-port checks. Sixteen native Rust smokes cover exact
Ethernet, all TIDs, PTK/GTK0/GTK2 and RSC, malformed later subframes, MIC/RA/TA/
TID/header denial, aggregation-bit injection, atomic PN, default size/work
bounds, closed/pending ports and real retained pairwise/group rekeys.

`Security::receive_amsdu_block_ack` composes the explicit unicast BA aggregate
key entry under those same current-port, RAW, peer, slot and replay checks.
It requires the driver to supply the actual live BA/order proof and never
relaxes the default aggregate entry. Additional all-TID, unchanged-header,
malformed-tail/MIC/policy, multicast denial and pending-port vectors pass
the coordinated Wi-Fi suites on x86_64 and aarch64.

`Security::handshake_active()` reports a retained reply awaiting terminal
delivery or the supplicant waiting for M3 after M2 delivery. It is false after
terminal failure. During an established pairwise rekey, the old-key data port
can reopen after the exact M2 receipt while this exchange remains active;
drivers must track the handshake deadline independently of `port_open()` and
established carrier. The matching M4 terminal receipt finishes that exchange.

### 3.5 EAPOL supplicant (`eapol.rs`)

`Supplicant` runs the 4-way handshake (`handle`) and, once it completed,
the Group Key Handshake: `process_group_m1(pdu, mic_len, group_key_len,
mgmt_group_key_len)` applies wpa_supplicant's `wpa_sm_rx_eapol` checks
(length, descriptor, replay counter, SMK / Ack / Request bits, descriptor
version 2 or 3, MIC by `eapol_key_mic`, AES-unwrapped Key Data) and
`wpa_supplicant_process_1_of_2` (GTK KDE, length = group cipher key
length, IGTK KDE only with PMF, key-reinstallation check), and returns the
keys plus the 2/2 PDU (802.1X version 1, Key Info = key index | version |
Secure | MIC). `GroupKeyError::Drop` = ignore the frame,
`GroupKeyError::Fail` = deauthenticate (`WLAN_REASON_UNSPECIFIED`). The
caller installs the keys, then calls `group_keys_installed`.

The connect profile requires a scanned BSSID, SSID and 2.4/5 GHz frequency.
Open networks need no key. WPA2 requires a 32-byte PMK, WPA version 2,
PSK AKM, and CCMP-128 pairwise/group suites. Drivers opt in through
`supports_handshake_offload()`; only those advertise the PSK four-way
handshake offload feature. Required MFP, other ciphers/AKMs, arbitrary
association IEs, random scan MACs and other unsupported mutation options
are rejected. Scan execution is passive. Full wpa_supplicant/iw process
interoperability remains a separate integration test.

`Supplicant::rx_eapol_with_nonce(pdu, encrypted, provider)` supplies the
RSNA path with a fallible, lazy SNonce provider (`FnMut() -> Option<[u8;32]>`).
The provider runs only for a validated new message1 while `renew_snonce` is
set, after existing EAPOL/front, PMF and KDE checks. Retries, message3, group
rekeys and discarded traffic never request fresh entropy. `None` returns
`EapolRxError::NonceUnavailable` before committing new nonce/key state; the
caller aborts the attempted handshake/rekey. Production callers use the
fallible hardware-seeded crypto API, with no timing fallback. Existing
`rx_eapol` retains its fixed-byte interface through this same implementation.

### 3.5.1 SAE commit entropy (`sae`)

Production `SaeSession::try_build_commit()` and the P-256 `EccGroup` backend
obtain their secret scalar/mask material through
`narf_crypto::try_fill_random_bytes`. Unavailable entropy returns
`SaeError::EntropyUnavailable` without publishing a Commit, changing state,
or retaining partial samples. Temporary seed buffers are zeroized on success
and failure. `try_build_commit_with_entropy` accepts a driver's fallible secure
provider: it must fill every requested byte unpredictably or return an error;
timing counters and deterministic fallbacks are inadmissible. A Committed retry
returns the existing scalar/element without consulting the provider.

Scalar generation accepts a complete 32-byte candidate only when its checked
big-endian encoding lies in `[1, n)` for the P-256 order. It never reduces an
out-of-range encoding or substitutes one for zero. Each scalar has a maximum of
16 attempts; exhaustion fails without committing session/group secrets.
Production candidates come directly from the fallible secure provider.
Deterministic fixture seeds expand under separate scalar domains with an explicit
rejection counter. Literal `0`, `n`, `n-1` and persistent invalid-provider
regressions check the acceptance range and bounded work; explicit Annex J.10
rand/mask fixtures retain their existing wire/key values.

The generic `Sae::try_build_commit` delegates to `EccGroup::try_make_commit`;
entropy-dependent production groups must implement that fallible surface.
Legacy infallible Commit wrappers return empty output on failure and leave
state unchanged; transmitters use the fallible APIs. Deterministic seed and
scalar/mask constructors exist only in test or `kernel-test` builds. Protocol
fixtures use explicit injected material and do not depend on target entropy.

### 3.5 Deployment regulatory policy

`reg::parse_policy` decodes an NRGD v1 policy; parsing alone conveys no
authority. `reg::policy::load()` opens the exact `wireless-regulatory.bin`
through trusted firmware-registry authority, invokes the blob's current
capability, requires verified signer metadata and returns a fully decoded
owned domain. Unsigned policies are rejected even in unsigned-firmware builds.
`reg::db::ensure_domain()` preserves an existing caller-installed domain,
otherwise performs that signed bootstrap without holding the database lock.
Only successful loads install state; a caller policy installed during lookup
wins the race. A clear during lookup invalidates that in-flight bootstrap;
a later explicit bootstrap may load afresh. Saturated revisions reject bootstrap
rather than alias a previous empty installation. Existing `set_domain` callers retain responsibility for their
policy's authority. `reg::db::Database::{new,install,clear,snapshot}` supplies
isolated or shared immutable `Arc<RegulatoryDomain>` snapshots. An unchanged
installation preserves pointer identity; replacement allocates a new snapshot,
and clear removes current authority while existing readers retain safe storage.
Global `snapshot`, `ensure_snapshot` and `clear_domain` complement the existing
owned-value APIs. Lookup, decoding, rule cloning and retired-snapshot destruction
happen outside the database's IRQ-disabling lock. This cache does not authenticate
arbitrary caller-installed domains or automatically observe firmware-blob
capability revocation: a trusted installer/source must replace or clear policy.

Native CYW43439/BCM43602 attachment observes the live shared installation through
`Station::initialize_live` and a `PolicySource`; explicit `Station::initialize`
retains its fixed-domain contract. Live setup requires the original snapshot
before/after WLC_UP and before interface publication. Scan, join, disconnect,
power-save and packet progress observe replacement/absence, including every
resume of native control futures (before credit-delayed publication), command
receipts and final host-port fences. Country changes, removal, NO_IR/DFS or power
below an acknowledged TX grant close the host port and poison that firmware
lifetime, retaining uncertain DMA. Reinstallation and late firmware events cannot
reopen it. Same-country changes that still cover the acknowledged ceiling preserve
the connection without increasing firmware power. These checks close host
admission when a change is observed; they do not retract in-flight commands or
prove autonomous firmware RF quiescence. Other families retain their documented
policy-observation contracts.

Intel probe, MT76 publication/TX admission, ath10k station-control entry points
and the common CYW/Broadcom FullMAC attachment use this bootstrap. A standalone
driver no longer requires another wireless driver to populate the database.
FullMAC attachment and TX admission fail when policy is missing/invalid;
Intel/MT76 diagnostic/passive receive paths retain their existing closed-TX
behavior. No calibration, country or default transmit authority is inferred.
RTL8188EU uses `policy::load()` directly on every attach, preserving its
fresh-signed-artifact requirement independently of the shared domain cache.
Deployment public keys are baked into the image with
`NARF_FIRMWARE_TRUSTED_KEYS`; the firmware packer accepts a verified
detached signature. No deployment country or signing key is chosen by
the driver. The policy must be supplied by the image builder.
Without a configured policy the interface may scan passively but cannot
associate. This is a deployment-selected policy, not a bundled global
regulatory database or a country inferred from AP advertisements.

The byte format is `NRGD[4]`, version `u16=1`, uppercase country `[u8;2]`,
rule count `u16`, reserved `u16=0`, followed by 1–64 rules of 16 bytes:
start MHz `u32`, end MHz `u32`, maximum bandwidth MHz `u32`, power dBm
`i8`, `RegFlags` `u8`, reserved `u16=0`. Integers are little-endian;
unknown flags, malformed ranges and length mismatches are rejected.
`RegFlags` assigns DFS=bit0, INDOOR_ONLY=bit1, NO_P2P=bit2 and NO_IR=bit3.
NO_IR permits passive reception but denies active probes and host-initiated
station TX in the current host-policy profiles. Drivers must not discard an
overlapping restriction because another rule grants a wider channel span;
future relaxation needs an explicit firmware/regulatory proof. nl80211
GET_REG maps this flag to Linux `NL80211_RRF_NO_IR` (bit7). Older readers that
do not recognize NRGD bit3 reject the policy rather than ignore it.
Bits 4 and 5 are NO_6GHZ_VLP_CLIENT and NO_6GHZ_AFC_CLIENT (GET_REG bits 22
and 23). Bit 6, WMM_ETSI, attaches wireless-regdb's `wmmrule=ETSI` (ETSI EN
301 893), the only WMM rule in `db.txt`. The 6 GHz bits are described with
6 GHz band identity in §3.

**Regulatory WMM rule (`reg::{WmmRule, WmmAcRule}`).** `RegRule::wmm_rule()
-> Option<WmmRule>` is cfg80211 `ieee80211_reg_rule.wmm_rule` with
`has_wmm`. `RegulatoryDomain::rule_for(mhz)` (`freq_reg_info`) and
`wmm_rule_for(mhz)` (`reg_query_regdb_wmm`) look it up by channel.
`WmmRule { client, ap }` holds `[WmmAcRule { cw_min, cw_max, cot_us,
aifsn }; 4]` in mac80211 AC order (VO, VI, BE, BK). `WmmRule::ETSI` copies
the `db.txt` values. `WmmRule::limit(ac, ap, wmm::Ac) -> wmm::Ac` is mac80211
`ieee80211_regulatory_limit_wmm_params`: it raises ECWmin, ECWmax and AIFSN to
the floor and caps TXOP at COT/32 us. `limit_parameters(ap, wmm::Parameters)`
applies it in the parser's ACI order (BE, BK, VI, VO). A driver applies it to
every EDCA set it programs on a channel whose rule carries the WMM rule.
The driver intersects the selected host rule with firmware MCC permission
and applies its power ceiling before transmitting association frames.

The iwlwifi driver hosts the station MLME
and WPA2 state machine behind `WirelessNetIface`. That in-kernel placement
is the approved architecture (decision §8.3, 2026-10-23), not an interim
step toward a userspace-daemon split; the daemon design described in
earlier revisions of this specification is dropped.

## 4. Architecture: SoftMAC vs. FullMAC

NARF supports both through the `WirelessIface` trait:

- **FullMAC Drivers**: The firmware handles scan/associate state machines. The driver implements the high-level `associate()` call by sending a command to hardware.
- **SoftMAC Drivers**: The hardware only does radio/PHY. The driver and kernel handle the 802.11 MAC management.
  - In NARF, SoftMAC logic is split:
    - **Driver**: Timing-critical frames (ACKs, Beacons where possible).
    - **Kernel (`narf-wireless` + driver)**: MLME (scan, authentication, association, reassociation) and the RSNA supplicant (§3.5, §5).
    - **Narf-Link / nl80211**: Userspace configures connections and receives events over the nl80211 control plane (§3.4). A userspace SME remains available on drivers that advertise it, but is not the default path.

## 5. Security: In-Kernel RSNA and Key Management

Key management runs where the keys are used (decision §8.3); there is no
userspace wireless daemon in the trust path:
- WPA2/WPA3 (SAE) encryption/decryption happens in hardware where possible.
- Key management and the 4-way handshake happen in the **kernel**: the shared
  `narf-wireless` RSNA supplicant (`eapol`/`rsna`, SAE in `sae`) for SoftMAC
  and handshake-offload families, the driver's own supplicant for families
  with per-driver implementations (iwlwifi), and the firmware supplicant for
  FullMAC families (cyw43439, brcmfmac). Derived temporal keys are installed
  into the hardware/firmware by the driver; key material is never returned
  to userspace.
- Userspace holds capabilities, not keys: connection requests are gated by
  the `Cap<WirelessIface, Associate>` / `Cap<WirelessIface, Config>` rights
  through the nl80211 permission model (§3.4), and userspace supplies only
  credentials (passphrase, PMK, or SAE password).
- Compat path: on drivers advertising nl80211 handshake offload
  (`4WAY_HANDSHAKE_STA_PSK` / `SAE_OFFLOAD`), a userspace supplicant such as
  wpa_supplicant derives the PMK (or supplies the SAE password) and passes it
  in `CONNECT`, while the in-kernel supplicant still runs the 4-way
  handshake. On external-supplicant drivers (§3.4) userspace runs the
  handshake itself over the control port — the exception, not the model.

## 6. Zero-Copy Management Path

Management frames (Beacons, Probe Requests) are voluminous.
- A `Monitor` cap allows a process to open a `MgmtRing`.
- `MgmtRing` carries `DmaBuffer` caps pointing to raw 802.11 frames.
- No copy between hardware → driver → monitor consumer.

## 7. Stage Assignment

- **Stage 4**: Initial design and `narf-wireless` crate skeleton.
- **Stage 5**: First clean-room driver (candidate: MediaTek MT76 or Atheros AR9271).
- **Stage 6**: Multi-band support, WPA3 integration.

## 8. Resolved Decisions

### 8.1 No MLME in Kernel (Resolved — superseded by §8.3, 2026-10-23)
**Decision**: The 802.11 MLME (Media Access Control Sublayer Management Entity) state machine is too complex and bug-prone for the Frame. It lives in userspace. The kernel only provides the mechanism to send/receive management frames.
**Superseded**: The implementation went the other way; §8.3 records the ruling that replaced this decision. Kept for history.

### 8.2 Hardware-Agnostic Scan (Resolved)
**Decision**: Drivers implement a unified `scan()` async call. If the hardware supports "Offload Scan", the driver uses it. If not, the driver performs the channel-hopping and probe-sending manually in the driver domain.

### 8.3 In-Kernel MLME and RSNA (Resolved, 2026-10-23)
**Decision** (project owner, 2026-10-23 — "the 4-way handshake can be in-kernel"): The station MLME and the RSNA supplicant (WPA2/WPA3 4-way and group-key handshakes, SAE) live in-kernel. SoftMAC families share the `narf-wireless` supplicant (`eapol`/`rsna`, `sae`); FullMAC families (cyw43439, brcmfmac) use their firmware supplicants; iwlwifi retains its per-driver implementation. nl80211 is the control plane: userspace supplies credentials and policy and receives events, and the nl80211 handshake-offload mode (`4WAY_HANDSHAKE_STA_PSK` / `SAE_OFFLOAD` via `CONNECT`) is retained as the compat path for a userspace supplicant such as wpa_supplicant; external-supplicant drivers (§3.4) remain the exception. No userspace "Wireless Daemon" is part of the design. This supersedes §8.1 and the daemon placement described in earlier revisions of §§1, 2, 4 and 5.

## 9. Dependencies

- **Consumes**: `net/` (base interface), `drivers/`, `capabilities/`, `ipc/`, `io/`, and `firmware/` for authenticated deployment-policy bootstrap.
- **Provides**: Wireless-specific control plane to userspace daemons.
