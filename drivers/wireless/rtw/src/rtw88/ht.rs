// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact-chip static HT20 qualification and native gain/path programming.
//! Sources: rtw88/{rtw8821c,rtw8822c,phy,tx,fw,mac80211}.c. No asset is supplied.
use super::{
    firmware_transport::{Error, Io},
    hardware::Features,
    packet_format::DataProfile,
    station_control::Admission,
    station_profile,
};
use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Facts {
    pub hardware: Features,
    pub maximum: u8,
    pub maximum_2ss: Option<u8>,
    pub legacy: [u8; 12],
    pub cck: [u8; 2],
}
impl Facts {
    pub(super) fn capability(self) -> Option<[u8; 26]> {
        self.local()?;
        let mut rx = [0; 10];
        rx[0] = 255;
        if self.hardware.antennas >= 2 && self.hardware.streams >= 2 && self.maximum_2ss.is_some() {
            rx[1] = 255;
        }
        LocalHt::new(
            rx,
            rx,
            HtWidth::Twenty,
            HtGi {
                rx20: true,
                tx20: true,
                rx40: false,
                tx40: false,
            },
            0,
            4,
        )
        .ok()
        .map(|ht| ht.capability_body())
    }
    pub(super) fn local(self) -> Option<LocalPhy> {
        // Source chips implement HT; the actual report may only narrow paths.
        // A board's actual paths and complete factory fields can only narrow
        // metadata. Association still requires a separately current H grant.
        (self.hardware.antennas != 0 && self.hardware.streams != 0 && self.hardware.protocol == 3)
            .then(|| {
                let mask = if self.hardware.antennas >= 2
                    && self.hardware.streams >= 2
                    && self.maximum_2ss.is_some()
                {
                    0xffff
                } else {
                    0xff
                };
                local(mask, mask, true, 0, 0)
            })
            .flatten()
    }
}
/// `did`/`coding` select the RX/TX coding of `main.c::rtw_init_ht_cap`;
/// did 0 (beacon observation only) advertises no coding.
fn local(tx: u16, rx_mask: u16, sgi: bool, did: u16, coding: u8) -> Option<LocalPhy> {
    local_width(tx, rx_mask, sgi, did, coding, None)
}
/// `wide` = Some(TX SGI40) advertises `SUP_WIDTH_20_40 | SGI_40` like
/// `rtw_init_ht_cap` with `hw_cap.bw` 40 (N2xB bound); SGI40 TX needs the
/// record's SGI40 qualification.
fn local_width(
    tx: u16,
    rx_mask: u16,
    sgi: bool,
    did: u16,
    coding: u8,
    wide: Option<bool>,
) -> Option<LocalPhy> {
    local_ht(tx, rx_mask, sgi, did, coding, wide).and_then(|h| {
        if wide.is_some() {
            LocalPhy::ht40(h).ok()
        } else {
            LocalPhy::ht20(h).ok()
        }
    })
}
fn local_ht(
    tx: u16,
    rx_mask: u16,
    sgi: bool,
    did: u16,
    coding: u8,
    wide: Option<bool>,
) -> Option<LocalHt> {
    let mut rx = [0; 10];
    rx[..2].copy_from_slice(&rx_mask.to_le_bytes());
    let mut transmit = [0; 10];
    transmit[..2].copy_from_slice(&tx.to_le_bytes());
    LocalHt::new(
        rx,
        rx,
        if wide.is_some() {
            HtWidth::TwentyForty
        } else {
            HtWidth::Twenty
        },
        HtGi {
            rx20: true,
            tx20: sgi,
            rx40: wide.is_some(),
            tx40: wide == Some(true),
        },
        0,
        4,
    )
    .map(|h| {
        h.with_ldpc(
            super::coding::rx_ldpc(did),
            coding & super::coding::LDPC != 0 && tx & 0xff00 == 0,
        )
        .with_rx_stbc(did != 0)
        // rtw_init_ht_cap: SUP_WIDTH_20_40 | DSSSCCK40 | SGI_40 together.
        .with_dsss_cck40(wide.is_some())
        .with_tx_stbc(coding & super::coding::STBC != 0 && tx & 0xff00 == 0)
    })
    .and_then(|h| h.with_tx_selection(transmit))
    .ok()
}
/// The committed wide program the HT readback must expect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Wide {
    /// N2xB 40MHz pair.
    Forty(super::ht40::Record),
    /// N2xV 80MHz block.
    Eighty(super::vht::Record),
}
pub(super) fn factory_limit(p: &[u8], factor: i16, max: u8) -> Option<u8> {
    factory_limit_group(p, 0, factor, max)
}
/// Linux `phy.c::rtw_phy_get_2g_tx_power_index` HT20 1S ceiling for the
/// 2.4GHz `rtw_get_channel_group` `group`: `bw40_base[group]` plus the
/// signed HT20 1S difference.
pub(super) fn factory_limit_group(p: &[u8], group: usize, factor: i16, max: u8) -> Option<u8> {
    if group > 4 {
        return None;
    }
    let base = *p.get(6 + group)?;
    let diff = *p.get(11)?;
    if base > max || diff == 255 {
        return None;
    }
    let n = i16::from(diff >> 4);
    let value = i16::from(base) + (if n & 8 != 0 { n - 16 } else { n }) * factor;
    (value >= 0).then_some(value.min(i16::from(max)) as u8)
}
/// Linux phy.c::rtw_phy_get_2g_tx_power_index: HT20's signed 1S
/// difference plus the additional signed low-nibble 2S difference.
pub(super) fn factory_limit_2ss(p: &[u8]) -> Option<u8> {
    factory_limit_2ss_group(p, 0)
}
/// [`factory_limit_2ss`] for `bw40_base[group]`.
pub(super) fn factory_limit_2ss_group(p: &[u8], group: usize) -> Option<u8> {
    if group > 4 {
        return None;
    }
    let base = *p.get(6 + group)?;
    let one = *p.get(11)?;
    let two = *p.get(12)?;
    if base > 127 || one == 255 || two == 255 {
        return None;
    }
    let signed = |v: u8| {
        let n = i16::from(v & 15);
        if n & 8 != 0 {
            n - 16
        } else {
            n
        }
    };
    let value = i16::from(base) + 2 * (signed(one >> 4) + signed(two));
    (value >= 0).then_some(value.min(127) as u8)
}
/// Linux `phy.c::rtw_phy_get_2g_tx_power_index` at BW40: `bw40_base[group]`
/// is the one-stream HT40 base (no HT difference is added).
pub(super) fn factory_limit_bw40(p: &[u8], group: usize, max: u8) -> Option<u8> {
    if group > 4 {
        return None;
    }
    let base = *p.get(6 + group)?;
    (base <= max).then_some(base)
}
/// Two-stream HT40: `bw40_base[group] + ht_2s_diff.bw40 * txgi_factor`
/// (`ht_2s_diff` byte 12, signed high nibble).
pub(super) fn factory_limit_bw40_2ss(p: &[u8], group: usize, factor: i16) -> Option<u8> {
    let base = factory_limit_bw40(p, group, 127)?;
    let two = *p.get(12)?;
    if two == 255 {
        return None;
    }
    let n = i16::from(two >> 4);
    let value = i16::from(base) + (if n & 8 != 0 { n - 16 } else { n }) * factor;
    (value >= 0).then_some(value.min(127) as u8)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
    /// Optional separately measured RTL8822CE HT20 RX/TX2SS v2 program.
    /// The legacy v1 proposal remains unchanged and authorizes only1SS.
    pub two_streams: Option<Box<Request>>,
}
pub(super) fn request(base: &station_profile::Grant) -> Result<Request, Error> {
    let f = base
        .ht_facts()
        .filter(|f| f.local().is_some())
        .ok_or(Error::Unsupported)?;
    if !base.wmm() || base.band5() && base.did() == 0xc822 && base.ofdm5_indices().is_none() {
        return Err(Error::Unsupported);
    }
    let (recipe, digest) = base.ht_identity();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF RTW88 exact-chip static HT20 one-stream MCS0..7 LGI/SGI20 v1");
    h.update(&base.did().to_le_bytes());
    h.update(&recipe);
    h.update(&digest);
    h.update(&f.hardware.raw);
    h.update(&[f.maximum]);
    h.update(&f.legacy);
    h.update(&f.cck);
    if base.band5() {
        // 5GHz HT20 variant: the ceilings above are this primary's
        // `rtw_phy_get_5g_tx_power_index` HT20 group values; C22 keeps the
        // N2xO OFDM selection under the MCS7 reference.
        h.update(b"5GHz HT20 GN: Power5g bw40_base+ht_1s.bw20(+ht_2s.bw20) group ceilings; rateID GN_N1SS5/N2SS4; C22 OFDM6..54 = min-path N2xO ofdm+diff relative to MCS7 reference (rtw8822c_set_tx_power_index), CCK refs/diffs zero; C21 0x1d0c HT TXAGC over N2xO OFDM TXAGC, CCK zero");
        h.update(&base.ofdm5_indices().unwrap_or([0; 8]));
    }
    h.update(match base.did() {
        0xc821 => b"C21 RF-A absolute1d0c/10; retained legacy12; unusedHT/VHTzero; RF18/RF08/IQK; RF42 SIPIc90 maskfffff trigger30000 wait13+2000000us actualread2908".as_slice(),
        0xb822 => b"B22 config_trx_mode(AB,AB,false): 1SS TX-A CDDTXP93c[31:20]=001, 2SS TX-AB TXPSEL1 940[15:4]=43, RX-AB; rtw8822b_set_tx_power_index_by_rate 1d00/1d80 absolute per-path indices; retained N2BP/N2BO legacy12 A+B; HT1S path-B words0; VHT words0; RF42 SIPIc90 trigger30000 wait13+2000000us actualread2908".as_slice(),
        _ => b"C22 TX-A RX-AB equalOFDMrefs=MCS7; source signed7bit per-rate difference; minAB; unusedrates effective0; retainedCCKrefs".as_slice(),
    });
    h.update(b"RX PHYST exact32 at24+shift; C21 RXSC/RFMODE no channel; C22 RXSC/current20/reportedchannel1; absentPHY None plus RXD facts; receive epoch fences callbacks and IPC across actual key/reply/close");
    h.update(b"full static raw thermal0..63 supply/antenna/BT envelope; exact source gain writes/readbacks; no tracking or fabricated calibration; transient/response+legacy+8LGI+8SGI measured peaks");
    h.update(b"bound original HT45/61/WMM response; generated localHT20 MCSff RX/TX SGI20 default3839AMSDU; BGN20_1SS3 RA mask12..19 PTdisabled; fixedDATA12..19 USE_RATE DISDATAFB BW0 SGIbit4; BE/TID0 QoS26 before softwareCCMP; originalRAW AMSDU authenticated once; ADDBA status37 nativeCCX; noTXBA");
    let mac = base.own();
    let mut proposal = Request {
        identity: h.finalize(),
        mac,
        filename: super::channel_policy::scoped_filename(
            &format!(
                "rtw88/{}-ht20-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                base.host().family(),
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            ),
            base.channel(),
        ),
        two_streams: None,
    };
    if base.did() == 0xb822 && f.hardware.streams >= 2 && f.hardware.antennas >= 2 {
        if let Some(maximum) = f.maximum_2ss {
            let mut h = narf_crypto::sha256::Sha256::new();
            h.update(b"NARF RTL8822BE exact retained HT20 two-stream v2");
            h.update(&proposal.identity);
            h.update(&[f.maximum, maximum]);
            h.update(b"N2BH256v2;MCS16/RXffff;MCS8..15 phy.c bw40_base+ht_1s.bw20+ht_2s.bw20 txgi1 minAB<=3f;path-A MCS0..15 and path-B MCS8..15 absolute indices 1d00/1d80 words 0c..1b;no path change: base config_trx_mode(AB,AB,false) 1SS-A/2SS-AB readback 93c/940");
            h.update(b"current N2BQ/N2BP/N2BS/N2BL source and policy;fresh RF42 inside N2BP windows;per-path word readback;all2SS LGI/SGI/transient/response/simultaneous-chain measured peaks");
            proposal.two_streams = Some(Box::new(Request {
                identity: h.finalize(),
                mac: proposal.mac,
                filename: proposal.filename.replace("ht20-v1-", "ht20-2ss-v2-"),
                two_streams: None,
            }));
        }
    }
    if base.did() == 0xc822 && f.hardware.streams >= 2 && f.hardware.antennas >= 2 {
        if let Some(maximum) = f.maximum_2ss {
            let mut h = narf_crypto::sha256::Sha256::new();
            h.update(b"NARF RTL8822CE exact retained HT20 two-stream v2");
            h.update(&proposal.identity);
            h.update(&[f.maximum, maximum]);
            h.update(b"N22H256v2;MCS16/RXffff;MCS8..15 cumulative signed HT1S+HT2S low nibble minAB;equal references MCS7;signed7bit shared TXAGC 12..27;legacy1SS-A/2SS-AB ANT820=31 TXLGMAP1e2c=0400;source BBreset twice;RX path unchanged AB;TXGI direct not inferred dBm");
            h.update(b"current original full C/Q/H source and policy before mutation;actual native queue/mailbox/MAC quiet;TXPAUSE+RXDMApark before BB;readback and current grant before resume;no partial restore on error;all2SS LGI/SGI/transient/response/simultaneous-chain measured peaks");
            proposal.two_streams = Some(Box::new(Request {
                identity: h.finalize(),
                mac: proposal.mac,
                filename: proposal.filename.replace("ht20-v1-", "ht20-2ss-v2-"),
                two_streams: None,
            }));
        }
    }
    Ok(proposal)
}
pub(super) enum Source {
    Registered,
    #[cfg(any(test, feature = "kernel-test"))]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
pub(super) struct Grant {
    request: Request,
    digest: [u8; 32],
    base: Arc<station_profile::Grant>,
    cap: Cap<FirmwareBlob, Read>,
    facts: Facts,
    indices: [u8; 16],
    /// B22 v2 path-B MCS8..15 indices (path A carries [`Self::indices`]).
    indices_b: [u8; 8],
    peaks: Vec<i16>,
    antenna: i16,
    ceiling: i16,
    mcs: u16,
    sgi: bool,
    version: u8,
    /// Coexistence `hal.txrx_1ss`: `config_trx_mode(A, A)` leaves 1SS TX on
    /// path A only (`REG_ANTMAP0` 0x11 instead of the two-path 0x31).
    txrx_1ss: core::sync::atomic::AtomicBool,
}
impl Source {
    pub(super) fn load(self, base: Arc<station_profile::Grant>) -> Result<Arc<Grant>, Error> {
        let r = request(&base)?;
        struct Decode {
            base: Arc<station_profile::Grant>,
            request: Request,
        }
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let v = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Grant::decode(v.bytes, v.signer, *cap, self.base, self.request)
                })())
            }
        }
        let g = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive::<Read>().ok())
                    .ok_or(Error::Access)?;
                let (cap, r) = if let Some(second) = r.two_streams.clone() {
                    match narf_firmware::open(&second.filename, &loader) {
                        Ok(cap) => (cap, *second),
                        Err(narf_firmware::FirmwareError::NotFound) => (
                            narf_firmware::open(&r.filename, &loader).map_err(Error::Firmware)?,
                            r,
                        ),
                        Err(error) => return Err(Error::Firmware(error)),
                    }
                } else {
                    (
                        narf_firmware::open(&r.filename, &loader).map_err(Error::Firmware)?,
                        r,
                    )
                };
                cap.invoke(Decode { base, request: r })
                    .map_err(|_| Error::Access)??
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => {
                let r = if bytes.get(4) == Some(&2) {
                    *r.two_streams.ok_or(Error::Unsupported)?
                } else {
                    r
                };
                Grant::decode(&bytes, signer, cap, base, r)?
            }
        };
        g.check()?;
        Ok(Arc::new(g))
    }
}
impl Grant {
    pub(super) fn request(&self) -> Request {
        self.request.clone()
    }
    fn decode(
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        base: Arc<station_profile::Grant>,
        request: Request,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let facts = base.ht_facts().ok_or(Error::Unsupported)?;
        let v2 = b.get(4) == Some(&2);
        let length = if v2 { 256 } else { 192 };
        if signer.is_none()
            || b.len() != length
            || b[..4]
                != *match base.did() {
                    0xc821 => b"N21H",
                    0xb822 => b"N2BH",
                    _ => b"N22H",
                }
            || b[4..8] != if v2 { [2, 0, 0, 1] } else { [1, 0, 192, 0] }
            || b[8..12] != (length as u32).to_le_bytes()
            || b[12..16] != base.host().header()
            || b[16..48] != request.identity
            || b[48..54] != request.mac
            || b[54..56] != [1, 20]
            || b[64..66] != [0, 63]
            || if v2 {
                !matches!(base.did(), 0xc822 | 0xb822)
                    || facts.hardware.streams < 2
                    || facts.hardware.antennas < 2
                    || facts.maximum_2ss.is_none()
                    || b[67] == 0
                    || b[68] & !1 != 0
                    || b[69] != 2
                    // B22 carries path-B MCS8..15 at 174..182.
                    || b[if base.did() == 0xb822 { 182 } else { 174 }..]
                        .iter()
                        .any(|&byte| byte != 0)
            } else {
                b[66] == 0 || b[67] & !1 != 0 || b[132..].iter().any(|&byte| byte != 0)
            }
        {
            return Err(Error::Prerequisite);
        }
        let signed = |at| i16::from_le_bytes([b[at], b[at + 1]]);
        let mut indices = [0; 16];
        if v2 {
            indices.copy_from_slice(&b[70..86]);
        } else {
            indices[..8].copy_from_slice(&b[68..76]);
        }
        let mut indices_b = [0; 8];
        if v2 && base.did() == 0xb822 {
            indices_b.copy_from_slice(&b[174..182]);
        }
        let peaks = (0..if v2 { 46 } else { 30 })
            .map(|i| {
                signed(if i < 2 {
                    60 + i * 2
                } else if v2 {
                    if i < 34 {
                        86 + (i - 2) * 2
                    } else {
                        150 + (i - 34) * 2
                    }
                } else if i < 18 {
                    76 + (i - 2) * 2
                } else {
                    108 + (i - 18) * 2
                })
            })
            .collect();
        let g = Self {
            request,
            digest: {
                let mut h = narf_crypto::sha256::Sha256::new();
                h.update(b);
                h.finalize()
            },
            base,
            cap,
            facts,
            indices,
            indices_b,
            peaks,
            antenna: signed(56),
            ceiling: signed(58),
            mcs: if v2 {
                u16::from_le_bytes([b[66], b[67]])
            } else {
                u16::from(b[66])
            },
            sgi: b[if v2 { 68 } else { 67 }] != 0,
            version: if v2 { 2 } else { 1 },
            txrx_1ss: core::sync::atomic::AtomicBool::new(false),
        };
        if !(0..=128).contains(&g.antenna)
            || !(-512..=256).contains(&g.ceiling)
            || g.indices[..8].iter().any(|&i| i > facts.maximum)
            || v2
                && g.indices[8..]
                    .iter()
                    .chain(g.indices_b.iter())
                    .any(|&i| i > facts.maximum_2ss.unwrap_or(0))
            || g.peaks.iter().any(|&p| !(-512..=256).contains(&p))
            || g.peaks[1..].iter().any(|&p| p > g.peaks[0])
            || g.base.ofdm5_indices().is_some_and(|o| {
                o.iter()
                    .any(|&v| !(-64..=63).contains(&(i16::from(v) - i16::from(g.indices[7]))))
            })
            || g.base.did() == 0xc822
                && (g.indices[7] > 64
                    || g.indices
                        .iter()
                        .any(|&v| !(-64..=63).contains(&(i16::from(v) - i16::from(g.indices[7])))))
        {
            return Err(Error::Prerequisite);
        }
        Ok(g)
    }
    fn two_streams(&self) -> bool {
        self.version == 2
    }
    /// Record whether coexistence 1SS (`hal.txrx_1ss`) is in effect.
    pub(super) fn set_txrx_1ss(&self, on: bool) {
        self.txrx_1ss
            .store(on, core::sync::atomic::Ordering::Release);
    }
    /// Two-stream TX path readback: `config_tx_path(AB, A, A)` (0x820 0x31,
    /// TXLGMAP 0x0400, CCK path A), or under coexistence 1SS
    /// `config_tx_path(A, A, A)` (0x820 0x11; TXLGMAP 15:8 and CCK unchanged).
    async fn tx_paths(
        &self,
        read: &mut impl super::firmware_transport::Read32,
    ) -> Result<(), Error> {
        let ant = if self.txrx_1ss.load(core::sync::atomic::Ordering::Acquire) {
            0x11
        } else {
            0x31
        };
        if self.two_streams()
            && (read.read32(0x820).await? & 255 != ant
                || read.read32(0x1e2c).await? & 0xffff != 0x400
                || read.read32(0x1a04).await? & 0xf0000000 != 0x80000000)
        {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn rx_mask(&self) -> u16 {
        if self.two_streams() {
            0xffff
        } else {
            0xff
        }
    }
    pub(super) fn local(&self) -> LocalPhy {
        self.local_coded(0)
    }
    /// Base RX coding plus the separately qualified N2xC TX `coding` flags.
    pub(super) fn local_coded(&self, coding: u8) -> LocalPhy {
        local(self.mcs, self.rx_mask(), self.sgi, self.base.did(), coding)
            .expect("validated native HT facts")
    }
    /// [`Self::local_coded`] advertising 20/40MHz under a bound N2xB record.
    pub(super) fn local_wide(&self, coding: u8, sgi40: bool) -> LocalPhy {
        local_width(
            self.mcs,
            self.rx_mask(),
            self.sgi,
            self.base.did(),
            coding,
            Some(sgi40),
        )
        .expect("validated native HT facts")
    }
    /// `rtw_init_ht_cap` (20/40MHz, RX SGI40, no HT TX SGI40) plus
    /// `rtw_init_vht_cap` for a bound N2xV record (`LocalPhy::vht80`).
    pub(super) fn local_vht80(&self, coding: u8, record: &super::vht::Record) -> Option<LocalPhy> {
        let (ht, vht) = self.vht80_parts(coding, record)?;
        LocalPhy::vht80(ht, vht).ok()
    }
    fn vht80_parts(
        &self,
        coding: u8,
        record: &super::vht::Record,
    ) -> Option<(LocalHt, narf_wireless::association::phy::LocalVht)> {
        let ht = local_ht(
            self.mcs,
            self.rx_mask(),
            self.sgi,
            self.base.did(),
            coding,
            Some(false),
        )?;
        let streams = if self.two_streams() { 2 } else { 1 };
        let vht = super::vht::local(self.base.did(), streams, record)?;
        Some((ht, vht))
    }
    /// Wiphy HT Capabilities body of the uncoded HT20 station offer
    /// ([`Self::local_coded`] with coding 0; `rtw_init_ht_cap` without a
    /// bound N2xB/N2xC record).
    pub(super) fn ht20_capability(&self) -> Option<[u8; 26]> {
        local_ht(self.mcs, self.rx_mask(), self.sgi, self.base.did(), 0, None)
            .map(|ht| ht.capability_body())
    }
    /// Wiphy (HT, VHT) Capabilities bodies of [`Self::local_vht80`] with
    /// coding 0: the exact elements the station offers when it joins on
    /// `record` (main.c `rtw_init_ht_cap` + `rtw_init_vht_cap`).
    pub(super) fn vht80_capability(
        &self,
        record: &super::vht::Record,
    ) -> Option<([u8; 26], [u8; 12])> {
        let (ht, vht) = self.vht80_parts(0, record)?;
        LocalPhy::vht80(ht, vht).ok()?;
        Some((ht.capability_body(), vht.capability_body()))
    }
    /// The locally advertised VHT RX set (`VhtRates::rx`).
    pub(super) fn vht_rx(&self) -> u32 {
        DataProfile::vht_rx_for(self.rx_mask())
    }
    pub(super) fn profile(&self, rates: u16, mcs: u16, sgi: bool) -> Result<DataProfile, Error> {
        let p = DataProfile {
            rates,
            qos: true,
            mcs,
            rx_mcs: self.rx_mask(),
            sgi,
            ldpc: false,
            stbc: false,
            acs: 0,
            fallback: false,
            bw40: false,
            band5: self.base.band5(),
            vht: None,
        };
        if !self.allows(p) {
            return Err(Error::Unsupported);
        }
        Ok(p)
    }
    pub(super) fn allows(&self, p: DataProfile) -> bool {
        // TX coding is admitted separately by the bound N2xC continuation.
        p.valid()
            && p.qos
            && !p.ldpc
            && !p.stbc
            && p.rates & !self.base.rates() == 0
            && p.mcs != 0
            && p.mcs & !self.mcs == 0
            && p.rx_mcs == self.rx_mask()
            && (!p.sgi || self.sgi)
    }
    pub(super) fn mcs(&self) -> u16 {
        self.mcs
    }
    pub(super) fn sgi(&self) -> bool {
        self.sgi
    }
    /// Operating primary of the extension this HT program was qualified over.
    pub(super) fn channel(&self) -> u8 {
        self.base.channel()
    }
    pub(super) fn matches(&self, b: &station_profile::Grant) -> bool {
        request(b).ok().is_some_and(|proposal| {
            if self.two_streams() {
                proposal.two_streams.as_deref() == Some(&self.request)
            } else {
                proposal == self.request
            }
        })
    }
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        struct Live<'a, F>(&'a Grant, F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let d = self.0.base.current_domain()?;
                    let limit = self.0.base.ht_limit(&d)?.min(self.0.ceiling);
                    if self
                        .0
                        .peaks
                        .iter()
                        .any(|&p| i32::from(p) + i32::from(self.0.antenna) > i32::from(limit))
                    {
                        return Err(Error::Prerequisite);
                    }
                    (self.1)()
                })())
            }
        }
        self.base
            .invoke(|| self.cap.invoke(Live(self, op)).map_err(|_| Error::Access)?)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
    pub(super) fn rx_ba_identity(&self) -> ([u8; 32], [u8; 32], u16) {
        (self.request.identity, self.digest, self.base.did())
    }
    /// Host identity keying this board's records (`phy8821c::Host`).
    pub(super) fn host(&self) -> super::phy8821c::Host {
        self.base.host()
    }
    pub(super) fn rx_ba_limit(&self) -> Result<i16, Error> {
        let domain = self.base.current_domain()?;
        Ok(self.base.ht_limit(&domain)?.min(self.ceiling))
    }
    pub(super) fn within(&self, limit: i16) -> bool {
        self.peaks
            .iter()
            .all(|&p| i32::from(p) + i32::from(self.antenna) <= i32::from(limit))
    }
    pub(super) fn tracking_indices(&self) -> [u8; 8] {
        self.indices[..8]
            .try_into()
            .expect("one-stream tracking indices")
    }
    /// B22 TXAGC words 0..6 (DESC_RATE 0x00..0x1b) per path as
    /// `rtw8822b_set_tx_power_index_by_rate` packs them: the primary's
    /// retained legacy12 indices, MCS0..7 on path A (1SS transmits on A
    /// only under `config_trx_mode(AB, AB, false)`; path-B HT1S zero) and,
    /// for v2, MCS8..15 on both paths.
    fn b22_words(&self) -> Result<[[u32; 7]; 2], Error> {
        let legacy = self.base.b22_indices().ok_or(Error::Unsupported)?;
        Ok(core::array::from_fn(|path| {
            let mut rates = [0u8; 28];
            rates[..12].copy_from_slice(&legacy[path]);
            if path == 0 {
                rates[12..20].copy_from_slice(&self.indices[..8]);
            }
            if self.two_streams() {
                rates[20..].copy_from_slice(if path == 0 {
                    &self.indices[8..]
                } else {
                    &self.indices_b
                });
            }
            core::array::from_fn(|w| {
                u32::from_le_bytes(rates[w * 4..w * 4 + 4].try_into().unwrap())
            })
        }))
    }
    /// B22 per-path DESC_RATE 0..count table for `rtw8822b_pwrtrack_set`
    /// headroom: the programmed words, except that path B's HT1S entries
    /// (programmed zero; 1SS transmits on A) take path A's index, the
    /// smaller-headroom choice.
    pub(super) fn b22_rates(&self) -> Option<([[u8; super::tracking8822b::RATES]; 2], usize)> {
        if self.base.did() != 0xb822 {
            return None;
        }
        let words = self.b22_words().ok()?;
        let mut rates = [[0; super::tracking8822b::RATES]; 2];
        for (r, w) in rates.iter_mut().zip(words) {
            for (i, v) in w.into_iter().enumerate() {
                r[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        rates[1][12..20].copy_from_slice(&self.indices[..8]);
        Some((rates, if self.two_streams() { 28 } else { 20 }))
    }
    /// B22 readback: base 1SS-A/2SS-AB path selection, both paths' words
    /// 0..6, host-only crypto.
    async fn readback_b22(
        &self,
        read: &mut impl super::firmware_transport::Read32,
    ) -> Result<(), Error> {
        if read.read32(0x93c).await? >> 20 != 0x001
            || read.read32(0x940).await? >> 4 & 0xfff != 0x43
        {
            return Err(Error::Prerequisite);
        }
        for (base, words) in [0x1d00u16, 0x1d80].into_iter().zip(self.b22_words()?) {
            for (i, v) in words.into_iter().enumerate() {
                if read.read32(base + i as u16 * 4).await? != v {
                    return Err(Error::Prerequisite);
                }
            }
        }
        if read.read32(0x100).await? & 0x200 != 0 || read.read32(0x680).await? & 0xcf != 0 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    /// [`Self::readback_b22`] at the committed width: under `N2BB` words
    /// 0..6 are the HT40 selection (`ht40::check8822b`), under `N2BV` the
    /// whole 0x1d00/0x1d80 tables are the VHT80 ones (`vht::b22_tables`,
    /// HT zero).
    async fn readback_b22_at(
        &self,
        read: &mut impl super::firmware_transport::Read32,
        wide: Option<&Wide>,
    ) -> Result<(), Error> {
        let legacy = self.base.b22_indices().ok_or(Error::Unsupported)?;
        let tables = match wide {
            None => return self.readback_b22(read).await,
            Some(Wide::Forty(r)) => {
                if r.mcs != self.mcs {
                    return Err(Error::State);
                }
                super::ht40::check8822b(read, legacy, r).await?;
                None
            }
            Some(Wide::Eighty(v)) => Some(super::vht::b22_tables(legacy, v)),
        };
        if read.read32(0x93c).await? >> 20 != 0x001
            || read.read32(0x940).await? >> 4 & 0xfff != 0x43
        {
            return Err(Error::Prerequisite);
        }
        if let Some(tables) = tables {
            for (base, table) in [0x1d00u16, 0x1d80].into_iter().zip(tables) {
                for (w, rates) in table.chunks_exact(4).enumerate() {
                    if (7..11).contains(&w) {
                        continue;
                    }
                    let v = u32::from_le_bytes([rates[0], rates[1], rates[2], rates[3]]);
                    if read.read32(base + w as u16 * 4).await? != v {
                        return Err(Error::Prerequisite);
                    }
                }
            }
        }
        if read.read32(0x100).await? & 0x200 != 0 || read.read32(0x680).await? & 0xcf != 0 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn words(&self) -> [u32; 16] {
        let mut bytes = [0; 64];
        let reference = i16::from(self.indices[7]);
        // 5GHz keeps the N2xO OFDM selection (management/EAPOL at OFDM6).
        let ofdm = self.base.ofdm5_indices();
        for (rate, b) in bytes.iter_mut().enumerate() {
            let index = if (12..if self.two_streams() { 28 } else { 20 }).contains(&rate) {
                i16::from(self.indices[rate - 12])
            } else if let (Some(o), 4..=11) = (ofdm, rate) {
                i16::from(o[rate - 4])
            } else {
                0
            };
            *b = if rate < 4 {
                0
            } else {
                ((index - reference) as i8 as u8) & 127
            };
        }
        core::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
    }
    /// [`Self::readback`] at the committed width: with the N2xB pair
    /// programmed, the HT TXAGC is the record's HT40 selection and (C21) RF18
    /// carries the 40MHz center.
    pub(super) async fn readback_at(
        &self,
        mut read: impl super::firmware_transport::Read32,
        wide: Option<&Wide>,
    ) -> Result<(), Error> {
        if self.base.did() == 0xb822 {
            return self.readback_b22_at(&mut read, wide).await;
        }
        let r = match wide {
            None => return self.readback(read).await,
            Some(Wide::Forty(r)) => r,
            Some(Wide::Eighty(v)) => return self.readback_vht(read, v).await,
        };
        if self.base.did() == 0xc821 {
            let mcs: [u8; 8] = r.indices[..8].try_into().expect("one-stream HT40 indices");
            return super::radio8821c::operating_readback_wide(
                read,
                self.facts.legacy,
                mcs,
                r.center(),
            )
            .await;
        }
        self.tx_paths(&mut read).await?;
        for (reg, v) in [0x18a0, 0x41a0].into_iter().zip(self.facts.cck) {
            if read.read32(reg).await? >> 16 & 127 != u32::from(v) {
                return Err(Error::Prerequisite);
            }
        }
        super::ht40::check_power(&mut read, 0xc822, r, self.base.ofdm5_indices()).await?;
        if read.read32(0x100).await? & 0x200 != 0 || read.read32(0x680).await? & 0xcf != 0 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    /// [`Self::readback`] at the N2xV 80MHz block: C22 difference words
    /// are the VHT selection (`vht::check_power`), C21 keeps the HT20 words
    /// and carries the VHT words with RF18 BW80 on the center.
    async fn readback_vht(
        &self,
        mut read: impl super::firmware_transport::Read32,
        v: &super::vht::Record,
    ) -> Result<(), Error> {
        if self.base.did() == 0xc821 {
            let mut vht = [0; 12];
            vht[..10].copy_from_slice(&v.indices[..10]);
            return super::radio8821c::operating_readback_vht(
                read,
                self.facts.legacy,
                self.tracking_indices(),
                vht,
                v.center,
            )
            .await;
        }
        self.tx_paths(&mut read).await?;
        for (reg, c) in [0x18a0, 0x41a0].into_iter().zip(self.facts.cck) {
            if read.read32(reg).await? >> 16 & 127 != u32::from(c) {
                return Err(Error::Prerequisite);
            }
        }
        super::vht::check_power(&mut read, 0xc822, v, self.base.ofdm5_indices()).await?;
        if read.read32(0x100).await? & 0x200 != 0 || read.read32(0x680).await? & 0xcf != 0 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    pub(super) async fn readback(
        &self,
        mut read: impl super::firmware_transport::Read32,
    ) -> Result<(), Error> {
        if self.base.did() == 0xb822 {
            return self.readback_b22(&mut read).await;
        }
        if self.base.did() == 0xc821 {
            return super::radio8821c::operating_readback_ht(
                read,
                self.facts.legacy,
                self.tracking_indices(),
                self.channel(),
            )
            .await;
        }
        self.tx_paths(&mut read).await?;
        for (r, v) in [0x18a0, 0x41a0].into_iter().zip(self.facts.cck) {
            if read.read32(r).await? >> 16 & 127 != u32::from(v) {
                return Err(Error::Prerequisite);
            }
        }
        for r in [0x18e8, 0x41e8] {
            if read.read32(r).await? & 0x1fc00 != u32::from(self.indices[7]) << 10 {
                return Err(Error::Prerequisite);
            }
        }
        for (i, v) in self.words().into_iter().enumerate() {
            if read.read32(0x3a00 + i as u16 * 4).await? != v {
                return Err(Error::Prerequisite);
            }
        }
        if read.read32(0x100).await? & 0x200 != 0 || read.read32(0x680).await? & 0xcf != 0 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    async fn guarded<T>(
        &self,
        admission: &Admission,
        op: impl core::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        super::firmware_transport::enclosed(|inner| self.invoke(|| admission.run(inner)), op).await
    }
    pub(super) async fn program(
        &self,
        io: &mut impl Io,
        admission: &Admission,
    ) -> Result<(), Error> {
        self.check()?;
        // C22 v2 changes TX paths and resets BB; B22 keeps the base path
        // selection and only rewrites TXAGC words, as C21 does.
        let parked = if self.two_streams() && self.base.did() == 0xc822 {
            Some(
                self.guarded(admission, async {
                    io.station_allowed()?;
                    if !io.station_ht_program_quiet().await? {
                        return Err(Error::State);
                    }
                    let pause = io.read8(0x522).await?;
                    let rx = io.read32(super::dma_stop::RXPKT_NUM).await?;
                    if pause != 0 || rx == u32::MAX || rx & super::dma_stop::RW_RELEASE != 0 {
                        return Err(Error::Prerequisite);
                    }
                    io.write8(0x522, 255).await?;
                    io.write32(super::dma_stop::RXPKT_NUM, rx | super::dma_stop::RW_RELEASE)
                        .await?;
                    if io.read8(0x522).await? != 255 {
                        return Err(Error::Prerequisite);
                    }
                    Ok(pause)
                })
                .await?,
            )
        } else {
            None
        };
        if parked.is_some() {
            // Bounded by the same 10ms the synchronous spin used; each sample
            // re-enters the gate, and the executor runs between samples.
            let deadline = narf_time::Deadline::after_ms(10);
            let idle = loop {
                let idle = self
                    .guarded(admission, async {
                        io.station_allowed()?;
                        let rx = io.read32(super::dma_stop::RXPKT_NUM).await?;
                        if rx == u32::MAX {
                            return Err(Error::Gone);
                        }
                        if rx & super::dma_stop::RW_RELEASE == 0 {
                            return Err(Error::Prerequisite);
                        }
                        Ok(rx & super::dma_stop::RXDMA_IDLE != 0)
                    })
                    .await?;
                if idle {
                    break true;
                }
                if deadline.expired() {
                    break false;
                }
                narf_scheduler::yield_now().await;
            };
            if !idle {
                return Err(Error::Timeout);
            }
        }
        // Call only after the retained gate encloses this NEW complete program.
        // C21's actual fresh RF42 conversion is required, never a factory byte.
        if matches!(self.base.did(), 0xc821 | 0xb822) {
            crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
                io.station_allowed()?;
                let old = io.read32(0x2908).await?;
                if old == u32::MAX {
                    return Err(Error::Gone);
                }
                io.write32(0xc90, (0x42 << 20) | (old & 0xfffff & !0x30000) | 0x30000)
                    .await
            })
            .await?;
            io.delay_us(13).await;
            io.delay_us(2_000_000).await;
            crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
                io.station_allowed()?;
                let meter = io.read32(0x2908).await?;
                if meter == u32::MAX {
                    return Err(Error::Gone);
                }
                self.base.temperature(((meter >> 10) & 63) as u8)
            })
            .await?;
            if self.base.did() == 0xb822 {
                // `rtw8822b_set_tx_power_index_by_rate` HT1S/HT2S words
                // (0x0c..0x1b) of both paths; legacy words stay as programmed.
                for (base, words) in [0x1d00u16, 0x1d80].into_iter().zip(self.b22_words()?) {
                    for (i, v) in words.into_iter().enumerate().skip(3) {
                        crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
                            io.station_allowed()?;
                            io.write32(base + i as u16 * 4, v).await
                        })
                        .await?;
                        narf_scheduler::yield_now().await;
                    }
                }
            } else {
                for (i, chunk) in self.indices[..8].chunks_exact(4).enumerate() {
                    let v = u32::from_le_bytes(chunk.try_into().unwrap());
                    crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
                        io.station_allowed()?;
                        io.write32(0x1d0c + i as u16 * 4, v).await
                    })
                    .await?;
                    narf_scheduler::yield_now().await;
                }
            }
        } else {
            for r in [0x18e8, 0x41e8] {
                self.guarded(admission, async {
                    io.station_allowed()?;
                    super::radio::mask(io, 0x1c90, 1 << 15, 0).await?;
                    super::radio::mask(io, r, 0x1fc00, u32::from(self.indices[7])).await
                })
                .await?;
                narf_scheduler::yield_now().await;
            }
            for (i, v) in self.words().into_iter().enumerate() {
                self.guarded(admission, async {
                    io.station_allowed()?;
                    super::radio::mask(io, 0x1c90, 1 << 15, 0).await?;
                    io.write32(0x3a00 + i as u16 * 4, v).await
                })
                .await?;
                narf_scheduler::yield_now().await;
            }
            if self.two_streams() {
                self.guarded(admission, async {
                    io.station_allowed()?;
                    super::radio::mask(io, 0x820, 255, 0x31).await?;
                    super::radio::mask(io, 0x1e2c, 0xffff, 0x400).await?;
                    // rtw8822c_config_ofdm_tx_path + outer config_tx_path.
                    // Both reset BB_RSTB while preserving all other SYS bits.
                    for _ in 0..2 {
                        let sys = io.read16(0x2).await?;
                        if sys == u16::MAX {
                            return Err(Error::Gone);
                        }
                        io.write16(0x2, sys | 1).await?;
                        io.write16(0x2, sys & !1).await?;
                        io.write16(0x2, sys | 1).await?;
                    }
                    if io.read16(0x2).await? & 1 == 0 {
                        return Err(Error::Prerequisite);
                    }
                    Ok(())
                })
                .await?;
            }
        }
        self.guarded(admission, async {
            io.station_allowed()?;
            self.readback(super::firmware_transport::IoRead32(io))
                .await?;
            if let Some(pause) = parked {
                let rx = io.read32(super::dma_stop::RXPKT_NUM).await?;
                if io.read8(0x522).await? != 255
                    || rx == u32::MAX
                    || rx & (super::dma_stop::RW_RELEASE | super::dma_stop::RXDMA_IDLE)
                        != super::dma_stop::RW_RELEASE | super::dma_stop::RXDMA_IDLE
                {
                    return Err(Error::Prerequisite);
                }
                io.write32(
                    super::dma_stop::RXPKT_NUM,
                    rx & !super::dma_stop::RW_RELEASE,
                )
                .await?;
                io.write8(0x522, pause).await?;
                if io.read8(0x522).await? != pause
                    || io.read32(super::dma_stop::RXPKT_NUM).await? & super::dma_stop::RW_RELEASE
                        != 0
                {
                    return Err(Error::Prerequisite);
                }
            }
            Ok(())
        })
        .await
    }
}
/// Bound normal-ACK immediate single-TID ADDBA request. No BA agreement is
/// created by the reply; its actual DMA/radio receipt is still mandatory.
pub(super) fn decline(frame: &[u8], own: [u8; 6], ap: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() != 33
        || frame[..2] != [0xd0, 0]
        || frame[4..10] != own
        || frame[10..16] != ap
        || frame[16..22] != ap
        || frame[22] & 15 != 0
        || frame[24..26] != [3, 0]
    {
        return None;
    }
    let parameter = u16::from_le_bytes([frame[27], frame[28]]);
    if parameter & 2 == 0 || u16::from_le_bytes([frame[31], frame[32]]) & 15 != 0 {
        return None;
    }
    let mut out = alloc::vec![0xd0, 0, 0, 0];
    out.extend_from_slice(&ap);
    out.extend_from_slice(&own);
    out.extend_from_slice(&ap);
    out.extend_from_slice(&[0, 0, 3, 1, frame[26], 37, 0]);
    out.extend_from_slice(&((parameter & 0x3c) | 2).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    Some(out)
}
