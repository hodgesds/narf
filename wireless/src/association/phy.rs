// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded HT/VHT facts and directional station negotiation. These profiles
//! describe implementation limits; they grant no radio, key, BA or port rights.
//! Wire definitions: Linux include/linux/ieee80211-{ht,vht}.h, mac80211/{ht,vht}.c.
use super::{channel, ies, Error};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtWidth {
    Twenty,
    TwentyForty,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HtGi {
    pub rx20: bool,
    pub tx20: bool,
    pub rx40: bool,
    pub tx40: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Twenty,
    Forty,
    Eighty,
}

/// Initial local encoding supports equal-modulation MCS0..31, no STBC/LDPC,
/// HT-control, beamforming or optional large A-MSDU. RX/TX must include
/// mandatory MCS0..7 (IEEE20.3.5; Linux ath10k/mac.c peer HT-rate check).
/// An optional subset bounds TX selection without changing capability IEs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalHt {
    rx: [u8; 10],
    tx: [u8; 10],
    tx_selection: [u8; 10],
    width: HtWidth,
    gi: HtGi,
    factor: u8,
    density: u8,
}
impl LocalHt {
    pub fn new(
        rx: [u8; 10],
        tx: [u8; 10],
        width: HtWidth,
        gi: HtGi,
        ampdu_factor: u8,
        mpdu_density: u8,
    ) -> Result<Self, Error> {
        if rx[0] != 255
            || tx[0] != 255
            || rx[4..].iter().chain(&tx[4..]).any(|v| *v != 0)
            || ampdu_factor > 3
            || mpdu_density > 7
            || width == HtWidth::Twenty && (gi.rx40 || gi.tx40)
        {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            rx,
            tx,
            tx_selection: tx,
            width,
            gi,
            factor: ampdu_factor,
            density: mpdu_density,
        })
    }
    pub fn siso20(rx_sgi20: bool, tx_sgi20: bool) -> Self {
        Self {
            rx: [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            tx: [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            tx_selection: [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            width: HtWidth::Twenty,
            gi: HtGi {
                rx20: rx_sgi20,
                tx20: tx_sgi20,
                rx40: false,
                tx40: false,
            },
            factor: 0,
            density: 0,
        }
    }
    /// Bound TX rate selection to a subset of actual implemented TX support.
    /// This expresses policy facts only; native power/radio proofs remain
    /// mandatory at every enabling/publication boundary.
    pub fn with_tx_selection(mut self, mask: [u8; 10]) -> Result<Self, Error> {
        if mask.iter().all(|v| *v == 0)
            || mask
                .iter()
                .zip(self.tx)
                .any(|(selected, actual)| selected & !actual != 0)
        {
            return Err(Error::UnsupportedRates);
        }
        self.tx_selection = mask;
        Ok(self)
    }
    pub fn capability_body(&self) -> [u8; 26] {
        let mut body = [0; 26];
        let cap: u16 = 0x000c // SMPS disabled, no optional receive feature.
            | if self.width == HtWidth::TwentyForty { 2 } else { 0 }
            | if self.gi.rx20 { 0x20 } else { 0 }
            | if self.gi.rx40 { 0x40 } else { 0 };
        body[..2].copy_from_slice(&cap.to_le_bytes());
        body[2] = self.factor | self.density << 2;
        body[3..13].copy_from_slice(&self.rx);
        body[15] = 1;
        if self.rx != self.tx {
            let streams = self.tx[..4].iter().rposition(|v| *v != 0).unwrap_or(0);
            body[15] |= 2 | (streams as u8) << 2;
        }
        body
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalVht {
    rx: u16,
    tx: u16,
    rx_sgi: bool,
    tx_sgi: bool,
    factor: u8,
}
impl LocalVht {
    pub fn new(
        rx_map: u16,
        tx_map: u16,
        rx_sgi80: bool,
        tx_sgi80: bool,
        ampdu_exponent: u8,
    ) -> Result<Self, Error> {
        if !map_has_rates(rx_map) || !map_has_rates(tx_map) || ampdu_exponent > 7 {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            rx: rx_map,
            tx: tx_map,
            rx_sgi: rx_sgi80,
            tx_sgi: tx_sgi80,
            factor: ampdu_exponent,
        })
    }
    pub fn capability_body(&self) -> [u8; 12] {
        let mut body = [0; 12];
        let cap = (u32::from(self.factor) << 23) | if self.rx_sgi { 1 << 5 } else { 0 };
        body[..4].copy_from_slice(&cap.to_le_bytes());
        body[4..6].copy_from_slice(&self.rx.to_le_bytes());
        body[8..10].copy_from_slice(&self.tx.to_le_bytes());
        body
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalPhy {
    ht: LocalHt,
    vht: Option<LocalVht>,
}
impl LocalPhy {
    pub fn ht20(local: LocalHt) -> Result<Self, Error> {
        if local.width != HtWidth::Twenty {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            ht: local,
            vht: None,
        })
    }
    pub fn ht40(local: LocalHt) -> Result<Self, Error> {
        if local.width != HtWidth::TwentyForty {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            ht: local,
            vht: None,
        })
    }
    pub fn vht80(ht: LocalHt, vht: LocalVht) -> Result<Self, Error> {
        if ht.width != HtWidth::TwentyForty {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self { ht, vht: Some(vht) })
    }
}

/// Fixed-size copies of the complete original element stream's PHY bodies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApElements {
    ht_cap: Option<[u8; 26]>,
    ht_op: Option<[u8; 22]>,
    vht_cap: Option<[u8; 12]>,
    vht_op: Option<[u8; 5]>,
}
impl ApElements {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 2048 {
            return Err(Error::InvalidBss);
        }
        let mut value = Self::default();
        let mut rates = [false; 2];
        ies(bytes, |id, body| {
            match id {
                45 => singleton(&mut value.ht_cap, body)?,
                61 => singleton(&mut value.ht_op, body)?,
                191 => singleton(&mut value.vht_cap, body)?,
                192 => singleton(&mut value.vht_op, body)?,
                1 | 50 => {
                    let index = usize::from(id == 50);
                    if rates[index] || body.is_empty() || id == 1 && body.len() > 8 {
                        return Err(Error::InvalidBss);
                    }
                    rates[index] = true;
                }
                _ => {}
            }
            Ok(())
        })?;
        if value.ht_cap.is_some() != value.ht_op.is_some()
            || value.vht_cap.is_some() != value.vht_op.is_some()
            || value.vht_cap.is_some() && value.ht_cap.is_none()
        {
            return Err(Error::InvalidBss);
        }
        if let Some(cap) = value.ht_cap {
            if le16(&cap[..2]) & 0x2000 != 0
                || le16(&cap[..2]) & 0x000c == 0x0008
                || cap[2] & 0xe0 != 0
                || cap[12] & 0xe0 != 0
                || le16(&cap[13..15]) & !0x03ff != 0
                || cap[15] & 0xe0 != 0
                || cap[16..19].iter().any(|v| *v != 0)
            {
                return Err(Error::InvalidBss);
            }
        }
        if let Some(op) = value.ht_op {
            if op[1] & 3 == 2 || op[15] & 0xe0 != 0 || op[16..].iter().any(|v| *v != 0) {
                return Err(Error::InvalidBss);
            }
        }
        if let Some(cap) = value.vht_cap {
            let info = le32(&cap[..4]);
            if info & 3 == 3 || info & 12 == 12 || le16(&cap[10..12]) & 0xc000 != 0 {
                return Err(Error::InvalidBss);
            }
        }
        Ok(value)
    }
    pub fn ht_capability(&self) -> Option<[u8; 26]> {
        self.ht_cap
    }
    pub fn ht_operation(&self) -> Option<[u8; 22]> {
        self.ht_op
    }
    pub fn vht_capability(&self) -> Option<[u8; 12]> {
        self.vht_cap
    }
    pub fn vht_operation(&self) -> Option<[u8; 5]> {
        self.vht_op
    }
}
fn singleton<const N: usize>(slot: &mut Option<[u8; N]>, body: &[u8]) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::InvalidBss);
    }
    *slot = Some(body.try_into().map_err(|_| Error::InvalidBss)?);
    Ok(())
}
fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}
fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtOperation {
    body: [u8; 22],
    secondary: Option<u8>,
}
impl HtOperation {
    pub fn primary(&self) -> u8 {
        self.body[0]
    }
    pub fn secondary(&self) -> Option<u8> {
        self.secondary
    }
    pub fn protection(&self) -> u8 {
        self.body[2] & 3
    }
    pub fn body(&self) -> [u8; 22] {
        self.body
    }
    fn parse(body: [u8; 22], primary: u8) -> Result<Self, Error> {
        if body[0] != primary || channel::band(primary).is_none() {
            return Err(Error::InvalidBss);
        }
        let secondary = match body[1] & 3 {
            0 => None,
            1 => Some(primary.checked_add(4).ok_or(Error::InvalidBss)?),
            3 => Some(primary.checked_sub(4).ok_or(Error::InvalidBss)?),
            _ => return Err(Error::InvalidBss),
        };
        if let Some(second) = secondary {
            let center = (u16::from(primary) + u16::from(second)) / 2;
            let valid = match channel::band(primary) {
                Some(channel::Band::Ghz2) => channel::band(second) == Some(channel::Band::Ghz2),
                Some(channel::Band::Ghz5) => [
                    38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175,
                ]
                .contains(&center),
                None => false,
            };
            if !valid || body[1] & 4 == 0 {
                return Err(Error::InvalidBss);
            }
        } else if body[1] & 4 != 0 {
            return Err(Error::InvalidBss);
        }
        Ok(Self { body, secondary })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtNegotiation {
    local: LocalHt,
    tx: [u8; 10],
    peer: [u8; 26],
    operation: HtOperation,
    basic: [u8; 10],
}
impl HtNegotiation {
    pub fn tx_mcs(&self) -> [u8; 10] {
        self.tx
    }
    pub fn rx_mcs(&self) -> [u8; 10] {
        self.local.rx
    }
    pub fn peer_rx_mcs(&self) -> [u8; 10] {
        self.peer[3..13].try_into().unwrap()
    }
    pub fn tx_sgi20(&self) -> bool {
        self.local.gi.tx20 && self.peer_capability() & 0x20 != 0
    }
    pub fn rx_sgi20(&self) -> bool {
        self.local.gi.rx20
    }
    pub fn tx_sgi40(&self) -> bool {
        self.local.gi.tx40 && self.peer_capability() & 0x40 != 0
    }
    pub fn rx_sgi40(&self) -> bool {
        self.local.gi.rx40
    }
    pub fn peer_capability(&self) -> u16 {
        le16(&self.peer[..2])
    }
    pub fn peer_capability_body(&self) -> [u8; 26] {
        self.peer
    }
    pub fn peer_ampdu_factor(&self) -> u8 {
        self.peer[2] & 3
    }
    pub fn peer_mpdu_density(&self) -> u8 {
        self.peer[2] >> 2 & 7
    }
    pub fn peer_tx_params(&self) -> u8 {
        self.peer[15]
    }
    pub fn operation(&self) -> &HtOperation {
        &self.operation
    }
    pub fn local_capability(&self) -> [u8; 26] {
        self.local.capability_body()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VhtNegotiation {
    local: LocalVht,
    tx: u16,
    peer: [u8; 12],
    operation: [u8; 5],
    basic: u16,
}
impl VhtNegotiation {
    pub fn rx_mcs_map(&self) -> u16 {
        self.local.rx
    }
    pub fn tx_mcs_map(&self) -> u16 {
        self.tx
    }
    pub fn peer_rx_mcs_map(&self) -> u16 {
        le16(&self.peer[4..6])
    }
    pub fn peer_tx_mcs_map(&self) -> u16 {
        le16(&self.peer[8..10])
    }
    pub fn peer_capability(&self) -> u32 {
        le32(&self.peer[..4])
    }
    pub fn peer_capability_body(&self) -> [u8; 12] {
        self.peer
    }
    pub fn rx_sgi80(&self) -> bool {
        self.local.rx_sgi
    }
    pub fn tx_sgi80(&self) -> bool {
        self.local.tx_sgi && self.peer_capability() & 0x20 != 0
    }
    pub fn operation_body(&self) -> [u8; 5] {
        self.operation
    }
    pub fn local_capability(&self) -> [u8; 12] {
        self.local.capability_body()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Selection {
    local: LocalPhy,
    ht: HtNegotiation,
    vht: Option<VhtNegotiation>,
    width: Width,
    center: u8,
    channels: [u8; 4],
    count: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer(Selection);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated(Selection);
macro_rules! selection_accessors {
    () => {
        pub fn ht(&self) -> &HtNegotiation {
            &self.0.ht
        }
        pub fn vht(&self) -> Option<&VhtNegotiation> {
            self.0.vht.as_ref()
        }
        pub fn width(&self) -> Width {
            self.0.width
        }
        pub fn center_channel(&self) -> u8 {
            self.0.center
        }
        pub fn occupied_channels(&self) -> &[u8] {
            &self.0.channels[..self.0.count]
        }
    };
}
impl Offer {
    selection_accessors!();
    pub(super) fn prepare(
        local: LocalPhy,
        bytes: &[u8],
        primary: u8,
        selectors: u8,
    ) -> Result<Option<Self>, Error> {
        let ap = ApElements::parse(bytes)?;
        if ap.ht_cap.is_none() {
            if selectors != 0 {
                return Err(Error::UnsupportedRates);
            }
            return Ok(None);
        }
        let selected = select(local, ap, primary)?;
        check_selectors(selectors, selected.vht.is_some())?;
        Ok(Some(Self(selected)))
    }
    pub(super) fn response(&self, bytes: &[u8], selectors: u8) -> Result<Negotiated, Error> {
        let mut next = select(
            self.0.local,
            ApElements::parse(bytes)?,
            self.0.ht.operation.primary(),
        )?;
        check_selectors(selectors, next.vht.is_some())?;
        if self.0.vht.is_some() && next.vht.is_none()
            || next.channels[..next.count]
                .iter()
                .any(|ch| !self.occupied_channels().contains(ch))
        {
            return Err(Error::UnsupportedRates);
        }
        for i in 0..10 {
            next.ht.tx[i] &= self.0.ht.tx[i];
            next.ht.basic[i] |= self.0.ht.basic[i];
        }
        if next.ht.tx.iter().all(|v| *v == 0) {
            return Err(Error::UnsupportedRates);
        }
        // A response cannot restore a transmit GI omitted by the scan offer.
        next.ht.local.gi.tx20 &= self.0.ht.tx_sgi20();
        next.ht.local.gi.tx40 &= self.0.ht.tx_sgi40();
        if let (Some(old), Some(new)) = (self.0.vht, next.vht.as_mut()) {
            new.tx = intersect_maps(new.tx, old.tx);
            new.local.tx_sgi &= old.tx_sgi80();
            if !map_has_rates(new.tx)
                || !supports_map(new.tx, old.basic)
                || !supports_map(new.local.rx, old.basic)
            {
                return Err(Error::UnsupportedRates);
            }
        }
        Ok(Negotiated(next))
    }
    pub(super) fn append_capabilities(&self, bytes: &mut alloc::vec::Vec<u8>) {
        bytes.extend_from_slice(&[45, 26]);
        bytes.extend_from_slice(&self.0.local.ht.capability_body());
        if self.0.vht.is_some() {
            bytes.extend_from_slice(&[191, 12]);
            bytes.extend_from_slice(&self.0.local.vht.unwrap().capability_body());
        }
    }
}
impl Negotiated {
    selection_accessors!();
}

pub(super) fn check_selectors(selectors: u8, vht: bool) -> Result<(), Error> {
    if selectors & 2 != 0 && !vht {
        return Err(Error::UnsupportedRates);
    }
    Ok(())
}
fn select(local: LocalPhy, ap: ApElements, primary: u8) -> Result<Selection, Error> {
    let cap = ap.ht_cap.ok_or(Error::UnsupportedRates)?;
    let op = HtOperation::parse(ap.ht_op.ok_or(Error::UnsupportedRates)?, primary)?;
    if op.secondary.is_some() && le16(&cap[..2]) & 2 == 0 {
        return Err(Error::InvalidBss);
    }
    let mut tx = [0; 10];
    let mut basic = [0; 10];
    for i in 0..10 {
        tx[i] = local.ht.tx_selection[i] & cap[3 + i];
        basic[i] = op.body[6 + i];
        if basic[i] & !local.ht.rx[i] != 0 {
            return Err(Error::UnsupportedRates);
        }
    }
    if tx.iter().all(|v| *v == 0) {
        return Err(Error::UnsupportedRates);
    }
    let mut selected = Selection {
        local,
        ht: HtNegotiation {
            local: local.ht,
            tx,
            peer: cap,
            operation: op,
            basic,
        },
        vht: None,
        width: Width::Twenty,
        center: primary,
        channels: [primary, 0, 0, 0],
        count: 1,
    };
    if local.ht.width == HtWidth::TwentyForty && le16(&cap[..2]) & 2 != 0 {
        if let Some(second) = op.secondary {
            selected.width = Width::Forty;
            selected.center = ((u16::from(primary) + u16::from(second)) / 2) as u8;
            selected.channels = [primary.min(second), primary.max(second), 0, 0];
            selected.count = 2;
        }
    }
    if let (Some(local_vht), Some(peer), Some(operation)) = (local.vht, ap.vht_cap, ap.vht_op) {
        if channel::band(primary) != Some(channel::Band::Ghz5) {
            return Err(Error::UnsupportedRates);
        }
        let peer_info = le32(&peer[..4]);
        // Extended NSS/BW requires a separate implementation of its tables.
        if peer_info >> 30 != 0 || le16(&peer[10..12]) & (1 << 13) != 0 {
            return Err(Error::UnsupportedRates);
        }
        let tx = intersect_maps(local_vht.tx, le16(&peer[4..6]));
        let basic = le16(&operation[3..5]);
        if !map_has_rates(tx) || !supports_map(tx, basic) || !supports_map(local_vht.rx, basic) {
            return Err(Error::UnsupportedRates);
        }
        if operation[2] != 0 {
            return Err(Error::UnsupportedRates);
        }
        match operation[0] {
            0 => {
                if operation[1] != 0 && operation[1] != selected.center {
                    return Err(Error::InvalidBss);
                }
            }
            1 => {
                let center = operation[1];
                if ![42, 58, 106, 122, 138, 155, 171].contains(&center)
                    || selected.width != Width::Forty
                {
                    return Err(Error::UnsupportedRates);
                }
                let channels = [center - 6, center - 2, center + 2, center + 6];
                let index = channels
                    .iter()
                    .position(|ch| *ch == primary)
                    .ok_or(Error::InvalidBss)?;
                if op.secondary != Some(channels[index ^ 1]) {
                    return Err(Error::InvalidBss);
                }
                selected.width = Width::Eighty;
                selected.center = center;
                selected.channels = channels;
                selected.count = 4;
            }
            _ => return Err(Error::UnsupportedRates),
        }
        selected.vht = Some(VhtNegotiation {
            local: local_vht,
            tx,
            peer,
            operation,
            basic,
        });
    }
    Ok(selected)
}
fn map_has_rates(map: u16) -> bool {
    map & 3 != 3
}
/// Per-NSS intersection. Encoding3 is absence, not a higher MCS ceiling.
pub fn intersect_maps(left: u16, right: u16) -> u16 {
    let mut result = 0;
    for n in 0..8 {
        let (a, b) = (left >> (n * 2) & 3, right >> (n * 2) & 3);
        result |= (if a == 3 || b == 3 { 3 } else { a.min(b) }) << (n * 2);
    }
    result
}
fn supports_map(local: u16, required: u16) -> bool {
    (0..8).all(|n| {
        let (have, need) = (local >> (n * 2) & 3, required >> (n * 2) & 3);
        need == 3 || have != 3 && have >= need
    })
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy_tests.rs"]
mod tests;
