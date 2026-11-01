// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Native MLD HE20/40/80/160 STA/LINK/TLC facts.
//! Source: Linux mld/{sta,link,tlc}.c and fw/api/{mac,mac-cfg,rs}.h.
//! These codecs establish neither NVM/MCC HE permission nor radio authority.
use super::boot_context::{put16, put32};
use narf_wireless::association::he::{HeCapability, HeNegotiation, HeOperation, LocalHe};

pub(super) fn native_supported(hw: &super::runtime::Hardware) -> bool {
    if hw.is_mvm89() {
        return rates_version(hw) == Some(2);
    }
    [(3, 8, 3), (3, 9, 8), (3, 10, 2), (1, 8, 6), (5, 0xf, 6)]
        .into_iter()
        .all(|(group, command, version)| hw.version(group, command).map(|v| v.0) == Some(version))
        && rates_version(hw).is_some()
}

/// Select the retained native consumer namespace before checking used wire
/// versions. Linux MVM checks all five rate consumers; MLD directly uses
/// v3 and has no RX_NO_DATA handler. Missing used entries prove no upgrade.
pub(super) fn rates_version(hw: &super::runtime::Hardware) -> Option<u8> {
    if !matches!(hw.command_version(0, 0x1c), Some(10 | 11)) {
        return None;
    }
    if hw.uses_mld_station_protocol() {
        select_mld_rates_version(|group, command| hw.version(group, command))
    } else {
        select_rates_version(|group, command| hw.version(group, command))
    }
}

/// Linux MLD has no RX_NO_DATA consumer: mld/rx.c reads the v3 NSS/code
/// fields directly. Its actual core103 tables omit5/f5. Admit only the
/// complete reached MLD station/TX/RX/TLC tuple; the MVM selector below
/// retains its separate five-consumer consistency contract.
fn select_mld_rates_version(version: impl Fn(u8, u8) -> Option<(u8, u8)>) -> Option<u8> {
    let commands = [(3, 8, 3), (3, 9, 8), (3, 10, 2), (1, 8, 6), (5, 0xf, 6)];
    (commands
        .into_iter()
        .all(|(g, c, v)| version(g, c).map(|v| v.0) == Some(v))
        && version(1, 0x1c) == Some((11, 9))
        && version(5, 0xf7).is_some_and(|v| v.1 == 4)
        && version(0, 0xc1).is_some_and(|v| matches!(v.1, 6..=8)))
    .then_some(3)
}
fn select_rates_version(version: impl Fn(u8, u8) -> Option<(u8, u8)>) -> Option<u8> {
    let command = |group, cmd| version(if group == 0 { 1 } else { group }, cmd).map_or(0, |v| v.0);
    let notification = |group, cmd| version(group, cmd).map_or(0, |v| v.1);
    let v2 = [
        command(0, 0x1c) >= 8,
        notification(5, 0xf7) >= 3,
        notification(0, 0xc1) >= 4,
        notification(1, 0x1c) >= 6,
    ];
    let v3 = [
        command(0, 0x1c) >= 11,
        notification(5, 0xf7) >= 4,
        notification(0, 0xc1) >= 6,
        notification(5, 0xf5) >= 4,
        notification(1, 0x1c) >= 9,
    ];
    if !v2.into_iter().all(|v| v) || v3.into_iter().any(|v| v) && !v3.into_iter().all(|v| v) {
        None
    } else {
        Some(if v3.into_iter().all(|v| v) { 3 } else { 2 })
    }
}

/// The existing native PHY/MCC owner must select the same span as the
/// shared HE offer. A narrower legacy span may use the legacy association
/// without advertising HE; a mandatory HE selector then fails admission.
pub(super) fn matches_native(
    offer: &narf_wireless::association::phy::Offer,
    native: &super::ht_vht::Negotiated,
) -> bool {
    use narf_wireless::association::phy::Width;
    native.mode != 0
        && !offer.discontiguous()
        && offer.he().is_some()
        && offer.center_channel() == native.center
        && match offer.width() {
            Width::Twenty => native.width == 0,
            Width::Forty => native.width == 1,
            Width::Eighty => native.width == 2,
            Width::OneSixty => native.width == 3,
        }
}

/// Bounded source-profile HE capability, only for callers that separately
/// proved the current NVM HE SKU, MCC bit13 and native firmware contract.
pub(super) fn local(phy: super::ht_vht::Local, primary: u8) -> Result<LocalHe, &'static str> {
    local_inner(phy, primary, false)
}
pub(super) fn local_six(phy: super::ht_vht::Local) -> Result<LocalHe, &'static str> {
    local_inner(phy, 1, true)
}
fn local_inner(phy: super::ht_vht::Local, primary: u8, six: bool) -> Result<LocalHe, &'static str> {
    if !phy.ht
        || primary == 14
        || !(1..=2).contains(&phy.rx_streams)
        || !(1..=2).contains(&phy.tx_streams)
        || !six && primary > 14 && !phy.vht
    {
        return Err("MLD local HE PHY prerequisites absent");
    }
    let mut capability = [0; 11];
    capability[0] = if six {
        0
    } else if primary <= 14 {
        2
    } else {
        4
    };
    capability[1] = 0x30;
    capability[2] = 2 | 8;
    capability[7] = 4;
    capability[8] = 1;
    capability[9] = 0x30;
    let map = |streams| if streams == 2 { 0xfff0 } else { 0xfffc };
    let local = LocalHe::new(
        [1, 0, 0x20, 0, 0, 0],
        capability,
        map(phy.rx_streams),
        map(phy.tx_streams),
    )
    .map_err(|_| "MLD local HE source profile invalid")?;
    if !six && primary > 14 && phy.supports160() {
        local
            .with_160mhz(map(phy.rx_streams), map(phy.tx_streams))
            .map_err(|_| "MLD local HE160 source profile invalid")
    } else {
        Ok(local)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Profile {
    pub negotiation: HeNegotiation,
    pub tx_map: u16,
    tx80: u16,
    rx80: u16,
    rates_version: u8,
    /// ACI-indexed three-byte source records, not firmware AC order.
    mu_edca: Option<[[u8; 3]; 4]>,
    uora: Option<u8>,
}
impl Profile {
    pub fn new(
        negotiation: HeNegotiation,
        ies: &[u8],
        single_stream: bool,
        rates_version: u8,
    ) -> Result<Self, &'static str> {
        if !matches!(rates_version, 2 | 3) {
            return Err("MLD HE requires a consistent native rate encoding");
        }
        let (mu_edca, uora) = optional_elements(ies)?;
        let tx_map = negotiation.tx_mcs_map() | if single_stream { 0xfffc } else { 0 };
        let local = negotiation.local_capability();
        let local = HeCapability::parse(&local[1..])
            .map_err(|_| "MLD retained local HE capability invalid")?
            .mcs_nss();
        let peer = negotiation.peer_capability().mcs_nss();
        let mut tx80 = 0xffffu16;
        for nss in 0..2 {
            let ours = (local.tx80 >> (nss * 2)) & 3;
            let theirs = (peer.rx80 >> (nss * 2)) & 3;
            let value = if ours == 3 || theirs == 3 || single_stream && nss == 1 {
                3
            } else {
                ours.min(theirs)
            };
            tx80 = (tx80 & !(3 << (nss * 2))) | (value << (nss * 2));
        }
        Ok(Self {
            negotiation,
            tx_map,
            tx80,
            rx80: local.rx80,
            rates_version,
            mu_edca,
            uora,
        })
    }
    pub fn matches(&self, ies: &[u8]) -> bool {
        // Compare only HE facts here: HT/VHT have their own native
        // live-beacon proof, and an already negotiated H2E selector123
        // is a security parsing fact, not a changed HE capability.
        let (mut capability, mut operation) = (None, None);
        let mut rest = ies;
        while !rest.is_empty() {
            if rest.len() < 2 || rest.len() < 2 + usize::from(rest[1]) {
                return false;
            }
            let body = &rest[2..2 + usize::from(rest[1])];
            if rest[0] == 255 {
                match body.first() {
                    Some(35) => {
                        if capability.is_some() {
                            return false;
                        }
                        let Ok(parsed) = HeCapability::parse(&body[1..]) else {
                            return false;
                        };
                        capability = Some(parsed);
                    }
                    Some(36) => {
                        if operation.is_some() {
                            return false;
                        }
                        let Ok(parsed) = HeOperation::parse(&body[1..]) else {
                            return false;
                        };
                        operation = Some(parsed);
                    }
                    _ => {}
                }
            }
            rest = &rest[2 + usize::from(rest[1])..];
        }
        capability.as_ref() == Some(self.negotiation.peer_capability())
            && operation.as_ref() == Some(self.negotiation.operation())
            && optional_elements(ies) == Ok((self.mu_edca, self.uora))
    }
    /// Original v3 RX descriptor rate word, before reorder/PN mutation.
    /// NSS moved from bit4 to bit5 in rates-v3; the actual firmware table
    /// chooses that interpretation. Local RX promises bound every HE MPDU.
    pub fn admits_rx_rate(&self, rate: u32) -> bool {
        use narf_wireless::association::phy::Width;
        let format = (rate >> 8) & 7;
        if format < 4 {
            return true;
        }
        if format != 4 {
            return false;
        }
        let (nss, mcs, reserved) = if self.rates_version == 3 {
            ((rate >> 5) & 1, rate & 31, 0xc0)
        } else {
            ((rate >> 4) & 1, rate & 15, 0xe0)
        };
        let width = (rate >> 11) & 7;
        let rx_map = if width <= 2 {
            self.rx80
        } else {
            self.negotiation.rx_mcs_map()
        };
        let highest = match (rx_map >> (2 * nss)) & 3 {
            0 => 7,
            1 => 9,
            2 => 11,
            _ => return false,
        };
        let maximum_width = match self.negotiation.width() {
            Width::Twenty => 0,
            Width::Forty => 1,
            Width::Eighty => 2,
            Width::OneSixty => 3,
        };
        let coding = u32::from(self.negotiation.rx_ldpc()) << 16
            | u32::from(self.negotiation.rx_stbc()) << 17;
        let kind = (rate >> 23) & 3;
        let gi = (rate >> 20) & 7;
        mcs <= highest
            && width <= maximum_width
            && kind <= 2
            && (kind != 1 || gi != 0)
            && gi <= if kind == 2 { 3 } else { 4 }
            && rate & (reserved | ((15 << 16) & !coding) | (1 << 25) | (1 << 26)) == 0
    }
    fn backoff(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        if let Some(records) = self.mu_edca {
            for (index, aci) in [1, 0, 2, 3].into_iter().enumerate() {
                let record = records[aci];
                let at = index * 8;
                put16(&mut bytes, at, u16::from(record[1] & 15));
                put16(&mut bytes, at + 2, u16::from(record[1] >> 4));
                put16(&mut bytes, at + 4, u16::from(record[0] & 15));
                put16(&mut bytes, at + 6, u16::from(record[2]));
            }
        }
        bytes
    }
    /// MAC_CONFIG v3's byte-sized wifi_gen fields. Local HE MAC2 does
    /// not promise ACK-enabled aggregation, so firmware must use the
    /// non-ACK-enabled delimiter interpretation (mld/iface.c).
    pub fn apply_mac(&self, bytes: &mut [u8; 52]) {
        bytes[24] = 1;
        bytes[25..32].fill(0);
        put32(bytes, 32, 1);
    }
    /// Native MLD STA_CONFIG v2, 104 bytes. It carries the v2 2x5x2
    /// packet-extension matrix directly, rather than a companion context.
    pub fn apply_sta(&self, bytes: &mut [u8; 104]) {
        let mac = self.negotiation.peer_capability().mac_capability();
        put32(
            bytes,
            40,
            u32::from(self.tx_map & 12 != 12 || self.tx80 & 12 != 12),
        );
        put32(bytes, 48, u32::from(mac[2] & 0x80 != 0));
        put32(bytes, 52, u32::from(self.uora.is_some()));
        let factor = u32::from_le_bytes(bytes[60..64].try_into().unwrap());
        put32(bytes, 60, (factor + u32::from((mac[3] >> 3) & 3)).min(9));
        for (stream, widths) in packet_extension(self.negotiation.peer_capability())
            .iter()
            .enumerate()
        {
            for (width, threshold) in widths.iter().enumerate() {
                let at = 72 + (stream * 5 + width) * 2;
                bytes[at..at + 2].copy_from_slice(threshold);
            }
        }
        let link_adapt = u8::from(mac[1] & 0x80 != 0) | ((mac[2] & 1) << 1);
        let htc = u32::from(mac[0] & 1)
            | if link_adapt >= 2 {
                u32::from(link_adapt) << 1
            } else {
                0
            }
            | (u32::from(mac[2] & 8 != 0) << 4)
            | (u32::from(mac[3] & 2 != 0) << 5)
            | (u32::from(mac[4] & 4 != 0) << 6);
        put32(bytes, 92, htc);
    }
    /// TLC v6 with three width slots per NSS. The admitted profile is
    /// HE20/40/80/160; the unsupported320 slot remains zero and no HT/VHT SGI
    /// fallback is advertised (iwl_mld_get_fw_sgi).
    pub fn apply_tlc(&self, bytes: &mut [u8; 44]) -> Result<(), &'static str> {
        use narf_wireless::association::phy::Width;
        if self.negotiation.discontiguous() {
            return Err("native HE80+80 has no retained two-segment owner");
        }
        bytes[8] = match self.negotiation.width() {
            Width::Twenty => 0,
            Width::Forty => 1,
            Width::Eighty => 2,
            Width::OneSixty => 3,
        };
        bytes[9] = 3;
        bytes[11] = 0;
        put16(
            bytes,
            12,
            u16::from(self.negotiation.tx_stbc()) | u16::from(self.negotiation.tx_ldpc()) << 1,
        );
        bytes[16..40].fill(0);
        for stream in 0..2 {
            let bits = |map: u16| match (map >> (stream * 2)) & 3 {
                0 => 0xff,
                1 => 0x3ff,
                2 => 0xfff,
                _ => 0,
            };
            put32(bytes, 16 + stream * 12, bits(self.tx80));
            if bytes[8] == 3 {
                put32(bytes, 20 + stream * 12, bits(self.tx_map));
            }
        }
        Ok(())
    }
    /// Native LINK_CONFIG v8, already associated link0. The removed
    /// flags_mask field stays zero (the Gen2 v1 owner uses it differently).
    pub fn apply_link(&self, bytes: &mut [u8; 208]) {
        let mask = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) | (1 << 5) | (1 << 6);
        put32(bytes, 24, mask);
        let op = self.negotiation.operation();
        bytes[100] = op.default_pe_duration();
        if let Some(range) = self.uora {
            bytes[101] = range & 7;
            bytes[102] = (range >> 3) & 7;
        }
        bytes[104..136].copy_from_slice(&self.backoff());
        put16(bytes, 146, op.txop_rts_threshold());
        let flags = u32::from(op.bss_color_disabled()) | (u32::from(self.mu_edca.is_some()) << 1);
        put32(bytes, 148, flags);
        put32(bytes, 152, 0);
        bytes[165] = op.bss_color();
        bytes[167] = u8::from(self.negotiation.peer_capability().mac_capability()[5] & 0x80 != 0);
    }
}

type MuEdca = Option<[[u8; 3]; 4]>;
fn optional_elements(mut ies: &[u8]) -> Result<(MuEdca, Option<u8>), &'static str> {
    let mut mu = None;
    let mut uora = None;
    while !ies.is_empty() {
        if ies.len() < 2 || ies.len() < 2 + usize::from(ies[1]) {
            return Err("truncated MLD HE information element");
        }
        let body = &ies[2..2 + usize::from(ies[1])];
        if ies[0] == 255 {
            match body.first() {
                Some(37) => {
                    if body.len() != 2
                        || uora.is_some()
                        || body[1] & 0xc0 != 0
                        || body[1] & 7 > (body[1] >> 3) & 7
                    {
                        return Err("invalid MLD UORA parameters");
                    }
                    uora = Some(body[1]);
                }
                Some(38) => {
                    if body.len() != 14 || mu.is_some() {
                        return Err("invalid MLD MU EDCA extent");
                    }
                    let mut records = [[0; 3]; 4];
                    let mut seen = 0;
                    for record in body[2..].chunks_exact(3) {
                        let aci = usize::from((record[0] >> 5) & 3);
                        if seen & (1 << aci) != 0
                            || record[0] & 0x90 != 0
                            || record[1] & 15 > record[1] >> 4
                        {
                            return Err("invalid MLD MU EDCA AC record");
                        }
                        seen |= 1 << aci;
                        records[aci].copy_from_slice(record);
                    }
                    mu = Some(records);
                }
                _ => {}
            }
        }
        ies = &ies[2 + usize::from(ies[1])..];
    }
    Ok((mu, uora))
}

/// Linux iwl_mvm_parse_ppe: [NSS][RU bandwidth][PPET8, PPET16]. HE
/// does not inherit a missing RU's thresholds from an earlier bandwidth.
fn packet_extension(peer: &narf_wireless::association::he::HeCapability) -> [[[u8; 2]; 5]; 2] {
    let mut result = [[[7; 2]; 5]; 2];
    let ppe = peer.ppe_thresholds();
    if let Some(header) = ppe.first() {
        let streams = usize::from((header & 7) + 1).min(2);
        let mut bit = 7;
        let field = |at: usize| -> u8 {
            (0..3).fold(0, |value, n| {
                value | ((ppe[(at + n) / 8] >> ((at + n) % 8)) & 1) << n
            })
        };
        for stream in result.iter_mut().take(streams) {
            for (width, threshold) in stream.iter_mut().enumerate().take(4) {
                if header & (1 << (3 + width)) != 0 {
                    *threshold = [field(bit + 3), field(bit)];
                    bit += 6;
                }
            }
        }
    } else {
        let pair = match peer.phy_capability()[9] >> 6 {
            1 => [0, 7],
            2 => [7, 0],
            _ => [7, 7],
        };
        result = [[pair; 5]; 2];
    }
    result
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    #[inline(never)]
    fn hardware_mld_namespace() -> Result<(), &'static str> {
        use super::super::{runtime::model, rx_rfh};
        let case = super::super::bz_fixture::Case::FmDiscrete;
        let image = case.image();
        let parsed = super::super::parse_ucode(&image)
            .map_err(|_| "MLD hardware namespace fixture metadata")?;
        let (mut hw, _firmware, _trace) =
            model::station_model_for_format(rx_rfh::CompletionFormat::Bz);
        let result = (|| {
            model::native_station_identity(&mut hw, case.did(), case.revision(), case.radio())?;
            model::firmware_profile(&mut hw, &parsed)?;
            hw.prepare_station_profile(&parsed)?;
            if !hw.uses_mld_station_protocol() || rates_version(&hw) != Some(3) {
                return Err("exact Bz hardware lost its admitted MLD consumer");
            }
            for (g, c, field) in [
                (3, 8, 2),
                (3, 9, 2),
                (3, 10, 2),
                (1, 8, 2),
                (5, 0xf, 2),
                (1, 0x1c, 2),
                (1, 0x1c, 3),
                (5, 0xf7, 3),
                (0, 0xc1, 3),
            ] {
                let mut table = case.commands();
                let row = table
                    .chunks_exact_mut(4)
                    .find(|row| row[0] == c && row[1] == g)
                    .ok_or("actual MLD hardware used row absent")?;
                row[field] = 0;
                model::versions(&mut hw, &table);
                if rates_version(&hw).is_some() {
                    return Err("MLD hardware admitted a malformed used native rate tuple");
                }
            }
            // This is complete for MVMv2. A retained MLD consumer must not
            // switch namespace just because that other tuple is consistent.
            model::versions(&mut hw, &[0x1c, 1, 10, 8, 0xf7, 5, 0, 3, 0xc1, 0, 0, 5]);
            if !hw.uses_mld_station_protocol() || rates_version(&hw).is_some() {
                return Err("MLD hardware fell through to a valid MVMv2 namespace");
            }
            Ok(())
        })();
        // SAFETY: this fixture owns all RAM DMA and no future or physical
        // endpoint survives; destroy Hardware before its device-side views.
        unsafe { model::destroy(hw) };
        result
    }
    fn smoke_sc_he_rate_encoding_requires_every_native_producer_and_consumer() -> TestResult {
        if let Err(reason) = hardware_mld_namespace() {
            return TestResult::Fail(reason);
        }
        let lookup = |table: &[[u8; 4]], g, c| {
            table
                .iter()
                .find(|r| r[0] == c && r[1] == g)
                .map(|r| (r[2], r[3]))
        };
        let v2 = [[0x1c, 1, 10, 8], [0xf7, 5, 0, 3], [0xc1, 0, 0, 5]];
        let v3 = [
            [0x1c, 1, 11, 9],
            [0xf7, 5, 0, 4],
            [0xc1, 0, 0, 6],
            [0xf5, 5, 0, 4],
        ];
        if select_rates_version(|g, c| lookup(&v2, g, c)) != Some(2)
            || select_rates_version(|g, c| lookup(&v3, g, c)) != Some(3)
        {
            return TestResult::Fail("Sc HE complete rate inventories lost their source encoding");
        }
        // Exact reached MLD tuple, deliberately without unconsumed5/f5.
        let mld = [
            [8, 3, 3, 0],
            [9, 3, 8, 0],
            [10, 3, 2, 0],
            [8, 1, 6, 0],
            [15, 5, 6, 0],
            [0x1c, 1, 11, 9],
            [0xf7, 5, 99, 4],
            [0xc1, 0, 99, 8],
        ];
        if select_mld_rates_version(|g, c| lookup(&mld, g, c)) != Some(3) {
            return TestResult::Fail(
                "MLD actual rate-v3 tuple required an unconsumed notification",
            );
        }
        for (row, field) in [
            (0, 2),
            (1, 2),
            (2, 2),
            (3, 2),
            (4, 2),
            (5, 2),
            (5, 3),
            (6, 3),
            (7, 3),
        ] {
            let mut table = mld;
            table[row][field] = 0;
            if select_mld_rates_version(|g, c| lookup(&table, g, c)).is_some() {
                return TestResult::Fail("MLD partial used native rate tuple admitted");
            }
        }
        for index in 0..4 {
            let mut table = v2;
            let (row, field) = [(0, 2), (1, 3), (2, 3), (0, 3)][index];
            table[row][field] = 0;
            if select_rates_version(|g, c| lookup(&table, g, c)).is_some() {
                return TestResult::Fail("Sc HE partial rates-v2 inventory admitted");
            }
        }
        for index in 0..5 {
            let mut table = v3;
            let (row, field, value) =
                [(0, 2, 10), (1, 3, 3), (2, 3, 5), (0, 3, 8), (3, 3, 0)][index];
            table[row][field] = value;
            if select_rates_version(|g, c| lookup(&table, g, c)).is_some() {
                return TestResult::Fail("Sc HE partial rates-v3 inventory admitted");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/sc/he",
        smoke_sc_he_rate_encoding_requires_every_native_producer_and_consumer
    );
}
