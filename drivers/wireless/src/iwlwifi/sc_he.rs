// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Native MLD HE20/40/80 STA/LINK/TLC facts.
//! Source: Linux mld/{sta,link,tlc}.c and fw/api/{mac,mac-cfg,rs}.h.
//! These codecs establish neither NVM/MCC HE permission nor radio authority.
use super::boot_context::{put16, put32};
use narf_wireless::association::he::{HeCapability, HeNegotiation, HeOperation, LocalHe};

pub(super) fn native_supported(hw: &super::runtime::Hardware) -> bool {
    [(3, 8, 3), (3, 9, 8), (3, 10, 2), (1, 8, 6), (5, 0xf, 6)]
        .into_iter()
        .all(|(group, command, version)| hw.version(group, command).map(|v| v.0) == Some(version))
        && rates_version(hw).is_some()
}

/// Linux mvm/ops.c checks every producer and consumer of rate_n_flags,
/// rejecting partially upgraded firmware tables. Missing entries are v1,
/// never evidence for a newer encoding. MLD's native TX body is v10/v11.
pub(super) fn rates_version(hw: &super::runtime::Hardware) -> Option<u8> {
    if !matches!(hw.command_version(0, 0x1c), Some(10 | 11)) {
        return None;
    }
    select_rates_version(|group, command| hw.version(group, command))
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
    native: super::ht_vht::Negotiated,
) -> bool {
    use narf_wireless::association::phy::Width;
    native.mode != 0
        && offer.he().is_some()
        && offer.center_channel() == native.center
        && match offer.width() {
            Width::Twenty => native.width == 0,
            Width::Forty => native.width == 1,
            Width::Eighty => native.width == 2,
            Width::OneSixty => false,
        }
}

/// Bounded source-profile HE capability, only for callers that separately
/// proved the current NVM HE SKU, MCC bit13 and native firmware contract.
pub(super) fn local(phy: super::ht_vht::Local, primary: u8) -> Result<LocalHe, &'static str> {
    if !phy.ht
        || primary == 14
        || !(1..=2).contains(&phy.rx_streams)
        || !(1..=2).contains(&phy.tx_streams)
        || primary > 14 && !phy.vht
    {
        return Err("MLD local HE PHY prerequisites absent");
    }
    let mut capability = [0; 11];
    capability[0] = if primary <= 14 { 2 } else { 4 };
    capability[1] = 0x30;
    capability[2] = 2 | 8;
    capability[7] = 4;
    capability[8] = 1;
    capability[9] = 0x30;
    let map = |streams| if streams == 2 { 0xfff0 } else { 0xfffc };
    LocalHe::new(
        [1, 0, 0x20, 0, 0, 0],
        capability,
        map(phy.rx_streams),
        map(phy.tx_streams),
    )
    .map_err(|_| "MLD local HE source profile invalid")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Profile {
    pub negotiation: HeNegotiation,
    pub tx_map: u16,
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
        Ok(Self {
            negotiation,
            tx_map,
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
        let highest = match (self.negotiation.rx_mcs_map() >> (2 * nss)) & 3 {
            0 => 7,
            1 => 9,
            2 => 11,
            _ => return false,
        };
        let maximum_width = match self.negotiation.width() {
            Width::Twenty => 0,
            Width::Forty => 1,
            Width::Eighty => 2,
            Width::OneSixty => return false,
        };
        let width = (rate >> 11) & 7;
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
        put32(bytes, 40, u32::from(self.tx_map & 12 != 12));
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
    /// HE20/40/80; unsupported160/320 slots remain zero and no HT/VHT SGI
    /// fallback is advertised (iwl_mld_get_fw_sgi).
    pub fn apply_tlc(&self, bytes: &mut [u8; 44]) -> Result<(), &'static str> {
        use narf_wireless::association::phy::Width;
        bytes[8] = match self.negotiation.width() {
            Width::Twenty => 0,
            Width::Forty => 1,
            Width::Eighty => 2,
            Width::OneSixty => return Err("MLD HE160 has no native owner yet"),
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
            let bits = match (self.tx_map >> (stream * 2)) & 3 {
                0 => 0xff,
                1 => 0x3ff,
                2 => 0xfff,
                _ => 0,
            };
            put32(bytes, 16 + stream * 12, bits);
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
    fn smoke_sc_he_rate_encoding_requires_every_native_producer_and_consumer() -> TestResult {
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
