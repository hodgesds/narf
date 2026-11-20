// SPDX-License-Identifier: GPL-2.0-or-later
//! NEHT v4 full20/40 program qualification; no measured board data is supplied.
use super::*;
const HEADER: usize = 192;
const LENGTH: usize = HEADER + 10 * 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtlwifi) struct Geometry {
    primary: u8,
    secondary: u8,
}
impl Geometry {
    pub(in crate::rtlwifi) fn new(primary: u8, secondary: u8) -> Result<Self, Error> {
        if !(1..=11).contains(&primary)
            || !(1..=11).contains(&secondary)
            || primary.abs_diff(secondary) != 4
        {
            return Err(Error::State);
        }
        Ok(Self { primary, secondary })
    }
    /// A 5 GHz HT40 pair on the RTL8821AE plan (`envelope::Operating`
    /// fixed pairing: 36/40 .. 140/144, 149/153, 157/161), for the 8821AE
    /// owner only; the 88EE NEHT programs keep [`Self::new`] (2.4 GHz).
    pub(in crate::rtlwifi) fn new_5g(primary: u8, secondary: u8) -> Result<Self, Error> {
        use crate::rtlwifi::rtl8821ae::envelope::{Band, Operating, Width};
        let width = if secondary == primary.wrapping_add(4) {
            Width::W40Above
        } else if secondary.wrapping_add(4) == primary {
            Width::W40Below
        } else {
            return Err(Error::State);
        };
        Operating {
            band: Band::B5g,
            width,
            channel: primary,
        }
        .center_mhz()
        .ok_or(Error::State)?;
        Ok(Self { primary, secondary })
    }
    pub(in crate::rtlwifi) fn primary(self) -> u8 {
        self.primary
    }
    pub(in crate::rtlwifi) fn secondary(self) -> u8 {
        self.secondary
    }
    pub(in crate::rtlwifi) fn center(self) -> u8 {
        // Widened: 5 GHz pairs above 127 (e.g. 157/161) overflow a u8 sum.
        ((u16::from(self.primary) + u16::from(self.secondary)) / 2) as u8
    }
    pub(in crate::rtlwifi) fn prime(self) -> u8 {
        if self.primary < self.secondary {
            1
        } else {
            2
        }
    }
    pub(in crate::rtlwifi) fn ceiling(self, domain: &RegulatoryDomain) -> Result<i16, Error> {
        let center = 2407 + 5 * u32::from(self.center());
        let mut ceiling = None;
        for rule in &domain.rules {
            if rule.freq_start_mhz < center + 20 && rule.freq_end_mhz > center - 20 {
                if rule.freq_start_mhz > center - 20
                    || rule.freq_end_mhz < center + 20
                    || rule.max_bandwidth_mhz < 40
                    || !rule.flags.is_empty()
                {
                    return Err(Error::Power(super::super::channel_power::Error::Policy));
                }
                let limit = i16::from(rule.max_power_dbm) * 4;
                ceiling = Some(ceiling.map_or(limit, |old: i16| old.min(limit)));
            }
        }
        ceiling.ok_or(Error::Power(super::super::channel_power::Error::Policy))
    }
    fn binding(self) -> [u8; 6] {
        [self.primary, 40, 1, 1, self.secondary, self.center()]
    }
    pub(in crate::rtlwifi) fn readback(self, io: &impl Io) -> Result<(), Error> {
        if (io.read8(0x442)? & 0x60) != self.prime() << 5
            || io.read32(0xa00)? & 0x10 != u32::from(self.prime() >> 1) << 4
            || io.read32(0xd00)? & 0xc00 != u32::from(self.prime()) << 10
            || io.read32(0x818)? & 0xc000000 != (if self.prime() == 1 { 2 } else { 1 }) << 26
        {
            return Err(Error::Readback);
        }
        Ok(())
    }
}
pub(in crate::rtlwifi) fn capability() -> LocalHt {
    use narf_wireless::association::phy::{HtGi, HtWidth};
    LocalHt::new(
        [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        HtWidth::TwentyForty,
        HtGi {
            rx20: true,
            tx20: true,
            rx40: false,
            tx40: false,
        },
        0,
        0,
    )
    .expect("fixed EE SISO20/40 LGI+SGI20")
    .with_rx_amsdu_7935(true)
}
pub(in crate::rtlwifi) fn local() -> LocalPhy {
    LocalPhy::ht40(capability()).expect("fixed EE SISO20/40")
}
pub(in crate::rtlwifi) fn request(
    base: &Calibration,
    firmware: super::super::firmware_transport::Identity,
    g: Geometry,
) -> Request {
    let f = base.factory();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF RTL8188EE PCI8179 NEHT4 full20/40 1T1R LGI40 SGI20 RX7935");
    h.update(&super::request_on_channel(base, firmware, g.primary).binding);
    h.update(&g.binding());
    h.update(b"core.c rtl_op_config current_channel=primary+/-2; phy_sw_chnl TX power AND RF channel CENTER; BW20 fallback PRIMARY with signed HT20 nibble, BW40 CENTER no HT20 diff; minimum of both exact factory/PG maxima; unchanged NEPC legacy raw gains also bounded by CENTER CCK/OFDM maxima and NEW full20/40 peak rows; all static antenna IQK LCK supply thermal0..63 autonomous responses, no tracking or measured data; pause actual SCH_TX_CMD then MAC TX/RX, BB603/800/900/442/a00/d00/818, RF18 preserveupper center BW400 vs primary BWc00 and exact native readback before reopening; same physical DMA receipts retained, no old40 RX accepted as20, capture/key/port retirement before width transition; source TXD DATA BW25 SC20/21=3 for40, primary20 SC=prime; no SGI40 MCS32 2SS RTS CTS or unqualified fallback");
    Request {
        name: format!(
            "rtlwifi/rtl8188ee-ht40-v4-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-p{}-s{}.bin",
            f.mac[0],
            f.mac[1],
            f.mac[2],
            f.mac[3],
            f.mac[4],
            f.mac[5],
            g.primary(),
            g.secondary()
        ),
        binding: h.finalize(),
    }
}
pub(super) struct Qualification {
    pub geometry: Geometry,
    pub legacy: [[i16; 64]; 2],
}
pub(super) fn parse(
    base: Arc<Calibration>,
    firmware: super::super::firmware_transport::Identity,
    b: &[u8],
    signer: Option<[u8; 32]>,
    cap: Cap<FirmwareBlob, Read>,
) -> Result<Grant, Error> {
    let bad = || Error::Power(super::super::channel_power::Error::Format);
    if signer.is_none() {
        return Err(Error::Power(super::super::channel_power::Error::Unsigned));
    }
    if b.len() != LENGTH {
        return Err(bad());
    }
    let g = Geometry::new(b[118], b[122])?;
    if b[..4] != *b"NEHT"
        || b[4..8] != [4, 0, 192, 0]
        || u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize != LENGTH
        || b[12..16] != [0xec, 0x10, 0x79, 0x81]
        || b[16..48] != request(&base, firmware, g).binding
        || b[48..80] != super::super::radio::factory_identity(base.factory())
        || b[80..112] != base.digest
        || b[112..118] != base.factory().mac
        || b[118..124] != g.binding()
        || b[128..160] != super::request_on_channel(&base, firmware, g.primary).binding
        || b[160..192] != [0; 32]
    {
        return Err(bad());
    }
    let antenna = i16::from_le_bytes(b[124..126].try_into().unwrap());
    let ceiling = i16::from_le_bytes(b[126..128].try_into().unwrap());
    if !(base.antenna()..=128).contains(&antenna) || !(-512..=80).contains(&ceiling) {
        return Err(bad());
    }
    let rows: [[i16; 64]; 10] = core::array::from_fn(|row| {
        core::array::from_fn(|i| {
            i16::from_le_bytes(
                b[HEADER + row * 128 + i * 2..HEADER + row * 128 + i * 2 + 2]
                    .try_into()
                    .unwrap(),
            )
        })
    });
    if rows
        .iter()
        .flatten()
        .any(|p| *p != UNKNOWN && !(-512..=256).contains(p))
    {
        return Err(bad());
    }
    let grant = Grant {
        channel: g.primary,
        base,
        cap,
        antenna,
        ceiling,
        curves: core::array::from_fn(|i| rows[i + 2]),
        firmware,
        measurement: super::digest(b),
        wide: Some(Qualification {
            geometry: g,
            legacy: [rows[0], rows[1]],
        }),
    };
    grant.invoke(|| Ok(()))?;
    Ok(grant)
}
impl Grant {
    pub(in crate::rtlwifi) fn readback_legacy(
        &self,
        io: &impl Io,
        permission: Permission,
    ) -> Result<(), Error> {
        if self.wide.is_none() {
            return Ok(());
        }
        let (cck, ofdm) = permission.gains();
        if (io.read32(0xe08)? >> 8) & 255 != u32::from(cck[0])
            || io.read32(0x86c)? >> 8
                != u32::from(cck[1]) | (u32::from(cck[2]) << 8) | (u32::from(cck[3]) << 16)
        {
            return Err(Error::Readback);
        }
        for (reg, row) in [0xe00, 0xe04].into_iter().zip(ofdm.chunks_exact(4)) {
            if io.read32(reg)? != u32::from_le_bytes(row.try_into().unwrap()) {
                return Err(Error::Readback);
            }
        }
        Ok(())
    }
    pub(in crate::rtlwifi) fn geometry(&self) -> Option<Geometry> {
        self.wide.as_ref().map(|q| q.geometry)
    }
    pub(in crate::rtlwifi) fn registered_wide(
        base: Arc<Calibration>,
        firmware: super::super::firmware_transport::Identity,
        primary: u8,
    ) -> Result<alloc::vec::Vec<Arc<Self>>, Error> {
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Power(super::super::channel_power::Error::Authority))?;
        let mut grants = alloc::vec::Vec::new();
        for secondary in [primary.checked_sub(4), primary.checked_add(4)]
            .into_iter()
            .flatten()
        {
            let Ok(g) = Geometry::new(primary, secondary) else {
                continue;
            };
            let source = match crate::firmware_asset::load(
                &authority,
                &request(&base, firmware, g).name,
                LENGTH,
                true,
            ) {
                Ok(s) => s,
                Err(FirmwareError::NotFound) => continue,
                Err(e) => {
                    return Err(Error::Power(super::super::channel_power::Error::Firmware(
                        e,
                    )))
                }
            };
            grants.push(Arc::new(parse(
                base.clone(),
                firmware,
                &source.bytes,
                source.signer,
                source.cap,
            )?));
        }
        Ok(grants)
    }
}
