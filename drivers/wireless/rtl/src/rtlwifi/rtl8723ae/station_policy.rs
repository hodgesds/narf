// SPDX-License-Identifier: GPL-2.0-or-later
//! NASR1/2/3: separately signed station programs. Neither NAPC nor NAQR
//! authorizes these on-air effects. NASR includes its own measured worst-case
//! station/coexistence power curves, not a reinterpretation of old NAPC rows.
use super::{envelope, irq, supervision::Binding, txpower};
use crate::platform::capabilities::{Cap, CapError, CapOp, Read};
use crate::platform::firmware::FirmwareBlob;
use crate::rtlwifi::{channel_power::Error as PowerError, prepare::Error};
use alloc::{format, string::String, sync::Arc};
use narf_wireless::reg::RegulatoryDomain;
const HEADER: usize = 256;
const LENGTH: usize = HEADER + 3 * 64 * 2;
const UNKNOWN: i16 = i16::MAX;
const HT20_RECIPE: &[u8] = b"NASR2 RTL8723AE exact original completed20MHz station; independently measured CCK/OFDM/MCS0..7 curves and all coexistence, SGI20, QoS/CCMP, RTS24M,response,retry/transitions; own source HT timing and N24 RA; single-MPDU TX only, no host-DD/onairACK inference; recipient BA64/AMPDU/AMSDU3839 and one-stream HT20; TX AMPDU,LPS/IPS,ASPM,retune/reset/reclaim excluded; optional selection once before station effects, no old-record upgrade";
const HT20_ASPM_RECIPE: &[u8] = b"NASR3 RTL8723AE NASR2 HT20 behavior plus separately measured complete station/firmware/coexistence/automatic-response program across disabled and actual parent/endpoint-intersected L0s/L1/CLKREQ states and transitions; source AE hw.c853..870 byte34b93/word350870c/byte3521 then byte3491b/word3502718/byte3521 with bounded DBI completion and byte readbacks; actual default aspm_support1 support_backdoortrue; no bridge/common-clock mutation, policy revalidated before each endpoint commit; per-access original current NASR/NAQR/NAPC/firmware/PCI effects, before packet enable only, terminal uncertain/cancel/drop with original owner retained and independent current-PCI endpoint-state withdrawal serialized after old effects; no old-record upgrade, no TX AMPDU/LPS/IPS/retune/reset/reclaim";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Profile {
    Legacy20,
    Ht20,
    Ht20Aspm,
}
impl Profile {
    fn version(self) -> u8 {
        match self {
            Self::Legacy20 => 1,
            Self::Ht20 => 2,
            Self::Ht20Aspm => 3,
        }
    }
    fn rates(self) -> u32 {
        match self {
            Self::Legacy20 => 0xfff,
            Self::Ht20 | Self::Ht20Aspm => 0xfffff,
        }
    }
}
const RECIPE: &[u8] = b"NARF RTL8723AE NASR1 1T1R2.4GHz legacy20 station only; retained exact NAQR-completed original cold Box/PG/IQK/LCK/PA and firmware; factory-capped Normal source RF6052 TXAGC words/readbacks; exact tx_desc8723e64 linked next40 buffer32; RX32 in-ring buf24 drvinfo+shift,FCS removed,softwareCCMP no hardware decrypt,nofrag,A-MPDU/HT/GI refused; actual sourceIRQ3a8/3ac3a0W1C noHISRE read; single shared station/coex H2C rotation HMETFR AND MCUTST ready,initial+99*10us/1bf,len1..5,bytesEXTfirst; H2C0Active1,2Join,3RSVD,6RA mask MACID0 B/G levels support,legacyfullindices CCK0..3 OFDM4..11 driver special rate1M,ordinaryDATA firmwareRA subset,RTSCTS24M fallback admitted; sourceAE BSSID/network/checkbssid/RRSR/SIFS/ERP/EDCA; reservedpage firmware locations4,2,3 actual source cmd descriptor OWN publication/kick beforeH2C/join, no BCN_VALID or onairACK receipt,buffer retained; source1/2antenna coex mech_init and fullhal_btc/hal_bt_coexistprogram,originRFbackup beforeeffect,actualC2H BTinfo and watchdog only,noBE specialpacket dispatch alias,all effects under samecurrentjoint; NASR curves are measured worstcase across every enabledstation/firmware/coexstate and sourceRF/AGC/CCK/OFDM transitions, no Normalcurve assumption,no guessedlimits; packetBME/CR enables only after original rings retained+source/host policy/currentPCI exact; no reset/recovery/reclaim or LPS/IPS/ASPM admission in profile1";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    permission: envelope::Permission,
    source: [u8; 32],
}
impl Grant {
    pub(crate) fn permission(self) -> envelope::Permission {
        self.permission
    }
    pub(crate) fn channel(self) -> u8 {
        self.permission.channel()
    }
}
/// One exact already-completed native preparation, held through all station
/// failures/removal. Constructible only from retained Work::Complete.
pub(crate) struct Program {
    profile: Profile,
    prepared: Arc<Binding>,
    cap: Cap<FirmwareBlob, Read>,
    curves: [[i16; 64]; 3],
    antenna: i16,
    qualified: i16,
    coex_peak: i16,
    digest: [u8; 32],
}
impl core::fmt::Debug for Program {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8723aeJointStationProgram")
            .field("operating", &self.prepared.operating())
            .finish_non_exhaustive()
    }
}
fn failure(error: PowerError) -> Error {
    Error::Power(error)
}
pub(super) fn recipe_digest() -> [u8; 32] {
    recipe_for(Profile::Legacy20)
}
pub(super) fn recipe_for(profile: Profile) -> [u8; 32] {
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(match profile {
        Profile::Legacy20 => RECIPE,
        Profile::Ht20 => HT20_RECIPE,
        Profile::Ht20Aspm => HT20_ASPM_RECIPE,
    });
    h.update(b"NASR selected source identity v1");
    h.update(&super::source_program::digest());
    h.update(&super::reserved::SOURCE);
    for value in [
        u32::from(irq::ISR),
        u32::from(irq::MASK0),
        u32::from(irq::MASK1),
        irq::IRQ0,
        irq::IRQ1,
        64,
        32,
        40,
        32,
        24,
    ] {
        h.update(&value.to_le_bytes());
    }
    h.finalize()
}
impl Program {
    pub(in crate::rtlwifi) async fn wait<F: core::future::Future<Output = Result<(), Error>>>(
        &self,
        grant: Grant,
        future: F,
    ) -> Result<(), Error> {
        let mut future = core::pin::pin!(future);
        core::future::poll_fn(|cx| {
            let result = self.with_current(|| {
                let domain = self.prepared.current_domain()?;
                if self.grant_for(&domain)? != grant {
                    return Err(Error::State);
                }
                Ok(future.as_mut().poll(cx))
            });
            match result {
                Ok(poll) => poll,
                Err(error) => core::task::Poll::Ready(Err(error)),
            }
        })
        .await
    }
    pub(super) fn request(prepared: &Binding) -> Result<Request, Error> {
        Self::request_for(prepared, Profile::Legacy20)
    }
    pub(super) fn request_ht20(prepared: &Binding) -> Result<Request, Error> {
        Self::request_for(prepared, Profile::Ht20)
    }
    pub(super) fn request_ht20_aspm(prepared: &Binding) -> Result<Request, Error> {
        Self::request_for(prepared, Profile::Ht20Aspm)
    }
    fn request_for(prepared: &Binding, profile: Profile) -> Result<Request, Error> {
        let op = prepared.operating();
        if op.width != envelope::Width::W20 || !(1..=11).contains(&op.channel) {
            return Err(Error::State);
        }
        prepared.invoke(|| Ok(()))?;
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"NARF NASR1 native station exact completed AE program");
        match profile {
            Profile::Legacy20 => {}
            Profile::Ht20 => h.update(b"distinct NASR2 HT20 profile"),
            Profile::Ht20Aspm => h.update(b"distinct NASR3 HT20 ASPM profile"),
        }
        h.update(&prepared.digest());
        h.update(&recipe_for(profile));
        let mac = prepared.factory().mac;
        Ok(Request {
            name: format!(
                "rtlwifi/rtl8723ae-station-v{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-p{}.bin",
                profile.version(),
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5],
                op.channel
            ),
            binding: h.finalize(),
        })
    }
    pub(super) fn registered(prepared: Arc<Binding>) -> Result<Arc<Self>, Error> {
        let loader = crate::platform::firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(failure(PowerError::Authority))?;
        for profile in [Profile::Ht20Aspm, Profile::Ht20, Profile::Legacy20] {
            let request = Self::request_for(&prepared, profile)?;
            let source = match crate::firmware_asset::load(&loader, &request.name, LENGTH, true) {
                Ok(source) => source,
                Err(crate::platform::firmware::FirmwareError::NotFound)
                    if profile != Profile::Legacy20 =>
                {
                    continue
                }
                Err(error) => return Err(failure(PowerError::Firmware(error))),
            };
            let program = Self::parse(prepared, &source.bytes, source.signer, source.cap)?;
            if program.profile != profile {
                return Err(failure(PowerError::Format));
            }
            return Ok(Arc::new(program));
        }
        Err(Error::State)
    }
    pub(super) fn parse(
        prepared: Arc<Binding>,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(failure(PowerError::Unsigned));
        }
        let bad = || failure(PowerError::Format);
        let profile = match bytes.get(4..8) {
            Some([1, 0, 0, 1]) => Profile::Legacy20,
            Some([2, 0, 0, 1]) => Profile::Ht20,
            Some([3, 0, 0, 1]) => Profile::Ht20Aspm,
            _ => return Err(bad()),
        };
        let op = prepared.operating();
        let request = Self::request_for(&prepared, profile)?;
        if bytes.len() != LENGTH
            || &bytes[..4] != b"NASR"
            || bytes[4..8] != [profile.version(), 0, 0, 1]
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != LENGTH as u32
            || bytes[12..16] != [0xec, 0x10, 0x23, 0x87]
            || bytes[16..48] != request.binding
            || bytes[48..80] != crate::rtlwifi::radio::factory_identity(prepared.factory())
            || bytes[80..112] != prepared.napc_digest()
            || bytes[112..144] != prepared.naqr_digest()
            || bytes[144..176] != prepared.firmware().digest
            || bytes[176..208] != recipe_for(profile)
            || bytes[208..214] != [op.channel, 20, 0, op.channel, 1, 0]
            || bytes[214..220] != prepared.factory().mac
            || bytes[226..228]
                != [
                    profile.version(),
                    u8::from(prepared.adapter().bt.coexistence),
                ]
            || u32::from_le_bytes(bytes[228..232].try_into().unwrap()) != profile.rates()
            || bytes[232..256] != [0; 24]
        {
            return Err(bad());
        }
        let antenna = i16::from_le_bytes(bytes[220..222].try_into().unwrap());
        let qualified = i16::from_le_bytes(bytes[222..224].try_into().unwrap());
        let coex_peak = i16::from_le_bytes(bytes[224..226].try_into().unwrap());
        if !(prepared.antenna()..=128).contains(&antenna)
            || !(-512..=80).contains(&qualified)
            || !(-512..=256).contains(&coex_peak)
        {
            return Err(bad());
        }
        let mut curves = [[UNKNOWN; 64]; 3];
        for (at, out) in curves.iter_mut().flatten().enumerate() {
            *out = i16::from_le_bytes(
                bytes[HEADER + at * 2..HEADER + at * 2 + 2]
                    .try_into()
                    .unwrap(),
            );
            if *out != UNKNOWN && !(-512..=256).contains(out) {
                return Err(bad());
            }
        }
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(bytes);
        Ok(Self {
            profile,
            prepared,
            cap,
            curves,
            antenna,
            qualified,
            coex_peak,
            digest: h.finalize(),
        })
    }
    /// Enclose the actual operation in all retained preparation sources plus
    /// NASR authority. A prior Noop check grants no later native access.
    pub(crate) fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Live<F>(F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        self.prepared.invoke(|| {
            self.cap
                .invoke(Live(operation))
                .map_err(|_| failure(PowerError::Authority))?
        })
    }
    pub(crate) fn grant_for(&self, domain: &RegulatoryDomain) -> Result<Grant, Error> {
        self.with_current(|| {
            let ceiling = envelope::span_ceiling(domain, self.prepared.operating())
                .map_err(failure)?
                .min(self.qualified);
            if i32::from(self.coex_peak) + i32::from(self.antenna) > i32::from(ceiling) {
                return Err(failure(PowerError::Policy));
            }
            let source = self.prepared.source_plan()?;
            let indices = source.indices()[0];
            let caps = indices[..20].try_into().map_err(|_| Error::State)?;
            let mut permission = self
                .prepared
                .base()
                .joint_permission(
                    domain,
                    self.prepared.operating(),
                    caps,
                    self.antenna,
                    self.qualified,
                    &self.curves,
                )
                .map_err(failure)?;
            permission.restrict_station_rates(u64::from(self.profile.rates()));
            Ok(Grant {
                permission,
                source: self.digest,
            })
        })
    }
    pub(crate) fn plan(&self, grant: Grant) -> Result<txpower::Plan, Error> {
        if grant.source != self.digest || grant.permission.operating() != self.prepared.operating()
        {
            return Err(Error::State);
        }
        self.with_current(|| {
            self.prepared
                .source_plan()?
                .bounded(core::array::from_fn(|i| grant.permission.index(i as u8)))
        })
    }
    pub(in crate::rtlwifi) fn prepared(&self) -> &Arc<Binding> {
        &self.prepared
    }
    pub(crate) fn ht20(&self) -> bool {
        self.profile != Profile::Legacy20
    }
    pub(crate) fn aspm(&self) -> bool {
        self.profile == Profile::Ht20Aspm
    }
}
