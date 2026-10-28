// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EU-only, parked HT20/LGI emission program.
//! Linux rtl8xxxu/8188e.c::rtl8188eu_parse_efuse deliberately does not import
//! the FU/EE HT20 nibble: the zero-initialized EU difference remains zero.
//! rtl8188f_set_tx_power therefore bounds all eight MCS by ht40_base[group0].
use super::{
    firmware_transport::{ControlIo, Executable, Owner},
    receive_runtime::Error,
    wmm_runtime::Proof,
};
use alloc::{format, string::String, sync::Arc};
use core::future::Future;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::association::phy::{LocalHt, LocalPhy};

const HEADER: usize = 160;
const LENGTH: usize = HEADER + 8 * 128;
const UNKNOWN: i16 = i16::MAX;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}
pub(super) fn local() -> LocalPhy {
    LocalPhy::ht20(LocalHt::siso20(false, false)).expect("fixed mandatory EU HT20/LGI profile")
}
pub(super) fn request(base: &Proof, executable: Executable) -> Request {
    let (factory, digest, _) = base.calibration().binding();
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8188EU USB HT20 LGI SISO ch1 MCS0-7 program1");
    hash.update(&factory);
    hash.update(&digest);
    hash.update(b"rtlwifi/rtl8188eufw.bin");
    hash.update(&executable.digest);
    hash.update(b"EU parse_efuse only CCK+HT40; zero HT20 diff; raw ch1 ht40base ceiling; MCS e10/e14; SIFS OFDM16; EDCA16+slot*AIFSN; TXDESC32 LGI QOS TID0-7 AC queue+pipe USE_DRIVER_RATE host RA decision_rate within peer mask (8188e rate_decision, TX_RPT2, RSSI levels) with HW fallback FB0x1ff00 and PT_STAGE; QoS DATA peer density+RTS/CTS24M, AGG_ENABLE only on operational originator BA TID, AGGLEN_LMT/AMPDU_MIN_SPACE per rtl8xxxu_ampdu_action; RXDESC16 rate/HT/BW/GF/SPLCP/HTC/paggr/faggr/frag/QOS/TID/AMSDU and rtl8723au phystats32 SGI; whole original3839 A-MSDU softwareCCMP; boundHT45/61/WMM; recipient ADDBA accept immediate window<=64 noAMSDU-in-AMPDU/decline37/38, DELBA, host reorder100ms before CCMP/PN, original USB terminal receipt; no RF retune");
    hash.update(b"whole static factory antenna LC/IQK supply thermal0..63 operating envelope; unchanged legacy12+all autonomous responses incl. BlockAck+BA actions+eight MCS upper peaks; no gain tracking or measured asset supplied; capture/key/IPC/callback epochs");
    let mac = &factory[8..14];
    Request {
        name: format!(
            "rtl8xxxu/rtl8188eu-ht20-lgi-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
        binding: hash.finalize(),
    }
}
pub(super) struct Grant {
    base: Arc<Proof>,
    executable: Executable,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    ceiling: i16,
    curves: [[i16; 64]; 8],
    maximum: u8,
}
impl Grant {
    pub(super) fn registered(
        base: Arc<Proof>,
        executable: Executable,
        maximum: u8,
    ) -> Result<Option<Arc<Self>>, Error> {
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Policy)?;
        let source = match crate::firmware_asset::load(
            &loader,
            &request(&base, executable).name,
            LENGTH,
            true,
        ) {
            Ok(source) => source,
            Err(FirmwareError::NotFound) => return Ok(None),
            Err(error) => {
                return Err(Error::Control(super::firmware_transport::Error::Firmware(
                    error,
                )))
            }
        };
        Self::parse(
            base,
            executable,
            maximum,
            &source.bytes,
            source.signer,
            source.cap,
        )
        .map(|g| Some(Arc::new(g)))
    }
    pub(super) fn parse(
        base: Arc<Proof>,
        executable: Executable,
        maximum: u8,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        let (factory, digest, minimum_antenna) = base.calibration().binding();
        if signer.is_none()
            || maximum > 63
            || bytes.len() != LENGTH
            || bytes[..4] != *b"N8HT"
            || bytes[4..8] != [1, 0, 160, 0]
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize != LENGTH
            || bytes[12..16] != factory[..4]
            || bytes[16..48] != request(&base, executable).binding
            || bytes[48..77] != factory
            || bytes[77..80] != [0; 3]
            || bytes[80..112] != digest
            || bytes[112..118] != factory[8..14]
            || bytes[118..124] != [1, 20, 1, 0, 0, 0]
            || bytes[128..HEADER] != [0; 32]
        {
            return Err(Error::State);
        }
        let antenna = i16::from_le_bytes(bytes[124..126].try_into().unwrap());
        let ceiling = i16::from_le_bytes(bytes[126..128].try_into().unwrap());
        if !(minimum_antenna..=128).contains(&antenna) || !(-512..=80).contains(&ceiling) {
            return Err(Error::Policy);
        }
        let curves: [[i16; 64]; 8] = core::array::from_fn(|m| {
            core::array::from_fn(|i| {
                let at = HEADER + m * 128 + i * 2;
                i16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
            })
        });
        if curves
            .iter()
            .flatten()
            .any(|v| *v != UNKNOWN && !(-512..=256).contains(v))
        {
            return Err(Error::State);
        }
        let grant = Self {
            base,
            executable,
            cap,
            antenna,
            ceiling,
            curves,
            maximum,
        };
        grant.gains()?;
        Ok(grant)
    }
    pub(super) fn invoke<T>(&self, operation: impl FnOnce() -> T) -> Result<T, Error> {
        struct Current<F>(F);
        impl<T, F: FnOnce() -> T> CapOp<FirmwareBlob, Read> for Current<F> {
            type Output = T;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<T, CapError> {
                Ok((self.0)())
            }
        }
        self.executable
            .invoke(|| {
                self.base.invoke(|| {
                    self.cap
                        .invoke(Current(operation))
                        .map_err(|_| Error::Policy)
                })
            })
            .map_err(Error::Control)??
    }
    pub(super) fn gains(&self) -> Result<[u8; 8], Error> {
        self.invoke(|| {
            let domain = self.base.domain()?;
            let permission = self.base.permission();
            if self
                .base
                .calibration()
                .permission(&domain, 1)
                .map_err(Error::Power)?
                != permission
            {
                return Err(Error::Policy);
            }
            let ceiling = permission.eirp_limit_qdbm().min(self.ceiling);
            if !self
                .base
                .calibration()
                .within(permission, ceiling, self.antenna)
            {
                return Err(Error::Policy);
            }
            let mut gains = [0; 8];
            for (gain, curve) in gains.iter_mut().zip(&self.curves) {
                *gain = (0..=self.maximum)
                    .rev()
                    .find(|i| {
                        curve[usize::from(*i)] != UNKNOWN
                            && i32::from(curve[usize::from(*i)]) + i32::from(self.antenna)
                                <= i32::from(ceiling)
                    })
                    .ok_or(Error::Policy)?;
            }
            Ok(gains)
        })?
    }
    pub(super) async fn program(
        &self,
        firmware: &Owner<impl ControlIo>,
        gains: [u8; 8],
    ) -> Result<(), Error> {
        let operation = async {
            if firmware.read16(0x100).await.map_err(Error::Control)? & 0xc0 != 0 {
                return Err(Error::State);
            }
            for (register, row) in [0xe10, 0xe14].into_iter().zip(gains.chunks_exact(4)) {
                let value = u32::from_le_bytes(row.try_into().unwrap());
                firmware
                    .write32(register, value)
                    .await
                    .map_err(Error::Control)?;
                if firmware.read32(register).await.map_err(Error::Control)? != value {
                    return Err(Error::State);
                }
            }
            // Linux EU uses OFDM SIFS16, not EE's 14us timing.
            let prior = firmware.read16(0x428).await.map_err(Error::Control)?;
            firmware
                .write16(0x428, (prior & 0xff) | 0x1000)
                .await
                .map_err(Error::Control)?;
            self.readback(firmware, gains).await?;
            if firmware.read16(0x100).await.map_err(Error::Control)? & 0xc0 != 0 {
                return Err(Error::State);
            }
            Ok(())
        };
        let mut operation = core::pin::pin!(operation);
        core::future::poll_fn(|cx| {
            self.invoke(|| operation.as_mut().poll(cx))
                .unwrap_or_else(|e| core::task::Poll::Ready(Err(e)))
        })
        .await
    }
    pub(super) async fn readback(
        &self,
        firmware: &Owner<impl ControlIo>,
        gains: [u8; 8],
    ) -> Result<(), Error> {
        if self.gains()? != gains {
            return Err(Error::Policy);
        }
        for (register, row) in [0xe10, 0xe14].into_iter().zip(gains.chunks_exact(4)) {
            if firmware.read32(register).await.map_err(Error::Control)?
                != u32::from_le_bytes(row.try_into().unwrap())
            {
                return Err(Error::State);
            }
        }
        if firmware.read8(0x603).await.map_err(Error::Control)? & 4 == 0
            || firmware.read32(0x800).await.map_err(Error::Control)? & 1 != 0
            || firmware.read32(0x900).await.map_err(Error::Control)? & 1 != 0
            || firmware.read16(0x428).await.map_err(Error::Control)? >> 8 != 16
        {
            return Err(Error::State);
        }
        Ok(())
    }
}
