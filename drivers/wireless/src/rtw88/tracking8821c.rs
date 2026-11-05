// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CE type0 thermal TXAGC/swing + associated IQK. N21W is distinct
//! from N21X RTS and the unchanged N21D dynamic-mechanism contract.
use super::{
    firmware_transport::{Error, Io},
    power_policy::Gate,
    qualification,
};
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_lib::sync::IrqSafeSpinLock;
#[path = "tracking8821c/program.rs"]
mod program;
#[cfg(any(test, feature = "kernel-test"))]
pub(super) use program::mcs_indices;
pub(super) use program::Tracker;

pub(super) const LENGTH: usize = 192;
pub(super) const SCALE: [u16; 37] = [
    0x081, 0x088, 0x090, 0x099, 0x0a2, 0x0ac, 0x0b6, 0x0c0, 0x0cc, 0x0d8, 0x0e5, 0x0f2, 0x101,
    0x110, 0x120, 0x131, 0x143, 0x156, 0x16a, 0x180, 0x197, 0x1af, 0x1c8, 0x1e3, 0x200, 0x21e,
    0x23e, 0x261, 0x285, 0x2ab, 0x2d3, 0x2fe, 0x32b, 0x35c, 0x38e, 0x3c4, 0x3fe,
];
const SOURCE: &[u8] = b"Linux7.2 rtw8821c type0 RF-A ch1 HT20; pwr_track RF42[17:16]=3 trigger and next2s sample[15:10]; EWMAthermal(10,4) delta<=29 exact2G OFDM/CCK positive-negative tables; global signed6bit TXAGCIDXc94[6:1] intersect ALL legacy/response/HT factory ceilings and source+-15; TXSCALEc1c[31:21]37table base+10/min0; threshold8 periodic IQK associatedsegment1 clear0 actual H2C ring consumption plus fresh RF08abcde, clear08 and IQKFAIL1bf0 low8/reload16 zero; quiet original queues+RXDMA_IDLE before mutation; retire copy epoch; preserve keys/PN/perTIDBA/DMA; static exact zerooffset/originalscale restore only if no periodic IQK has changed firmware coefficients; later source loss terminal/fresh owner required; never invent coefficient restore; full multidimensional measured thermal/supply/antenna/BT/rates/automatic-response/T2mixedQCU/retry/swing/AGC/calibration/transient envelope; no invented measurements";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Program {
    pub(super) agc: i8,
    pub(super) swing: u8,
}
#[derive(Clone, Copy)]
enum Phase {
    Stable(Program),
    Changing,
    Retired,
}
pub(super) struct Grant {
    request: Request,
    cap: Cap<FirmwareBlob, Read>,
    /// Exact source snapshot; invocation never dispatches through this Gate.
    base: Gate,
    sources: [Option<Arc<qualification::Grant>>; 4],
    phase: IrqSafeSpinLock<Phase>,
    initial: u8,
    thermal: u8,
    interval: [u8; 2],
    agc: [i8; 2],
    swing: [u8; 2],
    antenna: i16,
    ceiling: i16,
    peaks: [i16; 16],
}
impl core::fmt::Debug for Grant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8821cePowerTracking")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

pub(super) fn request(
    gate: &Gate,
    thermal: u8,
    scale: u16,
    dm: Option<&Arc<qualification::Grant>>,
) -> Result<Request, Error> {
    if gate.did() != 0xc821
        || thermal > 63
        || !SCALE.contains(&scale)
        || gate.power_tracking().is_some()
    {
        return Err(Error::Prerequisite);
    }
    gate.invoke_base(|| Ok(()))?;
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF RTL8821CE full native thermal tracking N21W v1");
    gate.tracking_identity(&mut h)?;
    if let Some(d) = dm {
        if !d.is(&super::dm::KIND) || !d.matches(gate) {
            return Err(Error::State);
        }
        let (i, b) = d.source_identity();
        h.update(b"D");
        h.update(&i);
        h.update(&b);
    } else {
        h.update(b"noD");
    }
    h.update(&[thermal]);
    h.update(&scale.to_le_bytes());
    h.update(SOURCE);
    program::bind(&mut h);
    for s in SCALE {
        h.update(&s.to_le_bytes());
    }
    let mac = gate.own();
    // HT20 and HT40 associations on one channel need distinct provisioned
    // records (their identities differ via the N2xB marker in
    // `tracking_identity`), so the HT40 variant gets its own filename.
    // The HT20 filename is byte-identical to before.
    let variant = if gate.ht40_record().is_some() {
        "-ht40"
    } else {
        ""
    };
    Ok(Request {
        identity: h.finalize(),
        mac,
        filename: super::channel_policy::scoped_filename(
            &format!(
                "rtw88/{}-power-track-v1{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                gate.host().family(),
                variant,
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            ),
            gate.channel(),
        ),
    })
}
pub(super) enum Source {
    Registered,
    #[cfg(any(test, feature = "kernel-test"))]
    Verified {
        bytes: alloc::vec::Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
struct Recipe {
    base: Gate,
    thermal: u8,
    scale: u16,
    request: Request,
    dm: Option<Arc<qualification::Grant>>,
}
impl Source {
    pub(super) fn load(
        self,
        base: Gate,
        thermal: u8,
        scale: u16,
        dm: Option<Arc<qualification::Grant>>,
    ) -> Result<Arc<Grant>, Error> {
        let request = request(&base, thermal, scale, dm.as_ref())?;
        struct Decode(Recipe);
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let v = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Grant::decode(v.bytes, v.signer, *cap, self.0)
                })())
            }
        }
        let g = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive::<Read>().ok())
                    .ok_or(Error::Access)?;
                let cap =
                    narf_firmware::open(&request.filename, &loader).map_err(Error::Firmware)?;
                cap.invoke(Decode(Recipe {
                    base,
                    thermal,
                    scale,
                    request,
                    dm,
                }))
                .map_err(|_| Error::Access)??
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => Grant::decode(
                &bytes,
                signer,
                cap,
                Recipe {
                    base,
                    thermal,
                    scale,
                    request,
                    dm,
                },
            )?,
        };
        g.invoke(|| Ok(()))?;
        Ok(Arc::new(g))
    }
}
fn with_source<T>(
    source: Option<&Arc<qualification::Grant>>,
    op: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    match source {
        Some(g) => g.invoke_source(op),
        None => op(),
    }
}
impl Grant {
    fn decode(
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        recipe: Recipe,
    ) -> Result<Self, Error> {
        let Recipe {
            base,
            thermal,
            scale,
            request,
            dm,
        } = recipe;
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        if signer.is_none()
            || b.len() != LENGTH
            || b[..4] != *b"N21W"
            || b[4..8] != [1, 0, 192, 0]
            || b[8..12] != 192u32.to_le_bytes()
            || b[12..16] != base.host().header()
            || b[16..48] != request.identity
            || b[48..54] != request.mac
            || b[54..56] != [1, 20]
            || b[98..] != [0; 94]
        {
            return Err(Error::Prerequisite);
        }
        let signed = |i| i16::from_le_bytes([b[i], b[i + 1]]);
        let initial = SCALE
            .iter()
            .position(|&s| s == scale)
            .ok_or(Error::Prerequisite)? as u8;
        let g = Self {
            sources: {
                let [c, q, f] = base.tracking_sources();
                [c, q, f, dm]
            },
            base,
            request,
            cap,
            initial,
            thermal,
            phase: IrqSafeSpinLock::new(Phase::Stable(Program {
                agc: 0,
                swing: initial,
            })),
            antenna: signed(56),
            ceiling: signed(58),
            interval: [b[60], b[61]],
            agc: [b[62] as i8, b[63] as i8],
            swing: [b[64], b[65]],
            peaks: core::array::from_fn(|i| signed(66 + i * 2)),
        };
        if !(0..=128).contains(&g.antenna)
            || !(-512..=256).contains(&g.ceiling)
            || g.interval[0] > thermal
            || g.interval[1] < thermal
            || g.interval[1] > 63
            || g.agc[0] < -15
            || g.agc[0] > 0
            || g.agc[1] < 0
            || g.agc[1] > 15
            || g.swing[0] > initial
            || g.swing[1] < initial
            || g.swing[1] > 36
            || g.peaks.iter().any(|p| !(-512..=256).contains(p))
            || g.peaks[1..].iter().any(|p| *p > g.peaks[0])
        {
            return Err(Error::Prerequisite);
        }
        Ok(g)
    }
    pub(super) fn initial_program(&self) -> Program {
        Program {
            agc: 0,
            swing: self.initial,
        }
    }
    pub(super) fn request(&self) -> Request {
        self.request.clone()
    }
    pub(super) fn matches(&self, gate: &Gate) -> bool {
        request(
            gate,
            self.thermal,
            SCALE[usize::from(self.initial)],
            self.sources[3].as_ref(),
        )
        .as_ref()
            == Ok(&self.request)
    }
    /// No call to Gate::invoke: Gate encloses this in its non-dispatching base.
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.authority(|| {
            if !matches!(*self.phase.lock(), Phase::Stable(_)) {
                return Err(Error::State);
            }
            op()
        })
    }
    pub(super) fn authority<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        struct Live<F>(F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        self.base.invoke_base(|| {
            self.cap
                .invoke(Live(|| {
                    with_source(self.sources[0].as_ref(), || {
                        with_source(self.sources[1].as_ref(), || {
                            with_source(self.sources[2].as_ref(), || {
                                with_source(self.sources[3].as_ref(), || {
                                    let limit = self.base.tracking_limit()?.min(self.ceiling);
                                    if self.peaks.iter().any(|p| {
                                        i32::from(*p) + i32::from(self.antenna) > i32::from(limit)
                                    }) {
                                        return Err(Error::Prerequisite);
                                    }
                                    op()
                                })
                            })
                        })
                    })
                }))
                .map_err(|_| Error::Access)?
        })
    }
    pub(super) fn begin(&self) -> Result<(), Error> {
        self.invoke(|| {
            *self.phase.lock() = Phase::Changing;
            Ok(())
        })
    }
    pub(super) fn commit(&self, p: Program) -> Result<(), Error> {
        self.authority(|| {
            if !matches!(*self.phase.lock(), Phase::Changing) || !self.permits(p) {
                return Err(Error::State);
            }
            *self.phase.lock() = Phase::Stable(p);
            Ok(())
        })
    }
    pub(super) fn begin_restore(&self) -> Result<(), Error> {
        if !matches!(*self.phase.lock(), Phase::Stable(_)) {
            return Err(Error::State);
        }
        *self.phase.lock() = Phase::Changing;
        Ok(())
    }
    pub(super) fn active(&self) -> bool {
        !matches!(*self.phase.lock(), Phase::Retired)
    }
    pub(super) fn retire(&self) {
        *self.phase.lock() = Phase::Retired;
    }
    pub(super) fn permits(&self, p: Program) -> bool {
        (self.agc[0]..=self.agc[1]).contains(&p.agc)
            && (self.swing[0]..=self.swing[1]).contains(&p.swing)
    }
    pub(super) fn temperature(&self, t: u8) -> Result<(), Error> {
        if (self.interval[0]..=self.interval[1]).contains(&t) {
            Ok(())
        } else {
            Err(Error::Prerequisite)
        }
    }
    pub(super) async fn readback(
        &self,
        mut read: impl super::firmware_transport::Read32,
    ) -> Result<(), Error> {
        let p = match *self.phase.lock() {
            Phase::Stable(p) => p,
            _ => return Err(Error::State),
        };
        Self::read_program(p, &mut read).await
    }
    pub(super) async fn read_program(
        p: Program,
        read: &mut impl super::firmware_transport::Read32,
    ) -> Result<(), Error> {
        let scale = SCALE.get(usize::from(p.swing)).ok_or(Error::Prerequisite)?;
        if read.read32(0xc94).await? & 0x7e != u32::from((p.agc as u8) & 63) << 1
            || read.read32(0xc1c).await? >> 21 != u32::from(*scale)
        {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
}
