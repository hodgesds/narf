//! Receive-only CLIENT registrations retain their own source metadata; each
//! actual RFH copy adds its original associated physical/native proof.
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::ap_control::{RadioEmissionAuthority, RadioEventAuthority, RadioReceiveFence};
pub(super) struct Host {
    registrations: IrqSafeSpinLock<Vec<Arc<Registration>>>,
    epoch: AtomicU64,
}
pub(super) struct Registration {
    pub event: RadioEventAuthority,
    pub emission: RadioEmissionAuthority,
    pub role: narf_net::native_emission::Lifetime,
    pub kind: u16,
    pub prefix: Vec<u8>,
}
impl Registration {
    fn current(&self) -> bool {
        self.role.current() && self.emission.current()
    }
}
impl Host {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            registrations: IrqSafeSpinLock::new(Vec::new()),
            epoch: AtomicU64::new(1),
        })
    }
    pub fn prune(&self) -> Result<(), &'static str> {
        // Dynamic source callbacks stay outside both State and this lock.
        let old = { self.registrations.lock().clone() };
        let stale: Vec<_> = old
            .into_iter()
            .filter(|r| r.event.registration_current().is_err() || !r.current())
            .collect();
        let mut list = self.registrations.lock();
        if !stale.is_empty() {
            self.advance()?;
            list.retain(|r| !stale.iter().any(|old| Arc::ptr_eq(old, r)));
        }
        Ok(())
    }
    fn advance(&self) -> Result<(), &'static str> {
        self.epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(1).filter(|n| *n != u64::MAX)
            })
            .map(|_| ())
            .map_err(|_| "CLIENT receive registration generation exhausted")
    }
    pub fn add(&self, registration: Registration) -> Result<(), &'static str> {
        if !registration.current() {
            return Err("CLIENT original receive source/role retired before installation");
        }
        let mut list = self.registrations.lock();
        if list.len() >= 16 {
            return Err("CLIENT receive registration bound");
        }
        self.advance()?;
        list.push(Arc::new(registration));
        Ok(())
    }
    pub fn wants_probes(&self) -> bool {
        self.registrations
            .lock()
            .iter()
            .any(|r| r.kind == 0x40 && r.current())
    }
    pub fn snapshot(self: &Arc<Self>) -> Snapshot {
        let list = self.registrations.lock();
        Snapshot {
            host: self.clone(),
            epoch: self.epoch.load(Ordering::Acquire),
            registrations: list.clone(),
        }
    }
}
pub(super) struct Snapshot {
    host: Arc<Host>,
    epoch: u64,
    registrations: Vec<Arc<Registration>>,
}
/// Actual API77 power and publication source, installed by admit_port only
/// after native keys/controlled-port receipts. No caller callback is stored.
pub(super) struct MvmPower {
    pub power: super::mvm_boot::PowerFence,
    pub policy: super::mld_policy::Source,
    pub source: super::mvm_publication::Source,
    pub generation: (Arc<AtomicU64>, u64),
}
impl MvmPower {
    fn check(&self) -> Result<(), &'static str> {
        if self.generation.0.load(Ordering::Acquire) != self.generation.1 {
            return Err("CLIENT copied API77 controlled-port owner retired");
        }
        let domain = self.policy.snapshot()?;
        self.source.invoke(|| self.power.invoke(&domain, || Ok(())))
    }
}
#[derive(Clone)]
pub(super) enum Receiver {
    Mld(alloc::sync::Weak<super::device::Device>),
    Mvm(alloc::sync::Weak<super::mvm_device::Device>),
}
impl Receiver {
    fn epoch(&self) -> Option<u64> {
        match self {
            Self::Mld(device) => device.upgrade()?.client_receive_epoch(),
            Self::Mvm(device) => device.upgrade()?.client_receive_epoch(),
        }
    }
    pub fn capture(&self) -> Option<Observation> {
        Some(Observation {
            receiver: self.clone(),
            epoch: self.epoch()?,
        })
    }
}
pub(super) struct Observation {
    receiver: Receiver,
    epoch: u64,
}
impl Observation {
    fn current(&self) -> bool {
        self.receiver.epoch() == Some(self.epoch)
    }
}
pub(super) struct CopyOwner {
    pub native: Arc<super::p2p_client::Native>,
    pub port: Observation,
    pub source: super::runtime::source::Fence,
    pub receive: super::runtime::rx_epoch::Publication,
    pub mvm: Option<Arc<MvmPower>>,
}
impl CopyOwner {
    fn check(&self) -> Result<(), &'static str> {
        self.source.invoke(|| {
            self.native.observation()?;
            if !self.port.current() || !self.receive.current() {
                return Err("CLIENT original physical copy epoch retired");
            }
            if let Some(power) = &self.mvm {
                power.check()?;
            }
            Ok(())
        })
    }
}
pub(super) struct Publication {
    registration: Arc<Registration>,
    snapshot: Arc<Snapshot>,
    owner: Arc<CopyOwner>,
    frame: Arc<Vec<u8>>,
    rssi: i8,
}
impl Snapshot {
    pub fn copy(
        self: &Arc<Self>,
        owner: &Arc<CopyOwner>,
        packet: &super::runtime::Packet,
        mpdu: &super::scan_api::Mpdu<'_>,
        band_in_rx: bool,
    ) -> Vec<Publication> {
        let f = mpdu.frame;
        if packet.receive_queue != 0
            || packet.receive_epoch.is_none()
            || mpdu.status & 3 != 3
            || mpdu.raw_fw_link != 0
            || mpdu.channel != owner.native.plan.channel.number
            || band_in_rx && mpdu.raw_band != owner.native.plan.channel.band as u8
            || mpdu.frame.first() == Some(&0x40) && !owner.native.probe_receipt()
            || !(24..=2048).contains(&f.len())
            || !matches!(f[0], 0x40 | 0xd0)
            || f[1] & 0xc7 != 0
            || f[22] & 15 != 0
            || f[4..10] != owner.native.plan.own && f[4..10] != [255; 6]
            || f[10] & 1 != 0
            || f[10..16] == [0; 6]
            || f[16..22] != owner.native.plan.peer && f[16..22] != [255; 6]
            || owner.check().is_err()
            || self.host.epoch.load(Ordering::Acquire) != self.epoch
        {
            return Vec::new();
        }
        let body = &f[24..];
        let public = f[0] == 0xd0
            && (body.starts_with(&[4, 9, 0x50, 0x6f, 0x9a, 9]) && body.len() >= 8
                || body.starts_with(&[127, 0x50, 0x6f, 0x9a, 9]) && body.len() >= 7)
            || f[0] == 0x40 && super::p2p_go::attributes(body).is_ok_and(|a| !a.is_empty());
        if !public {
            return Vec::new();
        }
        let frame = Arc::new(f.to_vec());
        self.registrations
            .iter()
            .filter(|r| r.kind == u16::from(f[0]) && body.starts_with(&r.prefix) && r.current())
            .map(|r| Publication {
                registration: r.clone(),
                snapshot: self.clone(),
                owner: owner.clone(),
                frame: frame.clone(),
                rssi: mpdu.rssi,
            })
            .collect()
    }
}
impl Publication {
    fn current(&self) -> Result<(), &'static str> {
        if self.snapshot.host.epoch.load(Ordering::Acquire) != self.snapshot.epoch
            || !self.registration.current()
        {
            return Err("CLIENT original receive registration/source retired");
        }
        self.owner.check()
    }
    pub fn publish(self) {
        if self.current().is_err() {
            return;
        }
        let Ok(prepared) = self.registration.event.prepare_management_received(
            self.owner.native.plan.channel.frequency(),
            Some(self.rssi),
            &self.frame,
        ) else {
            return;
        };
        // Arbitrary preparation may pump/retire the actual owner. The final
        // check reuses this exact original copy, never a fresh association.
        let _ = self.owner.source.invoke(|| {
            self.current()?;
            prepared
                .deliver(RadioReceiveFence {
                    epoch: &self.snapshot.host.epoch,
                    generation: self.snapshot.epoch,
                    receiver: &self.registration.emission,
                    origin: &self.registration.emission,
                })
                .map_err(|_| "CLIENT prepared original receive source retired")
        });
    }
}

pub(super) fn registration<I: narf_wireless::WirelessNetIface + ?Sized>(
    authority: &narf_wireless::ap_control::RadioControlAuthority,
    receiver: &I,
    generation: core::num::NonZeroU64,
    role: narf_net::native_emission::Lifetime,
    kind: u16,
    prefix: &[u8],
) -> Result<Registration, narf_wireless::WirelessError> {
    use narf_wireless::WirelessError;
    authority.check_for(receiver)?;
    authority.require_mode(8)?;
    authority.require_link()?;
    if !authority.has_reservation() || !matches!(kind, 0x40 | 0xd0) || prefix.len() > 256 {
        return Err(WirelessError::InvalidArgs);
    }
    let event = authority.event_authority()?;
    let emission = authority.native_emission_for(receiver)?;
    if !role.current() || !emission.matches_mode(receiver, 8, generation) {
        return Err(WirelessError::Denied);
    }
    // Receive-only metadata does not consult a native association or an
    // initiating NO_IR/MCC power proof. Each later copy captures those actual
    // original physical/association facts independently before RFH copying.
    Ok(Registration {
        event,
        emission,
        role,
        kind,
        prefix: prefix.to_vec(),
    })
}
