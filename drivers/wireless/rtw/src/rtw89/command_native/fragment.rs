// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Original same-Native binding and one logical MSDU's immutable fragment train.
//! Capture precedes crypto; no caller can manufacture a peer/radio receipt.
use super::*;
use crate::rtw89::{fragment_wire as wire, power, station_control as control};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
pub(in crate::rtw89) struct Binding {
    device: Cap<BusDeviceCap, Write>,
    qualification: FragmentQualification,
    peer: control::Peer,
    admission: control::Admission,
}
/// The signed fragment program a binding is measured against: B
/// (`radio_policy::Qualification`, N52F) or A
/// (`radio_policy_a::Qualification`, N5AF). C and RTL8851B have no signed
/// fragment companion: "no program".
#[derive(Clone)]
pub(in crate::rtw89) enum FragmentQualification {
    B(Arc<crate::rtw89::radio_policy::Qualification>),
    A(Arc<crate::rtw89::radio_policy_a::Qualification>),
}
impl FragmentQualification {
    fn fragments_allowed(&self) -> Result<bool, power::Error> {
        match self {
            Self::B(q) => q.fragments_allowed().map_err(|_| power::Error::Access),
            Self::A(q) => q.fragments_allowed().map_err(|_| power::Error::Access),
        }
    }
    fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        match self {
            Self::B(q) => q.with_current(operation),
            Self::A(q) => q.with_current(operation),
        }
    }
    /// Whether this binding's qualification is the installed ordinary
    /// grant (same program object, same chip).
    fn same_grant(&self, ordinary: Option<&OrdinaryGrant>) -> bool {
        match (self, ordinary) {
            (Self::B(q), Some(OrdinaryGrant::B(g))) => Arc::ptr_eq(g, q),
            (Self::A(q), Some(OrdinaryGrant::A(g))) => Arc::ptr_eq(g, q),
            _ => false,
        }
    }
}
enum Payload {
    Secure(Arc<narf_wireless::station_security::fragment::FragmentTrain>),
    Plain(Vec<Vec<u8>>),
}
pub(in crate::rtw89) struct Train {
    binding: Binding,
    payload: Payload,
    next: AtomicUsize,
    issued: AtomicBool,
}
#[derive(Clone)]
pub(in crate::rtw89) struct Part {
    train: Arc<Train>,
    index: usize,
}
impl Binding {
    /// Inert public-worker fixture's authenticated-program/controller boundary.
    /// Real Native capture remains mandatory in production (no such constructor).
    #[cfg(feature = "kernel-test")]
    pub(in crate::rtw89) fn model(
        device: Cap<BusDeviceCap, Write>,
        qualification: Arc<crate::rtw89::radio_policy::Qualification>,
        peer: control::Peer,
        admission: control::Admission,
    ) -> Result<Self, power::Error> {
        Self::new(
            device,
            FragmentQualification::B(qualification),
            peer,
            admission,
        )
    }
    /// The RTL8852A fixture counterpart of [`Self::model`].
    #[cfg(feature = "kernel-test")]
    pub(in crate::rtw89) fn model_a(
        device: Cap<BusDeviceCap, Write>,
        qualification: Arc<crate::rtw89::radio_policy_a::Qualification>,
        peer: control::Peer,
        admission: control::Admission,
    ) -> Result<Self, power::Error> {
        Self::new(
            device,
            FragmentQualification::A(qualification),
            peer,
            admission,
        )
    }
    /// Fixture-only shared construction for [`Self::model`]/[`Self::model_a`].
    #[cfg(feature = "kernel-test")]
    fn new(
        device: Cap<BusDeviceCap, Write>,
        qualification: FragmentQualification,
        peer: control::Peer,
        admission: control::Admission,
    ) -> Result<Self, power::Error> {
        if !peer.admission_same(&admission) {
            return Err(power::Error::Terminal);
        }
        let binding = Self {
            device,
            qualification,
            peer,
            admission,
        };
        binding.current()?;
        Ok(binding)
    }
    fn current(&self) -> Result<(), power::Error> {
        crate::rtw88::pci_park::invoke(&self.device, || Ok::<(), power::Error>(()))
            .map_err(|_| power::Error::Access)??;
        self.admission.check()?;
        self.peer.current()?;
        if !self
            .qualification
            .fragments_allowed()
            .map_err(|_| power::Error::Access)?
        {
            return Err(power::Error::Unsupported);
        }
        Ok(())
    }
    pub(in crate::rtw89) fn secure(
        self,
        train: narf_wireless::station_security::fragment::FragmentTrain,
    ) -> Result<Arc<Train>, power::Error> {
        self.finish(Payload::Secure(Arc::new(train)))
    }
    pub(in crate::rtw89) fn plain(self, frames: Vec<Vec<u8>>) -> Result<Arc<Train>, power::Error> {
        self.finish(Payload::Plain(frames))
    }
    fn finish(self, payload: Payload) -> Result<Arc<Train>, power::Error> {
        self.current()?;
        let frames = match &payload {
            Payload::Secure(train) => {
                if !train.current_key() {
                    return Err(power::Error::Terminal);
                }
                train.frames()
            }
            Payload::Plain(frames) => frames,
        };
        if !(2..=wire::MAX_FRAGMENTS).contains(&frames.len()) {
            return Err(power::Error::Unsupported);
        }
        let first = frames.first().ok_or(power::Error::Unsupported)?;
        let header = wire::header(first).ok_or(power::Error::Unsupported)?;
        let sequence = u16::from_le_bytes([first[22], first[23]]) >> 4;
        let protected = matches!(payload, Payload::Secure(_));
        for (index, frame) in frames.iter().enumerate() {
            if wire::header(frame) != Some(header)
                || !(header + 1..=crate::rtw89::packet_format::FRAGMENT_MAX_MPDU)
                    .contains(&frame.len())
                || frame[0] != first[0]
                || frame[1] & !4 != first[1] & !4
                || (frame[1] & 0x40 != 0) != protected
                || frame[4..22] != first[4..22]
                || u16::from_le_bytes([frame[22], frame[23]]) >> 4 != sequence
                || usize::from(frame[22] & 15) != index
                || (frame[1] & 4 != 0) != (index + 1 < frames.len())
                || frame[2..4]
                    != wire::duration(frames.get(index + 1).map(Vec::len))
                        .ok_or(power::Error::Unsupported)?
                        .to_le_bytes()
                || !self.peer.admits(frame)
                || frame[4..10] != self.peer.bssid()
                || frame[10..16] != self.peer.own()
                || frame[1] & !(4 | 0x40) != if frame[0] & 12 == 0 { 0 } else { 1 }
                || header == 26 && frame[24..26] != first[24..26]
            {
                return Err(power::Error::Unsupported);
            }
        }
        Ok(Arc::new(Train {
            binding: self,
            payload,
            next: AtomicUsize::new(0),
            issued: AtomicBool::new(false),
        }))
    }
}
impl Train {
    /// Fixed inert-producer observation only. A true value grants no current
    /// key/source/native authority and cannot issue/advance or retire a part.
    #[cfg(feature = "kernel-test")]
    pub(in crate::rtw89) fn model_issued(&self) -> bool {
        self.issued.load(Ordering::Acquire)
    }
    fn frames(&self) -> &[Vec<u8>] {
        match &self.payload {
            Payload::Secure(train) => train.frames(),
            Payload::Plain(frames) => frames,
        }
    }
    pub(in crate::rtw89) fn complete(&self) -> bool {
        self.next.load(Ordering::Acquire) == self.frames().len()
            && !self.issued.load(Ordering::Acquire)
    }
    pub(in crate::rtw89) fn next(self: &Arc<Self>) -> Option<Part> {
        let index = self.next.load(Ordering::Acquire);
        if self.issued.load(Ordering::Acquire) || index >= self.frames().len() {
            return None;
        }
        Some(Part {
            train: self.clone(),
            index,
        })
    }
}
impl Part {
    #[cfg(feature = "kernel-test")]
    pub(in crate::rtw89) fn model_issued_current(&self) -> Result<(), power::Error> {
        self.issued_current()
    }
    #[cfg(feature = "kernel-test")]
    pub(in crate::rtw89) fn model_with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        self.train.binding.qualification.with_current(|| {
            self.current()?;
            operation()
        })
    }
    pub(in crate::rtw89) fn bytes(&self) -> &[u8] {
        &self.train.frames()[self.index]
    }
    pub(in crate::rtw89) fn current(&self) -> Result<(), power::Error> {
        self.check(false)
    }
    pub(super) fn issued_current(&self) -> Result<(), power::Error> {
        self.check(true)
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        self.index == other.index && Arc::ptr_eq(&self.train, &other.train)
    }
    fn check(&self, issued: bool) -> Result<(), power::Error> {
        self.train.binding.current()?;
        if self.train.next.load(Ordering::Acquire) != self.index
            || self.train.issued.load(Ordering::Acquire) != issued
            || matches!(&self.train.payload,Payload::Secure(train) if !train.current_key())
        {
            return Err(power::Error::Terminal);
        }
        Ok(())
    }
    /// Native records issued ownership BEFORE descriptor publication. This is
    /// a one-shot original part, never a reusable RF admission/credit bool.
    pub(in crate::rtw89) fn issue(&self) -> Result<(), power::Error> {
        self.current()?;
        self.train
            .issued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| power::Error::Terminal)?;
        Ok(())
    }
    /// Called only from actual Core completion after DMA AND exact successful
    /// RPQ identity/status, using bytes acquired from its retained DMA body.
    /// Cleanup can retire the part after source/key loss; it emits nothing.
    pub(in crate::rtw89) fn terminal(&self, bytes: &[u8]) -> Result<(), power::Error> {
        if bytes != self.bytes()
            || self.train.next.load(Ordering::Acquire) != self.index
            || !self.train.issued.load(Ordering::Acquire)
        {
            return Err(power::Error::Terminal);
        }
        self.train.next.store(self.index + 1, Ordering::Release);
        self.train.issued.store(false, Ordering::Release);
        Ok(())
    }
}
impl Native {
    pub(in crate::rtw89) fn station_fragments_allowed(&mut self) -> Result<bool, power::Error> {
        self.ordinary_current()?;
        // RTL8852C and RTL8851B have no signed fragment companion: "no program".
        match self.ordinary.as_ref().ok_or(power::Error::Unsupported)? {
            OrdinaryGrant::A(qualification) => qualification
                .fragments_allowed()
                .map_err(|_| power::Error::Access),
            OrdinaryGrant::B(qualification) => qualification
                .fragments_allowed()
                .map_err(|_| power::Error::Access),
            OrdinaryGrant::C(_) | OrdinaryGrant::N51(_) => Ok(false),
        }
    }
    pub(in crate::rtw89) fn fragment_binding(
        &mut self,
        admission: &control::Admission,
    ) -> Result<Binding, power::Error> {
        self.with_ordinary_current(|native| {
            if !matches!(native.chip, ChipId::Rtl8852A | ChipId::Rtl8852B)
                || native.station_runtime.monitor.is_some()
                || native.sleep_blocked
                || native.sleep_reset.is_some()
                || !native.packets_ready()
            {
                return Err(power::Error::Busy);
            }
            admission.check()?;
            control::awake(&mut native.io)?;
            let qualification = match native.ordinary.as_ref().ok_or(power::Error::Terminal)? {
                OrdinaryGrant::A(q) if native.chip == ChipId::Rtl8852A => {
                    FragmentQualification::A(q.clone())
                }
                OrdinaryGrant::B(q) if native.chip == ChipId::Rtl8852B => {
                    FragmentQualification::B(q.clone())
                }
                _ => return Err(power::Error::Unsupported),
            };
            if !qualification
                .fragments_allowed()
                .map_err(|_| power::Error::Access)?
            {
                return Err(power::Error::Unsupported);
            }
            let peer = native
                .station_runtime
                .peer
                .as_ref()
                .ok_or(power::Error::Terminal)?
                .clone();
            peer.current()?;
            if !peer.admission_same(admission) {
                return Err(power::Error::Terminal);
            }
            if !native.station_runtime.backlog.is_empty()
                || native
                    .receive
                    .pending(&mut native.io)
                    .map_err(|_| power::Error::Access)?
            {
                return Err(power::Error::Busy);
            }
            Ok(Binding {
                device: native.authority,
                qualification,
                peer,
                admission: admission.clone(),
            })
        })
    }
    pub(super) fn fragment_part_current(
        &mut self,
        part: &Part,
        bytes: &[u8],
        quiet: bool,
        issued: bool,
    ) -> Result<(), crate::rtw89::packet_core::Error> {
        // Preserve the inner unpublished Busy separately from current-cap errors.
        self.with_ordinary_current(|native| {
            Ok((|| {
                if issued {
                    part.issued_current()
                } else {
                    part.current()
                }
                .map_err(|_| crate::rtw89::packet_core::Error::Access)?;
                let binding = &part.train.binding;
                if bytes != part.bytes()
                    || native.authority.slot() != binding.device.slot()
                    || native
                        .station_runtime
                        .peer
                        .as_ref()
                        .is_none_or(|peer| !peer.same(&binding.peer))
                    || !binding.qualification.same_grant(native.ordinary.as_ref())
                    || native.station_runtime.monitor.is_some()
                    || native.sleep_blocked
                    || native.sleep_reset.is_some()
                {
                    return Err(crate::rtw89::packet_core::Error::Access);
                }
                if quiet
                    && (!native.station_runtime.backlog.is_empty()
                        || native
                            .receive
                            .pending(&mut native.io)
                            .map_err(|_| crate::rtw89::packet_core::Error::Access)?)
                {
                    return Err(crate::rtw89::packet_core::Error::Busy);
                }
                Ok(())
            })())
        })
        .map_err(|_| crate::rtw89::packet_core::Error::Access)?
    }
}
