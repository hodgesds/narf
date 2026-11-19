// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained logical MSDU/MMPDU, original ciphertext and actual terminal parts.
use super::*;
use crate::rtw89::{command_native, fragment_wire};
pub(super) struct Deferred {
    frame: Vec<u8>,
    kind: Kind,
    assign: bool,
    threshold: u32,
}
pub(super) struct Flight {
    train: Arc<command_native::FragmentTrain>,
    kind: Kind,
    pending: Option<u64>,
    started: bool,
}
impl State {
    #[cfg(feature = "kernel-test")]
    pub(in crate::rtw89) fn model_management(
        &mut self,
        io: &mut impl Io,
        bytes: Vec<u8>,
    ) -> Result<(), Error> {
        let admission = self.admission.clone();
        admission.run(|| Ok(self.transmit(io, bytes, Kind::Action)))?
    }
    pub(in crate::rtw89) fn set_fragment_policy(
        &mut self,
        policy: Option<Arc<crate::rtw89::monitor::Desired>>,
    ) {
        self.fragment_policy = policy;
    }
    fn fragment_threshold(&self) -> u32 {
        self.fragment_policy
            .as_ref()
            .map_or(fragment_wire::DISABLED, |p| p.fragment_threshold())
    }
    fn fragment_needed(bytes: usize, threshold: u32) -> bool {
        threshold != fragment_wire::DISABLED
            && bytes
                .checked_add(4)
                .is_some_and(|size| size > threshold as usize)
    }
    /// The logical input is consumed once retained here. A later unpublished
    /// Busy retries this SAME immutable train, never crypto/SN/PN allocation.
    fn retain_fragments(
        &mut self,
        train: Arc<command_native::FragmentTrain>,
        kind: Kind,
    ) -> Result<(), Error> {
        if self.fragment_tx.is_some() || !self.transmit_room(kind, None) {
            return Err(Error::State);
        }
        self.fragment_tx = Some(Box::new(Flight {
            train,
            kind,
            pending: None,
            started: false,
        }));
        Ok(())
    }
    pub(super) fn fragment_data(
        &mut self,
        io: &mut impl Io,
        ethernet: &[u8],
        tid: u8,
        agg: Option<super::super::packet_format::Agg>,
    ) -> Result<bool, Error> {
        // mac80211 marks actual A-MPDU/A-MSDU DONTFRAG. No fragment train
        // enters a BA session, and the unchanged receive promises stay narrow.
        let threshold = self.fragment_threshold();
        let header = if self.wmm.is_some() { 26 } else { 24 };
        if agg.is_some() || !Self::fragment_needed(header + 8 + ethernet.len() - 14, threshold) {
            return Ok(false);
        }
        if !self.rx_idle || !self.incoming.is_empty() || self.fragment_tx.is_some() {
            return Err(Error::Busy);
        }
        // Capture original physical peer/program/source BEFORE any PN or SN.
        let binding = match io.packet_fragment_binding(&self.admission) {
            Ok(binding) => binding,
            Err(power::Error::Busy) => return Err(Error::Busy),
            Err(error) => return Err(Error::Native(error)),
        };
        let train = if let Some(security) = &mut self.security {
            let train =
                security.transmit_ethernet_fragments(ethernet, self.wmm.map(|_| tid), threshold)?;
            let durations: Vec<_> = train
                .frames()
                .iter()
                .enumerate()
                .map(|(n, _)| {
                    fragment_wire::duration(train.frames().get(n + 1).map(Vec::len))
                        .ok_or(Error::Profile)
                })
                .collect::<Result<_, _>>()?;
            binding.secure(train.with_durations(&durations)?)?
        } else {
            let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
            let mut frame = vec![if self.wmm.is_some() { 0x88 } else { 8 }, 1, 0, 0];
            frame.extend_from_slice(&peer);
            frame.extend_from_slice(&self.own);
            frame.extend_from_slice(&ethernet[..6]);
            frame.extend_from_slice(&(self.sequence << 4).to_le_bytes());
            if self.wmm.is_some() {
                frame.extend_from_slice(&[tid, 0]);
            }
            frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            frame.extend_from_slice(&ethernet[12..]);
            let mut frames = fragment_wire::split(&frame, threshold).ok_or(Error::Profile)?;
            fragment_wire::durations(&mut frames).ok_or(Error::Profile)?;
            self.sequence = (self.sequence + 1) & 4095;
            binding.plain(frames)?
        };
        self.retain_fragments(train, Kind::Data)?;
        self.progress_fragments(io)?;
        Ok(true)
    }
    /// Management's one host sequence is assigned only after original native
    /// capture. PMF encryption happens after splitting, not before it.
    pub(super) fn fragment_management(
        &mut self,
        io: &mut impl Io,
        frame: &[u8],
        kind: Kind,
        assign: bool,
    ) -> Result<bool, Error> {
        let threshold = self.fragment_threshold();
        if !Self::fragment_needed(frame.len(), threshold)
            || frame.get(4).is_none_or(|b| b & 1 != 0)
            || matches!(kind, Kind::Data | Kind::Security)
        {
            return Ok(false);
        }
        if self.fragment_wait.is_some() || self.fragment_tx.is_some() {
            return Err(Error::Busy);
        }
        self.fragment_wait = Some(Box::new(Deferred {
            frame: frame.to_vec(),
            kind,
            assign,
            threshold,
        }));
        self.progress_fragments(io)?;
        Ok(true)
    }
    /// A late real RX prefix/credit refusal owns the logical management input
    /// without consuming any SN/PN. The same retained station/source waits;
    /// it cannot rebind to another peer or physical owner.
    fn prepare_fragment_management(&mut self, io: &mut impl Io) -> Result<(), Error> {
        let Some(waiting) = self.fragment_wait.as_ref() else {
            return Ok(());
        };
        if !self.rx_idle
            || !self.pending.is_empty()
            || self.delivered_reply.is_some()
            || !io.packet_ready()
        {
            return Ok(());
        }
        if waiting.kind == Kind::Action && self.security.as_ref().is_some_and(|s| !s.port_open()) {
            self.fragment_wait = None;
            return Ok(());
        }
        let binding = match io.packet_fragment_binding(&self.admission) {
            Ok(binding) => binding,
            Err(power::Error::Busy) => return Ok(()),
            Err(error) => return Err(Error::Native(error)),
        };
        let Deferred {
            mut frame,
            kind,
            assign,
            threshold,
        } = *self.fragment_wait.take().ok_or(Error::State)?;
        if assign {
            frame[22..24].copy_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
        }
        let train = if let Some(security) = self
            .security
            .as_mut()
            .filter(|s| kind == Kind::Action && s.pmf() && s.port_open())
        {
            let train = security.protect_management_fragments(&frame, threshold)?;
            let durations: Vec<_> = train
                .frames()
                .iter()
                .enumerate()
                .map(|(n, _)| {
                    fragment_wire::duration(train.frames().get(n + 1).map(Vec::len))
                        .ok_or(Error::Profile)
                })
                .collect::<Result<_, _>>()?;
            binding.secure(train.with_durations(&durations)?)?
        } else {
            let mut frames = fragment_wire::split(&frame, threshold).ok_or(Error::Profile)?;
            fragment_wire::durations(&mut frames).ok_or(Error::Profile)?;
            binding.plain(frames)?
        };
        self.retain_fragments(train, kind)
    }
    pub(super) fn fragment_blocks_incoming(&self) -> bool {
        self.fragment_wait.is_some()
            || self
                .fragment_tx
                .as_ref()
                .is_some_and(|flight| flight.kind != Kind::Data)
    }
    pub(super) fn fragment_delivered(&mut self, id: u64) -> Result<(), Error> {
        let Some(flight) = self.fragment_tx.as_mut() else {
            return Ok(());
        };
        if flight.pending != Some(id) {
            return Err(Error::State);
        }
        flight.pending = None;
        Ok(())
    }
    pub(super) fn progress_fragments(&mut self, io: &mut impl Io) -> Result<(), Error> {
        self.prepare_fragment_management(io)?;
        if self.fragment_wait.is_some() {
            return Ok(());
        }
        let Some(flight) = self.fragment_tx.as_mut() else {
            return Ok(());
        };
        if flight.train.complete() {
            self.fragment_tx = None;
            return Ok(());
        }
        if flight.pending.is_some()
            || !self.pending.is_empty()
            || !io.packet_ready()
            || !self.rx_idle
            || self.delivered_reply.is_some()
        {
            return Ok(());
        }
        // Prepared but unissued data may not outlive a new closed controlled
        // port. An already-started original MSDU drains before serialized M2/M4,
        // while the original old key identity remains installed/current.
        if !flight.started
            && flight.kind == Kind::Data
            && self.security.as_ref().is_some_and(|s| !s.port_open())
        {
            self.fragment_tx = None;
            return Ok(());
        }
        let part = flight.train.next().ok_or(Error::State)?;
        let id = match io.packet_submit_fragment(&part, flight.kind != Kind::Data) {
            Ok(id) => id,
            Err(packet::Error::Busy) => return Ok(()),
            Err(error) => return Err(Error::Transport(error)),
        };
        flight.pending = Some(id);
        flight.started = true;
        self.pending.push_back(Pending {
            id,
            bytes: part.bytes().to_vec(),
            kind: flight.kind,
            agg: false,
        });
        Ok(())
    }
}
