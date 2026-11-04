// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained B clock-gated transition, with independent actual native receipts.
//! A dropped operation leaves a closed transition in this same owner. Neither
//! a metadata preference nor a copied wake bit reopens ordinary publication.
use super::{
    lps_packets::{Namespace, Packets, Stage},
    lps_wire::{self, Profile},
    power,
    station_control::{Admission, Peer},
};
use alloc::vec::Vec;
use narf_net::native_emission::Lifetime;
#[derive(Clone)]
pub(super) struct Binding {
    peer: Peer,
    admission: Admission,
    identity: Lifetime,
    association: u64,
}
impl Binding {
    pub(super) fn new(
        peer: Peer,
        admission: Admission,
        identity: Lifetime,
        association: u64,
    ) -> Result<Self, power::Error> {
        let value = Self {
            peer,
            admission,
            identity,
            association,
        };
        value.current()?;
        Ok(value)
    }
    /// Fixed denial checks only; the native adapter separately invokes the
    /// original actual device/FW/full measured joint program at each access.
    pub(super) fn matches_peer(&self, peer: &Peer) -> bool {
        self.peer.same(peer)
    }
    pub(super) fn current(&self) -> Result<(), power::Error> {
        self.admission.check()?;
        self.peer.current()?;
        if self.association == 0 || !self.identity.current() {
            return Err(power::Error::Access);
        }
        Ok(())
    }
    pub(super) fn run<T>(
        &self,
        operation: impl FnOnce() -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        self.current()?;
        self.admission.run(|| {
            self.current()?;
            operation()
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Installing,
    Active,
    Entering,
    Deep,
    Leaving,
    Restoring,
    Deleting,
    Removed,
    Terminal,
}
/// # Safety
/// One original physical Native/verified WCPU/peer owns all operations. Every
/// register transaction and actual H2C/doorbell invokes that current device,
/// exact joint measured LPS program and Binding, including after waits. Idle
/// must test real packet/command ownership and a completed native RX prefix.
/// Packet commands return only after actual DONE, DMA retirement and a fresh
/// independent exact id/op C2H. No callback/provider lookup runs under State.
/// Cleanup after binding loss is a nonemitting current-device physical reset;
/// it never uses this interface to emit an unauthorized NULL wake/leave.
pub(super) unsafe trait Io: Send {
    fn current(&mut self, binding: &Binding) -> Result<(), power::Error>;
    fn block(&mut self, blocked: bool);
    fn coex(
        &mut self,
        binding: &Binding,
        enter: bool,
    ) -> impl core::future::Future<Output = Result<(), power::Error>> + Send;
    fn reset(&mut self) -> impl core::future::Future<Output = Result<(), power::Error>> + Send;
    fn pending(&mut self, binding: &Binding) -> Result<bool, power::Error>;
    fn idle(&mut self, binding: &Binding) -> Result<bool, power::Error>;
    fn packet(
        &mut self,
        binding: &Binding,
        body: &[u8],
        id: u8,
        operation: u8,
    ) -> impl core::future::Future<Output = Result<Vec<u8>, power::Error>> + Send;
    fn command(
        &mut self,
        binding: &Binding,
        class: u8,
        function: u8,
        body: &[u8],
        done: bool,
    ) -> impl core::future::Future<Output = Result<(), power::Error>> + Send;
    fn read16(&mut self, binding: &Binding, address: u32) -> Result<u16, power::Error>;
    fn read32(&mut self, binding: &Binding, address: u32) -> Result<u32, power::Error>;
    fn write16(&mut self, binding: &Binding, address: u32, value: u16) -> Result<(), power::Error>;
    fn now_us(&self) -> u64;
    fn delay_us(&mut self, us: u64) -> impl core::future::Future<Output = ()> + Send;
    /// Actual source PHY environment/PHYSTS restoration, only after CPWM
    /// Active. No ordinary TX/BB tracking is released by this method alone.
    fn restore(&mut self, binding: &Binding) -> Result<(), power::Error>;
}
pub(super) struct Owner {
    binding: Binding,
    packets: Packets,
    profile: Profile,
    phase: Phase,
}
impl Owner {
    /// The namespace belongs to this same verified physical WCPU. Constructor
    /// grants no RF permission and retains metadata before any awaited ADD.
    pub(super) fn prepare(
        namespace: &mut Namespace,
        profile: Profile,
        binding: Binding,
        aid: u16,
        wmm: bool,
    ) -> Result<Self, power::Error> {
        binding.current()?;
        if Profile::for_version(profile.version) != Some(profile) {
            return Err(power::Error::Unsupported);
        }
        let packets = namespace
            .reserve(binding.peer.clone(), binding.association, aid, wmm)
            .map_err(|_| power::Error::Terminal)?;
        Ok(Self {
            binding,
            packets,
            profile,
            phase: Phase::Installing,
        })
    }
    pub(super) fn phase(&self) -> Phase {
        self.phase
    }
    pub(super) fn current(&self) -> Result<(), power::Error> {
        self.binding.current()
    }
    pub(super) fn active(&self) -> bool {
        self.phase == Phase::Active && self.current().is_ok()
    }
    pub(super) fn terminal(&mut self) {
        self.phase = Phase::Terminal;
        self.packets.uncertain();
    }
    /// Receipt bookkeeping is retained here while the actual command queue
    /// retains every possibly published DMA object on cancellation/error.
    pub(super) async fn install(&mut self, io: &mut impl Io) -> Result<(), power::Error> {
        if self.phase != Phase::Installing {
            return Err(power::Error::Terminal);
        }
        while matches!(self.packets.stage(), Stage::Add(_)) {
            io.current(&self.binding)?;
            let body = self
                .packets
                .begin_add()
                .map_err(|_| power::Error::Terminal)?;
            let (id, op) = self.packets.pending().ok_or(power::Error::Terminal)?;
            let response = io.packet(&self.binding, &body, id, op).await?;
            self.packets
                .command_done(id, op)
                .map_err(|_| power::Error::Terminal)?;
            if !self
                .packets
                .response(&response)
                .map_err(|_| power::Error::Terminal)?
            {
                return Err(power::Error::Access);
            }
        }
        let body = self.packets.general().map_err(|_| power::Error::Terminal)?;
        io.command(&self.binding, 0, 1, &body, true).await?;
        io.current(&self.binding)?;
        self.packets
            .general_done(body)
            .map_err(|_| power::Error::Terminal)?;
        self.phase = Phase::Active;
        Ok(())
    }
    pub(super) async fn enter(&mut self, io: &mut impl Io) -> Result<bool, power::Error> {
        if !self.active() || !self.packets.ready() {
            return Err(power::Error::Terminal);
        }
        if !io.idle(&self.binding)? {
            return Ok(false);
        }
        self.phase = Phase::Entering; // closed BEFORE any actual command/wait
        io.coex(&self.binding, true).await?;
        // The real awaited OFF policy may have copied deauth/rekey/data.
        // Restore only nonemitting coexistence state and defer to the normal
        // host controller before granting any autonomous ENTER emission.
        if !io.idle(&self.binding)? {
            io.coex(&self.binding, false).await?;
            io.current(&self.binding)?;
            self.phase = Phase::Active;
            return Ok(false);
        }
        match io
            .command(&self.binding, 2, 0, &lps_wire::parameters(true), false)
            .await
        {
            Ok(()) => {}
            Err(power::Error::Busy) => {
                // Adapter proves no descriptor/doorbell publication occurred.
                // Restore only current nonemitting coex state, then let the
                // original host controller process the captured input first.
                io.coex(&self.binding, false).await?;
                io.current(&self.binding)?;
                self.phase = Phase::Active;
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        self.change(io, self.profile.deep.state()).await?;
        io.current(&self.binding)?;
        self.phase = Phase::Deep;
        Ok(true)
    }
    pub(super) async fn wake(&mut self, io: &mut impl Io) -> Result<(), power::Error> {
        if self.phase == Phase::Active {
            return io.current(&self.binding);
        }
        if self.phase != Phase::Deep {
            return Err(power::Error::Terminal);
        }
        self.phase = Phase::Leaving;
        self.change(io, 0).await?;
        self.phase = Phase::Restoring;
        io.restore(&self.binding)?;
        io.command(
            &self.binding,
            2,
            0,
            &lps_wire::parameters(false),
            self.profile.leave_done_ack(),
        )
        .await?;
        let start = io.now_us();
        loop {
            io.current(&self.binding)?;
            let status = io.read32(&self.binding, 0xca0c)?;
            if status == u32::MAX {
                return Err(power::Error::Gone);
            }
            if status & 0xe == 0 {
                break;
            }
            if io.now_us().saturating_sub(start) >= 50_000 {
                return Err(power::Error::Timeout);
            }
            io.delay_us(1000).await;
        }
        io.coex(&self.binding, false).await?;
        io.current(&self.binding)?;
        self.phase = Phase::Active;
        Ok(())
    }
    async fn change(&mut self, io: &mut impl Io, state: u8) -> Result<(), power::Error> {
        for _ in 0..3 {
            io.current(&self.binding)?;
            let old = io.read16(&self.binding, 0x1e4)?;
            if old == u16::MAX {
                return Err(power::Error::Gone);
            }
            let request = self
                .packets
                .prepare_rpwm(old, state)
                .ok_or(power::Error::Terminal)?;
            io.write16(&self.binding, 0x10c0, request.wire)?;
            if !self.packets.rpwm_published(request) {
                return Err(power::Error::Terminal);
            }
            let start = io.now_us();
            loop {
                io.current(&self.binding)?;
                let ldm = io.read32(&self.binding, 0x1e8)?;
                if ldm == u32::MAX {
                    return Err(power::Error::Gone);
                }
                // Deep requires only LDM. Avoid unpowered CPWM/BB access.
                let cpwm = if state >= 5 {
                    0
                } else {
                    io.read16(&self.binding, 0x8170)?
                };
                if self.packets.cpwm_completed(request, ldm, cpwm) {
                    return Ok(());
                }
                if io.now_us().saturating_sub(start) >= 15_000 {
                    break;
                }
                io.delay_us(if state >= 5 { 10 } else { 150 }).await;
            }
        }
        Err(power::Error::Timeout)
    }
    /// Only called after actual awake/leave receipts. A dead binding cannot
    /// use this emitting H2C path; it requires physical reset instead.
    pub(super) async fn remove(&mut self, io: &mut impl Io) -> Result<(), power::Error> {
        if !self.active() {
            return Err(power::Error::Terminal);
        }
        io.current(&self.binding)?;
        self.phase = Phase::Deleting;
        self.packets.begin_retire();
        while matches!(self.packets.stage(), Stage::Delete(_)) {
            let body = self
                .packets
                .begin_delete()
                .map_err(|_| power::Error::Terminal)?;
            let (id, op) = self.packets.pending().ok_or(power::Error::Terminal)?;
            let response = io.packet(&self.binding, &body, id, op).await?;
            self.packets
                .command_done(id, op)
                .map_err(|_| power::Error::Terminal)?;
            if !self
                .packets
                .response(&response)
                .map_err(|_| power::Error::Terminal)?
            {
                return Err(power::Error::Access);
            }
        }
        io.current(&self.binding)?;
        self.phase = Phase::Removed;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "lps_tests.rs"]
pub(super) mod tests;

/// Retained runtime wrapper shared by the actual Startup and source model.
/// Original firmware namespace/receipts survive dropped service futures.
pub(super) struct Intent {
    pub identity: Option<Lifetime>,
    pub enabled: bool,
    pub idle: bool,
    pub force: bool,
}
pub(super) struct Manager {
    namespace: Namespace,
    profile: Profile,
    owner: Option<Owner>,
    association: u64,
    aid: Option<u16>,
}
impl Manager {
    pub(super) fn after_firmware(profile: Profile) -> Result<Self, power::Error> {
        if Profile::for_version(profile.version) != Some(profile) {
            return Err(power::Error::Unsupported);
        }
        Ok(Self {
            namespace: Namespace::after_firmware(1).ok_or(power::Error::Terminal)?,
            profile,
            owner: None,
            association: 0,
            aid: None,
        })
    }
    /// Caller has completed the same original physical controller commit.
    pub(super) fn committed(&mut self, aid: u16) -> Result<(), power::Error> {
        if self.owner.is_some() || !(1..=2007).contains(&aid) {
            return Err(power::Error::Terminal);
        }
        self.association = self
            .association
            .checked_add(1)
            .ok_or(power::Error::Terminal)?;
        self.aid = Some(aid);
        Ok(())
    }
    /// `rtw89_wow_leave_ps` precondition: no template owner, or one that
    /// is awake (`Active`); Deep or transitional sleep refuses the swap.
    pub(super) fn wow_ready(&self) -> bool {
        self.owner
            .as_ref()
            .is_none_or(|owner| owner.phase() == Phase::Active)
    }
    /// The image this namespace belonged to was replaced (WoW swap): its
    /// template ids are gone with it. The next image starts a new epoch;
    /// the committed association/AID stay so LPS may reinstall later.
    pub(super) fn wow_swapped(&mut self) -> Result<Namespace, power::Error> {
        if !self.wow_ready() {
            return Err(power::Error::Terminal);
        }
        self.owner = None;
        let wow = self.namespace.next().ok_or(power::Error::Terminal)?;
        self.namespace = wow.next().ok_or(power::Error::Terminal)?;
        Ok(wow)
    }
    pub(super) fn has_owner(&self) -> bool {
        self.owner.is_some()
    }
    pub(super) async fn service(
        &mut self,
        io: &mut impl Io,
        peer: Option<Peer>,
        admission: &Admission,
        intent: Intent,
    ) -> Result<(bool, bool), power::Error> {
        let Intent {
            identity,
            enabled,
            idle,
            mut force,
        } = intent;
        if self.owner.is_none() {
            if !enabled || !idle || force || self.aid.is_none() {
                return Ok((false, false));
            }
            let Some(identity) = identity.filter(Lifetime::current) else {
                return Ok((false, false));
            };
            let binding = Binding::new(
                peer.ok_or(power::Error::Terminal)?,
                admission.clone(),
                identity,
                self.association,
            )?;
            let wmm = binding.peer.qos_ready();
            self.owner = Some(Owner::prepare(
                &mut self.namespace,
                self.profile,
                binding,
                self.aid.ok_or(power::Error::Terminal)?,
                wmm,
            )?);
            io.block(true);
            let result = self
                .owner
                .as_mut()
                .ok_or(power::Error::Terminal)?
                .install(io)
                .await;
            if result.is_err() {
                let _ = io.reset().await;
                return result.map(|_| (false, false));
            }
            io.block(false);
        }
        let owner = self.owner.as_mut().ok_or(power::Error::Terminal)?;
        if owner.current().is_err()
            || io.current(&owner.binding).is_err()
            || !matches!(owner.phase(), Phase::Active | Phase::Deep)
        {
            owner.terminal();
            let _ = io.reset().await;
            return Err(power::Error::Terminal);
        }
        match io.pending(&owner.binding) {
            Ok(pending) => force |= pending,
            Err(error) => {
                owner.terminal();
                let _ = io.reset().await;
                return Err(error);
            }
        }
        let mut restored = false;
        if owner.phase() == Phase::Deep {
            if enabled && idle && !force {
                return Ok((true, false));
            }
            io.block(true);
            if let Err(error) = owner.wake(io).await {
                owner.terminal();
                let _ = io.reset().await;
                return Err(error);
            }
            io.block(false);
            restored = true;
        }
        if enabled && idle && !force {
            io.block(true);
            match owner.enter(io).await {
                Ok(true) => return Ok((true, restored)),
                Ok(false) => io.block(false),
                Err(error) => {
                    owner.terminal();
                    let _ = io.reset().await;
                    return Err(error);
                }
            }
        }
        Ok((false, restored))
    }
}
