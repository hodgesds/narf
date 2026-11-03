// SPDX-License-Identifier: GPL-2.0-or-later
//! Owned msgbuf adapter for the common FullMAC station lifecycle. Events are
//! decoded from actual posted DMA replies; there are no synthetic credits/ACKs.
use crate::{
    brcmfmac::runtime::{self, Bus, FlowState, FlowToken},
    cyw43439::{
        events,
        fullmac::{Family, Fullmac},
        ioctl::Direction,
        runtime::{Error, Event},
        station::wmm,
    },
};
use alloc::{collections::VecDeque, vec::Vec};
struct Flow {
    source: [u8; 6],
    destination: [u8; 6],
    priority: u8,
    token: FlowToken,
}
struct Tx {
    id: u32,
    deadline: narf_time::Deadline,
    ap_terminal: Option<alloc::sync::Weak<super::ap_tx::Terminal>>,
}
/// Retained firmware authority of one function: downloads and attaches a
/// fresh generation on a reset, halted bus (signed selection and assets are
/// re-verified on every call). A refused download returns the bus when the
/// boot owner kept it.
pub trait Reboot<B: Bus>: Send {
    fn boot(&mut self, bus: B) -> Result<runtime::Runtime<B>, (runtime::Error, Option<B>)>;
}
pub struct Adapter<B: Bus> {
    /// The current firmware generation. `None` once a teardown or reset
    /// released it; a reset installs the rebooted generation here.
    inner: Option<runtime::Runtime<B>>,
    events: VecDeque<Event>,
    flows: Vec<Flow>,
    tx: Vec<Tx>,
    peer: Option<[u8; 6]>,
    closing: bool,
    failed: bool,
    reboot: Option<alloc::boxed::Box<dyn Reboot<B>>>,
    /// A reset bus whose last download was refused, kept for a retry.
    parked: Option<B>,
    ap: Option<alloc::boxed::Box<super::ap_tx::Owner>>,
}
impl<B: Bus> core::fmt::Debug for Adapter<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MsgbufStationTransport")
            .field("peer", &self.peer)
            .field("closing", &self.closing)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
impl<B: Bus + Send> Adapter<B>
where
    B::Memory: Send,
{
    pub fn new(mut inner: runtime::Runtime<B>) -> Result<Self, Error> {
        match inner.enable_data() {
            Ok(()) | Err(runtime::Error::Busy) => {}
            Err(e) => return Err(map(e)),
        }
        Ok(Self {
            inner: Some(inner),
            events: VecDeque::new(),
            flows: Vec::new(),
            tx: Vec::new(),
            peer: None,
            closing: false,
            failed: false,
            reboot: None,
            parked: None,
            ap: None,
        })
    }
    /// Retain the firmware authority that a transport reset reboots with.
    pub fn with_reboot(mut self, reboot: alloc::boxed::Box<dyn Reboot<B>>) -> Self {
        self.reboot = Some(reboot);
        self
    }
    /// The current firmware generation, if one is attached.
    pub fn runtime(&self) -> Option<&runtime::Runtime<B>> {
        self.inner.as_ref()
    }
    fn progress(&mut self) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let inner = self.inner.as_mut().ok_or(Error::Failed)?;
        let count = inner.poll().map_err(map)?;
        for _ in 0..32 {
            let Some(bytes) = inner.pop_event() else {
                break;
            };
            let event = events::parse_event(&bytes).map_err(|_| Error::Malformed)?;
            if event.header.if_idx != 0 || event.header.bsscfg_idx != 0 || self.events.len() == 32 {
                return Err(Error::EventOverflow);
            }
            self.events.push_back(Event {
                header: event.header,
                payload: event.payload.to_vec(),
            });
        }
        while let Some(receipt) = inner.pop_tx_receipt() {
            let index = self
                .tx
                .iter()
                .position(|tx| tx.id == receipt.id)
                .ok_or(Error::Malformed)?;
            let tx = self.tx.remove(index);
            if let Some(terminal) = tx.ap_terminal.and_then(|weak| weak.upgrade()) {
                terminal.complete(receipt);
            }
        }
        if self.tx.iter().any(|tx| tx.deadline.expired()) {
            return Err(Error::Timeout);
        }
        // Delete ACK is the firmware ownership fence. Drop the old host token
        // before its retained hardware slot can be reopened with a generation.
        let mut index = 0;
        while index < self.flows.len() {
            if inner.flow_state(self.flows[index].token).map_err(map)? == FlowState::Closed {
                self.flows.remove(index);
            } else {
                index += 1;
            }
        }
        if self.closing {
            let mut closed = true;
            for flow in &self.flows {
                match inner.flow_state(flow.token).map_err(map)? {
                    FlowState::Open => {
                        closed = false;
                        match inner.close_flow(flow.token) {
                            Ok(()) | Err(runtime::Error::Busy) => {}
                            Err(e) => return Err(map(e)),
                        }
                    }
                    FlowState::Closed => {}
                    FlowState::Creating | FlowState::Deleting => closed = false,
                }
            }
            if closed {
                self.flows.clear();
                self.closing = false;
            }
        }
        if self.peer.is_none() && self.ap.is_none() || self.closing {
            while inner.pop_received().is_some() {}
        }
        Ok(count)
    }
}
impl<B: Bus + Send> Fullmac for Adapter<B>
where
    B::Memory: Send,
{
    const FAMILY: Family = Family::Pcie;
    // BCM43602 Linux BRCMF_FW_DEF firmware embeds CLM; external CLM isn't
    // required for this exact chip profile. Valid channels still intersect
    // authenticated host policy before station publication.
    const EXTERNAL_CLM: bool = false;
    const BAND_5GHZ: bool = true;
    const VHT80: bool = true;
    // This native adapter belongs to the admitted BCM43602 PCIe profile;
    // publication additionally requires its actual retained physical source.
    const PRIMARY_AP: bool = true;
    const PRIMARY_MONITOR: bool = true;
    fn ap_source(&self) -> Option<super::ap_source::Source> {
        self.inner.as_ref()?.ap_source()
    }
    fn monitor_reserve(&mut self, prepared: super::monitor_native::Prepared) -> Result<(), Error> {
        if self.failed
            || self.closing
            || self.ap.is_some()
            || self.peer.is_some()
            || !self.flows.is_empty()
            || !self.tx.is_empty()
        {
            return Err(Error::Busy);
        }
        self.inner
            .as_mut()
            .ok_or(Error::Failed)?
            .monitor_reserve(prepared)
            .map_err(map)
    }
    fn monitor_arm(&mut self, armed: super::monitor_native::Armed) -> Result<(), Error> {
        self.inner
            .as_mut()
            .ok_or(Error::Failed)?
            .monitor_arm(armed)
            .map_err(map)
    }
    fn monitor_leave(&mut self, original: &super::monitor_scope::Capture) -> Result<(), Error> {
        self.inner
            .as_mut()
            .ok_or(Error::Failed)?
            .monitor_leave(original)
            .map_err(map)
    }
    fn pop_monitor(&mut self) -> Option<super::monitor_scope::Received> {
        self.inner.as_mut()?.pop_monitor()
    }
    fn monitor_control_idle(&mut self) -> Result<bool, Error> {
        if !self.events.is_empty() {
            return Ok(false);
        }
        self.inner
            .as_mut()
            .ok_or(Error::Failed)?
            .monitor_control_idle()
            .map_err(map)
    }
    fn ap_enter(&mut self, original: super::ap_scope::Capture) -> Result<(), Error> {
        if self
            .inner
            .as_ref()
            .is_some_and(|inner| inner.monitor_reserved())
        {
            return Err(Error::Busy);
        }
        if !original.lifecycle() {
            return Err(Error::Authority);
        }
        if self.failed
            || self.peer.is_some()
            || self.ap.is_some()
            || self.closing
            || !self.tx.is_empty()
            || !self.flows.is_empty()
        {
            return Err(Error::Busy);
        }
        let inner = self.inner.as_ref().ok_or(Error::Failed)?;
        if !inner.ap_owns(&original.native) {
            return Err(Error::Authority);
        }
        original.current().map_err(|_| Error::Authority)?;
        self.ap = Some(alloc::boxed::Box::new(super::ap_tx::Owner { original }));
        Ok(())
    }
    fn ap_send(
        &mut self,
        bytes: &[u8],
        priority: u8,
        original: &super::ap_scope::Capture,
    ) -> Result<super::ap_tx::Ticket, Error> {
        if !original.transmit(bytes) {
            return Err(Error::Authority);
        }
        if self.failed || self.closing {
            return Err(Error::Failed);
        }
        self.ap
            .as_ref()
            .ok_or(Error::Unsupported)?
            .admits(original)?;
        if !self
            .inner
            .as_ref()
            .ok_or(Error::Failed)?
            .ap_owns(&original.native)
        {
            return Err(Error::Authority);
        }
        // Retain this exact original before consuming native input. An
        // actual event must be applied by the AP owner before any flow/TX
        // publication; it cannot be hidden behind a positive poll budget.
        // A bounded unfinished prefix defers, never invents an Idle receipt.
        let mut idle = false;
        for _ in 0..4 {
            if !self.events.is_empty() {
                return Err(Error::Busy);
            }
            let progress = self.progress()?;
            if !self.events.is_empty() {
                return Err(Error::Busy);
            }
            if progress == 0
                && self
                    .inner
                    .as_mut()
                    .ok_or(Error::Failed)?
                    .ap_completed_idle()
                    .map_err(map)?
            {
                idle = true;
                break;
            }
        }
        if !idle {
            return Err(Error::Busy);
        }
        self.ap.as_ref().ok_or(Error::Failed)?.admits(original)?;
        let id = self.begin_data(bytes, priority, Some(original))?;
        let (ticket, terminal) = super::ap_tx::Ticket::new(id, original.clone());
        self.tx
            .iter_mut()
            .find(|tx| tx.id == id)
            .ok_or(Error::Failed)?
            .ap_terminal = Some(terminal);
        Ok(ticket)
    }
    fn ap_leave(&mut self) -> Result<bool, Error> {
        if self.ap.is_none() {
            return Ok(true);
        }
        self.closing = true;
        self.progress()?;
        if self.closing || !self.tx.is_empty() || !self.flows.is_empty() {
            return Ok(false);
        }
        self.ap = None;
        Ok(true)
    }
    fn ap_completed_prefix(&mut self) -> Result<bool, Error> {
        if !self.events.is_empty() {
            return Ok(false);
        }
        self.inner
            .as_mut()
            .ok_or(Error::Failed)?
            .ap_completed_idle()
            .map_err(map)
    }
    fn ap_quiet(&mut self) -> Result<bool, Error> {
        if self.ap.is_none() {
            return Err(Error::Unsupported);
        }
        self.progress()?;
        if !self.events.is_empty() {
            return Ok(false);
        }
        Ok(self.tx.is_empty()
            && self
                .inner
                .as_mut()
                .ok_or(Error::Failed)?
                .ap_completed_idle()
                .map_err(map)?)
    }
    fn ap_retire_peer(&mut self, peer: [u8; 6]) -> Result<bool, Error> {
        if self.ap.is_none() || !super::ap_wire::unicast(peer) {
            return Err(Error::Unsupported);
        }
        self.progress()?;
        let inner = self.inner.as_mut().ok_or(Error::Failed)?;
        let mut pending = false;
        for flow in self.flows.iter().filter(|flow| flow.destination == peer) {
            match inner.flow_state(flow.token).map_err(map)? {
                FlowState::Open => {
                    pending = true;
                    match inner.close_flow(flow.token) {
                        Ok(()) | Err(runtime::Error::Busy) => {}
                        Err(error) => return Err(map(error)),
                    }
                }
                FlowState::Creating | FlowState::Deleting => pending = true,
                FlowState::Closed => {}
            }
        }
        // The retained flow cache removes Closed only after its correlated
        // native completion. Refused DELETE now fail-stops rather than
        // granting a false success/reuse fence (independent baseline repair).
        Ok(!pending
            && !self.flows.iter().any(|flow| flow.destination == peer)
            && inner.ap_completed_idle().map_err(map)?)
    }
    async fn command_ap<'a>(
        &'a mut self,
        original: &'a super::ap_scope::Capture,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if direction == Direction::Set {
            let mut idle = false;
            for _ in 0..4 {
                let progress = self.progress()?;
                if self
                    .events
                    .iter()
                    .any(|event| original.program_event_blocks(&event.header))
                {
                    return Err(Error::Busy);
                }
                if progress == 0
                    && self
                        .inner
                        .as_mut()
                        .ok_or(Error::Failed)?
                        .ap_completed_idle()
                        .map_err(map)?
                {
                    idle = true;
                    break;
                }
            }
            if !idle {
                return Err(Error::Busy);
            }
        }
        let extent = if direction == Direction::Set {
            input.len()
        } else {
            maximum
        };
        let mut response = self
            .inner
            .as_mut()
            .ok_or(Error::Failed)?
            .command_ap(
                command,
                input,
                extent,
                original,
                direction == Direction::Set,
            )
            .await
            .map_err(map)?;
        if direction == Direction::Set {
            response.clear();
        } else {
            response.truncate(maximum);
        }
        Ok(response)
    }
    async fn command<'a>(
        &'a mut self,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let extent = if direction == Direction::Set {
            input.len()
        } else {
            maximum
        };
        let mut response = self
            .inner
            .as_mut()
            .ok_or(Error::Failed)?
            .command(command, input, extent)
            .await
            .map_err(map)?;
        if direction == Direction::Set {
            response.clear();
        } else {
            // The physical IOCTL extent may include a longer iovar name.
            // Linux fwil copies only the caller's requested query length.
            response.truncate(maximum);
        }
        Ok(response)
    }
    async fn configure_bus(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn wake_source(&self) -> Option<(alloc::sync::Arc<crate::brcmfmac::irq::Signal>, bool)> {
        self.inner.as_ref().map(|inner| inner.interrupt())
    }
    /// `brcmf_cfg80211_suspend` (no WoWL) has already brought the link down;
    /// retire every flow and TX completion, then `brcmf_pcie_pm_enter_D3`.
    /// A timeout leaves the transport usable so the suspend unwinds.
    async fn suspend_transport(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        self.set_link(None);
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            self.poll()?;
            if self.flows.is_empty() && self.tx.is_empty() && !self.closing {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        self.inner
            .as_mut()
            .ok_or(Error::Failed)?
            .enter_d3()
            .await
            .map_err(map)
    }
    /// `brcmf_pcie_pm_leave_D3`: hot resume, or a terminal owner when the
    /// dongle lost power/firmware (Linux re-probes; NARF needs a transport
    /// reset, see `brcmfmac.md`).
    async fn resume_transport(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let Some(inner) = self.inner.as_mut() else {
            return Err(Error::Failed);
        };
        match inner.leave_d3().await {
            Ok(()) => Ok(()),
            // Not suspended: nothing to resume, the transport stays usable.
            Err(runtime::Error::Busy) => Err(Error::Busy),
            Err(error) => {
                self.fail();
                Err(map(error))
            }
        }
    }
    /// Linux v7.2 `brcmf_pcie_remove`/`brcmf_pcie_reset` stop the device
    /// before `brcmf_pcie_release_ringbuffers`. Here the stop is the
    /// confirmed-stop proof (`Runtime::quiesce`, `brcmfmac.md` "Confirmed
    /// stop and DMA reclamation"); the generation never resumes either way.
    async fn stop_transport(&mut self) -> Result<(), Error> {
        self.peer = None;
        self.closing = false;
        self.flows.clear();
        self.tx.clear();
        self.events.clear();
        self.failed = true;
        let inner = self.inner.as_mut().ok_or(Error::Failed)?;
        if inner.is_reclaimable() {
            return Ok(());
        }
        // A live generation acknowledges D3. A halted or terminal one (or
        // one whose ack never came) takes the dead-firmware stop; a proof
        // that observed device activity after the BME clear never does.
        let confirmed = if inner.is_failed() {
            Err(runtime::Error::Failed)
        } else {
            inner.quiesce().await.map(|_| ())
        };
        match confirmed {
            Ok(()) => Ok(()),
            Err(runtime::Error::Failed | runtime::Error::Timeout) => {
                inner.stop_dead().await.map(|_| ()).map_err(map)
            }
            Err(error) => Err(map(error)),
        }
    }
    /// Linux v7.2 `pcie.c::brcmf_pcie_reset` after the stop proof:
    /// `brcmf_pcie_reset_device`, release of every ring and buffer, then a
    /// fresh download (`brcmf_pcie_setup`) through the retained authority.
    async fn reset_transport(&mut self) -> Result<(), Error> {
        if self.reboot.is_none() {
            return Err(Error::Unsupported);
        }
        let bus = match self.parked.take() {
            Some(bus) => bus,
            None => {
                let mut inner = self.inner.take().ok_or(Error::Failed)?;
                if !inner.is_reclaimable() {
                    self.inner = Some(inner);
                    return Err(Error::Busy);
                }
                if let Err(error) = inner.reset_device().await {
                    self.inner = Some(inner);
                    return Err(map(error));
                }
                inner.into_bus().map_err(|_| Error::Failed)?
            }
        };
        let reboot = self.reboot.as_mut().ok_or(Error::Unsupported)?;
        match reboot.boot(bus) {
            Ok(mut fresh) => {
                match fresh.enable_data() {
                    Ok(()) | Err(runtime::Error::Busy) => {}
                    Err(error) => return Err(map(error)),
                }
                self.inner = Some(fresh);
                self.events.clear();
                self.flows.clear();
                self.tx.clear();
                self.peer = None;
                self.closing = false;
                self.failed = false;
                Ok(())
            }
            Err((error, bus)) => {
                self.parked = bus;
                Err(map(error))
            }
        }
    }
    fn take_generation(&mut self) -> Option<Self> {
        if self.failed {
            return None;
        }
        let inner = self.inner.take()?;
        self.failed = true;
        Some(Self {
            inner: Some(inner),
            events: VecDeque::new(),
            flows: Vec::new(),
            tx: Vec::new(),
            peer: None,
            closing: false,
            failed: false,
            reboot: self.reboot.take(),
            parked: None,
            ap: None,
        })
    }
    fn transport_failed(&self) -> bool {
        self.failed || self.inner.as_ref().is_none_or(|inner| inner.is_failed())
    }
    fn release_transport(&mut self) -> bool {
        self.failed = true;
        self.peer = None;
        match self.inner.take() {
            // Drop frees every mapping only after a complete proof and
            // otherwise leaks them (`Runtime`'s `Drop`).
            Some(inner) => inner.is_reclaimable(),
            None => true,
        }
    }
    fn poll(&mut self) -> Result<usize, Error> {
        let result = self.progress();
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn fail(&mut self) {
        self.failed = true;
        self.peer = None;
        if let Some(inner) = self.inner.as_mut() {
            inner.fail();
        }
    }
    fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
    fn pop_data(&mut self) -> Option<Vec<u8>> {
        if self.peer.is_none() && self.ap.is_none() || self.closing {
            return None;
        }
        self.inner.as_mut()?.pop_received()
    }
    fn send_data(&mut self, frame: &[u8], priority: u8) -> Result<(), Error> {
        if self.failed || self.peer.is_none() || self.ap.is_some() {
            return Err(Error::Failed);
        }
        self.begin_data(frame, priority, None).map(|_| ())
    }
    fn set_link(&mut self, peer: Option<[u8; 6]>) {
        if self.ap.is_some()
            || self
                .inner
                .as_ref()
                .is_some_and(|inner| inner.monitor_reserved())
        {
            // A station lifecycle can never open/retag an actual AP owner.
            if peer.is_some() {
                self.fail();
            }
            return;
        }
        if self.peer == peer {
            return;
        }
        if self.peer.is_some() {
            self.closing = true;
        }
        self.peer = peer;
    }
}
impl<B: Bus + Send> Adapter<B>
where
    B::Memory: Send,
{
    fn begin_data(
        &mut self,
        frame: &[u8],
        priority: u8,
        original: Option<&super::ap_scope::Capture>,
    ) -> Result<u32, Error> {
        if self.closing {
            return Err(Error::Busy);
        }
        if frame.len() < 14 || priority > 7 {
            return Err(Error::Malformed);
        }
        let inner = self.inner.as_mut().ok_or(Error::Failed)?;
        if let Some(original) = original {
            original.current().map_err(|_| Error::Authority)?;
        }
        let source = frame[6..12].try_into().unwrap();
        let destination = frame[..6].try_into().unwrap();
        let token = if let Some(flow) = self.flows.iter().find(|f| {
            // Linux brcmf_flowring_lookup: a station keeps one flow per
            // FIFO; its firmware TID is the priority that created it.
            f.source == source
                && f.destination == destination
                && wmm::fifo(f.priority) == wmm::fifo(priority)
        }) {
            flow.token
        } else {
            let opened = if let Some(original) = original {
                original
                    .publish(|| inner.open_flow(source, destination, priority))
                    .map_err(|_| Error::Authority)?
            } else {
                inner.open_flow(source, destination, priority)
            };
            let token = match opened {
                Ok(token) => token,
                Err(runtime::Error::Exhausted) => {
                    // A bounded cache may evict an idle destination, but
                    // never recycle its firmware slot before delete ACK.
                    for flow in &self.flows {
                        if inner.flow_state(flow.token).map_err(map)? != FlowState::Open {
                            continue;
                        }
                        match inner.close_flow(flow.token) {
                            Ok(()) => return Err(Error::Busy),
                            Err(runtime::Error::Busy) => continue,
                            Err(error) => return Err(map(error)),
                        }
                    }
                    return Err(Error::Busy);
                }
                Err(error) => return Err(map(error)),
            };
            self.flows.push(Flow {
                source,
                destination,
                priority,
                token,
            });
            return Err(Error::Busy);
        };
        let published = if let Some(original) = original {
            original
                .publish(|| inner.send_with_priority(token, frame, priority))
                .map_err(|_| Error::Authority)?
        } else {
            inner.send_with_priority(token, frame, priority)
        };
        let id = published.map_err(map)?;
        self.tx.push(Tx {
            id,
            deadline: narf_time::Deadline::after_ms(2000),
            ap_terminal: None,
        });
        Ok(id)
    }
}
fn map(error: runtime::Error) -> Error {
    match error {
        runtime::Error::Busy => Error::Busy,
        runtime::Error::Bounds | runtime::Error::Protocol => Error::Malformed,
        runtime::Error::Timeout => Error::Timeout,
        runtime::Error::Firmware(status) => Error::Firmware(status as i32 as u32),
        _ => Error::Failed,
    }
}
