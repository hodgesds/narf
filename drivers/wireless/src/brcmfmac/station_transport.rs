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
        })
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
            self.tx.remove(index);
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
        if self.peer.is_none() || self.closing {
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
        if self.peer.is_none() || self.closing {
            return None;
        }
        self.inner.as_mut()?.pop_received()
    }
    fn send_data(&mut self, frame: &[u8], priority: u8) -> Result<(), Error> {
        if self.failed || self.peer.is_none() {
            return Err(Error::Failed);
        }
        if self.closing {
            return Err(Error::Busy);
        }
        if frame.len() < 14 || priority > 7 {
            return Err(Error::Malformed);
        }
        let inner = self.inner.as_mut().ok_or(Error::Failed)?;
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
            let token = match inner.open_flow(source, destination, priority) {
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
        let id = inner
            .send_with_priority(token, frame, priority)
            .map_err(map)?;
        self.tx.push(Tx {
            id,
            deadline: narf_time::Deadline::after_ms(2000),
        });
        Ok(())
    }
    fn set_link(&mut self, peer: Option<[u8; 6]>) {
        if self.peer == peer {
            return;
        }
        if self.peer.is_some() {
            self.closing = true;
        }
        self.peer = peer;
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
