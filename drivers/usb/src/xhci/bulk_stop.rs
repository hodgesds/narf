//! One-shot cancellation of a retained non-stream bulk TD.
//! Intel xHCI1.2b§4.6.9–10: Stop transfers TD ownership, then Set TR Dequeue
//! invalidates cached transfer state. Neither Future Drop nor timeout does so.
//! https://cdrdv2-public.intel.com/625472/625472_xHCI_Rev1_2b.pdf
use super::bulk_owner::{StopIdentity, Token};
use core::future::Future;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    State,
    Pointer,
}
#[derive(Debug, Clone, Copy)]
pub(super) struct Context {
    pub state: u8,
    pub dequeue: u64,
}
#[derive(Debug)]
pub(super) struct Plan {
    pub identity: StopIdentity,
    pub ring: u64,
    pub entries: usize,
    pub enqueue: usize,
    pub cycle: u32,
}
impl Plan {
    pub fn new(
        identity: StopIdentity,
        ring: u64,
        entries: usize,
        enqueue: usize,
        cycle: u32,
    ) -> Result<Self, Error> {
        if ring == 0
            || ring & 15 != 0
            || !(2..=256).contains(&entries)
            || enqueue >= entries
            || cycle > 1
            || ring.checked_add(entries as u64 * 16).is_none()
        {
            return Err(Error::Pointer);
        }
        let (enqueue, cycle) = if enqueue == entries - 1 {
            (0, cycle ^ 1)
        } else {
            (enqueue, cycle)
        };
        Ok(Self {
            identity,
            ring,
            entries,
            enqueue,
            cycle,
        })
    }
    pub fn target(&self) -> u64 {
        (self.ring + self.enqueue as u64 * 16) | u64::from(self.cycle)
    }
    fn check_stopped(&self, ctx: Context) -> Result<(), Error> {
        if ctx.state != 3 {
            return Err(Error::State);
        }
        let pointer = ctx.dequeue & !15;
        if ctx.dequeue & 14 != 0
            || pointer < self.ring
            || pointer >= self.ring + self.entries as u64 * 16
        {
            return Err(Error::Pointer);
        }
        Ok(())
    }
    fn command(&self, kind: u32, dequeue: u64) -> [u32; 4] {
        [
            dequeue as u32,
            (dequeue >> 32) as u32,
            0,
            kind << 10 | u32::from(self.identity.slot) << 24 | u32::from(self.identity.dci) << 16,
        ]
    }
}
pub(super) trait Bus: Sync {
    type Error: From<Error>;
    /// Claims slot configuration and endpoint ownership before any command;
    /// no error/Drop path may release the claim or reuse its persistent page.
    fn claim(&self, token: &Token) -> Result<Plan, Self::Error>;
    /// Must match exact command TRB AND slot, and accept only Success CCE.
    /// Demux pop→latch publication must be serialized so CCE visibility also
    /// proves preceding forced Transfer Events have entered quarantine.
    fn command(&self, words: [u32; 4]) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn context(&self, plan: &Plan) -> Result<Context, Self::Error>;
    fn purge_events(&self, plan: &Plan) -> Result<(), Self::Error>;
    fn commit(&self, plan: Plan) -> Result<(), Self::Error>;
}
/// On every cancellation/error the retained bus claim remains closed. This
/// profile does not recover Halted endpoints or reset a USB device data toggle.
pub(super) async fn run<B: Bus>(bus: &B, token: &Token) -> Result<(), B::Error> {
    let plan = bus.claim(token)?;
    if bus.context(&plan)?.state != 1 {
        return Err(Error::State.into());
    }
    bus.command(plan.command(15, 0)).await?;
    plan.check_stopped(bus.context(&plan)?)?;
    bus.command(plan.command(16, plan.target())).await?;
    let context = bus.context(&plan)?;
    plan.check_stopped(context)?;
    if context.dequeue != plan.target() {
        return Err(Error::Pointer.into());
    }
    bus.purge_events(&plan)?;
    bus.commit(plan)
}
#[cfg(feature = "kernel-test")]
#[path = "bulk_stop_tests.rs"]
mod tests;
