//! Native CNM token/grant ownership (next role-owner batch).
//! The owner records firmware observations only. Actual PCI, RF policy,
//! current interface/request and native packet retirement remain separate.
use super::{
    firmware_transport::Error,
    p2p_wire::{Kind, Request},
};

#[derive(Debug)]
pub(super) struct Cnm {
    /// Linux's PHY-global opaque u8 token includes zero. Only one request
    /// may be outstanding; successful terminal-grant/finite-expiry/packet
    /// retirement permits recycling. Uncertain work retains its lease until
    /// actual verified MAC reset, never a host cancellation or timeout.
    next: u8,
    owner: Option<Lease>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Acquiring,
    Granted { interval_ms: u32, expires_ns: u64 },
    Aborting,
}
#[derive(Debug)]
pub(super) struct Lease {
    pub request: Request,
    pub phase: Phase,
    pub cookie: u64,
    pub frequency_mhz: u32,
}
impl Default for Cnm {
    fn default() -> Self {
        Self {
            next: 1,
            owner: None,
        }
    }
}
impl Cnm {
    pub(super) fn from_next(next: u8) -> Self {
        Self { next, owner: None }
    }
    pub(super) fn next_token(&self) -> u8 {
        self.next
    }
    pub fn pending(&self) -> bool {
        self.owner.is_some()
    }
    pub fn lease(&self) -> Option<&Lease> {
        self.owner.as_ref()
    }
    pub fn reserve(
        &mut self,
        bss: u8,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
        kind: Kind,
    ) -> Result<Request, Error> {
        if self.owner.is_some() {
            return Err(Error::Busy);
        }
        if cookie == 0 {
            return Err(Error::Bounds);
        }
        let token = self.next;
        let request = Request::new(bss, token, frequency_mhz, duration_ms, kind)?;
        self.next = self.next.wrapping_add(1);
        // Reservation precedes the first acquire publication. A dropped
        // caller cannot erase an uncertain command or give its token back.
        self.owner = Some(Lease {
            request,
            phase: Phase::Acquiring,
            cookie,
            frequency_mhz,
        });
        Ok(request)
    }
    pub fn grant(&mut self, payload: &[u8], now_ns: u64) -> Result<u32, Error> {
        let owner = self.owner.as_mut().ok_or(Error::Busy)?;
        if owner.phase != Phase::Acquiring {
            return Err(Error::MalformedEvent);
        }
        let interval_ms = owner.request.grant(payload)?;
        let expires_ns = now_ns
            .checked_add(u64::from(interval_ms) * 1_000_000)
            .ok_or(Error::Bounds)?;
        // Linux starts roc_timer from the actual received grant and its
        // max_interval. No acquire-TX or local guessed interval supplies it.
        owner.phase = Phase::Granted {
            interval_ms,
            expires_ns,
        };
        Ok(interval_ms)
    }
    pub fn current(&self, cookie: u64, frequency_mhz: u32, now_ns: u64) -> bool {
        self.owner.as_ref().is_some_and(|owner| {
            owner.cookie == cookie
                && owner.frequency_mhz == frequency_mhz
                && matches!(owner.phase,Phase::Granted { expires_ns,.. } if now_ns<expires_ns)
        })
    }
    /// Return the exact original abort request and close host use before
    /// sending it. The no-response abort itself supplies no terminal lease.
    pub fn abort(&mut self, cookie: u64) -> Result<Request, Error> {
        let owner = self
            .owner
            .as_mut()
            .filter(|owner| owner.cookie == cookie)
            .ok_or(Error::Bounds)?;
        owner.phase = Phase::Aborting;
        Ok(owner.request)
    }
    /// The firmware-specified finite dwell is observed as elapsed. The
    /// native caller must still retire actual pending management packets
    /// and obtain the owned abort's native command-ordering receipt before
    /// releasing this lease/recycling tokens; this is no plaintext-FIFO fence.
    pub fn expired(&self, now_ns: u64) -> bool {
        self.owner.as_ref().is_some_and(
            |owner| matches!(owner.phase,Phase::Granted { expires_ns,.. } if now_ns>=expires_ns),
        )
    }
    pub fn release_expired_after_packets(&mut self, now_ns: u64) -> Result<Lease, Error> {
        if !self.expired(now_ns) {
            return Err(Error::Busy);
        }
        self.owner.take().ok_or(Error::Busy)
    }
    /// Only the verified MAC/FW reset and DMA retirement path calls this;
    /// an abort/host timeout/source close cannot create such a boundary.
    pub fn reset_after_verified_mac(&mut self) {
        self.owner = None;
        self.next = 1;
    }
}
