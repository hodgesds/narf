// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8821CE/RTL8822CE port0 and four-box mailbox, Linux rtw88.
//! A consumed mailbox is transport evidence, never an applied-command ACK.
//!
//! The register stream (own MAC, peer BSSID, media/AID fields, beacon
//! control, DCF defaults, port-idle poll) lives in
//! `narf-drivers-wireless-rtl-chip::station`, generic over `RegIo`, so the
//! builtin driver and the loadable `.ko` share the exact byte stream (as
//! `mac.rs` shares the MAC/FIFO core). This file keeps the admission gate,
//! the station-ownership checks and the H2C mailbox words, and interleaves
//! the sends between the core's register pieces.
use super::chip_bridge::{bridge, gated};
use super::firmware_transport::{Error, Io};
#[cfg(feature = "module")]
#[allow(unused_imports)]
use crate::rtw88::platform::narf_lib;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_drivers_wireless_rtl_chip::station as chip_station;
use narf_lib::sync::IrqSafeSpinLock;
#[derive(Clone)]
pub(super) struct Admission {
    closed: Arc<AtomicBool>,
    teardown: Arc<AtomicBool>,
    publication: Arc<IrqSafeSpinLock<()>>,
    receive_epoch: Arc<AtomicU64>,
}
#[derive(Clone)]
pub(super) struct ReceiveEpoch {
    epoch: Arc<AtomicU64>,
    value: u64,
    closed: Arc<AtomicBool>,
}
impl ReceiveEpoch {
    pub(super) fn current(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && self.epoch.load(Ordering::Acquire) == self.value
    }
}
/// Own the terminal disconnect across an awaited lifecycle lock/control path.
/// Cancellation clears only the reservation: publication stays closed, so a
/// later worker can finish native shutdown without reopening the station.
pub(super) struct Disconnect {
    admission: Admission,
}
impl Drop for Disconnect {
    fn drop(&mut self) {
        let _publication = self.admission.publication.lock();
        self.admission.teardown.store(false, Ordering::Release);
    }
}
impl Admission {
    pub(super) fn new() -> Self {
        Self {
            closed: Arc::new(AtomicBool::new(false)),
            teardown: Arc::new(AtomicBool::new(false)),
            publication: Arc::new(IrqSafeSpinLock::new(())),
            receive_epoch: Arc::new(AtomicU64::new(0)),
        }
    }
    pub(super) fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub(super) fn epoch(&self) -> ReceiveEpoch {
        ReceiveEpoch {
            epoch: self.receive_epoch.clone(),
            value: self.receive_epoch.load(Ordering::Acquire),
            closed: self.closed.clone(),
        }
    }
    pub(super) fn receive_generation(&self) -> u64 {
        self.receive_epoch.load(Ordering::Acquire)
    }
    /// Only native key/reply/close transitions retire receive admission.
    /// Ordinary TX credit and completion never change this generation.
    pub(super) fn retire_receive(&self) -> Result<(), Error> {
        if self
            .receive_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |e| e.checked_add(1))
            .is_err()
        {
            self.closed.store(true, Ordering::Release);
            return Err(Error::State);
        }
        Ok(())
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        if self.closed() {
            Err(Error::State)
        } else {
            Ok(())
        }
    }
    pub(super) fn run<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let _publication = self.publication.lock();
        self.check()?;
        operation()
    }
    pub(super) fn close(&self) {
        let _publication = self.publication.lock();
        self.closed.store(true, Ordering::Release);
        let _ = self.retire_receive();
    }
    pub(super) fn teardown_pending(&self) -> bool {
        self.teardown.load(Ordering::Acquire)
    }
    /// Call outside `run`, before awaiting the retained owner lock. A second
    /// pending disconnect cannot steal or clear the first one's reservation.
    pub(super) fn begin_disconnect(&self) -> Result<Disconnect, Error> {
        let _publication = self.publication.lock();
        if self.teardown.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        // Publish pending before closed. A worker that acquires closed=true
        // must also see this prior reservation and preserve native cleanup.
        self.teardown.store(true, Ordering::Release);
        self.closed.store(true, Ordering::Release);
        let _ = self.retire_receive();
        Ok(Disconnect {
            admission: self.clone(),
        })
    }
}
pub(super) async fn send(
    io: &mut impl Io,
    words: [u8; 8],
    admission: Option<&Admission>,
) -> Result<(), Error> {
    if let Some(a) = admission {
        a.check()?;
    }
    if admission.is_none() && io.mailbox_pending() {
        for attempt in 0..=30 {
            if io.mailbox_consumed().await? {
                break;
            }
            if attempt < 30 {
                io.delay_us(100).await;
            }
        }
        if io.mailbox_pending() {
            return Err(Error::Timeout);
        }
    }
    let mut ready = false;
    for attempt in 0..=30 {
        if io.mailbox_ready().await? {
            ready = true;
            break;
        }
        if attempt < 30 {
            io.delay_us(100).await;
        }
        if let Some(a) = admission {
            a.check()?;
        }
    }
    if !ready {
        return Err(Error::Timeout);
    }
    if let Some(a) = admission {
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            io.station_allowed()?;
            io.mailbox_submit(words).await
        })
        .await?;
    } else {
        io.mailbox_submit(words).await?;
    }
    for attempt in 0..=30 {
        if io.mailbox_consumed().await? {
            return Ok(());
        }
        if attempt < 30 {
            io.delay_us(100).await;
        }
        if let Some(a) = admission {
            a.check()?;
        }
    }
    Err(Error::Timeout)
}
/// DCF/WMM defaults for the `kernel-test` smokes: the register stream
/// lives in the chip core; this wrapper only adds the admission gate, so
/// the smoke drives the same gated path production uses.
#[cfg(any(test, feature = "kernel-test"))]
async fn configure_dcf(io: &mut impl Io, short: bool, admission: &Admission) -> Result<(), Error> {
    configure_dcf_in(io, short, false, admission).await
}
#[cfg(any(test, feature = "kernel-test"))]
async fn configure_dcf_in(
    io: &mut impl Io,
    short: bool,
    band5: bool,
    admission: &Admission,
) -> Result<(), Error> {
    crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
        let mut b = gated(&mut *io);
        let r = chip_station::configure_dcf(&mut b, short, band5).await;
        r.map_err(|e| b.err(e))
    })
    .await
}
pub(super) async fn prepare_initial(
    io: &mut impl Io,
    own: [u8; 6],
    admission: &Admission,
) -> Result<(), Error> {
    admission.check()?;
    io.station_allowed()?;
    if !chip_station::mac_valid(own) || io.station_own() != Ok(own) {
        return Err(Error::Prerequisite);
    }
    // Register prefix from the chip core (own MAC, cleared peer, MS/AID
    // clear, beacon off, DCF defaults), gated per access.
    crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
        let mut b = gated(&mut *io);
        let r = chip_station::prepare_initial(&mut b, own).await;
        r.map_err(|e| b.err(e))
    })
    .await?;
    // Source leave_lps_core: ACTIVE, RLBM0/smartPS0/awake1/port0/ALL_ON0xc.
    send(
        io,
        super::runtime_ps_wire::parameters(false),
        Some(admission),
    )
    .await?;
    // Explicitly disable firmware keep-alive and disconnect-decision frames.
    send(io, [3, 2, 5, 0, 0, 0, 0, 0], Some(admission)).await?;
    send(io, [4, 0, 0, 0, 0, 0, 0, 0], Some(admission)).await?;
    for attempt in 0..=5 {
        let mut b = bridge(&mut *io);
        if chip_station::port_idle(&mut b)
            .await
            .map_err(|e| b.err(e))?
        {
            return admission.check();
        }
        if attempt < 5 {
            io.delay_us(20000).await;
        }
        admission.check()?;
    }
    Err(Error::Timeout)
}
/// `rtw_vif_port_config(PORT_SET_MAC_ADDR)`: port0 `REG_MACID` (0x610).
pub(super) async fn port_address(
    io: &mut impl Io,
    mac: [u8; 6],
    admission: &Admission,
) -> Result<(), Error> {
    admission.check()?;
    if !chip_station::mac_valid(mac) {
        return Err(Error::Prerequisite);
    }
    crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
        let mut b = gated(&mut *io);
        let r = chip_station::port_address(&mut b, mac).await;
        r.map_err(|e| b.err(e))
    })
    .await
}
pub(super) async fn prepare_peer(
    io: &mut impl Io,
    peer: [u8; 6],
    admission: &Admission,
) -> Result<(), Error> {
    admission.check()?;
    if !chip_station::mac_valid(peer) || peer == io.station_own()? {
        return Err(Error::Prerequisite);
    }
    crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
        let mut b = gated(&mut *io);
        let r = chip_station::prepare_peer(&mut b, peer).await;
        r.map_err(|e| b.err(e))
    })
    .await?;
    // Source RTW_RATEID_B_20M=8, initRA1, noSGI/20MHz/noLDPC/noVHT,
    // disable firmware power training, RA mask only CCK1, fixed peerMACid0.
    send(
        io,
        [0x40, 0, 8 | (1 << 5), 0x40, 1, 0, 0, 0],
        Some(admission),
    )
    .await
}
pub(super) async fn commit_peer(
    io: &mut impl Io,
    peer: [u8; 6],
    aid: u16,
    short_slot: bool,
    band5: bool,
    admission: &Admission,
) -> Result<(), Error> {
    admission.check()?;
    if !chip_station::mac_valid(peer) || peer == io.station_own()? || !(1..=2007).contains(&aid) {
        return Err(Error::Prerequisite);
    }
    crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
        let mut b = gated(&mut *io);
        let r = chip_station::write_address(&mut b, chip_station::REG_BSSID, peer).await;
        r.map_err(|e| b.err(e))
    })
    .await?;
    // Firmware receives actual source media/default-port messages. Their
    // mailbox consumption cannot stand in for the AP's successful AssocResp.
    send(io, [1, 1, 0, 0, 0, 0, 0, 0], Some(admission)).await?;
    send(io, [0x2c, 0, 0, 0, 0, 0, 0, 0], Some(admission)).await?;
    crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
        let mut b = gated(&mut *io);
        let r = chip_station::commit_peer_tail(&mut b, aid, short_slot, band5).await;
        r.map_err(|e| b.err(e))
    })
    .await
}
pub(super) async fn disconnect(io: &mut impl Io, _peer: [u8; 6]) -> Result<(), Error> {
    // Teardown remains permitted after Admission.close. No operation enables
    // a data port, installs a key or reopens RF/host packet publication.
    // The register part runs over the plain bridge (no station gate, as
    // before); only the mailbox word follows.
    let mut b = bridge(&mut *io);
    let r = chip_station::disconnect(&mut b).await;
    r.map_err(|e| b.err(e))?;
    send(io, [1, 0, 0, 0, 0, 0, 0, 0], None).await
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_control/tests.rs"]
mod tests;
