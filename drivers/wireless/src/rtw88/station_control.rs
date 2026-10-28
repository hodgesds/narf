// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8821CE/RTL8822CE port0 and four-box mailbox, Linux rtw88.
//! A consumed mailbox is transport evidence, never an applied-command ACK.
use super::{
    firmware_transport::{Error, Io},
    radio,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
            if io.mailbox_consumed()? {
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
        if io.mailbox_ready()? {
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
        a.run(|| {
            io.station_allowed()?;
            io.mailbox_submit(words)
        })?;
    } else {
        io.mailbox_submit(words)?;
    }
    for attempt in 0..=30 {
        if io.mailbox_consumed()? {
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
fn address(
    io: &mut impl Io,
    base: u16,
    mac: [u8; 6],
    admission: Option<&Admission>,
) -> Result<(), Error> {
    for (i, value) in mac.into_iter().enumerate() {
        if let Some(a) = admission {
            a.run(|| {
                io.station_allowed()?;
                io.write8(base + i as u16, value)
            })?;
        } else {
            io.write8(base + i as u16, value)?;
        }
    }
    Ok(())
}
fn update(
    io: &mut impl Io,
    reg: u16,
    mask: u32,
    value: u32,
    admission: Option<&Admission>,
) -> Result<(), Error> {
    if let Some(a) = admission {
        a.run(|| {
            io.station_allowed()?;
            radio::mask(io, reg, mask, value)
        })
    } else {
        radio::mask(io, reg, mask, value)
    }
}
fn mac_valid(mac: [u8; 6]) -> bool {
    mac[0] & 1 == 0 && mac != [0; 6]
}
fn configure_dcf(io: &mut impl Io, short: bool, admission: &Admission) -> Result<(), Error> {
    // mac80211::ieee80211_set_wmm_default(enable_qos=false) uses AIFSN2,
    // TXOP0 and CWmax1023. Retain the conservative 11b CWmin31 for this
    // fixed CCK1 profile, including on an ERP AP. rtw88::__rtw_conf_tx
    // encodes CW exponents and AIFS = AIFSN * slot + 2.4GHz SIFS10.
    let slot = if short { 9 } else { 20 };
    let value = (10 << 12) | (5 << 8) | (2 * u32::from(slot) + 10);
    let mask = 0x07ff_ffff; // source TXOP/CWmax/CWmin/AIFS fields
    for register in [0x500, 0x504, 0x508, 0x50c] {
        update(io, register, mask, value, Some(admission))?;
        admission.run(|| {
            io.station_allowed()?;
            if io.read32(register)? & mask != value {
                return Err(Error::Prerequisite);
            }
            Ok(())
        })?;
    }
    admission.run(|| {
        io.station_allowed()?;
        io.write8(0x51b, slot)?;
        io.station_allowed()?;
        if io.read8(0x51b)? != slot {
            return Err(Error::Prerequisite);
        }
        Ok(())
    })
}
pub(super) async fn prepare_initial(
    io: &mut impl Io,
    own: [u8; 6],
    admission: &Admission,
) -> Result<(), Error> {
    admission.check()?;
    io.station_allowed()?;
    if !mac_valid(own) || io.station_own() != Ok(own) {
        return Err(Error::Prerequisite);
    }
    address(io, 0x610, own, Some(admission))?;
    address(io, 0x618, [0; 6], Some(admission))?;
    update(io, 0x100, 0x30000, 0, Some(admission))?;
    update(io, 0x6a8, 0x7ff, 0, Some(admission))?;
    // No AP/autobeacon or TSF-update service in this one-shot host station.
    admission.run(|| {
        io.station_allowed()?;
        let v = io.read8(0x550)?;
        io.write8(0x550, (v & !8) | 16)
    })?;
    // Close the MAC's initial WMM/TXOP defaults before ordinary MAC traffic.
    configure_dcf(io, false, admission)?;
    // Source leave_lps_core: ACTIVE, RLBM0/smartPS0/awake1/port0/ALL_ON0xc.
    send(io, [0x20, 0, 0, 1, 0, 0x0c, 0, 0], Some(admission)).await?;
    // Explicitly disable firmware keep-alive and disconnect-decision frames.
    send(io, [3, 2, 5, 0, 0, 0, 0, 0], Some(admission)).await?;
    send(io, [4, 0, 0, 0, 0, 0, 0, 0], Some(admission)).await?;
    for attempt in 0..=5 {
        if radio::read(io, 0x604)? & (1 << 7) == 0 {
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
pub(super) fn port_address(
    io: &mut impl Io,
    mac: [u8; 6],
    admission: &Admission,
) -> Result<(), Error> {
    admission.check()?;
    if !mac_valid(mac) {
        return Err(Error::Prerequisite);
    }
    address(io, 0x610, mac, Some(admission))
}
pub(super) async fn prepare_peer(
    io: &mut impl Io,
    peer: [u8; 6],
    admission: &Admission,
) -> Result<(), Error> {
    admission.check()?;
    if !mac_valid(peer) || peer == io.station_own()? {
        return Err(Error::Prerequisite);
    }
    address(io, 0x618, peer, Some(admission))?;
    update(io, 0x100, 0x30000, 0, Some(admission))?;
    update(io, 0x6a8, 0x7ff, 0, Some(admission))?;
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
    admission: &Admission,
) -> Result<(), Error> {
    admission.check()?;
    if !mac_valid(peer) || peer == io.station_own()? || !(1..=2007).contains(&aid) {
        return Err(Error::Prerequisite);
    }
    address(io, 0x618, peer, Some(admission))?;
    // Firmware receives actual source media/default-port messages. Their
    // mailbox consumption cannot stand in for the AP's successful AssocResp.
    send(io, [1, 1, 0, 0, 0, 0, 0, 0], Some(admission)).await?;
    send(io, [0x2c, 0, 0, 0, 0, 0, 0, 0], Some(admission)).await?;
    update(io, 0x6a8, 0x7ff, u32::from(aid), Some(admission))?;
    configure_dcf(io, short_slot, admission)?;
    update(io, 0x100, 0x30000, 2, Some(admission))
}
pub(super) async fn disconnect(io: &mut impl Io, _peer: [u8; 6]) -> Result<(), Error> {
    // Teardown remains permitted after Admission.close. No operation enables
    // a data port, installs a key or reopens RF/host packet publication.
    update(io, 0x100, 0x30000, 0, None)?;
    update(io, 0x6a8, 0x7ff, 0, None)?;
    address(io, 0x618, [0; 6], None)?;
    send(io, [1, 0, 0, 0, 0, 0, 0, 0], None).await
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_control/tests.rs"]
mod tests;
