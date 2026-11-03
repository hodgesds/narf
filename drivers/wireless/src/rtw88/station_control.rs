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
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            io.station_allowed()?;
            io.mailbox_submit(words)
        })
        .await?;
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
async fn address(
    io: &mut impl Io,
    base: u16,
    mac: [u8; 6],
    admission: Option<&Admission>,
) -> Result<(), Error> {
    for (i, value) in mac.into_iter().enumerate() {
        if let Some(a) = admission {
            crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
                io.station_allowed()?;
                io.write8(base + i as u16, value).await
            })
            .await?;
        } else {
            io.write8(base + i as u16, value).await?;
        }
    }
    Ok(())
}
async fn update(
    io: &mut impl Io,
    reg: u16,
    mask: u32,
    value: u32,
    admission: Option<&Admission>,
) -> Result<(), Error> {
    if let Some(a) = admission {
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            io.station_allowed()?;
            radio::mask(io, reg, mask, value).await
        })
        .await
    } else {
        radio::mask(io, reg, mask, value).await
    }
}
fn mac_valid(mac: [u8; 6]) -> bool {
    mac[0] & 1 == 0 && mac != [0; 6]
}
async fn configure_dcf(io: &mut impl Io, short: bool, admission: &Admission) -> Result<(), Error> {
    configure_dcf_in(io, short, false, admission).await
}
async fn configure_dcf_in(
    io: &mut impl Io,
    short: bool,
    band5: bool,
    admission: &Admission,
) -> Result<(), Error> {
    // mac80211::ieee80211_set_wmm_default(enable_qos=false) uses AIFSN2,
    // TXOP0 and CWmax1023. Retain the conservative 11b CWmin31 for this
    // fixed base profile, including on an ERP or 5GHz AP (mac80211 would
    // use CWmin15 for OFDM). rtw88 mac80211.c::rtw_aifsn_to_aifs encodes
    // AIFS = AIFSN * slot + SIFS, SIFS 16 when `current_band_type` is
    // RTW_BAND_5G and 10 otherwise; mac80211 mlme.c
    // `ieee80211_handle_bss_capability` forces the short slot on 5GHz.
    let short = short || band5;
    let slot = if short { 9 } else { 20 };
    let sifs = if band5 { 16 } else { 10 };
    let value = (10 << 12) | (5 << 8) | (2 * u32::from(slot) + sifs);
    let mask = 0x07ff_ffff; // source TXOP/CWmax/CWmin/AIFS fields
    for register in [0x500, 0x504, 0x508, 0x50c] {
        update(io, register, mask, value, Some(admission)).await?;
        crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
            io.station_allowed()?;
            if io.read32(register).await? & mask != value {
                return Err(Error::Prerequisite);
            }
            Ok(())
        })
        .await?;
    }
    crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
        io.station_allowed()?;
        io.write8(0x51b, slot).await?;
        io.station_allowed()?;
        if io.read8(0x51b).await? != slot {
            return Err(Error::Prerequisite);
        }
        Ok(())
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
    if !mac_valid(own) || io.station_own() != Ok(own) {
        return Err(Error::Prerequisite);
    }
    address(io, 0x610, own, Some(admission)).await?;
    address(io, 0x618, [0; 6], Some(admission)).await?;
    update(io, 0x100, 0x30000, 0, Some(admission)).await?;
    update(io, 0x6a8, 0x7ff, 0, Some(admission)).await?;
    // No AP/autobeacon or TSF-update service in this one-shot host station.
    crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
        io.station_allowed()?;
        let v = io.read8(0x550).await?;
        io.write8(0x550, (v & !8) | 16).await
    })
    .await?;
    // Close the MAC's initial WMM/TXOP defaults before ordinary MAC traffic.
    configure_dcf(io, false, admission).await?;
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
        if radio::read(io, 0x604).await? & (1 << 7) == 0 {
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
    if !mac_valid(mac) {
        return Err(Error::Prerequisite);
    }
    address(io, 0x610, mac, Some(admission)).await
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
    address(io, 0x618, peer, Some(admission)).await?;
    update(io, 0x100, 0x30000, 0, Some(admission)).await?;
    update(io, 0x6a8, 0x7ff, 0, Some(admission)).await?;
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
    if !mac_valid(peer) || peer == io.station_own()? || !(1..=2007).contains(&aid) {
        return Err(Error::Prerequisite);
    }
    address(io, 0x618, peer, Some(admission)).await?;
    // Firmware receives actual source media/default-port messages. Their
    // mailbox consumption cannot stand in for the AP's successful AssocResp.
    send(io, [1, 1, 0, 0, 0, 0, 0, 0], Some(admission)).await?;
    send(io, [0x2c, 0, 0, 0, 0, 0, 0, 0], Some(admission)).await?;
    update(io, 0x6a8, 0x7ff, u32::from(aid), Some(admission)).await?;
    configure_dcf_in(io, short_slot, band5, admission).await?;
    update(io, 0x100, 0x30000, 2, Some(admission)).await
}
pub(super) async fn disconnect(io: &mut impl Io, _peer: [u8; 6]) -> Result<(), Error> {
    // Teardown remains permitted after Admission.close. No operation enables
    // a data port, installs a key or reopens RF/host packet publication.
    update(io, 0x100, 0x30000, 0, None).await?;
    update(io, 0x6a8, 0x7ff, 0, None).await?;
    address(io, 0x618, [0; 6], None).await?;
    send(io, [1, 0, 0, 0, 0, 0, 0, 0], None).await
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_control/tests.rs"]
mod tests;
