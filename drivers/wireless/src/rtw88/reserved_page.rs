// SPDX-License-Identifier: GPL-2.0-or-later
//! Persistent PCIe beacon-DMA reserved-page owner, Linux rtw88/{fw,pci,tx}.c.
use super::firmware_transport::{self, Error};
use alloc::boxed::Box;
const DESC: usize = 48;
const PAYLOAD: usize = 4096;
/// # Safety
/// Exclusive coherent CPU/device mappings; addresses belong to this device.
/// sync supplies cache maintenance and device (outer-shareable on ARM) order.
/// The enclosing owner alone decides when published memory can be reclaimed.
pub unsafe trait Memory: Send {
    fn address(&self) -> u64;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    fn sync(&self);
    /// Order the observed exact device completion before CPU buffer reuse.
    /// Requires a full outer-shareable device fence on aarch64.
    fn acquire(&self);
}
/// # Safety
/// Native implementation owns the exact current PCI authority plus all other
/// native rings/reset state. Claim configures this beacon base and enables
/// firmware-only DMA only after proving other queues/MAC/IRQs parked; no
/// inherited, unrelated or cached DMA mapping may remain runnable. Cancellation
/// and Drop retain every host mapping with uncertain device ownership.
#[async_trait::async_trait]
pub(super) unsafe trait Registers: Send {
    fn claim_firmware_dma(&mut self, beacon_base: u32) -> Result<(), Error>;
    fn read8(&mut self, reg: u16) -> Result<u8, Error>;
    fn read16(&mut self, reg: u16) -> Result<u16, Error>;
    fn read32(&mut self, reg: u16) -> Result<u32, Error>;
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error>;
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), Error>;
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error>;
    async fn delay_us(&mut self, us: u64);
    async fn lte_backup(&mut self) -> Result<u32, Error>;
    async fn lte_restore(&mut self, value: u32) -> Result<(), Error>;
    async fn finish_dma(&mut self) -> Result<(), Error>;
    fn begin_mac(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_calibration8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_operating8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_operating8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_station8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_station8821c(&mut self, _: super::power_policy::Gate) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn submit_h2c(&mut self, _: &[u8; 32]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn poll_h2c(&mut self) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn finish_radio(&mut self, _: super::power_policy::Gate) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn park_radio(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn parked_cpu<T>(&mut self, _: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        Err(Error::Unsupported)
    }

    fn station_allowed(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_publication(&mut self) -> Result<super::publication::Publication, Error> {
        Err(Error::Unsupported)
    }
    fn station_own(&mut self) -> Result<[u8; 6], Error> {
        Err(Error::Unsupported)
    }
    fn station_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::station_profile::Grant>>, Error> {
        Ok(None)
    }
    fn station_bind_extension(
        &mut self,
        _: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn packet_profile(&mut self, _: super::packet_format::DataProfile) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_profile_readback(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_ht_facts(&self) -> Option<super::ht::Facts> {
        None
    }
    fn station_ht_extension(
        &mut self,
        _: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::ht::Grant>>, Error> {
        Ok(None)
    }
    fn station_bind_ht(&mut self, _: alloc::sync::Arc<super::ht::Grant>) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_ht_request(&mut self) -> Result<super::ht::Request, Error> {
        Err(Error::Unsupported)
    }
    fn station_rx_ba_extension(
        &mut self,
        _: alloc::sync::Arc<super::ht::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::rx_ba_power::Grant>>, Error> {
        Ok(None)
    }
    fn station_bind_rx_ba(
        &mut self,
        _: alloc::sync::Arc<super::rx_ba_power::Grant>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_rx_ba_request(&mut self) -> Result<super::RxBaRequest, Error> {
        Err(Error::Unsupported)
    }
    fn station_tx_ba_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::tx_ba_power::Grant>>, Error> {
        Ok(None)
    }
    fn station_bind_tx_ba(
        &mut self,
        _: alloc::sync::Arc<super::tx_ba_power::Grant>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_tx_ba_request(&mut self) -> Result<super::TxBaRequest, Error> {
        Err(Error::Unsupported)
    }
    fn packet_aggregation(
        &mut self,
        _: Option<super::packet_format::Aggregation>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn packet_submit_batch(
        &mut self,
        _: &[alloc::vec::Vec<u8>],
    ) -> Result<alloc::vec::Vec<u64>, super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    fn mailbox_ready(&mut self) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn mailbox_submit(&mut self, _: [u8; 8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn mailbox_consumed(&mut self) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn mailbox_pending(&self) -> bool {
        false
    }

    fn packet_prepare(&mut self, _: [u8; 6], _: u8) -> Result<(), super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    fn packet_start(&mut self) -> Result<(), super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    fn packet_ready(&self) -> bool {
        false
    }
    fn packet_submit(&mut self, _: &[u8], _: bool) -> Result<u64, super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    fn packet_poll(&mut self) -> Result<super::packet_core::Step, super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    fn packet_stop(&mut self) -> Result<(), super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PageState {
    Unclaimed,
    Idle,
    /// Successful firmware-to-MAC transfer: beacon ownership is complete,
    /// but it must never be republished as another firmware page.
    Continued,
    Terminal,
}
pub(super) struct Backend<R: Registers, M: Memory> {
    io: R,
    ring: Option<M>,
    frame: Option<M>,
    state: PageState,
    published: bool,
    boundary: u16,
    completed: bool,
}
impl<R: Registers, M: Memory> core::fmt::Debug for Backend<R, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88ReservedPage")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
fn address(memory: &impl Memory, needed: usize, alignment: u64) -> Result<u32, Error> {
    let base = memory.address();
    if memory.len() < needed
        || base & (alignment - 1) != 0
        || base
            .checked_add(needed as u64 - 1)
            .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::Memory);
    }
    Ok(base as u32)
}
impl<R: Registers, M: Memory> Backend<R, M> {
    pub fn new(io: R, mut ring: M, mut frame: M, boundary: u16) -> Result<Self, Error> {
        let a = u64::from(address(&ring, 16, 256)?);
        let b = u64::from(address(&frame, DESC + PAYLOAD, 4)?);
        if a < b + (DESC + PAYLOAD) as u64 && b < a + 16 || boundary & !0xfff != 0 {
            return Err(Error::Memory);
        }
        // DMA may become enabled during claim: initialize and publish an
        // OWN-clear beacon descriptor before its base can reach hardware.
        ring.write(0, &[0; 16])?;
        ring.sync();
        frame.write(0, &[0; DESC])?;
        frame.sync();
        Ok(Self {
            io,
            ring: Some(ring),
            frame: Some(frame),
            state: PageState::Unclaimed,
            published: false,
            boundary,
            completed: false,
        })
    }
    fn word(memory: &mut M, offset: usize, value: u32) -> Result<(), Error> {
        memory.write(offset, &value.to_le_bytes())
    }
    async fn page(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != PageState::Idle {
            return Err(Error::State);
        }
        if data.is_empty() || data.len() > PAYLOAD {
            return Err(Error::Image);
        }
        // Poison before MMIO, page or descriptor mutation. An outstanding TD
        // and a cancelled restoration sequence must never permit buffer reuse.
        self.state = PageState::Terminal;
        let beacon = self.io.read8(0x550)?;
        self.io.write16(0x204, 1 << 15)?; // page0 + W1C prior beacon-valid
        if self.io.read16(0x204)? & 1 << 15 != 0 {
            return Err(Error::Prerequisite);
        }
        let cr = self.io.read8(0x101)?;
        self.io.write8(0x101, cr | 1)?;
        self.io.write8(0x550, beacon & !8 | 16)?;
        let queue = self.io.read8(0x422)?;
        self.io.write8(0x422, queue & !0x40)?;
        let ring = self.ring.as_mut().ok_or(Error::State)?;
        let frame = self.frame.as_mut().ok_or(Error::State)?;
        let base = address(frame, DESC + data.len(), 4)?;
        frame.write(0, &[0; DESC])?;
        frame.write(DESC, data)?;
        // Explicit firmware-only legacy descriptor: no MAC payload is emitted
        // because claim keeps MAC TX/RX closed. It mirrors the 2G1Mbps beacon
        // profile and avoids interpreting short firmware tails as 802.11 hdrs.
        let bmc = data.get(4).is_some_and(|byte| byte & 1 != 0);
        Self::word(
            frame,
            0,
            data.len() as u32 | 48 << 16 | u32::from(bmc) << 24 | 1 << 26 | 1 << 31,
        )?;
        Self::word(frame, 4, 16 << 8 | 8 << 16)?;
        Self::word(frame, 12, 1 << 8 | 1 << 10)?;
        Self::word(frame, 32, 1 << 15)?;
        frame.sync();
        let pages = (DESC + data.len()).div_ceil(128) as u32;
        // Segment0 carries the48-byte packet descriptor, segment1 its body.
        // Publish OWN last, with a device barrier before the actual doorbell.
        Self::word(ring, 0, 48)?;
        Self::word(ring, 4, base)?;
        Self::word(ring, 8, data.len() as u32)?;
        Self::word(ring, 12, base + 48)?;
        ring.sync();
        Self::word(ring, 0, 48 | (pages | 0x8000) << 16)?;
        ring.sync();
        let work = self.io.read8(0x383)?;
        self.io.write8(0x383, work | 0x10)?;
        let mut done = false;
        for _ in 0..1000 {
            let value = self.io.read32(0x204)?;
            if value == u32::MAX {
                return Err(Error::Gone);
            }
            if value & 1 << 15 != 0 {
                done = true;
                break;
            }
            self.io.delay_us(10).await;
        }
        if !done {
            return Err(Error::Timeout);
        }
        // MMIO's inner-shareable load ordering alone is insufficient on ARM.
        // Order the exact device completion before any restoration/reuse.
        ring.acquire();
        self.completed = true;
        frame.acquire();
        // Fresh beacon-valid proves the exact serially published page reached
        // device TXBUF. Only completed transfers restore registers/reopen reuse.
        self.io.write16(0x204, self.boundary | 1 << 15)?;
        self.io.write8(0x550, beacon)?;
        self.io.write8(0x422, queue)?;
        self.io.write8(0x101, cr)?;
        self.state = PageState::Idle;
        Ok(())
    }
}
#[async_trait::async_trait]
// SAFETY: Backend keeps the ring/frame live, claims exclusive firmware DMA
// before publication, poisons before mutation and reopens only on a fresh
// page completion; R's unsafe contract governs all other native queue state.
unsafe impl<R: Registers, M: Memory> firmware_transport::Io for Backend<R, M> {
    fn station_tx_ba_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::tx_ba_power::Grant>>, Error> {
        self.io.station_tx_ba_extension()
    }
    fn station_bind_tx_ba(
        &mut self,
        g: alloc::sync::Arc<super::tx_ba_power::Grant>,
    ) -> Result<(), Error> {
        self.io.station_bind_tx_ba(g)
    }
    fn station_tx_ba_request(&mut self) -> Result<super::TxBaRequest, Error> {
        self.io.station_tx_ba_request()
    }
    fn packet_aggregation(
        &mut self,
        cfg: Option<super::packet_format::Aggregation>,
    ) -> Result<(), Error> {
        self.io.packet_aggregation(cfg)
    }
    fn packet_submit_batch(
        &mut self,
        b: &[alloc::vec::Vec<u8>],
    ) -> Result<alloc::vec::Vec<u64>, super::packet_core::Error> {
        self.io.packet_submit_batch(b)
    }
    fn station_rx_ba_extension(
        &mut self,
        b: alloc::sync::Arc<super::ht::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::rx_ba_power::Grant>>, Error> {
        self.io.station_rx_ba_extension(b)
    }
    fn station_bind_rx_ba(
        &mut self,
        g: alloc::sync::Arc<super::rx_ba_power::Grant>,
    ) -> Result<(), Error> {
        self.io.station_bind_rx_ba(g)
    }
    fn station_rx_ba_request(&mut self) -> Result<super::RxBaRequest, Error> {
        self.io.station_rx_ba_request()
    }
    fn station_ht_facts(&self) -> Option<super::ht::Facts> {
        self.io.station_ht_facts()
    }
    fn station_ht_extension(
        &mut self,
        b: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::ht::Grant>>, Error> {
        self.io.station_ht_extension(b)
    }
    fn station_bind_ht(&mut self, g: alloc::sync::Arc<super::ht::Grant>) -> Result<(), Error> {
        self.io.station_bind_ht(g)
    }
    fn station_ht_request(&mut self) -> Result<super::ht::Request, Error> {
        self.io.station_ht_request()
    }
    fn station_publication(&mut self) -> Result<super::publication::Publication, Error> {
        self.io.station_publication()
    }
    fn station_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::station_profile::Grant>>, Error> {
        self.io.station_extension()
    }
    fn station_bind_extension(
        &mut self,
        grant: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<(), Error> {
        self.io.station_bind_extension(grant)
    }
    fn packet_profile(&mut self, profile: super::packet_format::DataProfile) -> Result<(), Error> {
        self.io.packet_profile(profile)
    }
    fn station_profile_readback(&mut self) -> Result<(), Error> {
        self.io.station_profile_readback()
    }
    fn claim_pristine(&mut self) -> Result<(), Error> {
        if self.state != PageState::Unclaimed {
            return Err(Error::Prerequisite);
        }
        self.state = PageState::Terminal;
        let ring = self.ring.as_ref().ok_or(Error::State)?;
        let base = address(ring, 16, 256)?;
        // Retain before a potentially visible base/BME write, including errors.
        self.published = true;
        self.io.claim_firmware_dma(base)?;
        self.state = PageState::Idle;
        Ok(())
    }
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        self.io.read8(reg)
    }
    fn read16(&mut self, reg: u16) -> Result<u16, Error> {
        self.io.read16(reg)
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        self.io.read32(reg)
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        self.io.write8(reg, value)
    }
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), Error> {
        self.io.write16(reg, value)
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        self.io.write32(reg, value)
    }
    async fn reserved_page(&mut self, data: &[u8]) -> Result<(), Error> {
        self.page(data).await
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        self.io.lte_backup().await
    }
    async fn lte_restore(&mut self, value: u32) -> Result<(), Error> {
        self.io.lte_restore(value).await
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        self.io.finish_dma().await
    }
    fn begin_mac(&mut self) -> Result<(), Error> {
        if self.state != PageState::Idle {
            return Err(Error::State);
        }
        // Firmware pages may never overwrite the parked beacon owner during
        // a later MAC/packet continuation, including cancellation.
        self.state = PageState::Terminal;
        self.io.begin_mac()?;
        self.state = PageState::Continued;
        Ok(())
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        self.io.finish_mac()
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        self.io.begin_phy()
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        self.io.finish_phy()
    }
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        self.io.begin_calibration8821c()
    }
    fn finish_calibration8821c(&mut self) -> Result<(), Error> {
        self.io.finish_calibration8821c()
    }
    fn begin_operating8821c(&mut self) -> Result<(), Error> {
        self.io.begin_operating8821c()
    }
    fn finish_operating8821c(&mut self) -> Result<(), Error> {
        self.io.finish_operating8821c()
    }
    fn begin_station8821c(&mut self) -> Result<(), Error> {
        self.io.begin_station8821c()
    }
    fn finish_station8821c(&mut self, gate: super::power_policy::Gate) -> Result<(), Error> {
        if self.state != PageState::Continued || !self.completed || gate.did() != 0xc821 {
            return Err(Error::State);
        }
        self.state = PageState::Terminal;
        // C21 arrived parked after IQK/power. There is no active command-DMA
        // ownership to park again; disarm only under actual parked authority.
        let ring = self.ring.as_mut().ok_or(Error::State)?;
        let frame = self.frame.as_mut().ok_or(Error::State)?;
        self.io.parked_cpu(|| {
            ring.write(0, &[0; 16])?;
            ring.sync();
            frame.write(0, &[0; DESC])?;
            frame.sync();
            Ok(())
        })?;
        let work = self.io.read8(0x383)?;
        self.io.write8(0x383, work & !0x10)?;
        let beacon = self.io.read8(0x550)?;
        self.io.write8(0x550, beacon & !8)?;
        if self.io.read8(0x383)? & 0x10 != 0 || self.io.read8(0x550)? & 8 != 0 {
            return Err(Error::Prerequisite);
        }
        self.io.finish_station8821c(gate)
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        self.io.begin_commands()
    }
    fn submit_h2c(&mut self, packet: &[u8; 32]) -> Result<(), Error> {
        self.io.submit_h2c(packet)
    }
    fn poll_h2c(&mut self) -> Result<bool, Error> {
        self.io.poll_h2c()
    }
    fn park_radio(&mut self) -> Result<(), Error> {
        // The calibration-only continuation retains the completed beacon
        // mappings unchanged and never admits ordinary packet producers.
        self.io.park_radio()
    }
    fn finish_radio(&mut self, gate: super::power_policy::Gate) -> Result<(), Error> {
        if self.state != PageState::Continued || !self.completed {
            return Err(Error::State);
        }
        // Poison before parking/disarming: any ambiguous native failure must
        // not reopen this one-shot transfer. Continued is never a generic
        // exception for a failed/uncertain firmware descriptor.
        self.state = PageState::Terminal;
        self.io.park_radio()?;
        // Only after the exact successful BCN_VALID receipt and native BMEoff
        // parking may the original completed beacon descriptor be disarmed.
        // Published mappings remain retained; this is not reclamation/reset.
        let ring = self.ring.as_mut().ok_or(Error::State)?;
        let frame = self.frame.as_mut().ok_or(Error::State)?;
        self.io.parked_cpu(|| {
            ring.write(0, &[0; 16])?;
            ring.sync();
            frame.write(0, &[0; DESC])?;
            frame.sync();
            Ok(())
        })?;
        let work = self.io.read8(0x383)?;
        self.io.write8(0x383, work & !0x10)?;
        let beacon = self.io.read8(0x550)?;
        self.io.write8(0x550, beacon & !8)?;
        if self.io.read8(0x383)? & 0x10 != 0 || self.io.read8(0x550)? & 8 != 0 {
            return Err(Error::Prerequisite);
        }
        self.state = PageState::Terminal;
        self.io.finish_radio(gate)
    }

    fn station_allowed(&mut self) -> Result<(), Error> {
        self.io.station_allowed()
    }
    fn station_own(&mut self) -> Result<[u8; 6], Error> {
        self.io.station_own()
    }
    fn mailbox_ready(&mut self) -> Result<bool, Error> {
        self.io.mailbox_ready()
    }
    fn mailbox_submit(&mut self, p: [u8; 8]) -> Result<(), Error> {
        self.io.mailbox_submit(p)
    }
    fn mailbox_consumed(&mut self) -> Result<bool, Error> {
        self.io.mailbox_consumed()
    }
    fn mailbox_pending(&self) -> bool {
        self.io.mailbox_pending()
    }
    fn packet_prepare(
        &mut self,
        own: [u8; 6],
        mac_id: u8,
    ) -> Result<(), super::packet_core::Error> {
        self.io.packet_prepare(own, mac_id)
    }
    fn packet_start(&mut self) -> Result<(), super::packet_core::Error> {
        self.io.packet_start()
    }
    fn packet_ready(&self) -> bool {
        self.io.packet_ready()
    }
    fn packet_submit(
        &mut self,
        frame: &[u8],
        report: bool,
    ) -> Result<u64, super::packet_core::Error> {
        self.io.packet_submit(frame, report)
    }
    fn packet_poll(&mut self) -> Result<super::packet_core::Step, super::packet_core::Error> {
        self.io.packet_poll()
    }
    fn packet_stop(&mut self) -> Result<(), super::packet_core::Error> {
        self.io.packet_stop()
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await;
    }
}
impl<R: Registers, M: Memory> Drop for Backend<R, M> {
    fn drop(&mut self) {
        if self.published {
            core::mem::forget(self.ring.take());
            core::mem::forget(self.frame.take());
        }
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "reserved_page_tests.rs"]
mod tests;
