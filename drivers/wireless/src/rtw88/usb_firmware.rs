// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CU firmware/register backend: `firmware_transport::Io` over the
//! USB host interface (Linux 7.3-rc4 `rtw88/usb.c` `rtw_usb_ops`).
//!
//! - Registers: `rtw_usb_read`/`rtw_usb_write` EP0 vendor requests with the
//!   `rtw_usb_reg_sec` mirror ([`usb::Registers`]).
//! - Firmware: `fw.c::rtw_fw_write_data_rsvd_page` without the PCIe-only
//!   `REG_FWHW_TXQ_CTRL` BCNQ_DL toggle; the page itself is
//!   `rtw_usb_write_data_rsvd_page` (BEACON qsel, `send_firmware_pkt`'s +1
//!   byte, [`usb::reserved_page_packet`]) on the bulk-OUT pipe that
//!   `qsel_to_ep` names, then `check_hw_ready(REG_FIFOPAGE_CTRL_2,
//!   BIT_BCN_VALID_V1)`.
//! - H2C packets: `rtw_usb_write_data_h2c` ([`usb::h2c_packet`], H2C qsel);
//!   mailbox H2C: `fw.c::rtw_fw_send_h2c_command` (HMETFR/HMEBOX_EXT/HMEBOX).
//! - Packets: `usb_packet::Owner` (non-blocking begin/poll bulk receipts).
//!
//! There is no host DMA mapping on USB: every bulk transfer is a retained
//! controller receipt. A receipt that did not reach its exact completion
//! stays retained until [`firmware_transport::Io::quiesce_dma`] stops it, and
//! any failure leaves the backend `Terminal`. The MAC gate checks of the PCI
//! backend that are MAC registers (CR, TXPAUSE, HIMR) are kept; the PCIe DMA
//! configuration (0x303) and bus-master gates have no USB counterpart.
//! Station-grant hooks (`station_*`) keep the trait's `Unsupported`
//! defaults here; the USB station front-end binds them.
use super::firmware_transport::{self, Error};
use super::packet_core::{self, Step};
use super::usb::{self, Endpoints, Registers, Speed};
use super::usb_packet;
use crate::rtl8xxxu::firmware_transport::ControlIo;
use crate::rtl8xxxu::packet_transport::Io as Bulk;
use alloc::{boxed::Box, collections::VecDeque};

/// `check_hw_ready` (1000 x 10 us) for BCN_VALID_V1.
const BEACON_POLLS: u32 = 1000;
/// Bulk-OUT completion bound for one firmware page / H2C packet.
const BULK_POLLS: u32 = 50_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Unclaimed,
    /// Claimed: firmware reserved pages may be downloaded.
    Firmware,
    /// Firmware running; MAC TX/RX closed between configuration phases.
    Configuring,
    MacPrepared,
    PhyTablesPrepared,
    Calibrating8821c,
    Commands,
    Calibration8821cPrepared,
    Operating8821cPrepared,
    Calibrated,
    /// Bulk-IN receipt posted; `opened` once CR/TXPAUSE are open.
    Packets,
    /// `packet_close` paused TX, closed CR's MAC/DMA gates and retired every
    /// packet receipt; `packet_stop` and `quiesce_dma` only record it.
    Closed,
    Terminal,
}

fn usb_error(error: usb::Error) -> Error {
    match error {
        usb::Error::Timeout => Error::Timeout,
        usb::Error::Gone => Error::Gone,
        usb::Error::Endpoints | usb::Error::BulkOut => Error::Unsupported,
        usb::Error::Packet => Error::Image,
        usb::Error::Usb(_) | usb::Error::Short | usb::Error::Already | usb::Error::Command => {
            Error::Access
        }
    }
}

/// One frame, C2H or receipt taken from a multi-record USB step.
#[derive(Default)]
struct Backlog {
    frames: VecDeque<packet_core::Frame>,
    c2h: VecDeque<alloc::vec::Vec<u8>>,
    receipts: VecDeque<packet_core::Receipt>,
}
impl Backlog {
    fn is_empty(&self) -> bool {
        self.frames.is_empty() && self.c2h.is_empty() && self.receipts.is_empty()
    }
    fn take(&mut self) -> Step {
        Step {
            consumed_rx: true,
            frame: self.frames.pop_front(),
            c2h: self.c2h.pop_front(),
            receipt: self.receipts.pop_front(),
        }
    }
}

pub(super) struct Backend<C: ControlIo, P: Bulk + Clone> {
    registers: Registers<C>,
    bulk: P,
    endpoints: Endpoints,
    speed: Speed,
    /// Reserved-page boundary restored after each firmware page
    /// (`fifo.rsvd_boundary`; `reserved_page::station_boundary`).
    boundary: u16,
    state: State,
    /// A bulk-OUT receipt (firmware page or H2C) not yet proven complete.
    outstanding: Option<(P::Receipt, usize)>,
    gate: Option<super::power_policy::Gate>,
    mailbox_cursor: u8,
    mailbox_pending: bool,
    packets: Option<usb_packet::Owner<P>>,
    backlog: Backlog,
    /// `packet_open` wrote CR = 0xff / TXPAUSE = 0 and read them back.
    opened: bool,
    reclaimable: bool,
}
impl<C: ControlIo, P: Bulk + Clone> core::fmt::Debug for Backend<C, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8821cuFirmware")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
impl<C: ControlIo, P: Bulk + Clone> Backend<C, P> {
    /// `endpoints` from `usb::Endpoints::parse`; the bulk-out count must have
    /// a `rqpn_table_8821c` USB row (2..=4 pipes).
    pub(super) fn new(
        control: C,
        bulk: P,
        endpoints: Endpoints,
        speed: Speed,
    ) -> Result<Self, Error> {
        usb::usb_tables(usize::from(endpoints.out_count)).map_err(usb_error)?;
        let boundary = super::reserved_page::station_boundary(0xc821).ok_or(Error::State)?;
        Ok(Self {
            registers: Registers::new(control),
            bulk,
            endpoints,
            speed,
            boundary,
            state: State::Unclaimed,
            outstanding: None,
            gate: None,
            mailbox_cursor: 0,
            mailbox_pending: false,
            packets: None,
            backlog: Backlog::default(),
            opened: false,
            reclaimable: false,
        })
    }
    pub(super) fn registers(&self) -> &Registers<C> {
        &self.registers
    }
    fn fail<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    /// Submit one descriptor-prefixed packet on the pipe for `qsel` and keep
    /// the receipt until its exact completion.
    fn begin_out(&mut self, qsel: u8, packet: &[u8]) -> Result<(), Error> {
        if self.outstanding.is_some() {
            return Err(Error::State);
        }
        let ep = self.endpoints.out_for(qsel).ok_or(Error::Unsupported)?;
        let dci = narf_drivers_usb::bulk::dci_for(ep);
        let receipt = self
            .bulk
            .begin_send(dci, packet)
            .map_err(|_| Error::Access)?;
        self.outstanding = Some((receipt, packet.len()));
        Ok(())
    }
    /// `Ok(true)` once the outstanding transfer completed with its exact
    /// length (the receipt is then released), `Ok(false)` while pending.
    fn poll_out(&mut self) -> Result<bool, Error> {
        let (receipt, length) = self.outstanding.as_ref().ok_or(Error::State)?;
        match self.bulk.poll_send(receipt) {
            Ok(None) => Ok(false),
            Ok(Some(n)) if n == *length => {
                self.outstanding = None;
                Ok(true)
            }
            _ => Err(Error::Access),
        }
    }
    async fn finish_out(&mut self) -> Result<(), Error> {
        for _ in 0..BULK_POLLS {
            if self.poll_out()? {
                return Ok(());
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(10_000)).await;
        }
        Err(Error::Timeout)
    }
    /// `fw.c::rtw_fw_write_data_rsvd_page` (USB: no BCNQ_DL toggle).
    async fn page(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Firmware {
            return Err(Error::State);
        }
        let packet = usb::reserved_page_packet(data).map_err(usb_error)?;
        // Poison before any register or bulk mutation; only a completed page
        // with a fresh BCN_VALID receipt reopens the firmware channel.
        self.state = State::Terminal;
        let r = &self.registers;
        let beacon = r.read8(0x550).await.map_err(usb_error)?;
        r.write16(0x204, 1 << 15).await.map_err(usb_error)?;
        if r.read16(0x204).await.map_err(usb_error)? & 1 << 15 != 0 {
            return Err(Error::Prerequisite);
        }
        let cr = r.read8(0x101).await.map_err(usb_error)?;
        r.write8(0x101, cr | 1).await.map_err(usb_error)?;
        r.write8(0x550, beacon & !8 | 16).await.map_err(usb_error)?;
        self.begin_out(usb::QSEL_BEACON, &packet)?;
        self.finish_out().await?;
        let r = &self.registers;
        let mut valid = false;
        for _ in 0..BEACON_POLLS {
            let value = r.read32(0x204).await.map_err(usb_error)?;
            if value == u32::MAX {
                return Err(Error::Gone);
            }
            if value & 1 << 15 != 0 {
                valid = true;
                break;
            }
            r.control().delay_us(10).await;
        }
        if !valid {
            return Err(Error::Timeout);
        }
        r.write16(0x204, self.boundary | 1 << 15)
            .await
            .map_err(usb_error)?;
        r.write8(0x550, beacon).await.map_err(usb_error)?;
        r.write8(0x101, cr).await.map_err(usb_error)?;
        self.state = State::Firmware;
        Ok(())
    }
    /// Phase transition `from` -> `to` with nothing outstanding.
    fn step(&mut self, from: State, to: State) -> Result<(), Error> {
        if self.state != from || self.outstanding.is_some() {
            return Err(Error::State);
        }
        self.state = to;
        Ok(())
    }
    fn gate_current(&self) -> Result<(), Error> {
        self.gate
            .as_ref()
            .ok_or(Error::State)?
            .current()
            .map_err(Error::Power)
    }
    /// `usb.c::rtw_usb_interface_cfg` speed this backend was probed at.
    pub(super) fn speed(&self) -> Speed {
        self.speed
    }
    fn now_us() -> u64 {
        narf_time::monotonic_ns() / 1000
    }
    /// Test fixture: an opened packet owner without the signed station
    /// gate (no receipt posted), so the asynchronous close can be replayed.
    #[cfg(feature = "kernel-test")]
    pub(super) fn opened_for_test(&mut self, own: [u8; 6]) -> Result<(), packet_core::Error> {
        self.packets = Some(usb_packet::Owner::prepare(
            self.bulk.clone(),
            self.endpoints,
            own,
            0,
            super::packet_phy::Chip::C21,
        )?);
        self.state = State::Packets;
        self.opened = true;
        Ok(())
    }
}

#[async_trait::async_trait]
// SAFETY: the backend owns the claimed USB function exclusively (EP0 vendor
// requests and every bulk pipe). There is no host DMA mapping; each bulk
// transfer is a retained controller receipt released only on its exact
// completion or by `quiesce_dma`'s endpoint stop, and every failure poisons
// the backend before further register or bulk mutation.
unsafe impl<C: ControlIo, P: Bulk + Clone> firmware_transport::Io for Backend<C, P> {
    fn hci(&self) -> super::mac::Hci {
        super::mac::Hci::Usb {
            bulkout: self.endpoints.out_count,
            speed: self.speed,
        }
    }
    fn claim_pristine(&mut self) -> Result<(), Error> {
        // The probe powered the MAC on (`usb::Registers::power_on`) and wrote
        // REG_C2HEVT = C2H_HW_FEATURE_REPORT (`rtw_chip_efuse_enable`).
        self.step(State::Unclaimed, State::Firmware)
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read8(&mut self, reg: u16) -> impl core::future::Future<Output = Result<u8, Error>> + Send {
        async move { self.registers.read8(reg).await.map_err(usb_error) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read16(
        &mut self,
        reg: u16,
    ) -> impl core::future::Future<Output = Result<u16, Error>> + Send {
        async move { self.registers.read16(reg).await.map_err(usb_error) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read32(
        &mut self,
        reg: u16,
    ) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        async move { self.registers.read32(reg).await.map_err(usb_error) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write8(
        &mut self,
        reg: u16,
        value: u8,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { self.registers.write8(reg, value).await.map_err(usb_error) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write16(
        &mut self,
        reg: u16,
        value: u16,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { self.registers.write16(reg, value).await.map_err(usb_error) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write32(
        &mut self,
        reg: u16,
        value: u32,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { self.registers.write32(reg, value).await.map_err(usb_error) }
    }
    async fn reserved_page(&mut self, data: &[u8]) -> Result<(), Error> {
        self.page(data).await
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        // `rtw_coex_read_indirect_reg(0x38)` through REG_WL_LTECOEX_CTRL.
        let r = &self.registers;
        poll32(r, 0x1700, 1 << 29, 1 << 29).await?;
        r.write32(0x1700, 0x800f_0038).await.map_err(usb_error)?;
        r.read32(0x1708).await.map_err(usb_error)
    }
    async fn lte_restore(&mut self, value: u32) -> Result<(), Error> {
        let r = &self.registers;
        poll32(r, 0x1700, 1 << 29, 1 << 29).await?;
        r.write32(0x1704, value).await.map_err(usb_error)?;
        r.write32(0x1700, 0xc00f_0038).await.map_err(usb_error)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        // USB has no firmware DMA window to park: close CR's MAC/DMA gates
        // and the host interrupt masks the PCI backend closes at claim.
        if self.state != State::Firmware || self.outstanding.is_some() {
            return Err(Error::State);
        }
        self.state = State::Terminal;
        let r = &self.registers;
        let result = async {
            let cr = r.read8(0x100).await.map_err(usb_error)?;
            r.write8(0x100, cr & !0xcf).await.map_err(usb_error)?;
            for register in [0xb0, 0xb8, 0x10b8] {
                r.write32(register, 0).await.map_err(usb_error)?;
            }
            Ok::<(), Error>(())
        }
        .await;
        result?;
        self.state = State::Configuring;
        Ok(())
    }
    fn begin_mac(&mut self) -> Result<(), Error> {
        // Firmware is parked in `Configuring` after `finish_dma`.
        if self.state != State::Configuring || self.outstanding.is_some() {
            return Err(Error::State);
        }
        Ok(())
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        self.step(State::Configuring, State::MacPrepared)
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        self.step(State::MacPrepared, State::Configuring)
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        self.step(State::Configuring, State::PhyTablesPrepared)
    }
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        self.step(State::PhyTablesPrepared, State::Calibrating8821c)
    }
    fn finish_calibration8821c(&mut self) -> Result<(), Error> {
        self.step(State::Configuring, State::Calibration8821cPrepared)
    }
    fn begin_operating8821c(&mut self) -> Result<(), Error> {
        self.step(State::Calibration8821cPrepared, State::Configuring)
    }
    fn finish_operating8821c(&mut self) -> Result<(), Error> {
        self.step(State::Configuring, State::Operating8821cPrepared)
    }
    fn begin_station8821c(&mut self) -> Result<(), Error> {
        self.step(State::Operating8821cPrepared, State::Configuring)
    }
    fn finish_station8821c(&mut self, gate: super::power_policy::Gate) -> Result<(), Error> {
        if self.state != State::Configuring || gate.did() != 0xc821 {
            return Err(Error::State);
        }
        let result = gate.current().map_err(Error::Power);
        self.fail(result)?;
        self.gate = Some(gate);
        self.state = State::Calibrated;
        Ok(())
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        if !matches!(
            self.state,
            State::PhyTablesPrepared | State::Calibrating8821c
        ) || self.outstanding.is_some()
        {
            return Err(Error::State);
        }
        self.state = State::Commands;
        Ok(())
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn submit_h2c(
        &mut self,
        packet: &[u8; 32],
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        let packet = *packet;
        async move {
            if self.state != State::Commands {
                return Err(Error::State);
            }
            // rtw_usb_write_data_h2c: CR's HCI TXDMA must carry the H2C
            // queue while MAC TX/RX stay closed (the PCI backend's 0x33).
            let r = &self.registers;
            let result = async {
                r.write8(0x100, 0x33).await.map_err(usb_error)?;
                usb::h2c_packet(&packet).map_err(usb_error)
            }
            .await;
            let bytes = self.fail(result)?;
            let result = self.begin_out(usb::QSEL_H2C, &bytes);
            self.fail(result)
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn poll_h2c(&mut self) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move {
            if self.state != State::Commands {
                return Err(Error::State);
            }
            let result = self.poll_out();
            self.fail(result)
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn park_radio(&mut self) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            if self.state != State::Commands || self.outstanding.is_some() {
                return Err(Error::State);
            }
            self.state = State::Terminal;
            let r = &self.registers;
            let cr = r.read8(0x100).await.map_err(usb_error)?;
            r.write8(0x100, cr & !0xcf).await.map_err(usb_error)?;
            if r.read8(0x100).await.map_err(usb_error)? & 0xcf != 0 {
                return Err(Error::Prerequisite);
            }
            self.state = State::Configuring;
            Ok(())
        }
    }
    fn station_allowed(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Calibrated | State::Packets) {
            return Err(Error::State);
        }
        self.gate_current()
    }
    fn station_own(&mut self) -> Result<[u8; 6], Error> {
        self.station_allowed()?;
        Ok(self.gate.as_ref().ok_or(Error::State)?.own())
    }
    fn station_gate(&mut self) -> Result<super::power_policy::Gate, Error> {
        self.gate.clone().ok_or(Error::State)
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn mailbox_ready(&mut self) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move {
            if !matches!(self.state, State::Calibrated | State::Packets) || self.mailbox_pending {
                return Err(Error::State);
            }
            // REG_HMETFR: the box is free while its bit is clear.
            let state = self.registers.read8(0x1cc).await.map_err(usb_error)?;
            if state == 255 {
                return Err(Error::Gone);
            }
            Ok(state & (1 << self.mailbox_cursor) == 0)
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn mailbox_submit(
        &mut self,
        words: [u8; 8],
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            if !self.mailbox_ready().await? {
                return Err(Error::State);
            }
            let cleanup = words == [1, 0, 0, 0, 0, 0, 0, 0];
            if !cleanup {
                self.gate_current()?;
            }
            self.mailbox_pending = true;
            let ext = u32::from_le_bytes([words[4], words[5], words[6], words[7]]);
            let body = u32::from_le_bytes([words[0], words[1], words[2], words[3]]);
            let cursor = u16::from(self.mailbox_cursor);
            let r = &self.registers;
            let result = async {
                // rtw_fw_send_h2c_command: HMEBOX_EXT before HMEBOX.
                r.write32(0x1f0 + cursor * 4, ext)
                    .await
                    .map_err(usb_error)?;
                r.write32(0x1d0 + cursor * 4, body).await.map_err(usb_error)
            }
            .await;
            self.fail(result)
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn mailbox_consumed(
        &mut self,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move {
            if !matches!(self.state, State::Calibrated | State::Packets) || !self.mailbox_pending {
                return Err(Error::State);
            }
            let state = self.registers.read8(0x1cc).await.map_err(usb_error)?;
            if state == 255 {
                return Err(Error::Gone);
            }
            if state & (1 << self.mailbox_cursor) != 0 {
                return Ok(false);
            }
            self.mailbox_pending = false;
            self.mailbox_cursor = (self.mailbox_cursor + 1) % 4;
            Ok(true)
        }
    }
    fn mailbox_pending(&self) -> bool {
        self.mailbox_pending
    }
    fn packet_prepare(&mut self, own: [u8; 6], mac_id: u8) -> Result<(), packet_core::Error> {
        if self.state != State::Calibrated || self.packets.is_some() {
            return Err(packet_core::Error::State);
        }
        self.gate_current()
            .map_err(|_| packet_core::Error::Access)?;
        let owner = usb_packet::Owner::prepare(
            self.bulk.clone(),
            self.endpoints,
            own,
            mac_id,
            super::packet_phy::Chip::C21,
        )?;
        self.packets = Some(owner);
        Ok(())
    }
    fn packet_start(&mut self) -> Result<(), packet_core::Error> {
        if self.state != State::Calibrated {
            return Err(packet_core::Error::State);
        }
        // Posts the persistent bulk-IN receipt; CR/TXPAUSE open in the
        // asynchronous `packet_open` that follows.
        self.packets
            .as_mut()
            .ok_or(packet_core::Error::State)?
            .start()?;
        self.state = State::Packets;
        Ok(())
    }
    /// The PCI `Port::start` MAC open (CR low byte 0xff enables HCI/packet
    /// DMA and MAC, TXPAUSE 0) over EP0. Linux USB leaves CR at
    /// `MAC_TRX_ENABLE` from `mac.c::rtw_mac_init`; this backend keeps it
    /// closed through configuration and opens it only for the station.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn packet_open(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), packet_core::Error>> + Send {
        async move {
            if self.state != State::Packets || self.opened || self.outstanding.is_some() {
                return Err(packet_core::Error::State);
            }
            self.gate_current()
                .map_err(|_| packet_core::Error::Access)?;
            self.state = State::Terminal;
            let r = &self.registers;
            let result = async {
                r.write8(0x100, 0xff).await?;
                r.write8(0x522, 0).await?;
                Ok::<_, usb::Error>(r.read8(0x100).await? == 0xff && r.read8(0x522).await? == 0)
            }
            .await;
            if result != Ok(true) {
                return Err(packet_core::Error::Access);
            }
            self.state = State::Packets;
            self.opened = true;
            Ok(())
        }
    }
    /// The PCI `Port::stop` MAC close (TXPAUSE 0xff, CR &= !0xcf) over EP0,
    /// then `usb.c::rtw_usb_cancel_rx_bufs` and the TX purge: every packet
    /// bulk receipt is stopped. A failure leaves the backend terminal with
    /// any unretired receipt for `quiesce_dma`.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn packet_close(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), packet_core::Error>> + Send {
        async move {
            if self.packets.is_none() || self.state == State::Closed {
                return Ok(());
            }
            let opened = core::mem::replace(&mut self.opened, false);
            self.state = State::Terminal;
            self.backlog = Backlog::default();
            let r = &self.registers;
            let closed = async {
                r.write8(0x522, 0xff).await?;
                let cr = r.read8(0x100).await?;
                r.write8(0x100, cr & !0xcf).await?;
                Ok::<_, usb::Error>(
                    r.read8(0x100).await? & 0xcf == 0 && r.read8(0x522).await? == 0xff,
                )
            }
            .await;
            // Receipts are retired even when the register close failed.
            let owner = self.packets.as_mut().ok_or(packet_core::Error::State)?;
            owner.stop().await?;
            if closed != Ok(true) {
                return Err(if opened {
                    packet_core::Error::Access
                } else {
                    packet_core::Error::State
                });
            }
            self.state = State::Closed;
            Ok(())
        }
    }
    fn packet_ready(&self) -> bool {
        self.state == State::Packets
            && self.opened
            && self.backlog.is_empty()
            && self.packets.as_ref().is_some_and(usb_packet::Owner::ready)
    }
    fn packet_submit(&mut self, frame: &[u8], report: bool) -> Result<u64, packet_core::Error> {
        if self.state != State::Packets || !self.opened {
            return Err(packet_core::Error::State);
        }
        self.packets
            .as_mut()
            .ok_or(packet_core::Error::State)?
            .submit(frame, report)
    }
    fn packet_scan_address(&mut self, address: Option<[u8; 6]>) -> Result<(), packet_core::Error> {
        self.packets
            .as_mut()
            .ok_or(packet_core::Error::State)?
            .set_scan(address)
    }
    fn packet_profile(&mut self, profile: super::packet_format::DataProfile) -> Result<(), Error> {
        self.packets
            .as_mut()
            .ok_or(Error::State)?
            .configure_data(profile)
            .map_err(|_| Error::State)
    }
    fn packet_poll(&mut self) -> Result<Step, packet_core::Error> {
        if self.state != State::Packets {
            return Err(packet_core::Error::State);
        }
        if !self.backlog.is_empty() {
            return Ok(self.backlog.take());
        }
        let owner = self.packets.as_mut().ok_or(packet_core::Error::State)?;
        let step = owner.poll(Self::now_us())?;
        self.backlog.frames.extend(step.frames);
        self.backlog.c2h.extend(step.c2h);
        self.backlog.receipts.extend(step.receipts);
        if self.backlog.is_empty() {
            return Ok(Step {
                consumed_rx: step.consumed_rx,
                ..Step::default()
            });
        }
        Ok(self.backlog.take())
    }
    fn packet_stop(&mut self) -> Result<(), packet_core::Error> {
        if self.packets.is_none() {
            return Err(packet_core::Error::State);
        }
        self.backlog = Backlog::default();
        self.opened = false;
        // After `packet_close` the MAC is closed and every receipt retired.
        // Without it (synchronous failure path) a sync stop cannot retire
        // bulk receipts: fail closed and leave them to `quiesce_dma`.
        if self.state != State::Closed {
            self.state = State::Terminal;
        }
        Ok(())
    }
    async fn quiesce_dma(&mut self) -> Result<(), Error> {
        // `Closed` already retired every packet receipt (`Owner::stop` is
        // idempotent); the backend still ends terminal.
        self.state = State::Terminal;
        if let Some((receipt, _)) = self.outstanding.as_ref() {
            self.bulk.stop(receipt).await.map_err(|_| Error::Access)?;
            self.outstanding = None;
        }
        if let Some(owner) = self.packets.as_mut() {
            owner.stop().await.map_err(|_| Error::Access)?;
        }
        self.reclaimable = true;
        Ok(())
    }
    fn dma_reclaimable(&self) -> bool {
        self.reclaimable
    }
}

async fn poll32<C: ControlIo>(
    r: &Registers<C>,
    reg: u16,
    mask: u32,
    target: u32,
) -> Result<(), Error> {
    for _ in 0..1000 {
        let value = r.read32(reg).await.map_err(usb_error)?;
        if value == u32::MAX {
            return Err(Error::Gone);
        }
        if value & mask == target {
            return Ok(());
        }
        r.control().delay_us(10).await;
    }
    Err(Error::Timeout)
}
