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
//! Station-grant hooks: the PCI backend's signed-gate operations
//! (extensions, HT/BA/protection/continuation/channel records, host bind)
//! and an EP0 profile readback; publications are `Publication::usb`.
//! Retune (2.4/5 GHz primaries under N2xO records), widening (N2xB 40 MHz /
//! N2xV 80 MHz), the in-retune IQK H2C, passive-primary TX grants and the
//! HT-program quiet proof follow `pci_firmware.rs` over EP0/bulk; the C21
//! RF/BB stages run unchanged over the asynchronous register `Io`.
//! TX A-MPDU binds the N21T record as PCI does; bursts are queued by
//! `usb_packet::Owner::submit_batch` inside the gate's `invoke_batch`.
//! Power-tracking maintenance and the PS RX quiet proof keep the trait's
//! `Unsupported` defaults.
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

pub(super) fn usb_error(error: usb::Error) -> Error {
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
    /// The die behind the USB function: 0xc821 (RTL8821CU) or 0xb822
    /// (RTL8822BU). Selects the FIFO page rows and the B22 hooks.
    did: u16,
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
    /// `packet_open` wrote CR = 0xff / TXPAUSE = 0 and read them back;
    /// shared with every [`super::publication::Publication::usb`] and cleared
    /// on close, stop, packet failure and quiesce.
    open: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
    reclaimable: bool,
    /// Committed operating primary and its retune epoch (initial 1, 1).
    channel: u8,
    channel_epoch: u64,
    /// Target primary of an in-progress retune or widening (TX refused,
    /// TXPAUSE = 0xff); `widening` marks the latter.
    retune: Option<u8>,
    widening: bool,
    /// A committed N2xB (40 MHz) / N2xV (80 MHz) program.
    wide: bool,
    /// `pci_firmware.rs` `passive_tx`: TX grant on a passive-only primary.
    passive_tx: Option<(u8, alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>)>,
    /// Linux's running `h2c.seq` for the in-station IQK H2C (the PCI
    /// backend's `tracking_sequence`).
    h2c_sequence: u16,
    /// `pci_firmware.rs` `tracking_maintenance`: an N21W power-tracking
    /// continuation owns TX quiet, TXPAUSE and the associated IQK H2C.
    tracking: bool,
}
impl<C: ControlIo, P: Bulk + Clone> core::fmt::Debug for Backend<C, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88UsbFirmware")
            .field("did", &self.did)
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
        Self::new_for(0xc821, control, bulk, endpoints, speed)
    }
    /// [`Self::new`] for chip `did` (0xc821 RTL8821CU, 0xb822 RTL8822BU):
    /// the chip's `page_table_*` USB row must exist for the pipe count, and
    /// each firmware page restores that chip's `fifo.rsvd_boundary`
    /// (`mac::Info`: C21 460, B22 1996).
    pub(super) fn new_for(
        did: u16,
        control: C,
        bulk: P,
        endpoints: Endpoints,
        speed: Speed,
    ) -> Result<Self, Error> {
        usb::usb_tables_for(did, usize::from(endpoints.out_count)).map_err(usb_error)?;
        let boundary = match did {
            0xb822 => 1996,
            _ => super::reserved_page::station_boundary(0xc821).ok_or(Error::State)?,
        };
        Ok(Self {
            registers: Registers::for_chip(control, did).map_err(usb_error)?,
            did,
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
            open: alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
            reclaimable: false,
            channel: 1,
            channel_epoch: 1,
            retune: None,
            widening: false,
            wide: false,
            passive_tx: None,
            h2c_sequence: 3,
            tracking: false,
        })
    }
    pub(super) fn registers(&self) -> &Registers<C> {
        &self.registers
    }
    fn fail<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.state = State::Terminal;
            self.set_open(false);
        }
        result
    }
    fn opened(&self) -> bool {
        self.open.load(core::sync::atomic::Ordering::Acquire)
    }
    fn set_open(&self, open: bool) {
        self.open.store(open, core::sync::atomic::Ordering::Release);
    }
    /// `pci_packet::Native::with_packet`: any packet error but `Busy` leaves
    /// the backend terminal and withdraws every publication.
    fn packet_fail<T>(
        &mut self,
        result: Result<T, packet_core::Error>,
    ) -> Result<T, packet_core::Error> {
        if result
            .as_ref()
            .is_err_and(|error| *error != packet_core::Error::Busy)
        {
            self.state = State::Terminal;
            self.set_open(false);
        }
        result
    }
    fn gate_ref(&self) -> Result<&super::power_policy::Gate, Error> {
        self.gate.as_ref().ok_or(Error::State)
    }
    /// Replace the station gate with `bind(current)` (`Gate::with_*`).
    fn rebind(
        &mut self,
        bind: impl FnOnce(&super::power_policy::Gate) -> Result<super::power_policy::Gate, Error>,
    ) -> Result<(), Error> {
        firmware_transport::Io::station_allowed(self)?;
        let next = bind(self.gate_ref()?)?;
        self.gate = Some(next);
        Ok(())
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
    /// `pci_firmware.rs::committed_wide`.
    fn committed_wide(&self) -> Result<Option<super::ht::Wide>, Error> {
        if !self.wide {
            return Ok(None);
        }
        let gate = self.gate_ref()?;
        match (gate.vht_record(), gate.ht40_record()) {
            (Some(v), None) => Ok(Some(super::ht::Wide::Eighty(v))),
            (None, Some(r)) => Ok(Some(super::ht::Wide::Forty(r))),
            _ => Err(Error::State),
        }
    }
    /// `pci_firmware.rs::passive_tx_allowed`: on a passive-only committed
    /// primary a frame is published only under the station's passive TX
    /// grant for this primary and policy snapshot.
    fn passive_tx_allowed(&self) -> Result<(), Error> {
        let gate = self.gate_ref()?;
        let Some(policy) = narf_wireless::reg::db::snapshot() else {
            return Ok(());
        };
        if !gate.passive_in(&policy).map_err(Error::Power)? {
            return Ok(());
        }
        match &self.passive_tx {
            Some((primary, granted))
                if *primary == gate.channel()
                    && *primary == self.channel
                    && alloc::sync::Arc::ptr_eq(granted, &policy) =>
            {
                Ok(())
            }
            _ => Err(Error::Power(super::power_policy::Error::Policy)),
        }
    }
    /// The USB counterpart of `pci_firmware.rs::retune_quiet`: no frame is
    /// queued, in a bulk-OUT URB or awaiting its CCX report, no H2C bulk
    /// receipt is outstanding, REG_TXDMA_PQ_MAP still carries this pipe
    /// count's `rqpn_table_8821c` mapping and each REG_FIFOPAGE_INFO_1..4
    /// queue reports all of its `page_table_8821c` pages free. There are no
    /// TXBD ring indices on USB.
    async fn transmit_quiet(&mut self) -> Result<bool, Error> {
        if !self.backlog.is_empty()
            || self.outstanding.is_some()
            || !self.packets.as_ref().is_some_and(usb_packet::Owner::ready)
        {
            return Ok(false);
        }
        let (rqpn, pages) = usb::usb_tables_for(self.did, usize::from(self.endpoints.out_count))
            .map_err(usb_error)?;
        let r = &self.registers;
        let map = r.read16(0x10c).await.map_err(usb_error)?;
        if map == u16::MAX {
            return Err(Error::Gone);
        }
        if map & 0xfff0 != usb::txdma_pq_map(rqpn) {
            return Err(Error::Prerequisite);
        }
        for (reg, n) in [
            (0x230, pages.hq),
            (0x234, pages.nq),
            (0x238, pages.lq),
            (0x23c, pages.exq),
        ] {
            if r.read16(reg).await.map_err(usb_error)? != n {
                return Err(Error::Prerequisite);
            }
            if r.read16(reg + 2).await.map_err(usb_error)? != n {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// REG_TXPAUSE = 0xff (once per retune) and its readback, then quiet.
    async fn pause_quiet(&mut self, first: bool) -> Result<bool, Error> {
        let r = &self.registers;
        if first {
            r.write8(0x522, 0xff).await.map_err(usb_error)?;
        }
        if r.read8(0x522).await.map_err(usb_error)? != 0xff {
            return Err(Error::Prerequisite);
        }
        self.transmit_quiet().await
    }
    /// The only H2C packet a retune (`command::iqk8821c`) or a power-tracking
    /// continuation (`command::iqk8821c_associated`) may send:
    /// `rtw8821c_do_iqk` at the running sequence, on the H2C pipe with MAC
    /// TX/RX already open (no CR rewrite).
    fn retune_h2c(&mut self, packet: &[u8; 32]) -> Result<(), Error> {
        // B22 sends the same pre-association `iqk8821c` H2C from its
        // associated `N2BW` maintenance (`pci_firmware.rs::submit_h2c`).
        let expected = if self.tracking && self.did == 0xc821 {
            super::command::iqk8821c_associated(self.h2c_sequence)
        } else {
            super::command::iqk8821c(self.h2c_sequence)
        };
        if self.outstanding.is_some() || *packet != expected {
            return Err(Error::State);
        }
        self.h2c_sequence = self.h2c_sequence.checked_add(1).ok_or(Error::State)?;
        let result = usb::h2c_packet(packet)
            .map_err(usb_error)
            .and_then(|bytes| self.begin_out(usb::QSEL_H2C, &bytes));
        self.fail(result)
    }
    fn retune_blocked(&self) -> bool {
        self.state != State::Packets
            || self.mailbox_pending
            || self.outstanding.is_some()
            || self.tracking
    }
    /// A retune/widening or power-tracking continuation owns the H2C pipe.
    fn mission(&self) -> bool {
        self.state == State::Packets && (self.retune.is_some() || self.tracking)
    }
    /// `pci_firmware.rs::station_power_tracking_quiet` over EP0: the
    /// continuation owns TX and no H2C or mailbox command is outstanding,
    /// then [`Self::transmit_quiet`]. USB has no RX descriptor ring; the RX
    /// side is the continuation's REG_RXPKT_NUM RXDMA_IDLE proof
    /// (`tracking8821c::program` park) and the station's receive retirement.
    async fn tracking_quiet(&mut self) -> Result<bool, Error> {
        if !self.tracking || self.mailbox_pending || self.outstanding.is_some() {
            return Err(Error::State);
        }
        self.transmit_quiet().await
    }
    /// `pci_firmware.rs::b22_iqk_quiet` over EP0: TXPAUSE held,
    /// [`Self::transmit_quiet`] (no queued/in-flight/awaiting frame, no H2C
    /// receipt, the `rqpn_table_8822b` map and every `page_table_8822b`
    /// page free), and the requested RXDMA park reporting idle.
    async fn b22_iqk_quiet(&mut self) -> Result<bool, Error> {
        use super::dma_stop::{RW_RELEASE, RXDMA_IDLE, RXPKT_NUM};
        let r = &self.registers;
        if r.read8(0x522).await.map_err(usb_error)? != 0xff {
            return Ok(false);
        }
        if self.outstanding.is_some() || !self.transmit_quiet().await? {
            return Ok(false);
        }
        let rx = self.registers.read32(RXPKT_NUM).await.map_err(usb_error)?;
        if rx == u32::MAX {
            return Err(Error::Gone);
        }
        if rx & RW_RELEASE == 0 {
            return Err(Error::Prerequisite);
        }
        Ok(rx & RXDMA_IDLE != 0)
    }
    /// `pci_firmware.rs::station_ps_rx_quiet` over EP0: an open, idle
    /// station (no retune, power-tracking continuation, H2C or mailbox
    /// command) with no undelivered RX backlog and [`Self::transmit_quiet`].
    async fn ps_rx_quiet(&mut self) -> Result<bool, Error> {
        if self.state != State::Packets
            || !self.opened()
            || self.retune.is_some()
            || self.tracking
            || self.mailbox_pending
        {
            return Ok(false);
        }
        self.transmit_quiet().await
    }
    /// Host-side LPS publication checks run inside the original PS source
    /// immediately before the publishing EP0 write: open, idle owner, no
    /// RX backlog, no outstanding H2C and the current signed gate.
    fn ps_publish_allowed(&self) -> Result<bool, Error> {
        if self.state != State::Packets
            || !self.opened()
            || self.outstanding.is_some()
            || self.retune.is_some()
            || self.tracking
        {
            return Err(Error::State);
        }
        if !self.backlog.is_empty() || !self.packets.as_ref().is_some_and(usb_packet::Owner::ready)
        {
            return Ok(false);
        }
        self.gate_current()?;
        self.passive_tx_allowed()?;
        Ok(true)
    }
    /// The LPS station TXBUF upload (`runtime_ps_page.rs` shape) over the
    /// bulk BEACON queue: Linux `fw.c::rtw_fw_write_data_rsvd_page` with
    /// `usb.c::rtw_usb_write_data_rsvd_page` (no BCNQ_DL toggle on USB).
    /// Every register access and the bulk submission run inside the
    /// original PS source and station admission.
    async fn ps_page(
        &mut self,
        data: &[u8],
        boundary: u16,
        source: &super::runtime_ps_scope::Bound,
        admission: &super::station_control::Admission,
    ) -> Result<(), Error> {
        use firmware_transport::enclosed;
        if source.did() != 0xc821 {
            return Err(Error::Unsupported);
        }
        if boundary != self.boundary || data.len() != 464 || data[..80].iter().any(|b| *b != 0) {
            return Err(Error::Image);
        }
        // Each EP0 step runs its first poll inside the original PS source and
        // station admission; both are re-checked when it completes.
        macro_rules! scoped {
            ($f:expr) => {
                enclosed(|op| admission.run(|| source.invoke(op)), $f).await
            };
        }
        if !source.matches(self.gate_ref()?) {
            return Err(Error::Access);
        }
        if !scoped!(self.ps_rx_quiet())? {
            return Err(Error::State);
        }
        let packet = usb::reserved_page_packet(data).map_err(usb_error)?;
        let r = &self.registers;
        let beacon = scoped!(async { r.read8(0x550).await.map_err(usb_error) })?;
        let head = scoped!(async { r.read16(0x204).await.map_err(usb_error) })?;
        if beacon & 8 != 0 || head & 0xfff != boundary {
            return Err(Error::Prerequisite);
        }
        // Poison before any mutation (the publication's open flag stays set
        // so the source can still enclose this upload); only the exact fresh
        // BCN_VALID and the full restore reopen the station.
        self.state = State::Terminal;
        let result = async {
            let r = &self.registers;
            let cr = scoped!(async {
                r.write16(0x204, boundary | 1 << 15)
                    .await
                    .map_err(usb_error)?;
                if r.read16(0x204).await.map_err(usb_error)? & 1 << 15 != 0 {
                    return Err(Error::Prerequisite);
                }
                let cr = r.read8(0x101).await.map_err(usb_error)?;
                r.write8(0x101, cr | 1).await.map_err(usb_error)?;
                r.write8(0x550, beacon & !8 | 16).await.map_err(usb_error)?;
                Ok(cr)
            })?;
            admission.run(|| source.invoke(|| self.begin_out(usb::QSEL_BEACON, &packet)))?;
            self.finish_out().await?;
            let r = &self.registers;
            let mut valid = false;
            for _ in 0..BEACON_POLLS {
                let value = scoped!(async { r.read32(0x204).await.map_err(usb_error) })?;
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
            scoped!(async {
                r.write16(0x204, boundary | 1 << 15)
                    .await
                    .map_err(usb_error)?;
                r.write8(0x550, beacon).await.map_err(usb_error)?;
                r.write8(0x101, cr).await.map_err(usb_error)?;
                if r.read8(0x550).await.map_err(usb_error)? != beacon
                    || r.read8(0x101).await.map_err(usb_error)? != cr
                {
                    return Err(Error::Prerequisite);
                }
                Ok(())
            })
        }
        .await;
        if result.is_err() {
            self.set_open(false);
            return result;
        }
        self.state = State::Packets;
        Ok(())
    }
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
        self.set_open(true);
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
    /// Every register access is an EP0 transfer: the station runs on the
    /// asynchronous `interface` worker, never through `ready_now`.
    const SYNCHRONOUS: bool = false;
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
    async fn station_reserved_page(
        &mut self,
        data: &[u8],
        boundary: u16,
        source: &super::runtime_ps_scope::Bound,
        admission: &super::station_control::Admission,
    ) -> Result<(), Error> {
        self.ps_page(data, boundary, source, admission).await
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
        if self.state != State::Configuring || gate.did() != self.did {
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
            if self.mission() {
                return self.retune_h2c(&packet);
            }
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
            if self.state != State::Commands && !self.mission() {
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
        // PCI checks bus mastering once packets run; USB checks the MAC
        // open from `packet_open` (between `packet_start` and it, only the
        // signed gate).
        self.gate_current()
    }
    fn station_publication(&mut self) -> Result<super::publication::Publication, Error> {
        self.station_allowed()?;
        if self.state != State::Packets || !self.opened() {
            return Err(Error::State);
        }
        Ok(super::publication::Publication::usb(
            self.gate_ref()?.clone(),
            self.open.clone(),
        ))
    }
    fn station_own(&mut self) -> Result<[u8; 6], Error> {
        self.station_allowed()?;
        Ok(self.gate_ref()?.own())
    }
    fn station_gate(&mut self) -> Result<super::power_policy::Gate, Error> {
        self.station_allowed()?;
        self.gate.clone().ok_or(Error::State)
    }
    // The signed-grant hooks below are the PCI backend's
    // (`pci_firmware.rs`) gate operations without register access; every
    // record is host-keyed (`rtw8821cu-*`, `Host::header`), so a PCI record
    // never admits this backend.
    fn station_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::station_profile::Grant>>, Error> {
        self.station_allowed()?;
        let gate = self.gate_ref()?;
        if gate.extension_request().is_none() {
            return Ok(None);
        }
        Ok(super::station_profile::Source::Registered
            .load(gate.clone())
            .ok())
    }
    fn station_bind_extension(
        &mut self,
        grant: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<(), Error> {
        self.rebind(|g| g.with_extension(grant))
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_profile_readback(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        // `pci_firmware.rs` readback over EP0, at the committed width.
        async move {
            let gate = self.gate_ref()?.clone();
            let wide = self.committed_wide()?;
            let r = Read(&self.registers);
            if let Some(w) = gate.power_tracking() {
                w.readback(Read(&self.registers)).await?;
                let thermal = self.registers.read32(0x2908).await.map_err(usb_error)?;
                w.temperature(((thermal >> 10) & 63) as u8)?;
            }
            if let Some(g) = gate.ht_grant() {
                return g.readback_at(r, wide.as_ref()).await;
            }
            if let Some((indices, channel)) = gate.c21_indices().map(|i| (i, gate.channel())) {
                return super::radio8821c::operating_readback(r, indices, channel).await;
            }
            if let Some((ofdm, diffs)) = gate.ofdm5() {
                return super::wmm::readback5(r, ofdm, diffs).await;
            }
            let gains = gate.cck_gains().ok_or(Error::Unsupported)?;
            super::wmm::readback(r, gains).await
        }
    }
    fn station_ht_facts(&self) -> Option<super::ht::Facts> {
        self.gate.as_ref()?.ht_facts()
    }
    fn station_ht_extension(
        &mut self,
        base: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::ht::Grant>>, Error> {
        self.station_allowed()?;
        Ok(super::ht::Source::Registered.load(base).ok())
    }
    fn station_bind_ht(&mut self, g: alloc::sync::Arc<super::ht::Grant>) -> Result<(), Error> {
        self.rebind(|gate| gate.with_ht(g))
    }
    fn station_ht_request(&mut self) -> Result<super::ht::Request, Error> {
        self.station_allowed()?;
        let gate = self.gate_ref()?;
        if let Some(g) = gate.ht_grant() {
            return Ok(g.request());
        }
        let base = match gate.ht_base() {
            Some(b) => b,
            None => super::station_profile::Source::Registered.load(gate.clone())?,
        };
        super::ht::request(&base)
    }
    fn station_rx_ba_extension(
        &mut self,
        base: alloc::sync::Arc<super::ht::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::rx_ba_power::Grant>>, Error> {
        self.station_allowed()?;
        Ok(super::rx_ba_power::Source::Registered.load(base).ok())
    }
    fn station_bind_rx_ba(
        &mut self,
        g: alloc::sync::Arc<super::rx_ba_power::Grant>,
    ) -> Result<(), Error> {
        self.rebind(|gate| gate.with_rx_ba(g))
    }
    fn station_rx_ba_request(&mut self) -> Result<super::RxBaRequest, Error> {
        self.station_allowed()?;
        let gate = self.gate_ref()?;
        let h = match gate.ht_grant() {
            Some(h) => h,
            None => {
                let base = match gate.ht_base() {
                    Some(b) => b,
                    None => super::station_profile::Source::Registered.load(gate.clone())?,
                };
                super::ht::Source::Registered.load(base)?
            }
        };
        super::rx_ba_power::request(&h)
    }
    fn station_tx_ba_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::tx_ba_power::Grant>>, Error> {
        self.station_allowed()?;
        // `pci_firmware.rs`: the N21T record over the gate's TX base; the
        // burst runs through `usb_packet::Owner::submit_batch`.
        let base = self.gate_ref()?.tx_base().ok_or(Error::State)?;
        Ok(super::tx_ba_power::Source::Registered.load(base).ok())
    }
    fn station_bind_tx_ba(
        &mut self,
        g: alloc::sync::Arc<super::tx_ba_power::Grant>,
    ) -> Result<(), Error> {
        self.rebind(|gate| gate.with_tx_ba(g))
    }
    fn station_tx_ba_request(&mut self) -> Result<super::TxBaRequest, Error> {
        self.station_allowed()?;
        let gate = self.gate_ref()?;
        if let Some(g) = gate.tx_grant() {
            return Ok(g.request());
        }
        let base = match gate.tx_base() {
            Some(b) => b,
            None => {
                let l = match gate.ht_base() {
                    Some(l) => l,
                    None => super::station_profile::Source::Registered.load(gate.clone())?,
                };
                let h = super::ht::Source::Registered.load(l)?;
                match super::rx_ba_power::Source::Registered.load(h.clone()).ok() {
                    Some(r) => super::tx_ba_power::Base::R(r),
                    None => super::tx_ba_power::Base::H(h),
                }
            }
        };
        super::tx_ba_power::request(&base)
    }
    fn station_protection_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::protection::Grant>>, Error> {
        self.station_allowed()?;
        let base = self.gate_ref()?.protection_base().ok_or(Error::State)?;
        Ok(super::protection::Source::Registered.load(base).ok())
    }
    fn station_bind_protection(
        &mut self,
        g: alloc::sync::Arc<super::protection::Grant>,
    ) -> Result<(), Error> {
        self.rebind(|gate| gate.with_protection(g))
    }
    fn station_rts_request(&mut self) -> Result<super::RtsRequest, Error> {
        self.station_allowed()?;
        let gate = self.gate_ref()?;
        if let Some(g) = gate.protection_grant() {
            return Ok(g.request());
        }
        super::protection::request(&super::protection::registered_base(gate)?)
    }
    fn station_bind_continuation(
        &mut self,
        g: alloc::sync::Arc<super::qualification::Grant>,
    ) -> Result<(), Error> {
        self.rebind(|gate| gate.with_continuation(g))
    }
    fn station_continuation(
        &mut self,
        kind: &'static super::qualification::Kind,
    ) -> Result<Option<alloc::sync::Arc<super::qualification::Grant>>, Error> {
        self.station_allowed()?;
        Ok(super::qualification::Source::Registered
            .load(kind, self.gate_ref()?)
            .ok())
    }
    fn station_continuation_request(
        &mut self,
        kind: &'static super::qualification::Kind,
    ) -> Result<super::ContinuationRequest, Error> {
        self.station_allowed()?;
        super::qualification::request(kind, self.gate_ref()?)
    }
    fn station_band5_capability(
        &mut self,
        channel: u8,
    ) -> Result<Option<super::vht::Band5Capability>, Error> {
        self.station_allowed()?;
        let base = self.gate_ref()?.clone();
        super::vht::band5_capability(&base, channel, |c| self.station_channel_grant(c))
    }
    fn station_channel_grant(
        &mut self,
        channel: u8,
    ) -> Result<Option<alloc::sync::Arc<super::qualification::Grant>>, Error> {
        self.station_allowed()?;
        let kind = super::channel_policy::kind(channel).ok_or(Error::Unsupported)?;
        let base = self.gate_ref()?.without_channel();
        Ok(super::qualification::Source::Registered
            .load(kind, &base)
            .ok()
            .filter(|g| base.with_channel(g.clone()).is_ok()))
    }
    fn station_regulatory(
        &self,
    ) -> Result<Option<alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>>, Error> {
        Ok(narf_wireless::reg::db::snapshot())
    }
    fn station_channel(&self) -> (u8, u64) {
        (self.channel, self.channel_epoch)
    }
    fn station_passive_tx(
        &mut self,
        grant: Option<(u8, alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>)>,
    ) -> Result<(), Error> {
        if let Some((primary, _)) = &grant {
            if self.retune.is_some() || *primary != self.channel {
                return Err(Error::State);
            }
        }
        self.passive_tx = grant;
        Ok(())
    }
    // N21W power tracking: `pci_firmware.rs` over EP0 (`phy.c::
    // rtw_phy_pwr_track` -> `rtw8821c_pwr_track`). The continuation flips
    // the bound W grant to Changing, which makes `Gate::current` (and so
    // `packet_submit` / `station_publication`) refuse TX until finish
    // commits or retires it.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_request(
        &mut self,
        thermal: u8,
        dm: Option<alloc::sync::Arc<super::qualification::Grant>>,
    ) -> impl core::future::Future<Output = Result<super::PowerTrackingRequest, Error>> + Send {
        async move {
            self.station_allowed()?;
            let gate = self.gate_ref()?.clone();
            if let Some(g) = gate.power_tracking() {
                return Ok(g.request());
            }
            let r = &self.registers;
            if r.read32(0xc94).await.map_err(usb_error)? & 0x7e != 0 {
                return Err(Error::Prerequisite);
            }
            let scale = (r.read32(0xc1c).await.map_err(usb_error)? >> 21) as u16;
            super::tracking8821c::request(&gate, thermal, scale, dm.as_ref())
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_extension(
        &mut self,
        thermal: u8,
        dm: Option<alloc::sync::Arc<super::qualification::Grant>>,
    ) -> impl core::future::Future<
        Output = Result<Option<alloc::sync::Arc<super::tracking8821c::Grant>>, Error>,
    > + Send {
        async move {
            self.station_allowed()?;
            let gate = self.gate_ref()?.clone();
            if gate.ht_grant().is_none() || gate.power_tracking().is_some() {
                return Ok(None);
            }
            let r = &self.registers;
            if r.read32(0xc94).await.map_err(usb_error)? & 0x7e != 0 {
                return Ok(None);
            }
            let swing = (r.read32(0xc1c).await.map_err(usb_error)? >> 21) as u16;
            // Host-keyed (`rtw8821cu-power-track-v1-*`, header = USB VID/PID):
            // an absent or unqualified W keeps the static profile.
            Ok(super::tracking8821c::Source::Registered
                .load(gate, thermal, swing, dm)
                .ok())
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_bind_power_tracking(
        &mut self,
        g: alloc::sync::Arc<super::tracking8821c::Grant>,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            self.station_allowed()?;
            g.readback(Read(&self.registers)).await?;
            self.rebind(|gate| gate.with_power_tracking(g))
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_begin(
        &mut self,
        g: &alloc::sync::Arc<super::tracking8821c::Grant>,
        restore: bool,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        let g = g.clone();
        async move {
            if self.retune_blocked()
                || self.retune.is_some()
                || self
                    .gate
                    .as_ref()
                    .and_then(super::power_policy::Gate::power_tracking)
                    .as_ref()
                    .is_none_or(|w| !alloc::sync::Arc::ptr_eq(w, &g))
            {
                return Err(Error::State);
            }
            // Only this exclusive owner may inspect/restore a revoked W.
            self.tracking = true;
            let result = async {
                self.gate_ref()?.invoke_base(|| Ok(()))?;
                g.readback(Read(&self.registers)).await?;
                if !self.tracking_quiet().await? {
                    return Ok(false);
                }
                if restore {
                    g.begin_restore()?;
                } else {
                    g.begin()?;
                }
                Ok(true)
            }
            .await;
            if !matches!(result, Ok(true)) {
                self.tracking = false;
            }
            result
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_quiet(
        &mut self,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        self.tracking_quiet()
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_iqk(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            if !self.tracking || self.state != State::Packets {
                return Err(Error::State);
            }
            let g = self
                .gate
                .as_ref()
                .and_then(super::power_policy::Gate::power_tracking)
                .ok_or(Error::State)?;
            let packet = super::command::iqk8821c_associated(self.h2c_sequence);
            g.authority(|| self.retune_h2c(&packet))
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_finish(
        &mut self,
        p: Option<super::tracking8821c::Program>,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        use super::dma_stop::{RW_RELEASE, RXDMA_IDLE, RXPKT_NUM};
        async move {
            if !self.tracking || self.outstanding.is_some() || !self.tracking_quiet().await? {
                return Err(Error::Prerequisite);
            }
            let r = &self.registers;
            if r.read8(0x522).await.map_err(usb_error)? != 255
                || r.read32(RXPKT_NUM).await.map_err(usb_error)? & (RXDMA_IDLE | RW_RELEASE)
                    != (RXDMA_IDLE | RW_RELEASE)
            {
                return Err(Error::Prerequisite);
            }
            let gate = self.gate_ref()?.clone();
            let g = gate.power_tracking().ok_or(Error::State)?;
            let actual = p.unwrap_or_else(|| g.initial_program());
            super::tracking8821c::Grant::read_program(actual, &mut Read(r)).await?;
            gate.ht_grant()
                .ok_or(Error::State)?
                .readback(Read(r))
                .await?;
            if p.is_some() {
                let thermal = r.read32(0x2908).await.map_err(usb_error)?;
                g.temperature(((thermal >> 10) & 63) as u8)?;
            }
            let rx = r.read32(RXPKT_NUM).await.map_err(usb_error)?;
            r.write32(RXPKT_NUM, rx & !RW_RELEASE)
                .await
                .map_err(usb_error)?;
            r.write8(0x522, 0).await.map_err(usb_error)?;
            if r.read32(RXPKT_NUM).await.map_err(usb_error)? & RW_RELEASE != 0
                || r.read8(0x522).await.map_err(usb_error)? != 0
            {
                return Err(Error::Prerequisite);
            }
            match p {
                Some(p) => g.commit(p)?,
                None => {
                    g.retire();
                    self.gate = Some(gate.without_power_tracking());
                }
            }
            self.tracking = false;
            Ok(())
        }
    }
    // Retune/widening: `pci_firmware.rs` over EP0. The target gate is
    // installed and TX publication refused before TXPAUSE; the C21 RF/BB
    // stages (`channel_policy::program`, `ht40::program`, `vht::program`)
    // then run over this backend's asynchronous register `Io` unchanged.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_retune_begin(
        &mut self,
        channel: u8,
        grant: Option<alloc::sync::Arc<super::qualification::Grant>>,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move {
            if self.retune_blocked()
                || self.retune.is_some_and(|c| c != channel)
                || self.widening
                || (channel == 1) != grant.is_none()
            {
                return Err(Error::State);
            }
            let first = self.retune.is_none();
            if first {
                if self.passive_tx.as_ref().is_some_and(|(p, _)| *p != channel) {
                    self.passive_tx = None;
                }
                let current = self.gate_ref()?;
                if !current.base_only() {
                    return Err(Error::State);
                }
                let base = current.without_channel();
                let target = match grant {
                    Some(g) => base.with_channel(g)?,
                    None => base,
                };
                if target.channel() != channel {
                    return Err(Error::State);
                }
                target.current().map_err(Error::Power)?;
                self.retune = Some(channel);
                self.gate = Some(target);
                self.packets
                    .as_mut()
                    .ok_or(Error::State)?
                    .set_operating_channel(channel);
            }
            let result = self.pause_quiet(first).await;
            self.fail(result)
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_width_begin(
        &mut self,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move {
            if self.retune_blocked() || self.retune.is_some_and(|c| c != self.channel) {
                return Err(Error::State);
            }
            let first = self.retune.is_none();
            if first {
                if self.wide {
                    return Err(Error::State);
                }
                let gate = self.gate_ref()?;
                // N2xV (80MHz, RTW bandwidth code 2) or N2xB (40MHz, code 1).
                let (primary, width) = match (gate.vht_record(), gate.ht40_record()) {
                    (Some(v), None) => (v.primary, 2),
                    (None, Some(r)) => (r.primary, 1),
                    _ => return Err(Error::State),
                };
                if primary != self.channel || gate.channel() != self.channel {
                    return Err(Error::State);
                }
                gate.current().map_err(Error::Power)?;
                self.retune = Some(self.channel);
                self.widening = true;
                self.packets
                    .as_mut()
                    .ok_or(Error::State)?
                    .set_operating_width(width);
            }
            let result = self.pause_quiet(first).await;
            self.fail(result)
        }
    }
    /// RTL8822BU associated `rtw8822b_do_iqk` maintenance (`N2BW`), the
    /// `pci_firmware.rs::station_b22_iqk` sequence over EP0: Begin holds
    /// every queue (TXPAUSE 0xff) and requests the RXDMA park
    /// (`BIT_RW_RELEASE`); Quiet is [`Self::b22_iqk_quiet`] with the B22
    /// `page_table_8822b` FIFO geometry; Submit sends the `rtw8822b_do_iqk`
    /// H2C on the H2C pipe; Finish, after the H2C receipt completed and the
    /// hardware is still quiet, releases RXDMA and TXPAUSE with readback.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_b22_iqk(
        &mut self,
        step: super::tracking8822b::Step,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        use super::dma_stop::{RW_RELEASE, RXPKT_NUM};
        use super::tracking8822b::Step;
        async move {
            if self.did != 0xb822 || self.state != State::Packets {
                return Err(Error::State);
            }
            match step {
                Step::Begin => {
                    if self.tracking
                        || self.retune.is_some()
                        || self.widening
                        || self.mailbox_pending
                        || self.outstanding.is_some()
                    {
                        return Err(Error::State);
                    }
                    let gate = self.gate_ref()?;
                    if gate.did() != 0xb822 {
                        return Err(Error::State);
                    }
                    gate.current().map_err(Error::Power)?;
                    let r = &self.registers;
                    let result = async {
                        if r.read8(0x522).await? != 0
                            || r.read32(RXPKT_NUM).await? & RW_RELEASE != 0
                        {
                            return Ok(false);
                        }
                        Ok(true)
                    }
                    .await
                    .map_err(usb_error);
                    if !self.fail(result)? {
                        return Err(Error::Prerequisite);
                    }
                    self.tracking = true;
                    let r = &self.registers;
                    let result = async {
                        r.write8(0x522, 0xff).await?;
                        let rx = r.read32(RXPKT_NUM).await?;
                        r.write32(RXPKT_NUM, rx | RW_RELEASE).await
                    }
                    .await
                    .map_err(usb_error);
                    self.fail(result)?;
                    let result = self.b22_iqk_quiet().await;
                    self.fail(result)
                }
                Step::Quiet => {
                    if !self.tracking {
                        return Err(Error::State);
                    }
                    let result = self.b22_iqk_quiet().await;
                    self.fail(result)
                }
                Step::Submit => {
                    if !self.tracking || !self.b22_iqk_quiet().await? {
                        return Err(Error::State);
                    }
                    let packet = super::command::iqk8821c(self.h2c_sequence);
                    self.retune_h2c(&packet)?;
                    Ok(true)
                }
                Step::Finish => {
                    if !self.tracking || self.outstanding.is_some() || !self.b22_iqk_quiet().await?
                    {
                        return Err(Error::Prerequisite);
                    }
                    self.gate_current()?;
                    let r = &self.registers;
                    let result = async {
                        let rx = r.read32(RXPKT_NUM).await?;
                        r.write32(RXPKT_NUM, rx & !RW_RELEASE).await?;
                        r.write8(0x522, 0).await?;
                        Ok((
                            r.read32(RXPKT_NUM).await? & RW_RELEASE == 0,
                            r.read8(0x522).await? == 0,
                        ))
                    }
                    .await
                    .map_err(usb_error);
                    if self.fail(result)? != (true, true) {
                        return self.fail(Err(Error::Prerequisite));
                    }
                    self.tracking = false;
                    Ok(true)
                }
            }
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_retune_iqk(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            if self.state != State::Packets || self.retune.is_none() {
                return Err(Error::State);
            }
            let packet = super::command::iqk8821c(self.h2c_sequence);
            self.retune_h2c(&packet)
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_retune_finish(
        &mut self,
        channel: u8,
    ) -> impl core::future::Future<Output = Result<u64, Error>> + Send {
        async move {
            if self.retune != Some(channel) || self.retune_blocked() {
                return Err(Error::State);
            }
            let result = async {
                if !self.pause_quiet(false).await? {
                    return Err(Error::State);
                }
                let gate = self.gate_ref()?;
                if gate.channel() != channel {
                    return Err(Error::State);
                }
                gate.current().map_err(Error::Power)?;
                let r = &self.registers;
                r.write8(0x522, 0).await.map_err(usb_error)?;
                if r.read8(0x522).await.map_err(usb_error)? != 0 {
                    return Err(Error::Prerequisite);
                }
                Ok(())
            }
            .await;
            self.fail(result)?;
            self.channel = channel;
            self.channel_epoch = self.channel_epoch.checked_add(1).ok_or(Error::State)?;
            self.retune = None;
            if core::mem::take(&mut self.widening) {
                self.wide = true;
            }
            Ok(self.channel_epoch)
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_ht_program_quiet(
        &mut self,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        // `pci_firmware.rs::station_ht_program_quiet` over EP0.
        async move {
            firmware_transport::Io::station_allowed(self)?;
            if self.state != State::Packets || self.mailbox_pending {
                return Ok(false);
            }
            let result = self.transmit_quiet().await;
            self.fail(result)
        }
    }
    fn station_bind_host(
        &mut self,
        host: narf_net::native_emission::Lifetime,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        if !self.packet_ready() || self.mailbox_pending || self.outstanding.is_some() {
            return Err(Error::State);
        }
        self.rebind(|gate| gate.with_host(host))
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
            if self.retune.is_some() || !self.mailbox_ready().await? {
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
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn ps_mailbox_submit(
        &mut self,
        words: [u8; 8],
        scope: &mut firmware_transport::PsScope<'_>,
    ) -> impl core::future::Future<Output = Result<firmware_transport::PsSubmit, Error>> + Send
    {
        use firmware_transport::PsSubmit;
        // `pci_firmware.rs::ps_mailbox_submit` over EP0 (Linux fw.c
        // `rtw_fw_send_h2c_command`): HMETFR free, HMEBOX_EXT, then the
        // HMEBOX low word that publishes the command. The HMETFR recheck is
        // an EP0 read before the scope; inside it the host-side quiet and
        // gate checks run and the publishing EP0 write is begun (first poll),
        // so the source encloses the actual publication.
        async move {
            if self.state != State::Packets || self.retune.is_some() || self.tracking {
                return Err(Error::State);
            }
            if !self.mailbox_ready().await? {
                return Err(Error::State);
            }
            self.gate_current()?;
            let cursor = u16::from(self.mailbox_cursor);
            let bit = 1u8 << self.mailbox_cursor;
            let ext = u32::from_le_bytes([words[4], words[5], words[6], words[7]]);
            let body = u32::from_le_bytes([words[0], words[1], words[2], words[3]]);
            self.mailbox_pending = true;
            let staged = async {
                let r = &self.registers;
                r.write32(0x1f0 + cursor * 4, ext)
                    .await
                    .map_err(usb_error)?;
                let state = r.read8(0x1cc).await.map_err(usb_error)?;
                if state == 255 {
                    return Err(Error::Gone);
                }
                if state & bit != 0 {
                    return Err(Error::State);
                }
                Ok(())
            }
            .await;
            if let Err(e) = staged {
                self.mailbox_pending = false;
                return Err(e);
            }
            let (result, published, written) = {
                let this = &*self;
                let mut write = core::pin::pin!(async {
                    this.registers
                        .write32(0x1d0 + cursor * 4, body)
                        .await
                        .map_err(usb_error)
                });
                let mut published = false;
                let mut written = None;
                let result = scope(&mut || {
                    if !this.ps_publish_allowed()? {
                        return Ok(false);
                    }
                    published = true;
                    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
                    if let core::task::Poll::Ready(r) =
                        core::future::Future::poll(write.as_mut(), &mut cx)
                    {
                        written = Some(r);
                    }
                    Ok(true)
                });
                let written = match (published, written) {
                    (true, Some(r)) => r,
                    (true, None) => write.await,
                    (false, _) => Ok(()),
                };
                (result, published, written)
            };
            match (result, written) {
                (Ok(true), Ok(())) if published => Ok(PsSubmit::Issued),
                (Ok(false), _) if !published => {
                    self.mailbox_pending = false;
                    Ok(PsSubmit::Unissued)
                }
                (Err(e), _) if !published => {
                    self.mailbox_pending = false;
                    Err(e)
                }
                // Low word begun: mailbox ownership is ambiguous; never retry.
                _ => {
                    self.state = State::Terminal;
                    self.set_open(false);
                    Err(Error::State)
                }
            }
        }
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
            if self.state != State::Packets || self.opened() || self.outstanding.is_some() {
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
            self.set_open(true);
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
            let opened = self.open.swap(false, core::sync::atomic::Ordering::AcqRel);
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
    /// `usb.c::rtw_usb_dynamic_rx_agg` -> `rtw_usb_dynamic_rx_agg_v1`
    /// (`RTW_CHIP_TYPE_8821C` and `RTW_CHIP_TYPE_8822B`). Only with packets open; a failed EP0
    /// transfer leaves the backend terminal.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn dynamic_rx_agg(
        &mut self,
        enable: bool,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            if self.state != State::Packets || !self.opened() {
                return Err(Error::State);
            }
            let result = self
                .registers
                .dynamic_rx_agg(enable)
                .await
                .map_err(usb_error);
            self.fail(result)
        }
    }
    fn packet_ready(&self) -> bool {
        self.state == State::Packets
            && self.opened()
            && self.backlog.is_empty()
            && self.packets.as_ref().is_some_and(usb_packet::Owner::ready)
    }
    fn packet_submit(&mut self, frame: &[u8], report: bool) -> Result<u64, packet_core::Error> {
        if self.state != State::Packets || !self.opened() {
            return Err(packet_core::Error::State);
        }
        if self.retune.is_some() {
            return Err(packet_core::Error::State);
        }
        // `Port::transmit_allowed`: the signed station gate is current, and
        // a passive-only primary needs the passive TX grant.
        if self.gate_current().is_err() || self.passive_tx_allowed().is_err() {
            return Err(packet_core::Error::Access);
        }
        let result = self
            .packets
            .as_mut()
            .ok_or(packet_core::Error::State)
            .and_then(|owner| owner.submit(frame, report));
        self.packet_fail(result)
    }
    fn packet_aggregation(
        &mut self,
        cfg: Option<super::packet_format::Aggregation>,
    ) -> Result<(), Error> {
        // `pci_firmware.rs::packet_aggregation`: an envelope only within the
        // bound N21T grant.
        self.station_allowed()?;
        if cfg.is_some_and(|c| {
            self.gate
                .as_ref()
                .and_then(super::power_policy::Gate::tx_grant)
                .is_none_or(|g| !g.allows(c))
        }) {
            return Err(Error::Prerequisite);
        }
        self.packets
            .as_mut()
            .ok_or(Error::State)?
            .aggregation(cfg)
            .map_err(|_| Error::State)
    }
    fn packet_submit_batch(
        &mut self,
        b: &[alloc::vec::Vec<u8>],
    ) -> Result<alloc::vec::Vec<u64>, packet_core::Error> {
        if self.state != State::Packets || !self.opened() || self.retune.is_some() {
            return Err(packet_core::Error::State);
        }
        if self.gate_current().is_err() || self.passive_tx_allowed().is_err() {
            return Err(packet_core::Error::Access);
        }
        // `Port::originator_ba_allowed` + `batch_allowed`: a bound N21T
        // grant naming this TID (< 6) and admitting the DATA profile.
        let gate = self
            .gate_ref()
            .map_err(|_| packet_core::Error::Access)?
            .clone();
        let owner = self.packets.as_mut().ok_or(packet_core::Error::State)?;
        let profile = owner.data_profile();
        let tid = usb_packet::Owner::<P>::batch_tid(b)?;
        if tid >= 6
            || gate.tx_grant().is_none_or(|g| g.tids() & (1 << tid) == 0)
            || !gate.allows_profile(profile)
            || profile.tid_queue(tid).is_none()
        {
            return Err(packet_core::Error::Access);
        }
        // `batch_publication`: the burst is queued (and its first URB
        // begun) inside the current signed gate and all-AC continuation.
        let result = gate
            .invoke_batch(profile, || Ok(owner.submit_batch(b)))
            .map_err(|_| packet_core::Error::Access)
            .and_then(|r| r);
        // A refusal before anything was queued (PCI `Core` returns those
        // without failing) leaves the owner running; a failed URB begin
        // fails it, and with it the backend.
        if self
            .packets
            .as_ref()
            .is_some_and(usb_packet::Owner::running)
        {
            return result;
        }
        self.packet_fail(result)
    }
    fn packet_scan_address(&mut self, address: Option<[u8; 6]>) -> Result<(), packet_core::Error> {
        self.packets
            .as_mut()
            .ok_or(packet_core::Error::State)?
            .set_scan(address)
    }
    fn packet_profile(&mut self, profile: super::packet_format::DataProfile) -> Result<(), Error> {
        let gate = self.gate_ref()?.clone();
        if !gate.allows_profile(profile) {
            return Err(Error::Unsupported);
        }
        gate.current().map_err(Error::Power)?;
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
        let step = owner.poll(Self::now_us());
        let step = self.packet_fail(step)?;
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
        self.set_open(false);
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
        self.set_open(false);
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

/// `firmware_transport::Read32` over EP0 (signed-record readbacks).
struct Read<'a, C: ControlIo>(&'a Registers<C>);
impl<C: ControlIo> firmware_transport::Read32 for Read<'_, C> {
    fn read32(
        &mut self,
        reg: u16,
    ) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        let r = self.0;
        async move { r.read32(reg).await.map_err(usb_error) }
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
