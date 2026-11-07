//! RMI4-over-SMBus transport driver.
//!
//! Wraps the [`crate::rmi4_core::Rmi4Transport`] register protocol
//! around the Synaptics SMBus wire format, so a Synaptics touchpad
//! attached to the platform SMBus controller (ICH/PCH, or any
//! adapter behind the [`SmbusIo`] trait) can be probed, PDT-walked,
//! and read through the same F$01 / F$11 / F$12 / F$30 decoders the
//! HID transport uses.
//!
//! Reference (read post-relicense, GPL-2.0-or-later):
//! `drivers/input/rmi4/rmi_smbus.c` — the Synaptics-origin file
//! (Benjamin Tissoires, 2016) that upstream Linux still ships.
//! The constants and framing below cite it directly:
//!
//! - `SMB_PROTOCOL_VERSION_ADDRESS 0xFD` — probe reads a byte
//!   here; the protocol version is the value + 1 (`rmi_smb_probe`).
//! - `RMI_PAGE_SELECT_REGISTER 0xFF`, `RMI_SMB_PAGE(addr)` —
//!   the 16-bit RMI4 space is paged through register 0xFF on
//!   every page (`rmi_set_page`).
//! - `SMB_MAX_COUNT 32` — SMBus block transfers cap at 32 bytes.
//! - v1 ("smb1"): page-select is a 2-byte master send
//!   `{0xFF, page}`; a register write is a master send of
//!   `{addr_lo, data...}`; a register read sends `{addr_lo}`
//!   then receives `len` bytes (`rmi_smb_v1_write_block` /
//!   `rmi_smb_v1_read_block`).
//! - v2 ("smb2"): an 8-entry mapping table of 4-byte entries
//!   `{rmiaddr:u16 LE, readcount:u8, flags:u8 (WE=0x01)}`,
//!   programmed with a block write to command code `0x80+i`;
//!   reads/writes then go through `i2c_smbus_read_block_data` /
//!   `i2c_smbus_write_block_data` with the table index as the
//!   command code (`rmi_smb_v2_get_command_code`,
//!   `smb_v2_block_read`, `smb_v2_block_write`). Chunks are
//!   ≤32 bytes and `rmiaddr` advances by the chunk size.
//!
//! NARF mapping notes (where the ICH host differs from Linux's
//! `i2c_client` adapter):
//!
//! - v1 page-select `{0xFF, page}` is wire-identical to an SMBus
//!   Write Byte Data transaction with command `0xFF` and data
//!   `page`, so it goes through the existing `write_byte_data`
//!   host op. Likewise a 1-byte v1 write is `write_byte_data`
//!   with command `addr_lo`, and a 2-byte v1 write is
//!   `write_word_data` — both produce exactly the v1 master-send
//!   bytes. Longer v1 writes are issued as sequential byte-data
//!   writes to incrementing addresses, which is semantically
//!   identical to one master send because the device
//!   auto-increments its register pointer.
//! - v1 reads are assembled from word/byte reads for the same
//!   reason: the ICH host has no verified plain-I2C block-read
//!   op (its block read is the count-led SMBus form, which the
//!   v1 device does not speak), so each 2-byte chunk is one
//!   `read_word_data` at the chunk's address. Slower than a
//!   single block read, but correct — and the probe path only
//!   ever reads 6-byte PDT entries and 11-byte query blocks.
//! - v2 reads use the existing `read_block_data` host op
//!   (SMBus Block Read, count-led — exactly what
//!   `smb_v2_block_read` wraps). v2 writes need the new
//!   [`Smbus::write_block_data`] host op (SMBus Block Write).
//!   v2 write chunks are capped at 31 data bytes so the echoed
//!   command code keeps the block within the 32-byte SMBus
//!   limit (the reference driver passes `len+1` with `len ≤ 32`,
//!   which overruns the limit for a full 32-byte write).
//!
//! Binding: there is no ACPI enumeration for SMBus touchpads —
//! Linux learns the address from psmouse platform data filled
//! by the PS/2 companion driver. NARF has no such companion, so
//! the probe tries the de-facto Synaptics address `0x2C` (the
//! address Linux logs as `rmi4_smbus 6-002c` on ThinkPads) once
//! the SMBus controller is up, and declines anything whose F$01
//! manufacturer is not Synaptics. A stray version read at
//! `0xFD` on an unrelated device at `0x2C` is a benign SMBus
//! read; the only write a non-RMI4 device can see is one
//! page-select to register `0xFF`, which unimplemented-register
//! writes ignore or NAK.
//!
//! The ATTN-driven report pump lives in [`crate::smbus_rmi_attn`]:
//! it routes the attention GPIO/IRQ from the touchpad's ACPI
//! `GpioInt` (falling back to a coordinated status poll through
//! the shared controller when no IRQ is routable) and services
//! each attention by reading the F$01 interrupt status and
//! pumping F$12/F$11 + F$30 through this transport.

extern crate alloc;

use core::fmt::Write as _;

use narf_drivers_platform::smbus::{Smbus, SmbusError};

use crate::rmi4_core::{probe_device, Rmi4DeviceProbe, Rmi4Transport, TransportError};

/// De-facto Synaptics SMBus touchpad address (7-bit). See the
/// module docs for why the probe uses a fixed address.
pub const SMBUS_RMI_DEFAULT_ADDR: u8 = 0x2C;

/// Command byte that reports the SMBus protocol version
/// (`rmi_smbus.c:40`). The version is the returned byte + 1.
pub const SMB_PROTOCOL_VERSION_ADDRESS: u8 = 0xFD;

/// RMI4 page-select register — present at 0xFF of every page
/// (`rmi_smbus.c:42`).
pub const RMI_PAGE_SELECT_REGISTER: u8 = 0xFF;

/// SMBus block-transfer cap, in bytes (`rmi_smbus.c:46`).
pub const SMB_MAX_COUNT: usize = 32;

/// v2 mapping-table size, in entries (`rmi_smbus.c:48`).
pub const RMI_SMB2_MAP_SIZE: usize = 8;

/// v2 mapping-table write command codes start here: entry `i`
/// is programmed with a block write to `0x80 + i`
/// (`rmi_smbus.c:763`).
pub const RMI_SMB2_MAP_CMD_BASE: u8 = 0x80;

/// v2 mapping-entry flag: the entry may be used for writes
/// (`rmi_smbus.c:50`).
pub const RMI_SMB2_MAP_FLAGS_WE: u8 = 0x01;

/// RMI4-over-SMBus protocol version, negotiated by the probe.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SmbusRmiVersion {
    /// v1 ("smb1"): plain master send/recv framing.
    V1,
    /// v2 ("smb2"): mapping-table + SMBus block transfers.
    V2,
}

/// Minimal SMBus host surface the transport needs. Implemented
/// for the real ICH host ([`Smbus`]) and for fixtures; the
/// transport never touches PIO directly.
pub trait SmbusIo: core::fmt::Debug {
    fn read_byte_data(&self, addr: u8, cmd: u8) -> Result<u8, SmbusError>;
    fn write_byte_data(&self, addr: u8, cmd: u8, value: u8) -> Result<(), SmbusError>;
    fn read_word_data(&self, addr: u8, cmd: u8) -> Result<u16, SmbusError>;
    fn write_word_data(&self, addr: u8, cmd: u8, value: u16) -> Result<(), SmbusError>;
    fn read_block_data(&self, addr: u8, cmd: u8, buf: &mut [u8]) -> Result<usize, SmbusError>;
    fn write_block_data(&self, addr: u8, cmd: u8, data: &[u8]) -> Result<(), SmbusError>;
}

impl SmbusIo for Smbus {
    fn read_byte_data(&self, addr: u8, cmd: u8) -> Result<u8, SmbusError> {
        Smbus::read_byte_data(self, addr, cmd)
    }
    fn write_byte_data(&self, addr: u8, cmd: u8, value: u8) -> Result<(), SmbusError> {
        Smbus::write_byte_data(self, addr, cmd, value)
    }
    fn read_word_data(&self, addr: u8, cmd: u8) -> Result<u16, SmbusError> {
        Smbus::read_word_data(self, addr, cmd)
    }
    fn write_word_data(&self, addr: u8, cmd: u8, value: u16) -> Result<(), SmbusError> {
        Smbus::write_word_data(self, addr, cmd, value)
    }
    fn read_block_data(&self, addr: u8, cmd: u8, buf: &mut [u8]) -> Result<usize, SmbusError> {
        Smbus::read_block_data(self, addr, cmd, buf)
    }
    fn write_block_data(&self, addr: u8, cmd: u8, data: &[u8]) -> Result<(), SmbusError> {
        Smbus::write_block_data(self, addr, cmd, data)
    }
}

impl<H: SmbusIo> SmbusIo for &H {
    fn read_byte_data(&self, addr: u8, cmd: u8) -> Result<u8, SmbusError> {
        (*self).read_byte_data(addr, cmd)
    }
    fn write_byte_data(&self, addr: u8, cmd: u8, value: u8) -> Result<(), SmbusError> {
        (*self).write_byte_data(addr, cmd, value)
    }
    fn read_word_data(&self, addr: u8, cmd: u8) -> Result<u16, SmbusError> {
        (*self).read_word_data(addr, cmd)
    }
    fn write_word_data(&self, addr: u8, cmd: u8, value: u16) -> Result<(), SmbusError> {
        (*self).write_word_data(addr, cmd, value)
    }
    fn read_block_data(&self, addr: u8, cmd: u8, buf: &mut [u8]) -> Result<usize, SmbusError> {
        (*self).read_block_data(addr, cmd, buf)
    }
    fn write_block_data(&self, addr: u8, cmd: u8, data: &[u8]) -> Result<(), SmbusError> {
        (*self).write_block_data(addr, cmd, data)
    }
}

fn map_smbus_error(e: SmbusError) -> TransportError {
    match e {
        SmbusError::Timeout | SmbusError::Busy => TransportError::Timeout,
        SmbusError::BarMissing => TransportError::NotReady,
        SmbusError::DeviceError | SmbusError::BusError | SmbusError::Failed => {
            TransportError::Protocol
        }
    }
}

/// One v2 mapping-table entry — `{rmiaddr:u16 LE, readcount:u8,
/// flags:u8}` (`rmi_smbus.c:58-76`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct MappingEntry {
    rmiaddr: u16,
    readcount: u8,
    flags: u8,
}

/// RMI4-over-SMBus transport. Generic over [`SmbusIo`] so
/// fixtures can drive it without PIO.
#[derive(Debug)]
pub struct SmbusRmiTransport<H: SmbusIo> {
    io: H,
    addr: u8,
    version: Option<SmbusRmiVersion>,
    /// Last page written via the page-select register —
    /// `Some(page)` only after `set_page` succeeded. v1 only;
    /// v2 addressing goes through the mapping table.
    page: Option<u8>,
    map: [MappingEntry; RMI_SMB2_MAP_SIZE],
    /// Next mapping slot to allocate (round-robin, as the
    /// reference driver's `table_index`).
    map_next: usize,
}

/// Device-side session state the ATTN pump carries between
/// service passes.
///
/// The pump cannot hold a [`SmbusRmiTransport`] across awaits:
/// the transport borrows the shared controller out of
/// [`narf_drivers_platform::smbus::with_controller`], which
/// holds the controller spinlock for the closure only. So each
/// pass rebuilds a transport from this state
/// ([`SmbusRmiTransport::from_state`]) and writes it back
/// ([`SmbusRmiTransport::into_state`]) — the negotiated
/// version, the v1 page cache, and the v2 mapping table survive
/// across passes, so the device-side mapping table is not
/// re-programmed on every touch frame.
#[derive(Clone, Debug, Default)]
pub struct SmbusRmiSessionState {
    version: Option<SmbusRmiVersion>,
    page: Option<u8>,
    map: [MappingEntry; RMI_SMB2_MAP_SIZE],
    map_next: usize,
}

impl<H: SmbusIo> SmbusRmiTransport<H> {
    pub fn new(io: H, addr: u8) -> Self {
        Self {
            io,
            addr,
            version: None,
            page: None,
            map: [MappingEntry::default(); RMI_SMB2_MAP_SIZE],
            map_next: 0,
        }
    }

    /// Rebuild a transport from pump-carried session state —
    /// same negotiated version / page / mapping table as the
    /// transport the state came from, so no re-negotiation or
    /// mapping-table re-programming happens on the next pass.
    pub fn from_state(io: H, addr: u8, state: SmbusRmiSessionState) -> Self {
        Self {
            io,
            addr,
            version: state.version,
            page: state.page,
            map: state.map,
            map_next: state.map_next,
        }
    }

    /// Hand the session state back to the pump after a pass.
    pub fn into_state(self) -> SmbusRmiSessionState {
        SmbusRmiSessionState {
            version: self.version,
            page: self.page,
            map: self.map,
            map_next: self.map_next,
        }
    }

    /// Negotiated protocol version (`None` before [`Self::probe_version`]).
    pub fn version(&self) -> Option<SmbusRmiVersion> {
        self.version
    }

    /// Negotiate the protocol version: read a byte at
    /// `SMB_PROTOCOL_VERSION_ADDRESS`; the version is the value
    /// + 1 (`rmi_smb_probe`). v1 additionally sets the page to 0
    ///   — which both puts the page-select register in a known
    ///   state and proves the device answers. Any other version
    ///   (or a failed read) declines the device.
    pub fn probe_version(&mut self) -> Result<SmbusRmiVersion, TransportError> {
        let v = self
            .io
            .read_byte_data(self.addr, SMB_PROTOCOL_VERSION_ADDRESS)
            .map_err(map_smbus_error)?;
        let version = match v.wrapping_add(1) {
            1 => SmbusRmiVersion::V1,
            2 => SmbusRmiVersion::V2,
            _ => return Err(TransportError::Protocol),
        };
        self.version = Some(version);
        if version == SmbusRmiVersion::V1 {
            self.set_page(0)?;
        }
        Ok(version)
    }

    /// Switch RMI page via the page-select register (v1 only).
    /// Cached so repeated reads in the same page don't re-issue.
    /// Wire-identical to the reference `{0xFF, page}` master
    /// send: an SMBus Write Byte Data with command `0xFF`.
    fn set_page(&mut self, page: u8) -> Result<(), TransportError> {
        if self.page == Some(page) {
            return Ok(());
        }
        self.io
            .write_byte_data(self.addr, RMI_PAGE_SELECT_REGISTER, page)
            .map_err(map_smbus_error)?;
        self.page = Some(page);
        Ok(())
    }

    fn require_version(&self) -> Result<SmbusRmiVersion, TransportError> {
        self.version.ok_or(TransportError::NotReady)
    }

    // ── v1 (plain master send/recv framing) ─────────────────────

    fn v1_read_block(&mut self, addr: u16, dst: &mut [u8]) -> Result<(), TransportError> {
        // The reference does one master-recv of the whole block
        // with the device auto-incrementing; the ICH host has no
        // such op, so the block is assembled from word/byte
        // reads at incrementing addresses (page switches when a
        // chunk crosses a page boundary).
        let mut off = 0usize;
        while off < dst.len() {
            let cur = addr.wrapping_add(off as u16);
            self.set_page((cur >> 8) as u8)?;
            let cmd = cur as u8;
            if off + 1 < dst.len() && (cur & 0xFF) != 0xFF {
                let w = self
                    .io
                    .read_word_data(self.addr, cmd)
                    .map_err(map_smbus_error)?;
                dst[off..off + 2].copy_from_slice(&w.to_le_bytes());
                off += 2;
            } else {
                dst[off] = self
                    .io
                    .read_byte_data(self.addr, cmd)
                    .map_err(map_smbus_error)?;
                off += 1;
            }
        }
        Ok(())
    }

    fn v1_write_block(&mut self, addr: u16, src: &[u8]) -> Result<(), TransportError> {
        // Sequential byte-data writes to incrementing addresses —
        // semantically identical to one `{addr_lo, data...}`
        // master send (see the module docs).
        for (i, b) in src.iter().enumerate() {
            let cur = addr.wrapping_add(i as u16);
            self.set_page((cur >> 8) as u8)?;
            self.io
                .write_byte_data(self.addr, cur as u8, *b)
                .map_err(map_smbus_error)?;
        }
        Ok(())
    }

    // ── v2 (mapping table + SMBus block transfers) ──────────────

    /// Resolve (or allocate) the command code for a transfer,
    /// mirroring `rmi_smb_v2_get_command_code`: reuse an entry
    /// matching `(rmiaddr, readcount)` for reads or
    /// `(rmiaddr, WE)` for writes; otherwise allocate the next
    /// round-robin slot and program the device's mapping table
    /// with a block write to `0x80 + i`.
    fn v2_command_code(
        &mut self,
        rmiaddr: u16,
        bytecount: u8,
        is_read: bool,
    ) -> Result<u8, TransportError> {
        for (i, e) in self.map.iter().enumerate() {
            if e.rmiaddr == rmiaddr {
                if is_read {
                    if e.readcount == bytecount {
                        return Ok(i as u8);
                    }
                } else if e.flags & RMI_SMB2_MAP_FLAGS_WE != 0 {
                    return Ok(i as u8);
                }
            }
        }
        let i = self.map_next;
        self.map_next = (i + 1) % RMI_SMB2_MAP_SIZE;
        let entry = MappingEntry {
            rmiaddr,
            readcount: bytecount,
            flags: RMI_SMB2_MAP_FLAGS_WE,
        };
        // Program the device-side table: block write to
        // 0x80+i with data [0x80+i, rmiaddr_lo, rmiaddr_hi,
        // readcount, flags] — the command code is echoed as the
        // first data byte, exactly as `smb_v2_block_write`
        // builds it.
        let cmd = RMI_SMB2_MAP_CMD_BASE + i as u8;
        let tx = [
            cmd,
            (rmiaddr & 0xFF) as u8,
            (rmiaddr >> 8) as u8,
            bytecount,
            RMI_SMB2_MAP_FLAGS_WE,
        ];
        self.io
            .write_block_data(self.addr, cmd, &tx)
            .map_err(map_smbus_error)?;
        self.map[i] = entry;
        Ok(i as u8)
    }

    fn v2_read_block(&mut self, addr: u16, dst: &mut [u8]) -> Result<(), TransportError> {
        let mut off = 0usize;
        let mut cur = addr;
        while off < dst.len() {
            let chunk_len = (dst.len() - off).min(SMB_MAX_COUNT);
            let cmd = self.v2_command_code(cur, chunk_len as u8, true)?;
            let mut buf = [0u8; SMB_MAX_COUNT];
            let n = self
                .io
                .read_block_data(self.addr, cmd, &mut buf)
                .map_err(map_smbus_error)?;
            if n != chunk_len {
                return Err(TransportError::Short);
            }
            dst[off..off + chunk_len].copy_from_slice(&buf[..chunk_len]);
            off += chunk_len;
            cur = cur.wrapping_add(chunk_len as u16);
        }
        Ok(())
    }

    fn v2_write_block(&mut self, addr: u16, src: &[u8]) -> Result<(), TransportError> {
        let mut off = 0usize;
        let mut cur = addr;
        while off < src.len() {
            // Cap data at 31 bytes: the echoed command code is
            // the 32nd block byte (see the module docs).
            let chunk_len = (src.len() - off).min(SMB_MAX_COUNT - 1);
            let cmd = self.v2_command_code(cur, chunk_len as u8, false)?;
            let mut tx = alloc::vec![0u8; chunk_len + 1];
            tx[0] = cmd;
            tx[1..].copy_from_slice(&src[off..off + chunk_len]);
            self.io
                .write_block_data(self.addr, cmd, &tx)
                .map_err(map_smbus_error)?;
            off += chunk_len;
            cur = cur.wrapping_add(chunk_len as u16);
        }
        Ok(())
    }
}

impl<H: SmbusIo> Rmi4Transport for SmbusRmiTransport<H> {
    fn read_block(&mut self, addr: u16, dst: &mut [u8]) -> Result<(), TransportError> {
        match self.require_version()? {
            SmbusRmiVersion::V1 => self.v1_read_block(addr, dst),
            SmbusRmiVersion::V2 => self.v2_read_block(addr, dst),
        }
    }

    fn write_block(&mut self, addr: u16, src: &[u8]) -> Result<(), TransportError> {
        match self.require_version()? {
            SmbusRmiVersion::V1 => self.v1_write_block(addr, src),
            SmbusRmiVersion::V2 => self.v2_write_block(addr, src),
        }
    }
}

/// Probe one SMBus address as an RMI4 touchpad: negotiate the
/// protocol version, walk the page-0 PDT, and read the F$01
/// product info. Returns the negotiated version plus the probe
/// on success, or `None` when nothing answers, the version is
/// unrecognised, or the device is not a Synaptics part — the
/// caller declines the address in all those cases.
pub fn probe_at<H: SmbusIo>(io: H, addr: u8) -> Option<(SmbusRmiVersion, Rmi4DeviceProbe)> {
    probe_at_with_state(io, addr).map(|(version, probe, _)| (version, probe))
}

/// [`probe_at`] plus the post-probe session state, so the ATTN
/// pump can rebuild the transport without re-negotiating the
/// version or re-programming the v2 mapping table. The state
/// captures the transport exactly as the probe left it (v1 page
/// 0 selected; v2 mapping slots programmed by the PDT walk and
/// query reads).
pub fn probe_at_with_state<H: SmbusIo>(
    io: H,
    addr: u8,
) -> Option<(SmbusRmiVersion, Rmi4DeviceProbe, SmbusRmiSessionState)> {
    let mut transport = SmbusRmiTransport::new(io, addr);
    let version = transport.probe_version().ok()?;
    let probe = probe_device(&mut transport).ok()?;
    if !probe.product.is_synaptics() {
        return None;
    }
    let state = transport.into_state();
    Some((version, probe, state))
}

/// Probe the default Synaptics address (`0x2C`) on the platform
/// SMBus controller, if one is up. Logs the binding; returns the
/// probe on success. Runs inside `with_controller`, so the
/// transport never outlives the controller borrow.
pub fn probe_smbus_rmi() -> Option<Rmi4DeviceProbe> {
    probe_smbus_rmi_with_state().map(|(probe, _)| probe)
}

/// [`probe_smbus_rmi`] plus the post-probe session state, for
/// the ATTN pump ([`crate::smbus_rmi_attn`]): the pump needs the
/// probe and the transport state together, and re-probing here
/// is the only way to get both — the Stage::Device probe above
/// keeps only the probe.
pub fn probe_smbus_rmi_with_state() -> Option<(Rmi4DeviceProbe, SmbusRmiSessionState)> {
    narf_drivers_platform::smbus::with_controller(|c| {
        let (version, probe, state) = probe_at_with_state(c, SMBUS_RMI_DEFAULT_ADDR)?;
        let _ = writeln!(
            narf_console::Writer,
            "  smbus-rmi: bound addr={:#04x} version={:?} manufacturer={} f11={} f12={} f30={}",
            SMBUS_RMI_DEFAULT_ADDR,
            version,
            probe.product.manufacturer_id,
            probe.f11.is_some(),
            probe.f12.is_some(),
            probe.f30.is_some(),
        );
        Some((probe, state))
    })
    .flatten()
}

/// Stage::Device initcall: probe the SMBus RMI4 transport once
/// the SMBus controller is up (the platform `smbus` probe runs
/// at Stage::Subsys, so the controller is registered by now when
/// present). `NotPresent` when there is no controller or no
/// Synaptics touchpad answers at the default address.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "smbus-rmi-probe", || {
        match probe_smbus_rmi() {
            Some(_) => InitResult::Ok,
            None => InitResult::NotPresent,
        }
    });
}
