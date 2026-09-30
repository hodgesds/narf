//! Firmware-owned Type-C connectors. Wire definitions checked against Linux
//! `drivers/usb/typec/ucsi/{ucsi.h,ucsi.c,displayport.c}`.
//!
//! One task owns a PPM and serializes command -> completion -> acknowledgement.
//! Notifications never execute AML or issue commands in interrupt context.
use alloc::{string::String, sync::Arc, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;

pub const COMPLETE: u32 = 1 << 31;
pub const ERROR: u32 = 1 << 30;
pub const ACK_COMPLETE: u32 = 1 << 29;
pub const BUSY: u32 = 1 << 28;
pub const RESET_COMPLETE: u32 = 1 << 27;
pub const NOT_SUPPORTED: u32 = 1 << 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io,
    Timeout,
    Unsupported,
    Protocol,
    Ppm,
    NeedsReset,
}

/// Implementations must bound all accesses to the advertised shared region.
pub trait Transport: Send {
    fn version(&mut self) -> Result<u16, Error>;
    fn cci(&mut self) -> Result<u32, Error>;
    fn control(&mut self, command: u64) -> Result<(), Error>;
    fn message(&mut self, data: &mut [u8]) -> Result<(), Error>;
}

/// A stable identity includes the PPM path: connector numbers are only local
/// to one PPM and must never be interpreted as GPU encoder indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connector {
    pub ppm: String,
    pub number: u8,
    /// False after transport failure; an unavailable port is not a detach report.
    pub available: bool,
    pub connected: bool,
    pub source: bool,
    pub partner_type: u8,
    pub power_mode: u8,
    /// UCSI 1.x does not report orientation.
    pub reversed: Option<bool>,
    pub usb: bool,
    pub usb4: bool,
    /// Current firmware CAM, if alternate-mode details are supported.
    pub active_mode: Option<AltMode>,
    pub modes: Vec<AltMode>,
    pub capability: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltMode {
    pub index: u8,
    pub svid: u16,
    pub vdo: u32,
}

impl Connector {
    fn new(ppm: &str, number: u8) -> Self {
        Self {
            ppm: ppm.into(),
            number,
            available: false,
            connected: false,
            source: false,
            partner_type: 0,
            power_mode: 0,
            reversed: None,
            usb: false,
            usb4: false,
            active_mode: None,
            modes: Vec::new(),
            capability: 0,
        }
    }

    fn status(&mut self, version: u16, data: &[u8]) -> Result<(), Error> {
        if data.len() < 9 || (version >= 0x0200 && data.len() < 11) {
            return Err(Error::Protocol);
        }
        let flags = u32::from_le_bytes(data[..4].try_into().unwrap());
        self.available = true;
        self.connected = flags & (1 << 19) != 0;
        self.source = self.connected && flags & (1 << 20) != 0;
        self.power_mode = if self.connected {
            ((flags >> 16) & 7) as u8
        } else {
            0
        };
        self.partner_type = if self.connected {
            (flags >> 29) as u8
        } else {
            0
        };
        self.usb = self.connected && flags & (1 << 21) != 0;
        self.usb4 = self.connected && version >= 0x0200 && flags & (3 << 23) != 0;
        self.reversed = (self.connected && version >= 0x0200).then(|| data[10] & 0x40 != 0);
        if !self.connected {
            self.active_mode = None;
        }
        Ok(())
    }
}

/// Observers run in task context, with no registry lock held. Firmware has
/// already selected the mux; observers must not transmit raw PD messages.
pub trait ConnectorObserver: Send + Sync {
    fn changed(&self, connector: &Connector);
}
static CONNECTORS: IrqSafeSpinLock<Vec<Connector>> = IrqSafeSpinLock::new(Vec::new());
static OBSERVERS: IrqSafeSpinLock<Vec<Arc<dyn ConnectorObserver>>> =
    IrqSafeSpinLock::new(Vec::new());
type TypecEntry = (String, u8, Arc<narf_drivers_extcon::typec::TypecConnector>);
static TYPEC: IrqSafeSpinLock<Vec<TypecEntry>> = IrqSafeSpinLock::new(Vec::new());
pub fn connectors() -> Vec<Connector> {
    CONNECTORS.lock().clone()
}
pub(crate) fn invalidate(path: &str) {
    for old in connectors().into_iter().filter(|c| c.ppm == path) {
        let mut unavailable = Connector::new(path, old.number);
        unavailable.capability = old.capability;
        unavailable.modes = old.modes;
        publish(&unavailable);
    }
}
pub fn register_observer(observer: Arc<dyn ConnectorObserver>) {
    OBSERVERS.lock().push(observer.clone());
    for connector in connectors() {
        observer.changed(&connector);
    }
}
fn publish(connector: &Connector) {
    let changed = {
        let mut list = CONNECTORS.lock();
        if let Some(old) = list
            .iter_mut()
            .find(|c| c.ppm == connector.ppm && c.number == connector.number)
        {
            if old == connector {
                false
            } else {
                *old = connector.clone();
                true
            }
        } else {
            list.push(connector.clone());
            true
        }
    };
    if changed {
        use narf_drivers_extcon::typec::{
            DataRole, FirmwareState, Orientation, PowerRole, TypecConnector,
        };
        let typec = {
            let mut list = TYPEC.lock();
            if let Some((_, _, c)) = list
                .iter()
                .find(|(path, number, _)| path == &connector.ppm && *number == connector.number)
            {
                c.clone()
            } else {
                // Connector identities and names are boot-lifetime objects.
                let name = alloc::boxed::Box::leak(
                    alloc::format!("{}:{}", connector.ppm, connector.number).into_boxed_str(),
                );
                let c = Arc::new(TypecConnector::new(name));
                narf_drivers_extcon::class::register(c.clone());
                list.push((connector.ppm.clone(), connector.number, c.clone()));
                c
            }
        };
        typec.update_firmware(FirmwareState {
            orientation: match connector.reversed {
                Some(false) => Orientation::Normal,
                Some(true) => Orientation::Reversed,
                None => Orientation::Unknown,
            },
            power_role: if !connector.connected {
                PowerRole::Dual
            } else if connector.source {
                PowerRole::Source
            } else {
                PowerRole::Sink
            },
            data_role: match connector.partner_type {
                1 => DataRole::Device,
                2 | 4 => DataRole::Host,
                _ => DataRole::Dual,
            },
            connected: connector.connected,
            usb: connector.usb,
            usb4: connector.usb4,
            audio: connector.partner_type == 6,
            displayport: connector.active_mode.is_some_and(|m| m.svid == 0xff01),
        });
        let observers = OBSERVERS.lock().clone();
        for observer in observers {
            observer.changed(connector);
        }
    }
}

/// Pollable command handshake, kept separate from the timer for device-model
/// tests. Timeout/ACK failure poisons the PPM until an explicit reset.
#[derive(Debug)]
pub struct Ppm<T> {
    io: T,
    pub version: u16,
    pub features: u16,
    pending_connectors: [bool; 128],
    healthy: bool,
    path: String,
    connector_count: u8,
}
impl<T: Transport> Ppm<T> {
    pub fn new(mut io: T) -> Result<Self, Error> {
        let version = io.version()?;
        if !matches!(version, 0x0100 | 0x0110 | 0x0120 | 0x0200 | 0x0210 | 0x0300) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            io,
            version,
            features: 0,
            pending_connectors: [false; 128],
            healthy: false,
            path: String::new(),
            connector_count: 0,
        })
    }
    fn read_cci(&mut self) -> Result<u32, Error> {
        let cci = self.io.cci()?;
        let connector = ((cci >> 1) & 127) as usize;
        if connector != 0 {
            self.pending_connectors[connector] = true;
        }
        Ok(cci)
    }
    async fn wait(&mut self, expected: u32) -> Result<u32, Error> {
        let deadline = narf_time::Deadline::after_ms(5000);
        loop {
            let cci = self.read_cci()?;
            if cci & BUSY == 0 && cci & expected != 0 {
                return Ok(cci);
            }
            if deadline.expired() {
                self.healthy = false;
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(20).as_instant()).await;
        }
    }
    pub async fn reset(&mut self) -> Result<(), Error> {
        self.healthy = false;
        if self.read_cci()? & RESET_COMPLETE != 0 {
            self.io.control(5)?;
            let _ = self.wait(COMPLETE).await;
        }
        self.io.control(1)?;
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(20).as_instant()).await;
        self.wait(RESET_COMPLETE).await?;
        self.pending_connectors.fill(false);
        self.healthy = true;
        Ok(())
    }
    fn response(&mut self, cci: u32, data: &mut [u8]) -> Result<usize, Error> {
        if cci & COMPLETE == 0 || cci & BUSY != 0 {
            return Err(Error::Protocol);
        }
        if cci & NOT_SUPPORTED != 0 {
            return Err(Error::Unsupported);
        }
        if cci & ERROR != 0 {
            return Err(Error::Ppm);
        }
        let len = ((cci >> 8) & 255) as usize;
        if len > data.len() || (self.version <= 0x0120 && len > 16) {
            return Err(Error::Protocol);
        }
        self.io.message(&mut data[..len])?;
        Ok(len)
    }
    async fn command(
        &mut self,
        command: u64,
        data: &mut [u8],
        connector_ack: bool,
    ) -> Result<usize, Error> {
        if !self.healthy {
            return Err(Error::NeedsReset);
        }
        // Remain poisoned if either transport operation fails. A stale response
        // must never be attributed to the next command.
        self.healthy = false;
        self.io.control(command)?;
        let cci = self.wait(COMPLETE).await?;
        let response = self.response(cci, data);
        let ack = 4
            | (1 << 17)
            | if connector_ack && response.is_ok() {
                1 << 16
            } else {
                0
            };
        self.io.control(ack)?;
        self.wait(ACK_COMPLETE).await?;
        self.healthy = true;
        response
    }
    pub async fn initialize(&mut self, path: &str) -> Result<Vec<Connector>, Error> {
        self.reset().await?;
        self.command(5 | (1 << 16) | (1 << 31), &mut [], false)
            .await?;
        let mut cap = [0; 16];
        if self.command(6, &mut cap, false).await? != 16 {
            return Err(Error::Protocol);
        }
        let count = cap[4] & 127;
        if count == 0 {
            return Err(Error::Protocol);
        }
        self.features = u16::from_le_bytes([cap[5], cap[6]]);
        self.path = path.into();
        self.connector_count = count;
        let mut ports = Vec::new();
        for number in 1..=count {
            let mut port = Connector::new(path, number);
            let mut cap = [0; 4];
            if self
                .command(7 | ((number as u64) << 16), &mut cap, false)
                .await?
                < 2
            {
                return Err(Error::Protocol);
            }
            port.capability = u32::from_le_bytes(cap);
            if self.features & 4 != 0 {
                for index in 0..cap_altmode_limit() {
                    let mut mode = [0; 6];
                    let command = 0x0c | ((number as u64) << 24) | ((index as u64) << 32);
                    let len = self.command(command, &mut mode, false).await?;
                    if len == 0 {
                        break;
                    }
                    if len != 6 {
                        return Err(Error::Protocol);
                    }
                    let svid = u16::from_le_bytes([mode[0], mode[1]]);
                    if svid == 0 {
                        break;
                    }
                    port.modes.push(AltMode {
                        index,
                        svid,
                        vdo: u32::from_le_bytes(mode[2..6].try_into().unwrap()),
                    });
                }
            }
            self.refresh(&mut port, false).await?;
            ports.push(port);
        }
        // Command/error, connect, partner, direction, operating mode and CAM.
        self.command(5 | 0xD905_0000, &mut [], false).await?;
        for port in &ports {
            publish(port);
        }
        Ok(ports)
    }
    async fn refresh(&mut self, port: &mut Connector, ack: bool) -> Result<(), Error> {
        if port.ppm != self.path || port.number == 0 || port.number > self.connector_count {
            return Err(Error::Protocol);
        }
        let mut data = [0; 19];
        let limit = if self.version <= 0x0120 { 16 } else { 19 };
        let len = self
            .command(0x12 | ((port.number as u64) << 16), &mut data[..limit], ack)
            .await?;
        port.status(self.version, &data[..len])?;
        if port.connected && self.features & 4 != 0 {
            let mut cam = [0xff];
            match self
                .command(0x0e | ((port.number as u64) << 16), &mut cam, false)
                .await
            {
                Ok(1) => port.active_mode = port.modes.iter().find(|m| m.index == cam[0]).copied(),
                Err(Error::Unsupported) => port.active_mode = None,
                Ok(_) => return Err(Error::Protocol),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    /// Select a mode only when firmware advertises OS override. `configuration`
    /// is the mode-specific Configure VDO, never a synthetic lane count.
    pub async fn set_mode(
        &mut self,
        port: &Connector,
        index: u8,
        configuration: u32,
        enter: bool,
    ) -> Result<(), Error> {
        if self.features & 8 == 0 {
            return Err(Error::Unsupported);
        }
        if port.ppm != self.path
            || port.number == 0
            || port.number > self.connector_count
            || index >= cap_altmode_limit()
        {
            return Err(Error::Protocol);
        }
        let mut current = port.clone();
        self.refresh(&mut current, false).await?;
        if !current.connected {
            return Err(Error::Protocol);
        }
        let mut mode = [0; 6];
        let get_mode = 0x0c | ((port.number as u64) << 24) | ((index as u64) << 32);
        if self.command(get_mode, &mut mode, false).await? != 6 || mode[..2] == [0, 0] {
            return Err(Error::Protocol);
        }
        let command = 0x0f
            | ((port.number as u64) << 16)
            | ((enter as u64) << 23)
            | ((index as u64) << 24)
            | ((configuration as u64) << 32);
        self.command(command, &mut [], false).await.map(|_| ())
    }
    pub async fn poll(&mut self, ports: &mut [Connector]) -> Result<(), Error> {
        self.read_cci()?;
        for port in ports {
            if port.ppm != self.path || port.number == 0 || port.number > self.connector_count {
                return Err(Error::Protocol);
            }
            if self.pending_connectors[port.number as usize] {
                // Clear before issuing the command so a subsequently reported
                // change is retained. ACK consumes precisely this status read.
                self.pending_connectors[port.number as usize] = false;
                self.refresh(port, true).await?;
                publish(port);
            }
        }
        Ok(())
    }
}
const fn cap_altmode_limit() -> u8 {
    30
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    struct Handshake {
        writes: Vec<u64>,
        cci: u32,
        fail_ack: bool,
        error: bool,
    }
    impl Transport for Handshake {
        fn version(&mut self) -> Result<u16, Error> {
            Ok(0x0200)
        }
        fn cci(&mut self) -> Result<u32, Error> {
            Ok(self.cci)
        }
        fn message(&mut self, data: &mut [u8]) -> Result<(), Error> {
            if self.cci & COMPLETE == 0 {
                return Err(Error::Protocol);
            }
            data.fill(42);
            Ok(())
        }
        fn control(&mut self, command: u64) -> Result<(), Error> {
            self.writes.push(command);
            if command & 255 == 4 {
                if self.fail_ack {
                    return Err(Error::Io);
                }
                self.cci = ACK_COMPLETE;
            } else {
                if self.cci & COMPLETE != 0 {
                    return Err(Error::Protocol);
                }
                self.cci = COMPLETE | (3 << 1) | if self.error { ERROR } else { 4 << 8 };
            }
            Ok(())
        }
    }
    fn ucsi_command_ack_and_transport_poison() -> TestResult {
        let mut ppm = Ppm::new(Handshake {
            writes: Vec::new(),
            cci: 0,
            fail_ack: false,
            error: false,
        })
        .unwrap();
        ppm.healthy = true;
        let mut bytes = [0; 4];
        if narf_scheduler::block_on_spin(ppm.command(0x12, &mut bytes, true)) != Ok(4)
            || bytes != [42; 4]
            || ppm.io.writes != [0x12, 4 | (3 << 16)]
            || !ppm.pending_connectors[3]
        {
            return TestResult::Fail(
                "completion payload must precede combined command/connector ACK",
            );
        }
        ppm.io.error = true;
        if narf_scheduler::block_on_spin(ppm.command(0x12, &mut bytes, true)) != Err(Error::Ppm)
            || ppm.io.writes.last() != Some(&(4 | (1 << 17)))
            || !ppm.healthy
        {
            return TestResult::Fail(
                "error ACK must preserve connector change and permit next command",
            );
        }
        ppm.io.error = false;
        ppm.io.fail_ack = true;
        if narf_scheduler::block_on_spin(ppm.command(0x12, &mut bytes, true)) != Err(Error::Io) {
            return TestResult::Fail("ACK transport error");
        }
        let writes = ppm.io.writes.len();
        if narf_scheduler::block_on_spin(ppm.command(0x12, &mut bytes, true))
            != Err(Error::NeedsReset)
            || ppm.io.writes.len() != writes
        {
            return TestResult::Fail("poisoned PPM issued another command");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/ucsi", ucsi_command_ack_and_transport_poison);
    struct Fake {
        cci: u32,
        message: Vec<u8>,
    }
    impl Transport for Fake {
        fn version(&mut self) -> Result<u16, Error> {
            Ok(0x0120)
        }
        fn cci(&mut self) -> Result<u32, Error> {
            Ok(self.cci)
        }
        fn control(&mut self, _: u64) -> Result<(), Error> {
            Ok(())
        }
        fn message(&mut self, data: &mut [u8]) -> Result<(), Error> {
            data.copy_from_slice(&self.message[..data.len()]);
            Ok(())
        }
    }
    fn ucsi_response_bounds_and_events() -> TestResult {
        let mut ppm = Ppm::new(Fake {
            cci: COMPLETE | (127 << 1),
            message: alloc::vec![7; 32],
        })
        .unwrap();
        ppm.read_cci().unwrap();
        let mut buf = [0; 32];
        if !ppm.pending_connectors[127]
            || ppm.response(COMPLETE | (17 << 8), &mut buf) != Err(Error::Protocol)
            || ppm.response(COMPLETE | NOT_SUPPORTED, &mut buf) != Err(Error::Unsupported)
            || ppm.response(COMPLETE | ERROR, &mut buf) != Err(Error::Ppm)
            || ppm.response(BUSY | COMPLETE, &mut buf) != Err(Error::Protocol)
            || ppm.response(COMPLETE | (6 << 8), &mut buf[..4]) != Err(Error::Protocol)
            || ppm.response(COMPLETE | (6 << 8), &mut buf) != Ok(6)
        {
            return TestResult::Fail("CCI bounds/error/event decoding");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/ucsi", ucsi_response_bounds_and_events);
    fn ucsi_status_versions_and_disconnect() -> TestResult {
        let mut c = Connector::new("\\_SB.UCSI", 1);
        let mut bytes = [0u8; 19];
        bytes[..4].copy_from_slice(&((1u32 << 19) | (1 << 20) | (1 << 23)).to_le_bytes());
        bytes[10] = 0x40;
        c.status(0x0120, &bytes).unwrap();
        if c.reversed.is_some() || c.usb4 || !c.connected || !c.source {
            return TestResult::Fail("v1 reserved bits interpreted");
        }
        c.status(0x0200, &bytes).unwrap();
        if c.reversed != Some(true) || !c.usb4 {
            return TestResult::Fail("v2 fields missing");
        }
        c.active_mode = Some(AltMode {
            index: 0,
            svid: 0xff01,
            vdo: 0,
        });
        c.status(0x0200, &[0; 19]).unwrap();
        if c.connected || c.source || c.usb4 || c.active_mode.is_some() || c.reversed.is_some() {
            return TestResult::Fail("stale disconnected state");
        }
        if c.status(0x0200, &[0; 10]) != Err(Error::Protocol) {
            return TestResult::Fail("short v2 status accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/ucsi", ucsi_status_versions_and_disconnect);
}
