//! Board-routed DP/eDP and HDMI sink discovery through retained DCN4 owners.
//! No encoder/clock/timing writes or implied modesetting readiness.
use crate::{
    amdgpu_dcn_inventory as inventory, amdgpu_ddc_navi48 as ddc, amdgpu_dmub_navi48 as dmub,
};
use alloc::vec::Vec;
use core::future::Future;

const MAX_EDID_BLOCKS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Allocation,
    Inventory(inventory::Error),
    Transport(dmub::Error),
    Ddc(ddc::Error),
    InvalidDpcd,
    InvalidEdid,
    EdidTooLarge,
}
impl Error {
    fn local(self) -> bool {
        matches!(self, Self::Ddc(e) if e.local())
            || matches!(
                self,
                Self::InvalidDpcd
                    | Self::InvalidEdid
                    | Self::EdidTooLarge
                    | Self::Transport(dmub::Error::Aux(_) | dmub::Error::CommandRejected(_))
            )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Scanning,
    Failed(Error),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sink {
    /// Receiver capabilities, replaced by extended caps when advertised and newer.
    /// None for HDMI, which has no DisplayPort receiver capabilities.
    pub dpcd: Option<[u8; 16]>,
    /// All advertised EDID blocks, with header/checksum validation; never truncated.
    pub edid: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    pub path: inventory::Path,
    /// A NACK is a nonresponding port, not proof of an HPD disconnect.
    pub sink: Result<Sink, Error>,
}

trait Aux {
    fn transfer(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
    fn delay(&mut self) -> impl Future<Output = ()> + Send;
}
trait Hdmi {
    fn edid(&mut self, channel: u8) -> impl Future<Output = Result<Vec<u8>, ddc::Error>> + Send;
}
impl Hdmi for ddc::Ddc {
    async fn edid(&mut self, channel: u8) -> Result<Vec<u8>, ddc::Error> {
        self.edid(channel).await
    }
}
impl Aux for dmub::Dmub {
    async fn transfer(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), dmub::Error> {
        self.aux(instance, action, address, data).await
    }
    async fn delay(&mut self) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
    }
}
async fn transfer(
    io: &mut impl Aux,
    instance: u8,
    action: u8,
    address: u32,
    data: &mut [u8],
) -> Result<(), Error> {
    for attempt in 0..7 {
        match io.transfer(instance, action, address, data).await {
            Err(dmub::Error::Aux(2 | 8)) if attempt != 6 => io.delay().await,
            result => return result.map_err(Error::Transport),
        }
    }
    unreachable!()
}
fn valid_dpcd(dpcd: &[u8; 16]) -> bool {
    matches!(dpcd[0], 0x10..=0x14 | 0x20 | 0x21) && matches!(dpcd[2] & 0x1f, 1 | 2 | 4)
}
async fn read_edid(io: &mut impl Aux, instance: u8) -> Result<Vec<u8>, Error> {
    // Segment zero resets state left by a previous OS/read. Older sinks may
    // NACK the segment pointer while supporting an ordinary EDID base block.
    match transfer(io, instance, 0, 0x30, &mut [0]).await {
        Ok(()) | Err(Error::Transport(dmub::Error::Aux(1 | 4))) => {}
        Err(e) => return Err(e),
    }
    let result = async {
        let mut bytes = Vec::new();
        let mut blocks = 1;
        let mut block = 0;
        while block < blocks {
            if block >= 2 && block % 2 == 0 {
                transfer(io, instance, 0, 0x30, &mut [(block / 2) as u8]).await?;
            }
            let start = bytes.len();
            bytes
                .try_reserve_exact(128)
                .map_err(|_| Error::Allocation)?;
            bytes.resize(start + 128, 0);
            transfer(io, instance, 0x40, 0x50, &mut [((block % 2) * 128) as u8]).await?;
            for offset in (0..128).step_by(16) {
                transfer(
                    io,
                    instance,
                    if offset == 112 { 0x10 } else { 0x50 },
                    0x50,
                    &mut bytes[start + offset..start + offset + 16],
                )
                .await?;
            }
            if block == 0 {
                narf_edid::Block::parse(&bytes).map_err(|_| Error::InvalidEdid)?;
                blocks = usize::from(bytes[126]) + 1;
                if blocks > MAX_EDID_BLOCKS {
                    return Err(Error::EdidTooLarge);
                }
            } else if bytes[start..]
                .iter()
                .fold(0u8, |sum, b| sum.wrapping_add(*b))
                != 0
            {
                return Err(Error::InvalidEdid);
            }
            block += 1;
        }
        Ok(bytes)
    }
    .await;
    if let Err(error) = result {
        if !error.local() {
            return Err(error);
        }
        // Terminate an I2C MOT transaction on a recoverable sink error. Fatal
        // mailbox failures refuse this command; propagate them to stop scanning.
        if let Err(e) = transfer(io, instance, 0x10, 0x50, &mut []).await {
            if !e.local() {
                return Err(e);
            }
        }
    }
    result
}
async fn read_sink(io: &mut impl Aux, instance: u8) -> Result<Sink, Error> {
    let mut dpcd = [0; 16];
    transfer(io, instance, 0x90, 0, &mut dpcd).await?;
    if !valid_dpcd(&dpcd) {
        return Err(Error::InvalidDpcd);
    }
    if dpcd[14] & 0x80 != 0 {
        let mut extended = [0; 16];
        transfer(io, instance, 0x90, 0x2200, &mut extended).await?;
        // drm_dp_read_extended_dpcd_caps keeps base caps for an older revision.
        if extended[0] >= dpcd[0] {
            if !valid_dpcd(&extended) {
                return Err(Error::InvalidDpcd);
            }
            dpcd = extended;
        }
    }
    Ok(Sink {
        dpcd: Some(dpcd),
        edid: read_edid(io, instance).await?,
    })
}

/// Retained transaction owner. Cancellation leaves Scanning set, including
/// between completed AUX commands, so a partial I2C MOT sequence cannot be
/// silently reused by the next scan. Retain this with the DMUB until reset.
#[derive(Debug)]
pub struct Probe {
    paths: Vec<inventory::Path>,
    state: State,
}
impl Probe {
    /// Accept board paths from `display_paths`; reject ambiguous native wires
    /// before issuing any AUX or DDC command.
    pub fn new(paths: Vec<inventory::Path>) -> Result<Self, Error> {
        for path in &paths {
            if !matches!(
                path.connector,
                inventory::Connector::DisplayPort
                    | inventory::Connector::EmbeddedDisplayPort
                    | inventory::Connector::HdmiTypeA
            ) {
                continue;
            }
            let aux = path
                .aux
                .ok_or(Error::Inventory(inventory::Error::Unsupported))?;
            if aux >= 4
                || path.transmitter >= 4
                || path.hpd > 4
                || paths.iter().filter(|p| p.aux == Some(aux)).count() != 1
                || paths
                    .iter()
                    .filter(|p| p.transmitter == path.transmitter)
                    .count()
                    != 1
            {
                return Err(Error::Inventory(inventory::Error::Invalid));
            }
        }
        Ok(Self {
            paths,
            state: State::Ready,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn paths(&self) -> &[inventory::Path] {
        &self.paths
    }
    /// Does not query HPD by transmitter number: AUX, HPD and connector ids
    /// need not coincide. DPCD response establishes a responsive DP sink.
    pub async fn scan(
        &mut self,
        dmub: &mut dmub::Dmub,
        ddc: Option<&mut ddc::Ddc>,
    ) -> Result<Vec<Port>, Error> {
        self.scan_with(dmub, ddc).await
    }
    async fn scan_with(
        &mut self,
        io: &mut impl Aux,
        mut ddc: Option<&mut impl Hdmi>,
    ) -> Result<Vec<Port>, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        self.state = State::Scanning;
        let result = async {
            let mut ports = Vec::new();
            ports.try_reserve_exact(4).map_err(|_| Error::Allocation)?;
            for path in &self.paths {
                let sink = match path.connector {
                    inventory::Connector::DisplayPort
                    | inventory::Connector::EmbeddedDisplayPort => {
                        read_sink(io, path.aux.unwrap()).await
                    }
                    inventory::Connector::HdmiTypeA => {
                        let ddc = ddc.as_mut().ok_or(Error::Ddc(ddc::Error::Unsupported))?;
                        ddc.edid(path.aux.unwrap())
                            .await
                            .map(|edid| Sink { dpcd: None, edid })
                            .map_err(Error::Ddc)
                    }
                    _ => continue,
                };
                if let Err(e) = sink {
                    if !e.local() {
                        return Err(e);
                    }
                }
                ports.push(Port { path: *path, sink });
            }
            Ok(ports)
        }
        .await;
        self.state = match result {
            Ok(_) => State::Ready,
            Err(e) => State::Failed(e),
        };
        result
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_display_tests.rs"]
mod tests;
