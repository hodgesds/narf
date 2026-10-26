// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained API77 MVM boot owner. This stage does not publish a station.
//! The native transport owns context-v1/RFH/TFH; this owner keeps it through
//! ALIVE, unified NVM initialization and mandatory awake-runtime defaults.
use super::{gen2_profile::Profile, runtime::Hardware, station_api::Nvm};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    New,
    Starting,
    Configured,
    Scanning,
    PreparingChannel,
    ChannelPrepared,
    ReleasingChannel,
    PreparingPeer,
    PeerPrepared,
    PreparingManagementQueue,
    ManagementQueuePrepared,
    PreparingTransmitPower,
    TransmitPowerPrepared,
    ActivatingLink,
    LinkActive,
    Authenticating,
    Associating,
    Associated,
    PreparingData,
    DataPrepared,
    TransmittingData,
    ClosingData,
    ClearingAssociation,
    DeactivatingLink,
    RemovingManagementQueue,
    RemovingPeer,
    Failed,
}
pub struct Owner {
    hardware: Hardware,
    firmware: Vec<u8>,
    profile: Profile,
    phase: Phase,
    mac: Option<[u8; 6]>,
    nvm: Option<Nvm>,
    beacons: Vec<super::connection::Beacon>,
    scan: scan::ScanContext,
    channel: channel::ChannelContext,
    peer: Option<peer::ApPeer>,
    management_queue: Option<queue::ManagementQueue>,
    power: power::Context,
}
impl core::fmt::Debug for Owner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MvmBootOwner")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
impl Owner {
    pub fn new(mut hardware: Hardware, firmware: &[u8]) -> Result<Self, &'static str> {
        let parsed = super::parse_ucode(firmware).map_err(|_| "invalid MVM firmware image")?;
        if parsed.header.version != 77
            || parsed.fw_version.is_some_and(|v| v.0 != 77)
            || !hardware.matches_firmware(&parsed)
        {
            return Err("MVM boot image/API differs from retained transport");
        }
        // Do not discover ABI incompatibility only after publishing DMA.
        for (group, command, version) in [
            (0xc, 0, 1),
            (0xc, 2, 1),
            (1, 0x98, 1),
            (1, 0x9b, 6),
            (2, 1, 2),
            (1, 0x77, 6),
            (1, 0xc, 5),
        ] {
            if hardware.version(group, command).map(|v| v.0) != Some(version) {
                return Err("unsupported MVM boot command API");
            }
        }
        if hardware.version(0, 1).map(|v| v.1) != Some(6)
            || hardware.version(0xc, 2).map(|v| v.1) != Some(4)
            || !parsed.api.has_capability(37)
            || !parsed.api.has_capability(2)
        {
            return Err("MVM API77 NVM/SoC/scan capability missing");
        }
        let profile = hardware.gen2_profile()?;
        Ok(Self {
            hardware,
            firmware: firmware.to_vec(),
            profile,
            phase: Phase::New,
            mac: None,
            nvm: None,
            beacons: Vec::new(),
            scan: scan::ScanContext::new(&parsed.api),
            channel: channel::ChannelContext::new(&parsed.api),
            peer: None,
            management_queue: None,
            power: power::Context::new(&parsed.api),
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn identity(&self) -> Option<([u8; 6], &Nvm)> {
        Some((self.mac?, self.nvm.as_ref()?))
    }
    /// One attempt owns boot even when its waiting future is dropped. Neither a
    /// partial command ACK nor a cancelled init allows a second reset or startup.
    /// Dropping this owner invokes the transport's stop/fence/quarantine policy.
    pub async fn initialize(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::New {
            return Err("MVM boot already attempted");
        }
        self.phase = Phase::Starting;
        let result = self.initialize_inner().await;
        if result.is_err() {
            self.hardware.fail();
        }
        result
    }
    async fn initialize_inner(&mut self) -> Result<(), &'static str> {
        let parsed =
            super::parse_ucode(&self.firmware).map_err(|_| "invalid retained MVM firmware")?;
        let mac = self.hardware.start(&parsed).await?;
        self.configure(mac).await
    }
    async fn configure(&mut self, mac: [u8; 6]) -> Result<(), &'static str> {
        if self.phase != Phase::Starting || mac == [0; 6] || mac[0] & 1 != 0 {
            return Err("invalid MVM post-init owner/identity");
        }
        let packet = self.hardware.command(0xc, 2, &[0; 4]).await?;
        let nvm = Nvm::parse(4, &packet.payload)?;
        self.scan.nvm_lar = u32::from_le_bytes(packet.payload[20..24].try_into().unwrap()) != 0;
        let defaults = configuration(self.profile);
        self.hardware
            .command(1, 0x98, &nvm.tx_chains.to_le_bytes())
            .await?;
        self.hardware
            .command(1, 0x9b, &defaults.coexistence)
            .await?;
        self.hardware.command(2, 1, &defaults.soc).await?;
        // Queue0 is already described by context-v1. Additional RX queues/RSS and
        // their PRPH allocations remain disabled in this single-queue boot profile.
        self.hardware.command(1, 0x77, &[0; 4]).await?;
        // DQA/LAR and the idle station MAC are owned by the scan preparation
        // transaction. SCAN_CFG is sent there after those prerequisites.
        self.power.nvm_permissions = Some(
            packet.payload[28..]
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect(),
        );
        self.mac = Some(mac);
        self.nvm = Some(nvm);
        self.phase = Phase::Configured;
        Ok(())
    }
}
struct Configuration {
    coexistence: [u8; 8],
    soc: [u8; 8],
}
fn configuration(profile: Profile) -> Configuration {
    let mut c = Configuration {
        coexistence: [1, 0, 0, 0, 17, 0, 0, 0],
        soc: [0; 8],
    };
    let flags = if !profile.integrated {
        1
    } else {
        (if profile.xtal_latency_us == 12000 {
            2
        } else {
            0
        }) | match profile.ltr_delay_us {
            200 => 4,
            2500 => 8,
            _ => 0,
        }
    };
    super::boot_context::put32(&mut c.soc, 0, flags);
    super::boot_context::put32(&mut c.soc, 4, profile.xtal_latency_us);
    c
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_boot_tests.rs"]
mod tests;

#[path = "mvm_scan.rs"]
mod scan;

#[path = "mvm_channel.rs"]
mod channel;

#[path = "mvm_peer.rs"]
mod peer;

#[path = "mvm_queue.rs"]
mod queue;

#[path = "mvm_power.rs"]
mod power;
pub type PowerRequest = power::PowerRequest;
pub type PowerStatus = power::PowerStatus;

#[path = "mvm_link.rs"]
mod link;
pub type ActiveLinkStatus = link::ActiveLinkStatus;

#[path = "mvm_auth.rs"]
mod auth;
pub type AuthenticationStatus = auth::AuthenticationStatus;

#[path = "mvm_assoc.rs"]
mod assoc;
pub type AssociationStatus = assoc::AssociationStatus;
pub type AssociationSecurity = narf_wireless::association::SecurityMode;

#[path = "mvm_data.rs"]
mod data;
pub type LegacyDataStatus = data::LegacyDataStatus;
pub type LegacyReceive = data::LegacyReceive;
