//! Sc c103 post-INIT station composition. The device side observes the real
//! TFH publication and writes receipts/MPDUs into posted RFH buffers. Device,
//! Connection, queues, RSNA, carrier, IPC and DHCP are production code. PCI,
//! firmware execution and radio/CCMP offload remain physical acceptance gates.

use super::super::runtime::model::{self, Published, TxTrace};
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::{udp_ipv4, ApPhase, DhcpServer, FakeAp, NetworkPlan};

#[cfg(feature = "kernel-test")]
#[path = "sc_source_tests.rs"]
mod source_tests;

#[cfg(feature = "kernel-test")]
#[path = "sc_power_tests.rs"]
mod power_tests;

#[cfg(feature = "kernel-test")]
#[path = "sc_security_tests.rs"]
mod security_tests;

#[cfg(feature = "kernel-test")]
#[path = "sc_he_tests.rs"]
mod he_tests;

#[cfg(feature = "kernel-test")]
#[path = "sc_rx_multi_tests.rs"]
mod rx_multi_tests;

#[cfg(feature = "kernel-test")]
#[path = "sc_tx_amsdu_tests.rs"]
mod tx_amsdu_tests;

#[path = "gen3_station_tests.rs"]
mod gen3_station_tests;
#[cfg(feature = "kernel-test")]
#[path = "native_160_tests.rs"]
mod native_160_tests;
#[path = "sc_scheduled_tests.rs"]
mod scheduled_tests;

type R<T = ()> = Result<T, &'static str>;
const OWN: [u8; 6] = [2, 0x71, 2, 3, 4, 5];
const AP: [u8; 6] = [2, 0x72, 2, 3, 4, 5];
const SSID: &[u8] = b"narf-sc-native";
const PMK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
const NETWORK: NetworkPlan = NetworkPlan {
    station: OWN,
    bssid: AP,
    server_ip: [10, 79, 0, 1],
    lease_ip: [10, 79, 0, 42],
    netmask: [255, 255, 255, 0],
    lease_seconds: 3600,
};

fn require(condition: bool, why: &'static str) -> R {
    if condition {
        Ok(())
    } else {
        Err(why)
    }
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn half(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    HoldM4,
    HoldRemoval,
    HoldRxFence,
    HoldGroupReply,
    HoldScan,
    HoldPower,
    HoldIgtk,
    WrongSaeSelector,
    HoldHe,
    HoldRfh,
    MalformedRfh,
    HoldSmem,
    HoldData,
}

/// Authored firmware/NVM/AP facts, only for the native HE composition.
#[derive(Clone, Copy)]
struct PhyModel {
    width: u8,
    streams: u8,
    rates: u8,
    mcc_he: bool,
    response_he: bool,
}
impl PhyModel {
    fn channel(self) -> u8 {
        if self.width >= 2 {
            36
        } else {
            6
        }
    }
    fn chains(self) -> u32 {
        if self.streams == 2 {
            3
        } else {
            1
        }
    }
}

/// Actual reported/default receive contracts are authored into firmware
/// metadata; no production cache/admission field is supplied separately.
#[derive(Clone, Copy)]
enum ReceiveModel {
    Single,
    ExplicitV1,
    NativeSc,
    Unsupported,
}
impl From<bool> for ReceiveModel {
    fn from(enabled: bool) -> Self {
        if enabled {
            Self::ExplicitV1
        } else {
            Self::Single
        }
    }
}
impl ReceiveModel {
    fn commands(self, versions: &mut Vec<u8>) {
        match self {
            Self::Single => {}
            Self::ExplicitV1 => versions.extend_from_slice(&[0x0d, 5, 1, 0, 0xb3, 1, 1, 0]),
            Self::NativeSc => versions.extend_from_slice(&[0x0d, 5, 2, 0]),
            Self::Unsupported => versions.extend_from_slice(&[0x0d, 5, 3, 0]),
        }
    }
    fn capability(self, image: &mut Vec<u8>) {
        if matches!(self, Self::NativeSc | Self::Unsupported) {
            image.extend_from_slice(&30u32.to_le_bytes());
            image.extend_from_slice(&8u32.to_le_bytes());
            image.extend_from_slice(&[2, 0, 0, 0, 0x10, 0, 0, 0]);
        }
    }
    fn enabled(self) -> bool {
        matches!(self, Self::ExplicitV1 | Self::NativeSc)
    }
}
/// Test-authored firmware capability TLVs and the literal native SMEM
/// response. Production cache fields are populated only by parsing/receipts.
#[derive(Clone)]
struct TxModel {
    extended: bool,
    cdb: bool,
    version: u8,
    memory: Vec<u8>,
}
struct Wire {
    firmware: model::Firmware,
    trace: TxTrace,
    versions: Vec<u8>,
    ap: FakeAp,
    server: DhcpServer,
    queues: Vec<(u16, u8, bool)>,
    commands: Vec<(u8, u8, Vec<u8>)>,
    data: Vec<(Vec<u8>, bool)>,
    received: Vec<Vec<u8>>,
    air: Vec<(u16, u16, u8, ApPhase)>,
    replies: Vec<u8>,
    key: Option<Vec<u8>>,
    ptk: Option<narf_wireless::eapol::Ptk>,
    group_rekey: bool,
    group_reply: bool,
    keys: usize,
    next_pn: u64,
    fault: Fault,
    held: Option<(u8, u8, u16)>,
    held_tx: Option<(u16, u16)>,
    held_rx: Option<u32>,
    m4: bool,
    error: Option<&'static str>,
    power_expectation: Option<i16>,
    security_fault_applied: bool,
    sa_query_reply: Option<[u8; 4]>,
    sae_h2e_only: bool,
    group_replay: u64,
    igtk_expected: Option<([u8; 16], u16, u64)>,
    gtk_expected: Option<(u8, [u8; 16])>,
    phy: Option<PhyModel>,
    phy_requests: Vec<Vec<u8>>,
    multi_receive: bool,
    rx_queues: Vec<model::ReceiveFirmware>,
    hold_rx_queue: Option<u8>,
    held_markers: Vec<(u8, Vec<u8>)>,
    baid_live: bool,
    tx_model: Option<TxModel>,
    aggregates: Vec<Vec<Vec<u8>>>,
    held_data: Vec<(u16, u16)>,
    scheduled: Option<scheduled_tests::Model>,
    api89: Option<gen3_station_tests::Case>,
    bz: Option<super::super::bz_fixture::Case>,
    mcc_caps_override: Option<u32>,
    mcc_permissions: Option<Vec<u32>>,
}

// SAFETY: no real device or thread accesses these fixture pointers. The sole
// Wire is moved only between the local driver and HARNESS, and all device-side
// access is serialized by HARNESS. Its posted buffers stay owned by Device
// until Guard removes both global references and destroys Hardware last.
unsafe impl Send for Wire {}

impl Wire {
    fn service(&mut self) -> R<bool> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let mut progressed = false;
        for _ in 0..64 {
            let Some(published) = self.trace.take() else {
                return Ok(progressed);
            };
            progressed = true;
            if let Err(error) = self.observe(published) {
                self.error = Some(error);
                return Err(error);
            }
        }
        Err("Sc firmware observer did not become idle")
    }

    /// Independent Linux iwl_tfh_tfd/iwl_tfh_tb offsets: a 16-bit count,
    /// then packed ten-byte (len:u16,address:u64) entries. These snapshots
    /// are observations; no DMA address is converted into a CPU pointer.
    fn descriptor(p: &Published) -> R {
        let count = usize::from(half(&p.descriptor, 0));
        require((1..=3).contains(&count), "Sc TFH transfer count")?;
        let first = u64::from_le_bytes(p.descriptor[4..12].try_into().unwrap());
        require(
            first != 0 && first == p.dma_base,
            "Sc TFH retained DMA address",
        )?;
        let mut extent = 0usize;
        for i in 0..count {
            let offset = 2 + i * 10;
            let len = usize::from(half(&p.descriptor, offset));
            let addr =
                u64::from_le_bytes(p.descriptor[offset + 2..offset + 10].try_into().unwrap());
            require(
                len != 0 && addr == first + extent as u64,
                "Sc TFH packed extent",
            )?;
            extent += len;
        }
        require(
            extent == p.bytes.len(),
            "Sc TFH extent differs from submitted DMA",
        )?;
        require(
            half(&p.descriptor, 2) as usize == p.bytes.len().min(20),
            "Sc TFH TB0 split",
        )?;
        require(
            p.descriptor[2 + count * 10..].iter().all(|b| *b == 0),
            "Sc TFH unused tail",
        )
    }

    fn observe(&mut self, published: Published) -> R {
        require(
            published.doorbell == (u32::from(published.queue) << 16) | u32::from(published.pointer),
            "Sc observed doorbell queue/pointer mismatch",
        )?;
        Self::descriptor(&published)?;
        if published.queue == 0 {
            self.command(published)
        } else {
            self.transmit(published)
        }
    }

    fn command(&mut self, p: Published) -> R {
        let bytes = &p.bytes;
        require(bytes.len() >= 8, "Sc long command header")?;
        let (cmd, group, sequence) = (bytes[0], bytes[1], half(bytes, 2));
        let version = self
            .versions
            .chunks_exact(4)
            .find(|entry| entry[0] == cmd && entry[1] == group)
            .map(|entry| if entry[2] == 99 { 0 } else { entry[2] })
            .unwrap_or(0);
        require(
            bytes[7]
                == if self.api89.is_some() && (group, cmd) == (5, 8) {
                    2
                } else {
                    0
                }
                && usize::from(half(bytes, 4)) + 8 == bytes.len()
                && sequence == (p.pointer.wrapping_sub(1) & 0xff),
            "Sc bare/WIDE_ID command header",
        )?;
        let body = &bytes[8..];
        self.commands.push((group, cmd, body.to_vec()));
        let mut response = Vec::new();
        match (group, cmd) {
            (1, 0x25) | (2, 0) if self.tx_model.is_some() => {
                let tx = self.tx_model.as_ref().unwrap();
                require(
                    body.is_empty()
                        && bytes[6] == 0
                        && ((group, cmd) == if tx.extended { (2, 0) } else { (1, 0x25) }),
                    "Sc shared-memory command ignored actual firmware TLV capability",
                )?;
                response = tx.memory.clone();
                if self.fault == Fault::HoldSmem {
                    self.held = Some((cmd, group, sequence));
                    return Ok(());
                }
            }
            (0xc, 2) => {
                require(body == [0; 4] && version == 1, "Sc NVM request")?;
                // The authored MLD table selects iwl_nvm_get_info_rsp v4:
                // legacy-only single-chain NVM, 14 valid channels/110 entries.
                response.resize(28 + 110 * 4, 0);
                let count = if self.phy.is_some() { 51u32 } else { 14 };
                let chains = self.phy.map_or(1, PhyModel::chains);
                response[8..12].copy_from_slice(&self.phy.map_or(0u32, |_| 28).to_le_bytes());
                response[12..16].copy_from_slice(&chains.to_le_bytes());
                response[16..20].copy_from_slice(&chains.to_le_bytes());
                response[24..28].copy_from_slice(&count.to_le_bytes());
                for i in 0..count as usize {
                    let flags = 1u32
                        | if self.phy.is_some_and(|phy| phy.width == 3) && (14..22).contains(&i) {
                            1 << 11
                        } else {
                            0
                        };
                    response[28 + i * 4..32 + i * 4].copy_from_slice(&flags.to_le_bytes());
                }
            }
            (1, 0xc8) => {
                require(
                    body.len() == 28 && half(body, 0) == u16::from_be_bytes(*b"US") && body[2] == 2,
                    "Sc MCC source/country",
                )?;
                let count = if self.phy.is_some() { 51u32 } else { 14 };
                let first = if self.api89.is_some() { 20 } else { 24 };
                response.resize(first + count as usize * 4, 0);
                response[4..6].copy_from_slice(&body[..2]);
                let capabilities = (1u32 << 4)
                    | (1 << 3)
                    | if self.phy.is_some_and(|phy| !phy.mcc_he) {
                        1 << 13
                    } else {
                        0
                    };
                if self.api89.is_some() {
                    let bits: u16 = 0x118
                        | if self.phy.is_some_and(|phy| !phy.mcc_he) {
                            1 << 10
                        } else {
                            0
                        };
                    let bits = if let Some(value) = self.mcc_caps_override {
                        u16::try_from(value).map_err(|_| "fixture MCC v6 cap word")?
                    } else {
                        bits
                    };
                    response[6..8].copy_from_slice(&bits.to_le_bytes());
                } else {
                    response[8..12].copy_from_slice(
                        &self.mcc_caps_override.unwrap_or(capabilities).to_le_bytes(),
                    );
                }
                response[first - 4..first].copy_from_slice(&count.to_le_bytes());
                let permission = if self.phy.is_some() {
                    13u32
                        | (1 << 9)
                        | (1 << 10)
                        | if self.phy.is_some_and(|phy| phy.width == 3) {
                            1 << 11
                        } else {
                            0
                        }
                } else {
                    13
                };
                for i in 0..count as usize {
                    let permission = self
                        .mcc_permissions
                        .as_ref()
                        .map_or(permission, |flags| flags[i]);
                    response[first + i * 4..first + 4 + i * 4]
                        .copy_from_slice(&permission.to_le_bytes());
                }
            }
            (5, 0x17) => {
                require(
                    version == 3 && body.len() == 36 && word(body, 4) == 1,
                    "Sc queue command ABI",
                )?;
                let tid = body[8];
                if word(body, 0) == 0 {
                    require(
                        (matches!(tid, 0 | 15) || self.phy.is_some() && matches!(tid, 1 | 4 | 6))
                            && word(body, 16) == 4
                            && body[20..28] != [0; 8]
                            && body[28..36] != [0; 8]
                            && !self.queues.iter().any(|(_, t, live)| *t == tid && *live),
                        "Sc native queue ownership",
                    )?;
                    let id = self.queues.len() as u16 + 1;
                    self.queues.push((id, tid, true));
                    response.resize(8, 0);
                    response[..2].copy_from_slice(&id.to_le_bytes());
                } else {
                    require(
                        word(body, 0) == 1 && body[12..].iter().all(|b| *b == 0),
                        "Sc queue remove layout",
                    )?;
                    let queue = self
                        .queues
                        .iter_mut()
                        .find(|(_, t, live)| *t == tid && *live)
                        .ok_or("Sc remove unowned queue")?;
                    if self.fault == Fault::HoldRemoval {
                        self.held = Some((cmd, group, sequence));
                        return Ok(());
                    }
                    queue.2 = false;
                    response.resize(8, 0);
                    response[..2].copy_from_slice(&queue.0.to_le_bytes());
                }
            }
            (5, 0x18) => {
                require(
                    version == 1 && body.len() == 80 && word(body, 4) == 1,
                    "Sc native key command",
                )?;
                if word(body, 0) == 3 {
                    require(
                        self.ap.pmf()
                            && ((word(body, 12) == 0x6a && (4..=5).contains(&word(body, 8)))
                                || (self.gtk_expected.is_some()
                                    && word(body, 12) == 0x4a
                                    && word(body, 8) <= 3))
                            && body[16..].iter().all(|b| *b == 0),
                        "Sc IGTK removal native identity/flags",
                    )?;
                    self.firmware.inject(cmd, group, sequence, &[]);
                    return Ok(());
                }
                require(word(body, 0) == 1, "Sc native key action")?;
                match word(body, 12) {
                    2 | 0x22 => require(
                        word(body, 8) == 0
                            && word(body, 12) == if self.ap.pmf() { 0x22 } else { 2 }
                            && self.key.as_deref() == Some(&body[16..32]),
                        "Sc installed PTK differs from AP exchange",
                    )?,
                    0x4a => require(
                        self.gtk_expected.map_or_else(
                            || {
                                (word(body, 8) == 1 && body[16..32] == [0x77; 16])
                                    || self.group_rekey
                                        && word(body, 8) == 2
                                        && body[16..32] == [0x88; 16]
                            },
                            |(id, material)| {
                                word(body, 8) == u32::from(id) && body[16..32] == material
                            },
                        ),
                        "Sc installed GTK differs from M3",
                    )?,
                    0x6a => {
                        let (material, id) = self
                            .igtk_expected
                            .map(|(material, id, _)| (material, id))
                            .or_else(|| self.ap.igtk())
                            .ok_or("Sc installed unnegotiated IGTK")?;
                        require(
                            word(body, 8) == u32::from(id)
                                && body[16..32] == material
                                && self
                                    .igtk_expected
                                    .is_none_or(|(_, _, pn)| body[64..72] == pn.to_le_bytes()),
                            "Sc native IGTK differs from authenticated M3",
                        )?;
                        if self.fault == Fault::HoldIgtk {
                            self.held = Some((cmd, group, sequence));
                            return Ok(());
                        }
                    }
                    _ => return Err("Sc key flags"),
                }
                self.keys += 1;
            }
            (5, 0x0d) if self.multi_receive => {
                self.rx_queues.clear();
                require(
                    body.len() == 68 && body[..4] == [2, 0, 0, 0],
                    "Sc additional RFH v1 extent/count",
                )?;
                for (index, entry) in body[4..].chunks_exact(32).enumerate() {
                    require(
                        entry[..4] == [index as u8 + 1, 0, 0, 0] && word(entry, 28) == 504,
                        "Sc additional RFH queue/enable/write index",
                    )?;
                }
            }
            (1, 0xb3) if self.multi_receive => {
                require(
                    body.len() == 176
                        && body[..8] == [1, 0, 0, 0, 0x3f, 0, 0, 0]
                        && body[48..]
                            .iter()
                            .enumerate()
                            .all(|(i, q)| *q == 1 + (i % 2) as u8),
                    "Sc RSS v1 flags/hash/indirection",
                )?;
                let configuration = &self
                    .commands
                    .iter()
                    .rev()
                    .find(|(g, c, _)| (*g, *c) == (5, 0x0d))
                    .ok_or("Sc RSS before RFH")?
                    .2;
                for queue in 1..=2 {
                    // SAFETY: Guard retains Hardware until this Wire and all
                    // views are destroyed; HARNESS serializes device injection
                    // with every production host poll of the actual rings.
                    let view = unsafe { self.trace.take_receive_queue(queue) }
                        .ok_or("Sc missing posted RFH allocation view")?;
                    let at = 4 + 32 * usize::from(queue - 1);
                    require(
                        view.queue == queue
                            && view.free_write == 504
                            && view.dma.iter().enumerate().all(|(i, dma)| {
                                configuration[at + 4 + i * 8..at + 12 + i * 8] == dma.to_le_bytes()
                            }),
                        "Sc RFH command did not name retained allocations",
                    )?;
                    self.rx_queues.push(view);
                }
            }
            (5, 0x16) if self.multi_receive => {
                require(
                    body.len() == 16 && word(body, 4) == 1 && word(body, 8) == 0,
                    "Sc BAID command station/TID",
                )?;
                if word(body, 0) == 0 {
                    require(
                        !self.baid_live && half(body, 12) == 100 && half(body, 14) == 32,
                        "Sc BAID allocation reuse/window",
                    )?;
                    self.baid_live = true;
                } else {
                    require(
                        word(body, 0) == 2 && self.baid_live && body[12..] == [0; 4],
                        "Sc BAID removal without owner",
                    )?;
                    self.baid_live = false;
                }
                response = 3u32.to_le_bytes().to_vec();
            }
            (5, 2) => {
                let baid = body.get(12) == Some(&1);
                let count = if baid { 12 } else { 8 };
                let mask = if self.multi_receive { 7 } else { 1 };
                require(
                    body.len() == 12 + count
                        && bytes[6] == 0
                        && word(body, 0) == 0
                        && word(body, 4) == mask
                        && word(body, 8) == count as u32
                        && word(body, 12)
                            == u32::from(baid) | if self.api89.is_some() { 1 << 16 } else { 0 }
                        && word(body, 16) != 0
                        && (!baid || self.multi_receive && word(body, 20) == 3),
                    "Sc all-owned-RFH epoch native contract",
                )?;
            }
            (3, 8) => require(body.len() == 52 && body[12..18] == OWN, "Sc MAC identity")?,
            (3, 9) => require(body.len() == 208 && body[16..22] == OWN, "Sc LINK identity")?,
            (3, 10) => {
                require(
                    body.len() == if self.api89.is_some() { 96 } else { 104 } && body[8..14] == AP,
                    "native peer identity/extent",
                )?;
                if self.fault == Fault::HoldHe && word(body, 92) & 1 != 0 {
                    self.held = Some((cmd, group, sequence));
                    return Ok(());
                }
            }
            (1, 8) => require(
                body.len() == 32
                    && word(body, 8) == u32::from(self.phy.map_or(6, PhyModel::channel)),
                "Sc PHY channel",
            )?,
            (1, 0x9f) => {
                require(
                    body.len() == if self.api89.is_some() { 120 } else { 108 }
                        && half(body, 8) == self.power_expectation.unwrap_or(136) as u16,
                    "Sc TX power policy ceiling",
                )?;
                if self.fault == Fault::HoldPower {
                    self.held = Some((cmd, group, sequence));
                    return Ok(());
                }
            }
            (5, 0xf) => require(
                body.len() == if self.api89.is_some() { 28 } else { 44 },
                "native TLC ABI",
            )?,
            (5, 8) if self.api89.is_some() => require(
                body.len() == 32
                    && body[..4] == [0; 4]
                    && word(body, 4)
                        == if self.phy.map_or(1, PhyModel::chains) == 3 {
                            0x2806
                        } else {
                            0x1402
                        }
                    && body[8..].iter().all(|b| *b == 0),
                "API89 literal RLC2 profile",
            )?,
            (3, 0xc) => require(
                body == [0; 4] && self.queues.iter().all(|q| !q.2),
                "Sc peer removal before queue receipts",
            )?,
            (3, 5) => require(
                body.len() == 24 && word(body, 4) == 1,
                "Sc association residency",
            )?,
            (1, 0x6e) if self.scheduled.is_some() => {
                self.scheduled.as_mut().unwrap().profiles(body)?
            }
            (1, 0xe) if self.scheduled.is_some() => {
                response = self.scheduled.as_mut().unwrap().abort(body)?;
            }
            (1, 0xd) if word(body, 0) == 1 && self.scheduled.is_some() => {
                self.scheduled.as_mut().unwrap().start(body)?;
                if self.scheduled.as_ref().unwrap().hold_start {
                    self.held = Some((cmd, group, sequence));
                    return Ok(());
                }
            }
            (1, 0xd) => require(
                body.len() == if self.api89.is_some() { 1940 } else { 1948 }
                    && (half(body, 8) == 0x802 || self.phy.is_some() && half(body, 8) == 2)
                    && body[45] == 1
                    && body[52] == self.phy.map_or(6, PhyModel::channel),
                "Sc passive scan ABI",
            )?,
            (1, 0x98) => require(
                body == self.phy.map_or(1, PhyModel::chains).to_le_bytes(),
                "Sc NVM chain identity",
            )?,
            (1, 0x9b) => require(body == [1, 0, 0, 0, 17, 0, 0, 0], "Sc coexistence defaults")?,
            (2, 1) => require(
                body == self.bz.map_or_else(
                    || {
                        self.api89
                            .map_or([10, 0, 0, 0, 224, 46, 0, 0], gen3_station_tests::Case::soc)
                    },
                    super::super::bz_fixture::Case::soc,
                ),
                "Sc integrated SoC defaults",
            )?,
            (1, 0xc) => require(
                body == [
                    0u32,
                    self.phy.map_or(1, PhyModel::chains),
                    self.phy.map_or(1, PhyModel::chains),
                ]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>(),
                "Sc scan chain defaults",
            )?,
            (1, 0x77) => require(body == [0; 4], "Sc continuously awake defaults")?,
            _ => return Err("unexpected command in Sc composition"),
        }
        if (group, cmd) == (5, 0x0d) && self.fault == Fault::HoldRfh {
            self.held = Some((cmd, group, sequence));
            return Ok(());
        }
        if (group, cmd) == (1, 0xd) && self.fault == Fault::HoldScan {
            self.held = Some((cmd, group, sequence));
            return Ok(());
        }
        if (group, cmd) == (5, 0x0d) && self.fault == Fault::MalformedRfh {
            response.push(1);
        }
        self.firmware
            .inject(cmd, if group == 1 { 0 } else { group }, sequence, &response);
        if (group, cmd) == (5, 2) {
            let marker = body[8..].to_vec();
            if self.fault == Fault::HoldRxFence {
                require(
                    self.held_rx.is_none(),
                    "Sc repeated uncertain receive fence",
                )?;
                self.held_rx = Some(word(body, 16));
            } else {
                self.firmware.inject(0xff, 5, 0x8000, &marker);
            }
            for queue in &mut self.rx_queues {
                if self.hold_rx_queue == Some(queue.queue) {
                    self.held_markers.push((queue.queue, marker.clone()));
                } else {
                    queue.inject(0xff, 5, 0x8000, &marker);
                }
            }
        } else if (group, cmd) == (3, 5) {
            self.firmware.inject(
                0xfb,
                3,
                0x8000,
                &[0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            );
        } else if (group, cmd) == (1, 0xd) {
            if word(body, 0) == 1 {
                // Actual autonomous periodic owner remains live after the
                // correlated command ACK. Test code injects real posted-ring
                // iteration/match/completion notifications independently.
                return Ok(());
            }
            let mut beacon = self.ap.beacon();
            if let Some(phy) = self.phy {
                beacon.extend_from_slice(&he_tests::elements(phy, true));
            }
            if self.sae_h2e_only {
                // Actual BSS membership selector123; the AP's RSNXE and
                // SAE Commit must independently confirm H2E.
                beacon.extend_from_slice(&[50, 1, 0xfb]);
            }
            self.mpdu(&beacon, false);
            let mut done = [0; 16];
            done[..4].copy_from_slice(&body[..4]);
            done[6] = 1;
            self.firmware.inject(0xf, 0, 0x8000, &done);
        } else if (group, cmd) == (1, 0xe) && self.scheduled.is_some() {
            let scheduled = self.scheduled.as_mut().unwrap();
            if !scheduled.hold_stop && scheduled.abort_status <= 1 {
                scheduled.live = false;
                let mut done = [0; 16];
                done[..4].copy_from_slice(&1u32.to_le_bytes());
                done[6] = 2;
                self.firmware.inject(0xf, 0, 0x8000, &done);
            }
        }
        Ok(())
    }

    /// Real native key commands, rather than the total number of historical
    /// installs, determine the current data key after authenticated rotation.
    fn native_data_keys(&self) -> bool {
        let installed = |flags: u32, id: u32, material: &[u8]| {
            self.commands
                .iter()
                .rev()
                .find(|(group, command, body)| {
                    (*group, *command) == (5, 0x18)
                        && body.len() == 80
                        && word(body, 8) == id
                        && word(body, 12) == flags
                })
                .is_some_and(|(_, _, body)| word(body, 0) == 1 && body[16..32] == *material)
        };
        let gtk = self.gtk_expected.unwrap_or((1, [0x77; 16]));
        let ptk = self
            .key
            .as_deref()
            .is_some_and(|material| installed(if self.ap.pmf() { 0x22 } else { 2 }, 0, material));
        let igtk = !self.ap.pmf()
            || self
                .igtk_expected
                .map(|(material, id, _)| (material, id))
                .or_else(|| self.ap.igtk())
                .is_some_and(|(material, id)| installed(0x6a, u32::from(id), &material));
        self.keys >= if self.ap.pmf() { 3 } else { 2 }
            && ptk
            && installed(0x4a, u32::from(gtk.0), &gtk.1)
            && igtk
            && (!self.group_rekey || self.group_reply)
            && self.held_tx.is_none()
    }

    fn transmit(&mut self, p: Published) -> R {
        require(
            self.queues
                .iter()
                .any(|(id, _, live)| *id == p.queue && *live),
            "Sc TX used unowned queue",
        )?;
        let bytes = &p.bytes;
        require(
            bytes.len() >= 56 && bytes[0] == 0x1c,
            "Sc TX command header",
        )?;
        let len = usize::from(half(bytes, 4));
        let header = ((word(bytes, 8) >> 8) & 31) as usize * 2;
        let amsdu = word(bytes, 8) & 0x4000 != 0;
        require(
            matches!(header, 24 | 26)
                && bytes.len()
                    == 32
                        + len
                        + if amsdu {
                            0
                        } else {
                            header.next_multiple_of(4) - header
                        },
            "Sc TX length/padding",
        )?;
        require(
            half(bytes, 2) == ((p.queue & 31) << 8) | (p.pointer.wrapping_sub(1) & 127),
            "Sc TX sequence",
        )?;
        let mut frame = bytes[32..32 + header].to_vec();
        frame.extend_from_slice(
            &bytes[32
                + if amsdu {
                    header
                } else {
                    header.next_multiple_of(4)
                }..],
        );
        if self.phy.is_some() && matches!(frame[0], 0 | 0x20) {
            self.phy_requests.push(frame.clone());
        }
        let protected = frame[1] & 0x40 != 0;
        if self.air.len() < 64 {
            self.air
                .push((p.queue, p.pointer, frame[0], self.ap.phase()));
        }
        require(
            (half(bytes, 6) & 2 == 0) == protected,
            "Sc native encryption flag",
        )?;
        let data = frame[0] & 0x0c == 8;
        if amsdu {
            require(
                self.tx_model.is_some()
                    && data
                    && header == 26
                    && frame[24] & 0x80 != 0
                    && word(bytes, 8) == 0x4d00
                    && protected == self.ap.protected(),
                "Sc native A-MSDU flag/header/PAD/encryption geometry",
            )?;
            let mut at = 26;
            let mut frames = Vec::new();
            while at < frame.len() {
                require(
                    frame.len() - at >= 22,
                    "Sc native A-MSDU literal subframe prefix",
                )?;
                let count = usize::from(u16::from_be_bytes([frame[at + 12], frame[at + 13]]));
                let end = at + 14 + count;
                require(
                    count >= 8
                        && end <= frame.len()
                        && frame[at] & 1 == 0
                        && frame[at + 6..at + 12] == OWN
                        && frame[at + 14..at + 20] == [0xaa, 0xaa, 3, 0, 0, 0],
                    "Sc native A-MSDU literal addresses/length/LLC",
                )?;
                let mut ethernet = frame[at..at + 12].to_vec();
                ethernet.extend_from_slice(&frame[at + 20..end]);
                require(
                    ethernet[12..14] != [0x88, 0x8e],
                    "Sc aggregated the private EAPOL port",
                )?;
                self.data.push((ethernet.clone(), protected));
                frames.push(ethernet);
                if end == frame.len() {
                    break;
                }
                let next = end + (4 - ((14 + count) % 4)) % 4;
                require(
                    next < frame.len() && frame[end..next].iter().all(|byte| *byte == 0),
                    "Sc A-MSDU inter-subframe padding/terminal extent",
                )?;
                at = next;
            }
            require(
                frames.len() == 2 && frame.len() <= 3819,
                "Sc native A-MSDU two-frame MPDU bound",
            )?;
            self.aggregates.push(frames);
            if self.fault == Fault::HoldData {
                self.held_data.push((p.queue, p.pointer));
            } else {
                self.firmware.tx_complete(p.queue, p.pointer);
            }
            return Ok(());
        }
        let eapol =
            data && frame.get(header..header + 8) == Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
        if !data || eapol {
            if eapol && self.group_rekey {
                let pdu = frame.get(header + 8..).ok_or("Sc group reply PDU")?;
                let reply = narf_wireless::eapol::KeyFrame::decode(
                    pdu.get(4..).ok_or("Sc group reply header")?,
                    16,
                )
                .ok_or("Sc group reply key frame")?;
                let mut unsigned = pdu.to_vec();
                unsigned[81..97].fill(0);
                require(
                    protected
                        && reply.key_information == 0x302
                        && reply.replay_counter == self.group_replay
                        && reply.key_data.is_empty()
                        && reply.key_mic.as_slice()
                            == super::super::handshake::compute_mic(
                                &self.ptk.as_ref().ok_or("Sc group PTK absent")?.kck,
                                &unsigned,
                            ),
                    "Sc actual group response MIC/replay/port",
                )?;
                self.group_reply = true;
                if self.fault == Fault::HoldGroupReply {
                    self.held_tx = Some((p.queue, p.pointer));
                    return Ok(());
                }
            } else if frame[0] == 0xd0 && self.multi_receive && frame.get(24..26) == Some(&[3, 1]) {
                require(
                    frame[24..] == [3, 1, 1, 0, 0, 2, 8, 0, 0],
                    "Sc BA response immediate/window/AMSDU decline",
                )?;
            } else if frame[0] == 0xd0 && self.ap.pmf() {
                require(
                    protected && frame.get(24..26) == Some(&[8, 1]) && frame.len() == 28,
                    "Sc SA Query response was not natively protected",
                )?;
                self.sa_query_reply = Some(frame[24..28].try_into().unwrap());
            } else if frame[0] == 0xa0 {
                require(
                    self.ap.phase() == ApPhase::Authorized,
                    "Sc disconnect before association",
                )?;
            } else {
                let phase = self.ap.phase();
                let responses = self
                    .ap
                    .receive(&frame)
                    .map_err(|error| match (error, phase) {
                        (narf_wifi_fixtures::ApError::Association, _) => {
                            "Sc AP rejected association RSNE/RSNXE/rates"
                        }
                        (narf_wifi_fixtures::ApError::Mic, _) => "Sc AP rejected four-way MIC",
                        (narf_wifi_fixtures::ApError::Key, ApPhase::Message2) => {
                            "Sc AP rejected M2 association transcript/nonce/counter"
                        }
                        (narf_wifi_fixtures::ApError::Key, ApPhase::Message4) => {
                            "Sc AP rejected M4 key information/counter"
                        }
                        (narf_wifi_fixtures::ApError::Key, ApPhase::Authentication) => {
                            "Sc AP rejected SAE Commit/Confirm"
                        }
                        _ => "shared AP rejected native Sc management/EAPOL",
                    })?;
                if phase == ApPhase::Message2 {
                    use narf_wireless::eapol::{derive_ptk, HmacPrimitive, KeyFrame};
                    struct Sha1;
                    impl HmacPrimitive for Sha1 {
                        fn out_len(&self) -> usize {
                            20
                        }
                        fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
                            narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
                        }
                    }
                    let m2 =
                        KeyFrame::decode(&frame[header + 12..], 16).ok_or("Sc M2 key frame")?;
                    if matches!(
                        self.ap.akm(),
                        None | Some(narf_wireless::eapol::KeyMgmt::Psk)
                    ) {
                        let ptk = derive_ptk(&Sha1, &PMK, &AP, &OWN, &ANONCE, &m2.key_nonce, 16);
                        self.key = Some(ptk.tk.clone());
                        self.ptk = Some(ptk);
                    } else {
                        self.key = Some(
                            self.ap
                                .pairwise_tk()
                                .ok_or("Sc AP did not derive negotiated TK")?
                                .to_vec(),
                        );
                    }
                }
                for mut response in responses {
                    if let Some(phy) = self
                        .phy
                        .filter(|_| response[0] == 0x10 || response[0] == 0x30)
                    {
                        response.extend_from_slice(&he_tests::elements(phy, phy.response_he));
                    }
                    if self.fault == Fault::WrongSaeSelector
                        && response[0] == 0xb0
                        && half(&response, 26) == 1
                        && response.ends_with(&[255, 5, 114, 0, 15, 172, 24])
                    {
                        *response.last_mut().unwrap() = 8;
                        self.security_fault_applied = true;
                    }
                    self.mpdu(&response, false);
                }
                if phase == ApPhase::Message4 {
                    self.m4 = true;
                    require(
                        self.keys == if self.ap.pmf() { 3 } else { 2 },
                        "Sc M4 before key receipts",
                    )?;
                    if self.fault == Fault::HoldM4 {
                        self.held_tx = Some((p.queue, p.pointer));
                        return Ok(());
                    }
                }
            }
        } else {
            require(
                self.ap.phase() == ApPhase::Authorized
                    && protected == self.ap.protected()
                    && (!protected || self.native_data_keys()),
                "Sc controlled port/protection",
            )?;
            require(
                frame[1] & 3 == 1
                    && frame[4..10] == AP
                    && frame[10..16] == OWN
                    && frame[header..header + 6] == [0xaa, 0xaa, 3, 0, 0, 0],
                "Sc uplink DS/LLC",
            )?;
            let mut ethernet = frame[16..22].to_vec();
            ethernet.extend_from_slice(&OWN);
            ethernet.extend_from_slice(&frame[header + 6..]);
            if let Some(response) = self.server.receive(&ethernet) {
                self.ethernet(&response);
            }
            self.data.push((ethernet, protected));
        }
        if data && !eapol && self.fault == Fault::HoldData {
            self.held_data.push((p.queue, p.pointer));
        } else {
            self.firmware.tx_complete(p.queue, p.pointer);
        }
        Ok(())
    }

    fn mpdu(&mut self, frame: &[u8], protected: bool) {
        if self.replies.len() < 64 {
            self.replies.push(frame[0]);
        }
        let mut payload = vec![0; 64];
        payload[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
        payload[12..16].copy_from_slice(&(if protected { 0x243u32 } else { 3 }).to_le_bytes());
        // Firmware follows the station's actual programmed TLC, not the
        // AP's advertised maximum. M1 may precede TLC and use a legacy rate;
        // a narrowed/non-HE association must not receive invented HE data.
        let he_programmed = self
            .commands
            .iter()
            .rev()
            .find(|(g, c, _)| (*g, *c) == (5, 0xf))
            .is_some_and(|(_, _, body)| {
                body.get(if self.api89.is_some() { 5 } else { 9 }) == Some(&3)
            });
        if let Some(phy) = self.phy.filter(|_| he_programmed && frame[0] & 0xc == 8) {
            let rate = 0x400u32
                | if phy.width == 3 {
                    self.commands
                        .iter()
                        .rev()
                        .find(|(g, c, _)| (*g, *c) == (5, 0xf))
                        .map_or(0, |(_, _, body)| {
                            u32::from(body[if self.api89.is_some() { 4 } else { 8 }]) << 11
                        })
                } else {
                    0
                }
                | if phy.streams == 2 {
                    if phy.rates == 3 {
                        32
                    } else {
                        16
                    }
                } else {
                    0
                };
            payload[36..40].copy_from_slice(&rate.to_le_bytes());
        } else if let Some(phy) = self.phy.filter(|phy| phy.width == 3 && frame[0] & 0xc == 8) {
            if let Some((_, _, body)) = self
                .commands
                .iter()
                .rev()
                .find(|(g, c, _)| (*g, *c) == (5, 0xf))
            {
                let mode = body[if self.api89.is_some() { 5 } else { 9 }];
                if mode == 2 {
                    let width = body[if self.api89.is_some() { 4 } else { 8 }];
                    let rate = 0x300u32
                        | (u32::from(width) << 11)
                        | if phy.streams == 2 {
                            if phy.rates == 3 {
                                32
                            } else {
                                16
                            }
                        } else {
                            0
                        };
                    payload[36..40].copy_from_slice(&rate.to_le_bytes());
                }
            }
        }
        payload[40] = 50;
        payload[41] = 60;
        payload[42] = self.phy.map_or(6, PhyModel::channel);
        payload.extend_from_slice(frame);
        self.firmware.inject(0xc1, 0, 0x8000, &payload);
    }

    fn ethernet(&mut self, ethernet: &[u8]) {
        let protected = self.ap.protected();
        let mut frame = vec![0; 24];
        frame[0] = 8;
        frame[1] = 2 | if protected { 0x40 } else { 0 };
        frame[4..10].copy_from_slice(&ethernet[..6]);
        frame[10..16].copy_from_slice(&AP);
        frame[16..22].copy_from_slice(&ethernet[6..12]);
        if protected {
            self.next_pn += 1;
            let pn = self.next_pn.to_le_bytes();
            let key = if ethernet[0] & 1 != 0 { 1 << 6 } else { 0 };
            frame.extend_from_slice(&[pn[0], pn[1], 0, 0x20 | key, pn[2], pn[3], pn[4], pn[5]]);
        }
        frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
        frame.extend_from_slice(&ethernet[12..]);
        self.mpdu(&frame, protected);
    }
}

static HARNESS: IrqSafeSpinLock<Option<(Arc<Device>, Box<Wire>)>> = IrqSafeSpinLock::new(None);

fn service() -> R<bool> {
    HARNESS
        .lock()
        .as_mut()
        .ok_or("missing Sc composition")?
        .1
        .service()
}

fn drain() -> bool {
    let device = {
        let mut slot = HARNESS.lock();
        let Some((device, wire)) = slot.as_mut() else {
            return false;
        };
        if wire.service().is_err() {
            return false;
        }
        device.clone()
    };
    let frames = device.step(None);
    let mut progress = !frames.is_empty();
    {
        let mut slot = HARNESS.lock();
        if let Some((_, wire)) = slot.as_mut() {
            wire.received.extend(frames.iter().map(|d| d.bytes.clone()));
            progress |= wire.service().unwrap_or(false);
        }
    }
    device.dispatch(frames);
    progress
}

fn run<F: Future>(future: F, mut progress: impl FnMut() -> R<bool>) -> R<F::Output> {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let deadline = narf_time::Deadline::after_ms(3000);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return Ok(value);
        }
        progress()?;
        if deadline.expired() {
            diagnose("Sc composition future stalled");
            return Err("Sc composition future stalled");
        }
        narf_scheduler::sleep_pumps::run();
        core::hint::spin_loop();
    }
}

struct NativeModel {
    receive_model: ReceiveModel,
    tx_model: Option<TxModel>,
    api89: Option<gen3_station_tests::Case>,
    bz: Option<super::super::bz_fixture::Case>,
}
struct Guard {
    device: Option<Arc<Device>>,
    policy_db: Arc<narf_wireless::reg::db::Database>,
    #[cfg(feature = "kernel-test")]
    owner: Option<narf_wireless::nl80211::ConnectionOwnerFixture>,
}
impl Guard {
    fn new(secured: bool, fault: Fault) -> R<Self> {
        Self::new_named(secured, fault, None)
    }
    fn new_named(secured: bool, fault: Fault, name: Option<&'static str>) -> R<Self> {
        Self::build_named(secured, fault, name, None)
    }
    fn build_named(
        secured: bool,
        fault: Fault,
        name: Option<&'static str>,
        sources: Option<(&crate::firmware_asset::Asset, &crate::firmware_asset::Asset)>,
    ) -> R<Self> {
        Self::build(secured, fault, name, sources, None)
    }
    fn build(
        secured: bool,
        fault: Fault,
        name: Option<&'static str>,
        sources: Option<(&crate::firmware_asset::Asset, &crate::firmware_asset::Asset)>,
        phy: Option<PhyModel>,
    ) -> R<Self> {
        Self::build_receive(secured, fault, name, sources, phy, false)
    }
    fn build_receive(
        secured: bool,
        fault: Fault,
        name: Option<&'static str>,
        sources: Option<(&crate::firmware_asset::Asset, &crate::firmware_asset::Asset)>,
        phy: Option<PhyModel>,
        multi_receive: bool,
    ) -> R<Self> {
        Self::build_features(secured, fault, name, sources, phy, multi_receive, None)
    }
    fn build_features(
        secured: bool,
        fault: Fault,
        name: Option<&'static str>,
        sources: Option<(&crate::firmware_asset::Asset, &crate::firmware_asset::Asset)>,
        phy: Option<PhyModel>,
        receive_model: impl Into<ReceiveModel>,
        tx_model: Option<TxModel>,
    ) -> R<Self> {
        Self::build_native_profile(
            secured,
            fault,
            name,
            sources,
            phy,
            NativeModel {
                receive_model: receive_model.into(),
                tx_model,
                api89: None,
                bz: None,
            },
        )
    }
    #[inline(never)]
    fn build_native_profile(
        secured: bool,
        fault: Fault,
        name: Option<&'static str>,
        sources: Option<(&crate::firmware_asset::Asset, &crate::firmware_asset::Asset)>,
        phy: Option<PhyModel>,
        model: NativeModel,
    ) -> R<Self> {
        let NativeModel {
            receive_model,
            tx_model,
            api89,
            bz,
        } = model;
        let multi_receive = receive_model.enabled();
        require(
            ACTIVE.lock().is_none()
                && narf_net::iface::lookup(super::super::iwl_ifname()).is_none()
                && name.is_none_or(|name| narf_net::iface::lookup(name).is_none()),
            "live iwlwifi owner exists",
        )?;
        let mut versions = api89.map_or_else(
            super::super::firmware_parser_tests::mld_commands,
            gen3_station_tests::Case::commands,
        );
        if let Some(case) = bz {
            versions = case.commands();
        }
        if api89.is_none() && bz.is_none() {
            if phy.is_some() {
                he_tests::versions(&mut versions);
            }
            receive_model.commands(&mut versions);
        }
        if api89.is_none() && bz.is_none() {
            if let Some(tx) = &tx_model {
                versions.extend_from_slice(&[0, 2, 0, tx.version]);
            }
        }
        let (mut hardware, firmware, trace) = if let Some(case) = api89 {
            let (mut hw, fw, trace) =
                model::station_model_for_format(super::super::rx_rfh::CompletionFormat::Ax210);
            model::native_station_identity(&mut hw, case.did(), case.revision(), case.radio())?;
            (hw, fw, trace)
        } else if let Some(case) = bz {
            let (mut hw, fw, trace) =
                model::station_model_for_format(super::super::rx_rfh::CompletionFormat::Bz);
            model::native_station_identity(&mut hw, case.did(), case.revision(), case.radio())?;
            (hw, fw, trace)
        } else {
            model::station_model()
        };
        let mut authored = if let Some(case) = api89 {
            case.image()
        } else if let Some(case) = bz {
            case.image()
        } else {
            tx_amsdu_tests::image(&versions, tx_model.as_ref())?
        };
        receive_model.capability(&mut authored);
        let parsed = super::super::parse_ucode(&authored)
            .map_err(|_| "Sc fixture firmware metadata parse")?;
        model::firmware_profile(&mut hardware, &parsed)?;
        if api89.is_some() || bz.is_some() {
            hardware.prepare_station_profile(&parsed)?;
        }
        if let Some((firmware, pnvm)) = sources {
            let parsed = super::super::parse_ucode(&firmware.bytes)
                .map_err(|_| "Sc source fixture parse")?;
            require(
                parsed.api.commands == versions,
                "Sc source fixture executable/command table mismatch",
            )?;
            model::firmware_profile(&mut hardware, &parsed)?;
            hardware.bind_sources(firmware, Some(pnvm))?;
        }
        Device::validate_station_profile(&hardware)?;
        let channel = phy.map_or(6, PhyModel::channel);
        let ap = if secured {
            FakeAp::wpa2(NETWORK, SSID, channel, 7, PMK, ANONCE)
        } else {
            FakeAp::open(NETWORK, SSID, channel, 7)
        }
        .map_err(|_| "shared Sc AP configuration")?;
        let mut wire = Box::new(Wire {
            firmware,
            trace,
            versions,
            ap,
            server: DhcpServer::new(NETWORK),
            queues: Vec::new(),
            commands: Vec::new(),
            data: Vec::new(),
            received: Vec::new(),
            air: Vec::new(),
            replies: Vec::new(),
            key: None,
            ptk: None,
            group_rekey: false,
            group_reply: false,
            keys: 0,
            next_pn: 0,
            fault,
            held: None,
            held_tx: None,
            held_rx: None,
            m4: false,
            error: None,
            power_expectation: None,
            security_fault_applied: false,
            sa_query_reply: None,
            sae_h2e_only: false,
            group_replay: 3,
            igtk_expected: None,
            gtk_expected: None,
            phy,
            phy_requests: Vec::new(),
            multi_receive,
            rx_queues: Vec::new(),
            hold_rx_queue: None,
            held_markers: Vec::new(),
            baid_live: false,
            tx_model,
            aggregates: Vec::new(),
            held_data: Vec::new(),
            scheduled: None,
            api89,
            bz,
            mcc_caps_override: None,
            mcc_permissions: None,
        });
        let configured = run(Device::configure(&mut hardware, OWN), || wire.service());
        let nvm = match configured {
            Ok(Ok(nvm)) => nvm,
            _ => {
                // SAFETY: no host future remains and no physical DMA was armed.
                unsafe {
                    model::destroy(hardware);
                }
                return Err(wire.error.unwrap_or("Sc post-INIT configure failed"));
            }
        };
        let (rx_producer, rx_consumer) = narf_ipc::channel();
        let mut state = State {
            hardware,
            scan_uid: 0,
            scheduled: None,
            beacons: Vec::new(),
            connection: None,
            needs_reset: false,
            stop_completed: false,
            producer: Some(rx_producer),
            receive_ipc: None,
            eapol: VecDeque::new(),
            tx: core::array::from_fn(|_| None),
            pending: core::array::from_fn(|_| None),
            pending_next: core::array::from_fn(|_| None),
            tx_progress: false,
        };
        let tx = core::array::from_fn(|category| {
            let (producer, consumer) = narf_ipc::channel();
            state.tx[category] = Some(consumer);
            IrqSafeSpinLock::new(Some(producer))
        });
        let source = state.hardware.source_fence()?;
        let policy_db = Arc::new(narf_wireless::reg::db::Database::new());
        policy_db.install(if phy.is_some_and(|phy| phy.width == 3) {
            native_160_tests::policy()
        } else if phy.is_some() {
            he_tests::policy()
        } else {
            policy()
        });
        let device = Arc::new_cyclic(|me| Device {
            test_name: name,
            me: me.clone(),
            radio_control: Arc::new(narf_wireless::ap_control::ExclusiveControl::new()),
            scan_generation: Arc::new(super::super::scheduled_epoch::Epoch::new()),
            state: Mutex::new(state),
            control: Mutex::new(None),
            publication: AtomicBool::new(true),
            source,
            policy: super::super::mld_policy::Source::database(policy_db.clone()),
            policy_fence: IrqSafeSpinLock::new(None),
            generation: Arc::new(AtomicU64::new(0)),
            quarantined: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            admission: IrqSafeSpinLock::new(()),
            mac: OWN,
            irq_vector: None,
            channels: nvm.channels,
            tx_chains: nvm.tx_chains,
            phy: nvm.phy,
            firmware: Vec::new(),
            pnvm: None,
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            rx: IrqSafeSpinLock::new(Some(rx_consumer)),
            tx,
        });
        *ACTIVE.lock() = Some(device.clone());
        *HARNESS.lock() = Some((device.clone(), wire));
        narf_net::iface::register(device.name(), OWN, send_frame);
        narf_net::iface::set_link_state(device.name(), true); // operator IFF_UP
        device.set_link(false);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Ok(Self {
            device: Some(device),
            policy_db,
            #[cfg(feature = "kernel-test")]
            owner: None,
        })
    }
    fn device(&self) -> &Arc<Device> {
        self.device.as_ref().unwrap()
    }
    #[cfg(feature = "kernel-test")]
    fn register_owner(&mut self, portid: u32) -> R {
        let device = self.device();
        require(
            !narf_wireless::registry::list()
                .iter()
                .any(|i| i.name() == device.name()),
            "Sc owner-close wireless name already registered",
        )?;
        narf_wireless::nl80211::register();
        narf_wireless::registry::register(device.clone());
        self.owner = Some(narf_wireless::nl80211::__connection_owner_for_test(
            device.name(),
            0,
            portid,
            AP,
        ));
        Ok(())
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(feature = "kernel-test")]
        if self.owner.take().is_some() {
            narf_wireless::registry::unregister(self.device().name());
        }
        if let Some(device) = &self.device {
            narf_net::iface::unregister(device.name());
        }
        let wire = HARNESS.lock().take().map(|(device, wire)| {
            drop(device);
            wire
        });
        let active = ACTIVE.lock().take();
        drop(active);
        if let Some(device) = self.device.take() {
            let Ok(device) = Arc::try_unwrap(device) else {
                // A failed lifecycle regression must retain the device-side
                // model storage while a spawned owner still holds Hardware.
                core::mem::forget(wire);
                return;
            };
            // SAFETY: all futures and fixture pointer views are gone; model
            // Hardware was never armed or published to a physical PCI device.
            unsafe {
                model::destroy(device.state.into_inner().hardware);
            }
        }
        drop(wire);
    }
}

fn policy() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::*;
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2482,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    }
}
fn request(secured: bool) -> AssociateRequest {
    AssociateRequest {
        bssid: AP,
        ssid: SSID.to_vec(),
        frequency_mhz: 2437,
        channel: 6,
        security: if secured {
            narf_wireless::SecurityConfig::Wpa2 { psk: PMK }
        } else {
            narf_wireless::SecurityConfig::Open
        },
        ie: Vec::new(),
    }
}
fn scan_request() -> ScanRequest {
    ScanRequest {
        ssids: vec![SSID.to_vec()],
        channels: vec![6],
        frequencies_mhz: vec![2437],
        active: false,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}
fn scan(device: &Device) -> R {
    let bss = run(device.scan(scan_request()), service)?.map_err(|_| "Sc native scan failed")?;
    require(
        bss.len() == 1 && bss[0].bssid == AP && bss[0].ssid == SSID && bss[0].channel == 6,
        "Sc native scan did not populate association identity",
    )
}
fn carrier(device: &Device, expected: bool) -> R {
    require(
        device.link_up() == expected
            && narf_net::iface::lookup(device.name())
                .is_some_and(|iface| iface.link_up && iface.carrier == expected),
        "Sc owner/registered carrier mismatch",
    )
}
fn flush() -> R {
    for _ in 0..32 {
        if !drain() {
            return HARNESS.lock().as_ref().unwrap().1.error.map_or(Ok(()), Err);
        }
    }
    Err("Sc packet drain did not become idle")
}

fn composition(secured: bool) -> R {
    let guard = Guard::new(secured, Fault::None)?;
    let device = guard.device();
    carrier(device, false)?;
    require(
        narf_net::dhcp::acquire(device.name(), 400).is_err(),
        "Sc DHCP before association",
    )?;
    scan(device)?;
    run(
        device.associate_in_domain(request(secured), &policy()),
        service,
    )?
    .map_err(|_| "Sc native association failed")?;
    carrier(device, true)?;
    narf_net::iface::set_link_state(device.name(), false);
    // This is the same production physical publication used by station
    // activation, under the retained owner lock just as on native progress.
    {
        let _owner = device.state.try_lock().unwrap();
        device.publish_link(AP, device.generation.load(Ordering::Acquire))?;
    }
    require(
        narf_net::iface::lookup(device.name()).is_some_and(|iface| !iface.link_up && iface.carrier),
        "Sc physical carrier overwrote operator DOWN",
    )?;
    narf_net::iface::set_link_state(device.name(), true);
    require(
        device.connected_bssid() == Some(AP),
        "Sc association BSSID publication",
    )?;
    {
        let slot = HARNESS.lock();
        let wire = &slot.as_ref().unwrap().1;
        require(
            wire.ap.phase() == ApPhase::Authorized && (!secured || (wire.m4 && wire.keys == 2)),
            "Sc native RSNA receipts",
        )?;
    }
    let lease = narf_net::dhcp::dhcp_acquire(device.name(), 0)
        .map_err(|_| "Sc native DHCP lease failed")?;
    require(NETWORK.matches_lease(&lease), "Sc lease terms")?;
    {
        let slot = HARNESS.lock();
        let wire = &slot.as_ref().unwrap().1;
        let seen = wire.server.observations();
        require(
            seen.discovers == 1
                && seen.requests == 1
                && wire.data.len() == 2
                && wire.data.iter().all(|(_, p)| *p == secured),
            "Sc DISCOVER/REQUEST native protection",
        )?;
    }
    let uplink = udp_ipv4(
        AP,
        OWN,
        NETWORK.lease_ip,
        NETWORK.server_ip,
        49152,
        7,
        b"sc-native-uplink",
    );
    narf_net::iface::send_on(device.name(), &uplink).map_err(|_| "Sc IP uplink admission")?;
    flush()?;
    require(
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .data
            .iter()
            .any(|(bytes, p)| bytes == &uplink && *p == secured),
        "Sc exact IP uplink bytes",
    )?;
    let downlink = udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        12345,
        54321,
        b"sc-native-downlink",
    );
    let rx_before = narf_net::iface::snapshot_counters()
        .into_iter()
        .find(|counters| counters.name == device.name())
        .ok_or("Sc RX counters")?
        .rx_packets;
    HARNESS.lock().as_mut().unwrap().1.ethernet(&downlink);
    flush()?;
    require(
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .received
            .contains(&downlink),
        "Sc exact IP downlink bytes",
    )?;
    require(
        narf_net::iface::snapshot_counters()
            .into_iter()
            .find(|counters| counters.name == device.name())
            .is_some_and(|c| c.rx_packets > rx_before),
        "Sc IP downlink did not enter network RX dispatch",
    )?;
    {
        let mut consumer = device.rx.lock();
        let consumer = consumer.as_mut().ok_or("Sc RX IPC not published")?;
        let mut delivered = false;
        while let Ok(Some(frame)) = consumer.try_recv() {
            delivered |= frame.payload() == downlink;
        }
        require(
            delivered,
            "Sc exact downlink bytes absent from native RX IPC",
        )?;
    }
    let before = HARNESS.lock().as_ref().unwrap().1.data.len();
    run(device.disassociate(), service)?.map_err(|_| "Sc native disconnect failed")?;
    carrier(device, false)?;
    {
        let state = device.state.try_lock().unwrap();
        require(
            !state.needs_reset && model::retained(&state.hardware) == (0, 0, 0),
            "Sc acknowledged teardown retained resources",
        )?;
    }
    require(
        narf_net::iface::send_on(device.name(), &uplink).is_err()
            && narf_net::dhcp::acquire(device.name(), 400).is_err(),
        "Sc post-disconnect admission",
    )?;
    flush()?;
    // Drop the static-slot guard before the tail expression: in edition2021
    // a tail temporary otherwise outlives Guard and deadlocks its cleanup.
    let unchanged = HARNESS.lock().as_ref().unwrap().1.data.len() == before;
    require(unchanged, "Sc post-disconnect data reached AP")
}

fn check(run: impl FnOnce() -> R) -> TestResult {
    if ACTIVE.lock().is_some() {
        return TestResult::Skip("live iwlwifi owner exists");
    }
    match run() {
        Ok(()) => TestResult::Pass,
        Err(error) => {
            diagnose(error);
            TestResult::Fail(error)
        }
    }
}

/// Bounded failure-only context. No per-poll logging changes wait timing and
/// no command/key payload, nonce or packet body is printed.
fn diagnose(error: &'static str) {
    use core::fmt::Write;
    let Some(slot) = HARNESS.try_lock() else {
        return;
    };
    let Some((device, wire)) = slot.as_ref() else {
        return;
    };
    let _ = writeln!(narf_console::Writer,
        "Sc fixture failure={error} phase={:?} keys={} m4={} held={:?} queues={:?} air={:?} replies={:?}",
        wire.ap.phase(), wire.keys, wire.m4, wire.held, wire.queues, wire.air, wire.replies);
    for (group, cmd, body) in wire.commands.iter().rev().take(12).rev() {
        let _ = writeln!(
            narf_console::Writer,
            "Sc command {group:02x}:{cmd:02x} len={}",
            body.len()
        );
    }
    if let Some(state) = device.state.try_lock() {
        let _ = writeln!(
            narf_console::Writer,
            "Sc owner reset={} failed={} retained={:?}",
            state.needs_reset,
            state.hardware.is_failed(),
            model::retained(&state.hardware)
        );
    };
}
fn smoke_sc_open_native_association_dhcp_ip() -> TestResult {
    check(|| composition(false))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_open_native_association_dhcp_ip
);
/// Non-WoWLAN system suspend leaves the BSS through the ordinary
/// disconnect owner, stops the transport and keeps the netdev closed until
/// resume restarts firmware and replays the runtime configuration.
fn suspend_resume() -> R {
    let guard = Guard::new(false, Fault::None)?;
    let device = guard.device();
    scan(device)?;
    run(
        device.associate_in_domain(request(false), &policy()),
        service,
    )?
    .map_err(|_| "Sc suspend setup association")?;
    carrier(device, true)?;
    run(device.system_resume(), service)?.map_err(|_| "Sc resume without suspend")?;
    carrier(device, true)?;
    run(device.system_suspend(), service)?.map_err(|_| "Sc system suspend failed")?;
    carrier(device, false)?;
    {
        let state = device.state.try_lock().ok_or("Sc suspend retained state")?;
        require(
            state.needs_reset
                && state.connection.is_none()
                && state.hardware.is_failed()
                && model::retained(&state.hardware) == (0, 0, 0)
                && device.suspended.load(Ordering::Acquire),
            "Sc suspend did not retire the station and stop the transport",
        )?;
    }
    let uplink = udp_ipv4(
        AP,
        OWN,
        NETWORK.lease_ip,
        NETWORK.server_ip,
        49152,
        7,
        b"suspended",
    );
    require(
        narf_net::iface::send_on(device.name(), &uplink).is_err(),
        "Sc suspended netdev admitted data",
    )?;
    run(device.system_suspend(), service)?.map_err(|_| "Sc repeated suspend")?;
    let before = HARNESS
        .lock()
        .as_ref()
        .unwrap()
        .1
        .commands
        .iter()
        .filter(|(g, c, _)| *g == 0xc && *c == 2)
        .count();
    run(device.system_resume(), service)?.map_err(|_| "Sc system resume failed")?;
    {
        let state = device.state.try_lock().ok_or("Sc resume retained state")?;
        require(
            !state.needs_reset
                && !state.hardware.is_failed()
                && !device.suspended.load(Ordering::Acquire),
            "Sc resume did not restart the transport",
        )?;
    }
    {
        let mut slot = HARNESS.lock();
        let wire = &mut slot.as_mut().unwrap().1;
        require(
            wire.commands
                .iter()
                .filter(|(g, c, _)| *g == 0xc && *c == 2)
                .count()
                == before + 1,
            "Sc resume did not replay actual NVM",
        )?;
        wire.ap = FakeAp::open(NETWORK, SSID, 6, 7).map_err(|_| "Sc AP restart")?;
        wire.server = DhcpServer::new(NETWORK);
    }
    scan(device)?;
    run(
        device.associate_in_domain(request(false), &policy()),
        service,
    )?
    .map_err(|_| "Sc association after resume failed")?;
    carrier(device, true)?;
    let lease = narf_net::dhcp::dhcp_acquire(device.name(), 0)
        .map_err(|_| "Sc DHCP after resume failed")?;
    require(NETWORK.matches_lease(&lease), "Sc lease after resume")?;
    run(device.disassociate(), service)?.map_err(|_| "Sc disconnect after resume")?;
    Ok(())
}
fn smoke_sc_system_suspend_leaves_bss_and_resume_restarts() -> TestResult {
    check(suspend_resume)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_system_suspend_leaves_bss_and_resume_restarts
);
fn smoke_sc_wpa2_native_association_dhcp_ip() -> TestResult {
    check(|| composition(true))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_wpa2_native_association_dhcp_ip
);

fn smoke_sc_m4_cancellation_keeps_controlled_port_and_dma_closed() -> TestResult {
    check(|| {
        let guard = Guard::new(true, Fault::HoldM4)?;
        let device = guard.device();
        scan(device)?;
        let domain = policy();
        let mut future = Box::pin(device.associate_in_domain(request(true), &domain));
        let mut cx = Context::from_waker(Waker::noop());
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                future.as_mut().poll(&mut cx).is_pending(),
                "Sc association completed without M4 receipt",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.m4 {
                break;
            }
            if deadline.expired() {
                diagnose("Sc M4 cancellation fixture stalled");
                return Err("Sc M4 cancellation fixture stalled");
            }
        }
        carrier(device, false)?;
        require(
            narf_net::dhcp::acquire(device.name(), 400).is_err(),
            "Sc DHCP before M4 receipt",
        )?;
        drop(future);
        let state = device
            .state
            .try_lock()
            .ok_or("Sc cancelled future retained state lock")?;
        require(
            state.needs_reset
                && state.connection.is_none()
                && model::retained(&state.hardware) == (0, 2, 1),
            "Sc cancelled M4 released device-owned queues",
        )?;
        drop(state);
        device.step(None);
        require(
            device.state.try_lock().unwrap().hardware.is_failed(),
            "Sc cancelled association pump did not fail closed",
        )?;
        let no_data = HARNESS.lock().as_ref().unwrap().1.data.is_empty();
        require(no_data, "Sc cancelled association sent IP")
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_m4_cancellation_keeps_controlled_port_and_dma_closed
);

fn smoke_sc_disconnect_cancellation_and_wrong_receipt_retain_queue_owner() -> TestResult {
    check(|| {
        let guard = Guard::new(false, Fault::HoldRemoval)?;
        let device = guard.device();
        scan(device)?;
        run(
            device.associate_in_domain(request(false), &policy()),
            service,
        )?
        .map_err(|_| "Sc cancel setup association")?;
        let mut future = Box::pin(device.disassociate());
        let mut cx = Context::from_waker(Waker::noop());
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                future.as_mut().poll(&mut cx).is_pending(),
                "Sc disconnect completed before queue receipt",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
                break;
            }
            if deadline.expired() {
                diagnose("Sc removal cancellation fixture stalled");
                return Err("Sc removal cancellation fixture stalled");
            }
        }
        carrier(device, false)?;
        drop(future);
        {
            let state = device
                .state
                .try_lock()
                .ok_or("Sc disconnect cancellation retained mutex")?;
            require(
                state.needs_reset
                    && state.connection.is_none()
                    && model::retained(&state.hardware) == (1, 2, 0),
                "Sc unacknowledged queue removal released DMA",
            )?;
        }
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            let (cmd, group, sequence) = wire.held.unwrap();
            wire.firmware.inject(cmd ^ 1, group, sequence, &[]);
        }
        let mut state = device.state.try_lock().unwrap();
        require(
            state.hardware.poll() == Err("command response identity mismatch"),
            "Sc wrong removal receipt was not rejected",
        )?;
        require(
            state.hardware.is_failed() && model::retained(&state.hardware) == (1, 2, 0),
            "Sc wrong removal receipt freed retained DMA",
        )?;
        let no_data = HARNESS.lock().as_ref().unwrap().1.data.is_empty();
        require(no_data, "Sc failed teardown admitted data")
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_disconnect_cancellation_and_wrong_receipt_retain_queue_owner
);

fn smoke_sc_disconnect_overrides_waiting_old_link_publication() -> TestResult {
    check(|| {
        let guard = Guard::new(false, Fault::None)?;
        let device = guard.device();
        scan(device)?;
        run(
            device.associate_in_domain(request(false), &policy()),
            service,
        )?
        .map_err(|_| "Sc racing disconnect setup association")?;
        carrier(device, true)?;
        let control = device.control.try_lock().ok_or("Sc fixture control busy")?;
        let state = device.state.try_lock().ok_or("Sc fixture state busy")?;
        let retired_epoch = device.generation.load(Ordering::Acquire);
        let mut disconnect = Box::pin(device.disassociate());
        require(
            disconnect
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "Sc disconnect did not wait for prior control owner",
        )?;
        carrier(device, false)?;
        require(
            device.connected_bssid().is_none(),
            "Sc early disconnect left cached BSSID",
        )?;
        // Attempt the actual old association publication under its state guard,
        // after disconnect's early close but before it can acquire state.
        require(
            state.connection.as_ref().is_some_and(|c| c.authorized),
            "Sc fixture lacks the previous authorized publisher",
        )?;
        require(
            device.publish_link(AP, retired_epoch).is_err(),
            "old native association bypassed close publication generation",
        )?;
        carrier(device, false)?;
        drop(state);
        drop(control);
        run(disconnect, service)?.map_err(|_| "Sc interleaved native disconnect")?;
        // No Device.step runs between teardown and these observations.
        carrier(device, false)?;
        require(
            device.connected_bssid().is_none()
                && narf_net::iface::lookup(device.name()).is_some_and(|i| {
                    i.link_up && i.carrier_up_count == 1 && i.carrier_down_count == 1
                }),
            "Sc old publisher reopened cached peer after completed disconnect",
        )?;
        let state = device
            .state
            .try_lock()
            .ok_or("Sc teardown retained state lock")?;
        require(
            state.connection.is_none()
                && !state.needs_reset
                && model::retained(&state.hardware) == (0, 0, 0),
            "Sc racing disconnect left native peer/queue ownership",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_disconnect_overrides_waiting_old_link_publication
);

#[cfg(feature = "kernel-test")]
fn smoke_sc_socket_owner_close_waits_for_native_m4_then_tears_down() -> TestResult {
    check(|| {
        const NAME: &str = "sc-owner-close-test";
        const PORTID: u32 = 0x5343_c103;
        let mut guard = Guard::new_named(true, Fault::HoldM4, Some(NAME))?;
        guard.register_owner(PORTID)?;
        let device = guard.device();
        scan(device)?;
        let domain = policy();
        let mut association = Box::pin(device.associate_in_domain(request(true), &domain));
        let mut cx = Context::from_waker(Waker::noop());
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                association.as_mut().poll(&mut cx).is_pending(),
                "Sc owner-close setup completed without M4 receipt",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held_tx.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("Sc owner-close setup stalled before native M4");
            }
        }
        carrier(device, false)?;
        // No control-slot work owns association: it holds state independently.
        require(
            device.control.try_lock().is_some_and(|slot| slot.is_none())
                && device.state.try_lock().is_none(),
            "Sc owner-close fixture did not hold native association state",
        )?;
        let baseline = Arc::strong_count(device);
        // This is the actual registered NETLINK_URELEASE -> autodisconnect
        // worker, not a copied decision or a direct disassociate() invocation.
        narf_net::netlink_generic::notify_release(0, PORTID);
        narf_scheduler::poll_one_round();
        let waited_for_association = Arc::strong_count(device) == baseline + 1;
        {
            let mut harness = HARNESS.lock();
            let wire = &mut harness.as_mut().unwrap().1;
            let (queue, pointer) = wire.held_tx.take().unwrap();
            wire.fault = Fault::None;
            // Release precisely the M4 descriptor observed from actual DMA.
            wire.firmware.tx_complete(queue, pointer);
        }
        let association_result = run(association.as_mut(), service);
        // On a failing association, drop its state guard before driving the
        // independently retained socket-close worker to terminal completion.
        drop(association);
        let deadline = narf_time::Deadline::after_ms(3000);
        let mut worker_complete = false;
        loop {
            let _ = service();
            narf_scheduler::poll_one_round();
            if Arc::strong_count(device) == baseline {
                worker_complete = true;
                break;
            }
            if deadline.expired() {
                break;
            }
            narf_scheduler::sleep_pumps::run();
        }
        require(worker_complete, "Sc socket-close worker retained its task")?;
        require(
            association_result?.is_err(),
            "Sc closing owner allowed stale association carrier publication",
        )?;
        require(
            waited_for_association,
            "Sc socket-close worker returned Busy and abandoned pending association",
        )?;
        carrier(device, false)?;
        let state = device
            .state
            .try_lock()
            .ok_or("Sc owner-close state retained")?;
        require(
            device.connected_bssid().is_none()
                && state.connection.is_none()
                && !state.needs_reset
                && !state.hardware.is_failed()
                && model::retained(&state.hardware) == (0, 0, 0),
            "Sc socket close left an authorized peer or native DMA owners",
        )?;
        drop(state);
        let probe = udp_ipv4(
            AP,
            OWN,
            NETWORK.lease_ip,
            NETWORK.server_ip,
            49154,
            7,
            b"sc-owner-closed",
        );
        require(
            send_frame(&probe, narf_net::TxMeta::default()).is_err()
                && narf_net::iface::send_on(NAME, &probe).is_err()
                && HARNESS.lock().as_ref().unwrap().1.data.is_empty(),
            "Sc socket close admitted orphan IP data",
        )
    })
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_socket_owner_close_waits_for_native_m4_then_tears_down
);

fn smoke_sc_current_policy_mcc_epoch_and_pending_native_configuration() -> TestResult {
    check(|| {
        let guard = Guard::new(false, Fault::None)?;
        let device = guard.device();
        scan(device)?;
        run(
            device.associate_in_domain(request(false), &policy()),
            service,
        )?
        .map_err(|_| "Sc policy association failed")?;
        require(device.link_up(), "Sc policy fixture did not associate")?;
        // Correlated MCC facts cannot survive a CHUB notification, even
        // when the host's country and rules are unchanged.
        HARNESS
            .lock()
            .as_mut()
            .unwrap()
            .1
            .firmware
            .inject(0xc9, 0, 0x8000, &[b'S', b'U', 2, 0]);
        for _ in 0..4 {
            device.step(None);
        }
        require(!device.link_up(), "Sc CHUB notification retained carrier")?;
        {
            let state = device
                .state
                .try_lock()
                .ok_or("Sc policy stop not terminal")?;
            require(
                state.needs_reset && state.stop_completed && state.hardware.is_failed(),
                "Sc MCC loss did not complete retained transport stop",
            )?;
        }
        drop(guard);
        let guard = Guard::new(true, Fault::HoldM4)?;
        let device = guard.device();
        scan(device)?;
        let domain = policy();
        let mut association = Box::pin(device.associate_in_domain(request(true), &domain));
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            if association
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return Err("Sc held-M4 policy fixture completed early");
            }
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held_tx.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("Sc policy test did not reach native M4");
            }
            narf_scheduler::sleep_pumps::run();
        }
        let mut replacement = policy();
        replacement.rules[0].max_power_dbm -= 1;
        guard.policy_db.install(replacement);
        require(
            matches!(
                association
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(_))
            ),
            "Sc configuration accepted changed installed policy",
        )?;
        drop(association);
        for _ in 0..4 {
            device.step(None);
        }
        require(
            !device.link_up(),
            "Sc policy change during M4 admitted carrier",
        )?;
        let state = device
            .state
            .try_lock()
            .ok_or("Sc held-M4 stop still busy")?;
        require(
            state.needs_reset
                && state.stop_completed
                && super::super::runtime::model::retained(&state.hardware).2 > 0,
            "Sc held native M4 DMA was released after policy loss",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/policy",
    smoke_sc_current_policy_mcc_epoch_and_pending_native_configuration
);

fn smoke_sc_dropped_public_scan_retains_native_command_until_transport_stop() -> TestResult {
    check(|| {
        let guard = Guard::new(false, Fault::HoldScan)?;
        let device = guard.device();
        let mut scan = Box::pin(device.scan(scan_request()));
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                scan.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "Sc held scan completed early",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("Sc held scan command was not published");
            }
            narf_scheduler::sleep_pumps::run();
        }
        drop(scan);
        {
            let state = device
                .state
                .try_lock()
                .ok_or("Sc dropped scan retained caller lock")?;
            require(
                state.needs_reset && model::retained(&state.hardware).0 == 1,
                "Sc dropped scan discarded pending native DMA",
            )?;
        }
        let commands = HARNESS.lock().as_ref().unwrap().1.commands.len();
        for _ in 0..4 {
            device.step(None);
        }
        let state = device
            .state
            .try_lock()
            .ok_or("Sc scan stop remains unowned")?;
        require(
            state.stop_completed
                && state.hardware.is_failed()
                && !device.link_up()
                && model::retained(&state.hardware).0 == 1
                && HARNESS.lock().as_ref().unwrap().1.commands.len() == commands,
            "Sc scan cancellation resumed emission or released uncertain command DMA",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/policy",
    smoke_sc_dropped_public_scan_retains_native_command_until_transport_stop
);

fn smoke_sc_dropped_close_waiter_after_m4_request_still_retires_native_station() -> TestResult {
    check(|| {
        let guard = Guard::new(true, Fault::HoldM4)?;
        let device = guard.device();
        scan(device)?;
        let domain = policy();
        let mut association = Box::pin(device.associate_in_domain(request(true), &domain));
        let mut cx = Context::from_waker(Waker::noop());
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                association.as_mut().poll(&mut cx).is_pending(),
                "Sc close-drop setup completed before held M4",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held_tx.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("Sc close-drop fixture did not reach M4");
            }
            narf_scheduler::sleep_pumps::run();
        }
        let mut close = Box::pin(device.disassociate());
        require(
            close.as_mut().poll(&mut cx).is_pending(),
            "Sc close did not wait for the native M4 owner",
        )?;
        drop(close);
        require(
            device.closing.load(Ordering::Acquire) && !device.link_up(),
            "Sc dropped close waiter lost its terminal request",
        )?;
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            let (queue, pointer) = wire.held_tx.take().ok_or("Sc held M4 absent")?;
            wire.fault = Fault::None;
            wire.firmware.tx_complete(queue, pointer);
        }
        require(
            run(association.as_mut(), service)?.is_err(),
            "Sc dropped close admitted stale carrier",
        )?;
        drop(association);
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            service()?;
            device.step(None);
            if !device.closing.load(Ordering::Acquire) {
                break;
            }
            if deadline.expired() {
                return Err("Sc retained close did not finish native retirement");
            }
            narf_scheduler::sleep_pumps::run();
        }
        let state = device
            .state
            .try_lock()
            .ok_or("Sc retained close still owns state")?;
        require(
            state.connection.is_none()
                && !state.needs_reset
                && !state.hardware.is_failed()
                && model::retained(&state.hardware) == (0, 0, 0)
                && !device.link_up(),
            "Sc dropped close waiter reset or leaked healthy native owners",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/policy",
    smoke_sc_dropped_close_waiter_after_m4_request_still_retires_native_station
);

#[path = "bz_station_tests.rs"]
mod bz_station_tests;
