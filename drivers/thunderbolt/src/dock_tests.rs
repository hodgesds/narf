//! Composed dock fixture (issue #1098): ONE end-to-end scenario
//! that drives the whole Thunderbolt/USB4 programme through its
//! production paths in a single flow, with assertions at every
//! stage boundary:
//!
//! 0. **ICM gate** — three controllers' firmware-status sample
//!    worlds go through `icm::classify` + `icm::record`, the exact
//!    decision `runtime::start` acts on: native proceeds,
//!    firmware-managed / unsettled / unreadable stand down. Only
//!    the native domain is scanned or programmed below.
//! 1. **Enumeration** — `topology::scan` walks a three-router
//!    fabric (host → dock, host → peer host) over the config
//!    model: router configuration, capability chains, lane
//!    pairing, the PCIe-ownership bit following the `_OSC` grant,
//!    and retimer enumeration on the trained links.
//! 2. **Retimer firmware path** — the chain the scan published on
//!    the dock link takes an NVM firmware update through the
//!    production surface (sector size, block write with zero
//!    padding, read-back, authenticate, re-enumeration), and a
//!    cable retimer refuses the same write.
//! 3. **Tunnels** — `tunnel::reconcile` under the full `_OSC`
//!    grant programs USB3 + DisplayPort + PCIe tunnels to the
//!    dock in one pass; the PCIe hop chain is followed by its
//!    Next-HopID fields and its invariant fields pinned against
//!    the USB4 path configuration layout (lane HopIDs are
//!    allocated first-free, so composed they are not the
//!    single-tunnel fixture's 8).
//! 4. **Suspend/replay** — the device-PM fan-out
//!    (`suspend_all_devices` / `resume_all_devices`, the pair the
//!    system sleep paths gate on) refuses, the CM quiesces the
//!    composed fabric, the retry proceeds, and resume replays
//!    every tunnel through its original activation path.
//! 5. **XDomain** — a second production engine, answering as the
//!    peer host on the host router's other link, is discovered
//!    through the scanned topology; properties are fetched and
//!    validated, ThunderboltIP logs in mutually, an Ethernet
//!    frame crosses the bound data transport through the
//!    registered netdevs, and the dock router on the first link
//!    never becomes a peer (it does not answer XDomain).
//! 6. **Composed PM veto** — with the XDomain link logged in,
//!    the fan-out refuses suspend *without* latching a tunnel
//!    quiesce: the link veto precedes the latch, observably.
//!
//! Stage models stay the independent per-spec implementations
//! the lanes built — no super-fake: the config fabric is the
//! tunnel lane's register model extended with the topology
//! fixtures' header/capability seeding, the sideband responder
//! is modelled from USB4 v2.0 §4.1.1.2/§8.3.2 (Table 8-13,
//! Table 4-18) like lane 7's, the XDomain peer is a second
//! production engine (lane 4's two-engine harness shape), and
//! the PM verdicts come from the production fan-out (lane 2's
//! harness shape).
//!
//! Two stages of the dock story belong to other crates and have
//! no in-tree composition seam — no crate depends on both sides,
//! and this crate neither reads PD state nor hands the USB3
//! tunnel to a USB host model — so they are asserted at the
//! CM's observable edge and named, not faked:
//! - **USB PD contract (usbpd/TCPM):** on hardware, a negotiated
//!   contract and USB4 alt-mode entry are what train the link;
//!   at the CM's edge that precondition *is* the PHY link state.
//!   `usb4_dock_untrained_link_is_no_fabric` pins the negative
//!   side of that edge: untrained links enumerate as no fabric
//!   and reconcile programs nothing.
//! - **USB class cascades (drivers/usb):** the handoff surface
//!   the CM owns is tunnel publication (`usb3_tunnels()` /
//!   `pcie_tunnels()`, spec §3); Ethernet/audio/storage binding
//!   behind the tunnelled hub is the USB programme's surface,
//!   exercised by its own fixtures.

use super::cm::CfgSpace;
use super::control::Config;
use super::retimer::{
    self, Retimer, OP_ENUMERATE_RETIMERS, OP_ERR, OP_GET_NVM_SECTOR_SIZE, OP_NVM_AUTH_WRITE,
    OP_NVM_BLOCK_WRITE, OP_NVM_READ, OP_NVM_SET_OFFSET, OP_ONS, OP_QUERY_CABLE_RETIMER,
    OP_QUERY_LAST_RETIMER, OP_SET_INBOUND_SBTX, OP_UNSET_INBOUND_SBTX, SB_DATA, SB_FW_VERSION,
    SB_LINK_CONF, SB_METADATA, SB_OPCODE, SB_PRODUCT_ID, SB_VENDOR_ID,
};
use super::ring::Error;
use super::topology::{Domain, Router};
use super::tunnel::tests::Model;
use super::xdomain::{Engine, PeerInfo, XdChannel, PKG_XDOMAIN_RESP, ROUTE_REPLY_BIT};
use alloc::collections::BTreeMap;
use alloc::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

/// The composed scenario's domain (the native CM's NHI) and the
/// peer host's domain, as published in the tunnel / peer
/// registries. Fixture-only ids, chosen away from every other
/// fixture's (u32::MAX, 90–99).
const LOCAL_DOMAIN: u32 = 1098;
const PEER_DOMAIN: u32 = 1099;
/// Route of the dock router in the local topology (host port 1).
const DOCK_ROUTE: u64 = 1;
/// Route of the peer host's router (host port 4 — the second
/// lane adapter, separated from port 1 by the NHI and USB3
/// adapters so the scan's lane pairing does not fold the two
/// links into one bonded pair).
const PEER_ROUTE: u64 = 4;
/// The `_OSC` grant the scenario runs under: USB3 + DP + PCIe +
/// XDomain (ACPI USB4 `_OSC` capabilities DWORD 2, bits 0–3).
const CONTROLS: u32 = super::firmware::CONTROL_REQUEST;
/// USB4 Port Capability offset in the lane adapters' capability
/// chains (fixture-chosen; PORT_CS_1 is at +1, the PORT_CS_2
/// data window at +2).
const USB4_CAP: u16 = 12;

// `PORT_CS_1` fields (USB4 v2.0 Table 8-13), restated for the
// sideband responder: Write/Not-Read, No Response, Pending.
// (The Result Code field, bit 26, is never set by this model:
// no modelled command is ever refused.)
const CS1_WNR: u32 = 1 << 24;
const CS1_NR: u32 = 1 << 25;
const CS1_PND: u32 = 1 << 31;

/// Link Configuration dword with the given Phase 3 decision
/// nibble: byte 0 = Enabling/Asymmetric Decisions, byte 1 bit 4
/// = Bonding Support, byte 2 bit 0 = SB channel support
/// (USB4 v2.0 §4.1.1.3), the shape lane 7's model uses.
fn link_conf(decisions: u8) -> u32 {
    (decisions as u32) | (0x10 << 8) | (0x01 << 16)
}

/// One SB register space (a router's or a retimer's), modelled
/// from USB4 v2.0 §4.1.1.3 / §8.3.2: Port Operations complete
/// asynchronously (the first Opcode read-back still shows the
/// opcode, the completion value appears on the next), an
/// `NVM_AUTH_WRITE` restarts the retimer with the outcome in the
/// Opcode/Metadata read-back, and NVM block writes program the
/// whole 64-byte Data register.
#[derive(Clone, Debug)]
struct SbDevice {
    present: bool,
    vendor: u32,
    product: u32,
    fw: u32,
    link_conf: u32,
    last: bool,
    cable: bool,
    opcode: u32,
    metadata: u32,
    data: [u32; retimer::SB_DATA_DWORDS],
    op_pending: Option<(u32, u32)>,
    op_reads: u8,
    sector_size: u32,
    nvm: Vec<u8>,
    nvm_offset: usize,
    auth_code: u32,
}

impl Default for SbDevice {
    fn default() -> Self {
        Self {
            present: false,
            vendor: 0,
            product: 0,
            fw: 0,
            link_conf: 0,
            last: false,
            cable: false,
            opcode: 0,
            metadata: 0,
            data: [0; retimer::SB_DATA_DWORDS],
            op_pending: None,
            op_reads: 0,
            sector_size: 0,
            nvm: Vec::new(),
            nvm_offset: 0,
            auth_code: 0,
        }
    }
}

impl SbDevice {
    fn execute_op(&mut self, opcode: u32) {
        if opcode == OP_NVM_AUTH_WRITE {
            // The retimer restarts on the new image; the opcode
            // register reads back ERR with the validation status
            // in Metadata.
            self.opcode = OP_ERR;
            self.metadata = self.auth_code;
            self.op_pending = None;
            return;
        }
        let result = match opcode {
            OP_QUERY_LAST_RETIMER => (0, self.last as u32),
            OP_QUERY_CABLE_RETIMER => (0, self.cable as u32),
            OP_GET_NVM_SECTOR_SIZE => (0, self.sector_size),
            OP_NVM_SET_OFFSET => {
                self.nvm_offset = (((self.metadata >> 2) & 0x003f_ffff) as usize) * 4;
                (0, self.metadata)
            }
            OP_NVM_BLOCK_WRITE => {
                let mut bytes = Vec::with_capacity(64);
                for word in self.data {
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
                if self.nvm.len() < self.nvm_offset + 64 {
                    self.nvm.resize(self.nvm_offset + 64, 0);
                }
                self.nvm[self.nvm_offset..self.nvm_offset + 64].copy_from_slice(&bytes);
                self.nvm_offset += 64;
                (0, 0)
            }
            OP_NVM_READ => {
                let dwords = ((self.metadata >> 24) & 0xf) as usize;
                let dwords = if dwords == 0 {
                    retimer::SB_DATA_DWORDS
                } else {
                    dwords
                };
                let base = (((self.metadata >> 2) & 0x003f_ffff) as usize) * 4;
                for i in 0..dwords {
                    let mut word = [0u8; 4];
                    for (j, byte) in word.iter_mut().enumerate() {
                        *byte = self.nvm.get(base + i * 4 + j).copied().unwrap_or(0);
                    }
                    self.data[i] = u32::from_le_bytes(word);
                }
                (0, self.metadata)
            }
            OP_SET_INBOUND_SBTX | OP_UNSET_INBOUND_SBTX => (0, 0),
            OP_ENUMERATE_RETIMERS => (0, 0),
            _ => (OP_ONS, 0),
        };
        self.opcode = opcode;
        self.op_pending = Some(result);
        self.op_reads = 0;
    }

    fn register(&self, reg: u8) -> u32 {
        match reg {
            SB_VENDOR_ID => self.vendor,
            SB_PRODUCT_ID => self.product,
            SB_FW_VERSION => self.fw,
            SB_METADATA => self.metadata,
            SB_LINK_CONF => self.link_conf,
            _ => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SbLoad {
    Router,
    Retimer(usize),
}

/// The sideband channel model for one trained link: a router SB
/// space plus the link's retimer chain, behind the PORT_CS_1 /
/// PORT_CS_2 transaction protocol. Pending clears on the second
/// CS1 read after a command (USB4 v2.0 §4.1.1.2).
#[derive(Debug)]
struct SbLink {
    router: SbDevice,
    retimers: Vec<SbDevice>,
    cs1: u32,
    reads: u8,
    outcome_nr: bool,
    outcome_len: u8,
    pending_load: Option<(SbLoad, u8)>,
    window: [u32; retimer::SB_DATA_DWORDS],
    cs1_writes: Vec<u32>,
}

impl SbLink {
    fn new() -> Self {
        let mut router = SbDevice {
            present: true,
            ..SbDevice::default()
        };
        router.link_conf = link_conf(0x03);
        Self {
            router,
            retimers: Vec::new(),
            cs1: 0,
            reads: 0,
            outcome_nr: false,
            outcome_len: 0,
            pending_load: None,
            window: [0; retimer::SB_DATA_DWORDS],
            cs1_writes: Vec::new(),
        }
    }

    fn device_mut(&mut self, load: SbLoad) -> Option<&mut SbDevice> {
        match load {
            SbLoad::Router => Some(&mut self.router),
            SbLoad::Retimer(i) => self.retimers.get_mut(i),
        }
    }

    fn command(&mut self, command: u32) {
        self.cs1_writes.push(command);
        self.cs1 = command;
        self.reads = 0;
        self.outcome_nr = false;
        self.outcome_len = 0;
        self.pending_load = None;
        let reg = (command & 0xff) as u8;
        let len = ((command >> 8) & 0xff) as u8;
        let target = (command >> 16) & 0x7;
        let index = ((command >> 20) & 0xf) as u8;
        let write = command & CS1_WNR != 0;
        let load = match target {
            0 => Some(SbLoad::Router),
            2 if (1..=retimer::MAX_RETIMERS).contains(&index) => {
                Some(SbLoad::Retimer((index - 1) as usize))
            }
            _ => None,
        };
        let present = match load {
            Some(SbLoad::Router) => true,
            Some(SbLoad::Retimer(i)) => self.retimers.get(i).is_some_and(|device| device.present),
            _ => false,
        };
        if !present {
            self.outcome_nr = true;
            return;
        }
        let load = load.unwrap();
        if write {
            let staged = self.window;
            match reg {
                SB_OPCODE => {
                    if let Some(device) = self.device_mut(load) {
                        device.execute_op(staged[0]);
                    }
                }
                SB_METADATA => {
                    if let Some(device) = self.device_mut(load) {
                        device.metadata = staged[0];
                    }
                }
                SB_DATA => {
                    if let Some(device) = self.device_mut(load) {
                        device.data = staged;
                    }
                }
                _ => {}
            }
        } else {
            self.outcome_len = len;
            self.pending_load = Some((load, reg));
        }
    }

    fn cs1_read(&mut self) -> u32 {
        if self.reads == 0 && self.cs1 & CS1_PND != 0 {
            self.reads = 1;
            return self.cs1;
        }
        self.complete_read()
    }

    fn complete_read(&mut self) -> u32 {
        if let Some((load, reg)) = self.pending_load.take() {
            if reg == SB_OPCODE {
                if let Some(device) = self.device_mut(load) {
                    if let Some(result) = device.op_pending {
                        if device.op_reads == 0 {
                            device.op_reads = 1;
                            self.window[0] = device.opcode;
                        } else {
                            device.opcode = result.0;
                            device.metadata = result.1;
                            device.op_pending = None;
                            self.window[0] = result.0;
                        }
                    } else {
                        self.window[0] = device.opcode;
                    }
                }
            } else if reg == SB_DATA {
                if let Some(device) = self.device_mut(load) {
                    self.window = device.data;
                }
            } else if let Some(device) = self.device_mut(load) {
                self.window[0] = device.register(reg);
            }
        }
        let mut value = self.cs1 & !CS1_PND;
        value = (value & !(0xff << 8)) | ((self.outcome_len as u32) << 8);
        if self.outcome_nr {
            value |= CS1_NR;
        }
        value
    }
}

/// The composed config fabric: the tunnel lane's register model
/// (its handshake behaviours are the production-shaped device
/// semantics the tunnels were proven against) with the USB4
/// Port Capability range of the two trained lane ports routed
/// to per-link sideband responders.
struct DockModel {
    inner: Model,
    links: BTreeMap<(u64, u8), SbLink>,
}

impl DockModel {
    fn get(&self, route: u64, port: u8, space: CfgSpace, offset: u16) -> u32 {
        self.inner.get(route, port, space, offset)
    }

    /// The hop entry programmed for ingress HopID `id` on
    /// (`route`, `port`): two dwords at Hops offsets 2·id,
    /// 2·id + 1 (USB4 path configuration space layout).
    fn hop(&self, route: u64, port: u8, id: u16) -> [u32; 2] {
        [
            self.get(route, port, CfgSpace::Hops, 2 * id),
            self.get(route, port, CfgSpace::Hops, 2 * id + 1),
        ]
    }

    /// Walk the composed PCIe tunnel's forward hop chain:
    /// PCIe-DOWN adapter (fixed endpoint HopID 8) → allocated
    /// lane hop on the host's dock link → allocated lane hop on
    /// the dock's upstream link → PCIe-UP adapter (fixed HopID
    /// 8). Lane HopIDs are allocated first-free from 8 (USB4
    /// path setup), so with three tunnels composed they are not
    /// 8 — the chain is followed by its Next-HopID fields
    /// instead of pinning the IDs. The invariant fields are
    /// pinned: valid bits, the PCIe protocol/counter encoding in
    /// word 1's low half, and the buffer-allocation credit (2,
    /// from the Switch-space allocation table) in the lane hops'
    /// credit field.
    fn pcie_chain_ok(&self) -> bool {
        let down = self.hop(0, 7, 8);
        if down[0] & (1 << 31) == 0 || down[1] != 0x0200_0201 {
            return false;
        }
        let n1 = (down[0] & 0x7ff) as u16;
        if n1 < 8 {
            return false;
        }
        let lane_host = self.hop(0, 1, n1);
        if lane_host[0] & (1 << 31) == 0
            || lane_host[1] & 0xffff != 0x0201
            || (lane_host[0] >> 17) & 127 != 2
        {
            return false;
        }
        let n2 = (lane_host[0] & 0x7ff) as u16;
        if n2 < 8 {
            return false;
        }
        let lane_dock = self.hop(DOCK_ROUTE, 1, n2);
        if lane_dock[0] & (1 << 31) == 0
            || lane_dock[1] & 0xffff != 0x0201
            || (lane_dock[0] >> 17) & 127 != 2
            || lane_dock[0] & 0x7ff != 8
        {
            return false;
        }
        let up = self.hop(DOCK_ROUTE, 7, 8);
        up[0] & (1 << 31) != 0 && up[1] == 0x0200_0201
    }
}

impl Config for DockModel {
    async fn read(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        len: u8,
    ) -> Result<Vec<u32>, Error> {
        if space == CfgSpace::Port && self.links.contains_key(&(route, port)) {
            if offset == USB4_CAP + 1 {
                let link = self.links.get_mut(&(route, port)).unwrap();
                return Ok(alloc::vec![link.cs1_read()]);
            }
            if (USB4_CAP + 2..USB4_CAP + 2 + retimer::SB_DATA_DWORDS as u16).contains(&offset) {
                let link = self.links.get_mut(&(route, port)).unwrap();
                let start = (offset - (USB4_CAP + 2)) as usize;
                return Ok(link.window[start..start + len as usize].to_vec());
            }
        }
        self.inner.read(route, port, space, offset, len).await
    }

    async fn write(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        data: &[u32],
    ) -> Result<(), Error> {
        if space == CfgSpace::Port && self.links.contains_key(&(route, port)) {
            if offset == USB4_CAP + 1 {
                let link = self.links.get_mut(&(route, port)).unwrap();
                link.command(data[0]);
                return Ok(());
            }
            if (USB4_CAP + 2..USB4_CAP + 2 + retimer::SB_DATA_DWORDS as u16).contains(&offset) {
                let link = self.links.get_mut(&(route, port)).unwrap();
                let start = (offset - (USB4_CAP + 2)) as usize;
                link.window[start..start + data.len()].copy_from_slice(data);
                return Ok(());
            }
        }
        self.inner.write(route, port, space, offset, data).await
    }
}

/// Seed one port's header + capability chain into the model.
/// `kind` is the raw adapter type (USB4 adapter-type values:
/// 0 inactive, 1 lane, 2 NHI, 0x100101/2 PCIe down/up,
/// 0x200101/2 USB3 down/up, 0x0e0101/2 DP in/out). Lane adapters
/// get a PHY + USB4 capability chain (the USB4 cap carries the
/// sideband responder); protocol adapters get a PHY cap pointing
/// at the adapter capability at dword 32 — the offset the tunnel
/// fixtures' register behaviours key on, whose header dword
/// doubles as the adapter's resting ADP_CS_0.
fn seed_port(m: &mut Model, route: u64, number: u8, kind: u32, link_state: u32) {
    m.put(
        route,
        number,
        CfgSpace::Port,
        1,
        if kind == 0 { 0 } else { 8 },
    );
    m.put(route, number, CfgSpace::Port, 2, kind);
    m.put(route, number, CfgSpace::Port, 4, (64 << 20) | (1 << 31));
    m.put(
        route,
        number,
        CfgSpace::Port,
        5,
        15 | (15 << 11) | (1 << 31),
    );
    if kind == 1 {
        // PHY capability at 8, USB4 capability at 12, chain end.
        m.put(
            route,
            number,
            CfgSpace::Port,
            8,
            (1 << 8) | (USB4_CAP as u32),
        );
        m.put(route, number, CfgSpace::Port, USB4_CAP, 6 << 8);
        // PHY link state (the trained states are 2..=6).
        m.put(route, number, CfgSpace::Port, 9, link_state << 26);
    } else if kind != 0 && kind != 2 {
        // PHY capability at 8 pointing at the adapter capability
        // header at 32 (capability id 4, chain end).
        m.put(route, number, CfgSpace::Port, 8, (1 << 8) | 32);
        m.put(route, number, CfgSpace::Port, 32, 4 << 8);
    }
}

fn seed_router(m: &mut Model, route: u64, vendor: u16, device: u16, count: u8, upstream: u8) {
    m.put(
        route,
        0,
        CfgSpace::Switch,
        0,
        ((device as u32) << 16) | vendor as u32,
    );
    m.put(
        route,
        0,
        CfgSpace::Switch,
        1,
        ((count as u32) << 14) | ((upstream as u32) << 8),
    );
    m.put(route, 0, CfgSpace::Switch, 4, 1 << 29);
    // ROUTER_CS_6: configuration-ready bits the router()
    // configure sequence waits on.
    m.put(route, 0, CfgSpace::Switch, 6, (1 << 24) | (1 << 25));
}

/// Build the composed fabric. `link_state` is the PHY link-state
/// field for the two downstream links (2 = trained; 0 = the
/// untrained state a link sits in before any PD contract and
/// alt-mode entry have run on hardware).
fn dock_model(link_state: u32) -> DockModel {
    let mut m = Model::default();
    // Host router (AMD, device 1): port 1 lane → dock, port 2
    // NHI, port 3 USB3-DOWN, port 4 lane → peer host, port 5
    // DP-IN, port 6 inactive, port 7 PCIe-DOWN.
    seed_router(&mut m, 0, 0x1022, 1, 7, 0);
    seed_port(&mut m, 0, 1, 1, link_state);
    seed_port(&mut m, 0, 2, 2, 0);
    seed_port(&mut m, 0, 3, 0x200101, 0);
    seed_port(&mut m, 0, 4, 1, link_state);
    seed_port(&mut m, 0, 5, 0x0e0101, 0);
    seed_port(&mut m, 0, 6, 0, 0);
    seed_port(&mut m, 0, 7, 0x100101, 0);
    // Dock router (Intel, device 2).
    seed_router(&mut m, DOCK_ROUTE, 0x8086, 2, 7, 1);
    seed_port(&mut m, DOCK_ROUTE, 1, 1, 0);
    seed_port(&mut m, DOCK_ROUTE, 2, 0, 0);
    seed_port(&mut m, DOCK_ROUTE, 3, 0x200102, 0);
    seed_port(&mut m, DOCK_ROUTE, 4, 0, 0);
    seed_port(&mut m, DOCK_ROUTE, 5, 0x0e0102, 0);
    seed_port(&mut m, DOCK_ROUTE, 6, 0, 0);
    seed_port(&mut m, DOCK_ROUTE, 7, 0x100102, 0);
    // Peer host router (Intel, device 3): one upstream lane.
    seed_router(&mut m, PEER_ROUTE, 0x8086, 3, 1, 1);
    seed_port(&mut m, PEER_ROUTE, 1, 1, 0);
    // Register seeds the tunnel model's handshake behaviours
    // expect (the tunnel fixtures' model() set): DP adapter
    // dword +4 on both ends, USB3 dword +3 on both ends, the DP
    // OUT handshake word.
    for route in [0, DOCK_ROUTE] {
        m.put(route, 5, CfgSpace::Port, 36, 2 << 12);
        m.put(route, 3, CfgSpace::Port, 35, 7);
        m.put(route, 1, CfgSpace::Port, 4, 64 << 20);
    }
    m.put(DOCK_ROUTE, 5, CfgSpace::Port, 34, 1 << 6);
    // Sideband responders: the dock link carries a two-retimer
    // chain (index 1 on-board and NVM-updatable, index 2 last);
    // the peer link carries none.
    let mut links = BTreeMap::new();
    let mut dock_link = SbLink::new();
    let mut rt1 = SbDevice {
        present: true,
        vendor: 0x8087,
        product: 0x1111,
        fw: 0x0001_0000,
        last: false,
        sector_size: 0x1000,
        nvm: alloc::vec![0; 0x1000],
        ..SbDevice::default()
    };
    rt1.link_conf = link_conf(0x03);
    let mut rt2 = SbDevice {
        present: true,
        vendor: 0x0451,
        product: 0x2222,
        fw: 0x0002_0000,
        last: true,
        ..SbDevice::default()
    };
    rt2.link_conf = link_conf(0x03);
    dock_link.retimers = alloc::vec![rt1, rt2];
    links.insert((0, 1), dock_link);
    links.insert((0, 4), SbLink::new());
    DockModel { inner: m, links }
}

// ── XDomain stage: a second production engine as the peer ────
//
// The harness shape is lane 4's two-engine fixture: delivering a
// frame to the peer runs the peer engine's packet handler
// synchronously, and an exchange completes with the first queued
// frame matching the reference match rule (kind 7, masked route
// equal, protocol UUID equal). The one composition difference:
// frames addressed to any route but the peer host's are never
// delivered — in this topology the only other depth-1 router is
// the dock, which does not answer XDomain, so exchanges to it
// time out exactly as an unanswered control transaction does.

type Inbox = Rc<RefCell<Vec<(u8, Vec<u32>)>>>;
type FrameQueue = Arc<narf_lib::sync::IrqSafeSpinLock<Vec<(u8, Vec<u8>)>>>;

struct DockSide {
    engine: Rc<RefCell<Engine>>,
    inbox: Inbox,
    domain: Domain,
}

impl DockSide {
    fn new(domain: Domain) -> Option<Self> {
        let (uuid, root) = super::xdomain::local_identity(&domain)?;
        let mut engine = Engine::new(domain.id, CONTROLS);
        engine.set_identity(uuid, root);
        Some(Self {
            engine: Rc::new(RefCell::new(engine)),
            inbox: Rc::new(RefCell::new(Vec::new())),
            domain,
        })
    }

    fn channel(&self, peer: &DockSide) -> DockChannel {
        DockChannel {
            mine: self.inbox.clone(),
            peer_inbox: peer.inbox.clone(),
            peer_engine: peer.engine.clone(),
        }
    }

    fn peer_info(&self) -> Option<PeerInfo> {
        super::xdomain::peers()
            .into_iter()
            .find(|p| p.domain == self.domain.id)
    }
}

struct DockChannel {
    mine: Inbox,
    peer_inbox: Inbox,
    peer_engine: Rc<RefCell<Engine>>,
}

fn wire_route(words: &[u32]) -> u64 {
    ((words[0] as u64) << 32) | words[1] as u64
}

impl XdChannel for DockChannel {
    async fn exchange(&mut self, kind: u8, words: &[u32]) -> Result<Vec<u32>, Error> {
        if wire_route(words) & !ROUTE_REPLY_BIT != PEER_ROUTE {
            return Err(Error::Timeout);
        }
        self.peer_inbox.borrow_mut().push((kind, words.to_vec()));
        let queued: Vec<(u8, Vec<u32>)> = self.peer_inbox.borrow_mut().drain(..).collect();
        let mut engine = self.peer_engine.borrow_mut();
        for (k, w) in queued {
            for out in engine.handle_packet(k, &w) {
                self.mine.borrow_mut().push(out);
            }
        }
        drop(engine);
        let want_route = wire_route(words) & !ROUTE_REPLY_BIT;
        let mut inbox = self.mine.borrow_mut();
        let pos = inbox.iter().position(|(k, w)| {
            *k == PKG_XDOMAIN_RESP
                && w.len() >= 7
                && wire_route(w) & !ROUTE_REPLY_BIT == want_route
                && w[3..7] == words[3..7]
        });
        match pos {
            Some(pos) => Ok(inbox.remove(pos).1),
            None => Err(Error::Timeout),
        }
    }

    async fn send(&mut self, kind: u8, words: &[u32]) -> Result<(), Error> {
        if wire_route(words) & !ROUTE_REPLY_BIT == PEER_ROUTE {
            self.peer_inbox.borrow_mut().push((kind, words.to_vec()));
        }
        Ok(())
    }

    fn drain(&mut self) -> Vec<(u8, Vec<u32>)> {
        self.mine.borrow_mut().drain(..).collect()
    }
}

/// An in-memory data transport pair endpoint (lane 4's shape).
struct MemLink {
    out: FrameQueue,
    inc: FrameQueue,
}

impl super::tbnet::DataLink for MemLink {
    fn send_frame(&mut self, pdf: u8, frame: &[u8]) {
        self.out.lock().push((pdf, frame.to_vec()));
    }
    fn poll_frames(&mut self) -> Vec<(u8, Vec<u8>)> {
        core::mem::take(&mut *self.inc.lock())
    }
}

/// Run both engines' service passes alternately.
fn drive(a: &DockSide, b: &DockSide, rounds: usize) {
    for _ in 0..rounds {
        {
            let mut chan = a.channel(b);
            let mut engine = a.engine.borrow_mut();
            narf_scheduler::block_on_spin(engine.service(&mut chan, &a.domain));
        }
        {
            let mut chan = b.channel(a);
            let mut engine = b.engine.borrow_mut();
            narf_scheduler::block_on_spin(engine.service(&mut chan, &b.domain));
        }
    }
}

/// The registered netdev name for a domain's ThunderboltIP
/// interface (`tbnet<domain>-<n>`), found by prefix so the
/// fixture does not depend on the engine's counter.
fn netdev_name(domain: u32) -> Option<alloc::string::String> {
    let prefix = alloc::format!("tbnet{domain}-");
    narf_net::registry()
        .snapshots()
        .iter()
        .find(|s| s.name.starts_with(&prefix))
        .map(|s| s.name.clone())
}

fn stack_frame(payload: &[u8]) -> Option<narf_net::Frame> {
    let buf =
        narf_io::alloc_coherent(payload.len().max(1), narf_lib::id::DomainId::DRIVER_0).ok()?;
    // SAFETY: the buffer was just allocated for at least
    // `payload.len()` bytes and is exclusively owned here.
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), buf.cpu_mut_ptr::<u8>(), payload.len());
    }
    Some(narf_net::Frame::new(buf, payload.len() as u32))
}

/// Queue one Ethernet frame on the named netdev's TX ring (the
/// stack's side of the interface — the same rings the net stack
/// itself produces into).
fn push_tx(name: &str, payload: &[u8]) -> bool {
    narf_net::registry()
        .with_interface(name, |iface| {
            let Some(frame) = stack_frame(payload) else {
                return false;
            };
            let mut ring = iface.tx_ring().lock();
            match ring.as_mut() {
                Some(producer) => producer.try_send(frame).is_ok(),
                None => false,
            }
        })
        .unwrap_or(false)
}

/// Take one Ethernet frame off the named netdev's RX ring.
fn pop_rx(name: &str) -> Option<Vec<u8>> {
    narf_net::registry()
        .with_interface(name, |iface| {
            let mut ring = iface.rx_ring().lock();
            let consumer = ring.as_mut()?;
            consumer
                .try_recv()
                .ok()
                .flatten()
                .map(|f| f.payload().to_vec())
        })
        .flatten()
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i % 251) as u8))
        .collect()
}

/// The device-PM fan-out outcome for the CM's handler, by
/// registration name (other registrants' outcomes are not this
/// fixture's to judge).
fn usb4_pm_outcome(
    report: &narf_power::device_pm::FanoutReport,
) -> Option<Result<(), narf_power::device_pm::DeviceSuspendError>> {
    report
        .outcomes
        .iter()
        .find(|o| o.name == super::pm::PM_NAME)
        .map(|o| o.result)
}

fn reset_world() {
    super::tunnel::forget_domain(LOCAL_DOMAIN);
    super::xdomain::forget_domain(LOCAL_DOMAIN);
    super::xdomain::forget_domain(PEER_DOMAIN);
    super::tunnel::__reset_pm_for_test();
    super::icm::__reset_for_test();
}

fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

/// The composed dock scenario. See this module's documentation
/// for the stage list and the two named cross-crate boundaries.
fn usb4_dock_composed_end_to_end() -> TestResult {
    use super::icm::{classify, CmMode, FW_STS_ICM_EN, FW_STS_NVM_AUTH_DONE};
    use super::tunnel::{displays, pcie_tunnels, usb3_tunnels, Endpoint, Protocol};
    use narf_power::device_pm::{suspend_all_devices, DeviceSuspendError};

    reset_world();

    // ── Stage 0: the ICM gate ────────────────────────────────
    // The decision runtime::start acts on, over four sample
    // worlds: settled-native proceeds; settled firmware-managed,
    // never-settling, and unreadable all stand down. Verdicts are
    // recorded per controller, and only the native one is ever
    // scanned or programmed below.
    let settled_native = FW_STS_NVM_AUTH_DONE;
    let settled_icm = FW_STS_ICM_EN | FW_STS_NVM_AUTH_DONE;
    let native = classify(&[Some(settled_native), Some(settled_native)]);
    let firmware = classify(&[Some(settled_icm), Some(settled_icm)]);
    let unsettled = classify(&[Some(0), Some(FW_STS_ICM_EN), Some(0), Some(FW_STS_ICM_EN)]);
    let unreadable = classify(&[None, None]);
    if native.mode != CmMode::Native
        || native.mode.stands_down()
        || firmware.mode != CmMode::FirmwareManaged
        || !firmware.mode.stands_down()
        || unsettled.mode != CmMode::Unsettled
        || !unsettled.mode.stands_down()
        || unreadable.mode != CmMode::Unreadable
        || !unreadable.mode.stands_down()
    {
        return TestResult::Fail("dock: ICM verdicts do not gate as runtime::start expects");
    }
    super::icm::record(0, native);
    super::icm::record(1, firmware);
    super::icm::record(2, unsettled);
    super::icm::record(3, unreadable);
    let statuses = super::icm::domain_statuses();
    if statuses.len() != 4
        || statuses[0].mode != CmMode::Native
        || statuses[1].mode != CmMode::FirmwareManaged
        || super::icm::firmware_managed_count() != 1
    {
        return TestResult::Fail("dock: ICM verdicts not published per controller");
    }
    super::icm::__reset_for_test();

    // ── Stage 1: enumeration of the native domain ────────────
    let mut m = dock_model(2);
    let previous = Domain {
        id: LOCAL_DOMAIN,
        routers: Vec::new(),
    };
    let domain = match run(super::topology::scan(
        &mut m,
        LOCAL_DOMAIN,
        CONTROLS,
        &previous,
    )) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("dock: topology scan failed"),
    };
    if domain.routers.len() != 3
        || domain.routers[0].route != 0
        || domain.routers[1].route != DOCK_ROUTE
        || domain.routers[1].upstream != 1
        || domain.routers[2].route != PEER_ROUTE
    {
        return TestResult::Fail("dock: scan did not enumerate host + dock + peer host");
    }
    // The dock router was configured with PCIe tunnelling
    // ownership (ROUTER_CS_5 PTO): the grant includes PCIe and
    // its parent carries a PCIe downstream adapter.
    let dock_cs5 = m.get(DOCK_ROUTE, 0, CfgSpace::Switch, 5);
    if dock_cs5 & (1 << 24) == 0 || dock_cs5 & (1 << 31) == 0 {
        return TestResult::Fail("dock: dock router PTO does not follow the grant");
    }
    // Retimers on the dock link, none on the peer link, no
    // faults — as published on the scanned ports.
    let host = &domain.routers[0];
    let dock_port = match host.ports.iter().find(|p| p.number == 1) {
        Some(p) => p.clone(),
        None => return TestResult::Fail("dock: host dock-link port missing"),
    };
    if dock_port.retimer_fault.is_some()
        || dock_port.retimers.len() != 2
        || dock_port.retimers[0].vendor_id != 0x8087
        || dock_port.retimers[0].product_id != 0x1111
        || dock_port.retimers[0].last
        || dock_port.retimers[1].vendor_id != 0x0451
        || !dock_port.retimers[1].last
        || !dock_port.retimers[0].lane1_enabled()
    {
        return TestResult::Fail("dock: retimer chain on the dock link is wrong");
    }
    let peer_port = host.ports.iter().find(|p| p.number == 4);
    if peer_port.is_none_or(|p| !p.retimers.is_empty() || p.retimer_fault.is_some()) {
        return TestResult::Fail("dock: peer link should carry no retimers and no fault");
    }
    // Byte-for-byte PORT_CS_1 pins (Table 8-13): the
    // ENUMERATE_RE-TIMERS broadcast write to the router's Opcode
    // register, and the Vendor ID read addressed to retimer
    // index 2 — the same dwords lane 7's fixtures pin, produced
    // here through the topology scan's own enumeration.
    let dock_link = &m.links[&(0, 1)];
    if !dock_link.cs1_writes.contains(&0x8100_0408) || !dock_link.cs1_writes.contains(&0x8022_0400)
    {
        return TestResult::Fail("dock: PORT_CS_1 command dwords differ from Table 8-13");
    }

    // ── Stage 2: retimer firmware path ───────────────────────
    // The chain the scan published takes an NVM update through
    // the production surface; the image lands zero-padded to the
    // 64-byte Data register, reads back, and authenticates.
    let rt = dock_port.retimers[0].clone();
    if run(retimer::nvm_sector_size(&mut m, 0, &dock_port, &rt)) != Ok(0x1000) {
        return TestResult::Fail("dock: retimer NVM sector size");
    }
    let image: Vec<u8> = (0..100u32).map(|i| (i as u8) ^ 0xa5).collect();
    if run(retimer::nvm_write(&mut m, 0, &dock_port, &rt, 0, &image)).is_err() {
        return TestResult::Fail("dock: retimer NVM block write");
    }
    {
        let device = &m.links[&(0, 1)].retimers[0];
        if device.nvm[..100] != image[..] || device.nvm[100..128] != [0; 28] {
            return TestResult::Fail("dock: retimer NVM contents after block writes");
        }
    }
    let mut back = [0u8; 100];
    if run(retimer::nvm_read(&mut m, 0, &dock_port, &rt, 0, &mut back)).is_err()
        || back != image[..]
    {
        return TestResult::Fail("dock: retimer NVM read-back");
    }
    if run(retimer::nvm_authenticate(&mut m, 0, &dock_port, &rt)).is_err() {
        return TestResult::Fail("dock: retimer NVM authenticate");
    }
    // Authentication unassigns the index; re-enumeration (as the
    // production flow prescribes) restores the chain and reads
    // the outcome back as a clean auth status.
    let chain = match run(retimer::scan_link(&mut m, 0, &dock_port)) {
        Ok(chain) => chain,
        Err(_) => return TestResult::Fail("dock: retimer re-enumeration after auth"),
    };
    if chain.len() != 2 || chain[0].auth_status != Some(0) {
        return TestResult::Fail("dock: auth status not clean after re-enumeration");
    }
    // A cable retimer refuses the same write — firmware update
    // is an on-board-retimer operation.
    let cable = Retimer {
        index: 2,
        vendor_id: 0x0451,
        product_id: 0x2222,
        fw_version: 0,
        last: true,
        cable: true,
        auth_status: None,
        link_conf: [0x03, 0x10, 0x01],
    };
    if run(retimer::nvm_write(&mut m, 0, &dock_port, &cable, 0, &image))
        != Err(retimer::Error::CableRetimer)
    {
        return TestResult::Fail("dock: cable retimer accepted an NVM write");
    }

    // ── Stage 3: tunnels, one reconcile under the full grant ─
    let mut tunnels = Vec::new();
    if run(super::tunnel::reconcile(
        &mut m,
        &domain,
        &mut tunnels,
        CONTROLS,
    ))
    .is_err()
        || tunnels.len() != 3
    {
        return TestResult::Fail("dock: reconcile did not program USB3 + DP + PCIe");
    }
    if super::tunnel::granted_controls() != CONTROLS || !super::tunnel::pcie_tunnelling_granted() {
        return TestResult::Fail("dock: grant state not published");
    }
    let usb3 = usb3_tunnels();
    let dp = displays();
    let pcie = pcie_tunnels();
    if usb3.len() != 1
        || usb3[0].input != (Endpoint { route: 0, port: 3 })
        || usb3[0].output
            != (Endpoint {
                route: DOCK_ROUTE,
                port: 3,
            })
        || dp.len() != 1
        || dp[0].protocol != Protocol::DisplayPort
        || dp[0].input != (Endpoint { route: 0, port: 5 })
        || dp[0].output
            != (Endpoint {
                route: DOCK_ROUTE,
                port: 5,
            })
        || pcie.len() != 1
        || pcie[0].input != (Endpoint { route: 0, port: 7 })
        || pcie[0].output
            != (Endpoint {
                route: DOCK_ROUTE,
                port: 7,
            })
        || super::tunnel::live_tunnel_count() != 3
    {
        return TestResult::Fail("dock: published tunnel set is not the dock's three tunnels");
    }
    // The PCIe hop chain, followed by its Next-HopID fields
    // through the composed fabric (lane HopIDs are allocated,
    // not fixed, once three tunnels share the links).
    if !m.pcie_chain_ok() {
        return TestResult::Fail("dock: PCIe hop chain differs from the spec layout");
    }
    // USB3 bandwidth handshake completed; both DP adapters are
    // enabled (lane 1/3 fixtures' mask-shaped assertions).
    if m.get(0, 3, CfgSpace::Port, 34) & 0x00ff_ffff == 0
        || m.get(0, 3, CfgSpace::Port, 34) & (1 << 31) != 0
        || m.get(0, 5, CfgSpace::Port, 32) & (3 << 30) != 3 << 30
        || m.get(DOCK_ROUTE, 5, CfgSpace::Port, 32) & (3 << 30) != 3 << 30
    {
        return TestResult::Fail("dock: USB3 handshake or DP enables missing");
    }

    // ── Stage 4: suspend quiesce + resume replay ─────────────
    // Through the production device-PM fan-out (both system
    // sleep paths gate on it), not the CM's internal handlers.
    super::pm::register();
    if usb4_pm_outcome(&suspend_all_devices()) != Some(Err(DeviceSuspendError::Busy)) {
        return TestResult::Fail("dock: fan-out did not refuse suspend with live tunnels");
    }
    if run(super::tunnel::service_pm_suspend(
        &mut m,
        &domain,
        &mut tunnels,
    ))
    .is_err()
        || !tunnels.is_empty()
        || super::tunnel::live_tunnel_count() != 0
        || super::tunnel::suspended_tunnels().len() != 3
    {
        return TestResult::Fail("dock: quiesce did not drain the composed fabric");
    }
    if usb4_pm_outcome(&suspend_all_devices()) != Some(Ok(())) {
        return TestResult::Fail("dock: quiesced fabric still vetoes suspend");
    }
    if usb4_pm_outcome(&narf_power::device_pm::resume_all_devices()) != Some(Ok(())) {
        return TestResult::Fail("dock: resume fan-out refused the replay latch");
    }
    if run(super::tunnel::service_pm_resume(
        &mut m,
        &domain,
        &mut tunnels,
    ))
    .is_err()
        || tunnels.len() != 3
        || super::tunnel::live_tunnel_count() != 3
        || !super::tunnel::suspended_tunnels().is_empty()
        || !super::tunnel::replay_failures().is_empty()
    {
        return TestResult::Fail("dock: replay did not restore the composed fabric");
    }
    if !m.pcie_chain_ok()
        || m.get(0, 7, CfgSpace::Port, 32) & (1 << 31) == 0
        || m.get(DOCK_ROUTE, 7, CfgSpace::Port, 32) & (1 << 31) == 0
    {
        return TestResult::Fail("dock: replayed PCIe programming differs from the original");
    }

    // ── Stage 5: XDomain with the peer host ──────────────────
    // The peer engine's own view of the world: itself at route 0
    // and this host at the same route string it is reached at
    // (routes are per-domain paths; the two engines model the
    // symmetric depth-1 pairing the protocol runs on).
    let peer_view = Domain {
        id: PEER_DOMAIN,
        routers: alloc::vec![
            Router {
                route: 0,
                upstream: 0,
                vendor: 0x8086,
                device: 3,
                ports: Vec::new(),
            },
            Router {
                route: PEER_ROUTE,
                upstream: 1,
                vendor: 0x1022,
                device: 1,
                ports: Vec::new(),
            },
        ],
    };
    let (local_side, peer_side) = match (DockSide::new(domain.clone()), DockSide::new(peer_view)) {
        (Some(a), Some(b)) => (a, b),
        _ => return TestResult::Fail("dock: engine identities did not derive"),
    };
    let (local_uuid, _) = match super::xdomain::local_identity(&domain) {
        Some(pair) => pair,
        None => return TestResult::Fail("dock: local identity missing"),
    };
    drive(&local_side, &peer_side, 8);
    let (info_local, info_peer) = match (local_side.peer_info(), peer_side.peer_info()) {
        (Some(x), Some(y)) => (x, y),
        _ => return TestResult::Fail("dock: XDomain peers did not discover each other"),
    };
    if info_local.route != PEER_ROUTE
        || info_local.identity.vendor_id != 0x8086
        || info_local.identity.device_id != 3
        || info_local
            .services
            .iter()
            .all(|s| s.key != "network" || s.protocol_id != 1)
        || info_peer.uuid != local_uuid
        || info_peer.identity.vendor_id != 0x1022
    {
        return TestResult::Fail("dock: discovered peer identity/services are wrong");
    }
    // The dock router never became a peer: exactly one published
    // peer exists for this domain, at the peer host's route.
    if super::xdomain::peers()
        .iter()
        .filter(|p| p.domain == LOCAL_DOMAIN)
        .count()
        != 1
    {
        return TestResult::Fail("dock: the dock router was published as an XDomain peer");
    }
    // Bind the data transports and log in mutually.
    let ab = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(Vec::new()));
    let ba = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(Vec::new()));
    local_side.engine.borrow_mut().bind_data_link(
        PEER_ROUTE,
        Box::new(MemLink {
            out: ab.clone(),
            inc: ba.clone(),
        }),
    );
    peer_side.engine.borrow_mut().bind_data_link(
        PEER_ROUTE,
        Box::new(MemLink {
            out: ba.clone(),
            inc: ab.clone(),
        }),
    );
    drive(&local_side, &peer_side, 8);
    let (info_local, info_peer) = match (local_side.peer_info(), peer_side.peer_info()) {
        (Some(x), Some(y)) => (x, y),
        _ => return TestResult::Fail("dock: peers vanished after login"),
    };
    if !info_local.login_connected
        || !info_peer.login_connected
        || !info_local.link_up
        || !info_peer.link_up
        || super::xdomain::live_link_count() != 2
    {
        return TestResult::Fail("dock: mutual ThunderboltIP login did not complete");
    }
    // An Ethernet frame crosses through the registered netdevs:
    // queued on the local stack-facing TX ring, delivered to the
    // peer's RX ring intact.
    let (local_net, peer_net) = match (netdev_name(LOCAL_DOMAIN), netdev_name(PEER_DOMAIN)) {
        (Some(a), Some(b)) => (a, b),
        _ => return TestResult::Fail("dock: tbnet netdevs not registered"),
    };
    let frame = pattern(60, 0x10);
    if !push_tx(&local_net, &frame) {
        return TestResult::Fail("dock: could not queue a frame on the tbnet TX ring");
    }
    drive(&local_side, &peer_side, 3);
    if pop_rx(&peer_net) != Some(frame) {
        return TestResult::Fail("dock: frame did not cross the ThunderboltIP link intact");
    }

    // ── Stage 6: the composed suspend veto ───────────────────
    // With the link logged in, the fan-out refuses — and the
    // refusal is the link veto, which precedes the tunnel
    // quiesce latch: nothing is latched or drained.
    if usb4_pm_outcome(&suspend_all_devices()) != Some(Err(DeviceSuspendError::Busy))
        || !super::tunnel::suspended_tunnels().is_empty()
        || super::tunnel::live_tunnel_count() != 3
    {
        return TestResult::Fail("dock: logged-in XDomain link did not veto suspend cleanly");
    }

    // ── Teardown: logout, tunnel teardown, clean world ───────
    local_side.engine.borrow_mut().initiate_logout(PEER_ROUTE);
    {
        let mut chan = local_side.channel(&peer_side);
        let mut engine = local_side.engine.borrow_mut();
        run(engine.service(&mut chan, &local_side.domain));
    }
    if local_side.peer_info().map(|i| i.login_connected) != Some(false) {
        return TestResult::Fail("dock: logout did not drop the local session");
    }
    drop(local_side);
    drop(peer_side);
    super::xdomain::forget_domain(LOCAL_DOMAIN);
    super::xdomain::forget_domain(PEER_DOMAIN);
    for tunnel in tunnels.iter_mut().rev() {
        if run(tunnel.teardown(&mut m, &domain)).is_err() {
            return TestResult::Fail("dock: tunnel teardown failed");
        }
    }
    super::tunnel::forget_domain(LOCAL_DOMAIN);
    super::tunnel::__reset_pm_for_test();
    if super::tunnel::live_tunnel_count() != 0
        || super::xdomain::live_link_count() != 0
        || !usb3_tunnels().is_empty()
        || !displays().is_empty()
        || !pcie_tunnels().is_empty()
        || super::xdomain::peers()
            .iter()
            .any(|p| p.domain == LOCAL_DOMAIN || p.domain == PEER_DOMAIN)
    {
        return TestResult::Fail("dock: fixture left published state behind");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/dock", usb4_dock_composed_end_to_end);

/// The negative side of the PD stage's edge: with both
/// downstream links untrained — the fabric state before a USB PD
/// contract and USB4 alt-mode entry have run on hardware — the
/// scan enumerates the host router alone and reconcile programs
/// nothing. The PD negotiation itself is usbpd's stage; at the
/// CM's edge it appears as link training, and this fixture pins
/// that the CM invents no fabric without it.
fn usb4_dock_untrained_link_is_no_fabric() -> TestResult {
    use super::tunnel::{displays, pcie_tunnels, usb3_tunnels};

    reset_world();
    let mut m = dock_model(0);
    let previous = Domain {
        id: LOCAL_DOMAIN,
        routers: Vec::new(),
    };
    let domain = match run(super::topology::scan(
        &mut m,
        LOCAL_DOMAIN,
        CONTROLS,
        &previous,
    )) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("dock: untrained-link scan failed"),
    };
    if domain.routers.len() != 1 || domain.routers[0].route != 0 {
        return TestResult::Fail("dock: untrained links enumerated phantom routers");
    }
    let host_port = &domain.routers[0].ports[0];
    if !host_port.retimers.is_empty() || host_port.retimer_fault.is_some() {
        return TestResult::Fail("dock: retimer state appeared on an untrained link");
    }
    let mut tunnels = Vec::new();
    if run(super::tunnel::reconcile(
        &mut m,
        &domain,
        &mut tunnels,
        CONTROLS,
    ))
    .is_err()
        || !tunnels.is_empty()
        || !usb3_tunnels().is_empty()
        || !displays().is_empty()
        || !pcie_tunnels().is_empty()
        || super::tunnel::live_tunnel_count() != 0
    {
        return TestResult::Fail("dock: tunnels programmed over untrained links");
    }
    super::tunnel::forget_domain(LOCAL_DOMAIN);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/dock",
    usb4_dock_untrained_link_is_no_fabric
);
