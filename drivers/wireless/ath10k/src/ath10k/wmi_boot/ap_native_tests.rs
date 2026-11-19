//! Native AP protocol observer. Expected fields and event layouts are authored
//! from Linux7.3-rc4 headers; no production encoder constructs expected bytes.
use super::*;
use alloc::{boxed::Box, string::String, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use narf_capabilities::{Cap, Invoke, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::Interface;
use narf_wireless::{ap_control::ApControlAuthority, WirelessNetIface};
const OWN: [u8; 6] = [2, 3, 4, 5, 6, 7];
const PEER: [u8; 6] = [2, 0x73, 2, 3, 4, 5];
/// The P2P GO netdev's own (interface) address.
const GO: [u8; 6] = [6, 3, 4, 5, 0x86, 7];
/// A minimal WFA P2P IE (P2P Capability attribute) for the GO beacon.
const P2P_IE: [u8; 11] = [221, 9, 0x50, 0x6f, 0x9a, 0x09, 2, 2, 0, 0, 0];
const TK: [u8; 16] = [0x31; 16];
const GTK: [u8; 16] = [0x32; 16];
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn require(ok: bool) -> Result<(), BmiError> {
    if ok {
        Ok(())
    } else {
        Err(BmiError::BadResponse)
    }
}
#[derive(Debug, Default)]
struct Signals {
    hold: AtomicBool,
    tx: AtomicU32,
    terminal: AtomicU32,
}
#[derive(Debug, Default)]
pub(super) struct Fixture {
    signals: Arc<Signals>,
    active: bool,
    qos: bool,
    legacy_11g: bool,
    up: bool,
    beacon: bool,
    probe: bool,
    peers: Vec<([u8; 6], u16)>,
    commands: Vec<Vec<u8>>,
    packets: Vec<Vec<u8>>,
    hold_map: bool,
    held: Vec<(u16, bool)>,
    ps: Vec<(u32, u32)>,
    /// The AP-type vdev under test (0: the managed vdev the AP replaces).
    vdev: u32,
    /// A GO's own address (`None`: the INIT address OWN).
    own: Option<[u8; 6]>,
    /// The GO's P2P IE reached firmware (0xd003) before its beacon.
    p2p_ie: bool,
}
fn event_body(m: &mut RadioModel, id: u32, tag: u16, body: &[u8]) {
    let mut out = Vec::new();
    item(&mut out, tag, body);
    add_event(m, id, &out);
}
fn peer_map(m: &mut RadioModel, mac: [u8; 6], id: u16) {
    // PEER_MAP byte 1 is the peer's vdev (`ath10k_peer_map_event`).
    let vdev = m.ap.as_ref().map_or(0, |f| f.vdev as u8);
    let mut out = vec![3, vdev];
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&mac);
    out.extend_from_slice(&[0, 0]);
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &out)));
}
fn unmap(m: &mut RadioModel, id: u16) {
    let mut out = vec![4, 0];
    out.extend_from_slice(&id.to_le_bytes());
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &out)));
}
fn tx_receipt(m: &mut RadioModel, id: u16, management: bool) {
    let mut out = if management {
        vec![0x0e, 0, 0, 0]
    } else {
        vec![7, 0, 1, 0]
    };
    if management {
        out.extend_from_slice(&u32::from(id).to_le_bytes());
        out.resize(20, 0);
    } else {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
    }
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &out)));
}
pub(super) fn command(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let b = &bytes[8..];
    require(b.len() >= 8)?;
    let id = word(b, 0);
    let tag = word(b, 4) >> 16;
    m.ap.as_mut().unwrap().commands.push(b.to_vec());
    // The AP-type vdev and its address: the managed vdev 0 with OWN, or a
    // GO's own vdev and address beside it.
    let (vdev, own) = {
        let f = m.ap.as_ref().unwrap();
        (f.vdev, f.own.unwrap_or(OWN))
    };
    let go = vdev != 0;
    let at = vdev.to_le_bytes();
    // Actual HTC credits replenish only the command endpoint. They never
    // complete a management/DATA DMA ID or fabricate a firmware response.
    m.inner.inner.rx.push_back((
        2,
        vec![
            2,
            2,
            8,
            0,
            8,
            0,
            0,
            0,
            1,
            4,
            0,
            0,
            2,
            bytes.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
    match id {
        0x5001 => {
            require(
                tag == 86
                    && b.len() == 28
                    && word(b, 8) == vdev
                    && b[20..26] == own
                    && word(b, 16) == if go { 3 } else { 0 },
            )?;
            require(matches!(word(b, 12), 1 | 2))?;
            m.ap.as_mut().unwrap().active = word(b, 12) == 1;
        }
        0x5002 => {
            require(tag == 87 && b.len() == 12 && word(b, 8) == vdev)?;
            m.ap.as_mut().unwrap().active = false;
            add_event(m, 0x5006, &[]);
        }
        0x6001 => {
            require(tag == 97 && b.len() == 24 && word(b, 8) == vdev && word(b, 20) == 0)?;
            let mac: [u8; 6] = b[12..18].try_into().unwrap();
            let f = m.ap.as_mut().unwrap();
            require(f.active && !f.peers.iter().any(|(old, _)| *old == mac))?;
            let id = if mac == own { 2 } else { 1800 };
            f.peers.push((mac, id));
            if !f.hold_map {
                peer_map(m, mac, id);
            }
        }
        0x6002 => {
            require(tag == 98 && b.len() == 20 && word(b, 8) == vdev)?;
            let mac: [u8; 6] = b[12..18].try_into().unwrap();
            let f = m.ap.as_mut().unwrap();
            let index = f
                .peers
                .iter()
                .position(|(old, _)| *old == mac)
                .ok_or(BmiError::BadResponse)?;
            let (_, id) = f.peers.remove(index);
            unmap(m, id);
            let mut body = vec![0; 12];
            body[..4].copy_from_slice(&at);
            body[4..10].copy_from_slice(&mac);
            event_body(m, 0x6007, 451, &body);
        }
        0x5003 => {
            require(
                tag == 88
                    && b.len() == 112
                    && word(b, 8) == vdev
                    && word(b, 16) == 100
                    && word(b, 20) == 2
                    && word(b, 28) == 4
                    && b[32..36] == *b"narf"
                    && word(b, 84) == 2412
                    && word(b, 88) == 2412,
            )?;
            let mut response = [0; 16];
            response[..4].copy_from_slice(&at);
            event_body(m, 0x5001, 40, &response);
        }
        0x7003 => {
            require(
                tag == 103
                    && b.len() >= 72
                    && word(b, 8) == vdev
                    && word(b, 20) == (105 << 16 | 8)
                    && word(b, 32) >> 16 == 17,
            )?;
            let n = word(b, 16) as usize;
            let tim = word(b, 12) as usize;
            let template = b.get(36..36 + n).ok_or(BmiError::BadResponse)?;
            require(
                template[0] == 0x80
                    && template[4..10] == [255; 6]
                    && template[10..16] == own
                    && template.get(tim..tim + 6) == Some(&[5, 4, 0, 2, 0, 0]),
            )?;
            // `ath10k_mac_remove_vendor_ie`: the GO's P2P IE went to
            // firmware in 0xd003 and is not in the template.
            require(
                !template
                    .windows(6)
                    .any(|w| w[0] == 221 && w[2..6] == [0x50, 0x6f, 0x9a, 0x09])
                    && (!go || m.ap.as_ref().unwrap().p2p_ie),
            )?;
            m.ap.as_mut().unwrap().beacon = true;
        }
        0xd003 => {
            // WMI_TLV_P2P_GO_SET_BEACON_IE: tag 90 {vdev, ie_len}, tag 17.
            require(
                go && tag == 90
                    && word(b, 8) == vdev
                    && word(b, 12) as usize == P2P_IE.len()
                    && word(b, 16) >> 16 == 17
                    && b.get(20..20 + P2P_IE.len()) == Some(&P2P_IE[..]),
            )?;
            m.ap.as_mut().unwrap().p2p_ie = true;
        }
        0x7007 => {
            require(
                tag == 104
                    && b.len() >= 68
                    && word(b, 8) == vdev
                    && word(b, 16) == (105 << 16 | 8)
                    && word(b, 28) >> 16 == 17
                    && b[32] == 0x50
                    && b[42..48] == own,
            )?;
            m.ap.as_mut().unwrap().probe = true;
        }
        0x5005 => {
            let f = m.ap.as_mut().unwrap();
            require(
                tag == 92
                    && b.len() == 24
                    && word(b, 8) == vdev
                    && word(b, 12) == 0
                    && b[16..22] == own
                    && f.beacon
                    && f.probe
                    && f.peers.iter().any(|(mac, _)| *mac == own),
            )?;
            f.up = true;
            let mut status = [0; 8];
            status[..4].copy_from_slice(&at);
            event_body(m, 0x7004, 222, &status);
        }
        0x5007 => {
            require(tag == 94 && word(b, 8) == vdev)?;
            m.ap.as_mut().unwrap().up = false;
        }
        0x5006 => {
            require(tag == 93 && word(b, 8) == vdev && !m.ap.as_ref().unwrap().up)?;
            event_body(m, 0x5002, 41, &at);
        }
        0x6005 => {
            require(
                tag == 101
                    && b.len() >= 112
                    && word(b, 16) == vdev
                    && word(b, 24) == 1
                    && word(b, 36) == 10
                    && word(b, 56) == 1
                    && if m.ap.as_ref().unwrap().legacy_11g {
                        word(b, 64) == 1
                            && word(b, 76) == 12
                            && b[88..100] == [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108]
                    } else {
                        word(b, 64) == 2 && word(b, 76) == 4 && b[88..92] == [2, 4, 11, 22]
                    },
            )?;
        }
        0xe001 => {
            require(tag == 130 && b.len() == 28 && word(b, 8) == vdev && b[12..18] == PEER)?;
            m.ap.as_mut().unwrap().ps.push((word(b, 20), word(b, 24)));
        }
        0x6004 => require(
            tag == 100
                && b.len() == 28
                && word(b, 8) == vdev
                && b[12..18] == PEER
                && word(b, 20) == 3
                && word(b, 24) <= 1,
        )?,
        0x1d001 => {
            require(tag == 149 && b.len() == 12 && word(b, 8) != 0)?;
            event_body(m, 0x1d001, 54, &b[8..12]);
        }
        0x4006 => {
            require(tag == 83 && b.len() == 128 && word(b, 8) == 0 && word(b, 12) == 0)?;
            let qos = m.ap.as_ref().unwrap().qos && m.ap.as_ref().unwrap().active;
            let rows = if qos {
                [
                    [15, 1023, 3, 0, 0, 0],
                    [15, 1023, 7, 0, 0, 0],
                    [7, 15, 2, 3008, 0, 0],
                    [3, 7, 2, 1504, 0, 0],
                ]
            } else {
                [[
                    if m.ap.as_ref().unwrap().legacy_11g {
                        15
                    } else {
                        31
                    },
                    1023,
                    2,
                    0,
                    0,
                    0,
                ]; 4]
            };
            for (ac, expected) in rows.into_iter().enumerate() {
                let at = 16 + ac * 28;
                require(word(b, at) == (84 << 16 | 24))?;
                for (i, value) in expected.into_iter().enumerate() {
                    require(word(b, at + 4 + i * 4) == value)?;
                }
            }
        }
        0x4001 | 0x4003 | 0x3003 => {} // existing factory/power/channel codecs have independent old goldens
        0x5008 => {
            require(tag == 95 && b.len() == 20 && word(b, 8) == vdev)?;
            let (id, value) = (word(b, 12), word(b, 16));
            require(matches!(
                (id, value),
                (25 | 35 | 36, 0x43) | (32 | 21, 0) | (34, 1 | 2) | (20, 0 | 1) | (7 | 8, 1 | 2)
            ))?;
        }
        _ => return Err(BmiError::Unsupported),
    }
    Ok(())
}
pub(super) fn transmit(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let b = bytes.get(8..).ok_or(BmiError::BadResponse)?;
    require(
        b.len() >= 16
            && bytes[..2] == [1, 0]
            && bytes[5] == m.inner.sequence
            && bytes[2..4] == (b.len() as u16).to_le_bytes()
            && b[0] == 1
            && b[12..16] == [255, 255, 0, 0],
    )?;
    m.inner.sequence = m.inner.sequence.wrapping_add(1);
    let id = u16::from_le_bytes([b[6], b[7]]);
    let length = usize::from(u16::from_le_bytes([b[4], b[5]]));
    let (address, payload) = m
        .inner
        .storage
        .as_ref()
        .ok_or(BmiError::BadResponse)?
        .tx
        .snapshot(id)
        .ok_or(BmiError::BadResponse)?;
    let prefetch = length.min(50).div_ceil(4) * 4;
    require(b.len() == 16 + prefetch && b[16..] == payload[..prefetch])?;
    let frame = payload.get(..length).ok_or(BmiError::BadResponse)?.to_vec();
    let management = b[1] == 0x65;
    // `frags_paddr` (htt_tx.c `ath10k_htt_tx_32`): the MSDU itself for
    // ATH10K_HW_TXRX_MGMT; for RAW data on a part without
    // `continuous_frag_desc` (QCA6174) the per-MSDU fragment list, whose
    // one entry is the payload address and length.
    if management {
        require(word(b, 8) == address as u32)?;
    } else {
        let (list, entry) = m
            .inner
            .storage
            .as_ref()
            .ok_or(BmiError::BadResponse)?
            .tx
            .fragment_list(id)
            .ok_or(BmiError::BadResponse)?;
        let mut want = [0u8; 8];
        want[..4].copy_from_slice(&(address as u32).to_le_bytes());
        want[4..].copy_from_slice(&(length as u32).to_le_bytes());
        require(word(b, 8) == list as u32 && entry == want)?;
    }
    require(
        frame.len() >= 24
            && frame[10..16] == OWN
            && if management {
                b[2..4] == [0x40, 0x0c] && frame[1] & 3 == 0
            } else {
                b[1] == 5
                    && b[2..4]
                        == if frame[4] & 1 != 0 {
                            [0x40, 0x0c]
                        } else {
                            [0, 0x0c]
                        }
                    && frame[1] & 3 == 2
            },
    )?;
    let f = m.ap.as_mut().unwrap();
    require(f.up)?;
    f.packets.push(frame);
    f.signals.tx.fetch_add(1, Ordering::AcqRel);
    if f.signals.hold.load(Ordering::Acquire) {
        f.held.push((id, management));
    } else {
        f.signals.terminal.fetch_add(1, Ordering::AcqRel);
        tx_receipt(m, id, management);
    }
    Ok(())
}
pub(super) fn poll(m: &mut RadioModel) {
    let Some(f) = &mut m.ap else {
        return;
    };
    if !f.signals.hold.load(Ordering::Acquire) {
        let held = core::mem::take(&mut f.held);
        f.signals
            .terminal
            .fetch_add(held.len() as u32, Ordering::AcqRel);
        for (id, management) in held {
            tx_receipt(m, id, management);
        }
    }
}
struct Callback(alloc::boxed::Box<dyn FnOnce() + Send>);
impl core::fmt::Debug for Callback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Callback")
    }
}
#[derive(Debug)]
struct Source {
    life: narf_net::native_emission::ProviderLifetime,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
    callback: IrqSafeSpinLock<Option<Callback>>,
}
impl Source {
    fn new() -> Self {
        Self {
            life: narf_net::native_emission::ProviderLifetime::new(),
            messages: IrqSafeSpinLock::new(Vec::new()),
            callback: IrqSafeSpinLock::new(None),
        }
    }
}
impl narf_net::netlink_generic::DeferredReplySink for Source {
    fn current(&self) -> bool {
        let callback = self.callback.lock().take();
        if let Some(callback) = callback {
            callback.0();
        }
        self.life.observe().current()
    }
    fn native_source(&self) -> Option<narf_net::native_emission::Lifetime> {
        Some(self.life.observe())
    }
    fn deliver(&self, bytes: Vec<u8>) -> Result<(), i32> {
        if !self.life.observe().current() {
            return Err(125);
        }
        self.messages.lock().push(bytes);
        Ok(())
    }
}
type Device = crate::ath10k::interface::Device<RadioModel>;
/// Thin concrete dispatcher. The model's Rc-backed inert hardware futures
/// need no Send erasure: ordinary callbacks drive the SAME retained controller
/// within this poll; held/cancel cases pin that controller directly below.
fn dispatched<F: Future>(future: F) -> Result<F::Output, narf_wireless::WirelessError> {
    match drive(future) {
        Poll::Ready(result) => Ok(result),
        Poll::Pending => Err(narf_wireless::WirelessError::Timeout),
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for Device {
    fn current_iftype(&self) -> u32 {
        self.ap_iftype()
    }
    fn set_iftype(&self, mode: u32) -> Result<(), narf_wireless::WirelessError> {
        self.ap_set_iftype(mode)
    }
    fn supports_ap(&self) -> bool {
        self.ap_generation().is_some()
    }
    fn supports_ap_userspace_mlme(&self) -> bool {
        self.supports_ap()
    }
    fn supports_ap_authenticator(&self) -> bool {
        self.supports_ap()
    }
    fn supports_ap_key_sequence(&self) -> bool {
        self.supports_ap()
    }
    fn supports_ap_uapsd(&self) -> bool {
        self.radio.try_lock().is_some_and(|radio| radio.ap_uapsd())
    }
    fn ap_control_generation(&self) -> Option<core::num::NonZeroU64> {
        self.ap_generation()
    }
    fn reserve_ap_control(
        &self,
    ) -> Result<
        Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>,
        narf_wireless::WirelessError,
    > {
        self.reserve_control()
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        narf_wireless::WirelessIfaceInfo {
            base_name: self.name().into(),
            base_mac: self.mac(),
            bands: Vec::new(),
            modes: narf_wireless::iface::WirelessModes::STATION
                | narf_wireless::iface::WirelessModes::AP,
            hw_caps: narf_wireless::iface::HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(
        &self,
        _: narf_wireless::ScanRequest,
    ) -> Result<Vec<narf_wireless::BssInfo>, narf_wireless::WirelessError> {
        Err(narf_wireless::WirelessError::NotSupported)
    }
    async fn associate(
        &self,
        _: narf_wireless::AssociateRequest,
    ) -> Result<(), narf_wireless::WirelessError> {
        Err(narf_wireless::WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), narf_wireless::WirelessError> {
        Err(narf_wireless::WirelessError::NotSupported)
    }
    async fn set_config(
        &self,
        _: narf_wireless::WirelessConfig,
    ) -> Result<(), narf_wireless::WirelessError> {
        Err(narf_wireless::WirelessError::NotSupported)
    }
    async fn start_ap_with_settings_async(
        &self,
        a: &ApControlAuthority,
        c: narf_wireless::ApConfig,
        s: narf_wireless::ApStartSettings,
    ) -> Result<(), narf_wireless::WirelessError> {
        dispatched(self.ap_control(
            a,
            crate::ath10k::interface::ApOperation::Start(
                alloc::boxed::Box::new(c),
                alloc::boxed::Box::new(s),
            ),
        ))?
        .map(|_| ())
    }
    async fn stop_ap_async(
        &self,
        a: &ApControlAuthority,
    ) -> Result<(), narf_wireless::WirelessError> {
        dispatched(self.ap_control(a, crate::ath10k::interface::ApOperation::Stop))?.map(|_| ())
    }
    async fn add_station_async(
        &self,
        a: &ApControlAuthority,
        s: narf_wireless::StationConfig,
    ) -> Result<(), narf_wireless::WirelessError> {
        dispatched(self.ap_control(a, crate::ath10k::interface::ApOperation::Add(s)))?.map(|_| ())
    }
    async fn set_station_async(
        &self,
        a: &ApControlAuthority,
        s: narf_wireless::StationConfig,
    ) -> Result<(), narf_wireless::WirelessError> {
        dispatched(self.ap_control(a, crate::ath10k::interface::ApOperation::Set(s)))?.map(|_| ())
    }
    async fn del_station_async(
        &self,
        a: &ApControlAuthority,
        p: Option<[u8; 6]>,
        _: u16,
    ) -> Result<(), narf_wireless::WirelessError> {
        dispatched(self.ap_control(a, crate::ath10k::interface::ApOperation::Delete(p)))?
            .map(|_| ())
    }
    async fn register_mgmt_frame_ap_async(
        &self,
        a: &ApControlAuthority,
        t: u16,
        p: Vec<u8>,
    ) -> Result<(), narf_wireless::WirelessError> {
        dispatched(self.ap_register(a, t, p))?
    }
    async fn add_key_ap_async(
        &self,
        a: &ApControlAuthority,
        k: narf_wireless::OwnedKey,
    ) -> Result<(), i32> {
        dispatched(self.ap_control(a, crate::ath10k::interface::ApOperation::Key(k)))
            .map_err(|_| 110)?
            .map(|_| ())
            .map_err(|_| 5)
    }
    async fn key_sequence_ap_async(
        &self,
        a: &ApControlAuthority,
        i: u8,
        p: bool,
        m: Option<[u8; 6]>,
    ) -> Result<narf_wireless::KeySequence, i32> {
        dispatched(self.ap_sequence(a, i, p, m)).map_err(|_| 110)?
    }
    async fn default_key_ap_async(
        &self,
        a: &ApControlAuthority,
        i: u8,
        u: bool,
        m: bool,
        g: bool,
        b: bool,
    ) -> Result<(), i32> {
        dispatched(self.ap_control(
            a,
            crate::ath10k::interface::ApOperation::DefaultKey(i, (u, m, g, b)),
        ))
        .map_err(|_| 110)?
        .map(|_| ())
        .map_err(|_| 5)
    }
    async fn tx_control_port_ap_async(
        &self,
        a: &ApControlAuthority,
        r: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, i32> {
        dispatched(self.ap_control(a, crate::ath10k::interface::ApOperation::Control(r)))
            .map_err(|_| 110)?
            .map_err(|_| 5)
    }
}
struct Adapter(Arc<Device>);
impl Interface for Adapter {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.0.link_up()
    }
    fn rx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<narf_net::Frame, { narf_net::RX_RING_N }>>>
    {
        self.0.rx_ring()
    }
    fn tx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<narf_net::Frame, { narf_net::TX_RING_N }>>>
    {
        self.0.tx_ring()
    }
}
struct Bound {
    device: Arc<Device>,
    iface: Arc<dyn WirelessNetIface>,
    cap: Cap<narf_net::NetIface, Write>,
    admin: narf_net::AdminHandle,
    source: Arc<Source>,
    database: Arc<narf_wireless::reg::db::Database>,
    name: String,
}
impl Bound {
    fn new() -> Self {
        Self::with(false)
    }
    /// `go`: the device is a P2P GO netdev with address GO, whose AP owns
    /// its own vdev 1 beside the managed vdev 0.
    fn with(go: bool) -> Self {
        let mac = if go { GO } else { OWN };
        let mut radio = radio_boot_source_ap(
            4,
            Dialect::Tlv,
            1 << 10,
            (3, 1),
            0x8348,
            None,
            (
                RadioSource {
                    hardware: HwRev::Qca6174,
                    rf_chains: 2,
                    vht: None,
                },
                true,
            ),
        );
        assert!(matches!(
            drive(radio.start(&[2412, 5180])),
            Poll::Ready(Ok(_))
        ));
        let model = &mut radio.htt.wmi.htc.transport;
        model.ce = Some(crate::ath10k::boot::CeFixture::new(HwRev::Qca6174));
        model.ap = Some(Fixture {
            vdev: u32::from(go),
            own: go.then_some(GO),
            ..Fixture::default()
        });
        let name: String = narf_net::iface::reserve_name("wlan%d").into();
        narf_net::iface::register_with_context(&name, mac, 0, |_, _, _| Err(()));
        narf_net::iface::set_link_state(&name, false);
        let database = Arc::new(narf_wireless::reg::db::Database::new());
        database.install(station_tests::policy());
        let device = Device::for_test(&name, mac, Arc::new(Mutex::new(radio)), || {
            Some(station_tests::policy())
        });
        let device = Arc::new(if go {
            device.into_go_for_test()
        } else {
            device
        });
        device.ap_database_for_test(database.clone());
        assert!(device.supports_ap());
        assert_eq!(device.set_iftype(if go { 9 } else { 3 }), Ok(()));
        let cap = narf_net::registry()
            .register(&narf_net::bootstrap_authority(), Adapter(device.clone()))
            .unwrap();
        let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon,
        })
        .unwrap()
        .admin;
        let iface: Arc<dyn WirelessNetIface> = device.clone();
        narf_wireless::registry::register(iface.clone());
        narf_net::iface::set_link_state(&name, true);
        Self {
            device,
            iface,
            cap,
            admin,
            source: Arc::new(Source::new()),
            database,
            name,
        }
    }
    fn authority(&self) -> ApControlAuthority {
        let index = narf_net::iface::lookup(&self.name).unwrap().ifindex;
        // Diagnostic bind failure (CI jobs 126311582883 and 126465300433
        // panic here with `NotSupported`, killing the boot): bind reports
        // `NotSupported` only when the AP control generation is absent
        // (device closed/retired) or the mode is not AP/GO, so record the
        // device state that distinguishes those halves instead of a bare
        // unwrap. `supports_ap` false means the generation is gone;
        // `iftype` not 3/9 means the mode moved out from under the bind.
        match ApControlAuthority::bind(
            self.admin.clone(),
            &self.iface,
            0,
            index,
            self.source.clone(),
        ) {
            Ok(authority) => authority.reserve().unwrap(),
            Err(error) => panic!(
                "AP authority bind failed: {error:?} (supports_ap={} iftype={} link_up={})",
                self.device.supports_ap(),
                self.device.current_iftype(),
                self.device.link_up()
            ),
        }
    }
    fn model<R>(&self, f: impl FnOnce(&mut RadioModel) -> R) -> R {
        f(&mut self.device.radio.try_lock().unwrap().htt.wmi.htc.transport)
    }
    fn start(&self, secure: bool) -> Result<(), narf_wireless::WirelessError> {
        let (config, settings) = if self.model(|m| m.ap.as_ref().unwrap().vdev != 0) {
            go_config()
        } else {
            config(secure)
        };
        let authority = self.authority();
        match drive(
            self.device
                .start_ap_with_settings_async(&authority, config, settings),
        ) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(narf_wireless::WirelessError::Timeout),
        }
    }
    fn add(&self, secure: bool) -> Result<(), narf_wireless::WirelessError> {
        let authority = self.authority();
        match drive(self.device.add_station_async(&authority, station(secure))) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(narf_wireless::WirelessError::Timeout),
        }
    }
    fn install(&self, pairwise: bool) -> Result<(), i32> {
        let authority = self.authority();
        match drive(self.device.add_key_ap_async(&authority, key(pairwise))) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(110),
        }
    }
    fn sequence(&self, pairwise: bool) -> Result<narf_wireless::KeySequence, i32> {
        let authority = self.authority();
        match drive(self.device.key_sequence_ap_async(
            &authority,
            if pairwise { 0 } else { 1 },
            pairwise,
            pairwise.then_some(PEER),
        )) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(110),
        }
    }
}
impl Drop for Bound {
    fn drop(&mut self) {
        self.device.retire_host();
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister_for_handle(&self.cap);
        narf_net::iface::unregister(&self.name);
    }
}
fn config(secure: bool) -> (narf_wireless::ApConfig, narf_wireless::ApStartSettings) {
    let mut beacon = vec![0; 36];
    beacon[0] = 0x80;
    beacon[4..10].fill(255);
    beacon[10..16].copy_from_slice(&OWN);
    beacon[16..22].copy_from_slice(&OWN);
    beacon[32..34].copy_from_slice(&100u16.to_le_bytes());
    beacon[34] = 1 | if secure { 16 } else { 0 };
    beacon.extend_from_slice(&[
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 1,
    ]);
    if secure {
        let body = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
        beacon.extend_from_slice(&[48, body.len() as u8]);
        beacon.extend_from_slice(&body);
    }
    let config = narf_wireless::ApConfig {
        ssid: b"narf".to_vec(),
        beacon_head: beacon,
        beacon_tail: Vec::new(),
        probe_resp: None,
        beacon_interval: 100,
        dtim_period: 2,
        frequency_mhz: 2412,
        channel_width: 0,
        center_freq1_mhz: None,
        center_freq2_mhz: None,
        hidden_ssid: 0,
        privacy: secure,
        mbssid: None,
        mbssid_elems: Vec::new(),
        ema_rnr_elems: Vec::new(),
        fils_discovery: None,
        unsol_bcast_probe_resp: None,
        ftm_responder: None,
        twt_responder: false,
        he_obss_pd: None,
        he_bss_color: None,
    };
    let mut settings = narf_wireless::ApStartSettings::default();
    if secure {
        settings.control_port = narf_wireless::ControlPort {
            enabled: true,
            ethertype: 0x888e,
            no_encrypt: false,
            over_nl80211: true,
            no_preauth: false,
        };
    }
    (config, settings)
}
/// An open GO beacon from GO carrying the WFA P2P IE in its tail.
fn go_config() -> (narf_wireless::ApConfig, narf_wireless::ApStartSettings) {
    let (mut config, settings) = config(false);
    config.beacon_head[10..16].copy_from_slice(&GO);
    config.beacon_head[16..22].copy_from_slice(&GO);
    config.beacon_tail = P2P_IE.to_vec();
    (config, settings)
}
fn station(secure: bool) -> narf_wireless::StationConfig {
    narf_wireless::StationConfig {
        mac: PEER,
        aid: 1,
        listen_interval: 10,
        supported_rates: vec![2, 4, 11, 22],
        wme: Some(false),
        uapsd_queues: Some(0),
        uapsd_max_sp: Some(0),
        mfp: Some(false),
        capability: None,
        ext_capability: None,
        ht_capability: None,
        vht_capability: None,
        he_capability: None,
        he_6ghz_capability: None,
        authorized: Some(!secure),
        station_tx_power: None,
    }
}
fn key(pairwise: bool) -> narf_wireless::OwnedKey {
    narf_wireless::OwnedKey::new(narf_wireless::KeyParams {
        idx: if pairwise { 0 } else { 1 },
        pairwise,
        peer: pairwise.then_some(PEER),
        cipher: narf_wireless::CIPHER_SUITE_CCMP,
        key: if pairwise { TK } else { GTK }.to_vec(),
        seq: Vec::new(),
        default_mgmt: false,
    })
}
fn ethernet() -> Vec<u8> {
    narf_wifi_fixtures::udp_ipv4(
        PEER,
        OWN,
        [10, 77, 0, 1],
        [10, 77, 0, 42],
        1111,
        2222,
        b"AP-native-UDP",
    )
}
fn smoke_ath10k_ap_native_start_templates_tim_peer_port_data_and_teardown() -> TestResult {
    let b = Bound::new();
    if b.start(false).is_err() || !b.device.link_up() || b.add(false).is_err() {
        return TestResult::Fail("AP real START/self MAP/templates/client association");
    }
    if b.device
        .enqueue(&ethernet(), narf_net::TxMeta::default())
        .is_err()
    {
        return TestResult::Fail("AP Ethernet enqueue");
    }
    b.device.drain();
    b.device.drain();
    if !b.model(|m| {
        m.ap.as_ref()
            .unwrap()
            .packets
            .iter()
            .any(|f| f[0] == 8 && f[1] == 2 && f[4..10] == PEER && f[16..22] == OWN)
    }) {
        return TestResult::Fail("AP real FromDS HTT DMA");
    }
    let authority = b.authority();
    if !matches!(
        drive(b.device.stop_ap_async(&authority)),
        Poll::Ready(Ok(()))
    ) || b.device.link_up()
        || b.model(|m| {
            m.ap.as_ref().unwrap().active
                || !m.ap.as_ref().unwrap().peers.is_empty()
                || m.inner.storage.as_ref().unwrap().tx.pending() != 0
        })
    {
        return TestResult::Fail(
            "AP exact peer UNMAP/delete STOPPED/vdev delete and STA recreation",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_native_start_templates_tim_peer_port_data_and_teardown
);
fn smoke_ath10k_ap_staged_group_is_not_installed_until_actual_start_and_pn_never_reinstalls(
) -> TestResult {
    let b = Bound::new();
    if b.install(false).is_err() || b.sequence(false).is_ok() || b.device.link_up() {
        return TestResult::Fail("AP pre-START group staging claimed installed key/carrier");
    }
    // Diagnostic probes for the CI bind panic (jobs 126311582883 and
    // 126465300433): `drain` is the one staged-flow step whose failure is
    // ignored, so a device closed there would surface only as a later
    // bind panic. Each probe fails cleanly at its own stage instead, and
    // `supports_ap` false means the AP control generation is gone
    // (device closed), not merely that an operation returned an error.
    if !b.device.supports_ap() {
        return TestResult::Fail("AP staged pre-START closed the device before default-key bind");
    }
    let authority = b.authority();
    if !matches!(
        drive(
            b.device
                .default_key_ap_async(&authority, 1, false, true, false, false)
        ),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP staged default metadata");
    }
    drop(authority);
    if b.start(true).is_err()
        || b.sequence(false).ok().map(|s| s.seq) != Some([0; 6])
        || b.add(true).is_err()
        || b.install(true).is_err()
    {
        return TestResult::Fail("AP actual secure start and zeroizing key owner");
    }
    if !b.device.supports_ap() {
        return TestResult::Fail(
            "AP device closed before authorized-peer set in staged-group test",
        );
    }
    let authority = b.authority();
    let mut peer = station(true);
    peer.authorized = Some(true);
    if !matches!(
        drive(b.device.set_station_async(&authority, peer)),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP real authorized peer prefix");
    }
    drop(authority);
    if b.device
        .enqueue(&ethernet(), narf_net::TxMeta::default())
        .is_err()
    {
        return TestResult::Fail("AP protected Ethernet enqueue");
    }
    if !b.device.supports_ap() {
        return TestResult::Fail("AP device closed before drain in staged-group test");
    }
    b.device.drain();
    b.device.drain();
    if !b.device.supports_ap() {
        return TestResult::Fail("AP drain closed the device before PN check");
    }
    if b.sequence(true).ok().map(|s| s.seq) != Some([1, 0, 0, 0, 0, 0])
        || b.install(true).is_err()
        || b.sequence(true).ok().map(|s| s.seq) != Some([1, 0, 0, 0, 0, 0])
    {
        return TestResult::Fail("AP allocated TX PN or same-key reinstallation reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_staged_group_is_not_installed_until_actual_start_and_pn_never_reinstalls
);
fn auth_response() -> narf_wireless::MgmtTxRequest {
    let mut frame = vec![0xb0, 0, 0, 0];
    frame.extend_from_slice(&PEER);
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&[0, 0, 0, 0, 2, 0, 0, 0]);
    narf_wireless::MgmtTxRequest {
        frequency_mhz: 2412,
        frame,
        offchannel_ok: false,
        duration: 0,
        no_cck: false,
    }
}
fn smoke_ath10k_ap_management_waits_for_actual_air_terminal_and_retains_cancelled_dma() -> TestResult
{
    let b = Bound::new();
    if b.start(false).is_err() {
        return TestResult::Fail("AP terminal setup");
    }
    let signals = b.model(|m| m.ap.as_ref().unwrap().signals.clone());
    signals.hold.store(true, Ordering::Release);
    let mut cx = Context::from_waker(Waker::noop());
    {
        let authority = b.authority();
        let mut future = core::pin::pin!(b.device.ap_control(
            &authority,
            crate::ath10k::interface::ApOperation::Management(auth_response())
        ));
        for _ in 0..128 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail("AP invented ACK before HTT terminal");
            }
            if signals.tx.load(Ordering::Acquire) == 1 {
                break;
            }
        }
        if signals.tx.load(Ordering::Acquire) != 1 || signals.terminal.load(Ordering::Acquire) != 0
        {
            return TestResult::Fail("AP actual native management handoff");
        }
        signals.hold.store(false, Ordering::Release);
        let mut result = None;
        for _ in 0..128 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                result = Some(value);
                break;
            }
        }
        if result != Some(Ok(true)) || signals.terminal.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("AP exact air terminal/status");
        }
    }

    signals.hold.store(true, Ordering::Release);
    {
        let authority = b.authority();
        let mut request = core::pin::pin!(b.device.ap_control(
            &authority,
            crate::ath10k::interface::ApOperation::Management(auth_response())
        ));
        for _ in 0..128 {
            if request.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail("AP cancellation fixture terminal arrived early");
            }
            if signals.tx.load(Ordering::Acquire) == 2 {
                break;
            }
        }
    }
    if b.model(|m| m.inner.storage.as_ref().unwrap().tx.pending()) != 1 {
        return TestResult::Fail("AP dropped waiter recycled native DMA");
    }
    signals.hold.store(false, Ordering::Release);
    if !matches!(
        drive(b.device.cleanup_worker_step()),
        Poll::Ready(Ok(false))
    ) || b.model(|m| m.inner.storage.as_ref().unwrap().tx.pending()) != 0
    {
        return TestResult::Fail("AP actual retained cancellation cleanup");
    }
    // Production uses this exact cleanup step. A proven teardown must leave
    // the retained worker live and admit a later explicit native BSS owner.
    if b.start(false).is_err()
        || !b.device.link_up()
        || b.model(|m| {
            m.ap.as_ref()
                .unwrap()
                .commands
                .iter()
                .filter(|c| word(c, 0) == 0x7003)
                .count()
        }) != 2
    {
        return TestResult::Fail(
            "AP terminal cleanup exited the retained worker or lost later native BSS",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_management_waits_for_actual_air_terminal_and_retains_cancelled_dma
);
fn native_management(m: &mut RadioModel, subtype: u8) {
    let mut frame = vec![
        0;
        if matches!(subtype, 0xa0 | 0xc0) {
            26
        } else {
            30
        }
    ];
    frame[0] = subtype;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&PEER);
    frame[16..22].copy_from_slice(&OWN);
    if subtype == 0xb0 {
        frame[26] = 1;
    }
    let mut head = vec![0; 40];
    u32at(&mut head, 0, 1);
    u32at(&mut head, 4, 31);
    u32at(&mut head, 16, frame.len() as u32);
    let mut body = Vec::new();
    item(&mut body, 44, &head);
    item(&mut body, 17, &frame);
    add_event(m, 0x7001, &body);
}
fn smoke_ath10k_ap_copied_known_peer_management_cannot_rebind_after_actual_delete_and_readd(
) -> TestResult {
    let b = Bound::new();
    if b.start(false).is_err() || b.add(false).is_err() {
        return TestResult::Fail("AP copy setup");
    }
    let authority = b.authority();
    if !matches!(
        drive(
            b.device
                .register_mgmt_frame_ap_async(&authority, 0xb0, Vec::new())
        ),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP original frame registration");
    }
    drop(authority);
    b.model(|m| native_management(m, 0xb0));
    let device = b.device.clone();
    let iface = b.iface.clone();
    let admin = b.admin.clone();
    let source = b.source.clone();
    let index = narf_net::iface::lookup(&b.name).unwrap().ifindex;
    *b.source.callback.lock() = Some(Callback(alloc::boxed::Box::new(move || {
        let authority = ApControlAuthority::bind(admin.clone(), &iface, 0, index, source.clone())
            .unwrap()
            .reserve()
            .unwrap();
        assert!(matches!(
            drive(device.del_station_async(&authority, Some(PEER), 3)),
            Poll::Ready(Ok(()))
        ));
        drop(authority);
        let authority = ApControlAuthority::bind(admin, &iface, 0, index, source)
            .unwrap()
            .reserve()
            .unwrap();
        assert!(matches!(
            drive(device.add_station_async(&authority, station(false))),
            Poll::Ready(Ok(()))
        ));
    })));
    b.device.drain();
    if !b.source.messages.lock().is_empty() {
        return TestResult::Fail("AP old native copy rebound to same-MAC replacement peer");
    }
    b.model(|m| native_management(m, 0xb0));
    b.device.drain();
    if b.source.messages.lock().len() != 1 || !b.device.link_up() {
        return TestResult::Fail("AP fresh genuine management/carrier suppressed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_copied_known_peer_management_cannot_rebind_after_actual_delete_and_readd
);
fn smoke_ath10k_ap_native_loss_beyond_sixty_four_events_denies_original_data_before_pn_or_dma(
) -> TestResult {
    let b = Bound::new();
    if b.start(false).is_err() || b.add(false).is_err() {
        return TestResult::Fail("AP queued-prefix setup");
    }
    b.model(|m| {
        for _ in 0..130 {
            add_event(m, 0x1d001, &[4, 0, 54, 0, 1, 0, 0, 0]);
        }
        unmap(m, 1800);
    });
    if b.device
        .enqueue(&ethernet(), narf_net::TxMeta::default())
        .is_err()
    {
        return TestResult::Fail("AP original queue setup");
    }
    for _ in 0..4 {
        b.device.drain();
    }
    if b.model(|m| {
        !m.ap.as_ref().unwrap().packets.is_empty()
            || m.inner.storage.as_ref().unwrap().tx.pending() != 0
    }) {
        return TestResult::Fail("AP completed loss behind bounded prefix published old DATA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_native_loss_beyond_sixty_four_events_denies_original_data_before_pn_or_dma
);
fn smoke_ath10k_ap_prepublication_map_and_invalid_template_never_authorize_new_native_peer(
) -> TestResult {
    let b = Bound::new();
    let authority = b.authority();
    let (mut invalid, settings) = config(false);
    invalid.beacon_tail = vec![5, 4, 0, 2, 0, 0];
    if !matches!(
        drive(
            b.device
                .start_ap_with_settings_async(&authority, invalid, settings)
        ),
        Poll::Ready(Err(_))
    ) || b.model(|m| !m.ap.as_ref().unwrap().commands.is_empty())
    {
        return TestResult::Fail("AP invalid later TIM published native prefix");
    }
    drop(authority);
    if b.start(false).is_err() {
        return TestResult::Fail("AP old-MAP setup");
    }
    b.model(|m| {
        m.ap.as_mut().unwrap().hold_map = true;
        peer_map(m, PEER, 1800);
    });
    if b.add(false).is_ok()
        || b.model(|m| {
            m.ap.as_ref()
                .unwrap()
                .commands
                .iter()
                .any(|c| word(c, 0) == 0x6005)
        })
    {
        return TestResult::Fail("AP pre-create MAP supplied new association receipt");
    }
    let mixed = Bound::new();
    mixed.model(|m| m.ap.as_mut().unwrap().legacy_11g = true);
    let (mut config, settings) = config(false);
    config
        .beacon_tail
        .extend_from_slice(&[50, 8, 12, 18, 24, 36, 48, 72, 96, 108, 42, 1, 0]);
    let authority = mixed.authority();
    if !matches!(
        drive(
            mixed
                .device
                .start_ap_with_settings_async(&authority, config, settings)
        ),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP native mixed OFDM/CCK BSS setup");
    }
    drop(authority);
    let before = mixed.model(|m| m.ap.as_ref().unwrap().commands.len());
    if mixed.add(false).is_ok() || mixed.model(|m| m.ap.as_ref().unwrap().commands.len()) != before
    {
        return TestResult::Fail(
            "AP non-ERP client triggered unsupported mandatory protection or native prefix",
        );
    }
    let mut erp = station(false);
    erp.supported_rates
        .extend_from_slice(&[12, 18, 24, 36, 48, 72, 96, 108]);
    let authority = mixed.authority();
    if !matches!(
        drive(mixed.device.add_station_async(&authority, erp)),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP genuine ERP client was denied on mixed BSS");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_prepublication_map_and_invalid_template_never_authorize_new_native_peer
);
fn smoke_ath10k_ap_original_policy_arc_and_source_retirement_permanently_deny_old_owner(
) -> TestResult {
    let b = Bound::new();
    if b.start(false).is_err() || b.add(false).is_err() {
        return TestResult::Fail("AP policy setup");
    }
    b.database.install(station_tests::policy()); // equal bytes, distinct signed snapshot owner
    if b.device
        .enqueue(&ethernet(), narf_net::TxMeta::default())
        .is_err()
    {
        return TestResult::Fail("AP policy queue setup");
    }
    b.device.drain();
    b.database.install(station_tests::policy());
    b.device.drain();
    if b.model(|m| !m.ap.as_ref().unwrap().packets.is_empty()) || b.device.link_up() {
        return TestResult::Fail("AP old policy owner revived after equal replacement/restore");
    }
    let c = Bound::new();
    if c.start(false).is_err() {
        return TestResult::Fail("AP source setup");
    }
    let retired = c.source.life.retire();
    retired.notify();
    c.device.drain();
    if c.device.link_up() || c.model(|m| !m.ap.as_ref().unwrap().packets.is_empty()) {
        return TestResult::Fail("AP retired original SME source remained live");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_original_policy_arc_and_source_retirement_permanently_deny_old_owner
);
struct Ccm;
impl narf_wireless::ccmp::AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        bytes: &mut [u8],
    ) -> Result<[u8; 8], narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, bytes)
            .map_err(|_| narf_wireless::ccmp::CcmpError::AuthFailed)
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        bytes: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, bytes, tag)
            .map_err(|_| narf_wireless::ccmp::CcmpError::AuthFailed)
    }
}
fn encrypted(pn: u64) -> Vec<u8> {
    let mut head = vec![8, 0x41, 0, 0];
    head.extend_from_slice(&OWN);
    head.extend_from_slice(&PEER);
    head.extend_from_slice(&OWN);
    head.extend_from_slice(&[0, 0]);
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3, 4];
    let ciphertext =
        narf_wireless::ccmp::protect(&Ccm, &head, &TK, pn, 0, 0, false, &mut body).unwrap();
    head.extend_from_slice(&ciphertext);
    head
}
fn inject(m: &mut RadioModel, mut frame: Vec<u8>, peer: u16) {
    let sequence = u16::from_le_bytes([frame[22], frame[23]]) >> 4;
    frame.extend_from_slice(&[0; 4]);
    let mut desc = [0u8; 300];
    u32at(&mut desc, 4, (1 << 31) | 3);
    u32at(
        &mut desc,
        12,
        u32::from(peer) | 0x1000 | (u32::from(sequence) << 16) | (7 << 28),
    );
    u32at(&mut desc, 24, frame.len() as u32);
    u32at(&mut desc, 56, 0xc000);
    u32at(&mut desc, 104, 0x0400001b);
    let storage = m.inner.storage.as_mut().unwrap();
    let index = *storage.order.front().unwrap();
    let buffer = storage.buffers[index].as_mut().unwrap();
    buffer.bytes[..300].copy_from_slice(&desc);
    buffer.bytes[300..300 + frame.len()].copy_from_slice(&frame);
    let mut b = vec![0x12, 16];
    b.extend_from_slice(&peer.to_le_bytes());
    b.extend_from_slice(&[0, 0, 1, 0]);
    b.extend_from_slice(&(buffer.address as u32).to_le_bytes());
    b.extend_from_slice(&(frame.len() as u16).to_le_bytes());
    b.extend_from_slice(&[0, 0]);
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &b)));
}
fn receive(b: &Bound) -> Option<Vec<u8>> {
    b.device
        .rx_ring()
        .lock()
        .as_mut()
        .and_then(|rx| rx.try_recv().ok().flatten())
        .map(|f| f.payload().to_vec())
}
fn smoke_ath10k_ap_raw_ccmp_mic_port_replay_and_original_copy_policy_gates() -> TestResult {
    let b = Bound::new();
    if b.start(true).is_err() || b.add(true).is_err() || b.install(true).is_err() {
        return TestResult::Fail("AP CCMP setup");
    }
    b.model(|m| inject(m, encrypted(1), 1800));
    b.device.drain();
    if receive(&b).is_some() {
        return TestResult::Fail("AP pre-port protected DATA published");
    }
    let authority = b.authority();
    let mut peer = station(true);
    peer.authorized = Some(true);
    if !matches!(
        drive(b.device.set_station_async(&authority, peer)),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP secure port actual native prefix");
    }
    drop(authority);
    b.model(|m| inject(m, encrypted(1), 1799));
    b.device.drain();
    if receive(&b).is_some() {
        return TestResult::Fail("AP foreign native peer ID published ciphertext");
    }
    b.model(|m| inject(m, encrypted(1), 1800));
    b.device.drain();
    let mut expected = Vec::from(OWN);
    expected.extend_from_slice(&PEER);
    expected.extend_from_slice(&[8, 0, 1, 2, 3, 4]);
    if receive(&b) != Some(expected.clone()) {
        return TestResult::Fail("AP valid AES-CCMP after port or pre-port PN poisoned replay");
    }
    b.model(|m| inject(m, encrypted(1), 1800));
    b.device.drain();
    if receive(&b).is_some() {
        return TestResult::Fail("AP CCMP replay accepted");
    }
    let mut damaged = encrypted(2);
    *damaged.last_mut().unwrap() ^= 1;
    b.model(|m| inject(m, damaged, 1800));
    b.device.drain();
    if receive(&b).is_some() {
        return TestResult::Fail("AP invalid MIC published DATA");
    }
    b.model(|m| inject(m, encrypted(2), 1800));
    b.device.drain();
    if receive(&b) != Some(expected) {
        return TestResult::Fail("AP bad MIC consumed a good PN");
    }
    let database = b.database.clone();
    b.device.set_receive_hook_for_test(move |point| {
        if point == crate::ath10k::interface::ReceivePoint::AfterFrameAllocation {
            database.install(station_tests::policy());
        }
    });
    b.model(|m| inject(m, encrypted(3), 1800));
    b.device.drain();
    if receive(&b).is_some() {
        return TestResult::Fail(
            "AP original native copy bypassed post-allocation policy replacement",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_raw_ccmp_mic_port_replay_and_original_copy_policy_gates
);
fn smoke_ath10k_ap_uapsd_programs_actual_ac_maxsp_ageout_and_refuses_malformed_requests_atomically(
) -> TestResult {
    let b = Bound::new();
    b.model(|m| m.ap.as_mut().unwrap().qos = true);
    let (mut config, settings) = config(false);
    // Literal WMM parameter IE advertises U-APSD; native service6 was present
    // in the actual parsed SERVICE_READY before INIT/READY.
    config.beacon_tail = vec![
        221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x80, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94,
        0, 0x62, 0x32, 47, 0,
    ];
    let authority = b.authority();
    if !matches!(
        drive(
            b.device
                .start_ap_with_settings_async(&authority, config, settings)
        ),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP source-qualified WMM/UAPSD start");
    }
    drop(authority);
    let mut peer = station(false);
    peer.wme = Some(true);
    peer.uapsd_queues = Some(1);
    peer.uapsd_max_sp = Some(1);
    let authority = b.authority();
    if !matches!(
        drive(b.device.add_station_async(&authority, peer.clone())),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP real UAPSD peer association");
    }
    drop(authority);
    if !b.model(|m| {
        let f = m.ap.as_ref().unwrap();
        f.ps == [(0, 0xc0), (1, 1), (2, 10)]
            && f.commands
                .iter()
                .any(|c| word(c, 0) == 0x6005 && word(c, 28) == 0x803 && word(c, 52) == 0x400)
    }) {
        return TestResult::Fail(
            "AP WMM VO mapping/MAX_SP/ageout/association flags not actual wire",
        );
    }
    let before = b.model(|m| m.ap.as_ref().unwrap().commands.len());
    peer.uapsd_queues = Some(16);
    let authority = b.authority();
    if !matches!(
        drive(b.device.set_station_async(&authority, peer)),
        Poll::Ready(Err(_))
    ) || b.model(|m| m.ap.as_ref().unwrap().commands.len()) != before
    {
        return TestResult::Fail("AP malformed UAPSD mutated native prefix");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_uapsd_programs_actual_ac_maxsp_ageout_and_refuses_malformed_requests_atomically
);
fn signed(mut key: narf_wireless::eapol::KeyFrame, kck: &[u8]) -> Vec<u8> {
    key.key_mic.fill(0);
    let mut pdu = key.into_eapol();
    let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(kck, &pdu);
    pdu[81..97].copy_from_slice(&mic[..16]);
    pdu
}
fn control_message(source: &Source) -> Option<Vec<u8>> {
    let messages = source.messages.lock();
    let message = messages.iter().rev().find(|m| m.get(16) == Some(&129))?;
    let mut at = 20;
    while at + 4 <= message.len() {
        let n = usize::from(u16::from_ne_bytes([message[at], message[at + 1]]));
        if n < 4 || at + n > message.len() {
            return None;
        }
        if u16::from_ne_bytes([message[at + 2], message[at + 3]]) == 51 {
            return Some(message[at + 4..at + n].to_vec());
        }
        at += (n + 3) & !3;
    }
    None
}
fn eapol_rx(m: &mut RadioModel, pdu: &[u8]) {
    let mut f = vec![8, 1, 0, 0];
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    f.extend_from_slice(pdu);
    inject(m, f, 1800);
}
fn transmit_control(b: &Bound, pdu: Vec<u8>) -> bool {
    let authority = b.authority();
    matches!(
        drive(b.device.tx_control_port_ap_async(
            &authority,
            narf_wireless::ControlPortTxRequest::new(PEER, 0x888e, pdu, true, true)
        )),
        Poll::Ready(Ok(true))
    )
}
fn smoke_ath10k_ap_userspace_rsn_exchange_uses_native_eapol_air_receipts_before_key_and_port(
) -> TestResult {
    use narf_wireless::eapol::*;
    let b = Bound::new();
    if b.start(true).is_err() || b.add(true).is_err() {
        return TestResult::Fail("AP userspace RSN setup");
    }
    let pmk = [0x55; 32];
    let anonce = [0xaa; 32];
    let snonce = [0x77; 32];
    let ptk = wpa_pmk_to_ptk(KeyMgmt::Psk, &pmk, &OWN, &PEER, &anonce, &snonce, 16);
    let mut m1 = KeyFrame::empty(16);
    m1.key_information = KI_VERSION_HMAC_SHA1_AES | KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK;
    m1.key_length = 16;
    m1.replay_counter = 1;
    m1.key_nonce = anonce;
    let m1 = m1.into_eapol();
    // Diagnostic split of the M1 check (CI job 126311582883 reports only the
    // combined failure): a transmit failure and a packet-shape mismatch have
    // different root causes, so they fail with distinct messages. Both halves
    // keep the original expectations; neither is weakened.
    if !transmit_control(&b, m1.clone()) {
        return TestResult::Fail(
            "AP M1 control transmit did not complete (no HTT air-terminal ack)",
        );
    }
    if !b.model(|m| {
        m.ap.as_ref().unwrap().packets.last().is_some_and(|f| {
            f[1] == 2
                && f.get(24..32) == Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e])
                && f.get(32..) == Some(m1.as_slice())
        })
    }) {
        return TestResult::Fail(
            "AP M1 packet did not traverse actual unprotected HTT control/DMA/air terminal",
        );
    }
    let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
    let mut ie = vec![48, rsn.len() as u8];
    ie.extend_from_slice(&rsn);
    let mut m2 = KeyFrame::empty(16);
    m2.key_information = KI_VERSION_HMAC_SHA1_AES | KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC;
    m2.replay_counter = 1;
    m2.key_nonce = snonce;
    m2.key_data = ie.clone();
    let m2 = signed(m2, &ptk.kck);
    b.model(|m| eapol_rx(m, &m2));
    b.device.drain();
    if control_message(&b.source) != Some(m2.clone()) || receive(&b).is_some() {
        return TestResult::Fail("AP M2 bypassed original native SME source or ordinary DATA port");
    }
    let mut clear = ie;
    clear.extend_from_slice(&[221, 22, 0, 15, 172, 1, 1, 0]);
    clear.extend_from_slice(&GTK);
    if clear.len() % 8 != 0 {
        clear.push(221);
    }
    while clear.len() % 8 != 0 {
        clear.push(0);
    }
    let mut m3 = KeyFrame::empty(16);
    m3.key_information = KI_VERSION_HMAC_SHA1_AES
        | KI_KEY_TYPE_PAIRWISE
        | KI_KEY_ACK
        | KI_KEY_MIC
        | KI_INSTALL
        | KI_SECURE
        | KI_ENCRYPTED_KEY_DATA;
    m3.key_length = 16;
    m3.replay_counter = 2;
    m3.key_nonce = anonce;
    m3.key_data =
        narf_crypto::aes_kw::aes_wrap(ptk.kek.as_slice().try_into().unwrap(), &clear).unwrap();
    if !transmit_control(&b, signed(m3, &ptk.kck)) {
        return TestResult::Fail("AP real MIC/AES-wrapped M3 lacks native air terminal");
    }
    let mut m4 = KeyFrame::empty(16);
    m4.key_information = KI_VERSION_HMAC_SHA1_AES | KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC | KI_SECURE;
    m4.replay_counter = 2;
    let m4 = signed(m4, &ptk.kck);
    b.model(|m| eapol_rx(m, &m4));
    b.device.drain();
    let Some(delivered) = control_message(&b.source) else {
        return TestResult::Fail("AP native M4 missing");
    };
    let mut unsigned = delivered.clone();
    unsigned[81..97].fill(0);
    if delivered != m4
        || narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.kck, &unsigned)[..16] != delivered[81..97]
    {
        return TestResult::Fail("AP userspace authenticator did not receive actual MIC-valid M4");
    }
    let authority = b.authority();
    let mut key = key(true).params().clone();
    key.key = ptk.tk.clone();
    if !matches!(
        drive(
            b.device
                .add_key_ap_async(&authority, narf_wireless::OwnedKey::new(key))
        ),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP derived PTK native software owner");
    }
    drop(authority);
    if b.install(false).is_err() {
        return TestResult::Fail("AP actual group key owner");
    }
    let authority = b.authority();
    if !matches!(
        drive(
            b.device
                .default_key_ap_async(&authority, 1, false, true, false, false)
        ),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP installed GTK selection");
    }
    drop(authority);
    let authority = b.authority();
    let mut peer = station(true);
    peer.authorized = Some(true);
    if !matches!(
        drive(b.device.set_station_async(&authority, peer)),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("AP port before actual M4/key/native peer prefix");
    }
    drop(authority);
    if b.device
        .enqueue(&ethernet(), narf_net::TxMeta::plain())
        .is_err()
    {
        return TestResult::Fail("AP post-RSNA Ethernet queue");
    }
    b.device.drain();
    b.device.drain();
    let actual = b.model(|m| m.ap.as_ref().unwrap().packets.last().cloned().unwrap());
    let mut replay = narf_wireless::ccmp::ReplayWindow::default();
    let Ok(plain) = narf_wireless::ccmp::unprotect(
        &Ccm,
        &actual[..24],
        ptk.tk.as_slice().try_into().unwrap(),
        0,
        false,
        &mut replay,
        &mut actual[24..].to_vec(),
    ) else {
        return TestResult::Fail("AP actual TX not encrypted with derived PTK");
    };
    if plain[..8] != [0xaa, 0xaa, 3, 0, 0, 0, 8, 0] || plain[8..] != ethernet()[14..] {
        return TestResult::Fail("AP post-RSNA exact LLC/UDP bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ap",
    smoke_ath10k_ap_userspace_rsn_exchange_uses_native_eapol_air_receipts_before_key_and_port
);

/// `mac.c::ath10k_add_interface` for `NL80211_IFTYPE_P2P_GO`: the GO's
/// AP START creates its own AP/P2P_GO vdev 1 (no delete or replacement of
/// the managed vdev 0), sends its NSS parameter and self peer, publishes
/// 0xd003 before the P2P-IE-stripped beacon; STOP deletes its self peer
/// and vdev 1 (`ath10k_remove_interface`) without recreating a station
/// vdev, and the id is free again for a second GO start.
fn smoke_ath10k_p2p_go_own_vdev_start_and_teardown() -> TestResult {
    let b = Bound::with(true);
    if b.start(false).is_err() || !b.device.link_up() {
        return TestResult::Fail("GO start on its own vdev");
    }
    let started = b.model(|m| {
        let commands = &m.ap.as_ref().unwrap().commands;
        let create = commands
            .iter()
            .position(|c| word(c, 0) == 0x5001)
            .is_some_and(|at| word(&commands[at], 8) == 1);
        let nss = commands
            .iter()
            .any(|c| word(c, 0) == 0x5008 && word(c, 8) == 1 && word(c, 12) == 0x22);
        let primary_untouched = !commands
            .iter()
            .any(|c| matches!(word(c, 0), 0x5001 | 0x5002) && word(c, 8) == 0);
        create && nss && primary_untouched && m.ap.as_ref().unwrap().p2p_ie
    });
    if !started {
        return TestResult::Fail("GO VDEV_CREATE/NSS on vdev 1, vdev 0 untouched");
    }
    {
        let radio = b.device.radio.try_lock().unwrap();
        if !radio.ap_is_go() || radio.primary_vdev() != 0 || radio.go_identity() != Some((1, GO)) {
            return TestResult::Fail("GO session identity");
        }
    }
    let stop = |b: &Bound| {
        let authority = b.authority();
        matches!(
            drive(b.device.stop_ap_async(&authority)),
            Poll::Ready(Ok(()))
        )
    };
    if !stop(&b) || b.device.link_up() {
        return TestResult::Fail("GO stop");
    }
    let stopped = b.model(|m| {
        let f = m.ap.as_ref().unwrap();
        let self_peer = f
            .commands
            .iter()
            .position(|c| word(c, 0) == 0x6002 && word(c, 8) == 1 && c[12..18] == GO);
        let delete = f
            .commands
            .iter()
            .rposition(|c| word(c, 0) == 0x5002 && word(c, 8) == 1);
        let recreated =
            delete.is_some_and(|at| f.commands[at..].iter().any(|c| word(c, 0) == 0x5001));
        !f.active
            && f.peers.is_empty()
            && self_peer.zip(delete).is_some_and(|(p, d)| p < d)
            && !recreated
    });
    if !stopped {
        return TestResult::Fail("GO self-peer delete, vdev 1 delete, no station restore");
    }
    if b.device.radio.try_lock().unwrap().ap_exists() {
        return TestResult::Fail("GO session retired");
    }
    b.model(|m| {
        let f = m.ap.as_mut().unwrap();
        f.beacon = false;
        f.probe = false;
        f.p2p_ie = false;
    });
    if b.start(false).is_err() || !stop(&b) {
        return TestResult::Fail("GO vdev 1 reused after release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_go_own_vdev_start_and_teardown
);
/// AP <-> station-slot routing: a GO on vdev 1 shares the radio, so a
/// PEER_MAP for the managed vdev 0 (a station-side peer,
/// `ath10k_peer_map_event` byte 1) polled by the GO is not its peer and
/// does not fail it; the GO keeps running and stops cleanly.
fn smoke_ath10k_p2p_go_ignores_other_vdev_peer_map() -> TestResult {
    let b = Bound::with(true);
    if b.start(false).is_err() {
        return TestResult::Fail("GO start on its own vdev");
    }
    b.model(|m| {
        let mut out = vec![3, 0];
        out.extend_from_slice(&7u16.to_le_bytes());
        out.extend_from_slice(&[2, 0x55, 3, 4, 5, 6]);
        out.extend_from_slice(&[0, 0]);
        m.inner
            .inner
            .rx
            .push_back((m.inner.receive_pipe, header(1, &out)));
    });
    {
        let mut radio = b.device.radio.try_lock().unwrap();
        if radio.ap_poll_now(&station_tests::policy()).is_err() || !radio.ap_running() {
            return TestResult::Fail("vdev 0 PEER_MAP failed the GO");
        }
    }
    let authority = b.authority();
    if !matches!(
        drive(b.device.stop_ap_async(&authority)),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("GO stop after foreign PEER_MAP");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_go_ignores_other_vdev_peer_map
);
/// The GO netdev is iftype 9 for its whole life (`set_iftype` accepts only
/// 9) and owns the GO session alone: a home netdev of the same radio may
/// still re-assert station mode while the GO runs, cannot become an AP
/// (one AP session), sees none of the GO's stations and cannot stop it.
fn smoke_ath10k_p2p_go_session_owned_by_go_netdev() -> TestResult {
    let b = Bound::with(true);
    if b.device.current_iftype() != 9
        || b.device.set_iftype(3) != Err(narf_wireless::WirelessError::NotSupported)
        || b.device.set_iftype(9) != Ok(())
    {
        return TestResult::Fail("GO netdev iftype is fixed at 9");
    }
    if b.start(false).is_err() {
        return TestResult::Fail("GO start on its own vdev");
    }
    let home = Device::for_test(
        "ath10kgohome0",
        [2, 0, 0, 0, 0, 0x31],
        b.device.radio.clone(),
        || Some(station_tests::policy()),
    );
    if home.current_iftype() != 2
        || home.set_iftype(2) != Ok(())
        || home.set_iftype(3) != Err(narf_wireless::WirelessError::Busy)
        || !home.ap_station_macs().is_empty()
    {
        return TestResult::Fail("home netdev beside a running GO");
    }
    if !b
        .device
        .radio
        .try_lock()
        .is_some_and(|radio| radio.ap_running())
    {
        return TestResult::Fail("GO still running");
    }
    let authority = b.authority();
    if !matches!(
        drive(b.device.stop_ap_async(&authority)),
        Poll::Ready(Ok(()))
    ) {
        return TestResult::Fail("GO stop by its own netdev");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_go_session_owned_by_go_netdev
);
