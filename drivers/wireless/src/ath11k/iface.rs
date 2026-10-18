//! The `wlan%d` network interface: `narf_net::Interface` (frame rings,
//! MAC, MTU, carrier) + `narf_wireless::WirelessNetIface` (scan /
//! connect / disconnect forwarded to the mac layer) over the runtime
//! ([`super::runtime`]).
//!
//! Linux: mac80211's netdev (`ieee80211_if_add`, `ieee80211_subif_start_xmit`,
//! `ieee80211_deliver_skb` → `netif_receive_skb`, `netif_carrier_on/off`
//! from `ieee80211_set_associated` / `ieee80211_set_disassoc`) and the
//! cfg80211 SME entry points (`cfg80211_connect` → `ieee80211_mgd_auth` /
//! `_assoc`, `cfg80211_disconnect`).
//!
//! Tasks (all spawned; nothing runs on the init path):
//!
//! - the **runtime loop** ([`Ath11kNetdev::run`]): service the device
//!   (CE, WMI / HTT routing, DP groups, timers), deliver received data to
//!   the stack and the RX frame ring, run the mac layer's housekeeping
//!   (`Mac::poll`: kickout / beacon loss / deauth → carrier off) when no
//!   control operation holds it, sleep ≤ 10 ms on the device interrupts;
//! - the **TX pump** ([`Ath11kNetdev::tx_pump`]): Ethernet frames from the
//!   TX frame ring (the stack's send hook queues there) → 802.11 → TCL.
//!
//! Control operations (`scan`, `associate`, `disassociate`) lock the mac
//! layer (an async mutex held across their awaits, like mac80211's
//! `wiphy` mutex); each port call they make services the device itself.
//!
//! Firmware crash recovery ([`Ath11kNetdev::recover`]) is one more such
//! operation, run by the runtime loop when the transport reported a
//! crash: carrier off, the device recovered
//! ([`super::runtime::Shared::recover_device`]), then what
//! `ath11k_core_post_reconfigure_recovery` → `ieee80211_restart_hw` does
//! for the station (mac layer restarted: `ath11k_mac_op_start` +
//! `ath11k_mac_op_add_interface`) and a reconnect to the last network.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use async_trait::async_trait;
use narf_ipc::{Consumer, Producer};
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::iface::{HwCaps, WirelessBand, WirelessIfaceInfo, WirelessModes};
use narf_wireless::{
    AssociateRequest, BssInfo, KeyParams, MlmeAssocRequest, MlmeAuthRequest, ScanRequest,
    SecurityConfig, WirelessConfig, WirelessError, WirelessNetIface,
};

use super::core::FwNotice;
use super::mac::{channel_number_freq, Disconnect, Mac};
use super::mac_frame::{self as frame, freq_band, Band};
use super::mac_reg::chan_flag;
use super::runtime::{DpIrq, Port, RtIo, RtQmi, Shared};

/// Frames the TX pump takes off the stack's ring per runtime step
/// (`NAPI_POLL_WEIGHT`).
pub const TX_PUMP_BATCH: usize = 64;

/// The mac layer over the runtime ports.
pub type RtMac<Io, Irq, Q> = Mac<Port<Io, Irq, Q>, Port<Io, Irq, Q>>;

/// Where received frames and carrier changes go (the kernel stack on
/// hardware; recorders in the tests).
#[derive(Copy, Clone, Debug)]
pub struct Sinks {
    /// `netif_receive_skb` (`narf_net::iface::on_rx_frame_from`).
    pub rx: fn(&str, &mut [u8]),
    /// Carrier on / off (`netif_carrier_on/off`:
    /// `narf_net::iface::set_link_metadata`).
    pub link: fn(&str, bool),
    /// `IFF_UP` changed by the driver itself: an open that failed brings
    /// the interface back down (`narf_net::iface::set_link_state`).
    pub admin: fn(&str, bool),
    /// The association went away while the carrier was on:
    /// `cfg80211_process_deauth` / `_disassoc` with the frame
    /// ([`Disconnect::frame`], our address given) →
    /// `nl80211::notify_mlme_disconnect`.
    pub disconnected: fn(&str, Disconnect, &[u8; 6]),
    /// A Deauthentication sent with no connection to report
    /// (`cfg80211_tx_mlme_mgmt` for an authentication in progress):
    /// `nl80211::notify_mlme_frame`.
    pub mlme_tx: fn(&str, &[u8]),
    /// `cfg80211_rx_control_port(name, src, proto, pdu, unencrypted)`;
    /// `false` = no owner to take it (the frame is dropped).
    pub control_port: fn(&str, [u8; 6], u16, &[u8], bool) -> bool,
}

/// Who asked for the association a recovery would restore: the
/// command-line autoconnect (in-kernel: NARF reconnects by itself) or an
/// nl80211 CONNECT (userspace: cfg80211 reports the loss and the
/// supplicant reconnects, as when mac80211's `ieee80211_reconfig` cannot
/// restore the association).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectOrigin {
    Kernel,
    Nl80211,
}

/// An external-supplicant operation, applied in order on the runtime
/// loop under the mac layer (the netlink caller cannot wait).
#[derive(Clone, PartialEq, Eq)]
enum ExtOp {
    AddKey(KeyParams),
    DelKey {
        idx: u8,
        pairwise: bool,
    },
    Authorize(bool),
    /// A control-port frame (802.3).
    Tx(Vec<u8>),
    PowerSave(bool),
}

/// What nl80211 may already know synchronously about the keys
/// (mac80211's key table): which are installed.
#[derive(Clone, Copy, Debug, Default)]
struct KeyBook {
    ptk: bool,
    group: [bool; 6],
}

/// What `get_wireless_info` reports, captured from the mac layer at
/// registration (`wiphy->bands[]` after `ath11k_mac_setup_channels_rates`
/// + `ath11k_mac_setup_ht_vht_cap`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RadioInfo {
    /// `(2400 | 5000, enabled channel numbers)`; 6 GHz is not listed
    /// (`narf_wireless` uses bare channel numbers, which collide).
    pub bands: Vec<(u32, Vec<u32>)>,
    pub ht: bool,
    pub vht: bool,
    /// HE capabilities on 2.4 / 5 GHz (`ath11k_mac_setup_he_cap`).
    pub he: bool,
}

impl RadioInfo {
    pub fn from_mac<P: super::mac::WmiPort, D: super::mac::DataPort>(m: &Mac<P, D>) -> Self {
        let mut b2 = Vec::new();
        let mut b5 = Vec::new();
        for c in m.wiphy().iter() {
            if c.flags & chan_flag::DISABLED != 0 {
                continue;
            }
            match freq_band(c.center_freq) {
                Band::Ghz2 => b2.push(frame::freq_to_channel(c.center_freq)),
                Band::Ghz5 => b5.push(frame::freq_to_channel(c.center_freq)),
                _ => {}
            }
        }
        let own = m.own_caps();
        let mut bands = Vec::new();
        if !b2.is_empty() {
            bands.push((2400, b2));
        }
        if !b5.is_empty() {
            bands.push((5000, b5));
        }
        RadioInfo {
            bands,
            ht: own.ht_2g.ht_supported || own.ht_5g.ht_supported,
            vht: own.vht_5g.vht_supported,
            he: m.own_he(Band::Ghz2).is_some() || m.own_he(Band::Ghz5).is_some(),
        }
    }
}

/// The ath11k station netdev.
#[allow(missing_debug_implementations)]
pub struct Ath11kNetdev<Io: RtIo, Irq: DpIrq, Q: RtQmi> {
    name: &'static str,
    mac_addr: [u8; 6],
    pub shared: Arc<Shared<Io, Irq, Q>>,
    pub mac: Mutex<RtMac<Io, Irq, Q>>,
    radio: RadioInfo,
    sinks: Sinks,
    up: AtomicBool,
    /// `IFF_UP` as the stack last requested it (`ndo_open` / `ndo_stop`).
    admin_up: AtomicBool,
    /// bit 63 = associated, low 48 bits = BSSID (LE).
    bssid: AtomicU64,
    channel: AtomicU32,
    rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    rx_prod: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    pub stats: NetdevStats,
    /// The network of the last successful `associate` (cleared by
    /// `disassociate`) and who asked for it: where a kernel-originated
    /// connection reconnects after a recovery.
    last_assoc: IrqSafeSpinLock<Option<(AssociateRequest, ConnectOrigin)>>,
    ext_ops: IrqSafeSpinLock<alloc::collections::VecDeque<ExtOp>>,
    keys: IrqSafeSpinLock<KeyBook>,
    /// The association's control port: EtherType, and whether
    /// pre-authentication frames go to nl80211 (`over_nl80211 &&
    /// !no_preauth`) — bit 16.
    ctrl_port: AtomicU32,
    /// `wdev->ps` as requested.
    ps: AtomicBool,
}

/// `AssociateRequest` is not `Clone`.
fn copy_request(r: &AssociateRequest) -> AssociateRequest {
    AssociateRequest {
        bssid: r.bssid,
        ssid: r.ssid.clone(),
        channel: r.channel,
        security: match &r.security {
            SecurityConfig::Open => SecurityConfig::Open,
            SecurityConfig::Wpa2 { psk } => SecurityConfig::Wpa2 { psk: *psk },
            SecurityConfig::Wpa3 { password } => SecurityConfig::Wpa3 {
                password: password.clone(),
            },
            SecurityConfig::External(e) => SecurityConfig::External(*e),
        },
        ie: r.ie.clone(),
    }
}

/// Counters.
#[derive(Debug, Default)]
pub struct NetdevStats {
    pub rx_delivered: AtomicU32,
    pub rx_ring_full: AtomicU32,
    pub tx_queued: AtomicU32,
    pub tx_dropped: AtomicU32,
    /// Frames whose offload request was refused (TSO / VLAN insertion
    /// asked for, or a checksum request the hardware cannot complete:
    /// [`super::tx_offload::csum_partial_prepare`]).
    pub tx_offload_refused: AtomicU32,
    pub link_losses: AtomicU32,
    /// Firmware recoveries run / completed / reconnected after.
    pub recoveries: AtomicU32,
    pub recovered: AtomicU32,
    pub reconnects: AtomicU32,
}

fn alloc_frame(bytes: &[u8]) -> Option<Frame> {
    let buf = narf_io::alloc_coherent(bytes.len().max(1), narf_lib::id::DomainId::DRIVER_0).ok()?;
    let mut f = Frame::new(buf, bytes.len() as u32);
    f.payload_mut().copy_from_slice(bytes);
    Some(f)
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Ath11kNetdev<Io, Irq, Q> {
    /// A netdev named `name` over the runtime and its (started, vif
    /// added) mac layer. The frame rings are created here.
    pub fn new(
        name: &'static str,
        shared: Arc<Shared<Io, Irq, Q>>,
        mac: RtMac<Io, Irq, Q>,
        mac_addr: [u8; 6],
        sinks: Sinks,
    ) -> (Self, Consumer<Frame, TX_RING_N>) {
        let radio = RadioInfo::from_mac(&mac);
        let (rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
        (
            Ath11kNetdev {
                name,
                mac_addr,
                shared,
                mac: Mutex::new(mac),
                radio,
                sinks,
                up: AtomicBool::new(false),
                admin_up: AtomicBool::new(false),
                bssid: AtomicU64::new(0),
                channel: AtomicU32::new(0),
                rx_ring: IrqSafeSpinLock::new(Some(rx_cons)),
                tx_ring: IrqSafeSpinLock::new(Some(tx_prod)),
                rx_prod: IrqSafeSpinLock::new(Some(rx_prod)),
                stats: NetdevStats::default(),
                last_assoc: IrqSafeSpinLock::new(None),
                ext_ops: IrqSafeSpinLock::new(alloc::collections::VecDeque::new()),
                keys: IrqSafeSpinLock::new(KeyBook::default()),
                ctrl_port: AtomicU32::new(0),
                ps: AtomicBool::new(true),
            },
            tx_cons,
        )
    }

    pub fn radio(&self) -> &RadioInfo {
        &self.radio
    }

    /// Carrier down with the reason cfg80211 reports (`None` when the
    /// mac layer recorded none: a local disconnect).
    fn link_down(&self, why: Option<Disconnect>) {
        let was = self.link_up();
        let bssid = self.connected_bssid().unwrap_or([0; 6]);
        self.set_link(false, None, 0);
        if was {
            let d = why.unwrap_or(Disconnect {
                reason: frame::WLAN_REASON_DEAUTH_LEAVING,
                from_ap: false,
                deauth: true,
                bssid,
            });
            let d = if d.bssid == [0; 6] {
                Disconnect { bssid, ..d }
            } else {
                d
            };
            (self.sinks.disconnected)(self.name, d, &self.mac_addr);
        }
    }

    fn set_link(&self, up: bool, bssid: Option<[u8; 6]>, channel: u32) {
        match bssid {
            Some(b) if up => {
                let mut packed = 1u64 << 63;
                for (i, byte) in b.iter().enumerate() {
                    packed |= (*byte as u64) << (8 * i);
                }
                self.bssid.store(packed, Ordering::Release);
                self.channel.store(channel, Ordering::Release);
            }
            _ => {
                self.bssid.store(0, Ordering::Release);
                self.channel.store(0, Ordering::Release);
                // The station entry and its keys are gone.
                *self.keys.lock() = KeyBook::default();
                self.ext_ops.lock().clear();
                self.ctrl_port.store(0, Ordering::Release);
            }
        }
        let was = self.up.swap(up, Ordering::AcqRel);
        if was != up {
            (self.sinks.link)(self.name, up);
        }
    }

    /// The stack's `ndo_open` / `ndo_stop` (`narf_net::iface::set_open_stop`):
    /// record `IFF_UP`. Sync and lock-free (it runs in the caller's
    /// syscall); the runtime loop, or the next control operation, applies
    /// it under the mac layer ([`Self::sync_admin`]).
    pub fn request_admin(&self, up: bool) {
        self.admin_up.store(up, Ordering::Release);
    }

    /// `IFF_UP` as requested.
    pub fn admin_up(&self) -> bool {
        self.admin_up.load(Ordering::Acquire)
    }

    /// Bring the mac layer to the requested administrative state, holding
    /// it. `true` while the interface is open (hardware started, station
    /// vif added).
    pub async fn sync_admin(&self, m: &mut RtMac<Io, Irq, Q>) -> bool {
        let want = self.admin_up();
        let open = m.vif().is_some();
        if want && !open {
            if self.do_open(m).await.is_err() {
                // dev_open failed: the device stays down.
                self.admin_up.store(false, Ordering::Release);
                (self.sinks.admin)(self.name, false);
                return false;
            }
            return true;
        }
        if !want && open {
            self.do_stop(m).await;
            return false;
        }
        open
    }

    /// `ieee80211_do_open` for the station vif: `drv_start`
    /// (`ath11k_mac_op_start`) when the hardware is not running
    /// (`local->open_count == 0`), then `drv_add_interface`; a failed
    /// add_interface stops the hardware again (`err_stop`). Each step
    /// latches its own mac step on failure. The carrier stays off until
    /// association.
    async fn do_open(&self, m: &mut RtMac<Io, Irq, Q>) -> Result<(), super::mac::MacError> {
        let started_here = !m.is_started();
        if started_here {
            m.start().await?;
        }
        if let Err(e) = m.add_interface().await {
            if started_here {
                m.stop().await;
            }
            return Err(e);
        }
        Ok(())
    }

    /// `dev_close` for the station: NETDEV_GOING_DOWN (`cfg80211_leave` →
    /// `cfg80211_disconnect(WLAN_REASON_DEAUTH_LEAVING)`, carrier off),
    /// then `ieee80211_do_stop` (TXQs purged, `drv_remove_interface` →
    /// `ath11k_mac_op_remove_interface`, the vif's management TX IDR
    /// entries freed, `drv_stop` → `ath11k_mac_op_stop` with
    /// `num_pending_mgmt_tx = 0`).
    async fn do_stop(&self, m: &mut RtMac<Io, Irq, Q>) {
        if m.link().is_some() {
            self.shared.flush_queues(true).await;
            let _ = m.disassociate().await;
        }
        let why = m.take_disconnect();
        self.link_down(why);
        self.shared.lock().await.purge_txqs();
        if let Err(e) = m.remove_interface().await {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {}: failed to delete vdev: (-{}) (step {})",
                self.name,
                e,
                super::runtime::step::IF_DOWN_VDEV_DELETE
            );
        }
        {
            let mut g = self.shared.lock().await;
            // ath11k_mac_vif_txmgmt_idr_remove; the ath11k_vif (and its
            // ath11k_dp_vdev_tx_attach state) goes with the vif.
            g.mgmt = super::runtime::MgmtTx::default();
            g.link.vif = None;
            // ieee80211_do_stop frees what is still waiting for a status.
            let pending: Vec<u32> = g.ack_frames.ids().collect();
            for id in pending {
                g.ack_frames.remove(id);
                g.ack_status.push_back((id, super::txq::TxStatus::DROPPED));
            }
        }
        m.stop().await;
    }

    /// The stack's send hook (`ieee80211_subif_start_xmit`): queue an
    /// Ethernet frame (with the stack's offload request, carried in the
    /// frame) on the TX ring. Sync and IRQ-safe (no runtime lock). TSO and
    /// VLAN insertion are not advertised ([`super::tx_offload::OFFLOADS`])
    /// and refused.
    pub fn queue_tx(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if meta.tso_mss.is_some() || meta.vlan_tag.is_some() {
            self.stats
                .tx_offload_refused
                .fetch_add(1, Ordering::Relaxed);
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
        if !self.link_up() {
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
        let Some(mut f) = alloc_frame(bytes) else {
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(());
        };
        f.set_tx_meta(meta);
        let mut g = self.tx_ring.lock();
        let Some(p) = g.as_mut() else {
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(());
        };
        match p.try_send(f) {
            Ok(()) => {
                self.stats.tx_queued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                Err(())
            }
        }
    }

    /// A frame taken from the TX ring, ready for the TXQs: a checksum
    /// request (`TxMeta::csum_l4`, Linux `CHECKSUM_PARTIAL`) is validated
    /// and its seed written ([`super::tx_offload::csum_partial_prepare`]);
    /// one the hardware cannot complete is dropped, never sent
    /// half-checksummed.
    fn tx_prepare(&self, frame: &Frame) -> Result<(Vec<u8>, bool), i32> {
        let meta = frame.tx_meta();
        if meta.tso_mss.is_some() || meta.vlan_tag.is_some() {
            self.stats
                .tx_offload_refused
                .fetch_add(1, Ordering::Relaxed);
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(super::tx_offload::EINVAL);
        }
        let mut eth = frame.payload().to_vec();
        if let Some(kind) = meta.csum_l4 {
            if let Err(e) = super::tx_offload::csum_partial_prepare(&mut eth, kind) {
                self.stats
                    .tx_offload_refused
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        }
        Ok((eth, meta.csum_l4.is_some()))
    }

    /// Hand frames taken from the TX ring to the runtime's per-AC TXQs
    /// (one lock hold; [`super::txq`]); each frame's result.
    pub async fn tx_batch(&self, frames: &[Frame]) -> Vec<Result<(), i32>> {
        let mut out: Vec<Result<(), i32>> = Vec::with_capacity(frames.len());
        let mut ok = Vec::with_capacity(frames.len());
        for f in frames {
            match self.tx_prepare(f) {
                Ok(p) => {
                    ok.push(p);
                    out.push(Ok(()));
                }
                Err(e) => out.push(Err(e)),
            }
        }
        if ok.is_empty() {
            return out;
        }
        let mut res = self.shared.tx_frames(ok).await.into_iter();
        for r in out.iter_mut().filter(|r| r.is_ok()) {
            *r = res.next().unwrap_or(Err(super::runtime::EIO));
            if r.is_err() {
                self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        out
    }

    /// One frame through [`Self::tx_batch`].
    pub async fn tx_one(&self, frame: &Frame) -> Result<(), i32> {
        self.tx_batch(core::slice::from_ref(frame))
            .await
            .pop()
            .unwrap_or(Err(super::runtime::EIO))
    }

    /// The TX pump task: wait for the stack's TX ring, take what is
    /// queued (up to [`TX_PUMP_BATCH`]) and hand it to the TXQs in one
    /// runtime step, so a backlog drains VO → BK ([`super::txq`]).
    pub async fn tx_pump(self: Arc<Self>, mut cons: Consumer<Frame, TX_RING_N>) {
        while let Ok(first) = cons.recv().await {
            let mut batch = alloc::vec![first];
            while batch.len() < TX_PUMP_BATCH {
                match cons.try_recv() {
                    Ok(Some(f)) => batch.push(f),
                    _ => break,
                }
            }
            let _ = self.tx_batch(&batch).await;
        }
    }

    fn deliver(&self, frames: Vec<(Vec<u8>, bool)>) -> usize {
        let n = frames.len();
        let preauth_up = self.ctrl_port.load(Ordering::Acquire) & (1 << 16) != 0;
        for (mut f, csum_ok) in frames {
            // ieee80211_deliver_skb_to_local_stack: ETH_P_PREAUTH over
            // nl80211 unless CONTROL_PORT_NO_PREAUTH.
            if preauth_up
                && f.len() >= 14
                && u16::from_be_bytes([f[12], f[13]]) == narf_wireless::ETH_P_PREAUTH
            {
                let src: [u8; 6] = f[6..12].try_into().unwrap();
                (self.sinks.control_port)(
                    self.name,
                    src,
                    narf_wireless::ETH_P_PREAUTH,
                    &f[14..],
                    false,
                );
                continue;
            }
            if let Some(p) = self.rx_prod.lock().as_mut() {
                if let Some(mut fr) = alloc_frame(&f) {
                    // ath11k_dp_rx_h_csum_offload → the ring's RxMeta.
                    fr.set_rx_meta(super::tx_offload::rx_meta(&f, csum_ok));
                    if p.try_send(fr).is_err() {
                        self.stats.rx_ring_full.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            self.stats.rx_delivered.fetch_add(1, Ordering::Relaxed);
            (self.sinks.rx)(self.name, &mut f);
        }
        n
    }

    /// One pass of the runtime loop: service + deliver RX (outside every
    /// lock: the stack may answer synchronously through `queue_tx`), then
    /// the mac layer's housekeeping if no control operation holds it.
    /// Returns the frames delivered.
    pub async fn service_once(&self) -> usize {
        let frames = self.shared.take_rx().await;
        let n = self.deliver(frames);
        if let Some(notice) = self.shared.take_fw_notice().await {
            self.recover(notice).await;
            return n;
        }
        if let Some(mut m) = self.mac.try_lock() {
            self.sync_admin(&mut m).await;
            self.run_ext_ops(&mut m).await;
            let loss = m.poll().await;
            let ctrl = m.take_control_port_rx();
            if !ctrl.is_empty() {
                self.deliver_control_port(ctrl);
            }
            if loss.is_some() {
                self.stats.link_losses.fetch_add(1, Ordering::Relaxed);
                // ieee80211_set_disassoc → ieee80211_flush_queues(drop).
                self.shared.lock().await.purge_txqs();
            }
            let linked = m.connected_bssid();
            let why = if linked.is_none() {
                m.take_disconnect()
            } else {
                None
            };
            drop(m);
            if linked.is_none() && self.link_up() {
                // ieee80211_set_disassoc → netif_carrier_off, then
                // cfg80211_disconnected.
                self.link_down(why);
            }
        }
        n
    }

    /// Apply the queued external-supplicant operations in order
    /// (key installs, port authorization, control-port frames, power
    /// save), each the way mac80211's synchronous call would.
    async fn run_ext_ops(&self, m: &mut RtMac<Io, Irq, Q>) {
        loop {
            let Some(op) = self.ext_ops.lock().pop_front() else {
                return;
            };
            match op {
                ExtOp::AddKey(k) => {
                    let _ = m.ext_add_key(&k).await;
                }
                ExtOp::DelKey { idx, pairwise } => {
                    let _ = m.ext_del_key(idx, pairwise).await;
                }
                ExtOp::Authorize(on) => {
                    let _ = m.ext_set_authorized(on).await;
                }
                ExtOp::Tx(eth) => {
                    // ieee80211_tx_control_port → the TXQs; built (and
                    // protected or not) by the PTK state at this point.
                    let _ = self.shared.tx_frames(alloc::vec![(eth, false)]).await;
                }
                ExtOp::PowerSave(on) => m.set_power_save(on).await,
            }
        }
    }

    /// Received control-port frames: to the owner over nl80211, or up the
    /// netdev (PF_PACKET sockets on ETH_P_PAE) as any received frame.
    fn deliver_control_port(&self, frames: Vec<super::mac::ext::ControlPortRx>) {
        let mut up = Vec::new();
        for f in frames {
            if f.over_nl80211 {
                let src: [u8; 6] = f.eth[6..12].try_into().unwrap();
                let proto = u16::from_be_bytes([f.eth[12], f.eth[13]]);
                (self.sinks.control_port)(self.name, src, proto, &f.eth[14..], !f.decrypted);
            } else {
                up.push((f.eth, false));
            }
        }
        if !up.is_empty() {
            self.deliver(up);
        }
    }

    fn queue_ext(&self, op: ExtOp) {
        // The runtime loop applies it at its next step (≤ one slice).
        self.ext_ops.lock().push_back(op);
    }

    /// `associate` for the in-kernel autoconnect: a recovery reconnects
    /// this one by itself.
    pub async fn associate_kernel(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        self.associate_from(req, ConnectOrigin::Kernel).await
    }

    async fn associate_from(
        &self,
        req: AssociateRequest,
        origin: ConnectOrigin,
    ) -> Result<(), WirelessError> {
        if self.shared.is_dead() {
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        if !self.sync_admin(&mut m).await {
            return Err(WirelessError::HardwareError);
        }
        m.associate(&req).await?;
        let b = m.connected_bssid();
        drop(m);
        if let SecurityConfig::External(e) = &req.security {
            self.set_control_port(e.control_port);
        }
        if b.is_some() {
            // An external supplicant's association is userspace's to
            // restore.
            let origin = if matches!(req.security, SecurityConfig::External(_)) {
                ConnectOrigin::Nl80211
            } else {
                origin
            };
            *self.last_assoc.lock() = Some((copy_request(&req), origin));
        }
        // ieee80211_set_associated → netif_carrier_on.
        self.set_link(b.is_some(), b, req.channel);
        Ok(())
    }

    /// `ieee80211_mgd_deauth` / `_disassoc` for the userspace SME.
    async fn sme_leave(
        &self,
        peer: [u8; 6],
        reason: u16,
        deauth: bool,
    ) -> Result<Vec<u8>, WirelessError> {
        *self.last_assoc.lock() = None;
        let mut m = self.mac.lock().await;
        if m.link().is_some_and(|l| l.assoc) {
            self.shared.flush_queues(true).await;
        }
        let r = m.sme_deauthenticate(peer, reason, deauth).await;
        let why = m.take_disconnect();
        drop(m);
        let frame = r.map_err(|e| e.wireless())?;
        if why.is_some() && self.link_up() {
            // DEAUTHENTICATE / DISASSOCIATE + DISCONNECT.
            self.link_down(why);
        } else {
            (self.sinks.mlme_tx)(self.name, &frame);
        }
        Ok(frame)
    }

    fn set_control_port(&self, port: narf_wireless::ControlPort) {
        let preauth = port.over_nl80211 && !port.no_preauth;
        self.ctrl_port.store(
            port.ethertype as u32 | if preauth { 1 << 16 } else { 0 },
            Ordering::Release,
        );
    }

    /// The runtime loop task (ends when a recovery failed: the device is
    /// gone).
    pub async fn run(self: Arc<Self>) {
        loop {
            self.service_once().await;
            if self.shared.is_dead() {
                return;
            }
            self.shared.irq.wait(self.shared.slice_ms).await;
        }
    }

    /// Firmware crash recovery for the station (Linux `ath11k_core_reset`
    /// / `ath11k_core_restart`, then `ath11k_core_post_reconfigure_recovery`
    /// → `ath11k_core_halt` + `ieee80211_restart_hw`): the link goes down,
    /// the mac layer is locked (operations in flight end: CRASH_FLUSH
    /// fails their waits), the device is recovered, and the mac layer is
    /// rebuilt from the new capabilities and started with its station
    /// vif. mac80211 then restores the association; NARF associates again
    /// with the last network's parameters (and the command-line
    /// autoconnect keeps retrying if that fails). `true` when the device
    /// came back.
    pub async fn recover(&self, notice: FwNotice) -> bool {
        use core::fmt::Write as _;
        self.stats.recoveries.fetch_add(1, Ordering::Relaxed);
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: {}: firmware crashed ({:?}), recovering",
            self.name,
            notice
        );
        // The association does not survive here (it is made again
        // below): cfg80211 hears the loss as mac80211's
        // `ieee80211_sta_connection_lost(sdata, WLAN_REASON_UNSPECIFIED,
        // false)` would report it.
        self.link_down(Some(Disconnect {
            reason: frame::WLAN_REASON_UNSPECIFIED,
            from_ap: false,
            deauth: true,
            bssid: [0; 6],
        }));
        let mut m = self.mac.lock().await;
        let dev = match self.shared.recover_device(notice).await {
            Ok(d) => d,
            Err(_) => return false,
        };
        // ath11k_core_halt + ieee80211_restart_hw → drv_start +
        // drv_add_interface on the rebuilt mac layer.
        // The interface was open: mac80211's reconfig brings the hardware
        // and the station vif back the way `ieee80211_do_open` did.
        let was_open = m.vif().is_some();
        let mut mac = Mac::new(
            Port(self.shared.clone()),
            Port(self.shared.clone()),
            dev.caps,
            m.config(),
            dev.reg_info.as_deref(),
        );
        let opened = if was_open {
            self.do_open(&mut mac).await
        } else {
            Ok(())
        };
        *m = mac;
        drop(m);
        if opened.is_err() {
            super::hal::TransportError::new(super::runtime::step::RECOVERY_MAC, 1, 5)
                .report("ath11k recovery: mac");
            self.shared.park(alloc::boxed::Box::new(()));
            return false;
        }
        // ath11k_mac_op_reconfig_complete.
        self.shared.reconfig_complete().await;
        narf_memory::diag::note_wifi_recovered();
        self.stats.recovered.fetch_add(1, Ordering::Relaxed);
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: {}: firmware recovered",
            self.name
        );
        // Only an in-kernel connection is restored here; userspace heard
        // the loss above and reconnects itself.
        let last = self.last_assoc.lock().take();
        if let Some((req, ConnectOrigin::Kernel)) = last {
            *self.last_assoc.lock() = Some((copy_request(&req), ConnectOrigin::Kernel));
            self.reconnect(req).await;
        }
        true
    }

    /// Associate again after a recovery: a scan directed at the network
    /// on its channel (the new mac layer has no BSS table), then the
    /// association.
    async fn reconnect(&self, req: AssociateRequest) {
        use core::fmt::Write as _;
        let scan = ScanRequest {
            ssids: alloc::vec![req.ssid.clone()],
            channels: alloc::vec![req.channel],
            active: true,
        };
        let r = match self.scan(scan).await {
            Ok(_) => self.associate_kernel(req).await,
            Err(e) => Err(e),
        };
        match r {
            Ok(()) => {
                self.stats.reconnects.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  ath11k: {}: reconnect after recovery failed: {:?}",
                    self.name,
                    e
                );
            }
        }
    }

    /// Synchronous drain for the stack's busy-wait paths
    /// (`narf_net::iface::install_rx_drain`): service + deliver if the
    /// runtime is free. `true` when frames were delivered.
    pub fn drain_sync(&self) -> bool {
        let frames: Vec<(Vec<u8>, bool)> = {
            let Some(mut g) = self.shared.try_lock() else {
                return false;
            };
            g.service();
            g.link.data_rx.drain(..).collect()
        };
        self.deliver(frames) > 0
    }
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Interface for Ath11kNetdev<Io, Irq, Q> {
    fn name(&self) -> &str {
        self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac_addr
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ring
    }
    fn offloads(&self) -> narf_net::OffloadCapabilities {
        super::tx_offload::OFFLOADS
    }
}

#[async_trait]
impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> WirelessNetIface for Ath11kNetdev<Io, Irq, Q> {
    fn supports_handshake_offload(&self) -> bool {
        // Like ath11k on Linux (mac80211 with its SME in userspace), no
        // offload is advertised: wpa_supplicant runs SME and supplicant.
        // The mac layer's own 4-way handshake serves the in-kernel
        // autoconnect (`associate_kernel`).
        false
    }

    fn supports_userspace_mlme(&self) -> bool {
        true
    }

    fn supports_external_supplicant(&self) -> bool {
        true
    }

    fn reports_disconnect_events(&self) -> bool {
        true
    }

    async fn mlme_authenticate(&self, req: MlmeAuthRequest) -> Result<Vec<u8>, WirelessError> {
        if self.shared.is_dead() {
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        if !self.sync_admin(&mut m).await {
            return Err(WirelessError::HardwareError);
        }
        let r = m.sme_authenticate(&req).await;
        let why = m.take_disconnect();
        drop(m);
        if why.is_some() {
            // A new authentication left the old association.
            self.link_down(why);
        }
        r.map_err(|e| e.wireless())
    }

    async fn mlme_associate(&self, req: MlmeAssocRequest) -> Result<Vec<u8>, WirelessError> {
        if self.shared.is_dead() {
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        let r = m.sme_associate(&req).await;
        let b = m.connected_bssid();
        drop(m);
        let frame = r.map_err(|e| e.wireless())?;
        if b.is_some() {
            self.set_control_port(req.control_port);
            *self.last_assoc.lock() = None;
            // ieee80211_set_associated → netif_carrier_on.
            self.set_link(true, b, req.channel);
        }
        Ok(frame)
    }

    async fn mlme_deauthenticate(
        &self,
        peer: [u8; 6],
        reason: u16,
    ) -> Result<Vec<u8>, WirelessError> {
        self.sme_leave(peer, reason, true).await
    }

    async fn mlme_disassociate(
        &self,
        peer: [u8; 6],
        reason: u16,
    ) -> Result<Vec<u8>, WirelessError> {
        self.sme_leave(peer, reason, false).await
    }

    fn add_key(&self, key: KeyParams) -> Result<(), i32> {
        let ap = self.connected_bssid();
        if key.pairwise && (ap.is_none() || key.peer != ap) {
            return Err(super::mac::errno::ENOENT);
        }
        if ap.is_none() {
            return Err(super::mac::errno::ENOENT);
        }
        match key.cipher {
            narf_wireless::CIPHER_SUITE_CCMP | narf_wireless::CIPHER_SUITE_AES_CMAC => {}
            _ => return Err(super::mac::errno::EOPNOTSUPP),
        }
        {
            let mut book = self.keys.lock();
            if key.pairwise {
                book.ptk = true;
            } else if let Some(s) = book.group.get_mut(key.idx as usize) {
                *s = true;
            }
        }
        self.queue_ext(ExtOp::AddKey(key));
        Ok(())
    }

    fn del_key(&self, idx: u8, pairwise: bool, peer: Option<[u8; 6]>) -> Result<(), i32> {
        let ap = self.connected_bssid();
        if pairwise && (ap.is_none() || peer != ap) {
            return Err(super::mac::errno::ENOENT);
        }
        {
            let mut book = self.keys.lock();
            let slot = if pairwise {
                Some(&mut book.ptk)
            } else {
                book.group.get_mut(idx as usize)
            };
            match slot {
                Some(s) if *s => *s = false,
                _ => return Err(super::mac::errno::ENOENT),
            }
        }
        self.queue_ext(ExtOp::DelKey { idx, pairwise });
        Ok(())
    }

    fn set_port_authorized(&self, peer: [u8; 6], authorized: bool) -> Result<(), i32> {
        if self.connected_bssid() != Some(peer) {
            return Err(super::mac::errno::ENOENT);
        }
        self.queue_ext(ExtOp::Authorize(authorized));
        Ok(())
    }

    fn tx_control_port(
        &self,
        dest: [u8; 6],
        proto: u16,
        frame: Vec<u8>,
        _no_encrypt: bool,
    ) -> Result<(), i32> {
        let ctrl = self.ctrl_port.load(Ordering::Acquire);
        // "Only accept CONTROL_PORT_PROTOCOL configured in
        // CONNECT/ASSOCIATE or Pre-Authentication".
        let configured = (ctrl & 0xffff) as u16;
        if proto != configured && proto != narf_wireless::ETH_P_PREAUTH || ctrl == 0 {
            return Err(super::mac::errno::EINVAL);
        }
        let mut eth = Vec::with_capacity(14 + frame.len());
        eth.extend_from_slice(&dest);
        eth.extend_from_slice(&self.mac_addr);
        eth.extend_from_slice(&proto.to_be_bytes());
        eth.extend_from_slice(&frame);
        self.queue_ext(ExtOp::Tx(eth));
        Ok(())
    }

    fn power_save_default(&self) -> Option<bool> {
        // mac80211's set_power_mgmt; SUPPORTS_PS on WCN6855.
        Some(true)
    }

    fn set_power_save(&self, enabled: bool) -> Result<(), i32> {
        self.ps.store(enabled, Ordering::Release);
        self.queue_ext(ExtOp::PowerSave(enabled));
        Ok(())
    }

    fn regulatory_domain(&self) -> Option<narf_wireless::RegDomainInfo> {
        let r = self.mac.try_lock()?.regd();
        Some(narf_wireless::RegDomainInfo {
            alpha2: r.alpha2,
            dfs_region: r.dfs_region as u8,
            // ath11k_mac_register: REGULATORY_WIPHY_SELF_MANAGED.
            self_managed: true,
            rules: r
                .rules
                .iter()
                .map(|x| narf_wireless::RegRuleInfo {
                    flags: x.flags,
                    start_khz: x.start * 1000,
                    end_khz: x.end * 1000,
                    max_bw_khz: x.max_bw * 1000,
                    max_antenna_gain_mbi: x.max_antenna_gain * 100,
                    max_eirp_mbm: x.max_eirp * 100,
                    dfs_cac_ms: x.dfs_cac_ms,
                })
                .collect(),
        })
    }

    fn station_info(&self) -> Option<narf_wireless::StationInfo> {
        let m = self.mac.try_lock()?;
        let l = m.link()?;
        Some(narf_wireless::StationInfo {
            signal_dbm: l.last_signal.map(|s| s.clamp(-128, 127) as i8),
            ..Default::default()
        })
    }

    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.mac
            .try_lock()?
            .bss_table()
            .iter()
            .find(|b| b.bssid == bssid)
            .map(|b| b.ies.clone())
    }

    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        WirelessIfaceInfo {
            base_name: self.name.into(),
            base_mac: self.mac_addr,
            bands: self
                .radio
                .bands
                .iter()
                .map(|(f, ch)| WirelessBand {
                    freq_mhz: *f,
                    channels: ch.clone(),
                })
                .collect(),
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: self.radio.ht,
                vht_supported: self.radio.vht,
                // HE association on 2.4 / 5 GHz (ath11k.md §3.9).
                he_supported: self.radio.he,
                eht_supported: false,
            },
        }
    }

    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if self.shared.is_dead() {
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        // nl80211 refuses a scan on a down interface (-ENETDOWN).
        if !self.sync_admin(&mut m).await {
            return Err(WirelessError::HardwareError);
        }
        m.scan(&req).await
    }

    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        // nl80211 CONNECT: userspace's connection.
        self.associate_from(req, ConnectOrigin::Nl80211).await
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        *self.last_assoc.lock() = None;
        if self.shared.is_dead() {
            self.set_link(false, None, 0);
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        // ieee80211_set_disassoc: "drop any frame before deauth/disassoc".
        if m.link().is_some() {
            self.shared.flush_queues(true).await;
        }
        let r = m.disassociate().await;
        let why = m.take_disconnect();
        drop(m);
        self.link_down(why);
        r
    }

    fn connected_bssid(&self) -> Option<[u8; 6]> {
        let packed = self.bssid.load(Ordering::Acquire);
        (packed & (1 << 63) != 0).then(|| core::array::from_fn(|i| (packed >> (8 * i)) as u8))
    }

    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError> {
        // A station follows its AP's channel; transmit power is the
        // regulatory / firmware limit (no `iw set txpower`).
        if cfg.tx_power_dbm.is_some() {
            return Err(WirelessError::NotSupported);
        }
        if channel_number_freq(cfg.channel).is_none() {
            return Err(WirelessError::InvalidArgs);
        }
        if self.channel.load(Ordering::Acquire) == cfg.channel && self.link_up() {
            Ok(())
        } else {
            Err(WirelessError::InvalidArgs)
        }
    }
}

// ── registration (PCI) ────────────────────────────────────────────

/// The hardware netdev.
pub type PciNetdev = Ath11kNetdev<super::core::Bar0, super::ce::MsiCeIrq, super::pci::Wlfw>;

/// The function-pointer stack hooks need the live device.
static ACTIVE: IrqSafeSpinLock<Option<Arc<PciNetdev>>> = IrqSafeSpinLock::new(None);

fn pci_send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let dev = ACTIVE.lock().clone().ok_or(())?;
    dev.queue_tx(bytes, meta)
}

fn pci_drain() -> bool {
    let Some(dev) = ACTIVE.lock().clone() else {
        return false;
    };
    dev.drain_sync()
}

fn pci_link(name: &str, up: bool) {
    // netif_carrier_on / netif_carrier_off (IFF_UP is the stack's).
    narf_net::iface::set_link_metadata(name, up, None, None);
}

fn pci_disconnected(name: &str, d: Disconnect, own: &[u8; 6]) {
    narf_wireless::nl80211::notify_mlme_disconnect(name, &d.frame(own), *own);
}

fn pci_mlme_tx(name: &str, frame: &[u8]) {
    narf_wireless::nl80211::notify_mlme_frame(name, frame);
}

fn pci_control_port(name: &str, src: [u8; 6], proto: u16, pdu: &[u8], unencrypted: bool) -> bool {
    narf_wireless::nl80211::rx_control_port(name, src, proto, pdu, unencrypted)
}

fn pci_admin(name: &str, up: bool) {
    narf_net::iface::set_link_state(name, up);
}

fn pci_open_stop(_name: &str, up: bool) {
    if let Some(dev) = ACTIVE.lock().clone() {
        dev.request_admin(up);
    }
}

/// Netdevs the capability registry holds (`Box<dyn Interface>`): a view
/// on the shared device.
struct Registered(Arc<PciNetdev>);

impl Interface for Registered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        self.0.mtu()
    }
    fn link_up(&self) -> bool {
        self.0.link_up()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
    fn offloads(&self) -> narf_net::OffloadCapabilities {
        self.0.offloads()
    }
}

/// `ieee80211_register_hw` + `ieee80211_if_add("wlan%d")`: name the
/// netdev, register it with the stack (send hook, RX drain, carrier off),
/// the capability registry and the wireless registry, and spawn the
/// runtime loop + TX pump. Returns the name.
pub fn register_pci(
    shared: Arc<Shared<super::core::Bar0, super::ce::MsiCeIrq, super::pci::Wlfw>>,
    mac: RtMac<super::core::Bar0, super::ce::MsiCeIrq, super::pci::Wlfw>,
    mac_addr: [u8; 6],
) -> &'static str {
    use core::fmt::Write as _;
    let name = narf_net::iface::reserve_name("wlan%d");
    let (dev, tx_cons) = Ath11kNetdev::new(
        name,
        shared,
        mac,
        mac_addr,
        Sinks {
            rx: narf_net::iface::on_rx_frame_from,
            link: pci_link,
            admin: pci_admin,
            disconnected: pci_disconnected,
            mlme_tx: pci_mlme_tx,
            control_port: pci_control_port,
        },
    );
    let dev = Arc::new(dev);
    *ACTIVE.lock() = Some(dev.clone());
    narf_net::iface::register(name, mac_addr, pci_send);
    narf_net::iface::set_driver_info(name, "ath11k_pci", None, alloc::string::String::new());
    // ath11k_mac_register: hw->netdev_features = NETIF_F_HW_CSUM.
    narf_net::iface::set_offloads(name, super::tx_offload::OFFLOADS);
    // register_netdevice: down, no carrier; IFF_UP opens the hardware.
    narf_net::iface::set_link_metadata(name, false, None, None);
    narf_net::iface::set_open_stop(name, pci_open_stop);
    narf_net::iface::install_rx_drain(pci_drain);
    match narf_net::trusted_net_authority().and_then(|a| a.derive().ok()) {
        Some(authority) => {
            if let Err(e) = narf_net::registry().register(&authority, Registered(dev.clone())) {
                let d = match e {
                    narf_net::RegisterError::AuthorityRevoked => 2,
                    narf_net::RegisterError::DuplicateName => 3,
                };
                let _ = writeln!(
                    narf_console::Writer,
                    "  ath11k: {}: capability registry: {:?} (step {} detail {})",
                    name,
                    e,
                    super::runtime::step::NET_REGISTER,
                    d
                );
            }
        }
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {}: no net authority for the capability registry (step {} detail 1)",
                name,
                super::runtime::step::NET_REGISTER
            );
        }
    }
    narf_wireless::registry::register(dev.clone());
    let d = dev.clone();
    narf_scheduler::spawn(async move { d.run().await });
    let d = dev.clone();
    narf_scheduler::spawn(async move { d.tx_pump(tx_cons).await });
    // Bring-up aid: `ath11k.scan=1` / `ath11k.ssid=…` (autoconnect.rs).
    match super::autoconnect::parse(narf_boot::cmdline()) {
        Ok(Some(cfg)) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {}: autoconnect {:?}",
                name,
                cfg
            );
            // Like `ip link set wlan0 up` before wpa_supplicant connects.
            narf_net::iface::set_link_state(name, true);
            narf_scheduler::spawn(super::autoconnect::run(dev, cfg));
        }
        Ok(None) => {}
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {}: ignoring ath11k.* cmdline: {:?}",
                name,
                e
            );
        }
    }
    name
}
