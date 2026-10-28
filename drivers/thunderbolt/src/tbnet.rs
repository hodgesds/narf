//! ThunderboltIP netdev: an Ethernet-class [`narf_net::Interface`]
//! whose frames cross a host-to-host XDomain link as ThunderboltIP
//! data frames.
//!
//! The fragmentation and reassembly rules are the reference
//! driver's (`drivers/net/thunderbolt.c`): 4 KiB frames carrying a
//! 12-byte little-endian header (`frame_size`, `frame_index`,
//! `frame_id`, `frame_count`), at most 4084 payload bytes per
//! frame, every frame sent with both the frame-start and frame-end
//! PDF bits set, packets reassembled strictly in index order with
//! the count/id of the first fragment, and any validation failure
//! dropping the packet being assembled. The local MAC follows
//! `tbnet_generate_mac`: jhash2 of the local XDomain UUID with the
//! link number in the first octet; the peer's MAC is learned from
//! its LOGIN_RESPONSE (the protocol never depends on the
//! derivation, only on uniqueness).
//!
//! Data transport seam: frames move through a [`DataLink`]. The
//! in-kernel binding is the NHI high-speed DMA ring pair
//! (TX `RING_FLAG_FRAME`, RX `RING_FLAG_FRAME | RING_FLAG_E2E`
//! with the frame-start/end PDF masks, HopID `TBNET_LOCAL_PATH`);
//! `drivers/thunderbolt/src/ring.rs` today implements only ring 0,
//! so no production binding exists yet (specification §8 records
//! the remaining work with these exact parameters). Until one is
//! bound, a peer session still completes its ThunderboltIP login,
//! but the netdev reports link down and no frames flow; the
//! fixtures bind an in-memory pair and drive the whole data plane
//! end-to-end.

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_capabilities::{Cap, Write};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, NetIface, RX_RING_N, TX_RING_N};

use super::xdomain::Uuid;

/// ThunderboltIP frame size (`TBNET_FRAME_SIZE`).
pub(crate) const FRAME_SIZE: usize = 4096;
/// Data-frame header size (`struct thunderbolt_ip_frame_header`).
pub(crate) const FRAME_HEADER_SIZE: usize = 12;
/// Payload bytes per frame (`TBNET_MAX_PAYLOAD_SIZE`).
pub(crate) const MAX_PAYLOAD: usize = FRAME_SIZE - FRAME_HEADER_SIZE;
/// Largest packet the reassembler accepts (`TBNET_MAX_MTU`).
pub(crate) const MAX_PACKET: usize = 65536;
/// Largest fragment count of one packet (`TBNET_RING_SIZE / 4`).
pub(crate) const MAX_FRAGMENTS: u32 = 64;
/// Interface MTU: the Ethernet default. The pump fragments and
/// reassembles up to [`MAX_PACKET`] regardless of the MTU the stack
/// configures; packets beyond it are dropped with an error count,
/// never truncated.
pub(crate) const MTU: u32 = 1500;

/// PDF bits (`thunderbolt_ip_frame_pdf`); both are set on every
/// data frame, as the reference TX ring setup programs them.
pub(crate) const PDF_FRAME_START: u8 = 1;
pub(crate) const PDF_FRAME_END: u8 = 2;

/// One direction of the high-speed data path. Implementations move
/// whole ThunderboltIP data frames (12-byte header + payload) with
/// their PDF bits.
pub(crate) trait DataLink: Send {
    fn send_frame(&mut self, pdf: u8, frame: &[u8]);
    fn poll_frames(&mut self) -> Vec<(u8, Vec<u8>)>;
}

/// The stack-facing interface. Owns the caller ends of the frame
/// rings; the CM-side ends live in [`NetLink`].
pub(crate) struct TbNetInterface {
    name: String,
    mac: [u8; 6],
    link: Arc<AtomicBool>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
}

impl fmt::Debug for TbNetInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TbNetInterface")
            .field("name", &self.name)
            .field("mac", &self.mac)
            .field("link_up", &self.link.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Interface for TbNetInterface {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        MTU
    }
    fn link_up(&self) -> bool {
        self.link.load(Ordering::SeqCst)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}

/// The registry holds one handle and the CM side keeps another, so
/// the pump and the fixtures can reach the rings after
/// registration. A newtype because the orphan rule forbids
/// implementing the foreign `Interface` for `Arc<_>` directly.
struct SharedTbNet(Arc<TbNetInterface>);

impl Interface for SharedTbNet {
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
}

/// Fragment one Ethernet packet into ThunderboltIP data frames.
/// The frame id is the caller's current value for the whole
/// packet (it advances once per packet, and only when the peer
/// announced `MATCH_FRAGS_ID`).
pub(crate) fn fragment(packet: &[u8], frame_id: u16) -> Vec<(u8, Vec<u8>)> {
    let count = packet.len().div_ceil(MAX_PAYLOAD) as u32;
    let mut out = Vec::with_capacity(count as usize);
    for (index, chunk) in packet.chunks(MAX_PAYLOAD).enumerate() {
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + chunk.len());
        frame.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        frame.extend_from_slice(&(index as u16).to_le_bytes());
        frame.extend_from_slice(&frame_id.to_le_bytes());
        frame.extend_from_slice(&count.to_le_bytes());
        frame.extend_from_slice(chunk);
        out.push((PDF_FRAME_START | PDF_FRAME_END, frame));
    }
    out
}

/// Packet reassembler with the reference driver's validation
/// (`tbnet_check_frame` + the `tbnet_poll` accumulation rule): a
/// frame is accepted only as the exact next fragment of the packet
/// in progress (or as a well-formed first fragment), and any
/// failure discards the packet in progress.
#[derive(Debug, Default)]
pub(crate) struct Reassembler {
    buf: Vec<u8>,
    frame_id: u16,
    frame_count: u32,
    next_index: u16,
    active: bool,
    pub errors: u64,
}

impl Reassembler {
    fn reset(&mut self) {
        self.buf.clear();
        self.active = false;
        self.frame_count = 0;
        self.next_index = 0;
    }

    /// Push one data frame; returns the completed packet, if any.
    pub(crate) fn push(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() <= FRAME_HEADER_SIZE {
            self.errors += 1;
            self.reset();
            return None;
        }
        let frame_size = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        let frame_index = u16::from_le_bytes(frame[4..6].try_into().unwrap());
        let frame_id = u16::from_le_bytes(frame[6..8].try_into().unwrap());
        let frame_count = u32::from_le_bytes(frame[8..12].try_into().unwrap());
        if frame_size == 0 || frame_size > frame.len() - FRAME_HEADER_SIZE {
            self.errors += 1;
            self.reset();
            return None;
        }
        if self.active {
            if frame_count != self.frame_count
                || frame_index != self.next_index
                || frame_id != self.frame_id
                || self.buf.len() + frame_size > MAX_PACKET
            {
                self.errors += 1;
                self.reset();
                return None;
            }
        } else {
            if frame_count == 0 || frame_count > MAX_FRAGMENTS || frame_index != 0 {
                self.errors += 1;
                return None;
            }
            self.frame_count = frame_count;
            self.frame_id = frame_id;
            self.buf.clear();
            self.active = true;
        }
        self.buf
            .extend_from_slice(&frame[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + frame_size]);
        self.next_index = frame_index + 1;
        if frame_index as u32 == frame_count - 1 {
            self.active = false;
            return Some(core::mem::take(&mut self.buf));
        }
        None
    }
}

/// The CM-side half of one peer's netdev: rings, registration,
/// data transport, and pump. Created when a peer's properties
/// advertise the networking service; dropped (unregistering the
/// interface) when the peer goes away.
pub(crate) struct NetLink {
    name: String,
    mac: [u8; 6],
    match_frags: bool,
    link_flag: Arc<AtomicBool>,
    iface: Arc<TbNetInterface>,
    registered: bool,
    handle: Option<Cap<NetIface, Write>>,
    tx_cons: Consumer<Frame, TX_RING_N>,
    rx_prod: Producer<Frame, RX_RING_N>,
    data: Option<Box<dyn DataLink>>,
    session_up: bool,
    frame_id: u16,
    reasm: Reassembler,
    pub tx_errors: u64,
    pub rx_errors: u64,
}

impl fmt::Debug for NetLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetLink")
            .field("name", &self.name)
            .field("mac", &self.mac)
            .field("link_up", &self.link_up())
            .field("registered", &self.handle.is_some())
            .finish_non_exhaustive()
    }
}

impl NetLink {
    pub(crate) fn new(name: String, mac: [u8; 6], match_frags: bool) -> Self {
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();
        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let link_flag = Arc::new(AtomicBool::new(false));
        let iface = Arc::new(TbNetInterface {
            name: name.clone(),
            mac,
            link: link_flag.clone(),
            tx: IrqSafeSpinLock::new(Some(tx_prod)),
            rx: IrqSafeSpinLock::new(Some(rx_cons)),
        });
        Self {
            name,
            mac,
            match_frags,
            link_flag,
            iface,
            registered: false,
            handle: None,
            tx_cons,
            rx_prod,
            data: None,
            session_up: false,
            frame_id: 0,
            reasm: Reassembler::default(),
            tx_errors: 0,
            rx_errors: 0,
        }
    }

    pub(crate) fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Bind the data transport (see the module documentation for
    /// the production binding's status).
    // Used by the fixtures; production binding lands with the data transport.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn bind(&mut self, link: Box<dyn DataLink>) {
        self.data = Some(link);
        self.refresh_link();
    }

    /// Record the ThunderboltIP session state (mutual login).
    pub(crate) fn set_link(&mut self, session_up: bool) {
        self.session_up = session_up;
        self.refresh_link();
    }

    pub(crate) fn link_up(&self) -> bool {
        self.link_flag.load(Ordering::SeqCst)
    }

    fn refresh_link(&mut self) {
        let up = self.session_up && self.data.is_some();
        self.link_flag.store(up, Ordering::SeqCst);
        if !up {
            self.reasm.reset();
        }
    }

    /// The published interface (the registry holds a second
    /// handle to the same object).
    // Used by the fixtures; production binding lands with the data transport.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn interface(&self) -> &Arc<TbNetInterface> {
        &self.iface
    }

    /// Register with the netdev registry once a trusted authority
    /// exists; retried on each pump until it sticks (the e1000
    /// registration pattern, deferred to CM-pass time).
    fn ensure_registered(&mut self) {
        if self.registered {
            return;
        }
        let Some(authority) = narf_net::trusted_net_authority() else {
            return;
        };
        match narf_net::registry().register(&authority, SharedTbNet(self.iface.clone())) {
            Ok(handle) => {
                self.handle = Some(handle);
                self.registered = true;
            }
            Err(_) => {
                // Duplicate name or revoked authority: retried on
                // the next pump; the rings stay usable either way.
            }
        }
    }

    /// One data-plane pass: register if needed, drain the TX ring
    /// into the data transport, and deliver reassembled RX packets
    /// into the RX ring.
    pub(crate) fn pump(&mut self) {
        self.ensure_registered();
        // Taken out for the pass so the counters and `deliver` can
        // borrow `self`; put back before returning.
        let Some(mut data) = self.data.take() else {
            return;
        };
        if self.link_up() {
            while let Ok(Some(frame)) = self.tx_cons.try_recv() {
                let packet = frame.payload().to_vec();
                if packet.is_empty() || packet.len() > MAX_PACKET {
                    self.tx_errors += 1;
                    continue;
                }
                let frame_id = if self.match_frags {
                    let id = self.frame_id;
                    self.frame_id = self.frame_id.wrapping_add(1);
                    id
                } else {
                    0
                };
                for (pdf, bytes) in fragment(&packet, frame_id) {
                    data.send_frame(pdf, &bytes);
                }
            }
        }
        for (_pdf, bytes) in data.poll_frames() {
            // Frames arriving while the session is down are
            // drained and dropped: the peer must not send before
            // mutual login, and a half-open link must not deliver.
            if !self.link_up() {
                continue;
            }
            if let Some(packet) = self.reasm.push(&bytes) {
                if !self.deliver(packet) {
                    self.rx_errors += 1;
                }
            }
        }
        self.data = Some(data);
    }

    fn deliver(&mut self, packet: Vec<u8>) -> bool {
        let len = packet.len();
        let Ok(buf) = narf_io::alloc_coherent(len.max(1), DomainId::DRIVER_0) else {
            return false;
        };
        // SAFETY: the buffer was just allocated for at least `len`
        // bytes and is exclusively owned here; the packet is
        // exactly `len` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(packet.as_ptr(), buf.cpu_mut_ptr::<u8>(), len);
        }
        let frame = Frame::new(buf, len as u32);
        self.rx_prod.try_send(frame).is_ok()
    }

    /// Unregister the interface (peer gone). Idempotent.
    pub(crate) fn teardown(&mut self) {
        if self.handle.take().is_some() {
            narf_net::registry().unregister(&self.name);
        }
        self.link_flag.store(false, Ordering::SeqCst);
    }
}

impl Drop for NetLink {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// `tbnet_generate_mac`: first octet is the link (the peer's
/// downstream port number on our host router) shifted up with the
/// locally-administered bit; the rest is jhash2 of the local UUID,
/// chained. Linux additionally maps the link to a physical port
/// number; the address only needs local uniqueness — the peer
/// learns it from our LOGIN_RESPONSE — so the link number is used
/// directly.
pub(crate) fn generate_mac(local_uuid: Uuid, route: u64) -> [u8; 6] {
    let dwords = local_uuid.dwords();
    let link = (route & 0x3f) as u8;
    let mut mac = [0u8; 6];
    mac[0] = (link << 4) | 0x02;
    let hash = jhash2(&dwords, 0);
    mac[1..5].copy_from_slice(&hash.to_le_bytes());
    mac[5] = (jhash2(&dwords, hash) & 0xff) as u8;
    mac
}

/// Jenkins jhash2 over whole dwords, as used by the reference MAC
/// derivation (`lib/jhash.c`).
fn jhash2(k: &[u32], initval: u32) -> u32 {
    fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
        *a = a.wrapping_sub(*c);
        *a ^= c.rotate_left(4);
        *c = c.wrapping_add(*b);
        *b = b.wrapping_sub(*a);
        *b ^= a.rotate_left(6);
        *a = a.wrapping_add(*c);
        *c = c.wrapping_sub(*b);
        *c ^= b.rotate_left(8);
        *b = b.wrapping_add(*a);
        *a = a.wrapping_sub(*c);
        *a ^= c.rotate_left(16);
        *c = c.wrapping_add(*b);
        *b = b.wrapping_sub(*a);
        *b ^= a.rotate_left(19);
        *a = a.wrapping_add(*c);
        *c = c.wrapping_sub(*b);
        *c ^= b.rotate_left(4);
        *b = b.wrapping_add(*a);
    }
    fn final_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
        *c ^= *b;
        *c = c.wrapping_sub(b.rotate_left(14));
        *a ^= *c;
        *a = a.wrapping_sub(c.rotate_left(11));
        *b ^= *a;
        *b = b.wrapping_sub(a.rotate_left(25));
        *c ^= *b;
        *c = c.wrapping_sub(b.rotate_left(16));
        *a ^= *c;
        *a = a.wrapping_sub(c.rotate_left(4));
        *b ^= *a;
        *b = b.wrapping_sub(a.rotate_left(14));
        *c ^= *b;
        *c = c.wrapping_sub(b.rotate_left(24));
    }
    let length = k.len();
    let mut a = 0x9e37_79b9_u32;
    let mut b = 0x9e37_79b9_u32;
    let mut c = initval;
    let mut i = 0;
    while length - i > 3 {
        a = a.wrapping_add(k[i]);
        b = b.wrapping_add(k[i + 1]);
        c = c.wrapping_add(k[i + 2]);
        mix(&mut a, &mut b, &mut c);
        i += 3;
    }
    match length - i {
        3 => {
            c = c.wrapping_add(k[i + 2]);
            b = b.wrapping_add(k[i + 1]);
            a = a.wrapping_add(k[i]);
        }
        2 => {
            b = b.wrapping_add(k[i + 1]);
            a = a.wrapping_add(k[i]);
        }
        1 => {
            a = a.wrapping_add(k[i]);
        }
        _ => {}
    }
    if length - i > 0 {
        final_mix(&mut a, &mut b, &mut c);
    }
    c
}
