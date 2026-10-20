//! IPv4 output: per-datagram header policy (Don't-Fragment, IP ID), the
//! datagram size limit, and fragmentation of datagrams larger than the MTU.
//!
//! Linux ref: `net/ipv4/ip_output.c` (`ip_setup_cork`, `__ip_append_data`,
//! `__ip_make_skb`, `__ip_finish_output`, `ip_fragment`, `ip_do_fragment`,
//! `ip_frag_init`, `ip_frag_next`), `include/net/ip.h` (`ip_dont_fragment`,
//! `ip_sk_use_pmtu`, `ip_sk_ignore_df`, `ip_select_ident_segs`),
//! `net/ipv4/route.c` (`__ip_select_ident`, `ip_idents_reserve`) and
//! `net/ipv4/ip_options.c` (`ip_options_fragment`).
//!
//! Every IPv4 sender that can produce a datagram larger than the egress MTU
//! (UDP, ping sockets, ICMP echo replies, forwarding) goes through
//! [`ip_finish_output`]. The order matches Linux:
//!
//! 1. [`append_check`] at send time (`ip_setup_cork` + `__ip_append_data`):
//!    an MTU below 68 is ENETUNREACH; a datagram over the non-fragmentable
//!    limit is EMSGSIZE, reported with the MTU so the socket layer can queue
//!    the `ip_local_error` record.
//! 2. [`make_header`] (`__ip_make_skb`): the DF bit and the IP ID.
//! 3. Netfilter LOCAL_OUT / POST_ROUTING run on the whole datagram (callers).
//! 4. [`ip_finish_output`]: a datagram that fits goes out as is — no copy, no
//!    allocation; a larger one is split by `ip_do_fragment`'s slow path.
//!
//! NARF has no route MTU metrics and no PMTU exception cache, so
//! `dst4_mtu()` (what `ip_sk_use_pmtu` sockets use) and the device MTU (what
//! PROBE / INTERFACE / OMIT sockets use) are the same number here: the egress
//! interface's MTU clamped to `IP_MAX_MTU`. For the same reason no route
//! has a locked MTU, so `ip_dont_fragment` is true for every WANT socket.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicUsize, Ordering};

use narf_lib::sync::{IrqSafeSpinLock, Once, OnceLock};

use crate::pkt::ip_checksum;

// ── IP_MTU_DISCOVER values (`include/uapi/linux/in.h`) ──────────────────────

pub const IP_PMTUDISC_DONT: i32 = 0;
pub const IP_PMTUDISC_WANT: i32 = 1;
pub const IP_PMTUDISC_DO: i32 = 2;
pub const IP_PMTUDISC_PROBE: i32 = 3;
pub const IP_PMTUDISC_INTERFACE: i32 = 4;
pub const IP_PMTUDISC_OMIT: i32 = 5;

/// `IP_MAX_MTU` (`include/net/route.h`).
pub const IP_MAX_MTU: u32 = 0xFFFF;
/// `IPV4_MIN_MTU` (`include/linux/inetdevice.h`); `inetdev_valid_mtu`.
pub const IPV4_MIN_MTU: u32 = 68;

const IP_DF: u16 = 0x4000;
const IP_MF: u16 = 0x2000;
const IP_OFFSET: u16 = 0x1FFF;
const IPV4_MIN_HDR: usize = 20;

// `include/uapi/linux/ip.h`.
const IPOPT_COPY: u8 = 0x80;
const IPOPT_END: u8 = 0;
const IPOPT_NOOP: u8 = 1;

/// `ip_sk_use_pmtu`: sockets below PROBE size datagrams by the path MTU.
#[inline]
pub fn ip_sk_use_pmtu(pmtudisc: i32) -> bool {
    pmtudisc < IP_PMTUDISC_PROBE
}

/// `ip_sk_ignore_df`: DONT, WANT and OMIT may fragment locally (and are
/// limited to `IP_MAX_MTU` rather than the MTU).
#[inline]
pub fn ip_sk_ignore_df(pmtudisc: i32) -> bool {
    pmtudisc < IP_PMTUDISC_DO || pmtudisc == IP_PMTUDISC_OMIT
}

/// `ip_dont_fragment`: DO, or WANT on a route whose MTU is not locked. NARF
/// has no locked route MTUs (no `RTAX_MTU` lock, no `rt_mtu_locked`).
#[inline]
pub fn ip_dont_fragment(pmtudisc: i32) -> bool {
    pmtudisc == IP_PMTUDISC_DO || pmtudisc == IP_PMTUDISC_WANT
}

/// `cork->fragsize` (`ip_setup_cork`): `dst4_mtu()` for `ip_sk_use_pmtu`
/// sockets, the device MTU otherwise. Without a PMTU cache or route MTU
/// metric both are the device MTU, clamped to `IP_MAX_MTU` as `dst4_mtu`
/// clamps it.
#[inline]
pub fn fragsize(pmtudisc: i32, dev_mtu: u32) -> u32 {
    if ip_sk_use_pmtu(pmtudisc) {
        dev_mtu.min(IP_MAX_MTU)
    } else {
        // `READ_ONCE(rt->dst.dev->mtu)`, then `ip_skb_dst_mtu`'s
        // `min(dev->mtu, IP_MAX_MTU)` at output time.
        dev_mtu.min(IP_MAX_MTU)
    }
}

/// The device MTU of the route a datagram to `dst` leaves through, for
/// callers that size a datagram before handing it to a sender here (the
/// userspace socket layer delivers local destinations in-process).
///
/// A local destination routes through `lo` (`ip_route_output_key_hash_rcu`
/// picks the loopback device for an RTN_LOCAL route whatever the bound
/// device); otherwise the socket's bound device (`flowi4_oif`) or the route
/// to `dst`. `None` when no interface would carry it.
pub fn route_dev_mtu_in(net_ns_id: u64, dst: [u8; 4], bound_ifindex: u32) -> Option<u32> {
    if dst[0] == 127 || crate::iface::is_local_addr_in(net_ns_id, dst) {
        // A namespace without a registered `lo` still has Linux's 64 KiB
        // loopback (`loopback_setup`).
        return Some(crate::iface::lookup_in(net_ns_id, "lo").map_or(64 * 1024, |lo| lo.mtu));
    }
    if bound_ifindex != 0 {
        return crate::iface::snapshot_all_in(net_ns_id)
            .into_iter()
            .find(|i| crate::iface::ifindex_of(&i.name) == Some(bound_ifindex))
            .map(|i| i.mtu);
    }
    crate::iface::for_dst_in(net_ns_id, dst).map(|i| i.mtu)
}

/// Why [`append_check`] refused a datagram.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AppendError {
    /// `ip_setup_cork`: `!inetdev_valid_mtu(fragsize)` → -ENETUNREACH.
    NetUnreach,
    /// `__ip_append_data` → -EMSGSIZE. `info` is what `ip_local_error`
    /// reports as `ee_info`: `mtu - optlen` (NARF sends no options).
    MsgSize { info: u32 },
}

/// `ip_setup_cork` + `__ip_append_data`'s size check for a datagram whose
/// payload after the IP header (transport header included) is `length`
/// bytes.
pub fn append_check(pmtudisc: i32, fragsize: u32, length: usize) -> Result<(), AppendError> {
    if fragsize < IPV4_MIN_MTU {
        return Err(AppendError::NetUnreach);
    }
    let maxnonfragsize = if ip_sk_ignore_df(pmtudisc) {
        IP_MAX_MTU
    } else {
        fragsize
    };
    if length > (maxnonfragsize as usize) - IPV4_MIN_HDR {
        return Err(AppendError::MsgSize { info: fragsize });
    }
    Ok(())
}

/// [`append_check`] for a UDP GSO send. `ip_setup_cork` still validates the
/// path MTU (`fragsize`), but `__ip_append_data` then sizes the datagram by
/// `mtu = cork->gso_size ? IP_MAX_MTU : cork->fragsize`, whatever the
/// IP_MTU_DISCOVER mode; `ip_local_error`'s `ee_info` is that `IP_MAX_MTU`.
/// The per-segment MTU check is `udp_gso::gso_check`'s.
pub fn append_check_gso(fragsize: u32, length: usize) -> Result<(), AppendError> {
    if fragsize < IPV4_MIN_MTU {
        return Err(AppendError::NetUnreach);
    }
    if length > (IP_MAX_MTU as usize) - IPV4_MIN_HDR {
        return Err(AppendError::MsgSize { info: IP_MAX_MTU });
    }
    Ok(())
}

/// `__ip_make_skb`'s DF rule for a datagram of `ip_len` bytes (header
/// included): DO and PROBE always; otherwise only a datagram that fits the
/// path MTU and whose socket wants DF (`ip_dont_fragment`).
#[inline]
pub fn df_wanted(pmtudisc: i32, ip_len: usize, fragsize: u32) -> bool {
    pmtudisc == IP_PMTUDISC_DO
        || pmtudisc == IP_PMTUDISC_PROBE
        || (ip_len <= fragsize as usize && ip_dont_fragment(pmtudisc))
}

/// `__ip_make_skb`'s header policy on a built header at `iph[0..20]`: set or
/// clear DF, then pick the IP ID (`ip_select_ident`). `inet_id` is the
/// socket's `inet_id` counter when it is connected (`inet_daddr != 0`),
/// `None` otherwise. The caller computes the header checksum afterwards.
pub fn make_header(
    net_ns_id: u64,
    iph: &mut [u8],
    pmtudisc: i32,
    fragsize: u32,
    inet_id: Option<&AtomicU16>,
) {
    let ip_len = u16::from_be_bytes([iph[2], iph[3]]) as usize;
    let mut word = u16::from_be_bytes([iph[6], iph[7]]) & !IP_DF;
    if df_wanted(pmtudisc, ip_len, fragsize) {
        word |= IP_DF;
    }
    iph[6..8].copy_from_slice(&word.to_be_bytes());
    select_ident(net_ns_id, iph, inet_id, ip_sk_ignore_df(pmtudisc));
}

/// `ip_select_ident_segs(net, skb, sk, 1)`.
///
/// * A connected socket takes the next value of its own `inet_id` counter
///   (`atomic_add_return(segs, &inet->inet_id)`), DF or not.
/// * Otherwise a DF datagram that may not be fragmented locally
///   (`!skb->ignore_df` — DO and PROBE, the modes that set DF without
///   `ip_sk_ignore_df`) carries ID 0.
/// * Everything else — every datagram that is, or may be, fragmented — takes
///   an ID from the per-destination generator (`__ip_select_ident`).
pub fn select_ident(net_ns_id: u64, iph: &mut [u8], inet_id: Option<&AtomicU16>, ignore_df: bool) {
    let id = if let Some(counter) = inet_id {
        counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    } else if u16::from_be_bytes([iph[6], iph[7]]) & IP_DF != 0 && !ignore_df {
        0
    } else {
        let daddr = u32::from_be_bytes([iph[16], iph[17], iph[18], iph[19]]);
        let saddr = u32::from_be_bytes([iph[12], iph[13], iph[14], iph[15]]);
        ip_select_ident_hashed(net_ns_id, daddr, saddr, iph[9], 1)
    };
    iph[4..6].copy_from_slice(&id.to_be_bytes());
}

// ── Randomness ──────────────────────────────────────────────────────────────

/// The kernel CSPRNG, installed at boot (`narf_filesystem::csprng::fill`).
/// `narf-net` cannot depend on the crate that owns it, so the boot path
/// hands it in, as it does every other cross-crate service.
static RANDOM_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the CSPRNG fill function (`get_random_bytes`). Must be IRQ-safe:
/// the ID generator runs on RX-driven send paths (ICMP echo replies).
pub fn install_random_hook(fill: fn(&mut [u8])) {
    RANDOM_HOOK.store(fill as usize, Ordering::Release);
}

/// `get_random_bytes`. Before the boot path installs the CSPRNG (host unit
/// tests only) this falls back to a clock-seeded splitmix64 stream.
pub fn get_random_bytes(buf: &mut [u8]) {
    let raw = RANDOM_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only `install_random_hook` stores here, and it stores a
        // valid `fn(&mut [u8])`.
        let fill: fn(&mut [u8]) = unsafe { core::mem::transmute::<usize, fn(&mut [u8])>(raw) };
        fill(buf);
        return;
    }
    static FALLBACK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    for chunk in buf.chunks_mut(8) {
        let seed = FALLBACK
            .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
            .wrapping_add(narf_scheduler::narf_time::monotonic_ns());
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
}

fn get_random_u32() -> u32 {
    let mut b = [0u8; 4];
    get_random_bytes(&mut b);
    u32::from_ne_bytes(b)
}

/// `get_random_u16()`: the seed `__ip4_datagram_connect` gives `inet_id`.
pub fn get_random_u16() -> u16 {
    let mut b = [0u8; 2];
    get_random_bytes(&mut b);
    u16::from_ne_bytes(b)
}

/// `__get_random_u32_below(ceil)` (`drivers/char/random.c`): Lemire's
/// multiply-shift with the rejection step, so the result is uniform.
fn get_random_u32_below(ceil: u32) -> u32 {
    if ceil <= 1 {
        return 0;
    }
    let mut mult = u64::from(ceil) * u64::from(get_random_u32());
    if (mult as u32) < ceil {
        let bound = ceil.wrapping_neg() % ceil;
        while (mult as u32) < bound {
            mult = u64::from(ceil) * u64::from(get_random_u32());
        }
    }
    (mult >> 32) as u32
}

// ── __ip_select_ident / ip_idents_reserve ───────────────────────────────────

/// Number of ID buckets. Linux sizes `ip_idents` from memory with a floor of
/// 2048 (`ip_rt_init`'s `alloc_large_system_hash(..., 2048, 256 * 1024)`).
const IP_IDENTS_SZ: usize = 2048;

static IP_IDENTS: [AtomicU32; IP_IDENTS_SZ] = [const { AtomicU32::new(0) }; IP_IDENTS_SZ];
static IP_TSTAMPS: [AtomicU32; IP_IDENTS_SZ] = [const { AtomicU32::new(0) }; IP_IDENTS_SZ];
/// `ip_rt_init` seeds every bucket with `get_random_bytes`; done here on the
/// first ID drawn, once the CSPRNG is installed.
static IP_IDENTS_INIT: Once = Once::new();
/// `net->ipv4.ip_id_key`: a boot-random siphash key, generated on first use
/// as `__ip_select_ident` does. One key serves every namespace; the
/// namespace id is hashed with the flow, which separates namespaces' ID
/// streams the way Linux's per-netns keys do.
static IP_ID_KEY: OnceLock<[u64; 2]> = OnceLock::new();

fn ip_idents_init() {
    IP_IDENTS_INIT.call_once(|| {
        let mut b = [0u8; IP_IDENTS_SZ * 4];
        get_random_bytes(&mut b);
        for (slot, chunk) in IP_IDENTS.iter().zip(b.chunks_exact(4)) {
            slot.store(
                u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                Ordering::Relaxed,
            );
        }
    });
}

/// `jiffies` at HZ=1000.
fn jiffies() -> u32 {
    (narf_scheduler::narf_time::monotonic_ns() / 1_000_000) as u32
}

/// `ip_idents_reserve(hash, segs)`: reserve `segs` consecutive IDs from the
/// bucket `hash` selects, after advancing it by a random amount bounded by
/// the jiffies elapsed since the bucket was last used (so an observer cannot
/// count another flow's datagrams by sampling a shared bucket).
fn ip_idents_reserve(hash: u32, segs: u32) -> u32 {
    ip_idents_init();
    let bucket = hash as usize & (IP_IDENTS_SZ - 1);
    let now = jiffies();
    let p_tstamp = &IP_TSTAMPS[bucket];
    let old = p_tstamp.load(Ordering::Relaxed);
    let mut delta = 0;
    if old != now
        && p_tstamp
            .compare_exchange(old, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        delta = get_random_u32_below(now.wrapping_sub(old));
    }
    IP_IDENTS[bucket]
        .fetch_add(segs.wrapping_add(delta), Ordering::Relaxed)
        .wrapping_add(delta)
}

/// `__ip_select_ident`: `siphash_3u32(daddr, saddr, protocol, ip_id_key)`
/// picks the bucket. Exposed for the forward/ICMP paths and tests.
pub fn ip_select_ident_hashed(
    net_ns_id: u64,
    daddr: u32,
    saddr: u32,
    protocol: u8,
    segs: u32,
) -> u16 {
    let key = IP_ID_KEY.get_or_init(|| {
        let mut b = [0u8; 16];
        get_random_bytes(&mut b);
        let mut k0 = [0u8; 8];
        let mut k1 = [0u8; 8];
        k0.copy_from_slice(&b[..8]);
        k1.copy_from_slice(&b[8..]);
        [u64::from_le_bytes(k0), u64::from_le_bytes(k1)]
    });
    let hash = siphash24(
        key,
        &[
            u64::from(daddr) | (u64::from(saddr) << 32),
            u64::from(protocol) | ((net_ns_id & 0xFFFF_FFFF) << 32),
            net_ns_id >> 32,
        ],
    ) as u32;
    ip_idents_reserve(hash, segs) as u16
}

/// SipHash-2-4 over `words` (little-endian 64-bit message words), as
/// `lib/siphash.c` computes it.
pub(crate) fn siphash24(key: &[u64; 2], words: &[u64]) -> u64 {
    let mut v0 = 0x736f_6d65_7073_6575u64 ^ key[0];
    let mut v1 = 0x646f_7261_6e64_6f6du64 ^ key[1];
    let mut v2 = 0x6c79_6765_6e65_7261u64 ^ key[0];
    let mut v3 = 0x7465_6462_7974_6573u64 ^ key[1];
    macro_rules! round {
        () => {
            v0 = v0.wrapping_add(v1);
            v1 = v1.rotate_left(13);
            v1 ^= v0;
            v0 = v0.rotate_left(32);
            v2 = v2.wrapping_add(v3);
            v3 = v3.rotate_left(16);
            v3 ^= v2;
            v0 = v0.wrapping_add(v3);
            v3 = v3.rotate_left(21);
            v3 ^= v0;
            v2 = v2.wrapping_add(v1);
            v1 = v1.rotate_left(17);
            v1 ^= v2;
            v2 = v2.rotate_left(32);
        };
    }
    for &m in words {
        v3 ^= m;
        round!();
        round!();
        v0 ^= m;
    }
    let b = ((words.len() as u64 * 8) & 0xff) << 56;
    v3 ^= b;
    round!();
    round!();
    v0 ^= b;
    v2 ^= 0xff;
    round!();
    round!();
    round!();
    round!();
    v0 ^ v1 ^ v2 ^ v3
}

// ── Fragmentation statistics ────────────────────────────────────────────────

/// `/proc/net/snmp` fragmentation counters (`IPSTATS_MIB_FRAG*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FragStats {
    /// FragOKs: datagrams fragmented successfully.
    pub oks: u64,
    /// FragFails: datagrams that needed fragmenting and could not be.
    pub fails: u64,
    /// FragCreates: fragments generated.
    pub creates: u64,
}

static FRAG_STATS: IrqSafeSpinLock<BTreeMap<u64, FragStats>> =
    IrqSafeSpinLock::new(BTreeMap::new());

fn bump(net_ns_id: u64, f: impl FnOnce(&mut FragStats)) {
    f(FRAG_STATS.lock().entry(net_ns_id).or_default());
}

/// The namespace's fragmentation counters.
pub fn frag_stats_in(net_ns_id: u64) -> FragStats {
    FRAG_STATS
        .lock()
        .get(&net_ns_id)
        .copied()
        .unwrap_or_default()
}

pub(crate) fn remove_namespace(net_ns_id: u64) {
    FRAG_STATS.lock().remove(&net_ns_id);
}

#[doc(hidden)]
pub fn __reset_frag_stats_for_test() {
    FRAG_STATS.lock().clear();
}

// ── ip_finish_output / ip_fragment / ip_do_fragment ─────────────────────────

/// Why [`ip_finish_output`] did not put the datagram on the wire.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OutputError {
    /// `ip_fragment`: DF set, may not fragment locally — -EMSGSIZE
    /// (FragFails counted).
    MsgSize,
    /// The output function failed for the datagram or one of its fragments
    /// (`ip_do_fragment`'s `fail:` path counts FragFails for a fragmented
    /// one).
    Output,
}

/// The IPv4 total length of the packet at `frame[ll..]`, bounded by the
/// buffer.
fn ip_len(frame: &[u8], ll: usize) -> usize {
    if frame.len() < ll + IPV4_MIN_HDR {
        return frame.len().saturating_sub(ll);
    }
    let total = u16::from_be_bytes([frame[ll + 2], frame[ll + 3]]) as usize;
    total.min(frame.len() - ll)
}

/// Would [`ip_finish_output`] fragment the datagram in `frame[ll..]`?
#[inline]
pub fn needs_fragment(frame: &[u8], ll: usize, mtu: u32) -> bool {
    ip_len(frame, ll) > mtu as usize
}

/// `__ip_finish_output` for the link-layer frame `frame`, whose IPv4 packet
/// starts at `frame[ll..]` and whose header (DF, ID, checksum) is final.
///
/// A packet no longer than `mtu` is handed to `output` unchanged. A longer
/// one goes through `ip_fragment`: with DF set and `ignore_df` false it is
/// refused (EMSGSIZE, FragFails); otherwise `ip_do_fragment` emits it as
/// fragments, each a copy of `frame[..ll]` (the link header) followed by its
/// own IPv4 header and data block.
pub fn ip_finish_output(
    net_ns_id: u64,
    frame: &[u8],
    ll: usize,
    mtu: u32,
    ignore_df: bool,
    mut output: impl FnMut(&[u8]) -> Result<(), ()>,
) -> Result<(), OutputError> {
    if !needs_fragment(frame, ll, mtu) {
        return output(frame).map_err(|()| OutputError::Output);
    }
    // `ip_fragment`.
    let word = u16::from_be_bytes([frame[ll + 6], frame[ll + 7]]);
    if word & IP_DF != 0 && !ignore_df {
        // Linux also sends an ICMP Fragmentation Needed back to the source
        // here (`icmp_send`). No local socket reaches this arm in NARF —
        // `append_check` refused every such datagram at send time and the
        // forwarder answers DF packets before output — so it is only
        // reachable after a netfilter mangle grew the packet.
        bump(net_ns_id, |s| s.fails += 1);
        return Err(OutputError::MsgSize);
    }
    ip_do_fragment(net_ns_id, frame, ll, mtu, output)
}

/// `ip_options_fragment`: after the first fragment, options without the
/// copied bit are overwritten with NOOPs so later fragments do not carry
/// them (the header length is unchanged).
fn ip_options_fragment(opts: &mut [u8]) {
    let mut i = 0;
    let mut l = opts.len();
    while l > 0 {
        match opts[i] {
            IPOPT_END => return,
            IPOPT_NOOP => {
                l -= 1;
                i += 1;
                continue;
            }
            _ => {}
        }
        if l < 2 {
            return;
        }
        let optlen = opts[i + 1] as usize;
        if optlen < 2 || optlen > l {
            return;
        }
        if opts[i] & IPOPT_COPY == 0 {
            opts[i..i + optlen].fill(IPOPT_NOOP);
        }
        l -= optlen;
        i += optlen;
    }
}

/// `ip_do_fragment`'s slow path (`ip_frag_init` + `ip_frag_next`).
fn ip_do_fragment(
    net_ns_id: u64,
    frame: &[u8],
    ll: usize,
    mtu: u32,
    mut output: impl FnMut(&[u8]) -> Result<(), ()>,
) -> Result<(), OutputError> {
    let total = ip_len(frame, ll);
    let pkt = &frame[ll..ll + total];
    let hlen = ((pkt[0] & 0x0F) as usize) * 4;
    if hlen < IPV4_MIN_HDR || pkt.len() < hlen || (mtu as usize) < hlen + 8 {
        bump(net_ns_id, |s| s.fails += 1);
        return Err(OutputError::Output);
    }
    // `mtu = mtu - hlen`: the data space per fragment.
    let space = mtu as usize - hlen;
    let mut hdr = [0u8; 60];
    hdr[..hlen].copy_from_slice(&pkt[..hlen]);
    let word = u16::from_be_bytes([pkt[6], pkt[7]]);
    // `ip_frag_init`: a fragment of a fragment keeps its base offset and,
    // if it was not the last, MF on every piece.
    let mut offset = ((word & IP_OFFSET) as usize) << 3;
    let not_last_frag = word & IP_MF != 0;
    let mut left = total - hlen;
    let mut ptr = hlen;
    let mut buf: Vec<u8> = Vec::with_capacity(ll + hlen + space.min(left));
    let mut created = 0u64;
    while left > 0 {
        // `first_frag = (state.offset == 0)`: only a datagram's real first
        // fragment triggers the options fix-up.
        let first_frag = offset == 0;
        let mut len = left.min(space);
        if len < left {
            len &= !7;
        }
        if (offset >> 3) > IP_OFFSET as usize {
            bump(net_ns_id, |s| {
                s.fails += 1;
                s.creates += created;
            });
            return Err(OutputError::Output);
        }
        buf.clear();
        buf.extend_from_slice(&frame[..ll]);
        buf.extend_from_slice(&hdr[..hlen]);
        buf.extend_from_slice(&pkt[ptr..ptr + len]);
        left -= len;
        // IPSKB_FRAG_PMTU is never set on NARF's output path, so no DF.
        let mut frag_off = (offset >> 3) as u16;
        if left > 0 || not_last_frag {
            frag_off |= IP_MF;
        }
        let ip = &mut buf[ll..];
        ip[6..8].copy_from_slice(&frag_off.to_be_bytes());
        ip[2..4].copy_from_slice(&((len + hlen) as u16).to_be_bytes());
        ip[10] = 0;
        ip[11] = 0;
        let cs = ip_checksum(&ip[..hlen]);
        ip[10..12].copy_from_slice(&cs.to_be_bytes());
        ptr += len;
        offset += len;
        // `ip_frag_ipcb`: fix the options once, after the first fragment,
        // so every later fragment inherits the trimmed set.
        if first_frag && hlen > IPV4_MIN_HDR {
            ip_options_fragment(&mut hdr[IPV4_MIN_HDR..hlen]);
        }
        if output(&buf).is_err() {
            bump(net_ns_id, |s| {
                s.fails += 1;
                s.creates += created;
            });
            return Err(OutputError::Output);
        }
        created += 1;
    }
    bump(net_ns_id, |s| {
        s.oks += 1;
        s.creates += created;
    });
    Ok(())
}
