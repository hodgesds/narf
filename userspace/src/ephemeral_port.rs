//! Ephemeral-port allocator for unbound `connect()` auto-bind.
//!
//! References (clean-room):
//! - RFC 6056 §3.2 Algorithm 1: <https://www.rfc-editor.org/rfc/rfc6056>
//! - IANA Service Name and Transport Protocol Port Number Registry:
//!   <https://www.iana.org/assignments/service-names-port-numbers/>
//!
//! Pool is keyed on `(family, local_ip, protocol)`; each pool is a
//! 16384-bit bitmap covering the IANA-recommended dynamic range
//! 49152..=65535. Allocation does a linear scan starting at a
//! per-boot random offset (seeded from the TSC) so port sequences
//! differ across boots without requiring CSPRNG strength.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::bitmap::Bitmap;
use narf_lib::sync::IrqSafeSpinLock;

/// IANA dynamic / ephemeral range, RFC 6056 §2.1.
pub const EPHEMERAL_MIN: u16 = 49152;
pub const EPHEMERAL_MAX: u16 = 65535;
pub const EPHEMERAL_COUNT: usize = (EPHEMERAL_MAX as usize) - (EPHEMERAL_MIN as usize) + 1;

/// Transport protocol selector. Carved out here so the allocator
/// can keep TCP and UDP pools independent (a UDP socket on port
/// 50000 doesn't block TCP from using the same number).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SocketProto {
    Tcp,
    Udp,
}

type PoolKey = (u16, u32, SocketProto);
type PoolMap = BTreeMap<PoolKey, Box<Bitmap<EPHEMERAL_COUNT>>>;

struct EphemeralPool {
    pools: PoolMap,
    /// Per-boot starting offset, advanced on each alloc to avoid
    /// the trivially-predictable "always 49152 first" pattern.
    cursor: u32,
}

impl EphemeralPool {
    const fn new() -> Self {
        Self {
            pools: BTreeMap::new(),
            cursor: 0,
        }
    }
}

static EPHEMERAL: IrqSafeSpinLock<EphemeralPool> = IrqSafeSpinLock::new(EphemeralPool::new());
static SEED_INIT: AtomicU64 = AtomicU64::new(0);

fn ensure_seeded(pool: &mut EphemeralPool) {
    if SEED_INIT.swap(1, Ordering::AcqRel) == 0 {
        let tsc = narf_time::now_cycles();
        pool.cursor = (tsc as u32) % (EPHEMERAL_COUNT as u32);
    }
}

/// Allocate an unused ephemeral port for `(family, local_ip, protocol)`.
/// Returns `None` if every port in the dynamic range is taken.
pub fn alloc(family: u16, local_ip: u32, protocol: SocketProto) -> Option<u16> {
    let mut pool = EPHEMERAL.lock();
    ensure_seeded(&mut pool);
    let start = pool.cursor as usize % EPHEMERAL_COUNT;
    pool.cursor = pool.cursor.wrapping_add(1);
    let key = (family, local_ip, protocol);
    let bitmap = pool
        .pools
        .entry(key)
        .or_insert_with(|| Box::new(Bitmap::new()));
    for step in 0..EPHEMERAL_COUNT {
        let idx = (start + step) % EPHEMERAL_COUNT;
        if !bitmap.get(idx) {
            bitmap.set(idx);
            return Some(EPHEMERAL_MIN + idx as u16);
        }
    }
    None
}

/// Return `port` to the pool for `(family, local_ip, protocol)`.
/// Silently ignored if `port` is outside the dynamic range or the
/// pool has never been touched.
pub fn free(family: u16, local_ip: u32, protocol: SocketProto, port: u16) {
    if port < EPHEMERAL_MIN {
        return;
    }
    let idx = (port - EPHEMERAL_MIN) as usize;
    let mut pool = EPHEMERAL.lock();
    let key = (family, local_ip, protocol);
    if let Some(bitmap) = pool.pools.get_mut(&key) {
        bitmap.clear(idx);
    }
}

fn count_in_use(family: u16, local_ip: u32, protocol: SocketProto) -> usize {
    let pool = EPHEMERAL.lock();
    pool.pools
        .get(&(family, local_ip, protocol))
        .map(|b| b.count_ones())
        .unwrap_or(0)
}

// ── Tests ───────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_ephemeral_port_alloc_returns_in_iana_range() -> TestResult {
    let family = 2u16;
    let ip = 0x0100_007fu32;
    for _ in 0..64 {
        let p = match alloc(family, ip, SocketProto::Tcp) {
            Some(p) => p,
            None => return TestResult::Fail("alloc returned None"),
        };
        if !(EPHEMERAL_MIN..=EPHEMERAL_MAX).contains(&p) {
            return TestResult::Fail("port outside IANA dynamic range");
        }
        free(family, ip, SocketProto::Tcp, p);
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/ephemeral_port",
    smoke_ephemeral_port_alloc_returns_in_iana_range
);

fn smoke_ephemeral_port_alloc_unique_until_exhausted() -> TestResult {
    let family = 2u16;
    let ip = 0x0200_007fu32;
    let mut seen = alloc::collections::BTreeSet::new();
    for _ in 0..EPHEMERAL_COUNT {
        let p = match alloc(family, ip, SocketProto::Tcp) {
            Some(p) => p,
            None => return TestResult::Fail("alloc exhausted early"),
        };
        if !seen.insert(p) {
            for q in &seen {
                free(family, ip, SocketProto::Tcp, *q);
            }
            return TestResult::Fail("duplicate port issued");
        }
    }
    for p in &seen {
        free(family, ip, SocketProto::Tcp, *p);
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/ephemeral_port",
    smoke_ephemeral_port_alloc_unique_until_exhausted
);

fn smoke_ephemeral_port_alloc_exhausted_returns_none() -> TestResult {
    let family = 2u16;
    let ip = 0x0300_007fu32;
    let mut ports = alloc::vec::Vec::with_capacity(EPHEMERAL_COUNT);
    for _ in 0..EPHEMERAL_COUNT {
        match alloc(family, ip, SocketProto::Tcp) {
            Some(p) => ports.push(p),
            None => {
                for p in &ports {
                    free(family, ip, SocketProto::Tcp, *p);
                }
                return TestResult::Fail("alloc exhausted early");
            }
        }
    }
    let extra = alloc(family, ip, SocketProto::Tcp);
    for p in &ports {
        free(family, ip, SocketProto::Tcp, *p);
    }
    if let Some(p) = extra {
        free(family, ip, SocketProto::Tcp, p);
        return TestResult::Fail("alloc returned Some past exhaustion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/ephemeral_port",
    smoke_ephemeral_port_alloc_exhausted_returns_none
);

fn smoke_ephemeral_port_free_recycles_port() -> TestResult {
    let family = 2u16;
    let ip = 0x0400_007fu32;
    let before = count_in_use(family, ip, SocketProto::Tcp);
    let p = match alloc(family, ip, SocketProto::Tcp) {
        Some(p) => p,
        None => return TestResult::Fail("alloc returned None"),
    };
    if count_in_use(family, ip, SocketProto::Tcp) != before + 1 {
        free(family, ip, SocketProto::Tcp, p);
        return TestResult::Fail("count did not rise after alloc");
    }
    free(family, ip, SocketProto::Tcp, p);
    if count_in_use(family, ip, SocketProto::Tcp) != before {
        return TestResult::Fail("count did not recover after free");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/ephemeral_port",
    smoke_ephemeral_port_free_recycles_port
);

fn smoke_ephemeral_port_different_local_ips_have_independent_pools() -> TestResult {
    let family = 2u16;
    let ip_a = 0x0500_007fu32;
    let ip_b = 0x0600_007fu32;
    let pa = match alloc(family, ip_a, SocketProto::Tcp) {
        Some(p) => p,
        None => return TestResult::Fail("alloc A failed"),
    };
    let pb = match alloc(family, ip_b, SocketProto::Tcp) {
        Some(p) => p,
        None => {
            free(family, ip_a, SocketProto::Tcp, pa);
            return TestResult::Fail("alloc B failed");
        }
    };
    let ok = (EPHEMERAL_MIN..=EPHEMERAL_MAX).contains(&pa)
        && (EPHEMERAL_MIN..=EPHEMERAL_MAX).contains(&pb);
    free(family, ip_a, SocketProto::Tcp, pa);
    free(family, ip_b, SocketProto::Tcp, pb);
    if !ok {
        return TestResult::Fail("alloc result out of range");
    }
    // Reserve a port in pool A; pool B must still be able to alloc
    // the *same numeric port* because pools are keyed on local_ip.
    let ra = match alloc(family, ip_a, SocketProto::Tcp) {
        Some(p) => p,
        None => return TestResult::Fail("alloc A re-acq failed"),
    };
    let target = ra;
    let mut held = alloc::vec::Vec::new();
    let got = loop {
        match alloc(family, ip_b, SocketProto::Tcp) {
            Some(p) if p == target => break true,
            Some(p) => held.push(p),
            None => break false,
        }
    };
    free(family, ip_a, SocketProto::Tcp, ra);
    for p in &held {
        free(family, ip_b, SocketProto::Tcp, *p);
    }
    if got {
        free(family, ip_b, SocketProto::Tcp, target);
        TestResult::Pass
    } else {
        TestResult::Fail("pool B never produced the colliding port")
    }
}
kernel_test_in!(
    "userspace/ephemeral_port",
    smoke_ephemeral_port_different_local_ips_have_independent_pools
);
