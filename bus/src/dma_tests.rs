//! `bus/dma` smokes: Devicetree → `DmaDevice` for synthetic PCI topologies.
//! QEMU `virt` is coherent, so every non-coherent case is a synthetic blob.
extern crate alloc;

use alloc::vec::Vec;

use narf_io::{alloc_coherent_for, DmaCoherence, IoError};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

use super::pci_from_dt;

/// `(name, props, children)` of a synthetic node.
struct Node<'a>(&'a str, &'a [(&'a str, &'a [u8])], &'a [Node<'a>]);

fn emit(s: &mut Vec<u8>, strings: &mut Vec<u8>, node: &Node<'_>) {
    let pad = |s: &mut Vec<u8>| {
        while s.len() % 4 != 0 {
            s.push(0);
        }
    };
    s.extend_from_slice(&1u32.to_be_bytes());
    s.extend_from_slice(node.0.as_bytes());
    s.push(0);
    pad(s);
    for (name, value) in node.1 {
        let off = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        s.extend_from_slice(&3u32.to_be_bytes());
        s.extend_from_slice(&(value.len() as u32).to_be_bytes());
        s.extend_from_slice(&off.to_be_bytes());
        s.extend_from_slice(value);
        pad(s);
    }
    for child in node.2 {
        emit(s, strings, child);
    }
    s.extend_from_slice(&2u32.to_be_bytes());
}

fn blob(children: &[Node<'_>]) -> Vec<u8> {
    let (mut s, mut strings) = (Vec::new(), Vec::new());
    emit(&mut s, &mut strings, &Node("", &[], children));
    s.extend_from_slice(&9u32.to_be_bytes());
    let off_struct = 56u32;
    let off_strings = off_struct + s.len() as u32;
    let mut out = Vec::new();
    for v in [
        0xd00d_feedu32,
        off_strings + strings.len() as u32,
        off_struct,
        off_strings,
        40,
        17,
        16,
        0,
        strings.len() as u32,
        s.len() as u32,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&s);
    out.extend_from_slice(&strings);
    out
}

const PCI: &[u8] = b"pci\0";
const REG0: &[u8] = &[0; 20];

/// Coherent / non-coherent / default host bridges; a non-coherent device
/// without any pool fails closed instead of getting write-back memory.
fn smoke_bus_dma_configure_coherence_from_dt() -> TestResult {
    let endpoint = [Node("wifi@0", &[("reg", REG0)], &[])];
    let tree = [
        Node(
            "pcie@1",
            &[
                ("device_type", PCI),
                ("linux,pci-domain", &[0, 0, 0, 0]),
                ("dma-coherent", &[]),
            ],
            &endpoint,
        ),
        Node(
            "pcie@2",
            &[
                ("device_type", PCI),
                ("linux,pci-domain", &[0, 0, 0, 1]),
                ("dma-noncoherent", &[]),
            ],
            &endpoint,
        ),
        Node(
            "pcie@3",
            &[("device_type", PCI), ("linux,pci-domain", &[0, 0, 0, 2])],
            &endpoint,
        ),
    ];
    let dt = blob(&tree);
    // SAFETY: the blob describes no shared-dma-pool.
    let cfg = |domain, default| unsafe { pci_from_dt(&dt, domain, Some(&[0]), default) };
    let (Ok(c), Ok(nc), Ok(arm_default), Ok(coherent_default)) =
        (cfg(0, false), cfg(1, true), cfg(2, false), cfg(2, true))
    else {
        return TestResult::Fail("configuration failed");
    };
    if c.coherence() != DmaCoherence::Coherent
        || nc.coherence() != DmaCoherence::NonCoherent
        || arm_default.coherence() != DmaCoherence::NonCoherent
        || coherent_default.coherence() != DmaCoherence::Coherent
        || [&c, &nc, &arm_default].iter().any(|d| d.pool().is_some())
    {
        return TestResult::Fail("host bridge coherence not applied");
    }
    if !matches!(
        alloc_coherent_for(&nc, 64, DomainId::DRIVER_0, u64::MAX),
        Err(IoError::NoCoherentPool)
    ) {
        return TestResult::Fail("non-coherent device without a pool got memory");
    }
    match alloc_coherent_for(&c, 64, DomainId::DRIVER_0, u64::MAX) {
        Ok(buf) if !buf.is_pool_backed() => TestResult::Pass,
        Ok(_) => TestResult::Fail("coherent device left the buddy path"),
        Err(_) => TestResult::Skip("frame allocator unavailable"),
    }
}
kernel_test_in!("bus/dma", smoke_bus_dma_configure_coherence_from_dt);

/// A function's `memory-region` pool and the `linux,dma-default` fallback
/// become mapped, non-cacheable reserved pools; a pool over RAM is refused.
/// The synthetic range is never dereferenced (the test allocates nothing).
#[cfg(target_arch = "aarch64")]
fn smoke_bus_dma_configure_reserved_pools() -> TestResult {
    use narf_memory::{PhysAddr, PAGE_SIZE};
    // Shared with io/ncdma's Normal-NC smoke: pools are permanent, so the
    // same range resolves to the same pool whichever test runs first.
    const BASE: u32 = 0x3f;
    if (0..2)
        .any(|i| narf_memory::frame::is_system_ram(PhysAddr::new(0x3f_0000_0000 + i * PAGE_SIZE)))
    {
        return TestResult::Skip("synthetic pool range is System RAM here");
    }
    let reg = [0, 0, 0, BASE as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0];
    let pool_props: &[(&str, &[u8])] = &[
        ("compatible", b"shared-dma-pool\0"),
        ("reg", &reg),
        ("no-map", &[]),
        ("linux,dma-default", &[]),
        ("phandle", &[0, 0, 0, 3]),
    ];
    let reserved = [Node("pool@3f00000000", pool_props, &[])];
    let with_region = [Node(
        "wifi@0",
        &[("reg", REG0), ("memory-region", &[0, 0, 0, 3])],
        &[],
    )];
    let plain = [Node("wifi@0", &[("reg", REG0)], &[])];
    let cells: &[(&str, &[u8])] = &[
        ("#address-cells", &[0, 0, 0, 2]),
        ("#size-cells", &[0, 0, 0, 2]),
    ];
    let tree = [
        Node("reserved-memory", cells, &reserved),
        Node(
            "pcie@1",
            &[("device_type", PCI), ("linux,pci-domain", &[0, 0, 0, 0])],
            &with_region,
        ),
        Node(
            "pcie@2",
            &[
                ("device_type", PCI),
                ("linux,pci-domain", &[0, 0, 0, 1]),
                ("dma-coherent", &[]),
            ],
            &plain,
        ),
        Node(
            "pcie@3",
            &[("device_type", PCI), ("linux,pci-domain", &[0, 0, 0, 2])],
            &plain,
        ),
    ];
    let dt = blob(&tree);
    // SAFETY: the pool range is an unpopulated physical range claimed only
    // by these permanent test pools and never dereferenced.
    let cfg = |domain| unsafe { pci_from_dt(&dt, domain, Some(&[0]), false) };
    let (Ok(own), Ok(coherent), Ok(fallback)) = (cfg(0), cfg(1), cfg(2)) else {
        return TestResult::Fail("reserved pool configuration failed");
    };
    let (Some(own_pool), Some(default_pool)) = (own.pool(), fallback.pool()) else {
        return TestResult::Fail("device or default pool missing");
    };
    if own_pool.phys().raw() != 0x3f_0000_0000
        || own_pool.pages() != 2
        || !alloc::sync::Arc::ptr_eq(own_pool, default_pool)
        || coherent.pool().is_some()
        || coherent.coherence() != DmaCoherence::Coherent
    {
        return TestResult::Fail("pool assignment mismatch");
    }
    // Same blob, but the pool now covers a buddy frame (System RAM).
    let Ok(frame) = narf_memory::alloc_pages_on(0, 0) else {
        return TestResult::Skip("frame allocator unavailable");
    };
    let ram = frame.start_address().raw().to_be_bytes();
    let mut ram_reg = [0u8; 16];
    ram_reg[..8].copy_from_slice(&ram);
    ram_reg[8..].copy_from_slice(&PAGE_SIZE.to_be_bytes());
    let ram_props: &[(&str, &[u8])] = &[
        ("compatible", b"shared-dma-pool\0"),
        ("reg", &ram_reg),
        ("no-map", &[]),
        ("phandle", &[0, 0, 0, 3]),
    ];
    let ram_reserved = [Node("pool@0", ram_props, &[])];
    let ram_tree = [
        Node("reserved-memory", cells, &ram_reserved),
        Node(
            "pcie@1",
            &[("device_type", PCI), ("linux,pci-domain", &[0, 0, 0, 0])],
            &with_region,
        ),
    ];
    let ram_dt = blob(&ram_tree);
    // SAFETY: refused before any mapping because the range is RAM.
    let refused = unsafe { pci_from_dt(&ram_dt, 0, Some(&[0]), false) };
    narf_memory::free_pages(frame, 0);
    match refused {
        Err(IoError::PoolRejected) => TestResult::Pass,
        _ => TestResult::Fail("pool over System RAM accepted"),
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("bus/dma", smoke_bus_dma_configure_reserved_pools);
