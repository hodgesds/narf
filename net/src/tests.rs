//! Subsystem smokes for `narf-net`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `net` subsystem.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_net_loopback_register() -> TestResult {
    use crate::{Loopback, bootstrap_authority, register_loopback_named, registry};

    // Scheduler must be live: register_loopback_named spawns a
    // forwarder task at registration time (per the Stage-3 spec).
    narf_scheduler::init();

    let authority = bootstrap_authority();
    let before = registry().len();
    let _handle = match register_loopback_named(&authority, "lo.smoke-register") {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("register_loopback_named failed on fresh authority"),
    };
    if registry().len() != before + 1 {
        return TestResult::Fail("registry length didn't grow after register");
    }

    let info = registry().with_interface("lo.smoke-register", |i| {
        (i.mac(), i.mtu(), i.link_up())
    });
    match info {
        Some((mac, mtu, link)) => {
            if mac != Loopback::DEFAULT_MAC { return TestResult::Fail("MAC mismatch"); }
            if mtu != Loopback::DEFAULT_MTU { return TestResult::Fail("MTU mismatch"); }
            if !link { return TestResult::Fail("loopback link not up"); }
            TestResult::Pass
        }
        None => TestResult::Fail("registered interface not found by name"),
    }
}
kernel_test_in!("net", smoke_net_loopback_register);

fn smoke_net_loopback_roundtrip() -> TestResult {
    // End-to-end zero-copy: write a known payload into a DmaBuffer,
    // wrap as a Frame, send via loopback's tx_ring, recv via rx_ring,
    // verify byte-exact match.
    use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    use crate::{Frame, bootstrap_authority, register_loopback_named, registry};

    const PAYLOAD: [u8; 24] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];

    static OUTCOME:  AtomicU8  = AtomicU8::new(0);
    static GOT_LEN:  AtomicU32 = AtomicU32::new(0);

    OUTCOME.store(0, Ordering::Relaxed);
    GOT_LEN.store(0, Ordering::Relaxed);

    narf_scheduler::init();

    let authority = bootstrap_authority();
    if register_loopback_named(&authority, "lo.smoke-roundtrip").is_err() {
        return TestResult::Fail("register_loopback_named failed");
    }

    let tx = registry().with_interface("lo.smoke-roundtrip", |i| {
        i.tx_ring().lock().take()
    }).flatten();
    let rx = registry().with_interface("lo.smoke-roundtrip", |i| {
        i.rx_ring().lock().take()
    }).flatten();
    let (Some(mut tx), Some(mut rx)) = (tx, rx) else {
        return TestResult::Fail("loopback ring halves missing");
    };

    narf_scheduler::spawn(async move {
        let Ok(buf) = alloc_coherent(PAYLOAD.len(), DomainId::DRIVER_0) else {
            return;
        };
        // SAFETY: buf is exclusively owned here; identity-mapped low-RAM.
        unsafe {
            let dst = buf.phys_addr().as_mut_ptr::<u8>();
            for (i, b) in PAYLOAD.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), *b);
            }
        }
        let frame = Frame::new(buf, PAYLOAD.len() as u32);
        let _ = tx.send(frame).await;
    });

    narf_scheduler::spawn(async move {
        let Ok(frame) = rx.recv().await else {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        };
        let len = frame.len();
        GOT_LEN.store(len, Ordering::Relaxed);
        let (buf, used) = frame.into_parts();
        let mut ok = used as usize == PAYLOAD.len();
        // SAFETY: buf ownership transferred here; identity-mapped read.
        unsafe {
            let src = buf.phys_addr().as_ptr::<u8>();
            for (i, expected) in PAYLOAD.iter().enumerate() {
                if core::ptr::read_volatile(src.add(i)) != *expected {
                    ok = false; break;
                }
            }
        }
        OUTCOME.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
    });

    narf_scheduler::run_until_empty();

    if GOT_LEN.load(Ordering::Relaxed) == 0 {
        return TestResult::Fail("receiver never observed a frame");
    }
    if GOT_LEN.load(Ordering::Relaxed) as usize != PAYLOAD.len() {
        return TestResult::Fail("frame length didn't match payload length");
    }
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("payload mismatch after loopback round-trip"),
        3 => TestResult::Fail("rx recv resolved Closed before delivering a frame"),
        _ => TestResult::Fail("receiver task never ran"),
    }
}
kernel_test_in!("net", smoke_net_loopback_roundtrip);

fn smoke_net_loopback_revoked_authority() -> TestResult {
    use crate::{RegisterError, bootstrap_authority, register_loopback_named};

    narf_scheduler::init();

    let authority = bootstrap_authority();
    authority.revoke();
    match register_loopback_named(&authority, "lo.smoke-revoked") {
        Err(RegisterError::AuthorityRevoked) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error variant from revoked-authority register"),
        Ok(_)  => TestResult::Fail("register_loopback_named accepted a revoked authority"),
    }
}
kernel_test_in!("net", smoke_net_loopback_revoked_authority);

fn smoke_net_arp_request_builder() -> TestResult {
    use crate::pkt::*;
    let mut buf = [0u8; 64];
    let n = build_arp_request(
        &mut buf,
        [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        [10, 0, 2, 15],
        [10, 0, 2, 2],
    ).unwrap_or(0);
    if n != ETH_HDR_LEN + ARP_PAYLOAD_LEN {
        return TestResult::Fail("arp request len wrong");
    }
    let (eth, body) = match parse_eth_header(&buf[..n]) {
        Some(t) => t, None => return TestResult::Fail("eth parse"),
    };
    if eth.ethertype != ETHERTYPE_ARP {
        return TestResult::Fail("ethertype != ARP");
    }
    let arp = match parse_arp(body) { Some(a) => a, None => return TestResult::Fail("arp parse") };
    if arp.op != ARP_OP_REQUEST {
        return TestResult::Fail("ARP op not request");
    }
    if arp.tpa != [10, 0, 2, 2] {
        return TestResult::Fail("ARP tpa mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("net", smoke_net_arp_request_builder);

fn smoke_net_stack_attach_not_implemented() -> TestResult {
    use narf_capabilities::{Cap, Invoke, Write};
    use crate::{AttachError, NetIface, StackAttach, StackDaemon};

    let iface: Cap<NetIface, Write> = Cap::bootstrap();
    let daemon: Cap<StackDaemon, Invoke> = Cap::bootstrap();
    let req = StackAttach { iface, daemon };

    let stub = crate::virtio_net::VirtioNet::new("vnet0", [0; 6], 1500);
    match crate::stack::attach(&req, &stub) {
        Err(AttachError::NotImplemented) => {}
        _ => return TestResult::Fail("attach should surface NotImplemented"),
    }
    iface.revoke();
    match crate::stack::attach(&req, &stub) {
        Err(AttachError::IfaceCapRevoked) => {}
        _ => return TestResult::Fail("revoked iface cap should be rejected first"),
    }
    TestResult::Pass
}
kernel_test_in!("net", smoke_net_stack_attach_not_implemented);
