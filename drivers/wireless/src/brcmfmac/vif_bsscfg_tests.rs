// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-bsscfg Fullmac adapter over the scripted seam: Linux 7.3-rc4
//! `fwil.c` `brcmf_fil_bsscfg_*` vs `brcmf_fil_iovar_*` addressing,
//! `fweh.c` per-bsscfg event dispatch and `brcmf_get_ifp` data routing.
use super::{
    vif_bsscfg::{wire_command, Bsscfg, Link, Parked},
    vif_owner::{Owner, Role},
    vif_wire::Features,
};
use crate::cyw43439::{
    fullmac::Fullmac,
    fullmac_fixture::{ready, Firmware, Mock},
    ioctl::Direction,
    runtime::Error,
};
use alloc::{boxed::Box, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const PRIMARY: [u8; 6] = [0x00, 0x90, 0x4c, 0x11, 0x22, 0x33];
const VIF: [u8; 6] = [0x02, 0x90, 0x4c, 0xb1, 0x22, 0x33];
const PEER: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

fn iovar(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = name.to_vec();
    out.push(0);
    out.extend_from_slice(data);
    out
}

fn smoke_brcmf_vif_bsscfg_adapter_addresses_its_own_interface() -> TestResult {
    // brcmf_create_bsscfg wire form; plain iovars and dcmds are unchanged.
    let mut prefixed = b"bsscfg:wsec\0".to_vec();
    prefixed.extend_from_slice(&2u32.to_le_bytes());
    prefixed.extend_from_slice(&4u32.to_le_bytes());
    if wire_command(2, 263, &iovar(b"wsec", &4u32.to_le_bytes())) != Ok(Some(prefixed.clone()))
        || wire_command(2, 263, &iovar(b"cur_etheraddr", &VIF)) != Ok(None)
        || wire_command(2, 20, &1u32.to_le_bytes()) != Ok(None)
        || wire_command(2, 262, b"wsec") != Err(Error::Malformed)
    {
        return TestResult::Fail("bsscfg iovar classification differs from fwil.c");
    }
    let mut fw = Firmware::new();
    fw.hook = Some(Box::new(|fw, command| {
        if command.direction == Direction::Get && command.iovar() == Some(b"interface_create") {
            fw.if_event(1, 1, 2, 1, VIF);
            return Some(Ok(Vec::new()));
        }
        None
    }));
    let mut runtime = Mock::<true>::new(fw);
    let mut owner = Owner::new(PRIMARY, Features::default());
    let Some(Ok(entry)) = ready(owner.create(&mut runtime, Role::Ap, None)) else {
        return TestResult::Fail("secondary interface create");
    };
    if runtime.vif_open(entry.ifidx).is_err() {
        return TestResult::Fail("vif_open");
    }
    let mut link = Link::new(entry);
    let before = runtime.fw.vif_log.len();
    {
        let mut adapter = Bsscfg::new(&mut runtime, &mut owner, &mut link);
        let wsec = iovar(b"wsec", &4u32.to_le_bytes());
        let mac = iovar(b"cur_etheraddr", &VIF);
        if ready(adapter.command(Direction::Set, 263, &wsec, 1502)).is_none()
            || ready(adapter.command(Direction::Set, 263, &mac, 1502)).is_none()
            || ready(adapter.command(Direction::Set, 20, &1u32.to_le_bytes(), 4)).is_none()
        {
            return TestResult::Fail("adapter command did not complete");
        }
    }
    let log = &runtime.fw.vif_log[before..];
    if log.len() != 3
        || log.iter().any(|(ifidx, _)| *ifidx != 1)
        || log[0].1.body != prefixed
        || log[1].1.body != iovar(b"cur_etheraddr", &VIF)
        || log[2].1.command != 20
    {
        return TestResult::Fail("adapter commands not addressed to ifidx/bsscfg");
    }
    // Events: only this bsscfg's; interface-0 events stay with the primary.
    runtime.fw.secondary_event(16, 1, 2, PEER, &[]);
    runtime.fw.secondary_event(16, 3, 3, PEER, &[]);
    runtime.fw.event(16, 0, 0, PEER, &[]);
    runtime.fw.vif_data.push_back((1, alloc::vec![0xaa; 20]));
    runtime.fw.vif_data.push_back((2, alloc::vec![0xbb; 20]));
    {
        let mut adapter = Bsscfg::new(&mut runtime, &mut owner, &mut link);
        if adapter.poll().is_err()
            || adapter.pop_event().map(|e| e.header.bsscfg_idx) != Some(2)
            || adapter.pop_event().is_some()
            || adapter.pop_data() != Some(alloc::vec![0xaa; 20])
            || adapter.pop_data().is_some()
            || adapter.send_data(&[0xcc; 20], 5).is_err()
        {
            return TestResult::Fail("adapter event/data routing");
        }
        adapter.set_link(Some(PEER));
    }
    if runtime.pop_event().map(|e| e.header.bsscfg_idx) != Some(0)
        || runtime.fw.vif_sent.last().map(|(i, _, p)| (*i, *p)) != Some((1, 5))
        || link.peer() != Some(PEER)
    {
        return TestResult::Fail("primary queues or link record disturbed");
    }
    // Unsolicited IF DEL: the adapter fail-stops locally, primary intact.
    runtime.fw.if_event(2, 1, 2, 1, VIF);
    let before = runtime.fw.vif_log.len();
    {
        let mut adapter = Bsscfg::new(&mut runtime, &mut owner, &mut link);
        if adapter.poll() != Err(Error::Failed)
            || ready(adapter.command(Direction::Set, 20, &1u32.to_le_bytes(), 4))
                != Some(Err(Error::Failed))
            || !adapter.transport_failed()
        {
            return TestResult::Fail("retired bsscfg kept command authority");
        }
    }
    if !link.failed()
        || link.peer().is_some()
        || runtime.fw.vif_log.len() != before
        || runtime.fw.failed
        || ready(runtime.command(Direction::Get, 1, &[0; 4], 4)).is_none()
    {
        return TestResult::Fail("bsscfg failure leaked to the primary");
    }
    let mut parked = Parked::<Mock<true>>::new();
    if parked.poll() != Err(Error::Failed)
        || ready(parked.command(Direction::Get, 1, &[], 4)) != Some(Err(Error::Failed))
    {
        return TestResult::Fail("parked runtime accepted work");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_vif_bsscfg_adapter_addresses_its_own_interface
);
