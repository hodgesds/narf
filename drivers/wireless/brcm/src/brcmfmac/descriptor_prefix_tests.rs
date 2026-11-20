// SPDX-License-Identifier: GPL-2.0-or-later
//! Real common-ring owners, original firmware strides and independent writes.
use super::*;
use crate::brcmfmac::msgbuf;

fn prefixed() -> (runtime::Runtime<Model>, Rc<IrqSafeSpinLock<State>>) {
    let (bus, state) = model();
    {
        let mut s = state.lock();
        put(&mut s, SHARED, &7u32.to_le_bytes());
        put(&mut s, SHARED + 36, &4u32.to_le_bytes());
    }
    (runtime::Runtime::attach(booted(bus)).unwrap(), state)
}
fn smoke_brcmf_prefix_geometry_rejects_before_any_dma_allocation_or_publication() -> TestResult {
    for version in [5, 6, 7] {
        for prefix in [0, 1, 2, 3, 4, 5, 8, 24, u32::MAX] {
            let admitted = prefix == 0 || version == 7 && prefix <= 4;
            if msgbuf::completion_prefix(version, prefix).is_some() != admitted {
                return TestResult::Fail("prefix crossed the original control/TX/RX stride");
            }
            let (bus, state) = model();
            {
                let mut s = state.lock();
                put(&mut s, SHARED, &u32::from(version).to_le_bytes());
                put(&mut s, SHARED + 36, &prefix.to_le_bytes());
            }
            // First exercise actual CR4 download/metadata admission, not only
            // a constructed Booted value. All cases still have BME disabled.
            let nvram = boot::pack_nvram(b"boardrev=1\n").unwrap();
            let boot = boot::Cr4::claim(bus, pci(), profile())
                .and_then(|cr4| cr4.boot(&[0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6], &nvram));
            if boot.is_ok() != admitted {
                return TestResult::Fail("CR4 readiness accepted an unbounded descriptor prefix");
            }
            if let Ok(boot) = boot {
                drop(boot);
            }
            let s = state.lock();
            if s.allocated != 0 || s.dma_enable || s.dma_enables != 0 {
                return TestResult::Fail("geometry admission allocated or published DMA");
            }
            drop(s);
            if !admitted {
                // attach is also a boundary: a previously parsed Booted must
                // not bypass the same check before its first allocation.
                let result = runtime::Runtime::attach(booted(Model(state.clone())));
                if !matches!(result, Err(runtime::Error::Protocol))
                    || state.lock().allocated != 0
                    || state.lock().dma_enables != 0
                {
                    return TestResult::Fail("runtime bypassed original geometry admission");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/prefix",
    smoke_brcmf_prefix_geometry_rejects_before_any_dma_allocation_or_publication
);

fn smoke_brcmf_prefixed_control_keeps_original_stride_correlations_and_wrap() -> TestResult {
    let (bus, state) = model();
    {
        let mut s = state.lock();
        put(&mut s, SHARED, &7u32.to_le_bytes());
        put(&mut s, SHARED + 36, &4u32.to_le_bytes());
        s.firmware = Some(Firmware::default());
    }
    let mut owner = runtime::Runtime::attach(booted(bus)).unwrap();
    for _ in 0..72 {
        let ticket = owner.begin_ioctl(1, &[], 4).unwrap();
        if owner.poll() != Ok(1)
            || !matches!(owner.take_response(&ticket), Ok(Some(Ok(bytes))) if bytes == 2u32.to_le_bytes())
        {
            return TestResult::Fail(
                "prefixed IOCTL lost actual transaction/command/buffer correlation",
            );
        }
    }
    let s = state.lock();
    for (ring, stride) in [(2, 24), (3, 24), (4, 40)] {
        if word(&s, RINGS + ring * 16 + 4) >> 16 != stride {
            return TestResult::Fail("host enlarged firmware ring stride for a prefix");
        }
    }
    let control = pointer(&s, RINGS + 2 * 16 + 8);
    if word(&s, D2HW) as u16 != 8
        || word(&s, D2HR) as u16 != 8
        || s.dma[&control]
            .chunks_exact(24)
            .any(|e| e[..4] != [0xa5; 4])
        || s.unsafe_free != 0
    {
        return TestResult::Fail("completion prefix, last-slot wrap or copy-before-retire lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/prefix",
    smoke_brcmf_prefixed_control_keeps_original_stride_correlations_and_wrap
);

fn smoke_brcmf_prefixed_rx_uses_explicit_or_shared_offset_and_retains_bad_native_owner(
) -> TestResult {
    for offset in [0u16, 256, u16::MAX] {
        let (mut owner, state) = prefixed();
        owner.enable_data().unwrap();
        let frame = ethernet();
        let (id, body) = {
            let mut s = state.lock();
            let posts = pointer(&s, RINGS + 16 + 8);
            let post = &s.dma[&posts][..32];
            let id = u32::from_le_bytes(post[4..8].try_into().unwrap());
            let body = u64::from_le_bytes(post[24..32].try_into().unwrap());
            if offset != u16::MAX {
                let at = if offset == 0 { 4 } else { usize::from(offset) };
                let memory = s.dma.get_mut(&body).unwrap();
                memory[..at].fill(0xa5);
                memory[at..at + frame.len()].copy_from_slice(&frame);
            }
            let entry = completion_entry(&mut s, 4, 0);
            entry[0] = 0x12;
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[14..16].copy_from_slice(&(frame.len() as u16).to_le_bytes());
            entry[16..18].copy_from_slice(&offset.to_le_bytes());
            entry[18..20].copy_from_slice(&1u16.to_le_bytes());
            put(&mut s, D2HW + 8, &1u16.to_le_bytes());
            (id, body)
        };
        if offset == u16::MAX {
            if owner.poll() != Err(runtime::Error::Bounds) || !owner.is_failed() {
                return TestResult::Fail("explicit RX extent escaped original posted DMA span");
            }
        } else {
            if owner.poll() != Ok(1) || owner.pop_received().as_deref() != Some(frame.as_slice()) {
                return TestResult::Fail("shared and explicit RX offsets were summed or ignored");
            }
            let mut s = state.lock();
            let posts = pointer(&s, RINGS + 16 + 8);
            let producer = word(&s, H2DW + 4) as usize & 0xffff;
            let repost = &s.dma[&posts][(producer - 1) * 32..producer * 32];
            if repost[0] != 0x11 || repost[4..8] == id.to_le_bytes() {
                return TestResult::Fail(
                    "prefixed RX did not repost with fresh original-buffer identity",
                );
            }
            let entry = completion_entry(&mut s, 4, 1);
            entry[0] = 0x12;
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[14..16].copy_from_slice(&(frame.len() as u16).to_le_bytes());
            put(&mut s, D2HW + 8, &2u16.to_le_bytes());
            drop(s);
            if owner.poll() != Err(runtime::Error::Protocol) || !owner.is_failed() {
                return TestResult::Fail("prefixed stale RX identity rebound to reposted DMA");
            }
        }
        drop(owner);
        let s = state.lock();
        if s.dma_enable || s.dropped_addresses.contains(&body) || s.unsafe_free != 0 {
            return TestResult::Fail("bad prefixed completion reclaimed uncertain native DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/prefix",
    smoke_brcmf_prefixed_rx_uses_explicit_or_shared_offset_and_retains_bad_native_owner
);

fn smoke_brcmf_prefixed_tx_requires_actual_matching_air_terminal_before_release() -> TestResult {
    for wrong in [false, true] {
        let (mut owner, state) = prefixed();
        owner.enable_data().unwrap();
        let frame = ethernet();
        let flow = owner
            .open_flow(
                frame[6..12].try_into().unwrap(),
                frame[..6].try_into().unwrap(),
                0,
            )
            .unwrap();
        flow_reply(&mut state.lock(), 0, 4, 2);
        if owner.poll() != Ok(1) {
            return TestResult::Fail("prefixed native flow creation failed");
        }
        let id = owner.send(flow, &frame).unwrap();
        let body = {
            let s = state.lock();
            let submits = pointer(&s, RINGS + 8);
            let create = &s.dma[&submits][16 * 40..17 * 40];
            let flow_address = u64::from_le_bytes(create[32..40].try_into().unwrap());
            let tx = &s.dma[&flow_address][..48];
            u64::from_le_bytes(tx[32..40].try_into().unwrap())
        };
        if state.lock().dropped_addresses.contains(&body) || owner.pop_tx_receipt().is_some() {
            return TestResult::Fail("submit or flow receipt retired actual TX DMA");
        }
        {
            let mut s = state.lock();
            let entry = completion_entry(&mut s, 3, 0);
            entry[0] = 0x10;
            entry[4..8].copy_from_slice(&(id + u32::from(wrong)).to_le_bytes());
            entry[10..12].copy_from_slice(&2u16.to_le_bytes());
            put(&mut s, D2HW + 4, &1u16.to_le_bytes());
        }
        if wrong {
            if owner.poll() != Err(runtime::Error::Protocol) || owner.pop_tx_receipt().is_some() {
                return TestResult::Fail("wrong prefixed terminal fabricated completion credit");
            }
            drop(owner);
            if state.lock().dropped_addresses.contains(&body) {
                return TestResult::Fail("wrong terminal freed uncertain TX mapping");
            }
        } else if owner.poll() != Ok(1)
            || owner.pop_tx_receipt().is_none_or(|r| r.id != id)
            || !state.lock().dropped_addresses.contains(&body)
            || state.lock().unsafe_free != 0
        {
            return TestResult::Fail("matching copied native TX terminal failed safe retirement");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/prefix",
    smoke_brcmf_prefixed_tx_requires_actual_matching_air_terminal_before_release
);
