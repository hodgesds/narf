// SPDX-License-Identifier: GPL-2.0-or-later
//! Compose distinct N85T4 with actual fresh H3 calibration/native owners.
use super::*;
fn smoke_ar9285_large_tx_actual_ht40_both_extensions_directional_sgi_density_and_dhcp() -> TestResult
{
    let _policy = policy();
    for width in [Width::FortyAbove, Width::FortyBelow] {
        for gi in [0, 3] {
            for protected in [false, true] {
                for mcs in [0usize, 7] {
                    let mut selected = spec(width, gi, protected);
                    selected.large = true;
                    selected.mask = 1 << mcs;
                    let owner = Owner::new(selected);
                    if owner.join().is_err() || network(&owner).is_err() {
                        return TestResult::Fail(
                            "distinct T4 did not compose actual fresh40 calibration/DHCP",
                        );
                    }
                    let device = owner.device();
                    let model = owner.model();
                    let peer = owner.peer();
                    let plan = peer.lock().plan;
                    let frames: Vec<Vec<u8>> = (0..8)
                        .map(|index| {
                            udp_ipv4(
                                AP,
                                plan.station,
                                plan.lease_ip,
                                plan.server_ip,
                                4880 + index,
                                7,
                                &[index as u8; 16],
                            )
                        })
                        .collect();
                    for frame in &frames {
                        device.enqueue(frame, narf_net::TxMeta::plain()).unwrap();
                    }
                    owner.pump();
                    let chain = model.last_chain.borrow().clone();
                    if chain.len() != 8 {
                        return TestResult::Fail(
                            "wide current IPC sender did not publish eight actual links",
                        );
                    }
                    let mut air = 0u32;
                    let bits = [54u32, 108, 162, 216, 324, 432, 486, 540][mcs];
                    for (index, descriptor) in chain.iter().enumerate() {
                        let length = model.word(*descriptor + 8).unwrap() & 4095; //Original+FCS.
                        air += length + 4;
                        let padding = if index == 7 {
                            0
                        } else {
                            let minimum = 256u32.saturating_sub(length).div_ceil(4);
                            // Source floor(16/4) and floor((16*5-4)/18)
                            // both give4 symbols. The PPDU duration below
                            // still independently distinguishes LGI/SGI.
                            let symbols = 4;
                            let density = (symbols * bits / 8).saturating_sub(length) / 4;
                            minimum.max(density)
                        };
                        if index != 7 {
                            air = air.next_multiple_of(4) + padding * 4;
                        }
                        if model.word(*descriptor + 32).unwrap() >> 18 != padding {
                            return TestResult::Fail(
                                "per-middle delimiter ignored real16us/width/GI density",
                            );
                        }
                    }
                    let symbols = (air * 8 + 22).div_ceil(bits);
                    let duration = 36
                        + if gi != 0 {
                            (symbols * 18).div_ceil(5)
                        } else {
                            symbols * 4
                        };
                    if model.word(chain[0] + 32).unwrap() & 65535 != air
                        || model.word(chain[0] + 24).unwrap() & 0x7fff != duration
                        || model.word(chain[0] + 36).unwrap() & 3 != if gi != 0 { 3 } else { 1 }
                        || !peer.lock().uplink.ends_with(&frames)
                    {
                        return TestResult::Fail(
                            "wide chain duration/GI/air/original delivery mismatch",
                        );
                    }
                    if gi != 0 && mcs == 0 {
                        let large: Vec<Vec<u8>> = (0..5)
                            .map(|index| {
                                udp_ipv4(
                                    AP,
                                    plan.station,
                                    plan.lease_ip,
                                    plan.server_ip,
                                    4890 + index,
                                    7,
                                    &[index as u8; 1338],
                                )
                            })
                            .collect();
                        let refs: Vec<&[u8]> = large.iter().map(Vec::as_slice).collect();
                        if device.radio.try_lock().unwrap().aggregate_count(&refs) != Ok(5) {
                            return TestResult::Fail("initial SGI current4ms prefix incorrect");
                        }
                        let mut offer = elements(selected.geometry, false);
                        offer[4] = 28;
                        peer.lock().ht = Some(offer);
                        let beacon = peer.lock().beacon();
                        model.inject(&beacon, 0).unwrap();
                        owner.pump();
                        if device.radio.try_lock().unwrap().aggregate_count(&refs) != Ok(4) {
                            return TestResult::Fail(
                                "current beacon SGI loss left stale sender4ms admission",
                            );
                        }
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/large-tx",
    smoke_ar9285_large_tx_actual_ht40_both_extensions_directional_sgi_density_and_dhcp
);
