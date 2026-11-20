// SPDX-License-Identifier: GPL-2.0-or-later
//! Native factory field order composition. Every generation runs actual
//! reset/EEPROM/PHY/calibration before its Packet/Radio/Device and DHCP.
use super::*;
use crate::ath9k::calibration::tests::factory::{self, Selection};
fn smoke_ar9285_factory_le_be_swapped_be_four_gain_profiles_native20_open_wpa2_dhcp() -> TestResult
{
    let _policy = policy();
    for minor in [1, 3] {
        for high in [false, true] {
            for xe2 in [false, true] {
                for (big, swapped) in [(false, false), (true, false), (true, true)] {
                    for protected in [false, true] {
                        let mut selected = spec(Width::Twenty, 0, protected);
                        selected.factory = Some(Selection {
                            minor,
                            high,
                            xe2,
                            big,
                            swapped,
                        });
                        let owner = Owner::new(selected);
                        if owner.join().is_err() || network(&owner).is_err() {
                            return TestResult::Fail("actual factory20 field-order/gain profile lost native association/DHCP/IP");
                        }
                        let reference = owner.reference.try_lock().unwrap();
                        let nominal = reference.as_ref().unwrap();
                        let model = owner.model();
                        let common = model.registers.borrow().get(&0x9964).copied();
                        if nominal.image != factory::image(selected.factory.unwrap())
                            || nominal.identity.big_endian_fields != big
                            || nominal.identity.eeprom_version != (0xe000 | minor)
                            || nominal.prepared.high_power_gain != high
                            || nominal.prepared.xe2_gain != xe2
                            || common != Some(0x89abcdef)
                        {
                            return TestResult::Fail("native factory20 raw image or actual selected gains/ant controls changed");
                        }
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/factory",
    smoke_ar9285_factory_le_be_swapped_be_four_gain_profiles_native20_open_wpa2_dhcp
);
fn smoke_ar9285_factory_be_full40_both_extensions_minor_versions_signed_sources_and_dhcp(
) -> TestResult {
    let _policy = policy();
    for minor in 1..=3 {
        for width in [Width::FortyAbove, Width::FortyBelow] {
            for swapped in [false, true] {
                for protected in [false, true] {
                    let mut selected = spec(width, 3, protected);
                    selected.factory = Some(Selection {
                        minor,
                        big: true,
                        swapped,
                        high: minor & 1 != 0,
                        xe2: width == Width::FortyBelow,
                    });
                    let owner = Owner::new(selected);
                    if owner.join().is_err()
                        || owner.device().channel_geometry() != Some(selected.geometry)
                        || network(&owner).is_err()
                        || owner.physical_calibrations.load(Ordering::Acquire) != 2
                    {
                        return TestResult::Fail(
                            "actual BE40 source/calibration/native DHCP composition failed",
                        );
                    }
                    let model = owner.model();
                    let actual = model.wide.borrow().unwrap();
                    if actual.powers.increment != if minor < 2 { 2 } else { 5 }
                        || (model.registers.borrow()[&0x9844] >> 7) & 127
                            != if minor < 3 { 11 } else { 27 }
                        || model.registers.borrow()[&0x9964] != 0x89abcdef
                    {
                        return TestResult::Fail(
                            "BE40 current power compensation/modal version/ant controls incorrect",
                        );
                    }
                    // B/T/Q3 requests bind the complete raw-BE H3 body; neither old
                    // LE recipes nor T4 membership is inferred by byte-order support.
                    if !owner.device().radio.try_lock().unwrap().can_aggregate() {
                        return TestResult::Fail("BE40 signed T3 sender setup did not complete");
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/factory",
    smoke_ar9285_factory_be_full40_both_extensions_minor_versions_signed_sources_and_dhcp
);
fn smoke_ar9285_factory_raw_hash_foreign_le_body_and_current_be_copy_source_fail_closed(
) -> TestResult {
    let _policy = policy();
    let selected = Selection {
        minor: 3,
        big: false,
        swapped: false,
        high: false,
        xe2: false,
    };
    let le = calibration::tests::channel_receipt_factory(
        2437,
        40,
        factory::image(selected),
        false,
        false,
    )
    .unwrap();
    let be = calibration::tests::channel_receipt_factory(
        2437,
        40,
        factory::image(Selection {
            big: true,
            ..selected
        }),
        true,
        false,
    )
    .unwrap();
    let facts = |receipt: &calibration::tests::ChannelReceipt| {
        ht::Facts::new(
            ht::tests::model_device(),
            receipt.identity,
            receipt.prepared,
            receipt.report,
            &receipt.image,
        )
        .unwrap()
    };
    let le_facts = facts(&le);
    let be_facts = facts(&be);
    if le_facts.request().identity == be_facts.request().identity || le.report != be.report {
        return TestResult::Fail(
            "raw BE source identity aliased LE despite identical actual report",
        );
    }
    let cap = Cap::<FirmwareBlob, Read>::bootstrap();
    if (ht::Source::Verified {
        bytes: ht::tests::record(&le_facts, 255),
        signer: Some([0x85; 32]),
        cap,
    })
    .load(be_facts)
    .is_ok()
    {
        return TestResult::Fail("foreign LE signed body granted raw BE profile");
    }
    let mut chosen = spec(Width::FortyAbove, 3, true);
    chosen.factory = Some(Selection {
        big: true,
        ..selected
    });
    let owner = Owner::new(chosen);
    if owner.join().is_err() || network(&owner).is_err() {
        return TestResult::Fail("BE current-source fixture setup");
    }
    let device = owner.device();
    let model = owner.model();
    let peer = owner.peer();
    let plan = peer.lock().plan;
    // Drain prior copied DHCP/IP first; revocation occurs at the actual next
    // native copy boundary, not by returning a manufactured host receipt.
    {
        let mut slot = device.rx_ring().lock();
        let ring = slot.as_mut().unwrap();
        while let Ok(Some(_)) = ring.try_recv() {}
    }
    let source = owner.qualification.lock().unwrap();
    *device.receive_hook.lock() = Some(Arc::new(move |point| {
        if point == ReceivePoint::AfterFrameAllocation {
            source.revoke();
        }
    }));
    let down = udp_ipv4(
        plan.station,
        AP,
        plan.server_ip,
        plan.lease_ip,
        7,
        4850,
        b"BE source revoked after actual copy",
    );
    let wire = peer.lock().downlink(&down).unwrap();
    model.inject(&wire, 0).unwrap();
    owner.pump();
    let mut slot = device.rx_ring().lock();
    let ring = slot.as_mut().unwrap();
    if matches!(ring.try_recv(), Ok(Some(_))) || device.link_up() {
        return TestResult::Fail("revoked BE source escaped real copy/host link closure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/factory",
    smoke_ar9285_factory_raw_hash_foreign_le_body_and_current_be_copy_source_fail_closed
);
