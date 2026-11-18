// SPDX-License-Identifier: GPL-2.0-or-later
//! Conservative NASR content binding to selected actual source helpers.
//! This identifies source inputs, not a signed executable, compiler/toolchain
//! identity, full dependency graph, calibration measurement or physical proof.
//! Even a nonfunctional edit of an included source invalidates old NASR.
use narf_crypto::sha256::Sha256;
use narf_lib::sync::OnceLock;

// Explicit scope: no filesystem access, build script, generated binary,
// external dependency or whole-repository fingerprint. Include the shared
// rtl8723com-identical RF scalar body actually called by AE coexistence.
const SOURCES: &[(&[u8], &[u8])] = &[
    (b"AE/source_program.rs", include_bytes!("source_program.rs")),
    (b"AE/station_policy.rs", include_bytes!("station_policy.rs")),
    (b"AE/envelope.rs", include_bytes!("envelope.rs")),
    (b"AE/ps.rs", include_bytes!("ps.rs")),
    (b"AE/station.rs", include_bytes!("station.rs")),
    (b"AE/mac.rs", include_bytes!("mac.rs")),
    (b"AE/trx.rs", include_bytes!("trx.rs")),
    (b"AE/packet_owner.rs", include_bytes!("packet_owner.rs")),
    (b"AE/h2c.rs", include_bytes!("h2c.rs")),
    (b"AE/ht.rs", include_bytes!("ht.rs")),
    (b"AE/aspm.rs", include_bytes!("aspm.rs")),
    (b"AE/irq.rs", include_bytes!("irq.rs")),
    (b"AE/coex.rs", include_bytes!("coex.rs")),
    (b"AE/dm.rs", include_bytes!("dm.rs")),
    (b"AE/c2h.rs", include_bytes!("c2h.rs")),
    (b"AE/phy.rs", include_bytes!("phy.rs")),
    (
        b"rtlwifi/rtl8723be/phy.rs",
        include_bytes!("../rtl8723be/phy.rs"),
    ),
    (b"AE/iqk.rs", include_bytes!("iqk.rs")),
    (b"AE/txpower.rs", include_bytes!("txpower.rs")),
    (b"AE/tables.rs", include_bytes!("tables.rs")),
    (b"AE/station_native.rs", include_bytes!("station_native.rs")),
    (b"AE/reserved.rs", include_bytes!("reserved.rs")),
    (b"AE/radio_switch.rs", include_bytes!("radio_switch.rs")),
    (b"AE/ring_owner.rs", include_bytes!("ring_owner.rs")),
    (
        b"AE/native_activation.rs",
        include_bytes!("native_activation.rs"),
    ),
    (b"AE/station_owner.rs", include_bytes!("station_owner.rs")),
    (b"AE/retained.rs", include_bytes!("retained.rs")),
    (b"AE/park.rs", include_bytes!("park.rs")),
    (b"AE/park_native.rs", include_bytes!("park_native.rs")),
    (
        b"rtlwifi/watchdog_traffic.rs",
        include_bytes!("../watchdog_traffic.rs"),
    ),
    (b"rtlwifi/station.rs", include_bytes!("../station.rs")),
    (b"rtlwifi/packet.rs", include_bytes!("../packet.rs")),
    (b"rtlwifi/aspm.rs", include_bytes!("../aspm.rs")),
    (
        b"rtlwifi/aspm_native.rs",
        include_bytes!("../aspm_native.rs"),
    ),
    (
        b"rtlwifi/prepare_native.rs",
        include_bytes!("../prepare_native.rs"),
    ),
    (
        b"rtlwifi/station_power.rs",
        include_bytes!("../station_power.rs"),
    ),
    (b"rtlwifi/interface.rs", include_bytes!("../interface.rs")),
    (
        b"rtlwifi/firmware_transport.rs",
        include_bytes!("../firmware_transport.rs"),
    ),
];
static DIGEST: OnceLock<[u8; 32]> = OnceLock::new();
fn compute(sources: &[(&[u8], &[u8])]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"NARF RTL8723AE NASR selected source inputs v1\0");
    h.update(&(sources.len() as u64).to_le_bytes());
    for (name, bytes) in sources {
        h.update(&(name.len() as u64).to_le_bytes());
        h.update(name);
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    h.finalize()
}
pub(super) fn digest() -> [u8; 32] {
    *DIGEST.get_or_init(|| compute(SOURCES))
}

#[cfg(any(test, feature = "kernel-test"))]
fn smoke_ae_nasr_source_identity_frames_names_lengths_and_order() -> narf_kernel_test::TestResult {
    use narf_kernel_test::{kt_assert, TestResult};
    // Both unframed byte streams would be "abc". Different helper names
    // or name/body boundaries must not reuse one station recipe identity.
    kt_assert!(compute(&[(b"ab", b"c")]) != compute(&[(b"a", b"bc")]));
    kt_assert!(compute(&[(b"a", b"bc")]) != compute(&[(b"a", b"bd")]));
    kt_assert!(compute(&[(b"a", b"x"), (b"b", b"y")]) != compute(&[(b"b", b"y"), (b"a", b"x")]));
    kt_assert!(compute(&[(b"a", b"x")]) != compute(&[(b"a", b"x"), (b"", b"")]));
    kt_assert!(digest() != compute(&[]));
    TestResult::Pass
}
#[cfg(any(test, feature = "kernel-test"))]
narf_kernel_test::kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_nasr_source_identity_frames_names_lengths_and_order}
