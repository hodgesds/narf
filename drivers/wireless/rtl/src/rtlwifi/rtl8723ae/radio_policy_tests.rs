// SPDX-License-Identifier: GPL-2.0-or-later
//! Native policy tests; no source extraction, with execution deferred.
use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

pub(in crate::rtlwifi::rtl8723ae) fn domain() -> RegulatoryDomain {
    use narf_wireless::reg::{RegFlags, RegRule};
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 40,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    }
}
pub(in crate::rtlwifi::rtl8723ae) fn curves() -> [[i16; 64]; 3] {
    let mut out = [[i16::MAX; 64]; 3];
    for family in &mut out {
        family[63] = -512;
        family[10] = 81;
        family[7] = 79;
    }
    out[0][0] = 0; // Actual source A11M=0 requires its own measurement.
    out
}
pub(in crate::rtlwifi::rtl8723ae) fn napc(
    input: &factory::Inputs,
    op: envelope::Operating,
    values: [[i16; 64]; 3],
) -> Vec<u8> {
    let mut b = vec![0; 96 + 388];
    b[..4].copy_from_slice(b"NAPC");
    b[4..8].copy_from_slice(&[2, 0, 96, 0]);
    b[8..12].copy_from_slice(&(484u32).to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x23, 0x87]);
    b[16..48].copy_from_slice(&crate::rtlwifi::radio::factory_identity(input.factory()));
    b[48..54].copy_from_slice(&input.factory().mac);
    b[58..60].copy_from_slice(&256i16.to_le_bytes());
    b[60] = 1;
    b[96] = op.channel;
    b[98] = if op.width == envelope::Width::W20 {
        20
    } else {
        40
    };
    b[99] = match op.width {
        envelope::Width::W20 => 0,
        envelope::Width::W40Above => 1,
        envelope::Width::W40Below => 2,
    };
    for (n, value) in values.iter().flatten().enumerate() {
        b[100 + n * 2..102 + n * 2].copy_from_slice(&value.to_le_bytes());
    }
    b
}
fn program(
    input: Arc<factory::Inputs>,
    op: envelope::Operating,
    values: [[i16; 64]; 3],
) -> (Program, [Cap<FirmwareBlob, Read>; 3]) {
    let caps = [Cap::bootstrap(), Cap::bootstrap(), Cap::bootstrap()];
    let bytes = napc(&input, op, values);
    let base = envelope::Calibration::from_verified(&bytes, Some([1; 32]), input.factory())
        .expect("inert NAPC")
        .bind_fixture_authority(caps[0]);
    // Requires the narrowly test-only fixture_with_source patch; production
    // Identity creation still belongs solely to successful firmware startup.
    let fw = Identity::fixture_with_source(b"inert AE signed firmware", caps[1]);
    let pg = PgStore::from_pg(&tables::PHY_REG_PG).expect("AE source PG");
    let cold = Arc::new(ColdBinding::fixture(&input, pg));
    (
        Program::bind(input, Arc::new(base), fw, cold, op).expect("inert bound program"),
        caps,
    )
}
pub(in crate::rtlwifi::rtl8723ae) fn record(program: &Program, peak: i16) -> Vec<u8> {
    let mut b = vec![0; 256];
    let a = program.inputs.adapter();
    b[..4].copy_from_slice(b"NAQR");
    b[4..8].copy_from_slice(&[1, 0, 0, 1]);
    b[8..12].copy_from_slice(&256u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x23, 0x87]);
    b[16..48].copy_from_slice(&program.request().binding);
    b[48..80].copy_from_slice(&program.base.board_identity());
    b[80..112].copy_from_slice(&program.base.digest);
    b[112..144].copy_from_slice(&program.firmware.digest);
    b[144..176].copy_from_slice(&recipe_digest());
    b[176..182].copy_from_slice(&program.inputs.factory().mac);
    b[182..188].copy_from_slice(&program.geometry());
    b[188..190].copy_from_slice(&a.version.raw().to_le_bytes());
    b[190] = u8::from(a.version.polarity() == version::Polarity::HighActive);
    b[191] = program.inputs.pa();
    b[193] = 1;
    b[194..196].copy_from_slice(&program.cold.pci[2].to_le_bytes());
    b[196..198].copy_from_slice(&program.cold.pci[3].to_le_bytes());
    b[198..204].copy_from_slice(&program.facts());
    b[206..208].copy_from_slice(&80i16.to_le_bytes());
    b[208..210].copy_from_slice(&peak.to_le_bytes());
    b
}

fn smoke_rtl8723ae_naqr_exact_binding_and_legacy_refusal() -> TestResult {
    let (p, caps) = program(
        factory::tests::inputs(),
        envelope::Operating::twenty(6),
        curves(),
    );
    let b = record(&p, 80);
    kt_assert!(QualifiedProgram::parse(p.clone(), &b, Some([1; 32]), caps[2]).is_ok());
    kt_assert!(QualifiedProgram::parse(p.clone(), &b, None, caps[2]).is_err());
    for at in [
        0, 4, 6, 8, 12, 14, 16, 48, 80, 112, 144, 176, 182, 183, 184, 185, 186, 187, 188, 190, 191,
        192, 193, 194, 196, 198, 199, 200, 201, 202, 203, 210, 255,
    ] {
        let mut bad = b.clone();
        bad[at] ^= 1;
        kt_assert!(QualifiedProgram::parse(p.clone(), &bad, Some([1; 32]), caps[2]).is_err());
    }
    for length in [0, 95, 96, 255] {
        kt_assert!(
            QualifiedProgram::parse(p.clone(), &b[..length], Some([1; 32]), caps[2]).is_err()
        );
    }
    let legacy = napc(&p.inputs, p.op, curves());
    kt_assert!(QualifiedProgram::parse(p.clone(), &legacy, Some([1; 32]), caps[2]).is_err());
    // A different physical byte changes exact request identity although the
    // logical factory SHA and existing NAPC payload are identical.
    let other = factory::tests::inputs_for(factory::tests::expected(), 0xfe);
    let (q, _) = program(other, p.op, curves());
    kt_assert_eq!(p.base.board_identity(), q.base.board_identity());
    kt_assert_eq!(p.base.digest, q.base.digest);
    kt_assert!(p.request().binding != q.request().binding);
    kt_assert!(QualifiedProgram::parse(q, &b, Some([1; 32]), caps[2]).is_err());
    TestResult::Pass
}

fn smoke_rtl8723ae_naqr_nonmonotonic_factory_search_and_exact_words() -> TestResult {
    let (p, caps) = program(
        factory::tests::inputs(),
        envelope::Operating::twenty(6),
        curves(),
    );
    // Old metadata helper selects63; source cap is10. Index10 is unsafe,
    // so min(63,10) would violate the measured bound. Correct search picks7.
    let old = p
        .base
        .permission_for(&domain(), p.op)
        .expect("inert old metadata");
    kt_assert_eq!(old.index(4), 63);
    let q = QualifiedProgram::parse(p.clone(), &record(&p, 80), Some([1; 32]), caps[2])
        .expect("inert NAQR");
    let grant = match q.grant_for(&domain()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("bounded nonmonotonic plan"),
    };
    for r in 0..20 {
        kt_assert_eq!(grant.permission().index(r), if r == 3 { 0 } else { 7 });
    }
    kt_assert_eq!(grant.plan().cck_words()[0], 0x0007_0707);
    for word in &grant.plan().ofdm_words()[..4] {
        kt_assert_eq!(word[0], 0x0707_0707);
    }
    kt_assert_eq!(grant.plan().ofdm_words()[4][0], 0x0a0a_0a0a);
    kt_assert_eq!(grant.plan().ofdm_words()[5][0], 0x0a0a_0a0a);
    let mut missing = curves();
    missing[1][7] = i16::MAX;
    let (p, c) = program(factory::tests::inputs(), p.op, missing);
    let q = QualifiedProgram::parse(p.clone(), &record(&p, 80), Some([1; 32]), c[2])
        .expect("inert missing row");
    kt_assert_eq!(
        q.grant_for(&domain()),
        Err(power(channel_power::Error::NoMeasuredGain))
    );
    let mut forced = curves();
    forced[0][0] = i16::MAX;
    let (p, c) = program(factory::tests::inputs(), p.op, forced);
    let q = QualifiedProgram::parse(p.clone(), &record(&p, 80), Some([1; 32]), c[2])
        .expect("inert forced0");
    kt_assert_eq!(
        q.grant_for(&domain()),
        Err(power(channel_power::Error::NoMeasuredGain))
    );
    TestResult::Pass
}

fn smoke_rtl8723ae_naqr_current_sources_enclose_each_operation() -> TestResult {
    for source in 0..3 {
        let (p, caps) = program(
            factory::tests::inputs(),
            envelope::Operating::twenty(6),
            curves(),
        );
        let q = QualifiedProgram::parse(p.clone(), &record(&p, 80), Some([1; 32]), caps[2])
            .expect("inert NAQR authority");
        let effects = AtomicUsize::new(0);
        kt_assert!(q
            .invoke(|| {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_ok());
        caps[source].revoke();
        kt_assert!(q
            .invoke(|| {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err());
        kt_assert_eq!(effects.load(Ordering::SeqCst), 1);
        kt_assert!(q.grant_for(&domain()).is_err());
    }
    TestResult::Pass
}

fn smoke_rtl8723ae_naqr_center_factory_index_and_calibration_peak() -> TestResult {
    let mut f = (*factory::tests::expected()).clone();
    f.logical[0x10..=0x12].copy_from_slice(&[10, 20, 30]);
    f.logical[0x16..=0x18].copy_from_slice(&[10, 20, 30]);
    let input = factory::tests::inputs_for(Arc::new(f), 0xff);
    let op = envelope::Operating {
        width: envelope::Width::W40Above,
        channel: 2,
    };
    let mut measured = [[0; 64]; 3];
    for v in &mut measured {
        v[63] = 0;
    }
    let (p, caps) = program(input, op, measured);
    kt_assert_eq!(p.geometry(), [2, 40, 6, 4, 1, 0]);
    let q = QualifiedProgram::parse(p.clone(), &record(&p, 80), Some([1; 32]), caps[2])
        .expect("inert wide NAQR");
    let grant = q.grant_for(&domain()).expect("inert measured wide grant");
    // Center4 selects group1 base20, unlike primary2 group0 base10.
    kt_assert_eq!(grant.permission().index(0), 20);
    kt_assert_eq!(grant.permission().index(4), 20);
    kt_assert_eq!(grant.plan().channel, 4);
    kt_assert!(grant.plan().forty);
    let q = QualifiedProgram::parse(p.clone(), &record(&p, 81), Some([1; 32]), caps[2])
        .expect("inert excessive peak");
    kt_assert_eq!(
        q.grant_for(&domain()),
        Err(power(channel_power::Error::Policy))
    );
    let mut no_cold = domain();
    no_cold.rules[0].freq_start_mhz = 2407;
    let q = QualifiedProgram::parse(p.clone(), &record(&p, 80), Some([1; 32]), caps[2])
        .expect("inert missing cold span");
    kt_assert!(q.grant_for(&no_cold).is_err());
    TestResult::Pass
}

struct GainRam(narf_lib::sync::IrqSafeSpinLock<Vec<u32>>);
#[async_trait::async_trait]
impl crate::rtlwifi::firmware_transport::Io for GainRam {
    fn read8(&self, r: u16) -> Result<u8, crate::rtlwifi::firmware_transport::Error> {
        Ok((self.0.lock()[usize::from(r) / 4] >> ((r & 3) * 8)) as u8)
    }
    fn read32(&self, r: u16) -> Result<u32, crate::rtlwifi::firmware_transport::Error> {
        Ok(self.0.lock()[usize::from(r) / 4])
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), crate::rtlwifi::firmware_transport::Error> {
        let mut m = self.0.lock();
        let word = &mut m[usize::from(r) / 4];
        let shift = (r & 3) * 8;
        *word = (*word & !(0xff << shift)) | (u32::from(v) << shift);
        Ok(())
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), crate::rtlwifi::firmware_transport::Error> {
        self.0.lock()[usize::from(r) / 4] = v;
        Ok(())
    }
    fn write_bytes(
        &self,
        _: u16,
        _: &[u8],
    ) -> Result<(), crate::rtlwifi::firmware_transport::Error> {
        Err(crate::rtlwifi::firmware_transport::Error::Access)
    }
}

fn smoke_rtl8723ae_bounded_power_keeps_independent_bytes_and_mcs7_tail() -> TestResult {
    let input = factory::tests::inputs();
    let pg = PgStore::from_pg(&tables::PHY_REG_PG).unwrap();
    let source = txpower::Plan::for_channel(
        &input.efuse(),
        &pg,
        6,
        false,
        false,
        txpower::DynamicPower::Normal,
    )
    .unwrap();
    let selected = [1, 2, 3, 0, 4, 5, 6, 7, 8, 9, 10, 0, 2, 4, 6, 8, 1, 3, 5, 9];
    let bounded = source.bounded(selected).unwrap();
    kt_assert_eq!(&bounded.indices()[0][..20], &selected);
    kt_assert_eq!(&bounded.indices()[0][20..], &source.indices()[0][20..]);
    kt_assert_eq!(bounded.indices()[1], source.indices()[1]);
    let io = GainRam(narf_lib::sync::IrqSafeSpinLock::new(vec![
        0xaabb_ccdd;
        0x1000 / 4
    ]));
    let mut writer = txpower::Owner::new();
    kt_assert!(writer.program(&io, &bounded).is_ok());
    let m = io.0.lock();
    kt_assert_eq!(m[0xe08 / 4], 0xaabb_01dd);
    kt_assert_eq!(m[0x86c / 4], 0x0003_0200);
    kt_assert_eq!(m[0xe00 / 4], 0x0706_0504);
    kt_assert_eq!(m[0xe04 / 4], 0x000a_0908);
    kt_assert_eq!(m[0xe10 / 4], 0x0806_0402);
    kt_assert_eq!(m[0xe14 / 4], 0x0905_0301);
    kt_assert_eq!(m[0xc90 / 4], 0xaa00_0003); // actual MCS7=9 ->3,0,0
    kt_assert_eq!(m[0xc98 / 4], 0xaa00_0000);
    kt_assert_eq!(m[0xe18 / 4], 0x0a0a_0a0a);
    kt_assert_eq!(m[0xe1c / 4], 0x0a0a_0a0a);
    drop(m);
    let mut bad = selected;
    bad[3] = 1;
    kt_assert!(source.bounded(bad).is_err());
    let mut bad = selected;
    bad[5] = 11;
    kt_assert!(source.bounded(bad).is_err());
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_naqr_exact_binding_and_legacy_refusal
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_naqr_nonmonotonic_factory_search_and_exact_words
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_naqr_current_sources_enclose_each_operation
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_naqr_center_factory_index_and_calibration_peak
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_bounded_power_keeps_independent_bytes_and_mcs7_tail
);
