//! Independent native WMI/HTC chainmask and VDEV NSS observer, not a codec echo.
use super::*;
pub(super) fn stage(d: Dialect, command: &[u8]) -> Option<u8> {
    let word = |at| {
        command
            .get(at..at + 4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
    };
    let pdev = match d {
        Dialect::Main | Dialect::Tlv => 0x4003,
        Dialect::TenFour => 0x9008,
        _ => 0x9006,
    };
    let vdev = match d {
        Dialect::Main | Dialect::Tlv => 0x5008,
        Dialect::TenOne => 0x901a,
        Dialect::TenFour => 0x901c,
        _ => 0x9019,
    };
    let p_at = if d == Dialect::Tlv { 12 } else { 4 };
    let v_at = if d == Dialect::Tlv { 12 } else { 8 };
    match (word(0), word(p_at), word(v_at)) {
        (Some(id), Some(1), _) if id == pdev => Some(0),
        (Some(id), Some(2), _) if id == pdev => Some(1),
        (Some(id), _, Some(p))
            if id == vdev
                && p == if matches!(d, Dialect::TenOne | Dialect::TenTwo | Dialect::TenTwoFour) {
                    32
                } else {
                    34
                } =>
        {
            Some(2)
        }
        _ => None,
    }
}
pub(super) async fn send(model: &mut RadioModel, bytes: &[u8], stage: u8) -> Result<(), BmiError> {
    let d = model.inner.inner.dialect;
    let word = |at: usize| u32::from_le_bytes(bytes[8 + at..12 + at].try_into().unwrap());
    let at = if d == Dialect::Tlv {
        12
    } else if stage == 2 {
        8
    } else {
        4
    };
    let expected = if stage == 2 {
        model.chain_mask.count_ones()
    } else {
        u32::from(model.chain_mask)
    };
    if usize::from(stage) != model.chain_sent.len()
        || model.phase != u8::from(stage == 2)
        || bytes.len()
            != 8 + if d == Dialect::Tlv {
                20
            } else if stage == 2 {
                16
            } else {
                12
            }
        || word(at + 4) != expected
        || d == Dialect::Tlv && word(4) != (((if stage == 2 { 95 } else { 82 }) << 16) | 12)
        || stage == 2 && word(if d == Dialect::Tlv { 8 } else { 4 }) != 0
        || d == Dialect::Tlv && stage != 2 && word(8) != 0
    {
        return Err(BmiError::BadResponse);
    }
    model.chain_sent.push(bytes.to_vec());
    model.inner.inner.rx.push_back((
        2,
        vec![
            2,
            2,
            8,
            0,
            8,
            0,
            0,
            0,
            1,
            4,
            0,
            0,
            2,
            bytes.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
    if model.chain_stall == Some(stage) {
        core::future::pending::<()>().await;
    }
    Ok(())
}
fn smoke_ath10k_native_chain_selection_uses_actual_service_ready_and_init_mask() -> TestResult {
    (|| {
        for (version, d) in [
            (1, Dialect::Main),
            (2, Dialect::TenOne),
            (3, Dialect::TenTwo),
            (4, Dialect::Tlv),
            (5, Dialect::TenTwoFour),
            (6, Dialect::TenFour),
        ] {
            for rf in 1..=4 {
                let mut r =
                    radio_boot_country_ht_rf(version, d, 1 << 10, 3, 0x8348, Some(0x79), rf);
                let hw = if d == Dialect::Tlv {
                    HwRev::Qca6174
                } else if d == Dialect::TenFour {
                    HwRev::Qca9984
                } else {
                    HwRev::Qca988x
                };
                r.htt.wmi.htc.transport.ce = Some(crate::ath10k::boot::CeFixture::new(hw));
                // The independent generic firmware model authors the
                // two-row2412/5180 inventory. Chain selection is checked on
                // that actual vector, without an unmatched single-row setup.
                if !matches!(drive(r.start(&[2412, 5180])), Poll::Ready(Ok(_))) {
                    return Err("native chain selection failed");
                }
                let m = &r.htt.wmi.htc.transport;
                let n = rf.min(if d == Dialect::TenFour { 4 } else { 3 });
                if m.chain_sent.len() != 3 || r.htt.wmi.caps.as_ref().unwrap().rf_chains != rf {
                    return Err("chain program lost actual raw facts or a native submission");
                }
                let body = r
                    .ht_capabilities()
                    .ok_or("configured HT capability absent")?;
                if body[3..3 + n as usize].iter().any(|m| *m != 255)
                    || body[3 + n as usize..13].iter().any(|m| *m != 0)
                    || (body[0] & 0x80 != 0) != (n > 1)
                {
                    return Err(
                        "HT NSS/TX STBC did not follow actual initialized/submitted chain mask",
                    );
                }
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/chains",
    smoke_ath10k_native_chain_selection_uses_actual_service_ready_and_init_mask
);
fn smoke_ath10k_native_chain_publication_cancellation_never_advertises_partial_program(
) -> TestResult {
    (|| {
        for stage in 0..3 {
            let mut r =
                radio_boot_country_ht_rf(4, Dialect::Tlv, 1 << 10, 3, 0x8348, Some(0x79), 2);
            r.htt.wmi.htc.transport.ce = Some(crate::ath10k::boot::CeFixture::new(HwRev::Qca6174));
            r.htt.wmi.htc.transport.chain_stall = Some(stage);
            if !matches!(once(r.start(&[5180])), Poll::Pending)
                || r.ready.is_some()
                || r.ht_capabilities().is_some()
                || matches!(drive(r.start(&[5180])), Poll::Ready(Ok(_)))
            {
                return Err("cancelled partial chain program advertised a reusable native owner");
            }
            let model = &r.htt.wmi.htc.transport;
            let source = model.ce.as_ref().unwrap().source_bytes(3);
            if model.chain_sent.len() != usize::from(stage)
                || self::stage(Dialect::Tlv, source.get(8..).unwrap_or_default()) != Some(stage)
            {
                return Err(
                    "cancelled chain program lost exact held native CE descriptor/bounce ownership",
                );
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/chains",
    smoke_ath10k_native_chain_publication_cancellation_never_advertises_partial_program
);
