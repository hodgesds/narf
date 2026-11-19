//! Literal codecs accompany actual native owner cases. SESSION fixtures
//! deliberately grant no API77/API89 native role or PHY/power receipt.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn check(condition: bool, error: &'static str) -> Result<(), &'static str> {
    condition.then_some(()).ok_or(error)
}
fn api(commands: &[u8], session: bool) -> FirmwareApi<'_> {
    let mut api = FirmwareApi {
        commands,
        ..Default::default()
    };
    if session {
        api.capabilities[1] = 1 << 22; // IWL_UCODE_TLV_CAPA_SESSION_PROT_CMD54
    }
    api
}
pub(super) fn actual_metadata_and_target_classes() -> Result<(), &'static str> {
    let roc = [8, 3, 3, 0, 0x0e, 3, 6, 0, 0xf8, 3, 99, 1];
    let session1 = [8, 3, 1, 0, 5, 3, 1, 0, 0xfb, 3, 99, 2];
    let session2 = [
        8, 3, 2, 0, 5, 3, 2, 0, 0xfb, 3, 99, 3, 0x0e, 3, 3, 0, 0xf8, 3, 99, 1,
    ];
    check(
        Abi::read(&api(&roc, false)) == Ok(Abi::Roc6)
            && Abi::read(&api(&session1, true)) == Ok(Abi::Session1)
            && Abi::read(&api(&session2, true)) == Ok(Abi::Session2),
        "P2P actual metadata did not select its literal native ABI",
    )?;
    check(
        Abi::read(&api(&session1, false)).is_err() && Abi::read(&api(&session2, false)).is_err(),
        "P2P session version substituted for actual capability54",
    )?;
    for offset in [2, 6, 11] {
        let mut wrong = session1;
        wrong[offset] ^= 1;
        check(
            Abi::read(&api(&wrong, true)).is_err(),
            "P2P incompatible MAC/session/notification shape admitted",
        )?;
    }
    let mut aux_version = session2;
    aux_version[14] = 4;
    check(
        Abi::read(&api(&aux_version, true)).is_err(),
        "P2P ROCv4 source reused the API89 session-only adapter",
    )?;
    let duration = Duration::from_ms(100)?;
    check(
        Abi::Session1
            .session_add(Target::Link(1), Activity::Discover, duration)
            .is_err()
            && Abi::Session2
                .session_add(Target::Mac(1), Activity::Discover, duration)
                .is_err()
            && Abi::Roc6
                .session_add(Target::Link(1), Activity::Discover, duration)
                .is_err(),
        "P2P observed MAC/FW-link identity became an interchangeable selector",
    )
}
pub(super) fn literal_roc_and_notification_extents() -> Result<(), &'static str> {
    let duration = Duration::from_ms(200)?;
    check(
        duration.microseconds() == 199_680
            && Duration::from_ms(0).is_err()
            && Duration::from_ms(1).is_err()
            && Duration::from_ms(u32::MAX).is_err(),
        "P2P finite native TU conversion overflowed or rounded up",
    )?;
    let channel = Channel::legacy(6).ok_or("P2P fixture channel invalid")?;
    let command = Abi::Roc6.roc_add(
        Activity::Discover,
        10,
        channel,
        [2, 0, 0, 0, 0, 7],
        duration,
    )?;
    check(
        command
            == [
                1, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 6, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 7, 0,
                0, 195, 0, 0, 0, 195, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        "P2P ROCv6 actual44-byte payload differs from primary source",
    )?;
    let mut removed = [0; 44];
    removed[0] = 3;
    removed[4] = 1;
    check(
        Abi::Roc6.roc_remove(Activity::Discover)? == removed,
        "P2P ROC REMOVE leaked old duration/STA/channel fields",
    )?;
    let started = [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0];
    check(
        Abi::Roc6.roc_notification(Activity::Discover, &started)?
            == Notification {
                success: true,
                started: true,
            }
            && Abi::Roc6
                .roc_notification(Activity::Negotiate, &started)
                .is_err()
            && Abi::Roc6
                .roc_notification(Activity::Discover, &started[..11])
                .is_err(),
        "P2P ROC notification accepted another activity or a short extent",
    )?;
    let mut invalid = started;
    invalid[4] = 2;
    check(
        Abi::Roc6
            .roc_notification(Activity::Discover, &invalid)
            .is_err(),
        "P2P malformed native START flag became a matching notification",
    )?;
    let mut failed_start = started;
    failed_start[0] = 0;
    check(
        Abi::Roc6.roc_notification(Activity::Discover, &failed_start)?
            == Notification {
                success: false,
                started: true,
            },
        "P2P failed START was lost instead of requiring native removal",
    )
}
pub(super) fn literal_session_targets_and_configurations() -> Result<(), &'static str> {
    for (abi, target, id) in [
        (Abi::Session1, Target::Mac(1), 1),
        (Abi::Session2, Target::Link(1), 1),
    ] {
        let duration = Duration::from_ms(100)?;
        check(
            abi.session_add(target, Activity::Negotiate, duration)?
                == [
                    id, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
                && abi.session_remove(target, Activity::Negotiate)?
                    == [
                        id, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ],
            "P2P session literal target/ADD/REMOVE/configuration payload differs",
        )?;
        let notification = [id, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0];
        check(
            abi.session_notification(target, Activity::Negotiate, &notification)?
                == Notification {
                    success: true,
                    started: true,
                }
                && abi
                    .session_notification(target, Activity::Discover, &notification)
                    .is_err()
                && abi
                    .session_notification(target, Activity::Negotiate, &notification[..15])
                    .is_err(),
            "P2P session accepted wrong config/short native notification",
        )?;
        let mut foreign = notification;
        foreign[0] ^= 1;
        check(
            abi.session_notification(target, Activity::Negotiate, &foreign)
                .is_err(),
            "P2P foreign native MAC/FW-link opened the current session",
        )?;
    }
    Ok(())
}
fn smoke_iwl_p2p_literal_native_roc_and_disjoint_session_codecs() -> TestResult {
    actual_metadata_and_target_classes()
        .and_then(|_| literal_roc_and_notification_extents())
        .and_then(|_| literal_session_targets_and_configurations())
        .map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p",
    smoke_iwl_p2p_literal_native_roc_and_disjoint_session_codecs
);
