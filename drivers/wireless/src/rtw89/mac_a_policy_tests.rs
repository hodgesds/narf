// Explicit inert authenticated boundary used only by Native adapter cases.
pub(in crate::rtw89) fn model() -> (Qualification, Cap<FirmwareBlob, Read>) {
    let cap = Cap::bootstrap();
    let board = Board {
        identity: [7; 32],
        mac: [2, 4, 6, 8, 10, 12],
        device: 0x8852,
    };
    (
        Qualification::decode(&image(board, b"N5AM"), Some([3; 32]), board, cap).unwrap(),
        cap,
    )
}
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn image(board: Board, magic: &[u8; 4]) -> [u8; 96] {
    let mut out = [0; 96];
    out[..4].copy_from_slice(magic);
    out[4..8].copy_from_slice(&[1, 0, 96, 0]);
    out[8..12].copy_from_slice(&96u32.to_le_bytes());
    out[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    out[14..16].copy_from_slice(&board.device.to_le_bytes());
    out[16..48].copy_from_slice(&board.identity);
    out[48..54].copy_from_slice(&board.mac);
    out
}
fn smoke_rtw8852a_mac_scope_authenticates_exact_record_and_never_replays_revoked_grant(
) -> TestResult {
    let (q, cap) = model();
    let board = q.board;
    let exact = image(board, b"N5AM");
    let mut effects = 0;
    if q.with_current(|| {
        effects += 1;
        Ok(())
    })
    .is_err()
        || effects != 1
    {
        return TestResult::Fail("A MAC current source scope refused");
    }
    for at in [0, 4, 7, 8, 12, 14, 16, 48, 54, 95] {
        let mut bytes = exact;
        bytes[at] ^= 1;
        if Qualification::decode(&bytes, Some([3; 32]), board, cap).is_ok() {
            return TestResult::Fail("A MAC accepted wrong/reserved/old record");
        }
    }
    if Qualification::decode(&exact, None, board, cap).is_ok() {
        return TestResult::Fail("A MAC unsigned scope");
    }
    cap.revoke();
    if q.with_current(|| {
        effects += 1;
        Ok(())
    })
    .is_ok()
        || effects != 1
    {
        return TestResult::Fail("A MAC effects ran outside original current source grant");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_mac_scope_authenticates_exact_record_and_never_replays_revoked_grant
);
fn smoke_rtw8852a_secure_policy_requires_signed_board_and_exact_bitmap() -> TestResult {
    let (_, cap) = model();
    let board = Board {
        identity: [7; 32],
        mac: [2, 4, 6, 8, 10, 12],
        device: 0xa85a,
    };
    let mut bytes = image(board, b"N5AS");
    bytes[54] = 1;
    bytes[56] = 0x20;
    let policy = match SecurePolicy::decode(&bytes, Some([3; 32]), board, cap) {
        Ok(q) => q,
        Err(_) => return TestResult::Fail("A signed secure board policy refused"),
    };
    let fuses = crate::rtw89::secure::Fuses::decode(ChipId::Rtl8852A, 255, 0x7f).unwrap();
    // Blacklist is independently inspected; no secure fuse/default selector is invented.
    let mut section = [0; 34];
    section[32] = 5;
    section[33] = 1;
    if fuses.check_blacklist(Some(policy.blacklist), &section)
        != Err(crate::rtw89::secure::Error::Blacklisted)
        || SecurePolicy::decode(&bytes, None, board, cap).is_ok()
    {
        return TestResult::Fail("A authenticated blacklist lost actual signed bitmap");
    }
    cap.revoke();
    if policy.current().is_ok() {
        return TestResult::Fail("A secure policy ignored current original record");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_secure_policy_requires_signed_board_and_exact_bitmap
);
