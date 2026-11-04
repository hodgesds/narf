// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Literal native control adapter receipts/current-scope/fault coverage.
use super::*;
use crate::rtw89::monitor_wire as wire;
fn check() -> Result<(), &'static str> {
    for failure in 0..9 {
        let admission = Admission::new();
        let mut io = Model::new();
        io.bytes[0xce20..0xce24].copy_from_slice(&0x031644beu32.to_le_bytes());
        io.bytes[0xc400..0xc404].copy_from_slice(&0x00013c18u32.to_le_bytes());
        match failure {
            1 => io.reply = Reply::ReceiveOnly,
            2 => io.reply = Reply::Failure,
            3 => io.close = Some(admission.clone()),
            4 => io.revoke_before = true,
            5 => io.ignore = Some(wire::RX_FILTER),
            6 => io.ignore = Some(0x1073c + 6 * 4),
            7 => io.bytes[0xc000..0xc004].copy_from_slice(&wire::CMAC_TX.to_le_bytes()),
            8 => io.aperture = 0x10800,
            _ => {}
        }
        let result = narf_scheduler::block_on(initialize_monitor(&mut io, OWN, false, &admission));
        if failure != 0 {
            if result.is_ok() {
                return Err("monitor skipped exact native ACK/readback/source/noTX proof");
            }
            if failure == 7 && (!io.writes.is_empty() || !io.packets.is_empty()) {
                return Err("monitor configured role before actual TX disable proof");
            }
            continue;
        }
        if result.is_err()
            || io.packets.len() != 5
            || io.word(0xc000) & wire::CMAC_TX != 0
            || io.word(wire::RX_FILTER as usize) != 0x03164401
            || io.word(0xc400) != 0x4
            || io.word(0x9d00) & 31 != 0
            || io.word(0x9d04) & 3 != 0
            || wire::FORWARD
                .into_iter()
                .any(|address| io.word(address as usize) != 0x55555555)
            || io.word(0x1073c + 6 * 4) != (1 << 13 | 1 << 9 | 1 << 10)
            || io.word(0x1073c + 13 * 4) != (1 << 20 | 1 << 9)
            || io.packets[1][8..] != 0xe000u32.to_le_bytes()
            || io.packets[2][8..] != 0x1c000100u32.to_le_bytes()
            || io.packets[3][8..] != codec::cam(OWN, [0; 6], 0, false, true)
            || io.packets[4][8..] != codec::default_cctl()
        {
            return Err("monitor native role/NoLink/sniffer/forward/crypto/PHYSTS literal program");
        }
        if io
            .writes
            .iter()
            .any(|&(address, value)| address == 0xc000 && value & wire::CMAC_TX != 0)
        {
            return Err("receive-only program enabled automatic responses");
        }
    }
    crate::rtw89::command_native::tests::monitor_boundary()?;
    Ok(())
}
fn smoke_rtw8852b_monitor_native_role_filter_physts_receipts_and_transmit_disable() -> TestResult {
    check().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/monitor",
    smoke_rtw8852b_monitor_native_role_filter_physts_receipts_and_transmit_disable
);
