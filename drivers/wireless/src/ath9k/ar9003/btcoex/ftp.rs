// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! gpio.c::ath_mci_ftp_adjust and the NETWORK_SLEEP-only period branch.
//! Saturating at each predicate's threshold preserves the source decision
//! without letting a long sleep or packet stream wrap back below it.
use super::*;
use crate::ath9k::{ar9003::ps::NetworkSleep, packet::Error};
#[derive(Default)]
pub(super) struct Ftp {
    wait_ms: u32,
    packets: u8,
}

#[cfg(feature = "kernel-test")]
fn smoke_ath9k_mci_ftp_literal_wait_packet_profile_and_ar9565_disable(
) -> narf_kernel_test::TestResult {
    struct NoIo;
    impl RegisterIo for NoIo {
        fn read32(&mut self, _: u64) -> u32 {
            panic!("pure FTP state read hardware");
        }
        fn write32(&mut self, _: u64, _: u32) {
            panic!("pure FTP state wrote hardware");
        }
    }
    for chip in [Chip::Ar9462, Chip::Ar9565] {
        let mut bt = Btcoex::new(chip);
        init_mci(&mut bt);
        let mut link = MciLink::new(bt, None);
        link.btcoex.mci.profiles.num_pan = 1;
        link.ftp.wait_ms = 100;
        link.ftp.packets = 4;
        if link.adjust_ftp(&mut NoIo).is_err()
            || link.ftp_counters() != (100, 4)
            || link.btcoex.mci.stomp_ftp
        {
            return narf_kernel_test::TestResult::Fail("FTP threshold was not strict wait>100");
        }
        link.ftp.wait_ms = 101;
        if link.adjust_ftp(&mut NoIo).is_err()
            || link.ftp_counters() != (0, 0)
            || link.btcoex.mci.stomp_ftp != (chip == Chip::Ar9462)
        {
            return narf_kernel_test::TestResult::Fail(
                "FTP four-packet/PAN or fixed AR9565-disable predicate",
            );
        }
        link.ftp.wait_ms = 101;
        link.ftp.packets = 5;
        if link.adjust_ftp(&mut NoIo).is_err() || link.btcoex.mci.stomp_ftp {
            return narf_kernel_test::TestResult::Fail("FTP admitted exactly five native packets");
        }
        link.btcoex.mci.profiles.num_pan = 0;
        link.ftp.wait_ms = 101;
        if link.adjust_ftp(&mut NoIo).is_err() || link.btcoex.mci.stomp_ftp {
            return narf_kernel_test::TestResult::Fail("FTP admitted an ineligible profile");
        }
        link.btcoex.mci.profiles.num_other_acl = 1;
        link.ftp.wait_ms = 101;
        if link.adjust_ftp(&mut NoIo).is_err()
            || link.btcoex.mci.stomp_ftp != (chip == Chip::Ar9462)
        {
            return narf_kernel_test::TestResult::Fail("FTP other-ACL/source-disable predicate");
        }
    }
    narf_kernel_test::TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_mci_ftp_literal_wait_packet_profile_and_ar9565_disable
);
impl MciLink {
    #[cfg(feature = "kernel-test")]
    pub(in crate::ath9k) fn ftp_counters(&self) -> (u32, u8) {
        (self.ftp.wait_ms, self.ftp.packets)
    }
    /// Called only for a descriptor/CRC/rate-admitted DATA-present MPDU.
    /// Plain/QoS Null frames, malformed frames and continuations never count.
    pub(in crate::ath9k) fn received_data(&mut self) {
        self.ftp.packets = self.ftp.packets.saturating_add(1).min(5);
    }
    /// The owner observed actual retained NETWORK_SLEEP before normal
    /// packet/IRQ access could wake it. Exactly one source timer period is
    /// counted; lateness never invents elapsed sleeping callbacks.
    pub(in crate::ath9k) fn sleep_period(
        &mut self,
        observation: NetworkSleep,
        now: u64,
    ) -> Result<(), Error> {
        observation.invoke(|| {
            if !self.duty.running
                || !self.mci_enabled()
                || !self.btcoex.mci.ready
                || !self.btcoex.mci.is_2g
                || self.duty.applied != Some((self.btcoex.mci.scheme_revision, true))
                || self.duty.period.is_none_or(|due| now < due)
            {
                return Ok(());
            }
            let period = self.btcoex.mci.profiles.btcoex_period;
            if period == 0 {
                return Err(Error::State);
            }
            self.ftp.wait_ms = self.ftp.wait_ms.saturating_add(period).min(101);
            self.duty.period = Some(now.saturating_add(u64::from(period) * 1000));
            // Source skips every hardware/RSSI/audio/FTP adjustment here.
            // An independently pending no-stomp callback is not cancelled.
            Ok(())
        })
    }
    pub(super) fn adjust_ftp(&mut self, io: &mut impl RegisterIo) -> Result<(), BringUpError> {
        if self.ftp.wait_ms > 100 {
            let need = super::super::mci::state(
                io,
                &mut self.btcoex.mci,
                super::super::mci::MciState::NeedFtpStomp,
            )? != 0;
            let profiles = &self.btcoex.mci.profiles;
            self.btcoex.mci.stomp_ftp = need
                && (profiles.num_pan != 0 || profiles.num_other_acl != 0)
                && self.ftp.packets < 5;
            self.ftp.wait_ms = 0;
            self.ftp.packets = 0;
        }
        Ok(())
    }
}
