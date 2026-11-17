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
//! `mci.c::ath9k_mci_stomp_audio` and `gpio.c::ath_btcoex_period_timer`.
//! The station's associated-beacon hook supplies RSSI after native RX
//! validation; source `common.c::ath9k_cmn_process_rssi` filtering is shared
//! with ANI. Timer pause/resume does not discard the audio history.
use crate::ath9k::periodic::BeaconRssi;

pub(super) struct Audio {
    rssi: BeaconRssi,
    unsampled_rssi: u8,
    weak_periods: u32,
}

impl Audio {
    pub(super) fn new() -> Self {
        Self {
            rssi: BeaconRssi::new(),
            unsampled_rssi: 0,
            weak_periods: 0,
        }
    }

    pub(super) fn beacon(&mut self, native_rssi: i8) {
        self.rssi.beacon(native_rssi);
    }

    /// `main.c::ath9k_set_assoc_state(changed)`: an association starts
    /// with ATH_RSSI_DUMMY_MARKER (127) until its first valid beacon.
    /// The audio-period counter is not reset by that source call.
    pub(super) fn association_changed(&mut self) {
        self.rssi = BeaconRssi::new();
        self.unsampled_rssi = 127;
    }

    /// Linux's default `avgbrssi` is zero until an associated beacon
    /// arrives. Only an audio profile changes its weak-period count.
    /// The period callback selects AUDIO on the fifth weak period.
    pub(super) fn period(&mut self, has_audio: bool) -> bool {
        if has_audio {
            if self.rssi.value().unwrap_or(self.unsampled_rssi) > 25 {
                self.weak_periods = 0;
            } else {
                self.weak_periods += 1;
            }
        }
        if self.weak_periods >= 5 {
            self.weak_periods = 0;
            true
        } else {
            false
        }
    }
}
