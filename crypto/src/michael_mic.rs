//! Michael MIC for TKIP data frames.
//!
//! The construction is deliberately kept separate from TKIP's RC4 key
//! mixing: ath11k decrypts the MPDU in hardware, but leaves a fragmented
//! MPDU's Michael MIC for the host to verify before reinjection.  This is
//! the algorithm in IEEE 802.11-2020 §12.3.3.3 and Linux
//! `net/mac80211/michael.c`.

/// Size, in octets, of a Michael MIC and of its directional key.
pub const MIC_LEN: usize = 8;

#[derive(Copy, Clone)]
struct State {
    left: u32,
    right: u32,
}

impl State {
    fn new(key: &[u8; MIC_LEN]) -> Self {
        Self {
            left: u32::from_le_bytes(key[..4].try_into().unwrap()),
            right: u32::from_le_bytes(key[4..].try_into().unwrap()),
        }
    }

    fn block(&mut self, value: u32) {
        self.left ^= value;
        self.right ^= self.left.rotate_left(17);
        self.left = self.left.wrapping_add(self.right);
        self.right ^= ((self.left & 0xff00_ff00) >> 8) | ((self.left & 0x00ff_00ff) << 8);
        self.left = self.left.wrapping_add(self.right);
        self.right ^= self.left.rotate_left(3);
        self.left = self.left.wrapping_add(self.right);
        self.right ^= self.left.rotate_right(2);
        self.left = self.left.wrapping_add(self.right);
    }

    fn data(&mut self, data: &[u8]) {
        let blocks = data.len() / 4;
        for block in data[..blocks * 4].chunks_exact(4) {
            self.block(u32::from_le_bytes(block.try_into().unwrap()));
        }
        // IEEE 802.11's `0x5a || 0x00*` terminator followed by a full
        // zero block.  This is expressed as a little-endian word exactly
        // as Linux's backwards partial-byte loop does.
        let mut last = 0x5au32;
        for &byte in data[blocks * 4..].iter().rev() {
            last = (last << 8) | byte as u32;
        }
        self.block(last);
        self.block(0);
    }

    fn finish(self) -> [u8; MIC_LEN] {
        let mut mic = [0u8; MIC_LEN];
        mic[..4].copy_from_slice(&self.left.to_le_bytes());
        mic[4..].copy_from_slice(&self.right.to_le_bytes());
        mic
    }
}

/// Calculate the Michael MIC over a TKIP 802.11 data payload.
///
/// `da` and `sa` are the Ethernet destination/source selected from the
/// 802.11 addressing mode.  `tid` is the QoS TID, or zero for non-QoS data.
/// The function adds the mandated 16-byte pseudo-header
/// `DA || SA || TID || 0,0,0` before `payload`.
pub fn michael_mic(
    key: &[u8; MIC_LEN],
    da: &[u8; 6],
    sa: &[u8; 6],
    tid: u8,
    payload: &[u8],
) -> [u8; MIC_LEN] {
    let mut pseudo = [0u8; 16];
    pseudo[..6].copy_from_slice(da);
    pseudo[6..12].copy_from_slice(sa);
    pseudo[12] = tid;
    // `State::data` finalizes, so feed the already block-aligned
    // pseudo-header by hand and finalize only after the payload.
    let mut state = State::new(key);
    for block in pseudo.chunks_exact(4) {
        state.block(u32::from_le_bytes(block.try_into().unwrap()));
    }
    state.data(payload);
    state.finish()
}

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn mic_without_pseudo_header(key: [u8; MIC_LEN], data: &[u8]) -> [u8; MIC_LEN] {
        let mut state = State::new(&key);
        state.data(data);
        state.finish()
    }

    // IEEE 802.11i Michael test vectors, also used by Linux
    // `crypto/testmgr.h:michael_mic_tv_template`.
    fn smoke_michael_mic_ieee80211i_vectors() -> TestResult {
        let cases = [
            (
                [0; 8],
                &b""[..],
                [0x82, 0x92, 0x5c, 0x1c, 0xa1, 0xd1, 0x30, 0xb8],
            ),
            (
                [0x82, 0x92, 0x5c, 0x1c, 0xa1, 0xd1, 0x30, 0xb8],
                &b"M"[..],
                [0x43, 0x47, 0x21, 0xca, 0x40, 0x63, 0x9b, 0x3f],
            ),
            (
                [0xd5, 0x5e, 0x10, 0x05, 0x10, 0x12, 0x89, 0x86],
                &b"Michael"[..],
                [0x0a, 0x94, 0x2b, 0x12, 0x4e, 0xca, 0xa5, 0x46],
            ),
        ];
        if cases
            .iter()
            .any(|(key, data, expected)| mic_without_pseudo_header(*key, data) != *expected)
        {
            return TestResult::Fail("IEEE 802.11i Michael MIC vector mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/michael", smoke_michael_mic_ieee80211i_vectors);

    fn smoke_michael_mic_binds_da_sa_and_tid() -> TestResult {
        let key = [0x42; MIC_LEN];
        let da = [0, 1, 2, 3, 4, 5];
        let sa = [6, 7, 8, 9, 10, 11];
        let mic = michael_mic(&key, &da, &sa, 5, b"payload");
        if mic == michael_mic(&key, &da, &sa, 4, b"payload")
            || mic == michael_mic(&key, &sa, &da, 5, b"payload")
            || mic == michael_mic(&key, &da, &sa, 5, b"payloae")
        {
            return TestResult::Fail("Michael MIC did not bind pseudo-header and payload");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/michael", smoke_michael_mic_binds_da_sa_and_tid);
}
