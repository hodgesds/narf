//! API77 AP software BIP fallback, selected by actual missing BIGTK_TX.
//! This host key/IPN owner never claims a firmware IGTK install receipt.
use alloc::vec::Vec;
use zeroize::Zeroize;

pub(super) struct Key(narf_crypto::bip_cmac::Igtk);
impl Key {
    pub fn new(id: u8, material: [u8; 16]) -> Result<Self, &'static str> {
        narf_crypto::bip_cmac::Igtk::install(material, u16::from(id))
            .map(Self)
            .map_err(|_| "AP software BIP key ID invalid")
    }
    pub fn id(&self) -> u8 {
        self.0.key_id as u8
    }
    pub fn protect(&mut self, frame: &mut Vec<u8>, own: [u8; 6]) -> Result<(), &'static str> {
        if frame.len() < 26
            || frame[0] & 12 != 0
            || frame[1] & 0xc7 != 0
            || frame[4] & 1 == 0
            || frame[10..16] != own
            || frame[16..22] != own
            || !super::packet::robust(frame[0], &frame[24..])
            || self.0.tx_pn >= (1u64 << 48) - 1
        {
            return Err("AP software BIP physical frame/IPN owner invalid");
        }
        let mut body = frame[24..].to_vec();
        // Reserve once before publication. A failed/abandoned native send
        // burns this IPN; retries retain the already protected same MPDU.
        narf_wireless::mfp::protect_outbound(&mut self.0, &frame[..24], &mut body)
            .map_err(|_| "AP software BIP CMAC failed")?;
        frame.truncate(24);
        frame.extend_from_slice(&body);
        Ok(())
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        self.0.key.zeroize();
        self.0.rx_pn.zeroize();
        self.0.tx_pn.zeroize();
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn frame() -> Vec<u8> {
        let mut frame = alloc::vec![0;26];
        frame[0] = 0xc0;
        frame[4..10].fill(255);
        frame[10..16].fill(2);
        frame[16..22].fill(2);
        frame[24] = 3;
        frame
    }
    fn case() -> Result<(), &'static str> {
        let mut key = Key::new(4, [0x37; 16])?;
        let mut bad = frame();
        bad[10] = 4;
        if key.protect(&mut bad, [2; 6]).is_ok() || key.0.tx_pn != 0 {
            return Err("AP software BIP consumed PN before exact physical owner admission");
        }
        let mut first = frame();
        key.protect(&mut first, [2; 6])?;
        let mut receiver = narf_wireless::mfp::MfpKeyStore::new();
        receiver.install_active([0x37; 16], 4).unwrap();
        if first[1] & 0x40 != 0
            || first.len() != 44
            || key.0.tx_pn != 1
            || narf_wireless::mfp::verify_inbound(&mut receiver, &first[..24], &first[24..])
                .is_err()
        {
            return Err("AP software BIP did not produce real CMAC/MMIE with clear Protected bit");
        }
        if narf_wireless::mfp::verify_inbound(&mut receiver, &first[..24], &first[24..]).is_ok() {
            return Err("AP software BIP same-IPN management replay admitted");
        }
        let mut second = frame();
        key.protect(&mut second, [2; 6])?;
        let mut tampered = second.clone();
        tampered[24] ^= 1;
        if narf_wireless::mfp::verify_inbound(&mut receiver, &tampered[..24], &tampered[24..])
            .is_ok()
            || receiver.find_by_key_id(4).unwrap().rx_pn != 1
            || narf_wireless::mfp::verify_inbound(&mut receiver, &second[..24], &second[24..])
                .is_err()
            || receiver.find_by_key_id(4).unwrap().rx_pn != 2
            || key.0.tx_pn != 2
        {
            return Err("AP software BIP altered MIC consumed PN or next genuine frame was lost");
        }
        key.0.tx_pn = (1u64 << 48) - 1;
        let mut exhausted = frame();
        if key.protect(&mut exhausted, [2; 6]).is_ok()
            || key.0.tx_pn != (1u64 << 48) - 1
            || exhausted.len() != 26
        {
            return Err("AP software BIP wrapped the 48-bit IPN or emitted after exhaustion");
        }
        Ok(())
    }
    fn smoke_iwl_native_ap_api77_software_bip_has_real_mic_physical_owner_and_nonwrapping_ipn(
    ) -> TestResult {
        match case() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/gen2",
        smoke_iwl_native_ap_api77_software_bip_has_real_mic_physical_owner_and_nonwrapping_ipn
    );
}
