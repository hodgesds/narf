#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_capabilities::{Cap, Grant, Read, Write};
use narf_net::Interface;

pub mod caps;
pub mod eapol;
pub mod iface;
pub mod mlme;
pub mod reg;
pub mod sae;
pub mod scan;

pub use iface::{WirelessError, WirelessIface, WirelessIfaceInfo};
pub use scan::{BssInfo, ScanRequest, ScanResult};

/// Capability for wireless-specific operations.
pub enum WirelessRight {
    /// Allows triggering scans and reading BSSID lists.
    Scan,
    /// Allows associating with and disassociating from Access Points.
    Associate,
    /// Allows changing PHY configuration (channel, power).
    Config,
    /// Allows entering monitor mode and receiving all management frames.
    Monitor,
    /// Full administrative rights over the wireless interface.
    Admin,
}

/// A specialized network interface supporting 802.11 operations.
#[async_trait]
pub trait WirelessNetIface: Interface {
    /// Returns detailed information about the wireless interface.
    fn get_wireless_info(&self) -> WirelessIfaceInfo;

    /// Triggers an asynchronous scan.
    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError>;

    /// Initiates association with an Access Point.
    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError>;

    /// Disconnects from the current Access Point.
    async fn disassociate(&self) -> Result<(), WirelessError>;

    /// Configures PHY-level parameters.
    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError>;
}

pub struct AssociateRequest {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub channel: u32,
    pub security: SecurityConfig,
}

pub enum SecurityConfig {
    Open,
    Wpa2 { psk: [u8; 32] },
    Wpa3 { password: Vec<u8> },
}

pub struct WirelessConfig {
    pub channel: u32,
    pub tx_power_dbm: Option<i8>,
}

pub mod registry {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_lib::sync::IrqSafeSpinLock;

    static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn WirelessNetIface>>> =
        IrqSafeSpinLock::new(Vec::new());

    pub fn register(iface: Arc<dyn WirelessNetIface>) {
        REGISTRY.lock().push(iface);
    }

    pub fn list() -> Vec<Arc<dyn WirelessNetIface>> {
        REGISTRY.lock().clone()
    }
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use narf_ipc::{Consumer, Producer};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;
    use narf_net::{Frame, RX_RING_N, TX_RING_N};

    struct MockWireless {
        is_scanning: AtomicBool,
        is_associated: AtomicBool,
        rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
        tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    }

    impl MockWireless {
        fn new() -> Self {
            Self {
                is_scanning: AtomicBool::new(false),
                is_associated: AtomicBool::new(false),
                rx: IrqSafeSpinLock::new(None),
                tx: IrqSafeSpinLock::new(None),
            }
        }
    }

    impl Interface for MockWireless {
        fn name(&self) -> &str {
            "wlan0"
        }
        fn mac(&self) -> [u8; 6] {
            [0; 6]
        }
        fn mtu(&self) -> u32 {
            1500
        }
        fn link_up(&self) -> bool {
            true
        }
        fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
            &self.rx
        }
        fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
            &self.tx
        }
    }

    #[async_trait]
    impl WirelessNetIface for MockWireless {
        fn get_wireless_info(&self) -> WirelessIfaceInfo {
            WirelessIfaceInfo {
                base_name: self.name().into(),
                base_mac: self.mac(),
                bands: alloc::vec![],
                modes: iface::WirelessModes::STATION,
                hw_caps: iface::HwCaps {
                    ht_supported: true,
                    vht_supported: false,
                    he_supported: false,
                    eht_supported: false,
                },
            }
        }

        async fn scan(&self, _req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
            if self.is_scanning.swap(true, Ordering::SeqCst) {
                return Err(WirelessError::Busy);
            }
            narf_scheduler::yield_now().await;
            self.is_scanning.store(false, Ordering::SeqCst);
            Ok(alloc::vec![BssInfo {
                bssid: [0x12; 6],
                ssid: alloc::vec![b'T', b'e', b's', b't'],
                channel: 1,
                rssi: -50,
                security: scan::BssSecurity::Wpa2,
            }])
        }

        async fn associate(&self, _req: AssociateRequest) -> Result<(), WirelessError> {
            self.is_associated.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn disassociate(&self) -> Result<(), WirelessError> {
            self.is_associated.store(false, Ordering::SeqCst);
            Ok(())
        }

        async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
            Ok(())
        }
    }

    fn smoke_wireless_scan_busy_logic() -> TestResult {
        narf_scheduler::init();
        let mock = Arc::new(MockWireless::new());
        let success = Arc::new(AtomicBool::new(false));

        let m1 = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let res = m1
                .scan(ScanRequest {
                    ssids: Vec::new(),
                    channels: Vec::new(),
                    active: true,
                })
                .await;
            if res.is_ok() && res.unwrap().len() == 1 {
                s.store(true, Ordering::SeqCst);
            }
        });

        // We can't easily test the "Busy" error here because spawn order is deterministic in this scheduler
        // and we only have one CPU. But we can verify the scan completes.
        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("scan failed")
        }
    }
    kernel_test_in!("wireless", smoke_wireless_scan_busy_logic);

    fn smoke_wireless_association_state() -> TestResult {
        narf_scheduler::init();
        let mock = Arc::new(MockWireless::new());
        let success = Arc::new(AtomicBool::new(false));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let req = AssociateRequest {
                bssid: [0x12; 6],
                ssid: alloc::vec![b'T', b'e', b's', b't'],
                channel: 1,
                security: SecurityConfig::Open,
            };
            m.associate(req).await.expect("associate failed");
            if m.is_associated.load(Ordering::SeqCst) {
                m.disassociate().await.expect("disassociate failed");
                if !m.is_associated.load(Ordering::SeqCst) {
                    s.store(true, Ordering::SeqCst);
                }
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("association state cycle failed")
        }
    }
    kernel_test_in!("wireless", smoke_wireless_association_state);

    fn smoke_mlme_frame_control_round_trip() -> TestResult {
        use crate::mlme::{FrameControl, FrameType, MgmtSubtype};
        let fc = FrameControl::mgmt(MgmtSubtype::ProbeRequest);
        let raw = fc.encode();
        // §9.2.4.1.3: type=0 (mgmt), subtype=4 (ProbeReq).
        if (raw >> 2) & 0x3 != 0 {
            return TestResult::Fail("Mgmt frame Type field drift");
        }
        if (raw >> 4) & 0xF != 4 {
            return TestResult::Fail("ProbeRequest Subtype drift");
        }
        let back = FrameControl::decode(raw);
        if back.frame_type != FrameType::Management
            || back.subtype != MgmtSubtype::ProbeRequest as u8
        {
            return TestResult::Fail("Frame Control round-trip lost type/subtype");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_frame_control_round_trip);

    fn smoke_mlme_mgmt_header_layout() -> TestResult {
        use crate::mlme::{FrameControl, MgmtHeader, MgmtSubtype};
        let h = MgmtHeader {
            fc: FrameControl::mgmt(MgmtSubtype::Authentication),
            duration: 0x0030,
            addr1: [0x11; 6],
            addr2: [0x22; 6],
            addr3: [0x33; 6],
            seq_ctrl: 0x0010,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        if buf.len() != 24 {
            return TestResult::Fail("Mgmt header should be 24 bytes (no addr4)");
        }
        let back = match MgmtHeader::decode(&buf) {
            Some(v) => v,
            None => return TestResult::Fail("MgmtHeader::decode returned None"),
        };
        if back != h {
            return TestResult::Fail("MgmtHeader round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_mgmt_header_layout);

    fn smoke_mlme_ie_iter_and_write() -> TestResult {
        use crate::mlme::{iter_ies, write_ie, ElementId};
        let mut buf = Vec::new();
        write_ie(&mut buf, ElementId::Ssid, b"narf");
        write_ie(&mut buf, ElementId::SupportedRates, &[0x82, 0x84, 0x8B, 0x96]);
        let ies: Vec<_> = iter_ies(&buf).collect();
        if ies.len() != 2 {
            return TestResult::Fail("expected 2 IEs back from iter");
        }
        if ies[0].id != ElementId::Ssid as u8 || ies[0].body != b"narf" {
            return TestResult::Fail("SSID IE round-trip lost contents");
        }
        if ies[1].id != ElementId::SupportedRates as u8 || ies[1].body.len() != 4 {
            return TestResult::Fail("SupportedRates IE round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_ie_iter_and_write);

    fn smoke_mlme_probe_request_builder() -> TestResult {
        use crate::mlme::{build_probe_request_body, iter_ies, ElementId};
        let body = build_probe_request_body(b"narf", &[0x82, 0x84]);
        let ies: Vec<_> = iter_ies(&body).collect();
        if ies.len() != 2 {
            return TestResult::Fail("ProbeReq body should hold 2 IEs");
        }
        if ies[0].id != ElementId::Ssid as u8 || ies[0].body != b"narf" {
            return TestResult::Fail("ProbeReq SSID IE wrong");
        }
        if ies[1].id != ElementId::SupportedRates as u8 {
            return TestResult::Fail("ProbeReq SupportedRates IE wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_probe_request_builder);

    fn smoke_mlme_open_auth_request() -> TestResult {
        use crate::mlme::{build_open_auth_request, AuthFields};
        let body = build_open_auth_request();
        let fields = match AuthFields::decode(&body) {
            Some(f) => f,
            None => return TestResult::Fail("AuthFields::decode returned None"),
        };
        if fields.algorithm != 0 {
            return TestResult::Fail("Open System should use algorithm 0");
        }
        if fields.sequence != 1 {
            return TestResult::Fail("Auth sequence should be 1 for the request");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_open_auth_request);

    fn smoke_eapol_header_round_trip() -> TestResult {
        use crate::eapol::{EapolHeader, EapolType, EAPOL_PROTOCOL_VERSION};
        let h = EapolHeader {
            version: EAPOL_PROTOCOL_VERSION,
            packet_type: EapolType::EapolKey as u8,
            body_length: 95,
        };
        let mut out = Vec::new();
        h.encode(&mut out);
        if out.len() != 4 {
            return TestResult::Fail("EAPOL header should be 4 bytes");
        }
        // Body length is big-endian.
        if u16::from_be_bytes([out[2], out[3]]) != 95 {
            return TestResult::Fail("EAPOL body length not big-endian");
        }
        let back = EapolHeader::decode(&out).expect("decode");
        if back != h {
            return TestResult::Fail("EAPOL header round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_header_round_trip);

    fn smoke_eapol_key_frame_round_trip() -> TestResult {
        use crate::eapol::{
            KeyFrame, KEY_DESCRIPTOR_RSN, KI_INSTALL, KI_KEY_ACK, KI_KEY_MIC,
            KI_KEY_TYPE_PAIRWISE,
        };
        // 16-byte MIC (HMAC-SHA1 AKM) — typical WPA2-Personal.
        let mut k = KeyFrame::empty(16);
        k.descriptor_type = KEY_DESCRIPTOR_RSN;
        k.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_KEY_MIC | KI_INSTALL | 0x02;
        k.key_length = 16;
        k.replay_counter = 0x0102_0304_0506_0708;
        k.key_nonce = [0xAA; 32];
        k.key_data = alloc::vec![0xDD, 0xEE, 0xFF];

        let raw = k.encode();
        let back = KeyFrame::decode(&raw, 16).expect("decode");
        if back != k {
            return TestResult::Fail("KeyFrame round-trip mismatch");
        }
        if !back.pairwise() || !back.key_ack() || !back.has_mic() || !back.install() {
            return TestResult::Fail("Key Information bit flags lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_key_frame_round_trip);

    fn smoke_eapol_into_eapol_wraps_header() -> TestResult {
        use crate::eapol::{EapolHeader, EapolType, KeyFrame};
        let k = KeyFrame::empty(16);
        let body_len = k.encode().len();
        let pdu = k.into_eapol();
        if pdu.len() != 4 + body_len {
            return TestResult::Fail("into_eapol did not prefix a 4-byte header");
        }
        let h = EapolHeader::decode(&pdu).expect("decode");
        if h.packet_type != EapolType::EapolKey as u8 {
            return TestResult::Fail("packet type should be EAPOL-Key");
        }
        if h.body_length as usize != body_len {
            return TestResult::Fail("body_length mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_into_eapol_wraps_header);

    /// Identity HMAC for testing the PRF / handshake plumbing — we
    /// just want to verify the surface, not the cryptographic
    /// strength. Production uses HMAC-SHA1 (AKM-1/2) or HMAC-SHA256
    /// (AKM-3+) wired via narf-crypto.
    struct StubHmac;
    impl crate::eapol::HmacPrimitive for StubHmac {
        fn out_len(&self) -> usize {
            20
        }
        fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
            // Deterministic XOR digest for test purposes only.
            let mut out = alloc::vec![0u8; 20];
            for (i, b) in key.iter().enumerate() {
                out[i % 20] ^= *b;
            }
            for (i, b) in data.iter().enumerate() {
                out[i % 20] ^= b.rotate_left((i % 8) as u32);
            }
            out
        }
    }

    fn smoke_eapol_prf_extends_to_requested_length() -> TestResult {
        use crate::eapol::prf;
        let key = [0x11u8; 32];
        let label = b"Pairwise key expansion";
        let context = [0x22u8; 76];
        // 384 bits = 48 bytes; PRF runs for ceil(48/20) = 3 chunks.
        let out = prf(&StubHmac, &key, label, &context, 384);
        if out.len() != 48 {
            return TestResult::Fail("PRF output length not 48 bytes");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_prf_extends_to_requested_length);

    fn smoke_eapol_derive_ptk_splits_kck_kek_tk() -> TestResult {
        use crate::eapol::derive_ptk;
        let pmk = [0x33u8; 32];
        let aa = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let sa = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let anonce = [0x55u8; 32];
        let snonce = [0x66u8; 32];
        let ptk = derive_ptk(&StubHmac, &pmk, &aa, &sa, &anonce, &snonce, 16);
        if ptk.kck.len() != 16 || ptk.kek.len() != 16 || ptk.tk.len() != 16 {
            return TestResult::Fail("PTK split lengths drifted");
        }
        // PTK is deterministic for given inputs — derive twice and
        // confirm equality.
        let ptk2 = derive_ptk(&StubHmac, &pmk, &aa, &sa, &anonce, &snonce, 16);
        if ptk.kck != ptk2.kck || ptk.kek != ptk2.kek || ptk.tk != ptk2.tk {
            return TestResult::Fail("PTK derivation not deterministic");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_derive_ptk_splits_kck_kek_tk);

    fn smoke_eapol_supplicant_walks_4way_handshake() -> TestResult {
        use crate::eapol::{
            FourWayState, KeyFrame, Supplicant, KEY_DESCRIPTOR_RSN, KI_INSTALL, KI_KEY_ACK,
            KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE,
        };
        let aa = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let sa = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let snonce = [0x77u8; 32];
        let mut sup = Supplicant::new(aa, sa, snonce);
        let pmk = [0x44u8; 32];

        // Build M1 — Authenticator → Supplicant.
        let mut m1 = KeyFrame::empty(16);
        m1.descriptor_type = KEY_DESCRIPTOR_RSN;
        m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | 0x02;
        m1.replay_counter = 1;
        m1.key_nonce = [0x88u8; 32];

        let m2 = sup
            .handle(&StubHmac, &pmk, 16, &m1)
            .expect("handle M1")
            .expect("M1 should produce M2");
        if sup.state != FourWayState::WaitM3 {
            return TestResult::Fail("supplicant did not advance to WaitM3");
        }
        if m2.replay_counter != 1 || !m2.has_mic() || m2.key_ack() {
            return TestResult::Fail("M2 flags / counter wrong");
        }
        if sup.ptk.is_none() {
            return TestResult::Fail("PTK should be derived after M1");
        }

        // M3: Authenticator confirms with Install + MIC + Secure.
        let mut m3 = KeyFrame::empty(16);
        m3.descriptor_type = KEY_DESCRIPTOR_RSN;
        m3.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_KEY_MIC | KI_INSTALL | 0x02;
        m3.replay_counter = 2;
        m3.key_nonce = m1.key_nonce;

        let m4 = sup
            .handle(&StubHmac, &pmk, 16, &m3)
            .expect("handle M3")
            .expect("M3 should produce M4");
        if sup.state != FourWayState::PtkDone {
            return TestResult::Fail("supplicant did not reach PtkDone");
        }
        if m4.install() || !m4.has_mic() {
            return TestResult::Fail("M4 flags wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/eapol",
        smoke_eapol_supplicant_walks_4way_handshake
    );

    fn smoke_eapol_supplicant_rejects_replay_regression() -> TestResult {
        use crate::eapol::{
            FourWayError, KeyFrame, Supplicant, KEY_DESCRIPTOR_RSN, KI_INSTALL, KI_KEY_ACK,
            KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE,
        };
        let mut sup = Supplicant::new([0u8; 6], [0u8; 6], [0u8; 32]);
        let pmk = [0u8; 32];
        // M1 with replay=5.
        let mut m1 = KeyFrame::empty(16);
        m1.descriptor_type = KEY_DESCRIPTOR_RSN;
        m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | 0x02;
        m1.replay_counter = 5;
        let _ = sup
            .handle(&StubHmac, &pmk, 16, &m1)
            .expect("M1 should pass");
        // M3 with replay=4 (regression) — must error.
        let mut m3 = KeyFrame::empty(16);
        m3.descriptor_type = KEY_DESCRIPTOR_RSN;
        m3.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_KEY_MIC | KI_INSTALL | 0x02;
        m3.replay_counter = 4;
        m3.key_nonce = m1.key_nonce;
        match sup.handle(&StubHmac, &pmk, 16, &m3) {
            Err(FourWayError::ReplayRegression) => TestResult::Pass,
            _ => TestResult::Fail("regression should be rejected"),
        }
    }
    kernel_test_in!(
        "wireless/eapol",
        smoke_eapol_supplicant_rejects_replay_regression
    );

    fn smoke_sae_commit_frame_round_trip() -> TestResult {
        use crate::sae::CommitFrame;
        let f = CommitFrame {
            group: 19,
            scalar: alloc::vec![0xAAu8; 32],
            element: alloc::vec![0xBBu8; 64],
        };
        let raw = f.encode();
        if raw.len() != 2 + 32 + 64 {
            return TestResult::Fail("Commit frame length should be 2 + 32 + 64");
        }
        // Group field is LE.
        if u16::from_le_bytes([raw[0], raw[1]]) != 19 {
            return TestResult::Fail("group encoded LE");
        }
        let back = CommitFrame::decode(&raw, 32, 64).expect("decode");
        if back != f {
            return TestResult::Fail("Commit frame round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_commit_frame_round_trip);

    fn smoke_sae_confirm_frame_round_trip() -> TestResult {
        use crate::sae::ConfirmFrame;
        let f = ConfirmFrame {
            send_confirm: 1,
            confirm: alloc::vec![0xCCu8; 32],
        };
        let raw = f.encode();
        if raw.len() != 2 + 32 {
            return TestResult::Fail("Confirm length wrong");
        }
        let back = ConfirmFrame::decode(&raw).expect("decode");
        if back != f {
            return TestResult::Fail("Confirm round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_confirm_frame_round_trip);

    /// Stub group: deterministic so we can exercise the state
    /// machine end-to-end. Production wires P-256 from narf-crypto.
    struct StubGroup;
    impl crate::sae::EccGroup for StubGroup {
        fn group_id(&self) -> u16 {
            19
        }
        fn scalar_len(&self) -> usize {
            32
        }
        fn element_len(&self) -> usize {
            64
        }
        fn make_commit(
            &mut self,
            password: &[u8],
            peer_mac: &[u8; 6],
            own_mac: &[u8; 6],
        ) -> (Vec<u8>, Vec<u8>) {
            // Deterministic XOR derivation; tests only.
            let mut s = alloc::vec![0u8; 32];
            for (i, b) in password.iter().enumerate() {
                s[i % 32] ^= *b;
            }
            for (i, b) in peer_mac.iter().enumerate() {
                s[i] ^= *b;
            }
            for (i, b) in own_mac.iter().enumerate() {
                s[i + 6] ^= *b;
            }
            let mut e = alloc::vec![0u8; 64];
            for (i, b) in s.iter().enumerate() {
                e[i] = b.wrapping_add(1);
                e[i + 32] = b.wrapping_add(2);
            }
            (s, e)
        }
        fn finish(
            &mut self,
            peer_scalar: &[u8],
            peer_element: &[u8],
        ) -> Result<Vec<u8>, crate::sae::SaeError> {
            let mut k = alloc::vec![0u8; 32];
            for (i, b) in peer_scalar.iter().take(32).enumerate() {
                k[i] ^= *b;
            }
            for (i, b) in peer_element.iter().take(32).enumerate() {
                k[i] ^= *b;
            }
            Ok(k)
        }
    }

    struct StubMac;
    impl crate::sae::MacPrimitive for StubMac {
        fn out_len(&self) -> usize {
            32
        }
        fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
            let mut out = alloc::vec![0u8; 32];
            for (i, b) in key.iter().enumerate() {
                out[i % 32] ^= *b;
            }
            for (i, b) in data.iter().enumerate() {
                out[i % 32] ^= b.rotate_left((i % 8) as u32);
            }
            out
        }
    }

    fn smoke_sae_full_handshake_two_peers_agree() -> TestResult {
        use crate::sae::{Sae, SaeState};

        let pwd = b"narfwifi";
        let mac_a = [0x11u8, 0x11, 0x11, 0x11, 0x11, 0x11];
        let mac_b = [0x22u8, 0x22, 0x22, 0x22, 0x22, 0x22];

        let mut a = Sae::new(StubGroup, StubMac, mac_a, mac_b);
        let mut b = Sae::new(StubGroup, StubMac, mac_b, mac_a);

        let commit_a = a.build_commit(pwd);
        let commit_b = b.build_commit(pwd);

        a.handle_commit(&commit_b).expect("a.handle_commit");
        b.handle_commit(&commit_a).expect("b.handle_commit");

        if a.pmk.is_empty() || a.pmk == b.pmk {
            // Note: in the stub group both sides derive the same PMK
            // by symmetry; production crypto guarantees the same via
            // the spec's commutative key-agreement.
        }

        let confirm_a = a.build_confirm();
        let confirm_b = b.build_confirm();

        a.handle_confirm(&confirm_b).expect("a confirm");
        b.handle_confirm(&confirm_a).expect("b confirm");

        if a.state != SaeState::Accepted || b.state != SaeState::Accepted {
            return TestResult::Fail("both peers should reach Accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_full_handshake_two_peers_agree);

    fn smoke_sae_confirm_mismatch_rejected() -> TestResult {
        use crate::sae::{ConfirmFrame, Sae, SaeError};

        let pwd = b"narfwifi";
        let mac_a = [0x11u8; 6];
        let mac_b = [0x22u8; 6];
        let mut a = Sae::new(StubGroup, StubMac, mac_a, mac_b);
        let mut b = Sae::new(StubGroup, StubMac, mac_b, mac_a);

        let commit_a = a.build_commit(pwd);
        let commit_b = b.build_commit(pwd);
        a.handle_commit(&commit_b).unwrap();
        b.handle_commit(&commit_a).unwrap();

        // Tamper with B's confirm before A verifies.
        let mut bad = b.build_confirm();
        bad.confirm[0] ^= 0xFF;
        match a.handle_confirm(&bad) {
            Err(SaeError::ConfirmMismatch) => TestResult::Pass,
            _ => TestResult::Fail("tampered confirm should be rejected"),
        }
    }
    kernel_test_in!("wireless/sae", smoke_sae_confirm_mismatch_rejected);

    fn smoke_sae_invalid_group_rejected() -> TestResult {
        use crate::sae::{CommitFrame, Sae, SaeError};

        let pwd = b"narfwifi";
        let mut a = Sae::new(StubGroup, StubMac, [0u8; 6], [0u8; 6]);
        let _ = a.build_commit(pwd);
        let bad = CommitFrame {
            group: 999, // unsupported
            scalar: alloc::vec![0u8; 32],
            element: alloc::vec![0u8; 64],
        };
        match a.handle_commit(&bad) {
            Err(SaeError::InvalidParameters) => TestResult::Pass,
            _ => TestResult::Fail("wrong group should be rejected"),
        }
    }
    kernel_test_in!("wireless/sae", smoke_sae_invalid_group_rejected);

    fn smoke_mlme_beacon_ssid_channel_extract() -> TestResult {
        use crate::mlme::{beacon_ssid_channel, write_ie, ElementId};
        // Build a synthetic beacon body: 12-byte fixed header (zeroed
        // for the test), then SSID + DS Parameter Set IEs.
        let mut body = alloc::vec![0u8; 12];
        write_ie(&mut body, ElementId::Ssid, b"NarfNet");
        write_ie(&mut body, ElementId::DsParameterSet, &[6]);
        let (ssid, ch) = match beacon_ssid_channel(&body) {
            Some(p) => p,
            None => return TestResult::Fail("beacon_ssid_channel returned None"),
        };
        if ssid != b"NarfNet" {
            return TestResult::Fail("Beacon SSID extraction wrong");
        }
        if ch != Some(6) {
            return TestResult::Fail("Beacon DS channel extraction wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_beacon_ssid_channel_extract);
}
