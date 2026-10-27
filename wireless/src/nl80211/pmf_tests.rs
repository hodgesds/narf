//! Required-PMF WPA2 admission through the real CONNECT parser.
use super::*;

// IEEE RSNE: CCMP group/pairwise, PSK, MFPC|MFPR, zero PMKIDs, BIP-CMAC128.
const REQUIRED: [u8; 28] = [
    48, 26, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 192, 0, 0, 0, 0, 15,
    172, 6,
];

fn connect(ie: Option<&[u8]>, mfp: Option<u32>) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_attr(&mut bytes, 52, b"pmf-test");
    push_attr(&mut bytes, 254, &[0x42; 32]);
    for (kind, value) in [
        (75, 2u32),
        (76, 0x000fac02),
        (73, 0x000fac04),
        (74, 0x000fac04),
    ] {
        push_attr(&mut bytes, kind, &value.to_ne_bytes());
    }
    if let Some(mode) = mfp {
        push_attr(&mut bytes, 66, &mode.to_ne_bytes());
    }
    if let Some(ie) = ie {
        push_attr(&mut bytes, 42, ie);
    }
    bytes
}

fn check() -> Result<(), &'static str> {
    let supported = ConnectCaps {
        psk_offload: true,
        psk_mfp_offload: true,
        cipher_suites: &[crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_AES_CMAC],
        ..ConnectCaps::default()
    };
    let parse =
        |bytes: &[u8], caps| parse_operation_caps(CONNECT, &attributes(bytes).unwrap(), caps, 0);
    for length in [22, 24, 28] {
        let mut ie = REQUIRED[..length].to_vec();
        ie[1] = (length - 2) as u8;
        if !matches!(
            parse(&connect(Some(&ie), Some(1)), supported),
            Ok(Operation::Connect { cred: Credential::Psk(ref pmk), ie: ref actual, .. })
                if **pmk == [0x42; 32] && *actual == ie
        ) {
            return Err("required/default BIP PMF did not preserve the exact CONNECT request");
        }
    }
    let unsupported = ConnectCaps {
        psk_mfp_offload: false,
        ..supported
    };
    if !matches!(
        parse(&connect(Some(&REQUIRED), Some(1)), unsupported),
        Err(EOPNOTSUPP)
    ) {
        return Err("BIP cipher advertisement fabricated required-PMF handshake support");
    }
    let stub = InterfaceStub {
        name: "pmf-default-closed",
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    };
    if ConnectCaps::of(&stub).psk_mfp_offload {
        return Err("required-PMF offload default was not closed");
    }
    if !matches!(
        parse(&connect(None, None), unsupported),
        Ok(Operation::Connect { .. })
    ) {
        return Err("ordinary WPA2 CONNECT regressed");
    }
    for (ie, mode) in [
        (None, Some(1)),
        (Some(&REQUIRED[..]), Some(0)),
        (Some(&REQUIRED[..]), None),
        (Some(&REQUIRED[..]), Some(2)),
    ] {
        if parse(&connect(ie, mode), supported).is_ok() {
            return Err("required/optional MFP attributes silently downgraded");
        }
    }
    for offset in [2, 13, 19, 20, 27] {
        let mut ie = REQUIRED;
        ie[offset] = match offset {
            20 => 128,
            _ => ie[offset] ^ 1,
        };
        if parse(&connect(Some(&ie), Some(1)), supported).is_ok() {
            return Err("unsupported required-PMF version/suite/capability accepted");
        }
    }
    let mut missing_mfpc = REQUIRED;
    missing_mfpc[20] = 64;
    if parse(&connect(Some(&missing_mfpc), Some(1)), supported).is_ok() {
        return Err("MFPR without MFPC accepted");
    }
    let mut ocv = REQUIRED;
    ocv[21] = 64;
    if parse(&connect(Some(&ocv), Some(1)), supported).is_ok() {
        return Err("required OCV promise silently discarded by PMF offload");
    }
    for length in 0..REQUIRED.len() {
        if parse(&connect(Some(&REQUIRED[..length]), Some(1)), supported).is_ok() {
            return Err("truncated required-PMF RSNE accepted");
        }
    }
    let mut duplicate = REQUIRED.to_vec();
    duplicate.extend_from_slice(&REQUIRED);
    let mut trailing = REQUIRED.to_vec();
    trailing[1] += 1;
    trailing.push(0);
    for ie in [duplicate, trailing, alloc::vec![0; 2050]] {
        if parse(&connect(Some(&ie), Some(1)), supported).is_ok() {
            return Err("duplicate/trailing/unbounded required-PMF IE accepted");
        }
    }
    Ok(())
}

fn smoke_nl80211_required_pmf_psk_capability_and_rsne_admission() -> TestResult {
    check().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_required_pmf_psk_capability_and_rsne_admission
);

fn optional_admission() -> Result<(), &'static str> {
    let parse =
        |bytes: &[u8], caps| parse_operation_caps(CONNECT, &attributes(bytes).unwrap(), caps, 0);
    let mut optional = REQUIRED;
    optional[20] = 128;
    for offload in [false, true] {
        for required in [false, true] {
            for capable in [false, true] {
                let caps = ConnectCaps {
                    psk_offload: offload,
                    psk_mfp_offload: required,
                    optional_mfp: capable,
                    ..ConnectCaps::default()
                };
                let result = parse(&connect(Some(&optional), Some(2)), caps);
                if result.is_ok() != (offload && required && capable) {
                    return Err("optional PMF inferred from incomplete firmware capabilities");
                }
            }
        }
    }
    let supported = ConnectCaps {
        psk_offload: true,
        psk_mfp_offload: true,
        optional_mfp: true,
        ..ConnectCaps::default()
    };
    for length in [22, 24, 28] {
        let mut ie = optional[..length].to_vec();
        ie[1] = (length - 2) as u8;
        if !matches!(
            parse(&connect(Some(&ie), Some(2)), supported),
            Ok(Operation::Connect { cred: Credential::Psk(ref key), ie: ref actual, .. })
                if **key == [0x42; 32] && *actual == ie
        ) {
            return Err("optional PMF lost its original caller RSNE or default BIP format");
        }
    }
    for mode in [None, Some(0), Some(1)] {
        if parse(&connect(Some(&optional), mode), supported).is_ok() {
            return Err("MFPC-only RSNE bypassed explicit optional-PMF policy");
        }
    }
    for ie in [None, Some(&REQUIRED[..])] {
        if parse(&connect(ie, Some(2)), supported).is_ok() {
            return Err("optional PMF accepted missing or required-PMF caller RSNE");
        }
    }
    let mut bad = Vec::new();
    for offset in [13, 19, 20, 27] {
        let mut ie = optional.to_vec();
        ie[offset] ^= 1;
        bad.push(ie);
    }
    let mut ocv = optional.to_vec();
    ocv[21] |= 64;
    bad.push(ocv);
    let mut no_mfpc = optional.to_vec();
    no_mfpc[20] = 0;
    bad.push(no_mfpc);
    let mut duplicate = optional.to_vec();
    duplicate.extend_from_slice(&optional);
    bad.push(duplicate);
    let mut pmkid = optional[..24].to_vec();
    pmkid[1] = 38;
    pmkid[22] = 1;
    pmkid.extend_from_slice(&[0; 16]);
    bad.push(pmkid);
    for ie in bad {
        if parse(&connect(Some(&ie), Some(2)), supported).is_ok() {
            return Err("optional PMF accepted unsupported suites, OCV, PMKID or duplicate RSNE");
        }
    }
    for length in 0..optional.len() {
        if parse(&connect(Some(&optional[..length]), Some(2)), supported).is_ok() {
            return Err("optional PMF accepted a truncated original RSNE");
        }
    }
    let mut external = Vec::new();
    for (id, body) in attributes(&connect(Some(&optional), Some(2))).unwrap() {
        if id != 254 {
            push_attr(&mut external, id, body);
        }
    }
    if parse(
        &external,
        ConnectCaps {
            external: true,
            ..supported
        },
    )
    .is_ok()
    {
        return Err("optional firmware PMF leaked into the external-supplicant path");
    }
    Ok(())
}
fn smoke_nl80211_optional_pmf_requires_explicit_policy_capabilities_and_exact_rsne() -> TestResult {
    optional_admission().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_optional_pmf_requires_explicit_policy_capabilities_and_exact_rsne
);

struct OptionalMfpIface {
    base: InterfaceStub,
    flags: u8,
}
impl Interface for OptionalMfpIface {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.base.mac()
    }
    fn mtu(&self) -> u32 {
        self.base.mtu()
    }
    fn link_up(&self) -> bool {
        false
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.base.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.base.tx_ring()
    }
}
#[async_trait::async_trait]
impl crate::WirelessNetIface for OptionalMfpIface {
    fn supports_handshake_offload(&self) -> bool {
        self.flags & 1 != 0
    }
    fn supports_wpa2_mfp_offload(&self) -> bool {
        self.flags & 2 != 0
    }
    fn supports_optional_mfp(&self) -> bool {
        self.flags & 4 != 0
    }
    fn supports_userspace_mlme(&self) -> bool {
        self.flags & 8 != 0
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        crate::WirelessNetIface::get_wireless_info(&self.base)
    }
    async fn scan(
        &self,
        _: crate::ScanRequest,
    ) -> Result<Vec<crate::BssInfo>, crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
}
fn smoke_nl80211_optional_mfp_wiphy_bit_and_parser_use_complete_offload_contract() -> TestResult {
    for flags in 0..16 {
        let iface = OptionalMfpIface {
            base: InterfaceStub {
                name: "optional-pmf-capability",
                rx: IrqSafeSpinLock::new(None),
                tx: IrqSafeSpinLock::new(None),
            },
            flags,
        };
        let mut attrs = Vec::new();
        wiphy_security_attrs(&mut attrs, &iface);
        let ext = find_attr(&attrs, 217).unwrap_or(&[]);
        // Independent Linux UAPI value: NL80211_EXT_FEATURE_MFP_OPTIONAL21.
        let advertised = ext.get(2).is_some_and(|b| b & 32 != 0);
        let mut optional = REQUIRED;
        optional[20] = 128;
        let accepted = parse_operation_caps(
            CONNECT,
            &attributes(&connect(Some(&optional), Some(2))).unwrap(),
            ConnectCaps::of(&iface),
            0,
        )
        .is_ok();
        if advertised != (flags == 7) || accepted != advertised {
            return TestResult::Fail(
                "optional-PMF wiphy bit disagrees with full native PSK admission",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_optional_mfp_wiphy_bit_and_parser_use_complete_offload_contract
);
