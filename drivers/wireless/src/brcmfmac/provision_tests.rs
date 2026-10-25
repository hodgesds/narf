//! Independent literal NBSP layout, then real-registry ownership proofs.
use super::*;
use crate::brcmfmac::boot;
use narf_capabilities::Write;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("provision/golden.rs");

pub(crate) const TEST_MANIFEST: &str = "narf-test/brcm/board-selection";
const FW: &[u8] = &[0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6];
const NV: &[u8] = b"boardrev=1\n";
const CLM: &[u8] = b"inert-clm";
fn envelope(payload: &[u8], signed: bool) -> Vec<u8> {
    let mut result = payload.to_vec();
    if signed {
        // Known private seed exists only in this kernel-test module. These
        // keys/blobs never qualify a deployment canonical manifest name.
        let seed = [0x69; 32];
        let public = narf_crypto::ed25519::ed25519_public_key(&seed);
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(&public);
        let fingerprint = hash.finalize();
        narf_firmware::register_trusted_signer(fingerprint, public);
        result.extend_from_slice(&narf_crypto::ed25519::ed25519_sign(
            &seed,
            &narf_crypto::blake3_hash(payload),
        ));
        result.extend_from_slice(&fingerprint);
    } else {
        result.extend_from_slice(&[0; 96]);
    }
    result.extend_from_slice(&[0; 4]);
    result.extend_from_slice(&narf_firmware::BLOB_TRAILER_MAGIC);
    result
}
struct Install<'a> {
    name: &'static str,
    bytes: &'a [u8],
}
impl CapOp<FirmwareRegistry, Write> for Install<'_> {
    type Output = Result<(), narf_firmware::FirmwareError>;
    fn execute(self, cap: &Cap<FirmwareRegistry, Write>) -> Result<Self::Output, CapError> {
        Ok(narf_firmware::install(self.name, self.bytes, cap))
    }
}
fn install(
    write: &Cap<FirmwareRegistry, Write>,
    name: &'static str,
    payload: &[u8],
    signed: bool,
) -> Result<(), narf_firmware::FirmwareError> {
    write
        .invoke(Install {
            name,
            bytes: &envelope(payload, signed),
        })
        .map_err(|_| narf_firmware::FirmwareError::AuthorityRevoked)?
}
type RegistryCaps = (Cap<FirmwareRegistry, Write>, Cap<FirmwareRegistry, Read>);
pub(crate) fn registry() -> Result<RegistryCaps, &'static str> {
    let (write, read) = narf_firmware::bootstrap_authority();
    for (key, bytes) in [
        ("narf-test/brcm/fw", FW),
        ("narf-test/brcm/nv", NV),
        ("narf-test/brcm/clm", CLM),
        (TEST_MANIFEST, MANIFEST_BYTES.as_slice()),
    ] {
        install(&write, key, bytes, true).map_err(|_| "signed fixture registry installation")?;
    }
    Ok((write, read))
}
/// Independent Python hashlib hashes for statically impossible loader shapes.
/// CR4 stages the real one-byte image. The SDIO record declares 4 MiB+1;
/// current registry coherent backing cannot represent that payload at all.
pub(crate) fn stage_invalid_executable(write: &Cap<FirmwareRegistry, Write>, family: Family) {
    let (record, length, hash) = match family {
        Family::Pcie43602 => (
            0,
            1u32,
            [
                0x3f, 0x39, 0xd5, 0xc3, 0x48, 0xe5, 0xb7, 0x9d, 0x06, 0xe8, 0x42, 0xc1, 0x14, 0xe6,
                0xcc, 0x57, 0x15, 0x83, 0xbb, 0xf4, 0x4e, 0x4b, 0x0e, 0xbf, 0xda, 0x1a, 0x01, 0xec,
                0x05, 0x74, 0x5d, 0x43,
            ],
        ),
        Family::Sdio43439 => (
            1,
            4_194_305u32,
            [
                0x13, 0xa0, 0x67, 0xb2, 0x4d, 0xa3, 0x2b, 0x2b, 0xfd, 0xa4, 0xe2, 0xf9, 0x48, 0x90,
                0xba, 0xa5, 0x3a, 0x6f, 0x01, 0x56, 0x6f, 0x9f, 0x40, 0xa6, 0x4e, 0x90, 0x67, 0xe0,
                0x9c, 0xb0, 0x89, 0x3a,
            ],
        ),
    };
    if family == Family::Pcie43602 {
        install(write, "narf-test/brcm/fw", b"D", true).unwrap();
    }
    let mut manifest = MANIFEST_BYTES.to_vec();
    let at = HEADER + record * RECORD + 112;
    manifest[at + 4..at + 8].copy_from_slice(&length.to_le_bytes());
    manifest[at + 8..at + 40].copy_from_slice(&hash);
    install(write, TEST_MANIFEST, &manifest, true).unwrap();
}

pub(crate) fn choose(
    read: &Cap<FirmwareRegistry, Read>,
    family: Family,
) -> Result<Selection, Error> {
    let rows = parse(&MANIFEST_BYTES)?;
    let row = &rows[if family == Family::Pcie43602 { 0 } else { 1 }];
    select_using(
        read,
        TEST_MANIFEST,
        family,
        row.host,
        if family == Family::Sdio43439 {
            Some((1, 0x2d0, 0xa9af))
        } else {
            None
        },
    )
}
pub(crate) fn selected_fixture(family: Family) -> Result<(Selection, Assets), &'static str> {
    let (_, read) = registry()?;
    let selection = choose(&read, family).map_err(|_| "real signed board selection")?;
    let assets = selection
        .load_using(&read)
        .map_err(|_| "real signed selected assets")?;
    Ok((selection, assets))
}

fn smoke_brcm_board_selection_real_registry_identity_asset_and_signature_binding() -> TestResult {
    let (write, read) = match registry() {
        Ok(value) => value,
        Err(reason) => return TestResult::Fail(reason),
    };
    for family in [Family::Pcie43602, Family::Sdio43439] {
        let selection = choose(&read, family).unwrap();
        let assets = selection.load_using(&read).unwrap();
        if assets.firmware != FW
            || assets.nvram != NV
            || family == Family::Sdio43439 && assets.clm != CLM
            || assets.proof.validate().is_err()
        {
            return TestResult::Fail(
                "verified selected bytes differ from independent SHA256/key/length fixture",
            );
        }
        let mut host = selection.host;
        host.id.subsystem_id ^= 1;
        if select_using(
            &read,
            TEST_MANIFEST,
            family,
            host,
            if family == Family::Sdio43439 {
                Some((1, 0x2d0, 0xa9af))
            } else {
                None
            },
        )
        .is_ok()
        {
            return TestResult::Fail("board selection ignored actual host subsystem identity");
        }
        let mut moved = selection.host;
        if let narf_bus::BusAddr::Pcie(ref mut address) = moved.address {
            address.function ^= 1;
        }
        if select_using(
            &read,
            TEST_MANIFEST,
            family,
            moved,
            if family == Family::Sdio43439 {
                Some((1, 0x2d0, 0xa9af))
            } else {
                None
            },
        )
        .is_ok()
        {
            return TestResult::Fail("board selection ignored exact host address");
        }
        if !selection.admits_chip(
            if family == Family::Pcie43602 {
                43602
            } else {
                43439
            },
            if family == Family::Pcie43602 { 3 } else { 0 },
        ) || selection.admits_chip(43602, 15)
        {
            return TestResult::Fail("board selection chip/revision mask mismatch");
        }
    }
    let sdio = choose(&read, Family::Sdio43439).unwrap();
    if select_using(
        &read,
        TEST_MANIFEST,
        Family::Sdio43439,
        sdio.host,
        Some((2, 0x2d0, 0xa9af)),
    )
    .is_ok()
        || select_using(
            &read,
            TEST_MANIFEST,
            Family::Sdio43439,
            sdio.host,
            Some((1, 0x2d0, 0xa9ae)),
        )
        .is_ok()
    {
        return TestResult::Fail("board selection ignored actual F1 identity");
    }
    let selection = choose(&read, Family::Pcie43602).unwrap();
    install(&write, "narf-test/brcm/fw", &[9; 8], true).unwrap();
    if !matches!(selection.load_using(&read), Err(Error::Mismatch)) {
        return TestResult::Fail("independently signed wrong firmware hash satisfied selection");
    }
    install(&write, "narf-test/brcm/fw", FW, true).unwrap();
    let mut changed = MANIFEST_BYTES.to_vec();
    changed[HEADER + 112 + 4] = 9;
    install(&write, TEST_MANIFEST, &changed, true).unwrap();
    if !matches!(
        choose(&read, Family::Pcie43602).unwrap().load_using(&read),
        Err(Error::Mismatch)
    ) {
        return TestResult::Fail("selected firmware length mismatch accepted");
    }
    let mut changed = MANIFEST_BYTES.to_vec();
    let at = HEADER + 112 + 40;
    changed[at..at + 128].fill(0);
    let missing = b"narf-test/brcm/absent-image";
    changed[at..at + missing.len()].copy_from_slice(missing);
    install(&write, TEST_MANIFEST, &changed, true).unwrap();
    if !matches!(
        choose(&read, Family::Pcie43602).unwrap().load_using(&read),
        Err(Error::Missing)
    ) {
        return TestResult::Fail("missing selected key fell back to generic chip filename");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/provision",
    smoke_brcm_board_selection_real_registry_identity_asset_and_signature_binding
);

fn smoke_brcm_board_selection_never_trusts_unsigned_manifest_or_calibration() -> TestResult {
    let (write, read) = match registry() {
        Ok(value) => value,
        Err(reason) => return TestResult::Fail(reason),
    };
    match install(&write, TEST_MANIFEST, &MANIFEST_BYTES, false) {
        Ok(()) => {
            if !matches!(choose(&read, Family::Pcie43602), Err(Error::Unsigned)) {
                return TestResult::Fail("unsigned developer manifest granted board identity");
            }
        }
        Err(narf_firmware::FirmwareError::UnsignedRejected) => {}
        Err(_) => return TestResult::Fail("unexpected unsigned-manifest registry error"),
    }
    install(&write, TEST_MANIFEST, &MANIFEST_BYTES, true).unwrap();
    match install(&write, "narf-test/brcm/nv", NV, false) {
        Ok(()) => {
            if !matches!(
                choose(&read, Family::Pcie43602).unwrap().load_using(&read),
                Err(Error::Unsigned)
            ) {
                return TestResult::Fail("unsigned developer NVRAM granted board calibration");
            }
        }
        Err(narf_firmware::FirmwareError::UnsignedRejected) => {}
        Err(_) => return TestResult::Fail("unexpected unsigned-calibration registry error"),
    }
    install(&write, "narf-test/brcm/nv", NV, true).unwrap();
    match install(&write, "narf-test/brcm/clm", CLM, false) {
        Ok(()) => {
            if !matches!(
                choose(&read, Family::Sdio43439).unwrap().load_using(&read),
                Err(Error::Unsigned)
            ) {
                return TestResult::Fail("unsigned developer CLM granted calibration authority");
            }
        }
        Err(narf_firmware::FirmwareError::UnsignedRejected) => {}
        Err(_) => return TestResult::Fail("unexpected unsigned-CLM registry error"),
    }
    install(&write, "narf-test/brcm/clm", CLM, true).unwrap();
    match install(&write, "narf-test/brcm/fw", FW, false) {
        Ok(()) => {
            if choose(&read, Family::Pcie43602)
                .unwrap()
                .load_using(&read)
                .is_err()
            {
                return TestResult::Fail(
                    "board loader overrode explicit developer executable policy",
                );
            }
        }
        Err(narf_firmware::FirmwareError::UnsignedRejected) => {}
        Err(_) => return TestResult::Fail("unexpected unsigned-executable registry error"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/provision",
    smoke_brcm_board_selection_never_trusts_unsigned_manifest_or_calibration
);

fn smoke_brcm_board_selection_pins_replacement_and_honors_current_source_epochs() -> TestResult {
    let (write, read) = match registry() {
        Ok(value) => value,
        Err(reason) => return TestResult::Fail(reason),
    };
    let selection = choose(&read, Family::Pcie43602).unwrap();
    let assets = selection.load_using(&read).unwrap();
    install(&write, "narf-test/brcm/fw", &[9; 8], true).unwrap();
    if assets.proof.validate().is_err()
        || assets.firmware != FW
        || !matches!(selection.load_using(&read), Err(Error::Mismatch))
    {
        return TestResult::Fail(
            "hot replacement retargeted pinned owner or mismatched new asset admitted",
        );
    }
    install(&write, "narf-test/brcm/fw", FW, true).unwrap();
    let assets = selection.load_using(&read).unwrap();
    assets.proof.receipts[1].cap.revoke();
    if assets.proof.validate().is_ok() {
        return TestResult::Fail("actual registry blob epoch revocation ignored");
    }
    read.revoke();
    if choose(&read, Family::Pcie43602).is_ok() {
        return TestResult::Fail("revoked current registry authority read manifest");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/provision",
    smoke_brcm_board_selection_pins_replacement_and_honors_current_source_epochs
);

fn smoke_brcm_revoked_board_source_precedes_native_pcie_configuration_dma_and_mmio() -> TestResult {
    use super::super::{chip::Backplane, pcie::PcieBackplane};
    let (selection, assets) = match selected_fixture(Family::Pcie43602) {
        Ok(value) => value,
        Err(reason) => return TestResult::Fail(reason),
    };
    assets.proof.receipts[0].cap.revoke();
    let host = selection.host();
    let narf_bus::BusAddr::Pcie(address) = host.address else {
        return TestResult::Fail("fixture PCI identity");
    };
    let device = narf_bus::BusDevice {
        addr: host.address,
        id: host.id,
        kind: narf_bus::BusKind::Pcie {
            addr: address,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let cap = Cap::<narf_bus::BusDeviceCap, Write>::bootstrap();
    let region = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 4096,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // Deliberately invalid config/BAR addresses must remain unreachable even
    // with a live PCI cap when the actual board source instance was revoked.
    let mut bus = PcieBackplane {
        proof: Some(assets.proof),
        bar0: region,
        bar2: Some(region),
        device,
        cap,
        pcie_core: None,
    };
    if bus.read32(0x18000000).is_ok()
        || bus.write32(0x18000000, 0).is_ok()
        || boot::Bus::read_tcm(&mut bus, 0, &mut [0; 4]).is_ok()
        || boot::Bus::write_tcm(&mut bus, 0, &[0; 4]).is_ok()
        || super::super::runtime::Bus::allocate(&mut bus, 128).is_ok()
        || super::super::runtime::Bus::enable_dma(&mut bus).is_ok()
    {
        return TestResult::Fail("revoked board source reached native PCI configuration/DMA/MMIO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/provision",
    smoke_brcm_revoked_board_source_precedes_native_pcie_configuration_dma_and_mmio
);

struct FunctionModel(Arc<core::sync::atomic::AtomicUsize>);
impl narf_drivers_sdio::SdioFunction for FunctionModel {
    fn cmd52_read(&mut self, _: u8, _: u32) -> Result<u8, narf_drivers_sdio::SdioError> {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(0)
    }
    fn cmd52_write(&mut self, _: u8, _: u32, _: u8) -> Result<(), narf_drivers_sdio::SdioError> {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn cmd53_read(
        &mut self,
        _: u8,
        _: u32,
        bytes: &mut [u8],
    ) -> Result<(), narf_drivers_sdio::SdioError> {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        bytes.fill(0);
        Ok(())
    }
    fn cmd53_write(&mut self, _: u8, _: u32, _: &[u8]) -> Result<(), narf_drivers_sdio::SdioError> {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn cmd53_block_read(
        &mut self,
        f: u8,
        a: u32,
        _: u16,
        _: u16,
        b: &mut [u8],
    ) -> Result<(), narf_drivers_sdio::SdioError> {
        self.cmd53_read(f, a, b)
    }
    fn cmd53_block_write(
        &mut self,
        f: u8,
        a: u32,
        _: u16,
        _: u16,
        b: &[u8],
    ) -> Result<(), narf_drivers_sdio::SdioError> {
        self.cmd53_write(f, a, b)
    }
    fn enable_func(&mut self, _: u8) -> Result<(), narf_drivers_sdio::SdioError> {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn set_block_size(&mut self, _: u8, _: u16) -> Result<(), narf_drivers_sdio::SdioError> {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}
fn smoke_cyw_selected_source_revocation_blocks_actual_sdio_transport_dispatch() -> TestResult {
    use crate::cyw43439::{
        sdio_bridge::SdioTransport,
        transport::{Function, PacketTransport, Transport},
    };
    let (_, assets) = match selected_fixture(Family::Sdio43439) {
        Ok(value) => value,
        Err(reason) => return TestResult::Fail(reason),
    };
    let calls = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let mut transport =
        SdioTransport::new(FunctionModel(calls.clone())).qualify(assets.proof.clone());
    if transport.prepare().is_err() || transport.initialize_packets(0x18011000).is_err() {
        return TestResult::Fail("qualified SDIO setup failed");
    }
    let before = calls.load(core::sync::atomic::Ordering::Acquire);
    assets.proof.receipts[2].cap.revoke();
    if transport.transmit_packet(&[0; 12]).is_ok()
        || transport.receive_packet(&mut [0; 64]).is_ok()
        || transport.write32(Function::Backplane, 0, 0).is_ok()
        || calls.load(core::sync::atomic::Ordering::Acquire) != before
    {
        return TestResult::Fail("revoked calibration source reached F1/F2 command dispatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/provision",
    smoke_cyw_selected_source_revocation_blocks_actual_sdio_transport_dispatch
);

fn smoke_brcm_signed_board_manifest_literal_layout_and_rejections() -> TestResult {
    let records = match parse(&MANIFEST_BYTES) {
        Ok(records) => records,
        Err(_) => return TestResult::Fail("independent NBSP layout rejected"),
    };
    if records.len() != 2
        || records[0].family != Family::Pcie43602
        || records[1].family != Family::Sdio43439
        || records[0].revisions != 8
        || records[1].revisions != 1
        || records[0].assets[0].length != 8
        || records[0].assets[1].length != 11
    {
        return TestResult::Fail("literal NBSP identities/assets decoded incorrectly");
    }
    for at in [
        4,
        6,
        7,
        14,
        16 + 7,
        16 + 96,
        16 + 112,
        16 + 112 + 2,
        16 + 112 + ASSET + 1,
    ] {
        let mut bytes = MANIFEST_BYTES.to_vec();
        bytes[at] ^= 0x80;
        if parse(&bytes).is_ok() {
            return TestResult::Fail("malformed NBSP version/extent/reserved/asset role accepted");
        }
    }
    for length in [0, 15, 16, MANIFEST_BYTES.len() - 1] {
        if parse(&MANIFEST_BYTES[..length]).is_ok() {
            return TestResult::Fail("truncated NBSP manifest accepted");
        }
    }
    let mut duplicate = MANIFEST_BYTES[..HEADER + RECORD].to_vec();
    duplicate.extend_from_slice(&MANIFEST_BYTES[HEADER..HEADER + RECORD]);
    let length = duplicate.len() as u32;
    duplicate[8..12].copy_from_slice(&length.to_le_bytes());
    duplicate[12..14].copy_from_slice(&2u16.to_le_bytes());
    if !matches!(parse(&duplicate), Err(Error::Ambiguous)) {
        return TestResult::Fail("ambiguous NBSP selectors accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/provision",
    smoke_brcm_signed_board_manifest_literal_layout_and_rejections
);

fn smoke_brcm_signed_manifest_family_executable_boundaries_precede_asset_loading() -> TestResult {
    // Literal old-loader boundaries; no call to the production shape helper.
    for (record, length, accepted) in [
        (0, 0u32, false),
        (0, 1, false),
        (0, 3, false),
        (0, 4, true),
        (1, 0, false),
        (1, 1, true),
        (1, 4_194_304, true),
        (1, 4_194_305, false),
    ] {
        let mut manifest = MANIFEST_BYTES.to_vec();
        let at = HEADER + record * RECORD + 112 + 4;
        manifest[at..at + 4].copy_from_slice(&length.to_le_bytes());
        if parse(&manifest).is_ok() != accepted {
            return TestResult::Fail(
                "signed retained executable shape disagrees with original loader boundaries",
            );
        }
    }
    let (write, read) = registry().unwrap();
    stage_invalid_executable(&write, Family::Pcie43602);
    if !matches!(choose(&read, Family::Pcie43602), Err(Error::Invalid))
        || !matches!(
            trusted_assets_using(&read, "narf-test/brcm/fw", "narf-test/brcm/nv"),
            Err(Error::Invalid)
        )
    {
        return TestResult::Fail(
            "short exact signed CR4 executable bypassed manifest or trusted-platform preflight",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/provision",
    smoke_brcm_signed_manifest_family_executable_boundaries_precede_asset_loading
);
