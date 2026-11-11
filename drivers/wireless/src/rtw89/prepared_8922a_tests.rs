use super::bacam_v1;
use super::chip_8922a;
use super::dma::{TxBd, TXBD_OPT_LS, TXCH_NUM};
use super::dma_8922a::WP_SEL_BASE;
use super::dma_be::{Regs, INIT_CFG1};
use super::efuse_be::BeFactory;
use super::fw::FwError;
use super::irq::Line;
use super::mac::ChipId;
use super::mac_pre_init_8922a::{Cid, HalChipVer};
use super::prepared::{self, Files};
use super::prepared_8922a::*;
use super::ra_mask::{EhtCaps, StationCaps};
use super::station_8922a::{Band, Error as StationError, Request, SixGhzAdmission};
use super::tx_8922a::{PrepareArgs, DATA_RING_DEPTH};
use super::txrx_be::{encode_txwd_be, fill_txwd_info_v2, TxwdBeInfo, TxwdInfoV2};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use narf_bus::{BusDevice, BusDeviceCap, BusKind};
use narf_capabilities::{Cap, Write};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::PowerType6Ghz;

/// Fixture register bank implementing [`Regs`] (same shape as the
/// `dma_8922a` fixture: reads default to 0, so the DMA-idle
/// predicates pass; `bound_clears` simulates the hardware clearing
/// the BDRAM bound bit after `rst_bdram_set`).
struct Model {
    regs32: BTreeMap<u32, u32>,
    regs16: BTreeMap<u32, u16>,
    bound_clears: bool,
}

impl Model {
    fn new() -> Self {
        Self {
            regs32: BTreeMap::new(),
            regs16: BTreeMap::new(),
            bound_clears: false,
        }
    }

    fn with32(mut self, addr: u32, value: u32) -> Self {
        self.regs32.insert(addr, value);
        self
    }

    fn with_bound_clears(mut self) -> Self {
        self.bound_clears = true;
        self
    }
}

impl Regs for Model {
    fn read32(&mut self, address: u32) -> u32 {
        let value = *self.regs32.get(&address).unwrap_or(&0);
        if self.bound_clears && address == INIT_CFG1 {
            value & !(1 << 16)
        } else {
            value
        }
    }

    fn write32(&mut self, address: u32, value: u32) {
        self.regs32.insert(address, value);
    }

    fn write16(&mut self, address: u32, value: u16) {
        self.regs16.insert(address, value);
    }
}

/// [`super::irq::Regs`] over the same fixture bank, for the v2
/// interrupt programs. Infallible, like the production `MmioRegs`.
impl super::irq::Regs for Model {
    fn read32(&mut self, address: u32) -> Result<u32, super::power::Error> {
        Ok(<Self as Regs>::read32(self, address))
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), super::power::Error> {
        <Self as Regs>::write32(self, address, value);
        Ok(())
    }
}

fn test_cap() -> Cap<BusDeviceCap, Write> {
    // Fresh live BusDevice/Write fixture authority, minted via the
    // safe `Cap::bootstrap` path (SEC-B5, #1293: `Cap::mint` is
    // crate-private to `capabilities/`).
    Cap::bootstrap()
}

/// Non-PCI fixture function: MSI discovery must fail without
/// touching config space (`enable_msi` refuses VirtioMmio first).
fn mmio_device() -> BusDevice {
    let base = narf_memory::PhysAddr::new(0);
    BusDevice {
        addr: narf_bus::BusAddr::Mmio(base),
        id: narf_bus::DeviceId {
            vendor: 0x10ec,
            device: 0x8922,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::VirtioMmio {
            base,
            len: 0x1000,
            device_id: 1,
        },
    }
}

fn factory() -> BeFactory {
    BeFactory {
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        rfe_type: 0,
        xtal_cap: 0,
        country: [b'U', b'S'],
        phycap: [0u8; chip_8922a::PHYCAP_SIZE],
        cv: None,
        thermal_k: None,
        secure: super::efuse_be::SecureInfo::disabled(),
    }
}

fn base_req() -> Request<'static> {
    Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
        band: Band::Ghz5,
        width_mhz: 160,
        primary: 36,
        nss: 2,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: true,
        punctured: 0,
        peer_ies: &[],
        has_he: true,
        mgq_rpt_en: false,
        p2p: false,
        six_ghz: None,
    }
}

fn eht_caps() -> StationCaps {
    StationCaps {
        band: Band::Ghz5,
        width_mhz: 80,
        supp_rates: 0xFF,
        ht: None,
        vht: None,
        he: None,
        eht: Some(EhtCaps {
            bw_80: [0x22, 0x11, 0x00],
            bw_160: [0; 3],
            bw_320: [0; 3],
            only_20mhz: [0; 4],
            ap_20mhz_only: false,
        }),
        rx_nss: 2,
        tx_nss: 2,
        rssi: 200,
        no_mcs_12_13: true,
        er_cap: false,
    }
}

/// `Files` that records every name requested and reports them all
/// missing, so `load` proves its walk order without a firmware blob.
struct MissingFiles {
    names: Vec<&'static str>,
}

impl Files for MissingFiles {
    fn load(&mut self, name: &'static str) -> Result<Vec<u8>, FwError> {
        self.names.push(name);
        Err(FwError::BlobMissing)
    }
}

fn smoke_rtw89_prepared_8922a_filenames() -> TestResult {
    // Linux `fw.c:1102` tries `fw_format` from `fw_format_max`
    // down to 0; `fw.h:4736` names format <= 0 `%s.bin`, else
    // `%s-%d.bin`. 8922A: basename `rtw89/rtw8922a_fw`, max 4
    // (`rtw8922a.c:18..19`).
    let names = prepared::filenames(ChipId::Rtl8922A);
    if names
        != [
            "rtw89/rtw8922a_fw-4.bin",
            "rtw89/rtw8922a_fw-3.bin",
            "rtw89/rtw8922a_fw-2.bin",
            "rtw89/rtw8922a_fw-1.bin",
            "rtw89/rtw8922a_fw.bin",
        ]
        .as_slice()
    {
        return TestResult::Fail("8922A firmware filename list wrong");
    }
    let mut files = MissingFiles { names: Vec::new() };
    match prepared::load(&mut files, ChipId::Rtl8922A, 0) {
        Err(FwError::BlobMissing) => {}
        _ => {
            return TestResult::Fail("all-missing firmware load did not report BlobMissing");
        }
    }
    if files.names.as_slice() != names {
        return TestResult::Fail("firmware load did not walk the names in order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_filenames
);

fn smoke_rtw89_prepared_8922a_full_sequence() -> TestResult {
    let f = factory();
    let mut owner = match Prepared8922a::new(f.clone(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    if owner.mac() != f.mac
        || owner.chip_version() != 0
        || owner.rings_programmed()
        || !owner.eht_profile().width_320
        || owner.eht_profile().max_mpdu_len != chip_8922a::MAX_EHT_MPDU_CAP
    {
        return TestResult::Fail("prepared owner identity/profile wrong");
    }

    // Pre-init halves in Linux order (pci_be.c:493): before-reset
    // on an idle bus, after-reset once the BDRAM bound clears.
    let mut regs = Model::new();
    if owner
        .pre_init_dma_before_reset(&mut regs, 256, 256)
        .is_err()
    {
        return TestResult::Fail("pre_init before_reset failed");
    }
    let mut regs = Model::new().with32(INIT_CFG1, 0).with_bound_clears();
    if owner.pre_init_dma_after_reset(&mut regs).is_err() {
        return TestResult::Fail("pre_init after_reset failed");
    }

    // Ring programming: 13 TX + 2 RX at the Linux maxima.
    let tx_phys: [u64; TXCH_NUM] = core::array::from_fn(|i| 0x1_0000 + (i as u64) * 0x800);
    let rx_phys: [u64; 2] = [0x2_0000, 0x2_1000];
    if owner
        .program_rings(&mut regs, &tx_phys, &rx_phys, 256, 256)
        .is_err()
    {
        return TestResult::Fail("program_rings failed");
    }
    if !owner.rings_programmed() {
        return TestResult::Fail("rings_programmed not set");
    }
    // CH0 NUM/DESA (BE set: NUM 0xB030, DESA 0xB200/0xB204).
    if regs.regs16.get(&0xB030) != Some(&256)
        || regs.regs32.get(&0xB200) != Some(&0x1_0000)
        || regs.regs32.get(&0xB204) != Some(&0)
    {
        return TestResult::Fail("CH0 ring programming wrong");
    }
    // CH12 NUM (0xB048) + RXQ doorbell seed len-1 (0xB160 = 255).
    if regs.regs16.get(&0xB048) != Some(&256) || regs.regs16.get(&0xB160) != Some(&255) {
        return TestResult::Fail("CH12/RXQ ring programming wrong");
    }
    // WP-select block: group 0 packs channels 0..3, group 12 packs
    // channels 12..15.
    if regs.regs32.get(&WP_SEL_BASE) != Some(&0x0302_0100)
        || regs.regs32.get(&(WP_SEL_BASE + 12)) != Some(&0x0F0E_0D0C)
    {
        return TestResult::Fail("wp_16sel programming wrong");
    }
    owner.post_init_dma(&mut regs);

    // Station admission composes MACID + G7 CCTL + BA-CAM + EHT.
    let macid = match owner.admit_station(&base_req()) {
        Ok(macid) => macid,
        Err(_) => return TestResult::Fail("admit_station failed"),
    };
    if macid != 0 {
        return TestResult::Fail("first MACID not 0");
    }
    let Some(station) = owner.station(0) else {
        return TestResult::Fail("admitted station not retained");
    };
    if station.peer != base_req().peer
        || station.band != Band::Ghz5
        || station.width_mhz != 160
        || station.nss != 2
        || station.aid != 7
    {
        return TestResult::Fail("admitted station record mismatch");
    }
    if owner.station_ra(0, &eht_caps()).is_err() {
        return TestResult::Fail("station_ra failed");
    }
    if owner.txwd_info_eht(0).is_none() {
        return TestResult::Fail("txwd_info_eht missing");
    }
    let bitmap = match owner.acquire_bacam(0, 0) {
        Ok(index) => index,
        Err(_) => return TestResult::Fail("acquire_bacam failed"),
    };
    if owner
        .ba_h2c(0, 0, bacam_v1::bmap_size(64), 0, bitmap as u32)
        .is_err()
    {
        return TestResult::Fail("ba_h2c failed");
    }
    if owner.release_bacam(0, bitmap).is_err() {
        return TestResult::Fail("release_bacam failed");
    }

    // Data submit on CH0 (100-byte frame, MACID 0, QSEL 0).
    let mut body = [0u8; 32];
    if encode_txwd_be(
        &TxwdBeInfo {
            channel: 0,
            qsel: 0,
            mac_id: 0,
            pkt_size: 100,
        },
        &mut body,
    )
    .is_none()
    {
        return TestResult::Fail("encode_txwd_be failed");
    }
    let mut bd = vec![TxBd::default(); DATA_RING_DEPTH as usize];
    let mut regs = Model::new();
    let prepared = match owner.prepare_data(PrepareArgs {
        channel: 0,
        mac_id: 0,
        qsel: 0,
        body: &body,
        header_dma: 0x20000,
        frame_dma: 0x10000,
        frame_len: 100,
        bd: &mut bd,
    }) {
        Ok(prepared) => prepared,
        Err(_) => return TestResult::Fail("prepare_data failed"),
    };
    if prepared.ticket.slot != 0
        || prepared.ticket.sequence != 0
        || prepared.header.len() != 46
        || bd[0].length != 46
        || bd[0].opt != TXBD_OPT_LS
        || bd[0].dma != 0x20000
    {
        return TestResult::Fail("prepared frame/TXBD wrong");
    }
    let wp = match owner.kick_data(&mut regs, &prepared) {
        Ok(wp) => wp,
        Err(_) => return TestResult::Fail("kick_data failed"),
    };
    if wp != 1 || regs.regs16.get(&0xB100) != Some(&1) {
        return TestResult::Fail("kick_data doorbell wrong");
    }
    if owner.kick_data(&mut regs, &prepared).is_ok() {
        return TestResult::Fail("double kick accepted");
    }

    // Completion: RP update first (no completion yet — the report
    // half is still missing), then the 4-byte RPQ record
    // (seq 0, status 1, qsel 0, mac 0).
    let mut regs = Model::new();
    regs.regs32.insert(0xB100, 0x0001_0000); // HW RP 1, host WP 0.
    match owner.observe_data_rp(&mut regs, 0) {
        Ok(completed) if completed.is_empty() => {}
        _ => return TestResult::Fail("RP update completed without a report"),
    }
    let record = 1u32 << 13;
    match owner.observe_data_report(&record.to_le_bytes()) {
        Ok(Some(completion))
            if completion.status == 1
                && completion.resource.header_dma == 0x20000
                && completion.resource.frame_dma == 0x10000 => {}
        _ => return TestResult::Fail("RPQ release did not complete"),
    }

    // H2C submit on CH12 (caller-framed 64-byte buffer).
    let mut bd12 = vec![TxBd::default(); DATA_RING_DEPTH as usize];
    let mut regs = Model::new();
    let h2c = match owner.prepare_h2c(&mut bd12, 0x30000, 64) {
        Ok(h2c) => h2c,
        Err(_) => return TestResult::Fail("prepare_h2c failed"),
    };
    if h2c.slot != 0 || bd12[0].length != 64 || bd12[0].dma != 0x30000 {
        return TestResult::Fail("prepared H2C/TXBD wrong");
    }
    let wp = match owner.kick_h2c(&mut regs, &h2c) {
        Ok(wp) => wp,
        Err(_) => return TestResult::Fail("kick_h2c failed"),
    };
    if wp != 1 || regs.regs16.get(&0xB130) != Some(&1) {
        return TestResult::Fail("kick_h2c doorbell wrong");
    }

    // Release returns the MACID to the pool (next admit reuses 0).
    owner.release_station(0);
    if owner.station(0).is_some() {
        return TestResult::Fail("released station still retained");
    }
    if owner.admit_station(&base_req()) != Ok(0) {
        return TestResult::Fail("MACID not returned to the pool");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_full_sequence
);

fn smoke_rtw89_prepared_8922a_refusals() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    let body = [0u8; 32];
    let mut bd = vec![TxBd::default(); DATA_RING_DEPTH as usize];
    // Transport before ring programming is refused.
    if owner
        .prepare_data(PrepareArgs {
            channel: 0,
            mac_id: 0,
            qsel: 0,
            body: &body,
            header_dma: 0x20000,
            frame_dma: 0x10000,
            frame_len: 100,
            bd: &mut bd,
        })
        .is_ok()
    {
        return TestResult::Fail("prepare_data before program_rings accepted");
    }
    if owner.prepare_h2c(&mut bd, 0x30000, 64).is_ok() {
        return TestResult::Fail("prepare_h2c before program_rings accepted");
    }
    // 6 GHz without a power program is refused; with one (20 MHz
    // LPI) it admits through the Prepared owner. 320 MHz admission
    // is refused (later steps).
    let mut six_ghz = base_req();
    six_ghz.band = Band::Ghz6;
    if owner.admit_station(&six_ghz) != Err(Error::Station(StationError::SixGhzPowerMissing)) {
        return TestResult::Fail("6 GHz admission not refused");
    }
    six_ghz.width_mhz = 20;
    six_ghz.primary = 5;
    six_ghz.six_ghz = Some(SixGhzAdmission {
        power: PowerType6Ghz::Lpi,
        tpe_dbm: None,
    });
    let macid = match owner.admit_station(&six_ghz) {
        Ok(macid) => macid,
        Err(_) => return TestResult::Fail("6 GHz LPI admission refused"),
    };
    if owner.station(macid).is_none_or(|st| st.six_ghz().is_none()) {
        return TestResult::Fail("6 GHz station records no power program");
    }
    let mut wide = base_req();
    wide.width_mhz = 320;
    if owner.admit_station(&wide) != Err(Error::Station(StationError::WidthNotAdvertised)) {
        return TestResult::Fail("320 MHz admission not refused");
    }
    // Ring-length bounds.
    let tx_phys: [u64; TXCH_NUM] = [0x1_0000; TXCH_NUM];
    let rx_phys: [u64; 2] = [0x2_0000, 0x2_1000];
    let mut regs = Model::new();
    if owner
        .program_rings(&mut regs, &tx_phys, &rx_phys, 0, 256)
        .is_ok()
        || owner
            .program_rings(&mut regs, &tx_phys, &rx_phys, 257, 256)
            .is_ok()
    {
        return TestResult::Fail("out-of-range ring length accepted");
    }
    if owner
        .program_rings(&mut regs, &tx_phys, &rx_phys, 256, 256)
        .is_err()
    {
        return TestResult::Fail("program_rings failed");
    }
    // Data for an unadmitted MACID is refused even with rings up.
    if owner
        .prepare_data(PrepareArgs {
            channel: 0,
            mac_id: 5,
            qsel: 0,
            body: &body,
            header_dma: 0x20000,
            frame_dma: 0x10000,
            frame_len: 100,
            bd: &mut bd,
        })
        .is_ok()
    {
        return TestResult::Fail("prepare_data for unadmitted MACID accepted");
    }
    if owner.station_ra(5, &eht_caps()) != Err(Error::NoStation) {
        return TestResult::Fail("station_ra for unadmitted MACID accepted");
    }
    // stop_dma clears the programmed mark; the transport refuses
    // again until the rings are re-programmed.
    if owner.stop_dma(&mut regs).is_err() || owner.rings_programmed() {
        return TestResult::Fail("stop_dma did not clear the programmed mark");
    }
    if owner.prepare_h2c(&mut bd, 0x30000, 64).is_ok() {
        return TestResult::Fail("prepare_h2c after stop_dma accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_refusals
);

fn smoke_rtw89_prepared_8922a_irq_unarmed_is_polled() -> TestResult {
    let f = factory();
    let mut owner = match Prepared8922a::new(f, 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    let mut regs = Model::new();
    if owner.irq_armed() {
        return TestResult::Fail("fresh owner must not be irq-armed");
    }
    // No binding: service reports nothing, rearm/release are no-ops.
    match owner.irq_service(&mut regs) {
        Ok(events) if events == super::irq::Events::default() => {}
        _ => return TestResult::Fail("unarmed irq_service must report default events"),
    }
    if owner.irq_rearm(&mut regs).is_err() {
        return TestResult::Fail("unarmed irq_rearm must succeed");
    }
    owner.irq_release(&mut regs, &test_cap());
    if owner.irq_armed() {
        return TestResult::Fail("unarmed irq_release must stay unarmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_irq_unarmed_is_polled
);

fn smoke_rtw89_prepared_8922a_irq_start_needs_rings() -> TestResult {
    let f = factory();
    let mut owner = match Prepared8922a::new(f, 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    let mut regs = Model::new();
    let line = Line::new();
    let device = mmio_device();
    let cap = test_cap();
    // The gate returns before any MSI/config-space access, so the
    // non-PCI fixture function is safe here.
    if owner.irq_start(&device, &cap, &line, &mut regs) != Err(Error::NotProgrammed) {
        return TestResult::Fail("irq_start before program_rings must be NotProgrammed");
    }
    if owner.irq_armed() {
        return TestResult::Fail("refused irq_start must not arm the owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_irq_start_needs_rings
);

fn smoke_rtw89_prepared_8922a_irq_bind_fails_cleanly() -> TestResult {
    let f = factory();
    let mut owner = match Prepared8922a::new(f, 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    // Program the rings first (same pre-init halves as the
    // full-sequence test), so the bind is reached.
    let mut regs = Model::new();
    if owner
        .pre_init_dma_before_reset(&mut regs, 256, 256)
        .is_err()
    {
        return TestResult::Fail("pre_init before_reset failed");
    }
    let mut regs = Model::new().with32(INIT_CFG1, 0).with_bound_clears();
    if owner.pre_init_dma_after_reset(&mut regs).is_err() {
        return TestResult::Fail("pre_init after_reset failed");
    }
    let tx_phys: [u64; TXCH_NUM] = core::array::from_fn(|i| 0x1_0000 + (i as u64) * 0x800);
    let rx_phys: [u64; 2] = [0x2_0000, 0x2_1000];
    if owner
        .program_rings(&mut regs, &tx_phys, &rx_phys, 256, 256)
        .is_err()
    {
        return TestResult::Fail("program_rings failed");
    }
    // MSI discovery on a non-PCI fixture function fails inside
    // `enable_msi` before any config-space access, and the owner
    // must stay unarmed.
    let line = Line::new();
    let device = mmio_device();
    let cap = test_cap();
    if owner.irq_start(&device, &cap, &line, &mut regs) != Err(Error::Irq(super::irq::Error::Msi)) {
        return TestResult::Fail("irq_start on a non-PCI function must fail with Irq(Msi)");
    }
    if owner.irq_armed() {
        return TestResult::Fail("failed irq_start must not arm the owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_irq_bind_fails_cleanly
);

fn smoke_rtw89_prepared_8922a_chip_ver() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    if owner.chip_ver().is_some() {
        return TestResult::Fail("chip_ver must be None before the pre-init runs");
    }
    owner.record_chip_ver(HalChipVer {
        cv: 1,
        cid: Cid::Cid7090,
        acv: 2,
        aid: 0x1234,
    });
    match owner.chip_ver() {
        Some(ver)
            if ver.cv == 1 && ver.cid == Cid::Cid7090 && ver.acv == 2 && ver.aid == 0x1234 => {}
        _ => return TestResult::Fail("chip_ver record/accessor wrong"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_chip_ver
);

fn smoke_rtw89_prepared_8922a_prepare_data_with_info() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    let mut regs = Model::new();
    if owner
        .pre_init_dma_before_reset(&mut regs, 256, 256)
        .is_err()
    {
        return TestResult::Fail("pre_init before_reset failed");
    }
    let mut regs = Model::new().with32(INIT_CFG1, 0).with_bound_clears();
    if owner.pre_init_dma_after_reset(&mut regs).is_err() {
        return TestResult::Fail("pre_init after_reset failed");
    }
    let tx_phys: [u64; TXCH_NUM] = core::array::from_fn(|i| 0x1_0000 + (i as u64) * 0x800);
    let rx_phys: [u64; 2] = [0x2_0000, 0x2_1000];
    if owner
        .program_rings(&mut regs, &tx_phys, &rx_phys, 256, 256)
        .is_err()
    {
        return TestResult::Fail("program_rings failed");
    }
    if owner.admit_station(&base_req()).is_err() {
        return TestResult::Fail("admit_station failed");
    }
    let mut body = [0u8; 32];
    if encode_txwd_be(
        &TxwdBeInfo {
            channel: 0,
            qsel: 0,
            mac_id: 0,
            pkt_size: 100,
        },
        &mut body,
    )
    .is_none()
    {
        return TestResult::Fail("encode_txwd_be failed");
    }
    // One info field set so the block is distinguishable from the
    // body: STBC + port 3 + ampdu 64.
    let mut info = [0u8; 32];
    let info_in = TxwdInfoV2 {
        stbc: true,
        port: 3,
        ampdu_num: 64,
        ..Default::default()
    };
    if fill_txwd_info_v2(&info_in, &mut info).is_none() {
        return TestResult::Fail("fill_txwd_info_v2 failed");
    }
    let mut bd = vec![TxBd::default(); DATA_RING_DEPTH as usize];
    let prepared = match owner.prepare_data_with_info(
        PrepareArgs {
            channel: 0,
            mac_id: 0,
            qsel: 0,
            body: &body,
            header_dma: 0x20000,
            frame_dma: 0x10000,
            frame_len: 100,
            bd: &mut bd,
        },
        &info,
    ) {
        Ok(prepared) => prepared,
        Err(_) => return TestResult::Fail("prepare_data_with_info failed"),
    };
    // 32 body + 32 info + 8 WP + 6 addr-info (100-byte frame).
    if prepared.header.len() != 78 || bd[0].length != 78 {
        return TestResult::Fail("info header length wrong");
    }
    if u32::from_le_bytes(prepared.header[0..4].try_into().unwrap()) & (1 << 22) == 0 {
        return TestResult::Fail("WDINFO_EN not set with info block");
    }
    if prepared.header[32..64] != info {
        return TestResult::Fail("info block bytes wrong in header");
    }
    if u16::from_le_bytes(prepared.header[64..66].try_into().unwrap()) != 0x8000 {
        return TestResult::Fail("WP seq0 wrong with info block");
    }
    // The reserved CH0 slot must be published before the next
    // prepare: `TxQueue::reserve` refuses while the WP slot is held.
    if owner.kick_data(&mut Model::new(), &prepared).is_err() {
        return TestResult::Fail("kick_data of the info frame failed");
    }
    // The plain path is unchanged: same body, no info block.
    let mut bd = vec![TxBd::default(); DATA_RING_DEPTH as usize];
    let plain = match owner.prepare_data(PrepareArgs {
        channel: 0,
        mac_id: 0,
        qsel: 0,
        body: &body,
        header_dma: 0x20000,
        frame_dma: 0x10000,
        frame_len: 100,
        bd: &mut bd,
    }) {
        Ok(prepared) => prepared,
        Err(_) => return TestResult::Fail("prepare_data failed"),
    };
    if plain.header.len() != 46
        || u32::from_le_bytes(plain.header[0..4].try_into().unwrap()) & (1 << 22) != 0
    {
        return TestResult::Fail("plain prepare_data must stay 46 bytes with WDINFO_EN clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_prepare_data_with_info
);
