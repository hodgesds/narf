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
use super::radio_assets::Element;
use super::radio_power_c::{
    ID_BYRATE, ID_LMT_2GHZ, ID_LMT_5GHZ, ID_LMT_6GHZ, ID_LMT_RU_2GHZ, ID_LMT_RU_5GHZ,
    ID_LMT_RU_6GHZ, ID_REGD, ID_TX_SHAPE_LMT, RS_CCK, RS_HEDCM, RS_MCS, RS_OFDM, RS_OFFSET, WW,
};
use super::station_8922a::{Band, Error as StationError, LinkRequest, Request, SixGhzAdmission};
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

const MLD_ADDR: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

fn link1_req() -> Request<'static> {
    Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC],
        band: Band::Ghz2,
        width_mhz: 40,
        primary: 6,
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

fn two_mld_links() -> [LinkRequest<'static>; 2] {
    [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: link1_req(),
        },
    ]
}

fn link1_caps() -> StationCaps {
    StationCaps {
        band: Band::Ghz2,
        width_mhz: 40,
        ..eht_caps()
    }
}

/// Fresh owner with rings programmed (same pre-init halves +
/// ring programming as the full-sequence test).
fn programmed_owner() -> Result<(Prepared8922a, Model), &'static str> {
    let mut owner = Prepared8922a::new(factory(), 0).map_err(|_| "Prepared8922a::new failed")?;
    let mut regs = Model::new();
    owner
        .pre_init_dma_before_reset(&mut regs, 256, 256)
        .map_err(|_| "pre_init before_reset failed")?;
    let mut regs = Model::new().with32(INIT_CFG1, 0).with_bound_clears();
    owner
        .pre_init_dma_after_reset(&mut regs)
        .map_err(|_| "pre_init after_reset failed")?;
    let tx_phys: [u64; TXCH_NUM] = core::array::from_fn(|i| 0x1_0000 + (i as u64) * 0x800);
    let rx_phys: [u64; 2] = [0x2_0000, 0x2_1000];
    owner
        .program_rings(&mut regs, &tx_phys, &rx_phys, 256, 256)
        .map_err(|_| "program_rings failed")?;
    Ok((owner, regs))
}

fn smoke_rtw89_prepared_8922a_mld_admit() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    let links = two_mld_links();
    let base = match owner.admit_mld(MLD_ADDR, &links) {
        Ok(base) => base,
        Err(_) => return TestResult::Fail("admit_mld failed"),
    };
    if base != 0 {
        return TestResult::Fail("first MLD base MACID not 0");
    }
    let Some(mld) = owner.mld(0) else {
        return TestResult::Fail("admitted MLD not retained");
    };
    if mld.mld_addr != MLD_ADDR
        || mld.base_macid != 0
        || mld.aid != 7
        || mld.port != 0
        || mld.link_count() != 2
    {
        return TestResult::Fail("admitted MLD record mismatch");
    }
    // Strided per-link MACIDs + instance indexes.
    let l0 = match mld.link(0) {
        Some(v) => v,
        None => return TestResult::Fail("link 0 missing"),
    };
    let l1 = match mld.link(1) {
        Some(v) => v,
        None => return TestResult::Fail("link 1 missing"),
    };
    if l0.macid() != 0 || l0.index != 0 || l1.macid() != 16 || l1.index != 1 {
        return TestResult::Fail("per-link MACID/index mismatch");
    }
    if mld.designated_link().map(|link| link.link_id) != Some(0) {
        return TestResult::Fail("designated link must be link 0");
    }
    // Per-link TXWD EHT fields.
    if owner.txwd_info_eht_mld(0, 0) != Some((0, 0))
        || owner.txwd_info_eht_mld(0, 1) != Some((0, 0))
    {
        return TestResult::Fail("per-link TXWD EHT fields mismatch");
    }
    if owner.txwd_info_eht_mld(0, 9).is_some() || owner.txwd_info_eht_mld(9, 0).is_some() {
        return TestResult::Fail("unknown MLD/link must have no TXWD fields");
    }
    // Per-link RA: w0 carries the link MACID (bits 8..16), w3
    // carries the phy index as band_num (low byte) and the
    // band (bits 29..31) — link 0: MACID 0, phy 0, 5 GHz;
    // link 1: MACID 16, phy 1, 2.4 GHz.
    let ra0 = match owner.station_ra_mld(0, 0, &eht_caps()) {
        Ok(ra) => ra,
        Err(_) => return TestResult::Fail("link 0 RA failed"),
    };
    if (ra0[0] >> 8) & 0xFF != 0 || ra0[3] & 0xFF != 0 || (ra0[3] >> 29) & 0x3 != 1 {
        return TestResult::Fail("link 0 RA MACID/phy/band wrong");
    }
    let ra1 = match owner.station_ra_mld(0, 1, &link1_caps()) {
        Ok(ra) => ra,
        Err(_) => return TestResult::Fail("link 1 RA failed"),
    };
    if (ra1[0] >> 8) & 0xFF != 16 || ra1[3] & 0xFF != 1 || (ra1[3] >> 29) & 0x3 != 0 {
        return TestResult::Fail("link 1 RA MACID/phy/band wrong");
    }
    // BA-CAM through the designated link: MLD_EN set,
    // BAND_SEL clear (link 0, mac_idx 0).
    let idx = match owner.acquire_bacam_mld(0, 0) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("designated BA-CAM acquire failed"),
    };
    if idx != 0 {
        return TestResult::Fail("designated BA-CAM first slot must be 0");
    }
    let h2c = match owner.ba_h2c_mld(0, 0, bacam_v1::bmap_size(64), 0, idx as u32) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("designated BA-CAM H2C failed"),
    };
    if h2c.w0 != 0x3 || h2c.w1 != 0x0800_0500 {
        return TestResult::Fail("MLD BA-CAM H2C golden mismatch");
    }
    if owner.release_bacam_mld(0, idx).is_err() {
        return TestResult::Fail("designated BA-CAM release failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_mld_admit
);

fn smoke_rtw89_prepared_8922a_mld_data_and_teardown() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner() {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let links = two_mld_links();
    if owner.admit_mld(MLD_ADDR, &links) != Ok(0) {
        return TestResult::Fail("admit_mld failed");
    }
    // Data submit to a link MACID is admitted (link 1: 16).
    let mut body = [0u8; 32];
    if encode_txwd_be(
        &TxwdBeInfo {
            channel: 0,
            qsel: 0,
            mac_id: 16,
            pkt_size: 100,
        },
        &mut body,
    )
    .is_none()
    {
        return TestResult::Fail("encode_txwd_be failed");
    }
    let mut bd = vec![TxBd::default(); DATA_RING_DEPTH as usize];
    let prepared = match owner.prepare_data(PrepareArgs {
        channel: 0,
        mac_id: 16,
        qsel: 0,
        body: &body,
        header_dma: 0x20000,
        frame_dma: 0x10000,
        frame_len: 100,
        bd: &mut bd,
    }) {
        Ok(prepared) => prepared,
        Err(_) => return TestResult::Fail("prepare_data to link MACID refused"),
    };
    if prepared.header.len() != 46 {
        return TestResult::Fail("link data header length wrong");
    }
    let wp = match owner.kick_data(&mut regs, &prepared) {
        Ok(wp) => wp,
        Err(_) => return TestResult::Fail("kick_data to link MACID failed"),
    };
    if wp != 1 || regs.regs16.get(&0xB100) != Some(&1) {
        return TestResult::Fail("kick_data doorbell wrong");
    }
    // Per-link teardown: drop link 1, the MLD survives on
    // link 0 — and its MACID stops admitting data.
    if owner.release_mld_link(0, 1) != Ok(16) {
        return TestResult::Fail("link 1 release failed");
    }
    if owner.mld(0).is_none_or(|mld| {
        mld.link_count() != 1 || mld.designated_link().map(|l| l.link_id) != Some(0)
    }) {
        return TestResult::Fail("link 1 teardown state mismatch");
    }
    let mut bd = vec![TxBd::default(); DATA_RING_DEPTH as usize];
    if owner
        .prepare_data(PrepareArgs {
            channel: 0,
            mac_id: 16,
            qsel: 0,
            body: &body,
            header_dma: 0x20000,
            frame_dma: 0x10000,
            frame_len: 100,
            bd: &mut bd,
        })
        .is_ok()
    {
        return TestResult::Fail("prepare_data to released link MACID accepted");
    }
    // Re-add link 1 on a new channel: it retakes instance
    // index 1 and MACID 16.
    let rejoin = LinkRequest {
        link_id: 1,
        req: Request {
            peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC],
            band: Band::Ghz5,
            width_mhz: 80,
            primary: 44,
            ..base_req()
        },
    };
    if owner.add_mld_link(0, &rejoin) != Ok(16) {
        return TestResult::Fail("link 1 re-add failed");
    }
    // Drop link 0: link 1 becomes designated, so the next
    // BA-CAM H2C carries its MACID and BAND_SEL set.
    if owner.release_mld_link(0, 0) != Ok(0) {
        return TestResult::Fail("link 0 release failed");
    }
    let idx = match owner.acquire_bacam_mld(0, 0) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("link 1 BA-CAM acquire failed"),
    };
    let h2c = match owner.ba_h2c_mld(0, 0, bacam_v1::bmap_size(64), 0, idx as u32) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("link 1 BA-CAM H2C failed"),
    };
    if h2c.w0 != 0x1003 || h2c.w1 != 0x0800_0700 {
        return TestResult::Fail("link 1 BA-CAM H2C golden mismatch");
    }
    if owner.release_bacam_mld(0, idx).is_err() {
        return TestResult::Fail("link 1 BA-CAM release failed");
    }
    // Whole-MLD release; the pool is fully reusable.
    owner.release_mld(0);
    if owner.mld(0).is_some() {
        return TestResult::Fail("released MLD still retained");
    }
    if owner.admit_station(&base_req()) != Ok(0) {
        return TestResult::Fail("MACID not returned to the pool");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_mld_data_and_teardown
);

fn smoke_rtw89_prepared_8922a_mld_refusals() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    // Unknown MLD base: every per-link route refuses NoMld;
    // whole-MLD release is an idempotent no-op.
    if owner.station_ra_mld(9, 0, &eht_caps()) != Err(Error::NoMld) {
        return TestResult::Fail("station_ra_mld for unknown MLD accepted");
    }
    if owner.acquire_bacam_mld(9, 0) != Err(Error::NoMld) {
        return TestResult::Fail("acquire_bacam_mld for unknown MLD accepted");
    }
    if owner.ba_h2c_mld(9, 0, 0, 0, 0) != Err(Error::NoMld) {
        return TestResult::Fail("ba_h2c_mld for unknown MLD accepted");
    }
    if owner.release_bacam_mld(9, 0) != Err(Error::NoMld) {
        return TestResult::Fail("release_bacam_mld for unknown MLD accepted");
    }
    if owner.txwd_info_eht_mld(9, 0).is_some() {
        return TestResult::Fail("txwd_info_eht_mld for unknown MLD accepted");
    }
    if owner.add_mld_link(9, &two_mld_links()[0]) != Err(Error::NoMld) {
        return TestResult::Fail("add_mld_link for unknown MLD accepted");
    }
    if owner.release_mld_link(9, 0) != Err(Error::NoMld) {
        return TestResult::Fail("release_mld_link for unknown MLD accepted");
    }
    owner.release_mld(9);
    // Empty link list is refused with no MACID consumed.
    if owner.admit_mld(MLD_ADDR, &[]) != Err(Error::Station(StationError::NoLinks)) {
        return TestResult::Fail("empty MLD admission not refused");
    }
    let links = two_mld_links();
    if owner.admit_mld(MLD_ADDR, &links) != Ok(0) {
        return TestResult::Fail("admit_mld failed");
    }
    // Unknown link on a known MLD.
    if owner.station_ra_mld(0, 9, &eht_caps()) != Err(Error::Station(StationError::LinkNotFound)) {
        return TestResult::Fail("station_ra_mld for unknown link accepted");
    }
    if owner.release_mld_link(0, 9) != Err(Error::Station(StationError::LinkNotFound)) {
        return TestResult::Fail("release_mld_link for unknown link accepted");
    }
    if owner.txwd_info_eht_mld(0, 9).is_some() {
        return TestResult::Fail("txwd_info_eht_mld for unknown link accepted");
    }
    // release_station must not free an MLD link MACID, and
    // the single-link RA route stays closed to link MACIDs.
    owner.release_station(16);
    if owner.mld(0).is_none_or(|mld| mld.link_count() != 2) {
        return TestResult::Fail("release_station freed an MLD link");
    }
    if owner.station_ra(16, &eht_caps()) != Err(Error::NoStation) {
        return TestResult::Fail("station_ra for a link MACID accepted");
    }
    owner.release_mld(0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_mld_refusals
);

fn smoke_rtw89_prepared_8922a_vif_tdls_peer() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    let vif_addr = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let main = match owner.add_vif(vif_addr, VifRole::Station) {
        Ok(main) => main,
        Err(_) => return TestResult::Fail("add_vif failed"),
    };
    if main != 0 {
        return TestResult::Fail("first VIF main MACID not 0");
    }
    let Some(vif) = owner.vif(0) else {
        return TestResult::Fail("admitted VIF not retained");
    };
    if vif.addr != vif_addr
        || vif.role != VifRole::Station
        || vif.main_macid() != 0
        || vif.main_port() != 0
    {
        return TestResult::Fail("VIF record mismatch");
    }
    if owner
        .vif_by_addr(vif_addr)
        .is_none_or(|v| v.main_macid() != 0)
    {
        return TestResult::Fail("vif_by_addr mismatch");
    }
    if owner.add_vif(vif_addr, VifRole::Station) != Err(Error::VifExists) {
        return TestResult::Fail("duplicate VIF address accepted");
    }
    // The TDLS peer takes the VIF main MACID, not a pool
    // MACID — and the next pool station skips it.
    if owner.admit_tdls_peer(0, &base_req()) != Ok(0) {
        return TestResult::Fail("admit_tdls_peer failed");
    }
    if owner.station(0).is_none_or(|st| st.peer != base_req().peer) {
        return TestResult::Fail("TDLS peer not retained as station 0");
    }
    if owner.admit_station(&base_req()) != Ok(1) {
        return TestResult::Fail("pool station took the VIF main MACID");
    }
    // Releasing the peer drops its record but never frees the
    // VIF's MACID: the next pool station is 2, not 0.
    owner.release_station(0);
    if owner.station(0).is_some() {
        return TestResult::Fail("released TDLS peer still retained");
    }
    if owner.admit_station(&base_req()) != Ok(2) {
        return TestResult::Fail("peer release freed the VIF main MACID");
    }
    // Removing the VIF returns its base to the pool.
    owner.release_station(1);
    owner.release_station(2);
    owner.remove_vif(0);
    if owner.vif(0).is_some() {
        return TestResult::Fail("removed VIF still retained");
    }
    if owner.admit_station(&base_req()) != Ok(0) {
        return TestResult::Fail("VIF base MACID not returned to the pool");
    }
    // A live TDLS peer dissolves with its VIF.
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    if owner.add_vif(vif_addr, VifRole::Station) != Ok(0) {
        return TestResult::Fail("add_vif failed");
    }
    if owner.admit_tdls_peer(0, &base_req()) != Ok(0) {
        return TestResult::Fail("admit_tdls_peer failed");
    }
    owner.remove_vif(0);
    if owner.station(0).is_some() || owner.vif(0).is_some() {
        return TestResult::Fail("VIF removal left its TDLS peer behind");
    }
    if owner.admit_station(&base_req()) != Ok(0) {
        return TestResult::Fail("VIF base MACID not returned to the pool");
    }
    // AP-mode VIFs and unknown VIFs refuse the peer; a
    // wrong-port request refuses too.
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    if owner.add_vif(vif_addr, VifRole::Ap) != Ok(0) {
        return TestResult::Fail("add_vif failed");
    }
    if owner.admit_tdls_peer(0, &base_req()) != Err(Error::NotStationMode) {
        return TestResult::Fail("TDLS peer on AP-mode VIF accepted");
    }
    if owner.admit_tdls_peer(9, &base_req()) != Err(Error::NoVif) {
        return TestResult::Fail("TDLS peer on unknown VIF accepted");
    }
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    if owner.add_vif(vif_addr, VifRole::Station) != Ok(0) {
        return TestResult::Fail("add_vif failed");
    }
    let mut wrong_port = base_req();
    wrong_port.port = 1;
    if owner.admit_tdls_peer(0, &wrong_port) != Err(Error::PortMismatch) {
        return TestResult::Fail("wrong-port TDLS peer accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_vif_tdls_peer
);

fn smoke_rtw89_prepared_8922a_vif_ports() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    // Five VIFs take the five hardware ports (mains 0..4).
    for i in 0..5u8 {
        let addr = [0x02, 0, 0, 0, 0, i];
        let main = match owner.add_vif(addr, VifRole::Station) {
            Ok(main) => main,
            Err(_) => return TestResult::Fail("add_vif failed"),
        };
        if main != i {
            return TestResult::Fail("VIF main MACID not lowest free");
        }
        if owner.vif(i).is_none_or(|v| v.main_port() != i) {
            return TestResult::Fail("VIF port not lowest free");
        }
    }
    // The sixth VIF has no port: refused, and the MACID its
    // failed admission allocated is freed again (the next
    // pool station takes it).
    if owner.add_vif([0x02, 0, 0, 0, 0, 5], VifRole::Station) != Err(Error::NoPort) {
        return TestResult::Fail("sixth VIF not refused");
    }
    if owner.admit_station(&base_req()) != Ok(5) {
        return TestResult::Fail("failed VIF admission leaked its MACID");
    }
    // Removing a VIF frees its port and base together.
    owner.release_station(5);
    owner.remove_vif(2);
    let main = match owner.add_vif([0x02, 0, 0, 0, 0, 6], VifRole::Station) {
        Ok(main) => main,
        Err(_) => return TestResult::Fail("VIF re-add after removal failed"),
    };
    if main != 2 || owner.vif(2).is_none_or(|v| v.main_port() != 2) {
        return TestResult::Fail("removed VIF port/base not reused");
    }
    owner.remove_vif(9);
    TestResult::Pass
}

/// Firmware TXPWR element builder (the `radio_power_be`
/// tests' fixture, extended): one element per ID, header
/// `[0, 0, rfe, size]` + LE32 count, rows padded to `size`.
/// Duplicated from `station_8922a_tests` (this tree's
/// per-module fixture pattern): the prepared owner builds
/// its program from the same elements.
fn elm(id: u32, rfe: u8, size: u8, entries: &[&[u8]]) -> Element {
    let mut bytes = vec![0, 0, rfe, size];
    bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let mut row = e.to_vec();
        row.resize(usize::from(size), 0);
        bytes.extend_from_slice(&row);
    }
    Element {
        id,
        version: [0; 4],
        bytes,
    }
}

/// By-rate entry {band, nss, rs, shf, len, data[4], bw, ofdma}
/// (11-byte shipped layout).
fn byr(band: u8, nss: u8, rs: u8, shf: u8, data: &[i8], bw: u8, ofdma: u8) -> Vec<u8> {
    let mut e = vec![band, nss, rs, shf, data.len() as u8, 0, 0, 0, 0, bw, ofdma];
    for (i, &v) in data.iter().enumerate() {
        e[5 + i] = v as u8;
    }
    e
}

/// The `radio_power_be` `base` + `six_set` elements (rfe 0,
/// tag 10) plus the REGD map (`radio_power_c` `six_set`):
/// US FCC, GB UK/ETSI, BO not-applicable. Additions over the
/// BE fixture: an FCC/STD OFDM limit (50) and RU limit (40)
/// so a US Standard-Power TPE bites, and 6 GHz shape rows
/// (OFDM 1 FCC/STD, 2 ETSI/STD, 0 FCC/LPI).
fn txpwr_elements() -> Vec<Element> {
    vec![
        elm(
            ID_BYRATE,
            0,
            11,
            &[
                &byr(0, 0, RS_CCK, 0, &[10, 2, 4, 6], 0, 0),
                &byr(1, 0, RS_CCK, 0, &[99, 99, 99, 99], 0, 0),
                &byr(0, 0, RS_OFDM, 4, &[-3, 8, 10, 12], 0, 0),
                &byr(0, 0, RS_MCS, 14, &[30, 32], 0, 0),
                &byr(0, 0, RS_MCS, 14, &[34, 36], 0, 1),
                &byr(0, 0, RS_MCS, 0, &[20, 22, 24, 26], 0, 0),
                &byr(0, 0, RS_HEDCM, 0, &[40, 42], 0, 0),
                &byr(0, 1, RS_MCS, 8, &[30, 32, 34, 36], 0, 0),
                &byr(0, 1, RS_HEDCM, 0, &[40, 42], 0, 0),
                &byr(0, 0, RS_OFDM, 0, &[8, 10, 12, 14], 1, 0),
                &byr(0, 0, RS_OFDM, 0, &[16, 18, 20, 22], 2, 0),
                &byr(1, 0, RS_OFDM, 0, &[20, 22, 24, 26], 0, 0),
                &byr(1, 1, RS_MCS, 8, &[30, 32, 34, 36], 0, 0),
                &byr(1, 1, RS_HEDCM, 0, &[40, 42], 0, 0),
                &byr(1, 0, RS_OFFSET, 0, &[-2, 2, 4, 6], 0, 0),
                &byr(1, 0, RS_OFFSET, 4, &[8, 10, 12, 14], 0, 0),
                // nss 2 is invalid for MCS: skipped, never an error.
                &byr(1, 2, RS_MCS, 0, &[77], 0, 0),
                // 6 GHz OFDM by-rate row (band 2).
                &byr(2, 0, RS_OFDM, 0, &[16, 18, 20, 22], 0, 0),
            ],
        ),
        elm(
            ID_LMT_2GHZ,
            0,
            7,
            &[
                // bw, nt, rs, bf, regd, ch_idx, v
                &[0, 0, RS_CCK, 0, WW, 5, 40],
                &[0, 0, RS_OFDM, 1, WW, 5, 36],
                &[0, 1, RS_MCS, 0, WW, 5, 30],
                // non-WW regd is not read (regd = WW, no country).
                &[0, 0, RS_OFDM, 1, 2, 5, 2],
                // last entry wins.
                &[0, 1, RS_MCS, 0, WW, 5, -6i8 as u8],
            ],
        ),
        elm(
            ID_LMT_5GHZ,
            0,
            7,
            &[
                // 80MHz center 42: mcs_20m at 36/40/44/48 (idx 0/2/4/6).
                &[0, 0, RS_MCS, 0, WW, 0, 50],
                &[0, 0, RS_MCS, 0, WW, 6, 52],
                &[1, 0, RS_MCS, 0, WW, 1, 44],
                &[1, 0, RS_MCS, 0, WW, 5, 40],
                &[2, 0, RS_MCS, 1, WW, 3, 34],
                // ofdm at primary 36.
                &[0, 1, RS_OFDM, 0, WW, 0, 28],
                // bw 4 is out of the 5GHz range: skipped.
                &[4, 0, RS_MCS, 0, WW, 3, 1],
            ],
        ),
        elm(
            ID_LMT_RU_2GHZ,
            0,
            5,
            &[&[0, 0, WW, 5, 20], &[2, 1, WW, 5, 18]],
        ),
        elm(
            ID_LMT_RU_5GHZ,
            0,
            5,
            &[&[1, 0, WW, 2, 24], &[2, 1, WW, 6, 26]],
        ),
        elm(
            ID_TX_SHAPE_LMT,
            0,
            5,
            &[
                // [band, rs, regd, value, reg6]
                &[0, 0, WW, 1],
                &[1, 1, WW, 3],
                &[1, 1, 3, 3],
                &[2, 1, 2, 1, 2],
                &[2, 1, 1, 2, 2],
                &[2, 1, 2, 0, 1],
            ],
        ),
        elm(
            ID_LMT_6GHZ,
            0,
            8,
            &[
                // ch37 = 6G idx 17. FCC (2) LPI (1) OFDM: own value.
                &[0, 0, RS_OFDM, 0, 2, 1, 17, 30],
                // MCS: no FCC/LPI value, so [WW][DFLT] is read.
                &[0, 0, RS_MCS, 0, WW, 0, 17, 24],
                // ETSI (1) STD (2) OFDM for the GB/UK case.
                &[0, 0, RS_OFDM, 0, 1, 2, 17, 40],
                // reg6 3 is out of range: skipped.
                &[0, 0, RS_OFDM, 0, 2, 3, 17, 2],
                // FCC (2) STD (2) OFDM: the US SP own value.
                &[0, 0, RS_OFDM, 0, 2, 2, 17, 50],
            ],
        ),
        elm(
            ID_LMT_RU_6GHZ,
            0,
            6,
            &[
                &[0, 0, 2, 1, 17, 22],
                &[1, 0, WW, 0, 17, 20],
                &[0, 0, 2, 2, 17, 40],
            ],
        ),
        elm(
            ID_REGD,
            0,
            9,
            &[
                &[b'U', b'S', 2, 2, 2],
                &[b'G', b'B', 14, 14, 14],
                // `RTW89_NA` (4): not applicable.
                &[b'B', b'O', 2, 2, 4],
            ],
        ),
    ]
}

fn smoke_rtw89_prepared_8922a_set_txpwr_writes_program() -> TestResult {
    let elements = txpwr_elements();
    // 6 GHz SP ch37, TPE 5 dBm, US: FCC/STD.
    let mut req = base_req();
    req.band = Band::Ghz6;
    req.width_mhz = 20;
    req.primary = 37;
    req.six_ghz = Some(SixGhzAdmission {
        power: PowerType6Ghz::Sp,
        tpe_dbm: Some(5),
    });
    // Non-CAV cut (chip_version 1): the diff step leaves the
    // TXAGC reference at 0 with TSSI_K 0x12.
    let mut owner = match Prepared8922a::new(factory(), 1) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    let macid = match owner.admit_station(&req) {
        Ok(macid) => macid,
        Err(_) => return TestResult::Fail("6GHz SP admission refused"),
    };
    let mut regs = Model::new();
    if owner
        .set_txpwr(macid, &elements, *b"US", 37, &mut regs)
        .is_err()
    {
        return TestResult::Fail("set_txpwr refused");
    }
    // 197 writes over 194 distinct registers (the TXAGC
    // address is written twice per path, OFDM then CCK).
    if regs.regs32.len() != 194 {
        return TestResult::Fail("set_txpwr did not land on 194 registers");
    }
    // By-rate head (CCK [5,1,2,3], then 6G OFDM [8,9,10,11]),
    // zero rate offsets (no band-2 offset rows), the OFDM
    // shape bit, the TPE-capped limit word (OFDM 10, MCS20
    // 10 at page offset 4) and RU word (ru26 10), and the
    // zeroed reference fields.
    if regs.regs32.get(&0x11E00) != Some(&0x0302_0105)
        || regs.regs32.get(&0x11E04) != Some(&0x0B0A_0908)
        || regs.regs32.get(&0x11A30) != Some(&0)
        || regs.regs32.get(&(0x20000 + 0x6C04)) != Some(&1)
        || regs.regs32.get(&0x11FB0) != Some(&0x000A_000A)
        || regs.regs32.get(&0x12048) != Some(&0x0000_000A)
        || regs.regs32.get(&0x11A20) != Some(&0)
    {
        return TestResult::Fail("set_txpwr register values differ from rtw8922a_set_txpwr");
    }
    // Partial-mask writes merge into existing register
    // contents (read-modify-write), they do not clobber
    // neighbouring fields: ref fields cleared, shape bit
    // set, TXAGC reference 0, TSSI_K 0x12, SAR 126.
    let mut seeded = Model::new()
        .with32(0x11A20, u32::MAX)
        .with32(0x20000 + 0x6C04, u32::MAX)
        .with32(0x20000 + 0xE628, u32::MAX)
        .with32(0x20000 + 0xE6A0, u32::MAX)
        .with32(0x20000 + 0xE728, u32::MAX)
        .with32(0x20000 + 0xE7A0, u32::MAX)
        .with32(0x20000 + 0xE61C, u32::MAX)
        .with32(0x20000 + 0xE71C, u32::MAX);
    if owner
        .set_txpwr(macid, &elements, *b"US", 37, &mut seeded)
        .is_err()
    {
        return TestResult::Fail("seeded set_txpwr refused");
    }
    if seeded.regs32.get(&0x11A20) != Some(&0xFFF8_0001)
        || seeded.regs32.get(&(0x20000 + 0x6C04)) != Some(&0xFFFF_FFFD)
        || seeded.regs32.get(&(0x20000 + 0xE628)) != Some(&0xFFFC_0000)
        || seeded.regs32.get(&(0x20000 + 0xE6A0)) != Some(&0xC12F_FFFF)
        || seeded.regs32.get(&(0x20000 + 0xE728)) != Some(&0xFFFC_0000)
        || seeded.regs32.get(&(0x20000 + 0xE7A0)) != Some(&0xC12F_FFFF)
        || seeded.regs32.get(&(0x20000 + 0xE61C)) != Some(&0xFFE7_EFFF)
        || seeded.regs32.get(&(0x20000 + 0xE71C)) != Some(&0xFFE7_EFFF)
    {
        return TestResult::Fail("set_txpwr partial-mask merge differs");
    }
    // CAV cut (chip_version 0): the diff step raises the
    // TXAGC reference to 16 RF units (64 in the field's BB
    // units) on both paths.
    let mut cav = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    let cav_macid = match cav.admit_station(&req) {
        Ok(macid) => macid,
        Err(_) => return TestResult::Fail("6GHz SP admission refused (CAV)"),
    };
    let mut regs = Model::new()
        .with32(0x20000 + 0xE628, u32::MAX)
        .with32(0x20000 + 0xE728, u32::MAX);
    if cav
        .set_txpwr(cav_macid, &elements, *b"US", 37, &mut regs)
        .is_err()
    {
        return TestResult::Fail("CAV set_txpwr refused");
    }
    if regs.regs32.get(&(0x20000 + 0xE628)) != Some(&0xFFFC_8040)
        || regs.regs32.get(&(0x20000 + 0xE728)) != Some(&0xFFFC_8040)
    {
        return TestResult::Fail("CAV TXAGC reference differs from rtw8922a_set_txpwr_diff");
    }
    // Refusals write nothing: an unknown MACID, and a
    // container without the BYRATE element.
    let mut regs = Model::new();
    if owner.set_txpwr(9, &elements, *b"US", 37, &mut regs) != Err(Error::NoStation)
        || !regs.regs32.is_empty()
    {
        return TestResult::Fail("set_txpwr for an unknown MACID did not refuse cleanly");
    }
    let no_byrate: Vec<Element> = txpwr_elements()
        .into_iter()
        .filter(|e| e.id != ID_BYRATE)
        .collect();
    let mut regs = Model::new();
    if owner.set_txpwr(macid, &no_byrate, *b"US", 37, &mut regs)
        != Err(Error::Station(StationError::Txpwr(
            super::rfk::Error::Table,
        )))
        || !regs.regs32.is_empty()
    {
        return TestResult::Fail("set_txpwr without BYRATE did not refuse cleanly");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_vif_ports
);

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_set_txpwr_writes_program
);
