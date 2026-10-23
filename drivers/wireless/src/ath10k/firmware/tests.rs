use super::*;
use alloc::{collections::BTreeMap, vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Store(BTreeMap<String, Vec<u8>>);
impl Files for Store {
    fn load(&mut self, name: &str) -> Result<Vec<u8>, Error> {
        self.0.get(name).cloned().ok_or(Error::Missing)
    }
}
fn ie(out: &mut Vec<u8>, id: u32, data: &[u8]) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(4), 0);
}
fn image(features: u64, wmi: u32, htt: u32) -> Vec<u8> {
    let mut out = b"QCA-ATH10K\0\0".to_vec();
    ie(&mut out, 2, &features.to_le_bytes());
    ie(&mut out, 3, &[0x99; 4]);
    ie(&mut out, 4, &[0x44; 4]);
    if wmi != 0 {
        ie(&mut out, 5, &wmi.to_le_bytes());
    }
    if htt != 0 {
        ie(&mut out, 6, &htt.to_le_bytes());
    }
    out
}
fn board(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut nested = Vec::new();
    ie(&mut nested, 0, name.as_bytes());
    ie(&mut nested, 1, bytes);
    let mut out = b"QCA-ATH10K-BOARD\0".to_vec();
    out.resize(out.len().next_multiple_of(4), 0);
    ie(&mut out, 0, &nested);
    out
}
fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
#[derive(Debug, Default)]
struct Target {
    writes: Vec<(u32, Vec<u8>)>,
    commands: Vec<u32>,
    executions: Vec<(u32, u32)>,
    downloads: Vec<Vec<u8>>,
    compressed: Vec<u8>,
    failed_otp: bool,
    soc: BTreeMap<u32, u32>,
    sequence: Vec<(u32, u32, u32)>,
    codeswap: Option<SwapMemory>,
    board_ext: u32,
}
#[derive(Debug)]
struct SwapMemory(Vec<u8>);
impl super::super::dma::Memory for SwapMemory {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn dma_address(&self) -> u64 {
        0x123000
    }
    fn read(&self, at: usize) -> u8 {
        self.0[at]
    }
    fn write(&mut self, at: usize, value: u8) {
        self.0[at] = value;
    }
}
impl Transport for Target {
    fn prepare_codeswap(&mut self, bytes: &[u8]) -> Result<(u32, [u8; 208]), BmiError> {
        if self.codeswap.is_some() {
            return Err(BmiError::BadResponse);
        }
        let layout = super::super::swap::Layout::parse(bytes)?;
        let mut memory = SwapMemory(vec![0xcc; layout.size]);
        let info = layout.fill(bytes, &mut memory)?;
        self.codeswap = Some(memory);
        Ok((layout.target, info))
    }
    async fn exchange(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, BmiError> {
        let cmd = word(request, 0).unwrap();
        self.commands.push(cmd);
        match cmd {
            2 => {
                let address = word(request, 4).unwrap();
                if response.len() != 4 || word(request, 8).unwrap() != 4 {
                    return Err(BmiError::BadResponse);
                }
                let value = match address {
                    address if address == HI + 0x54 => 0x430000u32,
                    address if address == HI + 0xac => self.board_ext,
                    _ => 0,
                };
                response.copy_from_slice(&value.to_le_bytes());
                return Ok(4);
            }
            3 => {
                self.writes
                    .push((word(request, 4).unwrap(), request[12..].to_vec()));
                self.sequence
                    .push((3, word(request, 4).unwrap(), word(request, 12).unwrap()));
            }
            4 => {
                let address = word(request, 4).unwrap();
                let parameter = word(request, 8).unwrap();
                self.executions.push((address, parameter));
                let value = if parameter == 0x10 {
                    0x8c00u32
                } else {
                    u32::from(self.failed_otp)
                };
                response.copy_from_slice(&value.to_le_bytes());
                return Ok(4);
            }
            13 => {
                if word(request, 4).unwrap() == 0 {
                    self.downloads.push(core::mem::take(&mut self.compressed));
                } else {
                    self.compressed.clear();
                }
            }
            14 => self.compressed.extend_from_slice(&request[8..]),
            6 => {
                let address = word(request, 4).unwrap();
                let value = *self.soc.get(&address).unwrap_or(&0);
                self.sequence.push((6, address, value));
                response.copy_from_slice(&value.to_le_bytes());
                return Ok(4);
            }
            7 => {
                let address = word(request, 4).unwrap();
                let value = word(request, 8).unwrap();
                self.soc.insert(address, value);
                self.sequence.push((7, address, value));
            }
            _ => return Err(BmiError::Unsupported),
        }
        Ok(0)
    }
}
fn profile() -> Profile {
    Profile::select(0x3c, 0x4100016c).unwrap()
}
fn identity() -> Identity {
    Identity {
        vendor: 0x168c,
        device: 0x3c,
        subsystem_vendor: 0x1234,
        subsystem_device: 1,
    }
}

fn smoke_ath10k_firmware_profiles_container_and_board_bounds() -> TestResult {
    if Profile::select(0x3e, 0x4100016c).is_some()
        || Profile::select(0x3c, 0x05030000).is_some()
        || Profile::select(0x11ac, 0x4100016c).is_none()
        || Profile::select(0x41, 0x05010000).is_none()
    {
        return TestResult::Fail("firmware profile did not bind PCI ID and BMI target version");
    }
    for (features, wmi, htt) in [(0, 1, 1), (2, 2, 2), (18, 3, 2)] {
        let parsed = Image::parse(image(features, 0, 0), 3).unwrap();
        if parsed.wmi != wmi
            || parsed.htt != htt
            || parsed.image() != [0x99; 4]
            || parsed.otp() != Some(&[0x44; 4][..])
        {
            return TestResult::Fail(
                "legacy operation fallback or image/OTP ownership differs from Linux",
            );
        }
    }
    let mut truncated = image(0, 1, 1);
    truncated[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    for bytes in [truncated, image(0, 6, 0), image(1 << 19, 4, 3)] {
        if Image::parse(bytes, 6).is_ok() {
            return TestResult::Fail("truncated/unsupported firmware container admitted");
        }
    }
    let names = board_names(
        identity(),
        Some(OtpIdentity {
            board: 3,
            chip: 1,
            extended: false,
        }),
        "oem",
    )
    .unwrap();
    let bytes = board(&names[0], &[9; 8]);
    if names[0] != "bus=pci,bmi-chip-id=1,bmi-board-id=3,variant=oem"
        || select_board(&bytes, &names, false) != Ok(&[9; 8][..])
        || select_board(&bytes, &[String::from("wrong")], false) != Err(Error::BoardNotFound)
    {
        return TestResult::Fail("board record selection used an unrelated calibrated board");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_firmware_profiles_container_and_board_bounds
);

fn smoke_ath10k_rom_boot_downloads_selected_bdf_otp_and_firmware() -> TestResult {
    let p = profile();
    let image = Image::parse(image(1 << 9, 1, 1), 6).unwrap();
    let mut files = Store::default();
    files.0.insert(
        format!("{}/board-2.bin", p.directory),
        board("bus=pci,bmi-chip-id=1,bmi-board-id=3", &vec![0x77; p.board]),
    );
    let mut bmi = Bmi::new(Target::default());
    if ready(prepare(&mut bmi, &mut files, p, identity(), "", &image))
        != Some(Ok(Some(OtpIdentity {
            board: 3,
            chip: 1,
            extended: false,
        })))
    {
        return TestResult::Fail("actual BMI firmware/BDF/OTP orchestration failed");
    }
    let target = &bmi.transport;
    let mut downloaded = Vec::new();
    for (address, bytes) in &target.writes {
        if (0x430000..0x430000 + p.board as u32).contains(address) {
            downloaded.extend_from_slice(bytes);
        }
    }
    let value = |address| {
        target
            .writes
            .iter()
            .find(|(at, _)| *at == address)
            .map(|(_, bytes)| bytes.as_slice())
    };
    if downloaded != vec![0x77; p.board]
        || target.downloads != [vec![0x44; 4], vec![0x44; 4], vec![0x99; 4]]
        || target.executions != [(0x1234, 0x10), (0x1234, 0)]
        || value(HI + 0xbc) != Some(&[0x3c, 0, 0, 0][..])
        || value(HI + 0x58) != Some(&[1, 0, 0, 0][..])
        || value(HI + 0x20) != Some(&[1, 0, 0, 0][..])
        || target.commands.contains(&1)
    {
        return TestResult::Fail(
            "ROM bytes, OTP parameters, host-interest writes or premature DONE differ",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_rom_boot_downloads_selected_bdf_otp_and_firmware
);

fn smoke_ath10k_failed_calibration_never_downloads_or_activates_firmware() -> TestResult {
    let p = profile();
    let image = Image::parse(image(0, 1, 1), 6).unwrap();
    let mut files = Store::default();
    files
        .0
        .insert(format!("{}/board.bin", p.directory), vec![0x77; p.board]);
    let mut bmi = Bmi::new(Target {
        failed_otp: true,
        ..Target::default()
    });
    if ready(prepare(&mut bmi, &mut files, p, identity(), "", &image))
        != Some(Err(Error::Calibration))
        || bmi
            .transport
            .downloads
            .iter()
            .any(|bytes| bytes == &[0x99; 4])
        || bmi.transport.commands.contains(&1)
    {
        return TestResult::Fail("bad OTP result continued to firmware activation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_failed_calibration_never_downloads_or_activates_firmware
);

fn smoke_ath10k_pll_executes_rom_register_sequence_before_otp() -> TestResult {
    let p = Profile::select(0x3e, 0x05030000).unwrap();
    if !p.pll {
        return TestResult::Fail("QCA6174 hw3.2 profile omitted its required PLL operation");
    }
    let image = Image::parse(image(0, 4, 3), 6).unwrap();
    let mut files = Store::default();
    files
        .0
        .insert(format!("{}/board.bin", p.directory), vec![0x77; p.board]);
    let mut target = Target::default();
    target.soc.insert(0xb2c, 2 << 8);
    target.soc.insert(0xaf4, 0xf0000000);
    target.soc.insert(0x1018, 0xf0000000);
    target.soc.insert(0x914, 0xf0000000);
    target.soc.insert(0x1014, 1 << 16);
    target.soc.insert(0x820, 0xf0000000);
    let mut bmi = Bmi::new(target);
    if !matches!(
        ready(prepare(&mut bmi, &mut files, p, identity(), "", &image)),
        Some(Ok(_))
    ) {
        return TestResult::Fail("live ROM clock/OTP/firmware orchestration failed");
    }
    let expected = [
        (6, 0xb2c, 2 << 8),
        (6, 0xaf4, 0xf0000000),
        (7, 0xaf4, 0xf0055551),
        (6, 0x1018, 0xf0000000),
        (7, 0x1018, 0xf00004b0),
        (6, 0x914, 0xf0000000),
        (7, 0x914, 0xf0000001),
        (3, 0x404028, 1),
        (6, 0x1014, 0x10000),
        (7, 0x1014, 0x5001d),
        (6, 0x1244, 0),
        (6, 0x1014, 0x5001d),
        (7, 0x1014, 0x4001d),
        (6, 0x1244, 0),
        (6, 0x820, 0xf0000000),
        (7, 0x820, 0xf0000001),
        (6, 0x1014, 0x4001d),
        (7, 0x1014, 0x1d),
        (3, 0x404020, 1),
        (3, 0x404024, 176_000_000),
    ];
    if !bmi.transport.sequence.starts_with(&expected) || bmi.transport.commands.contains(&1) {
        return TestResult::Fail("sensitive Linux PLL order or preserved register bits changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_pll_executes_rom_register_sequence_before_otp
);

fn smoke_ath10k_codeswap_retains_segment_and_uploads_hardware_info() -> TestResult {
    let mut swap = Vec::new();
    for data in [&[1u8, 2, 3][..], &[4u8, 5][..]] {
        swap.extend_from_slice(&0x600000u32.to_le_bytes());
        swap.extend_from_slice(&(data.len() as u32).to_le_bytes());
        swap.extend_from_slice(data);
    }
    swap.extend_from_slice(&[0; 12]);
    swap.extend_from_slice(&0x420000u32.to_le_bytes());
    let p = profile();
    let mut container = image(0, 1, 1);
    ie(&mut container, 7, &swap);
    let image = Image::parse(container, 6).unwrap();
    let mut files = Store::default();
    files
        .0
        .insert(format!("{}/board.bin", p.directory), vec![0x77; p.board]);
    let mut bmi = Bmi::new(Target::default());
    if !matches!(
        ready(prepare(&mut bmi, &mut files, p, identity(), "", &image)),
        Some(Ok(_))
    ) {
        return TestResult::Fail("owned code-swap image failed actual ROM preparation");
    }
    let target = &bmi.transport;
    let Some(memory) = &target.codeswap else {
        return TestResult::Fail("code segment not retained");
    };
    let Some((_, info)) = target.writes.iter().find(|(at, _)| *at == 0x420000) else {
        return TestResult::Fail("code-swap hardware info was not uploaded with BMI");
    };
    if memory.0[..5] != [1, 2, 3, 4, 5]
        || memory.0[5..].iter().any(|&byte| byte != 0)
        || info.len() != 208
        || word(info, 0) != Ok(5)
        || word(info, 4) != Ok(1)
        || word(info, 8) != Ok(38)
        || word(info, 12) != Ok(5)
        || word(info, 16) != Ok(0x123000)
        || info[20..].iter().any(|&byte| byte != 0)
        || ready(bmi.configure_codeswap(&swap)) != Some(Err(BmiError::BadResponse))
    {
        return TestResult::Fail(
            "code-swap DMA payload, segment info, or retained-owner reuse differs",
        );
    }
    let mut truncated = swap.clone();
    truncated[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut bad_magic = swap.clone();
    bad_magic[swap.len() - 16] = 1;
    let mut missing_tail = swap;
    missing_tail.truncate(missing_tail.len() - 4);
    for invalid in [truncated, bad_magic, missing_tail] {
        if super::super::swap::Layout::parse(&invalid).is_ok() {
            return TestResult::Fail("invalid code-swap record/tail admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_codeswap_retains_segment_and_uploads_hardware_info
);

fn smoke_ath10k_zero_length_legacy_board_tail_publishes_rom_config() -> TestResult {
    let p = profile();
    let image = Image::parse(image(0, 1, 1), 6).unwrap();
    let mut files = Store::default();
    files
        .0
        .insert(format!("{}/board.bin", p.directory), vec![0x77; p.board]);
    let mut bmi = Bmi::new(Target {
        board_ext: 0x440000,
        ..Target::default()
    });
    if !matches!(
        ready(prepare(&mut bmi, &mut files, p, identity(), "", &image)),
        Some(Ok(_))
    ) || !bmi
        .transport
        .writes
        .iter()
        .any(|(at, bytes)| *at == HI + 0xb0 && bytes == &[1, 0, 0, 0])
        || bmi.transport.writes.iter().any(|(at, _)| *at == 0x440000)
        || bmi.transport.commands.contains(&1)
    {
        return TestResult::Fail(
            "nonzero ROM pointer rejected a valid zero-byte legacy board tail",
        );
    }
    let mut bmi = Bmi::new(Target {
        board_ext: 0x440001,
        ..Target::default()
    });
    if ready(prepare(&mut bmi, &mut files, p, identity(), "", &image))
        != Some(Err(Error::Calibration))
    {
        return TestResult::Fail("malformed ROM board-tail pointer admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_zero_length_legacy_board_tail_publishes_rom_config
);
