//! Actual platform-granted AML -> decoded BIOS -> TFH/RFH power receipts.
//! All MMIO/config/firmware endpoints are owned RAM, never physical RF proof.
use super::super::super::mld_power::{InputStatus, Inputs};
use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};
use narf_aml::Value;
use narf_bus::{BusAddr, BusDevice, BusKind, DeviceId, PcieAddr};
use narf_capabilities::{Cap, Write};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    f().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn poll<T>(f: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let value = f.poll(&mut Context::from_waker(Waker::noop()));
    if value.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    value
}
struct Transport {
    hw: Option<Hardware>,
    firmware: model::Firmware,
    trace: model::TxTrace,
}
impl Transport {
    fn new(version: u8) -> Self {
        let (mut hw, firmware, trace) = model::station_model_for_format(if version == 10 {
            rx_rfh::CompletionFormat::Ax210
        } else {
            rx_rfh::CompletionFormat::Bz
        });
        model::versions(
            &mut hw,
            &[
                0x9f,
                1,
                version,
                0,
                7,
                4,
                if version == 10 { 7 } else { 8 },
                0,
                5,
                4,
                if version == 10 { 5 } else { 6 },
                0,
            ],
        );
        Self {
            hw: Some(hw),
            firmware,
            trace,
        }
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(hw) = self.hw.take() {
            // SAFETY: all posted endpoints are this fixture's RAM; no outstanding
            // borrowed future or physical device can access them after this scope.
            unsafe { model::destroy(hw) };
        }
    }
}
struct Config {
    _bytes: Vec<u8>,
    ptr: *mut u8,
    physical: PhysAddr,
}
impl Config {
    fn new() -> Self {
        let mut bytes = vec![0; 8192];
        let ptr = ((bytes.as_mut_ptr() as usize + 4095) & !4095) as *mut u8;
        Self {
            _bytes: bytes,
            ptr,
            physical: PhysAddr::from_kernel_ptr(ptr),
        }
    }
    fn put(&self, at: usize, value: u32) {
        assert!(at % 4 == 0 && at < 4096);
        // SAFETY: aligned complete word in the exclusively owned config page.
        unsafe { self.ptr.add(at).cast::<u32>().write_volatile(value) };
    }
    fn device(&self, bus: u8, slot: u8) -> BusDevice {
        let addr = PcieAddr::new(0x7f34, bus, slot, 0);
        BusDevice {
            addr: BusAddr::Pcie(addr),
            id: DeviceId {
                vendor: 0x8086,
                device: 0xe340,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: BusKind::Pcie {
                addr,
                cfg_phys: self.physical,
            },
        }
    }
}
struct Registry(Vec<BusDevice>);
impl Drop for Registry {
    fn drop(&mut self) {
        narf_bus::registry::install(core::mem::take(&mut self.0));
    }
}
fn package(op: &[u8], body: &[u8]) -> Vec<u8> {
    let length = body.len() + 2;
    assert!(length < 4096);
    let mut out = op.to_vec();
    out.extend_from_slice(&[0x40 | (length as u8 & 15), (length >> 4) as u8]);
    out.extend_from_slice(body);
    out
}
fn aml(value: &Value) -> Vec<u8> {
    match value {
        Value::Integer(0) => vec![0],
        Value::Integer(1) => vec![1],
        Value::Integer(value) if *value <= 255 => vec![0x0a, *value as u8],
        Value::Package(values) => {
            let mut out = vec![values.len() as u8];
            for value in values {
                out.extend_from_slice(&aml(value));
            }
            package(&[0x12], &out)
        }
        _ => panic!("native BIOS fixture only contains byte integers/packages"),
    }
}
fn values() -> [Value; 3] {
    let mut wrds = vec![Value::Integer(7), Value::Integer(0x0b)];
    wrds.extend((0..48).map(|i| Value::Integer(30 + i)));
    let mut wgds = vec![Value::Integer(7), Value::Integer(3)];
    for profile in 0..8 {
        for band in 0..4 {
            wgds.extend([
                Value::Integer(20 + profile * 4 + band),
                Value::Integer(2),
                Value::Integer(3),
            ]);
        }
    }
    let mut ppag = vec![Value::Integer(7), Value::Integer(15)];
    ppag.extend((0..22).map(|i| Value::Integer(if i == 0 { 240 } else { i })));
    [
        Value::Package(vec![Value::Integer(3), Value::Package(wrds)]),
        Value::Package(vec![Value::Integer(4), Value::Package(wgds)]),
        Value::Package(vec![Value::Integer(4), Value::Package(ppag)]),
    ]
}
fn firmware() -> Vec<u8> {
    let mut endpoint = b"EP00\x08_ADR\x00\x08SEEN\x00".to_vec();
    for (key, value) in [b"WRDS", b"WGDS", b"PPAG"].into_iter().zip(values()) {
        let mut method = key.to_vec();
        method.extend_from_slice(b"\x00\x70\x01SEEN\xa4");
        method.extend_from_slice(&aml(&value));
        endpoint.extend_from_slice(&package(&[0x14], &method));
    }
    let mut port = b"RP01\x08_ADR\x0c\x00\x00\x01\x00\x08WRDS\x0a\x63".to_vec();
    port.extend_from_slice(&package(&[0x5b, 0x82], &endpoint));
    let mut root = b"ZIB0\x08_HID\x0dPNP0A08\x00\x08_SEG\x0b\x34\x7f\x08_BBN\x00".to_vec();
    root.extend_from_slice(&package(&[0x5b, 0x82], &port));
    package(&[0x5b, 0x82], &root)
}
fn source_snapshot() -> Result<Inputs, &'static str> {
    let _registry = Registry(narf_bus::registry::devices());
    // SAFETY: serialized fixture; no production AML transaction or test
    // metadata facade survives this namespace and its owned config windows.
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    narf_aml::__parse_body_for_test(&firmware(), "\\")
        .map_err(|_| "Intel actual AML fixture parse")?;
    let bridge = Config::new();
    let endpoint = Config::new();
    // SAFETY: owned uniquely mapped config pages outlive the ECAM scope.
    let _ecam = unsafe {
        narf_bus::ecam::__test_windows(&[
            (bridge.physical, bridge.ptr, 4096),
            (endpoint.physical, endpoint.ptr, 4096),
        ])
    };
    bridge.put(0x0c, 1 << 16);
    bridge.put(0x18, 0x0003_0300);
    let child = endpoint.device(3, 0);
    narf_bus::registry::install(vec![bridge.device(0, 1), child]);
    let cap = Cap::<narf_bus::BusDeviceCap, Write>::bootstrap();
    let power = narf_power::bootstrap_power_authority();
    // SAFETY: actual scoped fixture grant, restored only after all metadata
    // transactions complete; no wake owner or physical firmware is involved.
    let _power = unsafe { narf_power::pci_firmware::__test_platform_authority_scope(&power) }
        .map_err(|_| "Intel fixture platform grant")?;
    let input = super::super::super::mld_platform::read(child, &cap);
    if input.status
        != [
            InputStatus::Present,
            InputStatus::Absent,
            InputStatus::Present,
            InputStatus::Present,
        ]
        || narf_aml::eval::strict::evaluate_object("\\ZIB0.RP01.EP00.SEEN", &[])
            != Ok(Value::Integer(1))
    {
        return Err("Intel BIOS did not use real granted exact-endpoint method results");
    }
    cap.revoke();
    let denied = super::super::super::mld_platform::read(child, &cap);
    if denied.status != [InputStatus::Authority; 4] {
        return Err("revoked PCI BIOS lookup became absent data");
    }
    Ok(input)
}
fn observe(packet: &model::Published, version: u8) -> Result<(), &'static str> {
    if packet.bytes.len() < 8 || packet.bytes[7] != 0 {
        return Err("native BIOS power command header");
    }
    let body = &packet.bytes[8..];
    match (packet.bytes[1], packet.bytes[0]) {
        (4, 7) => {
            if body.len() != 32
                || body[..4] != [1, 4, 0, 0]
                || body[4..8] != [15, 0, 0, 0]
                || body[8] != 240
            {
                return Err("actual PPAG source/mode/gains were not copied to native DMA");
            }
        }
        (1, 0x9f) => {
            let bands = if version == 10 { 11 } else { 12 };
            if body.len() != if version == 10 { 108 } else { 116 }
                || body[..10] != [2, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                || body[10..12] != [30, 0]
                || body[10 + 2 * bands..12 + 2 * bands] != [42, 0]
                || body[10 + 4 * bands..body.len() - 4].iter().any(|v| *v != 0)
                || body[body.len() - 4..] != [5, 0, 0, 0]
            {
                return Err("actual WRDS limits/flags/native v10-v11 geometry/CDB bytes");
            }
        }
        (4, 5) => {
            if body.len() != if version == 10 { 104 } else { 136 }
                || body[..8] != [0, 0, 0, 0, 20, 0, 2, 3]
                || body[body.len() - 4..]
                    != if version == 10 {
                        [0, 0, 0, 0]
                    } else {
                        [1, 4, 0, 0]
                    }
            {
                return Err("actual WGDS native table/source/revision bytes");
            }
        }
        _ => return Err("unexpected optional platform command"),
    }
    Ok(())
}
fn smoke_iwl_mld_native_bios_source_and_power_receipts_precede_ready() -> TestResult {
    check(|| {
        let input = source_snapshot()?;
        for version in [10, 11] {
            let mut t = Transport::new(version);
            // A separate explicit DMI model covers the optional PPAG branch;
            // the actual BIOS values above still come from the granted facade.
            let mut input = input.clone();
            input.ppag_approved = super::super::super::mld_power::ppag_approved(b"HP", b"");
            {
                let mut future = pin!(t.hw.as_mut().unwrap().prepare_platform_power_using(input));
                for expected in [(4, 7), (1, 0x9f), (4, 5)] {
                    if !poll(future.as_mut()).is_pending() {
                        return Err("BIOS power skipped its native receipt");
                    }
                    let p = t
                        .trace
                        .take()
                        .ok_or("BIOS native TFH publication missing")?;
                    if (p.bytes[1], p.bytes[0]) != expected {
                        return Err("PPAG/SAR/geo native order");
                    }
                    observe(&p, version)?;
                    t.firmware.inject(
                        p.bytes[0],
                        p.bytes[1],
                        u16::from_le_bytes([p.bytes[2], p.bytes[3]]),
                        &[],
                    );
                }
                if !matches!(poll(future.as_mut()), Poll::Ready(Ok(()))) {
                    return Err("final BIOS receipt did not complete preparation");
                }
            }
            let hw = t.hw.as_mut().unwrap();
            if hw.platform_power.phase != Phase::Ready || hw.platform_power.receipts.len() != 3 {
                return Err("native BIOS receipt facts not retained");
            }
            if !matches!(
                poll(
                    pin!(
                        hw.prepare_platform_power_using(Inputs::unavailable(InputStatus::Firmware))
                    )
                    .as_mut()
                ),
                Poll::Ready(Err(_))
            ) || hw.platform_power.receipts.len() != 3
                || t.trace.take().is_some()
            {
                return Err("later input failure erased or reprogrammed an applied BIOS limit");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/power",
    smoke_iwl_mld_native_bios_source_and_power_receipts_precede_ready
);

fn smoke_iwl_mld_native_bios_cancellation_pins_pending_and_never_defaults() -> TestResult {
    check(|| {
        let mut input = source_snapshot()?;
        input.ppag_approved = false;
        let mut t = Transport::new(10);
        {
            let mut future = pin!(t.hw.as_mut().unwrap().prepare_platform_power_using(input));
            if !poll(future.as_mut()).is_pending() {
                return Err("SAR did not await native receipt");
            }
            let p = t.trace.take().ok_or("SAR publication absent")?;
            t.firmware
                .inject(0x9f, 1, u16::from_le_bytes([p.bytes[2], p.bytes[3]]), &[]);
            if !poll(future.as_mut()).is_pending() {
                return Err("geo did not retain native receipt");
            }
            observe(&t.trace.take().ok_or("geo publication absent")?, 10)?;
        }
        let retained = model::retained(t.hw.as_ref().unwrap());
        if retained.0 != 1 || t.hw.as_ref().unwrap().platform_power.receipts.len() != 1 {
            return Err("dropped BIOS waiter released uncertain native DMA");
        }
        if !matches!(
            poll(pin!(t.hw.as_mut().unwrap().ensure_platform_power()).as_mut()),
            Poll::Ready(Err(_))
        ) || model::retained(t.hw.as_ref().unwrap()) != retained
            || t.trace.take().is_some()
        {
            return Err("cancelled BIOS owner retried with permissive/default limits");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/power",
    smoke_iwl_mld_native_bios_cancellation_pins_pending_and_never_defaults
);

fn smoke_iwl_mld_optional_bios_absent_disabled_and_invalid_do_not_invent_commands() -> TestResult {
    check(|| {
        let values = values();
        let mut disabled = values[0].clone();
        if let Value::Package(root) = &mut disabled {
            if let Value::Package(wifi) = &mut root[1] {
                wifi[1] = Value::Integer(0);
            }
        }
        for input in [
            Inputs::decoded(Ok(None), Ok(None), Ok(None), Ok(None), false),
            Inputs::unavailable(InputStatus::Authority),
            Inputs::decoded(
                Ok(Some(Value::Integer(1))),
                Ok(None),
                Ok(Some(values[1].clone())),
                Ok(None),
                false,
            ),
            Inputs::decoded(
                Ok(Some(disabled)),
                Ok(None),
                Ok(Some(values[1].clone())),
                Ok(None),
                false,
            ),
        ] {
            let mut t = Transport::new(10);
            if !matches!(
                poll(pin!(t.hw.as_mut().unwrap().prepare_platform_power_using(input)).as_mut()),
                Poll::Ready(Ok(()))
            ) || t.trace.take().is_some()
                || !t.hw.as_ref().unwrap().platform_power.receipts.is_empty()
            {
                return Err("optional unavailable/invalid/disabled BIOS data manufactured SAR or a new board gate");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/power",
    smoke_iwl_mld_optional_bios_absent_disabled_and_invalid_do_not_invent_commands
);
