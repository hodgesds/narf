use super::super::{runtime, rx_rfh};
use super::*;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
const VERSIONS: &[u8] = &[
    8, 3, 1, 0, 0x18, 1, 12, 2, 0x19, 1, 2, 0, 0xf, 5, 4, 0, 0x18, 5, 1, 0, 0x17, 5, 3, 2, 0x91, 1,
    13, 0, 0x1e, 1, 2, 1, 0x1c, 1, 9, 7, 0xc1, 0, 99, 4, 0xf7, 5, 99, 3,
];
fn api(ultra: bool) -> FirmwareApi<'static> {
    let mut api = FirmwareApi {
        commands: VERSIONS,
        ..FirmwareApi::default()
    };
    api.api_changes[0] = 1 << 30;
    api.capabilities[3] = 1 << 14; // MLD MAC/LINK, not MLD STA_CONFIG
    if ultra {
        api.capabilities[1] |= 1 << 16;
    }
    api
}
fn nvm() -> Nvm {
    let mut bytes = vec![0; 28 + 110 * 4];
    bytes[12..16].copy_from_slice(&3u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&3u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
    bytes[28] = 1;
    Nvm::parse(4, &bytes).unwrap()
}
struct Fixture {
    hw: Option<runtime::Hardware>,
    fw: runtime::model::Firmware,
    trace: runtime::model::TxTrace,
}
impl Fixture {
    fn new(ultra: bool) -> Self {
        let (mut hw, fw, trace) =
            runtime::model::station_model_for_format(rx_rfh::CompletionFormat::Qu);
        runtime::model::versions(&mut hw, VERSIONS);
        hw.retain_gen2_ap_adapter(&api(ultra), &nvm());
        Self {
            hw: Some(hw),
            fw,
            trace,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(hw) = self.hw.take() {
            // SAFETY: all published mappings belong only to this RAM fixture.
            unsafe {
                runtime::model::destroy(hw);
            }
        }
    }
}
fn run(
    fut: impl Future<Output = Result<(), &'static str>>,
    fw: &mut runtime::model::Firmware,
    trace: &runtime::model::TxTrace,
    group: u8,
    command: u8,
    expected: &[u8],
    reply: &[u8],
) -> Result<Result<(), &'static str>, &'static str> {
    let mut fut = core::pin::pin!(fut);
    let deadline =
        narf_time::now_cycles().saturating_add(narf_time::wall::ns_to_cycles(3_000_000_000));
    let mut seen = false;
    loop {
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => {
                if !seen {
                    return Err("API77 AP native future completed without DMA receipt");
                }
                return Ok(result);
            }
            Poll::Pending => {}
        }
        if let Some(p) = trace.take() {
            if seen
                || p.bytes.len() != 8 + expected.len()
                || p.bytes[0] != command
                || p.bytes[1] != group
                || p.bytes[8..] != *expected
            {
                return Err("API77 AP actual TFH command differs from literal ABI");
            }
            let sequence = u16::from_le_bytes(p.bytes[2..4].try_into().unwrap());
            fw.inject(command, group, sequence, reply);
            seen = true;
        }
        if narf_time::now_cycles() >= deadline {
            return Err("API77 AP native command receipt timeout");
        }
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
}
fn native_case() -> Result<(), &'static str> {
    for ultra in [false, true] {
        let mut f = Fixture::new(ultra);
        let hw = f.hw.as_mut().unwrap();
        if super::super::ap_session::supported(hw) {
            return Err("API77 codec facts opened incomplete AP admission");
        }
        let peer = super::super::ap_wire::internal(0, 2);
        let mut literal = [0; 48];
        literal[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
        literal[8] = 3;
        literal[35] = 2;
        if run(
            hw.ap_peer(&peer),
            &mut f.fw,
            &f.trace,
            1,
            0x18,
            &literal,
            &[2, 0, 0, 0],
        )?
        .is_ok()
        {
            return Err("API77 AP negative ADD_STA status became native peer authority");
        }
        let before = f.fw.tx_write();
        {
            let mut remove = core::pin::pin!(hw.ap_remove_peer(0));
            if !matches!(
                remove
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(_))
            ) || f.fw.tx_write() != before
            {
                return Err("failed API77 station add authorized REMOVE_STA publication");
            }
        }
        run(
            hw.ap_peer(&peer),
            &mut f.fw,
            &f.trace,
            1,
            0x18,
            &literal,
            &[1, 0, 0, 0],
        )??;
        literal[0] = 1;
        run(
            hw.ap_peer(&peer),
            &mut f.fw,
            &f.trace,
            1,
            0x18,
            &literal,
            &[1, 0, 0, 0],
        )??;
        run(
            hw.ap_remove_peer(0),
            &mut f.fw,
            &f.trace,
            1,
            0x19,
            &[0; 4],
            &[],
        )??;
        let mut client = super::super::station_api::peer([2, 4, 6, 8, 10, 12]);
        put32(&mut client, 0, 2);
        put32(&mut client, 28, 17);
        put32(&mut client, 36, 1);
        put32(&mut client, 64, 6);
        put32(&mut client, 68, 0x99);
        let mut literal = [0; 48];
        literal[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
        literal[8..14].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
        literal[16] = 2;
        literal[17] = 4;
        put32(&mut literal, 24, (3 << 26) | (3 << 28) | (1 << 17));
        literal[36] = 17;
        literal[46] = 6;
        literal[47] = 0x99;
        run(
            hw.ap_peer(&client),
            &mut f.fw,
            &f.trace,
            1,
            0x18,
            &literal,
            &[1, 0, 0, 0],
        )??;
        let mut unsupported = client;
        put32(&mut unsupported, 40, 1);
        let before = f.fw.tx_write();
        {
            let mut command = core::pin::pin!(hw.ap_peer(&unsupported));
            if !matches!(
                command
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(_))
            ) || f.fw.tx_write() != before
            {
                return Err("API77 AP silently dropped unadmitted PHY field before native ADD_STA");
            }
        }
        let canonical = super::super::station_api::phy(1, 1);
        let tail = if ultra { 24 } else { 20 };
        let mut physical = vec![0; tail + 16];
        put32(&mut physical, 4, 1);
        if ultra {
            put32(&mut physical, 16, 1);
            physical[20] = 1;
        } else {
            physical[16] = 1;
            physical[17] = 1;
        }
        put32(&mut physical, tail, 3);
        put32(&mut physical, tail + 4, 6 | (2 << 10) | (2 << 12));
        run(
            hw.ap_phy(&canonical),
            &mut f.fw,
            &f.trace,
            1,
            8,
            &physical,
            &[],
        )??;
        let mut captured = vec![0; 48 + 26];
        captured[..2].copy_from_slice(&26u16.to_le_bytes());
        put32(&mut captured, 12, 3);
        captured[32] = 40;
        captured[34] = 1;
        captured[48] = 0x88;
        let rx = hw
            .ap_mpdu(&captured)
            .ok_or("API77 AP native48 RX envelope refused")?;
        if rx.frame.len() != 26 || rx.frame[0] != 0x88 || rx.rssi != -40 || rx.channel != 1 {
            return Err("API77 AP decoded Gen3 offsets instead of actual48 native prefix");
        }
        let mut wrong = api(ultra);
        wrong.capabilities[3] = 0;
        if Adapter::read(&wrong, &nvm()).is_ok() {
            return Err("API77 AP inferred MLD MAC from enum/version alone");
        }
        wrong = api(ultra);
        wrong.api_changes[0] = 0;
        if Adapter::read(&wrong, &nvm()).is_ok() {
            return Err("API77 AP inferred STA_TYPE without source API30");
        }
    }
    Ok(())
}
fn smoke_iwl_native_ap_api77_closed_adapter_uses_status_phy_and_rfh48() -> TestResult {
    match native_case() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ap",
    smoke_iwl_native_ap_api77_closed_adapter_uses_status_phy_and_rfh48
);
