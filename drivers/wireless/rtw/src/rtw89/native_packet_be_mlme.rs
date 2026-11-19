// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact source BE no-link register/CH12 adapter, packet gates still closed.
use super::*;
use crate::rtw89::{be_mlme, link_h2c_8922a as link, power::Io};
pub(super) struct Native<'a> {
    prepared: &'a mut CheckedPrepared,
    region: &'a MmioRegion,
    cap: &'a Cap<BusDeviceCap, Write>,
    cancel: &'a AtomicBool,
    grant: &'a Ordinary,
    response: Response,
    fault: bool,
    radio: &'a native_radio_be::Radio,
}
// The same actual operation boundary is used by direct register writes and
// commands. A prior metadata/current check cannot authorize a resumed effect.
#[allow(clippy::too_many_arguments)]
fn source_scope<T>(
    radio: &native_radio_be::Radio,
    grant: &Ordinary,
    cap: &Cap<BusDeviceCap, Write>,
    region: &MmioRegion,
    response: Response,
    cancel: &AtomicBool,
    operation: impl FnOnce() -> Result<T, power::Error>,
) -> Result<T, power::Error> {
    radio.with_packet_preflight(|| {
        grant.with_current(|| {
            crate::rtw88::pci_park::invoke(cap, || {
                super::super::be_packet_qualification::closed(region)?;
                response.check(region)?;
                if cancel.load(Ordering::Acquire) {
                    return Err(power::Error::Access);
                }
                let value = operation()?;
                super::super::be_packet_qualification::closed(region)?;
                response.check(region)?;
                if cancel.load(Ordering::Acquire) {
                    return Err(power::Error::Access);
                }
                radio.with_packet_preflight(|| grant.with_current(|| Ok(value)))
            })
            .map_err(|_| power::Error::Access)?
        })
    })
}
impl<'a> Native<'a> {
    /// # Safety
    /// Same original packet-prepared inactive owner and exact current N22O
    /// snapshot on the complete live BAR; no competing reset/IRQ/producer.
    pub(super) unsafe fn new(
        prepared: &'a mut CheckedPrepared,
        region: &'a MmioRegion,
        cap: &'a Cap<BusDeviceCap, Write>,
        cancel: &'a AtomicBool,
        grant: &'a Ordinary,
        response: Response,
        radio: &'a native_radio_be::Radio,
    ) -> Self {
        Self {
            prepared,
            region,
            cap,
            cancel,
            grant,
            response,
            fault: false,
            radio,
        }
    }
    pub(super) fn poison(&mut self) {
        self.fault = true;
        self.prepared.poison_radio();
    }
    fn scope<T>(
        &mut self,
        op: impl FnOnce(&mut CheckedPrepared, &MmioRegion) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        if self.fault || self.cancel.load(Ordering::Acquire) {
            return Err(power::Error::Access);
        }
        let grant = self.grant;
        let region = self.region;
        let cancel = self.cancel;
        let radio = self.radio;
        let cap = self.cap;
        let response = self.response;
        let prepared = &mut *self.prepared;
        let result = source_scope(radio, grant, cap, region, response, cancel, || {
            op(prepared, region)
        });
        if result.is_err() {
            self.poison();
        }
        result
    }
    fn access<T>(
        &mut self,
        a: u32,
        width: u32,
        op: impl FnOnce(&MmioRegion, u64) -> T,
    ) -> Result<T, power::Error> {
        let allowed = match width {
            1 => [0x10590, 0x10e08].contains(&a),
            2 => [0x1040e, 0x10412, 0x10426, 0x10814].contains(&a),
            4 => [
                0x9d00, 0x9d04, 0x9c30, 0x10400, 0x10404, 0x10408, 0x1040c, 0x10414, 0x10568,
                0x1083c, 0x108a0, 0x11400, 0x11440, 0x11470, 0x11484,
            ]
            .contains(&a),
            _ => false,
        };
        if !allowed || a & (width - 1) != 0 || u64::from(a) + u64::from(width) > self.region.len {
            self.poison();
            return Err(power::Error::Access);
        }
        self.scope(|_, r| Ok(op(r, u64::from(a))))
    }
}
impl Io for Native<'_> {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        // SAFETY: exact current source byte width/extent and powered tuple.
        self.access(a, 1, |r, o| unsafe { r.read8(o) })
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        // SAFETY: exact current aligned source halfword, including1040e.
        self.access(a, 2, |r, o| unsafe { r.read16(o) })
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        // SAFETY: exact current source word width/extent and powered tuple.
        self.access(a, 4, |r, o| unsafe { r.read32(o) })
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        // SAFETY: exact current source byte only; subsequent source readback.
        self.access(a, 1, |r, o| unsafe { r.write8(o, v) })
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        // SAFETY: exact current source halfword; no adjacent field write.
        self.access(a, 2, |r, o| unsafe { r.write16(o, v) })
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        // SAFETY: exact current source word, no MAC1/HCI/packet-enable fields.
        self.access(a, 4, |r, o| unsafe { r.write32(o, v) })
    }
    fn now_us(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1000
    }
    async fn delay_us(&mut self, us: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(us.saturating_mul(1000))).await;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl be_mlme::Interface for Native<'_> {
    fn current(&mut self) -> Result<(), power::Error> {
        self.scope(|_, _| Ok(()))
    }
    async fn command(&mut self, command: link::LinkCmd, body: &[u8]) -> Result<(), power::Error> {
        let cctl = command.cmd
            == crate::rtw89::fwcmd_8922a::H2cCmd {
                cat: 1,
                class: 5,
                func: 0x11,
            }
            && !command.rec_ack
            && command.done_ack;
        if !(cctl
            || [
                link::CMD_MACID_PAUSE_SLEEP,
                link::CMD_ROLE_MAINTAIN,
                link::CMD_JOIN_INFO,
                link::CMD_CAM,
                link::CMD_DMAC_V2,
                be_mlme::BA_USERS,
            ]
            .contains(&command))
        {
            self.poison();
            return Err(power::Error::Unsupported);
        }
        let region = self.region;
        let cancel = self.cancel;
        let grant = self.grant;
        let radio = self.radio;
        self.scope(|prepared, _| {
            // SAFETY: actual bounded source controller emits these exact
            // source-selected bodies/ACK flags under retained original N22O.
            unsafe { prepared.send_mlme(region, cancel, grant, radio, command, body) }
                .map_err(|_| power::Error::Access)
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
    fn smoke_rtw8922a_native_mlme_original_source_revoke_refuses_after_prior_metadata_check(
    ) -> TestResult {
        for inside in [false, true] {
            let (wlan, signer) = crate::rtw89::be_wlan_qualification::tests::revocable();
            let radio = native_radio_be::Radio::fixture_packet_refusal_source(wlan);
            // Fixture holds historical stage metadata only, with NO reports
            // or RF/packet effect. This positive no-op is not RF authority.
            kt_assert!(radio
                .late_report(crate::rtw89::rfk::be_rfk::ReportKind::Dack)
                .is_none());
            kt_assert_eq!(
                radio.with_packet_preflight(|| Ok::<_, power::Error>(())),
                Ok(())
            );
            let (ordinary, _) = crate::rtw89::be_packet_qualification::tests::revocable();
            let cap = Cap::<BusDeviceCap, Write>::bootstrap();
            let cancel = AtomicBool::new(false);
            let mut words = vec![0u32; 0x40000 / 4];
            for (a, v) in [
                (0x24, 0x1f000000),
                (0x84, 0x02010000),
                (0x10000, 0),
                (0xb010, 0x80006fff),
                (0xb000, 0x30),
                (0xe348, 0xd57ddf),
                (0xac, 0x81004003),
                (0x1087c, 0x111),
            ] {
                words[a / 4] = v;
            }
            let region = MmioRegion {
                phys: narf_memory::PhysAddr::new(0),
                virt: words.as_mut_ptr() as u64,
                len: 0x40000,
                kind: narf_bus::BarKind::Mmio32 {
                    prefetchable: false,
                },
            };
            if !inside {
                signer.revoke();
            }
            let mut called = false;
            let result = source_scope(
                &radio,
                &ordinary,
                &cap,
                &region,
                Response::fixture(),
                &cancel,
                || {
                    called = true;
                    signer.revoke();
                    Ok(())
                },
            );
            kt_assert!(result.is_err());
            kt_assert_eq!(called, inside);
            let before = words.clone();
            let mut later = false;
            kt_assert!(source_scope(
                &radio,
                &ordinary,
                &cap,
                &region,
                Response::fixture(),
                &cancel,
                || {
                    later = true;
                    Ok(())
                }
            )
            .is_err());
            kt_assert!(!later);
            kt_assert_eq!(words, before);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89/8922a",
        smoke_rtw8922a_native_mlme_original_source_revoke_refuses_after_prior_metadata_check
    );
}
