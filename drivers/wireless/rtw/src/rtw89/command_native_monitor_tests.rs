// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Actual Native/NativeIo/control boundary, explicit inert RAM/full-RFK seal.
use super::*;
use crate::rtw89::{monitor, station_control::Admission};
use alloc::sync::Arc;
pub(super) fn run() -> Result<(), &'static str> {
    for failure in 0..6 {
        let mut f =
            Fixture::aperture(ChipId::Rtl8852B, 0x20000).map_err(|_| "native monitor RAM")?;
        f.activate().map_err(|_| "native monitor CH12")?;
        let (qualification, base) = crate::rtw89::radio_policy::tests::revocable_model();
        f.native.ordinary = Some(OrdinaryGrant::B(Arc::new(qualification)));
        let desired = monitor::Desired::new();
        let selected = desired
            .select(desired.snapshot(), 6)
            .ok_or("native desired monitor")?;
        let admission = Admission::new();
        let before = f.native.ring.as_ref().unwrap().as_slice().to_vec();
        match failure {
            1 => {
                base.revoke();
            }
            2 => admission.close(),
            3 => f.words[0xc000 / 4] = 1 << 29,
            4 => {
                desired.select(selected, 2).unwrap();
            }
            5 => f.native.station_runtime.model_started(),
            _ => {}
        }
        let result = f.native.monitor_prepare(desired, admission);
        if failure == 0 {
            if result.is_err()
                || f.native.monitor_current().is_err()
                || f.native.prepare_packets([2, 4, 6, 8, 10, 12], 0).is_ok()
                || f.native.packets_ready()
            {
                return Err("actual Native monitor borrowed station TX owner");
            }
            f.words[0xc000 / 4] = 1 << 29;
            if f.native.monitor_current().is_ok() {
                return Err("actual Native capture ignored changed CMAC TX/autoresponse state");
            }
        } else if result.is_ok() {
            return Err("actual Native monitor accepted foreign/current/TX/peer source");
        }
        if f.native.queue.pending() != 0 || f.native.ring.as_ref().unwrap().as_slice() != before {
            return Err("failed native monitor admission issued DMA");
        }
    }
    Ok(())
}
