// SPDX-License-Identifier: GPL-2.0-or-later
//! Native retained firmware/factory/IQK/LCK/PA -> separately signed NASR.
//! This is a child of runtime_tests::retained_tests::supervision_tests.
use super::super::super::super::station_policy::{self, Program as StationProgram};
use super::*;
#[path = "ht_packet_tests.rs"]
mod ht_packet_tests;
fn record(binding: &super::super::super::super::supervision::Binding) -> Vec<u8> {
    let mut b = vec![0; 640];
    b[..4].copy_from_slice(b"NASR");
    b[4..8].copy_from_slice(&[1, 0, 0, 1]);
    b[8..12].copy_from_slice(&640u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x23, 0x87]);
    b[16..48].copy_from_slice(&StationProgram::request(binding).unwrap().binding);
    b[48..80].copy_from_slice(&crate::rtlwifi::radio::factory_identity(binding.factory()));
    b[80..112].copy_from_slice(&binding.napc_digest());
    b[112..144].copy_from_slice(&binding.naqr_digest());
    b[144..176].copy_from_slice(&binding.firmware().digest);
    b[176..208].copy_from_slice(&station_policy::recipe_digest());
    let op = binding.operating();
    b[208..214].copy_from_slice(&[op.channel, 20, 0, op.channel, 1, 0]);
    b[214..220].copy_from_slice(&binding.factory().mac);
    b[222..224].copy_from_slice(&80i16.to_le_bytes());
    b[224..226].copy_from_slice(&80i16.to_le_bytes());
    b[226] = 1;
    b[227] = u8::from(binding.adapter().bt.coexistence);
    b[228..232].copy_from_slice(&0xfffu32.to_le_bytes());
    // Independent station/coex worst-case curves: index10 fits and7 does NOT.
    // Existing NAPC has the opposite safety relation. No monotonic inference.
    let mut curves = [[i16::MAX; 64]; 3];
    for curve in &mut curves {
        curve[63] = -512;
        curve[10] = 79;
        curve[7] = 81;
    }
    curves[0][0] = 0;
    for (n, value) in curves.iter().flatten().enumerate() {
        b[256 + n * 2..258 + n * 2].copy_from_slice(&value.to_le_bytes());
    }
    b
}
fn ht_record(binding: &super::super::super::super::supervision::Binding) -> Vec<u8> {
    let mut bytes = record(binding);
    bytes[4] = 2;
    bytes[16..48].copy_from_slice(&StationProgram::request_ht20(binding).unwrap().binding);
    bytes[176..208].copy_from_slice(&station_policy::recipe_for(station_policy::Profile::Ht20));
    bytes[226] = 2;
    bytes[228..232].copy_from_slice(&0xfffffu32.to_le_bytes());
    bytes
}
fn aspm_record(binding: &super::super::super::super::supervision::Binding) -> Vec<u8> {
    let mut bytes = ht_record(binding);
    bytes[4] = 3;
    bytes[16..48].copy_from_slice(&StationProgram::request_ht20_aspm(binding).unwrap().binding);
    bytes[176..208].copy_from_slice(&station_policy::recipe_for(
        station_policy::Profile::Ht20Aspm,
    ));
    bytes[226] = 3;
    bytes
}
fn smoke_ae_nasr3_original_port_profile_refuses_legacy_upgrade_and_revocation() -> TestResult {
    for profile in 1..=3 {
        let (raw, root, _, database) = registered();
        kt_assert_eq!(finish(&root), Ok(()));
        let binding = run(root.completed_binding()).unwrap();
        let bytes = match profile {
            1 => record(&binding),
            2 => ht_record(&binding),
            _ => aspm_record(&binding),
        };
        let cap = Cap::bootstrap();
        let program =
            Arc::new(StationProgram::parse(binding.clone(), &bytes, Some([1; 32]), cap).unwrap());
        kt_assert_eq!(program.aspm(), profile == 3);
        kt_assert_eq!(program.ht20(), profile != 1);
        let grant = program.grant_for(&database.snapshot().unwrap()).unwrap();
        let port = run(root.claim_station_port(program, grant)).unwrap();
        let before = raw.port.writes().len();
        kt_assert_eq!(port.require_ae_aspm_profile().is_ok(), profile == 3);
        kt_assert_eq!(raw.port.writes().len(), before);
        if profile == 3 {
            let mut old = ht_record(&binding);
            old[4] = 3;
            old[226] = 3;
            kt_assert!(StationProgram::parse(binding.clone(), &old, Some([1; 32]), cap).is_err());
            kt_assert!(StationProgram::request_ht20_aspm(&binding)
                .unwrap()
                .name
                .contains("station-v3-"));
            cap.revoke();
            kt_assert!(port.require_ae_aspm_profile().is_err());
            kt_assert!(port.write8(0x34b, 0x93).is_err());
            kt_assert_eq!(raw.port.writes().len(), before);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_ae_nasr3_original_port_profile_refuses_legacy_upgrade_and_revocation
);
fn smoke_ae_nasr2_profile_and_active_rate_mask_never_upgrade_legacy() -> TestResult {
    let (_, root, _, database) = registered();
    kt_assert_eq!(finish(&root), Ok(()));
    let binding = run(root.completed_binding()).unwrap();
    let legacy = record(&binding);
    let ht = ht_record(&binding);
    let source = Cap::bootstrap();
    let first = StationProgram::parse(binding.clone(), &legacy, Some([1; 32]), source).unwrap();
    let second = StationProgram::parse(binding.clone(), &ht, Some([1; 32]), source).unwrap();
    let domain = database.snapshot().unwrap();
    let a = first.grant_for(&domain).unwrap();
    let b = second.grant_for(&domain).unwrap();
    kt_assert!(!first.ht20() && second.ht20());
    kt_assert_eq!(a.permission().admitted_rates(), 0xfff);
    kt_assert_eq!(b.permission().admitted_rates(), 0xfffff);
    kt_assert!(a != b);
    // Legacy hardware words retain independently measured unused indices;
    // restricting its on-air bitmap must not write an unmeasured lower gain.
    kt_assert_eq!(first.plan(a).unwrap(), second.plan(b).unwrap());
    kt_assert!(StationProgram::request_ht20(&binding)
        .unwrap()
        .name
        .contains("station-v2-"));
    kt_assert!(
        StationProgram::request(&binding).unwrap().binding
            != StationProgram::request_ht20(&binding).unwrap().binding
    );
    let mut forged = legacy;
    forged[4] = 2;
    forged[226] = 2;
    forged[228..232].copy_from_slice(&0xfffffu32.to_le_bytes());
    kt_assert!(StationProgram::parse(binding.clone(), &forged, Some([1; 32]), source).is_err());
    let mut wrong = ht;
    wrong[228..232].copy_from_slice(&0xfffu32.to_le_bytes());
    kt_assert!(StationProgram::parse(binding, &wrong, Some([1; 32]), source).is_err());
    source.revoke();
    let effects = core::sync::atomic::AtomicUsize::new(0);
    kt_assert!(second
        .with_current(|| {
            effects.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .is_err());
    kt_assert_eq!(effects.load(core::sync::atomic::Ordering::SeqCst), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_ae_nasr2_profile_and_active_rate_mask_never_upgrade_legacy
);
fn smoke_ae_nasr_independent_joint_measurements_and_old_record_refusal() -> TestResult {
    let (_, root, _, database) = registered();
    kt_assert_eq!(finish(&root), Ok(()));
    let binding = run(root.completed_binding()).unwrap();
    let b = record(&binding);
    let cap = Cap::bootstrap();
    let program = StationProgram::parse(binding.clone(), &b, Some([1; 32]), cap).unwrap();
    let grant = program.grant_for(&database.snapshot().unwrap()).unwrap();
    for rate in 0..20 {
        kt_assert_eq!(
            grant.permission().index(rate),
            if rate == 3 { 0 } else { 10 }
        );
    }
    kt_assert_eq!(program.plan(grant).unwrap().cck_words()[0], 0x000a_0a0a);
    kt_assert!(StationProgram::parse(binding.clone(), &b, None, cap).is_err());
    for at in [
        0, 4, 6, 8, 12, 16, 48, 80, 112, 144, 176, 208, 209, 210, 211, 212, 213, 214, 226, 227,
        228, 232, 255,
    ] {
        let mut other = b.clone();
        other[at] ^= 1;
        kt_assert!(StationProgram::parse(binding.clone(), &other, Some([1; 32]), cap).is_err());
    }
    for length in [0, 96, 256, 639] {
        kt_assert!(
            StationProgram::parse(binding.clone(), &b[..length], Some([1; 32]), cap).is_err()
        );
    }
    cap.revoke();
    let counter = core::sync::atomic::AtomicUsize::new(0);
    kt_assert!(program
        .with_current(|| {
            counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(())
        })
        .is_err());
    kt_assert_eq!(counter.load(core::sync::atomic::Ordering::Relaxed), 0);
    TestResult::Pass
}
fn smoke_ae_nasr_completed_binding_refuses_unfinished_and_retired_context() -> TestResult {
    let (port, root, _, _) = registered();
    kt_assert!(run(root.completed_binding()).is_err());
    port.port.0.lock().pause_delay = Some(1_000);
    for _ in 0..16 {
        if status(&root) == Status::Running(Stage::Iqk) {
            break;
        }
        kt_assert!(step(&root).is_pending());
    }
    kt_assert!(run(root.completed_binding()).is_err());
    root.retire();
    let writes = port.port.writes().len();
    kt_assert!(matches!(step(&root), Poll::Ready(Err(_))));
    kt_assert!(run(root.completed_binding()).is_err());
    kt_assert_eq!(port.port.writes().len(), writes);
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_nasr_independent_joint_measurements_and_old_record_refusal}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_nasr_completed_binding_refuses_unfinished_and_retired_context}

pub(crate) struct Block {
    address: u64,
    bytes: Vec<u8>,
    drops: Arc<core::sync::atomic::AtomicUsize>,
}
impl Drop for Block {
    fn drop(&mut self) {
        self.drops
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}
// SAFETY: each private actor block has a disjoint fixed DMA32 extent and
// exclusively owned byte vector. No physical CPU/DMA mapping is fabricated.
unsafe impl crate::rtlwifi::prepare::Memory for Block {
    fn address(&self) -> u64 {
        self.address
    }
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn write32(&mut self, o: usize, v: u32) -> Result<(), Error> {
        self.write_bytes(o, &v.to_le_bytes())
    }
    fn read32(&self, o: usize) -> Result<u32, Error> {
        let mut b = [0; 4];
        self.read_bytes(o, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn write_bytes(&mut self, o: usize, b: &[u8]) -> Result<(), Error> {
        let target = self
            .bytes
            .get_mut(o..o.checked_add(b.len()).ok_or(Error::Memory)?)
            .ok_or(Error::Memory)?;
        target.copy_from_slice(b);
        Ok(())
    }
    fn read_bytes(&self, o: usize, b: &mut [u8]) -> Result<(), Error> {
        let n = b.len();
        b.copy_from_slice(
            self.bytes
                .get(o..o.checked_add(n).ok_or(Error::Memory)?)
                .ok_or(Error::Memory)?,
        );
        Ok(())
    }
    fn sync(&self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}
fn smoke_ae_nasr_original_port_native_ring_publication_and_retention() -> TestResult {
    use crate::rtlwifi::prepare::{Chip, Phase as RingPhase, Prepared};
    for fail in [false, true] {
        let (port, root, _, database) = registered();
        kt_assert_eq!(finish(&root), Ok(()));
        let binding = run(root.completed_binding()).unwrap();
        let b = record(&binding);
        let cap = Cap::bootstrap();
        let program = Arc::new(StationProgram::parse(binding, &b, Some([1; 32]), cap).unwrap());
        let grant = program.grant_for(&database.snapshot().unwrap()).unwrap();
        let original = run(root.claim_station_port(program.clone(), grant)).unwrap();
        kt_assert!(run(root.claim_station_port(program.clone(), grant)).is_err());
        let drops = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let mut address = 0x100000u64;
        let mut prepared = Prepared::allocate_for(Chip::Rtl8723ae, original, 4, |len| {
            let base = address;
            address += ((len + 255) & !255) as u64;
            Ok(Block {
                address: base,
                bytes: vec![0; len],
                drops: drops.clone(),
            })
        })
        .unwrap();
        prepared
            .adopt_rtl8723ae(Box::new(
                super::super::super::super::station_owner::State::new(program.clone(), grant),
            ))
            .unwrap();
        if fail {
            port.port.0.lock().fail_write = Some(0x310);
        }
        let at = port.port.writes().len();
        let storage = narf_lib::mutex::Mutex::new(None);
        let result = run(crate::rtlwifi::prepare::retain_and_prepare(
            &storage, prepared,
        ));
        kt_assert_eq!(result.is_ok(), !fail);
        let saved = run(storage.lock());
        kt_assert_eq!(
            saved.as_ref().unwrap().phase(),
            if fail {
                RingPhase::Failed
            } else {
                RingPhase::Prepared
            }
        );
        kt_assert!(saved.as_ref().unwrap().station_grant().is_none());
        drop(saved);
        let writes = port.port.writes();
        kt_assert!(writes[at..].iter().any(|(_, r, _)| *r == 0x308));
        kt_assert!(!writes[at..].iter().any(|(_, r, _)| *r == 0x1e0));
        if !fail {
            kt_assert!(!writes[at..]
                .iter()
                .any(|(_, r, _)| matches!(*r, 0x100 | 0x3a8 | 0x3ac)));
        } else {
            // Actual scalar failure retires admission and attempts only
            // restrictive current-PCI close, with all DMA still retained.
            kt_assert!(writes[at..].iter().any(|(_, r, v)| *r == 0x3a8 && *v == 0));
            kt_assert!(!root.registered_for(root.firmware()));
        }
        kt_assert_eq!(port.port.0.lock().regs[0x100] & 0xcf, 0);
        if !fail {
            kt_assert_eq!(port.port.reg32(0x340) & 0xff, 0);
        }
        let count = port.port.writes().len();
        cap.revoke();
        // All DMA resources and original context stay retained even after
        // the policy revokes; no retry or generic fallback owner is minted.
        kt_assert!(run(root.claim_station_port(program.clone(), grant)).is_err());
        kt_assert_eq!(port.port.writes().len(), count);
        drop(storage);
        kt_assert_eq!(drops.load(core::sync::atomic::Ordering::Relaxed), 0);
        kt_assert!(root.cold.bound().is_ok());
    }
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_nasr_original_port_native_ring_publication_and_retention}

/// Inject retirement INSIDE an already admitted scalar callback. The old
/// effect remains serialized; closing commands must follow it, and no later
/// scalar may re-enable CR. This is an inert original-PCI actor, no ACK or
/// reset/DMA-idle receipt and no fabricated native live-admission commit.
fn smoke_ae_nasr_scalar_retirement_closes_last_and_outer_scope_reenters() -> TestResult {
    for revoke_pci in [false, true] {
        let (port, root, _, database) = registered();
        kt_assert_eq!(finish(&root), Ok(()));
        let binding = run(root.completed_binding()).unwrap();
        let bytes = record(&binding);
        let cap = Cap::bootstrap();
        let program = Arc::new(StationProgram::parse(binding, &bytes, Some([1; 32]), cap).unwrap());
        let grant = program.grant_for(&database.snapshot().unwrap()).unwrap();
        let original = run(root.claim_station_port(program, grant)).unwrap();
        // Outer descriptor/poll authority is reentrant: its scalar child
        // takes the narrow effect gate exactly once, never recursively.
        kt_assert_eq!(original.with_io(|_| original.write8(0x522, 0xff)), Ok(()));
        kt_assert_eq!(
            original.with_effect_io(|raw| {
                kt_assert_internal_effect_gate(&root);
                // This original callback was admitted before retirement; model
                // the enable completing after the retirement atomic store.
                root.retire();
                raw.master
                    .store(true, core::sync::atomic::Ordering::Release);
                raw.port.0.lock().events.push(Event::Master(true));
                raw.write16(0x100, 0x02ff)
            }),
            Ok(())
        );
        let before = port.port.writes().len();
        if revoke_pci {
            port.cap.revoke();
        }
        let closed = root.terminal_park();
        kt_assert_eq!(closed.is_ok(), !revoke_pci);
        let after = port.port.writes();
        if revoke_pci {
            kt_assert_eq!(after.len(), before);
            kt_assert!(port.master.load(core::sync::atomic::Ordering::Acquire));
        } else {
            kt_assert_eq!(
                &after[before..],
                &[
                    (4, 0x3a8, 0),
                    (4, 0x3ac, 0),
                    (1, 0x522, 0xff),
                    (1, 0x100, 0x30)
                ]
            );
            kt_assert!(!port.master.load(core::sync::atomic::Ordering::Acquire));
            kt_assert_eq!(
                port.port.0.lock().events.last(),
                Some(&Event::Master(false))
            );
        }
        // No source-validity check performed before waiting on the effect
        // gate can be reused to write after the actual closing command.
        let count = after.len();
        kt_assert!(original.write16(0x100, 0x02ff).is_err());
        kt_assert_eq!(port.port.writes().len(), count);
        kt_assert!(root.cold.bound().is_ok());
        kt_assert!(!root.registered_for(root.firmware()));
    }
    TestResult::Pass
}
fn kt_assert_internal_effect_gate(root: &Retained<CheckedPort>) {
    assert!(
        root.effect_gate.try_lock().is_none(),
        "actual scalar did not own terminal-park gate"
    );
}

/// A dead station source cannot perform ordinary I/O. Its current original
/// PCI alone may still close gates. A dead PCI source cannot clean them.
fn smoke_ae_nasr_source_loss_uses_current_pci_only_for_restrictive_close() -> TestResult {
    for revoke_pci in [false, true] {
        let (port, root, _, database) = registered();
        kt_assert_eq!(finish(&root), Ok(()));
        let binding = run(root.completed_binding()).unwrap();
        let bytes = record(&binding);
        let cap = Cap::bootstrap();
        let program = Arc::new(StationProgram::parse(binding, &bytes, Some([1; 32]), cap).unwrap());
        let grant = program.grant_for(&database.snapshot().unwrap()).unwrap();
        let original = run(root.claim_station_port(program, grant)).unwrap();
        // Independent inert current PCI hardware observation (CR02ff),
        // without publishing a native readiness or reset/idle receipt.
        port.port.set8(0x100, 0xff);
        port.port.set8(0x101, 2);
        let before = port.port.writes().len();
        cap.revoke();
        if revoke_pci {
            port.cap.revoke();
        }
        kt_assert!(original.read8(0x100).is_err());
        let writes = port.port.writes();
        if revoke_pci {
            kt_assert_eq!(writes.len(), before);
        } else {
            kt_assert_eq!(
                &writes[before..],
                &[
                    (4, 0x3a8, 0),
                    (4, 0x3ac, 0),
                    (1, 0x522, 0xff),
                    (1, 0x100, 0x30)
                ]
            );
        }
        kt_assert!(!root.registered_for(root.firmware()));
        kt_assert!(root.cold.bound().is_ok());
    }
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_nasr_scalar_retirement_closes_last_and_outer_scope_reenters}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_nasr_source_loss_uses_current_pci_only_for_restrictive_close}

// This original-port actor deliberately has no packet-enable, doorbell or
// fabricated active-PCI receipt. It exercises only actual retained closed-ring
// -> AE MAC/coex setup and its incomplete-live/cancellation refusal boundary.
impl crate::rtlwifi::prepare::packet::Port for PacketIo<CheckedPort> {
    type Buffer = Block;
    fn authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        if active {
            return Err(Error::State);
        }
        self.with_io(|_| Ok(operation()))?
    }
    fn allocate_packet(&self, _bytes: usize) -> Result<Block, Error> {
        Err(Error::State)
    }
    fn master(&self, _enabled: bool) -> Result<(), Error> {
        Err(Error::State)
    }
    fn kick(&self, _queue: u16) -> Result<(), Error> {
        Err(Error::State)
    }
}
fn smoke_ae_original_coex_moves_into_retained_mac_prefix_without_live_grant() -> TestResult {
    use crate::rtlwifi::prepare::{Chip, Phase as Hardware, Prepared};
    for cancel in [false, true] {
        let (port, root, _, database) = registered();
        kt_assert_eq!(finish(&root), Ok(()));
        let binding = run(root.completed_binding()).unwrap();
        let bytes = record(&binding);
        let cap = Cap::bootstrap();
        let program =
            Arc::new(StationProgram::parse(binding.clone(), &bytes, Some([1; 32]), cap).unwrap());
        let grant = program.grant_for(&database.snapshot().unwrap()).unwrap();
        let original = run(root.claim_station_port(program.clone(), grant)).unwrap();
        let drops = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let mut address = 0x100000u64;
        let mut prepared = Prepared::allocate_for(Chip::Rtl8723ae, original, 4, |len| {
            let base = address;
            address += ((len + 255) & !255) as u64;
            Ok(Block {
                address: base,
                bytes: vec![0; len],
                drops: drops.clone(),
            })
        })
        .unwrap();
        prepared
            .adopt_rtl8723ae(Box::new(
                super::super::super::super::station_owner::State::new(program.clone(), grant),
            ))
            .unwrap();
        let storage = narf_lib::mutex::Mutex::new(None);
        kt_assert_eq!(
            run(crate::rtlwifi::prepare::retain_and_prepare(
                &storage, prepared
            )),
            Ok(())
        );
        let at = port.port.writes().len();
        let mut saved = run(storage.lock());
        let owner = saved.as_mut().unwrap();
        kt_assert!(owner.ae_fixture_coex().is_none());
        if cancel {
            // First actual source RF read is still pending. The original
            // Box is already in the retained Prepared before that await.
            port.port.0.lock().pause_delay = Some(120);
            {
                let mut future = Box::pin(program.wait(grant, owner.configure_rtl8723ae_station()));
                kt_assert!(future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
            kt_assert_eq!(owner.phase(), Hardware::Failed);
            let facts = owner.ae_fixture_coex().unwrap();
            kt_assert!(!facts.1);
            let count = port.port.writes().len();
            kt_assert!(run(owner.configure_rtl8723ae_station()).is_err());
            kt_assert_eq!(port.port.writes().len(), count);
        } else {
            kt_assert_eq!(
                run(program.wait(grant, owner.configure_rtl8723ae_station())),
                Ok(())
            );
            kt_assert_eq!(owner.phase(), Hardware::MacConfigured);
            let facts = owner.ae_fixture_coex().unwrap();
            kt_assert!(facts.1 && facts.2.is_some() && facts.3.is_some());
            kt_assert_eq!(
                owner.stage_rtl8723ae_station_program(
                    program.clone(),
                    &database.snapshot().unwrap()
                ),
                Ok(())
            );
        }
        // Local helper completion is not the retained native activation
        // receipt. Neither the actor nor an independent Box may mint it.
        kt_assert!(owner.station_grant().is_none());
        let mut duplicate = None;
        kt_assert!(run(binding.transfer_coex(&mut duplicate)).is_err());
        kt_assert!(duplicate.is_none());
        let writes = port.port.writes();
        kt_assert!(!writes[at..]
            .iter()
            .any(|(_, r, _)| matches!(*r, 0x100 | 0x3a8 | 0x3ac | 0x300)));
        if !cancel {
            let tail = &writes[at..];
            let counter = tail.iter().position(|e| *e == (1, 0x76e, 4)).unwrap();
            let pta = tail.iter().position(|e| *e == (1, 0x40, 0x20)).unwrap();
            let msr = tail.iter().position(|e| e.1 == 0x102).unwrap();
            kt_assert!(counter < pta && pta < msr);
        }
        drop(saved);
        drop(storage);
        kt_assert_eq!(drops.load(core::sync::atomic::Ordering::Relaxed), 0);
        kt_assert!(root.cold.bound().is_ok());
    }
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_original_coex_moves_into_retained_mac_prefix_without_live_grant}
