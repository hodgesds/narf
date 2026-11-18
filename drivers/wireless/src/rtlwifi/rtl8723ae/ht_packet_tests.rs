// SPDX-License-Identifier: GPL-2.0-or-later
//! Original cold/firmware/PG/calibration RAM actor plus the actual generic
//! native packet owner. Signed measurements and peer metadata are synthetic;
//! no physical PCI activation or over-air association/ACK is claimed.
use super::*;
use crate::rtlwifi::prepare::{packet, Chip, Prepared};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct PacketPort {
    raw: CheckedPort,
    program: Arc<StationProgram>,
    next: AtomicU64,
    drops: Arc<AtomicUsize>,
    kicks: AtomicUsize,
}
impl PacketPort {
    fn effect<T>(
        &self,
        f: impl FnOnce(&CheckedPort) -> Result<T, AccessError>,
    ) -> Result<T, AccessError> {
        self.program
            .with_current(|| f(&self.raw).map_err(Error::Access))
            .map_err(|_| AccessError::Gate)
    }
    fn allocate(&self, len: usize) -> Block {
        Block {
            address: self
                .next
                .fetch_add(((len + 255) & !255) as u64, Ordering::SeqCst),
            bytes: vec![0; len],
            drops: self.drops.clone(),
        }
    }
}
#[async_trait::async_trait]
impl Io for PacketPort {
    fn read8(&self, r: u16) -> Result<u8, AccessError> {
        self.effect(|io| io.read8(r))
    }
    fn read16(&self, r: u16) -> Result<u16, AccessError> {
        self.effect(|io| io.read16(r))
    }
    fn read32(&self, r: u16) -> Result<u32, AccessError> {
        self.effect(|io| io.read32(r))
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), AccessError> {
        self.effect(|io| io.write8(r, v))
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), AccessError> {
        self.effect(|io| io.write16(r, v))
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), AccessError> {
        self.effect(|io| io.write32(r, v))
    }
    fn write_bytes(&self, r: u16, bytes: &[u8]) -> Result<(), AccessError> {
        self.effect(|io| io.write_bytes(r, bytes))
    }
    async fn delay_us(&self, us: u64) {
        self.raw.delay_us(us).await;
    }
}
impl packet::Port for PacketPort {
    type Buffer = Block;
    fn authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.program.with_current(|| {
            if self.raw.master.load(Ordering::Acquire) != active {
                return Err(Error::State);
            }
            operation()
        })
    }
    fn allocate_packet(&self, bytes: usize) -> Result<Block, Error> {
        self.program.with_current(|| Ok(self.allocate(bytes)))
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.program.with_current(|| {
            self.raw
                .current(|raw| {
                    raw.master.store(enabled, Ordering::Release);
                    Ok(())
                })
                .map_err(Error::Access)
        })
    }
    fn kick(&self, _queue: u16) -> Result<(), Error> {
        self.program.with_current(|| {
            self.raw
                .current(|_| {
                    self.kicks.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .map_err(Error::Access)
        })
    }
}
type PacketFixture = (
    Box<Prepared<PacketPort, Block>>,
    Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    CheckedPort,
);
fn fixture(ht: bool) -> Result<PacketFixture, &'static str> {
    let (raw, root, _, database) = registered();
    if finish(&root).is_err() {
        return Err("AE complete original preparation");
    }
    let binding = run(root.completed_binding()).map_err(|_| "AE original binding")?;
    let bytes = if ht {
        ht_record(&binding)
    } else {
        record(&binding)
    };
    let cap = Cap::bootstrap();
    let program = Arc::new(
        StationProgram::parse(binding, &bytes, Some([1; 32]), cap)
            .map_err(|_| "AE actual NASR parser")?,
    );
    let grant = program
        .grant_for(&database.snapshot().unwrap())
        .map_err(|_| "AE joint permission")?;
    let port = PacketPort {
        raw: raw.clone(),
        program: program.clone(),
        next: AtomicU64::new(0x100000),
        drops: Arc::new(AtomicUsize::new(0)),
        kicks: AtomicUsize::new(0),
    };
    let mut owner = Box::new(
        Prepared::allocate_for(Chip::Rtl8723ae, port, 4, |bytes| {
            // Separate fixed inert extents for original rings and RX buffers.
            static NEXT: AtomicU64 = AtomicU64::new(0x10000000);
            Ok(Block {
                address: NEXT.fetch_add(((bytes + 255) & !255) as u64, Ordering::SeqCst),
                bytes: vec![0; bytes],
                drops: Arc::new(AtomicUsize::new(0)),
            })
        })
        .map_err(|_| "AE owned rings")?,
    );
    owner
        .adopt_rtl8723ae(Box::new(
            super::super::super::super::super::station_owner::State::new(program.clone(), grant),
        ))
        .map_err(|_| "AE original program adoption")?;
    run(program.wait(grant, owner.prepare())).map_err(|_| "AE native closed ring preparation")?;
    run(program.wait(grant, owner.configure_rtl8723ae_station()))
        .map_err(|_| "AE original coex transfer/native MAC")?;
    owner
        .start_packets()
        .map_err(|_| "AE actual native packet opening")?;
    Ok((owner, cap, raw))
}
const PEER: [u8; 6] = [2, 0x10, 0x20, 0x30, 0x40, 0x50];
fn smoke_ae_nasr2_native_negotiated_rx_ampdu_bar_and_long_bounds() -> TestResult {
    let (mut owner, _, _) = match fixture(true) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let own = owner.local().unwrap();
    let mut frame = vec![0; 30];
    frame[0] = 0x88;
    frame[4..10].copy_from_slice(&own);
    frame[10..16].copy_from_slice(&PEER);
    frame[16..22].copy_from_slice(&PEER);
    let no_peer = owner
        .ae_fixture_rx_slot(&frame, 1 << 14, 12 | 1 << 6)
        .unwrap();
    kt_assert!(no_peer.consumed && no_peer.packet.is_none());
    kt_assert_eq!(owner.ae_fixture_negotiated_ht(PEER, true), Ok(()));
    let received = owner
        .ae_fixture_rx_slot(&frame, 1 << 14, 12 | 1 << 6)
        .unwrap();
    kt_assert!(received
        .packet
        .as_ref()
        .is_some_and(|f| f.bytes() == &frame[..26]));
    let mut bar = [0; 24];
    bar[0] = 0x84;
    bar[4..10].copy_from_slice(&own);
    bar[10..16].copy_from_slice(&PEER);
    bar[16] = 4;
    kt_assert!(owner
        .ae_fixture_rx_slot(&bar, 0, 4)
        .unwrap()
        .packet
        .is_some());
    bar[10] ^= 2;
    kt_assert!(owner
        .ae_fixture_rx_slot(&bar, 0, 4)
        .unwrap()
        .packet
        .is_none());
    for len in [20usize, 21, 22, 23, 25, 26, 27] {
        let bytes = vec![0; len];
        kt_assert!(owner
            .ae_fixture_rx_slot(&bytes, 0, 4)
            .unwrap()
            .packet
            .is_none());
    }
    frame[24] = 0x80; // QoS A-MSDU present: maximum3839-byte receive promise.
    frame.resize(super::super::super::super::super::ht::LONGEST_RX, 0);
    kt_assert!(owner
        .ae_fixture_rx_slot(&frame, 0, 12 | 1 << 6)
        .unwrap()
        .packet
        .is_some());
    frame.push(0);
    kt_assert!(owner
        .ae_fixture_rx_slot(&frame, 0, 12 | 1 << 6)
        .unwrap()
        .packet
        .is_none());
    TestResult::Pass
}
fn smoke_ae_nasr2_native_single_mpdu_sgi_and_current_cap_refusal() -> TestResult {
    for ht in [false, true] {
        let (mut owner, cap, _) = match fixture(ht) {
            Ok(v) => v,
            Err(e) => return TestResult::Fail(e),
        };
        let own = owner.local().unwrap();
        let mut frame = vec![0x88, 1, 0, 0];
        frame.extend_from_slice(&PEER);
        frame.extend_from_slice(&own);
        frame.extend_from_slice(&PEER);
        frame.extend_from_slice(&[0; 14]);
        kt_assert_eq!(owner.ae_fixture_negotiated_ht(PEER, true).is_ok(), ht);
        if !ht {
            kt_assert!(owner.submit(&frame, 12).is_err());
            continue;
        }
        // No operational sender BA is installed or inferred from a host DD.
        kt_assert!(owner
            .submit_aggregate(&frame, 12, Some((7, true)), false, false)
            .is_err());
        kt_assert!(owner
            .submit_aggregate(&frame, 19, None, false, true)
            .is_ok());
        let words = owner.ae_fixture_pending_words().unwrap();
        kt_assert_eq!(words[5] & 127, 19 | 1 << 6);
        kt_assert_eq!(words[1] & (1 << 5), 0);
        cap.revoke();
        let mut inbound = vec![0; 28];
        inbound[0] = 0x80;
        kt_assert!(owner.ae_fixture_rx_slot(&inbound, 0, 4).is_err());
    }
    TestResult::Pass
}
fn smoke_ae_nasr2_native_n24_mask_uses_original_mailbox_and_capability() -> TestResult {
    use crate::rtlwifi::rtl8723ae::h2c;
    let peer = h2c::Peer {
        mode: h2c::WirelessMode::N24,
        supp_rates: 0xfff,
        rx_mask: [255, 0],
        sgi20: true,
        sgi40: false,
    };
    for ht in [false, true] {
        let (mut owner, cap, raw) = match fixture(ht) {
            Ok(v) => v,
            Err(e) => return TestResult::Fail(e),
        };
        let _ = owner.ae_fixture_negotiated_ht(PEER, true);
        for (level, lower) in [(1, [0, 0]), (2, [0, 0xf0]), (3, [5, 0xf0])] {
            let before = raw.port.writes().len();
            let result = run(owner.install_rtl8723ae_rate_mask(peer, level));
            let writes = raw.port.writes();
            if !ht {
                kt_assert!(result.is_err());
                kt_assert_eq!(writes.len(), before);
                continue;
            }
            kt_assert_eq!(result, Ok(()));
            let tail = &writes[before..];
            kt_assert_eq!(tail.len(), 6);
            // Linux hw.c1974..2008 N24 1T1R HIGH/MIDDLE/LOW masks and
            // fw.c EXT-before-MAIN writes. No independent test mailbox.
            let ext = tail[0].1;
            kt_assert!(matches!(ext, 0x88 | 0x8a | 0x8c | 0x8e));
            let main = 0x1d0 + (ext - 0x88) * 2;
            kt_assert_eq!(
                tail,
                &[
                    (1, ext, lower[0]),
                    (1, ext + 1, lower[1]),
                    (1, main, 0x86),
                    (1, main + 1, 0x0f),
                    (1, main + 2, 0),
                    (1, main + 3, 0xa0),
                ]
            );
        }
        if ht {
            let before = raw.port.writes().len();
            cap.revoke();
            kt_assert!(run(owner.install_rtl8723ae_rate_mask(peer, 1)).is_err());
            kt_assert_eq!(raw.port.writes().len(), before);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_ae_nasr2_native_negotiated_rx_ampdu_bar_and_long_bounds
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_ae_nasr2_native_single_mpdu_sgi_and_current_cap_refusal
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_ae_nasr2_native_n24_mask_uses_original_mailbox_and_capability
);
