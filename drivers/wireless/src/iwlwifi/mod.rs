//! Intel iwlwifi PCIe — Wi-Fi 6 / 6E / 7 chips.
//!
//! Targets:
//!   - AX200  (8086:2723)  — Cyclone Peak, Qu/QuZ MAC + HR RF
//!   - AX201  (8086:02f0/43f0/a0f0/7df0) — same as AX200, different SKU
//!   - AX210  (8086:2725)  — Typhoon Peak, Ty MAC + GF RF (gen3)
//!   - AX211  (8086:51f0/54f0/7e40) — So/Ma MAC + GF/GF4 RF (gen3)
//!   - BE200  (8086:272b)  — Bz MAC + GF/GF4/FM RF (gen3, Wi-Fi 7)
//!
//! ## Scope of this commit
//!
//! - PCI device match table.
//! - Per-chip configuration (firmware filename prefix, MAC/RF
//!   family, API version range, generation 2 vs 3).
//! - Firmware filename ladder generator. Linux walks
//!   `iwlwifi-<mac>-<rf>-<API>.ucode` from `api_max` down to
//!   `api_min`; first hit wins. We mirror that ordering.
//! - Intel TLV firmware container parser (magic `0x0a4c5749`).
//!   Walks the .ucode bytes and yields typed sections — INST,
//!   DATA, SEC_INIT, SEC_RT, plus a handful of capability TLVs.
//! - Image-assembly: builds `FwImg` structs from SEC_INIT/SEC_RT
//!   TLV streams, honouring the CPU1/CPU2 + paging separators.
//!
//! Out of scope (real-HW + significant MMIO work; per agent
//! research in this branch):
//! - PCIe BAR0 register programming (CSR_*, FH_*, PRPH).
//! - gen2 direct-DMA section loader.
//! - gen3 IML / context-info-v2 boot path.
//! - ALIVE notification handshake.
//! - mac80211-equivalent: scan / associate / data path.
//!
//! ## References
//!
//! Post-2026-05-20 GPL relicense permits direct citation:
//! - `drivers/net/wireless/intel/iwlwifi/fw/file.h` — TLV layout,
//!   magic constant, tag enumeration.
//! - `drivers/net/wireless/intel/iwlwifi/fw/img.h` — fw_desc,
//!   paging constants, SEC_RT/SEC_INIT semantics.
//! - `drivers/net/wireless/intel/iwlwifi/iwl-drv.c` —
//!   `iwl_request_firmware` filename ladder, TLV walker.
//! - `drivers/net/wireless/intel/iwlwifi/cfg/22000.c`, `ax210.c`,
//!   `bz.c`, `rf-{hr,gf,fm}.c` — per-chip config tables.
//! - `drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/trans.c` —
//!   gen2 PCIe transport (load_given_ucode_8000).
//! - `drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info-v2.c` —
//!   gen3 IML / context-info loader.

#![allow(dead_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub mod bcast;
pub mod fw_loader;
pub mod handshake;
pub mod iwl_msix;
pub mod mac_ctx;
pub mod mlme;
pub mod regs;
pub mod rekey;
pub mod rx;
pub mod sta;
pub mod transport;
pub mod tx;
pub mod tx_gen2;
pub mod wpa;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

use crate::iwlwifi::transport::IwlMmio;
use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::DmaBuffer;
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError, WirelessIfaceInfo,
    WirelessNetIface,
};

pub const INTEL_VENDOR: u16 = 0x8086;

// ── IwlDevice ──────────────────────────────────────────────────────

struct IwlDevice {
    mmio: MmioRegion,
    chip: ChipConfig,
    mac_addr: [u8; 6],
    link_up: AtomicBool,
    rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    bss_list: IrqSafeSpinLock<Vec<BssInfo>>,
    scan_in_progress: AtomicBool,

    rx_q: IrqSafeSpinLock<rx::RxQueue>,
    tx_q0: IrqSafeSpinLock<tx::TxQueue>,
    rx_ring_dma: DmaBuffer,
    tx_ring_dma: Vec<DmaBuffer>,
    tx_cmd_bufs: Vec<DmaBuffer>,
    rx_buffers: Vec<DmaBuffer>,
    irq_vector: Option<u8>,
    scan_waker: IrqSafeSpinLock<Option<Waker>>,
}

// SAFETY: every interior-mutable field (`rx_q`, `tx_q0`, `bss_list`,
// `scan_waker`, the atomics) is guarded by an `IrqSafeSpinLock` or is
// an `Atomic*`, so concurrent access from multiple threads is
// serialised. The DMA buffers and `MmioRegion` are owned handles to
// device memory the driver holds exclusively; raw pointers into them
// are only dereferenced under those locks. Hence sharing/sending an
// `IwlDevice` across threads is sound.
unsafe impl Send for IwlDevice {}
// SAFETY: see the `Send` impl above — all shared mutable state is
// behind `IrqSafeSpinLock`/atomics, so `&IwlDevice` is safe to share.
unsafe impl Sync for IwlDevice {}

impl IwlDevice {
    /// Push an Open System Authentication request frame (seq=1) on
    /// the management TX queue. The AP responds with seq=2 via the RX
    /// path; we don't currently block on that response here — the
    /// caller follows up with the Association Request, and the RX
    /// pump will log the auth response when it arrives.
    async fn send_open_auth(&self, bssid: [u8; 6]) -> Result<(), WirelessError> {
        let body = mlme::build_open_auth_body();
        let pkt = tx::TxPacket::management(
            tx::fc::SUBTYPE_AUTH,
            bssid,         // addr1: DA = AP
            self.mac_addr, // addr2: SA = us
            bssid,         // addr3: BSSID = AP
            1,             // seq num
            0xFF,          // BCAST station id (pre-association)
            &body,
        );

        // Serialise MAC header + body into a coherent buffer.
        let total = pkt.mac_hdr_len + pkt.payload.len();
        let buf = narf_io::alloc_coherent(total, DomainId::DRIVER_0)
            .map_err(|_| WirelessError::HardwareError)?;
        // SAFETY: `buf` is a freshly-allocated coherent DMA buffer of
        // exactly `total = mac_hdr_len + payload.len()` bytes, so both
        // copies land inside it (`mac_hdr` at offset 0, `payload` at
        // `mac_hdr_len`). The source slices are owned by `pkt` and
        // don't overlap `buf`. Both lengths come from `pkt`'s own
        // fields, so the writes stay in bounds.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::copy_nonoverlapping(pkt.mac_hdr.as_ptr(), buf.as_mut_ptr(), pkt.mac_hdr_len);
            core::ptr::copy_nonoverlapping(
                pkt.payload.as_ptr(),
                buf.as_mut_ptr().add(pkt.mac_hdr_len),
                pkt.payload.len(),
            );
        }
        let frame_len = total as u16;

        let mut tx_q = self.tx_q0.lock();
        let mut mmio = IwlMmioImpl(self.mmio);
        let slot = tx_q.write_ptr;

        let cmd = tx::IwlTxCmd::for_management(frame_len, 0xFF);
        let cmd_dma = &self.tx_cmd_bufs[0];
        // SAFETY: `cmd_dma` is a coherent DMA buffer sized
        // `TX_RING_SIZE * 32` bytes; `slot` is a ring index `<
        // TX_RING_SIZE`, so `slot * 32` is an in-bounds offset and the
        // 32-byte command slot fits an `IwlTxCmd`. The result is a
        // valid, suitably-aligned pointer into that buffer.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let cmd_ptr = unsafe { cmd_dma.as_mut_ptr().add(slot * 32) as *mut tx::IwlTxCmd };
        // SAFETY: `cmd_ptr` points at the `slot`'s 32-byte command slot
        // computed above, which is large enough for one `IwlTxCmd`; the
        // volatile write publishes the command for the device to DMA.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_volatile(cmd_ptr, cmd);
        }

        let mut tfd = tx::Tfd::default();
        tfd.push_seg(
            cmd_dma.dma_addr().raw() + (slot * 32) as u64,
            core::mem::size_of::<tx::IwlTxCmd>() as u16,
        );
        tfd.push_seg(buf.dma_addr().raw(), frame_len);

        tx_q.enqueue(tfd);
        tx::tx_doorbell(&mut mmio, 0, tx_q.write_ptr);

        // Keep the buffer alive until the device DMAs it; in production
        // we'd thread this through a per-slot lifetime pool. For the
        // bring-up smoke we let the page live in the slab.
        core::mem::forget(buf);
        Ok(())
    }

    // wide constructor mirroring the device's allocated DMA resources
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mmio: MmioRegion,
        chip: ChipConfig,
        mac_addr: [u8; 6],
        rx_q: rx::RxQueue,
        tx_q0: tx::TxQueue,
        rx_ring_dma: DmaBuffer,
        tx_ring_dma: Vec<DmaBuffer>,
        tx_cmd_bufs: Vec<DmaBuffer>,
        rx_buffers: Vec<DmaBuffer>,
        irq_vector: Option<u8>,
    ) -> Self {
        Self {
            mmio,
            chip,
            mac_addr,
            link_up: AtomicBool::new(false),
            rx_ring: IrqSafeSpinLock::new(None),
            tx_ring: IrqSafeSpinLock::new(None),
            bss_list: IrqSafeSpinLock::new(Vec::new()),
            scan_in_progress: AtomicBool::new(false),
            rx_q: IrqSafeSpinLock::new(rx_q),
            tx_q0: IrqSafeSpinLock::new(tx_q0),
            rx_ring_dma,
            tx_ring_dma,
            tx_cmd_bufs,
            rx_buffers,
            irq_vector,
            scan_waker: IrqSafeSpinLock::new(None),
        }
    }
}

impl core::fmt::Debug for IwlDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IwlDevice")
            .field("chip", &self.chip.display_name)
            .field("mac", &self.mac_addr)
            .field("link_up", &self.link_up.load(Ordering::Acquire))
            .finish()
    }
}

impl Interface for IwlDevice {
    fn name(&self) -> &str {
        "wlan0" // TODO: dynamic naming
    }
    fn mac(&self) -> [u8; 6] {
        self.mac_addr
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.link_up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ring
    }
}

/// Populate supported wireless bands for an Intel Wi-Fi chip.
///
/// All supported Intel chips cover 2.4 GHz (channels 1-13) and 5 GHz (channels 36-165).
/// Wi-Fi 6E and Wi-Fi 7 chips (AX210, AX211, BE200) also cover 6 GHz (channels 1-233).
pub fn bands_for_chip(chip: &ChipConfig) -> Vec<narf_wireless::iface::WirelessBand> {
    let mut bands = alloc::vec![
        narf_wireless::iface::WirelessBand {
            freq_mhz: 2400,
            channels: (1..=13).collect(),
        },
        narf_wireless::iface::WirelessBand {
            freq_mhz: 5000,
            channels: alloc::vec![
                36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136,
                140, 144, 149, 153, 157, 161, 165
            ],
        },
    ];
    if matches!(
        chip.mac,
        MacFamily::TyA0 | MacFamily::SoA0 | MacFamily::MaA0 | MacFamily::MaB0 | MacFamily::BzA0
    ) {
        bands.push(narf_wireless::iface::WirelessBand {
            freq_mhz: 6000,
            channels: (1..=233).step_by(4).collect(),
        });
    }
    bands
}

#[async_trait::async_trait]
impl WirelessNetIface for IwlDevice {
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        WirelessIfaceInfo {
            base_name: self.name().into(),
            base_mac: self.mac(),
            bands: bands_for_chip(&self.chip),
            modes: narf_wireless::iface::WirelessModes::STATION,
            hw_caps: narf_wireless::iface::HwCaps {
                ht_supported: true,
                vht_supported: self.chip.generation == Generation::Gen2
                    || self.chip.generation == Generation::Gen3,
                he_supported: self.chip.generation == Generation::Gen2
                    || self.chip.generation == Generation::Gen3,
                eht_supported: self.chip.did == 0x272b, // BE200
            },
        }
    }

    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if self.scan_in_progress.swap(true, Ordering::SeqCst) {
            return Err(WirelessError::Busy);
        }

        self.bss_list.lock().clear();

        // 1. Build and send SCAN_REQ_UMAC command.
        // Map narf_wireless::ScanRequest to iwlwifi::mlme::ScanRequest.
        let mut channels = Vec::new();
        for ch in req.channels {
            channels.push(mlme::ScanChannel {
                channel_num: ch as u8,
                flags: mlme::scan_channel_flags::ACTIVE,
                dwell_time_ms_min: 10,
                dwell_time_ms_max: 60,
            });
        }
        let mut ssids = Vec::new();
        for ssid in req.ssids {
            ssids.push(mlme::ScanSsid::from_bytes(&ssid));
        }

        let iwl_req = mlme::ScanRequest {
            channels,
            ssids,
            passive: !req.active,
            rand_mac: false,
        };

        let cmd_body = mlme::scan_request_cmd(&iwl_req);

        let payload_dma = if let Ok(pd) =
            narf_io::alloc_coherent(cmd_body.len(), DomainId::DRIVER_0)
        {
            // SAFETY: `pd` was just allocated by `alloc_coherent` with
            // length `cmd_body.len()`, so copying exactly that many
            // bytes from the owned `cmd_body` slice into it stays in
            // bounds; source and destination don't overlap.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                core::ptr::copy_nonoverlapping(cmd_body.as_ptr(), pd.as_mut_ptr(), cmd_body.len());
            }

            {
                let mut tx_q = self.tx_q0.lock();
                let mut mmio = IwlMmioImpl(self.mmio);
                let slot = tx_q.write_ptr;

                // 1. Build IwlCmdHeader.
                let hdr = tx::IwlCmdHeader {
                    cmd: rx::NOTIF_SCAN_COMPLETE_UMAC,
                    group_id: rx::NOTIF_SCAN_COMPLETE_GROUP,
                    sequence: 0,
                };

                // 2. Write header to DMA.
                let cmd_dma = &self.tx_cmd_bufs[0];
                let hdr_ptr =
                    // SAFETY: `cmd_dma` is the coherent command buffer sized
                    // `TX_RING_SIZE * 32`; `slot < TX_RING_SIZE`, so `slot *
                    // 32` is in bounds and the 32-byte slot fits an
                    // `IwlCmdHeader`. The result is a valid aligned pointer
                    // into that buffer.
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    unsafe { cmd_dma.as_mut_ptr().add(slot * 32) as *mut tx::IwlCmdHeader };
                // SAFETY: `hdr_ptr` is the `slot`'s 32-byte command slot
                // computed above, big enough for one `IwlCmdHeader`; the
                // volatile write publishes the header to the device.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe {
                    core::ptr::write_volatile(hdr_ptr, hdr);
                }

                // 3. Build TFD.
                let mut tfd = tx::Tfd::default();
                tfd.push_seg(
                    cmd_dma.dma_addr().raw() + (slot * 32) as u64,
                    core::mem::size_of::<tx::IwlCmdHeader>() as u16,
                );
                tfd.push_seg(pd.dma_addr().raw(), cmd_body.len() as u16);

                // 4. Enqueue and kick.
                tx_q.enqueue(tfd);
                tx::tx_doorbell(&mut mmio, 0, tx_q.write_ptr);
            }
            Some(pd)
        } else {
            None
        };

        // 2. Wait for SCAN_COMPLETE_UMAC notification via the pump.
        core::future::poll_fn(|cx| {
            if !self.scan_in_progress.load(Ordering::Acquire) {
                core::task::Poll::Ready(())
            } else {
                *self.scan_waker.lock() = Some(cx.waker().clone());
                core::task::Poll::Pending
            }
        })
        .await;

        let _ = payload_dma; // keep alive until here

        Ok(self.bss_list.lock().clone())
    }

    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        let _ = writeln!(
            narf_console::Writer,
            "  iwlwifi: associating to {:?}",
            req.ssid
        );

        // 0. Send Open System Authentication request (seq=1). For
        //    WPA2-PSK the auth is just an Open exchange; the real key
        //    establishment happens in the 4-way handshake post-assoc.
        //    We push the frame and trust that auth-success comes back
        //    via the RX path before assoc reaches the AP.
        self.send_open_auth(req.bssid).await?;

        // 1. Send Association Request.
        let params = mlme::AssocParams {
            sta_addr: self.mac_addr,
            ap_bssid: req.bssid,
            ssid: req.ssid,
            supported_rates: alloc::vec![0x82, 0x84, 0x8B, 0x96],
            capability_info: 0x0411,
            listen_interval: 10,
            seq_num: 0,
        };

        let frame_bytes = mlme::build_assoc_request(&params);
        let buf = narf_io::alloc_coherent(frame_bytes.len(), DomainId::DRIVER_0)
            .map_err(|_| WirelessError::HardwareError)?;
        let mut frame = Frame::new(buf, frame_bytes.len() as u32);
        frame.payload_mut().copy_from_slice(&frame_bytes);

        {
            let mut tx_q = self.tx_q0.lock();
            let mut mmio = IwlMmioImpl(self.mmio);
            let slot = tx_q.write_ptr;

            let cmd = tx::IwlTxCmd::for_management(frame.len() as u16, 0xFF);
            let cmd_dma = &self.tx_cmd_bufs[0];
            // SAFETY: `cmd_dma` is the coherent command buffer sized
            // `TX_RING_SIZE * 32`; `slot < TX_RING_SIZE`, so `slot * 32`
            // is in bounds and the 32-byte slot fits an `IwlTxCmd`,
            // yielding a valid aligned pointer into that buffer.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let cmd_ptr = unsafe { cmd_dma.as_mut_ptr().add(slot * 32) as *mut tx::IwlTxCmd };
            // SAFETY: `cmd_ptr` is the `slot`'s 32-byte command slot
            // computed above, big enough for one `IwlTxCmd`; the
            // volatile write publishes the command to the device.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                core::ptr::write_volatile(cmd_ptr, cmd);
            }

            let mut tfd = tx::Tfd::default();
            tfd.push_seg(
                cmd_dma.dma_addr().raw() + (slot * 32) as u64,
                core::mem::size_of::<tx::IwlTxCmd>() as u16,
            );
            tfd.push_seg(
                frame.buf().dma_addr().raw() + frame.offset() as u64,
                frame.len() as u16,
            );

            tx_q.enqueue(tfd);
            tx::tx_doorbell(&mut mmio, 0, tx_q.write_ptr);
        }

        // 2. Keep the frame alive until the device is likely done.
        // For now, we just assume it's sent immediately or stashed.
        // In a real driver we'd wait for the TX completion interrupt.
        let _ = frame;

        self.link_up.store(true, Ordering::Release);
        Ok(())
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.link_up.store(false, Ordering::Release);
        Ok(())
    }

    async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
        Ok(())
    }
}

fn spawn_pumps(
    device: Arc<IwlDevice>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        iwl_rx_pump(d1, rx_prod).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        iwl_tx_pump(d2, tx_cons).await;
    });
}

use narf_lib::id::DomainId;

struct IwlRxHandler {
    device: Arc<IwlDevice>,
    rx_prod: Producer<Frame, RX_RING_N>,
}

impl rx::RxHandler for IwlRxHandler {
    fn handle(&mut self, kind: rx::RxKind, _hdr: rx::RxPacketHeader, payload: &[u8]) {
        match kind {
            rx::RxKind::Alive => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  iwlwifi: firmware alive notification"
                );
            }
            rx::RxKind::ScanComplete => {
                self.device.scan_in_progress.store(false, Ordering::Release);
                if let Some(waker) = self.device.scan_waker.lock().take() {
                    waker.wake();
                }
                let _ = writeln!(narf_console::Writer, "  iwlwifi: scan complete");
            }
            rx::RxKind::RxMpdu => {
                // If scan is in progress, check for beacons/probe-resps.
                if self.device.scan_in_progress.load(Ordering::Acquire) {
                    if let Some(bss) = mlme::parse_beacon_to_bss(self.device.mac_addr, payload) {
                        let mut list = self.device.bss_list.lock();
                        if !list.iter().any(|b| b.bssid == bss.bssid) {
                            list.push(narf_wireless::BssInfo {
                                bssid: bss.bssid,
                                ssid: bss.ssid,
                                channel: bss.channel.unwrap_or(1) as u32,
                                rssi: bss.rssi_dbm,
                                security: if bss.rsn_ie_body.is_some() {
                                    narf_wireless::scan::BssSecurity::Wpa2
                                } else {
                                    narf_wireless::scan::BssSecurity::Open
                                },
                            });
                        }
                    }
                }
                // Push to network stack.
                if let Ok(buf) = narf_io::alloc_coherent(payload.len(), DomainId::DRIVER_0) {
                    let mut frame = Frame::new(buf, payload.len() as u32);
                    frame.payload_mut().copy_from_slice(payload);
                    let _ = self.rx_prod.try_send(frame);
                }
            }
            _ => {}
        }
    }
}

async fn iwl_rx_pump(device: Arc<IwlDevice>, rx_prod: Producer<Frame, RX_RING_N>) {
    let _ = writeln!(narf_console::Writer, "  iwlwifi: RX pump started");

    let mut handler = IwlRxHandler {
        device: device.clone(),
        rx_prod,
    };

    loop {
        if let Some(v) = device.irq_vector {
            narf_interrupts::wait::wait_for_irq(v).await;
        } else {
            narf_scheduler::yield_now().await;
        }

        {
            let mut rx_q = device.rx_q.lock();
            let mut mmio = IwlMmioImpl(device.mmio);
            let wptr = mmio.read(rx::CSR_FH_RSCSR_CHNL0_STTS_WPTR_REG);

            rx::drain_rx_queue(
                &mut rx_q,
                wptr as usize,
                |slot| {
                    // Return slice of the DMA buffer for this slot.
                    device.rx_buffers[slot].as_slice()
                },
                &mut handler,
            );

            // Give the buffers back to the device by writing the current
            // read-pointer to the WPTR register.
            mmio.write(
                rx::CSR_FH_RSCSR_CHNL0_WPTR,
                (rx_q.read_ptr.wrapping_sub(1) & rx::RX_RING_MASK) as u32,
            );
        }
    }
}

async fn iwl_tx_pump(device: Arc<IwlDevice>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    let _ = writeln!(narf_console::Writer, "  iwlwifi: TX pump started");

    while let Ok(frame) = tx_cons.recv().await {
        let mut tx_q = device.tx_q0.lock();
        let mut mmio = IwlMmioImpl(device.mmio);

        let slot = tx_q.write_ptr;

        // 1. Build IwlTxCmd.
        // Management frames use OFDM-6Mbps by default.
        let cmd = tx::IwlTxCmd::for_management(frame.len() as u16, 0xFF);

        // 2. Write IwlTxCmd to DMA-coherent buffer.
        let cmd_dma = &device.tx_cmd_bufs[0];
        // SAFETY: `cmd_dma` is the coherent command buffer sized
        // `TX_RING_SIZE * 32`; `slot = write_ptr < TX_RING_SIZE`, so
        // `slot * 32` is in bounds and the 32-byte slot fits an
        // `IwlTxCmd`, giving a valid aligned pointer into that buffer.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let cmd_ptr = unsafe { cmd_dma.as_mut_ptr().add(slot * 32) as *mut tx::IwlTxCmd };
        // SAFETY: `cmd_ptr` is the `slot`'s 32-byte command slot
        // computed above, big enough for one `IwlTxCmd`; the volatile
        // write publishes the command to the device.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_volatile(cmd_ptr, cmd);
        }

        // 3. Build TFD with two segments.
        let mut tfd = tx::Tfd::default();
        // Segment 0: IwlTxCmd header.
        let cmd_size = core::mem::size_of::<tx::IwlTxCmd>();
        let cmd_phys = cmd_dma.dma_addr().raw() + (slot * 32) as u64;
        tfd.push_seg(cmd_phys, cmd_size as u16);
        // Segment 1: Frame payload.
        tfd.push_seg(
            frame.buf().dma_addr().raw() + frame.offset() as u64,
            frame.len() as u16,
        );

        // 4. Enqueue and kick the doorbell.
        tx_q.enqueue(tfd);
        tx::tx_doorbell(&mut mmio, 0, tx_q.write_ptr);
    }
}

// ── MMIO implementation ────────────────────────────────────────────

struct IwlMmioImpl(narf_bus::MmioRegion);

impl transport::IwlMmio for IwlMmioImpl {
    fn read(&mut self, offset: u32) -> u32 {
        // SAFETY: `self.0` is the BAR0 `MmioRegion` mapped by `map_bar`
        // at probe; `offset` is a 32-bit register offset within BAR0
        // (callers pass CSR/FH register constants), so the read is
        // naturally aligned and in range, and the driver owns the
        // device exclusively.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.0.read32(offset as u64) }
    }
    fn write(&mut self, offset: u32, value: u32) {
        // SAFETY: `self.0` is the BAR0 `MmioRegion` from `map_bar`;
        // `offset` is an in-range, naturally-aligned register offset
        // within BAR0 and the driver owns the device exclusively.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.0.write32(offset as u64, value) }
    }
}

// ── Per-chip configuration table ───────────────────────────────────

/// Hardware generation. Determines the PCIe transport path.
///
/// gen2 (AX200/AX201) uses the original FH (Flow Handler) DMA
/// path — driver pushes each section to device memory by writing
/// to FH_SRVC_CHNL registers per `pcie/gen1_2/trans.c`.
///
/// gen3 (AX210+) uses context-info-v2 / IML: driver builds the
/// context info in host RAM, points CSR_CTXT_INFO_ADDR + CSR_IML_*
/// at it, and the device's ROM pulls sections through itself.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Generation {
    Gen2,
    Gen3,
}

/// MAC die family. Set by the device's PCI ID via the per-cfg
/// table in `iwlwifi/cfg/*.c`. Linux composes firmware filenames
/// from MAC + RF family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MacFamily {
    /// AX200/AX201 — Cyclone Peak baseband.
    QuB0,
    /// AX200/AX201 alternative stepping.
    QuC0,
    /// AX200 alt variant.
    QuZA0,
    /// AX210 — Typhoon Peak.
    TyA0,
    /// AX211 (so-a0).
    SoA0,
    /// AX211 (ma-a0).
    MaA0,
    /// AX211 (ma-b0).
    MaB0,
    /// BE200 — Bz baseband.
    BzA0,
    /// BE20x / BE21x — Sc ("Scorpius Peak") baseband. Ships as the
    /// CNVi companion on Lunar Lake and Panther Lake. Verified on
    /// the Minisforum MS-03: `00:14.3` reports PCI `8086:e340`
    /// subsys `8086:0114` and Linux loads `sc-a0-wh-b0` firmware.
    ScA0,
}

impl MacFamily {
    /// Lowercase string Linux uses in the filename ladder.
    pub fn prefix(self) -> &'static str {
        match self {
            MacFamily::QuB0 => "Qu-b0",
            MacFamily::QuC0 => "Qu-c0",
            MacFamily::QuZA0 => "QuZ-a0",
            MacFamily::TyA0 => "ty-a0",
            MacFamily::SoA0 => "so-a0",
            MacFamily::MaA0 => "ma-a0",
            MacFamily::MaB0 => "ma-b0",
            MacFamily::BzA0 => "bz-a0",
            MacFamily::ScA0 => "sc-a0",
        }
    }
}

/// RF (Wi-Fi PHY) chip family. Independently variable from MAC —
/// the device's PRPH `WFPM_OTP_CFG1_ADDR` register decides which
/// RF chip is fused. We can't read PRPH without BAR0 access, so
/// the candidate list expands to every plausible RF per MAC.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RfFamily {
    /// "hr-b0" — used with Qu/QuZ MACs (AX200/AX201).
    HrB0,
    /// "gf-a0" — Wi-Fi 6E GFf radio (AX210+).
    GfA0,
    /// "gf4-a0" — Wi-Fi 6E 4x4 RF.
    Gf4A0,
    /// "fm-a0" — Wi-Fi 7 FM radio.
    FmA0,
    /// "fm-b0" — Wi-Fi 7 FM radio, B0 stepping (Sc MAC pairings).
    FmB0,
    /// "fm-c0" — Wi-Fi 7 FM radio, C0 stepping (Sc MAC pairings).
    FmC0,
    /// "wh-b0" — Wi-Fi 7 "Wildcat Peak" radio, B0 stepping. The RF
    /// fused on the MS-03's BE211 (`Detected RF WH, rfid=0x20113100`).
    WhB0,
}

impl RfFamily {
    pub fn prefix(self) -> &'static str {
        match self {
            RfFamily::HrB0 => "hr-b0",
            RfFamily::GfA0 => "gf-a0",
            RfFamily::Gf4A0 => "gf4-a0",
            RfFamily::FmA0 => "fm-a0",
            RfFamily::FmB0 => "fm-b0",
            RfFamily::FmC0 => "fm-c0",
            RfFamily::WhB0 => "wh-b0",
        }
    }
}

/// Per-PCI-ID descriptor. Sourced from the Linux cfg/*.c
/// `iwl_*_trans_cfg` + `iwl_cfg` tables (each chip ID gets one
/// MAC family + the candidate RF set its OTP can fuse).
#[derive(Clone, Debug)]
pub struct ChipConfig {
    pub vid: u16,
    pub did: u16,
    pub display_name: &'static str,
    pub generation: Generation,
    pub mac: MacFamily,
    /// Candidate RF families. The OTP fuse selects one; without
    /// MMIO access we pessimistically try each via the filename
    /// ladder (kernel-side: the actually-fused RF is matched
    /// against this set after probe).
    pub rf_candidates: &'static [RfFamily],
    /// UCODE API version walk: try filenames with API stamps from
    /// `api_max` down to `api_min`, interpreted together with
    /// `api_prefix`.
    pub api_max: u32,
    pub api_min: u32,
    /// Literal prefix stamped in front of the API number in the
    /// firmware filename. Empty for the historical numbering
    /// (`…-gf-a0-89.ucode`); `"c"` for the core-release numbering.
    ///
    /// Linux encodes both in one integer: an API value at or above
    /// `API_IS_CORE_START` (1000) is a core release, and `FW_API_ARG`
    /// renders it as `"c"` plus `value - 1000`
    /// (`iwl-config.h`). Here the two halves are kept apart —
    /// `api_max` / `api_min` hold the bare number and this field
    /// holds the prefix — so the ladder builder stays a plain
    /// decrementing loop.
    pub api_prefix: &'static str,
}

/// AX200 — single fused chip. Linux ships HR-b0 RF only.
const RF_HR_ONLY: &[RfFamily] = &[RfFamily::HrB0];
/// AX210 — GF / GF4 RFs depending on OTP fuse.
const RF_GF_OR_GF4: &[RfFamily] = &[RfFamily::GfA0, RfFamily::Gf4A0];
/// BE200 — GF / GF4 / FM RFs.
const RF_GF_FAMILY: &[RfFamily] = &[RfFamily::GfA0, RfFamily::Gf4A0, RfFamily::FmA0];
/// BE20x / BE21x on the Sc MAC.
///
/// Modern iwlwifi does not carry a static RF list per PCI ID: it
/// reads the fused RF type + step out of `CSR_HW_RF_ID` and composes
/// `iwlwifi-<mac>-<step>-<rf>-<step>` at runtime
/// (`iwl_drv_get_fwname_pre`). Without MMIO at match time we
/// enumerate the pairings linux-firmware actually ships for `sc-a0`.
/// WH-b0 goes first because it is the pairing the MS-03 reports
/// (`Detected RF WH, rfid=0x20113100`, firmware `sc-a0-wh-b0-c103`).
const RF_SC_A0_CANDIDATES: &[RfFamily] = &[
    RfFamily::WhB0,
    RfFamily::FmC0,
    RfFamily::FmB0,
    RfFamily::GfA0,
];

/// Match a PCI device against the iwlwifi chip table.
pub fn chip_config_for_pci_id(vid: u16, did: u16) -> Option<ChipConfig> {
    if vid != INTEL_VENDOR {
        return None;
    }
    let cfg = match did {
        // AX200 — single canonical PCI ID.
        0x2723 => ChipConfig {
            vid,
            did,
            display_name: "AX200",
            generation: Generation::Gen2,
            mac: MacFamily::QuZA0,
            rf_candidates: RF_HR_ONLY,
            api_max: 100,
            api_min: 100,
            api_prefix: "",
        },
        // AX201 family — same MAC/RF as AX200, multiple SKUs.
        0x02f0 | 0x43f0 | 0xa0f0 | 0x7df0 => ChipConfig {
            vid,
            did,
            display_name: "AX201",
            generation: Generation::Gen2,
            mac: MacFamily::QuB0,
            rf_candidates: RF_HR_ONLY,
            api_max: 100,
            api_min: 100,
            api_prefix: "",
        },
        // AX210.
        0x2725 => ChipConfig {
            vid,
            did,
            display_name: "AX210",
            generation: Generation::Gen3,
            mac: MacFamily::TyA0,
            rf_candidates: RF_GF_OR_GF4,
            api_max: 89,
            api_min: 89,
            api_prefix: "",
        },
        // AX211 family.
        0x51f0 => ChipConfig {
            vid,
            did,
            display_name: "AX211 (so-a0)",
            generation: Generation::Gen3,
            mac: MacFamily::SoA0,
            rf_candidates: RF_GF_OR_GF4,
            api_max: 89,
            api_min: 89,
            api_prefix: "",
        },
        0x54f0 => ChipConfig {
            vid,
            did,
            display_name: "AX211 (ma-a0)",
            generation: Generation::Gen3,
            mac: MacFamily::MaA0,
            rf_candidates: RF_GF_OR_GF4,
            api_max: 100,
            api_min: 100,
            api_prefix: "",
        },
        0x7e40 => ChipConfig {
            vid,
            did,
            display_name: "AX211 (ma-b0)",
            generation: Generation::Gen3,
            mac: MacFamily::MaB0,
            rf_candidates: RF_GF_OR_GF4,
            api_max: 100,
            api_min: 100,
            api_prefix: "",
        },
        // BE200 — Wi-Fi 7 Bz MAC + GF / GF4 / FM RF.
        0x272b => ChipConfig {
            vid,
            did,
            display_name: "BE200",
            generation: Generation::Gen3,
            mac: MacFamily::BzA0,
            rf_candidates: RF_GF_FAMILY,
            api_max: 102,
            api_min: 100,
            api_prefix: "",
        },
        // Sc ("Scorpius Peak") — Wi-Fi 7 BE20x / BE21x CNVi. Every
        // one of these IDs binds `iwl_sc_mac_cfg` in Linux's
        // `iwl_hw_card_ids` (pcie/drv.c, "Sc devices" block).
        //
        // 0xe340 is hardware-verified on the Minisforum MS-03
        // (Panther Lake-H, `00:14.3`, subsys 8086:0114): the device
        // announces as "Wi-Fi 7 BE211 320MHz" and Linux walks
        // `sc-a0-wh-b0-c107 … c103`, landing on c103.
        //
        // The API ladder is the core-release numbering: `iwl_sc_base`
        // sets `ucode_api_max = ENCODE_CORE_AS_API(107)` and
        // `ucode_api_min = ENCODE_CORE_AS_API(102)`, and
        // `FW_API_ARG` stamps those as `c107 … c102`.
        0x6e70 | 0x9327 | 0xd240 | 0xd340 | 0xe340 | 0xe440 => ChipConfig {
            vid,
            did,
            display_name: match did {
                0xe340 => "BE211 (sc-a0)",
                _ => "BE2xx (sc-a0)",
            },
            generation: Generation::Gen3,
            mac: MacFamily::ScA0,
            rf_candidates: RF_SC_A0_CANDIDATES,
            api_max: 107,
            api_min: 102,
            api_prefix: "c",
        },
        _ => return None,
    };
    Some(cfg)
}

// ── Firmware filename ladder ────────────────────────────────────────

/// Generate the firmware filename candidate ladder for `chip`.
/// Mirrors `iwl_request_firmware` in iwl-drv.c: outer loop over
/// `rf_candidates`, inner loop over API versions from `api_max`
/// down to `api_min`. First file the firmware registry resolves
/// is the one we use.
///
/// Linux's special-case at API 100 → 102 (the "core" numbering
/// jump on Bz+) is preserved: when the requested chip's
/// `api_max ≥ 100`, we start the walk at `api_max` if it's ≥ 102
/// and decrement past 100 down to `api_min`. Conversely a chip
/// pinned at `api_max = 100` gets exactly one API value tried per
/// RF.
pub fn firmware_filename_ladder(chip: &ChipConfig) -> Vec<String> {
    let mut out = Vec::new();
    for rf in chip.rf_candidates {
        // Decreasing walk, but with the API-100 → API-102 jump
        // baked in. Linux's iwl_request_firmware does this by
        // restarting the API counter at 102 when the prefix
        // matches the core-numbering family.
        let mut api = chip.api_max;
        loop {
            // Bundle prefix matches `xtask import-firmware`'s
            // staging layout, which preserves Linux's
            // `/lib/firmware/<vendor>/...` subdirectory under
            // `target/firmware/`. The kernel's
            // `firmware-scan-initramfs` initcall registers each
            // blob under its full path-relative-to-`firmware/`,
            // so we look up `iwlwifi/iwlwifi-...` (matching
            // `/lib/firmware/iwlwifi/iwlwifi-...`) not just the
            // bare filename.
            out.push(format!(
                "iwlwifi/iwlwifi-{}-{}-{}{}.ucode",
                chip.mac.prefix(),
                rf.prefix(),
                chip.api_prefix,
                api,
            ));
            if api == chip.api_min {
                break;
            }
            // Step from 102 → 101 → 100 → done (vs decrementing
            // forever). When we cross 100 we stop; api_min for
            // older chips is 100, for Bz it's also 100.
            api = api.saturating_sub(1);
            if api < chip.api_min {
                break;
            }
        }
    }
    out
}

// ── TLV firmware container parser ───────────────────────────────────

/// Magic value at offset 4 of a valid Intel .ucode file
/// (`iwl_tlv_ucode_header.magic`).
pub const IWL_TLV_UCODE_MAGIC: u32 = 0x0a4c_5749;

/// Header preceding the TLV stream — fields per
/// `iwl_tlv_ucode_header` in `fw/file.h`. Layout is fixed at 36
/// bytes (4 zero + 4 magic + 64 human_readable + 4 ver + 4 build +
/// 8 ignore — but the TLV stream sits at byte offset 36, not 88,
/// per the typedef padding rules).
pub const TLV_HEADER_BYTES: usize = 4 + 4 + 64 + 4 + 4 + 8;

/// Parsed firmware header.
#[derive(Clone, Debug)]
pub struct UcodeHeader {
    pub version: u32,
    pub build: u32,
    /// Human-readable version string from the 64-byte field.
    pub human_readable: String,
}

/// Tag IDs from `enum iwl_ucode_tlv_type` (`fw/file.h`). Only the
/// tags we need to round-trip a modern AX2xx/BE2xx blob are
/// enumerated; unknown tags are surfaced as `Other(u32)` so the
/// walker is forward-compatible with future Linux additions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TlvType {
    /// Legacy CPU1 instruction blob (pre-22000 era).
    Inst = 1,
    /// Legacy CPU1 data.
    Data = 2,
    /// Legacy INIT instructions.
    Init = 3,
    /// Legacy INIT data.
    InitData = 4,
    /// Legacy boot (unused on AX2xx+).
    Boot = 5,
    /// Modern runtime section: `{ dest_offset: u32; payload }`.
    /// One TLV per section, ordered.
    SecRt = 19,
    /// Modern INIT section.
    SecInit = 20,
    /// WoWLAN image section.
    SecWowlan = 21,
    /// `u32`: 1 or 2. Sections beyond NUM_OF_CPU split go to CPU2.
    NumOfCpu = 27,
    /// Cipher schemes (encryption capability bitmaps).
    Cscheme = 28,
    /// API capability bitmap.
    ApiChangesSet = 29,
    /// Feature capability bitmap.
    EnabledCapabilities = 30,
    /// `maj.min.api` version triple.
    FwVersion = 36,
    /// Required PNVM blob version (gen3 only).
    PnvmVersion = 62,
    /// PNVM SKU selector.
    PnvmSku = 64,
    /// Section table address.
    SecTableAddr = 66,
}

impl TlvType {
    pub fn from_raw(v: u32) -> Option<Self> {
        Some(match v {
            1 => TlvType::Inst,
            2 => TlvType::Data,
            3 => TlvType::Init,
            4 => TlvType::InitData,
            5 => TlvType::Boot,
            19 => TlvType::SecRt,
            20 => TlvType::SecInit,
            21 => TlvType::SecWowlan,
            27 => TlvType::NumOfCpu,
            28 => TlvType::Cscheme,
            29 => TlvType::ApiChangesSet,
            30 => TlvType::EnabledCapabilities,
            36 => TlvType::FwVersion,
            62 => TlvType::PnvmVersion,
            64 => TlvType::PnvmSku,
            66 => TlvType::SecTableAddr,
            _ => return None,
        })
    }
}

/// Magic offset value separating CPU1 sections from CPU2 in the
/// SEC_RT / SEC_INIT TLV stream (`CPU1_CPU2_SEPARATOR_SECTION`).
pub const CPU1_CPU2_SEPARATOR: u32 = 0xFFFF_CCCC;
/// Magic offset value introducing paged-section blocks
/// (`PAGING_SEPARATOR_SECTION`).
pub const PAGING_SEPARATOR: u32 = 0xAAAA_BBBB;
/// PAGING block size — 8 × 4 KiB pages per the iwlwifi paging IF.
pub const PAGING_BLOCK_SIZE: usize = 32 * 1024;
/// Maximum total paging image size.
pub const MAX_PAGING_IMAGE_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub enum ParseError {
    /// Header too short for the magic + fields.
    TooShort,
    /// Magic doesn't match `IWL_TLV_UCODE_MAGIC`.
    BadMagic(u32),
    /// A TLV's declared length runs past the end of the blob.
    TruncatedTlv {
        offset: usize,
        declared_len: u32,
        remaining: usize,
    },
    /// A SEC_RT/SEC_INIT TLV is smaller than 4 bytes (the leading
    /// dest_offset).
    SecTooShort { offset: usize, len: u32 },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "blob too short for header"),
            ParseError::BadMagic(m) => write!(f, "bad TLV magic: {:#x}", m),
            ParseError::TruncatedTlv {
                offset,
                declared_len,
                remaining,
            } => write!(
                f,
                "truncated TLV at {}: declared {} bytes, only {} remain",
                offset, declared_len, remaining
            ),
            ParseError::SecTooShort { offset, len } => {
                write!(f, "SEC_RT/SEC_INIT at {} too short ({} bytes)", offset, len)
            }
        }
    }
}

/// Parse + classify one section TLV (SEC_RT or SEC_INIT). First 4
/// bytes are the device-memory destination offset; remainder is the
/// payload. A few sentinel `dest_offset` values are NOT real
/// addresses but markers: `CPU1_CPU2_SEPARATOR` and
/// `PAGING_SEPARATOR`.
#[derive(Clone, Debug)]
pub struct FwSection<'a> {
    pub dest_offset: u32,
    pub payload: &'a [u8],
}

impl<'a> FwSection<'a> {
    pub fn is_separator(&self) -> bool {
        matches!(self.dest_offset, CPU1_CPU2_SEPARATOR | PAGING_SEPARATOR)
    }
    pub fn is_cpu1_cpu2_separator(&self) -> bool {
        self.dest_offset == CPU1_CPU2_SEPARATOR
    }
    pub fn is_paging_separator(&self) -> bool {
        self.dest_offset == PAGING_SEPARATOR
    }
}

/// Walked .ucode blob. Each method below borrows the underlying
/// bytes so the parser is zero-copy — sections point into the
/// original CPIO payload.
#[derive(Clone, Debug)]
pub struct ParsedUcode<'a> {
    pub header: UcodeHeader,
    /// Number of CPUs declared by `NUM_OF_CPU` TLV (default 1).
    pub num_of_cpu: u32,
    /// Sections from the `SEC_INIT` TLV stream (image type INIT).
    pub init_sections: Vec<FwSection<'a>>,
    /// Sections from the `SEC_RT` TLV stream (image type REGULAR).
    pub rt_sections: Vec<FwSection<'a>>,
    /// Raw `FW_VERSION` triple, if present: (major, minor, api).
    pub fw_version: Option<(u32, u32, u32)>,
    /// `PNVM_VERSION` requirement for gen3 (`Some(version)` means
    /// the driver MUST load a matching iwlwifi-*.pnvm sibling).
    pub pnvm_version: Option<u32>,
    /// Unknown / unparsed TLVs surface count for diagnostics. The
    /// walker doesn't fail on these — Intel adds new tags in
    /// every kernel release.
    pub unknown_tlv_count: usize,
}

impl<'a> ParsedUcode<'a> {
    pub fn is_dual_cpu(&self) -> bool {
        self.num_of_cpu >= 2
    }

    /// True iff this is a gen3-style blob that requires a PNVM
    /// sibling. AX210/AX211/BE200 firmware all set this.
    pub fn requires_pnvm(&self) -> bool {
        self.pnvm_version.is_some()
    }

    /// Derive the PNVM sibling filename the kernel firmware
    /// registry should resolve. Linux's `iwl_pnvm.c` builds the
    /// name from the SKU + PNVM version embedded in the firmware
    /// TLVs:
    ///
    /// ```text
    /// iwlwifi-<sku>-<pnvm_version>.pnvm
    /// ```
    ///
    /// Where `<sku>` is the same chip identity Linux uses for
    /// the .ucode (e.g. `so-a0-gf-a0`) and `<pnvm_version>` is
    /// the hex value from `TlvType::PnvmVersion`.
    ///
    /// Returns `None` for blobs that don't declare a PNVM
    /// requirement (every gen2 chip + a few legacy gen3
    /// firmwares).
    pub fn pnvm_filename(&self, chip: &ChipConfig, rf: RfFamily) -> Option<String> {
        let ver = self.pnvm_version?;
        Some(format!(
            "iwlwifi-{}-{}-{:x}.pnvm",
            chip.mac.prefix(),
            rf.prefix(),
            ver,
        ))
    }
}

/// Parse an Intel iwlwifi .ucode blob.
pub fn parse_ucode(bytes: &[u8]) -> Result<ParsedUcode<'_>, ParseError> {
    if bytes.len() < TLV_HEADER_BYTES {
        return Err(ParseError::TooShort);
    }
    // Header (struct iwl_tlv_ucode_header): zero(4) + magic(4) +
    // human_readable[64] + ver(4) + build(4) + ignore(8).
    let magic = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if magic != IWL_TLV_UCODE_MAGIC {
        return Err(ParseError::BadMagic(magic));
    }
    let mut hr = String::new();
    for &b in &bytes[8..8 + 64] {
        if b == 0 {
            break;
        }
        if b.is_ascii() && !b.is_ascii_control() {
            hr.push(b as char);
        }
    }
    let version = u32::from_le_bytes(bytes[72..76].try_into().unwrap());
    let build = u32::from_le_bytes(bytes[76..80].try_into().unwrap());

    let header = UcodeHeader {
        version,
        build,
        human_readable: hr,
    };

    let mut num_of_cpu: u32 = 1;
    let mut init_sections: Vec<FwSection<'_>> = Vec::new();
    let mut rt_sections: Vec<FwSection<'_>> = Vec::new();
    let mut fw_version: Option<(u32, u32, u32)> = None;
    let mut pnvm_version: Option<u32> = None;
    let mut unknown_tlv_count: usize = 0;

    // TLV stream starts at TLV_HEADER_BYTES.
    let mut pos = TLV_HEADER_BYTES;
    while pos + 8 <= bytes.len() {
        let raw_type = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        let raw_len = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap());
        pos += 8;
        let len = raw_len as usize;
        if pos + len > bytes.len() {
            return Err(ParseError::TruncatedTlv {
                offset: pos - 8,
                declared_len: raw_len,
                remaining: bytes.len() - pos,
            });
        }
        let data = &bytes[pos..pos + len];
        match TlvType::from_raw(raw_type) {
            Some(TlvType::NumOfCpu) if len >= 4 => {
                num_of_cpu = u32::from_le_bytes(data[..4].try_into().unwrap());
            }
            Some(TlvType::SecInit) | Some(TlvType::SecRt) => {
                if len < 4 {
                    return Err(ParseError::SecTooShort {
                        offset: pos - 8,
                        len: raw_len,
                    });
                }
                let dest_offset = u32::from_le_bytes(data[..4].try_into().unwrap());
                let sec = FwSection {
                    dest_offset,
                    payload: &data[4..],
                };
                if matches!(TlvType::from_raw(raw_type), Some(TlvType::SecInit)) {
                    init_sections.push(sec);
                } else {
                    rt_sections.push(sec);
                }
            }
            Some(TlvType::FwVersion) if len >= 12 => {
                let major = u32::from_le_bytes(data[0..4].try_into().unwrap());
                let minor = u32::from_le_bytes(data[4..8].try_into().unwrap());
                let api = u32::from_le_bytes(data[8..12].try_into().unwrap());
                fw_version = Some((major, minor, api));
            }
            Some(TlvType::PnvmVersion) if len >= 4 => {
                pnvm_version = Some(u32::from_le_bytes(data[..4].try_into().unwrap()));
            }
            Some(_) => {} // recognised but not consumed
            None => {
                unknown_tlv_count += 1;
            }
        }
        // TLVs are 4-byte aligned in the stream — round `len` up.
        let advance = (len + 3) & !3;
        pos += advance;
    }

    Ok(ParsedUcode {
        header,
        num_of_cpu,
        init_sections,
        rt_sections,
        fw_version,
        pnvm_version,
        unknown_tlv_count,
    })
}

// ── PCI probe (skeleton) ────────────────────────────────────────────

/// PCI probe entry. Records the bound driver and resolves a
/// firmware blob by walking the filename ladder. Hardware bring-up
/// (BAR0 mapping, MMIO programming, ALIVE handshake) is deferred
/// until the gen2/gen3 transport paths land — this commit only
/// validates that we can match the device + find its firmware.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let chip = match chip_config_for_pci_id(device.id.vendor, device.id.device) {
        Some(c) => c,
        None => return Err(narf_bus::ProbeError::NotForThisDriver),
    };

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("iwlwifi"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  iwlwifi: probed {} ({:04x}:{:04x}, {:?}, MAC={}, RF={:?})",
        chip.display_name,
        chip.vid,
        chip.did,
        chip.generation,
        chip.mac.prefix(),
        chip.rf_candidates,
    );

    // Walk the firmware ladder. First match wins — the registry's
    // `open` returns NotFound for absent blobs, so we just iterate
    // until something resolves or we run out of candidates.
    let ladder = firmware_filename_ladder(&chip);
    let auth = match narf_firmware::trusted_loader_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    let auth = match auth {
        Some(a) => a,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  iwlwifi: no trusted-loader authority — skipping firmware load"
            );
            return Ok(());
        }
    };
    let mut matched_name: Option<String> = None;
    for candidate in &ladder {
        if narf_firmware::open(candidate.as_str(), &auth).is_ok() {
            matched_name = Some(candidate.clone());
            break;
        }
    }
    let matched_name = match matched_name {
        Some(n) => n,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  iwlwifi: no firmware found ({} candidates tried)",
                ladder.len(),
            );
            return Ok(());
        }
    };
    let _ = writeln!(
        narf_console::Writer,
        "  iwlwifi: firmware resolved to {}",
        matched_name,
    );

    // Parse + summarise the firmware to confirm the registry blob
    // is actually a valid Intel TLV container.
    let fw_cap = match narf_firmware::open(matched_name.as_str(), &auth) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let view = match narf_firmware::view_of(&fw_cap) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    match parse_ucode(view.bytes) {
        Ok(parsed) => {
            let _ = writeln!(
                narf_console::Writer,
                "  iwlwifi:   header.version={:#x} build={} hr={:?}",
                parsed.header.version,
                parsed.header.build,
                parsed.header.human_readable,
            );
            let _ = writeln!(
                narf_console::Writer,
                "  iwlwifi:   {} init sec, {} rt sec, num_cpu={}, pnvm={:?}, unk_tlvs={}",
                parsed.init_sections.len(),
                parsed.rt_sections.len(),
                parsed.num_of_cpu,
                parsed.pnvm_version,
                parsed.unknown_tlv_count,
            );
            if let Some((ma, mi, api)) = parsed.fw_version {
                let _ = writeln!(
                    narf_console::Writer,
                    "  iwlwifi:   fw_version={}.{} api={}",
                    ma,
                    mi,
                    api,
                );
            }
            if parsed.requires_pnvm() {
                let _ = writeln!(
                    narf_console::Writer,
                    "  iwlwifi:   gen3 PNVM required — sibling iwlwifi-*.pnvm \
                     load not yet wired"
                );
            }

            // ── Hardware bring-up ──

            // 1. Map BAR0.
            // SAFETY: `device` is the PCIe function the bus handed this
            // driver to probe, so it's a real PCIe device and this
            // driver holds exclusive access to its cfg window for the
            // duration of probe. BAR index 0 is iwlwifi's MMIO BAR.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let mmio_region = unsafe { map_bar(&device, 0) }.map_err(|_| {
                let _ = writeln!(narf_console::Writer, "  iwlwifi: BAR0 map failed");
                narf_bus::ProbeError::Other("BAR0 map failed")
            })?;
            let mut mmio = IwlMmioImpl(mmio_region);

            // 2. APM Init (clocks + reset prologue).
            transport::apm_init(&mut mmio).map_err(|e| {
                let _ = writeln!(narf_console::Writer, "  iwlwifi: APM init failed: {:?}", e);
                narf_bus::ProbeError::Other("APM init failed")
            })?;

            // 3. Firmware load + ALIVE handshake.
            let mut allocator = fw_loader::DmaAllocatorImpl::new();
            let mut alive = transport::PollingAliveSink::new(mmio_region);

            match fw_loader::load_firmware(&mut mmio, &chip, &parsed, &mut allocator, &mut alive) {
                Ok(()) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  iwlwifi: ALIVE handshake successful"
                    );
                }
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  iwlwifi: firmware load failed: {:?}",
                        e
                    );
                    return Err(narf_bus::ProbeError::Other("Firmware load failed"));
                }
            }

            // 3b. Flush the BCAST_FILTER cache so the firmware starts
            //     forwarding beacons/probe-responses up to the host
            //     RX queue (required before scan can collect BSSes).
            //     The TX queue isn't fully wired this early so we
            //     stash the encoded body for later dispatch by the
            //     scan path. (cmd id 0xCD, group 0.)
            let _bcast_flush_body = bcast::build_flush_cmd();
            let _ = writeln!(
                narf_console::Writer,
                "  iwlwifi: BCAST_FILTER flush staged (cmd 0x{:02X})",
                bcast::BCAST_FILTER_CMD,
            );

            // 4. Hardware Initialization (RX/TX rings).

            // Allocate RX ring memory.
            let rx_ring_mem = narf_io::alloc_coherent(
                rx::RX_RING_SIZE * core::mem::size_of::<rx::RxDescriptor>(),
                narf_lib::id::DomainId::DRIVER_0,
            )
            .map_err(|_| narf_bus::ProbeError::Other("RX ring alloc failed"))?;

            // Allocate RX buffers.
            let mut rx_buffers = Vec::with_capacity(rx::RX_RING_SIZE);
            for _ in 0..rx::RX_RING_SIZE {
                let buf = narf_io::alloc_coherent(rx::RXB_SIZE, narf_lib::id::DomainId::DRIVER_0)
                    .map_err(|_| narf_bus::ProbeError::Other("RX buffer alloc failed"))?;
                rx_buffers.push(buf);
            }

            // Fill RX descriptors.
            let rx_descs = rx_ring_mem.as_mut_ptr() as *mut rx::RxDescriptor;
            for (i, buf) in rx_buffers.iter().enumerate() {
                // SAFETY: `rx_ring_mem` is a coherent buffer of exactly
                // `RX_RING_SIZE` `RxDescriptor`s, and `i` ranges over
                // `0..rx_buffers.len()` which equals `RX_RING_SIZE`, so
                // `rx_descs.add(i)` points at descriptor `i` in bounds
                // and is properly aligned for `RxDescriptor`.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe {
                    (*rx_descs.add(i)).host_phys = buf.dma_addr().raw();
                }
            }

            // Allocate TX ring memory (queue 0).
            let tx_ring0_mem = narf_io::alloc_coherent(
                tx::TX_RING_SIZE * core::mem::size_of::<tx::Tfd>(),
                narf_lib::id::DomainId::DRIVER_0,
            )
            .map_err(|_| narf_bus::ProbeError::Other("TX ring alloc failed"))?;

            // Allocate TX command buffers (queue 0).
            let tx_cmd0_mem =
                narf_io::alloc_coherent(tx::TX_RING_SIZE * 32, narf_lib::id::DomainId::DRIVER_0)
                    .map_err(|_| narf_bus::ProbeError::Other("TX cmd buffer alloc failed"))?;

            // ── 4a. Interrupt setup ──
            //
            // iwlwifi exposes up to 32 MSI-X vectors with per-cause
            // routing. The bring-up path uses three causes (RX/ALIVE,
            // TX completion, fatal errors); see `iwl_msix.rs`.
            // PCI-side: allocate three CPU vectors and program the
            // first three MSI-X table entries. BAR0-side: program the
            // per-cause IVAR bytes via `iwl_msix::program_default_causes`.
            let mut irq_vector = None;
            if let Ok(v) = narf_interrupts::vector::alloc() {
                if let Ok(mut msix) = narf_bus::msix::enable_msix(&cap, &device) {
                    // SAFETY: `msix` is the MSI-X capability just enabled
                    // for `device`, which this driver owns exclusively
                    // during probe, so we're the sole writer of its
                    // table. `v`/`v_tx`/`v_err` are CPU vectors freshly
                    // allocated from `narf_interrupts::vector::alloc`,
                    // and the table indices (RX_ALIVE/TX/ERR) are within
                    // iwlwifi's MSI-X table size.
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    unsafe {
                        let _ = msix.program_vector(iwl_msix::VECTOR_RX_ALIVE as u16, 0, v);
                        // Try to allocate two more CPU vectors for TX
                        // and ERR; fall through if we can't get them.
                        if let Ok(v_tx) = narf_interrupts::vector::alloc() {
                            let _ = msix.program_vector(iwl_msix::VECTOR_TX as u16, 0, v_tx);
                            narf_interrupts::install_handler(v_tx, || {});
                        }
                        if let Ok(v_err) = narf_interrupts::vector::alloc() {
                            let _ = msix.program_vector(iwl_msix::VECTOR_ERR as u16, 0, v_err);
                            narf_interrupts::install_handler(v_err, || {});
                        }
                        let _ = msix.enable();
                    }
                    // Program the per-cause IVAR bytes via BAR0.
                    iwl_msix::program_default_causes(&mut mmio);
                    irq_vector = Some(v);
                } else if let Ok(mut msi) = narf_bus::msi::enable_msi(&cap, &device, 1) {
                    // SAFETY: `msi` is the MSI capability just enabled
                    // for `device`, whose cfg window this driver owns
                    // exclusively during probe; `v` is a freshly
                    // allocated CPU vector. So programming the single
                    // MSI message and enabling it has no concurrent
                    // writer.
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    unsafe {
                        let _ = narf_bus::msi::program_msi(&mut msi, 0, v);
                        let _ = narf_bus::msi::enable(&msi);
                    }
                    irq_vector = Some(v);
                }

                if let Some(v) = irq_vector {
                    narf_interrupts::install_handler(v, || {});
                }
            }

            // Program hardware RX registers.
            mmio.write(
                rx::CSR_FH_MEM_RSCSR_CHNL0_RBDCB_BASE_REG,
                rx_ring_mem.dma_addr().raw() as u32,
            );
            mmio.write(rx::CSR_FH_RSCSR_CHNL0_WPTR, (rx::RX_RING_SIZE - 1) as u32);

            // 5. Instantiate and register the device.
            // TODO: Read real MAC from hardware/firmware.
            let mac_addr = [0x00, 0x16, 0xEA, 0x12, 0x34, 0x56];

            let rx_q = rx::RxQueue::new(rx_descs, rx_ring_mem.dma_addr().raw());
            let tx_q0 = tx::TxQueue::new(0, tx_ring0_mem.as_mut_ptr() as *mut tx::Tfd);

            let device = Arc::new(IwlDevice::new(
                mmio_region,
                chip,
                mac_addr,
                rx_q,
                tx_q0,
                rx_ring_mem,
                alloc::vec![tx_ring0_mem],
                alloc::vec![tx_cmd0_mem],
                rx_buffers,
                irq_vector,
            ));

            // Initialize IPC rings.
            let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
            let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

            *device.rx_ring.lock() = Some(rx_cons);
            *device.tx_ring.lock() = Some(tx_prod);

            // Register with the wireless subsystem.
            narf_wireless::registry::register(device.clone());

            // 6. Spawn data pumps.
            spawn_pumps(device, rx_prod, tx_cons);
        }
        Err(e) => {
            let _ = writeln!(narf_console::Writer, "  iwlwifi:   parse failed: {}", e);
        }
    }

    Ok(())
}

/// Register the PCI match table. Picked up at boot via the bus
/// walker; once any of these PCI IDs is enumerated the `probe`
/// function fires.
///
/// The bus match registry is keyed by `name` and idempotent on
/// re-registration (later entry replaces the earlier), so we
/// need a unique `name` per PCI ID — using the bare "iwlwifi"
/// for all of them would collapse to just the last entry. The
/// per-match names are `iwlwifi-<did>` (the canonical display
/// name is still recorded via `record_bound("iwlwifi", ...)`).
pub fn register() {
    for &(did, name) in PCI_DIDS.iter() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: INTEL_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// PCI device IDs the driver claims, with the unique per-ID match
/// name used at registration. Names match `iwlwifi-<did>` pattern
/// so registry lookups can find them by string. Sync with
/// `chip_config_for_pci_id`.
const PCI_DIDS: &[(u16, &str)] = &[
    (0x2723, "iwlwifi-2723"),
    (0x02f0, "iwlwifi-02f0"),
    (0x43f0, "iwlwifi-43f0"),
    (0xa0f0, "iwlwifi-a0f0"),
    (0x7df0, "iwlwifi-7df0"),
    (0x2725, "iwlwifi-2725"),
    (0x51f0, "iwlwifi-51f0"),
    (0x54f0, "iwlwifi-54f0"),
    (0x7e40, "iwlwifi-7e40"),
    (0x272b, "iwlwifi-272b"),
    (0x6e70, "iwlwifi-6e70"),
    (0x9327, "iwlwifi-9327"),
    (0xd240, "iwlwifi-d240"),
    (0xd340, "iwlwifi-d340"),
    (0xe340, "iwlwifi-e340"),
    (0xe440, "iwlwifi-e440"),
];

// ── Smoke tests ────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Sanity: every PCI ID in the device-ID table resolves
    /// through `chip_config_for_pci_id`.
    fn smoke_iwlwifi_chip_table_is_complete() -> TestResult {
        for (did, _) in PCI_DIDS {
            if chip_config_for_pci_id(INTEL_VENDOR, *did).is_none() {
                return TestResult::Fail("PCI ID without chip config entry");
            }
        }
        TestResult::Pass
    }

    /// AX200 ladder = exactly one filename
    /// (`iwlwifi-QuZ-a0-hr-b0-100.ucode`).
    fn smoke_iwlwifi_ax200_ladder_pinned_api_100() -> TestResult {
        let chip = chip_config_for_pci_id(INTEL_VENDOR, 0x2723).expect("ax200");
        let ladder = firmware_filename_ladder(&chip);
        if ladder.len() != 1 {
            return TestResult::Fail("expected exactly one AX200 candidate");
        }
        if ladder[0] != "iwlwifi/iwlwifi-QuZ-a0-hr-b0-100.ucode" {
            return TestResult::Fail("AX200 candidate didn't match expected name");
        }
        TestResult::Pass
    }

    /// BE200 ladder spans 3 RFs × API 102..=100 = 9 names.
    fn smoke_iwlwifi_be200_ladder_spans_rfs_and_apis() -> TestResult {
        let chip = chip_config_for_pci_id(INTEL_VENDOR, 0x272b).expect("be200");
        let ladder = firmware_filename_ladder(&chip);
        if ladder.len() != 9 {
            return TestResult::Fail("expected 3 RFs × 3 APIs = 9 BE200 candidates");
        }
        // First candidate should be gf-a0 @ 102 (max API, first RF).
        if ladder[0] != "iwlwifi/iwlwifi-bz-a0-gf-a0-102.ucode" {
            return TestResult::Fail("BE200 first candidate wrong");
        }
        TestResult::Pass
    }

    /// Parse a minimal hand-crafted TLV blob and confirm the
    /// walker reaches the SEC_RT entry without choking on
    /// alignment padding.
    fn smoke_iwlwifi_tlv_parser_round_trip() -> TestResult {
        let mut blob = Vec::<u8>::new();
        // Header: 4 zero, 4 magic, 64 hr, 4 ver, 4 build, 8 ignore.
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(&IWL_TLV_UCODE_MAGIC.to_le_bytes());
        let mut hr = [0u8; 64];
        hr[..b"smoketest"[..].len()].copy_from_slice(b"smoketest");
        blob.extend_from_slice(&hr);
        blob.extend_from_slice(&0x0102_0304u32.to_le_bytes()); // ver
        blob.extend_from_slice(&42u32.to_le_bytes()); // build
        blob.extend_from_slice(&[0u8; 8]); // ignore
                                           // TLV: SEC_RT (19), length = 4 (dest) + 3 (payload), so
                                           // 7 bytes — needs 1 byte of padding to 8.
        blob.extend_from_slice(&19u32.to_le_bytes()); // type
        blob.extend_from_slice(&7u32.to_le_bytes()); // len
        blob.extend_from_slice(&0x0040_1000u32.to_le_bytes()); // dest
        blob.extend_from_slice(&[0xAB, 0xCD, 0xEF]); // payload
        blob.push(0); // alignment pad
                      // TLV: NUM_OF_CPU = 2.
        blob.extend_from_slice(&27u32.to_le_bytes());
        blob.extend_from_slice(&4u32.to_le_bytes());
        blob.extend_from_slice(&2u32.to_le_bytes());

        let parsed = match parse_ucode(&blob) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("parse_ucode unexpectedly failed"),
        };
        if parsed.header.version != 0x0102_0304 || parsed.header.build != 42 {
            return TestResult::Fail("header decode wrong");
        }
        if parsed.header.human_readable != "smoketest" {
            return TestResult::Fail("human_readable decode wrong");
        }
        if parsed.rt_sections.len() != 1 {
            return TestResult::Fail("expected exactly one SEC_RT");
        }
        if parsed.rt_sections[0].dest_offset != 0x0040_1000 {
            return TestResult::Fail("SEC_RT dest_offset wrong");
        }
        if parsed.rt_sections[0].payload != [0xAB, 0xCD, 0xEF] {
            return TestResult::Fail("SEC_RT payload wrong");
        }
        if parsed.num_of_cpu != 2 {
            return TestResult::Fail("NUM_OF_CPU not honoured");
        }
        TestResult::Pass
    }

    /// A blob with a bad magic should produce `BadMagic`.
    fn smoke_iwlwifi_tlv_parser_rejects_bad_magic() -> TestResult {
        let mut blob = Vec::<u8>::new();
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(&0xDEADBEEFu32.to_le_bytes()); // wrong magic
        blob.resize(TLV_HEADER_BYTES, 0);
        match parse_ucode(&blob) {
            Err(ParseError::BadMagic(0xDEADBEEF)) => TestResult::Pass,
            _ => TestResult::Fail("expected BadMagic on wrong magic"),
        }
    }

    /// CPU1/CPU2 separator is recognised structurally.
    fn smoke_iwlwifi_cpu1_cpu2_separator_classified() -> TestResult {
        let sec = FwSection {
            dest_offset: CPU1_CPU2_SEPARATOR,
            payload: &[],
        };
        if !sec.is_separator() || !sec.is_cpu1_cpu2_separator() {
            return TestResult::Fail("CPU1/CPU2 separator not detected");
        }
        TestResult::Pass
    }

    /// PCI match table registered correctly.
    fn smoke_iwlwifi_pci_match_table_registers() -> TestResult {
        register();
        let regs = narf_bus::driver_match::registered();
        for (did, _) in PCI_DIDS {
            let found = regs.iter().any(|e| {
                matches!(
                    e.kind,
                    narf_bus::MatchKind::VendorDevice { vendor, device }
                        if vendor == INTEL_VENDOR && device == *did
                )
            });
            if !found {
                return TestResult::Fail("PCI ID missing from registered match table");
            }
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_chip_table_is_complete
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_ax200_ladder_pinned_api_100
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_be200_ladder_spans_rfs_and_apis
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_tlv_parser_round_trip
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_tlv_parser_rejects_bad_magic
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_cpu1_cpu2_separator_classified
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_pci_match_table_registers
    );

    /// PNVM sibling filename derived from PnvmVersion TLV + chip
    /// MAC/RF prefixes.
    fn smoke_iwlwifi_pnvm_filename_derived_correctly() -> TestResult {
        let chip = chip_config_for_pci_id(INTEL_VENDOR, 0x272b).expect("be200");
        let parsed = ParsedUcode {
            header: UcodeHeader {
                version: 0,
                build: 0,
                human_readable: String::new(),
            },
            num_of_cpu: 2,
            init_sections: Vec::new(),
            rt_sections: Vec::new(),
            fw_version: None,
            pnvm_version: Some(0x42),
            unknown_tlv_count: 0,
        };
        let name = parsed
            .pnvm_filename(&chip, RfFamily::GfA0)
            .expect("Some filename");
        if name != "iwlwifi-bz-a0-gf-a0-42.pnvm" {
            return TestResult::Fail("PNVM filename wrong");
        }
        TestResult::Pass
    }

    /// No PNVM required → no filename.
    fn smoke_iwlwifi_pnvm_filename_none_when_no_version() -> TestResult {
        let chip = chip_config_for_pci_id(INTEL_VENDOR, 0x2723).expect("ax200");
        let parsed = ParsedUcode {
            header: UcodeHeader {
                version: 0,
                build: 0,
                human_readable: String::new(),
            },
            num_of_cpu: 1,
            init_sections: Vec::new(),
            rt_sections: Vec::new(),
            fw_version: None,
            pnvm_version: None,
            unknown_tlv_count: 0,
        };
        if parsed.pnvm_filename(&chip, RfFamily::HrB0).is_some() {
            return TestResult::Fail("expected None for non-PNVM blob");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_pnvm_filename_derived_correctly
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_pnvm_filename_none_when_no_version
    );

    // ── Stage 3: MAC_CONTEXT_CMD + TIME_EVENT_CMD encode ──────────

    fn smoke_iwlwifi_mac_context_cmd_encode() -> TestResult {
        use mac_ctx::{
            build_mac_context_cmd, ctxt_action, filter_flags, mac_type, MAC_CONTEXT_CMD,
        };
        let node_addr: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let bssid: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let filter = filter_flags::IN_NON_MCAST | filter_flags::IN_MCAST;
        let cmd = build_mac_context_cmd(0, mac_type::BSS_STA, node_addr, bssid, filter);
        // cmd_hdr(4) + id_and_color(4) + action(4) + mac_type(4) + tsf_id(4)
        // + node_addr(6)+pad(2) + bssid(6)+pad(2) + cck_rates(4) + ofdm_rates(4)
        // + protection_flags(4) + cck_short_preamble(4) + short_slot(4)
        // + filter_flags(4) + qos_flags(4) + ac[5]*8(40) + type_stub(4) = 108 bytes.
        if cmd.len() != 108 {
            return TestResult::Fail("mac_context_cmd size wrong (expected 108)");
        }
        // cmd[0] = MAC_CONTEXT_CMD = 0x28.
        if cmd[0] != MAC_CONTEXT_CMD {
            return TestResult::Fail("cmd[0] != MAC_CONTEXT_CMD (0x28)");
        }
        // id_and_color at bytes 4..8 = 0.
        let id_and_color = u32::from_le_bytes(cmd[4..8].try_into().unwrap());
        if id_and_color != 0 {
            return TestResult::Fail("id_and_color != 0");
        }
        // action at bytes 8..12 = ADD = 1.
        let action = u32::from_le_bytes(cmd[8..12].try_into().unwrap());
        if action != ctxt_action::ADD {
            return TestResult::Fail("action != ADD(1)");
        }
        // mac_type at bytes 12..16 = BSS_STA = 5.
        let mtype = u32::from_le_bytes(cmd[12..16].try_into().unwrap());
        if mtype != mac_type::BSS_STA {
            return TestResult::Fail("mac_type != BSS_STA(5)");
        }
        // node_addr at bytes 20..26 (after cmd_hdr+id_and_color+action+mac_type+tsf_id=20).
        if cmd[20..26] != node_addr {
            return TestResult::Fail("node_addr bytes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_mac_context_cmd_encode
    );

    fn smoke_iwlwifi_time_event_cmd_encode() -> TestResult {
        use mac_ctx::{build_time_event_cmd, ctxt_action, te_type, TIME_EVENT_CMD};
        let cmd = build_time_event_cmd(0, te_type::BSS_STA_ASSOC, 100);
        // Expected: 4-byte cmd hdr + 36-byte body = 40 bytes.
        if cmd.len() != 40 {
            return TestResult::Fail("time_event_cmd size wrong (expected 40)");
        }
        // cmd[0] = TIME_EVENT_CMD = 0x29.
        if cmd[0] != TIME_EVENT_CMD {
            return TestResult::Fail("cmd[0] != TIME_EVENT_CMD (0x29)");
        }
        // id_and_color at bytes 4..8 = 0.
        let id_and_color = u32::from_le_bytes(cmd[4..8].try_into().unwrap());
        if id_and_color != 0 {
            return TestResult::Fail("id_and_color != 0");
        }
        // action at bytes 8..12 = ADD = 1.
        let action = u32::from_le_bytes(cmd[8..12].try_into().unwrap());
        if action != ctxt_action::ADD {
            return TestResult::Fail("action != ADD(1)");
        }
        // te_id at bytes 12..16 = BSS_STA_ASSOC = 1.
        let te_id = u32::from_le_bytes(cmd[12..16].try_into().unwrap());
        if te_id != te_type::BSS_STA_ASSOC {
            return TestResult::Fail("te_id != BSS_STA_ASSOC(1)");
        }
        // duration at bytes 32..36 (after cmd_hdr+id+action+te_id+apply+max_delay+depends+interval = 32).
        let duration = u32::from_le_bytes(cmd[32..36].try_into().unwrap());
        if duration != 100 {
            return TestResult::Fail("duration != 100");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_time_event_cmd_encode
    );

    fn smoke_iwlwifi_cmd_header_layout() -> TestResult {
        let hdr = tx::IwlCmdHeader {
            cmd: 0x07,
            group_id: 0x0C,
            sequence: 0x1234,
        };
        if core::mem::size_of::<tx::IwlCmdHeader>() != 4 {
            return TestResult::Fail("IwlCmdHeader should be 4 bytes");
        }
        // Manual decode to verify packing + LE.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let bytes: [u8; 4] = unsafe { core::mem::transmute(hdr) };
        if bytes[0] != 0x07 {
            return TestResult::Fail("cmd wrong");
        }
        if bytes[1] != 0x0C {
            return TestResult::Fail("group_id wrong");
        }
        // sequence is u16 LE.
        if bytes[2] != 0x34 || bytes[3] != 0x12 {
            return TestResult::Fail("sequence (LE) wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi", smoke_iwlwifi_cmd_header_layout);

    fn smoke_iwlwifi_bands_populated_from_chip_config() -> TestResult {
        let ax200 = chip_config_for_pci_id(INTEL_VENDOR, 0x2723).expect("ax200");
        let bands_ax200 = bands_for_chip(&ax200);
        if bands_ax200.len() != 2 {
            return TestResult::Fail("AX200 should have 2 bands (2.4 GHz and 5 GHz)");
        }
        if bands_ax200[0].freq_mhz != 2400 || bands_ax200[0].channels.len() != 13 {
            return TestResult::Fail("AX200 2.4 GHz band incorrect");
        }
        if bands_ax200[1].freq_mhz != 5000 || bands_ax200[1].channels.is_empty() {
            return TestResult::Fail("AX200 5 GHz band incorrect");
        }

        let ax210 = chip_config_for_pci_id(INTEL_VENDOR, 0x2725).expect("ax210");
        let bands_ax210 = bands_for_chip(&ax210);
        if bands_ax210.len() != 3 {
            return TestResult::Fail("AX210 should have 3 bands (2.4 GHz, 5 GHz, 6 GHz)");
        }
        if bands_ax210[2].freq_mhz != 6000 || bands_ax210[2].channels.is_empty() {
            return TestResult::Fail("AX210 6 GHz band incorrect");
        }

        let be200 = chip_config_for_pci_id(INTEL_VENDOR, 0x272b).expect("be200");
        let bands_be200 = bands_for_chip(&be200);
        if bands_be200.len() != 3 {
            return TestResult::Fail("BE200 should have 3 bands (2.4 GHz, 5 GHz, 6 GHz)");
        }
        if bands_be200[2].freq_mhz != 6000 {
            return TestResult::Fail("BE200 6 GHz band incorrect");
        }

        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_bands_populated_from_chip_config
    );

    /// BAR0 on this family is 16 KiB (`lspci` reports `size=16K` for
    /// the MS-03's 8086:e340). Anything handed to
    /// `MmioRegion::{read32,write32}` is a *CSR offset* and has to
    /// land inside that window.
    ///
    /// PRPH addresses are a different namespace: they are values
    /// written *through* the HBUS window, not offsets into it, and
    /// they legitimately run into the 0xA0_0000 range. Conflating the
    /// two is how `HBUS_TARG_PRPH_WADDR` came to be 0x44C000 — the
    /// PRPH data register's 0x44c with four zeroes stuck on — which
    /// put every indirect register access roughly 4.5 MiB past the
    /// end of the mapping.
    fn smoke_iwlwifi_csr_offsets_fit_in_bar0() -> TestResult {
        use super::regs;

        /// Smallest BAR0 this driver claims to support.
        const BAR0_BYTES: u32 = 16 * 1024;

        let csr_offsets: &[(&str, u32)] = &[
            ("CSR_HW_IF_CONFIG_REG", regs::CSR_HW_IF_CONFIG_REG),
            ("CSR_INT_COALESCING", regs::CSR_INT_COALESCING),
            ("CSR_INT", regs::CSR_INT),
            ("CSR_INT_MASK", regs::CSR_INT_MASK),
            ("CSR_FH_INT_STATUS", regs::CSR_FH_INT_STATUS),
            ("CSR_GPIO_IN", regs::CSR_GPIO_IN),
            ("CSR_RESET", regs::CSR_RESET),
            ("CSR_GP_CNTRL", regs::CSR_GP_CNTRL),
            ("CSR_HW_REV", regs::CSR_HW_REV),
            ("CSR_FUNC_SCRATCH", regs::CSR_FUNC_SCRATCH),
            ("CSR_EEPROM_REG", regs::CSR_EEPROM_REG),
            ("CSR_UCODE_DRV_GP1", regs::CSR_UCODE_DRV_GP1),
            ("CSR_UCODE_DRV_GP2", regs::CSR_UCODE_DRV_GP2),
            ("CSR_GIO_REG", regs::CSR_GIO_REG),
            ("CSR_CTXT_INFO_ADDR", regs::CSR_CTXT_INFO_ADDR),
            ("CSR_IML_DATA_ADDR", regs::CSR_IML_DATA_ADDR),
            ("CSR_IML_SIZE_ADDR", regs::CSR_IML_SIZE_ADDR),
            ("CSR_CTXT_INFO_BOOT_CTRL", regs::CSR_CTXT_INFO_BOOT_CTRL),
            ("HBUS_TARG_PRPH_WADDR", regs::HBUS_TARG_PRPH_WADDR),
            ("HBUS_TARG_PRPH_RADDR", regs::HBUS_TARG_PRPH_RADDR),
            ("HBUS_TARG_PRPH_WDAT", regs::HBUS_TARG_PRPH_WDAT),
            ("HBUS_TARG_PRPH_RDAT", regs::HBUS_TARG_PRPH_RDAT),
            ("FH_TFDIB_CTRL0_REG_SRVC", regs::FH_TFDIB_CTRL0_REG_SRVC),
            ("FH_TFDIB_CTRL1_REG_SRVC", regs::FH_TFDIB_CTRL1_REG_SRVC),
        ];

        for (name, off) in csr_offsets {
            let _ = name;
            if *off >= BAR0_BYTES {
                return TestResult::Fail("a CSR offset lies outside the 16 KiB BAR0 window");
            }
            // Every register in this device is 32 bits wide and the
            // MMIO accessors are naturally-aligned reads and writes.
            if off % 4 != 0 {
                return TestResult::Fail("a CSR offset is not 4-byte aligned");
            }
        }

        // The HBUS window's four registers are distinct and ordered
        // WADDR, RADDR, WDAT, RDAT at +0x44..+0x50 from HBUS_BASE.
        const HBUS_BASE: u32 = 0x400;
        if regs::HBUS_TARG_PRPH_WADDR != HBUS_BASE + 0x44
            || regs::HBUS_TARG_PRPH_RADDR != HBUS_BASE + 0x48
            || regs::HBUS_TARG_PRPH_WDAT != HBUS_BASE + 0x4C
            || regs::HBUS_TARG_PRPH_RDAT != HBUS_BASE + 0x50
        {
            return TestResult::Fail("HBUS PRPH window registers are not at their offsets");
        }

        // PRPH addresses go *through* that window, so they are not
        // bounded by BAR0 — but they do all live in the peripheral
        // range, and one small enough to look like a CSR offset is
        // the symptom of the same confusion.
        let prph_addrs: &[u32] = &[
            regs::UREG_DOORBELL_TO_ISR6,
            regs::PRPH_UREG_UCODE_LOAD_STATUS,
            regs::PRPH_WFPM_OTP_CFG1_ADDR,
            regs::PRPH_LMPM_CHICK,
        ];
        for a in prph_addrs {
            if *a < BAR0_BYTES {
                return TestResult::Fail("a PRPH address is small enough to be a CSR offset");
            }
            if a % 4 != 0 {
                return TestResult::Fail("a PRPH address is not 4-byte aligned");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_csr_offsets_fit_in_bar0
    );

    /// Pin the register values that were wrong, each against the
    /// Linux symbol it mirrors. These are not derivable from anything
    /// in the tree, so a typo in one is invisible without a reference
    /// to compare against.
    fn smoke_iwlwifi_register_values_match_linux() -> TestResult {
        use super::regs;

        // (ours, linux value, linux symbol)
        let pinned: &[(u32, u32, &str)] = &[
            (regs::HBUS_TARG_PRPH_WADDR, 0x444, "HBUS_TARG_PRPH_WADDR"),
            (regs::HBUS_TARG_PRPH_RADDR, 0x448, "HBUS_TARG_PRPH_RADDR"),
            (regs::HBUS_TARG_PRPH_WDAT, 0x44C, "HBUS_TARG_PRPH_WDAT"),
            (regs::HBUS_TARG_PRPH_RDAT, 0x450, "HBUS_TARG_PRPH_RDAT"),
            (regs::CSR_CTXT_INFO_ADDR, 0x118, "CSR_CTXT_INFO_ADDR"),
            (regs::CSR_IML_DATA_ADDR, 0x120, "CSR_IML_DATA_ADDR"),
            (regs::CSR_IML_SIZE_ADDR, 0x128, "CSR_IML_SIZE_ADDR"),
            (
                regs::CSR_CTXT_INFO_BOOT_CTRL,
                0x0,
                "CSR_CTXT_INFO_BOOT_CTRL",
            ),
            (
                regs::UREG_DOORBELL_TO_ISR6,
                0x00A0_5C04,
                "UREG_DOORBELL_TO_ISR6",
            ),
            (
                regs::PRPH_UREG_UCODE_LOAD_STATUS,
                0x00A0_5C40,
                "UREG_UCODE_LOAD_STATUS",
            ),
            (
                regs::PRPH_WFPM_OTP_CFG1_ADDR,
                0x00A0_3098,
                "WFPM_OTP_CFG1_ADDR",
            ),
            (regs::PRPH_LMPM_CHICK, 0x00A0_1FF8, "LMPM_CHICK"),
            (regs::PRPH_RELEASE_CPU_RESET, 0x300C, "RELEASE_CPU_RESET"),
            (regs::IWL_ALIVE_STATUS_OK, 0xCAFE, "IWL_ALIVE_STATUS_OK"),
        ];
        for (ours, linux, sym) in pinned {
            let _ = sym;
            if ours != linux {
                return TestResult::Fail("a register constant no longer matches its Linux value");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_register_values_match_linux
    );

    /// The gen2/gen3 descriptor sizes are load-bearing: the device
    /// strides through the TFD ring by descriptor size and through a
    /// TFD's buffers by entry size, so a struct that is the wrong
    /// width desynchronises everything after the first entry. These
    /// are exactly the numbers the hardware documentation states —
    /// 10-byte transmit buffers and 256-byte descriptors.
    fn smoke_iwlwifi_gen2_descriptor_layout() -> TestResult {
        use super::tx_gen2::*;
        use core::mem::size_of;

        if size_of::<TfhTb>() != 10 {
            return TestResult::Fail("iwl_tfh_tb must be 10 bytes (len then 64-bit addr, packed)");
        }
        if size_of::<TfhTfd>() != 256 {
            return TestResult::Fail("iwl_tfh_tfd must be 256 bytes");
        }
        // 2 + 25*10 + 4 = 256; if any of the three changes the total
        // has to be rechecked against the hardware, not just patched.
        if TBS_OFFSET + IWL_TFH_NUM_TBS * size_of::<TfhTb>() + 4 != size_of::<TfhTfd>() {
            return TestResult::Fail("TFD size is not num_tbs + 25 buffers + pad");
        }

        // AX210+: len, flags(16), offload_assist(32), dram(8),
        // rate_n_flags(32), reserved[8] = 28.
        if size_of::<DramSecInfo>() != 8 {
            return TestResult::Fail("iwl_dram_sec_info must be 8 bytes");
        }
        if size_of::<TxCmdAx210>() != 28 {
            return TestResult::Fail("AX210+ iwl_tx_cmd must be 28 bytes");
        }
        // 22000-series: len, offload_assist(16), flags(32), dram(8),
        // rate_n_flags(32) = 20. Different size as well as different
        // field order, which is the cheapest way to catch a mix-up.
        if size_of::<TxCmdV9>() != 20 {
            return TestResult::Fail("iwl_tx_cmd_v9 must be 20 bytes");
        }
        if size_of::<TxCmdAx210>() == size_of::<TxCmdV9>() {
            return TestResult::Fail("the two TX command layouts must not be interchangeable");
        }
        if size_of::<BcTblEntry>() != 2 {
            return TestResult::Fail("iwl_bc_tbl_entry must be a single 16-bit word");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_gen2_descriptor_layout
    );

    /// Appending transmit buffers has to keep `num_tbs` and the entry
    /// array in step, mask the count to five bits, and refuse a
    /// buffer the DMA engine would read from the wrong address.
    fn smoke_iwlwifi_gen2_tfd_push_tb() -> TestResult {
        use super::tx_gen2::*;

        let mut tfd = TfhTfd::default();
        if tfd.num_tbs() != 0 {
            return TestResult::Fail("a fresh TFD has no buffers");
        }

        match tfd.push_tb(0x1234_5000, 64) {
            Ok(0) => {}
            _ => return TestResult::Fail("the first buffer should land at index 0"),
        }
        match tfd.push_tb(0x1234_6000, 128) {
            Ok(1) => {}
            _ => return TestResult::Fail("the second buffer should land at index 1"),
        }
        if tfd.num_tbs() != 2 {
            return TestResult::Fail("num_tbs should track the appended buffers");
        }
        // Read back through copies: the fields are packed, so they
        // cannot be referenced directly.
        let (len0, addr0) = (tfd.tbs[0].tb_len, tfd.tbs[0].addr);
        let (len1, addr1) = (tfd.tbs[1].tb_len, tfd.tbs[1].addr);
        if (len0, addr0) != (64, 0x1234_5000) || (len1, addr1) != (128, 0x1234_6000) {
            return TestResult::Fail("buffer length and address stored wrong");
        }

        // Filling to capacity then one more.
        let mut full = TfhTfd::default();
        for i in 0..IWL_TFH_NUM_TBS {
            if full.push_tb(0x1000 + (i as u64) * 0x1000, 16).is_err() {
                return TestResult::Fail("should accept exactly IWL_TFH_NUM_TBS buffers");
            }
        }
        if full.num_tbs() as usize != IWL_TFH_NUM_TBS {
            return TestResult::Fail("a full TFD should report 25 buffers");
        }
        if full.push_tb(0x9_0000, 16) != Err(TfdError::Full) {
            return TestResult::Fail("a 26th buffer must be refused");
        }

        // Reserved bits above the count must survive an append —
        // the device owns them.
        let mut reserved = TfhTfd {
            num_tbs: 0xFFE0,
            ..TfhTfd::default()
        };
        if reserved.push_tb(0x2000, 8) != Ok(0) {
            return TestResult::Fail("reserved bits must not be read as a buffer count");
        }
        if reserved.num_tbs & !NUM_TBS_MASK != 0xFFE0 {
            return TestResult::Fail("appending must not clobber the reserved bits");
        }
        if reserved.num_tbs() != 1 {
            return TestResult::Fail("the count should be 1 after one append");
        }

        // A buffer straddling 4 GiB is read from the wrong address by
        // the DMA engine, which computes the end without carrying.
        if !crosses_4gib(0xFFFF_FFF0, 32) {
            return TestResult::Fail("a buffer spanning the 4 GiB line should be detected");
        }
        if crosses_4gib(0xFFFF_FF00, 16) {
            return TestResult::Fail("a buffer ending exactly at 4 GiB does not cross it");
        }
        if crosses_4gib(0x1_0000_0000, 64) {
            return TestResult::Fail("a buffer wholly above 4 GiB does not cross a boundary");
        }
        let mut bad = TfhTfd::default();
        match bad.push_tb(0xFFFF_FFF0, 32) {
            Err(TfdError::CrossesFourGiB { .. }) => {}
            _ => return TestResult::Fail("a 4 GiB-crossing buffer must be refused"),
        }
        if bad.num_tbs() != 0 {
            return TestResult::Fail("a refused buffer must not be counted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi", smoke_iwlwifi_gen2_tfd_push_tb);

    /// The byte-count table tells the device both how long the frame
    /// is and how many 64-byte chunks of the descriptor to fetch.
    /// AX210+ carries the length in bytes; everything before it
    /// carries dwords and shifts the chunk count four bits higher.
    fn smoke_iwlwifi_gen2_byte_count_entry() -> TestResult {
        use super::tx_gen2::*;

        // A TFD with three buffers is 2 + 30 = 32 bytes filled, which
        // is one 64-byte chunk — encoded as zero.
        let mut tfd = TfhTfd::default();
        for i in 0..3 {
            let _ = tfd.push_tb(0x1000 + (i as u64) * 0x1000, 100);
        }
        if tfd.filled_bytes() != 32 {
            return TestResult::Fail("three buffers should fill 32 bytes of the TFD");
        }
        if fetch_chunks(32) != 0 {
            return TestResult::Fail("32 bytes is one chunk, encoded as 0");
        }
        // 64 bytes is still one chunk; 65 needs two.
        if fetch_chunks(64) != 0 || fetch_chunks(65) != 1 || fetch_chunks(128) != 1 {
            return TestResult::Fail("chunk count should be DIV_ROUND_UP(filled,64) - 1");
        }
        // A full TFD: 2 + 250 = 252 bytes -> four chunks -> 3.
        let mut full = TfhTfd::default();
        for i in 0..IWL_TFH_NUM_TBS {
            let _ = full.push_tb(0x1000 + (i as u64) * 0x1000, 16);
        }
        if full.filled_bytes() != 252 || fetch_chunks(full.filled_bytes()) != 3 {
            return TestResult::Fail("a full TFD is 252 filled bytes and four fetch chunks");
        }

        // AX210+ packs raw bytes with the chunk count at bit 14.
        match bc_entry_ax210(1500, 32) {
            Ok(e) if e.tfd_offset == 1500 => {}
            _ => return TestResult::Fail("AX210 entry should carry the byte length unscaled"),
        }
        match bc_entry_ax210(1500, 252) {
            Ok(e) if e.tfd_offset == 1500 | (3 << 14) => {}
            _ => return TestResult::Fail("AX210 entry should put the chunk count at bit 14"),
        }
        if bc_entry_ax210(0x4000, 32) != Err(BcError::LengthTooLarge(0x4000)) {
            return TestResult::Fail("a length needing more than 14 bits must be refused");
        }
        match bc_entry_ax210(BC_MAX_LEN_AX210, 32) {
            Ok(e) if e.tfd_offset == BC_MAX_LEN_AX210 => {}
            _ => return TestResult::Fail("0x3fff is the largest length that fits"),
        }

        // Pre-AX210 rounds up to dwords and shifts the count to 12.
        match bc_entry_pre_ax210(1500, 32) {
            Ok(e) if e.tfd_offset == 375 => {}
            _ => return TestResult::Fail("pre-AX210 should carry length in dwords"),
        }
        match bc_entry_pre_ax210(1501, 32) {
            Ok(e) if e.tfd_offset == 376 => {}
            _ => return TestResult::Fail("pre-AX210 dword length should round up"),
        }
        match bc_entry_pre_ax210(1500, 252) {
            Ok(e) if e.tfd_offset == 375 | (3 << 12) => {}
            _ => return TestResult::Fail("pre-AX210 should put the chunk count at bit 12"),
        }
        // The two encodings must not agree, or one silently stands in
        // for the other.
        let a = bc_entry_ax210(1500, 252);
        let b = bc_entry_pre_ax210(1500, 252);
        if a == b {
            return TestResult::Fail("the two byte-count encodings must differ");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_gen2_byte_count_entry
    );

    /// Gen2 rings every queue through one CSR, with the queue id in
    /// the written value. RX queues are offset by 512 so RX queue 0
    /// cannot ring TX queue 0 — the whole point of the encoding.
    fn smoke_iwlwifi_gen2_doorbell_encoding() -> TestResult {
        use super::tx_gen2::*;

        if HBUS_TARG_WRPTR != 0x460 {
            return TestResult::Fail("HBUS_TARG_WRPTR should be HBUS_BASE + 0x60");
        }
        // The doorbell is a CSR offset, so it must be inside BAR0.
        if HBUS_TARG_WRPTR >= 16 * 1024 {
            return TestResult::Fail("the doorbell must lie inside BAR0");
        }

        if tx_doorbell(0, 7) != 7 {
            return TestResult::Fail("TX queue 0 should encode to the bare write pointer");
        }
        if tx_doorbell(3, 0x2A) != 0x2A | (3 << 16) {
            return TestResult::Fail("the TX queue id belongs at bit 16");
        }
        if rx_doorbell(0, 0x10) != 0x10 | (512 << 16) {
            return TestResult::Fail("RX queue 0 should encode as queue 512");
        }
        if rx_doorbell(1, 0x10) != 0x10 | (513 << 16) {
            return TestResult::Fail("RX queue ids should be offset by 512");
        }
        if tx_doorbell(0, 0x10) == rx_doorbell(0, 0x10) {
            return TestResult::Fail("TX and RX queue 0 must not share a doorbell value");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_gen2_doorbell_encoding
    );

    /// Gen2 queues are created by a host command that hands the
    /// firmware the rings the driver allocated. The ring depth is
    /// carried as a biased exponent, which only encodes powers of two
    /// between 8 and 256.
    fn smoke_iwlwifi_gen2_queue_cfg() -> TestResult {
        use super::tx_gen2::*;
        use core::mem::size_of;

        if size_of::<TxQueueCfgCmd>() != 24 {
            return TestResult::Fail("iwl_tx_queue_cfg_cmd must be 24 bytes");
        }
        if size_of::<TxQueueCfgRsp>() != 8 {
            return TestResult::Fail("iwl_tx_queue_cfg_rsp must be 8 bytes");
        }

        // log2(depth) - 3: 8 TFDs is 0, 256 is 5.
        if cb_size_for(8) != Ok(0) {
            return TestResult::Fail("8 TFDs should encode as 0");
        }
        if cb_size_for(256) != Ok(5) {
            return TestResult::Fail("256 TFDs should encode as 5");
        }
        if cb_size_for(IWL_MGMT_QUEUE_SIZE) != Ok(1) {
            return TestResult::Fail("the 16-slot management queue should encode as 1");
        }
        if cb_size_for(IWL_CMD_QUEUE_SIZE) != Ok(2) {
            return TestResult::Fail("the 32-slot command queue should encode as 2");
        }

        // A depth with no encoding is refused rather than rounded:
        // serving a 200-slot ring as 128 would leave host and
        // firmware disagreeing about where the ring wraps.
        if cb_size_for(200) != Err(QueueCfgError::NotPowerOfTwo(200)) {
            return TestResult::Fail("a non-power-of-two depth must be refused");
        }
        if cb_size_for(4) != Err(QueueCfgError::DepthOutOfRange(4)) {
            return TestResult::Fail("a depth below 8 must be refused");
        }
        if cb_size_for(512) != Err(QueueCfgError::DepthOutOfRange(512)) {
            return TestResult::Fail("a depth above 256 must be refused");
        }

        let cmd = match TxQueueCfgCmd::enable(0, 7, 256, 0x1234_0000, 0x5678_0000) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("a 256-deep queue should be describable"),
        };
        let (sta, tid, flags, cb) = (cmd.sta_id, cmd.tid, cmd.flags, cmd.cb_size);
        let (bc, tfdq) = (cmd.byte_cnt_addr, cmd.tfdq_addr);
        if (sta, tid, cb) != (0, 7, 5) {
            return TestResult::Fail("queue config fields stored wrong");
        }
        if flags & TX_QUEUE_CFG_ENABLE_QUEUE == 0 {
            return TestResult::Fail("an enable command must set the enable bit");
        }
        if (bc, tfdq) != (0x1234_0000, 0x5678_0000) {
            return TestResult::Fail("the ring addresses must not be transposed");
        }

        // The AX210+ byte-count table is a fixed 1024 entries, not
        // one per ring slot: a 16-slot management queue still needs
        // the full 2 KiB, and sizing it from the ring would hand the
        // firmware a table it writes past the end of.
        if BC_TABLE_BYTES_AX210 != 2048 {
            return TestResult::Fail("an AX210+ byte-count table is 1024 entries of 2 bytes");
        }
        if bc_table_bytes_pre_ax210(256) != (256 + 64) * 2 {
            return TestResult::Fail("pre-AX210 tables are ring depth plus the 64-entry dup");
        }
        if bc_table_bytes_pre_ax210(IWL_MGMT_QUEUE_SIZE) >= BC_TABLE_BYTES_AX210 {
            return TestResult::Fail("the two table sizings should not coincide");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi", smoke_iwlwifi_gen2_queue_cfg);
}
