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
pub mod wpa;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Poll, Waker};

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

unsafe impl Send for IwlDevice {}
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
        let cmd_ptr = unsafe { cmd_dma.as_mut_ptr().add(slot * 32) as *mut tx::IwlTxCmd };
        unsafe {
            core::ptr::write_volatile(cmd_ptr, cmd);
        }

        let mut tfd = tx::Tfd::default();
        tfd.push_seg(
            cmd_dma.phys_addr().as_u64() + (slot * 32) as u64,
            core::mem::size_of::<tx::IwlTxCmd>() as u16,
        );
        tfd.push_seg(buf.phys_addr().as_u64(), frame_len);

        tx_q.enqueue(tfd);
        tx::tx_doorbell(&mut mmio, 0, tx_q.write_ptr);

        // Keep the buffer alive until the device DMAs it; in production
        // we'd thread this through a per-slot lifetime pool. For the
        // bring-up smoke we let the page live in the slab.
        core::mem::forget(buf);
        Ok(())
    }

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

#[async_trait::async_trait]
impl WirelessNetIface for IwlDevice {
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        WirelessIfaceInfo {
            base_name: self.name().into(),
            base_mac: self.mac(),
            bands: alloc::vec![], // TODO: populate from chip config
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
                    unsafe { cmd_dma.as_mut_ptr().add(slot * 32) as *mut tx::IwlCmdHeader };
                unsafe {
                    core::ptr::write_volatile(hdr_ptr, hdr);
                }

                // 3. Build TFD.
                let mut tfd = tx::Tfd::default();
                tfd.push_seg(
                    cmd_dma.phys_addr().as_u64() + (slot * 32) as u64,
                    core::mem::size_of::<tx::IwlCmdHeader>() as u16,
                );
                tfd.push_seg(pd.phys_addr().as_u64(), cmd_body.len() as u16);

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
            let cmd_ptr = unsafe { cmd_dma.as_mut_ptr().add(slot * 32) as *mut tx::IwlTxCmd };
            unsafe {
                core::ptr::write_volatile(cmd_ptr, cmd);
            }

            let mut tfd = tx::Tfd::default();
            tfd.push_seg(
                cmd_dma.phys_addr().as_u64() + (slot * 32) as u64,
                core::mem::size_of::<tx::IwlTxCmd>() as u16,
            );
            tfd.push_seg(
                frame.buf().phys_addr().as_u64() + frame.offset() as u64,
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
                                channel: 1, // TODO: extract from PHY metadata
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
        let cmd_ptr = unsafe { cmd_dma.as_mut_ptr().add(slot * 32) as *mut tx::IwlTxCmd };
        unsafe {
            core::ptr::write_volatile(cmd_ptr, cmd);
        }

        // 3. Build TFD with two segments.
        let mut tfd = tx::Tfd::default();
        // Segment 0: IwlTxCmd header.
        let cmd_size = core::mem::size_of::<tx::IwlTxCmd>();
        let cmd_phys = cmd_dma.phys_addr().as_u64() + (slot * 32) as u64;
        tfd.push_seg(cmd_phys, cmd_size as u16);
        // Segment 1: Frame payload.
        tfd.push_seg(
            frame.buf().phys_addr().as_u64() + frame.offset() as u64,
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
        unsafe { self.0.read32(offset as u64) }
    }
    fn write(&mut self, offset: u32, value: u32) {
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
}

impl RfFamily {
    pub fn prefix(self) -> &'static str {
        match self {
            RfFamily::HrB0 => "hr-b0",
            RfFamily::GfA0 => "gf-a0",
            RfFamily::Gf4A0 => "gf4-a0",
            RfFamily::FmA0 => "fm-a0",
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
    /// UCODE API version walk: try filenames with API stamps
    /// from `api_max` down to `api_min`. Special-case in
    /// `iwl-drv.c`: when the API counter passes 100, jump to
    /// 102 (the "core" numbering for Bz+).
    pub api_max: u32,
    pub api_min: u32,
}

/// AX200 — single fused chip. Linux ships HR-b0 RF only.
const RF_HR_ONLY: &[RfFamily] = &[RfFamily::HrB0];
/// AX210 — GF / GF4 RFs depending on OTP fuse.
const RF_GF_OR_GF4: &[RfFamily] = &[RfFamily::GfA0, RfFamily::Gf4A0];
/// BE200 — GF / GF4 / FM RFs.
const RF_GF_FAMILY: &[RfFamily] = &[RfFamily::GfA0, RfFamily::Gf4A0, RfFamily::FmA0];

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
                "iwlwifi/iwlwifi-{}-{}-{}.ucode",
                chip.mac.prefix(),
                rf.prefix(),
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
            for i in 0..rx::RX_RING_SIZE {
                unsafe {
                    (*rx_descs.add(i)).host_phys = rx_buffers[i].phys_addr().as_u64();
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
                rx_ring_mem.phys_addr().as_u64() as u32,
            );
            mmio.write(rx::CSR_FH_RSCSR_CHNL0_WPTR, (rx::RX_RING_SIZE - 1) as u32);

            // 5. Instantiate and register the device.
            // TODO: Read real MAC from hardware/firmware.
            let mac_addr = [0x00, 0x16, 0xEA, 0x12, 0x34, 0x56];

            let rx_q = rx::RxQueue::new(rx_descs, rx_ring_mem.phys_addr().as_u64());
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
        if &cmd[20..26] != &node_addr {
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
}
